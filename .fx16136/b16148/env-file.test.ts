/**
 * goodqa#16148 spec v4 AC-6 (1), NEG-8, NEG-9, NEG-10: every job env reaches docker through a
 * private --env-file, never `-e KEY=VALUE` on the command line (/proc/PID/cmdline is
 * world-readable in the host PID namespace).
 *
 * The stub docker records its argv and inspects the env-file at call time: mode 0600 in a fresh
 * 0700 directory under TMPDIR, exactly one `KEY=VALUE` line per variable. Both are gone after the
 * call on every path (success, docker failure, timeout, a synchronous throw).
 */
import { lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, statSync, symlinkSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const execFileMock = vi.fn();
vi.mock('node:child_process', () => ({
  execFile: (...args: unknown[]) => execFileMock(...args),
}));

const { dockerRunDetached, sweepStaleEnvFileDirs, envEntryProblem, JobEnvError, NO_HARDENING, ENVFILE_DIR_PREFIX } = await import('../src/docker');
const { buildServer } = await import('../src/server');
const { loadConfig } = await import('../src/config');
const { clearExecutionsForTesting } = await import('../src/executions');

type Callback = (error: Error | null, stdout?: string, stderr?: string) => void;

interface Seen {
  args: string[];
  fileMode: number;
  dirMode: number;
  content: Buffer;
  path: string;
  dir: string;
}

let root = '';
const savedTmp = process.env.TMPDIR;

beforeEach(() => {
  const base = join(process.cwd(), '.scratch');
  mkdirSync(base, { recursive: true });
  root = mkdtempSync(join(base, 'envfile-test-'));
  process.env.TMPDIR = root;
  clearExecutionsForTesting();
});

afterEach(() => {
  execFileMock.mockReset();
  if (savedTmp === undefined) delete process.env.TMPDIR;
  else process.env.TMPDIR = savedTmp;
});

/** Stub docker: snapshot the env-file at call time, then behave as `mode` says. */
function stubDocker(mode: 'ok' | 'fail' | 'timeout' | 'throw', seen: Seen[]) {
  execFileMock.mockImplementationOnce((_file: string, args: string[], _opts: unknown, cb: Callback) => {
    const i = args.indexOf('--env-file');
    const path = i >= 0 ? args[i + 1]! : '';
    const dir = path ? path.slice(0, path.lastIndexOf('/')) : '';
    seen.push({
      args: [...args],
      fileMode: path ? statSync(path).mode & 0o777 : -1,
      dirMode: dir ? statSync(dir).mode & 0o777 : -1,
      content: path ? readFileSync(path) : Buffer.alloc(0),
      path,
      dir,
    });
    if (mode === 'throw') throw new Error('spawn EACCES');
    if (mode === 'ok') return cb(null, 'cid123\n', '');
    if (mode === 'timeout') return cb(Object.assign(new Error('timed out'), { killed: true, signal: 'SIGTERM' }), '', '');
    return cb(Object.assign(new Error('Command failed'), { code: 125, stderr: 'docker: boom' }), '', 'docker: boom');
  });
}

const ENV = {
  A_PLAIN: 'value',
  B_SPACES: '  lead inner  trail  ',
  C_EQ: 'x=y==z',
  D_HASH: '#not-a-comment # inner',
  E_EMPTY: '',
  F_QUOTES: `"double" 'single'`,
  G_BACKSLASH: 'a\\b\\\\c\\n',
  H_UTF8: 'café 日本 \u{1F600}',
};

function expectedFile(env: Record<string, string>): Buffer {
  return Buffer.from(Object.entries(env).map(([k, v]) => `${k}=${v}\n`).join(''), 'utf8');
}

describe('AC-6 (1): env reaches docker only through --env-file', () => {
  it('argv holds --env-file and no value; the file is 0600 in a fresh 0700 dir with one KEY=VALUE line each, and both are gone afterwards', async () => {
    const seen: Seen[] = [];
    stubDocker('ok', seen);
    const res = await dockerRunDetached('docker', 'img:tag', ['arg1'], ENV, 5000, NO_HARDENING);
    expect(res.containerId).toBe('cid123');
    const s = seen[0]!;
    expect(s.args).toEqual(['run', '--rm', '-d', '--env-file', s.path, 'img:tag', 'arg1']);
    expect(s.args).not.toContain('-e');
    for (const v of Object.values(ENV).filter((x) => x.length > 0)) {
      for (const a of s.args) expect(a.includes(v), `argv element carries a value: ${a}`).toBe(false);
    }
    expect(s.fileMode).toBe(0o600);
    expect(s.dirMode).toBe(0o700);
    expect(s.dir.startsWith(join(root, ENVFILE_DIR_PREFIX))).toBe(true);
    expect(s.content.equals(expectedFile(ENV))).toBe(true);
    expect(existsSync(s.dir)).toBe(false);
    expect(readdirSync(root)).toEqual([]);
  });

  it.each(['fail', 'timeout', 'throw'] as const)('NEG-9: the env-file and its dir are removed when docker %s', async (mode) => {
    const seen: Seen[] = [];
    stubDocker(mode, seen);
    await expect(dockerRunDetached('docker', 'img:tag', [], { K: 'secret-value-123' }, 5000, NO_HARDENING)).rejects.toBeTruthy();
    expect(seen).toHaveLength(1);
    expect(existsSync(seen[0]!.path)).toBe(false);
    expect(readdirSync(root)).toEqual([]);
  });

  it('two launches never share a directory', async () => {
    const seen: Seen[] = [];
    stubDocker('ok', seen);
    stubDocker('ok', seen);
    await dockerRunDetached('docker', 'i', [], { K: 'a' }, 5000, NO_HARDENING);
    await dockerRunDetached('docker', 'i', [], { K: 'b' }, 5000, NO_HARDENING);
    expect(seen[0]!.dir).not.toBe(seen[1]!.dir);
  });
});

describe('NEG-10: invalid keys or values are refused before anything is written', () => {
  it.each([
    ['empty key', { '': 'v' }],
    ['key with =', { 'A=B': 'v' }],
    ['key with space', { 'A B': 'v' }],
    ['non-ASCII key', { 'CAFÉ': 'v' }],
    ['key starting with a digit', { '1A': 'v' }],
    ['value with LF', { K: 'a\nb' }],
    ['value with CR', { K: 'a\rb' }],
    ['value with NUL', { K: 'a\u0000b' }],
    ['value that is not valid UTF-8 (lone surrogate)', { K: 'a\ud800b' }],
  ])('%s', async (_name, env) => {
    await expect(dockerRunDetached('docker', 'i', [], env as Record<string, string>, 5000, NO_HARDENING)).rejects.toBeInstanceOf(JobEnvError);
    expect(execFileMock).not.toHaveBeenCalled();
    expect(readdirSync(root)).toEqual([]);
  });

  it('the refusal names the key, never the value', () => {
    const problem = envEntryProblem('API_KEY', 'super-secret-value\nx');
    expect(problem).toContain('API_KEY');
    expect(problem).not.toContain('super-secret-value');
  });
});

describe('boot sweep of stale env-file dirs', () => {
  it('removes leftover goodqa-envfile-* dirs, leaves other entries, and never follows a symlink', () => {
    const stale = join(root, `${ENVFILE_DIR_PREFIX}stale1`);
    mkdirSync(stale, { mode: 0o700 });
    writeFileSync(join(stale, 'env'), 'K=old-secret\n', { mode: 0o600 });
    const other = join(root, 'unrelated');
    mkdirSync(other);
    const outside = mkdtempSync(join(process.cwd(), '.scratch', 'outside-'));
    writeFileSync(join(outside, 'keep'), 'keep');
    symlinkSync(outside, join(root, `${ENVFILE_DIR_PREFIX}link`));
    const removed = sweepStaleEnvFileDirs(root);
    expect(removed).toBe(2);
    expect(existsSync(stale)).toBe(false);
    expect(existsSync(other)).toBe(true);
    expect(() => lstatSync(join(root, `${ENVFILE_DIR_PREFIX}link`))).toThrow();
    expect(readFileSync(join(outside, 'keep'), 'utf8')).toBe('keep');
  });
});

describe('server: request env 400, base env 501, never docker', () => {
  const TOKEN = 'shim-token-not-real';
  const auth = { authorization: `Bearer ${TOKEN}` };
  function config(base: Record<string, string> = {}) {
    return {
      ...loadConfig({
        JOB_DISPATCH_TOKEN: TOKEN,
        JOB_IMAGE_SCAN: 'ar/scan:tag',
        JOB_IMAGE_TRANSCODE: 'ar/transcode:tag',
        JOB_IMAGE_INTELLIGENCE_WORKER: 'ar/iw:tag',
        JOB_IMAGE_SUGGEST_FIX_WORKER: 'ar/sf:tag',
      }),
      jobBaseEnv: { scan: base, transcode: {}, 'intelligence-worker': {}, 'suggest-fix-worker': {} },
    };
  }

  it.each([['LF', 'ghs_a\nb'], ['CR', 'ghs_a\rb'], ['NUL', 'ghs_a\u0000b']])('NEG-8: a request env value with %s answers 400', async (_n, value) => {
    const run = vi.fn();
    const app = buildServer(config(), { run, inspect: vi.fn() } as never);
    const res = await app.inject({ method: 'POST', url: '/jobs/scan/run', headers: auth, payload: { env: { SCAN_CLONE_TOKEN: value } } });
    expect(res.statusCode).toBe(400);
    expect(run).not.toHaveBeenCalled();
    expect(res.body).not.toContain('ghs_a');
  });

  it('a base env value with LF answers 501 with a named error and no value', async () => {
    const run = vi.fn();
    const app = buildServer(config({ DATABASE_URL: 'postgres://secret\nx' }), { run, inspect: vi.fn() } as never);
    const res = await app.inject({ method: 'POST', url: '/jobs/scan/run', headers: auth, payload: {} });
    expect(res.statusCode).toBe(501);
    expect(res.json().error).toContain('DATABASE_URL');
    expect(res.body).not.toContain('postgres://secret');
    expect(run).not.toHaveBeenCalled();
  });

  it('a JobEnvError from the launcher answers 501', async () => {
    const run = vi.fn().mockRejectedValue(new JobEnvError('job env K: value holds CR, LF or NUL'));
    const app = buildServer(config(), { run, inspect: vi.fn() } as never);
    const res = await app.inject({ method: 'POST', url: '/jobs/scan/run', headers: auth, payload: {} });
    expect(res.statusCode).toBe(501);
  });
});
