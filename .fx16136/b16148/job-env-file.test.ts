/**
 * goodqa#16148 spec v4 AC-4, AC-5, AC-9, NEG-4, NEG-6: an allow-listed `JOB_ENVFILE_KIND__VAR=PATH`
 * supplies VAR to that kind's job env, read from a file under the secrets dir at every launch.
 * Failures are per kind: 501 `job env file for KIND__VAR: REASON`, docker never called, the same
 * line logged with key name and path only. Boot logs one status line per key and never fails.
 * All values are fake.
 */
import { chmodSync, mkdirSync, mkdtempSync, renameSync, symlinkSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
import { Worker } from 'node:worker_threads';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { loadConfig } from '../src/config';
import { clearExecutionsForTesting } from '../src/executions';
import { buildServer } from '../src/server';
import { bootEnvFileStatusLines, readJobEnvFile, JOB_ENVFILE_ALLOWLIST } from '../src/job-env-file';

const TOKEN = 'shim-token-not-real';
const auth = { authorization: `Bearer ${TOKEN}` };
const KEY = 'JOB_ENVFILE_INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY';
const FAKE_PEM = '-----BEGIN FAKE KEY-----MIIFAKEfakeFAKEfake0123456789-----END FAKE KEY-----';

let dir = '';
beforeEach(() => {
  const base = join(process.cwd(), '.scratch');
  mkdirSync(base, { recursive: true });
  dir = mkdtempSync(join(base, 'secrets-'));
  clearExecutionsForTesting();
});

function config(env: Record<string, string> = {}) {
  return {
    ...loadConfig({
      JOB_DISPATCH_TOKEN: TOKEN,
      JOB_IMAGE_SCAN: 'ar/scan:tag',
      JOB_IMAGE_TRANSCODE: 'ar/transcode:tag',
      JOB_IMAGE_INTELLIGENCE_WORKER: 'ar/iw:tag',
      JOB_IMAGE_SUGGEST_FIX_WORKER: 'ar/sf:tag',
      ...env,
    }),
    jobEnvFileDir: dir,
  };
}

function okRun() {
  return vi.fn().mockResolvedValue({ containerId: 'c1', startedAt: '2026-11-16T00:00:00.000Z' });
}

async function launch(cfg: ReturnType<typeof config>, run = okRun(), kind = 'intelligence-worker', lines: string[] = []) {
  const app = buildServer(cfg, { run, inspect: vi.fn() } as never, { logStream: { write: (l: string) => lines.push(l) } });
  const res = await app.inject({ method: 'POST', url: `/jobs/${kind}/run`, headers: auth, payload: {} });
  return { res, run, lines };
}

describe('AC-4: injection', () => {
  it('the allow-listed key supplies VAR to intelligence-worker only, read at launch, one trailing LF removed', async () => {
    writeFileSync(join(dir, 'github-app-private-key'), `${FAKE_PEM}\n`);
    const cfg = config({ [KEY]: join(dir, 'github-app-private-key'), JOB_ENV_INTELLIGENCE_WORKER__OTHER: 'o' });
    const { res, run } = await launch(cfg);
    expect(res.statusCode).toBe(200);
    const env = run.mock.calls[0]![3] as Record<string, string>;
    expect(env.GITHUB_APP_PRIVATE_KEY).toBe(FAKE_PEM);
    expect(env.OTHER).toBe('o');
    // The value is a secret source: it is in the redaction list (goodqa#16185).
    expect(run.mock.calls[0]![6]).toContain(FAKE_PEM);
    for (const kind of ['scan', 'transcode', 'suggest-fix-worker']) {
      const other = await launch(cfg, okRun(), kind);
      expect(other.res.statusCode).toBe(200);
      expect((other.run.mock.calls[0]![3] as Record<string, string>).GITHUB_APP_PRIVATE_KEY).toBeUndefined();
    }
  });

  it('only INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY is allow-listed', () => {
    expect([...JOB_ENVFILE_ALLOWLIST]).toEqual(['INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY']);
  });

  it('a non-allow-listed JOB_ENVFILE key is ignored and logged by name at boot', async () => {
    writeFileSync(join(dir, 'x'), 'secret-x');
    const cfg = config({ JOB_ENVFILE_SCAN__DATABASE_URL: join(dir, 'x') });
    const { res, run } = await launch(cfg, okRun(), 'scan');
    expect(res.statusCode).toBe(200);
    expect((run.mock.calls[0]![3] as Record<string, string>).DATABASE_URL).toBeUndefined();
    expect(bootEnvFileStatusLines(cfg)).toContain('job env file key ignored (not allow-listed): JOB_ENVFILE_SCAN__DATABASE_URL');
  });

  it('JOB_ENV_KIND__VAR ending in _FILE keeps its literal meaning', async () => {
    const cfg = config({ JOB_ENV_INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY_FILE: '/some/path' });
    const { run } = await launch(cfg);
    expect((run.mock.calls[0]![3] as Record<string, string>).GITHUB_APP_PRIVATE_KEY_FILE).toBe('/some/path');
    expect((run.mock.calls[0]![3] as Record<string, string>).GITHUB_APP_PRIVATE_KEY).toBeUndefined();
  });
});

describe('AC-5 / NEG-4: fail closed per kind', () => {
  const name = 'github-app-private-key';
  const cases: Array<[string, () => string, RegExp]> = [
    ['missing file', () => join(dir, name), /: missing$/],
    ['unreadable (mode 000)', () => { writeFileSync(join(dir, name), FAKE_PEM); chmodSync(join(dir, name), 0o000); return join(dir, name); }, /: unreadable$/],
    ['empty', () => { writeFileSync(join(dir, name), ''); return join(dir, name); }, /: empty$/],
    ['only a newline', () => { writeFileSync(join(dir, name), '\n'); return join(dir, name); }, /: empty$/],
    ['a symlink to a readable file', () => { writeFileSync(join(dir, 'real'), FAKE_PEM); symlinkSync(join(dir, 'real'), join(dir, name)); return join(dir, name); }, /: is a symlink$/],
    ['a FIFO', () => { execFileSync('mkfifo', [join(dir, name)]); return join(dir, name); }, /: not a regular file$/],
    ['a directory', () => { mkdirSync(join(dir, name)); return join(dir, name); }, /: not a regular file$/],
    ['a 65 KiB file', () => { writeFileSync(join(dir, name), 'A'.repeat(65 * 1024)); return join(dir, name); }, /: over 64 KiB$/],
    ['a path outside the secrets dir', () => { writeFileSync(join(dir, '..', 'outside-key'), FAKE_PEM); return join(dir, '..', 'outside-key'); }, /: path outside the secrets directory$/],
    ['.. traversal', () => `${dir}/../${dir.split('/').pop()}/${name}`, /: path outside the secrets directory$/],
    ['a relative path', () => 'github-app-private-key', /: path outside the secrets directory$/],
    ['a CR inside the value', () => { writeFileSync(join(dir, name), 'abc\rdef\n'); return join(dir, name); }, /: value holds CR, LF or NUL$/],
    ['an inner LF', () => { writeFileSync(join(dir, name), 'abc\ndef\n'); return join(dir, name); }, /: value holds CR, LF or NUL$/],
    ['a NUL', () => { writeFileSync(join(dir, name), 'abc\u0000def'); return join(dir, name); }, /: value holds CR, LF or NUL$/],
    ['invalid UTF-8', () => { writeFileSync(join(dir, name), Buffer.from([0x41, 0xff, 0x42])); return join(dir, name); }, /: value is not valid UTF-8$/],
  ];

  it.each(cases)('%s: 501, docker not called, the named line logged without the value', async (_n, setup, reason) => {
    const path = setup();
    const { res, run, lines } = await launch(config({ [KEY]: path }));
    expect(res.statusCode).toBe(501);
    const error = (res.json() as { error: string }).error;
    expect(error.startsWith('job env file for INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY: ')).toBe(true);
    expect(error).toMatch(reason);
    expect(run).not.toHaveBeenCalled();
    expect(lines.some((l) => l.includes(error))).toBe(true);
    for (const l of [...lines, res.body]) expect(l).not.toContain('MIIFAKEfake');
    // Other kinds are unaffected.
    const other = await launch(config({ [KEY]: path }), okRun(), 'scan');
    expect(other.res.statusCode).toBe(200);
  });

  it('both JOB_ENV_ and JOB_ENVFILE_ for the same VAR: 501', async () => {
    writeFileSync(join(dir, name), FAKE_PEM);
    const { res, run } = await launch(config({ [KEY]: join(dir, name), JOB_ENV_INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY: 'inline' }));
    expect(res.statusCode).toBe(501);
    expect(res.json().error).toBe('job env file for INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY: both JOB_ENV_ and JOB_ENVFILE_ are set');
    expect(run).not.toHaveBeenCalled();
  });

  it('boot status lines: ok, or the named error; never the content; boot never throws', () => {
    writeFileSync(join(dir, name), FAKE_PEM);
    expect(bootEnvFileStatusLines(config({ [KEY]: join(dir, name) }))).toEqual(['job env file INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY: ok']);
    expect(bootEnvFileStatusLines(config({ [KEY]: join(dir, 'nope') }))).toEqual([
      'job env file for INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY: missing',
    ]);
    expect(bootEnvFileStatusLines(config())).toEqual([]);
  });
});

describe('AC-9 / NEG-6: rotation', () => {
  it('a changed file is used by the next launch without a restart, never the old value', async () => {
    const path = join(dir, 'github-app-private-key');
    writeFileSync(path, 'OLDfakeVALUE-0001');
    const cfg = config({ [KEY]: path });
    const app = buildServer(cfg, { run: okRun(), inspect: vi.fn() } as never);
    const run = okRun();
    const app2 = buildServer(cfg, { run, inspect: vi.fn() } as never);
    void app;
    await app2.inject({ method: 'POST', url: '/jobs/intelligence-worker/run', headers: auth, payload: {} });
    writeFileSync(join(dir, '.tmp'), 'NEWfakeVALUE-0002');
    renameSync(join(dir, '.tmp'), path);
    await app2.inject({ method: 'POST', url: '/jobs/intelligence-worker/run', headers: auth, payload: {} });
    expect((run.mock.calls[0]![3] as Record<string, string>).GITHUB_APP_PRIVATE_KEY).toBe('OLDfakeVALUE-0001');
    expect((run.mock.calls[1]![3] as Record<string, string>).GITHUB_APP_PRIVATE_KEY).toBe('NEWfakeVALUE-0002');
  });

  it('NEG-6: 200 reads while another thread renames in a loop each see exactly the old or the new value', async () => {
    const path = join(dir, 'github-app-private-key');
    const A = `A${'a'.repeat(4000)}`;
    const B = `B${'b'.repeat(6000)}`;
    writeFileSync(path, A);
    const worker = new Worker(
      `const { writeFileSync, renameSync } = require('node:fs');
       const { workerData, parentPort } = require('node:worker_threads');
       let i = 0, stop = false;
       parentPort.on('message', () => { stop = true; });
       (function loop() {
         for (let k = 0; k < 50 && !stop; k += 1) {
           const t = workerData.dir + '/.t' + (i % 2);
           writeFileSync(t, i % 2 ? workerData.A : workerData.B);
           renameSync(t, workerData.path);
           i += 1;
           if (i === 1) parentPort.postMessage('started');
         }
         if (!stop) setImmediate(loop); else parentPort.postMessage(i);
       })();`,
      { eval: true, workerData: { dir, path, A, B } },
    );
    await new Promise((res) => worker.once('message', res));
    const seen = new Set<string>();
    for (let n = 0; n < 200; n += 1) {
      const r = readJobEnvFile(path, dir);
      expect(r.ok).toBe(true);
      const v = (r as { value: string }).value;
      expect(v === A || v === B).toBe(true);
      seen.add(v[0]!);
      await new Promise((res) => setTimeout(res, 1));
    }
    const renames = await new Promise<number>((res) => {
      worker.once('message', res);
      worker.postMessage('stop');
    });
    await worker.terminate();
    expect(renames).toBeGreaterThan(0);
    expect(seen.size).toBe(2);
  });
});
