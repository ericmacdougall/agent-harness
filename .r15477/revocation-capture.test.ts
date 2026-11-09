/**
 * goodqa#15477 F1: real Electron, the real host (dist), a fake camera. After a revocation the capturing document and
 * what it staged must be gone even when the page resists replacement. Needs `pnpm run build` (dist) and, on Linux,
 * xvfb-run; otherwise skipped. Local 127.0.0.1 servers only.
 */
import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';

const requireFromDesktop = createRequire(resolve('package.json'));
const hostPath = resolve(process.env.REVOCATION_HOST_PATH ?? 'dist/agent-browser/host.js');
const skip = !existsSync(hostPath) || (process.platform === 'linux' && !process.env.DISPLAY);
const dir = skip ? '' : mkdtempSync(join(process.env.SCRATCH ?? tmpdir(), 'revocation-'));
afterAll(() => { if (dir) rmSync(dir, { recursive: true, force: true }); });

type Result = {
  before: { track?: string; files?: number; error?: string };
  mediaBefore: boolean;
  immediately: { media: boolean; revocation: string | null } | null;
  timeline: Array<{ ms: number; media: boolean | null; revocation: string | null }>;
  after: { doc: string | null; hasStream: string; state: string | null; input: string | null; files: number | null; cdpError?: string };
  final: { media: boolean; revocation: string | null; controller: string; stopped: boolean } | null;
  logs: string[];
  urlAfter: string;
};

function run(mode: string, path = 'stopTab'): Promise<Result> {
  const name = mode + '-' + path;
  const child = spawn(requireFromDesktop('electron'), ['--no-sandbox', '--disable-gpu', resolve('test/revocation-capture.cjs')], {
    detached: process.platform !== 'win32',
    env: { ...process.env, RC_HOST: hostPath, RC_MODE: mode, RC_PATH: path, RC_RESULT: join(dir, name + '.json'), RC_PROFILE: join(dir, name + '-profile'), XDG_CONFIG_HOME: join(dir, name + '-config'), XDG_CACHE_HOME: join(dir, name + '-cache') },
    stdio: ['ignore', 'ignore', 'pipe'],
  });
  return new Promise((done, fail) => {
    let stderr = '';
    child.stderr.setEncoding('utf8').on('data', (c) => { stderr = (stderr + c).slice(-4000); });
    const timer = setTimeout(() => { try { process.kill(-child.pid!, 'SIGKILL'); } catch { /* gone */ } }, 60000);
    child.once('error', fail);
    child.once('close', (code) => {
      clearTimeout(timer);
      if (code === 0) done(JSON.parse(readFileSync(join(dir, name + '.json'), 'utf8')));
      else fail(new Error('revocation fixture exited ' + code + '\n' + stderr));
    });
  });
}

function expectRevoked(r: Result) {
  const why = JSON.stringify(r);
  // The setup really captured and staged, so the assertions below cannot pass vacuously.
  expect(r.before, why).toMatchObject({ track: 'live', files: 1 });
  expect(r.mediaBefore, why).toBe(true);
  // The capturing document is gone (its tracks ended with it), and so is what the person or agent staged in it.
  expect(r.after.cdpError, why).toBeUndefined();
  expect(r.after.doc, why).toBeNull();
  expect(r.after.hasStream, why).toBe('undefined');
  expect(r.after.state === null || r.after.state === 'ended', why).toBe(true);
  expect(r.after.input ?? '', why).toBe('');
  expect(r.after.files ?? 0, why).toBe(0);
  // The tab stays with the person and the indicator says capture ended only now.
  expect(r.final, why).toMatchObject({ media: false, controller: 'user', stopped: true });
  expect(r.final?.revocation ?? null, why).toBeNull();
}

describe.skipIf(skip)('real Electron: a revoked visible tab loses its capture and staged state', () => {
  it('control: a plain GET page is replaced with no fallback and no failure log', async () => {
    const r = await run('control');
    expectRevoked(r);
    expect(r.logs, JSON.stringify(r)).toEqual([]);
  }, 90000);

  it('a beforeunload handler (after a click) cannot veto the replacement', async () => {
    const r = await run('beforeunload');
    expectRevoked(r);
    expect(r.logs, JSON.stringify(r)).toEqual([]);
  }, 90000);

  it('a GET that answers 204 falls back to about:blank, logged', async () => {
    const r = await run('nocontent');
    expectRevoked(r);
    expect(r.urlAfter).toBe('about:blank');
    expect(r.logs.some((l) => /revoke_failed id=\d+ reason=stopped_by_person step=load code=[a-z_]+$/.test(l)), JSON.stringify(r)).toBe(true);
  }, 90000);

  it('a GET that answers with an attachment falls back to about:blank, logged', async () => {
    const r = await run('download');
    expectRevoked(r);
    expect(r.urlAfter).toBe('about:blank');
    expect(r.logs.some((l) => / step=load code=[a-z_]+$/.test(l)), JSON.stringify(r)).toBe(true);
  }, 90000);

  it('a GET that never answers is stopped after the bound and sent to about:blank; the indicator holds until then', async () => {
    const r = await run('hang');
    expectRevoked(r);
    expect(r.urlAfter).toBe('about:blank');
    expect(r.logs.some((l) => / step=load code=timeout$/.test(l)), JSON.stringify(r)).toBe(true);
    // Capture was still live while the GET hung: the person kept seeing it until the replacement committed.
    expect(r.immediately, JSON.stringify(r)).toMatchObject({ media: true, revocation: 'pending' });
    expect(r.timeline[0], JSON.stringify(r)).toMatchObject({ media: true });
  }, 90000);

  it('stop() and a renew that drops capture take the same path (beforeunload page)', async () => {
    expectRevoked(await run('beforeunload', 'stop'));
    expectRevoked(await run('hang', 'renew'));
  }, 120000);
});
