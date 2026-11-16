/**
 * goodqa#16148 spec v4 AC-8 / P3: the release's trial boot runs the dispatcher image with the CLI flag `--boot-check`.
 * Lead ruling (Q2): a CLI flag only, never an env var; no port, no docker; prints the JOB_ENVFILE boot lines and exits
 * 0 only when every line is `ok`. Fake values only.
 */
import { mkdtempSync, readFileSync, rmSync, writeFileSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { BOOT_CHECK_FLAG, isBootCheck, runBootCheck } from '../src/boot-check';

const KEY = 'JOB_ENVFILE_INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY';
// One line, as derive writes it (the file value may not hold CR or LF).
const FAKE = '-----BEGIN FAKE KEY-----\\nFAKEbootCHECKmarker0123456789\\n-----END FAKE KEY-----\n';

describe('--boot-check (trial boot only)', () => {
  let dir: string;
  let out: string[];
  const write = (l: string) => out.push(l);
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'boot-check-'));
    out = [];
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  function secret(body = FAKE, mode = 0o440): string {
    const p = join(dir, 'github-app-private-key');
    writeFileSync(p, body);
    chmodSync(p, mode);
    return p;
  }

  it('is selected only by exactly one CLI argument, the flag itself', () => {
    expect(BOOT_CHECK_FLAG).toBe('--boot-check');
    expect(isBootCheck(['--boot-check'])).toBe(true);
    expect(isBootCheck([])).toBe(false);
    expect(isBootCheck(['--boot-check', 'x'])).toBe(false);
    expect(isBootCheck(['--boot-check=1'])).toBe(false);
    expect(isBootCheck(['-boot-check'])).toBe(false);
  });

  it('the entrypoint reads the flag from argv only: no env var can switch it on', () => {
    const src = readFileSync(join(__dirname, '../src/index.ts'), 'utf8');
    expect(src).toMatch(/isBootCheck\(process\.argv\.slice\(2\)\)/);
    // Code only: comments may name what the module avoids.
    const mod = readFileSync(join(__dirname, '../src/boot-check.ts'), 'utf8')
      .replace(/\/\*[\s\S]*?\*\//g, '')
      .replace(/\/\/.*$/gm, '');
    expect(mod).not.toMatch(/process\.env/);
    expect(mod).not.toMatch(/listen|node:child_process|docker/i);
    // A normal start (no argv) never takes the boot-check path, whatever the env says.
    expect(isBootCheck([])).toBe(false);
  });

  it('ok: prints the exact ok line and exits 0', () => {
    const code = runBootCheck({ JOB_DISPATCH_TOKEN: 'fake-token', [KEY]: secret() }, write, dir);
    expect(code).toBe(0);
    expect(out).toEqual(['job env file INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY: ok']);
    expect(out.join('\n')).not.toContain('FAKEbootCHECK');
  });

  it('a missing file is a non-zero exit with the error line (no value)', () => {
    const code = runBootCheck({ JOB_DISPATCH_TOKEN: 'fake-token', [KEY]: join(dir, 'github-app-private-key') }, write, dir);
    expect(code).toBe(1);
    expect(out).toHaveLength(1);
    expect(out[0]).toMatch(/^job env file for INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY: /);
  });

  it('no JOB_ENVFILE key at all is a non-zero exit (a trial must exercise the key)', () => {
    expect(runBootCheck({ JOB_DISPATCH_TOKEN: 'fake-token' }, write, dir)).toBe(3);
    expect(out).toEqual(['boot check: no JOB_ENVFILE key configured']);
  });

  it('an ignored (not allow-listed) key is a non-zero exit even beside an ok line', () => {
    const env = { JOB_DISPATCH_TOKEN: 'fake-token', [KEY]: secret(), JOB_ENVFILE_SCAN__OTHER: join(dir, 'x') };
    expect(runBootCheck(env, write, dir)).toBe(1);
    expect(out).toContain('job env file INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY: ok');
    expect(out.some((l) => l.startsWith('job env file key ignored'))).toBe(true);
  });

  it('a config refusal prints the error name only and exits 2', () => {
    const code = runBootCheck({ [KEY]: secret() }, write, dir);
    expect(code).toBe(2);
    expect(out).toEqual(['boot check: config refused (Error)']);
  });
});
