/**
 * goodqa#16136 AC-16 / NEG-12..14: the create-guard's mode hold (GUARD_HELD_ENV).
 *
 * With `GUARD_HELD_ENV=TRANSCODER_MODE=transcribe` the guard refuses any
 * `/containers/create` whose Env would make the transcoder run its
 * transcription mode, and allows every other create unchanged. The worker's own
 * mode parse (`apps/transcoder/src/mode.ts`) is imported here and pinned to
 * the guard's matcher: every value the worker would treat as transcription is
 * refused by the guard (the guard refuses a strict superset).
 */
import { describe, expect, it } from 'vitest';
import { validateContainerCreateBody } from '../src/create-guard';
import { loadGuardProcessConfig } from '../src/create-guard-main';
import { heldEnvViolation, parseHeldEnv, type HeldEnv } from '../src/held-env';
import { transcoderMode } from '../../transcoder/src/mode';

const IMAGES = [
  'goodqa-scan@sha256:' + 'a'.repeat(64),
  'goodqa-transcode@sha256:' + 'b'.repeat(64),
];
const HOLD: HeldEnv = { key: 'TRANSCODER_MODE', value: 'transcribe' };
const REQUIRED_HOST_CONFIG = { CapDrop: ['ALL'], SecurityOpt: ['no-new-privileges'], ReadonlyRootfs: true };

function body(env: unknown, extra: Record<string, unknown> = {}) {
  return { Image: IMAGES[1], Cmd: ['att-1', 'run-1'], Env: env, Entrypoint: null, ...extra, HostConfig: REQUIRED_HOST_CONFIG };
}
function verdict(env: unknown, extra: Record<string, unknown> = {}, hold: HeldEnv | null = HOLD) {
  return validateContainerCreateBody(body(env, extra), IMAGES, hold);
}

describe('GUARD_HELD_ENV parse (startup)', () => {
  it('held-env unset is a no-op', () => {
    expect(parseHeldEnv(undefined)).toBeNull();
    expect(parseHeldEnv('')).toBeNull();
  });
  it('parses the one supported pair', () => {
    expect(parseHeldEnv('TRANSCODER_MODE=transcribe')).toEqual(HOLD);
  });
  it.each([
    ['no =', 'TRANSCODER_MODE'],
    ['unknown key', 'OTHER=transcribe'],
    ['unknown value', 'TRANSCODER_MODE=frames'],
    ['miscased value', 'TRANSCODER_MODE=Transcribe'],
    ['two pairs', 'TRANSCODER_MODE=transcribe,TRANSCODER_MODE=frames'],
    ['whitespace', ' TRANSCODER_MODE=transcribe'],
    ['empty value', 'TRANSCODER_MODE='],
    ['control char', 'TRANSCODER_MODE=transcribe\n'],
  ])('malformed held env refuses startup: %s', (_name, raw) => {
    expect(() => parseHeldEnv(raw)).toThrow(/GUARD_HELD_ENV/);
  });
  it('malformed held env refuses startup through the process config, naming the variable', () => {
    expect(() =>
      loadGuardProcessConfig({ JOB_IMAGE_SCAN: IMAGES[0], GUARD_HELD_ENV: 'TRANSCODER_MODE' } as NodeJS.ProcessEnv),
    ).toThrow(/GUARD_HELD_ENV/);
  });
  it('the process config carries the hold, and none when unset', () => {
    expect(loadGuardProcessConfig({ JOB_IMAGE_SCAN: IMAGES[0], GUARD_HELD_ENV: 'TRANSCODER_MODE=transcribe' } as NodeJS.ProcessEnv).heldEnv).toEqual(HOLD);
    expect(loadGuardProcessConfig({ JOB_IMAGE_SCAN: IMAGES[0] } as NodeJS.ProcessEnv).heldEnv).toBeNull();
  });
});

describe('NEG-12: every transcription variant is refused while transcribe is held', () => {
  it.each([
    ['exact', ['TRANSCODER_MODE=transcribe']],
    ['capitalised', ['TRANSCODER_MODE=Transcribe']],
    ['upper', ['TRANSCODER_MODE=TRANSCRIBE']],
    ['leading space', ['TRANSCODER_MODE= transcribe']],
    ['trailing space', ['TRANSCODER_MODE=transcribe ']],
    ['tab', ['TRANSCODER_MODE=\ttranscribe']],
    ['newline', ['TRANSCODER_MODE=transcribe\n']],
    ['NUL', ['TRANSCODER_MODE=transcribe\u0000']],
    ['control char in another value of the key', ['TRANSCODER_MODE=fra\u0007mes']],
    ['repeated, transcribe last', ['TRANSCODER_MODE=frames', 'TRANSCODER_MODE=transcribe']],
    ['repeated, transcribe first', ['TRANSCODER_MODE=transcribe', 'TRANSCODER_MODE=frames']],
    ['repeated, neither transcribe', ['TRANSCODER_MODE=frames', 'TRANSCODER_MODE=frames']],
    ['key miscased', ['transcoder_mode=transcribe']],
    ['key padded', [' TRANSCODER_MODE=transcribe']],
    ['key without =', ['TRANSCODER_MODE']],
    ['among other keys', ['ATTACHMENT_ID=a', 'TRANSCODER_MODE=transcribe', 'TRANSCRIPT_RUN_ID=r']],
  ])('refuses %s', (_name, env) => {
    const v = verdict(env);
    expect(v.ok).toBe(false);
    if (!v.ok) expect(v.reason).toMatch(/held/);
  });

  it.each([
    ['Env not an array', 'TRANSCODER_MODE=transcribe'],
    ['Env an object', { TRANSCODER_MODE: 'transcribe' }],
    ['Env with a non-string', ['ATTACHMENT_ID=a', 42]],
    ['Env with null', [null]],
  ])('D4: fails closed when %s', (_name, env) => {
    expect(verdict(env).ok).toBe(false);
  });

  it('D2: refuses an Entrypoint override while a hold is active', () => {
    expect(verdict(['ATTACHMENT_ID=a'], { Entrypoint: ['node', 'dist/transcribe.js'] }).ok).toBe(false);
    expect(verdict(['ATTACHMENT_ID=a'], { Entrypoint: [] }).ok).toBe(false);
    expect(verdict(['ATTACHMENT_ID=a'], { Entrypoint: 'sh' }).ok).toBe(false);
  });
});

describe('allowed while transcribe is held', () => {
  it.each([
    ['MP4 (no TRANSCODER_MODE)', ['ATTACHMENT_ID=a', 'TRANSCODE_RUN_ID=r']],
    ['frames', ['TRANSCODER_MODE=frames']],
    ['an unrelated key with the value transcribe', ['NOTE=transcribe']],
    ['a key that only contains the held name', ['XTRANSCODER_MODE=transcribe']],
    ['no Env at all', undefined],
    ['empty Env', []],
  ])('allows %s', (_name, env) => {
    expect(verdict(env)).toEqual({ ok: true });
  });
  it('allows MP4 with the args the API sends (Cmd is argv after the image ENTRYPOINT, not a mode switch)', () => {
    expect(verdict(['ATTACHMENT_ID=a'], { Cmd: ['att-1', 'run-1'] })).toEqual({ ok: true });
  });
});

describe('NEG-13: no hold means exactly today', () => {
  it.each([
    ['transcription', ['TRANSCODER_MODE=transcribe']],
    ['repeated key', ['TRANSCODER_MODE=frames', 'TRANSCODER_MODE=transcribe']],
  ])('allows %s with the hold off', (_name, env) => {
    expect(verdict(env, {}, null)).toEqual({ ok: true });
    expect(validateContainerCreateBody(body(env), IMAGES)).toEqual({ ok: true });
  });
  it('heldEnvViolation is null without a hold', () => {
    expect(heldEnvViolation({ Env: ['TRANSCODER_MODE=transcribe'], Entrypoint: ['sh'] }, null)).toBeNull();
  });
});

describe('the guard matcher is pinned to the worker mode parse', () => {
  const candidates = [
    'transcribe', 'Transcribe', 'TRANSCRIBE', ' transcribe', 'transcribe ', '\ttranscribe', 'transcribe\n', 'transcribe\r',
    'transcribe\u0000', 'trans cribe', 'transcribed', 'frames', 'Frames', 'transcode', '', 'x', 'transcribe=1',
  ];
  it.each(candidates.map((c) => [JSON.stringify(c), c]))('value %s: worker transcribes => guard refuses', (_n, value) => {
    const workerTranscribes = transcoderMode({ TRANSCODER_MODE: value }) === 'transcribe';
    const guardRefuses = !verdict([`TRANSCODER_MODE=${value}`]).ok;
    if (workerTranscribes) expect(guardRefuses).toBe(true);
  });
  it('the worker parse is the exact comparison the worker entrypoint uses', () => {
    expect(transcoderMode({ TRANSCODER_MODE: 'transcribe' })).toBe('transcribe');
    expect(transcoderMode({ TRANSCODER_MODE: 'frames' })).toBe('frames');
    expect(transcoderMode({ TRANSCODER_MODE: 'Transcribe' })).toBe('transcode');
    expect(transcoderMode({})).toBe('transcode');
  });
});

describe('the transcoder entrypoint reads its mode only through mode.ts', () => {
  it('index.ts has no direct TRANSCODER_MODE comparison left', async () => {
    const { readFileSync } = await import('node:fs');
    const src = readFileSync(new URL('../../transcoder/src/index.ts', import.meta.url), 'utf8');
    expect(src).not.toMatch(/process\.env\.TRANSCODER_MODE/);
    expect(src).toMatch(/transcoderMode\(process\.env\)/);
  });
});

describe('Cmd cannot select a mode while transcribe is held (lead ruling 1)', () => {
  it.each([
    ['--mode transcribe', ['--mode', 'transcribe']],
    ['--mode=transcribe', ['--mode=transcribe']],
    ['bare transcribe', ['transcribe']],
    ['TRANSCODER_MODE=transcribe as an argument', ['TRANSCODER_MODE=transcribe']],
  ])('the guard lets Cmd %s through, and the worker still runs MP4: the mode reads env only', (_n, cmd) => {
    expect(verdict(['ATTACHMENT_ID=a'], { Cmd: cmd })).toEqual({ ok: true });
    // transcoderMode() takes the environment only; argv has no path into it.
    expect(transcoderMode({ ATTACHMENT_ID: 'a' })).toBe('transcode');
  });

  it('the transcoder reads argv only as the attachment id and run id (argv[2], argv[3])', async () => {
    const { readdirSync, readFileSync } = await import('node:fs');
    const dir = new URL('../../transcoder/src/', import.meta.url);
    const uses: string[] = [];
    for (const name of readdirSync(dir)) {
      if (!name.endsWith('.ts') || name.includes('.test.')) continue;
      const src = readFileSync(new URL(name, dir), 'utf8');
      for (const m of src.matchAll(/process\.argv[^\n;)]{0,24}/g)) uses.push(`${name}: ${m[0]}`);
    }
    expect(uses.length).toBeGreaterThan(0);
    const other = uses.filter((u) => !/process\.argv\[[23]\]( \?\?|$)/.test(u.split(': ')[1] ?? ''));
    expect(other).toEqual([]);
  });
});
