/**
 * goodqa#16185 (goodqa#16148 spec v4 AC-7, NEG-5, NEG-11, NEG-17; build conditions P1 and R5).
 *
 * A failed `docker run` must never put a job env value into the 422 body, the dispatcher log or
 * anything the API stores. The message is `docker run failed: CATEGORY (stderr N bytes)`, plus at
 * most one allow-listed first line. A held refusal's line is rebuilt from constants, so the hold
 * reason survives exactly (goodqa#16136 AC-13 pairs on it). Only values from a secret source (the
 * dispatcher's base env for the kind) are redacted; the caller's allow-listed request env is not.
 *
 * Stderr strings marked REAL were captured from the real docker CLI through the real create-guard
 * on t2-dev (goodqa#16148 WAL w276c9ce4c41).
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const execFileMock = vi.fn();
vi.mock('node:child_process', () => ({
  execFile: (...args: unknown[]) => execFileMock(...args),
}));

const { dockerRunDetached, describeDockerFailure, DockerLaunchError, NO_HARDENING } = await import('../src/docker');
const { buildServer } = await import('../src/server');
const { loadConfig } = await import('../src/config');
const { clearExecutionsForTesting } = await import('../src/executions');

type Callback = (error: Error | null, stdout?: string, stderr?: string) => void;

/** A fake secret: an alphanumeric marker of 40 characters. Never a real value. */
const MARKER = 'FAKEsecretMARKER0123456789abcdefghijKLMN';
const HELD_TAG = 'TRANSCODER_MODE=transcribe is held on this guard';
const REAL_HELD =
  'docker: Error response from daemon: job-dispatcher-create-guard: refused (create refused: TRANSCODER_MODE=transcribe is held on this guard)\n\nRun \'docker run --help\' for more information\n';
const REAL_NOT_ALLOWLISTED =
  'docker: Error response from daemon: job-dispatcher-create-guard: refused (Image must be one of the 1 pre-approved job images, got "busybox:1.36")\n\nRun \'docker run --help\' for more information\n';
const REAL_BAD_REF =
  "docker: invalid reference format: repository name (library/Not_A) must be lowercase\n\nRun 'docker run --help' for more information\n";
const REAL_NO_DAEMON = 'Cannot connect to the Docker daemon at tcp://127.0.0.1:1. Is the docker daemon running?\n';

function b64(s: string): string {
  return Buffer.from(s, 'utf8').toString('base64');
}

/** Every form of a value that must never appear, as substrings of at least `win` characters. */
function forbiddenForms(value: string): string[] {
  const forms = [
    value,
    b64(value),
    b64(`x${value}`).slice(2),
    b64(`xx${value}`).slice(3),
    Buffer.from(value).toString('hex'),
    Buffer.from(value).toString('hex').toUpperCase(),
    JSON.stringify(value).slice(1, -1),
    [...Buffer.from(value)].join(' '),
  ];
  return forms;
}

function assertNoValue(text: string, value: string, win = 16): void {
  for (const form of forbiddenForms(value)) {
    for (let i = 0; i + win <= form.length; i += 1) {
      const piece = form.slice(i, i + win);
      expect(text.includes(piece), `leaked ${win}-char window of a form of the value: ${JSON.stringify(piece)}`).toBe(false);
    }
  }
}

function respondFailure(stderr: string, extra: Record<string, unknown> = {}) {
  execFileMock.mockImplementationOnce((_file: string, args: string[], _opts: unknown, cb: Callback) => {
    const error = Object.assign(new Error(`Command failed: docker ${args.join(' ')}\n${stderr}`), {
      code: 125,
      cmd: `docker ${args.join(' ')}`,
      stderr,
      ...extra,
    });
    cb(error, '', stderr);
  });
}

async function failureMessage(stderr: string, env: Record<string, string>, secretValues: string[], extra = {}) {
  respondFailure(stderr, extra);
  try {
    await dockerRunDetached('docker', 'goodqa-transcode@sha256:' + 'a'.repeat(64), [], env, 5000, NO_HARDENING, secretValues);
  } catch (error) {
    expect(error).toBeInstanceOf(DockerLaunchError);
    return (error as Error).message;
  }
  throw new Error('expected a rejection');
}

afterEach(() => {
  execFileMock.mockReset();
});

describe('describeDockerFailure: fixed category and byte count', () => {
  it.each([
    ['guard_refused', REAL_NOT_ALLOWLISTED],
    ['guard_refused', REAL_HELD],
    ['invalid_reference', REAL_BAD_REF],
    ['daemon_unreachable', REAL_NO_DAEMON],
    ['daemon_unreachable', 'Got permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock'],
    ['image_not_found', "Unable to find image 'goodqa-scan:missing' locally\ndocker: Error response from daemon: pull access denied for goodqa-scan\n"],
    ['other', 'some future docker error this shim has never seen'],
    ['other', ''],
  ])('classifies as %s', (category, stderr) => {
    const msg = describeDockerFailure(stderr, []);
    expect(msg.startsWith(`docker run failed: ${category} (stderr ${Buffer.byteLength(stderr)} bytes)`)).toBe(true);
  });

  it('REAL held refusal: the line is the exact constant text, so HELD_TAG survives', () => {
    const msg = describeDockerFailure(REAL_HELD, []);
    expect(msg).toBe(
      `docker run failed: guard_refused (stderr ${Buffer.byteLength(REAL_HELD)} bytes): ` +
        'docker: Error response from daemon: job-dispatcher-create-guard: refused (create refused: TRANSCODER_MODE=transcribe is held on this guard)',
    );
    expect(msg).toContain(HELD_TAG);
    // The API keeps the first 300 chars of the 422 body (job-dispatch.ts); the tag must sit inside them.
    expect(JSON.stringify({ error: msg, started: false }).slice(0, 300)).toContain(HELD_TAG);
  });

  it.each([
    'Entrypoint overrides are refused while',
    'TRANSCODER_MODE without a value is refused while',
    'TRANSCODER_MODE with control characters is refused while',
    'TRANSCODER_MODE repeated in Env is refused while',
  ])('every held-guard reason form is rebuilt from constants: %s', (lead) => {
    const stderr = `docker: Error response from daemon: job-dispatcher-create-guard: refused (${lead} ${HELD_TAG})\n`;
    expect(describeDockerFailure(stderr, [])).toContain(`(${lead} ${HELD_TAG})`);
  });

  it('a line that only looks like a held refusal (an unknown reason before the tag) is not trusted as constant text', () => {
    const stderr = `docker: Error response from daemon: job-dispatcher-create-guard: refused (${MARKER} while ${HELD_TAG})\n`;
    const msg = describeDockerFailure(stderr, [MARKER]);
    assertNoValue(msg, MARKER);
  });

  it('NEG-17 / R5: short base values never shred the held line (1, true, on, this, guard, daemon, europe-west1)', () => {
    const shorts = ['1', 'true', 'on', 'this', 'guard', 'daemon', 'europe-west1', 'held', 'e'];
    const msg = describeDockerFailure(REAL_HELD, shorts);
    expect(msg).toContain(`(create refused: ${HELD_TAG})`);
  });

  it('a non-allow-listed first line is never appended', () => {
    const stderr = `panic: ${MARKER}\n`;
    const msg = describeDockerFailure(stderr, []);
    expect(msg).toBe(`docker run failed: other (stderr ${Buffer.byteLength(stderr)} bytes)`);
  });

  it('an allow-listed line is cut to 200 characters', () => {
    const stderr = `Unable to find image '${'x'.repeat(400)}' locally\n`;
    const msg = describeDockerFailure(stderr, []);
    const line = msg.slice(msg.indexOf('): ') + 3);
    expect(line.length).toBeLessThanOrEqual(200);
    expect(line.startsWith("Unable to find image 'xxx")).toBe(true);
  });

  it('REAL bad reference line is kept (after the docker: prefix) when it holds no value', () => {
    const msg = describeDockerFailure(REAL_BAD_REF, ['some-other-secret-value']);
    expect(msg).toContain('): docker: invalid reference format: repository name (library/Not_A) must be lowercase');
  });
});

describe('AC-7 / NEG-11: no secret-source value in any form survives', () => {
  const prefix = 'docker: Error response from daemon: job-dispatcher-create-guard: refused (';
  const cases: Array<[string, string]> = [
    ['plain echo', `${prefix}Env ${MARKER} not allowed)\n`],
    ['argv echo', `${prefix}bad) docker run -e API_KEY=${MARKER} img\n`],
    ['env-file content echo', `Unable to find image 'img' locally\nAPI_KEY=${MARKER}\n`],
    ['invalid UTF-8 byte list', `${prefix}${[...Buffer.from(MARKER)].join(' ')})\n`],
    ['JSON-escaped', `${prefix}${JSON.stringify(`k=${MARKER}\n`)})\n`],
    ['backslash-escaped', `${prefix}${MARKER.split('').join('\\')})\n`],
    ['base64 echo', `${prefix}${b64(MARKER)})\n`],
    ['base64 echo, other alignment', `${prefix}${b64(`x${MARKER}`)})\n`],
    ['hex echo', `${prefix}${Buffer.from(MARKER).toString('hex')})\n`],
    ['straddles the 200-char cut', `${prefix}${'y'.repeat(200 - prefix.length - 10)}${MARKER})\n`],
    ['part of the value', `${prefix}${MARKER.slice(5, 30)})\n`],
    ['non-ASCII around the value', `${prefix}\u00e9${MARKER.slice(0, 20)}\u00e9)\n`],
  ];

  it.each(cases)('%s', async (_name, stderr) => {
    const msg = await failureMessage(stderr, { API_KEY: MARKER }, [MARKER]);
    expect(msg.startsWith('docker run failed: ')).toBe(true);
    assertNoValue(msg, MARKER, 16);
    // The 8-byte residue rule: not even an 8-char window of the raw value.
    const unescaped = msg.replace(/\\/g, '');
    for (let i = 0; i + 8 <= MARKER.length; i += 1) {
      expect(msg).not.toContain(MARKER.slice(i, i + 8));
      expect(unescaped).not.toContain(MARKER.slice(i, i + 8));
    }
  });

  it('never forwards err.message or err.cmd (they hold the full argv)', async () => {
    const msg = await failureMessage('', { API_KEY: MARKER }, [MARKER], { code: 1 });
    expect(msg).toBe('docker run failed: other (stderr 0 bytes)');
  });

  it('a maxBuffer overflow or timeout message carries no value', async () => {
    execFileMock.mockImplementationOnce((_f: string, args: string[], _o: unknown, cb: Callback) => {
      cb(Object.assign(new Error(`stdout maxBuffer length exceeded ${args.join(' ')}`), { killed: true, signal: 'SIGTERM', code: 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER' }), '', '');
    });
    let msg = '';
    try {
      await dockerRunDetached('docker', 'img', [], { API_KEY: MARKER }, 5000, NO_HARDENING, [MARKER]);
    } catch (error) {
      msg = (error as Error).message;
    }
    expect(msg).not.toBe('');
    assertNoValue(msg, MARKER, 8);
  });

  it('defaults to treating every env value as secret when no secret list is given', async () => {
    respondFailure(`${prefix}${MARKER})\n`);
    let msg = '';
    try {
      await dockerRunDetached('docker', 'img', [], { API_KEY: MARKER }, 5000, NO_HARDENING);
    } catch (error) {
      msg = (error as Error).message;
    }
    assertNoValue(msg, MARKER, 8);
  });

  it('P1: an allow-listed request value (not a secret source) is not redacted', () => {
    const stderr = `${prefix}Image must be one of the 1 pre-approved job images, got "lease-owner-abc-123")\n`;
    const msg = describeDockerFailure(stderr, []);
    expect(msg).toContain('got "lease-owner-abc-123"');
  });
});

describe('server: the 422 body and log carry the category only (end to end with the real dockerRunDetached)', () => {
  const TOKEN = 'shim-token-not-real';
  beforeEach(() => clearExecutionsForTesting());

  function config() {
    return {
      ...loadConfig({
        JOB_DISPATCH_TOKEN: TOKEN,
        JOB_IMAGE_SCAN: 'ar/scan:tag',
        JOB_IMAGE_TRANSCODE: 'ar/transcode:tag',
        JOB_IMAGE_INTELLIGENCE_WORKER: 'ar/iw:tag',
        JOB_IMAGE_SUGGEST_FIX_WORKER: 'ar/sf:tag',
      }),
      jobBaseEnv: {
        scan: {},
        transcode: { GCS_BUCKET: MARKER, SHORT_FLAG: '1', REGION: 'europe-west1' },
        'intelligence-worker': {},
        'suggest-fix-worker': {},
      },
    };
  }

  it('a held transcribe refusal: 422 with the exact held text, no base value', async () => {
    const logs: string[] = [];
    const app = buildServer(config(), {
      run: dockerRunDetached,
      inspect: vi.fn(),
    } as never, { logStream: { write: (line: string) => logs.push(line) } });
    app.addHook('onSend', async (_req, _reply, payload) => {
      logs.push(String(payload));
      return payload;
    });
    respondFailure(REAL_HELD.replace('\n\n', `\n${MARKER}\n`));
    const res = await app.inject({
      method: 'POST',
      url: '/jobs/transcode/run',
      headers: { authorization: `Bearer ${TOKEN}` },
      payload: { env: { TRANSCODER_MODE: 'transcribe' } },
    });
    expect(res.statusCode).toBe(422);
    const body = res.json() as { error: string; started: boolean };
    expect(body.started).toBe(false);
    expect(body.error).toContain(`(create refused: ${HELD_TAG})`);
    expect(body.error.startsWith('docker run failed: guard_refused (stderr ')).toBe(true);
    assertNoValue(res.body, MARKER, 8);
    for (const l of logs) assertNoValue(l, MARKER, 8);
  });

  it('an unexpected (non-docker) error logs the error name only', async () => {
    const lines: string[] = [];
    const app = buildServer(config(), {
      run: vi.fn().mockRejectedValue(Object.assign(new TypeError(`boom ${MARKER}`), { cmd: `docker -e K=${MARKER}` })),
      inspect: vi.fn(),
    } as never, { logStream: { write: (s: string) => lines.push(s) } } as never);
    const res = await app.inject({ method: 'POST', url: '/jobs/transcode/run', headers: { authorization: `Bearer ${TOKEN}` }, payload: {} });
    expect(res.statusCode).toBe(500);
    assertNoValue(res.body, MARKER, 8);
    for (const l of lines) assertNoValue(l, MARKER, 8);
  });
});
