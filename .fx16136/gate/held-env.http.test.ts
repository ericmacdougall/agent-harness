/**
 * goodqa#16136 AC-16 / NEG-12, NEG-13 over REAL loopback HTTP (receipt pr1369-v2 BLOCK).
 *
 * held-env.test.ts calls validateContainerCreateBody directly, so it cannot see whether the
 * running guard forwards its hold into that call. Here the real createGuardServer runs with the
 * config the guard process itself loads (loadGuardProcessConfig, GUARD_HELD_ENV set or unset)
 * in front of a recording upstream, and each create is judged by what the upstream received.
 * Dropping `config.heldEnv` at the server's validate call fails this file.
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { createGuardServer } from '../src/create-guard';
import { loadGuardProcessConfig } from '../src/create-guard-main';

const SCAN = 'goodqa-scan@sha256:' + 'a'.repeat(64);
const TRANSCODE = 'goodqa-transcode@sha256:' + 'b'.repeat(64);
const HOST_CONFIG = { CapDrop: ['ALL'], SecurityOpt: ['no-new-privileges'], ReadonlyRootfs: true };

interface Upstream { server: Server; port: number; creates: string[] }

async function startUpstream(): Promise<Upstream> {
  const creates: string[] = [];
  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      if (req.url === '/containers/create') creates.push(Buffer.concat(chunks).toString('utf8'));
      res.writeHead(201, { 'content-type': 'application/json' }).end(JSON.stringify({ Id: 'upstream-created' }));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  return { server, port: (server.address() as AddressInfo).port, creates };
}

async function startGuard(upstreamPort: number, held: string | undefined): Promise<{ server: Server; port: number }> {
  const env: NodeJS.ProcessEnv = {
    JOB_IMAGE_SCAN: SCAN,
    JOB_IMAGE_TRANSCODE: TRANSCODE,
    GUARD_UPSTREAM_HOST: '127.0.0.1',
    GUARD_UPSTREAM_PORT: String(upstreamPort),
  };
  if (held !== undefined) env.GUARD_HELD_ENV = held;
  const config = loadGuardProcessConfig(env);
  expect(config.heldEnv === null).toBe(held === undefined);
  const server = createGuardServer(config);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  return { server, port: (server.address() as AddressInfo).port };
}

function create(port: number, body: Record<string, unknown>): Promise<Response> {
  return fetch(`http://127.0.0.1:${port}/containers/create`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ Image: TRANSCODE, Cmd: ['att-1', 'run-1'], HostConfig: HOST_CONFIG, ...body }),
  });
}

describe.each([
  ['GUARD_HELD_ENV=TRANSCODER_MODE=transcribe', 'TRANSCODER_MODE=transcribe' as string | undefined],
  ['GUARD_HELD_ENV unset', undefined],
])('the running guard (%s), judged by what the upstream receives', (_name, held) => {
  let upstream: Upstream;
  let guard: { server: Server; port: number };
  beforeAll(async () => {
    upstream = await startUpstream();
    guard = await startGuard(upstream.port, held);
  });
  afterEach(() => {
    upstream.creates.length = 0;
  });
  afterAll(async () => {
    await new Promise((resolve) => guard.server.close(resolve));
    await new Promise((resolve) => upstream.server.close(resolve));
  });

  it(held ? 'a transcription create is refused with 403 and never reaches upstream' : 'a transcription create reaches upstream (no hold: exactly today)', async () => {
    const res = await create(guard.port, { Env: ['ATTACHMENT_ID=a', 'TRANSCODER_MODE=transcribe'] });
    if (held) {
      expect(res.status).toBe(403);
      expect(await res.text()).toMatch(/held/);
      expect(upstream.creates).toEqual([]);
    } else {
      expect(res.status).toBe(201);
      expect(upstream.creates).toHaveLength(1);
      expect(JSON.parse(upstream.creates[0]!).Env).toContain('TRANSCODER_MODE=transcribe');
    }
  });

  it.runIf(held)('an Entrypoint override is refused with 403 and never reaches upstream', async () => {
    const res = await create(guard.port, { Env: ['ATTACHMENT_ID=a'], Entrypoint: ['node', 'dist/transcribe.js'] });
    expect(res.status).toBe(403);
    expect(upstream.creates).toEqual([]);
  });

  it.each([
    ['MP4 (no TRANSCODER_MODE)', ['ATTACHMENT_ID=a', 'TRANSCODE_RUN_ID=r']],
    ['frames', ['ATTACHMENT_ID=a', 'TRANSCODER_MODE=frames']],
  ])('%s reaches upstream', async (_kind, env) => {
    const res = await create(guard.port, { Env: env });
    expect(res.status).toBe(201);
    expect(await res.json()).toEqual({ Id: 'upstream-created' });
    expect(upstream.creates).toHaveLength(1);
    expect(JSON.parse(upstream.creates[0]!).Env).toEqual(env);
  });
});
