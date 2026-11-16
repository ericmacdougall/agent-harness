# PR review packet (delta only): PR #1369 receipt pr1369-v2 BLOCK fix, the guard hold judged over HTTP

Ticket: GoodQA goodqa#16136. Source: main's exact-head receipt receipts/bugtracker-pr1369-v2.md, BLOCK.
The finding is a coverage gap: held-env.test.ts calls validateContainerCreateBody directly, so dropping `config.heldEnv` at `create-guard.ts:819` would disable the hold for real requests and stay green.

Repo: ericmacdougall/bugtracker
Reviewed before: #1369 at 3e478c28d57b (fix/16136-guard-held-env)
Expected HEAD: 11a85a026b43bfe21c02de3672f1b938fc5c826d (#1369, fast-forward)

Commits in this delta:
- 11a85a026b4 (#1369) test(job-dispatcher): judge the guard hold over HTTP from its own config

The change is a test only; no source changed. 1369 is not an ancestor of 1370, 1371 or the gate branch, so nothing else moves.

## Claims to verify
1. `test/held-env.http.test.ts` builds the guard exactly as the process does: `loadGuardProcessConfig(env)` with GUARD_UPSTREAM_HOST/PORT pointing at a loopback recording upstream, then `createGuardServer(config)`.
   - It runs once with GUARD_HELD_ENV=TRANSCODER_MODE=transcribe and once with it unset.
   - It asserts that `config.heldEnv` is set or null to match.
2. With the hold:
   - a transcription create gets 403, the body names the hold, and the upstream records no create;
   - an Entrypoint override gets 403 and no upstream create;
   - MP4 and frames creates get 201 with the upstream's own body, and the upstream receives exactly that Env.
3. Without the hold, a transcription create reaches upstream with TRANSCODER_MODE=transcribe intact (NEG-13).
4. Negative control: with line 819 passing `null` instead of `config.heldEnv ?? null`, the two held refusals fail. The existing held-env.test.ts stays green on that same broken source, which is the gap the receipt named. The source was restored afterwards with no diff.

## Evidence (t2-dev)
At HEAD 11a85a026b43bfe21c02de3672f1b938fc5c826d (31G free):

```
$ cd apps/job-dispatcher && timeout 300 npx vitest run test/held-env.http.test.ts
 ✓ test/held-env.http.test.ts (8 tests | 1 skipped)
      Tests  7 passed | 1 skipped (8)
$ (line 819: config.heldEnv ?? null -> null) npx vitest run test/held-env.http.test.ts test/held-env.test.ts
   × a transcription create is refused with 403 and never reaches upstream
   × an Entrypoint override is refused with 403 and never reaches upstream
      Tests  2 failed | 72 passed | 1 skipped (75)
$ cd apps/job-dispatcher && timeout 600 npx vitest run
 Test Files  14 passed | 1 skipped (15)
      Tests  353 passed | 15 skipped (368)
$ cd apps/job-dispatcher && npx tsc --noEmit -p .
exit 0
```

The skipped case is the Entrypoint one under "GUARD_HELD_ENV unset" (`it.runIf(held)`): without a hold an Entrypoint override is today's behaviour, and the other create-guard tests already cover it.

## Delta diff (3e478c28..11a85a02)
```diff
diff --git a/apps/job-dispatcher/test/held-env.http.test.ts b/apps/job-dispatcher/test/held-env.http.test.ts
new file mode 100644
index 00000000000..c7d7d272109
--- /dev/null
+++ b/apps/job-dispatcher/test/held-env.http.test.ts
@@ -0,0 +1,106 @@
+/**
+ * goodqa#16136 AC-16 / NEG-12, NEG-13 over REAL loopback HTTP (receipt pr1369-v2 BLOCK).
+ *
+ * held-env.test.ts calls validateContainerCreateBody directly, so it cannot see whether the
+ * running guard forwards its hold into that call. Here the real createGuardServer runs with the
+ * config the guard process itself loads (loadGuardProcessConfig, GUARD_HELD_ENV set or unset)
+ * in front of a recording upstream, and each create is judged by what the upstream received.
+ * Dropping `config.heldEnv` at the server's validate call fails this file.
+ */
+import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
+import type { AddressInfo } from 'node:net';
+import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
+import { createGuardServer } from '../src/create-guard';
+import { loadGuardProcessConfig } from '../src/create-guard-main';
+
+const SCAN = 'goodqa-scan@sha256:' + 'a'.repeat(64);
+const TRANSCODE = 'goodqa-transcode@sha256:' + 'b'.repeat(64);
+const HOST_CONFIG = { CapDrop: ['ALL'], SecurityOpt: ['no-new-privileges'], ReadonlyRootfs: true };
+
+interface Upstream { server: Server; port: number; creates: string[] }
+
+async function startUpstream(): Promise<Upstream> {
+  const creates: string[] = [];
+  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
+    const chunks: Buffer[] = [];
+    req.on('data', (c: Buffer) => chunks.push(c));
+    req.on('end', () => {
+      if (req.url === '/containers/create') creates.push(Buffer.concat(chunks).toString('utf8'));
+      res.writeHead(201, { 'content-type': 'application/json' }).end(JSON.stringify({ Id: 'upstream-created' }));
+    });
+  });
+  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
+  return { server, port: (server.address() as AddressInfo).port, creates };
+}
+
+async function startGuard(upstreamPort: number, held: string | undefined): Promise<{ server: Server; port: number }> {
+  const env: NodeJS.ProcessEnv = {
+    JOB_IMAGE_SCAN: SCAN,
+    JOB_IMAGE_TRANSCODE: TRANSCODE,
+    GUARD_UPSTREAM_HOST: '127.0.0.1',
+    GUARD_UPSTREAM_PORT: String(upstreamPort),
+  };
+  if (held !== undefined) env.GUARD_HELD_ENV = held;
+  const config = loadGuardProcessConfig(env);
+  expect(config.heldEnv === null).toBe(held === undefined);
+  const server = createGuardServer(config);
+  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
+  return { server, port: (server.address() as AddressInfo).port };
+}
+
+function create(port: number, body: Record<string, unknown>): Promise<Response> {
+  return fetch(`http://127.0.0.1:${port}/containers/create`, {
+    method: 'POST',
+    headers: { 'content-type': 'application/json' },
+    body: JSON.stringify({ Image: TRANSCODE, Cmd: ['att-1', 'run-1'], HostConfig: HOST_CONFIG, ...body }),
+  });
+}
+
+describe.each([
+  ['GUARD_HELD_ENV=TRANSCODER_MODE=transcribe', 'TRANSCODER_MODE=transcribe' as string | undefined],
+  ['GUARD_HELD_ENV unset', undefined],
+])('the running guard (%s), judged by what the upstream receives', (_name, held) => {
+  let upstream: Upstream;
+  let guard: { server: Server; port: number };
+  beforeAll(async () => {
+    upstream = await startUpstream();
+    guard = await startGuard(upstream.port, held);
+  });
+  afterEach(() => {
+    upstream.creates.length = 0;
+  });
+  afterAll(async () => {
+    await new Promise((resolve) => guard.server.close(resolve));
+    await new Promise((resolve) => upstream.server.close(resolve));
+  });
+
+  it(held ? 'a transcription create is refused with 403 and never reaches upstream' : 'a transcription create reaches upstream (no hold: exactly today)', async () => {
+    const res = await create(guard.port, { Env: ['ATTACHMENT_ID=a', 'TRANSCODER_MODE=transcribe'] });
+    if (held) {
+      expect(res.status).toBe(403);
+      expect(await res.text()).toMatch(/held/);
+      expect(upstream.creates).toEqual([]);
+    } else {
+      expect(res.status).toBe(201);
+      expect(upstream.creates).toHaveLength(1);
+      expect(JSON.parse(upstream.creates[0]!).Env).toContain('TRANSCODER_MODE=transcribe');
+    }
+  });
+
+  it.runIf(held)('an Entrypoint override is refused with 403 and never reaches upstream', async () => {
+    const res = await create(guard.port, { Env: ['ATTACHMENT_ID=a'], Entrypoint: ['node', 'dist/transcribe.js'] });
+    expect(res.status).toBe(403);
+    expect(upstream.creates).toEqual([]);
+  });
+
+  it.each([
+    ['MP4 (no TRANSCODER_MODE)', ['ATTACHMENT_ID=a', 'TRANSCODE_RUN_ID=r']],
+    ['frames', ['ATTACHMENT_ID=a', 'TRANSCODER_MODE=frames']],
+  ])('%s reaches upstream', async (_kind, env) => {
+    const res = await create(guard.port, { Env: env });
+    expect(res.status).toBe(201);
+    expect(await res.json()).toEqual({ Id: 'upstream-created' });
+    expect(upstream.creates).toHaveLength(1);
+    expect(JSON.parse(upstream.creates[0]!).Env).toEqual(env);
+  });
+});
```
## Risks
- Test-only. The fake upstream answers 201 to every create, so the test proves forwarding and refusal, not Docker's own behaviour. The real-guard Docker path is in create-guard.integration.docker.test.ts.
- Nothing is merged or deployed.
