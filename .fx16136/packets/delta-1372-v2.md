# PR review packet (delta only): PR #1372 receipt pr1372-v1 BLOCK fix, the residue threshold in UTF-8 bytes

Ticket: GoodQA goodqa#16185 (parent goodqa#16148). Source: main's exact-head receipt receipts/bugtracker-pr1372-v1.md, BLOCK.
- The finding: `apps/job-dispatcher/src/docker.ts` compared `value.length`, which counts UTF-16 code units, against the 8-byte MIN_WINDOW.
- So a secret under 8 code units but at least 8 UTF-8 bytes skipped the encoded-form checks, and its base64, hex or decimal-byte echo passed through in full.

Repo: ericmacdougall/bugtracker
Reviewed before: #1372 at c9d61ac1aa3a575781e5e5fc9430bee993be1e86
Expected HEAD: 80b26c7eeba20f9fa716fa7e2a8221d31f32cc31 (#1372, fast-forward on fix/16185-docker-failure-category)

Commits in this delta:
- 80b26c7eeba2 (#1372) fix(job-dispatcher): count the residue threshold in UTF-8 bytes

Also, outside this delta: #1373 (fix/16148-job-envfile) took it as merge commit 5dd6865c06499c30df6051d9ebf62a60e0ab294a.
- It is the parent 97bfac51 plus a merge of 80b26c7e, and it auto-merged with no conflict.
- Its #1373 suite at 5dd6865c: `npx vitest run` gives 375 passed and 14 skipped.

## Claims to verify
1. `byteLength(v)` is `Buffer.byteLength(v, 'utf8')`, and it is the only measure compared with MIN_WINDOW:
   - in `hasResidueIn`, so every value of at least 8 bytes gets every encoded-form window check;
   - in the whole-stderr redaction filter and its sort in `describeDockerFailure`.

   No `value.length` comparison against MIN_WINDOW remains.
2. A value under 8 bytes keeps the exact-token rule (NEG-17: short base values never shred a line), unchanged.
3. For a fake secret of 6 code units and 18 bytes, and one of 4 code units and 8 bytes, each echoed as base64, base64 at the other alignment, hex, HEX and decimal bytes in an allow-listed guard line, the message is exactly `docker run failed: guard_refused (stderr N bytes)`.
4. The same holds through the server's real 422 path (buildServer with the real dockerRunDetached): the body error is exactly the category and byte count. Neither the body nor any log line holds a 12-char piece of any encoded form.
5. Fail first: on c9d61ac1, 11 of the new cases fail. The leaked output was visible, for example `(got 56eY5a+G6Y215YCk5YWt5a2X)` in the 422 body. A broken variant that keeps the filter fix but puts the residue check back on `value.length` also fails those 11. No earlier test changed.

## Evidence (t2-dev)
At c9d61ac1 with only the new tests: `npx vitest run test/docker-failure-message.test.ts`: 11 failed, 41 passed (52).

At HEAD 80b26c7eeba20f9fa716fa7e2a8221d31f32cc31 (clean, 31G free):

```
$ cd apps/job-dispatcher && timeout 300 npx vitest run test/docker-failure-message.test.ts
      Tests  52 passed (52)
$ cd apps/job-dispatcher && timeout 600 npx vitest run
 Test Files  13 passed | 1 skipped (14)
      Tests  331 passed | 14 skipped (345)
$ cd apps/job-dispatcher && npx tsc --noEmit -p .
exit 0 (no output)
$ (broken variant: line 268 back to value.length) npx vitest run test/docker-failure-message.test.ts
      Tests  11 failed | 41 passed (52)
```

## Delta diff (c9d61ac1..80b26c7e)
```diff
diff --git a/apps/job-dispatcher/src/docker.ts b/apps/job-dispatcher/src/docker.ts
index 5a1feab52ab..bf59009634d 100644
--- a/apps/job-dispatcher/src/docker.ts
+++ b/apps/job-dispatcher/src/docker.ts
@@ -249,6 +249,11 @@ function valueForms(value: string): string[] {
   ];
 }
 
+/** The residue rule is in UTF-8 bytes (receipt pr1372-v1): a value of 6 CJK characters is 18 bytes, not 6. */
+function byteLength(value: string): number {
+  return Buffer.byteLength(value, 'utf8');
+}
+
 function escapeRegExp(s: string): string {
   return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
 }
@@ -260,7 +265,7 @@ function hasResidue(rawLine: string, values: readonly string[]): boolean {
 
 function hasResidueIn(line: string, values: readonly string[]): boolean {
   for (const value of values) {
-    if (value.length < MIN_WINDOW) {
+    if (byteLength(value) < MIN_WINDOW) {
       if (new RegExp(`(^|[^A-Za-z0-9])${escapeRegExp(value)}($|[^A-Za-z0-9])`).test(line)) return true;
       continue;
     }
@@ -290,7 +295,7 @@ export function describeDockerFailure(stderr: string, secretValues: readonly str
 
   const values = [...new Set(secretValues.filter((v) => v.length > 0))];
   let redacted = stderr;
-  for (const value of [...values].filter((v) => v.length >= MIN_WINDOW).sort((a, b) => b.length - a.length)) {
+  for (const value of [...values].filter((v) => byteLength(v) >= MIN_WINDOW).sort((a, b) => byteLength(b) - byteLength(a))) {
     redacted = redacted.split(value).join('[redacted]');
   }
   const line = (redacted.split('\n', 1)[0] ?? '').replace(/\r$/, '').trimEnd().slice(0, SCAN_LIMIT);
diff --git a/apps/job-dispatcher/test/docker-failure-message.test.ts b/apps/job-dispatcher/test/docker-failure-message.test.ts
index d7794682b50..59e82d7d95e 100644
--- a/apps/job-dispatcher/test/docker-failure-message.test.ts
+++ b/apps/job-dispatcher/test/docker-failure-message.test.ts
@@ -319,3 +319,65 @@ describe('F4 (code review goodqa#16148): a huge first line is cut before the res
     expect(msg).toContain('[redacted]');
   }, 30_000);
 });
+
+describe('receipt pr1372-v1 BLOCK: the 8-byte residue rule counts UTF-8 bytes, not UTF-16 code units', () => {
+  // Fake secrets only: short in code units, at least 8 bytes in UTF-8.
+  const CJK = '秘密鍵値六字'; // 6 code units, 18 bytes
+  const LATIN = 'éèêë'; // 4 code units, 8 bytes
+  const prefix = 'docker: Error response from daemon: job-dispatcher-create-guard: refused (';
+  const forms: Array<[string, (v: string) => string]> = [
+    ['base64', (v) => b64(v)],
+    ['base64, other alignment', (v) => b64(`x${v}`)],
+    ['hex', (v) => Buffer.from(v, 'utf8').toString('hex')],
+    ['HEX', (v) => Buffer.from(v, 'utf8').toString('hex').toUpperCase()],
+    ['decimal bytes', (v) => [...Buffer.from(v, 'utf8')].join(' ')],
+  ];
+  const cases = [CJK, LATIN].flatMap((v) => forms.map(([n, f]) => [`${v.length} units / ${Buffer.byteLength(v)} bytes, ${n}`, v, f(v)] as const));
+
+  it.each(cases)('%s: only the category and the byte count come out', (_name, value, echo) => {
+    const stderr = `${prefix}got ${echo})\n`;
+    expect(value.length).toBeLessThan(8);
+    expect(Buffer.byteLength(value, 'utf8')).toBeGreaterThanOrEqual(8);
+    expect(describeDockerFailure(stderr, [value])).toBe(
+      `docker run failed: guard_refused (stderr ${Buffer.byteLength(stderr, 'utf8')} bytes)`,
+    );
+  });
+
+  it('a value under 8 bytes keeps the exact-token rule (short base values never shred a line)', () => {
+    const msg = describeDockerFailure(`${prefix}Image must be one of the 1 pre-approved job images, got "abc")\n`, ['éé']);
+    expect(msg).toContain('got "abc")');
+  });
+
+  it('server: the 422 body for an encoded echo of a short-in-units secret is the category and byte count only', async () => {
+    clearExecutionsForTesting();
+    const TOKEN = 'shim-token-not-real';
+    const logs: string[] = [];
+    const app = buildServer({
+      ...loadConfig({
+        JOB_DISPATCH_TOKEN: TOKEN,
+        JOB_IMAGE_SCAN: 'ar/scan:tag',
+        JOB_IMAGE_TRANSCODE: 'ar/transcode:tag',
+        JOB_IMAGE_INTELLIGENCE_WORKER: 'ar/iw:tag',
+        JOB_IMAGE_SUGGEST_FIX_WORKER: 'ar/sf:tag',
+      }),
+      jobBaseEnv: { scan: {}, transcode: { GCS_BUCKET: CJK }, 'intelligence-worker': {}, 'suggest-fix-worker': {} },
+    }, { run: dockerRunDetached, inspect: vi.fn() } as never, { logStream: { write: (line: string) => logs.push(line) } });
+    app.addHook('onSend', async (_req, _reply, payload) => {
+      logs.push(String(payload));
+      return payload;
+    });
+    for (const [, f] of forms) {
+      const stderr = `${prefix}got ${f(CJK)})\n`;
+      respondFailure(stderr);
+      const res = await app.inject({ method: 'POST', url: '/jobs/transcode/run', headers: { authorization: `Bearer ${TOKEN}` }, payload: {} });
+      expect(res.statusCode).toBe(422);
+      expect((res.json() as { error: string }).error).toBe(
+        `docker run failed: guard_refused (stderr ${Buffer.byteLength(stderr, 'utf8')} bytes)`,
+      );
+      for (const [, g] of forms) {
+        expect(res.body).not.toContain(g(CJK).slice(0, 12));
+        for (const l of logs) expect(l).not.toContain(g(CJK).slice(0, 12));
+      }
+    }
+  });
+});
```
## Risks
- The threshold is now in bytes, so more values get window checks: any value of at least 8 UTF-8 bytes. A short non-ASCII base value (for example 3 CJK characters, 9 bytes) can now drop an allow-listed line to the category-only head. That fails closed: the message loses its line, never gains a value.
- The scan cost is unchanged in kind: SCAN_LIMIT 4096 still bounds the line (F4).
- Nothing is merged or deployed.
