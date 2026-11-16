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
