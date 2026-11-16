# PR review packet: bugtracker guard mode hold (goodqa#16136 AC-16, NEG-12, NEG-13; D2-D5; lead ruling 1)

Ticket: GoodQA goodqa#16136
Repo: ericmacdougall/bugtracker, branch fix/16136-guard-held-env, draft PR #1369
Base: ed296b0a6b6fb4883abbd77adaa64e35f52c983d (origin/main)
Expected HEAD: 3e478c28d574c805b6fcd16235a4bdc3f84f3e12
Commits: fbea063b8964 (feat: guard hold + transcoder mode.ts), 3e478c28d574 (test: Cmd cannot select the mode)
Spec: v2.1, core 7d2a2622 (both reviews ACCEPT), attached to the ticket (comment 1ca3cf56)

## Scope
- apps/job-dispatcher/src/held-env.ts (new): parseHeldEnv and heldEnvViolation.
- apps/job-dispatcher/src/create-guard.ts: GuardConfig.heldEnv, checked after the image allowlist.
- apps/job-dispatcher/src/create-guard-main.ts: GUARD_HELD_ENV env and the startup line heldEnv=.
- apps/transcoder/src/mode.ts (new) and index.ts, which now uses transcoderMode(process.env).
- apps/job-dispatcher/test/held-env.test.ts (new).

## Claims to verify
1. With GUARD_HELD_ENV unset, behavior is unchanged (NEG-13). The existing create-guard and cli-schema suites are unchanged and pass.
2. While the hold is active, the guard refuses (NEG-12, D3, D4, D2):
   - any Env entry whose name is TRANSCODER_MODE after trim and upper-casing and whose value is transcribe after trim and lower-casing;
   - the key repeated;
   - the key without `=`;
   - NUL or control characters in its value;
   - an Env that is not an array of strings;
   - any non-null Entrypoint.
   Allowed: MP4 (no key), frames, an unrelated key, and Cmd.
3. The guard refuses a superset of what the worker treats as transcription. A table test imports transcoderMode() from the transcoder.
4. Cmd cannot select the mode (lead ruling 1). transcoderMode() reads only env.TRANSCODER_MODE. Every process.argv use in the transcoder sources is argv[2] or argv[3], the attachment and run ids. A broken index.ts variant that reads --mode=transcribe from argv fails the test.
5. A malformed GUARD_HELD_ENV refuses startup with a message that names GUARD_HELD_ENV. The release runner probes for exactly this.
6. D5: glibc getenv returns the FIRST duplicate. Refusing a repeated key makes the question moot.

Honest-path scope: this is not a boundary against a compromised dispatcher. The image allowlist and the HostConfig checks remain that boundary.

## Evidence (t2-dev, `df -h /`: 58G free)

```
$ cd apps/job-dispatcher && pnpm exec vitest run test/held-env.test.ts
 Test Files 1 passed (1)
 Tests 67 passed (67)
exit 0
```

```
$ pnpm exec vitest run --exclude "**/*.docker.test.ts" --exclude "**/*.e2e.*"
 Test Files 11 passed (11)
 Tests 328 passed (328)
exit 0
```

```
$ pnpm exec tsc --noEmit   (apps/job-dispatcher, then apps/transcoder)
tsc-jd exit 0; tsc-transcoder exit 0 (no output)
```

Failing first: the first run of held-env.test.ts, before held-env.ts existed, failed with "Cannot find module '../src/held-env'". That line in the earlier run log is this failing-first run, not the final run.

Broken variants: `bash mutate.sh` on t2-dev applies each mutation to held-env.ts, runs held-env.test.ts, then restores the file. Each variant fails:

| Variant | Result |
|---|---|
| no value normalization | 4 failed |
| no key normalization | 2 failed |
| no repeat refusal | 1 failed |
| no control-char refusal | 2 failed |
| no array check | 2 failed |
| no Entrypoint refusal | 1 failed |
| hold ignored | 22 failed |

Argv variant (index.ts takes the mode from --mode=transcribe): 1 failed, 66 passed. Restored: 67 passed.

Real built images on t2-dev, running the exact rw-ship probe command:

| Image | Probe result | Startup line |
|---|---|---|
| guard built from fbea063 | rc=1, "GUARD_HELD_ENV must be empty or exactly one of TRANSCODER_MODE=transcribe; refusing to start with "TRANSCODER_MODE"." | heldEnv=TRANSCODER_MODE=transcribe, or heldEnv=none when unset |
| guard built from main ed296b0a6b6f | keeps listening until timeout, rc=124 | (none) |

## Coupling (AC-17)
This ships in the same production release as the bugtracker release-harness fix (fix/16136-job-images-rh, tag release-16136-rh at c6b303aee61c). That runner holds the whole transcode image unless the probe proves the hold, so transcription never launches unheld in between.

## Risks
- Cmd is allowed by design. The image ENTRYPOINT is `pnpm start` = `tsx src/index.ts`, and argv goes to index.ts only as ids.
- The docker integration tests (*.docker.test.ts) were not run. They need a Docker-in-test setup, and they do not cover this change.
