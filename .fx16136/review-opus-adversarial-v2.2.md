# Adversarial delta review: goodqa#16136 spec v2.2 (delta only)

Reviewer: agent:a5a2642f07434bbc9 (claude-opus-5-5), adversarial role
Date: 2026-11-15

Inputs (verified):
- `v2.1-to-v2.2.diff`, sha256 `bd7e9b8c2e5c990d411c649cf74d39393701e9e08666ca70f988a29f3e20a8e8`
- `spec-16136-v2.2.frozen.md`, sha256 `c14b9ab87bd3091fe065327e3f1541cb19d62d7ad3d211f82e0a6024c1ca04bb`
- the author's live `.fx16136/spec-16136-v2.md`, same sha256 before recording

Location note: the worktree-isolation guard refuses paths outside this worktree, so the report sits in the author's untracked `.fx16136/`, as in earlier rounds.

Code read (read-only, t2-dev, bugtracker 618b289d):
- `apps/job-dispatcher/src/server.ts`, lines 105-118
- `apps/job-dispatcher/src/config.ts`, lines 124-128
- `apps/job-dispatcher/src/create-guard-main.ts`, lines 68-90
- `apps/api/src/lib/job-dispatch.ts`, lines 95-118 (`dispositionForShimHttpStatus`)
- `packages/db/src/intelligence-jobs.ts`, lines 436-474
- `apps/api/src/modules/intelligence/dispatch.ts:57`

No production access. No probes.

## Verdict: ACCEPT (recorded against core ddce2e82), with build notes E1 to E4

The empty-value hold is a real launch block, and it cannot start a container or break either process's startup. Its retry behaviour is the same as today's 422 path.

## 1. Can an empty value start a container or break startup?

No.

**Dispatcher.**
- `server.ts:112-117` returns 501 when `config.jobImages[kind]` is falsy, before admission control and before any docker invocation. A held kind therefore never takes a concurrency slot or reaches docker.
- The production digest check (`config.ts:126`) filters with `jobImages[kind] && …`, so `""` is skipped and startup is unaffected.

**Guard.**
- `create-guard-main.ts` filters the allowlist with `ref.length > 0`, so `""` is not an allowlisted image. A create with `Image: ""` fails the guard's `allowedImages.includes`.
- The production digest check runs only over the filtered list.
- The empty-allowlist refusal (line 81) cannot trigger: only intelligence and transcode are holdable, and scan and suggest-fix are always pinned.
- Edge: a whitespace-only value such as `" "` would survive the length filter and make the guard refuse to start, failing closed. selfhost-ctl writes exactly `""`, so the risk is only a hand edit, which is acceptable.

**Compose.**
- `KEY: "" # held` resolves to the empty string on both services through the anchor. AC-20's real-compose test covers this.

## 2. 501 retry behaviour

`job-dispatch.ts`: `dispositionForShimHttpStatus` maps 400, 401, 403, 422 and 501 alike to `definitive_not_started`. So 501 takes exactly the code path today's 422 takes:
- `intelligence-jobs.ts` restores attempts (`Math.max(0, attempts - 1)`), re-queues the job and sets a fixed 60-second `availableAt`.
- The cron dispatches at most 10 per tick.

There is no tight loop and no attempt burn. The backlog analysis from my v2 review holds unchanged. AC-20's citation is accurate.

Transcription is marked failed once per launch, as today.

## 3. Unhold and rollback

**Unhold.** Unholding is a release that builds, loads and pins a fresh `goodqa-JOB@sha256:` ref, so no older image can be revived. Correct.

**Rollback from a release that has this fix.** It restores the previous compose, whose held line is `""`, so a rollback stays held. Correct, and stated.

**Residual (E1).** A rollback of the first release restores the pre-fix compose with the DigitalOcean (DO) refs. That compose is not a launch block: it relies on those DO images being absent from the host, the property main ruled a hold must not rely on. With IMAGES=0 they cannot be pulled, so a launch would need a DO image already on the host. That is unlikely, and unverified.

## 4. Whole-transcode hold (AC-17) and MP4

It is stated in AC-17 ("So MP4 waits"). In that branch the transcode line is `""`: MP4 also gets 501 and is marked failed, which is exactly today's user-visible state.

The consequences for the transcode acceptance criteria are not stated (E2).

## Build notes

- **E1.** Before the first deploy, record a read-only `docker image inspect` of the four DO refs on the app host, showing that none resolves. That makes the first-release rollback a launch block in fact. If one does resolve, say so in the deploy note and treat that rollback as unheld for that kind.
- **E2.** If AC-17's whole-transcode hold fires, AC-11 and AC-12 for transcode cannot pass, and AC-13's floor of at least one transcode 2xx would read as a failure. State that, in that branch, transcode is `TARGET_MISMATCH` (held: guard lacks GUARD_HELD_ENV), goodqa#16136 stays open for transcode, and AC-13's floor excludes it.
- **E3.** AC-13 was not updated for v2.2. Held-by-empty kinds now show 501, not 422. The held intelligence route will log 501s; only guard-refused transcription stays 422. Update the matcher and labels so held 501s are counted and labelled, and excluded from the zero-422 count.
- **E4.** The selfhost-ctl reads that parse the existing job lines (`state.jobs`, the presence check, the AC-7 post-switch check, the `restore` warning) must accept `""` only together with the `# held` marker. A bare `""` without the marker, or `""` on a non-holdable key (scan, suggest-fix), must refuse or be reported as missing. Add a test.

## Not examined

- the selfhost-ctl and rw-ship implementation of the empty write (read only as spec)
- whether any DO job image exists on the production host (E1)
- production
