# Adversarial delta review: goodqa#16136 spec v2.1 (delta only)

Reviewer: agent:a5a2642f07434bbc9 (claude-opus-5-5), adversarial role
Date: 2026-11-15

Inputs (verified):
- `v2-to-v2.1.diff`, sha256 `c3ee2ac5cfcf645d6207aa77c59ac47ee772083a62cac0740ee65e682528dbde`
- `spec-16136-v2.1.frozen.md`, sha256 `b8f3fa161911aedc58977f80e92c9e9e61c6d27c2b8077ccf0ba8b449278f511`
- the author's live `.fx16136/spec-16136-v2.md`, same sha256 as the frozen copy

Location note: the worktree-isolation guard refused both the requested `review-16136/` path and my own agent folder, because both lie outside this worktree. The report sits in the author's untracked `.fx16136/`.

Code read (read-only, t2-dev, bugtracker origin/main ed296b0a6b6):
- `apps/transcoder/src/index.ts`, lines 470-496
- `apps/transcoder/package.json` and `apps/transcoder/Dockerfile`
- `apps/job-dispatcher/src/create-guard.ts`: the top-level key allowlist and its Env and Entrypoint handling
- `apps/job-dispatcher/src/jobs.ts`: the per-kind env allowlist
- `apps/job-dispatcher/src/server.ts:149`: the env merge
- `apps/api/src/modules/recordings/routes.ts`, lines 176-240: the transcribe spawner and its launch-failure handling

No production access. No probes.

## Verdict: ACCEPT (recorded), with build notes D1 to D5 (D1 is a must-do)

On the honest path, no create can launch transcription past the AC-16 hold. The superset refuses nothing legitimate.

AC-17's detection method is unspecified. A string search would pass its pytest yet fail open, so D1 constrains it. If an AC-17 false positive did let a transcription container start, it would still fail closed on the missing GCP_PROJECT, which is today's user-visible state. That bounds the harm, so D1 is a build-time must-do rather than a spec block.

## Attack 1: can a create still launch transcribe?

The worker selects the mode only through `process.env.TRANSCODER_MODE === 'transcribe'` (index.ts:475). The image sets no TRANSCODER_MODE (the Dockerfile ENV lines are NODE_ENV and ICU only). The entrypoint is `pnpm start`, which runs `tsx src/index.ts`, and the arguments are only `attachmentId` and `runId` (lines 495-496).

**Env ordering.** On the honest path a duplicate is impossible. `server.ts:149` merges base and request env as object spreads (`{...base, ...request}`), so each key appears at most once in the docker run. `jobs.ts:25` allows TRANSCODER_MODE as the only request env key for transcode.

A raw body with duplicates is refused by the repeated-key rule, whichever order the entries come in. That matters, because the spec's "the last Env entry wins" premise is not something to rely on: glibc `getenv` returns the first match. The rule makes the control order-independent, which is the right design.

**Empty value.** `TRANSCODER_MODE=` and a bare `TRANSCODER_MODE` both mean MP4 mode in the worker. Allowing them is correct.

**A key with whitespace or a different case.** ` TRANSCODER_MODE=transcribe`, `TRANSCODER_MODE =...` and `transcoder_mode=...` are different variables on Linux, and the worker never reads them. Matching the key exactly is correct. Trimming the key as well would only refuse more.

**The API sending the mode another way.** Two routes exist:
- `routes.ts:212` sends `env: { TRANSCODER_MODE: 'transcribe' }`.
- The API's frames route sends `frames`.

Neither has another channel. A guard refusal reaches `onLaunchFailed`, so the transcript fails as it does today, and the MP4 status is untouched.

**Routes that bypass the Env check.** `create-guard.ts:323-324` allows `Entrypoint` and `Cmd` with no content check. A body whose Entrypoint is `["sh","-c","TRANSCODER_MODE=transcribe exec pnpm start"]` carries no held Env entry and would run transcription. The honest dispatcher never sets Entrypoint (`docker run` without `--entrypoint`), and its positional arguments cannot set env through `pnpm start` and `tsx`.

So the hold is an honest-path policy control, not a boundary against a compromised dispatcher. A compromised dispatcher can already run arbitrary commands inside allowlisted images. See D2.

**NUL and control characters.** This is a hypothesis. A value such as `transcribe\u0000x` escapes the trimmed and lower-cased match. If the runtime truncated at the NUL, the process would see exactly `transcribe`. Go's exec path most likely rejects NUL with EINVAL, and the dispatcher's `hasControlChars` stops it on the honest path. See D3.

## Attack 2: does the superset refuse anything legitimate?

No:
- The honest path only ever sends a single `TRANSCODER_MODE` that is absent, `frames` or exactly `transcribe`.
- Refusing case and whitespace variants of `transcribe` refuses values no client sends.
- The repeated-key rule cannot trigger, because of the object merge.
- An unrelated key with the value `transcribe` is allowed, per NEG-12.

The one operational edge: if an operator ever set `JOB_ENV_TRANSCODE__TRANSCODER_MODE=transcribe` in dispatcher.env, every transcode would be refused. That fails closed and shows up as transcode-route 422s with the hold reason. It is acceptable.

## Attack 3: is AC-17's source inspection reliable?

Not as specified. "rw-ship checks the release source it just archived" has no defined method. A `grep GUARD_HELD_ENV` would match a comment, a doc, a test fixture or this spec text. Its pytest (`test_transcribe_hold_with/without_guard_support…`) would pass against a fake source tree either way.

A false positive fails open. An old guard's zod `envSchema` strips the unknown `GUARD_HELD_ENV`, so the guard starts normally and allows transcription. NEG-13's "malformed refuses startup" exists only in the new guard. See D1.

## Build notes

- **D1 (must-do: AC-17 detection must be behavioural, and the hold must be confirmed after the switch).**
  - Before the pin: run the built `goodqa-job-dispatcher` image's guard entrypoint on the build box with a malformed `GUARD_HELD_ENV` (for example `GUARD_HELD_ENV=x`) and a dummy job image, then require it to refuse startup (NEG-13). Only the new guard does. If it starts, hold the whole transcode image. Alternatively, run the image's exported matcher on `TRANSCODER_MODE=transcribe`. Either way the check tests the image bytes, not the text.
  - After the switch: the guard's startup line must name the active holds (for example `heldEnv=TRANSCODER_MODE=transcribe`), and rw-ship must assert it from `docker logs` of the create-guard container. If it is missing, treat it like AC-7: the switch failed, so roll back or re-pin with transcode held.
  - The pytest must cover a fake source that has the string but not the behaviour.
- **D2.** Have AC-16's text state that the hold is an honest-path policy and not a boundary against a compromised dispatcher. While the hold is active, cheaply refuse any transcode-image create with a non-empty `Entrypoint`. The CLI sends `null`, which the guard's empty check already treats as unset.
- **D3.** While the hold is active, refuse any held-key Env entry containing NUL or a control character, matching the dispatcher's `hasControlChars` rule. Add a NEG-12 case.
- **D4.** Make the Env matcher fail closed on a malformed `Env`: not an array, or an array element that is not a string. Today the daemon rejects these, but the matcher must not skip them.
- **D5.** The spec's last-Env-wins premise is inaccurate (glibc returns the first entry). The repeated-key refusal already makes this moot. Correct the wording, or keep the repeated-key rule as the stated reason.

## Rest of the delta

- AC-12 now says "a Level 2 failure for any other reason blocks". It closes the B5 gap.
- AC-10(b) cites main for the hold. Main's acceptance arrived relayed by the lead. A relayed message is not the user's words, but the hold is main's own call and is already labelled `TARGET_MISMATCH`, so it is acceptable.
- AC-13 excludes held kinds from the zero count. Its floors cover scan, MP4 transcode and suggest-fix.
- AC-18 and AC-19 close B6 and B7. NEG-2's added case and NEG-14 close B3. AC-6 `jobs_held` closes B4. AC-9's `grep -oE` closes B1. AC-2's `pytest -rA` PASSED line closes B2.

## Not examined

- the GUARD_HELD_ENV implementation (not written yet)
- whether Docker or runc rejects NUL in Env on engine 29.x (stated as a hypothesis)
- production
