# Adversarial delta review: goodqa#16136 spec v2

Reviewer: agent:a5a2642f07434bbc9 (claude-opus-5-5), adversarial role, delta round (code-review cap: this is the one delta)
Date: 2026-11-15
Spec reviewed: `spec-16136-v2.frozen.md`, sha256 `947e6547e2533479d3dc4091e8933d63a946bb2dcf024ac452eba301168de4be` (verified). The author's live `.fx16136/spec-16136-v2.md` has the same hash and is byte-identical (`diff` is empty).
Previous round: v1 sha `858c5e5b…`, my report `review-opus-adversarial.md` (sha256 `af639f55…`), verdict ACCEPT_WITH_CONDITIONS, C1 to C8.
Location note: the requested path `agent-af3f19d243286a8a7/review-16136/review-opus-adversarial-v2.md` was again refused by this agent's worktree-isolation guard. The report sits here, in the author's untracked `.fx16136/`, and main should copy it.
New code read (read-only, t2-dev):
- bugtracker `packages/db/src/intelligence-jobs.ts` around line 465 at 68b84c55a42
- `git diff --stat 5a78109 origin/main -- infra/release-harness`
- harness `bin/rw-ship.sh` and `bin/selfhost-ctl.py`, the ship-fast entry point, checked for any job-image handling
- the sha256 of the runtime `config/goodqa-release/bin/*`, compared with RELEASE_BINDING

No production access of any kind. No probes this round.

## Verdict: ACCEPT (recorded), with build notes B1 to B7

None of the remaining items needs a spec change: each is a command detail or a test-harness detail inside the existing ACs. The material findings from v1 are closed.

## C1 to C8

| | Status | Evidence in v2 |
|---|---|---|
| C1 env readiness, target labelling, Outcome | CLOSED | AC-9 lists the absent keys per kind, which agrees with my env-keys.json reading. #16148 is filed. The Outcome no longer promises transcripts. AC-12 labels transcribe, frames, suggest-fix and intelligence `TARGET_MISMATCH`. |
| C2 resolution visibility after the pin | CLOSED | AC-6 adds `state.jobs` and `jobs_missing`. AC-7 makes a post-switch job-ref check part of the switch, with rollback on a miss. NEG-11 covers prune and untag. #16149 (retention), #16150 (watch) and the README "never prune -a" line are in place. |
| C3 exact-string presence check and a realistic fake | CLOSED | AC-3: inspect the exact compose string and compare the Id. The fake models containerd resolution. All three negative cases are present, plus a missing service ref. |
| C4 classic store and the real guard path | CLOSED | AC-5 refuses on a classic store. AC-4 runs the real create-guard with GUARD_ENV=production behind the real socket-proxy env, using the dispatcher's own `docker run` argv, with refusal cases. Production `docker info` shows the containerd snapshotter. A post-deploy inspect of each ref is required. |
| C5 fingerprint decision | CLOSED | AC-6 keeps job pins outside the fp core, and `test_fp_unchanged_by_job_pin_reporting` compares the old and new `state` on one fixture. |
| C6 real compose and anchor integrity | CLOSED | AC-2's real `docker compose config` test is gated, but fails rather than skips when enabled (see B2). NEG-10 refuses a divergent dispatcher copy or a duplicate key. AC-3 takes its image list from the resolved config. |
| C7 AC-9 vacuity | CLOSED | AC-13 adds a pre-deploy positive control (422 count above 0), matches on the `request completed` statusCode field, requires at least one 2xx per non-held kind, and keeps the held intelligence route's 422s visible. |
| C8 AC-7 precision | CLOSED | AC-11 (Level 1) names the provoking API route per kind and requires the docker event for the pinned image plus the worker's own log line. AC-12 (Level 2) names the success reads. Intelligence's sync route and output timestamp are defined. AC-15 covers cleanup. |

v1 F9 to F12 are also addressed:
- F9: the AC-8 restore warnings, and `up --pull never` as part of rollback.
- F10: AC-1's raised gates, the VM disk check and a full cold and warm measurement.
- F11: AC-15's sha evidence.
- F12: the explicit statement that no production database query was used.

## New pieces

### Level 1 and Level 2 split (AC-11, AC-12): sound

- It is the honest form of the target: the labels follow the never-narrow rule.
- Level 1 is not vacuous. The docker event must name the pinned `goodqa-JOB@sha256:ID`, and the log line must come from the worker itself. NEG-8 rejects a 2xx wrapped around a guard or daemon refusal.
- For scan and transcode MP4, Level 2 is still required, because only env-caused Level 2 failures are excused.
- See B5 for one wording ambiguity.

### Intelligence held by default (AC-10a): sound, and I verified it

`packages/db/src/intelligence-jobs.ts` at 68b84c55a42, lines 461 to 480: a dispatch launch rejection puts the job back to `queued`, restores `attempts`, and sets a fixed 60-second `availableAt`. Today's 422 path therefore preserves the backlog.

Starting the real worker without PROJECT_INTELLIGENCE_KEYRING would turn each claim into a processing attempt counted towards `maxAttempts`. The reclaim at line 137 would then dead-letter the job as `failed`. Holding is the right default, and the DO ref stays digest-pinned, so AUD-031 and the guard still start.

The hold has a semantic edge, covered in B3 and B4.

### jobs_missing kept apart from missing: correct

`missing` feeds rw-ship's no-rollback-target refusal before the build. Today's DO job refs never resolve, so folding them into `missing` would refuse the first release, the one that fixes them. Keeping the two apart, with AC-7 enforcing resolution after the switch, closes the gap without that deadlock. See B4 for how the held ref should be shown.

## Build notes (to be met in the implementation and its evidence; they are not spec changes)

- **B1 (secret hygiene, must-do).** AC-9's names-only read says `cut -d= -f1`. `cut` prints any line with no `=` in full: comments, blank lines and any continuation line. Once #16148 adds a PEM private key, a stray line could print key material. Use a form that prints only names, for example `sudo grep -oE '^[A-Za-z_][A-Za-z0-9_]*=' /etc/goodqa/dispatcher.env | tr -d =` (or `cut -s`). Never pipe the file anywhere else.
- **B2.** `test_real_compose_resolves_anchor_for_both_services` skips without `RW_REAL_COMPOSE=1`. The evidence must show the command with the variable set and pytest reporting the test as passed, not skipped.
- **B3.** Hold freezes the line. It does not disable the kind. If a hold is ever applied while the line is a working local pin, the kind keeps running. Say so in the `--job-hold` help and the README.
  - Refuse a key given in both `--job-image` and `--job-hold`.
  - Refuse an unknown `SELFHOST_JOB_HOLD` value in ship.conf as a usage error, not silently.
- **B4.** A held ref that does not resolve (today's DO intelligence ref) will sit in `jobs_missing` permanently. Mark it `held` in `state`, so the #16150 watch alerts only on non-held refs and does not train people to ignore it.
- **B5.** AC-11's "any Level 1 failure blocks the ship" is post-deploy. State that it means the ticket stays open and the fix goes forward, not an automatic rollback: rolling back restores the DO refs and gains nothing for jobs.
- **B6 (delivery drift, ticket).** bugtracker main's `infra/release-harness` has diverged from 5a78109 (`git diff --stat`: 305 lines in rw-ship.sh, 164 in selfhost-ctl.py). Neither harness `bin/selfhost-ctl.py` nor bugtracker main's `selfhost-ctl.py` handles JOB_IMAGE. The forward-port PR is in scope but has no AC. A later restage to main's version would silently stop rebuilding job images while keeping stale pins. File a ticket, or add a check to the forward-port PR, so that the main copy carries the job-image build and its tests.
- **B7 (skew, ticket).** The ship-fast path (`bin/rw-ship.sh`) re-pins only service images. After a migration-bearing hotfix through that path, the job images run older code against a newer schema. Additive migrations make this mostly safe. Note it in the deploy runbook, or have the next full release rebuild the job images.

## Checked and fine

- The runtime `config/goodqa-release/bin/{rw-ship.sh,selfhost-ctl.py,rw-runtime.sh,rw-rollback.sh}` sha256 values equal the RELEASE_BINDING lines (commit 5a78109). That supports v2's "byte for byte" basis for branching from 5a78109.
- Production engine 29.9.0 and t2-dev 29.1.3 differ in minor version. The AC-4 post-deploy inspect on production covers it.
- Third-party refs only WARN. This is acceptable: caddy and the socket proxy are not in the `up` service set, so a missing third-party image cannot break the switch.

## Not examined

- the implementation (none yet)
- production files and logs (no access)
- whether the intelligence worker without a keyring fails per claim or once at startup: I inferred per claim, which does not change the hold decision
- the real dispatcher `request completed` log format
- the #16130 staging gate
