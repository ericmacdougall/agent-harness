# PR review packet: bugtracker release-harness job images (goodqa#16136 AC-1 to AC-10, AC-16, AC-17, AC-19)

Ticket: GoodQA goodqa#16136
Repo: ericmacdougall/bugtracker, branch fix/16136-job-images-rh, draft PR #1370
Base: b3604eaec1c6eac8a0f2558ca7f8ebd24cdc7254 (tag release-bound-14377; the PR base branch is base/release-bound-14377 at the same commit)
Expected HEAD: c6b303aee61cdeba2ff8e3784764d6d5c3bb1e74 (annotated tag release-16136-rh peels to it)

Commits:
- a6eaed755b37: fix, job images
- c6b303aee61c: fix, guard probe exit code and full output

Spec: v2.1, core 7d2a2622, both reviews ACCEPT, attached (comment 1ca3cf56).

## Base note
Production runs scripts that hash to 5a78109ac2d3, and no remote ref holds that commit. 5a78109 is a history-rewritten twin of b3604eae. The lead verified this on t2-dev: the trees for apps (7919eb08), packages (1fee4cca) and infra/release-harness (7241cb5f) are identical, and .dockerignore is unchanged. All 41731 differing paths sit under .lanes, plans, evidence, verification, .review2, docs/evidence and audit.

## Scope
Four files, all under infra/release-harness:
- rw-ship.sh
- selfhost-ctl.py
- README.md
- test_rw_ship_selfhost.py

## Claims to verify
1. AC-1:
   - The four job images are built from the release SHA and loaded with the app images.
   - The ids are checked on the VM.
   - The build-disk floor is SELFHOST_BUILD_MIN_FREE_GB, default 30. The VM-disk check runs before the load: SELFHOST_VM_MIN_FREE_GB, default 20.
2. AC-2: each pin is goodqa-JOB@sha256:<VM id>. Each key appears exactly once, in the create-guard &job-images block. The real `docker compose config` resolves the anchor for both services.
3. AC-3: presence is checked on the resolved prepared compose, by exact string, and each job ref resolves to its own digest. Third-party refs only WARN.
4. AC-5: a classic image store refuses.
5. AC-6:
   - state reports jobs, jobs_held, jobs_missing and guard_hold, outside the fp core.
   - The fp equals the 5a78109 ctl on the same stack.
   - Held refs never appear in jobs_missing (B4).
6. AC-7: a job ref that stops resolving after the switch rolls back.
7. AC-8: restore warns "jobs down after rollback:" and "core image missing:", and never blocks. `up` uses `--pull never`.
8. AC-10:
   - SELFHOST_JOB_HOLD defaults to intelligence-worker,transcribe.
   - `none` lifts the hold. Unknown tokens refuse before any build (NEG-14).
   - Held lines are marked `# held`.
9. AC-16 and AC-17 (D1):
   - Only a built dispatcher image that refuses a malformed GUARD_HELD_ENV (exit not 0 or 124, plus the text "GUARD_HELD_ENV must be") gets `--guard-hold TRANSCODER_MODE=transcribe`. Otherwise the whole transcode image is held.
   - After the switch, `vmctl guard-log` must report the hold, or the stack rolls back.
   - The deploy record lists jobHolds.
10. AC-19: the README says ship-fast and wave-loop do not rebuild job images, and to never run prune -a.

## Evidence (t2-dev, `df -h /`: 57G free)

```
$ RW_REAL_COMPOSE=1 python -m pytest -q -rA -p no:cacheprovider infra/release-harness/test_rw_ship_selfhost.py --deselect <4 baseline ThroughputProcess tests>
76 passed, 4 deselected in 189.81s (0:03:09)
PASSED infra/release-harness/test_rw_ship_selfhost.py::test_real_compose_resolves_anchor_for_both_services
pytest exit 0
```

Deselected tests. These four fail identically at base b3604eae/5a78109 and at HEAD, and the failed-set diff is empty:
- ThroughputProcess::test_api_only_boundary_refusal_starts_zero_image_jobs
- ThroughputProcess::test_cancelled_ship_reaps_owned_builds_before_exit
- ThroughputProcess::test_failed_build_never_transfers_or_switches
- ThroughputProcess::test_receipt_changed_after_qualification_starts_zero_jobs

Full run without deselect: 4 failed, 76 passed (exactly those 4).

test_selfhost_ctl.py is out of sync with this CLI at the base as well: 940 failed and 642 passed, with a failed set identical to the base. It is not the runtime.

Failing first:

| Run | Result |
|---|---|
| New v1 and v2 tests against the base scripts | 43 failed |
| New v2.1 tests against the base scripts | 11 failed |
| Probe fix: guard tests against a6eaed rw-ship.sh | 2 failed, 8 passed (with guard support; guard log missing) |
| Probe fix: guard tests against c6b303ae | 10 passed |

Real probe on t2-dev, built images, exact rw-ship command:
- The guard built from bugtracker fbea063 exits rc=1 with "GUARD_HELD_ENV must be empty or exactly one of TRANSCODER_MODE=transcribe". It starts with heldEnv=TRANSCODER_MODE=transcribe.
- The guard built from main ed296b0a6b6f keeps listening until rc=124, so the runner holds all of transcode.

## Risks
- Disclosed difference: evidence/, verification/ and .review2 are not in .dockerignore, and the transcoder Dockerfile does `COPY . .`. A transcoder image built from this base carries different non-executed files from the one built from 5a78109. Runtime code is identical.
- The job images are loaded, never pushed. A `prune -a` on the app host stops those kinds until the next full release (goodqa#16149, goodqa#16150).
- The guard hold needs the guard change (bugtracker PR #1369) in the same release. Without it, MP4 also stays held.
- Not proven here:
  - seven-image build timing (PENDING_REAL_TEST ac1-build-time);
  - the AC-4 real guard path on a stack;
  - every live proof (AC-11 to AC-15), which needs an authorized deploy.
