# PR review packet v3 (full): bugtracker release-harness job images (goodqa#16136 AC-1 to AC-10, AC-16, AC-17, AC-19; review F1, F2)

Ticket: GoodQA goodqa#16136
Repo: ericmacdougall/bugtracker, branch fix/16136-job-images-rh, draft PR #1370
Base: b3604eaec1c6eac8a0f2558ca7f8ebd24cdc7254 (tag release-bound-14377; PR base branch base/release-bound-14377 at the same commit)
Expected HEAD: 04dd4b1f6dcf3886af945a81b5a61286349da060 (annotated tag release-16136-rh3 peels to it; rh2 still peels to be8623fd8db6, unmoved)
Supersedes: pr-rh-v2.md (ae1f6cea, at be8623fd8db6, not yet reviewed), pr-rh.md and pr-rh-delta1.md

Commits (base..HEAD):
- a6eaed755b37 fix: job images
- c6b303aee61c fix: guard probe exit code and full output
- be8623fd8db6 fix: canonical job holds and a fail-closed VM disk gate (review F1, F2 of receipt bth-pr73-v1)
- 04dd4b1f6dcf test: pin the fp comparison to b3604eae on origin (test file only; rw-ship.sh blob 62adfed7cc9d and selfhost-ctl.py blob 56b09ac7fd57 unchanged from be8623fd8db6)

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
11. F1: SELFHOST_JOB_HOLD is accepted only as `none` or a single-comma list of intelligence-worker, transcribe (no spaces, no empty items); held() reads that same validated string; anything else refuses (exit 2) before any build.
12. F2: `disk` measures docker's DockerRootDir and, with the containerd store, the root from `containerd config dump`; any unresolved or unmeasurable root refuses, so rw-ship stops with NO DISK on the VM (exit 11) before any load. rw-ship needs max(SELFHOST_VM_MIN_FREE_GB, 2 x the bytes it loads); an unreadable size refuses.

## F1: one canonical SELFHOST_JOB_HOLD
- Before: validation split on commas and spaces, but held() matched ",$JHOLD,". So "intelligence-worker, transcribe" was accepted, and held transcribe was then false: no probe, no guard hold, transcription released.
- Now the value must be exactly `none` or match `^(intelligence-worker|transcribe)(,(intelligence-worker|transcribe))*$`. held() reads the same validated string.
- Anything else is refused with exit 2 before any build ("nothing built or switched"), and the deploy-failed state is recorded.
- The printed value replaces every character outside [a-z0-9,-] with `?`, so whitespace and control characters are never echoed raw.
- An empty value falls back to the default hold through shconf. It never releases a kind.

## F2: a VM disk gate on the runtime's own data roots, failing closed
- `selfhost-ctl.py disk` measures the runtime's own data roots:
  - docker's root, from `docker info -f {{.DockerRootDir}}`. It must be an absolute path.
  - with the containerd image store only, the `root` line of `containerd config dump`, single- or double-quoted, absolute.
- Each root is measured with `df -Pk`, and exactly one data row is required. The output is `{"free_gb": min, "paths": {root: GiB}}`.
- Any root that cannot be resolved or measured gets REFUSED (exit 3). rw-ship then has no number and stops with NO DISK on the VM, exit 11, before anything is loaded.
- rw-ship needs max(SELFHOST_VM_MIN_FREE_GB, ceil(2 x the summed `docker image inspect -f {{.Size}}` of every image it loads)). It logs "VM image store: <json>; need NG (...)".
- An unreadable size refuses.
- Prod, read-only, checked from t2-dev: DockerRootDir is /var/lib/docker, the store is io.containerd.snapshotter.v1, and `containerd config dump` gives root = '/var/lib/containerd'. Both roots are on /.

## Evidence (t2-dev)

Final run at HEAD 04dd4b1f (`df -h /`: 42G free):

```
$ RW_REAL_COMPOSE=1 python -m pytest -q -rA -p no:cacheprovider infra/release-harness/test_rw_ship_selfhost.py --deselect <4 baseline ThroughputProcess tests>
95 passed, 4 deselected in 222.26s (0:03:42)
PASSED infra/release-harness/test_rw_ship_selfhost.py::test_real_compose_resolves_anchor_for_both_services
pytest exit 0
```

Deselected: four tests that fail identically at base b3604eae/5a78109 and at every head (failed-set diff empty):
- ThroughputProcess::test_api_only_boundary_refusal_starts_zero_image_jobs
- ThroughputProcess::test_cancelled_ship_reaps_owned_builds_before_exit
- ThroughputProcess::test_failed_build_never_transfers_or_switches
- ThroughputProcess::test_receipt_changed_after_qualification_starts_zero_jobs

test_selfhost_ctl.py is out of sync with this CLI at the base too (940 failed, 642 passed at c6b303ae, failed set identical to the base); it is not the runtime.

Failing first:

| Run | Result |
|---|---|
| New v1 and v2 tests against the base scripts | 43 failed |
| New v2.1 tests against the base scripts | 11 failed |
| Probe fix: guard tests against a6eaed rw-ship.sh | 2 failed, 8 passed |
| Probe fix: guard tests against c6b303ae | 10 passed |
| F1/F2 tests (`-k "job_hold or vm_disk"`) against c6b303ae | 16 failed, 6 passed (the 6 are regression guards the old code met) |

Real probe on t2-dev, built images, exact rw-ship probe command:
- guard built from bugtracker fbea063 (PR #1369): rc=1, "GUARD_HELD_ENV must be empty or exactly one of TRANSCODER_MODE=transcribe"; starts with heldEnv=TRANSCODER_MODE=transcribe.
- guard built from main ed296b0a6b6f: keeps listening until rc=124, so the runner holds all of transcode.

F2 prod facts (read-only, from t2-dev): DockerRootDir /var/lib/docker; store io.containerd.snapshotter.v1; `containerd config dump` root = '/var/lib/containerd'; both on /.

New fixture pieces (test file only): a fake `containerd` (config dump root under FAKE_STATE, or failing, or no root), a VM-side fake `df` answering for the two roots from FAKE_STATE/vmdf-*, fake docker image sizes.

Fp test pin (04dd4b1f). test_fp_unchanged_by_job_pin_reporting (AC-6) now reads the old ctl from b3604eaec1c6, which origin holds (tag release-bound-14377), instead of 5a78109ac2d3, which no remote ref holds. infra/release-harness has tree 7241cb5f in both commits. Results in a fresh blobless clone of origin at 04dd4b1f's parent with no 5a78109 object (log ~/repos/fx-16136/fresh-rh.fp-fresh*.txt on t2-dev):

| Variant | Result |
|---|---|
| repointed test | 1 passed |
| old 5a78109 test | 1 failed (git show) |
| broken variant: job pins folded into fp | 1 failed |

## Risks
- Disclosed difference: evidence/, verification/ and .review2 are not in .dockerignore, and the transcoder Dockerfile does `COPY . .`. A transcoder image built from this base carries different non-executed files from the one built from 5a78109. Runtime code is identical.
- The job images are loaded, never pushed. A `prune -a` on the app host stops those kinds until the next full release (goodqa#16149, goodqa#16150).
- The guard hold needs the guard change (bugtracker PR #1369) in the same release. Without it, MP4 also stays held.
- Not proven here:
  - seven-image build timing (PENDING_REAL_TEST ac1-build-time);
  - the AC-4 real guard path on a stack;
  - every live proof (AC-11 to AC-15), which needs an authorized deploy.
- F2: `containerd config dump` reads containerd's default config path; a containerd started with a non-default `--config` would report the default root (prod uses the default).
- F2: 2 x incoming bytes is conservative (layers already present are not subtracted); it may refuse a load that would fit, never approve one that does not. Prod headroom against this release's load is being measured for the restage packet.
