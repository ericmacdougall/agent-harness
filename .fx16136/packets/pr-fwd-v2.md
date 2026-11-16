# PR review packet v2 (whole PR): bugtracker main forward-port of the job images (goodqa#16136 AC-18; review F1, F2)

Ticket: GoodQA goodqa#16136
Repo: ericmacdougall/bugtracker, branch fix/16136-job-images-main, draft PR #1371
Base: ed296b0a6b6fb4883abbd77adaa64e35f52c983d (origin/main)
Expected HEAD: f59392bb7301e63525ce34327272646d59c27655
Supersedes: pr-fwd.md (1d62b1d9, at f7e602bd, never sent)

Commits (base..HEAD):
- f7e602bd3543 fix: forward-port job images to main (AC-18)
- f59392bb7301 fix: port review F1/F2 and the id-recheck NEG to main

Spec: v2.1, core 7d2a2622, both reviews ACCEPT. AC-18 requires this forward-port. The PR carries the same ACs as #1370 (full packet pr-rh-v2.md, ae1f6cea…, HEAD be8623fd8db6). The claims below are the #1370 claims as re-anchored on main.
On main, test_fp_unchanged_by_job_pin_reporting checks claim 5's fp comparison by comparing main's ported ctl with the 5a78109 ctl (it reads that ctl from commit 5a78109ac2d3). The test passed on t2-dev, where that object exists locally; see Risks. Claim 1's build-disk floor is reached behind main's runtime preflight (see Retargeted tests).

## Scope
Four files under infra/release-harness:
- rw-ship.sh
- selfhost-ctl.py
- README.md
- test_rw_ship_selfhost.py

## Main-specific design (review focus)
1. Main's rw-image-jobs.py owns at most three image commands per plan (RESOURCE_ADMITTED maxJobs=3). The app plan is unchanged: api, web and job-dispatcher. The four job images build in further plans of at most three (job-images-1 holds three, job-images-2 holds one). They run one after another, under the same BUILD_DRIVER cancel trap and the same all-success barrier. The admitted cap is not raised.
2. The post-build id recheck reads $RD/jobs.json and every job-images-*/jobs.json. It skips only transcode, and only when the whole-image hold (`--job-hold JOB_IMAGE_TRANSCODE`) removed that image.
3. The guard probe, holds, VM-disk check, job-ref check after the switch, guard-log check and the jobHolds deploy record all match #1370. Main has no set-env or keyed push, so `pin` gets `$JOBARGS$HOLDARGS$GUARDARGS` only.
4. Build-disk floor: main's default rises from 15 to 30 (AC-1). Main's rw-runtime.sh resource preflight still runs first.

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

## Retargeted tests (no assertion deleted or relaxed)

| Test | AC / NEG | Change | Fails on unpatched main |
|---|---|---|---|
| test_job_images_build_failure_changes_nothing | AC-1 build-failure NEG | rh asserted the line "build transcode". Now it asserts rc 3, an abort naming a job-images receipt, transcode as the only failed job in the receipt, and nothing changed. | yes |
| test_full_build_disk_is_infrastructure | AC-1 | Keeps main's original assertion (rc 11, NO DISK, nothing built), because main's runtime preflight refuses first. | no; regression guard |
| test_rw_ship_build_floor_counts_seven_images (new) | AC-1 | Floor 1G and a fake df reporting 0G, so the run reaches rw-ship's own floor. It asserts "0G free", "seven images", nothing built and no job-images receipt. | yes |

Id-recheck NEGs (lead request). Main's skip logic was already correct at f7e602bd, so each NEG passes there. Per the lead's ruling, failing first is shown against broken variants (`mutate_recheck.py` on t2-dev, file restored and compared with cmp afterwards):

| Test | Proves | Broken variant: always skip transcode | Broken variant: never skip |
|---|---|---|---|
| test_id_recheck_refuses_missing_transcode_without_a_hold | with no hold, a transcode image gone at the recheck refuses (rc 3, nothing loaded, pins unchanged) | FAILS | passes |
| test_id_recheck_skips_transcode_removed_by_the_whole_image_hold | under the whole-image hold, the removed transcode is skipped, the run succeeds, transcode stays on its pin and is not loaded | passes | FAILS |

## Evidence (t2-dev, `df -h /`: 42G free)

```
$ RW_REAL_COMPOSE=1 python -m pytest -q -rA -p no:cacheprovider infra/release-harness/test_rw_ship_selfhost.py infra/release-harness/test_rw_image_jobs.py
106 passed in 274.96s (0:04:34)
PASSED infra/release-harness/test_rw_ship_selfhost.py::test_real_compose_resolves_anchor_for_both_services
pytest exit 0
```

```
$ python -m pytest -q -p no:cacheprovider infra/release-harness/test_selfhost_ctl.py
1582 passed in 119.01s (0:01:59)
ctl exit 0   (main unchanged: 1582 passed)
```

On main nothing is deselected: the ThroughputProcess tests that fail on the old base pass on main.

Failing first:

| Run | Result |
|---|---|
| Main baseline, unmodified test file | 37 passed |
| Job-image tests (f7e602bd file) against main's unchanged rw-ship.sh and selfhost-ctl.py | 39 failed, 41 passed, 1 skipped (exit 1) |
| First port attempt, before batching | 29 failed (ValueError: expected one to three distinct image jobs) |
| F1/F2 and id-recheck tests (`-k "job_hold or vm_disk or id_recheck"`) against f7e602bd scripts | 16 failed, 8 passed (the 8 are regression guards plus the two id-recheck NEGs, shown against broken variants above) |
| Id-recheck NEGs against broken variants | always-skip: 1 failed; never-skip: 1 failed |

The real guard probe and the prod storage-root facts are in pr-rh-v2.md and apply unchanged.

## Risks
- Job images build after the app plan, in up to two more sequential plans, so the build phase is longer. Not measured (PENDING_REAL_TEST ac1-build-time).
- Production does not run main's release-harness today. It runs the bound be8623fd8db6, through bugtracker-harness #73. Merging this keeps main from regressing; it does not change production.
- Same coupling as #1370: transcription is held at the guard only when #1369 is in the release. Otherwise the whole transcode image is held.
- F2: `containerd config dump` reads the default config path, and 2 x incoming bytes is conservative (see pr-rh-v2.md). The prod headroom estimate is in pr-restage-v2.md: about 31 GiB needed against 171 GiB free (ASSUMPTION bound on job image sizes).
- test_fp_unchanged_by_job_pin_reporting reads commit 5a78109ac2d3, which no remote ref holds. In a clone without that object it fails at its show step; it never passes vacuously. A follow-up is to pin the fp against b3604eae, which has the same tree.
