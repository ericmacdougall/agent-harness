# PR review packet: bugtracker main forward-port of the job images (goodqa#16136 AC-18)

Ticket: GoodQA goodqa#16136
Repo: ericmacdougall/bugtracker, branch fix/16136-job-images-main, draft PR #1371
Base: ed296b0a6b6fb4883abbd77adaa64e35f52c983d (origin/main)
Expected HEAD: f7e602bd354316048702a71cb76e3a4f0153f4f1
Commit: f7e602bd3543 (single commit)
Spec: v2.1, core 7d2a2622, both reviews ACCEPT. AC-18 requires the forward-port to main. This PR carries the same ACs as #1370 (packet pr-rh.md).

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

## Retargeted tests (no assertion deleted or relaxed)

| Test | AC / NEG | Change | Fails on unpatched main |
|---|---|---|---|
| test_job_images_build_failure_changes_nothing | AC-1 build-failure NEG | rh asserted the line "build transcode". Now it asserts rc 3, an abort naming a job-images receipt, transcode as the only failed job in the receipt, and nothing changed. | yes |
| test_full_build_disk_is_infrastructure | AC-1 | Keeps main's original assertion (rc 11, NO DISK, nothing built), because main's runtime preflight refuses first. | no; regression guard |
| test_rw_ship_build_floor_counts_seven_images (new) | AC-1 | Floor 1G and a fake df reporting 0G, so the run reaches rw-ship's own floor. It asserts "0G free", "seven images", nothing built and no job-images receipt. | yes |

## Evidence (t2-dev, `df -h /`: 47G free)

```
$ RW_REAL_COMPOSE=1 python -m pytest -q -rA -p no:cacheprovider infra/release-harness/test_rw_ship_selfhost.py infra/release-harness/test_rw_image_jobs.py
85 passed in 196.41s (0:03:16)
PASSED infra/release-harness/test_rw_ship_selfhost.py::test_real_compose_resolves_anchor_for_both_services
pytest exit 0
```

```
$ python -m pytest -q -p no:cacheprovider infra/release-harness/test_selfhost_ctl.py
1582 passed in 109.15s (0:01:49)
exit 0   (main unchanged: 1582 passed in 105.14s)
```

Failing first:

| Run | Result |
|---|---|
| Main baseline, unmodified test file | 37 passed |
| Job-image tests (final file) against main's unchanged rw-ship.sh and selfhost-ctl.py | 39 failed, 41 passed, 1 skipped, exit 1 |
| First port attempt, before the batching fix | 29 failed (ValueError: expected one to three distinct image jobs) |

## Risks
- Job images build after the app plan, in up to two more sequential plans, so the build phase is longer. Not measured (PENDING_REAL_TEST ac1-build-time).
- Production does not run main's release-harness today. That is #1370 plus the restage (bugtracker-harness #73). Merging this keeps main from regressing; it does not change production.
- Same coupling as #1370: transcription is held at the guard only when #1369 is in the release. Otherwise the whole transcode image is held.
