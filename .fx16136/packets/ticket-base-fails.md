On the off-main release-bound-14377 helper line, 945 tests fail at the base. That covers fix/16136-job-images-rh (PR #1370) and every branch based on origin/base/release-bound-14377.

## Cause (real code, not the environment)
The base commit b3604eaec1c is titled "chore(release): pin the installed runtime helper line for GoodQA 14377". It replaced infra/release-harness rw-runtime.sh, rw-ship.sh and selfhost-ctl.py with older installed-runtime bytes, and changed no tests. Its own message says it is deliberately off main and must never be merged.

As a result, main's newer test files run against older scripts. The merge-base with main is 9deb6d83dfed.

## The failures, with one evidence line each
1. **940 in test_selfhost_ctl.py.** The file is unchanged since 9deb6d83dfed; its last change is caf247f290d (goodqa#12707 B1). It drives the `set-secret-env` and `remove-secret-env` verbs, which the older ctl lacks, so every case exits rc 2 with "invalid choice".
   Evidence: a grep count of `set-secret-env` in infra/release-harness/selfhost-ctl.py is 7 at origin/main and 9deb6d83dfed, and 0 at b3604eaec1c, c4a1d054 and c1d221810a2.
2. **4 ThroughputProcess failures in test_rw_ship_selfhost.py:**
   - test_api_only_boundary_refusal_starts_zero_image_jobs
   - test_cancelled_ship_reaps_owned_builds_before_exit
   - test_failed_build_never_transfers_or_switches
   - test_receipt_changed_after_qualification_starts_zero_jobs

   They expect main's concurrent build pipeline: deploys/*/jobs.json, API-boundary exports and child build pids.
   Evidence: in rw-ship.sh, the grep counts for jobs.json and for "boundary" are 0 and 0 at c1d221810a2, against 2 and 4 at origin/main. Earlier review packets recorded that these tests pass on main and fail identically at b3604eae.
3. **1 PIN2 failure:** test_rw_release_authority_d2.py::test_ctl_restore_of_an_older_stamp_is_refused_after_a_newer_pin.
   Evidence: the test's PIN2 pin call omits the job arguments that the job-image ctl now requires. The same failure occurs at bff96cc5 (PR #1371). The fix is `+ sh.JOBARGS` in the goodqa#16148 gate PR, and it is not ported to the rh line.

The PR #1370 delta (c4a1d054..c1d221810a2) neither covers nor changes these failures. The failing test ids are identical at the base and at the head, compared with `comm` of the sorted FAILED lists on t2-dev.

## Open question to settle before the landing window (a read-only check, not a run)
The window unholds only after every intelligence-worker key is set via set-secret-env.

infra/selfhost/app/set-secret-env.sh loads the ctl from `Path($SELFHOST_SECRET_HELPER).resolve().parents[2] / 'release-harness/selfhost-ctl.py'`, which is the selfhost-ctl.py inside the same checkout as the helper. On the older helper-line ctl, that verb does not exist.

Confirm on the host, by name and path only, three things:
- which checkout SELFHOST_SECRET_HELPER points into;
- whether that checkout's selfhost-ctl.py has the set-secret-env verb;
- that it is not the installed release-bound runtime copy.

## Decision for the owner of the release-bound line
Choose one of:
- skip or mark these tests on the helper line, with a reason;
- port the verbs and the pipeline into the pinned bytes.

Refs: goodqa#16136, goodqa#16148, goodqa#14377, goodqa#12707. Packet: .fx16136/packets/delta-1370-v2b.md on harness branch fx/16148-pem-spec.
