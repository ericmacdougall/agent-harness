# PR review packet v4 (whole PR): bugtracker main forward-port of the job images (goodqa#16136 AC-18); delta over v3: hold launch block and review fixes

Ticket: GoodQA goodqa#16136
Repo: ericmacdougall/bugtracker, branch fix/16136-job-images-main, draft PR #1371
Base: ed296b0a6b6fb4883abbd77adaa64e35f52c983d (origin/main)
Expected HEAD: bff96cc5121bb501122798bbc9247a2246038f09
Supersedes: pr-fwd-v3.md (23286da5, at 59501565, built but never sent). The v3 content (main-specific design: job images in further plans of at most three under main's RESOURCE_ADMITTED maxJobs=3, the id recheck, retargeted tests, the id-recheck NEGs, F1/F2, the fp pin) still holds; full text in pr-fwd-v2.md plus the fp pin note in pr-rh-v3.md.

Commits (base..HEAD):
- f7e602bd3543 fix: forward-port job images to main (AC-18)
- f59392bb7301 fix: port review F1/F2 and the id-recheck NEG to main
- 59501565a393 test: pin the fp comparison to b3604eae
- bff96cc5121b fix: port the hold launch block and fixes to main (new)

Spec: v2.3, core 0de4b5ea, ACCEPTed by both delta reviewers and attached (comment 13e3d9ae). The PR carries the same ACs as #1370 (packet pr-rh-v4.md, HEAD c4a1d054fb53, tag release-16136-rh6); this packet re-anchors the new claims on main.

## Scope
Six files under infra/release-harness: rw-ship.sh, selfhost-ctl.py, README.md, test_rw_ship_selfhost.py, ac13-count.py (new), test_ac13_count.py (new).

## Claims to verify (new; same as pr-rh-v4.md claims 1 to 5)
1. AC-20 / AC-10(a), AC-17: a held line is `KEY: "" # held`; the dispatcher answers 501 and never calls docker; the guard drops the empty value; no guard change (PR #1369 stays at 3e478c28).
2. NEG-15: with the old held images on the host the held kinds still resolve to "" on both services; no post-switch docker command names an old held ref; "" is never an image argument.
3. NEG-16 (E4, G3): "" only with `# held` on intelligence-worker or transcode; `# held` only with ""; a non-held line only as a digest-pinned ref (plain or quoted); `--job-hold` of scan or suggest-fix refused.
4. AC-13: ac13-count.py and test_ac13_count.py are byte-identical to #1370 at c4a1d054 (per-launch ±5 s pairing over the widened window, every api replica, every other non-2xx fails).
5. Main-specific: the id recheck still skips transcode only under the whole-image hold (test_id_recheck_skips_transcode_removed_by_the_whole_image_hold now asserts the held line is "").
6. The ctl changes are the same lines as #1370: the HELD_VALUE, HOLDABLE_KEYS and JOB_PIN_VALUE_RE lines of selfhost-ctl.py are equal (checked by diff on t2-dev).

## Changed assertions
The same table as pr-rh-v4.md (old DO ref on held lines -> ""; renamed test_ctl_job_hold_empties_line_and_skips_presence), plus on main test_id_recheck_skips_transcode_removed_by_the_whole_image_hold: transcode stays on BASE_JOBS -> transcode is "".

## Evidence (t2-dev)

```
$ RW_REAL_COMPOSE=1 python -m pytest -q -rA -p no:cacheprovider infra/release-harness/test_rw_ship_selfhost.py infra/release-harness/test_rw_image_jobs.py infra/release-harness/test_ac13_count.py
138 passed in 287.41s (0:04:47)
selfhost+jobs+ac13 exit 0
$ python -m pytest -q -p no:cacheprovider infra/release-harness/test_selfhost_ctl.py
1582 passed in 112.44s (0:01:52)
ctl exit 0
```
Logs: t2-dev ~/repos/fx-16136/fwd-g.txt, fwd-ctl-g.txt. Nothing deselected on main.

Failing first (against the 59501565 scripts):

| Run | Result |
|---|---|
| hold tests (`-k "held or hold or unholding or id_recheck"`) | 10 failed, 22 passed |
| E4 tests plus the renamed test | 9 failed, 1 passed (the accept control) |
| G3 refusal cases, before the G3 ctl change | 7 failed, 3 passed (accept cases) |
| matcher | identical bytes to #1370; red-first and broken variants in pr-rh-v4.md |

Blobs at HEAD: rw-ship.sh 59de044354d4, selfhost-ctl.py 44943ff819a6.

## Risks
- Production does not run main's release-harness; it runs the bound #1370 bytes through bugtracker-harness #73 (now d71f73bb). Merging this keeps main from regressing.
- Same as #1370: AC-13 held-transcription pairing is by time, not job id (goodqa#16178); AC-21 pre-deploy check; ac1-build-time PENDING_REAL_TEST; live proofs need an authorized deploy.
