# PR review packet v5: bugtracker-harness PR #73, rebind to bugtracker 6c187f88 and the staged fixture port (goodqa#16136); delta over v4

Ticket: GoodQA goodqa#16136
Repo: ericmacdougall/bugtracker-harness (the lane harness), branch fix/16136-job-images, draft PR #73 into main
Receipt base: origin/main 1786659bb29d39c8facf1b2ed88fdd8d45d4845d. Main has not moved under the branch: `git merge-base 52fed569 origin/main` is 1786659b, and origin/main is an ancestor of HEAD (checked on t2-dev after `git fetch origin main`).
Expected HEAD: 52fed5695eba84becd22a58626cc4addb0dd74ec
Delta over the v4 packet: d71f73bbcc2511df03e40cf6fa88759ecfd6f773..52fed5695eba84becd22a58626cc4addb0dd74ec (fast-forward)
Answers: receipts/bth-pr73-v4b.md. F1 is fixed upstream in bugtracker 6c187f88 and restaged here. F2 is the fixture port with inline evidence.

Commits in this delta:
- 39026b15668616fe48dc5bc44b8dafc69fa67061 fix(goodqa-release): rebind the runtime to bugtracker 6c187f88
- 52fed5695eba84becd22a58626cc4addb0dd74ec test(goodqa-release): port the staged rw-ship fixture to job images

Files: config/goodqa-release/bin/{RELEASE_BINDING, selfhost-ctl.py, test_rw_release_authority_d2.py, test_rw_ship_selfhost.py}

## Upstream
- Bugtracker PR #1370 merged into base/release-bound-14377 as 63bcdc50bd2e548511ed0365d4215e31925ef747. 6c187f88018ed4f0f75e001210cd1f09f976f0db is its second parent, and the diff between them is empty.
- The final 1370 receipt is receipts/bugtracker-pr1370-v2c.md, PASS at 6c187f88. It has one Low finding, ported to the gate line and ticketed for this line as goodqa#16210.
- 6c187f88 contains the bth-pr73-v4b F1 fix:
  - job_lines requires the guard `environment` key;
  - presence_check compares every JOB_IMAGE_* key, held ones included, in both resolved services with exact parity.
- It also contains the pr1370 fail-closed fixes, among them the DriverStatus rows of exactly two strings.

## Byte equality against bugtracker 6c187f88 (t2-dev, at 52fed569)
Each staged file's sha256 equals its RELEASE_BINDING line, and `git show 6c187f88:infra/release-harness/<f> | cmp - <f>` reports equal for each script:

| Staged file | sha256 (staged = upstream = binding) | Changed in this delta |
|---|---|---|
| bin/rw-runtime.sh | 2107e0bbd2736bbd462d79e6294223b734ee5f561dca61f5beaf76323a853de1 | no |
| bin/rw-ship.sh | 2f6b81d5c659553b1546695371d9fbd921a6275353ebc23bff85b93871a21c59 | no |
| bin/selfhost-ctl.py | 2d12d87aec07e7d763bea9eff716ebecc9ea417e4b7922a4662cfe1ebcb60fa7 | yes (was e1aab26e9c9c, from c4a1d054) |
| bin/rw-rollback.sh | 2fc968e3eb29f07e700bc9d62c618b8f9674c5746da62451d848023de63737c7 | no |
| biz/prod-db-pool-20261013/ship-fast.sh | a812832784af69ba76126e13edaf25de770995528d46ad704956649bfaee942a | no (equal to upstream infra/release-harness/ship-fast.sh at 6c187f88) |

The RELEASE_BINDING `commit` line moves from c4a1d054 to 6c187f88018ed4f0f75e001210cd1f09f976f0db. There is no derive-job-secrets.py at 6c187f88, so the binding stays at 7 fields and carries no derive-blob line.

## Claims to verify
1. The selfhost-ctl.py bytes and RELEASE_BINDING are exactly as the table shows. No other runtime file changes.
2. The staged lane fixture now models the job-image runtime. It is ported from bugtracker's own test at 6c187f88, which is the later version of this same file:
   - fake docker answers `info` DriverStatus (containerd by default; `driverstatus-fail`, `driverstatus-out` and `classic-store` markers), and the fake VM gets `containerd config dump` and `df -Pk` stubs;
   - job image refs resolve as repo@<image id>, and image sizes are reported;
   - `compose config --format json` resolves the JOB_IMAGE_* keys per sub-key;
   - the guard probe and guard log are present;
   - the compose fixture carries the four JOB_IMAGE_* rows.

   The rw-image-jobs.py, image-policy and tzdata-policy copies are left out because the staged rw-ship.sh uses none of them (grep: 0 references).
3. Every one of the 30 original cases is kept, and no assertion is removed or relaxed. The test-side changes are:
   - the ctl pin, and the d2 PIN2, pass every job key (`JOBARGS`), because the runtime refuses a pin without them (AC-2);
   - a `J()` JSON parse skips warning lines before the JSON object;
   - the migrate-after-switch control turns a bare `StopIteration` into an assertion that prints rc and output when the mutant never reaches both the migration and the switch;
   - `COMPOSE.format` becomes `compose_text`, because the template now has digest fields.
4. The new `test_vm_disk_gate_refuses_when_the_image_store_is_unknown[driverstatus-fail|containerd-noroot]` turns the old accidental exit 11 into a deliberate check. Each case asserts exit 11, `NO DISK`, `nothing switched`, no LOAD on the VM, and `unchanged()` (pins, env and no up).
5. The three negative controls (no-migration-hold, no-schema-freeze, migrate-after-switch) each reach their intended outcome. A missing mutant anchor fails loudly.

## Evidence (t2-dev, 34-36G free)
Layout: these tests import the lane harness from `../../tools/lane-harness` relative to config/goodqa-release/bin, so they expect a bugtracker checkout's `tools/` beside `config/goodqa-release`. For these runs, `config/tools` was an uncommitted symlink to the bt-rh checkout's tools (bugtracker 6c187f88). The symlink is not part of the PR.

Fail first, and the before state:
```
$ pytest -q test_rw_ship_selfhost.py        (at base 1786659b)
30 passed
$ pytest -q test_rw_ship_selfhost.py        (at d71f73bb, the v4 head)
18 failed, 12 passed
$ pytest -q test_rw_ship_selfhost.py        (after the rebind 39026b15, old fixture)
18 failed, 12 passed
```
(Timings for these three before-runs were not kept; the counts are from the run outputs.)
Of those 18, 16 stopped at the VM disk gate with exit 11 ("VM image store: unresolved ... NO DISK on the VM ... nothing switched"). One was the migrate-after-switch control, which found no migration line because the run stopped at that gate. One was the ctl pin, "REFUSED every job image key needs --job-image or --job-hold".

At HEAD 52fed569:
```
$ pytest -q -p no:cacheprovider test_rw_ship_selfhost.py
32 passed in 107.76s
exit 0
$ pytest -q -p no:cacheprovider test_rw_release_authority_d2.py
27 passed in 109.56s
exit 0
$ python -B -m pytest -q -p no:cacheprovider bin/test_goodqa_staged_rw_ship_keyed.py
4 passed in 11.98s
exit 0
$ python -B bin/test-goodqa-release-unit.py
Ran 15 tests in 2.504s
OK
exit 0
```
test_rw_release_authority_d2.py imports this fixture (`import test_rw_ship_selfhost as sh`), so it failed with it:
```
$ pytest -q -p no:cacheprovider test_rw_release_authority_d2.py     (at d71f73bb, t2-dev worktree delta/pr73-head)
18 failed, 9 passed in 26.29s
  rollback: older_runs_rollback_cannot_revert_a_newer_release, hand_rollback_of_the_current_release_restores_and_bumps_the_epoch,
            hand_rollback_refuses_while_a_release_holds_the_lock, hand_rollback_whose_version_does_not_come_back_is_not_success,
            hand_rollback_dry_run_changes_nothing, rollback_record_names_the_one_hand_rollback
  ctl:      ctl_restore_of_an_older_stamp_is_refused_after_a_newer_pin, ctl_restore_after_a_part_way_pin_is_allowed,
            ctl_legacy_stamp_needs_the_live_fingerprint, ctl_restore_refuses_a_backup_that_is_not_the_recorded_before
  gates:    owner_smoke_skip_is_sha_and_time_bound[ok], owner_skip_for_another_sha_keeps_the_promote_gates,
            release_scripts_must_equal_the_bound_revision[bound], mutant_no_restore_fence_is_caught,
            mutant_rollback_without_lock_is_caught, mutant_gates_are_caught[skip-any-sha, skip-no-expiry, binding-no-blob-check]
$ (rebind + ported fixture, d2 PIN2 not yet given JOBARGS)
1 failed: ctl_restore_of_an_older_stamp_is_refused_after_a_newer_pin (the pin without job keys is refused)
$ (at 52fed569)
27 passed in 109.56s
```

Broken variants, each a copy of the staged rw-ship.sh passed through RW_SHIP_UNDER_TEST:
```
V1 VM disk gate removed (line 749 condition -> true)   -k vm_disk_gate_refuses            -> 2 failed
V2 mutant anchor "# MIGRATIONS (self-host)" missing     -k "negative_controls and migrate" -> ValueError: substring not found, 1 failed
```

Already failing at base, and not changed here: `pytest -q test_rw_authority.py` gives 2 failed:
- test_smoke_of_another_commit_with_the_same_tree_is_refused
- test_settle_refuses_a_release_that_is_not_deploy_unverified_or_another_sha

Both fail identically at base 1786659b (2 failed, 90 passed with d2) and at d71f73bb. The cause is `REFUSED: manual release registration row is absent or ambiguous; use supported rw register-release first` (rc 11, where the test expects 2). That refusal comes from the lane-harness `rw` in the bugtracker checkout used for tools/, a version mismatch between that rw and this test. It is not from the staged runtime.

## Not exercised (disclosed)
- **The bound path.** The fixture's ship.conf has no RELEASE_BINDING, so runs log `release scripts: UNBOUND` and take the unbound path. Exercising the bound path would need an installed, hash-checked binding in the fixture. The binding bytes themselves are checked by the byte-equality table, and the d2 installer tests run upstream.
- **Epoch read-before-write.** Runs print `rw-ship.sh: line 496: .../locks/gq-promote.epoch: No such file or directory`. This comes from the runtime, not the fixture. `tr ... < "$EPOCHF" 2>/dev/null` applies the input redirect before the stderr redirect. The behaviour is still correct (epoch 1, then written temp-then-rename); it is log noise only. Ticketed as goodqa#16221, low priority.

## Process notes
- The t2-dev clone had no git identity, so a repo-local user.name and user.email were set, copied from the bt-rh checkout. Both commits are authored as the repository owner, as earlier PR 73 commits were.
- Nothing is merged, tagged or deployed. The live release stays gated on the landing window of goodqa#16148 and on PENDING_REAL_TEST p16136-ac4-real-guard.

## Delta diff (d71f73bb..52fed569)
