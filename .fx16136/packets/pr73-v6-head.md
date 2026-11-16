# PR review packet v6: bugtracker-harness PR #73, rebind to bugtracker 5daddbbf (F1) and the bugtracker lane tests on the stage (F2); delta over v5

Ticket: GoodQA goodqa#16136
Repo: ericmacdougall/bugtracker-harness, branch fix/16136-job-images, draft PR #73 into main.
Receipt base: origin/main 1786659bb29d39c8facf1b2ed88fdd8d45d4845d. `git merge-base --is-ancestor origin/main 8085f29e` is true after `git fetch origin main` (t2-dev); main has not moved.
Expected HEAD: 8085f29e1b521f3290e892aebaff1c3a51603e50
Delta over v5: 52fed5695eba84becd22a58626cc4addb0dd74ec..8085f29e1b521f3290e892aebaff1c3a51603e50 (fast-forward).
Answers: receipts/bth-pr73-v5.md, BLOCK with F1 High (disk gate) and F2 High (job-hold coverage). Round 1 on these findings.

Commits:
- 54e9b05f1fb877f3e1f1afd2ffcb8acb4fec2aac fix(goodqa-release): rebind to bugtracker 5daddbbf (disk gate F1)
- 8085f29e1b521f3290e892aebaff1c3a51603e50 test(goodqa-release): run the bugtracker lane tests on the stage

## F1: fixed upstream, bound here
- Fixed in bugtracker, not diverged locally: RELEASE_BINDING requires the staged bytes to equal the bound commit (d2 test release_scripts_must_equal_the_bound_revision).
- Bugtracker branch fix/16136-active-containerd-root, off base/release-bound-14377 at 63bcdc50 (the 1370 merge; its release-harness tree equals 6c187f88): 730429f8 (fix), 3f99b22f and 5daddbbf (tests). Draft bugtracker PR #1384, its own receipt, to land with a merge commit. The same change (identical changed lines, checked by hash) is on the 1377 gate branch as f6e45adc..51ae3d52.
- The fix: selfhost-ctl.py containerd_root() measures the store of the containerd docker uses. Endpoint: docker info .Containerd.Address (Docker 27+); else the one process named dockerd holding docker's API socket and its --containerd; else its daemon.json "containerd" (unparseable refuses); else both default sockets (/run/containerd, dockerd-managed /var/run/docker/containerd), exactly one live or both with the same root. Then exactly one LISTEN inode and one holder through /proc (socket owner's processes, same pid namespace; as root an unreadable process refuses); its --root or the top-level root of its --config (section keys ignored, empty imports allowed, non-empty refuse, twice refuses), realpath, must exist. No `containerd config dump`. Every failure has its own message, which rw-ship.sh now prints after `VM image store: unresolved` (NO DISK, exit 11, nothing loaded).

## Byte equality against bugtracker 5daddbbf (t2-dev, at 8085f29e)
`git show 5daddbbf:infra/release-harness/<f> | cmp - <f>` equal for all five; each sha256 equals its RELEASE_BINDING line (5 ok). The runtime bytes at 5daddbbf are identical to 730429f8 (3f99b22f and 5daddbbf change tests only).

| Staged file | sha256 (staged = upstream = binding) | Changed in this delta |
|---|---|---|
| bin/rw-runtime.sh | 2107e0bbd2736bbd462d79e6294223b734ee5f561dca61f5beaf76323a853de1 | no |
| bin/rw-ship.sh | 759af97691b9b8ab0b3417cacfaa497c85e923821460dae06c7dd605c639762c | yes (was 2f6b81d5c659) |
| bin/selfhost-ctl.py | a8a45691cce35540afa8da7b292d8308d94abb5e561d16b4be8882b663dbe940 | yes (was 2d12d87aec07) |
| bin/rw-rollback.sh | 2fc968e3eb29f07e700bc9d62c618b8f9674c5746da62451d848023de63737c7 | no |
| biz/prod-db-pool-20261013/ship-fast.sh | a812832784af69ba76126e13edaf25de770995528d46ad704956649bfaee942a | no |

RELEASE_BINDING `commit` moves from 6c187f88 to 5daddbbfa8b282ff61835cf3d6f5d7ca34483eac; 7 fields, no derive-blob (no derive-job-secrets.py on this line).

## F2: the job-hold paths now run on the stage
The staged runtime is byte-equal to bugtracker 5daddbbf, so the staged test file is now bugtracker's own test file at 5daddbbf, with a recorded transform (the builder asserts every anchor and fails loudly if the source changes shape):
- SRoot does not copy rw-image-jobs.py, the image policy or the tzdata policy (not staged; the staged rw-ship.sh reads none of them).
- ThroughputProcess, install_real_promote and PromotionPhases (the release-throughput scheduler in bugtracker's promote.sh and rw-image-jobs.py, not part of the staged lane) are left out by name. The builder asserts no `def test_` sits in that block.
- Reads of the bugtracker tree (its compose.yaml for the real-compose and job-line tests, the b3604eae ctl from its history for the fp test) go through `BT`, the bugtracker checkout this suite already needs for tools/lane-harness (config/tools).
- The staged-only test_vm_disk_gate_refuses_when_the_image_store_is_unknown (from 52fed569) is kept; its containerd-noroot case was a failure of the removed config dump and is now a containerd address nobody listens on, same assertions.

What the receipt asked for, and where it is now tested (test_rw_ship_selfhost.py):
- Default holds active (no SELFHOST_JOB_HOLD): test_default_holds_intelligence_worker, test_held_kind_never_starts_even_with_its_old_image_on_the_host, test_held_value_never_reaches_docker.
- Transcription hold enforced at the guard (guard-held-support): test_transcribe_hold_with_guard_support_pins_transcode (transcode pinned, one GUARD_HELD_ENV line, deploy record names it).
- Whole-image fallback: test_transcribe_hold_without_guard_support_holds_transcode, test_transcribe_hold_string_present_behaviour_absent_holds_transcode, test_transcribe_hold_old_guard_that_just_listens_holds_transcode (guard-old-timeout, rc 124).
- Guard not reporting its hold (guard-log-missing): test_guard_not_reporting_hold_after_switch_rolls_back (rc 5, ROLLED BACK, pins, job pins and live sha restored).
- Resolved-env parity for held keys: test_resolved_compose_dropping_a_held_key_is_refused (resolved-drop-held), test_held_key_pin_passes_and_is_held_in_both_resolved_envs, test_job_key_under_labels_is_refused, test_real_compose_held_kind_is_empty_for_both_services (real `docker compose config`), test_ctl_job_images_refusals_change_nothing, test_ctl_pin_refuses_missing_job_image.
- Job pins on success: test_selfhost_release_ships_job_images (each `goodqa-<job>@<VM image id>`), test_canonical_job_hold_holds_every_named_kind, test_unholding_restores_a_real_pin.
- Files unchanged on refusal: `unchanged()` (pins, job pins, env sha, no up, no re-pin backups) in every refusal case.
- Pins restored on rollback: test_failed_switch_rolls_back_to_previous_pins, test_postcheck_failure_rolls_back, test_job_ref_unresolved_after_switch_rolls_back.
- Behavioural guard evidence (transcription refused while MP4 still runs) on the real dispatcher, from the 1373 work, REALLY_TESTED on t2-dev with real docker: w9cce3d7b822 (all 4 profiles, 0 mismatches, the held refusal still fires), w276c9ce4c41 (the held refusal is the same with -e or --env-file). The live check of the deployed guard stays PENDING_REAL_TEST p16136-ac4-real-guard, in the landing window.

## Evidence (t2-dev)
Layout: the tests expect a bugtracker checkout's tools/ at config/tools (uncommitted symlink to a bugtracker checkout, not part of the PR) and use it as BT.
```
$ cd config/goodqa-release/bin && pytest -q -p no:cacheprovider -rs test_rw_ship_selfhost.py test_rw_release_authority_d2.py   (at 8085f29e)
SKIPPED [1] test_rw_ship_selfhost.py:1073: real docker compose run: set RW_REAL_COMPOSE=1 (t2-dev)
198 passed, 1 skipped in 391.29s
exit 0
$ RW_REAL_COMPOSE=1 pytest -q test_rw_ship_selfhost.py -k real_compose
2 passed
exit 0
```
Before (v5 head 52fed569): the staged file had 32 tests, all with SELFHOST_JOB_HOLD=none; no guard-held-support, guard-old-timeout, guard-log-missing or resolved-drop-held case ran.

Broken variants of the staged runtime (f2_variants.sh: edit one committed file, run the named tests, restore from git; "restored clean" at the end):
```
V1 guard probe ignored (whole-image hold always)       -k transcribe_hold                     -> 1 failed, 3 passed
V2 guard startup log not checked                       -k guard_not_reporting                 -> 1 failed
V3 no default hold (default none)                      -k "default_holds or held_kind_never_starts or held_value_never_reaches" -> 2 failed, 1 passed
V4 held keys left out of resolved parity               -k "resolved_compose_dropping or held_key_pin_passes" -> 1 failed, 1 passed
V5 JOB_IMAGE key under labels accepted                 -k job_key_under_labels                -> 2 failed
V6 probe timeout (rc 124) counted as support           -k old_guard_that_just_listens         -> 1 failed
```
F1 evidence (bugtracker, the bound code):
```
new F1 tests on the pre-fix ctl (63bcdc50 and 5eafc9a0)  -> 27 failed (DID NOT RAISE, default-config root measured, rc 0 not 11)
pytest -q test_rw_ship_selfhost.py -k "f1_ or vm_disk or unresolved_containerd or measures_dockers"   (5daddbbf, 51ae3d52) -> 47 passed
mutants M1 holder count, M2 default disagreement, M3 dockerd count, M4 section stop, M5 two sockets, M6 imports, M7 root exists, M8 as-root refusal, M9 no-holder refusal -> each fails at least one test
pytest -q test_rw_ship_selfhost.py test_rw_release_authority_d2.py test_selfhost_ctl.py test_selfhost_ctl_gate.py test_selfhost_ctl_job_secrets.py test_rw_ship_jobsecret_gate.py   (gate f6e45adc) -> 1843 passed, 1 skipped
```
Earlier in this PR, unchanged here: test_rw_authority.py has 2 failures that also fail at base 1786659b (a lane-harness rw version mismatch: "manual release registration row is absent or ambiguous"); keyed test 4 passed; unit 15 OK.

## Not exercised (disclosed)
- The bound path in the fixture (ship.conf has no RELEASE_BINDING; runs log UNBOUND). The binding bytes are checked by the byte-equality table and the d2 tests.
- The real VM: Docker version, containerd layout, and the deployed guard. If the VM layout is ambiguous the gate refuses every release with exit 11 and a named reason; nothing is measured on the VM by an agent.
- goodqa#16221 (epoch "No such file" log noise) is unchanged.

## Process notes
- Repo-local git identity on the t2-dev clone, copied from the bugtracker checkout (as in v5).
- Nothing is merged, tagged or deployed.

## Delta diff (52fed569..8085f29e)
