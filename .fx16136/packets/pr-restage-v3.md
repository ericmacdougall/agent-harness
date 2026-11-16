# PR review packet v3: bugtracker-harness restage of the job-image runtime (goodqa#16136; review bth-pr73-v1 F1, F2, F3)

Ticket: GoodQA goodqa#16136
Repo: ericmacdougall/bugtracker-harness (the lane harness), branch fix/16136-job-images, draft PR #73
Base: 1786659bb29d39c8facf1b2ed88fdd8d45d4845d (origin/main)
Expected HEAD: 19cb8368bc4c658e9d0b652b1e2feaa8ca697274
Supersedes: pr-restage-v2.md (8ac52be8, at 6c7a0aa8) and pr-restage.md (8decaa66, BLOCK in bth-pr73-v1)

Commits (base..HEAD):
- 82b0fb2a9c5a: restage at bugtracker c6b303ae
- 6c7a0aa8d821: restage at bugtracker be8623fd8db6 (review F1/F2) and rebind
- 19cb8368bc4c: rebind to bugtracker 04dd4b1f6dcf (tag release-16136-rh3; test-only fast-forward on be8623fd8db6). RELEASE_BINDING line 2 only; staged scripts and all five hashes unchanged

Upstream: bugtracker 04dd4b1f6dcf3886af945a81b5a61286349da060, tag release-16136-rh3, PR #1370 (full packet pr-rh-v3.md, sha256 59ca711e…). This packet covers byte equality, the binding and behaviour evidence on these exact bytes.

## Scope
Three files:
- config/goodqa-release/bin/rw-ship.sh
- config/goodqa-release/bin/selfhost-ctl.py
- config/goodqa-release/bin/RELEASE_BINDING

## Review findings
- F1 (accepted hold value could release a kind) and F2 (VM disk gate on the wrong filesystem, no incoming-size term): fixed upstream in be8623fd8db6, so the staged bytes carry the fix. See pr-rh-v2.md, claims 11 and 12.
- F3 (no behaviour or upstream-equality evidence): see the next two sections.
- Correction to v1: v1 said ship.conf had no RELEASE_BINDING. That was wrong. The committed config/goodqa-release/biz/release-waves/ship.conf (line 15), and the installed ~/repos/harness on t2-dev, both set RELEASE_BINDING=/home/eric/repos/harness/config/goodqa-release/bin/RELEASE_BINDING. The binding is enforced, and the UNBOUND line I saw came from the test fixture.

## F3a: upstream byte equality (t2-dev)
Command at 19cb8368: sha256 and `git hash-object` of each staged file next to `git -C bugtracker show 04dd4b1f6dcf:infra/release-harness/<f> | sha256sum` and `git rev-parse 04dd4b1f6dcf:<path>`, and the RELEASE_BINDING line.

| Staged file | staged = upstream = binding sha256 | git blob (staged = upstream at 04dd4b1f) |
|---|---|---|
| bin/rw-runtime.sh | 2107e0bbd2736bbd462d79e6294223b734ee5f561dca61f5beaf76323a853de1 | 3070e6a3de5d |
| bin/rw-ship.sh | 59031330db3310a645339fe2549e453254cc04d1bfaab6e3ef0c63a22234c5c9 | 62adfed7cc9d |
| bin/selfhost-ctl.py | 9c8f4704f3980e1f5bf8d35d6af92896500df5a60412f553ed7412744f28f398 | 56b09ac7fd57 |
| bin/rw-rollback.sh | 2fc968e3eb29f07e700bc9d62c618b8f9674c5746da62451d848023de63737c7 | 59f34a89a1a1 |
| biz/prod-db-pool-20261013/ship-fast.sh | a812832784af69ba76126e13edaf25de770995528d46ad704956649bfaee942a | 37f769161902 |

All five rows are EQUAL. The binding names commit 04dd4b1f6dcf3886af945a81b5a61286349da060, path infra/release-harness, and keeps its seven-line format.

## F3b: behaviour on these exact bytes (t2-dev)
The staged rw-ship.sh and selfhost-ctl.py blobs are unchanged from 6c7a0aa8 (62adfed7, 56b09ac7), and `cmp` against the bugtracker worktree file reports identical for both. 04dd4b1f changes only the test file. The upstream suite then ran the real rw-ship.sh end to end on those bytes, with the real selfhost-ctl.py on a fake VM: stub ssh, sudo, docker, containerd and df.

```
$ RW_REAL_COMPOSE=1 python -m pytest -q -rA -p no:cacheprovider infra/release-harness/test_rw_ship_selfhost.py -k "job or hold or guard or transcribe or vm_disk or real_compose" --deselect <4 baseline ThroughputProcess tests>
59 passed, 40 deselected in 108.80s (0:01:48)
pytest exit 0
```

The 59 tests passed cover:
- **Job-image build, load and pin:** test_selfhost_release_ships_job_images, test_job_images_build_failure_changes_nothing, test_job_images_id_mismatch_after_transfer_refuses, test_job_ref_unresolved_after_switch_rolls_back, and the ctl pin refusals (9 variants plus 4 missing-image variants).
- **Holds:**
  - test_default_holds_intelligence_worker, test_bad_job_hold_value_refuses_before_building and test_canonical_job_hold_holds_every_named_kind;
  - all ten non-canonical F1 values;
  - test_held_line_marked_and_excluded_from_jobs_missing.
- **Guard probe and fallback:** test_transcribe_hold_with_guard_support_pins_transcode, test_transcribe_hold_without_guard_support_holds_transcode, test_transcribe_hold_string_present_behaviour_absent_holds_transcode, test_guard_not_reporting_hold_after_switch_rolls_back, and the guard-hold refusals.
- **Containerd and VM disk:**
  - test_vm_disk_low_stops_before_transfer;
  - each root full while the other has room;
  - containerd root unresolved, both variants;
  - a failed stat;
  - 2 x incoming bytes;
  - an unreadable size;
  - roots reported.
- **Rollback and restore:** test_restore_warns_jobs_down_and_never_runs_presence_check.
- **Real compose:** test_real_compose_resolves_anchor_for_both_services.

This subset ran at be8623fd. The scripts are identical at 04dd4b1f, and the full suite at 04dd4b1f gave 95 passed, exit 0 (pr-rh-v3.md). Without the deselect, the same filter gives 2 failed and 59 passed. The 2 failures are baseline ThroughputProcess tests (api_only_boundary_refusal, receipt_changed_after_qualification) that fail identically at base b3604eae.

Full upstream suite at be8623fd, baseline deselected: 95 passed, exit 0 (pr-rh-v2.md).

Real built-image guard probe (pr-rh-v2.md):
- guard built from #1369: rc=1 with the GUARD_HELD_ENV message;
- guard built from main: rc=124, so the whole transcode image is held.

## Harness suites (t2-dev, at 19cb8368)

```
$ python -B -m pytest -q -p no:cacheprovider bin/test_goodqa_staged_rw_ship_keyed.py
4 passed in 15.56s
keyed exit 0
```

```
$ python -B bin/test-goodqa-release-unit.py
Ran 15 tests in 2.606s
OK
unit exit 0
```

## Risks
- **Binding enforced:** a release from this lane needs 04dd4b1f6dcf in /home/eric/repos/bugtracker. The tag release-16136-rh3 pins it on origin, so fetch it before the release.
- **Pinned upstream commit:** the old binding named 5a78109, which no remote ref holds (goodqa#16146). It is now 04dd4b1f, which tag rh3 pins.
- **Prod VM disk gate (F2 rule, max(floor, 2 x loaded bytes)):**
  - Prod has 171 GiB free on / (179830844 KiB, read-only `df -Pk /`). /var/lib/docker and /var/lib/containerd are both on /.
  - The current app images are api 2248015480, web 513956149 and job-dispatcher 656458500 bytes: 3.42 GB in all.
  - The four job images were not built for this measurement. t2-dev has 42G free, and the 30G floor leaves no room for the build; the release archive alone is 1.89 GB.
  - ASSUMPTION, a bound and not a measurement: scan, intelligence-worker and suggest-fix-worker are pnpm-filtered node:22-slim images comparable to the 0.66 GB dispatcher, so at most 2 GB each. The transcoder does `COPY .` of the 1.89 GB context plus a full install, so at most 6 GB.
  - Under that bound the load is at most about 15.4 GB, so the gate needs about 31 GiB against 171 GiB free. It passes.
  - The gate would refuse only if the seven images together exceeded about 85 GB.
  - At deploy time, rw-ship logs the exact need ("VM image store: …; need NG") and refuses before any load if it is short (exit 11, nothing switched).
  - The measurement is PENDING_REAL_TEST ac1-build-time, the same build run.
- **Staged test copy:** the staged copy of test_rw_ship_selfhost.py is left unchanged. The reviewed tests live in the bound commit.
- **Deploy:** only through the release runner after merge, on main's authorization, in the same release as bugtracker PR #1369.
