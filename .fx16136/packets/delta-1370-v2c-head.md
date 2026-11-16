# PR review packet v2c (delta only): PR #1370, receipt pr1370-v2b BLOCK fixes F1, F2, F3

Tickets: GoodQA goodqa#16136. Base failures that this diff does not cover are tracked in goodqa#16208.
Source: main's exact-head receipt receipts/bugtracker-pr1370-v2b.md, BLOCK, with three material fail-open findings.

Repo: ericmacdougall/bugtracker
Reviewed before: #1370 at c1d221810a20926ddc869ad010b10faea8a4c4d5 (fix/16136-job-images-rh), packet v2b
Expected HEAD: 6c187f88018ed4f0f75e001210cd1f09f976f0db (fast-forward)

Commits in this delta:
- 86f0f898bba80cc26cdee9d831c6ac542a234423 fix(release-harness): keep unusable AC-13 times untimed, finite only (F1, F2)
- 6c187f88018ed4f0f75e001210cd1f09f976f0db fix(release-harness): require two-string DriverStatus rows (F3)

## Claims to verify
1. **F1 (ac13-count.py, the paired-completion branch).** When a launch completion's time is unusable, the unknown record keeps None, never the start time. An untimed unknown always counts, so a start before --since followed by a 500 completion with no usable time now gives INCONCLUSIVE (exit 1). When only the status is unusable, the record keeps its own usable completion time, so outside the window it is still ignored.
2. **F2 (`num()`).** A time must be a finite int or float, and never a bool. `math.isfinite` rejects NaN, Infinity, -Infinity and 1e999 (json.loads gives inf), so each of them becomes None, an untimed unknown. The rule applies to paired completions ('invalid status or time'), orphan completions ('orphan completion') and unfinished launches ('no completion'). A 2xx with a NaN time is never counted as an in-window ok.
3. **F3 (`store_is_containerd`).** Every DriverStatus row must be exactly `[name, value]`, two strings. `[[]]`, a one-element row, a three-element row, and a short row after a good one all raise Refused. Each negative case names `io.containerd.snapshotter`, so a lax check would read it as containerd and ship. The refusal reaches both the VM disk gate (rw-ship exit 11 'VM image store: unresolved') and `pin` (rc 3, nothing changed). A real classic store still gets 'is not containerd'.
4. No earlier assertion is changed or removed. The four F3 cases are added to the existing DISCOVERY_FAILURES list, which parametrizes both the disk test and the pin test.

## Evidence (t2-dev), commit-bound
Fail first: the new tests against the c1d22181 sources.
```
$ pytest -q test_ac13_count.py
FAILED test_ac13_count.py::test_unusable_completion_time_is_untimed_not_the_start_time
FAILED test_ac13_count.py::test_non_finite_times_are_untimed_unknowns
2 failed, 16 passed in 1.60s
$ pytest -q test_rw_ship_selfhost.py -k "cannot_be_discovered or classic_store"
FAILED ...test_vm_disk_refuses_when_the_store_cannot_be_discovered[empty-row-[[]]]
FAILED ...test_vm_disk_refuses_when_the_store_cannot_be_discovered[one-element-...]
FAILED ...test_vm_disk_refuses_when_the_store_cannot_be_discovered[three-element-...]
FAILED ...test_vm_disk_refuses_when_the_store_cannot_be_discovered[short-after-good-...]
FAILED ...test_ctl_pin_refuses_when_the_store_cannot_be_discovered[empty-row|one-element|three-element|short-after-good]  (4)
8 failed, 16 passed, 125 deselected in 25.47s
```
At HEAD 6c187f88:
```
$ pytest -q test_ac13_count.py
18 passed in 2.02s
exit 0
$ pytest -q test_rw_ship_selfhost.py -k "cannot_be_discovered or classic_store"
24 passed, 125 deselected in 22.10s
exit 0
```
Broken variants, each applied to the HEAD source and then restored with `cmp`:
```
V1 start-time fallback restored (t if t is not None else t_in)   test_ac13_count.py  -> 2 failed, 16 passed
V2 math.isfinite dropped from num()                               test_ac13_count.py  -> 1 failed, 17 passed
V3 row length check dropped (any-length string rows)              store -k subset     -> 8 failed, 16 passed
```
Regression at HEAD (34G free on t2-dev):
```
$ pytest -q test_ac13_count.py test_rw_ship_selfhost.py test_rw_release_authority_d2.py test_install_d2_upgrade.py
5 failed, 237 passed, 1 skipped in 523.60s
```
All 5 failures are pre-existing base failures, tracked in goodqa#16208 and present at c1d22181 and at the base b3604eae: the 4 ThroughputProcess tests and the d2 PIN2 test. No other test fails. test_selfhost_ctl.py (the 940, also #16208) is not in this run.

Follow-up: 1371 and the gate branch fix/16148-rwship-gate carry the same ac13-count.py and store_is_containerd code. These fixes, with the v2 F1, F2 and 73-F1 fixes, are ported there next and sent in the gate packet.

## Delta diff (c1d22181..6c187f88)
