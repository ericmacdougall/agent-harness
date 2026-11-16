# PR review packet v2c (delta only): PR #1370, receipt pr1370-v2b BLOCK fixes F1, F2, F3

Tickets: GoodQA goodqa#16136. Base failures that this diff does not cover are tracked in goodqa#16208.
Source: main's exact-head receipt receipts/bugtracker-pr1370-v2b.md, BLOCK, with three material fail-open findings.

Repo: ericmacdougall/bugtracker
Reviewed before: #1370 at c1d221810a20926ddc869ad010b10faea8a4c4d5 (fix/16136-job-images-rh), packet v2b
Expected HEAD: __HEAD__ (fast-forward)

Commits in this delta:
__COMMITS__

## Claims to verify
1. **F1 (ac13-count.py, the paired-completion branch).** When a launch completion's time is unusable, the unknown record keeps None, never the start time. An untimed unknown always counts, so a start before --since followed by a 500 completion with no usable time now gives INCONCLUSIVE (exit 1). When only the status is unusable, the record keeps its own usable completion time, so outside the window it is still ignored.
2. **F2 (`num()`).** A time must be a finite int or float, and never a bool. `math.isfinite` rejects NaN, Infinity, -Infinity and 1e999 (json.loads gives inf), so each of them becomes None, an untimed unknown. The rule applies to paired completions ('invalid status or time'), orphan completions ('orphan completion') and unfinished launches ('no completion'). A 2xx with a NaN time is never counted as an in-window ok.
3. **F3 (`store_is_containerd`).** Every DriverStatus row must be exactly `[name, value]`, two strings. `[[]]`, a one-element row, a three-element row, and a short row after a good one all raise Refused. Each negative case names `io.containerd.snapshotter`, so a lax check would read it as containerd and ship. The refusal reaches both the VM disk gate (rw-ship exit 11 'VM image store: unresolved') and `pin` (rc 3, nothing changed). A real classic store still gets 'is not containerd'.
4. No earlier assertion is changed or removed. The four F3 cases are added to the existing DISCOVERY_FAILURES list, which parametrizes both the disk test and the pin test.

## Evidence (t2-dev), commit-bound
__EVIDENCE__

## Delta diff (c1d22181..__SHORT__)
