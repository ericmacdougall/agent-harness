The 1370 v2c receipt (receipts/bugtracker-pr1370-v2c.md, PASS) raised one Low, non-blocking finding, F1. In infra/release-harness/ac13-count.py `num()`, `math.isfinite(v)` converts an int to a float. A JSON integer time too large for a float (for example 1 followed by 400 zeroes) therefore raises OverflowError, and the tool prints a traceback instead of its documented JSON verdict. It still exits non-zero, so it does not pass, but it gives no structured verdict.

Where: the rh line, fix/16136-job-images-rh and its PR #1370. That PR merged at 2026-11-16T05:49:30Z at head 6c187f88018ed4f0f75e001210cd1f09f976f0db, so the merged rh code still carries the finding.

Fixed on the gate line: commit 679c278a1aad04dadddc53d9ae76722173161661 on fix/16148-rwship-gate (goodqa#16148), "fix(release-harness): bound AC-13 integer times, no traceback".
- An int is a time only within +-2**53 epoch ms; anything else is an untimed unknown.
- Floats still need math.isfinite.
- A test fails on the old code with a traceback and passes after. A broken variant that accepts an unbounded int fails it.

To do on the rh line: port that commit (ac13-count.py and test_ac13_count.py; they were byte-identical to the gate before it). The rh line is release-bound, so it needs its own receipt and a new release tag; existing tags do not move.

Refs: goodqa#16136, goodqa#16148.
