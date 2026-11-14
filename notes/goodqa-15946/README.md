# Evidence for PR 238 (lane factory slice S1, GoodQA goodqa#15946)

Review base: c82ad2afd3af56c66bee8485924d982452551153 (the full S1 diff is base..head, not a narrower range).
Code head the logs were produced at: a9807c67fe4f7ec3338c1a28438c89b09fb26255. The commit that adds this directory changes
only `notes/goodqa-15946/` (check: `git diff --stat a9807c67fe4f7ec3338c1a28438c89b09fb26255 HEAD`).

Files:
- `spec-39cd576c.md`: the spec (S1 acceptance criteria and negative cases). File sha256
  e42f4d42db40a2890fa502ce7b3fe227a5688420e18c862fd0aa958791f29aef; spec_flow core sha
  39cd576c12d60e25dcad10f3a571d03ffacca7bc833b6b8e452b710e76922a95. Attached to goodqa#15946 (comment 4f681454-6c57-418c-a7a2-013c1c872475).
- `spec-review-adversarial-39cd576c.md`, `spec-review-acceptance-39cd576c.md`: the two spec reviews recorded on that core.
- `suites-a9807c67.txt`: raw output of `run_suites.py` (every lane suite plus tier_gate, ops_watch, install, doctor, backup_watch).
- `mutants-a9807c67.txt`: raw output of `run_mutants.py` (failing-first mutants: M1, root race, manifest source class,
  identity via git exec, double stamp consumption, F1 unproven caller, F2 unchecked worktree path).
- `run_suites.py`, `run_mutants.py`: the scripts (they run in a clean clone detached at the head).

Not covered by this evidence (pending, honestly listed in the PR packet): AC-44 live check on both hosts, the nested-path
remote install check (S1-NESTED-INSTALL), live behaviour of the real ports (ticket adapter, task register, session log
routing, session environment), and the items not implemented (AC-6 stubs, AC-9 installed-digest refusal, NEG-36 plan stub,
refresh authorization, grant lookup).

## Round 2 (review r2 at 6f5ef181; Opus rescue owner)

The round-1 files above (`suites-a9807c67.txt`, `mutants-a9807c67.txt`) are superseded history: they were produced at
a commit outside later review snapshots.

Code head for this round: 0e1bc98ac8f6c86f31823d6911e020e629d6a5ad. Later commits change only `notes/goodqa-15946/`;
check any log against a later head with `git rev-parse <head>:harness <head>:tests <head>:install.py` (each log header
carries the trees).

- `suites-r2-0e1bc98a.txt`: raw `-v` unittest output of all 28 touched suites (`run_suites_r2.py`), clean clone detached
  at the code head on t2-dev (Linux, Python 3.12; the Mac's heavy-job guard refuses the clone).
- `mac-r2-0e1bc98a.txt`: raw `-v` output on the Mac (Python 3.9) of test_lane_r2, LaneSpecState and the wal suites.
- `mutants-r2-0e1bc98a.txt`: raw output of `run_mutants_r2.py`, one mutant per fix (F1 source, F1 bind refusal, F2
  persisted id, F3 ready fallback, F4 dedupe, F4 per-op lock). Each is KILLED, then the restored source passes.
- `r2-failing-first-prefix.txt`: the first 13 new tests run against the pre-fix trees (6f5ef181). 12 of 13 fail (7
  failures, 5 errors); the ungrounded-ticket negative passes there too. Its F1 failure is exit 2 (no session passed),
  so the provenance rejection itself is shown by the F1-source mutant (`exit 3, provenance`).
- `suites-r2-8fd0e309.txt`: the same suites at the intermediate code head 8fd0e309 (superseded by 0e1bc98a).
- `run_suites_r2.py`, `run_mutants_r2.py`: the runners.
