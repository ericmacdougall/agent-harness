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

Code head for this round: 8fd0e309513f99bcdab2dbdfedcba1396368441c. Later commits change only `notes/goodqa-15946/`;
check the logs against any later head with `git rev-parse <head>:harness <head>:tests <head>:install.py` (the trees are
in each log header).

- `r2-failing-first-prefix.txt`: raw `-v` output of the new r2 tests (tests/test_lane_r2.py, tests/test_spec_flow.py
  LaneSpecState) run against the pre-fix code at 6f5ef181: 7 failures and 5 errors, each the defect r2 named.
- `suites-r2-8fd0e309.txt`: raw `-v` unittest output of every touched suite (`run_suites_r2.py`), in a clean clone
  detached at the code head on t2-dev (Linux, Python 3.12), per the heavy-jobs-off-the-Mac rule.
- `run_suites_r2.py`: the runner.
