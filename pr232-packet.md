# PR review packet: ah guard-selftest, a sanctioned live self-test for guard rules (agent-harness PR 232, GoodQA goodqa#15876)

Base: 83b993d9bd7db33e60e62d3cbe3ceffbd642a621 (origin/main, the merge of PR 231, and the merge base; use `--snapshot-base 83b993d9bd7db33e60e62d3cbe3ceffbd642a621`). Head: 7bf3473c8646349124331d9689ba626d75c464af (branch af9e-guard-selftest). Claude-authored: `--author-harness claude`.
Changed code paths: harness/hooks/guard_selftest.py (new), harness/hooks/ah.py (guard-selftest intercept at the start of `main()`), install.py and install_codex.py (file lists), tests/test_guard_selftest.py (new), tests/mutants_guard_selftest.py (new), notes/goodqa-15876/ (spec.md, review-opus.md, review-sonnet.md).

## Outcome
goodqa#15787's live step (does the bulk staging guard speak through the real hook under worktree isolation) could not be run because the isolation guard refuses the command text. `ah guard-selftest --rule bulk_staging --expect-manifest M --expect-policy absent|SHA` runs a fixed table of 7 cases through the real hook launcher against throwaway repositories and reports PASS or FAIL per case, with no caller-supplied command text.

## Design (read guard_selftest.py)
- No caller text reaches a command: the case table is code, each command is only the hook's JSON payload, every child is an argv list without a shell, with a fixed environment (PATH, HOME, LANG) and `python -I`; git is the first regular file owned by root or the user among three fixed paths. The parser has no abbreviations and no help; every error is a refusal (exit 3).
- D2: the CLI refuses unless the module directory is the installed `~/.claude/hooks` (so a worktree copy is refused).
- D6 pin: the manifest is the git blob ids of a reviewed list (`PINNED`: command_guard.py, command_guard_hook.py, guard_selftest.py, redact.py, safe_input.py), compared with `--expect-manifest` (sha256 of sorted `NAME BLOB` lines); the policy file is pinned separately (`--expect-policy`; a symlink or non-regular file is refused). Review H1 narrowed this from an import-and-literal closure (57 files, unsatisfiable on a host with unrelated differences) to the files the table's hook runs load; Sonnet verified the load set by running all cases in both modes and listing the modules loaded from the hooks directory, and compared blobs on t2-dev. Stated limit: a future lazy import on a tested path would not be pinned.
- D3 channels, each case: warn = exit 0, stdout JSON `hookSpecificOutput.additionalContext` containing `[bulk_staging/bulk-staging]`; enforce = exit 2 with the finding on stderr; allow = exit 0 with stdout and stderr both empty (so the launcher's crash/timeout fallback note fails the case); a timeout (20 s) fails.
- Cleanup: a private 0700 owner-checked parent `~/.agent-harness/tmp` (TMPDIR ignored); the run directory is opened with O_NOFOLLOW, its device and inode are checked against the entry before removal, and removal is descriptor-relative, unlinking symlinks without following; a swap makes the cleanup refuse. An audit row (`~/.agent-harness/guard-selftest-audit.jsonl`, 0600, O_NOFOLLOW, values bounded to 80 printable characters) is written in a finally.
- Exit codes: 0 all cases pass, 1 a case failed, 3 refused (bad arguments, wrong install, hash mismatch), 4 setup failed (no trusted git, private directory unusable, subprocess or OSError during setup).
- ah.py imports the module lazily from its own directory; a missing module prints a JSON "not installed" message with exit 4.

## Spec, reviews, decisions
Spec attached to goodqa#15876 (comment 23df5e01). Spec reviews: Opus BLOCK then ACCEPT, Sonnet BLOCK then ACCEPT at 5dbe780f (reports in notes/goodqa-15876/). Code reviews: Opus (adversarial) ACCEPT at e2e6e48b with lows L1 OSError escaping as a traceback (fixed), L3 own blob not reported (fixed by pinning guard_selftest.py), L2 argument refusals write no audit row, L4 default mode hard-coded warn, L5 check that no other guard rule speaks on quiet cases under the real home (to be settled by the live run). Sonnet (acceptance) BLOCK H1 at e2e6e48b (manifest too broad), fixed, then ACCEPT at 7bf3473c (delta) with the policy-symlink low fixed. Stage acceptances, not PR signoff.
Decision D1 (owner assumption, Main to confirm): the caller names the expected manifest hash taken from the MERGED commit (git blob ids of the five pinned files at the merge commit), never from the installed files, and the REALLY_TESTED row carries the merge sha.
Stated limits: TOCTOU between the manifest read and the hook run (D4); the byte-for-byte install assumption (D7); lows L2 and L4 (ticket to be filed).

## Failing-first and risk table
`python3 -B -m unittest tests.test_guard_selftest`: 38 tests, including real hook runs (warn and enforce) against real temporary repositories, crashing, garbage-printing and hanging analyser variants that must fail every case, a swapped run directory, symlinks inside, malformed arguments and hash text (`; touch`, `$(id)`, traversal), a policy symlink and an OSError in setup. `python3 -B tests/mutants_guard_selftest.py`: origin/main (no module) and 21 controlled broken variants each fail the tests (22 of 22, none vacuous, none "not applied"): installed-copy check removed (run and print-manifest), manifest check removed, policy check removed, unknown mode guessed, identity check before removal removed, symlink followed, private parent unchecked, abbreviations accepted, environment inherited, table not compared, timeout counted as pass, stderr ignored in a quiet or warn case, enforce not mode aware, audit values unbounded, child started without -I, this tool not pinned, policy symlink read as absent, OSError escaping, cleanup skipped on error. Highest-risk cases: arbitrary text reaching a command, deleting something not created, a false PASS (fallback note, timeout, wrong channel, missing pinned file).

Risk and rollback: revert the commit; the tool is read-only against the guard and writes only inside its own temp directory and the audit file. It is shipped by the install file lists; removing it from the lists and deleting the file reverts.

## Validation (exact head 7bf3473c8646349124331d9689ba626d75c464af, run in the owner worktree)
$ python3 -B -m unittest tests.test_guard_selftest
Ran 38 tests in 42.8s
OK
$ python3 -B tests/mutants_guard_selftest.py
origin/main (no module) FAILS (good); all 21 broken variants FAILS (good); none PASSES, none NOT APPLIED; exit 0
$ python3 -B -m unittest tests.test_ah_install tests.test_command_guard_bulk_staging tests.test_command_guard_install_files tests.test_ah_worktree_remove
Ran 128 tests
OK (skipped=1)
exit 0
