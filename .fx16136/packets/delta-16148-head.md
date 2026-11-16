# PR review packet (delta only): goodqa#16148 code-review fixes F2, F3 and F4 on PRs #1372 and #1373

Ticket: GoodQA goodqa#16148 (also GoodQA goodqa#16185). Source: code review by a5a2642f, PASS with five LOW findings, report .fx16136/review-opus-code-16148.md sha fb747cce. The lead's ruling: fix F2, F3 and F4 in one delta; ticket F1 as goodqa#16195 and F5 as goodqa#16196.
Repo: ericmacdougall/bugtracker
Reviewed before: #1372 at 3b7cde1a97478251ff15dde8c5a9768e7b4e493b, #1373 at 158ec0db4b6b0a9dbb56fdce63a05df97fc1548c
Expected HEAD: 97bfac5172322d3eddc3cf7d43e951421624dd67 (#1373). #1372 is now at c9d61ac1aa3a575781e5e5fc9430bee993be1e86.

Commits in this delta:
- c9d61ac1aa3a (#1372) fix(job-dispatcher): cut the stderr line before the residue scan (F4)
- f29da1848b3 (#1373) fix(selfhost): fail closed on a derive swap; catch clustered -e (F2, F3)
- 97bfac51723 (#1373) merge of fix/16185 at c9d61ac1 into fix/16148. It auto-merged with no conflict, and its diff against f29da184 has the same added and removed lines as c9d61ac1's. Only the hunk line offsets (+3) and blob ids differ, because docker.ts already carried step-2 lines; checked with diff after dropping the index lines.

## Claims to verify
1. F4: in `describeDockerFailure`, after the full-stderr redaction (unchanged), the first line is cut to SCAN_LIMIT 4096 before the prefix, printable and residue scans. The 200-char output is still a prefix of that line.
   - A value fragment inside the first 4096 chars still drops the line.
   - A full value anywhere in stderr is still redacted first.
   - Only a fragment past 4096 is no longer scanned, and it can never reach the output.
2. F2: in `write_secret`, on a post-rename mismatch, `os.unlink(NAME, dir_fd=dfd)` runs before the refusal. It removes the name, never what it points to.
   - In the link case, the sentinel target is untouched, the name is absent, and the next run writes the real file.
   - In the hardlink case, the other file keeps its bytes and the name is absent.
3. F3: `short_flag` reads a single-dash token as pflag reads a shorthand cluster.
   - The booleans d, i, t and P chain.
   - An e at position 0 gives -e(attached), and an e later in the chain gives -e(cluster). Both are BAD.
   - The first value-taking shorthand ends the chain.
   - So -de, -ieK=V and -dite FAIL, while -dit and -wexample do not. No marker window reaches the output.
4. Each fix has a failing-first test, and no earlier test was weakened. The only changed assertion is the old link-case line "refused next time too", which asserted the F2 bug itself. It is replaced by "the name is absent, the next run is written".

## Evidence (t2-dev)
- F4 fail first: on the 3b7cde1a docker.ts with the four new tests, `npx vitest run test/docker-failure-message.test.ts` gives 2 failed and 38 passed. The failures are the 1 MiB case (1909 ms against a 1000 ms bound) and the deterministic case. After the fix: 40 passed. #1372 full suite: 319 passed, 14 skipped; tsc exit 0.
- F2 fail first: `bash infra/selfhost/app/run_derive_tests.sh` with the new assertions and the old source gives, in the root container, FAILED (failures=2): test_temp_swapped_for_a_hardlink_before_rename_is_refused and test_temp_swapped_for_a_link_before_rename_is_refused.
- F3 fail first: `python3 -m unittest test_cmdline_sampler` with the old source gives FAILED (failures=1): test_neg18_clustered_short_flags_with_e_fail.
- Sampler variants rerun at 97bfac51: S1–S4 and the new S5 (e inside a cluster ignored) all FAILED; the file was restored, with 0 changed.

At HEAD 97bfac5172322d3eddc3cf7d43e951421624dd67 (clean, 31G free):

```
$ cd apps/job-dispatcher && timeout 900 npx vitest run
      Tests  363 passed | 14 skipped (377)
exit 0
$ cd apps/job-dispatcher && timeout 600 npx tsc --noEmit
exit 0
$ bash infra/selfhost/app/run_derive_tests.sh
Ran 61 tests in 1.281s
OK (skipped=41)
Ran 61 tests in 3.134s
OK (skipped=2)
exit 0
$ cd infra/selfhost/app && DERIVE_TEST_TMP=$PWD/../../../.scratch timeout 300 python3 -m unittest test_apply_job_secrets_wrapper test_cmdline_sampler
Ran 20 tests in 5.107s
OK
exit 0
$ timeout 300 node --test infra/selfhost-job-secrets-drift.test.mjs infra/selfhost-plan.test.mjs infra/selfhost/app/qa-closure-topology.test.mjs
# pass 23
# fail 0
exit 0
$ timeout 600 $HOME/repos/fx-16136/venv/bin/python -m pytest -q -p no:cacheprovider infra/release-harness/test_selfhost_ctl_job_secrets.py infra/release-harness/test_selfhost_ctl.py
1584 passed in 110.08s (0:01:50)
exit 0
```

## Delta diff (158ec0db..97bfac51: F2, F3 and the merged F4)
