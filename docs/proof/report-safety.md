# Report output safety proof

Baseline: merged `main` commit `19b35d0f439fb1abfe44db91c8e5bf00a67e8e3b`. The six regression tests below were copied from the candidate branch into a disposable archive of that baseline. They use disposable Git repositories, model stubs, and fixture files. The baseline run exited **1**, with six failures. Its sanitized transcript is [report-safety-baseline.txt](report-safety-baseline.txt). No production or user files were used.

Reproduce the failure-first run from a checkout containing the new tests:

```sh
BASELINE_DIR=$(mktemp -d)
git archive 19b35d0f439fb1abfe44db91c8e5bf00a67e8e3b | tar -x -C "$BASELINE_DIR"
cp tests/test_peer_review.py tests/test_rescue.py "$BASELINE_DIR/tests/"
cd "$BASELINE_DIR"
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest \
  tests.test_peer_review.PeerReviewTests.test_existing_unrelated_file_outside_repo_is_not_deleted \
  tests.test_peer_review.PeerReviewTests.test_file_created_during_review_is_not_overwritten \
  tests.test_peer_review.PeerReviewTests.test_relocated_report_directory_cannot_yield_false_signoff \
  tests.test_rescue.RescueTests.test_existing_unrelated_file_outside_repo_is_not_deleted \
  tests.test_rescue.RescueTests.test_file_created_during_rescue_is_not_overwritten \
  tests.test_rescue.RescueTests.test_relocated_report_directory_preserves_replacement_after_rescue_edits -v
```

On the repaired branch, `PYTHONDONTWRITEBYTECODE=1 /opt/homebrew/bin/python3 -W error::ResourceWarning -m unittest discover -s tests -v` exited **0**, with **129/129** passing on macOS, Python 3.15.0, in 116.064 seconds. The complete transcript is [report-safety-python315.txt](report-safety-python315.txt). The same full command with `python3` (Python 3.9.6) exited **0** with **129/129** in 95.603 seconds as a supplemental compatibility check; see [report-safety-python39.txt](report-safety-python39.txt). Focused peer-review and rescue tests passed **39/39**. `python3 -X pycache_prefix=/tmp/agent-harness-report-safety-pycache -m compileall -q install.py harness tests` and `git diff --check` passed.

The two directory-relocation regressions failed on the baseline with misleading success responses. A third deterministic test moves the report directory immediately after the exclusive link and checks that the helper detects the mismatch. Sol's second review found that trying to remove the unadvertised report after an inode check could delete a file substituted between that check and `unlink()`. The third test was tightened to forbid any unlink of the public destination; it failed against pre-fix commit `d199a7e` with exit **1** and passes after removing that cleanup. See the sanitized [cleanup failure transcript](report-safety-cleanup-failure.txt). The helper returns a nonzero result and leaves an unadvertised artifact for inspection if relocation happens after publication. The rescue tests perform an edit before the report collision and require an error directing the operator to inspect the worktree.
