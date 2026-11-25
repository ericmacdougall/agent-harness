"""goodqa#16811 round 1 (F2): a review-auth stamp lives only as long as the review run it was minted for.

peer_review.py takes main's stamp right after parsing its arguments, so a run that exits early (here a HEAD
mismatch) leaves nothing for a later process to take; and a stamp older than REVIEW_STAMP_TTL_SECONDS was left by
a run that never started, so it is never honoured. Before this change the stamp was taken only after the PR binding
was verified and lived 600 s, so a subagent's bound run could take a stamp a failed main run left behind.

The repository, PR and providers are local fixtures (test_review_merge_authorization's end-to-end setup).
"""
import sys
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "harness" / "hooks"))
sys.path.insert(0, str(HERE))
import caller_identity  # noqa: E402
import test_review_merge_authorization as e2e  # noqa: E402


class StampLifetime(unittest.TestCase):
    setUp = e2e.EndToEndTests.setUp
    fake = e2e.EndToEndTests.fake
    run_review = e2e.EndToEndTests.run_review

    def stamp(self, age=0):
        caller_identity.put_stamp("review-auth", ["o/r", 5], home=self.root, now=time.time() - age)

    def left(self):
        return caller_identity.take_stamp("review-auth", ["o/r", 5], home=self.root)

    def test_a_run_that_exits_early_consumes_the_stamp(self):
        self.stamp()
        self.head, real = "b" * 40, self.head  # --expected-head no longer matches the repo
        try:
            result = self.run_review("--author-harness", "claude")
        finally:
            self.head = real
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("repo HEAD differs from --expected-head", result.stderr)
        self.assertIsNone(self.left(), "the failed run took the stamp, so no later run can")

    def test_a_usage_error_consumes_the_stamp_too(self):
        self.stamp()
        result = self.run_review("--reviewer", "codex-only", "--secondary", "kimi")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIsNone(self.left())

    def test_an_argparse_refusal_consumes_the_stamp_too(self):
        # argparse exits inside parse_args, before the take that follows it.
        for extra in (("--no-such-option",), ("--author-harness", "nobody"), ("--help",)):
            with self.subTest(extra=extra):
                self.stamp()
                result = self.run_review(*extra)
                self.assertIn(result.returncode, (0, 2), result.stdout + result.stderr)
                self.assertIsNone(self.left(), extra)

    def test_an_argparse_refusal_with_no_main_stamp_leaves_the_stamp(self):
        # Control: the opt-out holds on the refusal path too.
        self.stamp()
        result = self.run_review("--no-main-stamp", "--no-such-option")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIsNotNone(self.left())

    def test_a_stamp_older_than_the_review_window_is_not_honoured(self):
        self.stamp(age=300)
        result = self.run_review("--author-harness", "claude")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("Merge authorization:", result.stdout)
        self.assertIn("no main-agent stamp", result.stderr)
        self.assertIn("honoured only within 120 s", result.stderr)

    def test_a_fresh_stamp_still_authorizes(self):
        # Control: the same run with a stamp minted now authorizes the merge and consumes the stamp.
        self.stamp(age=5)
        result = self.run_review("--author-harness", "claude")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Merge authorization:", result.stdout)
        self.assertIsNone(self.left())

    def test_no_main_stamp_never_touches_the_stamp_even_when_the_run_fails(self):
        # Control (goodqa#16049): the ahc daemon's run neither takes nor burns main's stamp.
        self.stamp()
        self.head, real = "b" * 40, self.head
        try:
            result = self.run_review("--no-main-stamp")
        finally:
            self.head = real
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIsNotNone(self.left())


if __name__ == "__main__":
    unittest.main()
