"""goodqa#15253 item 1: a fresh, settled peer_review PR ACCEPT receipt for the exact head acts as a single-use waiver
of the merge gate's soft (CI) reasons, for the main agent only. Hard reasons (head binding) still block.
"""
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from test_merge_gate import HEAD, OTHER, Base, mg  # noqa: E402
import usage_guard as guard  # noqa: E402


class ReceiptWaiver(Base):
    CMD = "gh pr merge 5 --match-head-commit {HEAD}"

    def setUp(self):
        super().setUp()
        self.usage = Path(tempfile.mkdtemp(prefix="mg-usage-"))
        self.addCleanup(__import__("shutil").rmtree, self.usage, True)
        env = mock.patch.dict(os.environ, {"AGENT_HARNESS_USAGE_DIR": str(self.usage / "store")})
        env.start()
        self.addCleanup(env.stop)
        self.repo = self.usage / "repo"
        self.repo.mkdir()

    def receipt(self, head=HEAD, stage="PR", verdict="ACCEPT", settle=True):
        store = guard.UsageStore()
        self.n = getattr(self, "n", 0) + 1
        subject = guard.Subject(schema=1, fingerprint="%064x" % self.n, reusable=True, head=head, tree="c" * 40)
        subject.repo, subject.manifest = self.repo, {}
        subject.probe = lambda: subject
        identity = guard.invocation_identity(subject, purpose="review", argv=["peer_review", str(self.n)], cwd=self.repo)
        run = store.begin(subject, identity, owner="fixture", label="review", timeout=10, kind="review",
                          minimum_bytes=0)
        passed = verdict == "ACCEPT"
        reference = run.finish(execution="COMPLETED", result="CHECK_OK" if passed else "CHECK_FAILED",
                               reason="NONE" if passed else "CODE_FINDINGS", exit_code=0,
                               review={"stage": stage, "verdict": verdict, "findings": [] if passed else ["F1"]})
        if settle:
            store.settle_review(reference)
        return reference

    def test_settled_pr_pass_for_the_head_waives_red_checks_once(self):
        code, text, _ = self.decide(self.CMD, "red_netwatch")
        self.assertEqual(code, 2, text)  # control: no receipt, red checks block
        self.receipt()
        code, text, _ = self.decide(self.CMD, "red_netwatch")
        self.assertEqual(code, 0, text)
        code, text, _ = self.decide(self.CMD, "red_netwatch")
        self.assertEqual(code, 2, "a receipt is single use: " + text)
        self.assertIn("receipt", mg.report_text(self.state))

    def test_receipts_that_do_not_qualify(self):
        for name, kwargs in (("other head", {"head": OTHER}), ("code inspection", {"stage": "CODE_INSPECTION"}),
                             ("block", {"verdict": "BLOCK"}), ("not settled", {"settle": False})):
            with self.subTest(name):
                self.receipt(**kwargs)
                code, text, _ = self.decide(self.CMD, "red_netwatch")
                self.assertEqual(code, 2, text)

    def test_subagents_and_stale_receipts_get_no_waiver(self):
        self.receipt()
        code, text, _ = self.decide(self.CMD, "red_netwatch", agent_id="owner-1")
        self.assertEqual(code, 2, text)
        gh = __import__("test_merge_gate").FakeGh(__import__("test_merge_gate").SCENARIOS["red_netwatch"])
        code, text = mg.decide(__import__("test_merge_gate").bash(self.CMD.replace("{HEAD}", HEAD)), gh, self.state,
                               now=time.time() + mg.WAIVER_TTL_SECONDS + 60)
        self.assertEqual(code, 2, text)

    def test_head_binding_is_still_required(self):
        self.receipt()
        code, text, _ = self.decide("gh pr merge 5", "red_netwatch")
        self.assertEqual(code, 2, text)


if __name__ == "__main__":
    unittest.main()
