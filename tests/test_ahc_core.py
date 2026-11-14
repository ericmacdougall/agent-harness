"""ahc core: submit validation (AC-1, NEG-1), live PR resolution (AC-2, NEG-2) and receipt verification (AC-5,
NEG-5). Scratch HOME per test, fake gh runner, no network. GoodQA goodqa#16034."""
import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import ahc_core as core  # noqa: E402

HEAD = "a" * 40
BASE = "b" * 40
REPO = "ericmacdougall/agent-harness"


class Fake:
    """gh stand-in: returns the configured PR JSON and records argv."""
    def __init__(self, pr=None, rc=0):
        self.pr, self.rc, self.calls = pr, rc, []

    def __call__(self, argv, timeout):
        self.calls.append(argv)
        return self.rc, json.dumps(self.pr or {}), ""


def live_pr(**over):
    pr = {"number": 7, "state": "OPEN", "headRefOid": HEAD, "baseRefOid": BASE, "baseRefName": "main",
          "isCrossRepository": False}
    pr.update(over)
    return pr


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name)
        self.paths = core.Paths(self.home)
        self.work = self.home / ".agent-harness" / "work" / "s1"
        self.work.mkdir(parents=True)
        self.packet = self.work / "packet.md"
        self.packet.write_text("packet " + HEAD + "\n")
        self.config = {"repos": [REPO], "work_roots": [str(self.home / ".agent-harness" / "work")]}

    def tearDown(self):
        self.tmp.cleanup()

    def request(self, **over):
        req = {"repo": REPO, "pr": 7, "head": HEAD, "base": BASE, "packet": str(self.packet),
               "ticket": "GoodQA goodqa#16034", "owner": "agent-abc123"}
        req.update(over)
        return req


class SubmitTests(Base):
    def test_valid_request_is_queued_once(self):
        first = core.submit(self.paths, self.config, self.request())
        again = core.submit(self.paths, self.config, self.request())
        self.assertEqual(first["id"], again["id"])
        self.assertTrue(again["duplicate"])
        self.assertEqual(len(list(self.paths.queue.glob("*.json"))), 1)

    def test_queue_file_is_private(self):
        item = core.submit(self.paths, self.config, self.request())
        mode = os.stat(self.paths.queue / (item["id"] + ".json")).st_mode & 0o777
        self.assertEqual(mode, 0o600)

    def refused(self, **over):
        with self.assertRaises(core.Refused):
            core.submit(self.paths, self.config, self.request(**over))
        self.assertEqual(list(self.paths.queue.glob("*.json")) if self.paths.queue.exists() else [], [])

    def test_short_head_refused(self):
        self.refused(head="abc1234")

    def test_uppercase_or_newline_head_refused(self):
        self.refused(head=HEAD.upper())
        self.refused(head=HEAD + "\n")

    def test_repo_not_allowlisted_refused(self):
        self.refused(repo="someone/else")

    def test_packet_outside_work_roots_refused(self):
        outside = self.home / "elsewhere.md"
        outside.write_text(HEAD)
        self.refused(packet=str(outside))

    def test_symlinked_packet_refused(self):
        link = self.work / "link.md"
        link.symlink_to(self.packet)
        self.refused(packet=str(link))

    def test_oversized_packet_refused(self):
        self.packet.write_text("x" * 150_001)
        self.refused()

    def test_bad_ticket_and_owner_refused(self):
        self.refused(ticket="#16034; rm -rf /")
        self.refused(owner="agent abc")


class ResolveTests(Base):
    def test_matching_live_pr_resolves(self):
        got = core.resolve(self.request(), Fake(live_pr()))
        self.assertEqual((got["head"], got["base"]), (HEAD, BASE))

    def test_head_moved_is_stale(self):
        with self.assertRaises(core.Stale):
            core.resolve(self.request(), Fake(live_pr(headRefOid="c" * 40)))

    def test_closed_pr_refused(self):
        with self.assertRaises(core.Refused):
            core.resolve(self.request(), Fake(live_pr(state="MERGED")))

    def test_base_moved_is_repaired_with_a_note(self):
        # D4 ruling: main advancing after submit is not the owner's error; the live base wins and is recorded.
        got = core.resolve(self.request(), Fake(live_pr(baseRefOid="d" * 40)))
        self.assertEqual(got["base"], "d" * 40)
        self.assertIn(BASE[:12], got["base_repaired_from"])

    def test_gh_failure_is_retryable_not_pass(self):
        with self.assertRaises(core.Retry):
            core.resolve(self.request(), Fake(rc=1))

    def test_gh_argv_has_no_shell(self):
        fake = Fake(live_pr())
        core.resolve(self.request(), fake)
        self.assertEqual(fake.calls[0][:4], ["gh", "pr", "view", "7"])
        self.assertIn("-R", fake.calls[0])


def report(head=HEAD, packet_sha="0" * 64, stage="pr", verdict="PASS"):
    return (f"Reviewer: Codex x\nStage: {stage}\nReviewed HEAD: {head}\nReviewed repository: {REPO}\n"
            f"Reviewed PR: 7\nReviewed packet SHA-256: {packet_sha}\n\nVERDICT: {verdict}\n\nbody\n")


class ReceiptTests(Base):
    def setUp(self):
        super().setUp()
        self.sha = hashlib.sha256(self.packet.read_bytes()).hexdigest()

    def check(self, text, rc=0):
        out = self.work / "r.md"
        out.write_text(text)
        return core.verify_receipt(rc, out, HEAD, self.packet)

    def test_pass_receipt_accepted(self):
        self.assertEqual(self.check(report(packet_sha=self.sha))["verdict"], "PASS")

    def test_block_receipt_is_block(self):
        self.assertEqual(self.check(report(packet_sha=self.sha, verdict="BLOCK"))["verdict"], "BLOCK")

    def test_wrong_head_invalid(self):
        self.assertEqual(self.check(report(head="c" * 40, packet_sha=self.sha))["verdict"], "INVALID")

    def test_wrong_packet_sha_invalid(self):
        self.assertEqual(self.check(report(packet_sha="1" * 64))["verdict"], "INVALID")

    def test_wrong_stage_invalid(self):
        self.assertEqual(self.check(report(packet_sha=self.sha, stage="plan"))["verdict"], "INVALID")

    def test_nonzero_exit_never_pass(self):
        self.assertEqual(self.check(report(packet_sha=self.sha), rc=1)["verdict"], "ERROR")

    def test_pass_with_tickets_is_not_pass(self):
        got = self.check(report(packet_sha=self.sha, verdict="PASS-WITH-TICKETS"))
        self.assertEqual(got["verdict"], "PASS-WITH-TICKETS")

    def test_real_block_exit_3_is_block_not_error(self):
        self.assertEqual(self.check(report(packet_sha=self.sha, verdict="BLOCK"), rc=3)["verdict"], "BLOCK")

    def test_pass_verdict_with_exit_3_is_never_pass(self):
        self.assertEqual(self.check(report(packet_sha=self.sha), rc=3)["verdict"], "ERROR")

    def test_advisory_exit_4_is_advisory(self):
        self.assertEqual(self.check(report(packet_sha=self.sha), rc=4)["verdict"], "ADVISORY")

    def test_exit_2_is_error_even_with_a_report(self):
        self.assertEqual(self.check(report(packet_sha=self.sha), rc=2)["verdict"], "ERROR")

    def test_block_with_wrong_head_is_invalid(self):
        self.assertEqual(self.check(report(head="c" * 40, packet_sha=self.sha, verdict="BLOCK"), rc=3)["verdict"],
                         "INVALID")

    # code-inspection r1 F4: only the authoritative verdict line after the header block counts
    def test_pr_result_marker_is_not_a_verdict(self):
        text = report(packet_sha=self.sha).replace("VERDICT: PASS", "PR_RESULT: PASS")
        self.assertEqual(self.check(text)["verdict"], "INVALID")

    def test_quoted_pass_further_down_is_not_a_verdict(self):
        text = report(packet_sha=self.sha).replace("VERDICT: PASS", "Summary first") + "Example:\nVERDICT: PASS\n"
        self.assertEqual(self.check(text)["verdict"], "INVALID")

    def test_pass_with_trailing_text_is_not_pass(self):
        text = report(packet_sha=self.sha).replace("VERDICT: PASS", "VERDICT: PASS / BLOCK")
        self.assertNotEqual(self.check(text)["verdict"], "PASS")

    def test_prefixed_pass_is_not_pass(self):
        text = report(packet_sha=self.sha).replace("VERDICT: PASS", "[marker omitted] VERDICT: PASS")
        self.assertEqual(self.check(text)["verdict"], "INVALID")

    def test_duplicate_header_is_invalid(self):
        text = report(packet_sha=self.sha).replace("Stage: pr\n", "Stage: pr\nReviewed HEAD: " + "c" * 40 + "\n")
        self.assertEqual(self.check(text)["verdict"], "INVALID")

    def test_header_in_body_does_not_count(self):
        text = report(head="c" * 40, packet_sha=self.sha).replace("body\n", "Reviewed HEAD: %s\n" % HEAD)
        self.assertEqual(self.check(text)["verdict"], "INVALID")

    def test_block_with_trailing_text_is_block(self):
        text = report(packet_sha=self.sha, verdict="BLOCK - see F1")
        self.assertEqual(self.check(text, rc=3)["verdict"], "BLOCK")

    def test_missing_report_is_error(self):
        self.assertEqual(core.verify_receipt(0, self.work / "none.md", HEAD, self.packet)["verdict"], "ERROR")


if __name__ == "__main__":
    unittest.main()
