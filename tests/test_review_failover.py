"""P19 (goodqa#14833): an explicit, receipted --failover same-harness after repeated cross-harness reviewer failures."""
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOOKS = ROOT / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
sys.path.insert(0, str(ROOT))
import usage_guard as guard  # noqa: E402
import model_tiers as tiers  # noqa: E402
import peer_review  # noqa: E402
import review_failover as rf  # noqa: E402

HEAD = "b" * 40
PACKET = "p" * 64


class Fixture(unittest.TestCase):
    """A real UsageStore holding prior review runs as peer_review.py would have left them."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="failover-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.store = guard.UsageStore(self.root / "private")
        self.counter = 0

    def subject(self, head=HEAD, repository="r" * 64):
        subject = guard.Subject(schema=1, fingerprint=hashlib.sha256((head + repository).encode()).hexdigest(), reusable=True,
                                head=head, tree="c" * 40, repository=repository)
        subject.repo, subject.manifest = self.repo, {}
        subject.probe = lambda: subject
        return subject

    def prior(self, reason="TIMEOUT", provider="codex", reconcile=True, head=HEAD, packet=PACKET, stage="PR",
              result="NO_RESULT", execution="INTERRUPTED", review=None, repository="r" * 64):
        self.counter += 1
        subject = self.subject(head, repository)
        invocation = guard.invocation_identity(subject, purpose="peer-review-" + stage.lower().replace("_", "-"),
                                               argv=["prior", str(self.counter)], cwd=self.repo, stage=stage,
                                               packet_digest=packet, provider=provider, model="m", pool="default")
        run = self.store.begin(subject, invocation, owner="fixture", label="peer-review-pr", timeout=1440,
                               aggregate_timeout=2880, kind="review")
        run.finish(execution=execution, result=result, reason=reason, review=review)
        if reconcile:
            self.store.reconcile(run.run_id, actor="fixture", reason="timeout reconciled", evidence="fixture")
        return run.run_id

    def evaluate(self, need=2, **over):
        facts = dict(repository="r" * 64, head=HEAD, stage="pr", packet_sha256=PACKET, primary_provider="codex", need=need)
        facts.update(over)
        return rf.evaluate(self.store, **facts)


class Eligibility(Fixture):
    def test_two_reconciled_timeouts_on_the_same_subject_qualify_and_name_both_runs(self):
        a, b = self.prior(), self.prior()
        out = self.evaluate()
        self.assertTrue(out["ok"], out)
        self.assertEqual(sorted(out["run_ids"]), sorted([a, b]))
        self.assertEqual(out["need"], 2)
        self.assertIn("2", out["reason"])
        self.assertEqual(sorted((r["run_id"], r["reason"]) for r in out["runs"]), sorted([(a, "TIMEOUT"), (b, "TIMEOUT")]))

    def test_one_failure_is_not_enough_and_the_default_is_two(self):
        self.prior()
        out = self.evaluate()
        self.assertFalse(out["ok"])
        self.assertIn("2", out["refusal"])
        self.assertEqual(rf.DEFAULT_AFTER, 2)

    def test_a_timeout_nobody_reconciled_does_not_count_and_is_named(self):
        self.prior(reconcile=False)
        unreconciled = self.prior(reconcile=False)
        out = self.evaluate()
        self.assertFalse(out["ok"])
        self.assertIn(unreconciled, out["unreconciled"])
        self.assertIn("reconcile", out["refusal"])

    def test_provider_unavailable_results_count_without_reconciliation(self):
        a = self.prior(reason="TRANSIENT_INFRA", execution="NOT_STARTED", reconcile=False)
        b = self.prior(reason="TRANSIENT_INFRA", execution="NOT_STARTED", reconcile=False)
        out = self.evaluate()
        self.assertTrue(out["ok"], out)
        self.assertEqual(sorted(out["run_ids"]), sorted([a, b]))
        self.assertEqual({r["reason"] for r in out["runs"]}, {"TRANSIENT_INFRA"})

    def test_a_timeout_and_an_unavailable_result_together_qualify(self):
        self.prior()
        self.prior(reason="TRANSIENT_INFRA", execution="NOT_STARTED", reconcile=False)
        self.assertTrue(self.evaluate()["ok"])

    def test_a_larger_threshold_is_honoured(self):
        self.prior(); self.prior()
        self.assertFalse(self.evaluate(need=3)["ok"])
        self.prior()
        self.assertTrue(self.evaluate(need=3)["ok"])

    def test_material_findings_refuse_even_after_enough_timeouts(self):
        self.prior(); self.prior()
        self.prior(reason="CODE_FINDINGS", provider="claude", execution="COMPLETED", result="CHECK_FAILED", reconcile=False)
        out = self.evaluate()
        self.assertFalse(out["ok"])
        self.assertIn("findings", out["refusal"])

    def test_a_block_verdict_alone_is_a_material_finding(self):
        self.prior(); self.prior()
        self.prior(reason="NONE", provider="claude", execution="COMPLETED", result="NO_RESULT", reconcile=False,
                   review={"stage": "PR", "verdict": "BLOCK", "findings": ["F1"]})
        self.assertFalse(self.evaluate()["ok"])

    def test_a_failed_check_alone_is_a_material_finding(self):
        self.prior(); self.prior()
        self.prior(reason="NONE", provider="claude", execution="COMPLETED", result="CHECK_FAILED", reconcile=False)
        self.assertFalse(self.evaluate()["ok"])

    def test_invalid_output_refuses(self):
        self.prior(); self.prior()
        self.prior(reason="INVALID_OUTPUT", execution="COMPLETED", reconcile=False)
        out = self.evaluate()
        self.assertFalse(out["ok"])
        self.assertIn("invalid", out["refusal"])

    def test_other_subjects_neither_count_nor_refuse(self):
        self.prior(head="a" * 40); self.prior(packet="q" * 64); self.prior(stage="PLAN"); self.prior(repository="s" * 64)
        self.prior(reason="CODE_FINDINGS", head="a" * 40, execution="COMPLETED", result="CHECK_FAILED", reconcile=False)
        out = self.evaluate()
        self.assertFalse(out["ok"])
        self.assertEqual(out["run_ids"], [])
        self.prior(); self.prior()
        self.assertTrue(self.evaluate()["ok"])

    def test_failures_of_the_other_provider_do_not_count(self):
        self.prior(provider="claude"); self.prior(provider="claude")
        self.assertFalse(self.evaluate()["ok"])
        self.assertTrue(self.evaluate(primary_provider="claude")["ok"])

    def test_the_zero_prior_case_and_a_bad_threshold_fail_closed(self):
        self.assertFalse(self.evaluate()["ok"])
        for bad in (0, -1, 11, True, "2", None):
            with self.assertRaises(ValueError, msg=str(bad)):
                self.evaluate(need=bad)


class Selection(unittest.TestCase):
    def setUp(self):
        self.policy = tiers.load_policy()
        self.available = {"openai": True, "claude": True}

    def normal(self, rung="R2", harness="claude"):
        return tiers.reviewer_for(self.policy, rung, harness, self.available)

    def test_failover_keeps_the_reviewer_rung_and_moves_to_the_authors_harness(self):
        normal = self.normal()
        self.assertEqual(normal["harness"], "openai")
        chosen, refusal = rf.failover_selection(self.policy, "R2", "claude", self.available, normal)
        self.assertIsNone(refusal)
        self.assertEqual((chosen["harness"], chosen["rung"], chosen["effort"]), ("claude", normal["rung"], normal["effort"]))
        self.assertEqual(chosen["model"], self.policy["rungs"][normal["rung"]]["models"]["claude"])
        self.assertIn("failover", chosen["why"])

    def test_an_unknown_author_harness_is_refused(self):
        _, refusal = rf.failover_selection(self.policy, "R2", "unknown", self.available, self.normal(harness="unknown"))
        self.assertIn("author harness", refusal)

    def test_nothing_to_fail_over_to_when_the_normal_reviewer_is_already_the_authors_harness(self):
        # codex is down, so the normal reviewer of a Claude author is Claude itself
        normal = tiers.reviewer_for(self.policy, "R2", "claude", {"openai": False, "claude": True})
        self.assertEqual(normal["harness"], "claude")
        chosen, refusal = rf.failover_selection(self.policy, "R2", "claude", {"openai": False, "claude": True}, normal)
        self.assertIsNone(chosen)
        self.assertIn("already", refusal)

    def test_the_authors_harness_must_be_available(self):
        _, refusal = rf.failover_selection(self.policy, "R2", "claude", {"openai": True, "claude": False}, self.normal())
        self.assertIn("not available", refusal)

    def test_a_review_only_selection_is_refused(self):
        nothing = {"rung": None, "harness": None}
        _, refusal = rf.failover_selection(self.policy, "R6", "claude", self.available, nothing)
        self.assertIsNotNone(refusal)


class Receipt(unittest.TestCase):
    def test_receipt_lines_state_each_prior_run_and_its_final_reason_verbatim(self):
        lines = rf.receipt_lines({"mode": "same-harness", "need": 2, "run_ids": ["aaa", "bbb"],
                                  "runs": [{"run_id": "aaa", "reason": "TIMEOUT"}, {"run_id": "bbb", "reason": "TRANSIENT_INFRA"}],
                                  "reason": "2 prior reviews of this subject ended in a reconciled TIMEOUT or provider-unavailable result"})
        self.assertIn("Failover: same-harness\n", lines)
        self.assertIn("Failover-Reason: 2 prior reviews", lines)
        self.assertIn("Failover-Prior-Runs: aaa (TIMEOUT, reconciled), bbb (TRANSIENT_INFRA)\n", lines)

    def test_no_failover_means_no_lines(self):
        self.assertEqual(rf.receipt_lines(None), "")



class LedgerEvent(unittest.TestCase):
    """The ladder never counts a failover as a failure, and the audit can list failovers per task."""

    def setUp(self):
        import escalation as ladder
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name) / "ladder"
        root.mkdir(mode=0o700)
        self.ledger = ladder.Ledger(root, tiers.load_policy())
        self.info = {"mode": "same-harness", "need": 2, "run_ids": ["a" * 32, "b" * 32], "reason": "2 prior reviews ..."}

    def test_a_failover_event_is_listed_and_changes_no_rung_or_failure_count(self):
        before = self.ledger.status("fo-ledger")
        after = self.ledger.record_failover("fo-ledger", self.info, source="peer_review:pr", head="c" * 40)
        self.assertEqual((after["rung"], after["failures_at_rung"], after["climbs"]),
                         (before["rung"], before["failures_at_rung"], before["climbs"]))
        events = self.ledger.load("fo-ledger")["events"]
        failovers = [e for e in events if e["kind"] == "failover"]
        self.assertEqual(len(failovers), 1)
        self.assertEqual((failovers[0]["class"], failovers[0]["failover"]["run_ids"]), ("FAILOVER", self.info["run_ids"]))

    def test_many_failovers_never_climb_the_ladder(self):
        for _ in range(6):
            status = self.ledger.record_failover("fo-many", self.info, source="peer_review:pr")
        self.assertEqual((status["failures_at_rung"], status["climbs"]), (0, 0))

    def test_a_malformed_record_is_refused(self):
        import escalation as ladder
        for bad in (None, {}, {"mode": "other", "run_ids": []}, {"mode": "same-harness", "run_ids": "x"}):
            with self.assertRaises(ladder.LedgerError, msg=str(bad)):
                self.ledger.record_failover("fo-bad", bad, source="x")


class Order(unittest.TestCase):
    def test_a_failover_run_has_no_fallback_back_to_the_failed_provider(self):
        codex, claude = ("codex", "c", "p"), ("claude", "l", "p")
        self.assertEqual(peer_review.reviewer_order({"harness": "claude"}, codex, claude, no_fallback=True), (claude,))
        self.assertEqual(peer_review.reviewer_order({"harness": "claude"}, codex, claude), (claude, codex))
        self.assertEqual(peer_review.reviewer_order({"harness": "openai"}, codex, claude), (codex, claude))


import tests.test_peer_review as _base  # noqa: E402


class EndToEnd(unittest.TestCase):
    """Drive peer_review.py itself with the fake codex and claude binaries of test_peer_review."""
    fake = _base.PeerReviewTests.fake
    evidence = staticmethod(_base.PeerReviewTests.evidence)

    def setUp(self):
        _base.PeerReviewTests.setUp(self)
        self.ladder = self.root / "ladder"
        self.ladder.mkdir(mode=0o700)
        self.argv_file = self.root / "argv.json"
        self.launches = self.root / "launches.log"
        body = f'''import json, os, sys
from pathlib import Path
Path({str(self.argv_file)!r}).write_text(json.dumps(sys.argv))
with open({str(self.launches)!r}, 'a') as stream: stream.write(os.path.basename(sys.argv[0]) + '\\n')
text = 'CODE_INSPECTION_RESULT: ACCEPT\\nReviewed.'
if '--output-last-message' in sys.argv:
    Path(sys.argv[sys.argv.index('--output-last-message') + 1]).write_text(text)
else:
    print(text)
'''
        self.fake("codex", body)
        self.fake("claude", body)
        self.tools = self.root / "tools"
        self.tools.mkdir(mode=0o700)
        import shutil
        for name in ("git", "python3", "sh", "env", "cat", "mkdir", "rm", "cp", "mv", "ln", "ls", "chmod", "sed", "grep", "awk",
                     "tr", "sort", "head", "tail", "wc", "date", "sleep", "dirname", "basename", "uname", "mktemp", "readlink",
                     "true", "false", "find", "xargs", "diff", "tar"):
            found = shutil.which(name, path="/usr/bin:/bin:/usr/local/bin")
            if found:
                (self.tools / name).symlink_to(found)
        self.head = subprocess.run(["git", "-C", str(self.repo), "rev-parse", "HEAD"], check=True, capture_output=True,
                                   text=True).stdout.strip()
        self.packet.write_text(self.packet.read_text() + self.evidence(self.head))
        self.packet_sha = hashlib.sha256(self.packet.read_bytes()).hexdigest()
        self.subject = guard.capture_subject(self.repo)
        self.store = guard.UsageStore()
        self.counter = 0

    def seed(self, reason="TIMEOUT", provider="codex", reconcile=True, execution="INTERRUPTED", result="NO_RESULT", review=None):
        self.counter += 1
        invocation = guard.invocation_identity(self.subject, purpose="peer-review-code-inspection",
                                               argv=["prior", str(self.counter)], cwd=self.repo, stage="CODE_INSPECTION",
                                               packet_digest=self.packet_sha, provider=provider, model="m", pool="default")
        run = self.store.begin(self.subject, invocation, owner="fixture", label="peer-review-code-inspection", timeout=1440,
                               aggregate_timeout=2880, kind="review")
        run.finish(execution=execution, result=result, reason=reason, review=review)
        if reconcile:
            self.store.reconcile(run.run_id, actor="fixture", reason="reconciled", evidence="fixture")
        return run.run_id

    def review(self, *extra):
        return _base.PeerReviewTests.invoke(self, stage="code-inspection", extra=list(extra), env={
            "AGENT_HARNESS_ESCALATION_DIR": str(self.ladder), "PATH": str(self.bin) + os.pathsep + str(self.tools)})

    def launched(self):
        return self.launches.read_text().split() if self.launches.exists() else []

    ARGS = ("--task", "fo-1", "--author-rung", "R2", "--author-harness", "claude")

    def test_without_the_flag_nothing_changes_and_codex_reviews(self):
        self.seed(); self.seed()
        result = self.review(*self.ARGS)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.launched(), ["codex"])
        self.assertNotIn("Failover", self.output.read_text())

    def test_failover_is_refused_with_no_prior_failures_and_launches_nothing(self):
        result = self.review(*self.ARGS, "--failover", "same-harness")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("failover", result.stderr.lower())
        self.assertEqual(self.launched(), [])
        self.assertFalse(self.output.exists())

    def test_two_reconciled_timeouts_run_claude_at_the_same_rung_with_a_receipt(self):
        first, second = self.seed(), self.seed()
        result = self.review(*self.ARGS, "--failover", "same-harness")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.launched(), ["claude"])
        report = self.output.read_text()
        self.assertIn("Failover: same-harness\n", report)
        self.assertIn("Failover-Prior-Runs: ", report)
        self.assertIn(first + " (TIMEOUT, reconciled)", report); self.assertIn(second + " (TIMEOUT, reconciled)", report)
        self.assertIn("Failover-Reason: ", report)
        self.assertIn("Author-Rung: R2\n", report)
        self.assertIn("Reviewer-Rung: R3\n", report)  # the same rung the cross-harness reviewer would have had
        self.assertIn("Reviewer-Selection: claude ", report)
        receipt = json.loads(next((self.ladder / "selections").glob("*.json")).read_text())
        self.assertEqual(receipt["author_harness"], "claude")
        self.assertEqual(receipt["author_rung"], "R2")
        self.assertEqual(receipt["selection"]["rung"], "R3")
        self.assertEqual(sorted(receipt["failover"]["run_ids"]), sorted([first, second]))
        import escalation as ladder
        events = ladder.Ledger(self.ladder, tiers.load_policy()).load("fo-1")["events"]
        self.assertEqual([e["kind"] for e in events if e["kind"] == "failover"], ["failover"])

    def test_a_failover_review_that_fails_is_still_audited_in_the_ledger(self):
        self.seed(); self.seed()
        self.fake("claude", f"""import os, sys
with open({str(self.launches)!r}, 'a') as stream: stream.write('claude\\n')
print('no verdict here')
""")
        result = self.review(*self.ARGS, "--failover", "same-harness")
        self.assertEqual(result.returncode, 2, result.stderr)
        import escalation as ladder
        events = ladder.Ledger(self.ladder, tiers.load_policy()).load("fo-1")["events"]
        self.assertEqual(len([e for e in events if e["kind"] == "failover"]), 1)

    def test_material_findings_or_invalid_output_in_the_history_refuse(self):
        for kind in (dict(reason="CODE_FINDINGS", provider="claude", execution="COMPLETED", result="CHECK_FAILED", reconcile=False),
                     dict(reason="INVALID_OUTPUT", execution="COMPLETED", reconcile=False)):
            with self.subTest(kind=kind["reason"]):
                self.seed(); self.seed(); self.seed(**kind)
                result = self.review(*self.ARGS, "--failover", "same-harness")
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(self.launched(), [])

    def test_an_unknown_author_harness_cannot_fail_over(self):
        self.seed(); self.seed()
        result = self.review("--task", "fo-2", "--author-rung", "R2", "--failover", "same-harness")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("author harness", result.stderr)
        self.assertEqual(self.launched(), [])

    def test_only_one_failover_mode_exists(self):
        result = self.review(*self.ARGS, "--failover", "other-harness")
        self.assertEqual(result.returncode, 2)

    def test_the_threshold_flag_is_bounded(self):
        for bad in ("0", "11", "x"):
            self.assertEqual(self.review(*self.ARGS, "--failover", "same-harness", "--failover-after", bad).returncode, 2)


if __name__ == "__main__":
    unittest.main()
