"""ahc_runner (Gate 1, receipt-only): one queued item through resolve, clone, lint/fix, review, verify, write-back
and digest, with a journal that makes every step idempotent and restart-safe. All children are fakes; no network.
GoodQA goodqa#16034 AC-6, AC-7, AC-9; NEG-9 (Gate 1 part), NEG-12, NEG-15, NEG-16."""
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import ahc_core as core  # noqa: E402
import ahc_runner as runner  # noqa: E402

HEAD, BASE, REPO = "a" * 40, "b" * 40, "ericmacdougall/agent-harness"
GOOD_PACKET = f"head {HEAD}\n```\n$ python3 -m unittest\nRan 12 tests\nOK\nexit 0\n```\n"


class Deps:
    """Records every child call; behavior is configurable per test."""
    def __init__(self, verdict="PASS", pr_head=HEAD, gh_rc=0, review_rc=0, findings="F1 - High - thing `x`"):
        self.verdict, self.pr_head, self.gh_rc, self.review_rc, self.findings = (
            verdict, pr_head, gh_rc, review_rc, findings)
        self.gh_calls, self.review_calls, self.ah_calls, self.clone_calls = [], [], [], []
        self.now = 1_800_000_000.0

    def gh(self, argv, timeout):
        self.gh_calls.append(argv)
        pr = {"number": 7, "state": "OPEN", "headRefOid": self.pr_head, "baseRefOid": BASE, "baseRefName": "main",
              "isCrossRepository": False}
        return self.gh_rc, json.dumps(pr), ""

    def clone(self, repo, head, base):
        self.clone_calls.append((repo, head, base))
        return "/clones/" + repo.replace("/", "__")

    def merge_base(self, clone, head, base):
        # D3 ruling: the daemon passes merge-base(head, live base) as --snapshot-base and --base.
        return base

    def changed_paths(self, clone, merge_base, head):
        return ["harness/hooks/example.py"]

    def review(self, argv, timeout):
        self.review_calls.append(argv)
        out = Path(argv[argv.index("--output") + 1])
        packet = Path(argv[argv.index("--packet") + 1])
        sha = hashlib.sha256(packet.read_bytes()).hexdigest()
        out.write_text(f"Stage: pr\nReviewed HEAD: {HEAD}\nReviewed packet SHA-256: {sha}\n\n"
                       f"VERDICT: {self.verdict}\n\n{self.findings}\n")
        return self.review_rc

    def ah(self, argv, timeout):
        self.ah_calls.append(argv)
        return 0, "{}", ""

    def clock(self):
        return self.now


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name)
        self.paths = core.Paths(self.home)
        work = self.home / ".agent-harness" / "work" / "s"
        work.mkdir(parents=True)
        self.packet = work / "p.md"
        self.packet.write_text(GOOD_PACKET)
        self.config = {"repos": [REPO], "work_roots": [str(work.parent)]}

    def tearDown(self):
        self.tmp.cleanup()

    def submit(self, head=HEAD, packet=None):
        req = {"repo": REPO, "pr": 7, "head": head, "base": BASE, "packet": str(packet or self.packet),
               "ticket": "GoodQA goodqa#16034", "owner": "agent-abc123"}
        return core.submit(self.paths, self.config, req)["id"]

    def run_all(self, deps):
        return runner.tick(self.paths, self.config, deps)

    def state(self, iid):
        return runner.Journal(self.paths, iid).state()


class FlowTests(Base):
    def test_pass_gate1_writes_digest_merge_command_and_one_comment(self):
        iid, deps = self.submit(), Deps()
        self.run_all(deps)
        self.assertEqual(self.state(iid), "pass-awaiting-main")
        digest = self.paths.digest.read_text()
        self.assertIn("--match-head-commit " + HEAD, digest)
        self.assertEqual(len(deps.review_calls), 1)
        argv = deps.review_calls[0]
        self.assertEqual(argv[argv.index("--expected-head") + 1], HEAD)
        self.assertEqual(argv[argv.index("--snapshot-base") + 1], BASE)
        self.assertNotIn("--github-repo", argv)  # Gate 1: unbound, cannot mint merge authority
        self.assertLessEqual(int(argv[argv.index("--timeout") + 1]), 720)

    def test_block_writes_back_once_with_key_and_inbox(self):
        iid, deps = self.submit(), Deps(verdict="BLOCK")
        self.run_all(deps)
        self.run_all(deps)  # a rerun must not duplicate anything
        self.assertEqual(self.state(iid), "blocked")
        comments = [a for a in deps.ah_calls if a[:3] == ["ah", "ticket", "comment"] or "comment" in a]
        self.assertEqual(len(comments), 1)
        self.assertIn("--key", comments[0])
        inbox = list((self.paths.inbox / "agent-abc123").glob("*.md"))
        self.assertEqual(len(inbox), 1)
        self.assertIn("F1", inbox[0].read_text())
        self.assertEqual(self.paths.digest.read_text().count(iid), 1)

    def test_finding_text_with_backticks_is_one_argv_element(self):
        self.submit()
        deps = Deps(verdict="BLOCK", findings="F1 - High - `$(rm -rf ~)` and ; | &")
        self.run_all(deps)
        body = deps.ah_calls[0][deps.ah_calls[0].index("--body") + 1]
        self.assertIn("`$(rm -rf ~)` and ; | &", body)

    def test_review_launches_once_across_ticks(self):
        self.submit()
        deps = Deps()
        for _ in range(3):
            self.run_all(deps)
        self.assertEqual(len(deps.review_calls), 1)

    def test_stale_head_tells_owner_and_never_reviews(self):
        iid, deps = self.submit(), Deps(pr_head="c" * 40)
        self.run_all(deps)
        self.assertEqual(self.state(iid), "stale-head")
        self.assertEqual(deps.review_calls, [])
        self.assertTrue(list((self.paths.inbox / "agent-abc123").glob("*.md")))

    def test_gh_failure_backs_off_without_review(self):
        iid, deps = self.submit(), Deps(gh_rc=1)
        self.run_all(deps)
        self.assertEqual(self.state(iid), "queued")
        self.run_all(deps)  # inside the backoff window: no second gh call
        self.assertEqual(len(deps.gh_calls), 1)
        self.assertEqual(deps.review_calls, [])

    def test_unfixable_lint_goes_to_owner_without_review(self):
        self.packet.write_text(f"head {HEAD}\ntests pass\n")
        iid, deps = self.submit(), Deps()
        self.run_all(deps)
        self.assertEqual(self.state(iid), "lint-failed")
        self.assertEqual(deps.review_calls, [])

    def test_packet_changed_after_submit_is_refused(self):
        iid = self.submit()
        self.packet.write_text(GOOD_PACKET + "edited\n")
        deps = Deps()
        self.run_all(deps)
        self.assertEqual(self.state(iid), "refused")
        self.assertEqual(deps.review_calls, [])

    def test_nonzero_review_exit_is_error_not_pass(self):
        iid, deps = self.submit(), Deps(review_rc=3)
        self.run_all(deps)
        self.assertEqual(self.state(iid), "review-error")
        self.assertNotIn("--match-head-commit", self.paths.digest.read_text())

    def test_newer_head_supersedes_older_item(self):
        old = self.submit()
        other = self.packet.parent / "p2.md"
        other.write_text(GOOD_PACKET.replace(HEAD, "c" * 40))
        new = self.submit(head="c" * 40, packet=other)
        deps = Deps(pr_head="c" * 40)
        self.run_all(deps)
        self.assertEqual(self.state(old), "superseded")
        self.assertNotEqual(self.state(new), "superseded")


class RecoveryTests(Base):
    def test_restart_mid_review_with_report_verifies_without_relaunch(self):
        iid, deps = self.submit(), Deps()
        runner.STOP_AFTER = "reviewing"   # simulate a kill right after the review returned, before the verdict
        try:
            self.run_all(deps)
        finally:
            runner.STOP_AFTER = None
        self.assertEqual(self.state(iid), "reviewing")
        self.run_all(deps)
        self.assertEqual(self.state(iid), "pass-awaiting-main")
        self.assertEqual(len(deps.review_calls), 1)

    def test_restart_mid_review_without_report_needs_attention_no_relaunch(self):
        iid, deps = self.submit(), Deps()
        journal = runner.Journal(self.paths, iid)
        journal.append("reviewing", report=str(self.paths.reports / "missing.md"), packet=str(self.packet))
        self.run_all(deps)
        self.assertEqual(self.state(iid), "needs-attention")
        self.assertEqual(deps.review_calls, [])

    def test_torn_journal_line_is_ignored(self):
        iid, deps = self.submit(), Deps()
        self.run_all(deps)
        with open(runner.Journal(self.paths, iid).path, "a") as handle:
            handle.write('{"event": "rev')
        self.assertEqual(self.state(iid), "pass-awaiting-main")

    def test_second_instance_exits_cleanly(self):
        first = runner.acquire_lock(self.paths)
        self.assertIsNotNone(first)
        self.assertIsNone(runner.acquire_lock(self.paths))
        first.close()


class ErrDeps(Deps):
    """peer_review exits 2 with a REVIEW_DIAGNOSTIC line on stderr; no report."""
    def __init__(self, code, **kw):
        super().__init__(**kw)
        self.code = code

    def review(self, argv, timeout):
        self.review_calls.append(argv)
        return 2, "REVIEW_DIAGNOSTIC code=%s reason=x" % self.code


class RetryTests(Base):
    """AC-18 / NEG-25: each failure class follows retry_policy, and counts survive restart."""

    def test_policy_table(self):
        now = 1000.0
        self.assertEqual(runner.retry_policy("quota", 1, now, retry_at=now + 7200), ("deferred", now + 7200))
        self.assertEqual(runner.retry_policy("quota", 3, now + 86400, first_at=now)[0], "needs-attention")
        self.assertEqual(runner.retry_policy("auth", 1, now), ("needs-attention", None))
        self.assertEqual(runner.retry_policy("block", 1, now), ("blocked", None))
        self.assertEqual(runner.retry_policy("invalid-output", 1, now)[0], "deferred")
        self.assertEqual(runner.retry_policy("invalid-output", 2, now), ("review-error", None))
        self.assertEqual(runner.retry_policy("invalid-output", 1, now, config={"bounds": {
            "invalid_output_repeat": False}}), ("review-error", None))
        self.assertEqual(runner.retry_policy("provider-transient", 2, now), ("review-error", None))
        self.assertEqual(runner.retry_policy("pre-provider", 3, now), ("needs-attention", None))
        self.assertEqual(runner.retry_policy("delivery", 30, now), ("pending", now + 1800))
        with self.assertRaises(ValueError):
            runner.retry_policy("mystery", 1, now)

    def test_quota_is_not_retried_before_retry_at(self):
        iid, deps = self.submit(), ErrDeps("PROVIDER_USAGE_LIMIT")
        self.run_all(deps)
        self.assertEqual(self.state(iid), "deferred")
        deps.now += 3000
        self.run_all(deps)
        self.assertEqual(len(deps.review_calls), 1, "quota retried before retry_at (NEG-25)")
        deps.now += 700
        self.run_all(deps)
        self.assertEqual(len(deps.review_calls), 2)
        self.assertIn("--repeat-reason", deps.review_calls[1])

    def test_auth_opens_circuit_and_never_retries_on_a_timer(self):
        iid, deps = self.submit(), ErrDeps("PROVIDER_AUTH")
        self.run_all(deps)
        self.assertEqual(self.state(iid), "needs-attention")
        other = self.packet.parent / "p2.md"
        other.write_text(GOOD_PACKET)
        req = {"repo": "ericmacdougall/agent-harness", "pr": 8, "head": HEAD, "base": BASE, "packet": str(other),
               "ticket": "GoodQA goodqa#16034", "owner": "agent-abc123"}
        second = core.submit(self.paths, self.config, req)["id"]
        for _ in range(3):
            deps.now += 7200
            self.run_all(deps)
        self.assertEqual(len(deps.review_calls), 1, "a review ran while the auth circuit was open")
        self.assertEqual(self.state(second), "queued")

    def test_invalid_output_gets_one_declared_repeat_then_owner(self):
        iid, deps = self.submit(), ErrDeps("PROVIDER_INVALID_OUTPUT")
        for _ in range(4):
            self.run_all(deps)
            deps.now += 120
        self.assertEqual(len(deps.review_calls), 2)
        repeat = deps.review_calls[1][deps.review_calls[1].index("--repeat-reason") + 1]
        self.assertTrue(repeat.startswith("PROVIDER_INVALID_OUTPUT"))
        self.assertEqual(self.state(iid), "review-error")

    def test_invalid_output_without_repeat_flag_goes_to_owner(self):
        self.config["bounds"] = {"invalid_output_repeat": False}
        iid, deps = self.submit(), ErrDeps("PROVIDER_INVALID_OUTPUT")
        for _ in range(3):
            self.run_all(deps)
            deps.now += 120
        self.assertEqual(len(deps.review_calls), 1)
        self.assertEqual(self.state(iid), "review-error")

    def test_block_is_never_rerun_for_the_same_head_and_packet(self):
        iid, deps = self.submit(), Deps(verdict="BLOCK")
        for _ in range(3):
            self.run_all(deps)
            deps.now += 86400
        self.assertEqual(len(deps.review_calls), 1)
        self.assertEqual(self.submit(), iid)  # resubmitting the same bytes is the same item, not a new review
        self.run_all(deps)
        self.assertEqual(len(deps.review_calls), 1)

    def test_attempt_counts_survive_restart(self):
        iid, deps = self.submit(), Deps(gh_rc=1)
        self.run_all(deps)
        deps.now += 61
        self.run_all(deps)   # a fresh tick opens a fresh ledger connection: counts come from SQLite
        ledger = runner.Ledger(self.paths)
        try:
            attempts = json.loads(ledger.item(iid)["attempts"])
            lineage = json.loads(ledger.db.execute("SELECT attempts FROM lineage").fetchone()["attempts"])
        finally:
            ledger.close()
        self.assertEqual(attempts["gh-transient"], 2)
        self.assertEqual(lineage["gh-transient"], 2)


class DeliveryTests(Base):
    """AC-19 / NEG-26 / NEG-34: an inbox file is not delivery; only the owner's ack is; no ack escalates once."""

    def block(self):
        iid, deps = self.submit(), Deps(verdict="BLOCK")
        self.run_all(deps)
        return iid, deps

    def notices(self, iid):
        ledger = runner.Ledger(self.paths)
        try:
            return [dict(r) for r in ledger.db.execute("SELECT * FROM notices WHERE item=?", (iid,))]
        finally:
            ledger.close()

    def comments(self, deps):
        return [a for a in deps.ah_calls if a[:3] == ["ah", "ticket", "comment"]]

    def test_inbox_file_is_not_delivery(self):
        iid, _deps = self.block()
        self.assertTrue(list((self.paths.inbox / "agent-abc123").glob("*.md")))
        self.assertIsNone(self.notices(iid)[0]["acked_at"])

    def test_no_ack_escalates_once_after_deadline(self):
        iid, deps = self.block()
        deps.now += 4 * 3600 - 10
        self.run_all(deps)
        self.assertEqual(len(self.comments(deps)), 1)
        deps.now += 20
        self.run_all(deps)
        self.run_all(deps)
        comments = self.comments(deps)
        self.assertEqual(len(comments), 2)
        self.assertIn("has not acknowledged", comments[1][comments[1].index("--body") + 1])

    def test_ack_by_owner_stops_escalation(self):
        iid, deps = self.block()
        with self.assertRaises(core.Refused):
            runner.ack(self.paths, iid, "agent-someone-else")
        self.assertEqual(runner.ack(self.paths, iid, "agent-abc123"), 1)
        deps.now += 5 * 3600
        self.run_all(deps)
        self.assertEqual(len(self.comments(deps)), 1)

    def test_ticket_outage_backs_off_and_does_not_storm(self):
        iid = self.submit()
        deps = Deps(verdict="BLOCK")
        deps.ah = lambda argv, timeout: (deps.ah_calls.append(argv) or (1, "", "spool down"))
        self.run_all(deps)
        self.run_all(deps)
        self.assertEqual(len(self.comments(deps)), 1, "retried inside the backoff window")
        deps.now += 61
        self.run_all(deps)
        self.assertEqual(len(self.comments(deps)), 2)
        keys = {a[a.index("--key") + 1] for a in self.comments(deps)}
        self.assertEqual(len(keys), 1, "a retry must reuse the same idempotency key")


if __name__ == "__main__":
    unittest.main()
