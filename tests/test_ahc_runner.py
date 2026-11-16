"""ahc_runner (Gate 1, receipt-only): one queued item through resolve, clone, lint/fix, review, verify, write-back
and digest, with a journal that makes every step idempotent and restart-safe. All children are fakes; no network.
GoodQA goodqa#16034 AC-6, AC-7, AC-9; NEG-9 (Gate 1 part), NEG-12, NEG-15, NEG-16."""
import hashlib
import os
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

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

    def commits(self, clone, merge_base, head):
        return [(head, "feat(ahc): an example commit")]

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

    # D19: a ready email route whose mail command hands every critical over at once (EmailRouteTests use the real
    # ops-watch instead)
    ops_caps = "emit\nforward-foreign-critical\ndeadman-delivered\n"
    ops_config = {"sinks": {"deadman": [["fake-mail", "{SUBJECT}"]]}}

    def ops_watch(self, argv, timeout):
        if argv[0] == "capabilities":
            return 0, self.ops_caps, ""
        if argv[0] == "config":
            return 0, json.dumps(self.ops_config), ""
        return 0, json.dumps({"key": argv[argv.index("--key") + 1], "delivered_at": self.now}), ""

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

    def record(self, iid):
        """The admitted request (spec v4 F2: it lives in the ledger, never in a queue file)."""
        ledger = runner.Ledger(self.paths)
        try:
            return json.loads(ledger.item(iid)["request"])
        finally:
            ledger.close()

    def state(self, iid):
        return runner.Journal(self.paths, iid).state()


class FlowTests(Base):
    def test_pass_gate1_writes_digest_merge_command_and_one_comment(self):
        iid, deps = self.submit(), Deps()
        self.run_all(deps)
        self.assertEqual(self.state(iid), "routed-to-main")
        digest = self.paths.digest.read_text()
        self.assertIn("--match-head-commit " + HEAD, digest)
        self.assertEqual(len(deps.review_calls), 1)
        argv = deps.review_calls[0]
        self.assertEqual(argv[argv.index("--expected-head") + 1], HEAD)
        self.assertEqual(argv[argv.index("--snapshot-base") + 1], BASE)
        # P0 AC-5 "unbound" superseded by goodqa#16049 M-1 (user: queue 2026-11-15T03:15:28Z#6165f60532c0): bound to
        # the exact PR, unstamped, never asserting the author harness, so the run still cannot mint merge authority
        self.assertEqual(argv[argv.index("--github-repo") + 1], REPO)
        self.assertEqual(argv[argv.index("--pr") + 1], "7")
        self.assertIn("--no-main-stamp", argv)
        self.assertNotIn("--author-harness", argv)
        self.assertNotIn("--approved-by", argv)
        self.assertLessEqual(int(argv[argv.index("--timeout") + 1]), 720)

    def test_review_argv_without_no_main_stamp_is_refused_before_launch(self):
        # M-1 NEG-7: the check that guards the launch, and the launch path using it
        good = ["peer_review.py", "pr", "--github-repo", REPO, "--pr", "7", "--no-main-stamp"]
        self.assertIsNone(runner.unstamped_argv_problem(good))
        for bad in ([a for a in good if a != "--no-main-stamp"], good + ["--author-harness", "claude"],
                    good + ["--approved-by", "main:x"], ["peer_review.py", "pr", "--no-main-stamp"]):
            with self.subTest(bad=bad):
                self.assertIsNotNone(runner.unstamped_argv_problem(bad))
        iid, deps = self.submit(), Deps()
        with mock.patch.object(runner, "unstamped_argv_problem", return_value="fixture refusal"):
            self.run_all(deps)
        self.assertEqual(deps.review_calls, [], "a refused argv is never launched")
        self.assertEqual(self.state(iid), "needs-attention")

    def test_block_writes_back_once_with_key_and_inbox(self):
        iid, deps = self.submit(), Deps(verdict="BLOCK")
        self.run_all(deps)
        self.run_all(deps)  # a rerun must not duplicate anything
        self.assertEqual(self.state(iid), "block-delivered")
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
        self.assertEqual(self.state(iid), "routed-to-main")
        self.assertEqual(len(deps.review_calls), 1)

    def test_restart_mid_review_without_report_is_outcome_unknown_no_relaunch(self):
        iid, deps = self.submit(), Deps()
        journal = runner.Journal(self.paths, iid)
        journal.append("reviewing", report=str(self.paths.reports / "missing.md"), packet=str(self.packet))
        self.run_all(deps)
        self.assertEqual(self.state(iid), "outcome-unknown")
        self.assertEqual(deps.review_calls, [])

    def test_neg51_unknown_outcome_never_records_failure_or_relaunches(self):
        """D26 / NEG-51: an in-flight review found on restart is not replay-safe: no relaunch, no failure or success
        verdict, an escalation past main on D20 timing, and the item's owner can dispose after reconciling."""
        iid, deps = self.submit(), Deps()
        runner.Journal(self.paths, iid).append("reviewing", report=str(self.paths.reports / "x.md"),
                                               packet=str(self.packet))
        for _ in range(6):
            self.run_all(deps)
            deps.now += 3600
        self.assertEqual(deps.review_calls, [], "a review is never replayed after a crash")
        self.assertEqual(self.state(iid), "outcome-unknown")
        ledger = runner.Ledger(self.paths)
        try:
            events = [r["event"] for r in ledger.db.execute("SELECT event FROM events WHERE item=?", (iid,))]
        finally:
            ledger.close()
        self.assertFalse([e for e in events if e in ("blocked", "block-delivered", "pass", "review-error") or e.startswith("review-error")])
        criticals = [a for a in deps.ah_calls if a[:3] == ["ah", "alert", "raise"]
                     and a[a.index("--severity") + 1] == "critical"]
        self.assertEqual(len(criticals), 1, "escalated past main once by 6 h")

    def test_queued_items_are_replayed_after_restart(self):
        """Replay-safe steps (read-only resolve, lint) are requeued: a crash before the review just runs again."""
        iid, deps = self.submit(), Deps()
        deps.gh_rc = 1
        self.run_all(deps)
        self.assertIn(self.state(iid), ("queued", "deferred"))
        deps.gh_rc = 0
        deps.now += 3600
        self.run_all(deps)
        self.assertEqual(self.state(iid), "routed-to-main")
        self.assertEqual(len(deps.review_calls), 1)

    def test_torn_journal_line_is_ignored(self):
        iid, deps = self.submit(), Deps()
        self.run_all(deps)
        with open(runner.Journal(self.paths, iid).path, "a") as handle:
            handle.write('{"event": "rev')
        self.assertEqual(self.state(iid), "routed-to-main")

    def test_second_instance_exits_cleanly(self):
        first = runner.acquire_lock(self.paths, "core")
        self.assertIsNotNone(first)
        self.assertIsNone(runner.acquire_lock(self.paths, "core"))
        self.assertIsNone(runner.acquire_lock(self.paths, "all"), "an all-in-one run never overlaps a unit")
        review = runner.acquire_lock(self.paths, "review")
        self.assertIsNotNone(review, "the two roles lock independently")
        first.close()
        review.close()

    # --- the ahc-core / ahc-review split (advisor review; NEG-39)
    def test_core_tick_never_touches_a_live_review(self):
        iid, deps = self.submit(), Deps()
        runner.tick(self.paths, self.config, deps, role="core")   # core ingests; it never reviews
        self.assertEqual(deps.review_calls, [])
        runner.STOP_AFTER = "reviewing"   # the review unit is mid-review: state reviewing, effect intent
        try:
            runner.tick(self.paths, self.config, deps, role="review")
        finally:
            runner.STOP_AFTER = None
        ledger = runner.Ledger(self.paths)
        try:
            before = dict(ledger.item(iid))
            ledger.db.execute("UPDATE effects SET status='intent' WHERE kind='review'")
        finally:
            ledger.close()
        for _ in range(3):
            runner.tick(self.paths, self.config, deps, role="core")
            deps.now += 600
        ledger = runner.Ledger(self.paths)
        try:
            after = dict(ledger.item(iid))
        finally:
            ledger.close()
        self.assertEqual((after["state"], after["lease_token"]), (before["state"], before["lease_token"]),
                         "core must neither recover nor lease an item the review unit holds")

    def test_neg39_stale_worker_is_fenced_after_reclaim(self):
        iid, _deps = self.submit(), Deps()
        ledger = runner.Ledger(self.paths)
        try:
            ledger.ensure_item(iid, self.config, _deps.now)
            stale = runner.Worker(self.paths, self.config, _deps, ledger)
            old = stale.lease(iid)
            stale.lease(iid)   # a reclaim mints a new fencing token
            with self.assertRaises(runner.Fenced):
                stale.settle(iid, old, "blocked", event="late-result")
            self.assertEqual(ledger.item(iid)["state"], "queued", "the stale worker changed nothing")
        finally:
            ledger.close()

    def test_roles_beat_their_own_heartbeat(self):
        deps = Deps()
        for role in ("core", "review"):
            runner.tick(self.paths, self.config, deps, role=role)
        services = [a[a.index("--service") + 1] for a in deps.ah_calls if a[:3] == ["ah", "heartbeat", "beat"]]
        self.assertEqual(services, ["ahc-core", "ahc-review"])

    def test_only_core_migrates(self):
        import sqlite3
        runner.Ledger(self.paths).close()
        db = sqlite3.connect(str(self.paths.root / "ledger.sqlite3"))
        db.execute("UPDATE meta SET v='1' WHERE k='schema_version'")
        db.commit()
        db.close()
        with self.assertRaises(runner.SchemaError):
            runner.tick(self.paths, self.config, Deps(), role="review")
        with self.assertRaises(runner.SchemaError):
            runner.Ledger(self.paths, migrate=False)
        self.assertFalse(list(self.paths.root.glob("ledger.sqlite3.pre-v*.bak")), "a non-core opener made no backup")
        runner.tick(self.paths, self.config, Deps(), role="core")
        self.assertEqual(len(list(self.paths.root.glob("ledger.sqlite3.pre-v*.bak"))), 1)


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
        self.assertEqual(runner.retry_policy("quota", 3, now + 86400, first_at=now)[0], "review-error")  # T8
        self.assertEqual(runner.retry_policy("auth", 1, now), ("deferred", now + 1800))  # T15
        self.assertEqual(runner.retry_policy("block", 1, now), ("block-delivered", None))
        self.assertEqual(runner.retry_policy("invalid-output", 1, now)[0], "deferred")
        self.assertEqual(runner.retry_policy("invalid-output", 2, now), ("review-invalid", None))  # T14
        self.assertEqual(runner.retry_policy("invalid-output", 1, now, config={"bounds": {
            "invalid_output_repeat": False}}), ("review-invalid", None))
        self.assertEqual(runner.retry_policy("provider-transient", 1, now), ("deferred", now + 900))  # T11
        self.assertEqual(runner.retry_policy("provider-transient", 2, now), ("needs-attention", None))  # T16
        self.assertEqual(runner.retry_policy("freshness", 1, now), ("deferred", now + 60))  # T13
        self.assertEqual(runner.retry_policy("freshness", 2, now), ("needs-attention", None))  # T16
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
        self.assertEqual(self.state(iid), "deferred", "T15: auth defers on the circuit")
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

    def test_auth_deferral_never_relaunches_and_ends_at_the_24h_deadline(self):
        """T15 + T8: an auth block defers on the open circuit, consumes no class, never relaunches while the circuit
        is open, and ends in review-error 24 h after the head's first deferral."""
        iid, deps = self.submit(), ErrDeps("PROVIDER_AUTH")
        start = deps.now
        self.run_all(deps)
        while deps.now < start + 25 * 3600:
            deps.now += 1800
            self.run_all(deps)
        self.assertEqual(len(deps.review_calls), 1, "relaunched while the auth circuit was open")
        self.assertEqual(self.state(iid), "review-error")
        ledger = runner.Ledger(self.paths)
        try:
            budget = ledger.head_budget("%s|7" % REPO, HEAD)
        finally:
            ledger.close()
        self.assertEqual((budget["transient"], budget["invalid"], budget["freshness"]), (0, 0, 0))

    def test_invalid_output_gets_one_declared_repeat_then_owner(self):
        iid, deps = self.submit(), ErrDeps("PROVIDER_INVALID_OUTPUT")
        for _ in range(4):
            self.run_all(deps)
            deps.now += 120
        self.assertEqual(len(deps.review_calls), 2)
        repeat = deps.review_calls[1][deps.review_calls[1].index("--repeat-reason") + 1]
        self.assertTrue(repeat.startswith("PROVIDER_INVALID_OUTPUT"))
        self.assertEqual(self.state(iid), "review-invalid")

    def test_invalid_output_without_repeat_flag_goes_to_owner(self):
        self.config["bounds"] = {"invalid_output_repeat": False}
        iid, deps = self.submit(), ErrDeps("PROVIDER_INVALID_OUTPUT")
        for _ in range(3):
            self.run_all(deps)
            deps.now += 120
        self.assertEqual(len(deps.review_calls), 1)
        self.assertEqual(self.state(iid), "review-invalid")

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


class AtomicNoticeTests(Base):
    """code-inspection r1 F1: a state change and its notice commit together; a crash in between loses neither."""

    def crash_once(self):
        real = runner.Worker._insert_notice
        calls = {"n": 0}

        def boom(worker, *a, **kw):
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("injected crash during notice insertion")
            return real(worker, *a, **kw)
        runner.Worker._insert_notice = boom
        self.addCleanup(setattr, runner.Worker, "_insert_notice", real)

    def rows(self, sql, *args):
        ledger = runner.Ledger(self.paths)
        try:
            return ledger.db.execute(sql, args).fetchall()
        finally:
            ledger.close()

    def test_crash_in_notice_insert_rolls_back_the_block_and_redelivers_once(self):
        iid, deps = self.submit(), Deps(verdict="BLOCK")
        self.crash_once()
        with self.assertRaises(RuntimeError):
            self.run_all(deps)
        self.assertNotEqual(self.state(iid), "block-delivered", "item settled without its notice (F1)")
        self.assertEqual(self.rows("SELECT * FROM notices WHERE item=?", iid), [])
        for _ in range(3):
            self.run_all(deps)
            deps.now += 120
        self.assertEqual(self.state(iid), "block-delivered")
        self.assertEqual(len(deps.review_calls), 1, "the crash must not cause a second review")
        self.assertEqual(len(self.rows("SELECT * FROM notices WHERE item=?", iid)), 1)
        comments = [a for a in deps.ah_calls if a[:3] == ["ah", "ticket", "comment"]]
        self.assertEqual(len(comments), 1)

    def test_crash_in_notice_insert_rolls_back_a_refusal(self):
        iid, deps = self.submit(), Deps()
        closed = {"number": 7, "state": "CLOSED", "headRefOid": HEAD, "baseRefOid": BASE, "baseRefName": "main",
                  "isCrossRepository": False}
        deps.gh = lambda argv, timeout: (0, json.dumps(closed), "")
        self.crash_once()
        with self.assertRaises(RuntimeError):
            self.run_all(deps)
        self.assertNotEqual(self.state(iid), "refused")
        self.run_all(deps)
        self.assertEqual(self.state(iid), "refused")
        self.assertEqual(len(self.rows("SELECT * FROM notices WHERE item=?", iid)), 1)

    def test_terminal_unsuccessful_gets_ticket_and_alert(self):
        iid, deps = self.submit(), ErrDeps("EXEC_MISSING")   # an environment defect: needs-attention
        self.run_all(deps)
        self.assertEqual(self.state(iid), "needs-attention")
        alerts = [a for a in deps.ah_calls if a[:3] == ["ah", "alert", "raise"]]
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0][alerts[0].index("--alert-key") + 1], "ahc:" + iid)
        self.assertEqual(alerts[0][alerts[0].index("--severity") + 1], "high")
        self.assertTrue([a for a in deps.ah_calls if a[:3] == ["ah", "ticket", "comment"]])
        kinds = {r["kind"] for r in self.rows("SELECT kind FROM effects WHERE item=?", iid)}
        self.assertTrue({"alert", "ticket"} <= kinds)
        self.assertNotIn("sink", kinds)

    def test_block_alone_does_not_alert_until_no_ack(self):
        iid, deps = self.submit(), Deps(verdict="BLOCK")
        self.run_all(deps)
        self.assertEqual([a for a in deps.ah_calls if a[:3] == ["ah", "alert", "raise"]], [])
        deps.now += 4 * 3600 + 1
        self.run_all(deps)
        alerts = [a for a in deps.ah_calls if a[:3] == ["ah", "alert", "raise"]]
        self.assertEqual(len(alerts), 1, "an unacked block escalates exactly once with an alert")
        self.run_all(deps)
        self.assertEqual(len([a for a in deps.ah_calls if a[:3] == ["ah", "alert", "raise"]]), 1)


class OutcomeClassTests(Base):
    """code-inspection r1 F3: only listed codes are transient; an unknown outcome is never retried automatically."""

    def test_classification_table(self):
        cls = runner.classify_review_failure
        diag = "REVIEW_DIAGNOSTIC code=%s reason=x"
        for code in ("PROVIDER_UNAVAILABLE", "PROVIDER_TIMEOUT", "BUDGET_EXHAUSTED", "SNAPSHOT_TIMEOUT",
                     "SNAPSHOT_SOURCE_CHANGED", "SNAPSHOT_GIT_FAILED", "REVIEW_NOT_STARTED"):
            self.assertEqual(cls(diag % code, 2)[0], "provider-transient", code)
        self.assertEqual(cls(diag % "PROVIDER_USAGE_LIMIT", 2)[0], "quota")
        self.assertEqual(cls(diag % "PROVIDER_AUTH", 2)[0], "auth")
        self.assertEqual(cls(diag % "FALLBACK_NO_RESULT", 2)[0], "invalid-output")
        self.assertEqual(cls(diag % "REVIEW_NOT_STARTED" + " pool held by run 12", 2)[0], "contention")
        for code in ("REVIEW_LAUNCH_UNCONFIRMED", "PROVIDER_IO_UNKNOWN", "ISOLATION_FAILED"):
            self.assertEqual(cls(diag % code, 2)[0], "unknown-outcome", code)
        self.assertEqual(cls("", 2)[0], "unknown-outcome")
        self.assertEqual(cls(diag % "PROVIDER_UNAVAILABLE", core.TIMEOUT_RC)[0], "unknown-outcome")
        self.assertEqual(cls("", 127)[0], "unknown-outcome")
        for code in ("EXEC_FAILED", "SNAPSHOT_TOO_LARGE", "PYTHON_UNSUPPORTED"):
            self.assertEqual(cls(diag % code, 2)[0], "environment", code)
        # spec owner ruling (v16b): an unlisted code may mean the provider launched
        self.assertEqual(cls(diag % "SOMETHING_NEW", 2)[0], "unknown-outcome")

    def test_unknown_outcome_is_outcome_unknown_and_never_relaunched(self):
        iid, deps = self.submit(), ErrDeps("REVIEW_LAUNCH_UNCONFIRMED")
        for _ in range(4):
            self.run_all(deps)
            deps.now += 7200
        self.assertEqual(len(deps.review_calls), 1)
        self.assertEqual(self.state(iid), "outcome-unknown")
        inbox = list((self.paths.inbox / "agent-abc123").glob("*.md"))
        self.assertIn("usage_guard", inbox[0].read_text())

    def test_missing_diagnostic_is_not_transient(self):
        iid, deps = self.submit(), ErrDeps("")

        def review(argv, timeout):
            deps.review_calls.append(argv)
            return 2, "boom"
        deps.review = review
        for _ in range(3):
            self.run_all(deps)
            deps.now += 7200
        self.assertEqual(len(deps.review_calls), 1)
        self.assertEqual(self.state(iid), "outcome-unknown")  # an unlisted failure may have launched (v16b ruling)

    def test_contention_waits_without_counting_or_repeat_reason(self):
        iid, deps = self.submit(), ErrDeps("REVIEW_NOT_STARTED")

        def review(argv, timeout):
            deps.review_calls.append(argv)
            return 2, "REVIEW_DIAGNOSTIC code=REVIEW_NOT_STARTED reason=pool held"
        deps.review = review
        for _ in range(4):
            self.run_all(deps)
            deps.now += 130
        self.assertGreaterEqual(len(deps.review_calls), 3, "contention must keep waiting, not give up")
        self.assertEqual(self.state(iid), "deferred")
        for argv in deps.review_calls:
            self.assertNotIn("--repeat-reason", argv)
        ledger = runner.Ledger(self.paths)
        try:
            attempts = json.loads(ledger.item(iid)["attempts"])
        finally:
            ledger.close()
        self.assertNotIn("contention", attempts)

    def test_policy_for_new_classes(self):
        self.assertEqual(runner.retry_policy("unknown-outcome", 1, 0.0), ("outcome-unknown", None))
        self.assertEqual(runner.retry_policy("environment", 1, 0.0), ("needs-attention", None))


class IngestValidationTests(Base):
    """code-inspection r2 F5: a queue file is re-validated at ingest; a bad one is quarantined with one alert and never
    stops the tick (heartbeat written, the valid item alongside it completes); inbox paths stay inside the inbox."""

    def plant(self, name, text):
        self.paths.ensure()
        path = self.paths.queue / name
        path.write_text(text)
        return path

    def valid_record(self):
        iid = self.submit()
        return iid, self.record(iid)

    def assert_isolated(self, bad_name, deps):
        """The bad file is quarantined with a reason, alerted once, and the valid item still completes."""
        rejected = self.paths.root / "rejected"
        self.assertFalse((self.paths.queue / bad_name).exists() or (self.paths.queue / bad_name).is_symlink())
        moved = [p for p in rejected.iterdir() if not p.name.endswith(".reason")]
        self.assertEqual(len(moved), 1)
        self.assertTrue((rejected / (moved[0].name + ".reason")).read_text().strip())
        heartbeats = [a for a in deps.ah_calls if a[:3] == ["ah", "heartbeat", "beat"]]
        self.assertGreaterEqual(len(heartbeats), 1, "the tick died before its heartbeat")
        alerts = [a for a in deps.ah_calls if a[:3] == ["ah", "alert", "raise"]
                  and a[a.index("--alert-key") + 1].startswith("ahc:rejected:")]
        self.assertEqual(len(alerts), 1, "exactly one alert per rejected file, also across re-scans")
        self.assertEqual(alerts[0][alerts[0].index("--key") + 1], "ahc-rejected-" + moved[0].name)
        self.assertEqual(alerts[0][alerts[0].index("--alert-key") + 1], "ahc:rejected:" + moved[0].name)

    def run_with_bad(self, bad_name, bad_text):
        good, _rec = self.valid_record()
        self.plant(bad_name, bad_text)
        deps = Deps()
        self.run_all(deps)
        deps.now += 120
        self.run_all(deps)  # a re-scan must not re-alert or re-raise
        self.assertEqual(self.state(good), "routed-to-main", "a poisoned queue file stopped a valid item")
        self.assert_isolated(bad_name, deps)
        return deps

    def test_missing_fields_are_quarantined_and_tick_continues(self):
        name = "ahc-00000000000000000000.json"
        self.run_with_bad(name, json.dumps({"id": "ahc-00000000000000000000"}))

    def test_non_finite_or_future_timestamp_is_quarantined(self):
        for submitted in (float("inf"), 1_800_000_000.0 + 86400, "1", None):
            with self.subTest(submitted=submitted):
                self.setUp()
                good, rec = self.valid_record()
                bad = dict(rec, pr=8, submitted=submitted)
                bad["id"] = core.item_id(bad, bad["packet_sha256"])
                self.plant(bad["id"] + ".json", json.dumps(bad))
                deps = Deps()
                self.run_all(deps)
                self.assertEqual(self.state(good), "routed-to-main")
                self.assert_isolated(bad["id"] + ".json", deps)
                self.tearDown()

    def test_forged_id_is_quarantined(self):
        _good, rec = self.valid_record()
        forged = dict(rec, pr=9)   # content changed, id kept: not the recomputed identity
        forged["id"] = "ahc-" + "1" * 20
        self.run_with_bad(forged["id"] + ".json", json.dumps(forged))

    def test_owner_traversal_is_quarantined_and_nothing_written_outside_inbox(self):
        _good, rec = self.valid_record()
        evil = dict(rec, pr=10, owner="../../../../escape")
        evil["id"] = core.item_id(evil, evil["packet_sha256"])
        self.run_with_bad(evil["id"] + ".json", json.dumps(evil))
        self.assertFalse(list(self.home.rglob("escape*")), "a notice was written outside the inbox")

    def test_symlinked_queue_entry_is_moved_not_followed(self):
        good, rec = self.valid_record()
        planted = dict(rec, pr=11)  # a fully valid record: only the symlink makes it unacceptable
        planted["id"] = core.item_id(planted, planted["packet_sha256"])
        outside = self.home / "outside.json"
        outside.write_text(json.dumps(planted))
        link = self.paths.queue / (planted["id"] + ".json")
        link.symlink_to(outside)
        deps = Deps()
        self.run_all(deps)
        self.assertEqual(self.state(good), "routed-to-main")
        self.assertIsNone(self.state(planted["id"]), "a symlinked queue entry was followed and accepted")
        self.assertTrue(outside.exists(), "the symlink target must not be moved or deleted")
        moved = self.paths.root / "rejected" / link.name
        self.assertTrue(moved.is_symlink(), "the link itself is quarantined")

    def test_a_report_not_written_into_the_attempt_directory_ahc_created_is_never_a_pass(self):
        """PR 258 v3 (main's ruling on the review child). ahc creates the attempt's private report directory
        exclusively and records its inode. After the child exits, ahc reads the report only through that same
        directory. The report must be that directory's only entry: a regular file owned by this uid with one link
        and within the size cap. A replaced directory (before or after the child exits), a linked or hard-linked
        report, an extra entry or an oversized report gives INVALID, never PASS. The attempt directory is
        quarantined into rejected/, and a file outside the root is never touched. A normal report in the created
        directory still passes. (Spec owner's conditions on the report-directory deviation.)"""
        cases = {}

        def swap_dir(out):          # before the child: the directory is replaced, and the child writes there
            aside = out.parent.with_name(out.parent.name + ".moved")
            os.rename(str(out.parent), str(aside))
            out.parent.mkdir(mode=0o700)
            return out, None

        def link_report(out):       # the report name is a link to a PASS report kept elsewhere
            elsewhere = self.home / "forged.md"
            os.symlink(str(elsewhere), str(out))
            return elsewhere, None

        def hard_link(out):         # after the child: a second name for the report, outside ahc's directory
            def after():
                os.link(str(out), str(self.home / ("hard-%s.md" % out.parent.name)))
            return out, after

        def extra_entry(out):       # after the child: another file beside the report
            def after():
                (out.parent / "extra.md").write_text("VERDICT: PASS\n")
            return out, after

        def swap_after_exit(out):   # after the child: the whole directory is replaced by a copy
            def after():
                body = out.read_bytes()
                os.rename(str(out.parent), str(out.parent.with_name(out.parent.name + ".moved")))
                out.parent.mkdir(mode=0o700)
                out.write_bytes(body)
            return out, after

        def oversized(out):         # after the child: the report grows past the cap
            def after():
                with open(str(out), "ab") as handle:
                    handle.write(b"x" * (core.REPORT_MAX_BYTES + 1))
            return out, after
        cases["replaced directory"] = swap_dir
        cases["linked report"] = link_report
        cases["hard-linked report"] = hard_link
        cases["extra entry"] = extra_entry
        cases["directory swapped after exit"] = swap_after_exit
        cases["oversized report"] = oversized
        for label, tamper in cases.items():
            with self.subTest(case=label):
                self.tearDown()
                self.setUp()
                iid = self.submit()
                deps = Deps(verdict="PASS")
                plain = deps.review

                def review(argv, timeout, tamper=tamper, plain=plain):
                    out = Path(argv[argv.index("--output") + 1])
                    target, after = tamper(out)
                    rc = plain(argv[:argv.index("--output") + 1] + [str(target)] + argv[argv.index("--output") + 2:],
                               timeout)
                    if after:
                        after()
                    return rc
                deps.review = review
                forged = self.home / "forged.md"
                self.run_all(deps)
                self.assertNotEqual(self.state(iid), "routed-to-main", "%s became a PASS" % label)
                rejected = sorted(p.name for p in (self.paths.root / "rejected").glob("report-%s-a1*" % iid))
                self.assertTrue(any(n.endswith(".reason") for n in rejected), "%s: no quarantine reason" % label)
                self.assertTrue(any(not n.endswith(".reason") for n in rejected), "%s: not quarantined" % label)
                if label == "hard-linked report":
                    outside = self.home / ("hard-%s-a1.md" % iid)
                    self.assertEqual(os.stat(str(outside)).st_nlink, 2, "the outside name must be left alone")
                if label == "linked report":
                    self.assertTrue(forged.exists(), "the link target outside the root must be left alone")
        self.tearDown()
        self.setUp()
        iid, deps = self.submit(), Deps(verdict="PASS")
        self.run_all(deps)
        self.assertEqual(self.state(iid), "routed-to-main", "an honest report in the created directory must pass")

    def test_links_in_every_shared_dir_are_refused_at_their_operation_while_ahc_keeps_serving(self):
        """PR 258 v2 (spec owner's condition 1). Shared dirs are checked per operation, not walked at start, so
        links in all five must neither stop ahc nor be followed. Item A is refused where the links touch it: its
        report name is taken by a link and its owner notice name is a link. Item B, untouched, still completes,
        and every external target stays byte-identical."""
        self.paths.ensure()
        b = self.submit()
        a = core.submit(self.paths, self.config, {   # a different PR, so B never supersedes it
            "repo": REPO, "pr": 8, "head": HEAD, "base": BASE, "packet": str(self.packet),
            "ticket": "GoodQA goodqa#16034", "owner": "agent-abc123"})["id"]
        externals = {}

        def plant(link, name):
            target = self.home / ("external-" + name)
            target.write_text("external " + name)
            externals[target] = target.read_text()
            link.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.symlink(str(target), str(link))
            return link

        _, rec = self.valid_record()
        queued = plant(self.paths.queue / (rec["id"] + ".json"), "queue")
        report = plant(self.paths.reports / ("%s-a1" % a), "report")
        plant(self.paths.inbox / "agent-abc123" / ("%s-needs-attention.md" % a), "inbox")
        staged = plant(self.paths.packets / ("e" * 64 + ".md"), "staging")
        rejected = plant(self.paths.root / "rejected" / "old.json", "rejected")
        deps = Deps(verdict="BLOCK")
        plain_gh = deps.gh

        def gh(argv, timeout):          # the fixture serves PR 7; answer for whichever PR is asked
            rc, out, err = plain_gh(argv, timeout)
            if argv[1:3] == ["pr", "view"]:
                pr = json.loads(out)
                pr["number"] = int(argv[3])
                out = json.dumps(pr)
            return rc, out, err
        deps.gh = gh
        for _ in range(4):
            self.run_all(deps)           # never ForeignRoot: shared-dir links do not stop the daemon
            deps.now += 7200
        self.assertEqual(self.state(b), "block-delivered", "an unrelated item stopped being served")
        self.assertEqual(self.state(a), "needs-attention", "a linked report path must refuse the review")
        self.assertTrue(report.is_symlink())
        self.assertFalse(queued.exists() or os.path.lexists(str(queued)), "the queue link was not quarantined")
        self.assertTrue((self.paths.root / "rejected" / queued.name).is_symlink())
        self.assertTrue(staged.is_symlink() and rejected.is_symlink())
        ledger = runner.Ledger(self.paths)
        try:
            notices = ledger.db.execute("SELECT status, result FROM effects WHERE item=? AND kind='inbox'",
                                        (a,)).fetchall()
        finally:
            ledger.close()
        self.assertTrue(notices, "item A's owner notice was never attempted")
        self.assertTrue(all(row["status"] != "done" and "refused" in (row["result"] or "") for row in notices),
                        "a notice written to a linked name looked delivered")
        for target, text in externals.items():
            self.assertEqual(target.read_text(), text, "%s was written through a link" % target.name)

    def test_inbox_path_rejects_escape_after_resolving(self):
        with self.assertRaises(core.Refused):
            core.inbox_path(self.paths, "..", "x.md")
        with self.assertRaises(core.Refused):
            core.inbox_path(self.paths, "agent-abc123", "../x.md")
        self.paths.ensure()
        elsewhere = self.home / "elsewhere"
        elsewhere.mkdir()
        (self.paths.inbox / "agent-evil1").symlink_to(elsewhere)
        with self.assertRaises(core.Refused):
            core.inbox_path(self.paths, "agent-evil1", "x.md")
        self.assertEqual(core.inbox_path(self.paths, "agent-abc123", "x.md"), self.paths.inbox / "agent-abc123" / "x.md")

    def test_inbox_write_never_follows_a_symlinked_owner_dir(self):
        self.paths.ensure()
        elsewhere = self.home / "elsewhere"
        elsewhere.mkdir()
        (self.paths.inbox / "agent-evil1").symlink_to(elsewhere)
        with self.assertRaises(OSError):
            runner._write_inbox(self.paths.inbox, "agent-evil1", "n.md", "body")
        self.assertEqual(list(elsewhere.iterdir()), [], "a notice was written through a symlink")
        runner._write_inbox(self.paths.inbox, "agent-abc123", "n.md", "body")
        self.assertEqual((self.paths.inbox / "agent-abc123" / "n.md").read_text(), "body")

    def test_owner_dir_swapped_after_the_check_is_not_followed(self):
        """Race: the owner directory becomes a symlink between inbox_path's check and the write (check-then-write)."""
        import shutil
        import sys as _sys
        elsewhere = self.home / "elsewhere"
        elsewhere.mkdir()
        real_check = core.inbox_path

        def check_then_swap(paths, owner, name, resolve=True):
            result = real_check(paths, owner, name, resolve=resolve)
            if _sys._getframe(1).f_code.co_name == "send":   # only the delivery-time check
                target = paths.inbox / owner
                if target.is_dir() and not target.is_symlink():
                    shutil.rmtree(target)
                if not target.is_symlink():
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.symlink_to(elsewhere)
            return result
        core.inbox_path = check_then_swap
        self.addCleanup(setattr, core, "inbox_path", real_check)
        iid, deps = self.submit(), Deps(verdict="BLOCK")
        self.run_all(deps)
        self.assertEqual(self.state(iid), "block-delivered")
        self.assertEqual(list(elsewhere.iterdir()), [], "the inbox write followed a swapped-in symlink")
        ledger = runner.Ledger(self.paths)
        try:
            row = ledger.db.execute("SELECT status, result FROM effects WHERE item=? AND kind='inbox'",
                                    (iid,)).fetchone()
        finally:
            ledger.close()
        self.assertNotEqual(row["status"], "done")
        self.assertIn("refused", row["result"] or "")

    def test_symlink_planted_at_the_notice_name_is_not_delivered(self):
        iid = self.submit()
        self.paths.ensure()
        owner_dir = self.paths.inbox / "agent-abc123"
        owner_dir.mkdir(mode=0o700)
        decoy = self.home / "decoy.md"
        decoy.write_text("anything")
        (owner_dir / ("%s-block-delivered.md" % iid)).symlink_to(decoy)
        deps = Deps(verdict="BLOCK")
        self.run_all(deps)
        self.assertEqual(self.state(iid), "block-delivered")
        self.assertEqual(decoy.read_text(), "anything", "the decoy target was written through the link")
        ledger = runner.Ledger(self.paths)
        try:
            row = ledger.db.execute("SELECT status, result, payload FROM effects WHERE item=? AND kind='inbox'",
                                    (iid,)).fetchone()
        finally:
            ledger.close()
        self.assertNotEqual(row["status"], "done", "a planted symlink made the notice look delivered")
        self.assertIn("refused", row["result"] or "")
        worker = runner.Worker(self.paths, self.config, deps, runner.Ledger(self.paths))
        try:
            self.assertFalse(worker.readback("inbox", json.loads(row["payload"])))
        finally:
            worker.led.close()

    def test_inbox_readback_requires_a_regular_file_with_the_written_bytes(self):
        self.paths.ensure()
        runner._write_inbox(self.paths.inbox, "agent-abc123", "n.md", "body one")
        self.assertTrue(runner._inbox_delivered(self.paths.inbox, "agent-abc123", "n.md", "body one"))
        self.assertFalse(runner._inbox_delivered(self.paths.inbox, "agent-abc123", "n.md", "body two"))
        self.assertFalse(runner._inbox_delivered(self.paths.inbox, "agent-abc123", "missing.md", "body one"))
        with self.assertRaises(OSError):   # a different notice already occupies the name: refuse, never overwrite
            runner._write_inbox(self.paths.inbox, "agent-abc123", "n.md", "body two")


class UntrustedReadTests(Base):
    """code-inspection r3 F5 (continued) and F6: no file another actor can write or replace (packet, notice, review
    report) can block the tick or exhaust memory. A SIGALRM guard turns a regression into a failure, not a hang."""

    def setUp(self):
        super().setUp()
        import signal

        def blocked(signum, frame):
            raise AssertionError("the tick blocked on an untrusted file (FIFO/oversize)")
        self._old_alarm = signal.signal(signal.SIGALRM, blocked)
        signal.alarm(15)

    def tearDown(self):
        import signal
        signal.alarm(0)
        signal.signal(signal.SIGALRM, self._old_alarm)
        super().tearDown()

    def plant_record(self, packet_path, pr):
        """An admitted item whose packet path later turns hostile (admitted directly: submit's lint never saw it)."""
        good = self.submit()
        bad = dict(self.record(good), pr=pr, packet=str(packet_path))
        bad["id"] = core.item_id(bad, bad["packet_sha256"])
        runner.admit(self.paths, self.config, bad)
        return good, bad["id"]

    def assert_tick_survives(self, good, bad, deps):
        self.assertEqual(self.state(good), "routed-to-main", "a valid item stopped behind an untrusted packet")
        self.assertEqual(self.state(bad), "refused")
        self.assertTrue([a for a in deps.ah_calls if a[:3] == ["ah", "heartbeat", "beat"]])
        inbox = list((self.paths.inbox / "agent-abc123").glob(bad + "-refused.md"))
        self.assertEqual(len(inbox), 1, "the owner was not told why the packet was refused")

    def test_fifo_packet_is_refused_without_blocking(self):
        import os
        fifo = self.packet.parent / "fifo.md"
        os.mkfifo(fifo)
        good, bad = self.plant_record(fifo, 12)
        deps = Deps()
        for _ in range(2):
            self.run_all(deps)
            deps.now += 120
        self.assert_tick_survives(good, bad, deps)

    def test_oversized_packet_is_refused_without_reading_it_all(self):
        big = self.packet.parent / "big.md"
        big.write_bytes(b"x" * (core.PACKET_MAX_BYTES + 1))
        good, bad = self.plant_record(big, 13)
        deps = Deps()
        for _ in range(2):
            self.run_all(deps)
            deps.now += 120
        self.assert_tick_survives(good, bad, deps)

    def test_packet_replaced_by_fifo_after_submit_is_refused(self):
        import os
        other = self.packet.parent / "p2.md"
        other.write_text(GOOD_PACKET)
        good = self.submit()
        req = {"repo": REPO, "pr": 14, "head": HEAD, "base": BASE, "packet": str(other),
               "ticket": "GoodQA goodqa#16034", "owner": "agent-abc123"}
        bad = core.submit(self.paths, self.config, req)["id"]
        other.unlink()
        os.mkfifo(other)
        deps = Deps()
        for _ in range(2):
            self.run_all(deps)
            deps.now += 120
        self.assert_tick_survives(good, bad, deps)

    def test_fifo_at_the_notice_name_is_not_delivered_and_does_not_block(self):
        import os
        iid = self.submit()
        self.paths.ensure()
        owner_dir = self.paths.inbox / "agent-abc123"
        owner_dir.mkdir(mode=0o700)
        os.mkfifo(owner_dir / ("%s-block-delivered.md" % iid))
        deps = Deps(verdict="BLOCK")
        self.run_all(deps)
        self.assertEqual(self.state(iid), "block-delivered")
        self.assertTrue([a for a in deps.ah_calls if a[:3] == ["ah", "heartbeat", "beat"]])
        ledger = runner.Ledger(self.paths)
        try:
            row = ledger.db.execute("SELECT status, result FROM effects WHERE item=? AND kind='inbox'",
                                    (iid,)).fetchone()
        finally:
            ledger.close()
        self.assertNotEqual(row["status"], "done")
        self.assertIn("refused", row["result"] or "")

    def test_notice_swapped_to_fifo_between_check_and_open_does_not_block(self):
        """F6 race, deterministic: a correct notice exists; the first open of that name swaps it for a FIFO."""
        import os
        self.paths.ensure()
        runner._write_inbox(self.paths.inbox, "agent-abc123", "n.md", "body one")
        real_open = os.open
        swapped = {"done": False}

        def swapping_open(path, flags, *args, **kwargs):
            if path == "n.md" and kwargs.get("dir_fd") is not None and not swapped["done"]:
                swapped["done"] = True
                target = self.paths.inbox / "agent-abc123" / "n.md"
                target.unlink()
                os.mkfifo(target)
            return real_open(path, flags, *args, **kwargs)
        os.open = swapping_open
        self.addCleanup(setattr, os, "open", real_open)
        self.assertFalse(runner._inbox_delivered(self.paths.inbox, "agent-abc123", "n.md", "body one"))
        self.assertTrue(swapped["done"], "the race was not exercised")

    def test_parent_dir_swapped_after_the_containment_check_is_not_followed(self):
        """r4 F1: the work dir becomes a symlink to an identical packet outside the work roots right after the check."""
        import os
        work = self.packet.parent
        outside = self.home / "outside"
        outside.mkdir()
        (outside / self.packet.name).write_text(GOOD_PACKET)   # same bytes, so only the path check can catch it
        iid = self.submit()
        real_inside = core._inside

        def check_then_swap(path_value, roots):
            ok = real_inside(path_value, roots)
            # only the review-time check in Worker.process; ingest's validation also calls _inside
            if ok and not work.is_symlink() and sys._getframe(1).f_code.co_name == "process":
                os.rename(work, work.with_name("s-moved"))
                work.symlink_to(outside)
            return ok
        core._inside = check_then_swap
        self.addCleanup(setattr, core, "_inside", real_inside)
        deps = Deps()
        self.run_all(deps)
        self.assertEqual(self.state(iid), "refused", "the packet was read through a swapped parent directory")
        self.assertEqual(deps.review_calls, [])

    def test_fifo_digest_and_lock_never_block(self):
        import os
        self.paths.ensure()
        iid, deps = self.submit(), Deps(verdict="BLOCK")
        os.mkfifo(self.paths.digest)
        self.assertFalse(runner._digest_has(self.paths.digest, "x"))
        with self.assertRaises(OSError):
            runner._append_private(self.paths.root, self.paths.digest, "line\n")
        # PR 258 v1 BLOCK: a FIFO at a top-level ahc name is not ahc's file, so the start is refused (exit 3 from
        # the CLI) instead of running around it; nothing blocks either way.
        with self.assertRaises(core.ForeignRoot):
            self.run_all(deps)
        os.unlink(self.paths.digest)
        self.run_all(deps)
        self.assertEqual(self.state(iid), "block-delivered")
        self.assertTrue([a for a in deps.ah_calls if a[:3] == ["ah", "heartbeat", "beat"]])
        lock = self.paths.root / "ahc-core.lock"
        if os.path.lexists(str(lock)):
            os.unlink(str(lock))
        os.mkfifo(lock)
        with self.assertRaises((OSError, core.ForeignRoot)):
            runner.acquire_lock(self.paths, "core")

    def test_digest_readback_reads_only_a_bounded_tail(self):
        self.paths.ensure()
        with open(self.paths.digest, "w") as handle:
            handle.write("[k:early]\n" + "x" * (runner.DIGEST_TAIL_BYTES + 10) + "\n[k:late]\n")
        self.assertTrue(runner._digest_has(self.paths.digest, "late"))
        self.assertFalse(runner._digest_has(self.paths.digest, "early"), "readback must not scan the whole digest")

    def test_submit_lints_and_hashes_the_same_bytes(self):
        """r4 F3: a packet swapped between the lint read and the hash read cannot be queued under the swapped bytes."""
        real = core.read_regular
        calls = {"n": 0}

        def swap_after_first(path, cap, dir_fd=None):
            calls["n"] += 1
            if calls["n"] == 2:
                self.packet.write_text(GOOD_PACKET + "\nswapped after lint\n")
            return real(path, cap, dir_fd=dir_fd)
        core.read_regular = swap_after_first
        self.addCleanup(setattr, core, "read_regular", real)
        req = {"repo": REPO, "pr": 7, "head": HEAD, "base": BASE, "packet": str(self.packet),
               "ticket": "GoodQA goodqa#16034", "owner": "agent-abc123"}
        original = hashlib.sha256(GOOD_PACKET.encode()).hexdigest()
        iid = runner.submit_with_lint(self.paths, self.config, req)["id"]
        self.assertEqual(self.record(iid)["packet_sha256"], original, "the hashed bytes are not the linted bytes")

    def test_fifo_review_report_does_not_block(self):
        import os
        iid = self.submit()
        deps = Deps()

        def fifo_review(argv, timeout):
            deps.review_calls.append(argv)
            os.mkfifo(argv[argv.index("--output") + 1])
            return 0
        deps.review = fifo_review
        self.run_all(deps)
        self.assertTrue([a for a in deps.ah_calls if a[:3] == ["ah", "heartbeat", "beat"]])
        self.assertNotEqual(self.state(iid), "routed-to-main", "a FIFO report must never verify as PASS")


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

    def test_ack_by_owner_stops_the_no_ack_escalation_only(self):
        iid, deps = self.block()
        with self.assertRaises(core.Refused):
            runner.ack(self.paths, iid, "agent-someone-else")
        self.assertEqual(runner.ack(self.paths, iid, "agent-abc123", now=deps.now), 1)
        self.assertEqual(self.state(iid), "acknowledged", "v6e M4: an ack moves a delivered BLOCK to acknowledged")
        deps.now += 3 * 3600
        self.run_all(deps)
        self.assertEqual(len(self.comments(deps)), 1, "no 'has not acknowledged' escalation after the ack")
        # the repair deadline is AckInactivityTests' subject: it still fires 4 h after the ack

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


class RoutedTests(Base):
    """D20: a PASS waits as routed-to-main; ticket escalation 4 h after routing, then every 24 h."""

    def overdue_comments(self, deps):
        return [a for a in deps.ah_calls if a[:3] == ["ah", "ticket", "comment"] and "-d20-routed-to-main-" in
                a[a.index("--key") + 1]]

    def test_escalates_at_4h_then_every_24h(self):
        iid, deps = self.submit(), Deps()
        self.run_all(deps)
        self.assertEqual(self.state(iid), "routed-to-main")
        for hours in range(1, 4):
            deps.now += 3600
            self.run_all(deps)
        self.assertEqual(self.overdue_comments(deps), [])
        deps.now += 3600
        self.run_all(deps)
        self.assertEqual(len(self.overdue_comments(deps)), 1)
        for _ in range(23):
            deps.now += 3600
            self.run_all(deps)
        self.assertEqual(len(self.overdue_comments(deps)), 1)
        deps.now += 3600
        self.run_all(deps)
        self.assertEqual(len(self.overdue_comments(deps)), 2)

    def test_protected_path_is_named_in_the_routing_reason(self):
        iid, deps = self.submit(), Deps()
        deps.changed_paths = lambda clone, mb, head: ["harness/hooks/merge_gate.py"]
        self.run_all(deps)
        self.assertIn("protected-path: main merge only (harness/hooks/merge_gate.py)", self.paths.digest.read_text())

    def test_diff_failure_counts_as_protected(self):
        iid, deps = self.submit(), Deps()

        def broken(clone, mb, head):
            raise RuntimeError("diff failed")
        deps.changed_paths = broken
        self.run_all(deps)
        self.assertIn("protected-path: unknown", self.paths.digest.read_text())

    def test_merged_by_main_closes_the_item(self):
        iid, deps = self.submit(), Deps()
        self.run_all(deps)
        gh = deps.gh

        def merged(argv, timeout):
            rc, out, err = gh(argv, timeout)
            pr = json.loads(out)
            pr.update(state="MERGED", mergeCommit={"oid": "d" * 40})
            return rc, json.dumps(pr), err
        deps.gh = merged
        deps.now += 3601
        self.run_all(deps)
        self.assertEqual(self.state(iid), "merged")


class D20Tests(Base):
    """D20 (spec v19/v22, Q1-Q3 rulings): covered states escalate past main 4 h after entry, then every 24 h, from the
    ledger alone; each escalation raises its own critical ahc:<item>:<n>; the repeat stops on disposition (owner or
    verified main per state), a newer submission, or the PR merging/closing; criticals are cleared when resolved."""

    def raises(self, deps, iid=None, severity="critical"):
        out = []
        for argv in deps.ah_calls:
            if argv[:3] == ["ah", "alert", "raise"] and argv[argv.index("--severity") + 1] == severity:
                key = argv[argv.index("--alert-key") + 1]
                if iid is None or key.startswith("ahc:%s:" % iid):
                    out.append(key)
        return out

    def standing(self, deps, iid):
        """The ahc:<item>:* keys still raised after replaying every raise and clear in call order (the ring view)."""
        up = set()
        for argv in deps.ah_calls:
            if argv[:2] != ["ah", "alert"]:
                continue
            key = argv[argv.index("--alert-key") + 1]
            if not key.startswith("ahc:%s:" % iid):
                continue
            (up.add if argv[2] == "raise" else up.discard)(key)
        return up

    def d20_comments(self, deps, state="routed-to-main"):
        return [a for a in deps.ah_calls if a[:3] == ["ah", "ticket", "comment"]
                and ("-d20-%s-" % state) in a[a.index("--key") + 1]]

    def routed(self):
        iid, deps = self.submit(), Deps()
        self.run_all(deps)
        self.assertEqual(self.state(iid), "routed-to-main")
        return iid, deps

    def hours(self, deps, n, step=3600):
        for _ in range(int(n * 3600 // step)):
            deps.now += step
            self.run_all(deps)

    def enter(self, deps, state, iid=None):
        """Settle a fresh item into `state` through the production settle path with the state's own notice."""
        iid = iid or self.submit()
        ledger = runner.Ledger(self.paths)
        try:
            ledger.ensure_item(iid, self.config, deps.now)
            worker = runner.Worker(self.paths, self.config, deps, ledger)
            token = worker.lease(iid)
            notice = runner._owner_notice(state, "test entry") if state in runner.OWNER_NOTICE_STATES else None
            nxt = deps.now + runner.PASS_RECHECK if state in runner.NON_TERMINAL else None
            worker.settle(iid, token, state, nxt, event="test-enter", notice=notice, reason="test entry")
        finally:
            ledger.close()
        return iid

    def row(self, iid):
        ledger = runner.Ledger(self.paths)
        try:
            return dict(ledger.item(iid))
        finally:
            ledger.close()

    def test_gh_outage_cannot_suppress_d20(self):
        iid, deps = self.routed()
        deps.gh_rc = 1  # every PR read fails from here on
        self.hours(deps, 4.5)
        self.assertEqual(self.raises(deps, iid), ["ahc:%s:1" % iid], "D20 must escalate while GitHub is down")
        self.assertEqual(len(self.d20_comments(deps)), 1)

    def test_each_escalation_has_its_own_critical_key_and_n_survives_restart(self):
        iid, deps = self.routed()
        self.hours(deps, 4.5)
        self.hours(deps, 24, step=6 * 3600)
        self.assertEqual(self.raises(deps, iid), ["ahc:%s:1" % iid, "ahc:%s:2" % iid])
        self.assertEqual(self.row(iid)["esc_n"], 2, "<n> is a ledger column")
        for _ in range(3):  # restarts and retries never bump <n>
            self.run_all(deps)
        self.assertEqual(self.row(iid)["esc_n"], 2)
        self.assertEqual(self.raises(deps, iid, severity="high"), [], "a user escalation is never only high")

    def test_needs_attention_escalates_and_main_disposition_stops_and_clears_it(self):
        deps = Deps()
        iid = self.enter(deps, "needs-attention")
        self.hours(deps, 4.5)
        self.assertEqual(self.raises(deps, iid), ["ahc:%s:1" % iid])
        self.assertEqual(runner.ack(self.paths, iid, "main", now=deps.now, main_proven=True,
                                    disposition="reconciled with usage_guard; run abc is dead"), 1)
        self.run_all(deps)
        self.assertEqual(self.standing(deps, iid), set(), "no ahc:<item>:* raise may stay open after disposition")
        self.hours(deps, 48, step=12 * 3600)
        self.assertEqual(self.raises(deps, iid), ["ahc:%s:1" % iid], "D20 stopped after the disposition")
        bodies = [a[a.index("--body") + 1] for a in deps.ah_calls if a[:3] == ["ah", "ticket", "comment"]]
        self.assertTrue(any("Disposition recorded" in b and "by main" in b and "usage_guard" in b
                            for b in bodies), "the disposition is a ticket comment naming actor and reason")

    def test_owner_disposition_is_refused_in_every_d20_state_and_escalation_continues(self):
        """v6e M3: every D20 disposition is main's (the ahc-dispose stamp); an owner can only ack and repair."""
        for state in sorted(runner.D20_STATES):
            with self.subTest(state=state):
                self.tearDown()
                self.setUp()
                deps = Deps()
                iid = self.enter(deps, state)
                with self.assertRaises(core.Refused):
                    runner.ack(self.paths, iid, "agent-abc123", now=deps.now, disposition="fixed it, trust me")
                self.assertIsNone(self.row(iid)["disposed_at"])
                self.hours(deps, 4.5)
                self.assertIn("ahc:%s:1" % iid, self.raises(deps, iid), "the next escalation must still fire")

    def test_subagent_claiming_main_is_refused_and_escalation_continues(self):
        iid, deps = self.routed()
        with self.assertRaises(core.Refused) as caught:
            runner.ack(self.paths, iid, "main", now=deps.now, disposition="looks fine", main_proven=False)
        self.assertIn("sub-agent cannot dispose", str(caught.exception))
        self.hours(deps, 4.5)
        self.assertEqual(self.raises(deps, iid), ["ahc:%s:1" % iid])

    def test_owner_cannot_silence_a_main_obligation(self):
        iid, deps = self.routed()
        with self.assertRaises(core.Refused):
            runner.ack(self.paths, iid, "agent-abc123", now=deps.now, disposition="please stop")
        runner.ack(self.paths, iid, "agent-abc123", now=deps.now)  # a plain owner ack is not a disposition
        self.hours(deps, 4.5)
        self.hours(deps, 24, step=6 * 3600)
        self.assertEqual(len(self.raises(deps, iid)), 2, "routed-to-main keeps escalating after an owner ack")
        self.assertEqual(len(self.standing(deps, iid)), 2, "an owner ack must not clear main's criticals")

    def test_verified_main_disposition_stops_routed_and_clears(self):
        iid, deps = self.routed()
        self.hours(deps, 4.5)
        with self.assertRaises(core.Refused):
            runner.ack(self.paths, iid, "main", now=deps.now, disposition="   ", main_proven=True)
        runner.ack(self.paths, iid, "main", now=deps.now, disposition="held for the release window", main_proven=True)
        self.run_all(deps)
        self.assertEqual(self.standing(deps, iid), set())
        self.hours(deps, 30, step=6 * 3600)
        self.assertEqual(self.raises(deps, iid), ["ahc:%s:1" % iid])
        with self.assertRaises(core.Refused):
            runner.ack(self.paths, iid, "main", now=deps.now, disposition="again", main_proven=True)

    def test_leaving_the_state_clears_its_criticals(self):
        iid, deps = self.routed()
        self.hours(deps, 4.5)
        gh = deps.gh

        def merged(argv, timeout):
            rc, out, err = gh(argv, timeout)
            pr = json.loads(out)
            pr.update(state="MERGED", mergeCommit={"oid": "d" * 40})
            return rc, json.dumps(pr), err
        deps.gh = merged
        self.hours(deps, 2)
        self.assertEqual(self.state(iid), "merged")
        self.assertEqual(self.standing(deps, iid), set())

    def test_packet_only_resubmit_does_not_stop_needs_attention(self):
        """v6e M1: only a new head is the owner's repair; a new packet on the same head stops nothing."""
        deps = Deps()
        first = self.enter(deps, "needs-attention")
        newer = self.packet.with_name("p2.md")
        newer.write_text(GOOD_PACKET + "\n")
        second = self.submit(packet=newer)
        self.assertNotEqual(second, first, "the resubmit must be a new request row, not a dropped duplicate")
        self.hours(deps, 5)
        self.assertEqual(self.raises(deps, first), ["ahc:%s:1" % first])
        self.assertIsNone(self.row(first)["disposed_at"])

    def test_newer_head_or_closed_pr_stops_needs_attention(self):
        deps = Deps()
        first = self.enter(deps, "needs-attention")
        self.submit(head="c" * 40)
        self.hours(deps, 5)
        self.assertEqual(self.raises(deps, first), [], "a submission at a new head stops D20")
        self.assertIsNotNone(self.row(first)["disposed_at"])
        self.tearDown()
        self.setUp()
        deps = Deps()
        iid = self.enter(deps, "needs-attention")
        gh = deps.gh

        def closed(argv, timeout):
            rc, out, err = gh(argv, timeout)
            pr = json.loads(out)
            pr.update(state="CLOSED")
            return rc, json.dumps(pr), err
        deps.gh = closed
        self.hours(deps, 5)
        self.assertEqual(self.raises(deps, iid), [], "a closed PR stops D20")

    # --- NEG-23: enumerated from the state table, never a hand list
    def test_every_person_waiting_state_has_an_escalation_past_main(self):
        waiting = [s for s, row in runner.STATE_TABLE.items() if row["waits_on"] in runner.PERSON_ACTORS]
        self.assertGreaterEqual(len(waiting), 7, "the enumeration would be vacuous")
        for state in waiting:
            with self.subTest(state=state):
                self.tearDown()
                self.setUp()
                cover = runner.STATE_TABLE[state].get("cover")
                self.assertIn(cover, ("d20", "ack"), "%s waits on a person but has no escalation" % state)
                deps = Deps()
                iid = self.enter(deps, state)
                wait = runner.D20_FIRST if cover == "d20" else runner.bounds(self.config)["block_ack_seconds"]
                self.assertFalse(self.raises(deps, iid))
                deps.now += wait + 1
                self.run_all(deps)
                self.run_all(deps)
                keys = self.raises(deps, iid)
                self.assertEqual(keys, ["ahc:%s:1" % iid], "%s: one critical row past main" % state)
                tickets = [a for a in deps.ah_calls if a[:3] == ["ah", "ticket", "comment"]
                           and "escalat" in a[a.index("--body") + 1].lower() + a[a.index("--key") + 1]]
                self.assertTrue(tickets or self.d20_comments(deps, state), "%s: a ticket row past main" % state)

    def test_every_settled_state_literal_is_in_the_table(self):
        import ast
        tree = ast.parse((HOOKS / "ahc_runner.py").read_text(encoding="utf-8"))
        seen = set()
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "settle"
                    and len(node.args) >= 3 and isinstance(node.args[2], ast.Constant)):
                seen.add(node.args[2].value)
        self.assertGreaterEqual(len(seen), 8, "the scan found too few settle calls to be meaningful")
        self.assertEqual(seen - set(runner.STATE_TABLE), set(), "a state is settled but missing from STATE_TABLE")


class MainStampTests(Base):
    """Q1: `ack --owner main --disposition` counts only with main's caller_identity stamp, bound to main's own still-
    running tool call and keyed by the exact argument list (mission_gate.py pretool writes it)."""

    def setUp(self):
        super().setUp()
        import os
        self._env = os.environ.get("AH_HOME")
        os.environ["AH_HOME"] = str(self.home)
        self.transcript = self.home / "main.jsonl"
        self.transcript.write_text('{"type":"user"}\n')

    def tearDown(self):
        import os
        if self._env is None:
            os.environ.pop("AH_HOME", None)
        else:
            os.environ["AH_HOME"] = self._env
        super().tearDown()

    ARGV = ["ack", "ahc-x", "--owner", "main", "--disposition", "held for release"]

    def stamp(self, argv):
        import caller_identity
        caller_identity.put_stamp(core.DISPOSE_STAMP, core.dispose_stamp_parts(argv), session="s", home=self.home,
                                  tool_use_id="toolu_01ABCDEFGHIJKLMNOPQRSTUV", transcript=str(self.transcript))

    def test_no_stamp_is_not_main(self):
        self.assertFalse(runner.claim_main(self.ARGV))

    def test_stamp_for_exact_argv_is_main_once(self):
        self.stamp(self.ARGV)
        self.assertTrue(runner.claim_main(self.ARGV))
        self.assertFalse(runner.claim_main(self.ARGV), "a stamp is single use")

    def test_stamp_for_other_words_does_not_count(self):
        self.stamp(self.ARGV[:-1] + ["something else"])
        self.assertFalse(runner.claim_main(self.ARGV))

    def test_finished_main_call_does_not_count(self):
        self.stamp(self.ARGV)
        with open(self.transcript, "a") as handle:
            handle.write('{"tool_use_id":"toolu_01ABCDEFGHIJKLMNOPQRSTUV","type":"tool_result"}\n')
        self.assertFalse(runner.claim_main(self.ARGV), "a stamp outliving main's call is dead")

    def test_mission_gate_stamps_only_a_real_disposition_command(self):
        import mission_gate
        line = "python3 ~/.claude/hooks/ahc_runner.py ack ahc-x --owner main --disposition 'held for release'"
        self.assertEqual(mission_gate.ahc_dispose_stamps(line), [core.dispose_stamp_parts(self.ARGV)])
        self.assertEqual(mission_gate.ahc_dispose_stamps("echo ahc_runner.py ack ahc-x --disposition x"), [])
        self.assertEqual(mission_gate.ahc_dispose_stamps("python3 ahc_runner.py ack ahc-x --owner o"), [])
        self.assertEqual(mission_gate.ahc_dispose_stamps('python3 ahc_runner.py ack "$ID" --disposition x'), [])
        self.assertEqual(mission_gate.ahc_dispose_stamps("ahc ack ahc-x --owner main --disposition 'held for release'"),
                         [core.dispose_stamp_parts(self.ARGV)], "the installed `ahc` wrapper is stamped too")
        self.assertEqual(mission_gate.ahc_dispose_stamps("ssh t2-dev ahc ack ahc-x --disposition x"), [],
                         "a command run on another host is never stamped here")


STALE_STDERR = ("Commit policy BLOCKED for %s..%s\n  ticket GoodQA goodqa#16034: STALE\n      fix: comment on the "
                "ticket naming commit %s\n  Fix tickets: comment on each STALE ticket naming the commit SHA or branch;"
                " reference real tickets for MISSING ones.\nPR review not started: fix the commit policy findings above"
                " first.\n" % (BASE[:12], HEAD[:12], HEAD[:12]))


class ScriptedDeps(Deps):
    """peer_review outcomes in order: pass, block, transient, invalid, quota, auth, stale (D24, pre-launch)."""
    OUTCOMES = {
        "transient": (1, "REVIEW_DIAGNOSTIC code=PROVIDER_UNAVAILABLE reason=x"),
        "invalid": (1, "REVIEW_DIAGNOSTIC code=PROVIDER_INVALID_OUTPUT reason=x"),
        "quota": (1, "REVIEW_DIAGNOSTIC code=PROVIDER_USAGE_LIMIT reason=x"),
        "stale": (2, STALE_STDERR),
    }

    def __init__(self, script, **kw):
        super().__init__(**kw)
        self.script = list(script)

    def review(self, argv, timeout):
        step = self.script.pop(0) if self.script else "invalid"
        if step in ("pass", "block"):
            self.verdict = "PASS" if step == "pass" else "BLOCK"
            return super().review(argv, timeout)
        self.review_calls.append(argv)
        return self.OUTCOMES[step]


class MixedFailureTests(Base):
    """AC-18 (v6e retry budget; v6d red-team M1, M2, L7): per (lineage, head), each of transient / invalid / freshness
    retries at most once, first-come, shared by every packet revision; quota and auth consume nothing; at most 3
    revisions reach reviewing and a 4th is refused at admission (N-T4). Each sequence also runs with a daemon restart
    between steps (`restart=True`: every step is separate core and review unit passes with fresh Deps objects)."""

    def drive(self, deps, iid, restart=False, hours=30):
        """Advance the clock and tick until the item stops changing (or `hours` pass)."""
        end = deps.now + hours * 3600
        while deps.now < end:
            if restart:
                fresh = ScriptedDeps(deps.script)
                fresh.now, fresh.review_calls, fresh.ah_calls = deps.now, deps.review_calls, deps.ah_calls
                runner.tick(self.paths, self.config, fresh, role="core")
                runner.tick(self.paths, self.config, fresh, role="review")
                runner.tick(self.paths, self.config, fresh, role="core")
                deps.script = fresh.script
            else:
                self.run_all(deps)
            if self.state(iid) in runner.TERMINAL:
                return self.state(iid)
            deps.now += 300
        return self.state(iid)

    def budget(self, head=HEAD):
        ledger = runner.Ledger(self.paths)
        try:
            return ledger.head_budget("%s|7" % REPO, head)
        finally:
            ledger.close()

    def notes(self, deps):
        return [a for a in deps.ah_calls if a[:3] == ["ah", "ticket", "comment"] and "-d24-" in a[a.index("--key") + 1]]

    def repeat_reasons(self, deps):
        return [c[c.index("--repeat-reason") + 1].split(":")[0] for c in deps.review_calls if "--repeat-reason" in c]

    def seq_a(self, restart):
        iid, deps = self.submit(), ScriptedDeps(["transient", "stale", "invalid", "invalid"])
        self.assertEqual(self.drive(deps, iid, restart), "review-invalid", "T14: the second invalid output")
        self.assertEqual(len(deps.review_calls), 4, "transient retry, freshness re-run, invalid repeat: once each")
        self.assertEqual(len(self.notes(deps)), 1, "one D24 note per (ticket, head)")
        body = self.notes(deps)[0][self.notes(deps)[0].index("--body") + 1]
        self.assertIn(runner.D24_LABEL, body)
        self.assertIn(HEAD, body)
        self.assertEqual(self.repeat_reasons(deps), ["PROVIDER_UNAVAILABLE", "D24_FRESHNESS", "PROVIDER_INVALID_OUTPUT"])
        budget = self.budget()
        self.assertEqual((budget["transient"], budget["invalid"], budget["freshness"]), (1, 1, 1))
        return iid, deps

    def test_a_transient_stale_invalid_invalid(self):
        self.seq_a(restart=False)

    def test_a_with_restarts(self):
        self.seq_a(restart=True)

    def seq_b(self, restart):
        iid, deps = self.submit(), ScriptedDeps(["stale", "stale"])
        self.assertEqual(self.drive(deps, iid, restart), "needs-attention", "T16: the second STALE")
        self.assertEqual(len(deps.review_calls), 2)
        self.assertEqual(len(self.notes(deps)), 1, "the second STALE posts no second note")
        self.assertEqual(self.budget()["transient"] + self.budget()["invalid"], 0, "STALE spends no provider class")

    def test_b_stale_stale(self):
        self.seq_b(restart=False)

    def test_b_with_restarts(self):
        self.seq_b(restart=True)

    def seq_c(self, restart):
        iid, deps = self.submit(), ScriptedDeps(["quota", "quota", "transient", "transient"])
        self.assertEqual(self.drive(deps, iid, restart), "needs-attention", "T16: the second transient")
        self.assertEqual(len(deps.review_calls), 4, "quota consumed no class (T15), so the transient retry ran")
        self.assertEqual(self.budget()["transient"], 1)

    def test_c_quota_quota_transient_transient(self):
        self.seq_c(restart=False)

    def test_c_with_restarts(self):
        self.seq_c(restart=True)

    def revision(self, n):
        packet = self.packet.with_name("rev%d.md" % n)
        packet.write_text(GOOD_PACKET + "\n" * n)   # a one-byte-per-revision packet change on the same head
        return packet

    def seq_d(self, restart):
        first, deps = self.seq_a(restart)
        second = self.submit(packet=self.revision(1))
        self.assertNotEqual(second, first, "the packet change must create a new request row (dedupe not vacuous)")
        deps.script = ["invalid"]
        self.assertEqual(self.drive(deps, second, restart), "review-invalid", "no invalid repeat is offered again")
        self.assertEqual(len(deps.review_calls), 5)
        third = self.submit(packet=self.revision(2))
        deps.script = ["transient"]
        self.assertEqual(self.drive(deps, third, restart), "needs-attention", "no transient retry is offered again")
        self.assertEqual(len(deps.review_calls), 6)
        self.assertEqual(len(self.budget()["reviewed"]), 3)
        with self.assertRaises(core.Refused) as refused:
            self.submit(packet=self.revision(3))
        self.assertIn("review budget exhausted for this head", str(refused.exception))
        fresh_head = self.submit(head="c" * 40, packet=self.revision(4))   # a new head starts a fresh budget
        self.assertNotIn(fresh_head, self.budget()["reviewed"])
        self.assertEqual(self.budget("c" * 40)["reviewed"], [])

    def test_d_exhausted_head_then_packet_revisions(self):
        self.seq_d(restart=False)

    def test_d_with_restarts(self):
        self.seq_d(restart=True)

    def test_stale_is_reported_before_any_provider_launch_in_the_helper_source(self):
        """AC-5 / v6e: a freshness STALE spends no provider budget only because peer_review refuses it before any
        launch. Pin that against the installed helper's source: the commit-policy gate's early return (with the
        exact text stale_tickets() keys on) comes before main()'s reviewer dispatch."""
        source = (Path(runner.__file__).parent / "peer_review.py").read_text()
        main_at = source.index("def main(")
        gate = source.index("code, text = commit_policy_gate(repo, args.base)", main_at)
        refusal = source.index("print('PR review not started: fix the commit policy findings above first.'", gate)
        self.assertLess(refusal - gate, 600, "the refusal is the gate's own early return")
        launch = source.index("review_snapshot(snapshot,", main_at)   # the only call that starts a reviewer CLI
        self.assertIn("options['launches'] +=", source[source.index("def review_snapshot("):main_at])
        self.assertLess(gate, launch, "the gate must precede any launch")

    def test_freshness_rerun_waits_for_the_note(self):
        """D24: the re-run never starts before every note is posted (split roles cannot spend it on a STALE the
        note would clear); a ticket outage holds it, and the head's 24 h deferred deadline still bounds the wait."""
        iid, deps = self.submit(), ScriptedDeps(["stale", "pass"])
        ah = deps.ah

        def ticket_down(argv, timeout):
            if argv[:3] == ["ah", "ticket", "comment"] and "-d24-" in argv[argv.index("--key") + 1]:
                deps.ah_calls.append(argv)
                return 1, "", "ticket system down"
            return ah(argv, timeout)
        deps.ah = ticket_down
        for _ in range(12):
            self.run_all(deps)
            deps.now += 300
        self.assertEqual(len(deps.review_calls), 1, "the re-run started before the note was posted")
        self.assertEqual(self.state(iid), "deferred")
        deps.ah = ah
        self.assertEqual(self.drive(deps, iid, hours=2), "routed-to-main")
        self.assertEqual(len(deps.review_calls), 2)
        self.assertEqual(self.budget()["freshness"], 1)

    def test_quota_flapping_ends_in_review_error_24h_after_the_first_deferral(self):
        """v6f T8: the 24 h deferred deadline is anchored at the head's FIRST deferral; re-entry never resets it."""
        iid, deps = self.submit(), ScriptedDeps(["quota"] * 40)
        start = deps.now
        state = self.drive(deps, iid, hours=30)
        self.assertEqual(state, "review-error")
        self.assertGreater(len(deps.review_calls), 3, "the quota retry_at cycle ran several times first")
        ledger = runner.Ledger(self.paths)
        try:
            entered = ledger.item(iid)["entered_at"]
        finally:
            ledger.close()
        self.assertLess(entered - start, 25 * 3600, "review-error must come at about 24 h, not later")
        self.assertGreaterEqual(entered - start, 24 * 3600)


class AckInactivityTests(Base):
    """AC-19 / v6e M4 (adv-4 F2): an ack acknowledges receipt only. A delivered BLOCK moves to `acknowledged`, whose
    D20 repair deadline runs from the ack (4 h, then every 24 h) until a new head, the PR closing or merging, or a
    main disposition. A repeat ack never resets it; a restart never moves it."""

    OWNER = "agent-abc123"

    def setUp(self):
        super().setUp()
        self.d20 = D20Tests("run")   # borrow its ledger readers only (no setUp of its own runs)
        self.d20.paths = self.paths

    def blocked(self):
        iid, deps = self.submit(), Deps(verdict="BLOCK")
        self.run_all(deps)
        self.assertEqual(self.state(iid), "block-delivered")
        return iid, deps

    def at(self, deps, when):
        deps.now = when
        self.run_all(deps)

    def acked_escalations(self, deps):
        return [a for a in deps.ah_calls if a[:3] == ["ah", "ticket", "comment"]
                and "-d20-acknowledged-" in a[a.index("--key") + 1]]

    def test_ack_then_inactivity_escalates_at_4h_and_28h(self):
        iid, deps = self.blocked()
        t0 = deps.now + 600
        runner.ack(self.paths, iid, self.OWNER, now=t0)
        self.assertEqual(self.state(iid), "acknowledged")
        self.at(deps, t0 + 4 * 3600 - 60)
        self.assertEqual(self.acked_escalations(deps), [], "nothing before 4 h after the ack")
        self.at(deps, t0 + 4 * 3600 + 60)
        self.assertEqual(len(self.acked_escalations(deps)), 1)
        self.at(deps, t0 + 28 * 3600 - 120)
        self.assertEqual(len(self.acked_escalations(deps)), 1)
        self.at(deps, t0 + 28 * 3600 + 120)
        self.assertEqual(len(self.acked_escalations(deps)), 2)
        keys = self.d20.raises(deps, iid)
        self.assertEqual(len(keys), len(set(keys)), "each escalation has its own critical key")
        self.assertEqual(self.state(iid), "acknowledged", "inactivity never closes the obligation")

    def test_ack_then_restart_keeps_the_deadline(self):
        iid, deps = self.blocked()
        t0 = deps.now + 600
        runner.ack(self.paths, iid, self.OWNER, now=t0)
        entered = self.d20.row(iid)["entered_at"]
        for minutes in (30, 90, 200):   # each pass opens a fresh ledger and worker: a daemon restart
            self.at(deps, t0 + minutes * 60)
        self.assertEqual(self.d20.row(iid)["entered_at"], entered, "a restart moved the repair deadline")
        self.assertEqual(self.acked_escalations(deps), [])
        self.at(deps, t0 + 4 * 3600 + 1)
        self.assertEqual(len(self.acked_escalations(deps)), 1)

    def test_ack_then_new_head_closes_as_superseded_by_head(self):
        iid, deps = self.blocked()
        t0 = deps.now + 600
        runner.ack(self.paths, iid, self.OWNER, now=t0)
        self.at(deps, t0 + 4 * 3600 + 60)
        self.assertEqual(len(self.acked_escalations(deps)), 1)
        newer = self.submit(head="c" * 40)
        self.at(deps, t0 + 5 * 3600)
        self.assertEqual(self.state(iid), "superseded")
        self.assertEqual(json.loads(self.d20.row(iid)["data"])["reason"], "superseded-by-head")
        self.assertEqual(json.loads(self.d20.row(iid)["data"])["by"], newer, "linked to the new item")
        self.assertEqual(self.d20.standing(deps, iid), set(), "its criticals are cleared")
        self.at(deps, t0 + 60 * 3600)
        self.assertEqual(len(self.acked_escalations(deps)), 1, "no escalation after the repair")

    def test_packet_only_resubmit_does_not_close_the_block(self):
        iid, deps = self.blocked()
        t0 = deps.now + 600
        runner.ack(self.paths, iid, self.OWNER, now=t0)
        other = self.packet.with_name("p2.md")
        other.write_text(GOOD_PACKET + "\n")
        self.assertNotEqual(self.submit(packet=other), iid)
        self.at(deps, t0 + 4 * 3600 + 60)
        self.assertEqual(self.state(iid), "acknowledged")
        self.assertEqual(len(self.acked_escalations(deps)), 1)

    def test_repeat_ack_does_not_reset_the_deadline(self):
        iid, deps = self.blocked()
        t0 = deps.now + 600
        runner.ack(self.paths, iid, self.OWNER, now=t0)
        runner.ack(self.paths, iid, self.OWNER, now=t0 + 3 * 3600)
        self.assertEqual(self.d20.row(iid)["entered_at"], t0)
        self.at(deps, t0 + 4 * 3600 + 60)
        self.assertEqual(len(self.acked_escalations(deps)), 1, "the second ack pushed the deadline out")

    def test_escalation_before_the_ack_does_not_push_the_first_repair_escalation_to_24h(self):
        iid, deps = self.blocked()
        start = deps.now
        self.at(deps, start + 4 * 3600 + 60)       # the delivered BLOCK escalates unacked
        n_before = self.d20.row(iid)["esc_n"]
        self.assertGreaterEqual(n_before, 1)
        t0 = start + 5 * 3600
        runner.ack(self.paths, iid, self.OWNER, now=t0)
        self.at(deps, t0 + 4 * 3600 + 60)
        self.assertEqual(len(self.acked_escalations(deps)), 1, "the repair deadline is ack + 4 h, not ack + 24 h")
        self.assertGreater(self.d20.row(iid)["esc_n"], n_before, "<n> stays monotonic across the ack")

    def test_owner_disposition_cannot_close_an_acknowledged_block(self):
        iid, deps = self.blocked()
        t0 = deps.now + 600
        runner.ack(self.paths, iid, self.OWNER, now=t0)
        with self.assertRaises(core.Refused):
            runner.ack(self.paths, iid, self.OWNER, now=t0 + 60, disposition="not a real finding")
        self.at(deps, t0 + 4 * 3600 + 60)
        self.assertEqual(len(self.acked_escalations(deps)), 1)
        self.assertEqual(runner.ack(self.paths, iid, "main", now=deps.now, main_proven=True,
                                    disposition="false positive, main accepts the risk"), 1)
        self.at(deps, t0 + 60 * 3600)
        self.assertEqual(len(self.acked_escalations(deps)), 1, "a main disposition stops the repair deadline")


class GuardAndNewHeadTests(Base):
    """Spec-owner rulings while the rescue spec is pending: (T33, child kill held) a guard refusal noticed while an
    item is reviewing applies once the child settles, and from queued it applies at once; (T25 + T2, v6e L5) a new
    PR head with no submission closes a delivered or acknowledged BLOCK as superseded-by-head and opens an
    `unsubmitted` item for the new head within one tick, so the obligation never disappears."""

    def items(self):
        ledger = runner.Ledger(self.paths)
        try:
            return {r["id"]: dict(r) for r in ledger.db.execute("SELECT * FROM items")}
        finally:
            ledger.close()

    def test_guard_refusal_during_review_applies_after_the_child_settles(self):
        iid, deps = self.submit(), Deps(verdict="PASS")
        review = deps.review
        config = self.config

        def review_then_delist(argv, timeout):
            rc = review(argv, timeout)
            config["repos"] = []   # the repo leaves the allowlist while the child runs
            return rc
        deps.review = review_then_delist
        self.run_all(deps)
        self.assertEqual(len(deps.review_calls), 1, "the child ran to completion, never killed or relaunched")
        self.assertEqual(self.state(iid), "blocked")
        ledger = runner.Ledger(self.paths)
        try:
            effect = ledger.db.execute("SELECT status, result FROM effects WHERE kind='review' AND item=?",
                                       (iid,)).fetchone()
            events = [r["event"] for r in ledger.db.execute("SELECT event FROM events WHERE item=? ORDER BY seq",
                                                             (iid,))]
        finally:
            ledger.close()
        self.assertEqual(effect["status"], "done", "the child's result is recorded before blocked")
        self.assertIn("blocked:guard", events)
        self.assertNotIn("pass", events, "a guard-refused PASS is never routed to main")

    def test_guard_refusal_from_queued_blocks_without_a_review(self):
        iid, deps = self.submit(), Deps()
        self.config["repos"] = []
        self.run_all(deps)
        self.assertEqual(self.state(iid), "blocked")
        self.assertEqual(deps.review_calls, [])

    def test_new_head_without_a_submit_supersedes_the_block_and_opens_unsubmitted(self):
        iid, deps = self.submit(), Deps(verdict="BLOCK")
        self.run_all(deps)
        runner.ack(self.paths, iid, "agent-abc123", now=deps.now)
        deps.pr_head = "c" * 40          # the owner pushed; nothing submitted
        deps.now += 60
        self.run_all(deps)               # one tick
        rows = self.items()
        self.assertEqual(rows[iid]["state"], "superseded")
        data = json.loads(rows[iid]["data"])
        self.assertEqual(data["reason"], "superseded-by-head")
        new = rows[data["by"]]
        self.assertEqual(new["state"], "unsubmitted")
        self.assertEqual(json.loads(new["request"])["head"], "c" * 40)
        # its own D20 clock: escalates 4 h after it opened
        deps.now += 4 * 3600 + 60
        self.run_all(deps)
        self.assertTrue([a for a in deps.ah_calls if a[:3] == ["ah", "alert", "raise"]
                         and a[a.index("--alert-key") + 1].startswith("ahc:%s:" % new["id"])],
                        "the unsubmitted head escalates under D20")
        # the owner's submission at the new head answers it
        sub = self.submit(head="c" * 40)
        self.run_all(deps)
        rows = self.items()
        self.assertEqual(rows[new["id"]]["state"], "superseded")
        self.assertEqual(json.loads(rows[new["id"]]["data"])["reason"], "resubmitted")
        self.assertEqual(json.loads(rows[new["id"]]["data"])["by"], sub)

    def test_unreadable_pr_never_supersedes(self):
        iid, deps = self.submit(), Deps(verdict="BLOCK")
        self.run_all(deps)
        deps.pr_head, deps.gh_rc = "c" * 40, 1
        deps.now += 3600
        self.run_all(deps)
        self.assertEqual(self.state(iid), "block-delivered")
        self.assertEqual(len(self.items()), 1)


class EffectCrashTests(Base):
    """v6f: a crash during a side effect marks only that effect row outcome-unknown; the item keeps its state, and
    the effect is read back (for a ticket: re-sent under the same idempotency key) before any redispatch."""

    class Crash(BaseException):
        pass

    def test_crash_mid_ticket_comment_leaves_the_item_state_and_reads_back(self):
        iid, deps = self.submit(), Deps(verdict="BLOCK")
        real = deps.ah
        crashed = []

        def ah(argv, timeout):
            if argv[:3] == ["ah", "ticket", "comment"] and not crashed:
                crashed.append(argv[argv.index("--key") + 1])
                deps.ah_calls.append(argv)
                raise self.Crash()   # the process dies between intent and result
            return real(argv, timeout)
        deps.ah = ah
        with self.assertRaises(self.Crash):
            self.run_all(deps)
        self.assertEqual(self.state(iid), "block-delivered")
        ledger = runner.Ledger(self.paths)
        try:
            row = ledger.db.execute("SELECT status FROM effects WHERE kind='ticket' AND item=?", (iid,)).fetchone()
        finally:
            ledger.close()
        self.assertEqual(row["status"], "intent")
        deps.now += 60
        self.run_all(deps)
        self.assertEqual(self.state(iid), "block-delivered", "the effect's crash never moves the item")
        ledger = runner.Ledger(self.paths)
        try:
            events = [r["event"] for r in ledger.db.execute("SELECT event FROM events WHERE item=?", (iid,))]
            status = ledger.db.execute("SELECT status FROM effects WHERE kind='ticket' AND item=?",
                                       (iid,)).fetchone()["status"]
        finally:
            ledger.close()
        self.assertIn("effect-outcome-unknown", events)
        self.assertEqual(status, "done")
        keys = [a[a.index("--key") + 1] for a in deps.ah_calls if a[:3] == ["ah", "ticket", "comment"]]
        self.assertEqual(keys, [crashed[0], crashed[0]], "re-sent once, under the same idempotency key")


class PacketRetentionTests(Base):
    """v6c: a stdin-staged packet is kept while its item is non-terminal and for 7 days after it turns terminal;
    then the core pass removes it. The ledger keeps the SHA-256. Injected clock throughout."""

    DAY = 86400

    def setUp(self):
        super().setUp()
        import io
        self.config["work_roots"].append(str(self.paths.packets))
        self.deps = Deps()
        self.staged, self.sha = runner.stage_packet(self.paths, io.BytesIO(GOOD_PACKET.encode()))
        os.utime(str(self.staged), (self.deps.now, self.deps.now))

    def submit_staged(self, head=HEAD):
        self.deps.now += 1
        req = {"repo": REPO, "pr": 7, "head": head, "base": BASE, "packet": str(self.staged),
               "ticket": "GoodQA goodqa#16034", "owner": "agent-abc123", "submitted": self.deps.now}
        return core.submit(self.paths, self.config, req)["id"]

    def set_state(self, iid, state, at):
        ledger = runner.Ledger(self.paths)
        try:
            with ledger.tx():
                ledger.db.execute("UPDATE items SET state=?, entered_at=?, updated=? WHERE id=?", (state, at, at, iid))
        finally:
            ledger.close()

    def core_tick(self, at):
        self.deps.now = at
        return runner.tick(self.paths, self.config, self.deps, role="core")

    def test_non_terminal_item_keeps_its_packet_indefinitely(self):
        iid = self.submit_staged()
        start = self.deps.now
        summary = self.core_tick(start + 30 * self.DAY)
        self.assertEqual(summary["pruned_packets"], [])
        self.assertTrue(self.staged.exists())
        self.assertIn(self.ledger_state(iid), runner.NON_TERMINAL)

    def ledger_state(self, iid):
        ledger = runner.Ledger(self.paths)
        try:
            return ledger.item(iid)["state"]
        finally:
            ledger.close()

    def test_terminal_item_packet_removed_after_seven_days_sha_kept(self):
        iid = self.submit_staged()
        ended = self.deps.now + 100
        self.set_state(iid, "closed", ended)
        self.core_tick(ended + 7 * self.DAY - 1)
        self.assertTrue(self.staged.exists(), "removed before 7 days after the terminal state")
        summary = self.core_tick(ended + 7 * self.DAY + 1)
        self.assertEqual(summary["pruned_packets"], [self.sha + ".md"])
        self.assertFalse(self.staged.exists())
        self.assertEqual(self.record(iid)["packet_sha256"], self.sha, "the ledger keeps the SHA-256")

    def test_shared_packet_kept_while_any_item_is_live(self):
        done, live = self.submit_staged(), self.submit_staged(head="c" * 40)
        self.set_state(done, "superseded", self.deps.now)
        self.core_tick(self.deps.now + 30 * self.DAY)
        self.assertTrue(self.staged.exists(), "a packet another live item names was removed")
        self.set_state(live, "closed", self.deps.now)
        self.core_tick(self.deps.now + 7 * self.DAY + 1)
        self.assertFalse(self.staged.exists())

    def test_restaging_an_old_orphan_restarts_its_clock(self):
        import io
        import time as _time
        self.assertEqual(self.paths.packets, self.paths.root / "staging", "spec D14 names the staging root")
        old = _time.time() - 30 * self.DAY
        os.utime(str(self.staged), (old, old))
        again, sha = runner.stage_packet(self.paths, io.BytesIO(GOOD_PACKET.encode()))
        self.assertEqual((again, sha), (self.staged, self.sha))
        self.core_tick(_time.time() + 60)   # between staging and admission
        self.assertTrue(self.staged.exists(), "a just-restaged packet was pruned before its submit was admitted")

    def test_unreferenced_staged_file_goes_after_seven_days_others_untouched(self):
        outside = self.home / "outside.md"
        outside.write_text("not ours")
        link = self.paths.packets / ("d" * 64 + ".md")
        os.symlink(str(outside), str(link))
        stray = self.paths.packets / "notes.txt"
        stray.write_text("x")
        self.core_tick(self.deps.now + 7 * self.DAY - 1)
        self.assertTrue(self.staged.exists())
        self.core_tick(self.deps.now + 2)
        self.assertFalse(self.staged.exists(), "an orphan staged packet (refused submit) is never removed")
        self.assertTrue(link.is_symlink() and outside.exists() and stray.exists(),
                        "only regular <sha>.md files in the staging root are touched")


class DisposeStampHookTests(unittest.TestCase):
    """v6c: the ahc-dispose stamp end to end against the REAL caller_identity, written by the real mission_gate
    PreToolUse hook (no hand-made stamps): main's call is stamped; a sub-agent's is not; no other purpose can take
    it; a changed argument list cannot consume it."""

    SESSION = "11111111-2222-4333-8444-555555555555"
    TOOL = "toolu_01DISPOSE000000000000001"
    ARGV = ["ack", "ahc-x", "--owner", "main", "--disposition", "held for release"]
    LINE = "ahc ack ahc-x --owner main --disposition 'held for release'"

    def setUp(self):
        from unittest import mock
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        env = mock.patch.dict(os.environ, {"AH_HOME": str(self.home), "HOME": str(self.home),
                                           "CLAUDE_CONFIG_DIR": str(self.home / ".claude")})
        env.start()
        self.addCleanup(env.stop)
        self.transcript = self.home / ".claude" / "projects" / "proj" / (self.SESSION + ".jsonl")
        self.transcript.parent.mkdir(parents=True)
        self.transcript.write_text('{"type":"user"}\n')

    def pretool(self, line=LINE, **extra):
        import mission_gate
        payload = {"tool_name": "Bash", "tool_input": {"command": line}, "session_id": self.SESSION,
                   "hook_event_name": "PreToolUse", "tool_use_id": self.TOOL, "transcript_path": str(self.transcript)}
        payload.update(extra)
        self.assertEqual(mission_gate.cmd_pretool(payload), {}, "the hook never denies")

    def stamps(self):
        import caller_identity
        folder = caller_identity.stamp_dir(self.home)
        return sorted(p.name for p in folder.glob("*.json")) if folder.exists() else []

    def test_main_call_is_stamped_and_claims_once(self):
        import caller_identity
        self.assertTrue(caller_identity.is_main({"session_id": self.SESSION, "transcript_path": str(self.transcript)}),
                        "fixture: this payload must be main's by the real caller_identity rule")
        self.pretool()
        self.assertEqual(len(self.stamps()), 1)
        self.assertTrue(runner.claim_main(self.ARGV))
        self.assertFalse(runner.claim_main(self.ARGV), "single use")

    def test_sub_agent_call_is_not_stamped(self):
        for extra in ({"agent_id": "a1234567"}, {"agent_type": "task-owner"},
                      {"agent_id": "a1234567", "agent_type": "task-owner"}):
            self.pretool(**extra)
            self.assertEqual(self.stamps(), [], "a sub-agent payload %r got a stamp" % (extra,))
            self.assertFalse(runner.claim_main(self.ARGV))

    def test_other_purpose_cannot_take_the_stamp(self):
        import caller_identity
        self.pretool()
        parts = core.dispose_stamp_parts(self.ARGV)
        for purpose in ("review-auth", "mission-main", "ahc-dispose-x", ""):
            self.assertIsNone(caller_identity.take_stamp(purpose, parts, home=self.home, bound=True),
                              "purpose %r took the ahc-dispose stamp" % purpose)
            self.assertIsNone(caller_identity.take_stamp(purpose, parts, home=self.home))
        self.assertEqual(len(self.stamps()), 1, "a refused probe must not burn main's stamp")
        self.assertTrue(runner.claim_main(self.ARGV), "the stamp is still main's to use")

    def test_changed_argv_cannot_consume_the_stamp(self):
        self.pretool()
        changed = [
            ["ack", "ahc-y", "--owner", "main", "--disposition", "held for release"],     # another item
            ["ack", "ahc-x", "--owner", "main", "--disposition", "dropped, not needed"],  # another disposition
            ["ack", "ahc-x", "--owner", "main", "--disposition", "held for release", "--owner", "o2"],
        ]
        for argv in changed:
            self.assertFalse(runner.claim_main(argv), "changed argv %r consumed main's stamp" % (argv,))
        self.assertEqual(len(self.stamps()), 1)
        self.assertTrue(runner.claim_main(self.ARGV))


class EmailRouteTests(Base):
    """D19 / AC-19: the daemon's critical escalations reach the mail command only through the REAL ops-watch
    forward_foreign, queue_events and deadman drain, in a temporary home with a fake deadman command. The daemon
    marks an escalation "handed to mail command" only on a `delivered` receipt at or after its raise."""

    HOST = "testhost"

    def setUp(self):
        super().setUp()
        import ops_watch as ow
        self.ow = ow
        self.ops_home = self.home / "opshome"
        self.ops_home.mkdir()
        self.cfg = ow.load_config(self.ops_home, host=self.HOST, overrides={})
        self.cfg["processes"] = dict(self.cfg["processes"], meminfo=str(self.ops_home / "no-meminfo"))
        self.cfg["liveness"] = dict(self.cfg["liveness"], wal_root=str(self.ops_home / "wals"), gq=None)
        self.sinks = {"comment_min_interval_s": 0, "comment": {"mode": "none"},
                      "deadman": [["fake-deadman", "{SUBJECT}"]]}
        self.mail = []            # subjects the fake mail command was given
        self.mail_mode = "ok"     # ok | fail | timeout
        self.config["ops_ticket"] = "GoodQA goodqa#16034"

    def deps(self, verdict="BLOCK"):
        deps = Deps(verdict=verdict)
        ow, test = self.ow, self

        def ah(argv, timeout):
            deps.ah_calls.append(argv)
            if argv[:2] == ["ah", "alert"]:
                arg = lambda name, default="": argv[argv.index(name) + 1] if name in argv else default  # noqa: E731
                ow.emit({"host": test.HOST, "source": arg("--source"), "event": argv[2],
                         "severity": arg("--severity", "info"), "key": arg("--alert-key"), "check": "ahc",
                         "message": arg("--message", "cleared"), "detail": {}}, home=test.ops_home)
            return 0, "{}", ""

        def ops_watch(argv, timeout):
            if argv[0] == "capabilities":
                return 0, "\n".join(ow.capabilities()) + "\n", ""
            if argv[0] == "config":
                return 0, json.dumps({"sinks": test.sinks}), ""
            key = argv[argv.index("--key") + 1]
            return 0, json.dumps({"key": key, "delivered_at": ow.delivered_at(test.ops_home, key)}), ""
        deps.ah, deps.ops_watch = ah, ops_watch
        return deps

    def ops_run(self, deps, save=None):
        """One real ops-watch run at the daemon's clock, its deadman command faked."""
        import subprocess as sp

        def deadman(argv, t, stdin):
            self.mail.append(argv[-1])
            if self.mail_mode == "timeout":
                raise sp.TimeoutExpired(argv, t)
            return (0 if self.mail_mode == "ok" else 1, "")
        cfg = dict(self.cfg, sinks=self.sinks)
        runner_ = _OpsRunner({("fake-deadman",): deadman})
        if save is None:
            return self.ow.run_once(cfg, self.ops_home, runner=runner_, checks={}, now=deps.now)
        from unittest import mock
        with mock.patch.object(self.ow, "save_state", side_effect=save):
            return self.ow.run_once(cfg, self.ops_home, runner=runner_, checks={}, now=deps.now)

    def escalate(self):
        """A BLOCK whose owner never acks: one critical escalation ahc:<item>:1 raised into the real ring."""
        deps = self.deps()
        iid = self.submit()
        self.run_all(deps)
        deps.now += runner.bounds(self.config)["block_ack_seconds"] + 1
        self.run_all(deps)
        self.assertIn(["--severity", "critical"], [a[3:5] for a in deps.ah_calls if a[:3] == ["ah", "alert", "raise"]])
        return iid, deps, "ahc:%s:1" % iid

    def mail_effect(self, iid):
        ledger = runner.Ledger(self.paths)
        try:
            return dict(ledger.db.execute("SELECT * FROM effects WHERE item=? AND kind='mail'", (iid,)).fetchone())
        finally:
            ledger.close()

    def bodies(self, deps):
        return [a[a.index("--body") + 1] for a in deps.ah_calls if a[:3] == ["ah", "ticket", "comment"]]

    def high_raises(self, deps, prefix):
        return [a[a.index("--alert-key") + 1] for a in deps.ah_calls if a[:3] == ["ah", "alert", "raise"]
                and a[a.index("--severity") + 1] == "high" and a[a.index("--alert-key") + 1].startswith(prefix)]

    def test_success_marks_handed_only_after_the_mail_command(self):
        iid, deps, key = self.escalate()
        self.assertEqual(self.mail_effect(iid)["status"], "pending", "a raise alone is never delivery")
        deps.now += 60
        self.ops_run(deps)
        self.assertEqual(len(self.mail), 1, "the mail command ran once for the escalation key")
        self.assertIn(key, self.mail[0])
        self.run_all(deps)
        effect = self.mail_effect(iid)
        self.assertEqual(effect["status"], "done")
        self.assertIn("handed to mail command", effect["result"])
        self.assertNotIn("emailed", " ".join(self.bodies(deps)).lower())

    def test_high_raise_queues_no_mail(self):
        deps = self.deps()
        iid = self.submit()
        deps.gh_rc = 1   # resolve fails repeatedly: a routine high path, never an escalation
        self.run_all(deps)
        ledger = runner.Ledger(self.paths)
        try:
            worker = runner.Worker(self.paths, self.config, deps, ledger)
            ledger.ensure_item(iid, self.config, deps.now)
            worker.refuse(iid, worker.lease(iid), "test refusal")
        finally:
            ledger.close()
        self.run_all(deps)
        self.assertTrue(self.high_raises(deps, "ahc:"), "the refusal raised its high alert")
        deps.now += 60
        self.ops_run(deps)
        self.assertEqual(self.mail, [], "a high raise must never be mailed")

    def test_missing_sink_is_unavailable_and_never_claims_mail(self):
        self.sinks = dict(self.sinks, deadman=[])
        iid, deps, key = self.escalate()
        self.run_all(deps)
        self.run_all(deps)
        ledger = runner.Ledger(self.paths)
        try:
            route = ledger.db.execute("SELECT v FROM meta WHERE k='email_route'").fetchone()["v"]
            mails = ledger.db.execute("SELECT COUNT(*) FROM effects WHERE kind='mail'").fetchone()[0]
        finally:
            ledger.close()
        self.assertEqual(route, "unavailable")
        self.assertEqual(mails, 0, "no receipt is awaited for an escalation that cannot be mailed")
        self.assertEqual(self.high_raises(deps, "ahc:email-route:"), ["ahc:email-route:1"], "one alert per episode")
        route_comments = [b for b in self.bodies(deps) if "email-route: unavailable" in b]
        self.assertEqual(len(route_comments), 1, "one ops-ticket comment per episode")
        self.assertTrue(any("NOT handed to the mail command" in b for b in self.bodies(deps)))
        self.sinks = dict(self.sinks, deadman=[["fake-deadman", "{SUBJECT}"]])
        self.run_all(deps)
        clears = [a for a in deps.ah_calls if a[:3] == ["ah", "alert", "clear"]
                  and a[a.index("--alert-key") + 1] == "ahc:email-route:1"]
        self.assertEqual(len(clears), 1, "the episode alert clears when the route is ready again")

    def test_no_ops_ticket_raises_alert_only(self):
        self.sinks = dict(self.sinks, deadman=[])
        del self.config["ops_ticket"]
        deps = self.deps()
        with self.assertLogs("ahc", level="WARNING") as logs:
            self.run_all(deps)
        self.assertEqual(self.high_raises(deps, "ahc:email-route:"), ["ahc:email-route:1"])
        self.assertFalse([b for b in self.bodies(deps) if "email-route" in b])
        self.assertTrue(any("no ops ticket configured" in line for line in logs.output))

    def assert_undelivered_once(self, iid, deps, key):
        st = self.ow.load_state(self.ops_home)
        self.assertIn(key, st.get("deadman_sent", {}), "queued and rate-limited by ops-watch")
        self.assertNotIn(key, st.get("deadman_delivered", {}), "a failed send is not a receipt")
        self.run_all(deps)
        self.assertEqual(self.mail_effect(iid)["status"], "pending")
        deps.now += runner.EMAIL_UNDELIVERED_SECONDS + 1
        self.run_all(deps)
        self.run_all(deps)
        undelivered = [b for b in self.bodies(deps) if "NOT handed to the mail command" in b]
        self.assertEqual(len(undelivered), 1, "email-undelivered fires once on the ticket")
        self.assertEqual(self.high_raises(deps, runner.UNDELIVERED_PREFIX), [runner.UNDELIVERED_PREFIX + iid + ":1"])

    def test_mail_command_failure_fires_email_undelivered(self):
        iid, deps, key = self.escalate()
        self.mail_mode = "fail"
        deps.now += 60
        self.ops_run(deps)
        self.assertEqual(len(self.mail), 1)
        self.assert_undelivered_once(iid, deps, key)
        # the queued mail succeeds later: the receipt arrives and the undelivered alert is cleared
        self.mail_mode = "ok"
        deps.now += 60
        self.ops_run(deps)
        self.run_all(deps)
        self.run_all(deps)
        self.assertEqual(self.mail_effect(iid)["status"], "done")
        cleared = [a for a in deps.ah_calls if a[:3] == ["ah", "alert", "clear"]
                   and a[a.index("--alert-key") + 1].startswith(runner.UNDELIVERED_PREFIX)]
        self.assertEqual(len(cleared), 1)

    def test_failed_oldest_sends_retry_and_land_late_while_newer_keys_wait(self):
        """adv-4 F3 / v6e AC-19: ops-watch drains at most 3 sends per run, oldest first, and a failed send stays in
        pending_deadman. Four escalations; the oldest three keep failing, so the fourth is never even tried. When
        mail recovers, every key lands on a later run: each late one clears its email-undelivered alert with a
        ticket note, send attempts outnumber deliveries, and no key is delivered twice."""
        deps = self.deps()
        gh = deps.gh

        def gh_any_pr(argv, timeout):
            rc, out, err = gh(argv, timeout)
            pr = json.loads(out)
            pr["number"] = int(argv[3])
            return rc, json.dumps(pr), err
        deps.gh = gh_any_pr
        items = []
        for pr in (11, 12, 13, 14):
            req = {"repo": REPO, "pr": pr, "head": HEAD, "base": BASE, "packet": str(self.packet),
                   "ticket": "GoodQA goodqa#16034", "owner": "agent-abc123", "submitted": deps.now + pr}
            items.append(core.submit(self.paths, self.config, req)["id"])
            self.run_all(deps)
        deps.now += runner.bounds(self.config)["block_ack_seconds"] + 1
        self.run_all(deps)
        keys = ["ahc:%s:1" % iid for iid in items]
        sent = []   # (key, ok) per send attempt

        def deadman(argv, t, stdin):
            key = next((k for k in keys if k in argv[-1]), None)
            ok = self.mail_mode == "ok"
            sent.append((key, ok))
            return (0 if ok else 1, "")
        cfg = dict(self.cfg, sinks=self.sinks)
        run = lambda: self.ow.run_once(cfg, self.ops_home, runner=_OpsRunner({("fake-deadman",): deadman}),  # noqa
                                       checks={}, now=deps.now)
        self.mail_mode = "fail"
        for _ in range(3):
            deps.now += 60
            run()
        queued = [e["key"] for e in self.ow.load_state(self.ops_home).get("pending_deadman", [])]
        self.assertEqual(sorted(queued), sorted(keys), "all four stay queued after failed sends")
        self.assertEqual({k for k, _ok in sent}, set(queued[:3]), "oldest first, at most 3 per run")
        self.assertNotIn(queued[3], {k for k, _ok in sent}, "the newest key is never tried while 3 older fail")
        self.assertEqual(len(sent), 9, "3 attempts per run over 3 runs")
        deps.now += runner.EMAIL_UNDELIVERED_SECONDS + 1
        self.run_all(deps)
        self.run_all(deps)
        self.assertEqual(len(self.high_raises(deps, runner.UNDELIVERED_PREFIX)), 4, "all four are undelivered")
        self.mail_mode = "ok"
        for _ in range(3):
            deps.now += 60
            run()
            self.run_all(deps)
        delivered = [k for k, ok in sent if ok]
        self.assertEqual(sorted(delivered), sorted(keys), "every key lands, each exactly once")
        self.assertGreater(len(sent), len(delivered), "send attempts are counted apart from deliveries")
        for iid in items:
            self.assertEqual(self.mail_effect(iid)["status"], "done")
        cleared = {a[a.index("--alert-key") + 1] for a in deps.ah_calls if a[:3] == ["ah", "alert", "clear"]
                   and a[a.index("--alert-key") + 1].startswith(runner.UNDELIVERED_PREFIX)}
        self.assertEqual(len(cleared), 4)
        late = [b for b in self.bodies(deps) if "handed to the mail command late" in b]
        self.assertEqual(len(late), 4, "one ticket note per late delivery")

    def test_mail_command_timeout_is_not_delivery(self):
        iid, deps, key = self.escalate()
        self.mail_mode = "timeout"
        deps.now += 60
        self.ops_run(deps)
        self.assert_undelivered_once(iid, deps, key)

    def test_ops_watch_crash_after_send_resends_once_then_one_receipt(self):
        iid, deps, key = self.escalate()
        real = self.ow.save_state
        calls = []

        def crash_on_final_save(home, state):
            calls.append(1)
            if len(calls) > 1:   # the forward save succeeds; the end-of-run save (after the send) is lost
                raise OSError("simulated crash before the final state save")
            return real(home, state)
        deps.now += 60
        self.ops_run(deps, save=crash_on_final_save)
        self.assertEqual(len(self.mail), 1)
        self.assertGreaterEqual(len(calls), 2, "test setup: the end-of-run save must have been attempted")
        self.assertIsNone(self.ow.delivered_at(self.ops_home, key), "the receipt was lost with the save")
        before = self.esc_n(iid)
        self.run_all(deps)
        self.assertEqual(self.mail_effect(iid)["status"], "pending")
        deps.now += 60
        self.ops_run(deps)
        self.assertEqual(len(self.mail), 2, "at-least-once: exactly one re-send")
        self.run_all(deps)
        self.assertEqual(self.mail_effect(iid)["status"], "done", "then exactly one receipt")
        deps.now += 60
        self.ops_run(deps)
        self.assertEqual(len(self.mail), 2, "no further sends after the receipt")
        self.assertEqual(self.esc_n(iid), before, "<n> is unchanged across the restart")

    def test_truncation_past_50_is_never_a_receipt(self):
        iid, deps, key = self.escalate()
        self.mail_mode = "fail"
        deps.now += 60
        self.ops_run(deps)
        for n in range(55):   # 55 newer criticals from another source push ours out of the last-50 window
            self.ow.emit({"host": self.HOST, "source": "other", "event": "raise", "severity": "critical",
                          "key": "other:%d" % n, "check": "x", "message": "m", "detail": {}}, home=self.ops_home)
        deps.now += 60
        self.ops_run(deps)
        self.mail_mode = "ok"
        for _ in range(3):
            deps.now += 60
            self.ops_run(deps)
        self.assertIsNone(self.ow.delivered_at(self.ops_home, key), "truncated from the deadman queue")
        self.assert_undelivered_once(iid, deps, key)

    def test_receipt_before_the_raise_does_not_count(self):
        iid, deps, key = self.escalate()
        state = self.ow.load_state(self.ops_home)
        state.setdefault("deadman_delivered", {})[key] = deps.now - 3600   # a stale receipt for the same key
        self.ow.save_state(self.ops_home, state)
        deps.now += 61   # past the per-tick recheck
        self.run_all(deps)
        self.assertEqual(self.mail_effect(iid)["status"], "pending")
        self.assertIn("predates", self.mail_effect(iid)["result"])

    def test_unreadable_or_mismatched_answer_is_not_delivered(self):
        iid, deps, key = self.escalate()
        for answer in ((1, "", "boom"), (0, "not json", ""), (0, json.dumps({"key": "other", "delivered_at": 9e12}), ""),
                       (0, json.dumps({"key": key, "delivered_at": True}), "")):
            with self.subTest(answer=answer[1][:20]):
                deps.ops_watch = lambda argv, t, _a=answer: ((0, "\n".join(self.ow.capabilities()), "")
                                                             if argv[0] == "capabilities" else
                                                             (0, json.dumps({"sinks": self.sinks}), "")
                                                             if argv[0] == "config" else _a)
                deps.now += 61
                self.run_all(deps)
                self.assertEqual(self.mail_effect(iid)["status"], "pending")

    def esc_n(self, iid):
        ledger = runner.Ledger(self.paths)
        try:
            return ledger.item(iid)["esc_n"]
        finally:
            ledger.close()


class _OpsRunner:
    """ops-watch runner fake: an argv prefix to a callable; anything else exits 127."""

    def __init__(self, table):
        self.table = table

    def __call__(self, argv, timeout, stdin=None, env=None, cwd=None):
        for prefix, fn in self.table.items():
            if tuple(argv[:len(prefix)]) == prefix:
                return fn(argv, timeout, stdin)
        return (127, "")


class FakeHost:
    """systemctl and loginctl on a fake Linux host: records argv, keeps linger and unit state."""

    def __init__(self, linger="no", fail=()):
        self.linger, self.fail, self.calls, self.active = linger, set(fail), [], set()

    def __call__(self, argv, timeout=60):
        self.calls.append(list(argv))
        verb = " ".join(argv[:3])
        if verb in self.fail or argv[0] in self.fail:
            return 1, ""
        if argv[:2] == ["loginctl", "show-user"]:
            return 0, self.linger + "\n"
        if argv[:2] == ["loginctl", "enable-linger"]:
            self.linger = "yes"
        if argv[:2] == ["loginctl", "disable-linger"]:
            self.linger = "no"
        if argv[:3] == ["systemctl", "--user", "enable"]:
            self.active |= {a.split(".")[0] for a in argv if a.endswith(".service")}
        if argv[:3] == ["systemctl", "--user", "disable"]:
            self.active -= {a.split(".")[0] for a in argv if a.endswith(".service")}
        if argv[:3] == ["systemctl", "--user", "is-active"]:
            unit = argv[3].split(".")[0]
            return (0, "active\n") if unit in self.active else (3, "inactive\n")
        return 0, ""


class _HostBase(Base):
    def setUp(self):
        super().setUp()
        import ahc_install
        self.inst = ahc_install
        self.out = []

    def install(self, host, apply=True, system="Linux"):
        return self.inst.install(self.paths, self.home, apply, run=host, system=system, out=self.out.append)

    def uninstall(self, host, apply=True, system="Linux"):
        return self.inst.uninstall(self.paths, self.home, apply, run=host, system=system, out=self.out.append)

    def unit(self, name):
        return self.home / ".config" / "systemd" / "user" / ("%s.service" % name)


class InstallTests(_HostBase):
    """AC-11 / AC-29: `ahc install --apply` writes and starts both user units with lingering on; dry run changes
    nothing; a non-systemd host is refused."""

    def test_apply_writes_units_enables_linger_and_starts_both(self):
        host = FakeHost(linger="no")
        self.assertEqual(self.install(host), 0)
        for name in ("ahc-core", "ahc-review"):
            text = self.unit(name).read_text()
            self.assertIn("ahc_runner.py run --role %s" % name.split("-")[1], text)
            self.assertIn("Restart=always", text)
            self.assertIn("RestartPreventExitStatus=3 75", text, "a schema refusal or lockout must not loop")
            self.assertIn("MemoryMax=", text)
            self.assertIn("WantedBy=default.target", text)
        self.assertIn(["loginctl", "enable-linger", self.inst._user()], host.calls)
        self.assertIn(["systemctl", "--user", "enable", "--now", "ahc-core.service", "ahc-review.service"], host.calls)
        self.assertEqual(host.active, {"ahc-core", "ahc-review"})
        self.assertEqual(json.loads((self.paths.root / "config.json").read_text())["ops_ticket"], "GoodQA goodqa#16034")
        wrapper = self.home / ".local" / "bin" / "ahc"
        self.assertTrue(os.access(str(wrapper), os.X_OK))
        self.assertIn("ahc_runner.py", wrapper.read_text())

    def test_dry_run_changes_nothing(self):
        host = FakeHost()
        self.assertEqual(self.install(host, apply=False), 0)
        self.assertFalse(self.unit("ahc-core").exists())
        self.assertFalse([c for c in host.calls if c[:2] != ["loginctl", "show-user"]], "a dry run runs nothing")
        self.assertTrue(any(line.startswith("would run systemctl") for line in self.out))

    def test_non_systemd_host_is_refused(self):
        host = FakeHost()
        self.assertEqual(self.install(host, system="Darwin"), 2)
        self.assertEqual(host.calls, [])
        self.assertFalse(self.unit("ahc-core").exists())

    def test_existing_config_keeps_its_ops_ticket_and_keys(self):
        self.paths.ensure()
        (self.paths.root / "config.json").write_text(json.dumps({"ops_ticket": "GoodQA x#1", "repos": ["a/b"]}))
        self.install(FakeHost())
        self.assertEqual(json.loads((self.paths.root / "config.json").read_text()),
                         {"ops_ticket": "GoodQA x#1", "repos": ["a/b"]})

    def test_a_failed_systemctl_is_a_nonzero_exit(self):
        self.assertEqual(self.install(FakeHost(fail={"systemctl --user enable"})), 1)


class UninstallTests(_HostBase):
    """spec P0 uninstall: stop and disable both units, remove the unit files, put lingering back as the install
    found it, and keep the ledger, clones and inbox with their paths printed."""

    def test_uninstall_restores_linger_off_and_keeps_data(self):
        host = FakeHost(linger="no")
        self.install(host)
        runner.Ledger(self.paths).close()
        (self.paths.inbox / "agent-x").mkdir(parents=True, exist_ok=True)
        self.out.clear()
        self.assertEqual(self.uninstall(host), 0)
        self.assertIn(["systemctl", "--user", "disable", "--now", "ahc-core.service", "ahc-review.service"],
                      host.calls)
        self.assertFalse(self.unit("ahc-core").exists() or self.unit("ahc-review").exists())
        self.assertEqual(host.linger, "no", "lingering was off before ahc, so it is off again")
        self.assertEqual(host.active, set())
        self.assertTrue((self.paths.root / "ledger.sqlite3").exists(), "the ledger is kept")
        self.assertTrue((self.paths.inbox / "agent-x").exists(), "the inbox is kept")
        printed = "\n".join(self.out)
        for path in (self.paths.root / "ledger.sqlite3", self.paths.clones, self.paths.inbox):
            self.assertIn(str(path), printed)
        self.assertFalse((self.home / ".local" / "bin" / "ahc").exists())

    def test_uninstall_leaves_linger_on_when_it_was_on(self):
        host = FakeHost(linger="yes")
        self.install(host)
        self.uninstall(host)
        self.assertEqual(host.linger, "yes")
        self.assertFalse([c for c in host.calls if c[:2] == ["loginctl", "disable-linger"]])

    def test_reinstall_never_overwrites_the_first_linger_record(self):
        host = FakeHost(linger="no")
        self.install(host)            # lingering turned on here
        self.install(host)            # a re-install sees it on; the record must still say "off before ahc"
        self.uninstall(host)
        self.assertEqual(host.linger, "no")

    def test_no_record_leaves_linger_alone(self):
        host = FakeHost(linger="yes")
        self.uninstall(host)
        self.assertEqual(host.linger, "yes")
        self.assertTrue(any("no record" in line for line in self.out))

    def test_foreign_ahc_on_path_is_not_removed(self):
        wrapper = self.home / ".local" / "bin" / "ahc"
        wrapper.parent.mkdir(parents=True)
        wrapper.write_text("#!/bin/sh\necho someone else's ahc\n")
        self.uninstall(FakeHost())
        self.assertTrue(wrapper.exists(), "uninstall removes only the wrapper it wrote")


class SchemaTests(Base):
    """v14 item 1 / NEG-37: schema_version; refuse newer or unknown; forward-only migration after a copy."""

    def test_new_ledger_records_its_version(self):
        ledger = runner.Ledger(self.paths)
        try:
            row = ledger.db.execute("SELECT v FROM meta WHERE k='schema_version'").fetchone()
        finally:
            ledger.close()
        self.assertEqual(int(row["v"]), runner.SCHEMA_VERSION)

    def set_version(self, value):
        ledger = runner.Ledger(self.paths)
        ledger.db.execute("UPDATE meta SET v=? WHERE k='schema_version'", (value,))
        ledger.close()

    def test_newer_version_refuses_to_start(self):
        self.set_version(str(runner.SCHEMA_VERSION + 1))
        with self.assertRaises(runner.SchemaError):
            runner.tick(self.paths, self.config, Deps())

    def test_unreadable_version_refuses_to_start(self):
        self.set_version("banana")
        with self.assertRaises(runner.SchemaError):
            runner.Ledger(self.paths)

    def test_pre_version_ledger_is_copied_then_migrated(self):
        iid, deps = self.submit(), Deps(verdict="BLOCK")
        self.run_all(deps)
        ledger = runner.Ledger(self.paths)
        ledger.db.execute("DELETE FROM meta WHERE k='schema_version'")
        ledger.close()
        runner.Ledger(self.paths).close()
        backups = list(self.paths.root.glob("ledger.sqlite3.pre-v*.bak"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(self.state(iid), "block-delivered")

    def test_failed_migration_rolls_back_and_keeps_the_copy(self):
        self.submit()
        self.run_all(Deps())
        ledger = runner.Ledger(self.paths)
        ledger.db.execute("DELETE FROM meta WHERE k='schema_version'")
        ledger.close()
        saved = dict(runner.MIGRATIONS)
        runner.MIGRATIONS[1] = ["CREATE TABLE extra(x)", "THIS IS NOT SQL"]
        try:
            with self.assertRaises(Exception):
                runner.Ledger(self.paths)
        finally:
            runner.MIGRATIONS.clear()
            runner.MIGRATIONS.update(saved)
        import sqlite3
        db = sqlite3.connect(str(self.paths.root / "ledger.sqlite3"))
        try:
            tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            version = db.execute("SELECT v FROM meta WHERE k='schema_version'").fetchone()
        finally:
            db.close()
        self.assertNotIn("extra", tables, "a failed migration left a partial change")
        self.assertIsNone(version)
        self.assertTrue(list(self.paths.root.glob("ledger.sqlite3.pre-v*.bak")))

    # --- v17 F2: the v1 -> v2 migration, its verified backup and the restore path
    V1_ITEMS = ("CREATE TABLE items (id TEXT PRIMARY KEY, lineage TEXT NOT NULL, owner TEXT NOT NULL, ticket TEXT NOT "
                "NULL, state TEXT NOT NULL, next_action_at REAL, submitted REAL NOT NULL, lease_token INTEGER NOT NULL "
                "DEFAULT 0, lease_until REAL NOT NULL DEFAULT 0, attempts TEXT NOT NULL DEFAULT '{}', request TEXT NOT "
                "NULL, data TEXT NOT NULL DEFAULT '{}', updated REAL)")

    def make_v1(self, rows=3):
        """A version-1 ledger whose item rows are committed but NOT checkpointed: they live only in the -wal file,
        held open by the returned connection (close it after the assertions)."""
        import sqlite3
        self.paths.ensure()
        db = sqlite3.connect(str(self.paths.root / "ledger.sqlite3"), isolation_level=None)
        db.execute("PRAGMA journal_mode=WAL")
        for statement in runner._statements(runner.SCHEMA):
            if statement.startswith("CREATE TABLE IF NOT EXISTS items"):
                statement = self.V1_ITEMS
            db.execute(statement)
        db.execute("INSERT INTO meta(k, v) VALUES ('schema_version', '1')")
        db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        db.execute("PRAGMA wal_autocheckpoint=0")
        for n in range(rows):
            db.execute("INSERT INTO items(id, lineage, owner, ticket, state, next_action_at, submitted, request, data,"
                       " updated) VALUES (?,?,?,?,?,?,?,?,?,?)",
                       ("ahc-%d" % n, "r|%d" % n, "o", "GoodQA #1", "routed-to-main", 5.0, 1.0, "{}",
                        json.dumps({"routed_escalations": n}), 100.0 + n))
        wal = Path(str(self.paths.root / "ledger.sqlite3") + "-wal")
        self.assertGreater(wal.stat().st_size, 0, "test setup: the rows must sit uncheckpointed in the -wal file")
        return db

    def columns(self, path):
        import sqlite3
        db = sqlite3.connect(str(path))
        try:
            cols = {row[1] for row in db.execute("PRAGMA table_info(items)")}
            version = db.execute("SELECT v FROM meta WHERE k='schema_version'").fetchone()
            count = db.execute("SELECT COUNT(*) FROM items").fetchone()[0]
        finally:
            db.close()
        return cols, version[0] if version else None, count

    def test_v1_migrates_to_v2_keeping_uncheckpointed_rows(self):
        held = self.make_v1()
        try:
            ledger = runner.Ledger(self.paths)
            try:
                rows = {r["id"]: (r["esc_n"], r["entered_at"]) for r in ledger.db.execute("SELECT * FROM items")}
            finally:
                ledger.close()
        finally:
            held.close()
        self.assertEqual(rows, {"ahc-0": (0, 100.0), "ahc-1": (1, 101.0), "ahc-2": (2, 102.0)},
                         "every uncheckpointed row survives; esc_n backfilled from routed_escalations")
        backups = list(self.paths.root.glob("ledger.sqlite3.pre-v%d.*.bak" % runner.SCHEMA_VERSION))
        self.assertEqual(len(backups), 1)
        cols, version, count = self.columns(backups[0])
        self.assertEqual((version, count), ("1", 3), "the backup is the v1 ledger with the -wal rows included")
        self.assertNotIn("esc_n", cols)

    def test_failed_v2_migration_restores_the_backup_and_moves_files_aside(self):
        held = self.make_v1()

        def boom(db):
            raise RuntimeError("injected migration failure")
        saved = dict(runner.MIGRATIONS)
        runner.MIGRATIONS[2] = list(saved[2]) + [boom]
        try:
            with self.assertRaises(runner.SchemaError) as caught:
                runner.Ledger(self.paths)
        finally:
            runner.MIGRATIONS.clear()
            runner.MIGRATIONS.update(saved)
            held.close()
        self.assertIn("restored", str(caught.exception))
        cols, version, count = self.columns(self.paths.root / "ledger.sqlite3")
        self.assertEqual((version, count), ("1", 3), "the restored ledger is the v1 copy with every row")
        self.assertNotIn("esc_n", cols, "no partial v2 change survives")
        aside = sorted(p.name for p in self.paths.root.glob("ledger.sqlite3.failed-*"))
        self.assertTrue(aside and aside[0].endswith(tuple("0123456789")), aside)
        suffixes = {name.rsplit("-", 1)[-1] if name.endswith(("-wal", "-shm")) else "db" for name in aside}
        self.assertIn("db", suffixes, "the failed database file is moved aside, never deleted")
        self.assertEqual(len({name.split(".failed-")[1].split("-")[0] for name in aside}), 1,
                         "db, -wal and -shm move together under one suffix")
        # the restored ledger opens again and migrates cleanly once the defect is gone
        runner.Ledger(self.paths).close()
        self.assertEqual(self.columns(self.paths.root / "ledger.sqlite3")[1:], (str(runner.SCHEMA_VERSION), 3))

    # --- PR 258 v4 F1: the restore streams the backup and never moves the live database aside before the copy
    def failing_migration(self, step):
        saved = dict(runner.MIGRATIONS)
        runner.MIGRATIONS[2] = [step] + list(saved[2])

        def undo():
            runner.MIGRATIONS.clear()
            runner.MIGRATIONS.update(saved)
        return undo

    def test_restore_memory_does_not_grow_with_the_backup(self):
        """A backup far larger than a small memory budget restores within it. The old restore read the whole backup
        into memory (read_regular joins its chunks, about twice the size) after moving the live database aside, so
        under the unit's MemoryMax a large ledger could not be restored. tracemalloc measures Python allocations
        while the restore runs; the copy must hold no more than a few chunks."""
        import tracemalloc
        held = self.make_v1()
        size = 8 * 1024 * 1024
        held.execute("CREATE TABLE ballast(b BLOB)")
        held.execute("INSERT INTO ballast(b) VALUES (randomblob(?))", (size,))
        held.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        peaks = {}

        def boom(db):
            raise RuntimeError("injected migration failure")
        real_restore = runner.Ledger.restore

        def measured(ledger, copy):
            tracemalloc.start()
            try:
                return real_restore(ledger, copy)
            finally:
                peaks["restore"] = tracemalloc.get_traced_memory()[1]
                tracemalloc.stop()
        undo = self.failing_migration(boom)
        try:
            with mock.patch.object(runner.Ledger, "restore", measured):
                with self.assertRaises(runner.SchemaError) as caught:
                    runner.Ledger(self.paths)
        finally:
            undo()
            held.close()
        self.assertIn("restored", str(caught.exception))
        budget = 4 * 1024 * 1024
        self.assertLess(peaks["restore"], budget, "the restore held %d bytes for an %d-byte backup"
                        % (peaks["restore"], size))
        cols, version, count = self.columns(self.paths.root / "ledger.sqlite3")
        self.assertEqual((version, count), ("1", 3), "the restored ledger is the v1 copy")
        import sqlite3
        db = sqlite3.connect(str(self.paths.root / "ledger.sqlite3"))
        try:
            self.assertEqual(db.execute("SELECT length(b) FROM ballast").fetchone()[0], size)
            self.assertEqual(db.execute("PRAGMA integrity_check").fetchone()[0], "ok")
        finally:
            db.close()

    def test_a_restore_whose_copy_fails_leaves_the_live_database_in_place(self):
        """The backup vanishes during the failed migration, so the restore cannot copy it. The old restore had
        already moved the live database aside, which left no ledger and a pending intent, so every restart failed
        the same way. Now the live database is never moved before the copy succeeds. It stays in place, unchanged,
        the intent is dropped, and the next start migrates it."""
        held = self.make_v1()

        def lose_backup(db):
            for backup in self.paths.root.glob("ledger.sqlite3.pre-v*.bak"):
                backup.unlink()
            raise RuntimeError("injected migration failure")
        undo = self.failing_migration(lose_backup)
        try:
            with self.assertRaises(runner.SchemaError) as caught:
                runner.Ledger(self.paths)
        finally:
            undo()
            held.close()
        self.assertIn("left in place", str(caught.exception))
        live = self.paths.root / "ledger.sqlite3"
        self.assertTrue(live.is_file(), "the live database was moved aside before the copy succeeded")
        self.assertEqual(self.columns(live)[1:], ("1", 3), "the live database is the unchanged v1 ledger")
        self.assertFalse(list(self.paths.root.glob("ledger.sqlite3.failed-*")), "nothing was moved aside")
        self.assertFalse(Path(str(live) + ".restore-intent").exists(), "a stale intent would repeat the restore")
        self.assertFalse(list(self.paths.root.glob(".ledger.sqlite3.*.tmp")), "the partial copy is removed")
        runner.Ledger(self.paths).close()                    # the next start migrates the intact ledger
        self.assertEqual(self.columns(live)[1:], (str(runner.SCHEMA_VERSION), 3))

    def test_a_ledger_over_the_cap_is_never_migrated(self):
        """The size cap is enforced before the migration starts: no backup, no intent, nothing moved."""
        held = self.make_v1()
        held.close()
        with mock.patch.object(runner, "RESTORE_MAX_BYTES", 1024):
            with self.assertRaises(runner.SchemaError) as caught:
                runner.Ledger(self.paths)
        self.assertIn("migration cap", str(caught.exception))
        self.assertFalse(list(self.paths.root.glob("ledger.sqlite3.pre-v*.bak")), "a backup was made")
        self.assertFalse(list(self.paths.root.glob("ledger.sqlite3.failed-*")))
        self.assertEqual(self.columns(self.paths.root / "ledger.sqlite3")[1:], ("1", 3))

    def test_an_interrupted_streaming_copy_is_discarded_and_the_restore_completes(self):
        """A crash in the middle of the copy leaves a partial temp file. With the live file already gone (the
        crash came between move and publish on an earlier attempt), the intent stays. The next start removes the
        partial copy, streams a full one and publishes it."""
        held = self.make_v1()
        held.close()
        live = self.paths.root / "ledger.sqlite3"
        backup = live.with_name("ledger.sqlite3.pre-v9.1.bak")
        import sqlite3
        src = sqlite3.connect(str(live))
        dst = sqlite3.connect(str(backup))
        src.backup(dst)
        src.close()
        dst.close()
        os.chmod(str(backup), 0o600)
        os.rename(str(live), str(live) + ".failed-1")
        for extra in ("-wal", "-shm"):
            if os.path.lexists(str(live) + extra):
                os.rename(str(live) + extra, str(live) + ".failed-1" + extra)
        partial = self.paths.root / ".ledger.sqlite3.0123456789abcdef.tmp"
        with open(str(backup), "rb") as handle:
            partial.write_bytes(handle.read(4096))
        os.chmod(str(partial), 0o600)
        Path(str(live) + ".restore-intent").write_text(json.dumps({"backup": backup.name, "suffix": ".failed-1"}))
        os.chmod(str(live) + ".restore-intent", 0o600)
        runner.Ledger(self.paths).close()
        self.assertFalse(partial.exists(), "the partial copy was left behind")
        self.assertFalse(Path(str(live) + ".restore-intent").exists())
        self.assertEqual(self.columns(live)[1:], (str(runner.SCHEMA_VERSION), 3), "restored, then migrated")

    # --- v3 (goodqa#16049 M-1): the v2 -> v3 step adds items.cause and the contract tables, keeping every row and
    # its D20 clock; a migrated ledger has exactly the fresh ledger's tables and columns
    def shape(self, path):
        import sqlite3
        db = sqlite3.connect(str(path))
        try:
            tables = sorted(r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table' "
                                                      "AND name NOT LIKE 'sqlite_%'"))
            return {name: sorted(r[1] for r in db.execute("PRAGMA table_info(%s)" % name)) for name in tables}
        finally:
            db.close()

    def make_v2(self):
        import sqlite3
        self.paths.ensure()
        db = sqlite3.connect(str(self.paths.root / "ledger.sqlite3"), isolation_level=None)
        contract_statements = set(runner._statements(runner.ahc_contracts.SCHEMA))
        for statement in runner._statements(runner.SCHEMA):
            if statement.startswith("CREATE TABLE IF NOT EXISTS items"):
                statement = statement.replace(", cause TEXT)", ")")
            if statement in contract_statements:
                continue
            db.execute(statement)
        db.execute("INSERT INTO meta(k, v) VALUES ('schema_version', '2')")
        db.execute("INSERT INTO items(id, lineage, owner, ticket, state, next_action_at, submitted, request, data,"
                   " updated, entered_at, esc_n) VALUES ('ahc-v2', 'r|1', 'o', 'GoodQA #1', 'block-delivered', NULL,"
                   " 1.0, '{}', '{}', 50.0, 40.0, 2)")
        db.close()

    def test_cause_is_kept_within_a_state_and_cleared_when_the_state_changes(self):
        iid = self.submit()
        ledger = runner.Ledger(self.paths)
        worker = runner.Worker(self.paths, self.config, Deps(), ledger)
        try:
            def cause():
                return worker.led.db.execute("SELECT cause FROM items WHERE id=?", (iid,)).fetchone()["cause"]
            token = worker.lease(iid)
            worker.settle(iid, token, "deferred", worker.now() + 60, cause="circuit:github-read")
            self.assertEqual(cause(), "circuit:github-read")
            worker.settle(iid, token, "deferred", worker.now() + 120)
            self.assertEqual(cause(), "circuit:github-read", "a same-state settle keeps the cause")
            worker.settle(iid, token, "queued", worker.now() + 1)
            self.assertIsNone(cause(), "a new state without a cause clears it")
        finally:
            ledger.close()

    def test_v2_migrates_to_current_with_the_fresh_shape_and_rows_intact(self):
        fresh_paths = core.Paths(self.home / "fresh")
        runner.Ledger(fresh_paths).close()
        self.make_v2()
        self.assertNotIn("reviews", self.shape(self.paths.root / "ledger.sqlite3"), "fixture is a real v2 ledger")
        self.assertNotIn("cause", self.shape(self.paths.root / "ledger.sqlite3")["items"])
        ledger = runner.Ledger(self.paths)
        try:
            row = dict(ledger.db.execute("SELECT * FROM items WHERE id='ahc-v2'").fetchone())
        finally:
            ledger.close()
        self.assertEqual((row["state"], row["entered_at"], row["esc_n"], row["cause"]),
                         ("block-delivered", 40.0, 2, None), "state and D20 clock survive; cause starts empty")
        self.assertEqual(self.shape(self.paths.root / "ledger.sqlite3"),
                         self.shape(fresh_paths.root / "ledger.sqlite3"), "migrated shape equals fresh shape")
        self.assertEqual(len(list(self.paths.root.glob("ledger.sqlite3.pre-v%d.*.bak" % runner.SCHEMA_VERSION))), 1)
        import sqlite3
        for path in (self.paths.root, fresh_paths.root):
            db = sqlite3.connect(str(path / "ledger.sqlite3"))
            try:
                self.assertEqual(db.execute("SELECT name FROM sqlite_master WHERE type='index' AND "
                                            "name='grants_one_live_per_scope'").fetchall(),
                                 [("grants_one_live_per_scope",)], "the one-grant-per-scope index exists")
            finally:
                db.close()

    # --- v4 (spec ahc-m1-v2e, Codex F5/F6): a populated ledger of the committed v3 layout (21357968, and the
    # earlier d398d7fb layout) upgrades with its grant and operation rows kept intact and reported, restarts cleanly,
    # and the pre-v4 backup is still readable by the previous release.
    V3_LAYOUTS = {
        "21357968": (
            "CREATE TABLE grants (id TEXT PRIMARY KEY, kind TEXT NOT NULL, source TEXT NOT NULL, principal TEXT NOT "
            "NULL, repo TEXT NOT NULL, pr INTEGER NOT NULL, head TEXT NOT NULL, base TEXT NOT NULL, policy_revision "
            "TEXT NOT NULL, uses INTEGER NOT NULL, expires_at REAL NOT NULL, state TEXT NOT NULL, operation TEXT, "
            "bound_key TEXT, authority_seq INTEGER, version INTEGER NOT NULL, created REAL NOT NULL, updated REAL "
            "NOT NULL)",
            "CREATE UNIQUE INDEX grants_one_live_per_scope ON grants(kind, repo, pr, head, base) WHERE state IN "
            "('validated', 'active', 'reserved')",
            "CREATE TABLE operations (key TEXT PRIMARY KEY, kind TEXT NOT NULL, item TEXT, repo TEXT NOT NULL, pr "
            "INTEGER NOT NULL, head TEXT NOT NULL, base TEXT NOT NULL, policy_revision TEXT NOT NULL, generation "
            "INTEGER NOT NULL, params TEXT, params_sha256 TEXT NOT NULL, grant_id TEXT, state TEXT NOT NULL, "
            "dispatch_count INTEGER NOT NULL DEFAULT 0, dispatched_at REAL, request_id TEXT, built_sha TEXT, refusal "
            "TEXT, probe_at REAL, escalate_at REAL, readbacks INTEGER NOT NULL DEFAULT 0, proof TEXT, evidence TEXT, "
            "incident INTEGER NOT NULL DEFAULT 0, pr_unmarked INTEGER NOT NULL DEFAULT 0, settled_at REAL, tombstone "
            "INTEGER NOT NULL DEFAULT 0, version INTEGER NOT NULL, created REAL NOT NULL, updated REAL NOT NULL)"),
        "d398d7fb": (
            "CREATE TABLE grants (id TEXT PRIMARY KEY, kind TEXT NOT NULL, source TEXT NOT NULL, principal TEXT NOT "
            "NULL, scope TEXT NOT NULL, policy_revision TEXT NOT NULL, uses INTEGER NOT NULL, expires_at REAL NOT "
            "NULL, state TEXT NOT NULL, operation TEXT, authority_seq INTEGER, version INTEGER NOT NULL, created REAL "
            "NOT NULL, updated REAL NOT NULL)",
            "CREATE TABLE operations (key TEXT PRIMARY KEY, kind TEXT NOT NULL, item TEXT, params TEXT, params_sha256 "
            "TEXT NOT NULL, grant_id TEXT, state TEXT NOT NULL, dispatch_count INTEGER NOT NULL DEFAULT 0, "
            "dispatched_at REAL, request_id TEXT, probe_at REAL, escalate_at REAL, readbacks INTEGER NOT NULL DEFAULT "
            "0, proof TEXT, evidence TEXT, incident INTEGER NOT NULL DEFAULT 0, settled_at REAL, tombstone INTEGER "
            "NOT NULL DEFAULT 0, version INTEGER NOT NULL, created REAL NOT NULL, updated REAL NOT NULL)"),
    }

    # The reviews table both committed v3 layouts share (no snapshot base B_r).
    V3_REVIEWS = (
        "CREATE TABLE reviews (id TEXT PRIMARY KEY, kind TEXT NOT NULL, item TEXT, repo TEXT NOT NULL, pr INTEGER NOT "
        "NULL, head TEXT NOT NULL, packet_sha256 TEXT NOT NULL, policy_revision TEXT NOT NULL, state TEXT NOT NULL, "
        "version INTEGER NOT NULL, receipt TEXT, successor TEXT, producer_unit TEXT, producer_uid INTEGER, data TEXT "
        "NOT NULL DEFAULT '{}', created REAL NOT NULL, updated REAL NOT NULL, UNIQUE(kind, repo, pr, head, "
        "packet_sha256, policy_revision))")

    def make_v3(self, layout):
        import sqlite3
        self.make_v2()
        db = sqlite3.connect(str(self.paths.root / "ledger.sqlite3"), isolation_level=None)
        db.execute("ALTER TABLE items ADD COLUMN cause TEXT")
        db.execute(self.V3_REVIEWS)
        db.execute("INSERT INTO reviews(id, kind, repo, pr, head, packet_sha256, policy_revision, state, version, "
                   "created, updated) VALUES ('rv-v3', 'adversarial', 'o/r', 5, ?, ?, 'p', 'running', 3, 1, 2)",
                   ("a" * 40, "d" * 64))
        for statement in runner._statements(runner.ahc_contracts.SCHEMA):
            if not any(statement.startswith(p) for p in ("CREATE TABLE IF NOT EXISTS reviews",
                                                         "CREATE TABLE IF NOT EXISTS grants",
                                                         "CREATE UNIQUE INDEX IF NOT EXISTS grants_",
                                                         "CREATE TABLE IF NOT EXISTS operations",
                                                         "CREATE TABLE IF NOT EXISTS contract_meta",
                                                         "INSERT OR IGNORE INTO contract_meta",
                                                         "CREATE TABLE IF NOT EXISTS repo_flags")):
                db.execute(statement)
        for statement in self.V3_LAYOUTS[layout]:
            db.execute(statement)
        if layout == "21357968":
            grant = "INSERT INTO grants VALUES (?,'merge','queue:x','ahc-policy','o/r',5,?,?,'p',1,?,?,?,NULL,1,2,1,1)"
            db.execute(grant, ("gr-live", "a" * 40, "c" * 40, 9e9, "reserved", "op-live"))
            db.execute(grant, ("gr-done", "b" * 40, "c" * 40, 9e9, "consumed", "op-done"))
            op = ("INSERT INTO operations(key, kind, repo, pr, head, base, policy_revision, generation, params, "
                  "params_sha256, grant_id, state, dispatch_count, built_sha, version, created, updated) "
                  "VALUES (?,'merge','o/r',5,?,?,'p',0,'{}','s',?,?,1,?,3,1,2)")
            db.execute(op, ("op-live", "a" * 40, "c" * 40, "gr-live", "outcome-unknown", "e" * 40))
            db.execute(op, ("op-done", "b" * 40, "c" * 40, "gr-done", "confirmed", "f" * 40))
        else:
            db.execute("INSERT INTO grants VALUES ('gr-live','merge','queue:x','ahc-policy','{}','p',1,9e9,"
                       "'reserved','op-live',1,2,1,1)")
            db.execute("INSERT INTO operations(key, kind, params, params_sha256, grant_id, state, version, created, "
                       "updated) VALUES ('op-live','merge','{}','s','gr-live','dispatched',2,1,1)")
        db.execute("UPDATE meta SET v='3' WHERE k='schema_version'")
        before = {t: sorted(db.execute("SELECT * FROM %s" % t).fetchall()) for t in ("grants", "operations",
                                                                                     "reviews")}
        db.close()
        return before

    def test_populated_v3_upgrades_keeping_unsettled_rows_and_restarts(self):
        import sqlite3
        for layout in self.V3_LAYOUTS:
            with self.subTest(layout=layout):
                self.setUp()
                before = self.make_v3(layout)
                for _ in range(2):        # the second open is a restart: a no-op on a v4 ledger
                    ledger = runner.Ledger(self.paths)
                    ledger.close()
                db = sqlite3.connect(str(self.paths.root / "ledger.sqlite3"))
                try:
                    self.assertEqual(db.execute("SELECT v FROM meta WHERE k='schema_version'").fetchone()[0],
                                     str(runner.SCHEMA_VERSION))
                    for t in ("grants", "operations", "reviews"):
                        self.assertEqual(sorted(db.execute("SELECT * FROM %s_v3_legacy" % t).fetchall()), before[t],
                                         "%s rows are kept byte for byte" % t)
                        self.assertEqual(db.execute("SELECT COUNT(*) FROM %s" % t).fetchone()[0], 0)
                    grant_cols = [r[1] for r in db.execute("PRAGMA table_info(grants)")]
                    self.assertIn("cap_held", grant_cols)
                    self.assertNotIn("merge_sha", grant_cols, "v4 (v2g2) has no candidate M")
                    self.assertIn("snapshot_base", [r[1] for r in db.execute("PRAGMA table_info(reviews)")])
                    index = db.execute("SELECT tbl_name, sql FROM sqlite_master WHERE name='grants_one_live_per_scope'")
                    table, sql = index.fetchone()
                    self.assertEqual(table, "grants", "the v4 index is on the new table, not the renamed v3 one")
                    self.assertIn("base, head", sql)
                    db.row_factory = sqlite3.Row
                    contracts = runner.ahc_contracts.Contracts(db, None)
                    unsettled = {(u["table"], u["id"]) for u in contracts.legacy_unsettled()}
                    self.assertEqual(unsettled, {("grants_v3_legacy", "gr-live"), ("operations_v3_legacy", "op-live")})
                finally:
                    db.close()
                self.assertEqual(len(list(self.paths.root.glob("ledger.sqlite3.pre-v4.*.bak"))), 1)

    def schema_sql(self, path):
        """Every non-legacy table and index, as SQLite stores it (autoindexes by table and name)."""
        import sqlite3
        db = sqlite3.connect(str(path))
        try:
            return sorted((t, n, tb, sql) for t, n, tb, sql in db.execute(
                "SELECT type, name, tbl_name, sql FROM sqlite_master WHERE type IN ('table', 'index')")
                if not tb.endswith("_v3_legacy") and n != "sqlite_sequence")
        finally:
            db.close()

    def test_fresh_v2_and_v3_paths_give_the_identical_v4_schema(self):
        """Advisor item 2: the marker-column detection and the reviews step leave no path with another layout."""
        fresh = core.Paths(self.home / "fresh")
        runner.Ledger(fresh).close()
        want = self.schema_sql(fresh.root / "ledger.sqlite3")
        self.assertTrue(any(n == "grants_one_live_per_scope" for _, n, _, _ in want))
        paths = {"v2": lambda: self.make_v2()}
        paths.update({"v3-%s" % layout: (lambda layout=layout: self.make_v3(layout)) for layout in self.V3_LAYOUTS})
        for name, make in paths.items():
            with self.subTest(path=name):
                self.setUp()
                make()
                runner.Ledger(self.paths).close()
                self.assertEqual(self.schema_sql(self.paths.root / "ledger.sqlite3"), want)

    def test_previous_release_still_reads_the_pre_v4_backup(self):
        """Rollback before cutover restores the pre-v4 backup and runs the previous release (21357968) on it."""
        import shutil as _shutil
        import subprocess
        repo = Path(__file__).resolve().parent.parent
        old = self.home / "release-prev"
        old.mkdir(parents=True)
        archive = subprocess.run(["git", "-C", str(repo), "archive", "21357968", "harness/hooks"],
                                 capture_output=True)
        if archive.returncode != 0:
            self.skipTest("commit 21357968 is not in this checkout")
        subprocess.run(["tar", "-x", "-C", str(old)], input=archive.stdout, check=True)
        self.make_v3("21357968")
        runner.Ledger(self.paths).close()
        backup = next(self.paths.root.glob("ledger.sqlite3.pre-v4.*.bak"))
        restored = self.home / "restored"
        (restored / ".agent-harness" / "coordinator").mkdir(parents=True)
        _shutil.copyfile(backup, restored / ".agent-harness" / "coordinator" / "ledger.sqlite3")
        script = ("import sys; sys.path.insert(0, sys.argv[1]); import ahc_core, ahc_runner; "
                  "l = ahc_runner.Ledger(ahc_core.Paths(sys.argv[2])); "
                  "print(l.db.execute(\"SELECT v FROM meta WHERE k='schema_version'\").fetchone()[0], "
                  "l.db.execute(\"SELECT state FROM operations WHERE key='op-live'\").fetchone()[0]); l.close()")
        proc = subprocess.run([sys.executable, "-B", "-c", script, str(old / "harness" / "hooks"), str(restored)],
                              capture_output=True, text=True, env=dict(os.environ, AH_HOME=str(self.home)))
        self.assertEqual(proc.returncode, 0, proc.stderr[-800:])
        self.assertEqual(proc.stdout.split(), ["3", "outcome-unknown"])
        # and the previous release refuses the migrated v4 ledger rather than misreading it. The previous release's
        # root is ~/.agent-harness/coordinator (ahc's root moved to ~/.agent-harness/ahc in slice 1), so the v4 file is
        # placed where that release looks for it.
        migrated = self.home / "migrated"
        (migrated / ".agent-harness" / "coordinator").mkdir(parents=True)
        _shutil.copyfile(self.paths.root / "ledger.sqlite3",
                         migrated / ".agent-harness" / "coordinator" / "ledger.sqlite3")
        proc = subprocess.run([sys.executable, "-B", "-c", script, str(old / "harness" / "hooks"),
                               str(migrated)], capture_output=True, text=True,
                              env=dict(os.environ, AH_HOME=str(self.home)))
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("not supported", proc.stderr)

    def test_unverified_backup_never_starts_the_migration(self):
        held = self.make_v1()
        real = runner.Ledger._counts
        calls = []

        def lying(ledger, db):
            calls.append(1)
            counts = real(ledger, db)
            return dict(counts, items=counts.get("items", 0) - 1) if len(calls) == 2 else counts
        runner.Ledger._counts = lying
        try:
            with self.assertRaises(runner.SchemaError) as caught:
                runner.Ledger(self.paths)
        finally:
            runner.Ledger._counts = real
            held.close()
        self.assertIn("failed verification", str(caught.exception))
        self.assertEqual(self.columns(self.paths.root / "ledger.sqlite3")[1:], ("1", 3), "the ledger is untouched")
        self.assertFalse(list(self.paths.root.glob("ledger.sqlite3.failed-*")))


class AuditMirrorTests(Base):
    """SQLite is the only recovery authority: the JSONL audit export is never read back."""

    def test_deleting_or_corrupting_the_mirror_changes_nothing(self):
        iid, deps = self.submit(), Deps()
        runner.STOP_AFTER = "reviewing"
        try:
            self.run_all(deps)
        finally:
            runner.STOP_AFTER = None
        mirror = runner.Journal(self.paths, iid).path
        self.assertTrue(mirror.exists())
        mirror.write_text('{"event": "blocked"}\n{"event": "refused", "at": 1}\nnot json\n')
        self.assertEqual(self.state(iid), "reviewing")
        self.run_all(deps)
        self.assertEqual(self.state(iid), "routed-to-main")
        mirror.unlink()
        self.run_all(deps)
        self.assertEqual(self.state(iid), "routed-to-main")
        self.assertEqual(len(deps.review_calls), 1)


class CapacityTests(Base):
    """NEG-38: submit beyond queue capacity refuses and names the depth; a duplicate stays a no-op."""

    def test_full_queue_refuses_with_depth(self):
        self.config["bounds"] = {"queue_capacity": 2}
        req = {"repo": REPO, "head": HEAD, "base": BASE, "packet": str(self.packet), "ticket": "GoodQA goodqa#16034",
               "owner": "agent-abc123"}
        first = runner.submit_with_lint(self.paths, self.config, dict(req, pr=1))
        runner.submit_with_lint(self.paths, self.config, dict(req, pr=2))
        with self.assertRaises(core.Refused) as caught:
            runner.submit_with_lint(self.paths, self.config, dict(req, pr=3))
        self.assertIn("2 items waiting (capacity 2)", str(caught.exception))
        again = runner.submit_with_lint(self.paths, self.config, dict(req, pr=1))
        self.assertEqual((again["id"], again["duplicate"]), (first["id"], True))

    def test_submit_lint_rejects_with_the_tools_exact_text(self):
        self.packet.write_text(f"head {HEAD}\ntests pass\n")
        req = {"repo": REPO, "pr": 7, "head": HEAD, "base": BASE, "packet": str(self.packet),
               "ticket": "GoodQA goodqa#16034", "owner": "agent-abc123"}
        import review_diagnostics
        expected = review_diagnostics.render_lint(review_diagnostics.lint_packet("pr", self.packet.read_text(), HEAD),
                                                  "pr")
        with self.assertRaises(core.Refused) as caught:
            runner.submit_with_lint(self.paths, self.config, req)
        self.assertEqual(str(caught.exception), expected)
        self.assertEqual(list(self.paths.queue.glob("*.json")), [])


class TimeoutTests(unittest.TestCase):
    """D21 / NEG-39: a child that hangs forever is killed with its whole process group."""

    def test_hung_child_and_grandchild_are_killed(self):
        import os
        import time as _time
        with tempfile.TemporaryDirectory() as tmp:
            pidfile = Path(tmp) / "grandchild.pid"
            script = Path(tmp) / "fake_gh.py"
            script.write_text(
                "import subprocess, sys, time\n"
                "p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(600)'])\n"
                f"open({str(pidfile)!r}, 'w').write(str(p.pid))\n"
                "time.sleep(600)\n")
            start = _time.monotonic()
            rc, _out, err = core.run_argv([sys.executable, str(script)], 1.5)
            elapsed = _time.monotonic() - start
            self.assertEqual(rc, core.TIMEOUT_RC)
            self.assertIn("process group killed", err)
            self.assertLess(elapsed, 15)
            grandchild = int(pidfile.read_text())
            for _ in range(50):
                try:
                    os.kill(grandchild, 0)
                except ProcessLookupError:
                    break
                _time.sleep(0.1)
            else:
                self.fail("the grandchild survived the timeout")

    def test_grandchild_that_ignores_sigterm_is_killed(self):
        # code-inspection r1 F2: the leader exits on SIGTERM; its child ignores SIGTERM and must still die.
        import os
        import time as _time
        with tempfile.TemporaryDirectory() as tmp:
            pidfile = Path(tmp) / "grandchild.pid"
            script = Path(tmp) / "fake_gh.py"
            script.write_text(
                "import signal, subprocess, sys, time\n"
                "p = subprocess.Popen([sys.executable, '-c', 'import signal, time; "
                "signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(600)'])\n"
                f"open({str(pidfile)!r}, 'w').write(str(p.pid))\n"
                "signal.signal(signal.SIGTERM, lambda *a: sys.exit(0))\n"
                "time.sleep(600)\n")
            rc, _out, err = core.run_argv([sys.executable, str(script)], 1.5)
            self.assertEqual(rc, core.TIMEOUT_RC)
            grandchild = int(pidfile.read_text())
            alive = True
            for _ in range(50):
                try:
                    os.kill(grandchild, 0)
                except ProcessLookupError:
                    alive = False
                    break
                _time.sleep(0.1)
            if alive:
                os.kill(grandchild, 9)
            self.assertFalse(alive, "a SIGTERM-ignoring grandchild survived")
            self.assertIn("process group killed", err)

    def test_lease_is_review_timeout_plus_60(self):
        self.assertEqual(runner.LEASE_SECONDS, core.TIMEOUTS["review"] + 60)
        self.assertEqual(core.TIMEOUTS, {"gh": 60, "git": 900, "ah": 60, "review": 1440})


class OwnerCopyTests(Base):
    """NEG-41: across a full run with real git, every git command runs inside the daemon clone root, never in the
    owner's working copy (which here holds the packet and a planted hook)."""

    def test_every_git_cwd_is_inside_the_clone_root(self):
        import os
        import subprocess
        import ahc_clone
        env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1", "GIT_AUTHOR_NAME": "t",
               "GIT_AUTHOR_EMAIL": "t@example.invalid", "GIT_COMMITTER_NAME": "t",
               "GIT_COMMITTER_EMAIL": "t@example.invalid"}

        def git(*args, cwd):
            return subprocess.run(["git", *args], cwd=cwd, env=env, check=True, capture_output=True,
                                  text=True).stdout.strip()
        owner = self.packet.parent / "owner-checkout"
        owner.mkdir()
        git("init", "-q", "-b", "main", cwd=owner)
        (owner / "a.txt").write_text("one\n")
        git("add", "a.txt", cwd=owner)
        git("commit", "-qm", "one", cwd=owner)
        base = git("rev-parse", "HEAD", cwd=owner)
        (owner / "a.txt").write_text("two\n")
        git("commit", "-qam", "two", cwd=owner)
        head = git("rev-parse", "HEAD", cwd=owner)
        remote = self.home / "remote.git"
        git("clone", "-q", "--bare", str(owner), str(remote), cwd=self.home)
        self.packet.write_text(GOOD_PACKET.replace(HEAD, head))
        calls = []
        real = ahc_clone.ahc_core.run_argv

        def recording(argv, timeout, cwd=None, env=None):
            if argv and argv[0] == "git":
                calls.append(cwd)
            return real(argv, timeout, cwd=cwd, env=env)

        class Hybrid(runner.LiveDeps):
            def __init__(self, paths, config):
                super().__init__(paths, config)
                self.fake = Deps(pr_head=head)
                self.review_calls = self.fake.review_calls

            def clock(self):
                return self.fake.now

            def gh(self, argv, timeout):
                rc, out, err = self.fake.gh(argv, timeout)
                pr = json.loads(out)
                pr.update(headRefOid=head, baseRefOid=base)
                return rc, json.dumps(pr), err

            def ah(self, argv, timeout):
                return self.fake.ah(argv, timeout)

            def review(self, argv, timeout):
                out = Path(argv[argv.index("--output") + 1])
                sha = hashlib.sha256(Path(argv[argv.index("--packet") + 1]).read_bytes()).hexdigest()
                out.write_text(f"Stage: pr\nReviewed HEAD: {head}\nReviewed packet SHA-256: {sha}\n\nVERDICT: PASS\n")
                self.review_calls.append(argv)
                return 0

        config = dict(self.config, clone_urls={REPO: str(remote)}, bounds={}, disk_floor_bytes=0,
                      clone_file_transport=True)
        req = {"repo": REPO, "pr": 7, "head": head, "base": base, "packet": str(self.packet),
               "ticket": "GoodQA goodqa#16034", "owner": "agent-abc123"}
        iid = core.submit(self.paths, config, req)["id"]
        ahc_clone.ahc_core.run_argv = recording
        try:
            deps = Hybrid(self.paths, config)
            runner.tick(self.paths, config, deps)
        finally:
            ahc_clone.ahc_core.run_argv = real
        self.assertEqual(self.state(iid), "routed-to-main", "the run did not complete")
        self.assertTrue(calls, "no git command was observed")
        root = str(self.paths.clones.resolve())
        for cwd in calls:
            self.assertIsNotNone(cwd, "a git command ran in the process cwd")
            self.assertTrue(str(Path(cwd).resolve()).startswith(root), "git ran outside the clone root: %s" % cwd)
        review_repo = deps.review_calls[0][deps.review_calls[0].index("--repo") + 1]
        self.assertTrue(str(Path(review_repo).resolve()).startswith(root))


class FileTransportOptInTests(unittest.TestCase):
    """Spec owner's condition on PR 258 v3: the local file transport is off by default and refused outside tests.
    The production root lives under the real home, so the opt-in is refused there before git runs. On a test
    root it is honoured, and without the key it stays off."""

    def run_clone(self, home, config):
        import ahc_clone
        seen = []
        real = ahc_clone.prepare

        def prepare(*args, **kw):
            seen.append(kw.get("allow_file"))
            return "/nonexistent/clone"
        ahc_clone.prepare = prepare
        try:
            with mock.patch.object(runner.shutil, "disk_usage", return_value=mock.Mock(free=1 << 50)):
                runner.LiveDeps(core.Paths(home), config).clone(REPO, HEAD, BASE)
        finally:
            ahc_clone.prepare = real
        return seen

    def test_production_root_refuses_the_file_transport(self):
        import ahc_clone
        real_home = os.path.expanduser("~")
        with self.assertRaises(ahc_clone.CloneError):
            self.run_clone(real_home, {"clone_file_transport": True})
        self.assertFalse(self.run_clone(real_home, {})[0], "without the key the file transport is off")

    def test_a_test_root_may_opt_in(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(self.run_clone(tmp, {"clone_file_transport": True}), [True])
            self.assertEqual(self.run_clone(tmp, {"clone_file_transport": "yes"}), [False], "only literal true")


class LiveIsolationTests(unittest.TestCase):
    """NEG-32: a full tick with default paths under a scratch HOME never touches the live coordinator state, the
    live harness state or the real `ah`."""

    @staticmethod
    def snapshot(root):
        import os
        if not root.exists():
            return None
        out = {}
        for path in sorted(root.rglob("*")):
            try:
                info = os.lstat(path)
            except OSError:
                continue
            out[str(path)] = (info.st_ino, info.st_mtime_ns, info.st_size)
        return out

    def test_full_tick_leaves_live_state_untouched(self):
        import os
        real_home = Path(os.path.expanduser("~"))
        coordinator = real_home / ".agent-harness" / "coordinator"   # another program's root (coordd)
        ahc_root = real_home / ".agent-harness" / "ahc"
        state = real_home / ".agent-harness" / "state"
        before_coord = self.snapshot(coordinator)
        before_ahc = self.snapshot(ahc_root)
        before_state = {k: v for k, v in (self.snapshot(state) or {}).items() if "ahc" in k or "coordinator" in k}
        with tempfile.TemporaryDirectory() as tmp:
            saved = os.environ.get("HOME")
            os.environ["HOME"] = tmp
            try:
                paths = core.Paths()
                self.assertTrue(str(paths.root).startswith(tmp), "default paths did not follow HOME")
                work = Path(tmp) / ".agent-harness" / "work" / "s"
                work.mkdir(parents=True)
                packet = work / "p.md"
                packet.write_text(GOOD_PACKET)
                config = {"repos": [REPO], "work_roots": [str(work.parent)]}
                core.submit(paths, config, {"repo": REPO, "pr": 7, "head": HEAD, "base": BASE, "packet": str(packet),
                                            "ticket": "GoodQA goodqa#16034", "owner": "agent-abc123"})
                deps = Deps(verdict="BLOCK")
                runner.tick(paths, config, deps)
            finally:
                if saved is None:
                    os.environ.pop("HOME", None)
                else:
                    os.environ["HOME"] = saved
        self.assertTrue(deps.ah_calls, "the fake ah was not used")
        self.assertEqual(self.snapshot(coordinator), before_coord)
        self.assertEqual(self.snapshot(ahc_root), before_ahc)
        after_state = {k: v for k, v in (self.snapshot(state) or {}).items() if "ahc" in k or "coordinator" in k}
        self.assertEqual(after_state, before_state)


from tests import test_ahc_contracts as TC  # noqa: E402

C = TC.C


class StateMachineTests(TC.Base):
    """WorkItem (spec M-1 v2g16, W1-W27) through the production transition function Contracts.wi_move. Slice 1 (a),
    shadow only: these rows write the ledger and send nothing. Rows whose guards need ELIG, observations, budgets
    or main's stamp are wired in later steps and are refused until then (test_unwired_rows_fail_closed)."""

    def setUp(self):
        super().setUp()
        self.item = self.admit()

    def admit(self, **kw):
        args = dict(repo="O/R", pr=5, head=TC.H1, base=TC.BASE, policy_revision=TC.POLICY, spec_core=TC.CORE1,
                    packet_sha256=TC.PKT, event_id=self.ev())
        args.update(kw)
        return self.c.admit_item(**args)

    def move(self, row, item=None, **kw):
        item = item or self.c._row("work_items", "id", self.item["id"])
        kw.setdefault("actor", C.Contracts.WI_TRANSITIONS[row][2])
        kw.setdefault("event_id", self.ev())
        return self.c.wi_move(item["id"], row, expected_version=item["version"], **kw)

    def at(self, state):
        """Put the fixture item in `state` directly, for guard tests of rows that leave it."""
        self.db.execute("UPDATE work_items SET state=? WHERE id=?", (state, self.item["id"]))

    def reserved(self, **changes):          # the Effect fixtures, bound to this item (operations.item)
        g = self.active_grant(**{k: v for k, v in changes.items() if k in C.Contracts.SCOPE})
        op = self.c.intend(self.params(**changes), item=self.item["id"], lease_ok=True, event_id=self.ev())
        g = self.reserve(g, op)
        return g, self.c._row("operations", "key", op["key"])

    def confirmed(self):
        g, op = self.dispatched()
        return g, self.c.confirm(op["key"], self.readback(), expected_version=op["version"], event_id=self.ev())

    def abandoned(self):
        g, op = self.absent_p("p1")
        return g, self.after(op, self.read(tip=TC.BASE))

    def wstate(self):
        return self.state("work_items", "id", self.item["id"])

    # ---- W1 and NEG-11

    def test_w01_admits_into_pr_gate_with_bound_review_rows(self):
        self.assertEqual((self.item["state"], self.item["repo"], self.item["head"]), ("pr-gate", "o/r", TC.H1))
        rows = self.db.execute("SELECT kind, head, snapshot_base, spec_core FROM reviews WHERE item=? ORDER BY kind",
                               (self.item["id"],)).fetchall()
        self.assertEqual(rows, [("adversarial", TC.H1, TC.BASE, ""), ("spec", TC.H1, "", TC.CORE1)])
        red = self.admit(pr=6, red_team=True)
        kinds = {r[0] for r in self.db.execute("SELECT kind FROM reviews WHERE item=?", (red["id"],))}
        self.assertEqual(kinds, {"adversarial", "spec", "red-team"})

    def test_neg11_a_resubmit_or_owner_action_never_moves_the_item(self):
        again = self.admit()
        self.assertEqual((again["id"], again["version"], again["state"]),
                         (self.item["id"], self.item["version"], "pr-gate"), "a resubmit attaches to the item")
        for row in ("W2", "W3", "W4", "W16", "W27"):
            with self.subTest(row=row), self.assertRaisesRegex(C.ContractError, "NEG-11"):
                self.move(row, actor="owner")
        self.assertEqual(self.c._row("work_items", "id", self.item["id"])["version"], self.item["version"])

    def test_w20_the_owner_cancels_its_own_item_from_pr_gate_only(self):
        with self.assertRaises(C.ContractError):
            self.move("W20", actor="ahc-core")
        self.assertEqual(self.move("W20")["state"], "cancelled")
        self.at("waiting-ask")
        with self.assertRaisesRegex(C.ContractError, "does not leave"):
            self.move("W20")

    # ---- ledger-fact rows

    def test_w03_findings_on_a_review_row_of_this_item(self):
        with self.assertRaisesRegex(C.ContractError, "findings"):
            self.move("W3")
        self.db.execute("UPDATE reviews SET state='findings' WHERE item=? AND kind='adversarial'", (self.item["id"],))
        self.assertEqual(self.move("W3")["state"], "waiting-ask")

    def test_w08_merged_only_on_a_confirmed_effect(self):
        self.at("merge-ready")
        with self.assertRaisesRegex(C.ContractError, "confirmed"):
            self.move("W8")
        self.confirmed()
        self.assertEqual(self.move("W8")["state"], "merged")

    def test_w09_abandoned_unmarked_back_to_pr_gate(self):
        self.at("merge-ready")
        self.abandoned()
        self.assertEqual(self.move("W9")["state"], "pr-gate")

    def test_w10_held_goes_to_waiting_ask_and_w26_settles_it(self):
        self.at("merge-ready")
        _g, op = self.held()
        self.assertEqual(self.move("W10")["state"], "waiting-ask")
        with self.assertRaisesRegex(C.ContractError, "confirmed"):
            self.move("W26")
        # E10 is exercised in OperationTests; here only the ledger fact W26 reads matters
        self.db.execute("UPDATE operations SET state='confirmed' WHERE key=?", (op["key"],))
        self.assertEqual(self.move("W26")["state"], "merged")

    def pr(self, **changes):
        o = {"id": "obs-%d" % self.n, "at": self.clock.t, "repo": "o/r", "pr": 5, "pr_state": "OPEN",
             "pr_head": TC.H1, "tip": TC.BASE}
        o.update(changes)
        return o

    def test_w24_marks_and_keeps_the_item_then_w25_ends_it(self):
        self.at("merge-ready")
        moved = self.pr(pr_head=TC.H2)
        with self.assertRaisesRegex(C.ContractError, "unsettled"):
            self.move("W24", mark="head-moved", obs=moved, successor_packet="e" * 64)
        _g, op = self.dispatched()
        with self.assertRaisesRegex(C.ContractError, "does not show"):
            self.move("W24", mark="head-moved", obs=self.pr(), successor_packet="e" * 64)
        with self.assertRaisesRegex(C.ContractError, "own packet"):
            self.move("W24", mark="head-moved", obs=moved)
        item = self.move("W24", mark="head-moved", obs=moved, successor_packet="e" * 64)
        self.assertEqual((item["state"], item["marks"]), ("merge-ready", "head-moved"))
        succ = self.c._row("work_items", "id", item["successor"])
        self.assertEqual((succ["head"], succ["state"]), (TC.H2, "pr-gate"), "the successor exists at once")
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM operations WHERE item=?", (succ["id"],)).fetchone()[0],
                         0, "the successor inherits no Effect")
        self.assertEqual(self.state("reviews", "id", self.db.execute(
            "SELECT id FROM reviews WHERE item=? AND kind='adversarial'", (self.item["id"],)).fetchone()[0]),
            "required", "W24 changes no Review row of this item")
        with self.assertRaisesRegex(C.ContractError, "already marked"):
            self.move("W24", mark="closed-in-flight", obs=self.pr(pr_state="CLOSED"))
        with self.assertRaisesRegex(C.ContractError, "abandoned"):
            self.move("W25", to="superseded")
        self.db.execute("UPDATE operations SET state='abandoned' WHERE key=?", (op["key"],))
        with self.assertRaisesRegex(C.ContractError, "W25 sends a head-moved item to superseded"):
            self.move("W25", to="closed-unmerged")
        with self.assertRaisesRegex(C.ContractError, "takes W25"):
            self.move("W9")
        self.assertEqual(self.move("W25", to="superseded")["state"], "superseded")

    # ---- observation rows (T2)

    def test_w04_head_moved_supersedes_with_a_successor_and_abandons_an_unsent_intent(self):
        self.at("merge-ready")
        op = self.c.intend(self.params(), item=self.item["id"], lease_ok=True, event_id=self.ev())
        stale = self.pr(pr_head=TC.H2, at=self.clock.t - C.Contracts.OBSERVATION_SECONDS)
        for bad, msg in ((None, "observation"), (stale, "stale"), (self.pr(pr_head=TC.H2, pr=6), "another"),
                         (self.pr(), "moved away"), (self.pr(pr_head=TC.H2, pr_state="CLOSED"), "OPEN"),
                         (self.pr(pr_head="x"), "full sha")):
            with self.subTest(msg=msg), self.assertRaisesRegex(C.ContractError, msg):
                self.move("W4", obs=bad, successor_packet="e" * 64)
        item = self.move("W4", obs=self.pr(pr_head=TC.H2), successor_packet="e" * 64)
        self.assertEqual(item["state"], "superseded")
        succ = self.c._row("work_items", "id", item["successor"])
        self.assertEqual((succ["head"], succ["state"], succ["lineage"]), (TC.H2, "pr-gate", self.item["lineage"]))
        old = dict(self.db.execute("SELECT kind, state FROM reviews WHERE item=?", (self.item["id"],)).fetchall())
        self.assertEqual(old, {"adversarial": "superseded", "spec": "superseded"})
        self.assertEqual(self.state("operations", "key", op["key"]), "abandoned", "E9")

    def test_w13_closed_without_integration_escalates(self):
        with self.assertRaisesRegex(C.ContractError, "CLOSED"):
            self.move("W13", obs=self.pr())
        ev = self.ev()
        self.assertEqual(self.move("W13", obs=self.pr(pr_state="CLOSED"), event_id=ev)["state"], "closed-unmerged")
        self.assertEqual(self.db.execute("SELECT kind FROM wi_notices WHERE event_id=?", (ev,)).fetchall(),
                         [("ticket",)], "a failure terminal escalates (R2)")

    def test_w14_merged_out_of_band_raises_an_incident(self):
        ev = self.ev()
        self.assertEqual(self.move("W14", obs=self.pr(pr_state="MERGED"), event_id=ev)["state"], "merged")
        self.assertEqual(self.db.execute("SELECT kind FROM wi_notices WHERE event_id=?", (ev,)).fetchall(),
                         [("incident",)])

    def test_w14_is_refused_when_this_items_effect_made_the_merge(self):
        self.at("merge-ready")
        self.confirmed()
        with self.assertRaisesRegex(C.ContractError, "W8"):
            self.move("W14", obs=self.pr(pr_state="MERGED"))

    def test_w18_base_moved_rebinds_b_and_classifies_the_move_from_the_ledger(self):
        with self.assertRaisesRegex(C.ContractError, "moved from B"):
            self.move("W18", obs=self.pr(fast_forward=True))
        for ff, kind in ((True, "digest"), (False, "incident")):
            with self.subTest(ff=ff):
                self.db.execute("UPDATE work_items SET base=?, state='pr-gate' WHERE id=?", (TC.BASE, self.item["id"]))
                ev = self.ev()
                item = self.move("W18", obs=self.pr(tip=TC.B2, fast_forward=ff, explained=True), event_id=ev)
                self.assertEqual((item["state"], item["base"]), ("pr-gate", TC.B2))
                self.assertEqual(self.db.execute("SELECT kind FROM wi_notices WHERE event_id=?", (ev,)).fetchall(),
                                 [(kind,)], "a caller's 'explained' flag is ignored")

    # ---- T6, T7 and the Q-A5.2 invariant

    def test_t6_a_replay_is_a_no_op_even_with_a_stale_version(self):
        ev = self.ev()
        first = self.move("W20", event_id=ev)
        again = self.c.wi_move(self.item["id"], "W20", expected_version=self.item["version"], event_id=ev,
                               actor="owner")
        self.assertEqual((again["state"], again["version"]), (first["state"], first["version"]))
        n = self.db.execute("SELECT COUNT(*) FROM transitions WHERE event_id=?", (ev,)).fetchone()[0]
        self.assertEqual(n, 1, "one audit row (T3)")
        other = self.admit(pr=7)
        with self.assertRaisesRegex(C.ContractError, "another subject"):
            self.c.wi_move(other["id"], "W20", expected_version=other["version"], event_id=ev, actor="owner")

    def test_t7_an_unsettled_effect_allows_only_its_own_rows(self):
        for setup in (self.dispatched, self.held, self.fenced, lambda: self.absent_p("p1")):
            with self.subTest(setup=getattr(setup, "__name__", "absent-proven")):
                self.db.execute("DELETE FROM operations")
                self.db.execute("DELETE FROM grants")
                self.at("merge-ready")
                setup()
                for row in ("W4", "W5", "W13", "W14", "W17", "W18", "W27"):
                    with self.assertRaisesRegex(C.ContractError, "T7"):
                        self.move(row)
                self.at("pr-gate")
                for row in ("W2", "W3", "W15", "W19", "W20", "W21", "W22", "W23"):   # W15 and W20 too
                    with self.assertRaisesRegex(C.ContractError, "T7"):
                        self.move(row)
                self.assertEqual(self.move("W24", mark="", obs=self.pr(tip=TC.B2))["marks"], "")

    def test_note8_absent_proven_waits_then_moves_once_abandoned_or_held(self):
        self.at("merge-ready")
        _g, op = self.absent_p("p1")
        with self.assertRaisesRegex(C.ContractError, "T7"):
            self.move("W5")
        self.after(op, self.read(tip=TC.BASE))                    # E8: abandoned
        self.assertEqual(self.move("W9")["state"], "pr-gate")

    def test_qa52_no_row_enters_waiting_dep_or_exhausted_with_an_unsettled_effect(self):
        for row, (src, dst, _a) in C.Contracts.WI_TRANSITIONS.items():
            if row in C.Contracts.T7_ALLOWED:
                self.assertFalse({"waiting-dep", "exhausted"} & set(dst), "%s would strand a send" % row)
        self.at("waiting-ask")
        _g, op = self.dispatched()
        with self.assertRaisesRegex(C.ContractError, "T7"):
            self.move("W16", to="pr-gate", actor="main")

    def test_unwired_rows_fail_closed(self):
        for row in ("W2", "W6", "W7", "W11", "W12", "W15", "W21", "W22", "W23"):
            src = C.Contracts.WI_TRANSITIONS[row][0][0]
            self.at(src)
            to = C.Contracts.WI_TRANSITIONS[row][1][0]
            with self.subTest(row=row), self.assertRaisesRegex(C.ContractError, "not wired"):
                self.move(row, to=to)
        self.assertEqual(self.c._row("work_items", "id", self.item["id"])["version"], self.item["version"])

    # ---- precedence (T7)

    def test_t7_precedence(self):
        S = C.Contracts.select_row
        self.assertEqual(S(["W2", "W17"], False), "W17", "a protected path beats W2")
        self.assertEqual(S(["W18", "W4"], False), "W4")
        self.assertEqual(S(["W17", "G8"], False), "W17")
        self.assertEqual(S(["W2", "G9"], False), "G9", "a kill-switch revoke beats an unranked WorkItem row")
        self.assertEqual(S(["W23", "W22", "W21"], False), "W21", "numeric order, not table order")
        self.assertEqual(S(["W4", "W8"], True), "W8", "W4 waits under T7")
        self.assertIsNone(S(["W4", "W5"], True))
        with self.assertRaises(C.ContractError):
            S(["G1"], False)

    def test_every_workitem_test_id_resolves_to_a_test(self):
        import re
        text = (HOOKS.parents[1] / "docs" / "spec" / "ahc-m1-state-machine.md").read_text(encoding="utf-8")
        part = text.split("### Entity: WorkItem", 1)[1].split("### Entity:", 1)[0]
        ids = sorted(set(re.findall(r"SMTests\.(test_\w+)", part)))
        self.assertEqual(len(ids), 38, "11 states and 27 rows")
        missing = [i for i in ids if not any(n == i or n.startswith(i + "_") for n in dir(self))]
        self.assertLessEqual(set(missing), set(self.PENDING_IDS), "a test id the spec names has no test")

    # Spec test ids not yet covered by a test of that name; each step of slice 1 (a) shrinks this list.
    PENDING_IDS = (
        "test_wi_pr_gate", "test_wi_merge_ready", "test_wi_waiting_dep", "test_wi_waiting_ask", "test_wi_exhausted",
        "test_wi_merged", "test_wi_headed_verified", "test_wi_handed", "test_wi_superseded", "test_wi_closed_unmerged",
        "test_wi_cancelled", "test_w02", "test_w05", "test_w06", "test_w07", "test_w11", "test_w12",
        "test_w15", "test_w16", "test_w17", "test_w19", "test_w21", "test_w22",
        "test_w23", "test_w25", "test_w26", "test_w27")


if __name__ == "__main__":
    unittest.main()
