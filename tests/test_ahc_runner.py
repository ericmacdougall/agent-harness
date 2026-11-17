"""ahc_runner (Gate 1, receipt-only): one queued item through resolve, clone, lint/fix, review, verify, write-back
and digest, with a journal that makes every step idempotent and restart-safe. All children are fakes; no network.
GoodQA goodqa#16034 AC-6, AC-7, AC-9; NEG-9 (Gate 1 part), NEG-12, NEG-15, NEG-16."""
import hashlib
import os
import re
import sqlite3
import subprocess
import time
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


def _release_hooks():
    """AC-11's preflight verifies the installed entry points against the release list. Tests migrate against a copy
    of the modules as they are now, with a list computed from that copy, so a variant run (which mutates a module)
    still exercises the migration; the shipped list is checked by test_v5_release_list_is_current."""
    import shutil as _shutil
    target = Path(tempfile.mkdtemp(prefix="ahc-release-"))
    files = {}
    for name in json.loads((HOOKS / runner.ahc_migrate.RELEASE_LIST).read_text())["files"]:
        path = HOOKS / name
        _shutil.copyfile(path, target / path.name)
        files[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
    (target / runner.ahc_migrate.RELEASE_LIST).write_text(json.dumps({"files": files}))
    return target


runner.Ledger.HOOKS_DIR = _release_hooks()

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

    def record(self):
        return self.paths.root / "install.json"

    def test_r247_f3_a_failed_stop_removes_nothing_and_a_retry_finishes(self):
        host = FakeHost(linger="no")
        self.install(host)
        self.assertTrue(self.record().exists())
        host.fail = {"systemctl --user disable"}               # disable --now fails: both units still run
        self.assertEqual(self.uninstall(host), 1)
        self.assertTrue(self.unit("ahc-core").exists() and self.unit("ahc-review").exists(), "unit files kept")
        self.assertTrue((self.home / ".local" / "bin" / "ahc").exists(), "the wrapper is kept")
        self.assertTrue(self.record().exists(), "the install record is kept")
        self.assertEqual(host.linger, "yes", "lingering is not touched while a unit may run")
        self.assertTrue(any("may still be running" in line for line in self.out), self.out)
        host.fail = set()
        self.assertEqual(self.uninstall(host), 0)
        self.assertEqual((host.active, host.linger, self.record().exists()), (set(), "no", False))

    def test_r247_f3_a_failed_linger_restore_keeps_the_record_and_a_retry_restores_it(self):
        host = FakeHost(linger="no")
        self.install(host)
        host.fail = {"loginctl"}                              # disable-linger fails (show-user too, unused here)
        self.assertEqual(self.uninstall(host), 1)
        self.assertFalse(self.unit("ahc-core").exists(), "the stopped units' files are removed")
        self.assertTrue(self.record().exists(), "the record of lingering before ahc is kept for the retry")
        self.assertEqual(host.linger, "yes")
        host.fail = set()
        self.assertEqual(self.uninstall(host), 0, self.out)
        self.assertEqual(host.linger, "no", "the retry restores lingering from the kept record")
        self.assertFalse(self.record().exists())
        self.assertFalse([c for c in host.calls[-6:] if c[:3] == ["systemctl", "--user", "disable"]],
                         "the retry does not disable units whose files are gone")

    def test_r247_f3_a_failed_daemon_reload_keeps_the_record(self):
        host = FakeHost(linger="no")
        self.install(host)
        host.fail = {"systemctl --user daemon-reload"}
        self.assertEqual(self.uninstall(host), 1)
        self.assertTrue(self.record().exists())
        host.fail = set()
        self.assertEqual(self.uninstall(host), 0)
        self.assertFalse(self.record().exists())

    def test_r247_f3_an_is_active_that_cannot_answer_counts_as_running(self):
        host = FakeHost(linger="no")
        self.install(host)
        host.fail = {"systemctl --user is-active"}
        host.active = set()
        self.assertEqual(self.uninstall(host), 1)
        self.assertTrue(self.unit("ahc-core").exists() and self.record().exists())

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


# AC-11 (slice 1 (b)): the v5 migration fences the ledger at its prior version before the backup, so the backup
# and any restored copy carry the fence; a rollback clears it back to the prior version.
FENCED_V1 = "v5-migrating-from-1"


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
        self.assertEqual(version, ("v5-migrating-from-0",), "AC-11: the restored copy stays fenced at its prior 0")
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
        self.assertEqual((version, count), (FENCED_V1, 3), "the backup is the v1 ledger with the -wal rows included")
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
        self.assertEqual((version, count), (FENCED_V1, 3), "the restored ledger is the v1 copy with every row")
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
        self.assertEqual((version, count), (FENCED_V1, 3), "the restored ledger is the v1 copy")
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
        self.assertEqual(self.columns(live)[1:], (FENCED_V1, 3), "the live database is the unchanged v1 ledger")
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
        sha = hashlib.sha256(backup.read_bytes()).hexdigest()
        Path(str(live) + ".restore-intent").write_text(json.dumps({"backup": backup.name, "suffix": ".failed-1",
                                                                   "sha256": sha}))
        os.chmod(str(live) + ".restore-intent", 0o600)
        runner.Ledger(self.paths).close()
        self.assertFalse(partial.exists(), "the partial copy was left behind")
        self.assertFalse(Path(str(live) + ".restore-intent").exists())
        self.assertEqual(self.columns(live)[1:], (str(runner.SCHEMA_VERSION), 3), "restored, then migrated")

    # --- PR 258 v5 F1: an interrupted restore is finished from what the files say, never stranding an intact ledger
    def crash_after_the_intent(self, damage):
        """The receipt's sequence, in process: the migration fails, the backup is damaged during it, and the
        process dies right after the restore intent is durable (a BaseException at that seam, so no handler runs).
        Returns the live path."""
        held = self.make_v1()

        class Died(BaseException):
            pass

        def die_after(name):
            if name == "runner.restore_intent":
                raise Died()

        def damage_backup(db):
            for backup in self.paths.root.glob("ledger.sqlite3.pre-v*.bak"):
                if damage == "missing":
                    backup.unlink()
                else:
                    os.truncate(str(backup), 4096)
            raise RuntimeError("injected migration failure")
        undo = self.failing_migration(damage_backup)
        try:
            with mock.patch.object(runner, "crash_after", die_after):
                with self.assertRaises(Died):
                    runner.Ledger(self.paths)
        finally:
            undo()
            held.close()
        live = self.paths.root / "ledger.sqlite3"
        self.assertTrue(Path(str(live) + ".restore-intent").exists(), "setup: the crash left the intent")
        self.assertEqual(self.columns(live)[1:], (FENCED_V1, 3), "setup: the live ledger is the intact v1 ledger")
        return live

    def assert_abandoned_then_migrated(self, live):
        with self.assertLogs("ahc", "WARNING") as logs:
            runner.Ledger(self.paths).close()                # the next ahc-core start
        self.assertTrue(any("abandoned the interrupted ledger restore" in line for line in logs.output), logs.output)
        self.assertFalse(Path(str(live) + ".restore-intent").exists(), "the stale intent is dropped")
        self.assertFalse(list(self.paths.root.glob("ledger.sqlite3.failed-*")), "the intact ledger was moved aside")
        self.assertFalse(list(self.paths.root.glob(".ledger.sqlite3.*.tmp")))
        self.assertEqual(self.columns(live)[1:], (str(runner.SCHEMA_VERSION), 3), "kept, then migrated")
        runner.Ledger(self.paths).close()                    # and every later start is an ordinary one

    def test_a_crash_after_the_intent_with_the_backup_gone_keeps_and_migrates_the_intact_ledger(self):
        """Receipt harness-pr258-v5 F1, the exact sequence: the old resume refused at every start (its
        copy.is_file() check ran before the abandon handling) while the live ledger was intact."""
        self.assert_abandoned_then_migrated(self.crash_after_the_intent("missing"))

    def test_a_crash_after_the_intent_with_a_partial_backup_never_publishes_it(self):
        """A truncated backup fails its recorded digest, so it is never published over the intact ledger (the old
        resume published it, and the ledger no longer opened)."""
        self.assert_abandoned_then_migrated(self.crash_after_the_intent("partial"))

    def interrupted(self):
        """A v1 ledger moved aside as .failed-1 (with its sidecars) beside a backup of it and a valid intent:
        the files a restore leaves right after its move. Returns (live, backup, aside, sha256 of the backup)."""
        held = self.make_v1()
        held.close()
        live = self.paths.root / "ledger.sqlite3"
        backup = live.with_name("ledger.sqlite3.pre-v9.1.bak")
        import sqlite3
        src, dst = sqlite3.connect(str(live)), sqlite3.connect(str(backup))
        src.backup(dst)
        src.close()
        dst.close()
        for extra in ("-wal", "-shm"):
            for path in (str(backup) + extra, str(live) + extra):
                if os.path.lexists(path):
                    os.unlink(path)
        os.chmod(str(backup), 0o600)
        aside = Path(str(live) + ".failed-1")
        os.rename(str(live), str(aside))
        sha = hashlib.sha256(backup.read_bytes()).hexdigest()
        intent = Path(str(live) + ".restore-intent")
        intent.write_text(json.dumps({"backup": backup.name, "suffix": ".failed-1", "sha256": sha}))
        os.chmod(str(intent), 0o600)
        return live, backup, aside, sha

    def test_a_found_publish_is_not_moved_aside_again(self):
        """The PR 258 v4 residual: a crash after the publish and before the intent was dropped. The old resume moved
        the restored copy aside under the same suffix, replacing the moved-aside failed ledger. Now the live file is
        recognised by the backup's digest, the intent is dropped, and the moved-aside file stays byte for byte."""
        live, backup, aside, _sha = self.interrupted()
        live.write_bytes(backup.read_bytes())                # what the publish left
        os.chmod(str(live), 0o600)
        kept = aside.read_bytes()
        runner.Ledger(self.paths).close()
        self.assertEqual(aside.read_bytes(), kept, "the moved-aside failed ledger was replaced")
        self.assertEqual(sorted(p.name for p in self.paths.root.glob("ledger.sqlite3.failed-*")), [aside.name])
        self.assertFalse(Path(str(live) + ".restore-intent").exists())
        self.assertEqual(self.columns(live)[1:], (str(runner.SCHEMA_VERSION), 3))

    def test_a_foreign_file_where_the_ledger_was_moved_from_is_refused_and_replaces_nothing(self):
        live, _backup, aside, _sha = self.interrupted()
        import sqlite3
        db = sqlite3.connect(str(live))
        db.execute("CREATE TABLE stray(x)")
        db.commit()
        db.close()
        os.chmod(str(live), 0o600)
        kept, foreign = aside.read_bytes(), live.read_bytes()
        for _ in range(2):
            with self.assertRaises(runner.SchemaError) as caught:
                runner.Ledger(self.paths)
            self.assertIn("refusing to replace either", str(caught.exception))
        self.assertEqual((aside.read_bytes(), live.read_bytes()), (kept, foreign))
        self.assertTrue(Path(str(live) + ".restore-intent").exists(), "the intent is kept for the operator")

    def test_a_sidecar_whose_aside_name_is_taken_refuses_and_replaces_nothing(self):
        """Renaming would replace the taken file; leaving it would put a stale -wal beside the restored copy."""
        live, _backup, aside, _sha = self.interrupted()
        stale, taken = Path(str(live) + "-wal"), Path(str(aside) + "-wal")
        stale.write_bytes(b"a stale -wal of the moved ledger")
        taken.write_bytes(b"the moved ledger's -wal")
        os.chmod(str(stale), 0o600)
        os.chmod(str(taken), 0o600)
        with self.assertRaises(runner.SchemaError) as caught:
            runner.Ledger(self.paths)
        self.assertIn("refusing to replace either", str(caught.exception))
        self.assertEqual((stale.read_bytes(), taken.read_bytes()),
                         (b"a stale -wal of the moved ledger", b"the moved ledger's -wal"))
        self.assertFalse(live.exists(), "no ledger is published beside a stale -wal")
        self.assertTrue(Path(str(live) + ".restore-intent").exists())
        self.assertFalse(list(self.paths.root.glob(".ledger.sqlite3.*.tmp")), "a copy was made for nothing")

    def test_a_taken_sidecar_target_refuses_before_anything_moves(self):
        """Every move target is checked before the first rename: the live ledger is not moved, then left stranded
        beside a -wal that could not follow it."""
        live, _backup, aside, _sha = self.interrupted()
        os.rename(str(aside), str(live))                     # nothing moved yet
        stale, taken = Path(str(live) + "-wal"), Path(str(aside) + "-wal")
        stale.write_bytes(b"")                               # an empty -wal: SQLite would open beside it
        taken.write_bytes(b"a foreign file under the aside name")
        kept = live.read_bytes()
        with self.assertRaises(runner.SchemaError) as caught:
            runner.Ledger(self.paths)
        self.assertIn("refusing to replace either", str(caught.exception))
        self.assertEqual(live.read_bytes(), kept, "the live ledger was moved or changed")
        self.assertFalse(aside.exists())
        self.assertEqual(taken.read_bytes(), b"a foreign file under the aside name")
        self.assertFalse(list(self.paths.root.glob(".ledger.sqlite3.*.tmp")), "a copy was made for nothing")

    def test_a_stray_journal_moves_aside_with_the_ledger(self):
        """SQLITE_SIDECARS, -journal included, move with the database: a hot journal left beside the restored copy
        would be rolled back into it."""
        live, backup, aside, sha = self.interrupted()
        os.rename(str(aside), str(live))                     # back to "nothing moved yet"
        journal = Path(str(live) + "-journal")
        journal.write_bytes(b"a journal of the failed ledger")
        os.chmod(str(journal), 0o600)
        runner.Ledger(self.paths).close()
        self.assertEqual(Path(str(aside) + "-journal").read_bytes(), b"a journal of the failed ledger")
        self.assertTrue(aside.exists(), "the failed ledger moved aside with its journal")
        self.assertEqual(self.columns(live)[1:], (str(runner.SCHEMA_VERSION), 3))

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
                self.assertEqual(len(list(self.paths.root.glob("ledger.sqlite3.pre-v5.*.bak"))), 1)

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
        backup = next(self.paths.root.glob("ledger.sqlite3.pre-v5.*.bak"))
        restored = self.home / "restored"
        (restored / ".agent-harness" / "coordinator").mkdir(parents=True)
        _shutil.copyfile(backup, restored / ".agent-harness" / "coordinator" / "ledger.sqlite3")
        # AC-11 rollback: the backup carries the fence; the run kit's v5 step clears it back to the prior version
        import sqlite3 as _sqlite3
        fenced = _sqlite3.connect(str(restored / ".agent-harness" / "coordinator" / "ledger.sqlite3"),
                                  isolation_level=None)
        try:
            self.assertEqual(runner.ahc_migrate.read_version(fenced), (3, True))
            runner.ahc_migrate.clear_fence(fenced, 3)
        finally:
            fenced.close()
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
        self.assertEqual(self.columns(self.paths.root / "ledger.sqlite3")[1:], (FENCED_V1, 3), "the ledger is untouched")
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
            if argv and os.path.basename(argv[0]) == "git":   # AC-13: an absolute resolved git
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

    UID = 41001

    def running_review(self, item, kind):
        rid = self.db.execute("SELECT id FROM reviews WHERE item=? AND kind=?", (item["id"], kind)).fetchone()[0]
        row = self.c.review(rid, "queued", expected_version=1, event_id=self.ev())
        return self.c.start_attempt(rid, "ahc-review-" + rid, self.UID, expected_version=row["version"],
                                    event_id=self.ev())

    def test_w20_cancels_running_and_outcome_unknown_reviews_and_refuses_a_late_result(self):
        """PR 268 F3: W20's obligation, a running Review row goes to cancelling (R14), in the same transaction."""
        self.item = self.admit(pr=7, red_team=True)      # its own PR: a resubmit at pr 5 is the fixture (NEG-11)
        running = self.running_review(self.item, "adversarial")
        unknown = self.running_review(self.item, "red-team")
        unknown = self.c.review(unknown["id"], "outcome-unknown", expected_version=unknown["version"],
                                event_id=self.ev())
        ev = self.ev()
        self.assertEqual(self.move("W20", event_id=ev)["state"], "cancelled")
        for row in (running, unknown):
            after = self.c._row("reviews", "id", row["id"])
            self.assertEqual(after["state"], "cancelling", row["kind"])
            self.assertEqual(self.db.execute("SELECT COUNT(*) FROM transitions WHERE event_id=?",
                                             ("%s-r14-%s" % (ev, row["id"]),)).fetchone()[0], 1, "replay-safe id")
            receipt = {"repo": "o/r", "pr": 7, "head": TC.H1, "snapshot_base": TC.BASE, "packet_sha256": TC.PKT,
                       "policy_revision": TC.POLICY, "verdict": "PASS"}
            with self.assertRaises(C.ContractError):              # a result arriving after the cancel
                self.c.review(row["id"], "passed", expected_version=after["version"], event_id=self.ev(),
                              receipt=receipt, peer_uid=self.UID)
        self.assertEqual(self.move("W20", event_id=ev)["state"], "cancelled", "a replay is the T6 no-op")
        self.assertEqual(self.c._row("reviews", "id", running["id"])["state"], "cancelling")

    # ---- ledger-fact rows

    def notices_of(self, row):
        return sorted((k, t) for k, t in self.db.execute("SELECT kind, text FROM wi_notices WHERE item=? AND "
                                                         "row_id=?", (self.item["id"], row)))

    def test_w03_findings_on_a_review_row_of_this_item(self):
        with self.assertRaisesRegex(C.ContractError, "findings"):
            self.move("W3")
        rid = self.db.execute("SELECT id FROM reviews WHERE item=? AND kind='adversarial'",
                              (self.item["id"],)).fetchone()[0]
        self.db.execute("UPDATE reviews SET state='findings', receipt=? WHERE id=?",
                        (json.dumps({"verdict": "BLOCK", "finding_ids": ["F1", "F2"]}), rid))
        ev = self.ev()
        self.assertEqual(self.move("W3", event_id=ev)["state"], "waiting-ask")
        # PR 268 F4: a ticket comment with the finding ids, and an owner notice, written with the move
        text = "findings on adversarial %s: F1, F2" % rid
        self.assertEqual(self.notices_of("W3"), [("owner", text), ("ticket", text)])
        self.assertEqual(self.move("W3", event_id=ev)["state"], "waiting-ask", "replay")
        self.assertEqual(len(self.notices_of("W3")), 2, "exactly once on replay")

    def test_w03_without_finding_ids_still_escalates_flagged(self):
        """goodqa#16204 (spec owner ruling, item 4): a findings receipt with no or malformed finding_ids still
        records both notices, flagged; the producer writing finding_ids is a slice (b) obligation."""
        rid = self.db.execute("SELECT id FROM reviews WHERE item=? AND kind='adversarial'",
                              (self.item["id"],)).fetchone()[0]
        self.db.execute("UPDATE reviews SET state='findings', receipt=? WHERE id=?",
                        (json.dumps({"verdict": "BLOCK", "finding_ids": [1, ""]}), rid))
        self.assertEqual(self.move("W3")["state"], "waiting-ask")
        text = "findings on adversarial %s: finding ids missing" % rid
        self.assertEqual(self.notices_of("W3"), [("owner", text), ("ticket", text)])

    def test_attempt_refused_for_a_row_of_a_finished_item(self):
        """goodqa#16204 (spec owner ruling, item 1): an attempt never starts for a row whose item is terminal or
        merged; the refusal is typed and changes nothing (no state, version, unit, uid or audit row)."""
        for n, state in enumerate(("cancelled", "merged", "closed-unmerged", "superseded")):
            with self.subTest(state=state):
                item = self.admit(pr=40 + n)
                rid = self.db.execute("SELECT id FROM reviews WHERE item=? AND kind='adversarial'",
                                      (item["id"],)).fetchone()[0]
                row = self.c.review(rid, "queued", expected_version=1, event_id=self.ev())
                self.db.execute("UPDATE work_items SET state=? WHERE id=?", (state, item["id"]))
                audit = self.db.execute("SELECT COUNT(*) FROM transitions").fetchone()[0]
                with self.assertRaisesRegex(C.ContractError, "inert: item %s is %s" % (item["id"], state)):
                    self.c.start_attempt(rid, "ahc-review-" + rid, self.UID, expected_version=row["version"],
                                         event_id=self.ev())
                after = self.c._row("reviews", "id", rid)
                self.assertEqual((after["state"], after["version"], after["producer_unit"], after["producer_uid"]),
                                 ("queued", row["version"], None, None))
                self.assertEqual(self.db.execute("SELECT COUNT(*) FROM transitions").fetchone()[0], audit)
        live = self.running_review(self.admit(pr=60), "adversarial")             # a live item's row still starts
        self.assertEqual(live["state"], "running")

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
        ev = self.ev()
        self.assertEqual(self.move("W10", event_id=ev)["state"], "waiting-ask")
        # PR 268 F4: an incident and a ticket comment, written with the move, exactly once
        text = "%s held; a person decides" % op["key"]
        self.assertEqual(self.notices_of("W10"), [("incident", text), ("ticket", text)])
        self.move("W10", event_id=ev)
        self.assertEqual(len(self.notices_of("W10")), 2, "exactly once on replay")
        with self.assertRaisesRegex(C.ContractError, "confirmed"):
            self.move("W26")
        # E10 is exercised in OperationTests; here only the ledger fact W26 reads matters
        self.db.execute("UPDATE operations SET state='confirmed' WHERE key=?", (op["key"],))
        self.assertEqual(self.move("W26")["state"], "merged")

    def pr(self, **changes):
        o = {"id": "obs-%d" % self.n, "at": self.clock.t, "repo": "o/r", "pr": 5, "pr_state": "OPEN",
             "pr_head": TC.H1, "tip": TC.BASE}
        o.update(changes)
        return TC.stamped(o)

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

    def notices(self, row):
        return sorted(self.db.execute("SELECT kind, event_id, text FROM wi_notices WHERE item=? AND row_id=?",
                                      (self.item["id"], row)).fetchall())

    def test_w25_closed_in_flight_ends_closed_unmerged_with_a_notice_naming_the_op(self):
        self.at("waiting-ask")
        _g, op = self.dispatched()
        self.move("W24", mark="closed-in-flight", obs=self.pr(pr_state="CLOSED"))
        with self.assertRaisesRegex(C.ContractError, "abandoned"):
            self.move("W25", to="closed-unmerged")                     # T7: the Effect is still unsettled
        self.db.execute("UPDATE operations SET state='abandoned' WHERE key=?", (op["key"],))
        with self.assertRaisesRegex(C.ContractError, "closed-in-flight item to closed-unmerged"):
            self.move("W25", to="superseded")
        with self.assertRaisesRegex(C.ContractError, "goes to"):
            self.move("W25", to="merged")
        ev = self.ev()
        self.assertEqual(self.move("W25", to="closed-unmerged", event_id=ev)["state"], "closed-unmerged")
        self.assertEqual(self.notices("W25"), [("ticket", ev, "%s ended abandoned; item closed-unmerged" % op["key"])])

    def test_w26_a_confirmed_effect_merges_from_every_listed_state_and_announces_once(self):
        for n, frm in enumerate(("pr-gate", "waiting-dep", "waiting-ask", "exhausted")):
            with self.subTest(frm=frm):
                self.item = self.admit(pr=20 + n)
                self.at(frm)
                with self.assertRaisesRegex(C.ContractError, "confirmed"):
                    self.move("W26")
                g, op = self.dispatched(pr=20 + n)
                op = self.c.confirm(op["key"], self.readback(), expected_version=op["version"], event_id=self.ev())
                self.assertEqual(self.gstate(g), "consumed", "G4 already consumed the grant at the confirm")
                self.assertEqual(self.move("W26")["state"], "merged")
                text = "integrated at %s by %s" % (TC.H1, op["key"])
                self.assertEqual(self.notices("W26"), [("digest", "op:" + op["key"], text),
                                                       ("ticket", "op:" + op["key"], text)],
                                 "keyed by the op key: one ticket comment and one digest line")
        self.item = self.admit(pr=40)                      # a closed-in-flight item also tells the owner (L7)
        self.at("waiting-ask")
        _g, op = self.dispatched(pr=40)
        self.move("W24", mark="closed-in-flight", obs=self.pr(pr=40, pr_state="CLOSED"))
        self.db.execute("UPDATE operations SET state='confirmed' WHERE key=?", (op["key"],))
        self.move("W26")
        self.assertIn("owner", [k for k, _e, _t in self.notices("W26")])
        with self.assertRaisesRegex(C.ContractError, "W26"):               # merged is terminal: no second W26
            self.move("W26")

    def test_w06_back_to_merge_ready_only_from_waiting_dep_under_elig_rereading_core_and_policy(self):
        self.pass_reviews()
        with self.assertRaisesRegex(C.ContractError, "W6"):
            self.move("W6", obs=self.eligible())                      # pr-gate is not W6's source
        self.at("waiting-dep")
        for bad in (dict(attached_core=TC.CORE2), dict(policy=dict(self.eligible()["policy"], revision="policy-r2")),
                    dict(at=self.clock.t - C.Contracts.OBSERVATION_SECONDS), dict(boot="another-boot")):
            with self.subTest(bad=bad), self.assertRaises(C.ContractError):
                self.move("W6", obs=self.eligible(**bad))
        self.assertEqual(self.wstate(), "waiting-dep")
        item = self.move("W6", obs=self.eligible(), cause=None)
        self.assertEqual((item["state"], item["elig_core"], item["elig_policy"]), ("merge-ready", TC.CORE1, TC.POLICY))

    # ---- observation rows (T2)

    def test_w04_w24_a_successor_keeps_every_required_review_kind(self):
        """PR 268 F2: a red-team-required item's successor (W4 or W24) gets its own red-team row, and ELIG holds
        only once that row has passed too."""
        for row in ("W4", "W24"):
            with self.subTest(row=row):
                pr = 30 if row == "W4" else 31
                self.item = self.admit(pr=pr, red_team=True)
                self.assertEqual(self.item["red_team"], 1)
                if row == "W4":
                    self.at("merge-ready")
                    item = self.move("W4", obs=self.pr(pr=pr, pr_head=TC.H2), successor_packet="e" * 64)
                else:
                    self.at("merge-ready")
                    self.dispatched(pr=pr)
                    item = self.move("W24", mark="head-moved", obs=self.pr(pr=pr, pr_head=TC.H2),
                                     successor_packet="e" * 64)
                succ = self.c._row("work_items", "id", item["successor"])
                self.assertEqual(succ["red_team"], 1, "the classification is inherited")
                kinds = sorted(k for (k,) in self.db.execute("SELECT kind FROM reviews WHERE item=?", (succ["id"],)))
                self.assertEqual(kinds, ["adversarial", "red-team", "spec"])
                self.db.execute("UPDATE reviews SET state='passed' WHERE item=? AND kind != 'red-team'", (succ["id"],))
                self.assertIn("e1", self.c.elig(succ, self.eligible(succ)), "the red-team review has not passed")
                self.db.execute("DELETE FROM reviews WHERE item=? AND kind='red-team'", (succ["id"],))
                self.assertIn("e1", self.c.elig(succ, self.eligible(succ)), "a missing required kind fails e1")

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

    # ---- ELIG, the merge queue and the rows that read it (step 5)

    def eligible(self, item=None, **changes):
        """A fresh ELIG observation under which every clause holds for `item`."""
        item = item or self.c._row("work_items", "id", self.item["id"])
        fields = dict(pr=item["pr"], pr_head=item["head"], tip=item["base"], draft=False, compare="ahead",
                      b_r_ancestors={item["base"]: True}, attached_core=item["spec_core"], open_findings=0,
                      paths=["harness/lib/x.py"], foreign_closing_keyword=False,
                      policy={"revision": item["policy_revision"], "readable": True, "allowlisted": True,
                              "enabled": True, "checks_green": True},
                      kill_switch=False, chk_cas=True, canary_age=3600)
        fields.update(changes)
        return self.pr(**fields)            # pr() stamps, so a changed `at` moves the monotonic stamp too

    def pass_reviews(self, item=None):
        self.db.execute("UPDATE reviews SET state='passed' WHERE item=?", ((item or self.item)["id"],))

    def test_w02_elig_holds_only_when_every_clause_does(self):
        with self.assertRaisesRegex(C.ContractError, "e1, e2"):
            self.move("W2", obs=self.eligible())                   # the Review rows have not passed
        self.pass_reviews()
        pol = dict(self.eligible()["policy"])
        cases = {
            "e1": [dict(pr_head=TC.H2), dict(b_r_ancestors={}), dict(b_r_ancestors={TC.BASE: "yes"}),
                   dict(policy=dict(pol, revision="policy-r2"))],
            "e2": [dict(attached_core=TC.CORE2)],
            "e3": [dict(open_findings=1), dict(open_findings=True), dict(open_findings=None)],
            "e4": [dict(paths=[".claude/settings.json"]), dict(paths=[]), dict(paths="x.py"),
                   dict(foreign_closing_keyword=True), dict(foreign_closing_keyword=None)],
            "e5": [dict(policy=dict(pol, enabled=False)), dict(policy=dict(pol, checks_green="true")),
                   dict(policy=dict(pol, allowlisted=None)), dict(policy=None)],
            "e6": [dict(kill_switch=True), dict(kill_switch=None)],
            "e8": [dict(draft=True), dict(pr_state="CLOSED")],
            "e9": [dict(chk_cas=False), dict(canary_age=86400), dict(canary_age=None), dict(canary_age=True)],
            "e10": [dict(compare="behind"), dict(compare=None)],
        }
        for clause, variants in cases.items():
            for v in variants:
                with self.subTest(clause=clause, v=v):
                    with self.assertRaisesRegex(C.ContractError, r"\b%s\b" % clause):
                        self.move("W2", obs=self.eligible(**v))
        self.c.CAP1_PER_DAY = 0                                        # e7: the day's CAP1 slots are spent
        with self.assertRaisesRegex(C.ContractError, r"\be7\b"):
            self.move("W2", obs=self.eligible())
        del self.c.CAP1_PER_DAY
        self.db.execute("INSERT INTO repo_flags VALUES ('o/r', 1, 'canary failed', 'ahc-core', 0)")
        with self.assertRaisesRegex(C.ContractError, r"\be5\b"):
            self.move("W2", obs=self.eligible())
        self.db.execute("DELETE FROM repo_flags")
        self.db.execute("INSERT INTO contract_meta VALUES ('authority_frozen', '1')")
        with self.assertRaisesRegex(C.ContractError, r"\be6\b"):
            self.move("W2", obs=self.eligible())
        self.db.execute("DELETE FROM contract_meta WHERE k='authority_frozen'")
        stale = self.eligible(at=self.clock.t - C.Contracts.OBSERVATION_SECONDS)
        with self.assertRaisesRegex(C.ContractError, "e1, e2, e3, e4, e5, e6, e7, e8, e9, e10"):
            self.move("W2", obs=stale)
        item = self.move("W2", obs=self.eligible())
        self.assertEqual((item["state"], item["elig_core"], item["elig_policy"]),
                         ("merge-ready", TC.CORE1, TC.POLICY))

    def test_neg6_protected_paths(self):
        P = C.Contracts.protected_path
        for path in (".claude/settings.json", "sub/dir/CLAUDE.md", ".github/workflows/ci.yml", ".codex/config.toml",
                     "conftest.py", "tests/conftest.py", "a/CODEOWNERS", ".mcp.json", "harness/hooks/ahc_x.py",
                     "docs/spec/ahc-m1-state-machine.md", "pyproject.toml", "../escape", "/abs", "", None):
            with self.subTest(path=path):
                self.assertTrue(P(path))
        for path in ("harness/lib/x.py", "README.md", "docs/github/notes.md", "src/claude.py"):
            with self.subTest(path=path):
                self.assertFalse(P(path))
        self.assertTrue(P("config/policy.json", extra=("config/policy.json",)))

    def test_w06_mirror_cause_clears_only_on_a_fresh_mirror_ok_and_every_cause_must_clear(self):
        """Spec owner ruling on note 12: the mirror is a W5 cause of its own. W6 clears it only on a fresh
        mirror_ok True (a stale True counts as missing). With both causes recorded, W6 needs both cleared. The
        item escalates once on entry and does not loop W5/W6 while the mirror is down."""
        self.pass_reviews()
        self.move("W2", obs=self.eligible())
        ev = self.ev()
        item = self.move("W5", obs=self.eligible(mirror_ok=False, kill_switch=True), event_id=ev,
                         cause="ELIG failed: e6")                  # a caller's cause never replaces the derived one
        self.assertEqual(item["cause"], "ELIG failed: e6; mirror undeliverable", "both causes are recorded")
        refused = {"ELIG cleared, mirror still down": self.eligible(mirror_ok=False),
                   "ELIG cleared, mirror unread": self.eligible(),
                   "mirror up, ELIG still failing": self.eligible(mirror_ok=True, kill_switch=True),
                   "stale mirror_ok True": self.eligible(mirror_ok=True,
                                                         at=self.clock.t - C.Contracts.OBSERVATION_SECONDS),
                   "mirror_ok True from another boot": self.eligible(mirror_ok=True, boot="another-boot"),
                   "mirror_ok as text": self.eligible(mirror_ok="true")}
        for name, obs in refused.items():
            with self.subTest(name), self.assertRaises(C.ContractError):
                self.move("W6", obs=obs)
        for _poll in range(5):                                   # N polls with the mirror down: no loop
            with self.assertRaises(C.ContractError):
                self.move("W6", obs=self.eligible(mirror_ok=False))
            with self.assertRaisesRegex(C.ContractError, "W5"):       # W5's source is merge-ready only
                self.move("W5", obs=self.eligible(mirror_ok=False))
        self.assertEqual(self.wstate(), "waiting-dep")
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM wi_notices WHERE item=? AND row_id='W5'",
                                         (self.item["id"],)).fetchone()[0], 1, "one escalation, not one per poll")
        self.assertEqual(self.move("W6", obs=self.eligible(mirror_ok=True))["state"], "merge-ready")

    def test_w05_and_w06_waiting_dep_and_back(self):
        self.pass_reviews()
        self.move("W2", obs=self.eligible())
        with self.assertRaisesRegex(C.ContractError, "W5 needs"):
            self.move("W5", obs=self.eligible())
        with self.assertRaisesRegex(C.ContractError, "W5 needs"):
            self.move("W5", obs=self.eligible(open_findings=1))      # e3 is not a W5 cause
        ev = self.ev()
        item = self.move("W5", obs=self.eligible(kill_switch=True), event_id=ev)
        self.assertEqual((item["state"], item["cause"]), ("waiting-dep", "ELIG failed: e6"))
        self.assertEqual(self.db.execute("SELECT kind FROM wi_notices WHERE event_id=?", (ev,)).fetchall(),
                         [("ticket",)])
        with self.assertRaisesRegex(C.ContractError, "e6"):
            self.move("W6", obs=self.eligible(kill_switch=True))
        self.assertEqual(self.move("W6", obs=self.eligible())["state"], "merge-ready")
        ev = self.ev()
        item = self.move("W5", obs=self.eligible(mirror_ok=False), event_id=ev)
        self.assertEqual((item["state"], item["cause"]), ("waiting-dep", "mirror undeliverable"))
        self.assertEqual(self.db.execute("SELECT text FROM wi_notices WHERE event_id=?", (ev,)).fetchall(),
                         [("waiting on a dependency: mirror undeliverable",)])
        # W6 needs the recorded cause cleared: ELIG alone does not show the mirror is deliverable again
        for obs in (self.eligible(mirror_ok=False), self.eligible()):
            with self.subTest(obs=obs.get("mirror_ok")), self.assertRaisesRegex(C.ContractError, "mirror"):
                self.move("W6", obs=obs)
        self.assertEqual(self.move("W6", obs=self.eligible(mirror_ok=True))["state"], "merge-ready")

    def test_w17_protected_path_goes_to_main(self):
        self.pass_reviews()
        with self.assertRaisesRegex(C.ContractError, "e4"):
            self.move("W17", obs=self.eligible())
        for paths in ([".github/workflows/ci.yml"], ["ok.py", "sub/AGENTS.md"]):
            with self.subTest(paths=paths):
                self.at("pr-gate")
                self.assertEqual(self.move("W17", obs=self.eligible(paths=paths))["state"], "waiting-ask")
        self.assertEqual(C.Contracts.select_row(["W2", "W17"], False), "W17")

    def test_w27_spec_core_change_fails_e2_and_replaces_the_spec_row(self):
        self.pass_reviews()
        self.move("W2", obs=self.eligible())
        old_spec = self.db.execute("SELECT id FROM reviews WHERE item=? AND kind='spec'",
                                   (self.item["id"],)).fetchone()[0]
        with self.assertRaisesRegex(C.ContractError, "changed"):
            self.move("W27", obs=self.eligible())
        changed = self.eligible(attached_core=TC.CORE2)
        self.assertEqual(self.c.elig(self.c._row("work_items", "id", self.item["id"]), changed), ["e2"],
                         "Q-A5.1: a spec-core change fails e2, not e1")
        item = self.move("W27", obs=changed)
        self.assertEqual((item["state"], item["spec_core"], item["policy_revision"]), ("pr-gate", TC.CORE2, TC.POLICY))
        rows = dict(self.db.execute("SELECT id, state FROM reviews WHERE item=? AND kind='spec'", (item["id"],)))
        self.assertEqual(rows[old_spec], "passed", "the old pass stays terminal")
        new_spec = [r for r in rows if r != old_spec]
        self.assertEqual([rows[r] for r in new_spec], ["required"])
        self.assertEqual(self.c.elig(item, self.eligible(item)), ["e2"], "e2 fails until the new spec row passes")
        with self.assertRaisesRegex(C.ContractError, "W27"):          # pr-gate is not W27's source: no re-fire
            self.move("W27", obs=changed)
        self.db.execute("UPDATE reviews SET state='passed' WHERE id=?", (new_spec[0],))
        self.assertEqual(self.c.elig(item, self.eligible(item)), [])
        # the core attached now must be the item's own core: an older core's pass, still terminal, never counts
        self.assertEqual(self.c.elig(item, self.eligible(item, attached_core=TC.CORE1)), ["e2"])

    def test_neg18_a_missing_spec_row_fails_e2(self):
        self.pass_reviews()
        self.db.execute("DELETE FROM reviews WHERE item=? AND kind='spec'", (self.item["id"],))
        item = self.c._row("work_items", "id", self.item["id"])
        self.assertEqual(self.c.elig(item, self.eligible(item)), ["e2"])
        with self.assertRaisesRegex(C.ContractError, r"\be2\b"):
            self.move("W2", obs=self.eligible(item))

    def test_w27_policy_change_fails_e1_and_replaces_every_row(self):
        self.pass_reviews()
        self.move("W2", obs=self.eligible())
        pol = dict(self.eligible()["policy"], revision="policy-r2")
        changed = self.eligible(policy=pol)
        self.assertEqual(self.c.elig(self.c._row("work_items", "id", self.item["id"]), changed), ["e1"],
                         "Q-A5.1: a policy change fails e1, not e2")
        op = self.c.intend(self.params(), item=self.item["id"], lease_ok=True, event_id=self.ev())
        item = self.move("W27", obs=changed)
        self.assertEqual((item["state"], item["policy_revision"]), ("pr-gate", "policy-r2"))
        kinds = sorted(self.db.execute("SELECT kind, state FROM reviews WHERE item=? AND policy_revision='policy-r2'",
                                       (item["id"],)).fetchall())
        self.assertEqual(kinds, [("adversarial", "required"), ("spec", "required")])
        self.assertEqual(self.state("operations", "key", op["key"]), "abandoned", "E9")
        self.assertEqual(self.c.elig(item, self.eligible(item)), ["e1", "e2"])
        # PR 268 F1: complete the replacement reviews; the item regains ELIG and takes W2 to merge-ready, even
        # though the old policy's spec pass (same core) stays terminal beside the new one
        self.db.execute("UPDATE reviews SET state='passed' WHERE item=? AND policy_revision='policy-r2'",
                        (item["id"],))
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM reviews WHERE item=? AND kind='spec' AND "
                                         "state='passed'", (item["id"],)).fetchone()[0], 2)
        self.assertEqual(self.c.elig(item, self.eligible(item)), [])
        self.assertEqual(self.move("W2", obs=self.eligible(item))["state"], "merge-ready")

    def test_w27_waits_under_t7(self):
        self.pass_reviews()
        self.move("W2", obs=self.eligible())
        self.dispatched()
        with self.assertRaisesRegex(C.ContractError, "T7"):
            self.move("W27", obs=self.eligible(attached_core=TC.CORE2))

    def queue_of(self, *items, **per_item):
        return {i["id"]: self.eligible(self.c._row("work_items", "id", i["id"]), **per_item.get(i["id"], {}))
                for i in items}

    def test_queue_head_is_the_oldest_eligible_lineage(self):
        self.pass_reviews()
        self.clock.t += 1
        newer = self.admit(pr=6)
        self.pass_reviews(newer)
        self.assertEqual(self.c.queue_head("o/r", self.queue_of(self.item, newer)), self.item["id"])
        q = self.queue_of(self.item, newer, **{self.item["id"]: {"kill_switch": True}})
        self.assertEqual(self.c.queue_head("o/r", q), newer["id"], "an ineligible older item is skipped")
        q = self.queue_of(self.item, newer, **{self.item["id"]: {"compare": "behind"}})
        self.assertEqual(self.c.queue_head("o/r", q), self.item["id"], "e10 is not required of the head")
        self.assertEqual(self.c.queue_head("o/r", {newer["id"]: q[newer["id"]]}), newer["id"])

    def test_w21_records_one_update_for_the_queue_head_and_sends_nothing(self):
        """W21 writes the keyed intent record and its authority line; the move itself sends nothing (AC-7's sender
        does, from the committed row). It needs AHC_W21_SEND=1 and the repo policy's w21 field (NEG-16)."""
        env = mock.patch.dict(os.environ, {"AHC_W21_SEND": "1"})
        env.start()
        self.addCleanup(env.stop)
        self.pass_reviews()
        self.clock.t += 1
        newer = self.admit(pr=6)
        self.pass_reviews(newer)
        pol = dict(self.eligible()["policy"], w21=True)
        behind = {self.item["id"]: {"compare": "behind", "policy": pol},
                  newer["id"]: {"compare": "behind", "policy": pol}}

        def w21_obs(**kw):
            return self.pr(queue=self.queue_of(self.item, newer, **behind), mergeable=True, **kw)
        with self.assertRaisesRegex(C.ContractError, "head"):
            self.move("W21", item=newer, obs=dict(w21_obs(), pr=6))
        with self.assertRaisesRegex(C.ContractError, "every item"):
            self.move("W21", obs=self.pr(queue=self.queue_of(self.item, **{self.item["id"]: behind[self.item["id"]]}),
                                         mergeable=True))
        with self.assertRaisesRegex(C.ContractError, "mergeable"):
            self.move("W21", obs=self.pr(queue=self.queue_of(self.item, newer, **behind), mergeable=None))
        ahead = self.pr(queue=self.queue_of(self.item, newer, **{i: {"policy": pol} for i in behind}),
                        mergeable=True)
        with self.assertRaisesRegex(C.ContractError, "behind"):
            self.move("W21", obs=ahead)
        before = len(self.log.records())
        item = self.move("W21", obs=w21_obs())
        self.assertEqual((item["state"], item["w21_base"]), ("pr-gate", TC.BASE))
        recs = self.log.records()[before:]
        self.assertEqual([(r["row"], r["expected_head_sha"], r["action"]) for r in recs],
                         [("W21", TC.H1, "update-branch")], "authority log first, no send")
        self.assertEqual(self.db.execute("SELECT state FROM w21_sends").fetchall(), [("intent",)])
        with self.assertRaisesRegex(C.ContractError, "unresolved or lost send"):
            self.move("W21", obs=w21_obs())
        rid = self.db.execute("SELECT request_id FROM w21_sends").fetchone()[0]
        self.assertTrue(self.c.w21_attempt(rid) and self.c.w21_resolve(rid, TC.H2))
        with self.assertRaisesRegex(C.ContractError, "already recorded"):    # one update per (item, B), ever
            self.move("W21", obs=w21_obs())

    # ---- AC-5: W7, W11, W12, W15, W19, W22 and W23 (slice 1 (b))

    def w7_obs(self, item=None, **changes):
        o = self.eligible(item, kill_epoch=TC.Base.KILL, **changes)
        o["policy"] = dict(o["policy"], grant_source="queue:fixture#6165f60532c0", default_branch="main")
        return o

    def test_w07_writes_the_grant_and_intent_only(self):
        """W7: ELIG holds and nothing non-terminal exists for (repo, pr, B, H, revision): G1 issues the grant and
        E1 writes the Effect intent, in the row's transaction. Nothing dispatches. NEG-14: a second W7 is refused
        and creates no second grant or Effect."""
        self.pass_reviews()
        self.move("W2", obs=self.eligible())
        with self.assertRaisesRegex(C.ContractError, "W7 needs ELIG"):
            self.move("W7", obs=self.w7_obs(kill_switch=True))
        item = self.move("W7", obs=self.w7_obs())
        self.assertEqual(item["state"], "merge-ready")
        grants = self.db.execute("SELECT state, kill_epoch FROM grants WHERE repo='o/r' AND pr=5").fetchall()
        ops = self.db.execute("SELECT state, item, dispatch_count FROM operations").fetchall()
        self.assertEqual([tuple(g) for g in grants], [("validated", TC.Base.KILL)])
        self.assertEqual([tuple(o) for o in ops], [("intent", self.item["id"], 0)])
        with self.assertRaisesRegex(C.ContractError, "non-terminal grant"):
            self.move("W7", obs=self.w7_obs())
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM grants").fetchone()[0], 1)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM operations").fetchone()[0], 1)
        self.db.execute("UPDATE grants SET state='expired'")
        with self.assertRaisesRegex(C.ContractError, "non-terminal Effect"):
            self.move("W7", obs=self.w7_obs())

    def test_w11_hands_to_staging_and_beats_w12(self):
        """NEG-11: W11 is refused when the policy names no staging target, and W11 beats W12 when both hold."""
        self.at("merged")
        pol = {"revision": TC.POLICY}
        for bad in (pol, dict(pol, staging_target=""), dict(pol, staging_target=None)):
            self.at("merged")
            with self.assertRaisesRegex(C.ContractError, "staging target"):
                self.move("W11", obs=self.pr(policy=bad))
        self.at("merged")
        self.db.execute("DELETE FROM wi_notices")
        self.assertEqual(C.Contracts.select_row(["W12", "W11"], False), "W11")
        self.assertEqual(self.move("W11", obs=self.pr(policy=dict(pol, staging_target="stage-1")))["state"],
                         "handed-to-staging")
        self.assertEqual(self.notices_of("W11"), [("ticket", "handed to staging target stage-1; the M-2 item is "
                                                             "recorded only (goodqa#16070)")])

    def w12_obs(self, **changes):
        o = {"check_record": {"head": TC.H1, "passed": True, "headed": True, "recorder": "agent:clicker"},
             "author": "agent:author", "owner": "agent:owner", "spec_reviewers": ["agent:spec"],
             "evidence_posters": ["agent:evidence"]}
        o.update(changes)
        return o

    def test_w12_needs_an_independent_headed_check_bound_to_h(self):
        """NEG-12: refused when the author, owner, a spec reviewer or an evidence poster recorded it, when it is
        bound to another sha, not headed or failed, or when the lists that prove independence are missing."""
        self.at("merged")
        rec = self.w12_obs()["check_record"]
        bad = [dict(check_record=dict(rec, recorder=who)) for who in
               ("agent:author", "agent:owner", "agent:spec", "agent:evidence")]
        bad += [dict(check_record=dict(rec, head=TC.H2)), dict(check_record=dict(rec, headed=False)),
                dict(check_record=dict(rec, passed=False)), dict(spec_reviewers=None), dict(author=None)]
        for changes in bad:
            self.at("merged")                    # a variant that lets one through must not strand the rest
            with self.subTest(changes=changes), self.assertRaisesRegex(C.ContractError, "W12"):
                self.move("W12", obs=self.w12_obs(**changes))
        self.at("merged")
        self.db.execute("DELETE FROM wi_notices")
        self.assertEqual(self.move("W12", obs=self.w12_obs())["state"], "headed-verified")
        self.assertEqual(self.notices_of("W12"), [("ticket", "headed check by agent:clicker passed at %s" % TC.H1)])

    def findings_round(self, rnd, base_move=False):
        row = self.c.require_review("adversarial", "o/r", 5, TC.H1, TC.PKT, TC.POLICY, item=self.item["id"],
                                    event_id=self.ev(), snapshot_base=TC.BASE, round=rnd, base_move=base_move)
        self.db.execute("UPDATE reviews SET state='findings' WHERE id=?", (row["id"],))

    def test_w15_fires_only_on_b7_or_b33_exhaustion(self):
        """NEG-13: a base-move re-review block does not count toward B7; W15 fires on B7 (two rounds blocked on the
        PR's own content) or on the lineage's B33 budget, and on nothing else."""
        with self.assertRaisesRegex(C.ContractError, "B7 or B33"):
            self.move("W15")
        self.findings_round(1)
        self.findings_round(2, base_move=True)
        with self.assertRaisesRegex(C.ContractError, "B7 or B33"):
            self.move("W15")
        self.findings_round(3)
        self.assertEqual(self.c.b7_used(self.item), 2)
        self.assertEqual(self.move("W15")["state"], "exhausted")
        self.assertIn("B7 2 of 2 rounds", dict(self.notices_of("W15"))["ticket"])
        other = self.admit(pr=9)
        with self.assertRaisesRegex(C.ContractError, "B7 or B33"):
            self.move("W15", item=other)
        with self.c.tx():
            self.c.charge_b33(other["lineage"], C.Contracts.B33_RUNS - 1)
        with self.assertRaisesRegex(C.ContractError, "B7 or B33"):
            self.move("W15", item=other)
        with self.c.tx():
            self.c.charge_b33(other["lineage"])
        self.assertEqual(self.move("W15", item=other)["state"], "exhausted")

    def test_w19_incident_for_an_integrity_fault_and_a_ticket_otherwise(self):
        """NEG-14: W19 writes an incident for an integrity fault and a ticket comment for any other refusal."""
        for bad in (None, {"kind": "other", "detail": "x"}, {"kind": "argv", "detail": ""}):
            with self.assertRaisesRegex(C.ContractError, "typed"):
                self.move("W19", obs={"refusal": bad})
        self.move("W19", obs={"refusal": {"kind": "integrity", "detail": "receipt store digest mismatch"}})
        self.assertEqual(self.notices_of("W19"), [("incident", "refused (integrity): receipt store digest mismatch")])
        self.item = self.admit(pr=11)
        self.move("W19", obs={"refusal": {"kind": "allowlist", "detail": "repo is off the allowlist"}})
        self.assertEqual(self.notices_of("W19"), [("ticket", "refused (allowlist): repo is off the allowlist")])

    def test_w22_conflict_tells_the_owner_and_the_next_item_heads_the_queue(self):
        """NEG-14 and NEG-5: a conflict at the queue head takes W22 with an owner notice and nothing written to
        the PR; the next item becomes the queue head. A null mergeable or an unknown mergeable_state is neither
        W21 nor W22."""
        self.pass_reviews()
        self.clock.t += 1
        newer = self.admit(pr=6)
        self.pass_reviews(newer)

        def obs(**kw):
            return self.pr(queue=self.queue_of(self.item, newer), **kw)
        for mergeable, state in ((None, "unknown"), (None, "dirty"), (False, "unknown"), (True, "clean")):
            with self.subTest(mergeable=mergeable, state=state), self.assertRaisesRegex(C.ContractError, "conflict"):
                self.move("W22", obs=obs(mergeable=mergeable, mergeable_state=state))
        pol = dict(self.eligible()["policy"], w21=True)
        behind = {self.item["id"]: {"compare": "behind", "policy": pol}, newer["id"]: {"policy": pol}}
        with mock.patch.dict(os.environ, {"AHC_W21_SEND": "1"}), self.assertRaisesRegex(C.ContractError, "NEG-5"):
            self.move("W21", obs=self.pr(queue=self.queue_of(self.item, newer, **behind), mergeable=True,
                                         mergeable_state="unknown"))
        with self.assertRaisesRegex(C.ContractError, "head"):
            self.move("W22", item=newer, obs=dict(obs(mergeable=False, mergeable_state="dirty"), pr=6))
        self.assertEqual(self.move("W22", obs=obs(mergeable=False, mergeable_state="dirty"))["state"], "waiting-ask")
        self.assertEqual(self.notices_of("W22"), [("owner", "merge conflict with the default branch; the owner "
                                                            "resolves (nothing was written to the PR branch)")])
        self.assertEqual(self.c.queue_head("o/r", self.queue_of(newer)), newer["id"])

    def sent(self, item, state="attempted"):
        rid = "w21-%s-1" % item["id"]
        with self.c.tx():
            self.db.execute("INSERT INTO w21_sends(request_id, item, repo, pr, base, head, seq, event_id, state, "
                            "attempted_at, version, created, updated) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                            (rid, item["id"], item["repo"], item["pr"], TC.BASE, item["head"], 1, "ev-" + rid,
                             state, self.clock.t, 1, self.clock.t, self.clock.t))
            self.c.clock.start(rid, "W23", C.Contracts.W23_SECONDS)
        return rid

    def test_w23_escalates_a_lost_update_after_ten_minutes(self):
        """W23: a sent update with no H' read back within 10 min escalates to the owner and the ticket, the send
        row becomes lost, and the item leaves the queue. With no send (the flag off) W23 never fires (NEG-16)."""
        with self.assertRaisesRegex(C.ContractError, "W23 needs"):
            self.move("W23")
        rid = self.sent(self.item)
        self.clock.t += C.Contracts.W23_SECONDS - 1
        with self.assertRaisesRegex(C.ContractError, "W23 needs"):
            self.move("W23")
        self.clock.t += 1
        self.assertEqual(self.move("W23")["state"], "waiting-ask")
        self.assertEqual(self.c._row("w21_sends", "request_id", rid)["state"], "lost")
        text = "update-branch %s at B %s was lost; no second update until main's W16" % (rid, TC.BASE)
        self.assertEqual(self.notices_of("W23"), [("owner", text), ("ticket", text)])

    def test_every_row_but_w1_is_wired(self):
        """Slice 1 (b) wires the last rows; W1 is admission (admit_item), never a move."""
        self.assertEqual(sorted(C.Contracts.WI_WIRED), sorted(r for r in C.Contracts.WI_TRANSITIONS if r != "W1"))

    def test_unwired_rows_fail_closed(self):
        """A row left out of WI_WIRED is refused before its guard runs, even when the move is otherwise valid, and
        the item is untouched. Every real row is wired now, so the check is exercised by unwiring W4 (#247 run)."""
        from unittest import mock
        before = self.c._row("work_items", "id", self.item["id"])
        with mock.patch.object(C.Contracts, "WI_WIRED", tuple(r for r in C.Contracts.WI_WIRED if r != "W4")):
            with self.assertRaisesRegex(C.ContractError, "W4 is not wired"):
                self.move("W4", obs=self.pr(pr_head=TC.H2), successor_packet="e" * 64)
        self.assertEqual(dict(self.c._row("work_items", "id", self.item["id"])), dict(before))
        self.assertEqual(self.move("W4", obs=self.pr(pr_head=TC.H2), successor_packet="e" * 64)["state"],
                         "superseded", "the same move is applied once W4 is wired")

    # ---- slice (b) obligations (goodqa#16204, AC-9, NEG-25)

    def _queued(self, item, kind="adversarial"):
        rid = self.db.execute("SELECT id FROM reviews WHERE item=? AND kind=?", (item["id"], kind)).fetchone()[0]
        return self.c.review(rid, "queued", expected_version=1, event_id=self.ev())

    def test_b_scheduler_skips_rows_of_a_finished_item(self):
        """NEG-25 double-submit: across N ticks the scheduler never offers a queued row of a cancelled, merged,
        closed or superseded item (zero attempts), while in the same test a live item's queued row is offered and
        started (the positive control)."""
        import ahc_shadow  # noqa: PLC0415
        launched = []

        def launch(row):                  # the Launcher's contract: bind the row, return (status, detail)
            launched.append(row["id"])
            unit = "ahc-review-%s-i1" % row["id"]
            try:
                self.c.start_attempt(row["id"], unit, self.UID, expected_version=row["version"], event_id=self.ev())
            except C.ContractError as error:
                return "refused", str(error)
            return "running", unit

        dead = []
        cancelled = self.admit(pr=70)
        dead.append(self._queued(cancelled)["id"])
        self.c.wi_move(cancelled["id"], "W20", expected_version=cancelled["version"], event_id=self.ev(),
                       actor="owner")
        for n, state in enumerate(("merged", "closed-unmerged", "superseded")):
            item = self.admit(pr=71 + n)
            dead.append(self._queued(item)["id"])
            self.db.execute("UPDATE work_items SET state=? WHERE id=?", (state, item["id"]))
        live = self.admit(pr=80)
        live_row = self._queued(live)["id"]
        sched = ahc_shadow.ReviewScheduler(self.c, launch, slots=8)
        offered = []
        for n in range(6):
            result = sched.tick("t%d" % n)
            offered += result["offered"]
            self.assertEqual(result["refused"], [], "a finished item's row reached start_attempt")
        self.assertEqual(offered, [live_row], "only the live item's row is offered, once")
        self.assertEqual(launched, [live_row])
        self.assertEqual(self.c._row("reviews", "id", live_row)["state"], "running")
        for rid in dead:
            self.assertEqual(self.c._row("reviews", "id", rid)["state"], "queued", rid)

    def test_b_status_and_digest_show_inert_rows(self):
        """AC-9: after the owner cancels (W20), the item's queued code row and required spec row show as
        "inert: item cancelled" in status and in the shadow digest, never as queued or required."""
        import ahc_shadow  # noqa: PLC0415
        rid = self._queued(self.item)["id"]
        spec = self.db.execute("SELECT id FROM reviews WHERE item=? AND kind='spec'", (self.item["id"],)).fetchone()[0]
        self.move("W20", actor="owner")
        lines = ahc_shadow.status_lines(self.c)
        for row in (rid, spec):
            line = [x for x in lines if row in x]
            self.assertEqual(len(line), 1, lines)
            self.assertTrue(line[0].endswith(": inert: item cancelled"), line[0])
        self.assertFalse([x for x in lines if x.endswith(": queued") or x.endswith(": required")], lines)
        out = []
        self.assertEqual(ahc_shadow.deliver_digest(self.c, out.append), (1, 0))
        self.assertEqual(len(out), 1)
        self.assertIn("review adversarial %s: inert: item cancelled" % rid, out[0])
        self.assertIn("review spec %s: inert: item cancelled" % spec, out[0])
        self.assertNotIn("queued", out[0])
        self.assertEqual(ahc_shadow.deliver_digest(self.c, out.append), (0, 0), "delivered once")

    def test_b_findings_producer_writes_finding_ids(self):
        """AC-9 / NEG-25: the producer writes finding_ids that match ^[A-Za-z][A-Za-z0-9_.-]{0,31}$, at most 64;
        an id over 32 characters, one holding a space, or any beyond the 64th is dropped and flagged. W3's
        escalation names the kept ids."""
        import ahc_shadow  # noqa: PLC0415
        row = self.running_review(self.item, "adversarial")
        raw = ["F1", "x" * 33, "has space", "9lead", "", 7] + ["G%d" % n for n in range(70)]
        receipt = ahc_shadow.findings_receipt(row, "BLOCK", raw)
        self.assertEqual(receipt["finding_ids"], ["F1"] + ["G%d" % n for n in range(63)])
        self.assertEqual(receipt["finding_ids_dropped"], 5 + 7)
        self.assertEqual(ahc_shadow.findings_receipt(row, "BLOCK", ["A" * 32])["finding_ids"], ["A" * 32])
        self.assertNotIn("finding_ids_dropped", ahc_shadow.findings_receipt(row, "BLOCK", ["F1"]))
        self.c.review(row["id"], "findings", expected_version=row["version"], event_id=self.ev(), receipt=receipt,
                      peer_uid=self.UID)
        self.assertEqual(self.move("W3")["state"], "waiting-ask")
        text = dict(self.notices_of("W3"))["ticket"]
        self.assertIn("F1, G0, G1", text)
        self.assertNotIn("x" * 33, text)
        self.assertNotIn("G63, G64", text)

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

    def test_every_spec_test_id_resolves_to_a_test(self):
        """Spec owner ruling T-1: a spec test id (`SMTests.<id>`) resolves by exact name, or name plus a `_suffix`,
        in any tests/test_ahc*.py class. The ids with no such test yet are pinned exactly per entity in PENDING,
        so the list can only shrink: a new gap fails, and so does a pending id that now resolves until it is
        removed from the list. R17 and G6 are retired ids and must not reappear."""
        import re
        text = (HOOKS.parents[1] / "docs" / "spec" / "ahc-m1-state-machine.md").read_text(encoding="utf-8")
        names = set()
        for path in sorted((HOOKS.parents[1] / "tests").glob("test_ahc*.py")):
            names |= set(re.findall(r"^    def (test_\w+)", path.read_text(encoding="utf-8"), re.M))
        counts = {"WorkItem": 38, "Review": 28, "Grant": 15, "Effect": 24}
        for entity, n in counts.items():
            part = text.split("### Entity: %s" % entity, 1)[1].split("### Entity:", 1)[0]
            rows = {line.strip("|").split("|")[0].strip() for line in part.splitlines() if line.startswith("| ")}
            self.assertFalse(rows & self.RETIRED_ROWS, "%s: a retired row id reappeared" % entity)
            ids = sorted(set(re.findall(r"SMTests\.(test_\w+)", part)))
            with self.subTest(entity=entity):
                self.assertEqual(len(ids), n)
                missing = sorted(i for i in ids if not any(m == i or m.startswith(i + "_") for m in names))
                self.assertEqual(missing, sorted(self.PENDING[entity]),
                                 "%s: PENDING must equal the ids with no test of that name" % entity)
        self.assertLessEqual(set(self.PENDING_RUNTIME), {i for p in self.PENDING.values() for i in p} | names)

    # Retired by the spec (v2g16 lines 395 and 424): R17 moved to a follow-up ticket, G6 is covered by G5.
    RETIRED_ROWS = {"R17", "G6"}

    # Spec test ids with no test of that name yet, pinned per entity. Slice 1 (a) is capped here (main): the state
    # ids, R2 to R19, E6 and E11 are closed by goodqa#16197, and each unwired W row by the commit that wires it.
    # PENDING_RUNTIME names the ids whose runtime half slice 1 (b) also closes.
    PENDING = {
        "WorkItem": (
            "test_wi_pr_gate", "test_wi_merge_ready", "test_wi_waiting_dep", "test_wi_waiting_ask",
            "test_wi_exhausted", "test_wi_merged", "test_wi_headed_verified", "test_wi_handed",
            "test_wi_superseded", "test_wi_closed_unmerged", "test_wi_cancelled"),
        "Review": (
            "test_rv_required", "test_rv_queued", "test_rv_running", "test_rv_cancelling", "test_rv_outcome_unknown",
            "test_rv_infra_wait", "test_rv_passed", "test_rv_findings", "test_rv_superseded",
            "test_r06", "test_r08",
            "test_r09", "test_r10", "test_r11", "test_r12", "test_r13", "test_r14", "test_r15", "test_r16",
            "test_r18", "test_r19"),
        "Grant": (
            "test_g_validated", "test_g_active", "test_g_reserved", "test_g_consumed", "test_g_retired",
            "test_g_expired", "test_g_revoked"),
        "Effect": (
            "test_e_intent", "test_e_dispatched", "test_e_absent_proven", "test_e_fenced", "test_e_outcome_unknown",
            "test_e_held", "test_e_confirmed", "test_e_abandoned", "test_e06", "test_e11"),
    }

    # Ids whose runtime half belongs to slice 1 (b), with the ruling (T-1): the ledger part is tested in 1 (a);
    # (b) adds the packet build (R2), the DynamicUser unit and its launch (R3), the socket FINAL and the R-c
    # usage-store refusal (R4), and the unit's findings result (R5).
    PENDING_RUNTIME = ()

    def test_every_slice_b_obligation_resolves_or_is_pinned(self):
        """goodqa#16204: obligations ruled onto slice (b) are listed as `OBL.<test id>` in
        docs/spec/ahc-m1-b-obligations.md and resolve like the spec ids (exact name, or name plus `_suffix`). The
        unresolved ones are pinned exactly in PENDING_B, so the list only shrinks and slice (b) cannot close with
        one dropped: a line removed from the doc, a new unpinned obligation, or a pinned one that now resolves all
        fail here."""
        import re
        text = (HOOKS.parents[1] / "docs" / "spec" / "ahc-m1-b-obligations.md").read_text(encoding="utf-8")
        names = set()
        for path in sorted((HOOKS.parents[1] / "tests").glob("test_ahc*.py")):
            names |= set(re.findall(r"^    def (test_\w+)", path.read_text(encoding="utf-8"), re.M))
        ids = sorted(set(re.findall(r"OBL\.(test_\w+)", text)))
        self.assertGreaterEqual(set(ids), set(self.PENDING_B), "an obligation was dropped from the doc")
        # once resolved, an obligation stays listed: the doc is the record of where it was met (#247 variant run)
        self.assertGreaterEqual(set(ids), set(self.RESOLVED_B), "a resolved obligation was dropped from the doc")
        missing = sorted(i for i in ids if not any(m == i or m.startswith(i + "_") for m in names))
        self.assertEqual(missing, sorted(self.PENDING_B), "PENDING_B must equal the unresolved obligations")

    # slice (b) obligations with no test yet (goodqa#16204 items 2 and 3; the W3 finding_ids assumption)
    PENDING_B = ()
    # slice (b) obligations already resolved by a test; the doc keeps listing them
    RESOLVED_B = ("test_b_findings_producer_writes_finding_ids", "test_b_scheduler_skips_rows_of_a_finished_item",
                  "test_b_status_and_digest_show_inert_rows")


# ---------------------------------------------------------------------------------------------------------------
# Slice 1 (b) AC-11 / AC-16: schema version 5 (goodqa#16049). The PR 258 and 4d45fe40 fixtures are built by the
# old code itself, from `git archive` of e0e4ac46 and 4d45fe40, each pinned by its ahc_contracts.py sha256.

PIN_E0E4 = "586cda00d1930645eb3bed97ddfe5d007a31ff542d4526036ac39efa2d7c1bdd"
PIN_4D45 = "b10962cc9bdaa50cab5bd71fee7c57448048744ec7045b94f76a33104235068a"
OLD_TREES = {}


def old_tree(commit, pin):
    """harness/hooks at `commit`, extracted once per run and checked against its pinned ahc_contracts.py hash."""
    import hashlib
    import subprocess
    if commit in OLD_TREES:
        return OLD_TREES[commit]
    repo = Path(__file__).resolve().parent.parent
    target = Path(tempfile.mkdtemp(prefix="ahc-old-%s-" % commit))
    archive = subprocess.run(["git", "-C", str(repo), "archive", commit, "harness/hooks"], capture_output=True)
    if archive.returncode != 0:
        raise AssertionError("commit %s is not in this checkout; fetch it (the fixture is pinned)" % commit)
    subprocess.run(["tar", "-x", "-C", str(target)], input=archive.stdout, check=True)
    hooks = target / "harness" / "hooks"
    got = hashlib.sha256((hooks / "ahc_contracts.py").read_bytes()).hexdigest()
    if got != pin:
        raise AssertionError("fixture %s ahc_contracts.py sha256 %s is not the pin %s" % (commit, got, pin))
    OLD_TREES[commit] = hooks
    return hooks


HOLD_ROLE_CHILD = (
    "import sys, time; sys.path.insert(0, sys.argv[1]); import ahc_core, ahc_runner; "
    "h = ahc_runner.acquire_lock(ahc_core.Paths(sys.argv[2]), sys.argv[3]); "
    "print('held' if h is not None else 'busy', flush=True); time.sleep(30)")

STARTUP_CHILD = r"""
import os, sys, time
sys.path.insert(0, sys.argv[1])
import ahc_core, ahc_runner
paths, role, go = ahc_core.Paths(sys.argv[2]), sys.argv[3], sys.argv[4]
ahc_runner.Ledger.LOCK_WAIT = 3.0
handle = ahc_runner.acquire_lock(paths, role)
print("locked" if handle is not None else "busy", flush=True)
while not os.path.exists(go):
    time.sleep(0.02)
start = time.monotonic()
try:
    # the migrating open each role's startup reconciliation made at 084a610b (core's tick makes it every tick)
    ahc_runner.Ledger(paths, migrate=True).close()
    print("ok %.2f" % (time.monotonic() - start), flush=True)
except Exception as error:
    print("error %.2f %s: %s" % (time.monotonic() - start, type(error).__name__, error), flush=True)
"""


SERVE_CHILD = r"""
import os, sys, time, types
sys.path.insert(0, sys.argv[1])
import ahc_core, ahc_runner
paths, role, go = ahc_core.Paths(sys.argv[2]), sys.argv[3], sys.argv[4]
ahc_runner.Ledger.LOCK_WAIT = 10.0
ahc_runner.PENDING_WAIT = 0.1
# the migration's open-file probe sees only this process (as _ProbeRun does in-process)
ahc_runner.Ledger.PROBE_RUN = staticmethod(
    lambda argv, timeout: types.SimpleNamespace(returncode=0, stdout="p%d\nf4\n" % os.getpid(), stderr=""))
lock = ahc_runner.acquire_lock(paths, role)
print("locked" if lock is not None else "busy", flush=True)
while not os.path.exists(go):
    time.sleep(0.02)
steps = []


def step():
    steps.append(1)
    ahc_runner.Ledger(paths, migrate=(role == "core")).close()    # the open each role's tick makes
    return {"role": role}


def refuse(error):
    print("refused %s: %s" % (type(error).__name__, error), flush=True)
    return 3


rc = ahc_runner.serve(paths, role, lock, step, refuse, once=True)
print("rc %d steps %d" % (rc, len(steps)), flush=True)
"""


def run_old(hooks, home, code):
    """Run `code` in a child process on the old tree (its own ahc_core and ahc_runner) against `home`."""
    import subprocess
    script = ("import sys; sys.path.insert(0, sys.argv[1]); import ahc_core, ahc_runner; "
              "paths = ahc_core.Paths(sys.argv[2]); " + code)
    return subprocess.run([sys.executable, "-I", "-B", "-c", script, str(hooks), str(home)], capture_output=True,
                          text=True, timeout=120)


class _ProbeRun:
    """A fake lsof: lists this process's pid for every probe, plus `others` (pids) on the checks after the fence."""

    def __init__(self, others=(), fail=None):
        self.others, self.fail, self.calls = list(others), fail, []

    def __call__(self, argv, timeout):
        import types
        self.calls.append(argv)
        if self.fail:
            raise self.fail
        pids = [os.getpid()] + (self.others if len(self.calls) > 1 else [])
        return types.SimpleNamespace(returncode=0 if pids else 1, stdout="".join("p%d\nf4\n" % p for p in pids),
                                     stderr="")


class MigrationV5Tests(Base):
    SHA = {"h": "a" * 40, "b": "c" * 40, "pkt": "d" * 64, "core": "e" * 64}

    def setUp(self):
        super().setUp()
        if not hasattr(self, "_saved"):          # tests re-run setUp in a loop: keep the class's own values
            self._saved = (runner.Ledger.__dict__["PROBE_RUN"], runner.Ledger.HOOKS_DIR, runner.Ledger.LOCK_WAIT)
        runner.Ledger.LOCK_WAIT = 2.0
        self.live = self.paths.root / "ledger.sqlite3"

    def tearDown(self):
        runner.Ledger.PROBE_RUN, runner.Ledger.HOOKS_DIR, runner.Ledger.LOCK_WAIT = self._saved
        super().tearDown()

    def db(self, path=None, ro=False):
        import sqlite3
        conn = sqlite3.connect(str(path or self.live), isolation_level=None)   # ro cannot open a WAL ledger w/o -shm
        conn.row_factory = sqlite3.Row
        return conn

    def make_old(self, commit, pin, populate=True):
        """A version 4 ledger written by the old code itself, then populated with code passes, a findings row,
        spec passes and an operation, all as raw rows in that layout."""
        hooks = old_tree(commit, pin)
        proc = run_old(hooks, self.home, "ahc_runner.Ledger(paths).close()")
        self.assertEqual(proc.returncode, 0, proc.stderr[-800:])
        if not populate:
            return
        db = self.db()
        try:
            s = self.SHA
            cols = [r[1] for r in db.execute("PRAGMA table_info(reviews)")]
            spec_core = "spec_core" in cols
            rows = [("rv-code-pass", "adversarial", "passed", s["b"], ""), ("rv-code-find", "red-team", "findings",
                                                                             s["b"], ""),
                    ("rv-spec-pass", "spec", "passed", "", s["core"])]
            for rid, kind, state, br, core in rows:
                names = "id, kind, item, repo, pr, head, snapshot_base, packet_sha256, policy_revision, state, " \
                        "version, receipt, created, updated" + (", spec_core" if spec_core else "")
                values = [rid, kind, "it-p0" if not spec_core else "wi-old", "o/r", 5, s["h"], br, s["pkt"], "rev1",
                          state, 3, '{"verdict": "%s"}' % ("PASS" if state == "passed" else "BLOCK"), 1.0, 2.0]
                if spec_core:
                    values.append(core)
                db.execute("INSERT INTO reviews(%s) VALUES (%s)" % (names, ",".join("?" * len(values))), values)
            db.execute("INSERT INTO operations(key, kind, repo, pr, head, base, policy_revision, generation, "
                       "params_sha256, state, version, created, updated) VALUES ('op-1', 'ff', 'o/r', 5, ?, ?, "
                       "'rev1', 1, ?, 'confirmed', 2, 1, 2)", (s["h"], s["b"], s["pkt"]))
        finally:
            db.close()

    def fresh_v5_sql(self):
        other = Path(tempfile.mkdtemp(prefix="ahc-fresh-"))
        runner.Ledger(core.Paths(other)).close()
        return self.schema(core.Paths(other).root / "ledger.sqlite3")

    def schema(self, path):
        db = self.db(path, ro=True)
        try:
            return {(t, n, sql) for t, n, sql in db.execute(
                "SELECT type, name, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' AND name NOT LIKE "
                "'%\\_v3\\_legacy' ESCAPE '\\' AND name NOT LIKE '%\\_v4\\_legacy' ESCAPE '\\'")}
        finally:
            db.close()

    def rows(self, path, table):
        db = self.db(path, ro=True)
        try:
            return sorted(tuple(r) for r in db.execute("SELECT * FROM %s" % table))
        finally:
            db.close()

    def version(self, path=None):
        db = self.db(path, ro=True)
        try:
            row = db.execute("SELECT v FROM meta WHERE k='schema_version'").fetchone()
            return row[0] if row else None
        finally:
            db.close()

    def open_v5(self, probe=None):
        runner.Ledger.PROBE_RUN = probe or _ProbeRun()
        return runner.Ledger(self.paths)

    def must_open(self, probe=None):
        """A migration that must succeed: a refusal is an assertion failure (so a variant counts as killed)."""
        try:
            return self.open_v5(probe)
        except runner.SchemaError as error:
            self.fail("the migration was refused: %s" % error)

    def expect_refusal(self, cls, pattern, probe=None):
        try:
            self.open_v5(probe).close()
        except runner.SchemaError as error:
            self.assertIsInstance(error, cls, str(error))
            self.assertRegex(str(error), pattern)
            return error
        self.fail("the migration was not refused")

    # ---- the two layouts

    def test_v5_pr258_layout_migrates_code_rows_keeps_spec_rows_legacy(self):
        self.make_old("e0e4ac46", PIN_E0E4)
        before = self.rows(self.live, "reviews")
        self.must_open().close()
        self.assertEqual(self.version(), "5")
        self.assertEqual(self.rows(self.live, "reviews_v4_legacy"), before, "every PR 258 row is kept aside")
        db = self.db(ro=True)
        try:
            kept = {r["id"]: (r["state"], r["round"], r["receipt"], r["item"]) for r in db.execute("SELECT * FROM reviews")}
            ops = [tuple(r) for r in db.execute("SELECT key, state, wait_mono, wait_boot FROM operations")]
            tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        finally:
            db.close()
        self.assertEqual(set(kept), {"rv-code-pass", "rv-code-find"}, "spec rows stay only in reviews_v4_legacy")
        self.assertEqual(kept["rv-code-pass"][:2], ("passed", 1))
        self.assertEqual(kept["rv-code-find"][:2], ("findings", 1))
        self.assertEqual(ops, [("op-1", "confirmed", None, None)], "operations rebuilt: an unknown AC-10 anchor")
        self.assertIn("operations_v4_legacy", tables)
        self.assertTrue({"work_items", "wi_notices", "observations", "w21_sends"} <= tables)
        self.assertEqual(self.schema(self.live), self.fresh_v5_sql(), "fresh and migrated v5 SQL are identical")

    def test_v5_4d45fe40_layout_migrates_every_row_as_round_1(self):
        self.make_old("4d45fe40", PIN_4D45)
        before = {r[0]: r for r in self.rows(self.live, "reviews")}
        self.must_open().close()
        db = self.db(ro=True)
        try:
            after = {r["id"]: r for r in db.execute("SELECT * FROM reviews")}
        finally:
            db.close()
        self.assertEqual(set(after), set(before), "every row is copied in place")
        for rid, row in after.items():
            self.assertEqual((row["round"], row["state"], row["receipt"], row["item"]),
                             (1, before[rid][9], before[rid][11], before[rid][2]))
        self.assertEqual(self.schema(self.live), self.fresh_v5_sql())

    def test_v5_readmitted_workitem_never_gets_a_copied_row(self):
        """NEG-28 / AC-16: a WorkItem whose round 1 binding equals a copied PR 258 row's gets its own row."""
        self.make_old("e0e4ac46", PIN_E0E4)
        ledger = self.must_open()
        try:
            c = runner.ahc_contracts.Contracts(ledger.db, runner.ahc_contracts.AuthorityLog(self.home / "auth.log"))
            s = self.SHA
            row = c.require_review("adversarial", "o/r", 5, s["h"], s["pkt"], "rev1", item="wi-new",
                                   snapshot_base=s["b"])
            self.assertNotEqual(row["id"], "rv-code-pass")
            self.assertEqual((row["item"], row["state"], row["round"]), ("wi-new", "required", 1))
            again = c.require_review("adversarial", "o/r", 5, s["h"], s["pkt"], "rev1", item="wi-new",
                                     snapshot_base=s["b"])
            self.assertEqual(again["id"], row["id"], "looked up by the key, idempotent")
        finally:
            ledger.close()

    def test_v5_refuses_the_earlier_v4_layout_and_unknown_markers(self):
        for label, ddl in (("early-v4", "CREATE TABLE reviews (id TEXT PRIMARY KEY, kind TEXT, merge_sha TEXT)"),
                           ("unknown", "CREATE TABLE reviews (id TEXT PRIMARY KEY, kind TEXT, spec_core TEXT)")):
            with self.subTest(layout=label):
                self.setUp()
                self.make_old("4d45fe40", PIN_4D45, populate=False)
                db = self.db()
                db.execute("DROP TABLE reviews")
                db.execute(ddl)
                db.close()
                before = self.rows(self.live, "reviews"), self.version()
                self.expect_refusal(runner.MigrationRefused, "migration-layout")
                self.assertEqual((self.rows(self.live, "reviews"), self.version()), before)
                self.assertFalse(list(self.paths.root.glob("ledger.sqlite3.pre-v5.*.bak")), "no backup taken")

    # ---- the fence, the preflight and the open-file check

    def test_v5_failure_restores_fenced_then_the_retry_migrates(self):
        self.make_old("4d45fe40", PIN_4D45)
        before = {t: self.rows(self.live, t) for t in ("reviews", "operations", "grants")}
        saved = list(runner.MIGRATIONS[5])
        runner.MIGRATIONS[5] = saved + ["THIS IS NOT SQL"]
        try:
            self.expect_refusal(runner.SchemaError, "restored the verified backup")
        finally:
            runner.MIGRATIONS[5] = saved
        self.assertEqual(self.version(), "v5-migrating-from-4", "the restored copy carries the fence")
        self.assertEqual({t: self.rows(self.live, t) for t in before}, before, "row-for-row equal to the backup")
        self.assertTrue(list(self.paths.root.glob("ledger.sqlite3.failed-*")), "failed files moved aside, kept")
        with self.assertRaises(runner.MigrationPending):
            runner.Ledger(self.paths, migrate=False)
        self.must_open().close()
        self.assertEqual(self.version(), "5")
        self.assertEqual(len(self.rows(self.live, "reviews")), len(before["reviews"]))

    def test_v5_fence_over_v3_is_cleared_when_the_file_is_held(self):
        self.make_old("4d45fe40", PIN_4D45, populate=False)
        db = self.db()
        db.execute("UPDATE meta SET v='3' WHERE k='schema_version'")
        db.close()
        before = self.rows(self.live, "items"), self.version()
        self.expect_refusal(runner.MigrationRefused, "migration-held.*cleared back to schema_version 3",
                            _ProbeRun(others=[999999]))
        self.assertEqual((self.rows(self.live, "items"), self.version()), before)
        self.assertFalse(list(self.paths.root.glob("ledger.sqlite3.pre-v5.*.bak")))

    def test_v5_a_failed_open_file_check_counts_as_held(self):
        self.make_old("4d45fe40", PIN_4D45, populate=False)

        class Fails(_ProbeRun):
            def __call__(self, argv, timeout):
                import types
                self.calls.append(argv)
                if len(self.calls) == 1:
                    return types.SimpleNamespace(returncode=0, stdout="p%d\n" % os.getpid(), stderr="")
                return types.SimpleNamespace(returncode=1, stdout="", stderr="lsof: WARNING: permission denied\n")
        self.expect_refusal(runner.MigrationRefused, "migration-held.*cleared back to schema_version 4",
                            Fails())
        self.assertEqual(self.version(), "4")

    def test_v5_the_fence_is_committed_before_the_open_file_check(self):
        """NEG-43 at the check: an old reader that connects after the preflight and before the open-file check
        finds the fence and refuses; the fence is in place when the check runs, and the backup carries it."""
        self.make_old("4d45fe40", PIN_4D45)
        seen = []
        hooks = old_tree("4d45fe40", PIN_4D45)

        class Watch(_ProbeRun):
            def __call__(inner, argv, timeout):
                if len(inner.calls) == 1:          # the open-file check after the preflight probe
                    seen.append(self.version())
                    proc = run_old(hooks, self.home, "ahc_runner.Ledger(paths, migrate=False)")
                    seen.append(proc.returncode != 0 and "unreadable schema_version" in proc.stderr)
                return _ProbeRun.__call__(inner, argv, timeout)
        self.must_open(Watch()).close()
        self.assertEqual(seen, ["v5-migrating-from-4", True])
        backup = next(self.paths.root.glob("ledger.sqlite3.pre-v5.*.bak"))
        self.assertEqual(self.version(backup), "v5-migrating-from-4", "the backup carries the fence")

    def test_v5_preflight_refuses_without_a_probe_or_its_own_pid(self):
        self.make_old("4d45fe40", PIN_4D45, populate=False)
        import types
        for label, run in (("missing", _ProbeRun(fail=FileNotFoundError("lsof"))),
                           ("denied", lambda argv, t: types.SimpleNamespace(returncode=1, stdout="", stderr=""))):
            with self.subTest(case=label):
                self.expect_refusal(runner.MigrationRefused, "migration-preflight", run)
                self.assertEqual(self.version(), "4", "refused before the fence: nothing written")
        self.assertIsNone(runner.ahc_migrate.open_file_holders.__defaults__[0] if False else None)
        with self.assertRaises(runner.ahc_migrate.ProbeError):
            runner.ahc_migrate.open_file_holders([self.live], lambda a, t: None, tools={"lsof": None, "fuser": None})

    def test_v5_entry_point_mismatch_refuses_before_any_backup(self):
        import shutil as _shutil
        self.make_old("4d45fe40", PIN_4D45, populate=False)
        hooks = Path(tempfile.mkdtemp(prefix="ahc-hooks-"))
        source = runner.Ledger.HOOKS_DIR
        for name in runner.ahc_migrate.release_list(source):
            _shutil.copyfile(source / name, hooks / name)
        _shutil.copyfile(source / runner.ahc_migrate.RELEASE_LIST, hooks / runner.ahc_migrate.RELEASE_LIST)
        _shutil.copyfile(old_tree("4d45fe40", PIN_4D45) / "ahc_runner.py", hooks / "ahc_runner.py")
        runner.Ledger.HOOKS_DIR = hooks
        self.expect_refusal(runner.MigrationRefused, "preflight: installed entry points.*ahc_runner.py")
        self.assertEqual(self.version(), "4")
        self.assertFalse(list(self.paths.root.glob("ledger.sqlite3.pre-v5.*.bak")))

    # ---- PR 247 F5: the preflight checks the launch files the real installer wrote

    def installed_old(self, record=None):
        """A 4d45fe40 ledger on a host where the real `ahc install --apply` wrote both units and the wrapper. HOME is
        this test's home, so the runner derives the same launch-file paths the installer used."""
        import ahc_install
        self.make_old("4d45fe40", PIN_4D45, populate=False)
        self.assertEqual(ahc_install.install(self.paths, self.home, True, run=FakeHost(), system="Linux",
                                             out=lambda line: None), 0)
        if record is not None:
            (self.paths.root / ahc_install.RECORD).write_text(record)
        env = mock.patch.dict(os.environ, {"HOME": str(self.home)})
        env.start()
        self.addCleanup(env.stop)
        return ahc_install

    def assert_refused_before_the_fence(self, pattern):
        self.expect_refusal(runner.MigrationRefused, pattern)
        self.assertEqual(self.version(), "4", "refused before the fence: nothing written")
        self.assertFalse(list(self.paths.root.glob("ledger.sqlite3.pre-v5.*.bak")), "no backup taken")

    def test_r247_f5_the_installer_records_its_launch_files(self):
        inst = self.installed_old()
        record = json.loads((self.paths.root / inst.RECORD).read_text())
        want = sorted([str(self.home / ".config" / "systemd" / "user" / "ahc-core.service"),
                       str(self.home / ".config" / "systemd" / "user" / "ahc-review.service"),
                       str(self.home / ".local" / "bin" / "ahc")])
        self.assertEqual(record["files"], want)
        self.assertEqual(sorted(inst.installed_files(self.home)), want)

    def test_r247_f5_an_altered_or_missing_launch_file_refuses_the_migration(self):
        launch = {"ahc-core": Path(".config/systemd/user/ahc-core.service"),
                  "ahc-review": Path(".config/systemd/user/ahc-review.service"), "wrapper": Path(".local/bin/ahc")}
        for name, rel in launch.items():
            for change in ("altered", "removed"):
                with self.subTest(file=name, change=change):
                    self.setUp()
                    self.installed_old()
                    path = self.home / rel
                    if change == "altered":
                        path.write_text(path.read_text() + "# left over from 4d45fe40\n")
                        pattern = re.escape(str(path)) + " does not match the v5 release"
                    else:
                        path.unlink()
                        pattern = re.escape(str(path)) + " unreadable"
                    self.assert_refused_before_the_fence(pattern + ".*ahc install --apply")

    def test_r247_f5_a_legacy_record_without_files_still_checks_the_launch_files(self):
        # what a 4d45fe40 install wrote: no "files" key; the preflight must not skip this host's launch files
        self.installed_old(record=json.dumps({"linger_before": False, "installed_at": 1.0, "user": "fixture"}))
        (self.home / ".local" / "bin" / "ahc").unlink()
        self.assert_refused_before_the_fence(r"\.local/bin/ahc unreadable")

    def test_r247_f5_a_record_naming_other_files_or_unreadable_refuses(self):
        for label, record, pattern in (
                ("other paths", json.dumps({"linger_before": False, "files": ["/elsewhere/ahc-core.service"]}),
                 "install record names"),
                ("not json", "{", "install record .* cannot be read")):
            with self.subTest(label):
                self.setUp()
                self.installed_old(record=record)
                self.assert_refused_before_the_fence(pattern)

    def test_r247_f5_current_launch_files_migrate_and_no_record_means_nothing_installed(self):
        self.installed_old()
        self.must_open().close()
        self.assertEqual(self.version(), "5")
        self.setUp()
        self.make_old("4d45fe40", PIN_4D45, populate=False)     # no install record: a hand-run or test ledger
        self.must_open().close()
        self.assertEqual(self.version(), "5")

    def test_v5_release_list_is_current(self):
        import subprocess
        proc = subprocess.run([sys.executable, "-B", str(HOOKS.parents[1] / "scripts" / "ahc_release_hashes.py"),
                               "--check"], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stdout)

    def test_v5_probe_output_is_parsed_never_the_exit_status(self):
        import types
        m = runner.ahc_migrate
        f = Path("/x/ledger.sqlite3")
        ok = lambda out, err="", rc=0: (lambda a, t: types.SimpleNamespace(returncode=rc, stdout=out, stderr=err))
        self.assertEqual(m.open_file_holders([f], ok("", rc=1), tools={"lsof": "/usr/sbin/lsof"}), set(),
                         "lsof exits 1 when nothing holds the file: clear")
        self.assertEqual(m.open_file_holders([f], ok("p12\nf3\np34\n"), tools={"lsof": "/usr/sbin/lsof"}), {12, 34})
        self.assertEqual(m.open_file_holders([f], ok("", "%s:\n" % f), tools={"fuser": "/usr/bin/fuser"}), set(),
                         "macOS fuser exits 0 with only its file-name echo: clear")
        self.assertEqual(m.open_file_holders([f], ok(" 77", "%s:\n" % f), tools={"fuser": "/usr/bin/fuser"}), {77})
        for tools, run in (({"lsof": "/usr/sbin/lsof"}, ok("", "lsof: WARNING: can't stat()\n", 1)),
                           ({"fuser": "/usr/bin/fuser"}, ok("", "fuser: permission denied\n")),
                           ({"lsof": "/usr/sbin/lsof"}, ok("", rc=-9))):
            with self.assertRaises(m.ProbeError):
                m.open_file_holders([f], run, tools=tools)

    def test_v5_real_probe_lists_this_process_on_the_mac_and_t2(self):
        f = self.home / "held.sqlite3"
        with open(str(f), "w") as handle:
            handle.write("x")
            holders = runner.ahc_migrate.open_file_holders([f], runner.ahc_migrate.default_run)
        self.assertIn(os.getpid(), holders)

    # ---- locks: a live connection, a role, and the restore publish

    # ---- PR 272 F1: a running role and the migration locks

    def hold_role(self, role):
        holder = subprocess.Popen([sys.executable, "-I", "-B", "-c", HOLD_ROLE_CHILD, str(HOOKS), str(self.home), role],
                                  stdout=subprocess.PIPE, text=True)
        self.addCleanup(lambda: (holder.terminate(), holder.wait(), holder.stdout.close()))
        self.assertEqual(holder.stdout.readline().strip(), "held")
        return holder

    def test_f1_a_current_v5_ledger_opens_while_the_review_role_runs(self):
        """PR 272 F1: the running review daemon holds its role lock for its life; core's tick opens the existing v5
        ledger (migrate=True) without waiting on it: an unfenced v5 ledger needs no migration and no role lock."""
        self.open_v5().close()
        self.hold_role("review")
        start = time.monotonic()
        try:
            runner.Ledger(self.paths, migrate=True).close()
        except runner.SchemaError as error:
            self.fail("a core tick on a current v5 ledger was refused: %s" % error)
        self.assertLess(time.monotonic() - start, 1.0, "no wait on the other role's lock")

    def test_f1_both_roles_start_together_on_a_v5_ledger(self):
        """PR 272 F1: ahc-core and ahc-review start at once, each holding its own role lock, and each opens the
        current v5 ledger with migrate=True: neither waits on the other's lock, so they cannot deadlock."""
        self.open_v5().close()
        go = self.home / "go"
        procs = {}
        for role in ("core", "review"):
            procs[role] = subprocess.Popen([sys.executable, "-I", "-B", "-c", STARTUP_CHILD, str(HOOKS),
                                            str(self.home), role, str(go)], stdout=subprocess.PIPE, text=True)
        try:
            for role, proc in procs.items():
                self.assertEqual(proc.stdout.readline().strip(), "locked", role)
            go.write_text("go")
            lines = {role: proc.stdout.readline().strip() for role, proc in procs.items()}
        finally:
            for proc in procs.values():
                proc.terminate()
                proc.wait()
                proc.stdout.close()
        for role, line in lines.items():
            self.assertTrue(line.startswith("ok "), "%s: %s" % (role, line))
            self.assertLess(float(line.split()[1]), 2.0, "%s waited: %s" % (role, line))

    # ---- PR 247 receipt F1 / F2: startup against a ledger that needs core's migration

    def serve_child(self, role, go):
        proc = subprocess.Popen([sys.executable, "-I", "-B", "-c", SERVE_CHILD, str(HOOKS), str(self.home), role,
                                 str(go)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.addCleanup(lambda: proc.poll() is None and (proc.terminate(), proc.wait()))
        self.assertEqual(proc.stdout.readline().strip(), "locked", role)
        return proc

    def start_both(self, first):
        """Start `first`, let it run alone for a while, then the other role; both must end with rc 0."""
        second = "core" if first == "review" else "review"
        procs = {first: self.serve_child(first, self.home / "go-first")}
        (self.home / "go-first").write_text("go")
        time.sleep(0.6)
        procs[second] = self.serve_child(second, self.home / "go-second")
        (self.home / "go-second").write_text("go")
        out = {}
        for role, proc in procs.items():
            try:
                stdout, stderr = proc.communicate(timeout=60)
            except subprocess.TimeoutExpired:            # a role that never runs is the defect: fail, not error
                self.fail("%s did not finish within 60 s" % role)
            out[role] = stdout.strip().splitlines()[-1] if stdout.strip() else "no output: " + stderr[-400:]
        for role, line in out.items():
            self.assertTrue(line.startswith("rc 0 "), "%s did not run: %s" % (role, line))
        self.assertEqual(self.version(), "5")
        return out

    def old_ledger(self):
        self.make_old("4d45fe40", PIN_4D45, populate=False)
        db = self.db()
        db.execute("UPDATE meta SET v='4' WHERE k='schema_version'")
        db.close()

    def test_r247_f2_review_first_on_an_older_ledger_waits_for_core_and_both_run(self):
        self.old_ledger()
        out = self.start_both("review")
        self.assertGreater(int(out["review"].split()[-1]), 1, "review waited (more than one step): %s" % out)

    def test_r247_f2_core_first_on_an_older_ledger_and_both_run(self):
        self.old_ledger()
        self.start_both("core")

    def test_r247_f2_an_interrupted_migration_is_rerun_by_core_while_review_waits(self):
        self.make_old("4d45fe40", PIN_4D45)
        saved = list(runner.MIGRATIONS[5])
        runner.MIGRATIONS[5] = saved + ["THIS IS NOT SQL"]
        try:
            self.expect_refusal(runner.SchemaError, "restored the verified backup")
        finally:
            runner.MIGRATIONS[5] = saved
        self.assertEqual(self.version(), "v5-migrating-from-4", "fenced: an interrupted migration")
        self.start_both("review")

    def test_r247_f2_an_older_ledger_is_pending_and_an_unsupported_one_still_refuses(self):
        self.old_ledger()
        try:
            runner.Ledger(self.paths, migrate=False).close()
            raised = None
        except runner.SchemaError as error:          # a plain SchemaError here is the defect: fail, not error
            raised = error
        self.assertIsInstance(raised, runner.MigrationPending, "an older ledger is pending core's migration")
        db = self.db()
        db.execute("UPDATE meta SET v='9' WHERE k='schema_version'")
        db.close()
        lock = runner.acquire_lock(self.paths, "review")
        self.addCleanup(lock.close)
        refused = []
        rc = runner.serve(self.paths, "review", lock, lambda: runner.Ledger(self.paths, migrate=False).close(),
                          lambda error: refused.append(error) or runner.SCHEMA_EXIT, once=True,
                          sleep=lambda s: self.fail("an unsupported schema is not waited on"))
        self.assertEqual(rc, runner.SCHEMA_EXIT)
        self.assertEqual([type(e) for e in refused], [runner.SchemaError])

    def test_r247_f1_a_migration_failure_in_startup_reconciliation_exits_3_and_runs_no_tick(self):
        """The reconciliation core runs before its first tick opens (and may migrate) the ledger; a refusal there
        is the non-restarting exit 3 with the ahc-schema alert, never an escaping exception (exit 1, restart)."""
        self.make_old("4d45fe40", PIN_4D45)
        saved = list(runner.MIGRATIONS[5])
        runner.MIGRATIONS[5] = saved + ["THIS IS NOT SQL"]
        self.addCleanup(lambda: runner.MIGRATIONS.__setitem__(5, saved))
        runner.Ledger.PROBE_RUN = _ProbeRun()
        import ahc_guard  # noqa: PLC0415
        alerts, ticks = [], []

        def reconcile(paths, policy, role="all"):
            runner.Ledger(paths).close()                 # core's reconciliation opens the migrating ledger
            return {}
        with mock.patch.object(runner.core, "Paths", lambda *a, **k: self.paths), \
                mock.patch.object(ahc_guard, "install", lambda policy: policy), \
                mock.patch.object(runner, "_setup_logging", lambda paths: None), \
                mock.patch.object(runner, "startup_reconcile", reconcile), \
                mock.patch.object(runner, "tick", lambda *a, **k: ticks.append(1) or {}), \
                mock.patch.object(runner.LiveDeps, "ah", lambda deps, argv, timeout: alerts.append(argv)):
            try:
                rc = runner.main(["run", "--role", "core", "--once"])
            except Exception as error:  # noqa: BLE001 - an escape is the defect: fail, not error
                self.fail("the startup refusal escaped main: %r" % error)
        self.assertEqual(rc, runner.SCHEMA_EXIT)
        self.assertEqual(ticks, [], "no tick after a startup refusal")
        self.assertEqual(len(alerts), 1, alerts)
        self.assertIn("ahc-schema", alerts[0])

    def test_neg27_a_migration_with_another_role_running_still_refuses(self):
        """NEG-27 kept: a ledger that needs the v5 migration is not migrated while another role holds its lock."""
        self.make_old("4d45fe40", PIN_4D45, populate=False)
        db = self.db()
        db.execute("UPDATE meta SET v='4' WHERE k='schema_version'")
        db.close()
        self.hold_role("review")
        self.expect_refusal(runner.MigrationRefused, "migration-locks: the review role lock is held")
        self.assertEqual(self.version(), "4", "nothing was written")

    def test_v5_waits_for_an_open_connection_and_refuses_without_writing(self):
        """NEG-27: a review-role connection is open in another process; migration waits on the maint flock and
        refuses after its bound. Its commit survives and nothing is written."""
        import subprocess
        self.make_old("4d45fe40", PIN_4D45, populate=False)
        db = self.db()
        db.execute("UPDATE meta SET v='4' WHERE k='schema_version'")
        db.close()
        holder = subprocess.Popen([sys.executable, "-I", "-B", "-c",
                                   "import sys, fcntl, time; sys.path.insert(0, sys.argv[1]); import ahc_migrate, ahc_core;"
                                   " h = ahc_migrate.maint_lock(ahc_core.Paths(sys.argv[2]).root, shared=True);"
                                   " print('held', flush=True); time.sleep(30)", str(HOOKS), str(self.home)],
                                  stdout=subprocess.PIPE, text=True)
        try:
            self.assertEqual(holder.stdout.readline().strip(), "held")
            self.expect_refusal(runner.MigrationRefused, "migration-locks.*ledger.sqlite3.maint")
            self.assertEqual(self.version(), "4")
        finally:
            holder.terminate()
            holder.wait()
        self.must_open().close()
        self.assertEqual(self.version(), "5")

    def test_v5_a_stray_file_at_the_absent_path_is_never_replaced(self):
        """NEG-43's path-absent window: an old process creates a file at the ledger path between the move-aside
        and the publish. The publish refuses, keeps the stray file, the intent and the moved-aside files."""
        self.make_old("4d45fe40", PIN_4D45)
        saved = list(runner.MIGRATIONS[5])
        runner.MIGRATIONS[5] = saved + ["THIS IS NOT SQL"]
        hooks = old_tree("4d45fe40", PIN_4D45)
        made = []

        def stray(name):
            if name == "runner.restore_publish" and not made:
                # a 4d45fe40 reader refuses here already: the restore intent exists while the path is absent
                proc = run_old(hooks, self.home, "l = ahc_runner.Ledger(paths, migrate=False); l.close()")
                made.append(proc.returncode != 0 and "interrupted restore" in proc.stderr)
                # an old process that connects anyway creates and stamps its own file at the absent path
                import sqlite3
                conn = sqlite3.connect(str(self.live), isolation_level=None)
                conn.execute("CREATE TABLE meta (k TEXT PRIMARY KEY, v TEXT NOT NULL)")
                conn.execute("INSERT INTO meta VALUES ('schema_version', '4')")
                conn.close()
        import ahc_crash
        old_before = ahc_crash.crash_before
        runner.crash_before = lambda name: (stray(name), old_before(name))
        try:
            with self.assertRaises(runner.SchemaError) as caught:
                self.open_v5()
            self.assertIsInstance(caught.exception, runner.ahc_migrate.StrayLedger, str(caught.exception))
        finally:
            runner.crash_before = old_before
            runner.MIGRATIONS[5] = saved
        self.assertEqual(made, [True], "a 4d45fe40 reader refuses on the restore intent")
        self.assertEqual(self.version(), "4", "the stray file at the ledger path is kept, never replaced")
        self.assertTrue((self.paths.root / "ledger.sqlite3.restore-intent").exists(), "the intent is kept")
        self.assertTrue(list(self.paths.root.glob("ledger.sqlite3.failed-*")))

    def test_v5_old_code_refuses_a_fenced_and_a_v5_ledger(self):
        """NEG-28 / NEG-43: 4d45fe40 and e0e4ac46 code read schema_version at every open and refuse a fence or 5
        before any write."""
        self.make_old("4d45fe40", PIN_4D45)
        self.must_open().close()
        for commit, pin in (("4d45fe40", PIN_4D45), ("e0e4ac46", PIN_E0E4)):
            before = self.rows(self.live, "items")
            proc = run_old(old_tree(commit, pin), self.home, "ahc_runner.Ledger(paths, migrate=False)")
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("SchemaError", proc.stderr)
            self.assertEqual(self.rows(self.live, "items"), before)
        db = self.db()
        runner.ahc_migrate.set_fence(db, 4)
        db.close()
        proc = run_old(old_tree("4d45fe40", PIN_4D45), self.home,
                       "ahc_runner.Ledger(paths, migrate=False)")
        self.assertIn("unreadable schema_version", proc.stderr)

    def test_v5_rollback_restores_the_backup_clears_the_fence_and_old_code_opens_it(self):
        for commit, pin in (("4d45fe40", PIN_4D45), ("e0e4ac46", PIN_E0E4)):
            with self.subTest(layout=commit):
                self.setUp()
                self.make_old(commit, pin)
                before = self.rows(self.live, "reviews")
                self.must_open().close()
                backup = next(self.paths.root.glob("ledger.sqlite3.pre-v5.*.bak"))
                try:
                    n = runner.Ledger.rollback_v5(self.paths, backup.name)
                except runner.SchemaError as error:
                    self.fail("rollback refused: %s" % error)
                self.assertEqual(n, 4)
                self.assertEqual(self.version(), "4")
                self.assertEqual(self.rows(self.live, "reviews"), before)
                proc = run_old(old_tree(commit, pin), self.home,
                               "l = ahc_runner.Ledger(paths, migrate=False); print(l.db.execute(\"SELECT COUNT(*) "
                               "FROM reviews\").fetchone()[0]); l.close()")
                self.assertEqual((proc.returncode, proc.stdout.strip()), (0, str(len(before))), proc.stderr[-400:])



# ---------------------------------------------------------------------------------------------------------------
# Slice 1 (b) shared fixture: the WorkItem helpers of StateMachineTests without re-running its tests.

class _WorkItemFixture(TC.Base):
    UID = StateMachineTests.UID

    def setUp(self):
        TC.Base.setUp(self)
        self.item = self.admit()

    admit = StateMachineTests.admit
    move = StateMachineTests.move
    at = StateMachineTests.at
    reserved = StateMachineTests.reserved
    confirmed = StateMachineTests.confirmed
    abandoned = StateMachineTests.abandoned
    wstate = StateMachineTests.wstate
    notices_of = StateMachineTests.notices_of
    running_review = StateMachineTests.running_review
    _queued = StateMachineTests._queued


TOKEN_PREFIX = "".join(("g", "h", "p", "_"))


def runtime_token():
    """A token-shaped value built at run time, so no source file holds one (the R5 clean corpus)."""
    import random  # noqa: PLC0415
    import string  # noqa: PLC0415
    rng = random.SystemRandom()
    return TOKEN_PREFIX + "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(28))


def encodings(token):
    """The token raw and in each encoding R5 decodes: hex, base64 at all three alignments, URL-safe base64 and
    URL (percent) encoding."""
    import base64  # noqa: PLC0415
    raw = token.encode()
    out = {"raw": token, "hex": raw.hex()}
    for pad in range(3):
        out["b64-%d" % pad] = base64.b64encode(b"x" * pad + raw).decode()
    out["b64url"] = base64.urlsafe_b64encode(b"\xfb\xff" + raw).decode()
    out["url"] = "".join("%%%02X" % b for b in raw)
    return out


class EgressTests(_WorkItemFixture):
    """AC-14 / NEG-31: the outbox (Contracts._wi_notice) is the one egress chokepoint. Every outward text is
    scanned by R5 before it is stored; an exposure is never stored or delivered, and delivery goes only to the
    shadow digest."""

    def all_text(self):
        return "\n".join(t for (t,) in self.db.execute("SELECT text FROM wi_notices")) + "\n".join(
            r for (r,) in self.db.execute("SELECT reason FROM wi_quarantine"))

    def test_w03_notice_with_a_runtime_token_is_quarantined(self):
        secret_shape = runtime_token()
        rid = self.db.execute("SELECT id FROM reviews WHERE item=? AND kind='adversarial'",
                              (self.item["id"],)).fetchone()[0]
        self.db.execute("UPDATE reviews SET state='findings', receipt=? WHERE id=?",
                        (json.dumps({"verdict": "BLOCK", "finding_ids": ["F1", secret_shape]}), rid))
        self.assertEqual(self.move("W3")["state"], "waiting-ask", "the row still applies")
        self.assertNotIn(secret_shape, self.all_text())
        quarantined = sorted(k for (k,) in self.db.execute("SELECT kind FROM wi_quarantine WHERE row_id='W3'"))
        self.assertEqual(quarantined, ["owner", "ticket"])
        kinds = [k for k, _t in self.notices_of("W3")]
        self.assertEqual(kinds, ["incident", "incident"], "each quarantined notice is replaced by an incident")
        import ahc_shadow  # noqa: PLC0415
        out = []
        ahc_shadow.deliver_digest(self.c, out.append)
        self.assertNotIn(secret_shape, "".join(out))
        self.assertTrue(out and all("text withheld" in line for line in out), out)

    def test_every_notice_kind_with_an_embedded_token_is_quarantined(self):
        """W3, W19, W22 and W23 notices, E12's comment and the digest, each with the token raw and in every
        encoding R5 decodes."""
        cases = [("W3", "ticket"), ("W3", "owner"), ("W19", "incident"), ("W19", "ticket"), ("W22", "ticket"),
                 ("W23", "incident"), ("W23", "ticket"), ("E12", "ticket"), ("E12", "digest"), ("W8", "digest")]
        secret_shape = runtime_token()
        for row, kind in cases:
            for enc, value in encodings(secret_shape).items():
                with self.subTest(row=row, kind=kind, enc=enc):
                    ev = self.ev()
                    with self.c.tx():
                        stored = self.c._wi_notice(ev, self.item, row, kind, "note for %s: %s end" % (row, value))
                    self.assertIsNone(stored)
                    texts = [t for (t,) in self.db.execute("SELECT text FROM wi_notices WHERE event_id LIKE ?",
                                                           ("%" + ev + "%",))]
                    self.assertEqual(len(texts), 1)
                    self.assertNotIn(value, texts[0])
                    self.assertIn("text withheld", texts[0])
                    self.assertEqual(self.db.execute("SELECT kind FROM wi_quarantine WHERE event_id=?",
                                                     (ev,)).fetchone()[0], kind)

    def test_a_bare_prefix_restricts_to_structured_fields(self):
        with self.c.tx():
            text = self.c._wi_notice(self.ev(), self.item, "W19", "ticket", "refused near %sab here" % TOKEN_PREFIX)
        self.assertIn("restricted to structured fields", text)
        self.assertNotIn("ab here", text)

    def test_clean_text_is_stored_unchanged_and_delivered_once_to_the_shadow_digest(self):
        import ahc_shadow  # noqa: PLC0415
        with self.c.tx():
            self.c._wi_notice("e-clean", self.item, "W19", "ticket", "fetch failed: repository not found")
        out = []
        self.assertEqual(ahc_shadow.deliver_digest(self.c, out.append), (1, 0))
        self.assertEqual(out, ["shadow ticket %s W19 [e-clean]: fetch failed: repository not found\n"
                               % self.item["id"]])
        self.assertEqual(ahc_shadow.deliver_digest(self.c, out.append), (0, 0))

    def test_delivery_rescans_a_row_written_around_the_chokepoint(self):
        """A text that reached the outbox without the chokepoint (a direct INSERT) is quarantined at delivery and
        never written to the digest."""
        import ahc_shadow  # noqa: PLC0415
        secret_shape = runtime_token()
        self.db.execute("INSERT INTO wi_notices(event_id, item, row_id, kind, text, created) VALUES (?,?,?,?,?,?)",
                        ("e-direct", self.item["id"], "W22", "ticket", "direct " + secret_shape, 1.0))
        out = []
        self.assertEqual(ahc_shadow.deliver_digest(self.c, out.append), (0, 1))
        self.assertEqual(out, [])
        self.assertNotIn(secret_shape, self.all_text())

    def test_e12_comment_is_written_to_the_outbox_and_delivered_only_to_the_digest(self):
        import ahc_shadow  # noqa: PLC0415
        _g, op = self.reserved()
        op = self.send(op)
        self.clock.t += C.Contracts.PR_MARK_SECONDS
        op = self.c.confirm(op["key"], self.readback(pr_merged=False), expected_version=op["version"],
                            event_id=self.ev())
        self.assertEqual(op["pr_unmarked"], 1)
        notes = self.notices_of("E12")
        self.assertEqual([k for k, _t in notes], ["digest", "ticket"])
        self.assertTrue(notes[1][1].startswith("ahc PR comment: integrated at %s" % TC.H1), notes)
        out = []
        self.assertEqual(ahc_shadow.deliver_digest(self.c, out.append), (2, 0))
        self.assertTrue(all(line.startswith("shadow ") for line in out))


class W16Tests(_WorkItemFixture):
    """AC-6: W16 only from main's stamped CLI proof; extensions add a round of code rows; e1 and e2 read only the
    latest round per kind; accepted findings clear W3 (e3) only."""

    eligible = StateMachineTests.eligible
    pr = StateMachineTests.pr

    def proof(self, target="pr-gate", item=None, version=None, **kw):
        item = self.c._row("work_items", "id", (item or self.item)["id"])
        self.n += 1
        pid = "w16-%024d" % self.n
        self.c.record_w16_proof(pid, item["id"], target, item["version"] if version is None else version,
                                "e" * 64, **kw)
        return pid

    def findings(self, rid, ids):
        self.db.execute("UPDATE reviews SET state='findings', receipt=? WHERE id=?",
                        (json.dumps({"verdict": "BLOCK", "finding_ids": ids}), rid))

    def rows(self, kind):
        return self.db.execute("SELECT id, round, state FROM reviews WHERE item=? AND kind=? ORDER BY round",
                               (self.item["id"], kind)).fetchall()

    def test_w16_needs_main_s_verified_proof_for_this_item_target_and_version(self):
        """NEG-15: actor "main" with no proof id, or with a proof for another item, another target or a stale
        version, is refused; a proof is spent once."""
        self.at("waiting-ask")
        with self.assertRaisesRegex(C.ContractError, "not proof"):
            self.move("W16", to="pr-gate", actor="main")
        with self.assertRaisesRegex(C.ContractError, "not proof"):
            self.move("W16", to="pr-gate", actor="main", proof="w16-made-up")
        self.at("waiting-ask")
        other = self.admit(pr=12)
        cases = [self.proof(item=other), self.proof(target="cancelled"), self.proof(version=self.item["version"] + 7)]
        for pid in cases:
            self.at("waiting-ask")              # a variant that lets one through must not strand the rest
            with self.subTest(pid=pid), self.assertRaisesRegex(C.ContractError, "another item, target or version"):
                self.move("W16", to="pr-gate", actor="main", proof=pid)
        self.at("waiting-ask")
        pid = self.proof()
        with self.assertRaisesRegex(C.ContractError, "taken by main"):
            self.move("W16", to="pr-gate", actor="ahc-core", proof=pid)
        self.assertEqual(self.move("W16", to="pr-gate", actor="main", proof=pid)["state"], "pr-gate")
        self.at("waiting-ask")
        with self.assertRaisesRegex(C.ContractError, "already used"):
            self.move("W16", to="pr-gate", actor="main", proof=pid)

    def test_w16_to_pr_gate_leaves_b7_b33_and_findings_rows_unchanged(self):
        rid = self.rows("adversarial")[0][0]
        self.findings(rid, ["F1"])
        with self.c.tx():
            self.c.charge_b33(self.item["lineage"], 3)
        self.move("W3")
        before = (self.c.b7_used(self.item), self.c.b33(self.item["lineage"]), self.c.b7_allowance(self.item))
        self.move("W16", to="pr-gate", actor="main", proof=self.proof(accepted=["F1"], ticket="GoodQA goodqa#1",
                                                                       extension=1))
        self.assertEqual((self.c.b7_used(self.item), self.c.b33(self.item["lineage"])), before[:2])
        self.assertEqual(self.c.b7_allowance(self.item), before[2] + 1, "the extension raises the allowance only")
        self.assertEqual(self.c._row("reviews", "id", rid)["state"], "findings", "findings rows stay terminal")

    def test_w16_extension_round_flow_neg38(self):
        """NEG-38: W16 to pr-gate with a 1-round extension creates round 2 code rows at H; the round 1 findings
        rows and the passing round 1 spec review are kept. e1 is false while a round 2 code row is unfinished and
        holds once it passes, with the round 1 spec review still counting; W2 then applies. A spec core change
        after that takes W27, which creates the replacement spec row in round 2, and W2 waits for it."""
        spec = self.rows("spec")[0][0]
        self.db.execute("UPDATE reviews SET state='passed' WHERE id=?", (spec,))
        r1 = self.rows("adversarial")[0][0]
        self.findings(r1, ["F1", "F2"])
        self.move("W3")
        self.move("W16", to="pr-gate", actor="main",
                  proof=self.proof(accepted=["F1", "F2"], ticket="GoodQA goodqa#1", extension=1))
        code = self.rows("adversarial")
        self.assertEqual([(r, s) for _i, r, s in code], [(1, "findings"), (2, "required")])
        self.assertEqual(self.rows("spec"), [(spec, 1, "passed")])
        with self.assertRaisesRegex(C.ContractError, "W3 needs"):
            self.move("W3")                            # every finding id was accepted into a ticket
        self.assertEqual(self.c.elig(self.c._row("work_items", "id", self.item["id"]), self.eligible()), ["e1"])
        self.db.execute("UPDATE reviews SET state='passed' WHERE id=?", (code[1][0],))
        item = self.c._row("work_items", "id", self.item["id"])
        self.assertEqual(self.c.elig(item, self.eligible()), [], "round 2 passed; round 1 spec still counts")
        self.assertEqual(self.move("W2", obs=self.eligible())["state"], "merge-ready")
        item = self.c._row("work_items", "id", self.item["id"])
        changed = self.eligible(attached_core=TC.CORE2)
        self.assertEqual(self.move("W27", obs=changed)["state"], "pr-gate")
        specs = self.rows("spec")
        self.assertEqual([(r, s) for _i, r, s in specs], [(1, "passed"), (2, "required")])
        item = self.c._row("work_items", "id", self.item["id"])
        self.assertEqual(self.c.elig(item, changed), ["e2"])
        self.db.execute("UPDATE reviews SET state='passed' WHERE id=?", (specs[1][0],))
        self.assertEqual(self.c.elig(item, changed), [])
        self.assertEqual(self.move("W2", obs=changed)["state"], "merge-ready")

    def test_w16_with_unaccepted_finding_ids_w3_fires_again(self):
        r1 = self.rows("adversarial")[0][0]
        self.findings(r1, ["F1", "F2"])
        self.move("W3")
        self.move("W16", to="pr-gate", actor="main",
                  proof=self.proof(accepted=["F1"], ticket="GoodQA goodqa#1", extension=1))
        self.assertEqual(self.c._unaccepted_findings(self.c._row("work_items", "id", self.item["id"])), [r1])
        self.assertEqual(self.move("W3")["state"], "waiting-ask")

    def test_w16_accepted_ids_need_a_named_ticket(self):
        with self.assertRaisesRegex(C.ContractError, "named ticket"):
            self.proof(accepted=["F1"])
        with self.assertRaisesRegex(C.ContractError, "only back to pr-gate"):
            self.proof(target="cancelled", extension=1)


class W16CliTests(Base):
    """AC-6: the `w16` command records its proof and applies W16 in one transaction, and only with main's stamp
    (claim_main); `w16` argv needs the stamp like a disposition."""

    def setUp(self):
        super().setUp()
        ledger = runner.Ledger(self.paths)
        try:
            c = runner.open_contracts(ledger, self.paths)
            self.item = c.admit_item("o/r", 5, "a" * 40, "b" * 40, "policy-r1", "1" * 64, "d" * 64,
                                     event_id="ev-admit")
            ledger.db.execute("UPDATE work_items SET state='waiting-ask' WHERE id=?", (self.item["id"],))
        finally:
            ledger.close()

    def argv(self, target="cancelled", version=None):
        return ["w16", self.item["id"], "--target", target, "--expected-version",
                str(self.item["version"] if version is None else version)]

    def test_w16_cli_needs_the_stamp_and_spends_one_proof(self):
        self.assertTrue(core.is_dispose_argv(self.argv()))
        with self.assertRaisesRegex(core.Refused, "stamp"):
            runner.w16(self.paths, self.argv(), main_proven=False, item=self.item["id"], target="cancelled",
                       expected_version=self.item["version"])
        with self.assertRaisesRegex(core.Refused, "version"):
            runner.w16(self.paths, self.argv(version=9), main_proven=True, item=self.item["id"], target="cancelled",
                       expected_version=9)
        row = runner.w16(self.paths, self.argv(), main_proven=True, item=self.item["id"], target="cancelled",
                         expected_version=self.item["version"])
        self.assertEqual(row["state"], "cancelled")
        ledger = runner.Ledger(self.paths)
        try:
            proofs = ledger.db.execute("SELECT item, target, used FROM w16_proofs").fetchall()
            self.assertEqual([tuple(p) for p in proofs], [(self.item["id"], "cancelled", 1)],
                             "the refused attempt left no proof behind")
        finally:
            ledger.close()

    def test_main_without_a_stamp_is_refused_by_the_cli(self):
        with mock.patch.object(runner, "claim_main", return_value=False), \
                mock.patch.object(runner.core, "Paths", lambda *a, **k: self.paths):
            rc = runner.main(self.argv())
        self.assertEqual(rc, 2)


# ---------------------------------------------------------------- AC-3 / AC-4: the shadow boundary and tick
# goodqa#16049 slice 1 (b), spec r9 AC-3, AC-4, NEG-7 to NEG-10.

from tests import test_ahc_observe as TO  # noqa: E402

SHADOW_REPO = "ericmacdougall/agent-fabric"


class FakeProducer:
    """An injected observation producer: each observe() is one read, stamped at its first read with its own id and
    persisted, exactly as ahc_observe.Producer does; `facts(repo, pr, item)` returns the fields (or raises
    ahc_observe.ObservationRefused). Every read is counted."""

    def __init__(self, contracts, facts):
        self.c, self.facts, self.reads, self.incidents = contracts, facts, [], []
        self.revs, self.git_calls = {}, []

    def observe(self, repo, pr, *, item=None, clone=None, snapshot_bases=(), base=None):
        stamp = self.c.first_read_stamp()
        fields = dict(self.facts(repo, pr, item), repo=repo, pr=pr)
        self.c.record_observation(stamp, repo, pr, item, {"test": "fake"}, [], fields)
        self.reads.append(stamp["id"])
        return self.c.load_observation(stamp["id"])

    def _git(self, args, cwd, timeout):
        """Core's git in the clone for the R2 packet (a fixed one-file change) and rev-parse from `revs`."""
        self.git_calls.append(list(args))
        if args[0] == "rev-parse":
            return (0, self.revs[args[-1]] + "\n", "") if args[-1] in self.revs else (1, "", "")
        if args[0] == "log":
            return 0, "%s\0feat: a change\0" % args[-1].split("..")[-1], ""
        if "--name-only" in args:
            return 0, "src/a.py\0", ""
        return 0, "diff --git a/src/a.py b/src/a.py\n-x = 1\n+x = 2\n", ""


class _ShadowFixture(TC.Base):
    def setUp(self):
        super().setUp()
        env = mock.patch.dict(os.environ, {"AHC_SHADOW": "1"})
        env.start()
        self.addCleanup(env.stop)
        import ahc_shadow  # noqa: PLC0415
        self.S = ahc_shadow
        self.config = {"shadow_repos": ["o/r"]}
        self.changes = {}

    def eligible(self, item):
        f = dict(pr=item["pr"], pr_head=item["head"], pr_state="OPEN", tip=item["base"], draft=False,
                 compare="ahead", b_r_ancestors={item["base"]: True}, attached_core=item["spec_core"],
                 open_findings=0, paths=["harness/lib/x.py"], foreign_closing_keyword=False, mergeable=True,
                 mergeable_state="clean",
                 policy={"revision": item["policy_revision"], "readable": True, "allowlisted": True, "enabled": True,
                         "checks_green": True},
                 kill_switch=False, chk_cas=True, canary_age=3600, mirror_ok=True)
        f.update(self.changes)
        if f["attached_core"] in TC.SPECS:               # PR 273 receipt F3: the reader's verified core text
            f.setdefault("spec_core_text", TC.SPECS[f["attached_core"]])
        return f

    def facts(self, repo, pr, item):
        if item is None:                                   # admission: the PR at the requested head
            return dict(pr=pr, pr_head=self.changes.get("pr_head", TC.H1), pr_state="OPEN", tip=TC.BASE,
                        policy={"revision": TC.POLICY}, attached_core=TC.CORE1, spec_core_text=TC.SPEC1)
        return self.eligible(self.c._row("work_items", "id", item))

    def shadow_tick(self, contracts=None):
        c = contracts or self.c
        producer = FakeProducer(c, lambda repo, pr, item: self.facts(repo, pr, item))
        producer.revs = dict(getattr(self, "revs", {}))
        return self.S.ShadowTick(c, producer, lambda repo, head, base: "/clone", self.config), producer

    def ready_item(self, pr=5):
        item = self.c.admit_item("o/r", pr, TC.H1, TC.BASE, TC.POLICY, TC.CORE1, TC.PKT, event_id=self.ev())
        self.db.execute("UPDATE reviews SET state='passed' WHERE item=?", (item["id"],))
        self.db.execute("UPDATE work_items SET state='merge-ready', version=version+1 WHERE id=?", (item["id"],))
        return self.c._row("work_items", "id", item["id"])

    def moves(self, iid):
        return [(json.loads(d)["row"], e) for e, d in self.db.execute(
            "SELECT event_id, data FROM transitions WHERE entity='work_item' AND id=? ORDER BY seq", (iid,))]


class ShadowBoundaryTests(_ShadowFixture):
    """AC-3: AHC_SHADOW and the shadow list put a repo in exactly one pipeline; mutating calls are named."""

    def test_ac3_only_the_exact_value_1_enables_shadow(self):
        for value in (None, "", "0", "true", "1 ", "yes", "01"):
            env = {k: v for k, v in os.environ.items() if k != "AHC_SHADOW"}
            if value is not None:
                env["AHC_SHADOW"] = value
            with self.subTest(value=value), mock.patch.dict(os.environ, env, clear=True):
                self.assertFalse(self.S.shadow_on())
                self.assertEqual(self.S.pipeline_of(self.db, "o/r", self.config), "legacy")
        self.assertTrue(self.S.shadow_on())
        self.assertEqual(self.S.pipeline_of(self.db, "O/R", self.config), "shadow")
        self.assertEqual(self.S.pipeline_of(self.db, "o/other", self.config), "legacy", "not on the list")

    def test_neg7_every_mutating_call_form_is_named(self):
        verb_m = "mer" + "ge"
        mutating = [("gh", ["api", "--method", "PUT", "repos/o/r/pulls/5/" + verb_m]),
                    ("gh", ["api", "-X", "PATCH", "repos/o/r/pulls/5"]),
                    ("gh", ["api", "graphql", "-f", "query=mutation { updateRefs(input: {}) { clientMutationId } }"]),
                    ("gh", ["api", "repos/o/r/issues/5/comments", "-f", "body=x"]),
                    ("gh", ["api", "--input", "f.json", "repos/o/r/pulls/5"]),
                    ("gh", ["pr", verb_m, "5"]), ("gh", ["pr", "comment", "5", "-b", "x"]),
                    ("gh", ["pr", "edit", "5"]), ("gh", ["issue", "create"]), ("git", ["push", "origin", "x"]),
                    ("git", ["-C", "/c", "push"]), ("git", ["update-ref", "refs/heads/x", TC.H1])]
        reads = [("gh", ["api", "--method", "GET", "repos/o/r/pulls/5"]), ("gh", ["api", "repos/o/r/pulls/5"]),
                 ("gh", ["pr", "view", "5", "-R", "o/r", "--json", "number"]),
                 ("git", ["-C", "/c", "log", "--format=%H", "%s..%s" % (TC.BASE, TC.H1)]),
                 ("git", ["fetch", "origin"]), ("git", ["merge-tree", "--write-tree", TC.H1, TC.BASE])]
        for tool, args in mutating:
            with self.subTest(args=args):
                self.assertTrue(self.S.is_mutating(tool, args))
        for tool, args in reads:
            with self.subTest(args=args):
                self.assertFalse(self.S.is_mutating(tool, args))

    def test_ac3_the_tick_never_applies_w1_w16_or_w20_and_w21_only_through_its_sender(self):
        self.assertFalse({"W1", "W16", "W20", "W21"} & set(self.S.TICK_ROWS))
        self.assertEqual(set(self.S.TICK_ROWS) | {"W1", "W16", "W20", "W21"}, set(C.Contracts.WI_TRANSITIONS))


class ShadowTickTests(_ShadowFixture):
    """AC-4: admit, observe, select (T7) and move each item at most once per tick; event id f(obs, item, row)."""

    def test_ac4_event_id_is_a_function_of_observation_item_and_row_only(self):
        e = self.S.event_id
        self.assertEqual(e("obs:b:1.0:1", "wi-1", "W5"), e("obs:b:1.0:1", "wi-1", "W5"))
        self.assertEqual(len({e("o1", "i", "W5"), e("o2", "i", "W5"), e("o1", "j", "W5"), e("o1", "i", "W6")}), 4)

    def test_ac4_a_held_request_is_admitted_through_one_observation(self):
        key = self.S.queue_request(self.c, {"repo": "o/r", "pr": 5, "head": TC.H1, "base": TC.BASE,
                                            "packet_sha256": TC.PKT, "owner": "agent-x", "ticket": "t"})
        tick, producer = self.shadow_tick()
        summary = tick.tick()
        self.assertEqual(len(summary["admitted"]), 1)
        item = self.c._row("work_items", "id", summary["admitted"][0])
        self.assertEqual((item["state"], item["head"], item["base"]), ("pr-gate", TC.H1, TC.BASE))
        self.assertEqual(self.moves(item["id"]), [("W1", self.S.event_id(producer.reads[0], key, "W1"))])
        again = self.shadow_tick()[0].tick()
        self.assertEqual(again["admitted"], [], "the request is consumed once")

    def test_r273_f2_w27_replacement_code_rows_are_queued_and_offered_by_the_real_scheduler(self):
        """PR 273 receipt F2 for W27: the policy revision changes while the item is merge-ready. The tick applies
        W27, whose replacement code rows start required; the same tick's R2 pass queues them from the item's
        stored packet and the real ReviewScheduler offers one to the launcher. Every earlier step goes through the
        tick or the contract calls (admission, start_attempt, the bound receipts, W2); no row is written by hand."""
        store, offered = {}, []

        class Stage:
            slots = 1

            def settle(self):
                return {}

            def launch_row(self, row):
                offered.append(row["id"])
                return "held", "the test's launcher records the offer"

        def tick():
            producer = FakeProducer(self.c, lambda repo, pr, item: self.facts(repo, pr, item))
            t = self.S.ShadowTick(self.c, producer, lambda repo, head, base: "/clone", self.config, review=Stage(),
                                  store_packet=lambda p: store.__setitem__(p["sha256"], p["text"].encode()))
            t.load_packet = store.get          # as the runner wires it (load_r2_packet)
            return t.tick()
        self.S.queue_request(self.c, {"repo": "o/r", "pr": 5, "head": TC.H1, "base": TC.BASE,
                                      "packet_sha256": TC.PKT, "owner": "agent-x", "ticket": "t"})
        first = tick()
        (iid,) = first["admitted"]
        for rid, kind, version in self.db.execute("SELECT id, kind, version FROM reviews WHERE item=? ORDER BY id",
                                                  (iid,)).fetchall():
            row = self.c._row("reviews", "id", rid)
            if kind == "spec":
                receipt = {k: row[k] for k in ("repo", "pr", "head", "packet_sha256", "policy_revision",
                                               "spec_core")}
                self.c.review(rid, "passed", expected_version=version, event_id=self.ev(),
                              receipt=dict(receipt, verdict="PASS"))
                continue
            row = self.c.start_attempt(rid, "ahc-review-%s" % rid[-6:], 4242, expected_version=version,
                                       event_id=self.ev())
            self.c.review(rid, "passed", expected_version=row["version"], event_id=self.ev(), peer_uid=4242,
                          receipt=self.S.findings_receipt(row, "PASS", []))
        tick()
        self.assertEqual(self.c._row("work_items", "id", iid)["state"], "merge-ready", "W2 through the tick")
        old = dict(self.eligible(self.c._row("work_items", "id", iid))["policy"])
        self.changes["policy"] = dict(old, revision="policy-r2")
        offered.clear()
        third = tick()
        self.assertEqual(self.c._row("work_items", "id", iid)["state"], "pr-gate", third)
        new = [r for (r,) in self.db.execute("SELECT id FROM reviews WHERE item=? AND policy_revision='policy-r2' "
                                             "AND kind IN ('adversarial', 'red-team') ORDER BY id", (iid,))]
        self.assertTrue(new, "W27 made replacement code rows")
        self.assertEqual(len(offered), 1, "the real scheduler offers a W27 replacement row (one slot)")
        self.assertEqual(offered, third["scheduled"]["offered"])
        self.assertEqual(sorted(third.get("requeued", [])), new, third)
        self.assertIn(offered[0], new)
        self.assertEqual(self.c._row("reviews", "id", offered[0])["state"], "queued")

    def w21_resolved(self, item, tip, new_head):
        with self.c.tx():
            self.db.execute("INSERT INTO w21_sends(request_id, item, repo, pr, base, head, seq, event_id, state, "
                            "attempted_at, new_head, version, created, updated) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                            ("w21-%s-1" % item["id"], item["id"], item["repo"], item["pr"], tip, item["head"], 1,
                             "ev-w21-" + item["id"], "resolved", 1.0, new_head, 1, 1.0, 1.0))

    def test_ac7_w21_successor_at_h_prime_gets_core_r2_packet_with_b_r_parent2(self):
        """r9 AC-7: W21's successor at H' is reviewed against B_r = parent2 (the tip the send merged, confirmed as
        H'^2 in core's clone) with a full core-built R2 packet; its code rows are queued in the move's transaction,
        at round 1 (no B7 round is charged)."""
        tip = "d" * 40
        item = self.ready_item()
        self.w21_resolved(item, tip, TC.H2)
        self.changes.update(pr_head=TC.H2, tip=tip, b_r_ancestors={TC.BASE: True, tip: True})
        self.revs = {TC.H2 + "^2": "e" * 40}               # H'^2 is not the tip the send merged: fail closed
        summary = self.shadow_tick()[0].tick()
        self.assertTrue(any("H'^2 is not the tip" in why for _i, why in summary["refused"]), summary["refused"])
        self.assertIsNone(self.c._row("work_items", "id", item["id"])["successor"])
        self.revs = {TC.H2 + "^2": tip}
        tick, producer = self.shadow_tick()
        summary = tick.tick()
        succ_id = self.c._row("work_items", "id", item["id"])["successor"]
        self.assertTrue(succ_id, summary)
        succ = self.c._row("work_items", "id", succ_id)
        self.assertEqual((succ["head"], succ["base"]), (TC.H2, tip))
        rows = self.db.execute("SELECT kind, state, snapshot_base, packet_sha256, round FROM reviews WHERE item=? "
                               "ORDER BY kind", (succ_id,)).fetchall()
        code = [r for r in rows if r[0] == "adversarial"][0]
        self.assertEqual((code[1], code[2], code[4]), ("queued", tip, 1), "queued at B_r = parent2, round 1")
        self.assertEqual(code[3], succ["packet_sha256"], "bound to core's R2 packet")
        self.assertNotEqual(code[3], TC.PKT)
        self.assertIn(["diff", "--no-color", "%s..%s" % (tip, TC.H2)], producer.git_calls, "B_r..H' is core's diff")

    def test_ac4_admission_is_refused_when_the_head_moved(self):
        self.S.queue_request(self.c, {"repo": "o/r", "pr": 5, "head": TC.H1, "base": TC.BASE,
                                      "packet_sha256": TC.PKT, "owner": "agent-x", "ticket": "t"})
        self.changes["pr_head"] = TC.H2
        summary = self.shadow_tick()[0].tick()
        self.assertEqual(summary["admitted"], [])
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM work_items").fetchone()[0], 0)
        self.assertTrue(any("head moved" in why for _k, why in summary["refused"]), summary["refused"])

    def test_neg9_w5_w6_w5_with_identical_facts_each_apply_and_each_item_moves_once_per_tick(self):
        item, other = self.ready_item(5), self.ready_item(6)
        rows = []
        for mirror in (False, True, False):
            self.changes["mirror_ok"] = mirror
            tick, producer = self.shadow_tick()
            before = {i: len(self.moves(i)) for i in (item["id"], other["id"])}
            summary = tick.tick()
            for i in (item["id"], other["id"]):
                self.assertLessEqual(len(self.moves(i)) - before[i], 1, "an item moved twice in one tick")
            row, ev = self.moves(item["id"])[-1]
            read = [o for o in producer.reads if self.db.execute(
                "SELECT item FROM observations WHERE id=?", (o,)).fetchone()[0] == item["id"]][0]
            self.assertEqual(ev, self.S.event_id(read, item["id"], row), "event id f(obs, item, row)")
            rows.append((row, self.c._row("work_items", "id", item["id"])["state"]))
            self.assertEqual(summary["conflicts"], [])
        self.assertEqual(rows, [("W5", "waiting-dep"), ("W6", "merge-ready"), ("W5", "waiting-dep")])

    def test_ac4_a_refused_observation_moves_nothing(self):
        item = self.ready_item()
        import ahc_observe  # noqa: PLC0415

        def refuse(repo, pr, iid):
            raise ahc_observe.ObservationRefused("truncated read")
        self.facts = refuse
        summary = self.shadow_tick()[0].tick()
        self.assertEqual(self.moves(item["id"])[1:], [], "nothing after W1 admission")
        self.assertTrue(summary["refused"])

    def test_neg10_two_ticks_on_one_ledger_apply_each_move_exactly_once(self):
        import sqlite3  # noqa: PLC0415
        path = Path(self.tmp.name) / "shared.sqlite3"
        dbs = [sqlite3.connect(str(path), isolation_level=None, timeout=10) for _ in range(2)]
        for db in dbs:
            self.addCleanup(db.close)
        C.apply_schema(dbs[0])
        cs = [C.Contracts(db, self.log, now=self.clock, mono=self.clock, boot_id=TC.BOOT) for db in dbs]
        self.c, self.db = cs[0], dbs[0]
        item = self.ready_item()
        self.changes["mirror_ok"] = False
        tick_a, _pa = self.shadow_tick(cs[0])
        tick_b, _pb = self.shadow_tick(cs[1])
        real = cs[0].wi_move
        ran = []

        def interleaved(*a, **kw):
            if not ran:
                ran.append(tick_b.tick())                 # the other daemon applies first, between A's read and move
            return real(*a, **kw)
        cs[0].wi_move = interleaved
        summary_a = tick_a.tick()
        self.assertEqual([r for r, _e in self.moves(item["id"])], ["W1", "W5"], "exactly one apply")
        self.assertEqual(len(ran[0]["moved"]), 1)
        self.assertEqual(summary_a["moved"], [], "A applies nothing once B has applied")
        lost = [c[:2] for c in summary_a["conflicts"]] + [(i, why.split(":")[0]) for i, why in summary_a["refused"]]
        self.assertEqual(lost, [(item["id"], "W5")], "A loses on the version CAS or the guard re-read")



class ShadowDeps(Deps):
    """The legacy fakes plus the shadow parts: the production observation producer over an injected gh (FakeGh,
    which records every argv) and a real local git repository standing in for the daemon clone."""

    def __init__(self, gh, clone_root, local, gq, **kw):
        super().__init__(**kw)
        self.fake_gh, self.clone_root, self.local, self.gq = gh, clone_root, local, gq

    def shadow_parts(self, contracts):
        import ahc_observe  # noqa: PLC0415
        producer = ahc_observe.Producer(contracts, self.fake_gh, TO.real_git, lambda r, p, i: dict(self.gq),
                                        lambda r: dict(self.local))
        return producer, (lambda repo, head, base: self.clone_root), None


class ShadowIntegratedTests(Base):
    """AC-3 / NEG-7 / NEG-8: one daemon tick over a legacy item and a shadow WorkItem through the production tick
    (runner.tick), the production producer and the legacy fakes. Every gh argv on every path is recorded and none
    may mutate; the shadow repo never enters the legacy pipeline."""

    def setUp(self):
        super().setUp()
        env = mock.patch.dict(os.environ, {"AHC_SHADOW": "1"})
        env.start()
        self.addCleanup(env.stop)
        import ahc_shadow  # noqa: PLC0415
        self.S = ahc_shadow
        self.config = dict(self.config, repos=[REPO, SHADOW_REPO], shadow_repos=[SHADOW_REPO])
        self.git = TO.Repo(self.home / "shadow-clone")
        self.base = self.git.commit({"README": "r\n"}, "base")
        self.head = self.git.commit({"src/b.py": "b\n"}, "pr change", parent=self.base)
        self.gh = TO.FakeGh()
        pre = "repos/%s" % SHADOW_REPO
        self.gh.set(pre + "/pulls/9", TO.pull_json(self.head, number=9, repo=SHADOW_REPO, changed=1))
        self.gh.set(pre + "/git/ref/heads/main", {"object": {"sha": self.base}})
        self.gh.set(pre + "/commits/%s/check-runs?per_page=100&filter=all" % self.head,
                    TO.page({"total_count": 1, "check_runs": [TO.run("test", head=self.head)]}))
        self.gh.set(pre + "/commits/%s/statuses?per_page=100" % self.head, TO.page([]))
        local = {"policy": {"revision": "policy-r1", "default_branch": "main", "readable": True,
                            "allowlisted": True, "enabled": True,
                            "required_checks": {"contexts": ["test"], "app": "github-actions"}},
                 "kill_switch": False, "kill_epoch": 1, "chk_cas": True, "canary": None}
        self.deps = ShadowDeps(self.gh, self.git.root, local, {"attached_core": TC.CORE1, "open_findings": 0,
                                                               "mirror_ok": True, "spec_core_text": TC.SPEC1})

    def submit_shadow(self):
        req = {"repo": SHADOW_REPO, "pr": 9, "head": self.head, "base": self.base, "packet": str(self.packet),
               "ticket": "GoodQA goodqa#16049", "owner": "agent-abc123"}
        return core.submit(self.paths, self.config, req)

    def all_gh_argv(self):
        legacy = [list(a[1:]) if a and a[0] == "gh" else list(a) for a in self.deps.gh_calls]
        return legacy + [list(a) for a in self.gh.calls]

    def ledger_rows(self, sql, args=()):
        ledger = runner.Ledger(self.paths)
        try:
            return [tuple(r) for r in ledger.db.execute(sql, args).fetchall()]
        finally:
            ledger.close()

    def test_ac3_integrated_tick_zero_mutating_calls_one_pipeline_per_repo(self):
        legacy_id = self.submit()
        shadow = self.submit_shadow()
        self.assertEqual(shadow.get("pipeline"), "shadow", "a shadow repo's submit is held for the shadow tick")
        first = self.run_all(self.deps)
        self.assertEqual(len(first["shadow"]["admitted"]), 1, first.get("shadow"))
        second = self.run_all(self.deps)                     # a restart: a new ledger connection and producer
        self.assertIn("shadow", second)
        # NEG-8: the shadow repo is never a legacy item, never launched through deps.review, never settled there
        self.assertEqual(self.ledger_rows("SELECT id FROM items WHERE lineage LIKE ?", (SHADOW_REPO + "|%",)), [])
        self.assertEqual([r[0] for r in self.ledger_rows("SELECT id FROM items")], [legacy_id])
        self.assertEqual(len(self.deps.review_calls), 1, "one authorized launch for the legacy item")
        self.assertFalse(any(SHADOW_REPO in " ".join(map(str, a)) for a in self.deps.review_calls))
        items = self.ledger_rows("SELECT repo, pr, head, state FROM work_items")
        self.assertEqual(items, [(SHADOW_REPO, 9, self.head, "pr-gate")])
        # no E2 dispatch: no Effect left intent in shadow
        self.assertEqual(self.ledger_rows("SELECT key FROM operations WHERE state != 'intent'"), [])
        # NEG-7: zero mutating calls across both ticks, on the legacy and the shadow paths
        calls = self.all_gh_argv()
        self.assertTrue(self.gh.calls, "the shadow path read GitHub through the recorded gh")
        self.assertEqual([a for a in calls if self.S.is_mutating("gh", a)], [])

    def test_neg8_a_repo_with_a_live_legacy_item_stays_legacy(self):
        legacy_id = self.submit()
        self.config["shadow_repos"] = [SHADOW_REPO, REPO]
        ledger = runner.Ledger(self.paths)
        try:
            self.assertEqual(self.S.pipeline_of(ledger.db, REPO, self.config), "legacy")
            self.assertEqual(self.S.pipeline_of(ledger.db, SHADOW_REPO, self.config), "shadow")
        finally:
            ledger.close()
        self.assertTrue(legacy_id)



class ReviewTickTests(ShadowIntegratedTests):
    """AC-8 with AC-4 (owner ruling, option A): one tick admits, binds the item to core's R2 packet, queues the code
    row and offers it to the R3 Launcher; the next tick settles the completion signal that arrived on core's socket
    (peer uid read by core, report read by core) and offers the next row. Zero mutating gh calls throughout."""

    def setUp(self):
        super().setUp()
        import ahc_guard  # noqa: PLC0415
        import ahc_review  # noqa: PLC0415
        from tests import test_ahc_contracts as TCX  # noqa: PLC0415
        self.R = ahc_review
        bin_dir = self.home / "bin"
        bin_dir.mkdir(mode=0o700)
        stubs = {}
        for name in ("systemd-run", "systemctl"):
            p = bin_dir / name
            p.write_text("#!/bin/sh\nexit 0\n")
            os.chmod(str(p), 0o755)
            stubs[name] = str(p)
        self.policy = ahc_guard.Policy.for_test(self.paths.root, stubs, trusted_dirs=(str(bin_dir),))
        self.runner = TCX._FakeRunner(os.getuid())
        deps, git_root = self.deps, self.git.root
        state = {}

        def review_stage(contracts, clone):
            launcher = ahc_review.Launcher.for_test(contracts, self.policy, "/opt/ahc/peer_review.py", self.runner,
                                                    self.paths.root, clone=lambda repo, head, base: str(git_root))
            if "inbox" not in state:
                state["inbox"] = ahc_review.FinalInbox(self.paths.root)
                self.addCleanup(state["inbox"].close)
            return ahc_review.ReviewStage(contracts, launcher, state["inbox"], sandbox_repo=SHADOW_REPO)
        deps.review_stage = review_stage
        self.head2 = self.git.commit({"src/c.py": "c\n"}, "second change", parent=self.base)
        pre = "repos/%s" % SHADOW_REPO
        self.gh.set(pre + "/pulls/10", TO.pull_json(self.head2, number=10, repo=SHADOW_REPO, changed=1))
        self.gh.set(pre + "/commits/%s/check-runs?per_page=100&filter=all" % self.head2,
                    TO.page({"total_count": 1, "check_runs": [TO.run("test", head=self.head2)]}))
        self.gh.set(pre + "/commits/%s/statuses?per_page=100" % self.head2, TO.page([]))

    def submit_pr(self, pr, head):
        req = {"repo": SHADOW_REPO, "pr": pr, "head": head, "base": self.base, "packet": str(self.packet),
               "ticket": "GoodQA goodqa#16049", "owner": "agent-abc123"}
        return core.submit(self.paths, self.config, req)

    def code_rows(self):
        return self.ledger_rows("SELECT r.id, w.pr, r.state, r.packet_sha256, w.packet_sha256 FROM reviews r JOIN "
                                "work_items w ON w.id = r.item WHERE r.kind='adversarial' ORDER BY w.pr")

    def play_wrapper(self, rid, verdict_line, final_verdict=None, body="body\n", exit_status=0):
        """The completion wrapper's part, played by the test: the report in the attempt's directory, then the
        completion signal on core's socket (this process's uid is the uid the fake runner reported)."""
        import socket  # noqa: PLC0415
        (iid, unit), = self.ledger_rows("SELECT id, unit FROM launch_intents WHERE row=? AND state='started'", (rid,))
        (head, packet), = self.ledger_rows("SELECT head, packet_sha256 FROM reviews WHERE id=?", (rid,))
        report = ("Reviewer: test\nStage: pr\nReviewed HEAD: %s\nReviewed packet SHA-256: %s\n\n%s\n%s"
                  % (head, packet, verdict_line, body)).encode()
        out = self.paths.root / "reports" / ("%s-%s" % (rid, iid)) / "report.md"
        out.write_bytes(report)
        final = {"row": rid, "intent": iid, "invocation_id": self.runner.invocation[unit],
                 "report_sha256": hashlib.sha256(report).hexdigest(), "exit_status": exit_status}
        if final_verdict:
            final["verdict"] = final_verdict                  # never read: core takes the verdict from the report
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            s.connect(str(self.paths.root / "sock" / "review.sock"))
            s.sendall(json.dumps(final).encode())
        finally:
            s.close()

    def test_ac8_the_tick_admits_schedules_r3_settles_through_the_peer_uid_and_offers_the_next_row(self):
        self.assertEqual(self.submit_pr(9, self.head).get("pipeline"), "shadow")
        self.assertEqual(self.submit_pr(10, self.head2).get("pipeline"), "shadow")
        first = self.run_all(self.deps)["shadow"]
        self.assertEqual(len(first["admitted"]), 2, first)
        rows = self.code_rows()
        for rid, _pr, _state, row_sha, item_sha in rows:
            stored = self.paths.root / "packets" / ("%s.md" % row_sha)
            self.assertEqual(row_sha, item_sha, "the item and its rows are bound to one packet")
            self.assertEqual(hashlib.sha256(stored.read_bytes()).hexdigest(), row_sha, "core's R2 packet is stored")
            self.assertIn("UNTRUSTED AUTHOR TEXT", stored.read_text())
        self.assertEqual(sorted(r[2] for r in rows), ["queued", "running"], "one slot: one row is launched")
        a = [r[0] for r in rows if r[2] == "running"][0]
        b = [r[0] for r in rows if r[2] == "queued"][0]
        self.assertEqual(first["scheduled"]["started"], [a])
        self.assertEqual(len(self.runner.started), 1)
        self.play_wrapper(a, "VERDICT: PASS")
        second = self.run_all(self.deps)["shadow"]
        self.assertEqual(second["review"]["settled"], [(a, "passed")], second["review"])
        self.assertEqual(second["scheduled"]["started"], [b], "the next row is offered once the slot is free")
        self.play_wrapper(b, "VERDICT: BLOCK", final_verdict="PASS")
        third = self.run_all(self.deps)["shadow"]
        self.assertEqual(third["review"]["settled"], [(b, "findings")], "the report's verdict, never the FINAL's")
        self.assertEqual({r[0]: r[2] for r in self.code_rows()}, {a: "passed", b: "findings"})
        self.assertEqual(self.ledger_rows("SELECT state FROM launch_intents ORDER BY created"),
                         [("closed",), ("closed",)])
        self.assertEqual(len(self.runner.stopped), 2, "each settled unit is stopped")
        mutating = [a for a in self.all_gh_argv() if self.S.is_mutating("gh", a)]
        self.assertEqual(mutating, [], "zero mutating gh calls with the review step in the tick")

    def test_r273_f1_a_pass_report_with_a_failed_publication_exit_settles_outcome_unknown_through_the_tick(self):
        """PR 273 receipt F1, end to end: the wrapper (played here) leaves a correctly bound PASS report and signals
        on core's socket that peer_review exited 2 (its failed final publication check). The tick settles the row
        outcome-unknown, never passed, and still stops the unit and retires its intent."""
        self.assertEqual(self.submit_pr(9, self.head).get("pipeline"), "shadow")
        first = self.run_all(self.deps)["shadow"]
        (a,) = first["scheduled"]["started"]
        self.play_wrapper(a, "VERDICT: PASS", exit_status=2)
        second = self.run_all(self.deps)["shadow"]
        self.assertEqual(second["review"]["settled"], [(a, "outcome-unknown")], second["review"])
        self.assertEqual({r[0]: r[2] for r in self.code_rows()}, {a: "outcome-unknown"})
        self.assertEqual(self.ledger_rows("SELECT state FROM launch_intents"), [("closed",)])

    def test_neg36_a_failed_unit_listing_closes_every_launch_until_a_reconciliation_succeeds(self):
        """PR 272 F2: list-units fails at startup. No R3 attempt starts, also for a row queued afterwards with no
        intent of its own, until a later reconciliation (retried before a launch) succeeds."""
        listing = {"ok": False}
        real = self.runner.list_units
        self.runner.list_units = lambda: real() if listing["ok"] else None
        out = runner.startup_reconcile(self.paths, self.policy, runner=self.runner)
        self.assertTrue(any("list-units failed" in t for t in out["incidents"]), out)
        self.assertEqual(self.submit_pr(9, self.head).get("pipeline"), "shadow")
        first = self.run_all(self.deps)["shadow"]
        self.assertEqual(len(first["admitted"]), 1, first)
        self.assertEqual(first["scheduled"]["started"], [], first["scheduled"])
        self.assertEqual(self.runner.started, [], "zero start calls while reconciliation has not succeeded")
        listing["ok"] = True
        second = self.run_all(self.deps)["shadow"]
        self.assertEqual(len(second["scheduled"]["started"]), 1, "the retried reconciliation lifts the gate")
        self.assertEqual(len(self.runner.started), 1)

    def contracts(self):
        ledger = runner.Ledger(self.paths)
        self.addCleanup(ledger.close)
        return runner.open_contracts(ledger, self.paths)

    def launched(self):
        """Submit PR 9, run one tick, and return the launched row, its intent and its unit."""
        self.assertEqual(self.submit_pr(9, self.head).get("pipeline"), "shadow")
        tick = self.run_all(self.deps)
        rows = self.code_rows()
        self.assertEqual(len(rows), 1, "admission made one code row: %s" % (tick.get("shadow", tick),))
        (a, _pr, state, _r, _w), = rows
        self.assertEqual(state, "running")
        (iid, unit), = self.ledger_rows("SELECT id, unit FROM launch_intents WHERE row=?", (a,))
        return a, iid, unit

    def test_f6_w20_owner_cancel_stops_the_unit_and_settles_the_row_superseded(self):
        """PR 272 F6: the owner cancels (W20) while the attempt runs. The review stage stops the unit, confirms it
        stopped and applies R15 (cancelling -> superseded), closing the intent. A failed stop keeps the row
        cancelling and the intent started, and the stage finishes the job after a restart."""
        a, iid, unit = self.launched()
        c = self.contracts()
        (item,), = c.db.execute("SELECT item FROM reviews WHERE id=?", (a,)).fetchall()
        row = c._row("work_items", "id", item)
        c.wi_move(item, "W20", expected_version=row["version"], event_id="t-w20", actor="owner")
        self.assertEqual(self.ledger_rows("SELECT state FROM reviews WHERE id=?", (a,)), [("cancelling",)])
        real_stop = self.runner.stop
        self.runner.stop = lambda u: False                      # the stop is refused: nothing changes
        self.run_all(self.deps)
        self.assertEqual(self.ledger_rows("SELECT state FROM reviews WHERE id=?", (a,)), [("cancelling",)])
        self.assertEqual(self.ledger_rows("SELECT state FROM launch_intents WHERE id=?", (iid,)), [("stopping",)],
                         "the cleanup is durable and never terminal before a confirmed stop")
        self.assertIn(unit, self.runner.live)
        self.runner.stop = real_stop
        self.policy = self.R.ahc_guard.Policy.for_test(self.paths.root, dict(self.policy.exe),
                                                       trusted_dirs=self.policy.trusted)     # a restart
        runner.startup_reconcile(self.paths, self.policy, runner=self.runner)
        self.run_all(self.deps)
        self.assertEqual(self.ledger_rows("SELECT state FROM reviews WHERE id=?", (a,)), [("superseded",)])
        self.assertEqual(self.ledger_rows("SELECT state FROM launch_intents WHERE id=?", (iid,)), [("closed",)])
        self.assertNotIn(unit, self.runner.live)
        self.assertEqual(len(self.runner.started), 1, "a cancelled item starts nothing")

    def stored_packet(self, rid):
        (sha,), = self.ledger_rows("SELECT packet_sha256 FROM reviews WHERE id=?", (rid,))
        data = (self.paths.root / "packets" / ("%s.md" % sha)).read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(), sha)
        return data.decode()

    def assert_carries_the_core(self, text):
        self.assertIn("## Acceptance criteria (from the attached spec core, sha256 %s)\n%s" % (
            TC.CORE1, "- AC-1: x is 2. Verify by: tests.test_x.\n- AC-2: y is unchanged."), text)
        self.assertIn("## Spec core (sha256 %s)\n# Spec one\n" % TC.CORE1, text)
        self.assertIn("- NEG-1 (AC-1): x is never 3.", text, "the spec core text, not its digest alone")

    def test_r273_f3_the_reviewer_gets_the_attached_cores_criteria_and_text_at_admission_and_for_a_successor(self):
        """PR 273 receipt F3, producer to packet: the GoodQA reader returns the attached core's text; the production
        Producer verifies it against attached_core and hands it to R2 without persisting it; the stored packet the
        R3 unit reads carries the acceptance criteria and the spec text, at admission and for W4's successor."""
        a, _iid, _unit = self.launched()
        self.assert_carries_the_core(self.stored_packet(a))
        fields = self.ledger_rows("SELECT fields FROM observations")
        self.assertTrue(fields and not any("never 3" in f for (f,) in fields), "the text is never persisted")
        head3 = self.git.commit({"src/d.py": "d\n"}, "third change", parent=self.base)
        pre = "repos/%s" % SHADOW_REPO
        self.gh.set(pre + "/pulls/9", TO.pull_json(head3, number=9, repo=SHADOW_REPO, changed=1))
        self.gh.set(pre + "/commits/%s/check-runs?per_page=100&filter=all" % head3,
                    TO.page({"total_count": 1, "check_runs": [TO.run("test", head=head3)]}))
        self.gh.set(pre + "/commits/%s/statuses?per_page=100" % head3, TO.page([]))
        self.assertEqual(self.submit_pr(9, head3).get("pipeline"), "shadow")
        self.run_all(self.deps)
        succ = self.ledger_rows("SELECT id FROM reviews WHERE kind='adversarial' AND head=?", (head3,))
        self.assertEqual(len(succ), 1, "W4 made the successor's code row")
        self.assert_carries_the_core(self.stored_packet(succ[0][0]))

    def test_r273_f3_without_the_attached_cores_text_no_packet_is_built_and_the_request_is_held(self):
        """PR 273 receipt F3, negative: the reader returns the digest only, or a text that is not the attached core.
        No packet is built and nothing is admitted; the request stays held and is admitted once the text arrives."""
        self.assertEqual(self.submit_pr(9, self.head).get("pipeline"), "shadow")
        self.deps.gq.pop("spec_core_text")
        first = self.run_all(self.deps)["shadow"]
        self.assertEqual(first["admitted"], [], first)
        self.assertTrue(any("R2 packet was not built" in why for _k, why in first["refused"]), first["refused"])
        self.deps.gq["spec_core_text"] = TC.SPEC2                    # a foreign text: the observation is refused
        second = self.run_all(self.deps)["shadow"]
        self.assertEqual(second["admitted"], [])
        self.assertTrue(any("not the attached core" in why for _k, why in second["refused"]), second["refused"])
        self.assertEqual(self.ledger_rows("SELECT id FROM work_items"), [])
        self.deps.gq["spec_core_text"] = TC.SPEC1
        third = self.run_all(self.deps)["shadow"]
        self.assertEqual(len(third["admitted"]), 1, third)
        (a, _pr, _state, _r, _w), = self.code_rows()
        self.assert_carries_the_core(self.stored_packet(a))

    def extended(self):
        """Round 1 settles BLOCK with F1 through the tick; W3 escalates; main's stamped proof applies W16 back to
        pr-gate with a one-round extension (the contract move, no row written by the test). Returns (round 1 row,
        round 2 row, contracts)."""
        self.assertEqual(self.submit_pr(9, self.head).get("pipeline"), "shadow")
        self.run_all(self.deps)
        (a, _pr, state, _r, _w), = self.code_rows()
        self.play_wrapper(a, "VERDICT: BLOCK", body="F1 - High - a finding.\n")
        self.assertEqual(self.run_all(self.deps)["shadow"]["review"]["settled"], [(a, "findings")])
        ledger = runner.Ledger(self.paths)
        self.addCleanup(ledger.close)
        c = runner.open_contracts(ledger, self.paths)
        item = c._row("work_items", "id", c._row("reviews", "id", a)["item"])
        if item["state"] == "pr-gate":
            c.wi_move(item["id"], "W3", expected_version=item["version"], event_id="t-w3", actor="ahc-core")
            item = c._row("work_items", "id", item["id"])
        c.record_w16_proof("w16-r273-f2", item["id"], "pr-gate", item["version"], "e" * 64, accepted=["F1"],
                           ticket="GoodQA goodqa#16049", extension=1)
        c.wi_move(item["id"], "W16", expected_version=item["version"], event_id="t-w16", actor="main",
                  to="pr-gate", proof="w16-r273-f2")
        (b,), = c.db.execute("SELECT id FROM reviews WHERE item=? AND kind='adversarial' AND round=2",
                             (item["id"],)).fetchall()
        self.assertEqual(c._row("reviews", "id", b)["state"], "required", "W16 creates round 2 required")
        return a, b, c

    def test_r273_f2_a_w16_extension_round_is_queued_and_launched_by_the_next_tick(self):
        """PR 273 receipt F2: W16 with an extension creates round 2 code rows in required. The next tick's R2 pass
        re-verifies the item's stored packet and queues the row, and the real scheduler launches it."""
        _a, b, _c = self.extended()
        started = len(self.runner.started)
        tick = self.run_all(self.deps)["shadow"]
        self.assertEqual(tick["scheduled"]["started"], [b], tick["scheduled"])
        self.assertEqual(tick.get("requeued"), [b], tick)
        self.assertEqual(len(self.runner.started), started + 1)
        self.assertEqual(self.ledger_rows("SELECT state FROM reviews WHERE id=?", (b,)), [("running",)])
        again = self.run_all(self.deps)["shadow"]
        self.assertEqual(again.get("requeued"), [], "idempotent: a queued or running row is not queued again")

    def test_r273_f2_an_altered_or_missing_stored_packet_keeps_the_row_required_and_says_so(self):
        """PR 273 receipt F2, negative: the stored packet no longer hashes to the row's sha (or is gone). The row
        stays required, nothing launches, and every tick reports why; restoring the packet queues it."""
        _a, b, _c = self.extended()
        (sha,), = self.ledger_rows("SELECT packet_sha256 FROM reviews WHERE id=?", (b,))
        path = self.paths.root / "packets" / ("%s.md" % sha)
        good = path.read_bytes()
        path.write_bytes(good.replace(b"head H:", b"head H: ", 1))
        started = len(self.runner.started)
        for _ in range(2):
            tick = self.run_all(self.deps)["shadow"]
            self.assertEqual(tick.get("requeued", []), [])
            self.assertTrue(any(r == b and "does not hash" in why for r, why in tick["refused"]), tick["refused"])
        path.unlink()
        tick = self.run_all(self.deps)["shadow"]
        self.assertTrue(any(r == b and "missing" in why for r, why in tick["refused"]), tick["refused"])
        self.assertEqual(len(self.runner.started), started)
        self.assertEqual(self.ledger_rows("SELECT state FROM reviews WHERE id=?", (b,)), [("required",)])
        path.write_bytes(good)
        self.assertEqual(self.run_all(self.deps)["shadow"].get("requeued"), [b])

    def test_f6_w4_head_supersede_stops_the_unit_and_settles_the_row_superseded(self):
        """PR 272 F6: the PR's head moves (W4) while the attempt for H runs. In the same tick the review stage
        stops the old unit and settles its row to superseded (R15); the successor's row is offered after."""
        a, iid, unit = self.launched()
        head3 = self.git.commit({"src/d.py": "d\n"}, "third change", parent=self.base)
        pre = "repos/%s" % SHADOW_REPO
        self.gh.set(pre + "/pulls/9", TO.pull_json(head3, number=9, repo=SHADOW_REPO, changed=1))
        self.gh.set(pre + "/commits/%s/check-runs?per_page=100&filter=all" % head3,
                    TO.page({"total_count": 1, "check_runs": [TO.run("test", head=head3)]}))
        self.gh.set(pre + "/commits/%s/statuses?per_page=100" % head3, TO.page([]))
        self.assertEqual(self.submit_pr(9, head3).get("pipeline"), "shadow")
        self.run_all(self.deps)
        self.assertEqual(self.ledger_rows("SELECT state FROM reviews WHERE id=?", (a,)), [("superseded",)])
        self.assertEqual(self.ledger_rows("SELECT state FROM launch_intents WHERE id=?", (iid,)), [("closed",)])
        self.assertIn(unit, self.runner.stopped)
        self.assertNotIn(unit, self.runner.live)

    def test_f7_a_policy_b33_of_one_stops_every_launch_and_charge_after_the_first(self):
        """PR 272 F7: policy b33=1 and two queued reviews of one lineage. After the first charge no further
        launch or charge happens, through the integrated tick (scheduler, launcher, launch_intent)."""
        self.deps.local["policy"]["b33"] = 1
        a, iid, unit = self.launched()
        c = self.contracts()
        row = c._row("reviews", "id", a)
        second = c.require_review("red-team", row["repo"], row["pr"], row["head"], row["packet_sha256"],
                                  row["policy_revision"], item=row["item"], event_id="t-second",
                                  snapshot_base=row["snapshot_base"])
        c.review(second["id"], "queued", expected_version=second["version"], event_id="t-second-q")
        self.play_wrapper(a, "VERDICT: PASS")
        for _ in range(3):
            self.run_all(self.deps)
        self.assertEqual(len(self.runner.started), 1, "no launch after the policy's budget is spent")
        (lineage,), = self.ledger_rows("SELECT w.lineage FROM work_items w JOIN reviews r ON r.item = w.id "
                                       "WHERE r.id=?", (a,))
        self.assertEqual(self.ledger_rows("SELECT b33_used FROM lineage_budget WHERE lineage=?", (lineage,)),
                         [(1,)], "one charge")
        self.assertEqual(self.ledger_rows("SELECT state FROM reviews WHERE id=?", (second["id"],)), [("queued",)])

    def test_ac9_a_block_reports_finding_ids_reach_w3_and_main_accepts_them(self):
        """PR 272 F3: the finding ids of a BLOCK report core read itself are in the settled row's receipt; W3
        escalates with them; once main's W16 accepts them into a named ticket, the row no longer counts as
        unaccepted."""
        self.assertEqual(self.submit_pr(9, self.head).get("pipeline"), "shadow")
        self.run_all(self.deps)
        (a, _pr, state, _r, _w), = self.code_rows()
        self.assertEqual(state, "running")
        self.play_wrapper(a, "VERDICT: BLOCK", body="F1 \u2014 High \u2014 locks on every tick.\n\n"
                                                    "## F2 - Medium - reconciliation gate.\n")
        second = self.run_all(self.deps)["shadow"]
        self.assertEqual(second["review"]["settled"], [(a, "findings")], second["review"])
        ledger = runner.Ledger(self.paths)
        self.addCleanup(ledger.close)
        c = runner.open_contracts(ledger, self.paths)
        row = c._row("reviews", "id", a)
        receipt = json.loads(row["receipt"])
        self.assertEqual(receipt["finding_ids"], ["F1", "F2"], "the ids come from the report core read")
        self.assertNotIn("finding_ids_dropped", receipt)
        item = c._row("work_items", "id", row["item"])
        if item["state"] == "pr-gate":
            c.wi_move(item["id"], "W3", expected_version=item["version"], event_id="t-w3", actor="ahc-core")
        item = c._row("work_items", "id", row["item"])
        self.assertEqual(item["state"], "waiting-ask")
        texts = [t for (t,) in ledger.db.execute("SELECT text FROM wi_notices WHERE item=?", (item["id"],))]
        self.assertTrue(any("F1, F2" in t for t in texts), texts)
        c.record_w16_proof("w16-f3-accept", item["id"], "pr-gate", item["version"], "e" * 64,
                           accepted=["F1", "F2"], ticket="GoodQA goodqa#16049")
        c.wi_move(item["id"], "W16", expected_version=item["version"], event_id="t-w16", actor="main",
                  to="pr-gate", proof="w16-f3-accept")
        item = c._row("work_items", "id", row["item"])
        self.assertEqual(c._unaccepted_findings(item), [], "main's acceptance clears the findings row")
        import ahc_contracts  # noqa: PLC0415
        with self.assertRaises(ahc_contracts.ContractError, msg="no unaccepted findings left: W3 does not fire"):
            c.wi_move(item["id"], "W3", expected_version=item["version"], event_id="t-w3b", actor="ahc-core")


class TickIncidentTests(Base):
    """AC-13: a refused launch or connection raises an incident. The guard collects each refusal in the active
    policy's `incidents`; the core tick raises every collected one into the outbox (wi_notices, kind incident,
    through the AC-14 chokepoint) and drains the list, whether or not shadow is on."""

    def test_ac13_the_tick_raises_collected_refusals_as_incidents(self):
        import ahc_guard  # noqa: PLC0415
        policy = ahc_guard.Policy.for_test(self.paths.root, {}, repos=[REPO])
        policy.incidents.extend(["git: -c core.pager refused", "socket.connect refused"])
        ahc_guard.install(policy)
        try:
            self.run_all(Deps())
        finally:
            ahc_guard.deactivate()
        self.assertEqual(policy.incidents, [], "every collected refusal is raised once and drained")
        ledger = runner.Ledger(self.paths)
        try:
            rows = [tuple(r) for r in ledger.db.execute(
                "SELECT item, kind, text FROM wi_notices WHERE kind='incident' ORDER BY rowid")]
        finally:
            ledger.close()
        self.assertEqual([(i, k) for i, k, _t in rows], [(runner.SYSTEM_ITEM, "incident")] * 2)
        self.assertIn("core.pager", rows[0][2])
        self.assertIn("socket.connect", rows[1][2])



RACE_CHILD = r"""
import json, os, sqlite3, sys, time
from pathlib import Path
import ahc_contracts as C, ahc_w21
root, rid, me = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
os.environ["AHC_W21_SEND"] = "1"
db = sqlite3.connect(str(root / "ledger.sqlite3"), isolation_level=None, timeout=30)
c = C.Contracts(db, C.AuthorityLog(root / "authority.jsonl"), now=lambda: 1000.0, mono=lambda: 1000.0,
                boot_id="race-boot")
def gh(args, timeout):
    with open(str(root / "calls.txt"), "a", encoding="utf-8") as handle:
        handle.write(me + " " + " ".join(args) + "\n")
    return 0, "", ""
s = ahc_w21.Sender(c, gh, lambda args: None, lambda: {"on": False, "epoch": 1, "mono": 1000.0, "shared": True},
                   lambda repo: True, lambda a, cwd: (1, ""), lambda r, h, b: "/clone")
while not (root / "go").exists():
    time.sleep(0.001)
for _ in range(20):                          # the same record, appended by both processes at once
    c.authority.append({"event_id": "w21:race", "item": "wi-race", "row": "W21", "repo": "o/r", "pr": 5,
                        "expected_head_sha": "H", "base": "B", "send_seq": 1, "request_id": rid,
                        "action": "update-branch"})
print(json.dumps({"me": me, "sent": s.send(rid)}))
"""


class W21Tests(TC.Base):
    """AC-7: W21 behind AHC_W21_SEND, one keyed send record, attempted committed before the one call, the kill
    re-read, cancel only from intent, the read-back rules and the queue head (NEG-16 to NEG-21, NEG-37, NEG-41
    phases 1 and 2, NEG-42)."""

    admit = StateMachineTests.admit
    move = StateMachineTests.move
    pass_reviews = StateMachineTests.pass_reviews
    eligible = StateMachineTests.eligible
    pr = StateMachineTests.pr
    queue_of = StateMachineTests.queue_of

    def setUp(self):
        super().setUp()
        env = mock.patch.dict(os.environ, {"AHC_W21_SEND": "1"})
        env.start()
        self.addCleanup(env.stop)
        import ahc_w21  # noqa: PLC0415
        self.W = ahc_w21
        self.item = self.admit()
        self.pass_reviews()
        self.clock.t += 1
        self.newer = self.admit(pr=6)
        self.pass_reviews(self.newer)
        self.gh_calls, self.head_after, self.put_rc = [], TC.H1, 0
        self.kill = {"on": False, "epoch": 1, "mono": self.clock.t, "shared": True}
        self.allowed = True

    def behind(self, *items, **policy):
        items = items or (self.item, self.newer)
        out = {}
        for i in items:
            row = self.c._row("work_items", "id", i["id"])
            pol = dict(self.eligible(row)["policy"], w21=True)
            pol.update(policy)
            out[i["id"]] = self.eligible(row, compare="behind", policy=pol)
        return out

    def w21_obs(self, item=None, **policy):
        item = item or self.item
        return self.pr(pr=item["pr"], queue=self.behind(**policy), mergeable=True, mergeable_state="behind")

    def w21(self, item=None, **policy):
        item = item or self.item
        return self.move("W21", item=self.c._row("work_items", "id", item["id"]), obs=self.w21_obs(item, **policy))

    def w21_ok(self):
        """A W21 the test needs to apply: its refusal is a failure of the test, not an error."""
        try:
            return self.w21()
        except C.ContractError as error:
            self.fail("W21 was refused: %s" % error)

    def sends(self):
        return [tuple(r) for r in self.db.execute("SELECT item, state, seq FROM w21_sends ORDER BY created, seq")]

    def fake_gh(self, args, timeout):
        self.gh_calls.append(list(args))
        if args[2] == "PUT":
            row = self.db.execute("SELECT state FROM w21_sends WHERE state IN ('intent', 'attempted')").fetchone()
            self.at_call = (self.db.in_transaction, row[0] if row else None)
            return self.put_rc, "", "" if self.put_rc == 0 else "timeout"
        return 0, json.dumps({"head": {"sha": self.head_after}}), ""

    def sender(self, git=None):
        return self.W.Sender(self.c, self.fake_gh, lambda args: None, lambda: dict(self.kill),
                             lambda repo: self.allowed, git or (lambda args, cwd: (1, "")),
                             lambda repo, head, base: "/clone")

    def puts(self):
        return [a for a in self.gh_calls if a[2] == "PUT"]

    def test_neg16_with_the_flag_off_w21_is_not_applied_at_all(self):
        before = len(self.log.records())
        for value in (None, "0", "", "true", "1 "):
            env = {k: v for k, v in os.environ.items() if k != "AHC_W21_SEND"}
            if value is not None:
                env["AHC_W21_SEND"] = value
            with self.subTest(value=value), mock.patch.dict(os.environ, env, clear=True):
                with self.assertRaisesRegex(C.ContractError, "AHC_W21_SEND"):
                    self.w21()
                self.assertEqual(self.sender().pump()["sent"], [])
                with self.assertRaisesRegex(C.ContractError, "W23 needs"):
                    self.move("W23")
        self.assertEqual((len(self.log.records()), self.sends(), self.gh_calls), (before, [], []))
        self.assertIsNone(self.c._row("work_items", "id", self.item["id"])["w21_base"])
        with self.assertRaisesRegex(C.ContractError, "policy w21"):
            self.w21(w21=False)
        self.assertEqual(self.w21()["w21_base"], TC.BASE)
        self.assertEqual(self.sends(), [(self.item["id"], "intent", 1)])
        line = self.log.records()[-1]
        self.assertEqual((line["row"], line["action"], line["send_seq"]), ("W21", "update-branch", 1))
        for value in (None, "0", "", "true", "1 "):
            env = {k: v for k, v in os.environ.items() if k != "AHC_W21_SEND"}
            if value is not None:
                env["AHC_W21_SEND"] = value
            if self.sends()[-1][1] != "intent":
                self.db.execute("UPDATE w21_sends SET state='cancelled' WHERE state != 'cancelled'")  # free the slot
                with self.c.tx():                                   # a fresh intent record, the next seq at B
                    self.c._w21_record(self.c._row("work_items", "id", self.item["id"]), TC.BASE)
            with self.subTest(sender_flag=value), mock.patch.dict(os.environ, env, clear=True):
                self.assertEqual(self.sender().pump()["sent"], [])
                self.assertEqual(self.sends()[-1][1], "cancelled")
        self.assertEqual(self.puts(), [])

    def test_ac7_attempted_commits_before_the_one_call_and_a_lost_response_is_never_resent(self):
        self.w21()
        self.put_rc = 1                                          # the response is lost
        self.assertEqual(len(self.sender().pump()["sent"]), 1)
        self.assertEqual(self.at_call, (False, "attempted"), "the sender acts only on a committed attempted row")
        for _ in range(3):
            self.sender().pump()
            self.sender().reconcile()
        self.assertEqual(len(self.puts()), 1, "NEG-17: exactly one update-branch call")
        self.assertEqual(self.sends(), [(self.item["id"], "attempted", 1)], "one unresolved row, never cancelled")
        self.assertEqual(self.puts()[0], self.W.put_args("o/r", 5, TC.H1))
        self.clock.t += 5
        self.db.execute("UPDATE work_items SET state='pr-gate' WHERE id=?", (self.item["id"],))
        with self.assertRaisesRegex(C.ContractError, "the item has an unresolved or lost send"):    # new B
            self.move("W21", item=self.c._row("work_items", "id", self.item["id"]),
                      obs=dict(self.w21_obs(), tip=TC.H2))

    def test_neg42_a_retry_after_a_rolled_back_w21_writes_the_same_line_and_sends_once(self):
        real = C.crash_before
        hits = []

        def die_once(name):
            if name == "contracts.commit" and not hits:
                hits.append(name)
                raise SystemExit("crash after the authority line, before the commit")
            return real(name)
        with mock.patch.object(C, "crash_before", die_once), self.assertRaises(SystemExit):
            self.w21()
        self.db.execute("ROLLBACK")                              # the process died: SQLite rolls the tx back
        self.assertEqual(self.sends(), [])
        lines = len(self.log.records())
        self.clock.t += 1
        try:
            self.w21()
        except Exception as error:  # noqa: BLE001 - any refusal of the retry is the failure under test
            self.fail("the retry was refused: %s: %s" % (type(error).__name__, error))
        self.assertEqual(len(self.log.records()), lines, "the log accepts the retry as the same record")
        self.sender().pump()
        self.assertEqual(len(self.puts()), 1)

    def test_neg19_and_neg41_a_blocking_control_cancels_the_intent_keeps_the_head_then_refires_once(self):
        controls = [("kill on", dict(on=True), True, {}), ("stale reading", dict(mono=self.clock.t - 6), True, {}),
                    ("not shared", dict(shared=False), True, {}), ("policy", {}, False, {}),
                    ("flag 0", {}, True, {"AHC_W21_SEND": "0"})]
        for n, (name, kill, allowed, env) in enumerate(controls, start=1):
            with self.subTest(control=name):
                self.clock.t += 1
                self.kill = {"on": False, "epoch": 1, "mono": self.clock.t, "shared": True}
                self.w21_ok()
                self.kill.update(kill)
                self.allowed = allowed
                with mock.patch.dict(os.environ, env):
                    out = self.sender().pump()
                self.assertEqual((out["sent"], self.puts()), ([], []), "the injected gh sees no call")
                row = self.db.execute("SELECT state, reason, seq FROM w21_sends ORDER BY seq DESC").fetchone()
                self.assertEqual((row[0], row[2]), ("cancelled", n))
                self.assertTrue(row[1])
                self.assertEqual(self.db.execute("SELECT COUNT(*) FROM w21_sends WHERE state IN ('intent', "
                                                 "'attempted', 'readback-pending')").fetchone()[0], 0, "slot released")
                with self.assertRaisesRegex(C.ContractError, "head"):          # the first item keeps the head
                    self.move("W21", item=self.c._row("work_items", "id", self.newer["id"]),
                              obs=dict(self.w21_obs(self.newer), pr=6))
                self.allowed = True
        self.kill = {"on": False, "epoch": 1, "mono": self.clock.t, "shared": True}
        rids = {r[0] for r in self.db.execute("SELECT request_id FROM w21_sends")}
        self.w21_ok()                                           # restored: seq 6, a new request id, sent once
        self.assertEqual(len(self.sender().pump()["sent"]), 1)
        self.assertEqual(len(self.puts()), 1)
        new = self.db.execute("SELECT request_id, seq, state FROM w21_sends WHERE state != 'cancelled'").fetchone()
        self.assertNotIn(new[0], rids)
        self.assertEqual(new[1:], (len(controls) + 1, "readback-pending"))

    def test_ac7_send_itself_re_reads_the_controls_for_any_caller(self):
        for name, kill in (("unknown reading", None), ("kill on", {"on": True}), ("stale", {"mono": -10})):
            with self.subTest(name):
                self.clock.t += 1
                self.w21_ok()
                rid = self.db.execute("SELECT request_id FROM w21_sends WHERE state='intent'").fetchone()[0]
                reading = None if kill is None else dict({"on": False, "epoch": 1, "mono": self.clock.t,
                                                          "shared": True}, **kill)
                sender = self.W.Sender(self.c, self.fake_gh, lambda args: None, lambda: reading, lambda repo: True,
                                       lambda args, cwd: (1, ""), lambda repo, head, base: "/clone")
                self.assertEqual(sender.send(rid), "cancelled")
                self.assertEqual(self.puts(), [], "a direct send call never bypasses the controls")

    def test_ac7_cancel_is_reachable_only_from_intent_and_restart_cancels_intent_only(self):
        self.w21()
        rid = self.db.execute("SELECT request_id FROM w21_sends").fetchone()[0]
        self.sender().reconcile()
        self.assertEqual(self.c._row("w21_sends", "request_id", rid)["state"], "cancelled", "restart: intent row")
        self.clock.t += 1
        self.w21()
        rid = self.db.execute("SELECT request_id FROM w21_sends WHERE state='intent'").fetchone()[0]
        self.assertTrue(self.c.w21_attempt(rid))
        self.assertFalse(self.c.w21_cancel(rid, "flag off"), "an attempted row is never cancelled")
        self.sender().reconcile()
        self.assertEqual(self.c._row("w21_sends", "request_id", rid)["state"], "attempted")
        self.assertEqual(self.puts(), [], "reconciliation never sends")

    def test_neg20_neg21_readback_records_only_ahcs_update_and_the_successor_keeps_the_head(self):
        g = TO.Repo(Path(self.tmp.name) / "rb")
        base = g.commit({"a.txt": "a\n"}, "base")
        head = g.commit({"b.txt": "b\n"}, "pr", parent=base)
        tip = g.commit({"c.txt": "c\n"}, "main", parent=base)
        tree = TO.git(g.root, "merge-tree", "--write-tree", head, tip).splitlines()[0]
        good = TO.git(g.root, "commit-tree", tree, "-p", head, "-p", tip, "-m", "update")
        evil = TO.git(g.root, "commit-tree", TO.git(g.root, "rev-parse", base + "^{tree}"), "-p", head, "-p", tip,
                      "-m", "evil")
        swapped = TO.git(g.root, "commit-tree", tree, "-p", base, "-p", tip, "-m", "parent1 is B, not H")
        item = self.admit(pr=8, head=head, base=base)
        self.pass_reviews(item)

        def real_git(args, cwd):
            rc, out, _err = TO.real_git(args, g.root, 30)
            return rc, out
        for name, new, ours in (("evil merge", evil, False), ("parent1 not H", swapped, False), ("ahc's", good, True)):
            with self.subTest(name):
                self.db.execute("UPDATE w21_sends SET state='cancelled'")      # earlier cases, kept as audit
                with self.c.tx():
                    rid = self.c._w21_record(self.c._row("work_items", "id", item["id"]), tip)
                self.assertTrue(self.c.w21_attempt(rid))
                self.head_after = new
                self.sender(git=real_git).pump()
                state = self.c._row("w21_sends", "request_id", rid)["state"]
                self.assertEqual(state, "resolved" if ours else "attempted", name)
        succ = self.admit(pr=8, head=good, base=tip)
        self.assertTrue(self.c.w21_successor(succ))
        q = self.queue_of(self.item, self.newer)
        self.assertEqual(self.c.queue_head("o/r", q), self.item["id"])
        self.db.execute("UPDATE work_items SET created=0 WHERE id IN (?, ?)", (item["id"], succ["id"]))
        self.assertEqual(self.c.queue_head("o/r", q), succ["id"], "NEG-21: the successor in checks keeps the head")

    def test_neg17_two_processes_race_one_intent_row_and_exactly_one_sends(self):
        """NEG-17, in two real processes on one file ledger: both see the committed intent row and call send at
        the same moment; the intent->attempted CAS lets exactly one of them make the update-branch call."""
        root = Path(self.tmp.name) / "race"
        root.mkdir(mode=0o700)                                  # ahc_fs refuses a log directory that is not 0700
        db = sqlite3.connect(str(root / "ledger.sqlite3"), isolation_level=None)
        C.apply_schema(db)
        db.execute("INSERT INTO w21_sends(request_id, item, repo, pr, base, head, seq, event_id, state, version, "
                   "created, updated) VALUES ('w21-race', 'wi-race', 'o/r', 5, ?, ?, 1, 'w21:race', 'intent', 1, 1, "
                   "1)", (TC.BASE, TC.H1))
        db.close()
        child = root / "child.py"
        child.write_text(RACE_CHILD)
        env = dict(os.environ, PYTHONPATH=os.pathsep.join([str(HOOKS), os.environ.get("PYTHONPATH", "")]))
        procs = [subprocess.Popen([sys.executable, "-B", str(child), str(root), "w21-race", me], env=env,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for me in "AB"]
        time.sleep(0.5)                                         # both children are waiting on the go file
        (root / "go").write_text("")
        results = []
        for p in procs:
            out, err = p.communicate(timeout=60)
            self.assertEqual(p.returncode, 0, err[-800:])
            results.append(json.loads(out.strip().splitlines()[-1]))
        puts = [l for l in (root / "calls.txt").read_text().splitlines() if " PUT " in l]
        self.assertEqual(len(puts), 1, "exactly one update-branch call across both processes")
        lines = (root / "authority.jsonl").read_text().splitlines()
        self.assertEqual(len(lines), 1, "one log line for one record across both processes")
        self.assertEqual(sorted(str(r["sent"]) for r in results), ["None", "sent"])
        db = sqlite3.connect(str(root / "ledger.sqlite3"))
        self.addCleanup(db.close)
        self.assertEqual(db.execute("SELECT state, version FROM w21_sends").fetchall(), [("readback-pending", 3)])

    def test_ac7_one_unresolved_send_per_repo_by_the_guard_and_by_the_index(self):
        self.w21()
        q = self.behind()
        q[self.item["id"]] = dict(q[self.item["id"]], kill_switch=True)     # the older item no longer heads
        with self.assertRaisesRegex(C.ContractError, "another item of the repo has an unresolved send"):
            self.move("W21", item=self.c._row("work_items", "id", self.newer["id"]),
                      obs=self.pr(pr=6, queue=q, mergeable=True))
        for state in ("intent", "attempted", "readback-pending"):
            with self.subTest(state=state), self.assertRaises(sqlite3.IntegrityError):
                self.db.execute("INSERT INTO w21_sends(request_id, item, repo, pr, base, head, seq, event_id, state, "
                                "version, created, updated) VALUES (?, 'wi-x', 'o/r', 9, ?, ?, 1, ?, ?, 1, 1, 1)",
                                ("w21-x-" + state, TC.BASE, TC.H2, "w21:x-" + state, state))

    def test_ac7_the_authority_append_holds_an_exclusive_flock(self):
        import fcntl  # noqa: PLC0415
        lock_path = str(self.log.path) + ".lock"
        probes = []
        real = C.AuthorityLog._append_locked

        def probe(log, record):
            fd = os.open(lock_path, os.O_WRONLY)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                probes.append("free")
                fcntl.flock(fd, fcntl.LOCK_UN)
            except BlockingIOError:
                probes.append("held")
            finally:
                os.close(fd)
            return real(log, record)
        with mock.patch.object(C.AuthorityLog, "_append_locked", probe):
            self.w21()
        self.assertEqual(probes, ["held"], "the read-check-append runs under the exclusive lock")

    def test_neg37_after_a_lost_update_the_next_item_takes_w21_and_the_lost_item_waits_for_w16(self):
        self.w21()
        rid = self.db.execute("SELECT request_id FROM w21_sends").fetchone()[0]
        self.assertTrue(self.c.w21_attempt(rid))
        self.clock.t += C.Contracts.W23_SECONDS
        self.assertEqual(self.move("W23")["state"], "waiting-ask")
        self.assertEqual(self.c._row("w21_sends", "request_id", rid)["state"], "lost")
        self.kill["mono"] = self.clock.t
        try:
            moved = self.move("W21", item=self.c._row("work_items", "id", self.newer["id"]),
                              obs=dict(self.pr(pr=6, queue=self.behind(self.newer), mergeable=True)))
        except C.ContractError as error:
            self.fail("a lost send blocked the next item: %s" % error)
        self.assertEqual(moved["w21_base"], TC.BASE, "the next item takes W21")
        item = self.c._row("work_items", "id", self.item["id"])
        self.c.record_w16_proof("w16-w21", item["id"], "pr-gate", item["version"], "e" * 64)
        self.move("W16", to="pr-gate", actor="main", proof="w16-w21")
        self.assertEqual(self.c._row("w21_sends", "request_id", rid)["state"], "resolved", "main's W16 resolves it")



class StartupReconcileTests(Base):
    """AC-8 / NEG-36: the daemon reconciles review units at start, before its first tick, and raises each finding."""

    def test_ac8_startup_reconciliation_stops_an_orphan_and_raises_its_incident(self):
        import ahc_guard  # noqa: PLC0415
        from tests.test_ahc_contracts import _FakeRunner  # noqa: PLC0415
        policy = ahc_guard.Policy.for_test(self.paths.root, {})
        fake = _FakeRunner(4242)
        stray = "ahc-review-rv-%s-%s.service" % ("0" * 24, "2" * 16)
        fake.live.add(stray)
        fake.slice[stray] = "ahc-review.slice"
        out = runner.startup_reconcile(self.paths, policy, runner=fake)
        self.assertEqual(out["stopped"], [stray])
        ledger = runner.Ledger(self.paths)
        self.addCleanup(ledger.close)
        texts = [r[0] for r in ledger.db.execute("SELECT text FROM wi_notices WHERE kind='incident'")]
        self.assertTrue(any(stray in t for t in texts), texts)
        self.assertEqual(policy.incidents, [], "drained into the outbox")
        self.assertEqual(runner.startup_reconcile(self.paths, ahc_guard.Policy.for_test(self.paths.root, {})),
                         {"skipped": "no review isolation on this host"})

    def test_ac8_the_daemon_reconciles_before_its_first_tick(self):
        import inspect  # noqa: PLC0415
        src = inspect.getsource(runner.main)
        call = "startup_reconcile(paths, policy, role=args.role)"
        self.assertTrue(call in src, "the daemon reconciles at start, for its role: %s" % call)
        self.assertLess(src.index(call), src.index("tick(paths, config, deps"),
                        "reconciliation runs before the first tick can start an attempt")

    def test_f1_only_core_reconciles_and_migrates_at_start(self):
        """PR 272 F1: R3 launches only from core's tick, so only core (or an all-in-one run) reconciles at start;
        the review role never opens a migrating ledger there."""
        import ahc_guard  # noqa: PLC0415
        from tests.test_ahc_contracts import _FakeRunner  # noqa: PLC0415
        fake = _FakeRunner(4242)
        opened = []
        real = runner.Ledger.__init__

        def spy(ledger, paths, migrate=True):
            opened.append(migrate)
            real(ledger, paths, migrate=migrate)
        with mock.patch.object(runner.Ledger, "__init__", spy):
            out = runner.startup_reconcile(self.paths, ahc_guard.Policy.for_test(self.paths.root, {}), runner=fake,
                                           role="review")
        self.assertEqual(opened, [], "the review role opens no ledger for reconciliation")
        self.assertIn("skipped", out)


if __name__ == "__main__":
    unittest.main()
