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
        self.assertEqual(self.state(iid), "routed-to-main")
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
        self.assertEqual(self.state(iid), "routed-to-main")
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
        self.assertEqual(self.state(iid), "routed-to-main")

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


class RoutedTests(Base):
    """D20: a PASS waits as routed-to-main; ticket escalation 4 h after routing, then every 24 h."""

    def overdue_comments(self, deps):
        return [a for a in deps.ah_calls if a[:3] == ["ah", "ticket", "comment"] and "routed-overdue" in
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
        self.assertEqual(self.state(iid), "blocked")

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

        config = dict(self.config, clone_urls={REPO: str(remote)}, bounds={}, disk_floor_bytes=0)
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
        coordinator = real_home / ".agent-harness" / "coordinator"
        state = real_home / ".agent-harness" / "state"
        before_coord = self.snapshot(coordinator)
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
        after_state = {k: v for k, v in (self.snapshot(state) or {}).items() if "ahc" in k or "coordinator" in k}
        self.assertEqual(after_state, before_state)


if __name__ == "__main__":
    unittest.main()
