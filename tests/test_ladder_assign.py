"""goodqa#14840: an audited `escalation.py assign` so a task that really runs at a higher rung is not shown as R0."""
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
import escalation as ladder  # noqa: E402
import model_tiers as tiers  # noqa: E402

SOURCE = "wal:/home/u/.claude/wals/s1/main.jsonl#w123"
HEX = "a" * 40


class Fixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="assign-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "ladder"
        self.root.mkdir(mode=0o700)
        self.policy = tiers.load_policy()
        self.ledger = ladder.Ledger(self.root, self.policy)

    def assign(self, task="g10", rung="R3", source=SOURCE, actor="rules-owner"):
        return self.ledger.assign(task, rung, source=source, actor=actor)

    def approve(self, task):
        wals = Path(self.temp.name) / "wals"
        (wals / "s").mkdir(parents=True)
        wal = wals / "s" / "main.jsonl"
        wal.write_text(json.dumps({"id": "w9", "event": "ask", "note": "fable for [task:%s]" % task, "source": 'user:s/u "yes"'}) + "\n"
                       + json.dumps({"id": "w10", "event": "ask_resolved", "ref": "w9", "note": "approved"}) + "\n")
        os.environ["AGENT_HARNESS_WALS_DIR"] = str(wals)
        self.addCleanup(lambda: os.environ.pop("AGENT_HARNESS_WALS_DIR", None))
        self.ledger.approve_top(task, "w9", wal)


class Assign(Fixture):
    def test_a_fresh_task_shows_r0_until_it_is_assigned_and_then_the_assigned_rung(self):
        self.assertEqual(self.ledger.status("g10")["rung"], "R0")
        status = self.assign(rung="R3")
        self.assertEqual(status["rung"], "R3")
        self.assertEqual(self.ledger.status("g10")["rung"], "R3")

    def test_the_assignment_is_appended_to_history_with_its_source_and_actor(self):
        self.ledger.claim_fix("g10", HEX)
        before = list(self.ledger.load("g10")["events"])
        self.assign(rung="R2")
        events = self.ledger.load("g10")["events"]
        self.assertEqual(events[:len(before)], before)  # append-only
        self.assertEqual(len(events), len(before) + 1)
        event = events[-1]
        self.assertEqual((event["kind"], event["class"], event["rung"], event["source"], event["actor"]),
                         ("assign", "ASSIGN", "R2", SOURCE, "rules-owner"))
        self.assertEqual(event["rung_at"], "R0")

    def test_failures_after_an_assignment_climb_from_the_assigned_rung(self):
        per = self.policy["failures_per_rung"]
        fails = [{"class": "FAIL", "fingerprint": "f", "head": "%040x" % n} for n in range(1, per + 1)]
        plain = tiers.next_writing_rung(self.policy, self.policy["lowest_rung"])
        self.assertEqual(ladder.rung_of(fails, self.policy)["rung"], plain)
        assigned = [{"class": "ASSIGN", "rung": "R2"}] + fails
        self.assertEqual(ladder.rung_of(assigned, self.policy)["rung"], tiers.next_writing_rung(self.policy, "R2"))

    def test_an_assignment_forgets_earlier_failures_at_the_old_rung(self):
        fails = [{"class": "FAIL", "fingerprint": "f", "head": "%040x" % 1}]
        out = ladder.rung_of(fails + [{"class": "ASSIGN", "rung": "R1"}], self.policy)
        self.assertEqual((out["rung"], out["failures_at_rung"]), ("R1", 0))

    def test_reviewer_selection_follows_the_assigned_author_rung(self):
        self.assign(rung="R2")
        author = self.ledger.status("g10")["rung"]
        selection = tiers.reviewer_for(self.policy, author, "claude", {"openai": True, "claude": True})
        self.assertEqual(selection["rung"], self.policy["rungs"]["R2"]["reviewer_rung"])
        self.assertNotEqual(selection["rung"], self.policy["rungs"]["R0"]["reviewer_rung"])

    def test_assigning_the_same_rung_again_is_allowed_and_audited(self):
        self.assign(rung="R2")
        self.assign(rung="R2")
        self.assertEqual(len([e for e in self.ledger.load("g10")["events"] if e["kind"] == "assign"]), 2)


class Refusals(Fixture):
    def refused(self, code=None, **kw):
        with self.assertRaises(ladder.LedgerError) as raised:
            self.assign(**kw)
        if code:
            self.assertEqual(raised.exception.code, code)
        return raised.exception

    def test_permission_rungs_need_approve_top(self):
        error = self.refused(rung="R5", code="permission_required")
        self.assertIn("approve-top", str(error))
        self.assertEqual(self.ledger.status("g10")["rung"], "R0")
        self.approve("g10")
        self.assertEqual(self.assign(rung="R5")["rung"], "R5")

    def test_a_permission_for_another_task_does_not_unlock_r5(self):
        self.approve("other")
        self.refused(task="g10", rung="R5", code="permission_required")

    def test_review_only_and_unknown_rungs_are_refused(self):
        for rung in ("R4", "R6", "R9", "r3", "", "R3; x"):
            with self.subTest(rung=rung):
                self.refused(rung=rung)
        self.assertEqual(self.ledger.status("g10")["rung"], "R0")

    def test_lowering_below_the_computed_rung_is_refused_and_points_at_reset(self):
        self.assign(rung="R3")
        error = self.refused(rung="R1")
        self.assertIn("reset", str(error))
        self.assertEqual(self.ledger.status("g10")["rung"], "R3")

    def test_a_source_must_be_a_traceable_reference(self):
        for bad in ("", "trust me", "the owner said so", "wal:", "wal:/x/main.jsonl", "x" * 400, None, 5):
            with self.subTest(source=str(bad)[:20]):
                self.refused(source=bad)
        for good in (SOURCE, "ticket:GoodQA goodqa#14840", 'user:s1/uuid-1 "use R3"', "file:/a/b.md:3@abcdef1"):
            self.assign(task="t-" + str(abs(hash(good)))[:6], source=good)

    def test_an_actor_must_be_a_plain_identifier(self):
        for bad in ("", "two words", "a\nb", "x" * 100, None, "../x"):
            with self.subTest(actor=str(bad)[:20]):
                self.refused(actor=bad)

    def test_an_unsafe_task_key_is_refused(self):
        for bad in ("", "../x", "a b", "-x"):
            with self.subTest(task=bad):
                self.refused(task=bad)


class Cli(Fixture):
    def run_cli(self, *args):
        return subprocess.run([sys.executable, str(HOOKS / "escalation.py"), "--root", str(self.root), *args],
                              capture_output=True, text=True, timeout=60)

    def test_assign_prints_the_new_status_and_status_then_agrees(self):
        done = self.run_cli("assign", "--task", "g10", "--rung", "R3", "--source", SOURCE, "--actor", "rules-owner")
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertEqual(json.loads(done.stdout)["rung"], "R3")
        self.assertEqual(json.loads(self.run_cli("status", "--task", "g10").stdout)["rung"], "R3")
        event = self.ledger.load("g10")["events"][-1]
        self.assertEqual((event["actor"], event["source"], event["rung"]), ("rules-owner", SOURCE, "R3"))

    def test_a_refusal_is_json_with_exit_2_and_changes_nothing(self):
        done = self.run_cli("assign", "--task", "g10", "--rung", "R5", "--source", SOURCE, "--actor", "x")
        self.assertEqual(done.returncode, 2)
        self.assertEqual(json.loads(done.stdout)["error"], "permission_required")
        self.assertEqual(json.loads(self.run_cli("status", "--task", "g10").stdout)["rung"], "R0")

    def test_every_argument_is_required(self):
        for args in (["--rung", "R3", "--source", SOURCE, "--actor", "x"], ["--task", "t", "--source", SOURCE, "--actor", "x"],
                     ["--task", "t", "--rung", "R3", "--actor", "x"], ["--task", "t", "--rung", "R3", "--source", SOURCE]):
            self.assertEqual(self.run_cli("assign", *args).returncode, 2, args)


import tier_gate as gate  # noqa: E402


class TierGate(Fixture):
    """The spawn hook reads the same ledger status, so an assignment moves what it requires."""

    def spawn(self, prompt, model=None, effort=None):
        tool_input = {"prompt": prompt, "description": "owner", "subagent_type": "task-owner"}
        if model:
            tool_input["model"] = model
        if effort:
            tool_input["effort"] = effort
        os.environ["AGENT_HARNESS_ESCALATION_DIR"] = str(self.root)
        self.addCleanup(lambda: os.environ.pop("AGENT_HARNESS_ESCALATION_DIR", None))
        return gate.decide_spawn({"tool_name": "Agent", "tool_input": tool_input, "session_id": "s1"}, self.policy, self.ledger,
                                 session_id="s1")

    def test_an_assigned_task_requires_its_assigned_rung_and_denies_a_lower_model(self):
        decision, _, _, facts = self.spawn("work [task:g10]", model="sonnet")
        self.assertEqual((decision, facts["required_rung"]), ("allow", "R0"))
        self.assign(task="g10", rung="R2")
        decision, reason, _, facts = self.spawn("work [task:g10]", model="sonnet")
        self.assertEqual(facts["required_rung"], "R2")
        self.assertEqual(decision, "deny")
        self.assertIn("rung-below", reason)
        decision, _, _, facts = self.spawn("work [task:g10]", model="opus", effort="high")
        self.assertEqual((decision, facts["required_rung"]), ("allow", "R2"))


import tests.test_peer_review as _base  # noqa: E402


class EndToEnd(unittest.TestCase):
    """peer_review.py --task reads the assigned author rung: the report and the selection receipt show it."""
    fake = _base.PeerReviewTests.fake
    evidence = staticmethod(_base.PeerReviewTests.evidence)

    def setUp(self):
        _base.PeerReviewTests.setUp(self)
        self.ladder = self.root / "ladder"
        self.ladder.mkdir(mode=0o700)
        body = '''import sys
from pathlib import Path
text = 'CODE_INSPECTION_RESULT: ACCEPT\\nReviewed.'
if '--output-last-message' in sys.argv:
    Path(sys.argv[sys.argv.index('--output-last-message') + 1]).write_text(text)
else:
    print(text)
'''
        self.fake("codex", body)
        self.fake("claude", body)
        import shutil
        self.tools = self.root / "tools"
        self.tools.mkdir(mode=0o700)
        for name in ("git", "python3", "sh", "env", "cat", "mkdir", "rm", "cp", "mv", "ln", "ls", "chmod", "sed", "grep", "awk",
                     "tr", "sort", "head", "tail", "wc", "date", "sleep", "dirname", "basename", "uname", "mktemp", "readlink",
                     "true", "false", "find", "xargs", "diff", "tar"):
            found = shutil.which(name, path="/usr/bin:/bin:/usr/local/bin")
            if found:
                (self.tools / name).symlink_to(found)

    def review(self, *extra):
        return _base.PeerReviewTests.invoke(self, stage="code-inspection", extra=list(extra), env={
            "AGENT_HARNESS_ESCALATION_DIR": str(self.ladder), "PATH": str(self.bin) + os.pathsep + str(self.tools)})

    def test_the_review_of_an_assigned_task_uses_the_assigned_author_rung(self):
        plain = self.review("--task", "g10", "--author-harness", "claude")
        self.assertEqual(plain.returncode, 0, plain.stderr)
        self.assertIn("Author-Rung: R0\n", self.output.read_text())
        ladder.Ledger(self.ladder, tiers.load_policy()).assign("g10", "R2", source=SOURCE, actor="rules-owner")
        first = self.output.read_text()
        self.assertIn("Reviewer-Rung: R1\n", first)  # R0 author: the reviewer sits one rung above R0
        self.output.unlink()
        again = self.review("--task", "g10", "--author-harness", "claude")
        self.assertEqual(again.returncode, 0, again.stderr)
        report = self.output.read_text()
        self.assertIn("Author-Rung: R2\n", report)
        self.assertIn("Reviewer-Rung: R3\n", report)


if __name__ == "__main__":
    unittest.main()
