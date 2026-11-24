"""asks_reconcile.py (GoodQA goodqa#16944): answered asks are found, unrelated or earlier rows are not, nothing is
written, and every printed command is quoted and cites the resolving evidence."""
import json
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import asks_reconcile as ar  # noqa: E402

S1 = "aaaaaaaa-0000-4000-8000-000000000001"   # predecessor session
S2 = "bbbbbbbb-0000-4000-8000-000000000002"   # successor session


def row(event, ident, at, note, source="inferred: test", **extra):
    return {"at": at, "event": event, "id": ident, "note": note, "source": source, **extra}


class Home:
    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def wal(self, session, rows, name="main.jsonl"):
        folder = self.root / "wals" / session
        folder.mkdir(parents=True, exist_ok=True)
        with open(folder / name, "a") as handle:
            for r in rows:
                handle.write(json.dumps(r) + "\n")
        return folder / name

    def transcript(self, session, records):
        folder = self.root / "projects" / "-Users-x"
        folder.mkdir(parents=True, exist_ok=True)
        with open(folder / (session + ".jsonl"), "a") as handle:
            for r in records:
                handle.write(json.dumps(r) + "\n")

    def snapshot(self):
        return {str(p): p.read_bytes() for p in self.root.rglob("*") if p.is_file()}


def bash_input(uuid, ts, command):
    return {"type": "user", "uuid": uuid, "timestamp": ts,
            "message": {"role": "user", "content": f"<bash-input>{command}</bash-input>"}}


class AsksReconcileTest(unittest.TestCase):
    def setUp(self):
        self.home = Home()
        self.addCleanup(self.home.tmp.cleanup)

    def run_tool(self, *sessions):
        return ar.reconcile(list(sessions), home=str(self.home.root))

    def by_id(self, result):
        return {c["id"]: c for c in result["candidates"]}

    def test_answer_row_in_successor_resolves_predecessor_ask(self):
        self.home.wal(S1, [row("ask", "wask00000001", "2026-11-23T19:06:00+00:00", "U6: may reviews attempt Astra?",
                               reason="r")])
        self.home.wal(S1, [row("decision", "wdec00000001", "2026-11-23T22:04:00+00:00",
                               "User answers: U6 (asks wask00000001) yes past the limit",
                               source='answer:%s/1111 "Yes, past the limit too"' % S1)])
        result = self.run_tool(S1)
        c = self.by_id(result)["wask00000001"]
        self.assertEqual(c["kind"], "answer")
        self.assertIn("--decision approved", c["command"])
        self.assertIn("--ref wask00000001", c["command"])
        self.assertIn("answer:%s/1111" % S1, c["command"])

    def test_unrelated_and_earlier_rows_do_not_resolve(self):
        self.home.wal(S1, [
            row("decision", "wearly000001", "2026-11-23T18:00:00+00:00", "about wask00000002 before it was asked",
                source='answer:%s/1 "Yes"' % S1),
            row("ask", "wask00000002", "2026-11-23T19:00:00+00:00", "may main delete X?", reason="r"),
            row("decision", "wother000001", "2026-11-23T20:00:00+00:00", "an answer about something else",
                source='answer:%s/2 "Yes"' % S1),
        ])
        result = self.run_tool(S1)
        self.assertEqual(result["candidates"], [])
        self.assertEqual([s["id"] for s in result["still_open"]], ["wask00000002"])

    def test_row_that_says_still_pending_is_not_an_answer_and_real_answer_wins(self):
        self.home.wal(S1, [
            row("ask", "wask00000013", "2026-11-21T21:29:00+00:00", "may the click-test sign in on staging?", reason="r"),
            row("decision", "wpend0000013", "2026-11-21T21:42:00+00:00",
                "staff flows NOT TESTED pending ask wask00000013", source='user:%s/9 "get it done"' % S1),
        ])
        self.assertEqual(self.run_tool(S1)["candidates"], [])
        self.home.wal(S1, [
            row("status", "wstat0000013", "2026-11-21T22:00:00+00:00", "see wask00000013 later",
                source='user:%s/10 "keep going"' % S1),
            row("decision", "wansw0000013", "2026-11-21T22:48:00+00:00",
                "Answer to ask wask00000013: the user approved signing in", source='user:%s/11 "Yes, use them"' % S1),
        ])
        c = self.by_id(self.run_tool(S1))["wask00000013"]
        self.assertEqual(c["evidence"][0]["ref"], "wansw0000013")
        self.assertIn("--decision approved", c["command"])

    def test_agent_words_are_not_an_answer(self):
        self.home.wal(S1, [
            row("ask", "wask00000003", "2026-11-23T19:00:00+00:00", "may main stop pid 1?", reason="r"),
            row("decision", "wdec00000003", "2026-11-23T19:30:00+00:00", "main decided wask00000003 is fine",
                source="inferred: main thinks so"),
        ])
        self.assertEqual(self.run_tool(S1)["candidates"], [])

    def test_already_resolved_ask_is_not_listed(self):
        self.home.wal(S1, [
            row("ask", "wask00000004", "2026-11-23T19:00:00+00:00", "q", reason="r"),
            row("ask_resolved", "wres00000004", "2026-11-23T19:10:00+00:00", "done", ref="wask00000004",
                source='answer:%s/3 "Yes"' % S1),
        ])
        result = self.run_tool(S1)
        self.assertEqual(result["candidates"], [])
        self.assertEqual(result["still_open"], [])

    def test_resolution_in_other_session_is_reported(self):
        self.home.wal(S1, [row("ask", "wask00000005", "2026-11-23T19:00:00+00:00", "q", reason="r")])
        self.home.wal(S2, [row("ask_resolved", "wres00000005", "2026-11-23T20:00:00+00:00", "closed here",
                               ref="wask00000005", source='answer:%s/4 "Yes"' % S2, decision="approved")])
        c = self.by_id(self.run_tool(S1, S2))["wask00000005"]
        self.assertEqual(c["kind"], "resolved-elsewhere")
        self.assertIn(str(self.home.root / "wals" / S1 / "main.jsonl"), c["command"])

    def test_terminal_action_matches_distinctive_token_and_needs_confirm(self):
        self.home.wal(S1, [row("ask", "wask00000006", "2026-11-23T22:47:00+00:00",
                               "Run on t2-dev: rm -r /home/eric/.agent-harness/work/heldout/scoring/__pycache__",
                               reason="r")])
        self.home.transcript(S1, [
            bash_input("u-before", "2026-11-23T22:00:00.000Z",
                       "ssh t2-dev rm -r /home/eric/.agent-harness/work/heldout/scoring/__pycache__"),
            bash_input("u-after", "2026-11-24T00:18:00.000Z",
                       "ssh t2-dev rm -r /home/eric/.agent-harness/work/heldout/scoring/__pycache__"),
        ])
        c = self.by_id(self.run_tool(S1))["wask00000006"]
        self.assertEqual(c["kind"], "terminal")
        self.assertTrue(c["confirm"])
        self.assertNotIn("--decision", c["command"])
        self.assertEqual([e["ref"] for e in c["evidence"]], [f"{S1}/u-after"])

    def test_generic_path_alone_is_not_a_terminal_match(self):
        self.home.wal(S1, [row("ask", "wask00000007", "2026-11-23T19:00:00+00:00",
                               "free space under /home/eric/.agent-harness/work", reason="r")])
        self.home.transcript(S1, [bash_input("u1", "2026-11-23T20:00:00Z", "du -sh /home/eric/.agent-harness/work")])
        self.assertEqual(self.run_tool(S1)["candidates"], [])

    def test_superseded_ask_has_no_decision(self):
        self.home.wal(S1, [
            row("ask", "wask00000008", "2026-11-23T18:27:00+00:00", "run h3d.sh", reason="r"),
            row("ask", "wask00000009", "2026-11-23T22:41:00+00:00", "SUPERSEDES wask00000008 (re-worded)", reason="r"),
        ])
        c = self.by_id(self.run_tool(S1))["wask00000008"]
        self.assertEqual(c["kind"], "superseded")
        self.assertNotIn("--decision", c["command"])
        self.assertIn("wal:", c["command"])

    def test_command_is_shell_safe(self):
        hostile = "it's $(rm -rf ~) `x` ; echo pwned"
        self.home.wal(S1, [
            row("ask", "wask00000010", "2026-11-23T19:00:00+00:00", "q", reason="r"),
            row("decision", "wdec00000010", "2026-11-23T20:00:00+00:00", "wask00000010 " + hostile,
                source='answer:%s/5 "%s"' % (S1, "Yes $(touch /tmp/x)")),
        ])
        command = self.by_id(self.run_tool(S1))["wask00000010"]["command"]
        tokens = shlex.split(command.replace("~/.claude", "HOME/.claude"))
        self.assertEqual(tokens[tokens.index("--ref") + 1], "wask00000010")
        self.assertTrue(any(t.startswith("Resolved by answer") for t in tokens))
        self.assertTrue(all("\n" not in t for t in tokens))

    def test_read_only_and_partial_read_is_reported(self):
        self.home.wal(S1, [row("ask", "wask00000011", "2026-11-23T19:00:00+00:00", "q", reason="r")])
        before = self.home.snapshot()
        result = self.run_tool(S1, S2)   # S2 has no WAL folder and S1 no transcript
        self.assertEqual(self.home.snapshot(), before)
        self.assertEqual(result["writes"], 0)
        self.assertTrue(any(S2 in u["source"] for u in result["unread"]))

    def test_cli_exit_codes(self):
        self.home.wal(S1, [row("ask", "wask00000012", "2026-11-23T19:00:00+00:00", "q", reason="r")])
        env = {"ASKS_RECONCILE_HOME": str(self.home.root), "PATH": "/usr/bin:/bin"}
        bad = subprocess.run([sys.executable, str(HOOKS / "asks_reconcile.py"), "--session", "../x"],
                             capture_output=True, text=True, env=env)
        self.assertEqual(bad.returncode, 3)
        partial = subprocess.run([sys.executable, str(HOOKS / "asks_reconcile.py"), "--session", S1, "--json"],
                                 capture_output=True, text=True, env=env)
        self.assertEqual(partial.returncode, 2)   # no transcript for S1: the list may be missing terminal evidence
        self.assertEqual(json.loads(partial.stdout)["writes"], 0)


if __name__ == "__main__":
    unittest.main()
