"""GoodQA #15565 (never-drop upgrade 5, first slice): do not route agent-doable or already-granted work to the user."""

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import ask_gate as ag  # noqa: E402
import wal_note  # noqa: E402

POLICY = ag.load_policy()
USER = 'user:11111111-1111-4111-8111-111111111111/22222222-2222-4222-8222-222222222222 "words"'


def row(note, source=USER, event="decision", **kw):
    return dict({"event": event, "note": note, "source": source, "id": "w" + "0" * 11}, **kw)


GRANTS = ag.grants_from_rows([
    row("GRANT: agent may drive my browser to edit Stripe settings"),
    row("GRANT: the agent can publish the FrameBright terms page", source='inferred: guess'),  # not the user's words
    row("not a grant, a plain decision about Stripe settings")])


class Pure(unittest.TestCase):
    def doable(self, note, reason="needs a decision before continuing"):
        return ag.agent_doable(note, reason, GRANTS, POLICY)

    def test_only_the_users_own_grant_rows_count(self):
        self.assertEqual(len(GRANTS), 1)
        self.assertIn("stripe", GRANTS[0]["tokens"])

    def test_the_stripe_ask_is_refused_as_already_granted(self):
        ok, why = self.doable("Edit the Stripe settings in the dashboard so the payout schedule matches?")
        self.assertTrue(ok)
        self.assertIn("already granted", why)

    def test_a_process_stop_a_sign_in_and_a_plain_chore_are_agent_doable(self):
        for note in ("Please stop the runaway test runner that you started","Please sign in to Hawkeye and check the box",
                     "Can you run the migration check for me?", "Could you log in to the staging box?"):
            with self.subTest(note=note):
                self.assertTrue(self.doable(note)[0], note)

    def test_a_real_question_and_the_human_only_steps_are_never_refused(self):
        for note in ("Is FrameBright your own product or client work?", "Which of the two quotes should we accept?",
                     "A CAPTCHA blocks the sign in, can you solve it?", "Approve the payment of the invoice?",
                     "Please accept the new terms of service on the vendor page", "Create an account for the vendor please",
                     "Edit the Hawkeye settings?",  # shares only generic words with the only grant
                     "Please stop the leftover adb server another session started",  # a foreign process needs the user's OK
                     "May main stop the orphaned process 83600 that has no owner?"):
            with self.subTest(note=note):
                self.assertFalse(self.doable(note)[0], note)

    def test_a_grant_from_an_agent_or_unsourced_row_grants_nothing(self):
        self.assertFalse(self.doable("Publish the FrameBright terms page?")[0])

    def test_a_malformed_policy_gives_defaults(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "p.json"
            path.write_text(json.dumps({"mode": "warn", "human_only": 5, "agent_doable": [5, {"pattern": "(", "why": "x"}]}))
            policy = ag.load_policy(path)
            self.assertEqual((policy["human_only"], policy["agent_doable"]), ([], []))
            self.assertEqual(ag.agent_doable("kill the process", "x" * 12, [], policy), (False, ""))


class WalNote(unittest.TestCase):
    """Through wal_note.py with a throwaway HOME."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        self.wal = self.home / ".claude" / "wals" / "sess-1" / "main.jsonl"
        self.wal.parent.mkdir(parents=True)
        self.wal.write_text(json.dumps(row("GRANT: agent may drive my browser to edit Stripe settings")) + "\n")
        self.mode = "warn"

    def write(self, note, reason="the user must decide this one", event="ask", source=None, by=None):
        argv = ["wal_note.py", "--wal", str(self.wal), "--event", event, "--note", note, "--reason", reason] \
            + (["--source", source or USER] if event == "ask" else []) + (["--by", by] if by else [])
        policy = dict(ag.load_policy(), mode=self.mode)
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, {"HOME": str(self.home)}), mock.patch("sys.argv", argv), \
                mock.patch.object(ag, "load_policy", lambda *a, **k: policy), \
                mock.patch("provenance.resolve", lambda *a, **k: {"ok": True, "kind": "user", "weak": False, "problems": [], "assumption": False, "weak_reasons": [], "backed": True}), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = wal_note.main()
            except SystemExit as exit_:
                code = exit_.code
        return code, err.getvalue()

    def rows(self):
        return [json.loads(x) for x in self.wal.read_text().splitlines()]

    def test_warn_mode_writes_the_ask_with_a_warning_and_a_flag(self):
        code, err = self.write("Edit the Stripe settings so the payout schedule matches?")
        self.assertNotEqual(code, 2, err)
        self.assertIn("agent-doable", err)
        self.assertTrue(self.rows()[-1].get("agent_doable"))

    def test_enforce_mode_refuses_it_and_writes_nothing(self):
        self.mode = "enforce"
        code, err = self.write("Edit the Stripe settings so the payout schedule matches?")
        self.assertEqual(code, 2)
        self.assertIn("REFUSED", err)
        self.assertEqual(len(self.rows()), 1)
        code, err = self.write("Is FrameBright your own product or client work?")  # a real question is still written
        self.assertNotEqual(code, 2, err)
        self.assertEqual(len(self.rows()), 2)

    def test_off_mode_tool_writers_and_other_events_are_left_alone(self):
        self.mode = "off"
        self.write("Edit the Stripe settings so the payout schedule matches?")
        self.assertEqual(len(self.rows()), 2)
        self.mode = "enforce"
        code, _ = self.write("Edit the Stripe settings", event="status", reason="n/a")
        self.assertNotEqual(code, 2)

    def test_a_broken_gate_never_stops_an_ask(self):
        self.mode = "enforce"
        with mock.patch.object(ag, "grants_from_wal", mock.Mock(side_effect=RuntimeError("boom"))):
            code, _ = self.write("Which quote should we accept?")
        self.assertNotEqual(code, 2)
        self.assertEqual(len(self.rows()), 2)


if __name__ == "__main__":
    unittest.main()
