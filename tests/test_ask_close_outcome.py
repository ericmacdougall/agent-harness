"""GoodQA #15565: an ask nobody can answer any more (or that was never the user's) can close on wal:/file: evidence,
audited as an agent close, and never as an approval."""

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
import wal_note  # noqa: E402

USER = 'user:11111111-1111-4111-8111-111111111111/22222222-2222-4222-8222-222222222222 "words"'
OK = {"ok": True, "kind": "wal", "weak": False, "problems": [], "assumption": False, "weak_reasons": [], "backed": True}


class OutcomeClose(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        self.wal = self.home / ".claude" / "wals" / "sess-1" / "main.jsonl"
        self.wal.parent.mkdir(parents=True)
        self.wal.write_text(json.dumps({"event": "ask", "id": "wask00000001", "note": "May main kill pid 9?", "source": USER,
                                        "reason": "needs the user", "at": "2026-11-01T00:00:00+00:00"}) + "\n")

    def run_note(self, *extra):
        argv = ["wal_note.py", "--wal", str(self.wal), "--event", "ask_resolved", "--ref", "wask00000001",
                "--note", "closing"] + list(extra)
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, {"HOME": str(self.home)}), mock.patch("sys.argv", argv), \
                mock.patch("provenance.resolve", lambda *a, **k: dict(OK)), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = wal_note.main()
            except SystemExit as exit_:
                code = exit_.code
        return code, err.getvalue()

    def rows(self):
        return [json.loads(x) for x in self.wal.read_text().splitlines()]

    def test_obsolete_close_on_wal_evidence_writes_an_audited_row_with_no_approval(self):
        code, err = self.run_note("--outcome", "obsolete", "--source", "wal:/x/main.jsonl#w0123456789a")
        self.assertIn(code, (0, None), err)
        row = self.rows()[-1]
        self.assertEqual((row["event"], row["ref"], row["outcome"], row["closed_by"]), ("ask_resolved", "wask00000001", "obsolete", "agent"))
        self.assertNotIn("decision", row)  # an obsolete close can never authorize an approval

    def test_not_user_close_on_file_and_ticket_evidence(self):
        code, err = self.run_note("--outcome", "not_user", "--source", "ticket:GoodQA goodqa#15565")
        self.assertIn(code, (0, None), err)
        self.assertEqual(self.rows()[-1]["outcome"], "not_user")

    def test_outcome_refuses_inferred_user_and_missing_sources(self):
        for source in ('inferred: from nothing -- because I think so and that is plenty of text', USER, "answer:s/u \"x\""):
            with self.subTest(source=source[:20]):
                code, err = self.run_note("--outcome", "obsolete", "--source", source)
                self.assertEqual(code, 2, err)
        self.assertEqual(len(self.rows()), 1)
        code, _ = self.run_note("--outcome", "obsolete")
        self.assertEqual(code, 2)

    def test_outcome_cannot_be_combined_with_an_approval(self):
        code, _ = self.run_note("--outcome", "obsolete", "--decision", "approved", "--source", "wal:/x/main.jsonl#w0123456789a")
        self.assertEqual(code, 2)
        self.assertEqual(len(self.rows()), 1)

    def test_without_outcome_a_wal_source_is_still_refused(self):
        code, err = self.run_note("--source", "wal:/x/main.jsonl#w0123456789a")
        self.assertEqual(code, 2)
        self.assertIn("--outcome", err)

    def test_evidence_that_is_the_ask_itself_or_traces_to_a_human_turn_is_refused(self):
        code, err = self.run_note("--outcome", "obsolete", "--source", "wal:/x/main.jsonl#wask00000001")
        self.assertEqual(code, 2)
        self.assertIn("the ask itself", err)
        human = dict(OK, origin="user")
        argv = ["wal_note.py", "--wal", str(self.wal), "--event", "ask_resolved", "--ref", "wask00000001", "--note", "closing",
                "--outcome", "obsolete", "--source", "wal:/x/main.jsonl#w0123456789a"]
        err = io.StringIO()
        with mock.patch.dict(os.environ, {"HOME": str(self.home)}), mock.patch("sys.argv", argv), \
                mock.patch("provenance.resolve", lambda *a, **k: dict(human)), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            code = wal_note.main()
        self.assertEqual(code, 2)
        self.assertIn("human turn", err.getvalue())
        self.assertEqual(len(self.rows()), 1)

    def test_evidence_must_really_resolve_unmocked(self):
        argv = ["wal_note.py", "--wal", str(self.wal), "--event", "ask_resolved", "--ref", "wask00000001", "--note", "closing",
                "--outcome", "obsolete", "--source", "wal:/nonexistent/main.jsonl#w0123456789a"]
        with mock.patch.dict(os.environ, {"HOME": str(self.home)}), mock.patch("sys.argv", argv), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = wal_note.main()
        self.assertEqual(code, 2)  # a source that does not resolve closes nothing
        self.assertEqual(len(self.rows()), 1)

    def test_a_tool_close_is_marked_and_never_an_approval_row(self):
        code, err = self.run_note("--by", "ask-sweep", "--source", USER)
        self.assertIn(code, (0, None), err)
        row = self.rows()[-1]
        self.assertEqual((row["by"], row["closed_by"]), ("ask-sweep", "ask-sweep"))
        self.assertNotIn("decision", row)

    def test_a_resolved_ask_is_not_open_again_and_the_row_is_not_an_approval_for_the_kill_gate(self):
        self.run_note("--outcome", "obsolete", "--source", "wal:/x/main.jsonl#w0123456789a")
        code, _ = self.run_note("--outcome", "obsolete", "--source", "wal:/x/main.jsonl#w0123456789a")
        self.assertEqual(code, 2)  # already resolved
        import ask_reminders
        self.assertEqual(ask_reminders.open_asks(self.wal, lambda v: 0.0), [])


if __name__ == "__main__":
    unittest.main()
