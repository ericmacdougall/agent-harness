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
                                        "reason": "needs the user", "at": "2026-11-01T00:00:00+00:00"}) + "\n"
                            + json.dumps({"event": "decision", "id": "w0123456789a", "note": "the plan changed; the ask is moot",
                                          "at": "2026-11-01T00:01:00+00:00"}) + "\n")

    def run_note(self, *extra):
        argv = ["wal_note.py", "--wal", str(self.wal), "--event", "ask_resolved", "--ref", "wask00000001",
                "--note", "closing"] + list(extra)
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, {"HOME": str(self.home), "CLAUDE_CONFIG_DIR": ""}), mock.patch("sys.argv", argv), \
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
        code, err = self.run_note("--outcome", "obsolete", "--source", "wal:sess-1/main.jsonl#w0123456789a")
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
        self.assertEqual(len(self.rows()), 2)
        code, _ = self.run_note("--outcome", "obsolete")
        self.assertEqual(code, 2)

    def test_outcome_cannot_be_combined_with_an_approval(self):
        code, _ = self.run_note("--outcome", "obsolete", "--decision", "approved", "--source", "wal:sess-1/main.jsonl#w0123456789a")
        self.assertEqual(code, 2)
        self.assertEqual(len(self.rows()), 2)

    def test_without_outcome_a_wal_source_is_still_refused(self):
        code, err = self.run_note("--source", "wal:sess-1/main.jsonl#w0123456789a")
        self.assertEqual(code, 2)
        self.assertIn("--outcome", err)

    def test_evidence_that_is_the_ask_itself_or_traces_to_a_human_turn_is_refused(self):
        code, err = self.run_note("--outcome", "obsolete", "--source", "wal:sess-1/main.jsonl#wask00000001")
        self.assertEqual(code, 2)
        self.assertIn("the ask itself", err)
        human = dict(OK, origin="user")
        argv = ["wal_note.py", "--wal", str(self.wal), "--event", "ask_resolved", "--ref", "wask00000001", "--note", "closing",
                "--outcome", "obsolete", "--source", "wal:sess-1/main.jsonl#w0123456789a"]
        err = io.StringIO()
        with mock.patch.dict(os.environ, {"HOME": str(self.home)}), mock.patch("sys.argv", argv), \
                mock.patch("provenance.resolve", lambda *a, **k: dict(human)), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            code = wal_note.main()
        self.assertEqual(code, 2)
        self.assertIn("human turn", err.getvalue())
        self.assertEqual(len(self.rows()), 2)

    def test_evidence_must_really_resolve_unmocked(self):
        argv = ["wal_note.py", "--wal", str(self.wal), "--event", "ask_resolved", "--ref", "wask00000001", "--note", "closing",
                "--outcome", "obsolete", "--source", "wal:/nonexistent/main.jsonl#w0123456789a"]
        with mock.patch.dict(os.environ, {"HOME": str(self.home)}), mock.patch("sys.argv", argv), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = wal_note.main()
        self.assertEqual(code, 2)  # a source that does not resolve closes nothing
        self.assertEqual(len(self.rows()), 2)

    def test_a_tool_close_is_marked_and_never_an_approval_row(self):
        code, err = self.run_note("--by", "ask-sweep", "--source", USER)
        self.assertIn(code, (0, None), err)
        row = self.rows()[-1]
        self.assertEqual((row["by"], row["closed_by"]), ("ask-sweep", "ask-sweep"))
        self.assertNotIn("decision", row)

    def test_line_number_evidence_naming_the_ask_itself_is_refused(self):
        code, err = self.run_note("--outcome", "obsolete", "--source", "wal:%s#L1" % self.wal)
        self.assertEqual(code, 2)
        self.assertIn("the ask itself", err)

    def test_the_ask_itself_is_refused_whichever_way_the_path_is_written(self):
        # Codex final gate F1: provenance resolves relative and ~ paths beneath ~/.claude/wals, so the self-entry check must
        # canonicalize the same way; a raw open of the relative path failed and let the ask's own entry close it
        for source in ("wal:sess-1/main.jsonl#L1", "wal:~/.claude/wals/sess-1/main.jsonl#L1", "wal:%s#L1" % self.wal,
                       "wal:sess-1/../sess-1/main.jsonl#L1", "wal:sess-1/main.jsonl#wask00000001"):
            with self.subTest(source=source):
                code, err = self.run_note("--outcome", "obsolete", "--source", source)
                self.assertEqual(code, 2, err)
                self.assertIn("the ask itself", err)
        self.assertEqual(len(self.rows()), 2)
        code, err = self.run_note("--outcome", "obsolete", "--source", "wal:sess-1/main.jsonl#L2")
        self.assertIn(code, (0, None), err)  # a different entry of the same WAL is still usable evidence

    def test_evidence_outside_the_wals_root_is_refused(self):
        outside = self.home / "elsewhere" / "main.jsonl"
        outside.parent.mkdir()
        outside.write_text(json.dumps({"event": "decision", "id": "wfeedfeed001", "note": "x"}) + "\n")
        link = self.wal.parent / "link.jsonl"
        link.symlink_to(outside)
        for source in ("wal:%s#L1" % outside, "wal:sess-1/link.jsonl#L1", "wal:sess-1/../../../elsewhere/main.jsonl#L1"):
            with self.subTest(source=source):
                code, err = self.run_note("--outcome", "obsolete", "--source", source)
                self.assertEqual(code, 2, err)
                self.assertIn("cannot be read", err)
        self.assertEqual(len(self.rows()), 2)

    def test_oversized_evidence_is_refused(self):
        big = self.wal.parent / "big.jsonl"
        big.write_text(json.dumps({"event": "decision", "id": "wbig00000001", "note": "y" * 400}) + "\n"
                       + "".join(json.dumps({"event": "decision", "id": "w%011d" % n, "note": "z"}) + "\n" for n in range(60)))
        with mock.patch("provenance.MAX_LINE", 128):
            code, err = self.run_note("--outcome", "obsolete", "--source", "wal:sess-1/big.jsonl#L1")
        self.assertEqual(code, 2, err)  # a line over the cap is never parsed
        self.assertIn("cannot be read", err)
        with mock.patch("provenance.MAX_SCAN_BYTES", 1024):
            for source in ("wal:sess-1/big.jsonl#L55", "wal:sess-1/big.jsonl#w00000000055"):
                with self.subTest(source=source):
                    code, err = self.run_note("--outcome", "obsolete", "--source", source)
                    self.assertEqual(code, 2, err)  # past the total byte budget: unread, so refused
                    self.assertIn("cannot be read", err)
        self.assertEqual(len(self.rows()), 2)

    def test_a_fifo_as_evidence_is_refused_without_hanging(self):
        import subprocess
        fifo = self.wal.parent / "pipe.jsonl"
        os.mkfifo(fifo)
        env = dict(os.environ, HOME=str(self.home))
        env.pop("CLAUDE_CONFIG_DIR", None)
        argv = [sys.executable, str(HOOKS / "wal_note.py"), "--wal", str(self.wal), "--event", "ask_resolved",
                "--ref", "wask00000001", "--note", "closing", "--outcome", "obsolete"]
        for source in ("wal:sess-1/pipe.jsonl#L1", "wal:%s#L1" % fifo):
            with self.subTest(source=source):
                try:  # the timeout is the guard: the old precheck's plain open() blocked here until a writer appeared
                    done = subprocess.run(argv + ["--source", source], env=env, capture_output=True, text=True, timeout=20)
                except subprocess.TimeoutExpired:
                    self.fail("the outcome precheck blocked on a FIFO")
                self.assertEqual(done.returncode, 2, done.stderr)
        self.assertEqual(len(self.rows()), 2)

    def test_a_tool_close_cannot_carry_a_decision(self):
        code, _ = self.run_note("--by", "ask-sweep", "--decision", "approved", "--source", USER)
        self.assertEqual(code, 2)
        self.assertEqual(len(self.rows()), 2)

    def test_a_tool_or_obsolete_close_never_satisfies_the_top_rung_pair_check(self):
        import escalation
        folder = self.home / "walsroot" / "sess-9"
        folder.mkdir(parents=True)
        main = folder / "main.jsonl"
        ask = {"event": "ask", "id": "wtop00000001", "note": "[task:T1] top rung", "source": USER, "reason": "r" * 12}
        for extra in ({"closed_by": "ask-sweep", "decision": "approved"}, {"outcome": "obsolete", "decision": "approved"}):
            resolved = dict({"event": "ask_resolved", "ref": "wtop00000001", "source": USER}, **extra)
            main.write_text(json.dumps(ask) + "\n" + json.dumps(resolved) + "\n")
            with mock.patch.dict(os.environ, {"AGENT_HARNESS_WALS_DIR": str(self.home / "walsroot")}):
                with self.assertRaises(escalation.LedgerError) as caught:
                    escalation.verify_ask_pair(main, "wtop00000001", "T1", allow_env_root=True)
            self.assertIn("closed by a tool", str(caught.exception))

    def test_a_resolved_ask_is_not_open_again_and_the_row_is_not_an_approval_for_the_kill_gate(self):
        self.run_note("--outcome", "obsolete", "--source", "wal:sess-1/main.jsonl#w0123456789a")
        code, _ = self.run_note("--outcome", "obsolete", "--source", "wal:sess-1/main.jsonl#w0123456789a")
        self.assertEqual(code, 2)  # already resolved
        import ask_reminders
        self.assertEqual(ask_reminders.open_asks(self.wal, lambda v: 0.0), [])


if __name__ == "__main__":
    unittest.main()
