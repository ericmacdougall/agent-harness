"""GoodQA #15565 (never-drop upgrade 4): target ledger and narrowing detection."""

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
import target_ledger as tl  # noqa: E402
import wal_note  # noqa: E402

POLICY = tl.load_policy()
USER = 'user:11111111-1111-4111-8111-111111111111/22222222-2222-4222-8222-222222222222 "words"'


def row(note, source=USER, event="requirement", **kw):
    return dict({"event": event, "note": note, "source": source, "id": "w" + "0" * 11}, **kw)


LEDGER = tl.ledger_from_rows([
    row("Collect 1000 desktop leads for the dialer"),
    row("Cover all repos, not a subset"),
    row("Click-tests use the real GoodQA browser on the fleet"),
    row("Use a dedicated key for Fabric with swarm on")], POLICY["terms"], POLICY["nouns"])


class Extraction(unittest.TestCase):
    def test_counts_all_and_terms_are_taken_from_the_users_words_only(self):
        kinds = {(t["kind"], t.get("noun") or t.get("term")) for t in LEDGER}
        self.assertIn(("count", "lead"), kinds)
        self.assertIn(("all", "repo"), kinds)
        self.assertIn(("term", "goodqa browser"), kinds)
        self.assertIn(("term", "dedicated key"), kinds)
        self.assertIn(("term", "swarm"), kinds)
        self.assertEqual([t["number"] for t in LEDGER if t["kind"] == "count"], [1000])

    def test_an_agent_or_unsourced_row_is_never_a_target(self):
        agent = tl.ledger_from_rows([row("Collect 1000 leads", source='inferred: from a guess'),
                                     row("Collect 1000 leads", source=""), row("Collect 1000 leads", unsourced=True),
                                     row("Collect 1000 leads", assumption=True),
                                     row("Collect 1000 leads", source=USER, event="status")], POLICY["terms"], POLICY["nouns"])
        self.assertEqual(agent, [])


class Narrowing(unittest.TestCase):
    def flag(self, text):
        return tl.check_text(text, LEDGER, POLICY["narrowing"])

    def test_the_audit_cases_are_flagged(self):
        for text in ("Dialer slice done on a 25-lead pilot.",                     # I011: 25 leads against 1000 desktop leads
                     "Reduced run: 40 leads and moved on",
                     "Reviewed the core repos only.",                             # all repos narrowed
                     "Used a pool key instead of a dedicated key for Fabric.",    # I032
                     "Click-test ran headless instead of the GoodQA browser.",    # headless instead of the real browser
                     "Ran without swarm for now, fallback to a single agent.",
                     "Interim result on a sample of the 1000 leads."):
            with self.subTest(text=text):
                self.assertTrue(self.flag(text), text)

    def test_a_labelled_note_passes(self):
        for text in ("ASSUMPTION: dialer slice ran on a 25-lead pilot, not the 1000 stated.",
                     "TARGET_MISMATCH: headless instead of the GoodQA browser; ask w0123456789a open.",
                     "Pilot of 25 leads. ASSUMPTION label: the user has not agreed."):
            with self.subTest(text=text):
                self.assertEqual(self.flag(text), [])

    def test_an_unrelated_or_full_scale_note_passes(self):
        for text in ("Fixed the retry loop in the dialer.", "Collected 1000 desktop leads.", "Collected 1200 leads, all repos covered.",
                     "Ran the pilot of the new theme on the blog.", "Used the GoodQA browser as asked."):
            with self.subTest(text=text):
                self.assertEqual(self.flag(text), [], text)

    def test_with_require_ask_a_label_without_an_ask_id_still_flags(self):
        text = "ASSUMPTION: 25-lead pilot only."
        self.assertEqual(tl.check_text(text, LEDGER, POLICY["narrowing"]), [])
        self.assertTrue(tl.check_text(text, LEDGER, POLICY["narrowing"], require_ask=True))
        self.assertEqual(tl.check_text(text + " ask w0123456789a", LEDGER, POLICY["narrowing"], require_ask=True), [])

    def test_no_ledger_means_nothing_to_check(self):
        self.assertEqual(tl.check_text("25-lead pilot", [], POLICY["narrowing"]), [])


class WalNote(unittest.TestCase):
    """Through wal_note.py itself, with a throwaway HOME."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        self.wal = self.home / ".claude" / "wals" / "sess-1" / "agent-x.jsonl"
        self.wal.parent.mkdir(parents=True)
        (self.wal.parent / "main.jsonl").write_text("".join(json.dumps(r) + "\n" for r in [
            row("Collect 1000 desktop leads for the dialer")]))
        self.mode = "warn"

    def write(self, note, event="status", source=None):
        argv = ["wal_note.py", "--wal", str(self.wal), "--event", event, "--note", note] + (["--source", source] if source else [])
        policy = dict(tl.load_policy(), mode=self.mode)
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, {"HOME": str(self.home)}), mock.patch("sys.argv", argv), \
                mock.patch.object(tl, "load_policy", lambda *a, **k: policy), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = wal_note.main()
            except SystemExit as exit_:
                code = exit_.code
        return code, out.getvalue(), err.getvalue()

    def rows(self):
        return [json.loads(x) for x in self.wal.read_text().splitlines()] if self.wal.exists() else []

    def test_warn_mode_writes_the_note_with_a_warning_and_a_flag(self):
        code, out, err = self.write("Dialer slice done on a 25-lead pilot.")
        self.assertEqual(code, None if code is None else 0)
        self.assertIn("target ledger", err)
        self.assertEqual(self.rows()[-1]["target_flags"], 1)

    def test_enforce_mode_refuses_the_unlabelled_note_and_writes_nothing(self):
        self.mode = "enforce"
        code, out, err = self.write("Dialer slice done on a 25-lead pilot.")
        self.assertEqual(code, 2)
        self.assertIn("REFUSED", err)
        self.assertEqual(self.rows(), [])
        code, out, err = self.write("ASSUMPTION: dialer slice ran on a 25-lead pilot.")
        self.assertNotEqual(code, 2)
        self.assertEqual(len(self.rows()), 1)

    def test_off_mode_and_unchecked_events_and_tool_writers_are_left_alone(self):
        self.mode = "off"
        self.write("25-lead pilot")
        self.assertEqual(len(self.rows()), 1)
        self.mode = "enforce"
        code, _, _ = self.write("25-lead pilot", event="intent")  # intent is not a checkpoint event
        self.assertNotEqual(code, 2)

    def test_the_users_own_words_are_not_narrowing(self):
        self.mode = "enforce"
        with mock.patch("provenance.resolve", lambda *a, **k: {"ok": True, "kind": "user", "weak": False, "problems": []}):
            code, _, err = self.write("User asked for a 25-lead pilot first", event="decision", source=USER)
        self.assertNotEqual(code, 2, err)


if __name__ == "__main__":
    unittest.main()
