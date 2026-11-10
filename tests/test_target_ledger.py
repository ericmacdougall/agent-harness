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
        return tl.check_text(text, LEDGER, POLICY["narrowing"], term_narrowing=POLICY["term_narrowing"])

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


class ReviewFindings(unittest.TestCase):
    """Independent review a422e875 of PR 167: F1 to F8."""

    def flag(self, text, ledger=None):
        return tl.check_text(text, LEDGER if ledger is None else ledger, POLICY["narrowing"], term_narrowing=POLICY["term_narrowing"])

    def test_f1_a_requirement_ending_on_its_noun_still_gives_a_count_target(self):
        for note in ("Target: 1000 leads", "Collect 1000 desktop leads", "We need 1k leads", "twenty-five hundred... no: 1,000 leads"):
            ledger = tl.ledger_from_rows([row(note)], POLICY["terms"], POLICY["nouns"])
            self.assertIn(("count", "lead"), {(t["kind"], t.get("noun")) for t in ledger}, note)
        ledger = tl.ledger_from_rows([row("Target: 1000 leads")], POLICY["terms"], POLICY["nouns"])
        self.assertEqual([t["number"] for t in ledger], [1000])
        self.assertTrue(self.flag("Dialer ran on a 25-lead pilot", ledger))
        quoted = tl.ledger_from_rows([row("see the quote", source='user:a/b "collect 1000 leads"')], (), POLICY["nouns"])
        self.assertEqual([t["number"] for t in quoted], [1000])  # the user's quoted words count, the ids do not

    def test_f2_a_label_must_start_a_sentence_outside_code_and_file_names(self):
        for text in ("Used `ASSUMPTION` token in code; 25-lead pilot.", "Pilot of 25 leads. See TARGET_MISMATCH.md file",
                     "Click-test ran headless instead of the GoodQA browser. Unrelated: ASSUMPTION about css.",
                     "Pilot of 25 leads, which is an ASSUMPTION we made"):
            with self.subTest(text=text):
                self.assertTrue(self.flag(text), text)
        for text in ("ASSUMPTION: pilot of 25 leads.", "Pilot of 25 leads.\nTARGET_MISMATCH: the user has not agreed.",
                     "(ASSUMPTION) headless instead of the GoodQA browser."):
            with self.subTest(text=text):
                self.assertEqual(self.flag(text), [], text)

    def test_f3_paraphrases_and_split_sentences_are_flagged(self):
        for text in ("Ran 25 leads. Pilot only.", "Collected 25 leads; the pilot batch.",
                     "Click-test used the GoodQA browser. Headless fallback was used for checkout.",
                     "Ran against a subset of repositories", "Covered the main repositories only.",
                     "Used a shared key rather than the dedicated key.", "Single agent run, no swarm.",
                     "Used it without swarm.", "Skipped the goodqa browser.", "twenty-five leads in a pilot",
                     "1k of the leads were a sample", "Dialer done on 25 leads.", "Interim result on a sample of the 1000 leads."):
            with self.subTest(text=text):
                self.assertTrue(self.flag(text), text)

    def test_f6_the_full_count_is_not_a_narrowing(self):
        for text in ("Ran 1,000 leads in a pilot environment.", "Ran 1000 desktop leads, all repos covered.",
                     "The ticket writer stays Mac-only."):
            self.assertEqual(self.flag(text), [], text)

    def test_f5_a_malformed_policy_gives_defaults(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "p.json"
            path.write_text(json.dumps({"mode": "warn", "terms": 5, "narrowing": 5, "nouns": 5}))
            policy = tl.load_policy(path)
            self.assertEqual((policy["terms"], policy["narrowing"], policy["nouns"]), ([], [], []))
            self.assertEqual(tl.check_text("25-lead pilot", LEDGER, policy["narrowing"]), [])

    def test_f7_f8_a_symlinked_main_log_gives_no_ledger_and_the_read_has_budgets(self):
        with tempfile.TemporaryDirectory() as tmp:
            real = Path(tmp) / "real.jsonl"
            real.write_text(json.dumps(row("Collect 1000 desktop leads")) + "\n")
            link = Path(tmp) / "main.jsonl"
            os.symlink(real, link)
            self.assertEqual(tl.ledger_from_wal(link, POLICY["terms"], POLICY["nouns"]), [])
            self.assertTrue(tl.ledger_from_wal(real, POLICY["terms"], POLICY["nouns"]))
            import safe_input
            seen = {}
            original = safe_input.iter_jsonl_lines

            def spy(*a, **k):
                seen.update(k)
                return original(*a, **k)
            with mock.patch.object(safe_input, "iter_jsonl_lines", spy):
                tl.ledger_from_wal(real, POLICY["terms"], POLICY["nouns"])
            self.assertTrue(seen.get("max_total_bytes") and seen.get("max_seconds"))


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

    def test_f4_a_source_that_only_looks_like_the_users_does_not_exempt_the_note(self):
        self.mode = "enforce"
        code, _, err = self.write("Dialer slice done on a 25-lead pilot.", source="user:fake")  # looks like a user source
        self.assertEqual(code, 2, err)
        self.assertEqual(self.rows(), [])
        self.mode = "warn"
        code, _, err = self.write("Dialer slice done on a 25-lead pilot.", source="user:fake")
        self.assertIn("target ledger", err)  # in warn mode the advice is no longer dropped either

    def test_f5_a_hostile_policy_or_ledger_never_stops_a_note_being_written(self):
        with mock.patch.object(tl, "ledger_from_wal", mock.Mock(side_effect=RuntimeError("boom"))):
            code, _, _ = self.write("a plain note")
        self.assertNotEqual(code, 2)
        self.assertEqual(len(self.rows()), 1)

    def test_the_users_own_words_are_not_narrowing(self):
        self.mode = "enforce"
        with mock.patch("provenance.resolve", lambda *a, **k: {"ok": True, "kind": "user", "weak": False, "problems": []}):
            code, _, err = self.write("User asked for a 25-lead pilot first", event="decision", source=USER)
        self.assertNotEqual(code, 2, err)


if __name__ == "__main__":
    unittest.main()
