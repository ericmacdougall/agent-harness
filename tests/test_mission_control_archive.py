"""Archive rule for asks and requirements (GoodQA goodqa#15920 AC-1, NEG-1, NEG-2, NEG-7).

The rule is pure and deterministic: first match of R1 terminal state, R2 deploy or live-test PASS (or closed
ticket), R3 superseded by a newer row with the same words, R4 expired. Nothing is deleted; an item always says
which rule put it where it is."""
import os
import random
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "harness" / "hooks"))
sys.path.insert(0, str(REPO / "harness" / "mission_control"))
os.environ.setdefault("MC_HOOKS", str(REPO / "harness" / "hooks"))

import archive  # noqa: E402

NOW = 1_800_000_000.0
DAY = 86400


def iso(age_s):
    import datetime
    return datetime.datetime.fromtimestamp(NOW - age_s, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def req(ident="w1", age=DAY, **extra):
    row = {"id": ident, "session": "s1", "text": f"requirement {ident}", "source": "user:s1/u \"x\"", "at": iso(age),
           "state": "recorded", "ticket": None, "owner": None, "evidence": None}
    row.update(extra)
    return row


def one(row, kind="requirement", **kw):
    return archive.classify_all([row], kind, NOW, **kw)[0]


class Rules(unittest.TestCase):
    def test_plain_recent_requirement_is_live_and_says_why(self):
        out = one(req())
        self.assertEqual((out["bucket"], out["rule"]), ("live", "live"))
        self.assertIn("open", out["reason"])

    def test_r1_terminal_state_archives(self):
        for state in ("resolved", "closed", "done", "superseded", "expired", "declined", "withdrawn", "RESOLVED"):
            with self.subTest(state=state):
                out = one(req(state=state))
                self.assertEqual((out["bucket"], out["rule"]), ("archived", "R1"), out)
                self.assertIn(state.lower(), out["reason"])

    def test_r1_resolved_ask_keeps_its_resolution_and_evidence(self):
        ask = {"id": "wa1", "at": iso(DAY), "note": "Ship it?", "owner": "main", "resolved_at": iso(DAY / 2),
               "decision": "approved", "resolved_by": "wres1", "resolution": "answered by the user: yes"}
        out = one(ask, "ask")
        self.assertEqual((out["bucket"], out["rule"]), ("archived", "R1"))
        self.assertIn("answered by the user: yes", out["reason"])
        self.assertEqual(out["evidence_ref"], "wal:wres1")

    def test_r2_pass_evidence_archives_but_fail_and_unstated_do_not(self):
        for verdict, bucket in (("PASS", "archived"), ("FAIL", "live"), ("UNSTATED", "live"), (None, "live")):
            with self.subTest(verdict=verdict):
                out = one(req(evidence={"kind": "live_test", "verdict": verdict, "id": "wev1"}))
                self.assertEqual(out["bucket"], bucket, out)
                if bucket == "archived":
                    self.assertEqual((out["rule"], out["evidence_ref"]), ("R2", "wev1"))

    def test_r2_closed_ticket_archives_and_reopened_ticket_restores(self):
        row = req(ticket="goodqa#15920")
        self.assertEqual(one(row, ticket_closed=lambda ref: True)["rule"], "R2")
        self.assertEqual(one(row, ticket_closed=lambda ref: False)["bucket"], "live")
        self.assertEqual(one(row, ticket_closed=lambda ref: None)["bucket"], "live")  # unknown never hides

    def test_r3_older_same_words_is_superseded_by_the_newest(self):
        rows = [req("wold", age=3 * DAY, text="Back up   transcripts"), req("wnew", age=DAY, text="back up transcripts"),
                req("wother", age=2 * DAY, text="something else")]
        out = {r["id"]: r for r in archive.classify_all(rows, "requirement", NOW)}
        self.assertEqual((out["wold"]["bucket"], out["wold"]["rule"]), ("archived", "R3"))
        self.assertEqual(out["wold"]["evidence_ref"], "requirement:wnew")
        self.assertEqual(out["wnew"]["bucket"], "live")
        self.assertEqual(out["wother"]["bucket"], "live")

    def test_r3_never_crosses_sessions(self):
        rows = [req("wa", age=3 * DAY, text="same", session="s1"), req("wb", age=DAY, text="same", session="s2")]
        self.assertEqual([r["bucket"] for r in archive.classify_all(rows, "requirement", NOW)], ["live", "live"])

    def test_r4_old_requirement_without_owner_ticket_or_evidence_expires(self):
        out = one(req(age=31 * DAY))
        self.assertEqual((out["bucket"], out["rule"]), ("archived", "R4"))
        self.assertIn("30 d", out["reason"])

    def test_r4_is_guarded_by_owner_ticket_or_evidence(self):
        for guard in ({"owner": "a1b2c3d"}, {"ticket": "goodqa#1"}, {"evidence": {"kind": "live_test", "verdict": "FAIL"}}):
            with self.subTest(guard=guard):
                out = one(req(age=90 * DAY, **guard))
                self.assertEqual(out["bucket"], "live", out)

    def test_live_requirement_without_guards_shows_when_it_will_expire(self):
        out = one(req(age=20 * DAY))
        self.assertEqual(out["bucket"], "live")
        self.assertEqual(out["expires_in_s"], 10 * DAY)

    def test_r4_ask_past_until_expires_and_future_until_stays(self):
        gone = {"id": "wa2", "at": iso(2 * DAY), "note": "q", "owner": "main", "until": iso(DAY)}
        keep = {"id": "wa3", "at": iso(2 * DAY), "note": "q2", "owner": "main", "until": iso(-DAY)}
        self.assertEqual((one(gone, "ask")["bucket"], one(gone, "ask")["rule"]), ("archived", "R4"))
        self.assertEqual(one(keep, "ask")["bucket"], "live")

    def test_ask_stale_only_by_inactivity_stays_live(self):
        out = one({"id": "wa4", "at": iso(5 * DAY), "note": "q", "owner": "main"}, "ask")
        self.assertEqual(out["bucket"], "live")
        self.assertTrue(out["stale"])

    def test_sweeper_cleared_rows_map_to_r1_or_r2(self):
        cleared = {"id": "wc1", "text": "q", "at": iso(DAY), "reason": "ticket-closed", "evidence": "ticket:goodqa#1"}
        out = one(cleared, "cleared")
        self.assertEqual((out["bucket"], out["rule"]), ("archived", "R2"))
        dup = dict(cleared, id="wc2", reason="duplicate", evidence="ask:wc1")
        self.assertEqual(one(dup, "cleared")["rule"], "R3")
        res = dict(cleared, id="wc3", reason="resolved", evidence="wal:wres")
        self.assertEqual(one(res, "cleared")["rule"], "R1")
        gone = dict(cleared, id="wc4", reason="owner-reassigned", evidence="owner:a1")
        self.assertEqual(one(gone, "cleared")["rule"], "R1")


class Malformed(unittest.TestCase):
    def test_garbage_never_raises_and_is_live_or_skipped(self):
        rows = [None, 5, "x", [], {}, {"id": None}, {"id": 7, "state": 9, "at": "nope"},
                {"id": "wf", "at": iso(-10 * DAY), "state": {"a": 1}, "text": 12},
                req("wbad", state=None, at="2026-13-45"), req("wnum", state=3.5), req("wev", evidence="oops"),
                req("wev2", evidence=[1, "a", None]), req("wtk", ticket=12)]
        out = archive.classify_all(rows, "requirement", NOW)
        self.assertTrue(all(r["bucket"] in ("live", "archived") for r in out))
        by = {r["id"]: r for r in out}
        self.assertEqual(by["wbad"]["bucket"], "live")
        self.assertEqual(by["wnum"]["bucket"], "live")
        self.assertEqual(by["wf"]["bucket"], "live")  # a future timestamp never ages out

    def test_old_row_without_timestamp_is_never_expired(self):
        self.assertEqual(one(req(at=None, age=0))["bucket"], "live")

    def test_markup_stays_plain_text_and_text_is_bounded(self):
        out = one(req(text="<img src=x onerror=alert(1)>" + "A" * 50000))
        self.assertIn("<img", out["text"])
        self.assertLessEqual(len(out["text"]), archive.TEXT_MAX)


class Determinism(unittest.TestCase):
    def test_input_order_never_changes_the_result(self):
        rows = [req(f"w{i}", age=(i % 40) * DAY, text=f"t{i % 7}", state="recorded" if i % 5 else "done") for i in range(120)]
        first = archive.classify_all(rows, "requirement", NOW)
        shuffled = rows[:]
        random.Random(7).shuffle(shuffled)
        self.assertEqual(first, archive.classify_all(shuffled, "requirement", NOW))
        self.assertEqual(first, archive.classify_all(rows, "requirement", NOW))

    def test_input_is_not_mutated(self):
        row = req(state="done")
        before = dict(row)
        one(row)
        self.assertEqual(row, before)

    def test_duplicate_ids_collapse_to_one_row(self):
        out = archive.classify_all([req("wd", age=DAY), req("wd", age=2 * DAY)], "requirement", NOW)
        self.assertEqual(len(out), 1)

    def test_large_volume_is_linearish(self):
        import time
        rows = [req(f"w{i}", age=(i % 90) * DAY, text=f"t{i}") for i in range(5000)]
        start = time.monotonic()
        out = archive.classify_all(rows, "requirement", NOW)
        self.assertLess(time.monotonic() - start, 2.0)
        self.assertEqual(len(out), 5000)

    def test_summary_counts_by_rule(self):
        rows = [req("a", state="done"), req("b"), req("c", age=40 * DAY)]
        summary = archive.summary(archive.classify_all(rows, "requirement", NOW))
        self.assertEqual(summary, {"live": 1, "archived": 2, "rules": {"R1": 1, "R4": 1, "live": 1}})


if __name__ == "__main__":
    unittest.main()
