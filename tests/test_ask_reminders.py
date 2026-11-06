"""P16: bounded escalating reminders for open asks (GoodQA goodqa#14791). Fails on main 247c104: no module."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import ask_reminders as ar  # noqa: E402

T0 = 1_800_000_000.0


def parse_ts(v):
    import datetime as dt
    try:
        return dt.datetime.fromisoformat(str(v).replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError):
        return None


class ScheduleTests(unittest.TestCase):
    def test_stages_escalate_then_repeat_every_4h_bounded(self):
        self.assertIsNone(ar.stage_at(T0, T0 - 1))
        self.assertEqual(ar.stage_at(T0, T0), 0)
        self.assertEqual(ar.stage_at(T0, T0 + 29 * 60), 0)
        self.assertEqual(ar.stage_at(T0, T0 + 30 * 60), 1)
        self.assertEqual(ar.stage_at(T0, T0 + 2 * 3600), 2)
        self.assertEqual(ar.stage_at(T0, T0 + 6 * 3600), 3)
        self.assertEqual(ar.stage_at(T0, T0 + 10 * 3600), 4)
        self.assertEqual(ar.stage_at(T0, T0 + 400 * 3600), 2 + ar.MAX_REPEATS)  # bounded: no infinite escalation

    def test_each_stage_fires_once_and_never_after_resolution(self):
        asks = [{"id": "wa5b00000001", "opened": T0, "note": "need the key"}]
        sent = {}
        first = ar.due(asks, T0 + 5, sent)
        self.assertEqual([r["stage"] for r in first], [0])
        sent["wa5b00000001"] = 0
        self.assertEqual(ar.due(asks, T0 + 10 * 60, sent), [])          # same stage: no repeat
        second = ar.due(asks, T0 + 31 * 60, sent)
        self.assertEqual([r["stage"] for r in second], [1])
        sent["wa5b00000001"] = 1
        self.assertEqual(ar.due([], T0 + 3 * 3600, sent), [])            # resolved asks are not passed in: nothing fires

    def test_open_asks_from_wal_excludes_resolved(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "sess1" / "main.jsonl"
            p.parent.mkdir()
            rows = [{"at": "2027-01-15T00:00:00+00:00", "event": "ask", "id": "wa5b00000001", "note": "key?"},
                    {"at": "2027-01-15T00:00:00+00:00", "event": "ask", "id": "wa5b00000002", "note": "scope?"},
                    {"at": "2027-01-15T01:00:00+00:00", "event": "ask_resolved", "ref": "wa5b00000002", "note": "user said go"},
                    "not json"]
            p.write_text("\n".join(r if isinstance(r, str) else json.dumps(r) for r in rows) + "\n")
            opened = ar.open_asks(p, parse_ts)
            self.assertEqual([a["id"] for a in opened], ["wa5b00000001"])
            self.assertEqual(opened[0]["session"], "sess1")

    def test_render_names_ids_and_age_without_the_full_question(self):
        text = ar.render([{"id": "wa5b00000001", "stage": 2, "age_s": 2 * 3600 + 120, "note": "x" * 500, "session": "s"}])
        self.assertIn("[ask:wa5b00000001] open 2h02m (reminder 3)", text)
        self.assertLess(len(text), 400)
        self.assertEqual(ar.render([]), "")


if __name__ == "__main__":
    unittest.main()
