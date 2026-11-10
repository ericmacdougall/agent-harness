"""GoodQA #15565: ask_sweep closes the asks the user already answered (by ask id, from the structured answer) and only lists stale ones."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "harness" / "hooks"))
import ask_sweep as sw  # noqa: E402

DAY = 86400.0
T0 = "2026-11-08T10:00:00+00:00"
T1 = "2026-11-08T12:00:00.000Z"


def ask(i, at=T0):
    return {"event": "ask", "id": i, "at": at, "note": f"question {i} for the user"}


def answer_record(uuid, pairs, ts=T1):
    return {"type": "user", "uuid": uuid, "timestamp": ts, "isSidechain": False,
            "message": {"content": [{"type": "tool_result", "content": "rendered"}]},
            "toolUseResult": {"answers": dict(pairs)}}


class Sweep(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def files(self, wal_rows, transcript_rows):
        wal = self.root / "main.jsonl"
        wal.write_text("".join(json.dumps(r) + "\n" for r in wal_rows))
        tr = self.root / "s.jsonl"
        tr.write_text("".join((json.dumps(r) if isinstance(r, dict) else r) + "\n" for r in transcript_rows))
        return wal, tr

    def now(self):
        return sw.parse_ts("2026-11-20T00:00:00+00:00")

    def test_an_open_ask_answered_by_id_is_planned_with_a_verbatim_excerpt(self):
        wal, tr = self.files([ask("w00000000001")], [answer_record("u1", {"[ask:w00000000001] Is it ours?": "My own product"})])
        plan = sw.plan(wal, tr, self.now())
        self.assertEqual([(a["ask"], a["turn"], a["answer"]) for a in plan["answered"]],
                         [("w00000000001", "u1", "My own product")])

    def test_a_short_answer_is_padded_with_its_neighbour_to_reach_the_12_char_floor(self):
        wal, tr = self.files([ask("w00000000001")], [answer_record("u1", {"[ask:w00000000001] Where?": "Vancouver",
                                                                         "[ask:w00000000002] Refund?": "14-day refund"})])
        item = sw.plan(wal, tr, self.now())["answered"][0]
        self.assertGreaterEqual(len(item["answer"]), 12)
        self.assertEqual(item["answer"], "Vancouver 14-day refund")

    def test_a_lone_short_answer_is_not_closed(self):
        wal, tr = self.files([ask("w00000000001")], [answer_record("u1", {"[ask:w00000000001] Where?": "Yes"})])
        plan = sw.plan(wal, tr, self.now())
        self.assertEqual(plan["answered"], [])

    def test_an_answer_older_than_the_ask_does_not_close_it(self):
        wal, tr = self.files([ask("w00000000001", at="2026-11-09T00:00:00+00:00")],
                             [answer_record("u1", {"[ask:w00000000001] Old?": "An older answer text"})])
        self.assertEqual(sw.plan(wal, tr, self.now())["answered"], [])

    def test_only_structured_answers_count_not_agent_text_or_sidechains_or_other_types(self):
        agent_text = {"type": "assistant", "uuid": "u2", "timestamp": T1,
                      "message": {"content": [{"type": "text", "text": "[ask:w00000000001] The user answered yes to this one"}]}}
        wal, tr = self.files([ask("w00000000001")], [agent_text, "not json [ask:w toolUseResult",
                                                     {"type": "user", "uuid": "u3", "timestamp": T1,
                                                      "message": {"content": "[ask:w00000000001] The user answered: yes please"}}])
        self.assertEqual(sw.plan(wal, tr, self.now())["answered"], [])

    def test_unanswered_asks_older_than_7_days_are_listed_never_closed(self):
        wal, tr = self.files([ask("w00000000001"), ask("w00000000002", at="2026-11-19T00:00:00+00:00")], [])
        plan = sw.plan(wal, tr, self.now())
        self.assertEqual([s["ask"] for s in plan["stale"]], ["w00000000001"])
        calls = []
        sw.close_answered("sess", wal, plan["answered"], runner=calls.append)
        self.assertEqual(calls, [])

    def test_close_runs_wal_note_with_an_answer_source_and_no_obsolete_outcome(self):
        calls = []
        sw.close_answered("sess-1", Path("/w/main.jsonl"),
                          [{"ask": "w00000000001", "turn": "u1-uuid", "answer": "My own product"}], runner=lambda a: calls.append(a) or 0)
        argv = calls[0]
        self.assertIn("--event", argv)
        self.assertEqual(argv[argv.index("--source") + 1], 'answer:sess-1/u1-uuid "My own product"')
        self.assertNotIn("--outcome", argv)
        self.assertEqual(argv[argv.index("--decision") + 1], "approved")

    def test_the_newest_answer_wins(self):
        wal, tr = self.files([ask("w00000000001")], [answer_record("u1", {"[ask:w00000000001] Q?": "First answer here"}),
                                                     answer_record("u9", {"[ask:w00000000001] Q?": "Second answer here"})])
        self.assertEqual(sw.plan(wal, tr, self.now())["answered"][0]["turn"], "u9")


if __name__ == "__main__":
    unittest.main()
