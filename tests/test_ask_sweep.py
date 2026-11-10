"""GoodQA #15565: ask_sweep lists asks the user answered (by ask id, structured answers), closes only what main names, and never
records an approval."""
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "harness" / "hooks"))
import ask_sweep as sw  # noqa: E402

SESSION = "11111111-1111-4111-8111-111111111111"
T0 = "2026-11-08T10:00:00+00:00"
T1 = "2026-11-08T12:00:00.000Z"
NOW = sw.parse_ts("2026-11-20T00:00:00+00:00")


def ask(i, at=T0):
    return {"event": "ask", "id": i, "at": at, "note": f"question {i} for the user"}


def answer_record(uuid, pairs, ts=T1, **extra):
    rec = {"type": "user", "uuid": uuid, "timestamp": ts, "isSidechain": False,
           "message": {"content": [{"type": "tool_result", "content": "rendered"}]},
           "toolUseResult": {"answers": dict(pairs)}}
    rec.update(extra)
    return rec


class Base(unittest.TestCase):
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


class Plan(Base):
    def test_an_open_ask_answered_by_id_is_planned_with_the_whole_answer(self):
        wal, tr = self.files([ask("w00000000001")], [answer_record("u1", {"[ask:w00000000001] Is it ours?": "My own product"})])
        plan = sw.plan(wal, tr, NOW)
        self.assertEqual([(a["ask"], a["turn"], a["answer"]) for a in plan["answered"]], [("w00000000001", "u1", "My own product")])

    def test_a_short_answer_is_never_padded_with_another_questions_answer(self):
        wal, tr = self.files([ask("w00000000001"), ask("w00000000002")],
                             [answer_record("u1", {"[ask:w00000000001] Fable?": "No", "[ask:w00000000002] Stop pid 4242?": "yes go ahead and stop it"})])
        plan = sw.plan(wal, tr, NOW)
        self.assertEqual([a["ask"] for a in plan["short"]], ["w00000000001"])
        self.assertEqual([a["ask"] for a in plan["answered"]], ["w00000000002"])
        for row in plan["answered"] + plan["short"]:
            self.assertNotIn("go ahead", row["answer"] if row["ask"].endswith("1") else "")

    def test_an_answer_older_than_the_ask_by_more_than_the_slack_does_not_close_it(self):
        wal, tr = self.files([ask("w00000000001", at="2026-11-09T00:00:00+00:00")],
                             [answer_record("u1", {"[ask:w00000000001] Old?": "An older answer text"})])
        self.assertEqual(sw.plan(wal, tr, NOW)["answered"], [])

    def test_the_sixty_second_slack_is_inclusive_on_both_sides(self):
        wal, tr = self.files([ask("w00000000001", at="2026-11-08T12:00:30+00:00")],
                             [answer_record("u1", {"[ask:w00000000001] Q?": "An answer given first"}, ts="2026-11-08T12:00:00.000Z")])
        self.assertEqual(len(sw.plan(wal, tr, NOW)["answered"]), 1)  # 30 s before the ask: inside the slack
        wal, tr = self.files([ask("w00000000001", at="2026-11-08T12:02:00+00:00")],
                             [answer_record("u1", {"[ask:w00000000001] Q?": "An answer given first"}, ts="2026-11-08T12:00:00.000Z")])
        self.assertEqual(sw.plan(wal, tr, NOW)["answered"], [])  # 120 s before: outside it

    def test_only_structured_user_answers_count(self):
        pair = {"[ask:w00000000001] Q?": "A real answer here"}
        agent_text = {"type": "assistant", "uuid": "u2", "timestamp": T1, "toolUseResult": {"answers": pair},
                      "message": {"content": [{"type": "text", "text": "[ask:w00000000001] The user answered yes to this one"}]}}
        for rec in (agent_text, answer_record("u3", pair, isSidechain=True),
                    "not json [ask:w toolUseResult",
                    {"type": "user", "uuid": "u4", "timestamp": T1, "message": {"content": "[ask:w00000000001] The user answered: yes"}}):
            with self.subTest(rec=str(rec)[:40]):
                wal, tr = self.files([ask("w00000000001")], [rec])
                self.assertEqual(sw.plan(wal, tr, NOW)["answered"], [])

    def test_the_ask_id_must_start_the_question_key(self):
        wal, tr = self.files([ask("w00000000001")], [answer_record("u1", {"Quoting [ask:w00000000001] inside agent text": "Some real answer"})])
        self.assertEqual(sw.plan(wal, tr, NOW)["answered"], [])

    def test_a_record_provenance_rejects_is_not_answered(self):
        wal, tr = self.files([ask("w00000000001")], [answer_record("u1", {"[ask:w00000000001] Q?": "A real answer here"})])
        self.assertEqual(sw.plan(wal, tr, NOW, check=lambda uuid: False)["answered"], [])
        self.assertEqual(len(sw.plan(wal, tr, NOW, check=lambda uuid: True)["answered"]), 1)

    def test_the_newest_answer_wins(self):
        wal, tr = self.files([ask("w00000000001")], [answer_record("u1", {"[ask:w00000000001] Q?": "First answer here"}),
                                                     answer_record("u9", {"[ask:w00000000001] Q?": "Second answer here"})])
        self.assertEqual(sw.plan(wal, tr, NOW)["answered"][0]["turn"], "u9")

    def test_unanswered_asks_older_than_7_days_are_listed_as_stale_and_a_young_one_is_not(self):
        wal, tr = self.files([ask("w00000000001"), ask("w00000000002", at="2026-11-19T00:00:00+00:00")], [])
        plan = sw.plan(wal, tr, NOW)
        self.assertEqual([s["ask"] for s in plan["stale"]], ["w00000000001"])
        self.assertEqual(plan["answered"], [])


class Close(Base):
    def test_close_runs_wal_note_with_an_answer_source_no_decision_and_a_tool_mark(self):
        calls = []
        sw.close_answered("sess-1", Path("/w/main.jsonl"),
                          [{"ask": "w00000000001", "turn": "u1-uuid", "answer": 'My "own" product'}], runner=lambda a: calls.append(a) or 0)
        argv = calls[0]
        self.assertEqual(argv[argv.index("--source") + 1], "answer:sess-1/u1-uuid \"My 'own' product\"")
        self.assertEqual(argv[argv.index("--by") + 1], "ask-sweep")
        self.assertNotIn("--decision", argv)
        self.assertNotIn("--outcome", argv)


class RealProvenance(Base):
    def test_verified_uses_provenance_and_rejects_a_record_not_bound_to_an_ask_user_question(self):
        home = self.root / "h"
        proj = home / ".claude" / "projects" / "p"
        proj.mkdir(parents=True)
        (proj / f"{SESSION}.jsonl").write_text(json.dumps(answer_record("u1", {"[ask:w00000000001] Q?": "A real answer here"})) + "\n")
        self.assertFalse(sw.verified(SESSION, "u1", home))  # the record has no AskUserQuestion tool_use binding
        self.assertFalse(sw.verified(SESSION, "no-such-uuid", home))
        self.assertFalse(sw.verified("22222222-2222-4222-8222-222222222222", "u1", home))  # no transcript


class Cli(Base):
    def setUp(self):
        super().setUp()
        self.home = self.root / "home"
        wals = self.home / ".claude" / "wals" / SESSION
        wals.mkdir(parents=True)
        proj = self.home / ".claude" / "projects" / "p"
        proj.mkdir(parents=True)
        (wals / "main.jsonl").write_text("".join(json.dumps(r) + "\n" for r in [
            ask("w00000000001"), ask("w00000000002"), ask("w00000000003", at="2026-10-01T00:00:00+00:00")]))
        (proj / f"{SESSION}.jsonl").write_text("".join(json.dumps(answer_record("u1", {
            "[ask:w00000000001] Q one?": "Answer number one", "[ask:w00000000002] Q two?": "Answer number two"})) + "\n"))
        self.calls = []
        patches = [mock.patch.dict(os.environ, {"AH_HOME": str(self.home)}),
                   mock.patch.object(sw, "verified", lambda *a: True),
                   mock.patch.object(sw, "close_answered", lambda s, w, items: [(i["ask"], 0) for i in items])]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def run_main(self, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = sw.main(["--session", SESSION, *args])
        return code, json.loads(out.getvalue())

    def test_listing_closes_nothing_and_apply_needs_only(self):
        code, doc = self.run_main()
        self.assertEqual((code, sorted(a["ask"] for a in doc["answered"])), (0, ["w00000000001", "w00000000002"]))
        self.assertNotIn("closed", doc)
        code, doc = self.run_main("--apply")
        self.assertEqual(code, 2)
        self.assertIn("--only", doc["problem"])

    def test_apply_closes_exactly_the_named_asks_and_never_a_stale_one(self):
        code, doc = self.run_main("--apply", "--only", "w00000000002", "w00000000003", "--stale")
        self.assertEqual(code, 0)
        self.assertEqual([c["ask"] for c in doc["closed"]], ["w00000000002"])  # the stale ask has no answer: never closed here
        self.assertEqual([s["ask"] for s in doc["stale"]], ["w00000000003"])

    def test_a_short_answer_stays_unclosable_even_when_named_with_only(self):
        proj = self.home / ".claude" / "projects" / "p" / f"{SESSION}.jsonl"
        proj.write_text(json.dumps(answer_record("u2", {"[ask:w00000000001] Fable?": "No"})) + "\n")
        code, doc = self.run_main("--apply", "--only", "w00000000001")
        self.assertEqual((code, doc["answered"], doc["closed"]), (0, [], []))
        self.assertEqual([s["ask"] for s in doc["short"]], ["w00000000001"])

    def test_a_bad_session_id_is_refused(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(sw.main(["--session", "../../x"]), 2)


if __name__ == "__main__":
    unittest.main()
