"""GoodQA #15565: ask_sweep lists asks the user answered (by ask id, structured answers), closes only what main names, and never
records an approval."""
import ast
import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "harness" / "hooks"))
import ask_evidence  # noqa: E402
import ask_sweep as sw  # noqa: E402
import provenance  # noqa: E402

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
    def test_close_runs_wal_note_with_the_cited_source_no_decision_and_a_tool_mark(self):
        wal, tr = self.files([ask("w00000000001")], [answer_record("u1", {"[ask:w00000000001] Q?": 'My "own" product'})])
        item = sw.plan(wal, tr, NOW, session=SESSION)["answered"][0]
        argv = sw.answered_argv(SESSION, wal, item)
        source = argv[argv.index("--source") + 1]
        # #170 round 2 F3: the inner quotes are escaped, never swapped for ', and provenance reads back the exact words
        self.assertEqual(source, 'answer:%s/u1 "My \\"own\\" product"' % SESSION)
        self.assertEqual(provenance.parse_excerpt(source.split(" ", 1)[1]), 'My "own" product')
        self.assertEqual(argv[argv.index("--by") + 1], "ask-sweep")
        self.assertNotIn("--decision", argv)
        self.assertNotIn("--outcome", argv)

    def test_an_answer_provenance_would_not_accept_goes_to_short_with_no_close(self):
        wal, tr = self.files([ask("w00000000001")],
                             [answer_record("u1", {"[ask:w00000000001] Q?": "Okay... sure... fine by me"})])
        got = sw.plan(wal, tr, NOW, session=SESSION)
        self.assertEqual([(s["ask"], "by hand" in s["reason"], "source" in s) for s in got["short"]],
                         [("w00000000001", True, False)])
        self.assertEqual(got["answered"], [])

    def test_an_elided_answer_is_never_closed_and_its_excerpt_is_never_offered(self):
        # #170 triage (CRITICAL): "Don't... stop the worker" cited as "...stop the worker" inverts the user's answer
        wal, tr = self.files([ask("w00000000001"), ask("w00000000002"), ask("w00000000003")],
                             [answer_record("u1", {"[ask:w00000000001] Stop it?": "Don't... stop the worker",
                                                   "[ask:w00000000002] Ship?": "Yes... ship it to staging now",
                                                   # the positive control: the same words, said whole, still close
                                                   "[ask:w00000000003] Stop it?": "Please stop the worker now"})])
        got = sw.plan(wal, tr, NOW, session=SESSION)
        self.assertEqual([(s["ask"], s.get("elided"), "by hand" in s["reason"]) for s in got["short"]],
                         [("w00000000001", True, True), ("w00000000002", True, True)])
        for row in got["short"]:
            self.assertFalse({"source", "close", "apply", "pin"} & set(row), row)
        listing = json.dumps(got)
        self.assertNotIn("...stop the worker", listing)
        self.assertNotIn("...ship it to staging now", listing)
        self.assertEqual([(a["ask"], a["source"]) for a in got["answered"]],
                         [("w00000000003", 'answer:%s/u1 "Please stop the worker now"' % SESSION)])

    def test_a_refused_close_carries_wal_note_s_message(self):
        got = sw.run_close("w00000000001", ["x"], runner=lambda a: (2, "", '{"status": "REFUSED", "problem": "nope"}'))
        self.assertEqual((got["rc"], "nope" in got["refused"]), (2, True))
        self.assertEqual(sw.run_close("w00000000001", ["x"], runner=lambda a: (0, "{}", "")), {"ask": "w00000000001", "rc": 0})


class RealProvenance(Base):
    def test_verified_uses_provenance_and_rejects_a_record_not_bound_to_an_ask_user_question(self):
        home = self.root / "h"
        proj = home / ".claude" / "projects" / "p"
        proj.mkdir(parents=True)
        (proj / f"{SESSION}.jsonl").write_text(json.dumps(answer_record("u1", {"[ask:w00000000001] Q?": "A real answer here"})) + "\n")
        self.assertFalse(sw.verified(SESSION, "u1", home))  # the record has no AskUserQuestion tool_use binding
        self.assertFalse(sw.verified(SESSION, "no-such-uuid", home))
        self.assertFalse(sw.verified("22222222-2222-4222-8222-222222222222", "u1", home))  # no transcript


class CliBase(Base):
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
        patches = [mock.patch.dict(os.environ, {"AH_HOME": str(self.home), "HOME": str(self.home)}),
                   mock.patch.object(sw, "verified", lambda *a: True),
                   mock.patch.object(sw, "_default_runner", lambda argv: self.calls.append(argv) or (0, "{}", ""))]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def run_main(self, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = sw.main(["--session", SESSION, *args])
        return code, json.loads(out.getvalue())


class Cli(CliBase):
    def test_listing_closes_nothing_and_apply_needs_only(self):
        code, doc = self.run_main()
        self.assertEqual((code, sorted(a["ask"] for a in doc["answered"])), (0, ["w00000000001", "w00000000002"]))
        self.assertNotIn("closed", doc)
        code, doc = self.run_main("--apply")
        self.assertEqual(code, 2)
        self.assertIn("--only", doc["problem"])

    def test_apply_closes_exactly_the_named_asks_and_never_a_stale_one(self):
        code, doc = self.run_main()
        pin = {a["ask"]: a["pin"] for a in doc["answered"]}["w00000000002"]
        self.assertEqual(pin, "w00000000002=u1")
        code, doc = self.run_main("--apply", "--only", pin, "w00000000003=x", "--stale")
        self.assertEqual(code, 1)  # the stale ask has no answer: never closed here, and that is reported
        self.assertEqual([(c["ask"], c["rc"]) for c in doc["closed"]], [("w00000000002", 0), ("w00000000003", 3)])
        self.assertEqual([a[a.index("--ref") + 1] for a in self.calls], ["w00000000002"])
        self.assertEqual([s["ask"] for s in doc["stale"]], ["w00000000003"])

    def test_a_short_answer_stays_unclosable_even_when_named_with_only(self):
        proj = self.home / ".claude" / "projects" / "p" / f"{SESSION}.jsonl"
        proj.write_text(json.dumps(answer_record("u2", {"[ask:w00000000001] Fable?": "No"})) + "\n")
        code, doc = self.run_main("--apply", "--only", "w00000000001=u2")
        self.assertEqual((code, doc["answered"], [c["rc"] for c in doc["closed"]], self.calls), (1, [], [3], []))
        self.assertEqual([s["ask"] for s in doc["short"]], ["w00000000001"])

    def test_a_bad_session_id_is_refused(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(sw.main(["--session", "../../x"]), 2)


S1 = "aaaaaaaa-0000-4000-8000-000000000001"   # the session that asked
S2 = "bbbbbbbb-0000-4000-8000-000000000002"   # a successor or the coordinator


def wrow(event, ident, at, note, source="inferred: test", **extra):
    return {"at": at, "event": event, "id": ident, "note": note, "source": source, **extra}


def bash_input(uuid, ts, command):
    return {"type": "user", "uuid": uuid, "timestamp": ts,
            "message": {"role": "user", "content": f"<bash-input>{command}</bash-input>"}}


class WalBase(unittest.TestCase):
    """GoodQA goodqa#16944: answers that arrive as decision rows, successor-session closes, SUPERSEDES asks or the user's
    own terminal commands. Listed for main; a close is bookkeeping (no --decision) and a terminal match needs CONFIRM."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)

    def wal(self, session, rows, name="main.jsonl"):
        folder = self.home / ".claude" / "wals" / session
        folder.mkdir(parents=True, exist_ok=True)
        with open(folder / name, "a") as fh:
            fh.write("".join(json.dumps(r) + "\n" for r in rows))

    def transcript(self, session, rows):
        folder = self.home / ".claude" / "projects" / "-Users-x"
        folder.mkdir(parents=True, exist_ok=True)
        with open(folder / (session + ".jsonl"), "a") as fh:
            fh.write("".join(json.dumps(r) + "\n" for r in rows))

    def items(self, related=()):
        return {i["ask"]: i for i in sw.wal_evidence(self.home, S1, related)["items"]}

    def said(self, session, n, text, ts="2026-11-23T19:01:00.000Z"):
        """A human turn of SESSION that says exactly TEXT, and the user: source that cites it whole. WAL evidence is
        offered as a close only for a citation of the whole turn (#170 round 4), so a closable fixture needs a real turn."""
        ident = "%08d-0000-4000-8000-%012d" % (9, n)
        self.transcript(session, [{"type": "user", "uuid": ident, "timestamp": ts, "sessionId": session,
                                   "origin": {"kind": "human"}, "message": {"role": "user", "content": text}}])
        return f'user:{session}/{ident} "{text}"'


class WalEvidence(WalBase):
    def test_decision_row_citing_the_users_answer_resolves_without_a_decision(self):
        source = self.said(S1, 1, "Yes, past the limit too")
        self.wal(S1, [wrow("ask", "w00000000a01", "2026-11-23T19:06:00+00:00", "U6: may reviews attempt Astra?"),
                      wrow("decision", "w00000000d01", "2026-11-23T22:04:00+00:00",
                           "User answers: U6 (asks w00000000a01) yes", source=source)])
        item = self.items()["w00000000a01"]
        self.assertEqual((item["kind"], item["manual"]), ("answer", False))
        argv = sw.close_argv(item)
        self.assertNotIn("--decision", argv)
        self.assertEqual(argv[argv.index("--source") + 1], source)
        self.assertEqual(argv[argv.index("--by") + 1], "ask-sweep")

    def test_a_row_citing_part_of_the_turn_is_manual_and_the_whole_turn_is_closed(self):
        # #170 round 4 (CRITICAL): "Do not stop the worker now" cited as "stop the worker now" says the opposite
        whole = self.said(S1, 60, "Do not stop the worker now")
        part = whole.replace('"Do not stop the worker now"', '"stop the worker now"')
        self.wal(S1, [wrow("ask", "w00000000a60", "2026-11-23T19:00:00+00:00", "may main stop the worker?"),
                      wrow("ask", "w00000000a61", "2026-11-23T19:00:00+00:00", "may main stop the worker? (again)"),
                      wrow("decision", "w00000000d60", "2026-11-23T20:00:00+00:00",
                           "Answer to ask w00000000a60: the user answered", source=part),
                      wrow("decision", "w00000000d61", "2026-11-23T20:00:00+00:00",
                           "Answer to ask w00000000a61: the user answered", source=whole)])
        items = self.items()
        self.assertEqual((items["w00000000a60"]["kind"], items["w00000000a60"]["manual"], items["w00000000a60"].get("partial")),
                         ("answer", True, True))
        self.assertIsNone(sw.close_argv(items["w00000000a60"]))
        self.assertEqual((items["w00000000a61"]["manual"], items["w00000000a61"].get("partial")), (False, None))
        argv = sw.close_argv(items["w00000000a61"])
        self.assertEqual(argv[argv.index("--source") + 1], whole)

    def test_earlier_unrelated_agent_and_pending_rows_do_not_resolve(self):
        self.wal(S1, [
            wrow("decision", "w00000000d02", "2026-11-23T18:00:00+00:00", "about w00000000a02 before it was asked",
                 source=f'answer:{S1}/1 "Yes"'),
            wrow("ask", "w00000000a02", "2026-11-23T19:00:00+00:00", "may main delete X?"),
            wrow("decision", "w00000000d03", "2026-11-23T19:30:00+00:00", "an answer about something else",
                 source=f'answer:{S1}/2 "Yes"'),
            wrow("decision", "w00000000d04", "2026-11-23T19:40:00+00:00", "main thinks w00000000a02 is fine",
                 source="inferred: main"),
            wrow("decision", "w00000000d05", "2026-11-23T19:50:00+00:00", "staff flows not tested pending ask w00000000a02",
                 source=f'user:{S1}/3 "get it done"'),
        ])
        self.assertEqual(self.items(), {})

    def test_the_real_answer_outranks_an_earlier_mention(self):
        self.wal(S1, [
            wrow("ask", "w00000000a03", "2026-11-21T21:29:00+00:00", "may the click-test sign in on staging?"),
            wrow("status", "w00000000s03", "2026-11-21T22:00:00+00:00", "see w00000000a03 later", source=f'user:{S1}/9 "keep going"'),
            wrow("decision", "w00000000d06", "2026-11-21T22:48:00+00:00", "Answer to ask w00000000a03: the user approved",
                 source=f'user:{S1}/10 "Yes, use them"'),
        ])
        self.assertEqual(self.items()["w00000000a03"]["evidence"][0]["ref"], "w00000000d06")

    def test_a_close_in_a_related_session_is_found_and_closes_the_asking_wal(self):
        self.wal(S1, [wrow("ask", "w00000000a04", "2026-11-23T19:00:00+00:00", "q")])
        self.wal(S2, [wrow("ask_resolved", "w00000000r04", "2026-11-23T20:00:00+00:00", "closed here",
                           ref="w00000000a04", source=self.said(S2, 4, "Yes"))])
        self.assertEqual(self.items(), {})
        item = self.items([S2])["w00000000a04"]
        self.assertEqual(item["kind"], "resolved-elsewhere")
        argv = sw.close_argv(item)
        self.assertEqual(argv[argv.index("--wal") + 1], str(self.home / ".claude" / "wals" / S1 / "main.jsonl"))

    def test_terminal_match_needs_a_distinctive_token_after_the_ask_and_is_manual_only(self):
        path = "/home/eric/.agent-harness/work/heldout/scoring/__pycache__"
        self.wal(S1, [wrow("ask", "w00000000a05", "2026-11-23T22:47:00+00:00", f"Run on t2-dev: rm -r {path}"),
                      wrow("ask", "w00000000a06", "2026-11-23T22:48:00+00:00", "free space under /home/eric/.agent-harness/work")])
        self.transcript(S1, [bash_input("u-before", "2026-11-23T22:00:00.000Z", f"ssh t2-dev rm -r {path}"),
                             bash_input("u-after", "2026-11-24T00:18:00.000Z", f"ssh t2-dev rm -r {path}"),
                             bash_input("u-du", "2026-11-24T00:19:00.000Z", "du -sh /home/eric/.agent-harness/work")])
        items = self.items()
        self.assertNotIn("w00000000a06", items)   # a generic path alone is not evidence
        item = items["w00000000a05"]
        self.assertEqual((item["kind"], item["manual"]), ("terminal", True))
        self.assertEqual([e["ref"] for e in item["evidence"]], [f"{S1}/u-after"])
        self.assertIsNone(sw.close_argv(item))  # no source exists that wal_note accepts: never closed here
        self.assertFalse(hasattr(sw, "check_argv"))  # and no observation row is ever written for it

    def test_ranking_with_every_kind_at_once(self):
        path = "/home/eric/.agent-harness/work/heldout/scoring/__pycache__"
        ask_row = wrow("ask", "w00000000a20", "2026-11-23T19:00:00+00:00", f"Run on t2-dev: rm -r {path}")
        superseding = wrow("ask", "w00000000b20", "2026-11-23T19:10:00+00:00", "SUPERSEDES w00000000a20: reworded")
        answer_user = wrow("decision", "w00000000d21", "2026-11-23T19:20:00+00:00", "Answer to ask w00000000a20: approved",
                           source=f'user:{S1}/7 "Yes, go ahead now"')
        answer_card = wrow("decision", "w00000000d22", "2026-11-23T19:30:00+00:00", "Answer to ask w00000000a20: approved",
                           source=f'answer:{S1}/8 "Yes, go ahead now"')
        elsewhere = wrow("ask_resolved", "w00000000r20", "2026-11-23T19:40:00+00:00", "closed there", ref="w00000000a20",
                         source=f'answer:{S2}/9 "Yes"')
        self.transcript(S1, [bash_input("u-after", "2026-11-23T19:05:00.000Z", f"ssh t2-dev rm -r {path}")])
        self.wal(S1, [ask_row, superseding])
        self.assertEqual(self.items()["w00000000a20"]["evidence"][0]["kind"], "superseded")  # superseded beats terminal
        self.wal(S1, [answer_user])
        self.assertEqual(self.items()["w00000000a20"]["evidence"][0]["ref"], "w00000000d21")  # an answer beats superseded
        self.wal(S1, [answer_card])
        self.assertEqual(self.items()["w00000000a20"]["evidence"][0]["ref"], "w00000000d22")  # answer: beats user:
        self.wal(S2, [elsewhere])
        kinds = [e["kind"] for e in self.items([S2])["w00000000a20"]["evidence"]]
        self.assertEqual(kinds, ["resolved-elsewhere", "answer", "answer", "superseded", "terminal"])

    def test_supersedes_needs_the_exact_id(self):
        self.wal(S1, [wrow("ask", "w00000000a07", "2026-11-23T18:27:00+00:00", "run h3d.sh"),
                      wrow("ask", "w00000000a08", "2026-11-23T22:41:00+00:00", "SUPERSEDES w00000000a071 (another ask)")])
        self.assertEqual(self.items(), {})

    def test_a_symlinked_or_fifo_wal_is_unread_never_followed(self):
        self.wal(S1, [wrow("ask", "w00000000a30", "2026-11-23T19:00:00+00:00", "q")])
        self.wal(S2, [wrow("decision", "w00000000d30", "2026-11-23T20:00:00+00:00", "Answer to ask w00000000a30: yes",
                           source=f'answer:{S2}/1 "Yes, do it"')])
        folder = self.home / ".claude" / "wals" / S1
        (folder / "agent-evil.jsonl").symlink_to(self.home / ".claude" / "wals" / S2 / "main.jsonl")
        os.mkfifo(folder / "agent-fifo.jsonl")
        found = sw.wal_evidence(self.home, S1)
        self.assertEqual(found["items"], [])
        reasons = {Path(u["source"]).name: u["reason"] for u in found["unread"]}
        self.assertEqual(reasons.get("agent-evil.jsonl"), "file-symlink")
        self.assertEqual(reasons.get("agent-fifo.jsonl"), "file-not-regular")

    def test_resolved_elsewhere_keeps_the_other_close_s_outcome(self):
        self.wal(S1, [wrow("ask", "w00000000a40", "2026-11-23T19:00:00+00:00", "q")])
        self.wal(S2, [wrow("ask_resolved", "w00000000r40", "2026-11-23T20:00:00+00:00", "obsolete there", ref="w00000000a40",
                           source=f"wal:/x/main.jsonl#w00000000b40", outcome="obsolete")])
        argv = sw.close_argv(self.items([S2])["w00000000a40"])
        self.assertEqual(argv[argv.index("--outcome") + 1], "obsolete")

    def test_a_superseded_ask_closes_as_obsolete_on_wal_evidence(self):
        self.wal(S1, [wrow("ask", "w00000000a07", "2026-11-23T18:27:00+00:00", "run h3d.sh"),
                      wrow("ask", "w00000000a08", "2026-11-23T22:41:00+00:00", "SUPERSEDES w00000000a07 (re-worded)")])
        item = self.items()["w00000000a07"]
        argv = sw.close_argv(item)
        self.assertEqual(argv[argv.index("--outcome") + 1], "obsolete")
        self.assertTrue(argv[argv.index("--source") + 1].startswith("wal:"))
        self.assertTrue(argv[argv.index("--source") + 1].endswith("#w00000000a08"))
        self.assertNotIn("--decision", argv)

    def test_listing_writes_nothing_and_unreadable_sources_are_named(self):
        self.wal(S1, [wrow("ask", "w00000000a09", "2026-11-23T19:00:00+00:00", "q")])
        before = {str(p): p.read_bytes() for p in self.home.rglob("*") if p.is_file()}
        found = sw.wal_evidence(self.home, S1, [S2])
        self.assertEqual({str(p): p.read_bytes() for p in self.home.rglob("*") if p.is_file()}, before)
        self.assertTrue(any(S2 in u["source"] for u in found["unread"]))

    def test_main_lists_evidence_and_applies_only_named_asks(self):
        self.wal(S1, [wrow("ask", "w00000000a10", "2026-11-23T19:00:00+00:00", "q one"),
                      wrow("ask", "w00000000a11", "2026-11-23T19:00:00+00:00", "q two"),
                      wrow("decision", "w00000000d10", "2026-11-23T20:00:00+00:00", "answered w00000000a10 and w00000000a11",
                           source=self.said(S1, 10, "Yes, both"))])
        calls = []
        with mock.patch.dict(os.environ, {"AH_HOME": str(self.home), "HOME": str(self.home)}), \
                mock.patch.object(sw, "_default_runner", lambda argv: calls.append(argv) or (0, "{}", "")), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(sw.main(["--session", S1]), 0)
            listed = json.loads(out.getvalue())
        self.assertEqual(sorted(i["ask"] for i in listed["evidence"]), ["w00000000a10", "w00000000a11"])
        self.assertEqual({i["pin"] for i in listed["evidence"]}, {"w00000000a10=w00000000d10", "w00000000a11=w00000000d10"})
        self.assertNotIn("closed", listed)
        self.assertEqual(calls, [])
        with mock.patch.dict(os.environ, {"AH_HOME": str(self.home), "HOME": str(self.home)}), \
                mock.patch.object(sw, "_default_runner", lambda argv: calls.append(argv) or (0, "{}", "")), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(sw.main(["--session", S1, "--apply", "--only", "w00000000a10=w00000000d10"]), 0)
        self.assertEqual([a[a.index("--ref") + 1] for a in calls], ["w00000000a10"])


REAL_RUNNER = sw._default_runner


class Home(CliBase):
    """#170 round 2 F7: ask_sweep, wal_note.py, wal.append and provenance must read and write one home."""

    def test_a_different_ah_home_or_config_dir_is_refused_and_nothing_runs(self):
        other = self.root / "elsewhere"
        other.mkdir()
        for env in ({"AH_HOME": str(other)}, {"CLAUDE_CONFIG_DIR": str(other / ".claude")}):
            with self.subTest(env=env), mock.patch.dict(os.environ, env):
                code, doc = self.run_main()
                self.assertEqual((code, doc["ok"]), (2, False))
                self.assertIn(next(iter(env)), doc["problem"])
                code, doc = self.run_main("--apply", "--only", "w00000000001=u1")
                self.assertEqual((code, self.calls), (2, []))

    def test_the_same_home_by_another_spelling_is_accepted(self):
        link = self.root / "home-link"
        link.symlink_to(self.home)
        with mock.patch.dict(os.environ, {"AH_HOME": str(link), "CLAUDE_CONFIG_DIR": str(link / ".claude")}):
            self.assertIsNone(sw.home_problem())
            self.assertEqual(self.run_main()[0], 0)
        with mock.patch.dict(os.environ, {"AH_HOME": "", "CLAUDE_CONFIG_DIR": ""}):
            self.assertIsNone(sw.home_problem())


class ApplyErrors(CliBase):
    """#170 round 2 F4: a timeout or a wal_note that cannot start never loses the report, and a rerun names closed asks."""

    def test_the_runner_turns_a_timeout_and_an_os_error_into_refused_results(self):
        with mock.patch.object(sw.subprocess, "run", side_effect=subprocess.TimeoutExpired(cmd="wal_note.py", timeout=60)):
            rc, _out, err = REAL_RUNNER(["wal_note.py"])
        self.assertEqual(rc, sw.RC_TIMEOUT)
        self.assertIn("did not finish", err)
        with mock.patch.object(sw.subprocess, "run", side_effect=FileNotFoundError("python")):
            self.assertEqual(REAL_RUNNER(["wal_note.py"])[0], sw.RC_NOT_RUN)

    def test_a_timeout_during_apply_still_prints_the_report_and_exits_1(self):
        with mock.patch.object(sw, "_default_runner", REAL_RUNNER), \
                mock.patch.object(sw.subprocess, "run", side_effect=subprocess.TimeoutExpired(cmd="wal_note.py", timeout=60)):
            code, doc = self.run_main("--apply", "--only", "w00000000001=u1", "w00000000002=u1")
        self.assertEqual(code, 1)
        self.assertEqual([(c["ask"], c["rc"]) for c in doc["closed"]], [("w00000000001", 124), ("w00000000002", 124)])
        self.assertIn("did not finish", doc["closed"][0]["refused"])

    def test_a_close_written_before_the_timeout_is_reported_as_written(self):
        wal = self.home / ".claude" / "wals" / SESSION / "main.jsonl"

        def slow_writer(argv):
            with open(wal, "a") as fh:
                fh.write(json.dumps({"event": "ask_resolved", "id": "w0000000c001", "ref": argv[argv.index("--ref") + 1],
                                     "source": argv[argv.index("--source") + 1], "by": "ask-sweep"}) + "\n")
            return sw.RC_TIMEOUT, "", "wal_note.py did not finish"
        with mock.patch.object(sw, "_default_runner", slow_writer):
            code, doc = self.run_main("--apply", "--only", "w00000000001=u1")
        self.assertEqual((code, doc["closed"][0]["rc"], doc["closed"][0]["written"]), (0, 0, "w0000000c001"))

    def test_a_close_another_row_wrote_meanwhile_is_reported_as_that_row(self):
        wal = self.home / ".claude" / "wals" / SESSION / "main.jsonl"

        def refused_but_closed_elsewhere(argv):
            with open(wal, "a") as fh:
                fh.write(json.dumps({"event": "ask_resolved", "id": "w0000000c003", "ref": "w00000000001",
                                     "source": "ticket:GoodQA x#1", "closed_by": "agent"}) + "\n")
            return 2, "", '{"status": "REFUSED"}'
        with mock.patch.object(sw, "_default_runner", refused_but_closed_elsewhere):
            code, doc = self.run_main("--apply", "--only", "w00000000001=u1")
        self.assertEqual((code, doc["closed"][0].get("already_resolved"), "written" in doc["closed"][0]),
                         (0, "w0000000c003", False))

    def test_a_rerun_reports_an_already_closed_ask_as_resolved_and_writes_nothing(self):
        wal = self.home / ".claude" / "wals" / SESSION / "main.jsonl"
        with open(wal, "a") as fh:
            fh.write(json.dumps({"event": "ask_resolved", "id": "w0000000c002", "ref": "w00000000002",
                                 "source": 'answer:x/u1 "Answer number two"', "by": "ask-sweep",
                                 "closed_by": "ask-sweep"}) + "\n")
        code, doc = self.run_main("--apply", "--only", "w00000000002=u1")
        self.assertEqual(code, 0)
        self.assertEqual(doc["closed"], [{"ask": "w00000000002", "rc": 0, "already_resolved": "w0000000c002",
                                          "closed_by": "ask-sweep", "note": "already closed; nothing was written"}])
        self.assertEqual(self.calls, [])


class Incomplete(CliBase):
    """#170 round 2 F2 at the CLI: whatever the reader could not read makes the listing exit 2, and --apply refuses."""

    def test_an_unparseable_wal_line_makes_the_listing_exit_2_and_apply_refuse(self):
        agent = self.home / ".claude" / "wals" / SESSION / "agent-x.jsonl"
        agent.write_text('{"event": "decision", "note": "torn\n')
        code, doc = self.run_main()
        self.assertEqual(code, 2)
        self.assertEqual([(Path(u["source"]).name, u["reason"]) for u in doc["unread"]], [("agent-x.jsonl", "line-malformed")])
        code, doc = self.run_main("--apply", "--only", "w00000000001=u1")
        self.assertEqual((code, doc["closed"][0]["rc"], self.calls), (1, 3, []))
        self.assertIn("incomplete", doc["closed"][0]["refused"])

    def test_a_newer_answer_on_a_skipped_line_is_never_silently_missed(self):
        proj = self.home / ".claude" / "projects" / "p" / f"{SESSION}.jsonl"
        newer = answer_record("u9", {"[ask:w00000000001] Q one?": "A much newer answer " + "z" * 400})
        with open(proj, "a") as fh:
            fh.write(json.dumps(newer) + "\n")
        with mock.patch.object(ask_evidence, "MAX_LINE", 400):
            code, doc = self.run_main()
            self.assertEqual(code, 2)  # the listing still shows the older u1, but it says it is not complete
            self.assertEqual([(u["reason"], u["lines"]) for u in doc["unread"]], [("line-too-long", [2])])
            code, doc = self.run_main("--apply", "--only", "w00000000001=u1")
        self.assertEqual((code, self.calls), (1, []))


S3 = "cccccccc-0000-4000-8000-000000000003"


class Ranking(WalBase):
    """#170 round 2 F6: the user's answer outranks a related-session close that carries an outcome."""

    def test_an_answer_row_outranks_an_obsolete_close_elsewhere(self):
        self.wal(S1, [wrow("ask", "w00000000a50", "2026-11-23T19:00:00+00:00", "may main release?"),
                      wrow("decision", "w00000000d50", "2026-11-23T20:00:00+00:00", "Answer to ask w00000000a50: approved",
                           source=self.said(S1, 50, "Yes, release it"))])
        self.wal(S2, [wrow("ask_resolved", "w00000000r50", "2026-11-23T21:00:00+00:00", "obsolete there",
                           ref="w00000000a50", source="wal:/x/main.jsonl#w00000000b50", outcome="obsolete")])
        item = self.items([S2])["w00000000a50"]
        self.assertEqual([e["ref"] for e in item["evidence"]], ["w00000000d50", "w00000000r50"])
        argv = sw.close_argv(item)
        self.assertNotIn("--outcome", argv)
        self.assertEqual(argv[argv.index("--source") + 1], f'user:{S1}/%08d-0000-4000-8000-%012d "Yes, release it"' % (9, 50))

    def test_a_human_close_is_not_hidden_behind_an_earlier_outcome_close(self):
        self.wal(S1, [wrow("ask", "w00000000a51", "2026-11-23T19:00:00+00:00", "q")])
        self.wal(S2, [wrow("ask_resolved", "w00000000r51", "2026-11-23T20:00:00+00:00", "obsolete there",
                           ref="w00000000a51", source="wal:/x/main.jsonl#w00000000b51", outcome="obsolete")])
        self.wal(S3, [wrow("ask_resolved", "w00000000r52", "2026-11-23T21:00:00+00:00", "answered there",
                           ref="w00000000a51", source=self.said(S3, 52, "Close it, it is done"))])
        item = self.items([S2, S3])["w00000000a51"]
        self.assertEqual([e["ref"] for e in item["evidence"]], ["w00000000r52", "w00000000r51"])
        self.assertNotIn("--outcome", sw.close_argv(item))


class OneRule(unittest.TestCase):
    """Class 2 and class 4 guard (#170 round 2 F5): one reader, one fold, one quoting rule, one SUPERSEDES matcher.

    - ask_sweep imports no hook module but ask_evidence and provenance, and reads no file itself;
    - ask_evidence opens files in jsonl_records only, through safe_input.open_regular_file;
    - ask_reminders.open_asks is ask_evidence.read_asks;
    - wal_note reads --outcome evidence through provenance.wal_entry and matches through ask_evidence;
    - no module swaps a double quote for a single one (the broken F3 substitution)."""

    HOOKS = Path(sw.__file__).resolve().parent
    READS = {"open", "read_text", "read_bytes", "fdopen", "pread", "readline", "readlines", "glob", "rglob", "scandir"}

    def tree(self, name):
        return ast.parse((self.HOOKS / name).read_text(), name)

    def calls(self, node):
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call):
                func = sub.func
                yield sub, func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else None

    def function(self, tree, name):
        return next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == name)

    def test_ask_sweep_reads_nothing_itself_and_depends_only_on_the_shared_modules(self):
        tree = self.tree("ask_sweep.py")
        local = {p.stem for p in self.HOOKS.glob("*.py")}
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        self.assertEqual(imported & local, {"ask_evidence", "provenance"})
        self.assertEqual(sorted(name for _call, name in self.calls(tree) if name in self.READS), [])

    def test_ask_evidence_opens_files_only_in_the_bounded_reader(self):
        tree = self.tree("ask_evidence.py")
        reader = self.function(tree, "jsonl_records")
        inside = {id(c) for c, _ in self.calls(reader)}
        outside = [name for call, name in self.calls(tree) if id(call) not in inside and name in self.READS | {"open_regular_file"}]
        self.assertEqual(outside, [])
        self.assertIn("open_regular_file", {name for _c, name in self.calls(reader)})
        self.assertNotIn("open", {name for _c, name in self.calls(reader)})

    def test_ask_reminders_open_asks_is_the_shared_fold(self):
        names = {name for _c, name in self.calls(self.function(self.tree("ask_reminders.py"), "open_asks"))}
        self.assertIn("read_asks", names)
        self.assertFalse(names & self.READS, names)

    def test_wal_note_reads_outcome_evidence_through_provenance_and_matches_through_ask_evidence(self):
        text = (self.HOOKS / "wal_note.py").read_text()
        self.assertNotIn("SUPERSEDES\\s", text)
        names = {name for _c, name in self.calls(self.function(self.tree("wal_note.py"), "outcome_evidence_problem"))}
        self.assertTrue({"wal_entry", "supersedes", "human_traced"} <= names, names)
        self.assertFalse(names & self.READS, names)

    def test_no_module_swaps_a_double_quote_for_a_single_one(self):
        def is_char(node, char):
            return ((isinstance(node, ast.Constant) and node.value == char)
                    or (isinstance(node, ast.Call) and getattr(node.func, "id", None) == "chr" and len(node.args) == 1
                        and isinstance(node.args[0], ast.Constant) and node.args[0].value == ord(char)))
        for name in ("ask_sweep.py", "ask_evidence.py"):
            swaps = [c.lineno for c, n in self.calls(self.tree(name)) if n == "replace" and len(c.args) == 2
                     and is_char(c.args[0], '"') and is_char(c.args[1], "'")]
            self.assertEqual(swaps, [], name)


if __name__ == "__main__":
    unittest.main()
