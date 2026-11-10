"""Mission coverage (GoodQA goodqa#15565): every active mission goal has a live owner, a live disposition, or done
evidence; anything else is UNCOVERED and blocks main's turn end.

Evidence: 2026-11-10 the user asked "whats moving the slowest" and then "why did i have to ask this? why doesnt the
dashboard and harness deal with this?". Leads (goodqa#15095) had no owner all night; the dropped-owner scan only sees
owners that existed and stopped, so a goal that never had an owner was invisible. These tests fail against main
54c5bb2, which has no mission_coverage.py, no mission_gate.py and no ops_watch `mission` check.
"""
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
HOOKS = ROOT / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import mission_coverage as mc  # noqa: E402
import ops_watch as ow  # noqa: E402

NOW = 1_800_000_000.0
SESSION = "11111111-2222-4333-8444-555555555555"
USER_UUID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
ASK = "w0123456789a"


def iso(ts):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def goal(gid="leads", ticket="goodqa#15095", status="active", priority=1, **extra):
    g = {"id": gid, "title": gid.title(), "ticket": ticket, "priority": priority, "status": status}
    g.update(extra)
    return g


def row(agent, ticket="GoodQA #15095", state="live", typ="task-owner", parent=None, last=NOW - 60, **extra):
    r = {"agent_id": agent, "type": typ, "ticket": ticket, "state": state, "owner": typ == "task-owner",
         "parent": parent, "last_activity": iso(last), "idle_s": int(NOW - last), "disposition": None,
         "decision_required": False}
    r.update(extra)
    return r


def never(_source):
    return False


def always(_source):
    return True


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        env = mock.patch.dict(os.environ, {"AH_HOME": str(self.home), "HOME": str(self.home),
                                           "CLAUDE_CONFIG_DIR": str(self.home / ".claude")})
        env.start()
        self.addCleanup(env.stop)
        for k in ("CLAUDE_CODE_SESSION_ID", "CLAUDE_SESSION_ID"):
            os.environ.pop(k, None)
        self.wal = self.home / ".claude" / "wals" / SESSION
        self.wal.mkdir(parents=True)
        (self.wal / "main.jsonl").write_text(
            json.dumps({"at": iso(NOW - 900), "event": "ask", "id": ASK, "note": "pick the leads source"}) + "\n")
        self.transcript = self.home / ".claude" / "projects" / "proj" / f"{SESSION}.jsonl"
        self.transcript.parent.mkdir(parents=True)
        self.transcript.write_text(json.dumps({
            "type": "user", "uuid": USER_UUID, "origin": {"kind": "human"}, "timestamp": iso(NOW - 600),
            "message": {"role": "user", "content": "park the self-update goal until next week"}}) + "\n")

    def results(self, goals, rows=(), **kw):
        kw.setdefault("asks", {})
        kw.setdefault("verify_source", never)
        kw.setdefault("verify_evidence", lambda g: False)
        return {r["id"]: r for r in mc.evaluate(goals, list(rows), NOW, **kw)}

    def write_goals(self, goals):
        for g in goals:
            mc.add_goal(self.home, g["id"], g.get("title") or g["id"], g.get("ticket", ""), g.get("priority", 3))

    def payload(self, **extra):
        p = {"session_id": SESSION, "hook_event_name": "Stop", "stop_hook_active": False,
             "transcript_path": str(self.transcript)}
        p.update(extra)
        return p

    def stop(self, rows=(), now=NOW, **extra):
        with mock.patch.object(mc, "owner_rows", return_value=list(rows)):
            return mission_gate.cmd_stop(self.payload(**extra), now=now)


class Coverage(Base):
    def test_goal_with_no_owner_and_no_disposition_is_uncovered(self):
        r = self.results([goal()])["leads"]
        self.assertEqual(r["state"], "UNCOVERED")

    def test_live_owner_on_the_goal_ticket_covers(self):
        r = self.results([goal()], [row("a1111111")])["leads"]
        self.assertEqual(r["state"], "COVERED")
        self.assertEqual(r["owners"], ["a1111111"])

    def test_owner_for_a_different_ticket_does_not_cover(self):
        r = self.results([goal()], [row("a1111111", ticket="GoodQA #15561")])["leads"]
        self.assertEqual(r["state"], "UNCOVERED")

    def test_ticket_match_is_by_number_and_project_not_by_name(self):
        self.assertEqual(mc.ticket_key("GoodQA goodqa #15095"), "goodqa#15095")
        self.assertEqual(mc.ticket_key("goodqa#15095"), "goodqa#15095")
        self.assertEqual(mc.ticket_key("ParentProof#615"), "parentproof#615")
        self.assertFalse(mc.same_ticket("goodqa#15095", "goodqa#150950"))
        self.assertFalse(mc.same_ticket("parentproof#615", "goodqa#615"))
        r = self.results([goal(title="leads")], [row("leads", ticket="GoodQA #1")])["leads"]
        self.assertEqual(r["state"], "UNCOVERED")  # an agent named like the goal is not its owner

    def test_helper_never_covers(self):
        for typ in ("red-team", "click-tester", "fixer", "Explore", "Plan"):
            r = self.results([goal()], [row("a2222222", typ=typ)])["leads"]
            self.assertEqual(r["state"], "UNCOVERED", typ)

    def test_stopped_or_dropped_owner_does_not_cover(self):
        for state in ("DROPPED", "done", "handoff", "returned", "finishing"):
            r = self.results([goal()], [row("a1111111", state=state)])["leads"]
            self.assertEqual(r["state"], "UNCOVERED", state)

    def test_subagent_owner_of_the_same_ticket_counts(self):
        rows = [row("aparent0", ticket="GoodQA #15565"), row("achild00", parent="aparent0", spawn_depth=2)]
        r = self.results([goal()], rows)["leads"]
        self.assertEqual(r["state"], "COVERED")
        self.assertEqual(r["owners"], ["achild00"])

    def test_fake_owner_id_in_the_goals_file_does_not_count(self):
        g = goal(owner="aaef3bc7", owners=["aaef3bc7"], dashboard={"owner": "aaef3bc7"})
        r = self.results([g], [])["leads"]
        self.assertEqual(r["state"], "UNCOVERED")

    def test_goal_without_ticket_cannot_be_owner_covered(self):
        r = self.results([goal(ticket="")], [row("a1111111", ticket=None)])["leads"]
        self.assertEqual(r["state"], "UNCOVERED")
        self.assertIn("ticket", r["reason"])


class Dispositions(Base):
    def test_open_ask_with_future_until_covers(self):
        g = goal(deferral={"by": "ask", "ref": ASK, "until": iso(NOW + 3600)})
        r = self.results([g], asks={ASK: "open"})["leads"]
        self.assertEqual(r["state"], "WAITING")

    def test_expired_disposition_blocks(self):
        g = goal(deferral={"by": "ask", "ref": ASK, "until": iso(NOW - 1)})
        self.assertEqual(self.results([g], asks={ASK: "open"})["leads"]["state"], "UNCOVERED")
        g = goal(deferral={"by": "ticket", "ref": "goodqa#15561", "until": iso(NOW - 1)})
        self.assertEqual(self.results([g])["leads"]["state"], "UNCOVERED")

    def test_closed_or_unknown_ask_does_not_count(self):
        g = goal(deferral={"by": "ask", "ref": ASK, "until": iso(NOW + 3600)})
        self.assertEqual(self.results([g], asks={ASK: "resolved"})["leads"]["state"], "UNCOVERED")
        self.assertEqual(self.results([g], asks={})["leads"]["state"], "UNCOVERED")

    def test_ticket_wait_needs_another_ticket_and_a_bounded_until(self):
        ok = goal(deferral={"by": "ticket", "ref": "goodqa#15561", "until": iso(NOW + 3600)})
        self.assertEqual(self.results([ok])["leads"]["state"], "WAITING")
        own = goal(deferral={"by": "ticket", "ref": "goodqa#15095", "until": iso(NOW + 3600)})
        self.assertEqual(self.results([own])["leads"]["state"], "UNCOVERED")
        forever = goal(deferral={"by": "ticket", "ref": "goodqa#15561", "until": iso(NOW + 30 * 86400)})
        self.assertEqual(self.results([forever])["leads"]["state"], "UNCOVERED")

    def test_deferral_without_resolving_user_source_does_not_count(self):
        g = goal(status="deferred", deferral={"by": "user", "source": f'user:{SESSION}/{USER_UUID} "park it"'})
        self.assertEqual(self.results([g], verify_source=never)["leads"]["state"], "UNCOVERED")
        self.assertEqual(self.results([g], verify_source=always)["leads"]["state"], "DEFERRED")

    def test_user_deferral_with_past_until_blocks(self):
        g = goal(status="deferred", deferral={"by": "user", "source": "x", "until": iso(NOW - 5)})
        self.assertEqual(self.results([g], verify_source=always)["leads"]["state"], "UNCOVERED")

    def test_default_source_verifier_resolves_the_users_own_words_only(self):
        good = f'user:{SESSION}/{USER_UUID} "park the self-update goal"'
        self.assertTrue(mc.verify_user_source(good))
        self.assertFalse(mc.verify_user_source(f'user:{SESSION}/{USER_UUID} "words the user never typed"'))
        self.assertFalse(mc.verify_user_source("inferred: from wal:x#w1 -- the agent thinks it can wait"))
        self.assertFalse(mc.verify_user_source(f'pasted:{SESSION}/{USER_UUID} "park the self-update goal"'))
        self.assertFalse(mc.verify_user_source("ticket:GoodQA goodqa#15095"))

    def test_agent_written_inferred_deferral_is_refused_at_write_and_ignored_at_read(self):
        self.write_goals([goal()])
        with self.assertRaises(mc.MissionError):
            mc.defer_goal(self.home, "leads", user_source="inferred: from wal:x#w1 -- the agent decided to wait",
                          session=SESSION, now=NOW)
        g = goal(status="deferred", deferral={"by": "user", "source": "inferred: from wal:x#w1 -- agent wants a pause"})
        self.assertEqual(self.results([g], verify_source=mc.verify_user_source)["leads"]["state"], "UNCOVERED")

    def test_defer_command_accepts_an_open_ask_and_a_verified_user_source(self):
        self.write_goals([goal(), goal("selfupdate", ticket="goodqa#15600", priority=3)])
        mc.defer_goal(self.home, "leads", ask=ASK, until=iso(NOW + 3600), session=SESSION, now=NOW)
        mc.defer_goal(self.home, "selfupdate", user_source=f'user:{SESSION}/{USER_UUID} "park the self-update goal"',
                      session=SESSION, now=NOW)
        loaded = {g["id"]: g for g in mc.load_goals(self.home)["goals"]}
        self.assertEqual(loaded["leads"]["deferral"]["by"], "ask")
        self.assertEqual(loaded["selfupdate"]["status"], "deferred")
        with self.assertRaises(mc.MissionError):  # a closed ask is refused at write time too
            with open(self.wal / "main.jsonl", "a") as fh:
                fh.write(json.dumps({"event": "ask_resolved", "ref": ASK, "at": iso(NOW)}) + "\n")
            mc.defer_goal(self.home, "leads", ask=ASK, until=iso(NOW + 3600), session=SESSION, now=NOW)


class DoneEvidence(Base):
    def add_evidence(self, deploy_note="DEPLOYED c81dfd8f to production for GoodQA goodqa#15095",
                     test_note="REALLY_TESTED leads-live: https://goodqa.app/crm live view lists 1,415 leads, "
                               "GoodQA goodqa#15095 c81dfd8f"):
        with open(self.wal / "main.jsonl", "a") as fh:
            fh.write(json.dumps({"at": iso(NOW - 500), "event": "deploy", "id": "w0000000dep1", "note": deploy_note}) + "\n")
            fh.write(json.dumps({"at": iso(NOW - 400), "event": "check", "id": "w0000000tst1", "note": test_note}) + "\n")

    def test_done_goal_without_evidence_blocks(self):
        r = self.results([goal(status="done")])["leads"]
        self.assertEqual(r["state"], "UNCOVERED")
        self.assertIn("evidence", r["reason"])

    def test_done_goal_with_evidence_passes(self):
        g = goal(status="done", done_evidence=[{"kind": "deploy", "ref": "w0000000dep1", "session": SESSION},
                                               {"kind": "really_tested", "ref": "leads-live", "session": SESSION}])
        self.assertEqual(self.results([g], verify_evidence=lambda x: True)["leads"]["state"], "DONE")
        self.add_evidence()
        self.assertTrue(mc.verify_done_evidence(self.home, g))

    def test_evidence_for_another_ticket_or_a_local_test_does_not_resolve(self):
        self.add_evidence(deploy_note="DEPLOYED c81dfd8f to production for GoodQA goodqa#15561")
        g = goal(status="done", done_evidence=[{"kind": "deploy", "ref": "w0000000dep1", "session": SESSION},
                                               {"kind": "really_tested", "ref": "leads-live", "session": SESSION}])
        self.assertFalse(mc.verify_done_evidence(self.home, g))
        only_deploy = goal(status="done", done_evidence=[{"kind": "deploy", "ref": "w0000000dep1", "session": SESSION}])
        self.assertFalse(mc.verify_done_evidence(self.home, only_deploy))

    def test_agent_marking_done_without_evidence_is_refused(self):
        self.write_goals([goal()])
        with self.assertRaises(mc.MissionError):
            mc.done_goal(self.home, "leads", deploy="w0000000dep1", live_test="leads-live", session=SESSION)
        self.assertEqual(mc.load_goals(self.home)["goals"][0]["status"], "active")
        self.add_evidence()
        mc.done_goal(self.home, "leads", deploy="w0000000dep1", live_test="leads-live", session=SESSION)
        self.assertEqual(mc.load_goals(self.home)["goals"][0]["status"], "done")

    def test_set_cannot_mark_done(self):
        self.write_goals([goal()])
        with self.assertRaises(mc.MissionError):
            mc.set_goal(self.home, "leads", status="done")


class Stalled(Base):
    def test_owner_without_progress_for_46_min_is_stalled_44_is_not(self):
        rows = [row("a1111111")]
        r = self.results([goal()], rows, progress={"a1111111": NOW - 46 * 60})["leads"]
        self.assertEqual(r["state"], "STALLED")
        self.assertEqual(r["progress_age_s"], 46 * 60)
        r = self.results([goal()], rows, progress={"a1111111": NOW - 44 * 60})["leads"]
        self.assertEqual(r["state"], "COVERED")

    def test_a_recent_commit_on_the_ticket_counts_as_progress(self):
        rows = [row("a1111111")]
        r = self.results([goal()], rows, progress={"a1111111": NOW - 90 * 60},
                         commits={"goodqa#15095": NOW - 10 * 60})["leads"]
        self.assertEqual(r["state"], "COVERED")
        self.assertEqual(r["progress_age_s"], 600)

    def test_progress_ignores_hook_lifecycle_rows(self):
        path = self.wal / "agent-a1111111.jsonl"
        path.write_text("\n".join(json.dumps(x) for x in [
            {"at": iso(NOW - 3600), "event": "subagent", "agent_id": "a1111111"},
            {"at": iso(NOW - 3000), "event": "intent", "note": "start GoodQA #15095"},
            {"at": iso(NOW - 10), "event": "pretool", "tool": "Bash"},
        ]) + "\n")
        self.assertEqual(mc.owner_progress(self.home, SESSION, "a1111111"), NOW - 3000)


class Hostile(Base):
    def write_raw(self, data: bytes):
        path = mc.goals_path(self.home)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_bytes(data)
        return path

    def assert_refused(self):
        t0 = time.monotonic()
        state = mc.load_goals(self.home)
        self.assertLess(time.monotonic() - t0, 5)
        self.assertEqual(state["state"], "error", state)
        return state

    def test_huge_file(self):
        self.write_raw(b"[" + b'{"id":"x","title":"t","ticket":"","priority":1,"status":"active"},' * 40000 + b"{}]")
        self.assert_refused()

    def test_deep_nesting(self):
        self.write_raw(b"[" * 50000 + b"]" * 50000)
        self.assert_refused()

    def test_symlink(self):
        real = self.home / "real.json"
        real.write_text(json.dumps([goal()]))
        path = mc.goals_path(self.home)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.symlink(real, path)
        self.assert_refused()

    def test_wrong_types(self):
        for bad in ({"goals": "x"}, ["leads"], [goal(ticket=15095)], [goal(status="bogus")], [goal(priority="high")],
                    [goal(gid="../etc")], [goal(), goal()], [goal(deferral="soon")], [goal(done_evidence="yes")]):
            self.write_raw(json.dumps(bad).encode())
            self.assert_refused()

    def test_fifo_does_not_hang(self):
        path = mc.goals_path(self.home)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.mkfifo(path)
        self.assert_refused()


class AuditChain(Base):
    def test_writes_are_chained_and_verify(self):
        self.write_goals([goal(), goal("tokens", ticket="goodqa#15561")])
        mc.set_goal(self.home, "tokens", priority=2)
        self.assertTrue(mc.verify_audit(self.home)["ok"])
        rows = [json.loads(x) for x in mc.audit_path(self.home).read_text().splitlines()]
        self.assertEqual([r["action"] for r in rows], ["add", "add", "set"])
        self.assertEqual(oct(mc.goals_path(self.home).stat().st_mode & 0o777), "0o600")
        self.assertEqual(oct(mc.goals_path(self.home).parent.stat().st_mode & 0o777), "0o700")

    def test_edited_audit_row_is_detected(self):
        self.write_goals([goal(), goal("tokens", ticket="goodqa#15561")])
        path = mc.audit_path(self.home)
        lines = path.read_text().splitlines()
        lines[0] = lines[0].replace('"add"', '"set"')
        path.write_text("\n".join(lines) + "\n")
        self.assertFalse(mc.verify_audit(self.home)["ok"])

    def test_deleted_audit_row_is_detected(self):
        self.write_goals([goal(), goal("tokens", ticket="goodqa#15561"), goal("g3", ticket="goodqa#3")])
        path = mc.audit_path(self.home)
        lines = path.read_text().splitlines()
        path.write_text("\n".join([lines[0], lines[2]]) + "\n")
        self.assertFalse(mc.verify_audit(self.home)["ok"])

    def test_goal_removed_by_hand_is_detected(self):
        self.write_goals([goal(), goal("tokens", ticket="goodqa#15561")])
        path = mc.goals_path(self.home)
        path.write_text(json.dumps([g for g in json.loads(path.read_text()) if g["id"] != "leads"]))
        result = mc.verify_audit(self.home)
        self.assertFalse(result["ok"])
        self.assertIn("outside mission_coverage.py", result["problem"])


class Import(Base):
    FIXTURE = ROOT / "tests" / "data" / "mission_initiatives.json"

    def test_round_trip_is_idempotent_and_keeps_manual_fields(self):
        first = mc.import_initiatives(self.home, self.FIXTURE)
        goals = {g["id"]: g for g in mc.load_goals(self.home)["goals"]}
        self.assertEqual(set(goals), {"leads", "tokens", "selfupdate", "audit", "missioncontrol"})
        self.assertEqual(goals["leads"]["ticket"], "goodqa#15095")
        self.assertEqual(goals["missioncontrol"]["title"], "Mission Control dashboard")
        self.assertTrue(all(g["status"] == "active" for g in goals.values()))  # "Done" on the dashboard is not evidence
        self.assertEqual(first["added"], 5)
        mc.set_goal(self.home, "leads", priority=1)
        mc.set_goal(self.home, "selfupdate", ticket="goodqa#15600")
        second = mc.import_initiatives(self.home, self.FIXTURE)
        self.assertEqual(second["added"], 0)
        goals = {g["id"]: g for g in mc.load_goals(self.home)["goals"]}
        self.assertEqual(goals["leads"]["priority"], 1)
        self.assertEqual(goals["selfupdate"]["ticket"], "goodqa#15600")
        self.assertEqual(len(goals), 5)
        self.assertTrue(mc.verify_audit(self.home)["ok"])

    def test_dashboard_owner_field_never_covers(self):
        mc.import_initiatives(self.home, self.FIXTURE)
        goals = mc.load_goals(self.home)["goals"]
        res = {r["id"]: r for r in mc.evaluate(goals, [], NOW, asks={}, verify_source=never,
                                               verify_evidence=lambda g: False)}
        self.assertEqual(res["tokens"]["state"], "UNCOVERED")  # dashboard says owner aaef3bc7; ah owners has none


class ReportOrder(Base):
    def test_uncovered_first_then_stalled_by_age_then_least_recent_progress(self):
        goals = [goal("covered-new", ticket="goodqa#1", priority=1), goal("stalled-old", ticket="goodqa#2"),
                 goal("uncovered-p3", ticket="goodqa#3", priority=3), goal("stalled-new", ticket="goodqa#4"),
                 goal("uncovered-p1", ticket="goodqa#5", priority=1), goal("covered-old", ticket="goodqa#6")]
        rows = [row("a1", "GoodQA #1"), row("a2", "GoodQA #2"), row("a4", "GoodQA #4"), row("a6", "GoodQA #6")]
        progress = {"a1": NOW - 60, "a2": NOW - 300 * 60, "a4": NOW - 50 * 60, "a6": NOW - 30 * 60}
        ordered = mc.sort_report(mc.evaluate(goals, rows, NOW, asks={}, verify_source=never,
                                             verify_evidence=lambda g: False, progress=progress))
        self.assertEqual([r["id"] for r in ordered],
                         ["uncovered-p1", "uncovered-p3", "stalled-old", "stalled-new", "covered-old", "covered-new"])


class CoverageMapShape(Base):
    """Mission Control's UI reads `coverage` from `report --json`: keyed by goal id AND ticket, values exactly
    {status: uncovered|stalled|moving, reason, action} (task owner af9e3370's requirement, 2026-11-10)."""

    def report(self, rows, cap=None):
        args = mc.build_parser().parse_args(["report", "--json", "--session", SESSION])
        with mock.patch.object(mc, "owner_rows", return_value=rows), mock.patch.object(mc, "owner_cap", return_value=cap), \
                mock.patch.object(mc, "owner_progress", side_effect=lambda h, s, a: NOW - (50 * 60 if a == "a2" else 60)), \
                mock.patch.object(mc.time, "time", return_value=NOW):
            doc, rc = mc.run(args, self.home)
        return doc

    def test_shape_keys_and_plain_sentences(self):
        self.write_goals([goal(), goal("tokens", ticket="goodqa#15561", priority=2),
                          goal("solve", ticket="goodqa#15584", priority=2)])
        doc = self.report([row("a2", "GoodQA #15561"), row("a3", "GoodQA #15584")])
        cov = doc["coverage"]
        self.assertEqual(set(cov), {"leads", "goodqa#15095", "tokens", "goodqa#15561", "solve", "goodqa#15584"})
        for value in cov.values():
            self.assertEqual(set(value), {"status", "reason", "action"})
            self.assertIn(value["status"], ("uncovered", "stalled", "moving"))
            for text in (value["reason"], value["action"]):
                self.assertTrue(text.endswith(".") and "\n" not in text and text.count(". ") == 0, text)
        self.assertEqual(cov["leads"], cov["goodqa#15095"])
        self.assertEqual(cov["leads"]["status"], "uncovered")
        self.assertEqual(cov["leads"]["reason"], "No live owner and no disposition.")
        self.assertEqual(cov["tokens"]["status"], "stalled")
        self.assertEqual(cov["solve"]["status"], "moving")
        self.assertEqual([g["id"] for g in doc["goals"]], ["leads", "tokens", "solve"])

    def test_action_names_the_owner_to_free_when_the_cap_is_full(self):
        self.write_goals([goal(), goal("tokens", ticket="goodqa#15561", priority=2)])
        rows = [row("a2", "GoodQA #15561"), row("azzzzzz1", "GoodQA #1", last=NOW - 4000)]
        doc = self.report(rows, cap=2)
        self.assertIn("azzzzzz1", doc["coverage"]["leads"]["action"])
        self.assertIn("azzzzzz1", doc["coverage"]["goodqa#15095"]["action"])


class Notify(Base):
    """notify_main: the producer that wakes the orchestrator (mc_chat is unmerged, goodqa#15585: tested on a stub)."""

    def test_notify_main_writes_through_mc_chat_when_importable_and_rings_always(self):
        calls = []

        class Chat:
            class ChatError(ValueError):
                pass

            @staticmethod
            def new_message(to, text, *, client_key, session=None, thread=None, root=None, ts=None):
                calls.append({"to": to, "text": text, "client_key": client_key, "session": session})
                return {"id": "dash-X"}, True
        mc.notify_main(["leads"], home=self.home, session=SESSION, chat=Chat)
        self.assertEqual(calls[0]["to"], "claude")
        self.assertEqual(calls[0]["session"], SESSION)
        self.assertIn("leads", calls[0]["text"])
        self.assertIn("not typed by the user", calls[0]["text"])
        ring = [e for e in ow.read_ring(ow.ring_path(self.home)) if e.get("key") == "mission:notify"]
        self.assertEqual(ring[-1]["event"], "raise")

    def test_notify_main_is_a_noop_on_the_chat_side_when_mc_chat_is_absent(self):
        with mock.patch.object(mc, "_load_chat", return_value=None):
            mc.notify_main(["leads"], home=self.home, session=SESSION)
        ring = [e for e in ow.read_ring(ow.ring_path(self.home)) if e.get("key") == "mission:notify"]
        self.assertEqual(ring[-1]["event"], "raise")
        mc.notify_main([], home=self.home, session=SESSION)
        ring = [e for e in ow.read_ring(ow.ring_path(self.home)) if e.get("key") == "mission:notify"]
        self.assertEqual(ring[-1]["event"], "clear")

    def test_chat_refusal_never_breaks_notify(self):
        class Chat:
            class ChatError(ValueError):
                pass

            @staticmethod
            def new_message(*a, **k):
                raise Chat.ChatError("no-target")
        mc.notify_main(["leads"], home=self.home, session=SESSION, chat=Chat)


if __name__ == "__main__":
    unittest.main()
