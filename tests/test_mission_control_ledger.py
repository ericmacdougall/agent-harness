"""The Ledger source (GoodQA goodqa#15920 AC-2, AC-9, NEG-3, NEG-4): goals, requirements and status reads, bounded,
last-good on failure, published only on change, with the archive rule applied."""
import json
import os
import sys
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "harness" / "hooks"))
sys.path.insert(0, str(REPO / "harness" / "mission_control"))
os.environ.setdefault("MC_HOOKS", str(REPO / "harness" / "hooks"))

import collectors as col  # noqa: E402
import events as ev  # noqa: E402
from safeio import Refused, Runner  # noqa: E402

SID = "baab765b-d85c-46b4-b7b9-588eb912c770"
NOW = time.time()


def iso(age):
    return ev.iso(NOW - age)


GOALS = {"generated": iso(0), "session": SID, "state": "OK", "warnings": [], "goals": [
    {"id": "leads", "title": "1000 leads in the CRM", "ticket": "goodqa#15533", "ledger_status": "imported",
     "state": "LIVE_TESTED", "priority": 3, "target": "1000 leads", "owners": ["a1"], "deferral": None,
     "missing": [], "tampered": [], "unpinned": [],
     "evidence": [{"id": "w1", "kind": "live_test", "verdict": "PASS", "at": iso(5000), "check": "crm", "note": "ok"}]},
    {"id": "x", "title": "<img src=x onerror=alert(1)>", "state": "UNKNOWN", "evidence": []}]}
REQS = {"generated": iso(0), "total": 3, "truncated": False, "requirements": [
    {"id": "wr1", "session": SID, "text": "keep chat live", "source": "user:s/u \"x\"", "at": iso(3600), "state": "recorded",
     "ticket": None, "owner": None, "evidence": None},
    {"id": "wr2", "session": SID, "text": "old thing", "source": "user:s/u \"y\"", "at": iso(40 * 86400), "state": "recorded",
     "ticket": None, "owner": None, "evidence": None},
    {"id": "wr3", "session": SID, "text": "done thing", "source": "user:s/u \"z\"", "at": iso(3600), "state": "done",
     "ticket": None, "owner": None, "evidence": None}]}
STATUS = {"session": SID, "since_s": 43200, "generated": iso(0), "entries": 10, "asks_open": [], "decisions": [],
          "assumptions": [], "commits": [], "claimed": [],
          "verified": [{"agent": "a1", "at": iso(60), "id": "wv1", "event": "check", "note": "REALLY_TESTED t: ok", "check": "t", "verdict": "PASS"}],
          "live": [{"agent": "a1", "at": iso(30), "id": "wl1", "event": "deploy", "note": "DEPLOYED x", "check": "", "verdict": ""}],
          "pending": [], "failed": [{"agent": "a2", "at": iso(90), "id": "wf1", "event": "check", "note": "FAIL", "check": "f", "verdict": "FAIL"}],
          "blockers": [{"agent": "a3", "at": iso(120), "id": "wb1", "event": "blocker", "note": "blocked on X"}],
          "live_legacy": [], "owners": {"counts": {"live": 2}, "attention": [], "live": ["a1"], "undisposed": []},
          "unread": 0, "rule": "x"}


class Fake:
    def __init__(self, goals=GOALS, reqs=REQS, status=STATUS):
        self.payload = {"ah-goals": goals, "ah-requirements": reqs, "ah-status": status}
        self.codes = {}
        self.calls = []

    def run(self, kind, *args, timeout=20.0, limit=0):
        self.calls.append((kind, args))
        payload = self.payload[kind]
        out = payload if isinstance(payload, str) else json.dumps(payload)
        return self.codes.get(kind, 0), out[:limit] if limit else out


def make(runner, session=SID, **kw):
    hub = ev.Hub()
    health = col.Health(hub)
    ledger = col.Ledger(hub, health, runner, lambda: session, **kw)
    return ledger, hub, health


class RunnerShapes(unittest.TestCase):
    def setUp(self):
        self.runner = Runner(python="/usr/bin/python3", ah="/h/hooks/ah.py")

    def test_shapes_are_fixed_read_only_argv(self):
        self.assertEqual(self.runner.argv("ah-goals"), ["/usr/bin/python3", "-I", "/h/hooks/ah.py", "goals", "--json"])
        self.assertEqual(self.runner.argv("ah-requirements", SID),
                         ["/usr/bin/python3", "-I", "/h/hooks/ah.py", "requirements", "--session", SID])
        self.assertEqual(self.runner.argv("ah-status", SID),
                         ["/usr/bin/python3", "-I", "/h/hooks/ah.py", "status", "--session", SID, "--since", "12h"])

    def test_bad_arguments_are_refused(self):
        for bad in ("--all", "a;rm -rf ~", "../x", "short", f"{SID} --all", "x" * 80):
            for kind in ("ah-requirements", "ah-status"):
                with self.subTest(kind=kind, bad=bad), self.assertRaises(Refused):
                    self.runner.argv(kind, bad)
        for kind, args in (("ah-goals", ("x",)), ("ah-requirements", ()), ("ah-status", ()), ("ah-status", (SID, "7d"))):
            with self.subTest(kind=kind, args=args), self.assertRaises(Refused):
                self.runner.argv(kind, *args)


class LedgerCollector(unittest.TestCase):
    def test_one_tick_reads_each_source_once_and_publishes_one_snapshot(self):
        runner = Fake()
        ledger, hub, health = make(runner)
        ledger.run(1000.0)
        self.assertEqual(sorted(k for k, _ in runner.calls), ["ah-goals", "ah-requirements", "ah-status"])
        self.assertEqual(health.rows["ledger"]["status"], "ok", health.rows)
        snap = hub.snapshots["ledger"]
        self.assertEqual(snap, ledger.snapshot())
        self.assertEqual([g["id"] for g in snap["goals"]["items"]], ["leads", "x"])
        self.assertEqual(snap["goals"]["items"][0]["evidence"][0]["verdict"], "PASS")
        self.assertEqual(snap["status"]["counts"]["verified"], 1)
        self.assertEqual(snap["status"]["blockers"][0]["id"], "wb1")
        self.assertEqual(snap["status"]["live"][0]["id"], "wl1")

    def test_requirements_carry_the_archive_verdict_and_summary(self):
        ledger, hub, _ = make(Fake())
        ledger.run(1000.0)
        reqs = {r["id"]: r for r in hub.snapshots["ledger"]["requirements"]["items"]}
        self.assertEqual(reqs["wr1"]["bucket"], "live")
        self.assertEqual(reqs["wr2"]["bucket"], "live")  # user-sourced: age never archives it
        self.assertIn("yours", reqs["wr2"]["unowned_note"])
        self.assertEqual((reqs["wr3"]["bucket"], reqs["wr3"]["rule"]), ("archived", "R1"))
        self.assertEqual(hub.snapshots["ledger"]["requirements"]["summary"], {"live": 2, "archived": 1, "rules": {"R1": 1, "live": 2}, "manual_user": 0})
        self.assertEqual(hub.snapshots["ledger"]["requirements"]["total"], 3)

    def test_markup_is_kept_as_plain_text(self):
        ledger, hub, _ = make(Fake())
        ledger.run(1000.0)
        self.assertEqual(hub.snapshots["ledger"]["goals"]["items"][1]["title"], "<img src=x onerror=alert(1)>")

    def test_unchanged_content_is_not_published_again(self):
        ledger, hub, _ = make(Fake())
        ledger.run(1000.0)
        seq = hub.seq
        ledger.run(1100.0)
        self.assertEqual(hub.seq, seq)

    def test_a_failing_source_keeps_its_last_good_rows_marked_stale(self):
        runner = Fake()
        ledger, hub, health = make(runner)
        ledger.run(1000.0)
        runner.codes["ah-status"] = 1
        runner.payload["ah-goals"] = "not json"
        ledger.run(1100.0)
        snap = hub.snapshots["ledger"]
        self.assertTrue(snap["status"]["stale"])
        self.assertIn("ah status", snap["status"]["error"])
        self.assertEqual(snap["status"]["blockers"][0]["id"], "wb1")
        self.assertTrue(snap["goals"]["stale"])
        self.assertEqual(len(snap["goals"]["items"]), 2)
        self.assertFalse(snap["requirements"]["stale"])
        self.assertEqual(health.rows["ledger"]["status"], "error")

    def test_first_failure_shows_an_error_and_no_rows(self):
        runner = Fake()
        runner.codes.update({"ah-goals": 2, "ah-requirements": 124, "ah-status": 1})
        ledger, hub, health = make(runner)
        ledger.run(1000.0)
        snap = hub.snapshots["ledger"]
        self.assertEqual((snap["goals"]["items"], snap["requirements"]["items"]), ([], []))
        self.assertTrue(snap["goals"]["error"] and snap["requirements"]["error"])
        self.assertEqual(health.rows["ledger"]["status"], "error")

    def test_rows_and_text_are_capped(self):
        reqs = dict(REQS, total=9000, requirements=[
            {"id": f"w{i:06d}", "session": SID, "text": "t%d " % i + "A" * 620, "at": iso(i), "state": "recorded"}
            for i in range(col.Ledger.MAX_REQUIREMENTS + 50)])
        goals = {"goals": [{"id": f"g{i}", "title": "T", "state": "UNKNOWN",
                            "evidence": [{"id": f"e{j}", "kind": "live_test", "verdict": "PASS", "at": iso(j)} for j in range(100)]}
                           for i in range(col.Ledger.MAX_GOALS + 20)]}
        ledger, hub, _ = make(Fake(goals=goals, reqs=reqs))
        ledger.run(1000.0)
        snap = hub.snapshots["ledger"]
        self.assertEqual(len(snap["requirements"]["items"]), col.Ledger.MAX_REQUIREMENTS)
        self.assertTrue(snap["requirements"]["truncated"])
        self.assertLessEqual(max(len(r["text"]) for r in snap["requirements"]["items"]), 600)
        self.assertEqual(len(snap["goals"]["items"]), col.Ledger.MAX_GOALS)
        self.assertEqual(len(snap["goals"]["items"][0]["evidence"]), col.Ledger.MAX_EVIDENCE)
        self.assertEqual(snap["goals"]["items"][0]["evidence_total"], 100)
        self.assertLess(len(json.dumps(snap)), 2 * 1024 * 1024)

    def test_oversize_output_is_refused_not_truncated_into_valid_data(self):
        runner = Fake(reqs=json.dumps(REQS) + " " * (col.Ledger.REQ_LIMIT + 10))
        ledger, hub, _ = make(runner)
        ledger.run(1000.0)
        self.assertEqual(hub.snapshots["ledger"]["requirements"]["items"], [])
        self.assertIn("ah requirements", hub.snapshots["ledger"]["requirements"]["error"])

    def test_a_two_mib_requirements_read_is_paged_not_stale(self):
        reqs = dict(REQS, total=4000, requirements=[
            {"id": f"w{i:06d}", "session": SID, "text": "t%d " % i + "A" * 480, "at": iso(i), "state": "recorded"} for i in range(4000)])
        self.assertGreater(len(json.dumps(reqs)), 2 * 1024 * 1024 - 400000)
        ledger, hub, health = make(Fake(reqs=reqs))
        ledger.run(1000.0)
        part = hub.snapshots["ledger"]["requirements"]
        self.assertFalse(part["stale"] or part["error"], part["error"])
        self.assertEqual((len(part["items"]), part["truncated"], part["total"]), (col.Ledger.MAX_REQUIREMENTS, True, 4000))

    def test_no_session_reads_goals_only(self):
        runner = Fake()
        ledger, hub, _ = make(runner, session="")
        ledger.run(1000.0)
        self.assertEqual([k for k, _ in runner.calls], ["ah-goals"])
        self.assertEqual(hub.snapshots["ledger"]["requirements"]["items"], [])
        self.assertEqual(ledger.next_at, 1010.0)  # retried soon, not after a full cadence

    def test_cadence_is_60_s_attached_and_300_s_idle(self):
        ledger, hub, _ = make(Fake())
        self.assertEqual((ledger.interval, ledger.idle_interval), (60.0, 300.0))
        hub.clients = []
        ledger.run(1000.0)
        self.assertEqual(ledger.next_at, 1300.0)

    def test_closed_ticket_in_the_sweeper_cache_archives_a_requirement_and_reopen_restores_it(self):
        import tempfile
        reqs = dict(REQS, requirements=[dict(REQS["requirements"][0], ticket="goodqa#9")])
        with tempfile.TemporaryDirectory() as tmp:
            needs = Path(tmp) / "needs"
            needs.mkdir()
            (needs / "tickets.json").write_text(json.dumps({"goodqa#9": {"state": "closed", "at": NOW}}))
            ledger, hub, _ = make(Fake(reqs=reqs), root=Path(tmp))
            ledger.run(1000.0)
            self.assertEqual(hub.snapshots["ledger"]["requirements"]["items"][0]["rule"], "R2")
            (needs / "tickets.json").write_text(json.dumps({"goodqa#9": {"state": "open", "at": NOW}}))
            ledger.run(1100.0)
            self.assertEqual(hub.snapshots["ledger"]["requirements"]["items"][0]["bucket"], "live")


class ServerIntegration(unittest.TestCase):
    def setUp(self):
        sys.path.insert(0, str(REPO / "tests"))
        from test_mission_control import ServerHarness, pin_app  # noqa: PLC0415

        class H(ServerHarness):
            def runTest(self):
                pass
        self.h = H()
        self.h.setUp()
        self.addCleanup(self.h.tearDown)
        self.h.app.runner.outputs.update({
            "ah-goals": (0, json.dumps(GOALS)), "ah-requirements": lambda *_a: (0, json.dumps(REQS)),
            "ah-status": lambda *_a: (0, json.dumps(STATUS))})
        pin_app(self.h.app, SID)   # goodqa#15961: the ledger follows the pin, not owners.session

    def test_state_carries_the_ledger_and_the_loop_reads_it(self):
        self.h.app.ledger.run(time.time())
        cookie, _ = self.h.login()
        resp, data = self.h.request("GET", "/api/state", {"Cookie": cookie, "Sec-Fetch-Site": "same-origin"})
        state = json.loads(data)
        self.assertEqual(state["ledger"]["requirements"]["summary"]["archived"], 1)
        self.assertEqual(state["ledger"]["goals"]["items"][0]["id"], "leads")
        self.assertIn("ledger", [r["name"] for r in state["health"]])

    def test_the_ledger_is_a_woken_collector_not_a_poll(self):
        self.assertIn(self.h.app.ledger, self.h.app.collectors + [self.h.app.ledger])
        self.h.app.ledger.run(time.time())
        self.h.app.ledger.next_at = 10 ** 12
        self.h.app.wake()
        self.assertLessEqual(self.h.app.ledger.next_at, self.h.app.ledger.ran_at + 60.0)


class AsksArchive(unittest.TestCase):
    def test_settled_and_expired_asks_are_archived_with_their_reason_and_nothing_is_removed(self):
        import tempfile
        from safeio import Runner as _R  # noqa: F401
        now = time.time()

        class R:
            def run(self, kind, *args, timeout=20.0, limit=0):
                if kind == "provenance-asks":
                    return 0, json.dumps({"items": [
                        {"id": "wlive0000001", "kind": "traced", "at": iso(60), "note": "Keep?", "owner": "main"},
                        {"id": "wuntil000001", "kind": "traced", "at": iso(3600), "note": "Expired?", "owner": "main",
                         "until": ev.iso(now - 60)}],
                        "resolved": [{"id": "wres00000001", "at": iso(90000), "owner": "main", "note": "Done?",
                                      "resolved_at": iso(80000), "decision": "approved", "resolved_by": "wr1",
                                      "resolution": "answered by the user: yes"}], "blocked": []})
                return 1, ""
        with tempfile.TemporaryDirectory() as tmp:
            hub = ev.Hub()
            asks = col.Asks(hub, col.Health(hub), R(), lambda: SID, root=Path(tmp))
            asks.run(now)
            snap = asks.snapshot()
        self.assertEqual([a["id"] for a in snap["items"]], ["wlive0000001"])
        rules = {a["id"]: (a["rule"], a["bucket"]) for a in snap["archive"]}
        self.assertEqual(rules["wres00000001"], ("R1", "archived"))
        self.assertNotIn("wuntil000001", rules)  # past its until: still live, answerable, in the stale list
        self.assertIn("wuntil000001", [a["id"] for a in snap["items"] + snap["stale"]])
        self.assertIn("answered by the user: yes", next(a for a in snap["archive"] if a["id"] == "wres00000001")["reason"])
        self.assertEqual([a["id"] for a in snap["resolved"]], ["wres00000001"])  # the original lists are untouched


class Coverage(unittest.TestCase):
    """AC-4: every key the server sends has a named UI section in web/coverage.json (the node test checks the ids exist)."""

    def test_every_state_key_and_snapshot_field_is_mapped(self):
        mapping = json.loads((REPO / "harness" / "mission_control" / "web" / "coverage.json").read_text())
        sys.path.insert(0, str(REPO / "tests"))
        from test_mission_control import ServerHarness, pin_app  # noqa: PLC0415

        class H(ServerHarness):
            def runTest(self):
                pass
        h = H()
        h.setUp()
        self.addCleanup(h.tearDown)
        h.app.owners.session = SID
        state = h.app.state()
        self.assertEqual(sorted(set(state) - set(mapping["state"])), [])
        self.assertEqual(sorted(set(state["asks"]) - set(mapping["asks"])), [])
        self.assertEqual(sorted(set(state["ledger"]) - set(mapping["ledger"])), [])

    def test_the_docs_name_every_rule_and_the_write_route(self):
        docs = (REPO / "docs" / "mission-control.md").read_text()
        for needle in ("M archived from the dashboard", "R1", "R2", "R3", "R4", "POST /api/requirements/archive", "actions.jsonl"):
            self.assertIn(needle, docs, needle)

    def test_the_page_never_polls_state_on_a_timer(self):
        live = (REPO / "harness" / "mission_control" / "web" / "js" / "live.js").read_text()
        self.assertNotIn("setInterval", live)
        self.assertEqual(live.count("'/api/state'"), 1)


if __name__ == "__main__":
    unittest.main()
