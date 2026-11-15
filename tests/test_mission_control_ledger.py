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
from safeio import Reader, Refused, Runner  # noqa: E402

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


class StatusUnread(unittest.TestCase):
    """review PR 234 v2 F2: a status read that could not open every WAL is marked incomplete, never shown as healthy."""

    def producer_shape(self, unread):
        import ah  # noqa: PLC0415 - the real producer, fed rows so it opens no file
        rows = [("a1", {"event": "check", "at": iso(60), "id": "wv1", "note": "REALLY_TESTED t: ok"})]
        report = ah.status_report(Path("/nonexistent"), SID, 43200, now=NOW, rows=rows, unread=unread)
        return json.loads(json.dumps(report, default=str))

    def test_unread_wals_mark_the_status_incomplete_with_a_bounded_redacted_list(self):
        token = "ghp_" + "A1b2" * 9
        unread = [{"wal": f"agent-x{i}.jsonl", "agent": f"x{i}", "reason": f"[Errno 13] Permission denied {token}"} for i in range(25)]
        ledger, hub, _ = make(Fake(status=self.producer_shape(unread)))
        ledger.run(1000.0)
        part = hub.snapshots["ledger"]["status"]
        self.assertIs(part["incomplete"], True)
        self.assertEqual(part["unread"]["count"], 25)
        self.assertLessEqual(len(part["unread"]["items"]), 10)
        blob = json.dumps(part)
        self.assertNotIn(token, blob)
        self.assertIn("agent-x0.jsonl", blob)
        self.assertFalse(part["error"])  # a partial read is not a failed read: the rows it did read still show

    def test_a_complete_read_is_not_incomplete(self):
        ledger, hub, _ = make(Fake(status=self.producer_shape([])))
        ledger.run(1000.0)
        part = hub.snapshots["ledger"]["status"]
        self.assertEqual((part["incomplete"], part["unread"]["count"], part["unread"]["items"]), (False, 0, []))

    def test_a_malformed_unread_field_fails_closed_as_incomplete(self):
        for value in ("lots", {"wal": "x"}, [1, None, "agent-y.jsonl"], 3):
            with self.subTest(value=value):
                ledger, hub, _ = make(Fake(status=dict(STATUS, unread=value)))
                ledger.run(1000.0)
                self.assertIs(hub.snapshots["ledger"]["status"]["incomplete"], True, value)


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

    def _ticket_case(self, cache_entry, lookup):
        """A requirement on goodqa#9 with no ask naming it; returns (bucket, cache entry after one ledger read)."""
        import tempfile
        reqs = dict(REQS, requirements=[dict(REQS["requirements"][0], ticket="goodqa#9")])
        runner = Fake(reqs=reqs)
        runner.payload["ah-ticket-get"] = lookup
        if lookup is None:
            runner.codes["ah-ticket-get"] = 1
            runner.payload["ah-ticket-get"] = ""
        with tempfile.TemporaryDirectory() as tmp:
            needs = Path(tmp) / "needs"
            needs.mkdir()
            (needs / "tickets.json").write_text(json.dumps({"goodqa#9": cache_entry}))
            ledger, hub, _ = make(runner, root=Path(tmp))
            ledger.run(1000.0)
            after = json.loads((needs / "tickets.json").read_text()).get("goodqa#9")
            return hub.snapshots["ledger"]["requirements"]["items"][0]["bucket"], after, runner

    def test_an_expired_closed_cache_entry_with_a_failed_refresh_is_unknown_not_closed(self):
        # review PR 234 F1: the sweeper only refreshes tickets its asks name; a requirement's ticket must not stay
        # "closed" forever on a cache row nobody rechecks
        bucket, after, runner = self._ticket_case({"state": "closed", "at": time.time() - 31 * 60}, None)
        self.assertEqual(bucket, "live")
        self.assertIn(("ah-ticket-get", ("goodqa#9",)), runner.calls)  # a bounded refresh was attempted
        self.assertEqual(after["state"], "closed")  # a failed lookup decides nothing and erases nothing

    def test_a_reopened_ticket_with_no_open_ask_restores_the_requirement(self):
        bucket, after, _ = self._ticket_case({"state": "closed", "at": time.time() - 31 * 60},
                                             {"issue": {"closedAt": None, "archivedAt": None}})
        self.assertEqual((bucket, after["state"]), ("live", "open"))

    def test_a_fresh_closed_entry_still_archives_without_a_lookup(self):
        bucket, _, runner = self._ticket_case({"state": "closed", "at": time.time() - 60}, None)
        self.assertEqual(bucket, "archived")
        self.assertNotIn("ah-ticket-get", [k for k, _ in runner.calls])


EMPTY_STATUS = dict(STATUS, verified=[], live=[], failed=[], blockers=[], unread=[])
FAILURES = {"timeout": (124, ""), "nonzero": (1, "Traceback: boom"), "invalid_json": (0, "{not json")}


class StatusTruth(unittest.TestCase):
    """review PR 234 v3 F1 (v2 F2): one status truth per source, computed by collectors.read_truth. An unsuccessful
    initial read is unknown, a failure after a good read is stale with its last good time, recovery is current."""

    def fail_status(self, runner, mode):
        code, out = FAILURES[mode]
        runner.codes["ah-status"] = code
        runner.payload["ah-status"] = out

    def heal_status(self, runner):
        runner.codes.pop("ah-status", None)
        runner.payload["ah-status"] = EMPTY_STATUS

    def test_an_initial_failure_is_unknown_never_an_empty_current_read(self):
        for mode in FAILURES:
            with self.subTest(mode=mode):
                runner = Fake(status=EMPTY_STATUS)
                self.fail_status(runner, mode)
                ledger, hub, health = make(runner)
                ledger.run(1000.0)
                ledger.run(1060.0)  # a failing streak keeps its first failure time, and is not republished for it
                part = hub.snapshots["ledger"]["status"]
                self.assertEqual((part["truth"], part["at"], part["stale"], part["blockers"]), ("unknown", "", False, []))
                self.assertTrue(part["error"])
                self.assertEqual(part["failed_at"], ev.iso(1000.0))
                self.assertEqual((health.rows["ledger"]["status"], health.rows["ledger"]["truth"]), ("error", "unknown"))
        self.assertIn("timed out", self.error_of("timeout"))

    def error_of(self, mode):
        runner = Fake(status=EMPTY_STATUS)
        self.fail_status(runner, mode)
        ledger, hub, _ = make(runner)
        ledger.run(1000.0)
        return hub.snapshots["ledger"]["status"]["error"]

    def test_a_failure_after_a_good_empty_read_is_stale_with_the_last_good_time(self):
        for mode in FAILURES:
            with self.subTest(mode=mode):
                runner = Fake(status=EMPTY_STATUS)
                ledger, hub, health = make(runner)
                ledger.run(1000.0)
                self.assertEqual(hub.snapshots["ledger"]["status"]["truth"], "current")
                self.fail_status(runner, mode)
                ledger.run(1100.0)
                ledger.run(1200.0)  # a second failure keeps the first failure time and the last good time
                part = hub.snapshots["ledger"]["status"]
                self.assertEqual((part["truth"], part["stale"], part["at"], part["failed_at"]), ("stale", True, ev.iso(1000.0), ev.iso(1100.0)))
                self.assertEqual(part["blockers"], [])
                self.assertEqual((health.rows["ledger"]["status"], health.rows["ledger"]["truth"]), ("error", "stale"))

    def test_recovery_after_an_initial_failure_or_a_stale_read_is_current(self):
        for mode in FAILURES:
            for good_first in (False, True):
                with self.subTest(mode=mode, good_first=good_first):
                    runner = Fake(status=EMPTY_STATUS)
                    ledger, hub, health = make(runner)
                    if good_first:
                        ledger.run(900.0)
                    self.fail_status(runner, mode)
                    ledger.run(1000.0)
                    self.heal_status(runner)
                    ledger.run(1100.0)
                    part = hub.snapshots["ledger"]["status"]
                    self.assertEqual((part["truth"], part["stale"], part["error"], part["failed_at"], part["at"]), ("current", False, "", "", ev.iso(1100.0)))
                    self.assertEqual((health.rows["ledger"]["status"], health.rows["ledger"]["truth"]), ("ok", "current"))

    def test_a_partial_read_is_partial_and_a_failure_after_it_is_stale(self):
        runner = Fake(status=dict(EMPTY_STATUS, unread=[{"wal": "agent-x.jsonl", "agent": "x", "reason": "denied"}]))
        ledger, hub, health = make(runner)
        ledger.run(1000.0)
        self.assertEqual(hub.snapshots["ledger"]["status"]["truth"], "partial")
        self.assertEqual((health.rows["ledger"]["status"], health.rows["ledger"]["truth"]), ("ok", "partial"))
        self.fail_status(runner, "nonzero")
        ledger.run(1100.0)
        self.assertEqual(hub.snapshots["ledger"]["status"]["truth"], "stale")

    def test_never_read_is_unknown_even_when_the_collector_is_ok(self):
        ledger, hub, health = make(Fake(), session="")
        ledger.run(1000.0)
        snap = hub.snapshots["ledger"]
        self.assertEqual((snap["goals"]["truth"], snap["requirements"]["truth"], snap["status"]["truth"]), ("current", "unknown", "unknown"))
        self.assertEqual((health.rows["ledger"]["status"], health.rows["ledger"]["truth"]), ("ok", "unknown"))

    def test_v5_F1_a_session_that_goes_away_leaves_no_current_rows(self):
        """review PR 234 v5 F1: a good read for A, then main's session drops to "" (the owners snapshot has none)."""
        session = {"id": SID}
        hub = ev.Hub()
        health = col.Health(hub)
        ledger = col.Ledger(hub, health, Fake(), lambda: session["id"])
        ledger.run(1000.0)
        self.assertEqual((hub.snapshots["ledger"]["status"]["truth"], hub.snapshots["ledger"]["requirements"]["truth"]), ("current", "current"))
        session["id"] = ""
        ledger.run(1060.0)
        for snap in (hub.snapshots["ledger"], ledger.snapshot()):  # what is pushed to the page and what /api/state serves
            for name in ("requirements", "status"):
                self.assertEqual((snap[name]["truth"], snap[name]["at"], snap[name]["session"]), ("unknown", "", ""), name)
            self.assertEqual((snap["requirements"]["items"], snap["status"]["blockers"]), ([], []))
            self.assertEqual(snap["goals"]["truth"], "current")
        self.assertEqual((health.rows["ledger"]["status"], health.rows["ledger"]["truth"]), ("ok", "unknown"))
        self.assertEqual(ledger.req_session, "")  # no archive or restore click pairs a row with the old session

    def test_a_failed_read_for_a_new_session_is_unknown_and_drops_the_old_sessions_rows(self):
        session = {"id": SID}
        runner = Fake()
        hub = ev.Hub()
        ledger = col.Ledger(hub, col.Health(hub), runner, lambda: session["id"])
        ledger.run(1000.0)
        self.assertEqual(hub.snapshots["ledger"]["status"]["blockers"][0]["id"], "wb1")
        session["id"] = "ffffffff-0000-4000-8000-000000000000"
        runner.codes.update({"ah-status": 1, "ah-requirements": 1})
        ledger.run(1100.0)
        snap = hub.snapshots["ledger"]
        for name in ("status", "requirements"):
            self.assertEqual((snap[name]["truth"], snap[name]["at"]), ("unknown", ""), name)
        self.assertEqual((snap["status"]["blockers"], snap["requirements"]["items"]), ([], []))
        self.assertEqual(snap["goals"]["truth"], "current")

    def test_more_goals_than_kept_and_truncated_requirements_are_partial(self):
        goals = dict(GOALS, goals=[dict(GOALS["goals"][0], id=f"g{i}") for i in range(col.Ledger.MAX_GOALS + 5)])
        ledger, hub, _ = make(Fake(goals=goals, reqs=dict(REQS, truncated=True)))
        ledger.run(1000.0)
        snap = hub.snapshots["ledger"]
        self.assertEqual((snap["goals"]["truth"], snap["goals"]["total"], len(snap["goals"]["items"])), ("partial", col.Ledger.MAX_GOALS + 5, col.Ledger.MAX_GOALS))
        self.assertEqual(snap["requirements"]["truth"], "partial")
        ledger.reclassify()
        self.assertEqual(hub.snapshots["ledger"]["requirements"]["truth"], "partial")

    def test_read_truth_and_worst_truth(self):
        self.assertEqual([col.read_truth("", ""), col.read_truth("", "x"), col.read_truth("t", "x"), col.read_truth("t", "", True), col.read_truth("t")],
                         ["unknown", "unknown", "stale", "partial", "current"])
        self.assertEqual(col.worst_truth("current", "partial"), "partial")
        self.assertEqual(col.worst_truth("partial", "stale", "current"), "stale")
        self.assertEqual(col.worst_truth("current", "bogus"), "unknown")
        self.assertEqual(col.worst_truth(), "unknown")


class HealthTruth(unittest.TestCase):
    """The Health row carries the same truth for the sources outside the ledger (asks, owners, initiatives, chat)."""

    def test_an_error_before_any_good_read_is_unknown_after_one_is_stale_and_recovery_is_current(self):
        health = col.Health(ev.Hub())
        health.error("asks", "boom")
        self.assertEqual((health.rows["asks"]["truth"], health.rows["asks"]["ok_at"]), ("unknown", None))
        health.ok("asks", "fine")
        ok_at = health.rows["asks"]["ok_at"]
        health.error("asks", "boom")
        self.assertEqual((health.rows["asks"]["truth"], health.rows["asks"]["ok_at"]), ("stale", ok_at))
        health.ok("asks", "fine")
        self.assertEqual(health.rows["asks"]["truth"], "current")

    def test_a_tick_that_reports_itself_off_is_not_overwritten_as_ok(self):
        hub = ev.Hub()
        health = col.Health(hub)
        asks = col.Asks(hub, health, Fake(), lambda: "")
        asks.run(1000.0)
        self.assertEqual(health.rows["asks"]["status"], "off")  # was overwritten as "ok" with detail "off"
        self.assertEqual(health.rows["asks"]["truth"], "unknown")

    def test_an_initiatives_file_that_is_not_configured_is_off_but_current(self):
        hub = ev.Hub()
        health = col.Health(hub)
        col.Initiatives(hub, health, None, None).run(1000.0)
        self.assertEqual(health.rows["initiatives"]["status"], "off")
        self.assertEqual(health.rows["initiatives"]["truth"], "current")

    def test_an_unreadable_initiatives_file_at_start_is_unknown(self):
        hub = ev.Hub()
        health = col.Health(hub)
        col.Initiatives(hub, health, None, "/nonexistent/initiatives.json").run(1000.0)
        self.assertEqual((health.rows["initiatives"]["status"], health.rows["initiatives"]["truth"]), ("error", "unknown"))

    def test_the_health_row_is_republished_when_its_truth_changes(self):
        hub = ev.Hub()
        health = col.Health(hub)
        health.ok("ledger", "x", truth="unknown")
        health.ok("ledger", "x", truth="current")
        self.assertEqual([r["truth"] for r in hub.snapshots["health"] if r["name"] == "ledger"], ["current"])


class ChatHealth(unittest.TestCase):
    def test_a_chat_store_failure_clears_on_the_next_good_read(self):
        sys.path.insert(0, str(REPO / "tests"))
        from test_mission_control import ServerHarness  # noqa: PLC0415

        class H(ServerHarness):
            def runTest(self):
                pass
        h = H()
        h.setUp()
        self.addCleanup(h.tearDown)
        app = h.app
        real = app.refresh_chat
        app.refresh_chat = lambda force=False: (_ for _ in ()).throw(OSError("chat store unreadable"))
        app.chat_once()
        self.assertEqual((app.health.rows["chat"]["status"], app.health.rows["chat"]["truth"]), ("error", "unknown"))
        app.refresh_chat = real
        app.chat_once()
        self.assertEqual((app.health.rows["chat"]["status"], app.health.rows["chat"]["truth"]), ("ok", "current"))


class ServerIntegration(unittest.TestCase):
    def setUp(self):
        sys.path.insert(0, str(REPO / "tests"))
        from test_mission_control import ServerHarness  # noqa: PLC0415

        class H(ServerHarness):
            def runTest(self):
                pass
        self.h = H()
        self.h.setUp()
        self.addCleanup(self.h.tearDown)
        self.h.app.runner.outputs.update({
            "ah-goals": (0, json.dumps(GOALS)), "ah-requirements": lambda *_a: (0, json.dumps(REQS)),
            "ah-status": lambda *_a: (0, json.dumps(STATUS))})
        self.h.app.owners.session = SID

    def test_state_carries_the_ledger_and_the_loop_reads_it(self):
        self.h.app.ledger.run(time.time())
        cookie, _ = self.h.login()
        resp, data = self.h.request("GET", "/api/state", {"Cookie": cookie, "Sec-Fetch-Site": "same-origin"})
        state = json.loads(data)
        self.assertEqual(state["ledger"]["requirements"]["summary"]["archived"], 1)
        self.assertEqual(state["ledger"]["goals"]["items"][0]["id"], "leads")
        self.assertIn("ledger", [r["name"] for r in state["health"]])

    def test_v6_D40_the_session_watch_unshows_the_old_sessions_rows_while_the_ledger_read_still_runs(self):
        """D40 [defect] review PR 234 v6: main moves while the ledger thread is inside a slow read; the page is told."""
        app = self.h.app
        # main's session as the sources see it, whichever server wiring supplies it (owners here, a pin in PR 243)
        main = {"id": SID}
        app.ledger.session_fn = app.asks.session_fn = lambda: main["id"]
        app.ledger.run(time.time())
        self.assertEqual(app.hub.snapshots["ledger"]["status"]["truth"], "current")
        main["id"] = SID_B  # the ledger thread has not ticked since (it may be inside a read for SID)
        getattr(app, "follow_sessions", lambda: None)()  # one pass of the session watch (none at ec6d0edd)
        snap = app.hub.snapshots["ledger"]
        self.assertEqual((snap["requirements"]["truth"], snap["status"]["truth"], snap["status"]["blockers"]), ("unknown", "unknown", []))
        self.assertEqual((app.health.rows["ledger"]["status"], app.health.rows["ledger"]["truth"]), ("ok", "unknown"))
        app.ledger.run(time.time())  # the ledger thread's next tick reads the new session
        self.assertEqual(app.hub.snapshots["ledger"]["status"]["truth"], "current")

    def test_v6_D41_the_session_watch_runs_on_its_own_thread(self):
        import inspect  # noqa: PLC0415
        self.assertIn("self.session_loop", inspect.getsource(type(self.h.app).start))

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
        from test_mission_control import ServerHarness  # noqa: PLC0415

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



# ---- review PR 234 v6: the status-truth table. Every source a zero or "none" claim on the page rests on, in each state
# and transition, observed where the page gets it: the pushed snapshot (SSE), the served one (/api/state) and the Health
# row. The invariant: a source is "current" only when its last attempted read succeeded, was whole, and was for the
# session main is in now. Row ids: D = the defect this fix removes (fails at ec6d0edd), G = a guard (passes there too),
# C = a deliberate change that was not a defect there (old head: stale, never current). One test per row (TruthTable).
SID_B = "ffffffff-0000-4000-8000-000000000000"
PARTS = ("goals", "requirements", "status")


class World:
    """One Ledger over a fake `ah`, with a main session the test can move."""

    def __init__(self, session=SID):
        self.main = {"id": session}
        self.runner = Fake()
        self.hub = ev.Hub()
        self.health = col.Health(self.hub)
        self.ledger = col.Ledger(self.hub, self.health, self.runner, lambda: self.main["id"])
        self.t = 1000.0
        self.held = None   # the pushed snapshot at a moment inside a tick (see hold)

    def tick(self):
        self.ledger.run(self.t)
        self.t += 60.0

    def fail(self, *kinds, mode="nonzero"):
        code, out = FAILURES[mode]
        for kind in kinds:
            self.runner.codes[kind], self.runner.payload[kind] = code, out

    def move(self, session):
        self.main["id"] = session

    def hook(self, kind, before=None, after=None):
        real = self.runner.run

        def run(k, *args, **kw):
            if k == kind and before:
                before()
            out = real(k, *args, **kw)
            if k == kind and after:
                after()
            return out
        self.runner.run = run

    def hold(self):
        self.held = json.loads(json.dumps(self.hub.snapshots.get("ledger") or {}))

    def seen(self, published=None):
        published = (self.hub.snapshots.get("ledger") or {}) if published is None else published
        served = self.ledger.snapshot()

        def truths(snap):
            return {p: (snap.get(p) or {}).get("truth", "unknown") for p in PARTS}

        def rows(snap):  # session-scoped rows on hand: requirement items and status blockers
            return len((snap.get("requirements") or {}).get("items") or []) + len((snap.get("status") or {}).get("blockers") or [])
        row = self.health.rows.get("ledger") or {}
        return {"published": truths(published), "served": truths(served), "rows": (rows(published), rows(served)),
                "health": (row.get("status", ""), row.get("truth", "")), "due": self.ledger.due(self.t - 59.0)}


def _parts(goals, requirements, status):
    return {"goals": goals, "requirements": requirements, "status": status}


def _ledger_row(rid, kind, what, run, published, served=None, rows=None, health=None, due=False):
    expected = {"published": published, "served": served or published}
    if rows is not None:
        expected["rows"] = rows
    if health is not None:
        expected["health"] = health
    expected["due"] = due
    return rid, kind, what, run, expected


def _scenario(*steps):
    def run(w):
        for step in steps:
            step(w)
        return w.seen()
    return run


def tick(w):
    w.tick()


def to(session):
    return lambda w: w.move(session)


def fail(*kinds, mode="nonzero"):
    return lambda w: w.fail(*kinds, mode=mode)


def heal(w):
    w.runner.codes.clear()
    w.runner.payload.update({"ah-goals": GOALS, "ah-requirements": REQS, "ah-status": STATUS})


def partial(w):
    w.runner.payload["ah-status"] = dict(STATUS, unread=[{"wal": "agent-x.jsonl", "agent": "x", "reason": "denied"}])


def without(kind, key, bad_row=False):
    """An exit-0 payload whose list is missing, or holds a row that is not one: a zero from it would be a guess."""
    base = {"ah-goals": GOALS, "ah-requirements": REQS, "ah-status": STATUS}[kind]

    def step(w):
        payload = dict(base)
        if bad_row:
            payload[key] = list(base[key]) + ["not a row"]
        else:
            payload.pop(key)
        w.runner.payload[kind] = payload
    return step


def misshapen(kind):
    """One more row the parser cannot show (no id): the counts the page states from that part would be short."""
    key, base = {"ah-goals": ("goals", GOALS), "ah-requirements": ("requirements", REQS)}[kind]

    def step(w):
        w.runner.payload[kind] = dict(base, **{key: base[key] + [{"title": "a row without an id"}]})
    return step


def _restart(w):
    w.tick()               # a good read in the process that then stops
    return World().seen()  # the new process: nothing it shows comes from the old one


def _during_next_goals_read(w):
    w.tick()
    w.move(SID_B)
    w.hook("ah-goals", before=w.hold)
    w.tick()
    return w.seen(published=w.held)


def _moves_during_status_read(w):
    w.hook("ah-status", after=lambda: w.move(SID_B))
    w.tick()  # read for A; main moved to B before it finished
    return w.seen()


def watch(w):
    """One pass of the server's session watch for this source (follow(); there is none at ec6d0edd)."""
    getattr(w.ledger if hasattr(w, "ledger") else w.asks, "follow", lambda: None)()


def _watch_during_status_read(w):
    w.tick()

    def moved():
        w.move(SID_B)
        watch(w)
        w.hold()
    w.hook("ah-status", before=moved)  # main moves while the next tick is inside its reads for A
    w.tick()
    return w.seen(published=w.held)


def _click_after_move(w):
    w.tick()
    w.move(SID_B)
    w.ledger.reclassify()  # an archive or restore click on an HTTP thread, before the ledger thread's next tick
    return w.seen()


CUR, UNK, STA, PAR = "current", "unknown", "stale", "partial"
ROWS_A = len(REQS["requirements"]) + len(STATUS["blockers"])
LEDGER_TABLE = [
    _ledger_row("G01", "guard", "never read (process start)", lambda w: w.seen(), _parts(UNK, UNK, UNK), rows=(0, 0), health=("", ""), due=True),
    _ledger_row("G02", "guard", "process restart after a good read", _restart, _parts(UNK, UNK, UNK), rows=(0, 0), health=("", ""), due=True),
    _ledger_row("G03", "guard", "good read for main's session (the zero claims are not vacuous)", _scenario(tick), _parts(CUR, CUR, CUR), rows=(ROWS_A, ROWS_A), health=("ok", CUR)),
    _ledger_row("G04", "guard", "initial status timeout", _scenario(fail("ah-status", mode="timeout"), tick), _parts(CUR, CUR, UNK), health=("error", UNK)),
    _ledger_row("G05", "guard", "initial status nonzero exit", _scenario(fail("ah-status"), tick), _parts(CUR, CUR, UNK), health=("error", UNK)),
    _ledger_row("G06", "guard", "initial status invalid JSON", _scenario(fail("ah-status", mode="invalid_json"), tick), _parts(CUR, CUR, UNK), health=("error", UNK)),
    _ledger_row("G07", "guard", "status read fails after a good read", _scenario(tick, fail("ah-status"), tick), _parts(CUR, CUR, STA), health=("error", STA)),
    _ledger_row("G08", "guard", "partial status read (unread WALs)", _scenario(partial, tick), _parts(CUR, CUR, PAR), health=("ok", PAR)),
    _ledger_row("G09", "guard", "failure after a partial read", _scenario(partial, tick, fail("ah-status"), tick), _parts(CUR, CUR, STA), health=("error", STA)),
    _ledger_row("G10", "guard", "recovery after a failure", _scenario(tick, fail("ah-status"), tick, heal, tick), _parts(CUR, CUR, CUR), health=("ok", CUR)),
    _ledger_row("G11", "guard", "no main session yet: goals only", _scenario(to(""), tick), _parts(CUR, UNK, UNK), rows=(0, 0), health=("ok", UNK)),
    _ledger_row("D01", "defect", "v5 F1: main's session set -> empty, then a tick", _scenario(tick, to(""), tick), _parts(CUR, UNK, UNK), rows=(0, 0), health=("ok", UNK)),
    _ledger_row("D02", "defect", "session set -> empty, then one session-watch pass before the next tick: pushed, served, Health, due at once", _scenario(tick, to(""), watch), _parts(CUR, UNK, UNK), rows=(0, 0), health=("ok", UNK), due=True),
    _ledger_row("D03", "defect", "session A -> B, then one session-watch pass before the next tick: pushed, served, Health, due at once", _scenario(tick, to(SID_B), watch), _parts(CUR, UNK, UNK), rows=(0, 0), health=("ok", UNK), due=True),
    _ledger_row("D04", "defect", "session A -> B: what the page holds while the next tick's first read runs", _during_next_goals_read, _parts(CUR, UNK, UNK), served=_parts(CUR, CUR, CUR)),
    _ledger_row("D05", "defect", "session moves A -> B while the status read for A runs", _moves_during_status_read, _parts(CUR, UNK, UNK), rows=(0, 0), health=("ok", UNK), due=True),
    _ledger_row("D06", "defect", "an archive click (reclassify) after A -> B, before the next tick", _click_after_move, _parts(CUR, UNK, UNK), rows=(0, 0), due=True),
    _ledger_row("D07", "defect", "session A -> B while the ledger thread is inside a read: what the session watch pushes", _watch_during_status_read, _parts(CUR, UNK, UNK), served=_parts(CUR, UNK, UNK), health=("ok", UNK), due=True),
    _ledger_row("G12", "guard", "session A -> B, B's reads fail", _scenario(tick, to(SID_B), fail("ah-requirements", "ah-status"), tick), _parts(CUR, UNK, UNK), rows=(0, 0), health=("error", UNK)),
    _ledger_row("G13", "guard", "session A -> B, B's reads succeed", _scenario(tick, to(SID_B), tick), _parts(CUR, CUR, CUR), rows=(ROWS_A, ROWS_A), health=("ok", CUR)),
    _ledger_row("G14", "guard", "initial goals nonzero exit", _scenario(fail("ah-goals"), tick), _parts(UNK, CUR, CUR), health=("error", UNK)),
    _ledger_row("G15", "guard", "goals timeout after a good read", _scenario(tick, fail("ah-goals", mode="timeout"), tick), _parts(STA, CUR, CUR), health=("error", STA)),
    _ledger_row("G16", "guard", "initial requirements timeout", _scenario(fail("ah-requirements", mode="timeout"), tick), _parts(CUR, UNK, CUR), health=("error", UNK)),
    _ledger_row("G17", "guard", "requirements nonzero exit after a good read", _scenario(tick, fail("ah-requirements"), tick), _parts(CUR, STA, CUR), health=("error", STA)),
    _ledger_row("G18", "guard", "requirements invalid JSON after a good read", _scenario(tick, fail("ah-requirements", mode="invalid_json"), tick), _parts(CUR, STA, CUR), health=("error", STA)),
    _ledger_row("D08", "defect", "goals: a row dropped for its shape is partial", _scenario(misshapen("ah-goals"), tick), _parts(PAR, CUR, CUR), health=("ok", PAR)),
    _ledger_row("D09", "defect", "requirements: a row dropped for its shape is partial", _scenario(misshapen("ah-requirements"), tick), _parts(CUR, PAR, CUR), health=("ok", PAR)),
    _ledger_row("D10", "defect", "goals: an exit-0 payload with no goals list is not read (never 0 goals)", _scenario(without("ah-goals", "goals"), tick), _parts(UNK, CUR, CUR), health=("error", UNK)),
    _ledger_row("D11", "defect", "requirements: an exit-0 payload with no requirements list is not read", _scenario(without("ah-requirements", "requirements"), tick), _parts(CUR, UNK, CUR), health=("error", UNK)),
    _ledger_row("D12", "defect", "status: an exit-0 payload with no blockers list is not read (never \"No blockers recorded.\")", _scenario(without("ah-status", "blockers"), tick), _parts(CUR, CUR, UNK), health=("error", UNK)),
    _ledger_row("D13", "defect", "status: a list holding a row that is not one is not read (its count would be short)", _scenario(without("ah-status", "live", bad_row=True), tick), _parts(CUR, CUR, UNK), health=("error", UNK)),
    _ledger_row("D14", "defect", "status: a list missing after a good read is stale, not a current zero", _scenario(tick, without("ah-status", "verified"), tick), _parts(CUR, CUR, STA), health=("error", STA)),
    _ledger_row("C01", "change", "session A -> empty -> A, then A's status read fails (no good read since the gap)", _scenario(tick, to(""), tick, to(SID), fail("ah-status"), tick), _parts(CUR, CUR, UNK), health=("error", UNK)),
]
# D04 serves the finished tick's result (current for B) and checks only what was pushed while its first read ran.


class AsksRunner:
    def __init__(self):
        self.code, self.items = 0, [ask_row(1)]

    def run(self, kind, *args, timeout=20.0, limit=0):
        if self.code:
            return self.code, ""
        return 0, json.dumps({"items": self.items, "blocked": [], "resolved": []})


def ask_row(n, ident=None):
    return {"id": ident or f"wa{n:04d}", "owner": "x", "note": f"ask {n}", "reason": "r", "at": iso(60), "kind": "ask"}


class AsksWorld:
    def __init__(self, session=SID):
        self.main = {"id": session}
        self.runner = AsksRunner()
        self.hub = ev.Hub()
        self.health = col.Health(self.hub)
        self.asks = col.Asks(self.hub, self.health, self.runner, lambda: self.main["id"])
        self.t = 1000.0

    def tick(self):
        self.asks.run(self.t)
        self.t += 300.0

    def move(self, session):
        self.main["id"] = session

    def seen(self):
        row = self.health.rows.get("asks") or {}
        published = self.hub.snapshots.get("asks") or {}
        return {"health": (row.get("status", ""), row.get("truth", "")), "items": len(published.get("items") or []),
                "due": self.asks.due(self.t - 299.0), "watch_blocked": getattr(self, "blocked", False)}


def _asks(*steps):
    def run(w):
        for step in steps:
            step(w)
        return w.seen()
    return run


def a_fail(w):
    w.runner.code = 1


def a_many(n=101):
    def step(w):
        w.runner.items = [ask_row(i) for i in range(n)]
    return step


def a_malformed(w):
    w.runner.items = [ask_row(1), ask_row(2, ident="bad id with spaces")]


def held_watch(w):
    """One session-watch pass (on its own thread, as the server runs it) while another thread holds the asks lock, as
    a click's read does. The watch must not wait for the lock; the join bounds the test if it ever does."""
    import threading  # noqa: PLC0415
    with w.asks.lock:
        thread = threading.Thread(target=watch, args=(w,), daemon=True)
        thread.start()
        thread.join(2.0)
        w.blocked = thread.is_alive()


ASKS_TABLE = [
    ("G20", "guard", "asks never read", _asks(), {"health": ("", ""), "items": 0, "due": True}),
    ("G21", "guard", "asks good read for main's session", _asks(tick), {"health": ("ok", CUR), "items": 1, "due": False}),
    ("G22", "guard", "asks read fails after a good read, same session", _asks(tick, a_fail, tick), {"health": ("error", STA), "items": 1, "due": False}),
    ("G23", "guard", "asks session A -> B, B's read succeeds", _asks(tick, to(SID_B), tick), {"health": ("ok", CUR), "items": 1, "due": False}),
    ("D20", "defect", "asks session A -> empty: A's asks are not shown", _asks(tick, to(""), tick), {"health": ("off", UNK), "items": 0, "due": False}),
    ("D21", "defect", "asks session A -> B, B's read fails: unknown, not A's last good read", _asks(tick, to(SID_B), a_fail, tick), {"health": ("error", UNK), "items": 0, "due": False}),
    ("D22", "defect", "asks session A -> B, then one session-watch pass before the next tick: Health unknown, due at once (the cadence is 300 s)", _asks(tick, to(SID_B), watch), {"health": ("ok", UNK), "items": 1, "due": True}),
    ("D23", "defect", "asks session A -> empty -> B, B's read fails", _asks(tick, to(""), tick, to(SID_B), a_fail, tick), {"health": ("error", UNK), "items": 0, "due": False}),
    ("D24", "defect", "asks: more open asks than the 100 kept is partial", _asks(a_many(), tick), {"health": ("ok", PAR), "items": 100, "due": False}),
    ("D25", "defect", "asks: a row dropped for its shape is partial", _asks(a_malformed, tick), {"health": ("ok", PAR), "items": 1, "due": False}),
    ("D26", "defect", "asks session A -> B while a click's read holds the lock: the session watch turns Health unknown at once", _asks(tick, to(SID_B), held_watch), {"health": ("ok", UNK), "items": 1, "due": True, "watch_blocked": False}),
]


def _owners(rows, then_fail=False):
    def run(_):
        hub = ev.Hub()
        health = col.Health(hub)
        answer = {"code": 0}

        class R:
            def run(self, kind, *args, **kw):
                return answer["code"], json.dumps({"session": SID, "owners": rows})
        owners = col.Owners(hub, health, R(), None)
        owners.run(1000.0)
        if then_fail:
            answer["code"] = 1
            owners.run(1060.0)
        row = health.rows["owners"]
        return {"health": (row["status"], row["truth"])}
    return run


def owner_row(n, ident=None):
    return {"agent_id": ident or f"a{n:016x}", "state": "live", "idle_s": 5, "type": "task-owner"}


def _initiatives(rows=None, configured=True):
    def run(case):
        hub = ev.Hub()
        health = col.Health(hub)
        path = None
        if configured:
            path = case.tmp / "initiatives.json"
            path.write_text(json.dumps({"initiatives": rows}))
        col.Initiatives(hub, health, Reader([case.tmp]), str(path) if path else None).run(1000.0)
        row = health.rows["initiatives"]
        return {"health": (row["status"], row["truth"])}
    return run


def _wals(layout, cap=None):
    def run(case):
        root = case.tmp / "wals"
        layout(root)
        hub = ev.Hub()
        health = col.Health(hub)
        tailer = col.WalTailer(hub, health, Reader([case.tmp]), [(root, "claude"), (case.tmp / "codex-wals-missing", "codex")])
        if cap:
            tailer.MAX_FILES = cap
        tailer.run(time.time())
        row = health.rows["wals"]
        return {"health": (row["status"], row["truth"])}
    return run


def two_wals(root):
    (root / SID).mkdir(parents=True)
    for name in ("main.jsonl", "agent-a1.jsonl"):
        (root / SID / name).write_text("")


def unreadable_root(root):
    root.mkdir()
    root.chmod(0)


def unreadable_session_dir(root):
    two_wals(root)
    (root / SID_B).mkdir()
    (root / SID_B / "main.jsonl").write_text("")
    (root / SID_B).chmod(0)


def _wal_unseeded(case):
    """At start the tailer reads each WAL's newest line; one it cannot open is unseen until a later read succeeds."""
    root = case.tmp / "wals"
    two_wals(root)
    path = root / SID / "agent-a1.jsonl"
    path.write_text(json.dumps({"event": "check", "note": "the newest line"}) + "\n")
    path.chmod(0)
    hub = ev.Hub()
    health = col.Health(hub)
    tailer = col.WalTailer(hub, health, Reader([case.tmp]), [(root, "claude")])
    tailer.run(time.time())
    first = health.rows["wals"]
    first = (first["status"], first["truth"])
    path.chmod(0o600)
    tailer.run(time.time() + 5)
    row = health.rows["wals"]
    return {"health": first, "after": (row["status"], row["truth"])}


def _wal_unopenable(case):
    """A WAL that grows after the first scan but can no longer be opened: its new lines are not seen."""
    root = case.tmp / "wals"
    two_wals(root)
    hub = ev.Hub()
    health = col.Health(hub)
    tailer = col.WalTailer(hub, health, Reader([case.tmp]), [(root, "claude")])
    tailer.run(time.time())
    path = root / SID / "agent-a1.jsonl"
    path.write_text(json.dumps({"event": "check", "note": "a line the page never sees"}) + "\n")
    path.chmod(0)
    tailer.run(time.time() + 5)
    row = health.rows["wals"]
    return {"health": (row["status"], row["truth"])}


def _off_then_error(_):
    health = col.Health(ev.Hub())
    health.ok("asks", "fine")
    health.off("asks", "no main session known yet")
    health.error("asks", "provenance asks exited 1")
    row = health.rows["asks"]
    return {"health": (row["status"], row["truth"])}


OTHER_TABLE = [
    ("G30", "guard", "owners: a whole read is current", _owners([owner_row(i) for i in range(3)]), {"health": ("ok", CUR)}),
    ("G31", "guard", "owners: a failure after a good read is stale", _owners([owner_row(1)], then_fail=True), {"health": ("error", STA)}),
    ("D30", "defect", "owners: more owners than the 60 kept is partial", _owners([owner_row(i) for i in range(61)]), {"health": ("ok", PAR)}),
    ("D31", "defect", "owners: a row dropped for a malformed id is partial", _owners([owner_row(1), owner_row(2, ident="bad id!")]), {"health": ("ok", PAR)}),
    ("G32", "guard", "initiatives: a whole file is current", _initiatives([{"id": f"i{i}", "initiative": "x"} for i in range(3)]), {"health": ("ok", CUR)}),
    ("G33", "guard", "initiatives: no file configured is off with nothing to report", _initiatives(configured=False), {"health": ("off", CUR)}),
    ("D32", "defect", "initiatives: more than the 100 kept is partial", _initiatives([{"id": f"i{i}", "initiative": "x"} for i in range(101)]), {"health": ("ok", PAR)}),
    ("G34", "guard", "WALs: readable roots (one missing: that runtime has none here) are current", _wals(two_wals), {"health": ("ok", CUR)}),
    ("D33", "defect", "WALs: a root that exists but cannot be listed is partial", _wals(unreadable_root), {"health": ("ok", PAR)}),
    ("D34", "defect", "WALs: the file cap reached is partial", _wals(two_wals, cap=1), {"health": ("ok", PAR)}),
    ("D36", "defect", "WALs: a session directory that exists but cannot be listed is partial", _wals(unreadable_session_dir), {"health": ("ok", PAR)}),
    ("D37", "defect", "WALs: a WAL that exists but cannot be opened is partial", _wal_unopenable, {"health": ("ok", PAR)}),
    ("D38", "defect", "WALs: a WAL whose newest line could not be read at start is partial, and current once it reads", _wal_unseeded, {"health": ("ok", PAR), "after": ("ok", CUR)}),
    ("D35", "defect", "Health: an error after off (nothing was read in between) is unknown, not stale", _off_then_error, {"health": ("error", UNK)}),
]


class TruthTable(unittest.TestCase):
    """The table above, one test per row (generated below), so a failing-first run names each row."""

    def setUp(self):
        import tempfile  # noqa: PLC0415
        tmp = tempfile.TemporaryDirectory(prefix="mc-truth-")
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        # an unreadable directory made by a row must be readable again for the cleanup
        self.addCleanup(lambda: [p.chmod(0o700) for p in self.tmp.rglob("*") if p.is_dir()] if self.tmp.exists() else None)

    def check(self, run, world, expected):
        got = run(world)
        self.assertEqual({k: got.get(k) for k in expected}, expected)


def _add(rid, kind, what, run, expected, world):
    def test(self):
        self.check(run, world() if world else self, expected)
    test.__doc__ = f"{rid} [{kind}] {what}"
    setattr(TruthTable, f"test_{rid}_{kind}", test)


for _row in LEDGER_TABLE:
    _add(*_row, world=World)
for _row in ASKS_TABLE:
    _add(*_row, world=AsksWorld)
for _row in OTHER_TABLE:
    _add(*_row, world=None)


if __name__ == "__main__":
    unittest.main()
