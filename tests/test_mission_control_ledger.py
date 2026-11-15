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


if __name__ == "__main__":
    unittest.main()
