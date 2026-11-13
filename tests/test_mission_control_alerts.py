"""The ops alerts and owner capacity sources (GoodQA goodqa#15934 AC-1 to AC-4, NEG-1 to NEG-9): the ops-watch
ring's active alerts and the owner cap, read-only, bounded, last-good on failure and published only on change."""
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "harness" / "hooks"))
sys.path.insert(0, str(REPO / "harness" / "mission_control"))
os.environ.setdefault("MC_HOOKS", str(REPO / "harness" / "hooks"))

import collectors as col  # noqa: E402
import demo  # noqa: E402
import events as ev  # noqa: E402
import ops_watch  # noqa: E402
import tier_gate  # noqa: E402
from safeio import Refused, Runner  # noqa: E402

NOW = time.time()
POLICY = json.loads((REPO / "harness" / "hooks" / "model_tiers.json").read_text())


def iso(age):
    return ev.iso(NOW - age)


def alert(key, severity="high", message="something is wrong", age=60, seq=1, host="mac", **detail):
    return {"host": host, "event": "raise", "severity": severity, "key": key, "message": message, "detail": detail,
            "seq": seq, "at": iso(age)}


ACTIVE = [
    alert("ask:w1c986659f85:due", "high", "ask w1c986659f85 awaits the user (reminder 6)", 900, 11),
    alert("liveness:ed7b14c4/agent-ad9581dd5b8cb2057", "critical", "owner SILENT-HIGH: ad9581dd5b8cb2057 goodqa#15585",
          7200, 10, agent="ad9581dd5b8cb2057", stop_block=True, text_sha="75f8673947c301e5", ticket=None),
    alert("mem:swap", "warning", "swap is growing", 30, 12),
    # newer than the ask above and later in key order: only a newest-first sort puts it ahead
    alert("disk:volume:t2-proxmox:/var/lib/vz", "high", "volume is 91% full", 300, 9, host="t2-proxmox"),
]


class Source:
    def __init__(self, rows=None, last_run=None):
        self.rows = ACTIVE if rows is None else rows
        self.last_run = NOW - 60 if last_run is None else last_run
        self.error = None
        self.calls = 0

    def __call__(self):
        self.calls += 1
        if self.error:
            raise self.error
        return {"rows": self.rows, "last_run": self.last_run} if isinstance(self.rows, list) else self.rows


def make(source):
    hub = ev.Hub()
    health = col.Health(hub)
    return col.Alerts(hub, health, source), hub, health


class RingRead(unittest.TestCase):
    """AC-1, NEG-1, NEG-2: the ring is read in process, read-only, and an untrustworthy ring is an error."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="mc-ring-")
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        self.ring = ops_watch.ring_path(self.home)

    def emit(self, key, event="raise", severity="high", source="ops-watch"):
        return ops_watch.emit({"host": "mac", "source": source, "event": event, "severity": severity, "check": "t",
                               "key": key, "message": f"message of {key}"}, home=self.home)

    def test_the_latest_row_per_key_decides_and_only_raises_are_active(self):
        self.emit("disk:a")
        self.emit("mem:b", severity="critical")
        self.emit("disk:a", event="clear")
        self.emit("ask:c")
        ops_watch.save_state(self.home, {"last_run": 1234.5})
        data = col.read_ring_active(self.home)
        self.assertEqual(sorted(r["key"] for r in data["rows"]), ["ask:c", "mem:b"])
        self.assertEqual(data["last_run"], 1234.5)
        self.assertEqual(sorted(data["rows"][0]), ["at", "detail", "event", "host", "key", "message", "seq", "severity"])

    def test_the_read_never_writes_even_with_a_broken_ops_watch_config(self):  # NEG-1 (review F1)
        self.emit("disk:a")
        (self.home / ".agent-harness" / "ops-watch.json").write_text("{broken")
        before = (self.ring.read_bytes(), self.ring.stat().st_mtime_ns, sorted(p.name for p in self.ring.parent.iterdir()))
        for _ in range(3):
            self.assertEqual([r["key"] for r in col.read_ring_active(self.home)["rows"]], ["disk:a"])
        after = (self.ring.read_bytes(), self.ring.stat().st_mtime_ns, sorted(p.name for p in self.ring.parent.iterdir()))
        self.assertEqual(before, after)

    def test_no_ops_watch_command_is_reachable_from_the_runner(self):  # NEG-1
        runner = Runner(python="/usr/bin/python3", ah="/h/hooks/ah.py")
        for kind in ("ops-watch-active", "ops-watch-run", "ops-watch-emit", "ops-watch"):
            with self.subTest(kind=kind), self.assertRaises(Refused):
                runner.argv(kind)
        source = (REPO / "harness" / "mission_control" / "safeio.py").read_text()
        self.assertNotIn("ops_watch", source)

    def test_a_ring_that_cannot_be_trusted_is_an_error_never_an_empty_list(self):  # NEG-2 (review F3)
        with self.assertRaisesRegex(ValueError, "does not exist"):
            col.read_ring_active(self.home)
        self.ring.parent.mkdir(parents=True)
        self.ring.write_bytes(b"")
        with self.assertRaisesRegex(ValueError, "no readable row"):
            col.read_ring_active(self.home)
        self.ring.write_bytes(b"\x00garbage" * 4096)
        with self.assertRaisesRegex(ValueError, "no readable row"):
            col.read_ring_active(self.home)
        self.ring.unlink()
        real = self.home / "elsewhere.jsonl"
        real.write_bytes(b"x" * 2048)
        self.ring.symlink_to(real)
        with self.assertRaisesRegex(ValueError, "not a regular file"):
            col.read_ring_active(self.home)
        self.ring.unlink()
        self.ring.mkdir()
        with self.assertRaisesRegex(ValueError, "not a regular file"):
            col.read_ring_active(self.home)

    def test_a_ring_with_every_alert_cleared_is_a_real_empty_list(self):
        self.emit("disk:a")
        self.emit("disk:a", event="clear")
        self.assertEqual(col.read_ring_active(self.home), {"rows": [], "last_run": None})

    def test_the_ops_watch_names_this_read_depends_on_exist(self):
        for name in ("ring_path", "safe_read", "_parse_slots", "latest_by_key", "compact", "load_state", "RING_SLOTS",
                     "SLOT_BYTES"):
            self.assertTrue(hasattr(ops_watch, name), name)


class AlertsCollector(unittest.TestCase):
    def test_one_tick_publishes_the_active_alerts_most_severe_then_newest_first(self):  # AC-1
        source = Source()
        alerts, hub, health = make(source)
        alerts.run(NOW)
        self.assertEqual(source.calls, 1)
        self.assertEqual(health.rows["alerts"]["status"], "ok", health.rows)
        snap = hub.snapshots["alerts"]
        self.assertEqual(snap, alerts.snapshot())
        self.assertEqual([a["key"] for a in snap["items"]],
                         ["liveness:ed7b14c4/agent-ad9581dd5b8cb2057", "disk:volume:t2-proxmox:/var/lib/vz",
                          "ask:w1c986659f85:due", "mem:swap"])
        self.assertEqual(snap["counts"], {"critical": 1, "high": 2, "warning": 1, "info": 0})
        self.assertEqual(snap["classes"], {"ask": 1, "disk": 1, "liveness": 1, "mem": 1})
        self.assertEqual((snap["total"], snap["truncated"], snap["stale"], snap["error"]), (4, False, False, ""))
        top = snap["items"][0]
        self.assertEqual((top["severity"], top["cls"], top["host"], top["agent"], top["stop_block"], top["ticket"]),
                         ("critical", "liveness", "mac", "ad9581dd5b8cb2057", True, "goodqa#15585"))
        self.assertEqual(snap["items"][1]["host"], "t2-proxmox")

    def test_newest_first_compares_instants_not_strings(self):  # review F5
        rows = [dict(alert("a:plus-two"), at="2026-11-13T10:00:00+02:00"),   # 08:00 UTC
                dict(alert("b:utc"), at="2026-11-13T09:00:00Z"),
                dict(alert("c:millis"), at="2026-11-13T09:30:00.250+00:00"),
                dict(alert("d:no-time"), at="yesterday")]
        alerts, hub, _ = make(Source(rows))
        alerts.run(NOW)
        self.assertEqual([a["key"] for a in hub.snapshots["alerts"]["items"]], ["c:millis", "b:utc", "a:plus-two", "d:no-time"])
        self.assertEqual(hub.snapshots["alerts"]["items"][3]["at"], "")

    def test_only_named_fields_leave_the_collector(self):  # AC-1: the detail object is never forwarded
        alerts, hub, _ = make(Source())
        alerts.run(NOW)
        for row in hub.snapshots["alerts"]["items"]:
            self.assertEqual(sorted(row), ["agent", "at", "cls", "host", "key", "message", "seq", "severity",
                                           "stop_block", "ticket"])
        self.assertNotIn("75f8673947c301e5", json.dumps(hub.snapshots["alerts"]))

    def test_text_is_redacted_and_clipped_in_every_free_text_field(self):  # NEG-5 (review F8)
        secret = "gh" + "p_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
        alerts, hub, _ = make(Source([alert("delivery:/tmp/a", message=f"token {secret} leaked"),
                                      alert(f"drift:{secret}", message="x" * 5000, seq=2),
                                      alert("k" * 900, seq=3, host=secret)]))
        alerts.run(NOW)
        blob = json.dumps(hub.snapshots["alerts"])
        self.assertNotIn(secret, blob)
        by_cls = {a["cls"]: a for a in hub.snapshots["alerts"]["items"]}
        self.assertLessEqual(len(by_cls["drift"]["message"]), col.Alerts.MAX_MESSAGE)
        self.assertTrue(all(len(a["key"]) <= col.Alerts.MAX_KEY and len(a["host"]) <= 64
                            for a in hub.snapshots["alerts"]["items"]))

    def test_hostile_text_stays_data(self):
        payload = "<img src=x onerror=alert(1)>"
        alerts, hub, _ = make(Source([alert(f"x:{payload}", message=payload, host=payload, agent=payload)]))
        alerts.run(NOW)
        row = hub.snapshots["alerts"]["items"][0]
        self.assertEqual(row["message"], payload)   # shown as text by the page, never parsed
        self.assertEqual(row["agent"], "")           # an id that is not an id is dropped, never rewritten
        self.assertNotIn("<", row["host"])
        self.assertEqual(row["cls"], "x")

    def test_rows_are_bounded_and_the_counts_cover_every_alert(self):  # AC-2, NEG-3
        many = [alert(f"heavy:copy:{i}", "warning", seq=i) for i in range(500)] + [alert("mem:jetsam", "critical", seq=900)]
        alerts, hub, _ = make(Source(many))
        alerts.run(NOW)
        snap = hub.snapshots["alerts"]
        self.assertEqual(len(snap["items"]), col.Alerts.MAX_ROWS)
        self.assertEqual((snap["total"], snap["truncated"]), (501, True))
        self.assertEqual(snap["counts"]["warning"], 500)
        self.assertEqual(snap["items"][0]["key"], "mem:jetsam")  # the cut never hides the most severe

    def test_an_unknown_severity_is_never_promoted_and_bad_rows_are_dropped(self):  # NEG-4
        alerts, hub, _ = make(Source([alert("a:1", "CRITICAL!!"), alert("b:1", None), "junk", 7, None, {"severity": "high"},
                                      {"key": "", "severity": "high"}, dict(alert("c:1"), event="clear"),
                                      alert("d:1", "critical"), alert("e:1", True), dict(alert("f:1"), key=["x"])]))
        alerts.run(NOW)
        snap = hub.snapshots["alerts"]
        self.assertEqual([(a["key"], a["severity"]) for a in snap["items"]],
                         [("d:1", "critical"), ("a:1", "info"), ("b:1", "info"), ("e:1", "info")])
        self.assertEqual(snap["total"], 4)

    def test_a_failed_read_keeps_the_last_good_rows_marked_stale(self):  # AC-3, NEG-2, NEG-3
        source = Source()
        alerts, hub, health = make(source)
        alerts.run(NOW)
        cases = ((ValueError("the alert ring does not exist"), None, "does not exist"),
                 (OSError("boom"), None, "boom"),
                 (None, {"rows": "nope"}, "unexpected shape"),
                 (None, [1, 2], "unexpected shape"),
                 (None, {"rows": [alert(f"k:{i}") for i in range(5000)], "last_run": NOW}, "more rows than a ring"))
        for error, payload, needle in cases:
            with self.subTest(needle=needle):
                source.error, source.rows = error, (ACTIVE if payload is None else payload)
                if isinstance(payload, list):
                    alerts.read = lambda: payload  # noqa: B023 - a bare list is not the read's shape
                alerts.next_at = 0
                alerts.run(NOW + 100)
                alerts.read = source
                snap = hub.snapshots["alerts"]
                self.assertEqual(len(snap["items"]), 4)
                self.assertTrue(snap["stale"])
                self.assertIn(needle, snap["error"])
                self.assertEqual(health.rows["alerts"]["status"], "error")
        source.error, source.rows = None, ACTIVE
        alerts.next_at = 0
        alerts.run(NOW + 200)
        self.assertEqual((hub.snapshots["alerts"]["stale"], hub.snapshots["alerts"]["error"]), (False, ""))

    def test_a_first_read_that_fails_is_unknown_never_zero_alerts(self):  # NEG-2
        source = Source()
        source.error = ValueError("the alert ring does not exist: ops-watch has not written on this machine")
        alerts, hub, _ = make(source)
        alerts.run(NOW)
        snap = hub.snapshots["alerts"]
        self.assertEqual((snap["items"], snap["at"], snap["stale"]), ([], "", False))
        self.assertIn("does not exist", snap["error"])

    def test_an_unchanged_read_publishes_nothing_even_when_the_watcher_ran_again(self):  # AC-3
        source = Source()
        alerts, hub, _ = make(source)
        alerts.run(NOW)
        seq = hub.seq
        source.last_run = NOW + 30
        alerts.next_at = 0
        alerts.run(NOW + 60)
        self.assertEqual(hub.seq, seq)
        source.rows = ACTIVE[:2]
        alerts.next_at = 0
        alerts.run(NOW + 120)
        self.assertEqual(hub.seq, seq + 1)

    def test_a_watcher_that_stopped_running_is_reported(self):  # NEG-9
        for last_run, at_known, late in ((NOW - 60, True, False), (NOW - 3600, True, True), (None, False, False),
                                         (NOW + 86400, False, False), (True, False, False), ("soon", False, False)):
            with self.subTest(last_run=last_run):
                source = Source()
                alerts, hub, _ = make(source)
                source.last_run = last_run
                alerts.read = lambda: {"rows": ACTIVE, "last_run": last_run}  # noqa: B023
                alerts.run(NOW)
                snap = hub.snapshots["alerts"]
                self.assertEqual((bool(snap["watcher_at"]), snap["watcher_late"]), (at_known, late))

    def test_the_source_idles_slower_without_a_page(self):
        alerts, _, _ = make(Source())
        self.assertGreaterEqual(alerts.interval, 60)
        self.assertGreaterEqual(alerts.idle_interval, 300)


def owner(agent, state, kind="task-owner", **extra):
    return {"agent_id": agent, "type": kind, "state": state, "owner": kind == "task-owner", **extra}


OWNER_ROWS = [
    owner("a1", "live"),
    owner("a2", "working", "general-purpose"),
    owner("a3", "quiet", "claude"),
    owner("a4", "live", "red-team"),                                                    # a helper never holds a slot
    owner("a5", "SILENT-HIGH"),                                                         # silent, undisposed: holds one
    owner("a6", "SILENT", disposition={"kind": "closed"}),                              # disposed: slot freed
    owner("a7", "SILENT", disposition={"kind": "waiting", "live": True}),               # a live wait frees it
    owner("a8", "SILENT", disposition={"kind": "waiting", "live": False}),              # a dead wait does not
    owner("a9", "SILENT", disposition={"kind": "closed"}, decision_required=True),      # ah still wants a decision
    owner("b1", "idle-helper", "general-purpose", idle_s=100),                          # quiet, still running
    owner("b2", "idle-helper", "general-purpose", idle_s=10 ** 6),                      # stale
    owner("b3", "DROPPED"),
    owner("b4", "done"),
    owner("b5", "live", "invented-label"),                                              # an unknown label is an owner
    "junk",
]


class Capacity(unittest.TestCase):
    """AC-4: the owner cap line, by the spawn gate's own slot rule, from the same `ah owners` read."""

    def test_held_slots_equal_what_the_spawn_gate_counts_over_the_same_rows(self):  # review F2: parity, not a lookalike
        rows = [r for r in OWNER_ROWS if isinstance(r, dict)]
        with mock.patch.object(tier_gate, "_owners_with_deadline", return_value={"owners": rows}):
            gate_ids = tier_gate.live_owner_ids("s", POLICY)
        out = col.capacity(OWNER_ROWS, POLICY)
        self.assertEqual(gate_ids, ["a1", "a2", "a3", "a5", "a8", "a9", "b1", "b5"])
        self.assertEqual(out["held"], len(gate_ids))
        self.assertEqual(out, {"known": True, "cap": 8, "held": 8, "live": 5, "silent": 3, "decisions": 3, "full": True,
                               "floor": False, "stale": False, "error": "", "source": "ah owners"})

    def test_parity_holds_for_every_single_row_and_state(self):
        states = ("live", "working", "quiet", "SILENT", "SILENT-HIGH", "DROPPED", "done", "handoff", "idle-helper", "")
        kinds = ("task-owner", "general-purpose", "claude", "fork", "", "red-team", "Explore", "new-kind")
        disps = (None, {"kind": "closed"}, {"kind": "waiting", "live": True}, {"kind": "reassigned", "live": False},
                 {"kind": "resumed"})
        checked = 0
        for state in states:
            for kind in kinds:
                for disp in disps:
                    for extra in ({}, {"decision_required": True}, {"idle_s": 5}, {"idle_s": 10 ** 7}):
                        row = owner("x1", state, kind, disposition=disp, **extra)
                        with mock.patch.object(tier_gate, "_owners_with_deadline", return_value={"owners": [row]}):
                            want = len(tier_gate.live_owner_ids("s", POLICY))
                        self.assertEqual(col.capacity([row], POLICY)["held"], want, row)
                        checked += 1
        self.assertEqual(checked, len(states) * len(kinds) * len(disps) * 4)

    def test_full_at_the_cap_and_a_floor_when_rows_are_hidden(self):
        rows = [owner(f"a{i}", "live") for i in range(7)]
        self.assertFalse(col.capacity(rows, POLICY)["full"])
        self.assertTrue(col.capacity(rows + [owner("z", "live")], POLICY)["full"])   # the gate refuses at the cap
        self.assertTrue(col.capacity(rows, POLICY, hidden=12)["floor"])
        for hidden in (0, None, "3", True, -1):
            self.assertFalse(col.capacity(rows, POLICY, hidden=hidden)["floor"], hidden)

    def test_a_missing_cap_or_rule_is_unknown_never_a_guess(self):  # NEG-8
        rows = [owner(f"a{i}", "live") for i in range(9)]
        for bad in (None, 0, -1, "8", 8.5, True, 10 ** 6):
            with self.subTest(bad=bad):
                out = col.capacity(rows, {"caps": {"session_owner_agents": bad}})
                self.assertEqual((out["known"], out["cap"], out["full"], out["held"]), (True, None, False, 9))
        self.assertEqual(col.capacity(rows, None)["cap"], None)
        for not_rows in (None, {"owners": []}, "x"):
            self.assertFalse(col.capacity(not_rows, POLICY)["known"])
        with mock.patch.object(col, "_gate", return_value=None):
            out = col.capacity(rows, POLICY)
        self.assertEqual((out["known"], out["held"]), (False, 0))
        self.assertIn("slot rule", out["error"])

    def test_the_cap_is_read_from_the_tier_policy_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "model_tiers.json"
            path.write_text(json.dumps({"caps": {"session_owner_agents": 8}}))
            self.assertEqual(col.read_owner_cap(path), 8)
            for bad in ("{broken", json.dumps({"caps": {"session_owner_agents": "many"}}), json.dumps([1]),
                        json.dumps({"caps": [8]})):
                path.write_text(bad)
                self.assertIsNone(col.read_owner_cap(path), bad)
            self.assertIsNone(col.read_owner_cap(Path(tmp) / "missing.json"))
            link = Path(tmp) / "link.json"
            path.write_text(json.dumps({"caps": {"session_owner_agents": 8}}))
            link.symlink_to(path)
            self.assertIsNone(col.read_owner_cap(link))  # a symlink is never followed
        self.assertEqual(col.read_owner_cap(REPO / "harness" / "hooks" / "model_tiers.json"), 8)


class OwnersCapacity(unittest.TestCase):
    """Review F4: the capacity path inside Owners.tick, its snapshot, its cap and its stale mark."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="mc-cap-")
        self.addCleanup(self.tmp.cleanup)
        self.policy = Path(self.tmp.name) / "model_tiers.json"
        self.policy.write_text(json.dumps({"caps": {"session_owner_agents": 3}}))
        self.hub = ev.Hub()
        self.runner = mock.Mock()
        self.owners = col.Owners(self.hub, col.Health(self.hub), self.runner, None, cap_path=self.policy)

    def payload(self, n, hidden=0):
        return 0, json.dumps({"session": "main-sess", "hidden": hidden,
                              "owners": [owner(f"a{i}", "live", task="t") for i in range(n)]})

    def test_before_the_first_read_capacity_is_unknown_not_zero(self):
        self.assertFalse(self.owners.capacity["known"])
        self.assertNotIn("capacity", self.hub.snapshots)

    def test_a_tick_publishes_capacity_with_the_cap_of_the_policy_file(self):
        self.runner.run.return_value = self.payload(2, hidden=40)
        self.owners.run(NOW)
        snap = self.hub.snapshots["capacity"]
        self.assertEqual((snap["known"], snap["cap"], snap["held"], snap["full"], snap["floor"], snap["stale"]),
                         (True, 3, 2, False, True, False))
        seq = self.hub.seq
        self.owners.next_at = 0
        self.owners.run(NOW + 60)
        self.assertEqual(self.hub.snapshots["capacity"], snap)  # unchanged: no second capacity snapshot
        self.assertLessEqual(self.hub.seq - seq, 1)             # at most the owners snapshot itself
        self.runner.run.return_value = self.payload(3)
        self.owners.next_at = 0
        self.owners.run(NOW + 120)
        self.assertEqual((self.hub.snapshots["capacity"]["held"], self.hub.snapshots["capacity"]["full"]), (3, True))

    def test_a_failed_owners_read_marks_the_count_stale(self):
        self.runner.run.return_value = self.payload(2)
        self.owners.run(NOW)
        self.runner.run.return_value = (4, "{}")
        self.owners.next_at = 0
        self.owners.run(NOW + 60)
        snap = self.hub.snapshots["capacity"]
        self.assertEqual((snap["held"], snap["stale"]), (2, True))
        self.runner.run.return_value = self.payload(2)
        self.owners.next_at = 0
        self.owners.run(NOW + 120)
        self.assertFalse(self.hub.snapshots["capacity"]["stale"])


class ServerState(unittest.TestCase):
    def test_state_carries_alerts_and_capacity_and_the_demo_reads_no_ring(self):
        sys.path.insert(0, str(REPO / "tests"))
        from test_mission_control import ServerHarness  # noqa: PLC0415

        class H(ServerHarness):
            def runTest(self):
                pass
        h = H()
        h.setUp()
        self.addCleanup(h.tearDown)
        state = h.app.state()
        self.assertEqual(sorted(state["alerts"]), ["at", "classes", "counts", "error", "items", "stale", "total",
                                                   "truncated", "watcher_at", "watcher_late"])
        self.assertEqual(sorted(state["capacity"]), ["cap", "decisions", "error", "floor", "full", "held", "known", "live",
                                                     "silent", "source", "stale"])
        self.assertFalse(state["capacity"]["known"])
        self.assertIn(h.app.alerts, h.app.collectors)
        rows = demo.alerts_payload(time.time())
        self.assertTrue(rows and all(r["event"] == "raise" and r["key"] and r["host"] == "demo" for r in rows))
        with self.assertRaises(PermissionError):
            demo.DemoRunner().run("ops-watch-active")

    def test_a_demo_instance_shows_fixture_alerts_without_touching_this_machines_ring(self):
        sys.path.insert(0, str(REPO / "tests"))
        import test_mission_control_demo as demo_tests  # noqa: PLC0415
        tmp = tempfile.TemporaryDirectory(prefix="mc-demo-alerts-")
        self.addCleanup(tmp.cleanup)
        with mock.patch.dict(os.environ, {"MC_HOME": str(Path(tmp.name) / "mc")}), \
                mock.patch.object(col, "read_ring_active", side_effect=AssertionError("the real ring was read in demo mode")):
            app = demo_tests.mcs.build_app(demo_tests.demo_args(demo_tests.free_port()))
            self.assertTrue(app.demo)
            app.alerts.run(time.time())
        snap = app.alerts.snapshot()
        self.assertEqual((snap["total"], snap["error"], snap["watcher_late"]), (4, "", False))
        self.assertTrue(all(row["host"] == "demo" for row in snap["items"]))


if __name__ == "__main__":
    unittest.main()
