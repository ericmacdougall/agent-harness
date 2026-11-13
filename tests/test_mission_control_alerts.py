"""The ops alerts and owner capacity sources (GoodQA goodqa#15934 AC-1 to AC-4, NEG-1 to NEG-6): the ops-watch
ring's active alerts and the owner cap, read-only, bounded, last-good on failure and published only on change."""
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "harness" / "hooks"))
sys.path.insert(0, str(REPO / "harness" / "mission_control"))
os.environ.setdefault("MC_HOOKS", str(REPO / "harness" / "hooks"))

import collectors as col  # noqa: E402
import demo  # noqa: E402
import events as ev  # noqa: E402
from safeio import Refused, Runner  # noqa: E402

NOW = time.time()


def iso(age):
    return ev.iso(NOW - age)


def alert(key, severity="high", message="something is wrong", age=60, seq=1, host="mac", **detail):
    return {"host": host, "event": "raise", "severity": severity, "key": key, "message": message, "detail": detail,
            "seq": seq, "at": iso(age), "source": "ops-watch"}


ACTIVE = [
    alert("ask:w1c986659f85:due", "high", "ask w1c986659f85 awaits the user (reminder 6)", 300, 11),
    alert("liveness:ed7b14c4/agent-ad9581dd5b8cb2057", "critical", "owner SILENT-HIGH: ad9581dd5b8cb2057 goodqa#15585",
          7200, 10, agent="ad9581dd5b8cb2057", stop_block=True, text_sha="75f8673947c301e5", ticket=None),
    alert("mem:swap", "warning", "swap is growing", 30, 12),
    alert("disk:volume:t2-proxmox:/var/lib/vz", "high", "volume is 91% full", 900, 9, host="t2-proxmox"),
]


class Fake:
    def __init__(self, payload=None, code=0):
        self.payload = ACTIVE if payload is None else payload
        self.code = code
        self.calls = []

    def run(self, kind, *args, timeout=20.0, limit=0):
        self.calls.append((kind, args, limit))
        out = self.payload if isinstance(self.payload, str) else json.dumps(self.payload)
        return self.code, out[:limit] if limit else out


def make(runner):
    hub = ev.Hub()
    health = col.Health(hub)
    return col.Alerts(hub, health, runner), hub, health


class RunnerShape(unittest.TestCase):
    def setUp(self):
        self.runner = Runner(python="/usr/bin/python3", ah="/h/hooks/ah.py")

    def test_the_shape_is_one_fixed_read_only_argv(self):
        self.assertEqual(self.runner.argv("ops-watch-active"),
                         ["/usr/bin/python3", "-I", "/h/hooks/ops_watch.py", "active", "--json"])

    def test_any_argument_is_refused(self):  # NEG-1
        for bad in ("run", "emit", "--json", "install", "a;rm -rf ~"):
            with self.subTest(bad=bad), self.assertRaises(Refused):
                self.runner.argv("ops-watch-active", bad)
        for kind in ("ops-watch-run", "ops-watch-emit", "ops-watch"):
            with self.subTest(kind=kind), self.assertRaises(Refused):
                self.runner.argv(kind)


class AlertsCollector(unittest.TestCase):
    def test_one_tick_publishes_the_active_alerts_most_severe_then_newest_first(self):  # AC-1
        runner = Fake()
        alerts, hub, health = make(runner)
        alerts.run(NOW)
        self.assertEqual([k for k, _, _ in runner.calls], ["ops-watch-active"])
        self.assertEqual(health.rows["alerts"]["status"], "ok", health.rows)
        snap = hub.snapshots["alerts"]
        self.assertEqual(snap, alerts.snapshot())
        self.assertEqual([a["key"] for a in snap["items"]],
                         ["liveness:ed7b14c4/agent-ad9581dd5b8cb2057", "ask:w1c986659f85:due",
                          "disk:volume:t2-proxmox:/var/lib/vz", "mem:swap"])
        self.assertEqual(snap["counts"], {"critical": 1, "high": 2, "warning": 1, "info": 0})
        self.assertEqual(snap["classes"], {"ask": 1, "disk": 1, "liveness": 1, "mem": 1})
        self.assertEqual((snap["total"], snap["truncated"], snap["stale"], snap["error"]), (4, False, False, ""))
        top = snap["items"][0]
        self.assertEqual((top["severity"], top["cls"], top["host"], top["agent"], top["stop_block"], top["ticket"]),
                         ("critical", "liveness", "mac", "ad9581dd5b8cb2057", True, "goodqa#15585"))
        self.assertEqual(snap["items"][2]["host"], "t2-proxmox")

    def test_only_named_fields_leave_the_collector(self):  # AC-1: the detail object is never forwarded
        alerts, hub, _ = make(Fake())
        alerts.run(NOW)
        for row in hub.snapshots["alerts"]["items"]:
            self.assertEqual(sorted(row), ["agent", "at", "cls", "host", "key", "message", "seq", "severity",
                                           "stop_block", "ticket"])
        self.assertNotIn("75f8673947c301e5", json.dumps(hub.snapshots["alerts"]))

    def test_text_is_redacted_and_clipped(self):  # NEG-5
        secret = "gh" + "p_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
        long = "x" * 5000
        alerts, hub, _ = make(Fake([alert("delivery:/tmp/a", message=f"token {secret} leaked"),
                                    alert("drift:hooks", message=long, seq=2),
                                    alert("k" * 900, seq=3)]))
        alerts.run(NOW)
        blob = json.dumps(hub.snapshots["alerts"])
        self.assertNotIn(secret, blob)
        by_cls = {a["cls"]: a for a in hub.snapshots["alerts"]["items"]}
        self.assertLessEqual(len(by_cls["drift"]["message"]), col.Alerts.MAX_MESSAGE)
        self.assertTrue(all(len(a["key"]) <= col.Alerts.MAX_KEY for a in hub.snapshots["alerts"]["items"]))

    def test_hostile_text_stays_data(self):
        payload = "<img src=x onerror=alert(1)>"
        alerts, hub, _ = make(Fake([alert(f"x:{payload}", message=payload, host=payload, agent=payload)]))
        alerts.run(NOW)
        row = hub.snapshots["alerts"]["items"][0]
        self.assertEqual(row["message"], payload)   # shown as text by the page, never parsed
        self.assertEqual(row["agent"], "")           # an id that is not an id is dropped, never rewritten
        self.assertNotIn("<", row["host"])
        self.assertEqual(row["cls"], "x")

    def test_rows_are_bounded_and_the_counts_cover_every_alert(self):  # AC-2, NEG-3
        many = [alert(f"heavy:copy:{i}", "warning", seq=i) for i in range(500)] + [alert("mem:jetsam", "critical", seq=900)]
        alerts, hub, _ = make(Fake(many))
        alerts.run(NOW)
        snap = hub.snapshots["alerts"]
        self.assertEqual(len(snap["items"]), col.Alerts.MAX_ROWS)
        self.assertEqual((snap["total"], snap["truncated"]), (501, True))
        self.assertEqual(snap["counts"]["warning"], 500)
        self.assertEqual(snap["items"][0]["key"], "mem:jetsam")  # the cut never hides the most severe

    def test_an_unknown_severity_is_never_promoted_and_bad_rows_are_dropped(self):  # NEG-4
        alerts, hub, _ = make(Fake([alert("a:1", "CRITICAL!!"), alert("b:1", None), "junk", 7, None, {"severity": "high"},
                                    {"key": "", "severity": "high"}, dict(alert("c:1"), event="clear"),
                                    alert("d:1", "critical")]))
        alerts.run(NOW)
        snap = hub.snapshots["alerts"]
        self.assertEqual([(a["key"], a["severity"]) for a in snap["items"]],
                         [("d:1", "critical"), ("a:1", "info"), ("b:1", "info")])
        self.assertEqual(snap["total"], 3)

    def test_a_failed_read_keeps_the_last_good_rows_marked_stale(self):  # AC-3, NEG-2
        runner = Fake()
        alerts, hub, health = make(runner)
        alerts.run(NOW)
        for code, payload, needle in ((3, ACTIVE, "exited 3"), (0, "not json", "unreadable"), (0, {"a": 1}, "shape"),
                                      (0, "[" + " " * (col.Alerts.LIMIT + 10) + "]", "over")):
            with self.subTest(needle=needle):
                runner.code, runner.payload = code, payload
                alerts.next_at = 0
                alerts.run(NOW + 100)
                snap = hub.snapshots["alerts"]
                self.assertEqual(len(snap["items"]), 4)
                self.assertTrue(snap["stale"])
                self.assertIn(needle, snap["error"])
                self.assertEqual(health.rows["alerts"]["status"], "error")
        runner.code, runner.payload = 0, ACTIVE
        alerts.next_at = 0
        alerts.run(NOW + 200)
        self.assertEqual((hub.snapshots["alerts"]["stale"], hub.snapshots["alerts"]["error"]), (False, ""))

    def test_a_first_read_that_fails_is_unknown_never_zero_alerts(self):  # NEG-2
        alerts, hub, _ = make(Fake(code=1))
        alerts.run(NOW)
        snap = hub.snapshots["alerts"]
        self.assertEqual((snap["items"], snap["at"], snap["stale"]), ([], "", False))
        self.assertIn("exited 1", snap["error"])

    def test_an_unchanged_read_publishes_nothing(self):  # AC-3
        alerts, hub, _ = make(Fake())
        alerts.run(NOW)
        seq = hub.seq
        alerts.next_at = 0
        alerts.run(NOW + 60)
        self.assertEqual(hub.seq, seq)

    def test_the_read_is_capped_and_idles_slower_without_a_page(self):
        runner = Fake()
        alerts, _, _ = make(runner)
        alerts.run(NOW)
        self.assertEqual(runner.calls[0][2], col.Alerts.LIMIT + 1)
        self.assertGreaterEqual(alerts.interval, 60)
        self.assertGreaterEqual(alerts.idle_interval, 300)


class Capacity(unittest.TestCase):
    """AC-4: the owner cap line, from the same `ah owners` read (no extra subprocess)."""

    ROWS = [
        {"agent_id": "a1", "owner": True, "state": "live"},
        {"agent_id": "a2", "owner": True, "state": "live"},
        {"agent_id": "a3", "owner": False, "state": "live"},                       # a helper never holds a slot
        {"agent_id": "a4", "owner": True, "state": "SILENT-HIGH", "disposition": None},
        {"agent_id": "a5", "owner": True, "state": "DROPPED", "disposition": {"kind": "closed"}},
        {"agent_id": "a6", "owner": True, "state": "SILENT", "disposition": {"kind": "waiting"}},
        {"agent_id": "a7", "owner": True, "state": "done"},
        {"agent_id": "a8", "owner": True, "state": "live", "decision_required": True},
        "junk",
    ]

    def test_counts_live_silent_and_undecided_owners_against_the_cap(self):
        out = col.capacity(self.ROWS, 8)
        self.assertEqual(out, {"cap": 8, "live": 3, "silent": 2, "decisions": 2, "over": False,
                               "source": "ah owners"})

    def test_over_the_cap_is_flagged_and_a_missing_cap_is_unknown(self):
        rows = [{"agent_id": f"a{i}", "owner": True, "state": "live"} for i in range(9)]
        self.assertTrue(col.capacity(rows, 8)["over"])
        for bad in (None, 0, -1, "8", 8.5, True, 10 ** 6):
            with self.subTest(bad=bad):
                out = col.capacity(rows, bad)
                self.assertEqual((out["cap"], out["over"]), (None, False))

    def test_the_cap_is_read_from_the_tier_policy_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "model_tiers.json"
            path.write_text(json.dumps({"caps": {"session_owner_agents": 8}}))
            self.assertEqual(col.read_owner_cap(path), 8)
            path.write_text("{broken")
            self.assertIsNone(col.read_owner_cap(path))
            path.write_text(json.dumps({"caps": {"session_owner_agents": "many"}}))
            self.assertIsNone(col.read_owner_cap(path))
            self.assertIsNone(col.read_owner_cap(Path(tmp) / "missing.json"))
            link = Path(tmp) / "link.json"
            path.write_text(json.dumps({"caps": {"session_owner_agents": 8}}))
            link.symlink_to(path)
            self.assertIsNone(col.read_owner_cap(link))  # a symlink is never followed
        self.assertEqual(col.read_owner_cap(REPO / "harness" / "hooks" / "model_tiers.json"), 8)


class ServerState(unittest.TestCase):
    def test_state_carries_alerts_and_capacity_and_the_demo_answers_the_shape(self):
        sys.path.insert(0, str(REPO / "tests"))
        from test_mission_control import ServerHarness  # noqa: PLC0415

        class H(ServerHarness):
            def runTest(self):
                pass
        h = H()
        h.setUp()
        self.addCleanup(h.tearDown)
        state = h.app.state()
        self.assertEqual(sorted(state["alerts"]), ["at", "classes", "counts", "error", "items", "stale", "total", "truncated"])
        self.assertEqual(sorted(state["capacity"]), ["cap", "decisions", "live", "over", "silent", "source"])
        self.assertIn(h.app.alerts, h.app.collectors)
        code, out = demo.DemoRunner().run("ops-watch-active")
        self.assertEqual(code, 0)
        rows = json.loads(out)
        self.assertTrue(rows and all(r["event"] == "raise" and r["key"] for r in rows))
        self.assertTrue(all("demo" in r["message"].lower() or r["host"] == "demo" for r in rows))


if __name__ == "__main__":
    unittest.main()
