"""ahd: the loop writes only through `ah` (a fake CLI records argv), deterministic keys, restart idempotency,
single instance, malformed/torn/rotated inputs, clock jump hold, full disk (writer refuses) and the tick budget.
Stdlib only; every test runs in a scratch HOME; no network, no real transcripts."""
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import tracemalloc
import unittest
from pathlib import Path
from unittest import mock

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import ahd  # noqa: E402
import ahd_peek  # noqa: E402

SESSION = "11111111-2222-4333-8444-555555555555"
NOW = 1_800_000_000.0

# A fake `ah`: logs argv (and stdin) as JSON lines; `alert raise|clear` also writes the ring in slot format with
# the same idempotency semantics as the real store (a repeated --key is a duplicate and writes nothing);
# `owners` prints $FAKE_AH_DIR/owners-<session>.json; FAKE_AH_FAIL=<verb> makes that verb exit 3 (ENOSPC).
FAKE_AH = r'''
import json, os, sys
d = os.environ["FAKE_AH_DIR"]
argv = sys.argv[1:]
stdin = sys.stdin.read() if "-" in argv else ""
with open(os.path.join(d, "calls.jsonl"), "a") as fh:
    fh.write(json.dumps({"argv": argv, "stdin": stdin}) + "\n")
fail = os.environ.get("FAKE_AH_FAIL", "")
verb = " ".join(argv[:2])
if fail and (verb.startswith(fail) or argv[0] == fail):
    sys.stderr.write("OSError: [Errno 28] No space left on device\n"); sys.exit(3)
def opt(name):
    return argv[argv.index(name) + 1] if name in argv else None
if argv[0] == "owners":
    p = os.path.join(d, "owners-" + opt("--session") + ".json")
    if not os.path.exists(p):
        print(json.dumps({"ok": False, "code": "session_unknown"})); sys.exit(3)
    print(open(p).read()); sys.exit(0)
if argv[:1] == ["alert"]:
    keys = os.path.join(d, "keys.txt")
    seen = set(open(keys).read().split()) if os.path.exists(keys) else set()
    k = opt("--key")
    if k in seen:
        print(json.dumps({"ok": True, "result": "duplicate"})); sys.exit(0)
    open(keys, "a").write(k + "\n")
    ring = os.path.join(os.environ["HOME"], ".agent-harness", "state", "alerts.jsonl")
    os.makedirs(os.path.dirname(ring), exist_ok=True)
    evs = [json.loads(l) for l in open(ring)] if os.path.exists(ring) else []
    seq = max([e.get("seq", 0) for e in evs] + [0]) + 1
    ev = {"schema": 1, "seq": seq, "host": os.environ["FAKE_HOST"], "source": opt("--source"),
          "event": argv[1], "severity": opt("--severity") or "info", "key": opt("--alert-key"),
          "message": opt("--message") or "resolved"}
    with open(ring, "a") as fh:
        fh.write(json.dumps(ev).ljust(1023) + "\n")
    print(json.dumps({"ok": True, "result": "applied", "seq": seq})); sys.exit(0)
if argv[:1] in (["heartbeat"], ["spool"]):
    print(json.dumps({"ok": True, "result": "applied"})); sys.exit(0)
sys.stderr.write("ah: error: argument cmd: invalid choice\n"); sys.exit(2)
'''


def owner(agent, state, idle=1900, typ="task-owner", task="build the thing", ticket=None, last="2027-01-15T07:28:00Z"):
    return {"agent_id": agent, "type": typ, "task": task, "state": state, "owner": True,
            "severity": {"SILENT": "warning", "SILENT-HIGH": "high", "DROPPED": "high"}.get(state, "info"),
            "idle_s": idle, "ticket": ticket, "last_activity": last}


def mono_deadline():
    return time.monotonic() + 30


class Scratch(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name)
        self.fake = self.home / "fake-ah"
        self.fake.mkdir()
        (self.fake / "ah.py").write_text(FAKE_AH)
        wal = self.home / ".claude" / "wals" / SESSION
        wal.mkdir(parents=True)
        self.main_wal = wal / "main.jsonl"
        self.main_wal.write_text(json.dumps({"at": "2027-01-15T08:00:00+00:00", "event": "intent", "note": "x"}) + "\n")
        os.utime(self.main_wal, (NOW - 60, NOW - 60))
        self.env = mock.patch.dict(os.environ, {"HOME": str(self.home), "FAKE_AH_DIR": str(self.fake),
                                                "FAKE_HOST": ahd.host()})
        self.env.start()
        self.clock = mock.patch.object(ahd, "now", side_effect=lambda: self.t)
        self.t = NOW
        self.clock.start()
        self.policy = ahd.load_policy()
        self.policy["ah"] = [sys.executable, "-I", str(self.fake / "ah.py")]

    def tearDown(self):
        self.clock.stop()
        self.env.stop()
        self.tmp.cleanup()

    def owners(self, rows, session=SESSION):
        (self.fake / f"owners-{session}.json").write_text(json.dumps({"session": session, "owners": rows}))

    def calls(self):
        p = self.fake / "calls.jsonl"
        return [json.loads(l) for l in p.read_text().splitlines()] if p.exists() else []

    def alert_calls(self, op=None):
        return [c["argv"] for c in self.calls() if c["argv"][:1] == ["alert"] and (op is None or c["argv"][1] == op)]

    def daemon(self):
        d = ahd.Daemon(policy=self.policy)
        self.assertTrue(d.acquire())
        self.addCleanup(d.release)
        return d

    def ring(self):
        return ahd.ring_state(ahd.read_ring(), "ahd", ahd.host())


class WritesOnlyThroughAh(Scratch):
    def test_silent_owner_raises_once_via_ah_and_control_stays_quiet(self):
        self.owners([owner("a1111111111111111", "SILENT"), owner("a2222222222222222", "live", idle=300)])
        d = self.daemon()
        d.tick()
        raises = self.alert_calls("raise")
        self.assertEqual(len(raises), 1, raises)
        argv = raises[0]
        self.assertEqual(argv[argv.index("--alert-key") + 1], f"liveness:{SESSION[:8]}/agent-a1111111111111111")
        self.assertEqual(argv[argv.index("--severity") + 1], "warning")
        d.tick()  # already active in the ring: no second raise
        self.assertEqual(len(self.alert_calls("raise")), 1)

    def test_dropped_and_silent_high_are_high(self):
        self.owners([owner("a3333333333333333", "DROPPED", typ="general-purpose"),
                     owner("a4444444444444444", "SILENT-HIGH", idle=4000)])
        self.daemon().tick()
        sev = {a[a.index("--alert-key") + 1]: a[a.index("--severity") + 1] for a in self.alert_calls("raise")}
        self.assertEqual(set(sev.values()), {"high"})
        self.assertEqual(len(sev), 2)

    def test_rows_ah_marks_as_non_owner_never_alert(self):
        helper = dict(owner("a5555555555555555", "SILENT-HIGH", typ=None), owner=False)
        self.owners([helper, dict(owner("a6666666666666666", "SILENT"), owner=True)])
        self.daemon().tick()
        keys = [a[a.index("--alert-key") + 1] for a in self.alert_calls("raise")]
        self.assertEqual(keys, [f"liveness:{SESSION[:8]}/agent-a6666666666666666"])

    def test_clear_when_owner_recovers(self):
        self.owners([owner("a1111111111111111", "SILENT")])
        d = self.daemon()
        d.tick()
        self.owners([owner("a1111111111111111", "live", idle=10)])
        d.tick()
        clears = self.alert_calls("clear")
        self.assertEqual(len(clears), 1)
        self.assertNotIn("liveness:", json.dumps([k for k, e in self.ring().items() if e["event"] == "raise"]))

    def test_ahd_never_opens_a_state_file_for_writing(self):
        self.owners([owner("a1111111111111111", "SILENT")])
        before = {p: p.stat().st_mtime_ns for p in self.home.rglob("*") if p.is_file() and "fake-ah" not in p.parts}
        real_open = open
        wrote = []

        def spy(file, mode="r", *a, **k):
            if any(c in mode for c in "wax+") and "fake-ah" not in str(file):
                wrote.append(str(file))
            return real_open(file, mode, *a, **k)

        with mock.patch("builtins.open", spy):
            self.daemon().tick()
        self.assertEqual(wrote, [])
        lock = self.home / ".agent-harness" / "run" / "ahd.lock"
        self.assertEqual(lock.stat().st_size, 0)
        changed = [p for p, m in before.items() if p.exists() and p.stat().st_mtime_ns != m
                   and "alerts.jsonl" not in p.name]  # the ring is written by the fake ah, not ahd
        self.assertEqual(changed, [])


class RestartAndKeys(Scratch):
    def test_restart_does_not_reraise(self):
        self.owners([owner("a1111111111111111", "SILENT")])
        d = self.daemon()
        d.tick()
        d.release()
        d2 = self.daemon()
        d2.tick()
        self.assertEqual(len(self.alert_calls("raise")), 1)

    def test_kill_before_apply_reissues_the_same_key(self):
        # A tick killed after deciding but before ah applied: the next instance must send the identical key.
        self.owners([owner("a1111111111111111", "SILENT")])
        os.environ["FAKE_AH_FAIL"] = "alert raise"
        d = self.daemon()
        d.tick()
        d.release()
        del os.environ["FAKE_AH_FAIL"]
        d2 = self.daemon()
        d2.tick()
        keys = [a[a.index("--key") + 1] for a in self.alert_calls("raise")]
        self.assertEqual(len(keys), 2)
        self.assertEqual(keys[0], keys[1])
        self.assertEqual(len([e for e in self.ring().values() if e["event"] == "raise"]), 1)

    def test_reraise_after_clear_gets_a_new_key(self):
        self.owners([owner("a1111111111111111", "SILENT")])
        d = self.daemon()
        d.tick()
        self.owners([])
        d.tick()
        self.owners([owner("a1111111111111111", "SILENT", last="2027-01-15T07:40:00Z")])  # went quiet again later
        d.tick()
        keys = [a[a.index("--key") + 1] for a in self.alert_calls("raise")]
        self.assertEqual(len(keys), 2)
        self.assertNotEqual(keys[0], keys[1])

    def test_key_shape(self):
        self.owners([owner("a1111111111111111", "SILENT")])
        self.daemon().tick()
        k = [a[a.index("--key") + 1] for a in self.alert_calls("raise")][0]
        self.assertRegex(k, r"^ahd:[A-Za-z0-9._-]+:liveness:11111111\.agent-a1111111111111111:raise-warning:\d+$")
        self.assertLessEqual(len(k), 128)
        self.assertEqual(k.rsplit(":", 1)[1], str(int(ahd.parse_ts("2027-01-15T07:28:00Z"))))

    def test_ring_wrap_reasserts_with_a_new_key(self):
        self.owners([owner("a1111111111111111", "SILENT")])
        d = self.daemon()
        d.tick()
        ring = self.home / ".agent-harness" / "state" / "alerts.jsonl"
        other = {"schema": 1, "seq": 99, "host": "elsewhere", "source": "x", "event": "raise", "severity": "info",
                 "key": "k", "message": "m"}
        ring.write_text(json.dumps(other).ljust(1023) + "\n")  # our raise was overwritten by the wrap
        d.tick()
        raises = self.alert_calls("raise")
        self.assertEqual(len(raises), 3)  # original, duplicate (ah already had it), reassert
        self.assertIn('"reasserted": true', raises[2][raises[2].index("--detail") + 1])
        self.assertNotEqual(raises[2][raises[2].index("--key") + 1], raises[0][raises[0].index("--key") + 1])
        self.assertEqual([e["event"] for e in self.ring().values()], ["raise"])


class SingleInstance(Scratch):
    def test_second_instance_cannot_lock(self):
        d = self.daemon()
        other = ahd.Daemon(policy=self.policy)
        self.assertFalse(other.acquire())
        d.release()
        self.assertTrue(other.acquire())
        other.release()

    def test_second_process_exits_zero_without_ticking(self):
        self.daemon()  # holds the lock in this process
        env = dict(os.environ)
        p = subprocess.run([sys.executable, "-I", str(HOOKS / "ahd.py"), "--once"], env=env,
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(p.returncode, 0)
        self.assertIn("already running", p.stderr)
        self.assertEqual(self.calls(), [])


class BadInputs(Scratch):
    def test_malformed_and_torn_ring_slots_are_skipped(self):
        ring = self.home / ".agent-harness" / "state" / "alerts.jsonl"
        ring.parent.mkdir(parents=True)
        good = {"schema": 1, "seq": 5, "host": ahd.host(), "source": "ahd", "event": "raise", "severity": "warning",
                "key": f"liveness:{SESSION[:8]}/agent-a1111111111111111", "message": "m"}
        ring.write_bytes(b"\x00\xffnot json\n" + json.dumps({"empty": True}).encode() + b"\n" +
                         json.dumps(good).encode() + b"\n" + b'{"seq": 9, "half')
        self.assertEqual(list(self.ring()), [good["key"]])
        self.owners([owner("a1111111111111111", "SILENT")])
        self.daemon().tick()
        # already active, so the torn tail did not hide it: the only raise is a refresh of the fixture's short text
        calls = self.alert_calls("raise")
        self.assertEqual(len(calls), 1)
        self.assertIn('"updated": true', " ".join(calls[0]))

    def test_wal_asks_survive_malformed_lines_and_truncation(self):
        lines = [json.dumps({"at": "2027-01-15T07:00:00+00:00", "event": "ask", "id": "w1", "note": "need key"}),
                 "garbage{", json.dumps({"event": "ask", "id": "w2", "note": "x"}),
                 json.dumps({"event": "ask_resolved", "ref": "w2"}), '{"event": "ask", "id": "w3"']
        self.main_wal.write_text("\n".join(lines))
        got = ahd.wal_asks(self.policy, [SESSION])
        self.assertEqual([a["id"] for a in got], ["w1"])
        self.main_wal.write_text("")  # truncated / rotated to empty
        self.assertEqual(ahd.wal_asks(self.policy, [SESSION]), [])

    def test_owner_doc_unreadable_never_clears_liveness(self):
        self.owners([owner("a1111111111111111", "SILENT")])
        d = self.daemon()
        d.tick()
        (self.fake / f"owners-{SESSION}.json").unlink()  # ah owners now fails for this session
        d.tick()
        self.assertEqual(self.alert_calls("clear"), [])

    def test_v1_ledger_flags(self):
        led = self.home / ".agent-harness" / "work-assignments.json"
        led.parent.mkdir(parents=True, exist_ok=True)
        items = {
            "WA-1": {"id": "WA-1", "state": "open", "owner": "unassigned", "description": "fix login",
                     "created": "2027-01-15T07:00:00Z", "state_since": "2027-01-15T07:00:00Z", "evidence": []},
            "WA-2": {"id": "WA-2", "state": "open", "owner": "main", "description": "owned",
                     "created": "2027-01-15T07:00:00Z", "state_since": "2027-01-15T07:00:00Z"},
            "WA-3": {"id": "WA-3", "state": "done", "owner": "main", "description": "shipped", "evidence": []},
            "WA-4": {"id": "WA-4", "state": "open", "owner": "unassigned", "description": "fresh",
                     "created": "2027-01-15T07:59:00Z", "state_since": "2027-01-15T07:59:00Z"},
            "bad": "not a dict"}
        led.write_text(json.dumps({"items": items}))
        self.t = ahd.parse_ts("2027-01-15T10:00:00Z")
        flags = ahd.ask_alerts(ahd.v1_asks(self.policy), self.policy, self.t)
        self.assertEqual(sorted(flags), ["ask:WA-1:unowned", "ask:WA-3:no-evidence", "ask:WA-4:unowned"])
        self.assertEqual(flags["ask:WA-1:unowned"]["severity"], "high")
        items = {"WA-5": {"id": "WA-5", "state": "open", "owner": "unassigned", "description": "Relaunch Solve now",
                          "created": "2027-01-15T07:00:00Z", "state_since": "2027-01-15T07:00:00Z",
                          "imported": {"when": "2027-01-10T00:00:00Z"}}}
        led.write_text(json.dumps({"items": items}))
        flags = ahd.ask_alerts(ahd.v1_asks(self.policy), self.policy, self.t)
        self.assertEqual(flags["ask:WA-5:unowned"]["severity"], "warning")  # old request, recent import
        self.assertNotIn("Solve", json.dumps(flags))
        led.write_text("{torn")
        self.assertIn("ask:ledger:error", ahd.ask_alerts(ahd.v1_asks(self.policy), self.policy, self.t))


class ClockAndDisk(Scratch):
    def test_clock_jump_holds_liveness_transitions_for_one_tick(self):
        self.owners([owner("a2222222222222222", "SILENT")])
        d = self.daemon()
        d.tick()
        self.t -= 3600  # wall clock jumps back an hour; monotonic does not
        self.owners([owner("a1111111111111111", "SILENT")])  # a new raise and a clear are both due
        s = d.tick()
        self.assertIn("clock_jump", s)
        self.assertEqual(len(self.alert_calls("raise")), 1)  # only the first tick's raise
        self.assertEqual(self.alert_calls("clear"), [])
        d.tick()
        self.assertEqual(len(self.alert_calls("raise")), 2)
        self.assertEqual(len(self.alert_calls("clear")), 1)

    def test_full_disk_degrades_without_crashing(self):
        self.owners([owner("a1111111111111111", "SILENT")])
        os.environ["FAKE_AH_FAIL"] = "alert"
        d = self.daemon()
        broken = mock.patch.object(ahd.log, "warning", side_effect=OSError(28, "No space left on device"))
        s = d.tick()
        self.assertEqual(s["sent"], 0)
        with broken:  # even the log write failing must not escape a step
            s = d.tick()
        self.assertIn("alerts", s["steps"])
        del os.environ["FAKE_AH_FAIL"]
        d.tick()
        self.assertEqual(len([e for e in self.ring().values() if e["event"] == "raise"]), 1)

    def test_serve_loop_survives_a_failing_tick(self):
        d = self.daemon()
        d.policy["tick_seconds"] = 0
        n = {"i": 0}

        def boom():
            n["i"] += 1
            if n["i"] >= 3:
                d.stop.set()
            raise RuntimeError("x")

        with mock.patch.object(d, "tick", boom), mock.patch.object(d.stop, "wait", lambda t: None), \
                mock.patch.object(ahd.signal, "signal"):
            self.assertEqual(d.serve_forever(), 0)
        self.assertEqual(n["i"], 3)

    def test_tick_budget_skips_late_steps_and_never_clears(self):
        self.owners([owner("a1111111111111111", "SILENT")])
        d = self.daemon()
        d.tick()
        self.owners([])
        d.policy["tick_budget_seconds"] = 0.0
        s = d.tick()
        self.assertTrue(s["skipped"])
        self.assertEqual(self.alert_calls("clear"), [])


class Batching(Scratch):
    def test_many_transitions_use_one_batch_call_when_supported(self):
        self.owners([owner(f"a{i:016x}", "SILENT") for i in range(12)])
        d = self.daemon()
        d.tick()
        apply_calls = [c for c in self.calls() if c["argv"][:1] == ["apply"]]
        self.assertEqual(len(apply_calls), 1)  # the fake rejects apply; ahd falls back to single calls
        self.assertEqual(len(apply_calls[0]["stdin"].strip().splitlines()), 12)
        self.assertEqual(len(self.alert_calls("raise")), 12)
        d.tick()
        self.assertEqual(len([c for c in self.calls() if c["argv"][:1] == ["apply"]]), 1)  # remembered unsupported


class EscalationAndTickets(Scratch):
    def test_critical_after_90_min_and_stop_block_detail(self):
        self.owners([owner("a1111111111111111", "DROPPED", idle=5500, typ="general-purpose"),
                     owner("a2222222222222222", "SILENT", idle=6000)])
        self.daemon().tick()
        by = {a[a.index("--alert-key") + 1]: a for a in self.alert_calls("raise")}
        k1 = f"liveness:{SESSION[:8]}/agent-a1111111111111111"
        k2 = f"liveness:{SESSION[:8]}/agent-a2222222222222222"
        self.assertEqual(by[k1][by[k1].index("--severity") + 1], "critical")
        self.assertEqual(by[k2][by[k2].index("--severity") + 1], "warning")  # SILENT never escalates by itself
        detail = json.loads(by[k1][by[k1].index("--detail") + 1])
        self.assertTrue(detail["stop_block"])
        self.assertEqual(detail["main_session"], SESSION)

    def test_ticket_comment_only_from_the_goodqa_poster_host(self):
        self.owners([owner("a1111111111111111", "DROPPED", ticket="goodqa#14506")])
        self.policy["goodqa_poster"] = False
        d = self.daemon()
        d.tick()
        self.assertEqual([c for c in self.calls() if c["argv"][:2] == ["ticket", "comment"]], [])
        d.release()
        self.policy["goodqa_poster"] = True
        (self.fake / "keys.txt").unlink()
        ring = self.home / ".agent-harness" / "state" / "alerts.jsonl"
        ring.unlink()
        self.daemon().tick()
        comments = [c["argv"] for c in self.calls() if c["argv"][:2] == ["ticket", "comment"]]
        self.assertEqual(len(comments), 1)
        self.assertEqual(comments[0][2], "GoodQA goodqa#14506")
        self.assertIn("--key", comments[0])

    def test_silent_warning_does_not_comment(self):
        self.policy["goodqa_poster"] = True
        self.owners([owner("a1111111111111111", "SILENT", ticket="goodqa#1")])
        self.daemon().tick()
        self.assertEqual([c for c in self.calls() if c["argv"][:2] == ["ticket", "comment"]], [])


AH_PY = HOOKS / "ah.py"


class AlertTextRefresh(unittest.TestCase):
    """ahd must not inherit the frozen text or the false-drop bug from ops-watch (GoodQA goodqa#14740)."""

    def flag(self, message, severity="high"):
        return {"severity": severity, "class": "liveness", "kind": "liveness", "subject": "s.t", "since": 100,
                "message": message, "detail": {"ticket": "goodqa#1"}}

    def ring(self, message, at="2027-01-15T07:00:00+00:00", severity="high"):
        return {"k": {"event": "raise", "severity": severity, "message": message, "at": at}}

    def test_state_change_at_the_same_severity_refreshes(self):
        plan = ahd.plan_transitions({"k": self.flag("owner DROPPED: a1")}, self.ring("owner SILENT-HIGH: a1"), now=NOW)
        self.assertEqual([(op, k) for op, k, _, _ in plan], [("raise", "k")])
        self.assertTrue(plan[0][2]["detail"]["updated"])

    def test_same_text_plans_nothing(self):
        self.assertEqual(ahd.plan_transitions({"k": self.flag("same")}, self.ring("same"), now=NOW), [])

    def test_lower_severity_replaces_the_stale_one(self):
        plan = ahd.plan_transitions({"k": self.flag("x", "warning")}, self.ring("x"), now=NOW)
        self.assertEqual(plan[0][2]["severity"], "warning")

    def test_refresh_key_differs_by_text_and_repeats_for_the_same_text(self):
        d = ahd.Daemon.__new__(ahd.Daemon)
        d.host = "h"
        plan = lambda m: ahd.plan_transitions({"k": self.flag(m)}, self.ring("old"), now=NOW)[0][2]
        self.assertNotEqual(d.key_for("raise", "k", plan("one"), None), d.key_for("raise", "k", plan("two"), None))
        self.assertEqual(d.key_for("raise", "k", plan("one"), None), d.key_for("raise", "k", plan("one"), None))

    def test_refresh_posts_no_ticket_comment(self):
        d = ahd.Daemon.__new__(ahd.Daemon)
        d.host, d.policy, d.call = "h", {"goodqa_poster": ["darwin", "linux"]}, mock.Mock(return_value=(0, {}))
        d.posts_goodqa = lambda: True
        f = ahd.plan_transitions({"k": self.flag("new")}, self.ring("old"), now=NOW)[0][2]
        d.ticket_comment("k", f, mono_deadline())
        d.call.assert_not_called()

    def test_only_real_owner_rows_alert(self):
        rows = [dict(owner("a1111111", "returned", typ="general-purpose"), owner=False),
                dict(owner("a2222222", "idle-helper", typ=None), owner=False),
                owner("a3333333", "finishing", typ="general-purpose"),
                owner("a4444444", "DROPPED", typ="general-purpose"),
                dict(owner("a5555555", "DROPPED", typ="general-purpose"), owner=False)]  # only the owner check stops it
        got = ahd.liveness_alerts({SESSION: {"owners": rows}}, ahd.load_policy())
        self.assertEqual([f["detail"]["agent"] for f in got.values()], ["a4444444"])


class FakeAhWriter:
    """Idempotent on --key and writes through the real ops_watch.emit, so redaction and slot limits are the real ones.
    What `ah alert raise` is expected to do; the real verb is not merged."""

    def __init__(self, ring, at):
        self.ring, self.at, self.seen, self.calls, self.writes = ring, at, set(), 0, 0

    def call(self, verb, args, deadline, stdin=None):
        self.calls += 1
        opt = {args[i]: args[i + 1] for i in range(0, len(args) - 1, 2)}
        if opt["--key"] in self.seen:
            return 0, {"result": "duplicate"}
        self.seen.add(opt["--key"])
        self.writes += 1
        import ops_watch
        kind = verb.split()[-1]
        ops_watch.emit({"host": ahd.host(), "source": "ahd", "event": kind, "severity": opt.get("--severity", "info"),
                        "key": opt["--alert-key"], "message": opt.get("--message", "cleared"), "at": self.at(),
                        "detail": json.loads(opt.get("--detail", "{}"))}, path=self.ring)
        return 0, {"result": "applied"}


class RefreshThroughARealRing(Scratch):
    """Review round 1 of goodqa#14740. A tick is 60 s."""

    KEY = "liveness:s/agent-a1"

    def setUp(self):
        super().setUp()
        self.ring_file = self.home / ".agent-harness" / "state" / "alerts.jsonl"
        self.ring_file.parent.mkdir(parents=True)
        self.d = self.daemon()
        self.ah = FakeAhWriter(self.ring_file, lambda: ahd.iso(self.t))
        self.d.call = self.ah.call
        self.d.posts_goodqa = lambda: False

    def flag(self, message, severity="high", since=100):
        return {"severity": severity, "class": "liveness", "kind": "liveness", "subject": "s.a1", "since": since,
                "message": message, "detail": {"agent": "a1"}}

    def tick(self, flag):
        ring = ahd.ring_state(ahd.read_ring(), "ahd", ahd.host())
        plan = ahd.plan_transitions({self.KEY: flag}, ring, now=self.t)
        self.d.send(plan, time.monotonic() + 60)
        return ahd.ring_state(ahd.read_ring(), "ahd", ahd.host())[self.KEY]

    def wrap_the_ring(self):
        import ops_watch
        for i in range(ahd.RING_SLOTS + 8):
            ops_watch.emit({"host": "other", "source": "noise", "event": "raise", "severity": "info", "key": f"n{i}",
                            "message": "x", "at": ahd.iso(self.t)}, path=self.ring_file)

    def test_redacted_text_writes_once_in_six_hours(self):
        # emit redacts this, so the ring's text can never equal the message
        message = "owner SILENT: a1 (general-purpose) fix auth redirect token=abcdef1234567890abcdef"
        for i in range(360):
            self.t = NOW + i * 60
            row = self.tick(self.flag(message))
        self.assertNotEqual(row["message"], message, "vacuous: emit did not change this text")
        self.assertEqual(self.ah.writes, 1)
        self.assertEqual(self.ah.calls, 1)

    def test_redacted_text_writes_once_on_a_wrapped_ring(self):
        self.wrap_the_ring()
        message = "owner SILENT: a1 fix auth redirect token=abcdef1234567890abcdef"
        for i in range(360):
            self.t = NOW + i * 60
            self.tick(self.flag(message))
        self.assertEqual(self.ah.writes, 1)

    def test_text_too_long_for_a_slot_stays_within_the_hourly_limit(self):
        message = "\u6f22" * 390  # JSON-escaped past the slot, so emit cuts it and drops the detail
        for i in range(360):
            self.t = NOW + i * 60
            row = self.tick(self.flag(message))
        self.assertTrue(row["detail"].get("truncated"), "vacuous: the slot did not overflow")
        self.assertLessEqual(self.ah.writes, 7)

    def test_text_flipping_back_to_an_earlier_value_still_reaches_the_ring(self):
        for i in range(12):
            self.t = NOW + i * 600
            text = "owner state A: a1" if i % 2 == 0 else "owner state B: a1"
            row = self.tick(self.flag(text))
            self.assertEqual(row["message"], text, i)

    def test_severity_flipping_back_to_an_earlier_value_still_reaches_the_ring(self):
        for i in range(12):
            self.t = NOW + i * 600
            severity = "high" if i % 2 == 0 else "warning"
            row = self.tick(self.flag("same text", severity))
            self.assertEqual(row["severity"], severity, i)

    def test_severity_flapping_every_tick_is_bounded(self):
        for i in range(60):
            self.t = NOW + i * 60
            self.tick(self.flag("same text", "high" if i % 2 == 0 else "warning"))
        self.assertLessEqual(self.ah.writes, 25)

    def test_a_rise_is_never_delayed(self):
        self.tick(self.flag("same text", "warning"))
        self.t = NOW + 1
        self.assertEqual(self.tick(self.flag("same text", "high"))["severity"], "high")

    def test_new_words_wait_for_the_limit_and_numbers_for_the_hour(self):
        self.tick(self.flag("owner SILENT: a1 since 10"))
        self.t = NOW + 60
        self.assertEqual(self.tick(self.flag("owner DROPPED: a1 since 10"))["message"], "owner SILENT: a1 since 10")
        self.t = NOW + 300
        self.assertEqual(self.tick(self.flag("owner DROPPED: a1 since 10"))["message"], "owner DROPPED: a1 since 10")
        self.t = NOW + 900
        self.assertEqual(self.tick(self.flag("owner DROPPED: a1 since 20"))["message"], "owner DROPPED: a1 since 10")
        self.t = NOW + 300 + 3600
        self.assertEqual(self.tick(self.flag("owner DROPPED: a1 since 20"))["message"], "owner DROPPED: a1 since 20")

    def test_non_string_ring_message_does_not_break_planning(self):
        ring = {self.KEY: {"event": "raise", "severity": "high", "message": 7, "at": ahd.iso(NOW - 7200), "seq": 1,
                           "detail": "not a dict"}}
        plan = ahd.plan_transitions({self.KEY: self.flag("text")}, ring, now=NOW)
        self.assertEqual([op for op, *_ in plan], ["raise"])


@unittest.skipUnless(AH_PY.is_file(), "needs ah.py from feat/ah-query (feat/ahd is stacked on it)")
class SolveDropFixture(Scratch):
    """The incident: a general-purpose owner, never in main.jsonl spawn events, stopped 2 h ago with no handoff,
    while its ask stays open. Asserted end to end through the real `ah owners`."""

    def test_solve_style_drop_is_flagged_critical(self):
        import time as _t
        real_now = _t.time()
        aid = "a5017e0000000000d"
        wal_dir = self.main_wal.parent
        two_h = real_now - 7200
        self.main_wal.write_text(json.dumps({"at": ahd.iso(two_h - 600), "event": "scope",
                                             "note": f"Owner for the capture app fix: agent {aid}, branch fix/x"}) + "\n")
        task_wal = wal_dir / f"agent-{aid}.jsonl"
        task_wal.write_text(json.dumps({"at": ahd.iso(two_h - 300), "event": "intent", "note": "start the fix"}) + "\n"
                            + json.dumps({"at": ahd.iso(two_h), "event": "pretool", "agent_id": aid, "tool": "Bash"}) + "\n")
        os.utime(task_wal, (two_h, two_h))
        sub = self.home / ".claude" / "projects" / "-Users-x-repo" / SESSION / "subagents"
        sub.mkdir(parents=True)
        tr = sub / f"agent-{aid}.jsonl"
        tr.write_text("{}\n")
        os.utime(tr, (two_h, two_h))
        (sub / f"agent-{aid}.meta.json").write_text(json.dumps({"agentType": "general-purpose", "finished": True,
                                                                "description": "capture app fix owner"}))
        os.utime(self.main_wal, (real_now - 60, real_now - 60))
        self.t = real_now
        self.policy["ah"] = [sys.executable, "-I", str(AH_PY)]
        d = self.daemon()
        d.tick()
        flag = d.last["desired"].get(f"liveness:{SESSION[:8]}/agent-{aid}")
        self.assertIsNotNone(flag, d.last["desired"])
        self.assertEqual(flag["detail"]["state"], "DROPPED")
        self.assertEqual(flag["severity"], "critical")
        # control: the same owner active 5 minutes ago is not flagged
        for p in (task_wal, tr):
            os.utime(p, (real_now - 300, real_now - 300))
        task_wal.write_text(task_wal.read_text() + json.dumps({"at": ahd.iso(real_now - 300), "event": "status",
                                                               "note": "still working"}) + "\n")
        (sub / f"agent-{aid}.meta.json").write_text(json.dumps({"agentType": "general-purpose"}))
        d.tick()
        self.assertNotIn(f"liveness:{SESSION[:8]}/agent-{aid}", d.last["desired"])


class Messages(Scratch):
    def test_interview_task_text_and_secrets_never_reach_the_writer(self):
        self.owners([owner("a1111111111111111", "SILENT", task="prep Solve interview answers"),
                     owner("a2222222222222222", "SILENT", task="use sk-ant-api03-AAAAAAAAAAAAAAAAAAAA now")])
        self.daemon().tick()
        blob = json.dumps(self.calls())
        self.assertNotIn("Solve", blob)
        self.assertNotIn("interview", blob.lower())
        self.assertNotIn("sk-ant-api03-AAAA", blob)


if __name__ == "__main__":
    unittest.main()


class ReviewRound1(Scratch):
    """Regressions for red-team round 1 (B1-B4, F1, F4, F6) at 37fb2f8."""

    def second_session(self, name="22222222-3333-4444-8555-666666666666"):
        d = self.home / ".claude" / "wals" / name
        d.mkdir(parents=True)
        (d / "main.jsonl").write_text("{}\n")
        os.utime(d / "main.jsonl", (NOW - 60, NOW - 60))
        return name

    def test_b1_partial_owner_failure_keeps_that_sessions_alerts(self):
        other = self.second_session()
        self.owners([owner("a1111111111111111", "SILENT")])
        self.owners([owner("a2222222222222222", "SILENT")], session=other)
        d = self.daemon()
        d.tick()
        (self.fake / f"owners-{other}.json").unlink()
        d.tick()
        self.assertEqual(self.alert_calls("clear"), [])

    def test_b1_unreadable_wal_root_clears_nothing(self):
        self.owners([owner("a1111111111111111", "SILENT")])
        d = self.daemon()
        d.tick()
        root = self.home / ".claude" / "wals"
        root.chmod(0)
        try:
            d.tick()
        finally:
            root.chmod(0o700)
        self.assertEqual(self.alert_calls("clear"), [])

    def ledger(self, text):
        led = self.home / ".agent-harness" / "work-assignments.json"
        led.parent.mkdir(parents=True, exist_ok=True)
        led.write_text(text)
        return led

    def test_b1_torn_ledger_or_failing_step_clears_no_ask(self):
        self.owners([])
        self.t = ahd.parse_ts("2027-01-15T10:00:00Z")
        self.ledger(json.dumps({"items": {"q1": {"id": "q1", "state": "open", "owner": "unassigned",
                                                 "description": "x", "created": "2027-01-15T07:00:00Z"}}}))
        d = self.daemon()
        d.tick()
        self.assertEqual(len(self.alert_calls("raise")), 1)
        self.ledger("{torn")
        d.tick()
        with mock.patch.object(ahd, "v1_asks", side_effect=RuntimeError("boom")):
            d.tick()
        self.assertEqual([a for a in self.alert_calls("clear") if "ask:q1" in " ".join(a)], [])

    def test_b2_type_and_ticket_naming_interview_never_reach_ah(self):
        self.owners([dict(owner("a1111111111111111", "DROPPED", typ="interview-coach", ticket="solvecapture#3"))])
        self.policy["goodqa_poster"] = True
        self.daemon().tick()
        blob = json.dumps(self.calls()).lower()
        self.assertNotIn("interview", blob)
        self.assertNotIn("solve", blob)
        self.assertEqual(len(self.alert_calls("raise")), 1)

    def test_b3_row_without_owner_field_never_raises(self):
        row = owner("a1111111111111111", "DROPPED")
        del row["owner"]
        self.owners([row])
        self.daemon().tick()
        self.assertEqual(self.alert_calls("raise"), [])

    def test_b4_cut_never_leaves_a_secret_fragment(self):
        for pad in range(180, 240, 3):
            jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0." + "s" * pad
            text = jwt + " sk-ant-api03-" + "F" * 40 + " tail"
            for limit in (60, 80):
                out = ahd_peek.scrub(text, limit)
                self.assertNotIn("sk-ant", out, (pad, limit))
                self.assertNotIn("FFFF", out, (pad, limit))

    def test_f1_fifo_and_dev_zero_never_hang_or_flood(self):
        self.main_wal.unlink()
        os.mkfifo(self.main_wal)
        os.utime(self.main_wal, (NOW - 60, NOW - 60))
        led = self.home / ".agent-harness" / "work-assignments.json"
        led.parent.mkdir(parents=True, exist_ok=True)
        big = self.home / "sparse.bin"  # never a real /dev/zero here: a regression must not be able to eat the host
        with open(big, "wb") as fh:
            fh.truncate(1 << 20)
        os.symlink(big, led)
        t0 = time.monotonic()
        s = self.daemon().tick()
        self.assertLess(time.monotonic() - t0, 10)
        self.assertEqual(s["sessions"], 0)
        self.assertIn("ask:ledger:error", self.daemon_last_desired(s))

    def daemon_last_desired(self, s):
        return ahd.ask_alerts(ahd.v1_asks(self.policy), self.policy, self.t)

    def test_f4_timeout_kills_the_whole_process_group(self):
        marker = self.home / "grandchild.pid"
        rc, _, _ = ahd.run_cmd(["/bin/sh", "-c", f"sleep 30 & echo $! > {marker}; wait"], 1.0)
        self.assertEqual(rc, 124)
        pid = int(marker.read_text())
        for _ in range(50):
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.05)
        else:
            self.fail("grandchild survived the timeout")

    def test_f6_report_runs_beside_the_service_and_writes_nothing(self):
        self.daemon()  # the service holds the lock
        self.owners([owner("a1111111111111111", "SILENT")])
        (self.home / ".claude" / "hooks").mkdir(parents=True)
        (self.home / ".claude" / "hooks" / "ah.py").write_text(FAKE_AH)
        p = subprocess.run([sys.executable, "-I", str(HOOKS / "ahd.py"), "report"], env=dict(os.environ),
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr)
        out = json.loads(p.stdout)
        self.assertEqual(len(out["silent"]), 1)
        self.assertEqual(self.alert_calls(), [])
        self.assertTrue(any(w.startswith("alert raise") or "alert raise" in w for w in out["would_write"]))


class MemoryBounds(Scratch):
    """The 76 GB incident: at 37fb2f8 v1_asks did p.read_bytes() on a ledger symlinked to /dev/zero. Worst case of a
    regression in these tests is the sparse file's 256 MiB, except the Linux-only child, which has an RLIMIT_AS."""

    def ledger_path(self):
        led = self.home / ".agent-harness" / "work-assignments.json"
        led.parent.mkdir(parents=True, exist_ok=True)
        return led

    def sparse(self, path, size=256 << 20):
        with open(path, "wb") as fh:
            fh.truncate(size)

    def test_oversized_ledger_allocates_under_the_bound(self):
        self.sparse(self.ledger_path())
        self.policy["ledger_max_bytes"] = 1 << 20
        tracemalloc.start()
        try:
            got = ahd.v1_asks(self.policy)
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        self.assertIn("error", got[0])
        self.assertLess(peak, 8 << 20)

    def test_ledger_symlink_is_refused_without_reading_it(self):
        small = self.home / "sparse.bin"
        self.sparse(small, 4 << 20)
        os.symlink(small, self.ledger_path())
        tracemalloc.start()
        try:
            got = ahd.v1_asks(self.policy)
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        self.assertIn("error", got[0])
        self.assertLess(peak, 1 << 20)

    def test_devices_are_rejected_at_open(self):
        with self.assertRaises(OSError):  # open + fstat only: nothing is read, so this is safe on any host
            ahd_peek.open_regular("/dev/zero")

    @unittest.skipUnless(sys.platform.startswith("linux"), "RLIMIT_AS is not enforced on macOS; proven on Linux")
    def test_real_dev_zero_ledger_under_rlimit(self):
        os.symlink("/dev/zero", self.ledger_path())
        code = ("import resource,sys,json;resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30));"
                f"sys.path.insert(0,{str(HOOKS)!r});import ahd;print(json.dumps(ahd.v1_asks(ahd.load_policy())))")
        p = subprocess.run([sys.executable, "-I", "-c", code], env=dict(os.environ), capture_output=True,
                           text=True, timeout=30)
        self.assertEqual(p.returncode, 0, p.stderr[-300:])
        self.assertIn("error", json.loads(p.stdout)[0])

    def test_no_unbounded_read_calls_in_the_daemon(self):
        for name in ("ahd.py", "ahd_peek.py"):
            src = (HOOKS / name).read_text()
            for bad in (".read_bytes(", ".read_text(", ".read()", ".readlines(", "communicate("):
                self.assertNotIn(bad, src, f"{name}: {bad}")

    def test_child_output_flood_is_cut_at_the_cap(self):
        flood = [sys.executable, "-I", "-c", "import os\nwhile True: os.write(1, b'x'*65536)"]
        t0 = time.monotonic()
        tracemalloc.start()
        try:
            rc, out, err = ahd.run_cmd(flood, 20, cap=1 << 20)
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        self.assertEqual((rc, out), (125, ""))
        self.assertLess(peak, 8 << 20)
        self.assertLess(time.monotonic() - t0, 15)

    def test_run_cmd_keeps_normal_output_stdin_and_rc(self):
        code = "import sys;d=sys.stdin.read();print(d.upper());sys.stderr.write('e');sys.exit(3)"
        self.assertEqual(ahd.run_cmd([sys.executable, "-I", "-c", code], 20, stdin="abc"), (3, "ABC\n", "e"))

    def test_memory_guard_exits_past_the_cap_and_stays_quiet_below(self):
        died = []
        stop = threading.Event()
        ahd.memory_guard(100, stop, period=0, die=died.append, peak=lambda: 101)
        self.assertEqual(died, [70])
        calls = []

        def low():
            calls.append(1)
            if len(calls) >= 3:
                stop.set()
            return 99

        ahd.memory_guard(100, stop, period=0, die=died.append, peak=low)
        self.assertEqual(died, [70])

    def blocked_tick(self, make_unsafe):
        self.owners([owner("a1111111111111111", "SILENT")])
        d = self.daemon()
        d.tick()
        self.policy["owners_wal_max_bytes"] = 1 << 20
        d.policy["owners_wal_max_bytes"] = 1 << 20
        make_unsafe(self.main_wal.parent / "agent-a2222222222222222.jsonl")
        d.tick()
        return d

    def test_oversized_task_wal_holds_alerts_and_says_so(self):
        def big(path):
            self.sparse(path, 2 << 20)
        d = self.blocked_tick(big)
        self.assertEqual(ahd.scan_sessions(self.policy, NOW)[0], [])
        self.assertEqual(self.alert_calls("clear"), [])  # the session's liveness alert stays up
        self.assertEqual(d.last["desired"][f"wal:unsafe:{SESSION[:8]}"]["severity"], "high")

    def test_symlinked_task_wal_is_never_handed_to_ah(self):
        def link(path):
            target = self.home / "sparse.bin"  # never real /dev/zero here: a regression must not eat the host
            self.sparse(target, 1024)
            os.symlink(target, path)
        d = self.blocked_tick(link)
        self.assertEqual(self.alert_calls("clear"), [])
        self.assertIn(f"wal:unsafe:{SESSION[:8]}", d.last["desired"])
        self.assertIn("not a regular file", d.last["desired"][f"wal:unsafe:{SESSION[:8]}"]["message"])

    def test_oversized_main_wal_is_not_handed_to_ah(self):
        self.sparse(self.main_wal, 2 << 20)
        os.utime(self.main_wal, (NOW - 60, NOW - 60))
        self.policy["owners_wal_max_bytes"] = 1 << 20
        self.assertEqual(ahd.active_sessions(self.policy, NOW), [])
