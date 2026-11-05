"""ahd: the loop writes only through `ah` (a fake CLI records argv), deterministic keys, restart idempotency,
single instance, malformed/torn/rotated inputs, clock jump hold, full disk (writer refuses) and the tick budget.
Stdlib only; every test runs in a scratch HOME; no network, no real transcripts."""
import json
import os
import subprocess
import sys
import tempfile
import time
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


def owner(agent, state, idle=1900, typ="task-owner", task="build the thing", ticket=None):
    return {"agent_id": agent, "type": typ, "task": task, "state": state,
            "severity": {"SILENT": "warning", "SILENT-HIGH": "high", "DROPPED": "high"}.get(state, "info"),
            "idle_s": idle, "ticket": ticket}


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
        self.owners([owner("a1111111111111111", "SILENT")])
        d.tick()
        keys = [a[a.index("--key") + 1] for a in self.alert_calls("raise")]
        self.assertEqual(len(keys), 2)
        self.assertNotEqual(keys[0], keys[1])


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
        self.assertEqual(self.alert_calls("raise"), [])  # already active: the torn tail did not hide it

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
    def test_clock_jump_holds_liveness_raises_for_two_ticks(self):
        self.owners([])
        d = self.daemon()
        d.tick()
        self.t -= 3600  # wall clock jumps back an hour; monotonic does not
        self.owners([owner("a1111111111111111", "SILENT")])
        s = d.tick()
        self.assertIn("clock_jump", s)
        self.assertEqual(self.alert_calls("raise"), [])
        d.tick()
        self.assertEqual(self.alert_calls("raise"), [])
        d.tick()
        self.assertEqual(len(self.alert_calls("raise")), 1)

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
