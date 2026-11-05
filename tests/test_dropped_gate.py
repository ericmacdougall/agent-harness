"""Dropped-owner gate (GoodQA goodqa#14791, NEVER-LOSE.md invariant I1).

Evidence: main WAL baab765b 2026-11-05 21:10Z, `ah owners` listed 12 DROPPED owners and the scan line said
"0 dropped" (WN/ahd/user-evidence/transcript-2105-to-now.md:141-190). These tests fail against main 247c104:
`ah owners` has no disposition or gate, and no Stop hook blocks on an undisposed DROPPED owner.
"""
import io
import json
import os
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import ah  # noqa: E402
import liveness  # noqa: E402
import dropped_gate  # noqa: E402

NOW = 1_800_000_000.0
SESSION = "sess-gate-0001"


def iso(ts):
    return time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(ts))


def jl(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a") as fh:
        for r in rows:
            fh.write((r if isinstance(r, str) else json.dumps(r)) + "\n")


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)
        p = mock.patch.dict(os.environ, {"AH_HOME": str(self.home), "HOME": str(self.home)})
        p.start()
        self.addCleanup(p.stop)
        w = self.home / ".claude" / "wals" / SESSION
        jl(w / "main.jsonl", [
            {"at": iso(NOW - 9000), "event": "subagent", "agent_id": "dropowner", "agent_type": "task-owner"},
            {"at": iso(NOW - 9000), "event": "subagent", "agent_id": "aliveowner", "agent_type": "task-owner"},
            {"at": iso(NOW - 100), "event": "subagent_stop", "agent_id": "dropowner", "agent_type": "task-owner"},
            {"at": iso(NOW - 8000), "event": "ask", "id": "wa5b00000001", "note": "need the key",
             "source": "user:x/y \"words\""},
        ])
        jl(w / "agent-dropowner.jsonl", [{"at": iso(NOW - 4000), "event": "intent", "note": "working GoodQA goodqa#14791"}])
        jl(w / "agent-aliveowner.jsonl", [{"at": iso(NOW - 30), "event": "intent", "note": "alive"}])

    def owners(self, now=NOW):
        return ah.owners(self.home, SESSION, now=now)

    def dispose(self, kind, key, now=NOW, **extra):
        args = {"agent": "dropowner", "session": SESSION, "kind": kind, "at": iso(now)}
        args.update(extra)
        return ah.write(self.home, "task.dispose", args, SESSION, key)

    def stop(self, now=NOW):
        payload = {"session_id": SESSION, "hook_event_name": "Stop", "stop_hook_active": False}
        return dropped_gate.cmd_stop(payload, now=now)


class ReviewFixes(Base):
    def test_a_status_written_by_main_does_not_undrop_the_owner(self):
        """Review H2: `ah task status` appended to the owner WAL by another actor used to flip is_stopped."""
        jl(self.home / ".claude" / "wals" / SESSION / "agent-dropowner.jsonl",
           [{"at": iso(NOW - 5), "event": "status", "id": "wa5b000000ff", "by": "main", "note": "[review] main poked it"}])
        by = {r["agent_id"]: r for r in self.owners()["owners"]}
        self.assertEqual(by["dropowner"]["state"], "DROPPED")
        jl(self.home / ".claude" / "wals" / SESSION / "agent-dropowner.jsonl",
           [{"at": iso(NOW - 4), "event": "intent", "note": "owner itself is back"}])
        by = {r["agent_id"]: r for r in self.owners()["owners"]}
        self.assertNotEqual(by["dropowner"]["state"], "DROPPED")

    def test_waiting_on_anything_is_not_a_wait(self):
        """Review H3: a note saying "waiting on vibes" parked an owner forever."""
        self.assertIsNone(liveness.waiting_on("waiting on vibes"))
        self.assertIsNone(liveness.waiting_on("waiting for the user"))
        self.assertEqual(liveness.waiting_on("waiting on wa5b00000001"), "wa5b00000001")
        self.assertEqual(liveness.waiting_on("blocked, waiting on GoodQA goodqa#14791"), "GoodQA goodqa#14791")
        self.assertEqual(liveness.waiting_on("waiting for a0e07708172d8b693"), "a0e07708172d8b693")

    def test_headless_sessions_are_not_gated(self):
        with mock.patch.dict(os.environ, {"CLAUDE_CODE_ENTRYPOINT": "sdk-cli"}):
            self.assertEqual(self.stop(), {})


class DispositionRule(unittest.TestCase):
    def test_pure_rule(self):
        self.assertFalse(liveness.disposition_live(None, NOW))
        self.assertTrue(liveness.disposition_live({"kind": "closed", "at": NOW - 99999}, NOW))
        self.assertTrue(liveness.disposition_live({"kind": "waiting", "at": NOW - 10, "until": NOW + 60}, NOW))
        self.assertFalse(liveness.disposition_live({"kind": "waiting", "at": NOW - 10, "until": NOW - 1}, NOW))
        self.assertTrue(liveness.disposition_live({"kind": "resumed", "at": NOW - 60}, NOW))
        self.assertFalse(liveness.disposition_live({"kind": "resumed", "at": NOW - 7200}, NOW, last_activity=NOW - 9000))
        self.assertTrue(liveness.disposition_live({"kind": "resumed", "at": NOW - 7200}, NOW, last_activity=NOW - 60))
        self.assertTrue(liveness.disposition_live({"kind": "reassigned", "at": NOW}, NOW, replacement_live=True))
        self.assertFalse(liveness.disposition_live({"kind": "reassigned", "at": NOW}, NOW, replacement_live=False))


class GateTests(Base):
    def test_dropped_owner_requires_a_decision(self):
        by = {r["agent_id"]: r for r in self.owners()["owners"]}
        self.assertEqual(by["dropowner"]["state"], "DROPPED")
        self.assertTrue(by["dropowner"]["decision_required"])
        self.assertFalse(by["aliveowner"]["decision_required"])
        self.assertEqual(self.owners()["undisposed"], ["dropowner"])

    def test_gate_exit_code_never_prints_zero_dropped(self):
        buf = io.StringIO()
        with redirect_stdout(buf), mock.patch.object(ah.time, "time", return_value=NOW):
            rc = ah.main(["owners", "--session", SESSION, "--gate"])
        self.assertEqual(rc, 1)
        self.assertIn("dropowner", buf.getvalue())
        self.assertNotIn("0 dropped", buf.getvalue())

    def test_stop_blocks_and_names_the_owner_with_the_dispose_line(self):
        out = self.stop()
        self.assertEqual(out.get("decision"), "block")
        self.assertIn("dropowner", out["reason"])
        self.assertIn("ah task dispose", out["reason"])

    def test_resumed_clears_then_expires_without_activity(self):
        self.dispose("resumed", "disp-resumed-0001")
        self.assertEqual(self.stop(), {})
        self.assertEqual(self.owners()["undisposed"], [])
        later = NOW + liveness.RESUMED_GRACE_S + 60  # no activity followed the "resumed": it re-blocks
        self.assertEqual(self.owners(now=later)["undisposed"], ["dropowner"])
        self.assertEqual(self.stop(now=later).get("decision"), "block")

    def test_waiting_needs_a_ref_and_expires(self):
        with self.assertRaises(ah.AhError) as cm:
            self.dispose("waiting", "disp-wait-noref", until=iso(NOW + 3600))
        self.assertEqual(cm.exception.code, "bad_request")
        with self.assertRaises(ah.AhError):
            self.dispose("waiting", "disp-wait-badref", until=iso(NOW + 3600), ref="my own excuse")
        with self.assertRaises(ah.AhError):  # the ask id must exist in this session's WAL
            self.dispose("waiting", "disp-wait-noask", until=iso(NOW + 3600), ref="wa5b00000009")
        self.dispose("waiting", "disp-wait-ok", until=iso(NOW + 3600), ref="wa5b00000001")
        self.assertEqual(self.stop(), {})
        self.assertEqual(self.stop(now=NOW + 3601).get("decision"), "block")  # expired: blocks again

    def test_closed_needs_reason_and_evidence_and_is_permanent(self):
        with self.assertRaises(ah.AhError):
            self.dispose("closed", "disp-closed-bad", reason="done enough")
        self.dispose("closed", "disp-closed-ok", reason="superseded by #14800", evidence="GoodQA goodqa#14800")
        self.assertEqual(self.stop(now=NOW + 10 * 86400), {})

    def test_reassigned_is_live_only_while_the_replacement_is(self):
        self.dispose("reassigned", "disp-reassign-ok", ref="aliveowner")
        self.assertEqual(self.stop(), {})
        with self.assertRaises(ah.AhError):
            self.dispose("reassigned", "disp-reassign-unknown", ref="nobody0001")

    def test_block_count_is_bounded_per_signature(self):
        blocks = sum(1 for _ in range(6) if self.stop().get("decision") == "block")
        self.assertEqual(blocks, dropped_gate.MAX_STOP_BLOCKS)
        out = self.stop()
        self.assertNotEqual(out.get("decision"), "block")
        self.assertIn("dropowner", out.get("systemMessage", ""))  # still named, never silent
        # a new signature (another owner dropped) gets its own bound
        w = self.home / ".claude" / "wals" / SESSION
        jl(w / "main.jsonl", [{"at": iso(NOW - 9000), "event": "subagent", "agent_id": "dropowner2", "agent_type": "task-owner"},
                              {"at": iso(NOW - 100), "event": "subagent_stop", "agent_id": "dropowner2", "agent_type": "task-owner"}])
        jl(w / "agent-dropowner2.jsonl", [{"at": iso(NOW - 4000), "event": "intent", "note": "second"}])
        self.assertEqual(self.stop().get("decision"), "block")

    def test_stop_hook_active_passes_through_with_a_message(self):
        payload = {"session_id": SESSION, "hook_event_name": "Stop", "stop_hook_active": True}
        out = dropped_gate.cmd_stop(payload, now=NOW)
        self.assertNotEqual(out.get("decision"), "block")
        self.assertIn("dropowner", out.get("systemMessage", ""))


class SubagentStopGate(Base):
    """I7: a sub-agent cannot end its turn with pending work and no armed waiter (desktop release owner, 2026-11-05)."""

    def sstop(self, agent, active=False, now=NOW):
        payload = {"session_id": SESSION, "hook_event_name": "SubagentStop", "agent_id": agent, "stop_hook_active": active}
        return dropped_gate.cmd_subagent_stop(payload, now=now)

    def test_pending_intent_blocks_once_then_marks_dropped_without_grace(self):
        w = self.home / ".claude" / "wals" / SESSION
        jl(w / "main.jsonl", [{"at": iso(NOW - 600), "event": "subagent", "agent_id": "pendingowner", "agent_type": "task-owner"}])
        jl(w / "agent-pendingowner.jsonl", [{"at": iso(NOW - 30), "event": "intent", "note": "running the dev2 suite"}])
        first = self.sstop("pendingowner")
        self.assertEqual(first.get("decision"), "block")
        self.assertIn("pending work", first["reason"])
        second = self.sstop("pendingowner", active=True)
        self.assertNotEqual(second.get("decision"), "block")
        self.assertIn("DROPPED", second.get("systemMessage", ""))
        # the stop arrives in main.jsonl; the owner is DROPPED at once, not "finishing" for 30 min
        jl(w / "main.jsonl", [{"at": iso(NOW), "event": "subagent_stop", "agent_id": "pendingowner", "agent_type": "task-owner"}])
        by = {r["agent_id"]: r for r in self.owners(now=NOW + 5)["owners"]}
        self.assertEqual(by["pendingowner"]["state"], "DROPPED")
        self.assertTrue(by["pendingowner"]["decision_required"])

    def test_handoff_or_named_wait_does_not_block(self):
        w = self.home / ".claude" / "wals" / SESSION
        jl(w / "main.jsonl", [{"at": iso(NOW - 600), "event": "subagent", "agent_id": "doneowner", "agent_type": "task-owner"},
                              {"at": iso(NOW - 600), "event": "subagent", "agent_id": "waitowner", "agent_type": "task-owner"}])
        jl(w / "agent-doneowner.jsonl", [{"at": iso(NOW - 30), "event": "handoff", "note": "handed to main: see PR"}])
        jl(w / "agent-waitowner.jsonl", [{"at": iso(NOW - 30), "event": "blocker", "note": "waiting on wa5b00000001"}])
        self.assertEqual(self.sstop("doneowner"), {})
        self.assertEqual(self.sstop("waitowner"), {})

    def test_armed_waiter_does_not_block(self):
        w = self.home / ".claude" / "wals" / SESSION
        jl(w / "agent-jobowner.jsonl", [{"at": iso(NOW - 30), "event": "intent", "note": "suite started under ah-run"}])
        with mock.patch.object(dropped_gate, "armed_waiter", return_value=True):
            self.assertEqual(self.sstop("jobowner"), {})
        with mock.patch.object(dropped_gate, "armed_waiter", return_value=False):
            self.assertEqual(self.sstop("jobowner").get("decision"), "block")


class TaskWalOwners(Base):
    """I8: task-named WALs are owners in the same view, with the same gate."""

    def test_abandoned_task_wal_is_dropped_and_gated(self):
        w = self.home / ".claude" / "wals" / SESSION
        jl(w / "fable-review.jsonl", [{"at": iso(NOW - 7 * 3600), "event": "intent", "note": "review GoodQA goodqa#14791"}])
        jl(w / "finished-task.jsonl", [{"at": iso(NOW - 8 * 3600), "event": "intent", "note": "x"},
                                       {"at": iso(NOW - 7 * 3600), "event": "status", "note": "WORKDIR_DONE: shipped"},
                                       {"at": iso(NOW - 7 * 3600), "event": "result", "note": "done"}])
        jl(w / "quiet-task.jsonl", [{"at": iso(NOW - 90 * 60), "event": "intent", "note": "still mine"}])
        data = self.owners()
        by = {r["agent_id"]: r for r in data["owners"]}
        self.assertEqual(by["fable-review"]["state"], "DROPPED")
        self.assertEqual(by["fable-review"]["type"], "task-wal")
        self.assertEqual(by["finished-task"]["state"], "done")
        self.assertEqual(by["quiet-task"]["state"], "SILENT-HIGH")
        self.assertEqual(data["undisposed"], ["dropowner", "fable-review"])
        self.dispose_task("fable-review")
        self.assertEqual(self.owners()["undisposed"], ["dropowner"])

    def dispose_task(self, name):
        return ah.write(self.home, "task.dispose", {"agent": name, "session": SESSION, "kind": "closed", "at": iso(NOW),
                                                    "reason": "review delivered elsewhere", "evidence": "GoodQA goodqa#14791"},
                        SESSION, "disp-task-" + name)

    def test_scan_wrapper_exit_code_follows_the_gate(self):
        """The wrapper runs `ah owners --gate` in a subprocess on the real clock, so this fixture uses real time."""
        import subprocess
        scan = Path(__file__).resolve().parents[1] / "harness" / "skills" / "check-dropped-workstreams" / "scan.py"
        real = time.time()
        sess = "sess-scan-real01"
        w = self.home / ".claude" / "wals" / sess
        jl(w / "main.jsonl", [{"at": iso(real - 9000), "event": "subagent", "agent_id": "realdrop", "agent_type": "task-owner"},
                              {"at": iso(real - 3700), "event": "subagent_stop", "agent_id": "realdrop", "agent_type": "task-owner"}])
        jl(w / "agent-realdrop.jsonl", [{"at": iso(real - 7200), "event": "intent", "note": "work"}])
        os.utime(w / "agent-realdrop.jsonl", (real - 7200, real - 7200))
        env = dict(os.environ, AH_HOME=str(self.home), HOME=str(self.home))
        p = subprocess.run([sys.executable, "-I", str(scan), "--session", sess], capture_output=True, text=True, env=env, timeout=120)
        self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
        doc = json.loads(p.stdout)
        self.assertEqual([u["agent"] for u in doc["sessions"][0]["undisposed"]], ["realdrop"])
        ah.write(self.home, "task.dispose", {"agent": "realdrop", "session": sess, "kind": "closed", "at": iso(real),
                                             "reason": "superseded in test", "evidence": "GoodQA goodqa#14791"}, sess, "disp-realdrop-01")
        p = subprocess.run([sys.executable, "-I", str(scan), "--session", sess, "--text"], capture_output=True, text=True, env=env, timeout=120)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("gate clear", p.stdout)
        self.assertNotIn("0 dropped", p.stdout)


if __name__ == "__main__":
    unittest.main()
