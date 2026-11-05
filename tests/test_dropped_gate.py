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


if __name__ == "__main__":
    unittest.main()
