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
        clock = mock.patch.object(ah, "server_now", side_effect=lambda: iso(NOW))  # the writer clock, pinned in-process only
        clock.start()
        self.addCleanup(clock.stop)
        p.start()
        self.addCleanup(p.stop)
        for k in ("CLAUDE_CODE_CHILD_SESSION", "AH_AGENT_ID", "AGENT_ID"):  # the runner may itself be a sub-agent;
            os.environ.pop(k, None)  # patch.dict restores them. Tests act as main unless they set an identity.
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

    def test_unacknowledged_owner_handoff_alerts_only_after_one_hour(self):
        w = self.home / ".claude" / "wals" / SESSION
        jl(w / "agent-dropowner.jsonl", [{"at": iso(NOW), "event": "handoff", "note": "to main: result ready"}])
        jl(w / "main.jsonl", [{"at": iso(NOW), "event": "subagent_stop", "agent_id": "dropowner",
                              "agent_type": "task-owner"}])
        self.assertNotIn("dropowner", self.owners()["undisposed"])
        before = {r["agent_id"]: r for r in self.owners(now=NOW + ah.HANDOFF_ACK_S - 1)["owners"]}
        self.assertNotIn("handoff-unacked", before["dropowner"]["flags"])
        after = {r["agent_id"]: r for r in self.owners(now=NOW + ah.HANDOFF_ACK_S + 1)["owners"]}
        self.assertIn("handoff-unacked", after["dropowner"]["flags"])
        self.assertTrue(after["dropowner"]["decision_required"])

    def test_live_waiting_disposition_acknowledges_handoff_until_it_expires(self):
        w = self.home / ".claude" / "wals" / SESSION
        jl(w / "agent-dropowner.jsonl", [
            {"at": iso(NOW - ah.HANDOFF_ACK_S - 1), "event": "handoff", "note": "to main: blocked on an ask"}])
        before = {r["agent_id"]: r for r in self.owners()["owners"]}
        self.assertIn("handoff-unacked", before["dropowner"]["flags"])
        self.dispose("waiting", "disp-handoff-wait", until=iso(NOW + 3600), ref="wa5b00000001", ack_handoff=True)
        waiting = {r["agent_id"]: r for r in self.owners()["owners"]}
        self.assertNotIn("handoff-unacked", waiting["dropowner"]["flags"])
        self.assertFalse(waiting["dropowner"]["decision_required"])
        expired = {r["agent_id"]: r for r in self.owners(now=NOW + 3601)["owners"]}
        self.assertIn("handoff-unacked", expired["dropowner"]["flags"])
        self.assertTrue(expired["dropowner"]["decision_required"])

    def test_a_wait_without_ack_handoff_does_not_acknowledge(self):
        # #134 red-team P4: the owner records its own wait; the unacknowledged handoff must stay visible
        w = self.home / ".claude" / "wals" / SESSION
        jl(w / "agent-dropowner.jsonl", [
            {"at": iso(NOW - ah.HANDOFF_ACK_S - 1), "event": "handoff", "note": "to main: done-ish"}])
        with mock.patch.dict(os.environ, {"AH_AGENT_ID": "dropowner"}):
            self.dispose("waiting", "self-wait", until=iso(NOW + 3 * 86400), ref="wa5b00000001")
        later = {r["agent_id"]: r for r in self.owners(now=NOW + 3600)["owners"]}
        self.assertIn("handoff-unacked", later["dropowner"]["flags"])
        self.assertTrue(later["dropowner"]["decision_required"])

    def test_the_owner_cannot_ack_its_own_handoff(self):
        with mock.patch.dict(os.environ, {"AH_AGENT_ID": "dropowner"}):
            with self.assertRaises(ah.AhError) as caught:
                self.dispose("waiting", "self-ack", until=iso(NOW + 3600), ref="wa5b00000001", ack_handoff=True)
        self.assertEqual(caught.exception.code, "forbidden")

    def test_ack_handoff_needs_kind_waiting(self):
        with self.assertRaises(ah.AhError):
            self.dispose("resumed", "bad-ack", ack_handoff=True)

    def test_subagent_cannot_run_an_acknowledging_wait(self):
        for cmd in ("python3 ~/.claude/hooks/ah.py task dispose --agent x --kind waiting --ack-handoff --ref "
                    "wa5b00000004 --until 2026-11-09T00:00:00Z",
                    "ah task dispose --agent x --kind waiting --ack-hand --ref wa5b00000004 --until X"):
            out = dropped_gate.cmd_pretool({"agent_id": "sub", "tool_name": "Bash", "tool_input": {"command": cmd}})
            self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny", cmd)
        plain = "ah task dispose --agent x --kind waiting --ref wa5b00000004 --until X"
        self.assertEqual(dropped_gate.cmd_pretool({"agent_id": "sub", "tool_name": "Bash",
                                                   "tool_input": {"command": plain}}), {})

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
        w = self.home / ".claude" / "wals" / SESSION
        jl(w / "main.jsonl", [
            {"at": iso(NOW - 60), "event": "deploy", "id": "wde000000001", "note": "DEPLOYED app v1.2.0 for dropowner"},
            {"at": iso(NOW - 30), "event": "check", "id": "wlt000000001",
             "note": "REALLY_TESTED DG-LIVE-1: dropowner verified live on https://app.example: pass"}])
        self.dispose("closed", "disp-closed-ok", reason="verified dropowner's v1.2.0 deploy serves and passes live",
                     deployed="wde000000001", live_test="DG-LIVE-1")
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


class ReassignInheritsTargetWait(Base):
    """goodqa#14791 repeat defect (3x on 2026-11-06): a mission owner that pauses into a named wait is DROPPED to
    `ah owners`; items reassigned to it flipped back to DROPPED and blocked Stop. A reassignment must inherit the
    target's live disposition, bounded by that disposition's own expiry."""

    def add_target(self, name="waitowner"):
        w = self.home / ".claude" / "wals" / SESSION
        jl(w / "main.jsonl", [{"at": iso(NOW - 9000), "event": "subagent", "agent_id": name, "agent_type": "task-owner"},
                              {"at": iso(NOW - 200), "event": "subagent_stop", "agent_id": name, "agent_type": "task-owner"}])
        jl(w / ("agent-%s.jsonl" % name), [{"at": iso(NOW - 4000), "event": "intent", "note": "paused"}])

    def wait(self, agent, key, until, ref="wa5b00000001"):
        return ah.write(self.home, "task.dispose", {"agent": agent, "session": SESSION, "kind": "waiting", "at": iso(NOW),
                                                    "until": iso(until), "ref": ref}, SESSION, key)

    def test_reassigned_to_a_target_in_a_live_named_wait_holds(self):
        self.add_target()
        self.wait("waitowner", "key-tw-1-0000", NOW + 3600)
        self.dispose("reassigned", "key-tw-r1-0000", ref="waitowner")
        by = {r["agent_id"]: r for r in self.owners()["owners"]}
        self.assertEqual(by["waitowner"]["state"], "DROPPED")  # the target itself is excused only by its wait
        self.assertEqual(self.owners()["undisposed"], [])
        self.assertEqual(self.stop(), {})

    def test_inherited_wait_expires_with_the_targets_wait(self):
        self.add_target()
        self.wait("waitowner", "key-tw-2-0000", NOW + 3600)
        self.dispose("reassigned", "key-tw-r2-0000", ref="waitowner")
        later = NOW + 3601
        self.assertEqual(self.owners(now=later)["undisposed"], ["dropowner", "waitowner"])
        self.assertEqual(self.stop(now=later).get("decision"), "block")

    def test_reassigned_to_a_dropped_target_without_a_decision_still_blocks(self):
        self.add_target()
        self.dispose("reassigned", "key-tw-r3-0000", ref="waitowner")
        self.assertIn("dropowner", self.owners()["undisposed"])

    def test_reassignment_cycle_does_not_excuse_either_owner(self):
        self.add_target()
        self.dispose("reassigned", "key-tw-r4-0000", ref="waitowner")
        ah.write(self.home, "task.dispose", {"agent": "waitowner", "session": SESSION, "kind": "reassigned",
                                             "at": iso(NOW), "ref": "dropowner"}, SESSION, "key-tw-r4b-0000")
        self.assertEqual(self.owners()["undisposed"], ["dropowner", "waitowner"])

    def test_chain_through_a_reassigned_target_reaches_the_live_wait(self):
        self.add_target("waitowner")
        self.add_target("middle")
        self.wait("waitowner", "key-tw-5-0000", NOW + 3600)
        ah.write(self.home, "task.dispose", {"agent": "middle", "session": SESSION, "kind": "reassigned",
                                             "at": iso(NOW), "ref": "waitowner"}, SESSION, "key-tw-r5b-0000")
        self.dispose("reassigned", "key-tw-r5-0000", ref="middle")
        self.assertEqual(self.owners()["undisposed"], [])

    def add_done_target(self, name="doneowner"):
        """A target that stopped after a result note: `ah owners` shows it as done, not DROPPED."""
        w = self.home / ".claude" / "wals" / SESSION
        jl(w / "main.jsonl", [{"at": iso(NOW - 9000), "event": "subagent", "agent_id": name, "agent_type": "task-owner"},
                              {"at": iso(NOW - 200), "event": "subagent_stop", "agent_id": name, "agent_type": "task-owner"}])
        jl(w / ("agent-%s.jsonl" % name), [{"at": iso(NOW - 4000), "event": "result", "note": "slice done; waiting on goodqa#14883"}])

    def test_reassigned_to_a_done_target_in_a_live_named_wait_holds(self):
        """Main's repro 2026-11-06 (pet-leads-x -> a9830089): target state done + live waiting disposition."""
        self.add_done_target()
        self.wait("doneowner", "key-tw-6-0000", NOW + 3600, ref="GoodQA goodqa#14883")
        self.dispose("reassigned", "key-tw-r6-0000", ref="doneowner")
        by = {r["agent_id"]: r for r in self.owners()["owners"]}
        self.assertEqual(by["doneowner"]["state"], "done")  # the fixture really has the repro shape
        self.assertTrue(by["dropowner"]["disposition"]["live"])
        self.assertNotIn("dropowner", self.owners()["undisposed"])

    def test_reassigned_to_a_done_target_without_a_live_decision_still_blocks(self):
        self.add_done_target()
        self.dispose("reassigned", "key-tw-r7-0000", ref="doneowner")
        self.assertIn("dropowner", self.owners()["undisposed"])
        self.wait("doneowner", "key-tw-7-0000", NOW + 60, ref="GoodQA goodqa#14883")
        self.assertIn("dropowner", self.owners(now=NOW + 61)["undisposed"])  # the inherited wait expires with it

    def test_stale_resumed_on_a_done_target_does_not_cover(self):
        """PR #107 review F1: `resumed` stays live forever once later activity exists; a target that resumed, then
        finished, holds no wait and must not excuse work reassigned to it."""
        self.add_done_target()
        ah.write(self.home, "task.dispose", {"agent": "doneowner", "session": SESSION, "kind": "resumed",
                                             "at": iso(NOW - 5000)}, SESSION, "key-tw-8-0000")
        self.dispose("reassigned", "key-tw-r8-0000", ref="doneowner")
        by = {r["agent_id"]: r for r in self.owners()["owners"]}
        self.assertEqual(by["doneowner"]["state"], "done")
        self.assertIn("dropowner", self.owners()["undisposed"])

    def test_closed_done_target_does_not_cover_a_later_reassignment(self):
        """Was "covers by design" (PR #107). The PR review of 24a786c (F1) showed that a permanent disposition on the
        target excused any later reassignment with none of the dispose guard's checks; main decided such a reassignment
        is not covered (goodqa#14791)."""
        self.add_done_target()
        # The dispose guard: `closed` means deployed live and tested, both naming this owner (docs/ah-query-spec.md).
        w = self.home / ".claude" / "wals" / SESSION
        jl(w / "main.jsonl", [
            {"at": iso(NOW - 120), "event": "deploy", "id": "wd00000000a1",
             "note": "DEPLOYED goodqa-web 1a2b3c4d5e6f to production for doneowner"},
            {"at": iso(NOW - 60), "event": "check", "id": "wc00000000a2",
             "note": "REALLY_TESTED LIVE-DONE: doneowner checked live at https://app.goodqa.example/health: pass"}])
        ah.write(self.home, "task.dispose", {"agent": "doneowner", "session": SESSION, "kind": "closed",
                                             "at": iso(NOW), "deployed": "wd00000000a1", "live_test": "LIVE-DONE",
                                             "reason": "doneowner shipped slice one; health check on production passed"},
                 SESSION, "key-tw-9-0000")
        self.dispose("reassigned", "key-tw-r9-0000", ref="doneowner")
        undisposed = self.owners()["undisposed"]
        self.assertIn("dropowner", undisposed)
        self.assertNotIn("doneowner", undisposed)


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

    def test_pretool_metadata_rows_do_not_hide_pending_work(self):
        """Blind review Part 3 #8: wal.py writes a `pretool` row before every write tool, so the last row is rarely
        the owner's own note; the gate must look past lifecycle rows."""
        w = self.home / ".claude" / "wals" / SESSION
        jl(w / "agent-pretoolowner.jsonl", [{"at": iso(NOW - 60), "event": "intent", "note": "running the suite"},
                                            {"at": iso(NOW - 30), "event": "pretool", "tool": "Bash", "agent_id": "pretoolowner"}])
        with mock.patch.object(dropped_gate, "armed_waiter", return_value=False):
            self.assertEqual(self.sstop("pretoolowner").get("decision"), "block")
        jl(w / "agent-handedowner.jsonl", [{"at": iso(NOW - 60), "event": "handoff", "note": "to main"},
                                           {"at": iso(NOW - 30), "event": "pretool", "tool": "Bash"}])
        self.assertEqual(self.sstop("handedowner"), {})

    def test_handoff_or_named_wait_does_not_block(self):
        w = self.home / ".claude" / "wals" / SESSION
        jl(w / "main.jsonl", [{"at": iso(NOW - 600), "event": "subagent", "agent_id": "doneowner", "agent_type": "task-owner"},
                              {"at": iso(NOW - 600), "event": "subagent", "agent_id": "waitowner", "agent_type": "task-owner"}])
        jl(w / "agent-doneowner.jsonl", [{"at": iso(NOW - 30), "event": "handoff", "note": "handed to main: see PR"}])
        jl(w / "agent-waitowner.jsonl", [{"at": iso(NOW - 30), "event": "blocker", "note": "waiting on wa5b00000001"}])
        self.assertEqual(self.sstop("doneowner"), {})
        self.assertEqual(self.sstop("waitowner"), {})

    def test_immediate_handoff_and_result_have_no_pending_work_but_an_intent_does(self):
        w = self.home / ".claude" / "wals" / SESSION
        for event in ("handoff", "result"):
            agent = "immediate-" + event
            jl(w / ("agent-%s.jsonl" % agent), [
                {"at": iso(NOW - 20), "event": "intent", "note": "finishing the slice"},
                {"at": iso(NOW), "event": event, "note": "returned to main"},
                {"at": iso(NOW), "event": "pretool", "tool": "Bash"},
            ])
            with self.subTest(event=event):
                self.assertIsNone(dropped_gate.pending_work(self.home, SESSION, agent))
                self.assertEqual(self.sstop(agent), {})
        jl(w / "agent-immediate-intent.jsonl", [{"at": iso(NOW), "event": "intent", "note": "still running"}])
        self.assertIsNotNone(dropped_gate.pending_work(self.home, SESSION, "immediate-intent"))

    def test_armed_waiter_does_not_block(self):
        w = self.home / ".claude" / "wals" / SESSION
        jl(w / "agent-jobowner.jsonl", [{"at": iso(NOW - 30), "event": "intent", "note": "suite started under ah-run"}])
        with mock.patch.object(dropped_gate, "armed_waiter", return_value=True):
            self.assertEqual(self.sstop("jobowner"), {})
        with mock.patch.object(dropped_gate, "armed_waiter", return_value=False):
            self.assertEqual(self.sstop("jobowner").get("decision"), "block")


class RealWalRows(Base):
    """Blind pr review finding 1: build the fixture from the real wal.py and wal_note.py hooks, not hand-written rows."""

    def hook(self, event, payload):
        import subprocess
        env = dict(os.environ, HOME=str(self.home), AH_HOME=str(self.home))
        p = subprocess.run([sys.executable, str(HOOKS / "wal.py"), event], input=json.dumps(payload), capture_output=True,
                           text=True, env=env, timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr[-400:])

    def note(self, agent, event, text):
        import subprocess
        env = dict(os.environ, HOME=str(self.home), AH_HOME=str(self.home))
        wal = self.home / ".claude" / "wals" / SESSION / f"agent-{agent}.jsonl"
        p = subprocess.run([sys.executable, str(HOOKS / "wal_note.py"), "--wal", str(wal), "--event", event, "--note", text],
                           capture_output=True, text=True, env=env, timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr[-400:])

    def test_real_hook_rows_still_show_pending_work(self):
        agent = "a0real000000001"
        self.hook("subagent", {"session_id": SESSION, "agent_id": agent, "agent_type": "task-owner"})
        self.hook("pretool", {"session_id": SESSION, "agent_id": agent, "tool_name": "Bash", "tool_use_id": "t1",
                              "tool_input": {"command": "ls"}})
        self.note(agent, "intent", "running the dev2 suite for goodqa#14791")
        self.hook("pretool", {"session_id": SESSION, "agent_id": agent, "tool_name": "Edit", "tool_use_id": "t2",
                              "tool_input": {"file_path": "/tmp/x"}})
        with mock.patch.object(dropped_gate, "armed_waiter", return_value=False):
            first = dropped_gate.cmd_subagent_stop({"session_id": SESSION, "agent_id": agent, "stop_hook_active": False})
            self.assertEqual(first.get("decision"), "block", first)
            second = dropped_gate.cmd_subagent_stop({"session_id": SESSION, "agent_id": agent, "stop_hook_active": True})
            self.assertIn("DROPPED", second.get("systemMessage", ""))
        self.hook("subagent_stop", {"session_id": SESSION, "agent_id": agent, "agent_type": "task-owner"})
        # finding 2: wal.py stamps microseconds and the stop is seconds later; zero grace must still apply
        by = {r["agent_id"]: r for r in ah.owners(self.home, SESSION, now=time.time() + 5)["owners"]}
        self.assertEqual(by[agent]["state"], "DROPPED")
        self.assertTrue(by[agent]["decision_required"])

    def test_real_handoff_row_passes(self):
        agent = "a0real000000002"
        self.hook("subagent", {"session_id": SESSION, "agent_id": agent, "agent_type": "task-owner"})
        self.note(agent, "handoff", "handed to main: PR opened")
        self.hook("pretool", {"session_id": SESSION, "agent_id": agent, "tool_name": "Bash", "tool_use_id": "t3",
                              "tool_input": {"command": "git status"}})
        self.assertEqual(dropped_gate.cmd_subagent_stop({"session_id": SESSION, "agent_id": agent}), {})

    def test_armed_waiter_reads_the_ah_run_ledger_directory(self):
        """Finding 3: a live ah-run row (agent attributed, no end) is an armed waiter; a finished one is not."""
        ledger = self.home / ".agent-harness" / "reserve" / "ledger"
        ledger.mkdir(parents=True)
        (ledger / "run1.json").write_text(json.dumps({"run_id": "run1", "agent": "jobowner", "task": "t", "start": "x"}))
        self.assertTrue(dropped_gate.armed_waiter("jobowner", self.home))
        (ledger / "run1.json").write_text(json.dumps({"run_id": "run1", "agent": "jobowner", "task": "t", "end": "y", "exit_code": 0}))
        self.assertFalse(dropped_gate.armed_waiter("jobowner", self.home))
        self.assertFalse(dropped_gate.armed_waiter("nobody", self.home))


class TaskWalOwners(Base):
    """I8: task-named WALs are owners in the same view, with the same gate."""

    def test_abandoned_task_wal_is_dropped_and_gated(self):
        w = self.home / ".claude" / "wals" / SESSION
        jl(w / "fable-review.jsonl", [{"at": iso(NOW - 7 * 3600), "event": "intent", "note": "review GoodQA goodqa#14791"}])
        jl(w / "finished-task.jsonl", [{"at": iso(NOW - 8 * 3600), "event": "intent", "note": "x"},
                                       {"at": iso(NOW - 7 * 3600), "event": "status", "note": "WORKDIR_DONE: shipped"},
                                       {"at": iso(NOW - 7 * 3600), "event": "result", "note": "done"}])
        jl(w / "quiet-task.jsonl", [{"at": iso(NOW - 90 * 60), "event": "intent", "note": "still mine"}])
        for name, age in (("fable-review", 7 * 3600), ("finished-task", 7 * 3600), ("quiet-task", 90 * 60)):
            os.utime(w / f"{name}.jsonl", (NOW - age, NOW - age))  # inside the 48 h task-WAL window on the fixture clock
        jl(w / "ancient-task.jsonl", [{"at": iso(NOW - 5 * 86400), "event": "intent", "note": "history"}])
        os.utime(w / "ancient-task.jsonl", (NOW - 5 * 86400, NOW - 5 * 86400))
        data = self.owners()
        self.assertNotIn("ancient-task", [r["agent_id"] for r in data["owners"]])  # outside the window: history, not an owner
        by = {r["agent_id"]: r for r in data["owners"]}
        self.assertEqual(by["fable-review"]["state"], "DROPPED")
        self.assertEqual(by["fable-review"]["type"], "task-wal")
        self.assertEqual(by["finished-task"]["state"], "done")
        self.assertEqual(by["quiet-task"]["state"], "SILENT-HIGH")
        self.assertEqual(data["undisposed"], ["dropowner", "fable-review"])
        self.dispose_task("fable-review")
        self.assertEqual(self.owners()["undisposed"], ["dropowner"])

    def test_waiting_on_a_dropped_agent_needs_a_decision(self):
        """Part 3 #7: `waiting on <agent id>` must not park an owner once that agent is itself DROPPED."""
        w = self.home / ".claude" / "wals" / SESSION
        jl(w / "main.jsonl", [{"at": iso(NOW - 9000), "event": "subagent", "agent_id": "aabb11223344", "agent_type": "task-owner"},
                              {"at": iso(NOW - 100), "event": "subagent_stop", "agent_id": "aabb11223344", "agent_type": "task-owner"},
                              {"at": iso(NOW - 9000), "event": "subagent", "agent_id": "waiter01", "agent_type": "task-owner"},
                              {"at": iso(NOW - 100), "event": "subagent_stop", "agent_id": "waiter01", "agent_type": "task-owner"}])
        jl(w / "agent-aabb11223344.jsonl", [{"at": iso(NOW - 4000), "event": "intent", "note": "target work"}])
        jl(w / "agent-waiter01.jsonl", [{"at": iso(NOW - 4000), "event": "blocker", "note": "waiting on aabb11223344"}])
        by = {r["agent_id"]: r for r in self.owners()["owners"]}
        self.assertEqual(by["aabb11223344"]["state"], "DROPPED")
        self.assertEqual(by["waiter01"]["state"], "waiting-on-aabb11223344")
        self.assertTrue(by["waiter01"]["decision_required"])  # its target is DROPPED
        jl(w / "agent-aabb11223344.jsonl", [{"at": iso(NOW - 5), "event": "intent", "note": "back"}])
        by = {r["agent_id"]: r for r in self.owners()["owners"]}
        self.assertFalse(by["waiter01"]["decision_required"])  # target live again: the wait holds

    def test_ahd_alerts_cover_task_wal_and_auto_owner_ids(self):
        """Part 3 #3: ahd.liveness_alerts skipped ids outside ^a[0-9a-f]{6,32}$, so task WALs raised nothing."""
        import ahd
        doc = {"owners": [{"agent_id": "fable-review", "state": "DROPPED", "owner": True, "idle_s": 30000, "type": "task-wal"},
                          {"agent_id": "auto-9f2c1a", "state": "SILENT-HIGH", "owner": True, "idle_s": 4000, "type": "headless-owner"}]}
        out = ahd.liveness_alerts({SESSION: doc}, ahd.load_policy())
        self.assertIn(f"liveness:{SESSION[:8]}/agent-fable-review", out)
        self.assertIn(f"liveness:{SESSION[:8]}/agent-auto-9f2c1a", out)

    def dispose_task(self, name):
        with mock.patch.object(ah, "_ticket_exists", return_value=True):
            return ah.write(self.home, "task.dispose", {"agent": name, "session": SESSION, "kind": "superseded", "at": iso(NOW),
                                                        "reason": f"the {name} review moved to the delta reviewer agent",
                                                        "ref": "GoodQA goodqa#14791"}, SESSION, "disp-task-" + name)

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
        with mock.patch.object(ah, "_ticket_exists", return_value=True):
            ah.write(self.home, "task.dispose", {"agent": "realdrop", "session": sess, "kind": "wontdo", "at": iso(real),
                                                 "reason": "the scan fixture owner exists only to exercise the wrapper",
                                                 "ref": "GoodQA goodqa#14791"}, sess, "disp-realdrop-01")
        p = subprocess.run([sys.executable, "-I", str(scan), "--session", sess, "--text"], capture_output=True, text=True, env=env, timeout=120)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("gate clear", p.stdout)
        self.assertNotIn("0 dropped", p.stdout)


if __name__ == "__main__":
    unittest.main()
