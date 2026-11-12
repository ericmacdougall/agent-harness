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

    def _helper_of(self, parent, parent_last):
        """dropowner becomes a helper spawned by `parent`, handing off at NOW; `parent` was last active at parent_last."""
        w = self.home / ".claude" / "wals" / SESSION
        jl(w / "agent-dropowner.jsonl", [{"at": iso(NOW), "event": "handoff", "note": "to my parent: result ready"}])
        jl(w / "main.jsonl", [{"at": iso(NOW), "event": "subagent_stop", "agent_id": "dropowner",
                              "agent_type": "task-owner"}])
        jl(w / f"agent-{parent}.jsonl", [{"at": iso(parent_last), "event": "intent", "note": "still working"}])
        meta = self.home / ".claude" / "projects" / "proj" / SESSION / "subagents" / "agent-dropowner.meta.json"
        meta.parent.mkdir(parents=True, exist_ok=True)
        meta.write_text(json.dumps({"agentType": "task-owner", "parentAgentId": parent, "finished": True, "spawnDepth": 2}))

    def test_handoff_to_a_live_parent_is_acknowledged(self):
        later = NOW + ah.HANDOFF_ACK_S + 1
        self._helper_of("aliveowner", parent_last=later - 30)
        by = {r["agent_id"]: r for r in self.owners(now=later)["owners"]}
        self.assertNotIn("handoff-unacked", by["dropowner"]["flags"])
        self.assertIn("handoff-to-parent", by["dropowner"]["flags"])
        self.assertFalse(by["dropowner"]["decision_required"])

    def test_handoff_to_a_dropped_parent_still_needs_a_decision(self):
        later = NOW + ah.HANDOFF_ACK_S + 1
        self._helper_of("aliveowner", parent_last=NOW - 40000)  # parent long silent: it no longer holds the work
        by = {r["agent_id"]: r for r in self.owners(now=later)["owners"]}
        self.assertNotEqual(by["aliveowner"]["state"], "live")
        self.assertIn("handoff-unacked", by["dropowner"]["flags"])
        self.assertTrue(by["dropowner"]["decision_required"])

    def test_live_waiting_disposition_acknowledges_handoff_until_it_expires(self):
        w = self.home / ".claude" / "wals" / SESSION
        jl(w / "agent-dropowner.jsonl", [
            {"at": iso(NOW - ah.HANDOFF_ACK_S - 1), "event": "handoff", "note": "to main: blocked on an ask"}])
        before = {r["agent_id"]: r for r in self.owners()["owners"]}
        self.assertIn("handoff-unacked", before["dropowner"]["flags"])
        import caller_identity
        caller_identity.put_stamp("ack-handoff", ["dropowner"], home=self.home)  # what main's hook writes
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

    def test_ack_handoff_without_mains_stamp_is_refused(self):
        # #134 red-team B4: AH_AGENT_ID is never set, so a copied script or Codex owner could ack itself
        with self.assertRaises(ah.AhError) as caught:
            self.dispose("waiting", "nostamp-ack", until=iso(NOW + 3600), ref="wa5b00000005", ack_handoff=True)
        self.assertEqual(caught.exception.code, "forbidden")
        self.assertIn("only the main agent", str(caught.exception))

    def test_only_proven_main_is_stamped_and_codex_payloads_are_denied(self):
        import caller_identity
        sid = "11111111-2222-3333-4444-555555555555"
        transcript = self.home / ".claude" / "projects" / "-x" / (sid + ".jsonl")
        transcript.parent.mkdir(parents=True, exist_ok=True)
        transcript.write_text("{}\n")
        cmd = ("python3 ~/.claude/hooks/ah.py task dispose --agent owner-7 --kind waiting --ack-handoff --ref "
               "wa5b00000006 --until 2026-11-09T00:00:00Z")
        codex = {"tool_name": "Bash", "tool_input": {"command": cmd}, "session_id": sid}
        out = dropped_gate.cmd_pretool(codex)
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertIsNone(caller_identity.take_stamp("ack-handoff", ["owner-7"], home=self.home))
        main = dict(codex, transcript_path=str(transcript))
        self.assertEqual(dropped_gate.cmd_pretool(main), {})
        self.assertIsNotNone(caller_identity.take_stamp("ack-handoff", ["owner-7"], home=self.home))

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
        # goodqa#15754: ten days on, the fixture's other owner (aliveowner) is SILENT with no disposition and needs a
        # decision of its own; the closed owner never comes back
        self.assertNotIn("dropowner", self.stop(now=NOW + 10 * 86400).get("reason", ""))
        self.assertEqual(self.stop(now=NOW + 3600), {})

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


class PendingStopNoise(Base):
    """GoodQA #15565: one pending_stop WAL line per stop episode, not one per stop (1,130 in one session)."""

    def pending(self, key, at):
        return ah.write(self.home, "task.pending", {"agent": "dropowner", "session": SESSION, "at": iso(at)}, SESSION, key)

    def markers(self):
        path = self.home / ".claude" / "wals" / SESSION / "agent-dropowner.jsonl"
        return [json.loads(x) for x in path.read_text().splitlines() if '"pending_stop"' in x]

    def test_repeated_stops_write_one_marker_until_the_owner_acts_again(self):
        for n in range(5):
            self.pending("pend-key-%02d-0000" % n, NOW + n * 700)
        self.assertEqual(len(self.markers()), 1)
        self.assertEqual(ah.pending_stops(self.home, SESSION).get("dropowner"), NOW)  # the ledger row liveness reads is still written
        jl(self.home / ".claude" / "wals" / SESSION / "agent-dropowner.jsonl",
           [{"at": iso(NOW + 4000), "event": "intent", "note": "back at work"}])
        self.pending("pend-key-09-0000", NOW + 5000)
        self.pending("pend-key-10-0000", NOW + 5700)
        self.assertEqual(len(self.markers()), 2)  # a new episode after real activity


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

    def test_the_block_message_names_only_commands_that_exist(self):
        # goodqa#15253: the message told agents to "arm a waiter with `ah job wait`", and ah has no job command
        import re as _re
        import shlex as _shlex
        w = self.home / ".claude" / "wals" / SESSION
        jl(w / "agent-msgowner.jsonl", [{"at": iso(NOW - 60), "event": "intent", "note": "running the suite"}])
        with mock.patch.object(dropped_gate, "armed_waiter", return_value=False):
            text = self.sstop("msgowner").get("reason") or ""
        self.assertIn("ah task dispose", text)
        self.assertNotIn("ah job", text)
        commands = [c for c in _re.findall(r"`([^`]+)`", text) if c.startswith("ah ")]
        self.assertTrue(commands, text)
        fill = {"<ask id or GoodQA ticket>": "wa5b00000001", "<ISO>": "2026-11-09T00:00:00Z"}
        for command in commands:
            for hole, value in fill.items():
                command = command.replace(hole, value)
            with self.subTest(command=command):
                ah.build_parser().parse_args(_shlex.split(command)[1:])  # SystemExit (a failure) if it does not parse

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


class QuotedPunctuation(Base):
    """goodqa#15684 (same flaw as PR 179 r14 F1): quoted or escaped shell punctuation is a word character. The old
    splitter cut `--note ";"` into two commands, so the acknowledging flags were no longer in the `ah task dispose`
    segment and a sub-agent's resume or close was not recognised. Every string here is data judged in memory."""
    BASE = "python3 ~/.claude/hooks/ah.py task dispose --agent X"

    def test_quoted_or_escaped_separators_do_not_hide_an_acknowledgement(self):
        notes = ['--note ";"', "--note '&&'", "--note \\;", '--note "a; b"', '--note "x | y"', "--note '('", '--note ")"',
                 "--note 'two\nlines'", '--note "a && b ; c"', "--note \\&\\&", "--note '||'", "--note ';;'"]
        for note in notes:
            for tail in ("--kind resumed", "--kind closed", "--kind waiting --ack-handoff", "--kind=superseded"):
                with self.subTest(note=note, tail=tail):
                    self.assertTrue(dropped_gate.acknowledges(self.BASE + " " + note + " " + tail))
                    self.assertTrue(dropped_gate.acknowledges(self.BASE + " " + tail + " " + note))

    def test_a_quoted_separator_inside_a_shell_wrapper_is_still_judged(self):
        self.assertTrue(dropped_gate.acknowledges("bash -c '" + self.BASE + " --note \";\" --kind resumed'"))
        self.assertTrue(dropped_gate.acknowledges("true && " + self.BASE + " --note ';' --kind closed"))

    def test_text_that_only_mentions_an_acknowledgement_is_not_one(self):
        for command in ('echo "' + self.BASE + ' --kind resumed"',
                        "echo " + self.BASE.replace("python3 ~/.claude/hooks/ah.py", "ah") + " --kind resumed",
                        "grep -n ';' notes.txt ; ah task dispose --agent X --kind waiting --ref wa5b00000004 --until X",
                        self.BASE + " --kind waiting --ref wa5b00000004 --until X --note ';'",
                        "ah task list --note ';' --kind resumed",
                        "echo ';' ; echo ah task dispose --kind resumed"):
            with self.subTest(command=command[:60]):
                self.assertFalse(dropped_gate.acknowledges(command))

    def test_a_line_the_shell_alone_can_read_is_judged_conservatively(self):
        # An unbalanced quote cannot be split, so the substring judgement applies. A `$(...)` is read in lenient mode:
        # the command here is really `ah`, so it is judged on its words; a computed COMMAND word is the next test.
        for command in (self.BASE + " --note 'open --kind resumed", self.BASE + " --note $(echo hi) --kind closed"):
            with self.subTest(command=command[:50]):
                self.assertTrue(dropped_gate.acknowledges(command))

    def stamped(self, command, agents):
        import caller_identity
        dropped_gate._stamp_ack(command, {"session_id": SESSION})
        return [a for a in agents if caller_identity.take_stamp("ack-handoff", [a], home=self.home) is not None]

    def test_the_handoff_stamp_is_minted_only_for_a_command_that_really_runs_the_dispose(self):
        self.assertEqual(self.stamped("python3 ~/.claude/hooks/ah.py task dispose --agent owner-1 --kind waiting "
                                      "--ack-handoff --ref wa5b00000006 --until 2026-11-09T00:00:00Z", ["owner-1"]),
                         ["owner-1"])
        for command in ('echo "ah task dispose --agent owner-2 --ack-handoff"',
                        "echo ah task dispose --agent owner-2 --ack-handoff",
                        "grep -n --agent owner-2 --ack-handoff notes.txt",
                        "printf %s 'ah task dispose --agent owner-2 --kind waiting --ack-handoff'",
                        "ah task list --agent owner-2 --ack-handoff",
                        "ah task dispose --agent owner-2 --kind waiting --ref wa5b00000006 --until X ; "
                        "echo --ack-handoff"):
            with self.subTest(command=command[:60]):
                self.assertEqual(self.stamped(command, ["owner-2"]), [])

    def test_the_stamp_covers_only_the_agents_of_the_dispose_segment(self):
        command = ("ah task dispose --agent owner-3 --kind waiting --ack-handoff --ref wa5b00000006 --until X ; "
                   "ah task dispose --agent owner-4 --kind waiting --ref wa5b00000006 --until X ; echo --agent owner-5")
        self.assertEqual(self.stamped(command, ["owner-3", "owner-4", "owner-5"]), ["owner-3"])

    def test_inline_python_code_and_oversized_lines_are_never_stamped(self):
        self.assertEqual(self.stamped("python3 -c 'print(1)' task dispose --agent owner-7 --kind waiting --ack-handoff",
                                      ["owner-7"]), [])
        # `-c` takes the next word as code, so the ah that follows is that code, not the program
        self.assertEqual(self.stamped("python3 -c ah task dispose --agent owner-7 --kind waiting --ack-handoff",
                                      ["owner-7"]), [])
        padded = ("ah task dispose --agent owner-8 --kind waiting --ack-handoff --ref wa5b00000006 --until X"
                  + " " * 21000)
        self.assertEqual(self.stamped(padded, ["owner-8"]), ["owner-8"])  # a long line is read, not skipped (r1 F1)
        huge = padded + " " * (dropped_gate.PRETOOL_MAX + 1)
        self.assertEqual(self.stamped(huge, ["owner-9"]), [])
        # An oversized line cannot be split, so a real acknowledgement in it is still judged by the substring rule.
        self.assertTrue(dropped_gate.acknowledges("ah task dispose --agent X --kind resumed" + " " * 101000))

    def test_a_quoted_separator_does_not_move_the_agent_out_of_its_segment(self):
        command = 'ah task dispose --agent owner-6 --reason ";" --kind waiting --ack-handoff --ref wa5b00000006 --until X'
        self.assertEqual(self.stamped(command, ["owner-6"]), ["owner-6"])


class ReviewRound1(Base):
    """PR 208 red-team round 1 (goodqa#15684): the stamp must survive the forms main really types, a here-document is
    judged only where the shell would see one, and a stamp is minted only for a command ah's own parser accepts."""
    DISPOSE = "ah task dispose --agent A --kind waiting --ack-handoff --ref wa5b00000006"
    RESUME = "ah task dispose --agent X --kind resumed"

    stamped = QuotedPunctuation.stamped

    def test_main_forms_with_a_computed_value_a_wrapper_or_a_heredoc_are_still_stamped(self):
        for command in (self.DISPOSE + ' --until "$(date -u -v+1H +%FT%TZ)"',
                        self.DISPOSE + " --until `date -u +%FT%TZ`",
                        "cat > n <<EOF\nnote\nEOF\n" + self.DISPOSE + " --until X",
                        "timeout 30s " + self.DISPOSE + " --until X",
                        "python3 -X utf8 ~/.claude/hooks/" + self.DISPOSE.replace("ah ", "ah.py ", 1) + " --until X",
                        "env -u FOO " + self.DISPOSE + " --until X",
                        "sudo -u eric " + self.DISPOSE + " --until X",
                        "AH_HOME=/x nice -n 5 " + self.DISPOSE + " --until X"):
            with self.subTest(command=command[:70]):
                self.assertEqual(self.stamped(command, ["A"]), ["A"])

    def test_a_command_ah_would_not_run_mints_no_stamp(self):
        for command in ("ah --help task dispose --agent A --kind waiting --ack-handoff",
                        "ah task dispose -h --agent A --kind waiting --ack-handoff",
                        "command -v ah task dispose --agent A --kind waiting --ack-handoff",
                        "ah task dispose --agent A --kind waiting",
                        "ah task dispose --agent A --kind nonsense --ack-handoff",
                        "ah task dispose --kind waiting --ack-handoff",
                        'ah task dispose --agent "$(echo A)" --kind waiting --ack-handoff',
                        "ah task dispose --agent $WHO --kind waiting --ack-handoff"):
            with self.subTest(command=command[:70]):
                self.assertEqual(self.stamped(command, ["A", "Y", "$(echo A)", "$WHO"]), [])

    def test_an_agent_flag_inside_another_options_value_is_not_the_agent(self):
        # argparse refuses an option-looking value, so ah would not run this: no stamp for A or Y (it used to stamp Y)
        command = self.DISPOSE + ' --reason "--agent=Y"'
        self.assertEqual(self.stamped(command, ["A", "Y"]), [])
        command = self.DISPOSE + ' --reason "see --agent Y"'
        self.assertEqual(self.stamped(command, ["A", "Y"]), ["A"])

    def test_a_hidden_heredoc_marker_does_not_hide_the_next_line(self):
        for prefix in ('echo "<<EOF"', "echo '<<EOF'", "true # <<EOF", "echo \\<<EOF", "cat <<<EOF"):
            with self.subTest(prefix=prefix):
                self.assertTrue(dropped_gate.acknowledges(prefix + "\n" + self.RESUME + " --reason r\nEOF"))

    def test_a_real_heredoc_body_is_data_unless_a_shell_runs_it(self):
        self.assertFalse(dropped_gate.acknowledges("cat <<EOF\n" + self.RESUME + "\nEOF"))
        self.assertFalse(dropped_gate.acknowledges("cat <<'EOF' > n.md\n" + self.RESUME + "\nEOF\necho done"))
        self.assertFalse(dropped_gate.acknowledges("cat <<-EOF\n\t" + self.RESUME + "\n\tEOF"))
        self.assertTrue(dropped_gate.acknowledges("cat <<-EOF\n\tx\n\tEOF\n" + self.RESUME))  # a tab-indented end marker
        self.assertTrue(dropped_gate.acknowledges("bash <<EOF\n" + self.RESUME + "\nEOF"))
        self.assertTrue(dropped_gate.acknowledges("cat <<'EOF' | bash\n" + self.RESUME + "\nEOF"))
        self.assertTrue(dropped_gate.acknowledges("cat <<'EOF' | sh -e\n" + self.RESUME + "\nEOF"))
        # an unquoted delimiter expands $(...) in the body, and the shell runs it; a quoted one does not
        self.assertTrue(dropped_gate.acknowledges("cat <<EOF\n$(" + self.RESUME + ")\nEOF"))
        self.assertFalse(dropped_gate.acknowledges("cat <<'EOF'\n$(" + self.RESUME + ")\nEOF"))
        # the command after the body is judged on its own
        self.assertTrue(dropped_gate.acknowledges("cat <<EOF\nnote\nEOF\n" + self.RESUME))

    def test_substitutions_are_judged_by_what_they_run(self):
        for command in ("$(" + self.RESUME + ")", "echo $(" + self.RESUME + ")", "echo `" + self.RESUME + "`",
                        'echo "$(' + self.RESUME + ')"', "x=$(" + self.RESUME + ")"):
            with self.subTest(command=command[:50]):
                self.assertTrue(dropped_gate.acknowledges(command))
        self.assertTrue(dropped_gate.acknowledges(self.RESUME + ' --until "$(date)"'))

    def test_wrappers_do_not_hide_an_acknowledgement(self):
        for wrapper in ("timeout 30s ", "timeout -s KILL 10 ", "sudo -u eric ", "env -u FOO ", "nice -n 5 ", "nohup "):
            with self.subTest(wrapper=wrapper):
                self.assertTrue(dropped_gate.acknowledges(wrapper + self.RESUME))
        self.assertTrue(dropped_gate.acknowledges("python3 -X utf8 ~/.claude/hooks/ah.py task dispose --agent X "
                                                  "--kind resumed"))
        self.assertTrue(dropped_gate.acknowledges("python3 -W ignore -I ah.py task dispose --agent X --kind closed"))
        self.assertFalse(dropped_gate.acknowledges("command -v " + self.RESUME))

    def test_commands_that_only_mention_the_words_are_not_denied(self):
        message = "git commit -m \"$(cat <<'EOF'\nfix: it's about dispose and closed\nEOF\n)\""
        self.assertFalse(dropped_gate.acknowledges(message))
        self.assertFalse(dropped_gate.acknowledges("echo dispose closed" + " " * 30000))
        self.assertFalse(dropped_gate.acknowledges("grep -n \"$(echo dispose)\" notes.txt # closed"))

    def test_the_strict_tokenizer_mission_gate_uses_still_refuses_what_only_the_shell_can_read(self):
        import shellwords
        for command in ("cat <<EOF\nx\nEOF", "cat <<-EOF\nx\nEOF", "cat <<< word", "echo $(date)", "echo `date`",
                        'echo "$(date)"'):
            with self.subTest(command=command):
                self.assertIsNone(shellwords.split_commands(command))
                self.assertIsNotNone(shellwords.split_commands(command, lenient=True))

    def test_a_computed_command_word_is_judged_by_the_conservative_text_rule(self):
        # red-team r2 F1: lenient mode made `$(command -v ah)` one opaque word, so the dispose behind it was not seen
        for program in ('"$(command -v ah)"', "$(command -v ah)", "`which ah`", "$AH", "${AH}", '"$(printf ah)"', "a?",
                        "/usr/local/bin/a[h]", "{ah,}"):
            for tail in ("--kind closed", "--kind resumed", "--kind waiting --ack-handoff"):
                with self.subTest(program=program, tail=tail):
                    self.assertTrue(dropped_gate.acknowledges(program + " task dispose --agent X " + tail))
        # a computed subcommand word with an ack word still denies; plain computed text with no ack word does not
        self.assertTrue(dropped_gate.acknowledges("ah $(echo task) dispose --agent X --kind closed"))
        self.assertTrue(dropped_gate.acknowledges("ah task $(echo dispose) --agent X --kind resumed"))
        self.assertFalse(dropped_gate.acknowledges("$(command -v ls) -l"))
        self.assertFalse(dropped_gate.acknowledges('"$(command -v ah)" task list --agent X'))
        self.assertFalse(dropped_gate.acknowledges("$(date) is the date; echo done"))
        # a computed assignment before a literal program is still read as the program it is
        self.assertTrue(dropped_gate.acknowledges("WHEN=$(date) " + self.RESUME))
        self.assertFalse(dropped_gate.acknowledges("WHEN=$(date) ah task list"))

    def test_python_here_documents_are_judged_by_what_the_code_says(self):
        # red-team r2 F2: `-c` code is judged by the substring rule, so is code on stdin
        body = 'import os; os.system("ah task dispose --agent X --kind closed")'
        for command in ("python3 - <<'EOF'\n" + body + "\nEOF", "python3 <<EOF\n" + body + "\nEOF",
                        "cat <<'EOF' | python3\n" + body + "\nEOF", "python -X dev - <<'EOF'\n" + body + "\nEOF",
                        "python3 -c '" + body.replace("'", "") + "'"):
            with self.subTest(command=command[:40]):
                self.assertTrue(dropped_gate.acknowledges(command))
        # python code that mentions neither word is data to the gate; a shell body is still read as shell
        self.assertFalse(dropped_gate.acknowledges("python3 - <<'EOF'\nprint('hello')\nEOF"))
        self.assertTrue(dropped_gate.acknowledges("python3 - <<'EOF' ; bash <<'EOF2'\nprint(1)\nEOF\n" + self.RESUME + "\nEOF2"))
        self.assertTrue(dropped_gate.acknowledges("bash <<'EOF'\n" + self.RESUME + "\nEOF"))
        self.assertFalse(dropped_gate.acknowledges("cat <<'EOF'\n" + body + "\nEOF"))  # cat prints it, nothing runs it

    def test_the_unused_text_pattern_is_gone(self):
        self.assertFalse(hasattr(dropped_gate, "_RUNS_TEXT"))

    def test_nested_and_unbalanced_substitutions_fail_safe(self):
        nest = "echo " + "$(" * 12 + "date" + ")" * 12
        self.assertFalse(dropped_gate.acknowledges(nest))  # too deep to read: the conservative text rule, no ack words
        self.assertTrue(dropped_gate.acknowledges(nest + " ; " + self.RESUME))
        self.assertTrue(dropped_gate.acknowledges("echo $(" + self.RESUME))  # unbalanced: judged by the text rule


class ReviewRound3(Base):
    """PR 208 red-team r3 (goodqa#15684), rescue: a word the shell computes, in ANY position of a command that may run
    ah, hides what ah receives (a computed `--kind`, `--agent`, `task` or `dispose`, `${VAR}`, `$'...'`), and text
    piped into a shell or python is code. Two rounds fixed one position at a time; these cover the class."""
    WAIT = " --kind waiting --ref wa5b00000006 --until 2026-11-12T00:00:00Z"

    stamped = QuotedPunctuation.stamped

    def test_a_computed_kind_value_is_denied_behind_any_program(self):
        for command in ('K=closed; "$(command -v ah)" task dispose --agent X --kind "$K"',
                        '$AH task dispose --agent X --kind "${K}"',
                        "$AH task dispose --agent X --kind=$K",
                        '"$(command -v ah)" task dispose --agent X --kind "$(printf clo)sed"',
                        "`which ah` task dispose --agent X --kind `printf resumed`",
                        'python3 "$AHPY" task dispose --agent X --kind "$K"',
                        "ah task dispose --agent X --kind clos?d",
                        "ah task dispose --agent X --kind {closed,}"):
            with self.subTest(command=command):
                self.assertTrue(dropped_gate.acknowledges(command))

    def test_a_computed_agent_or_option_word_that_can_split_into_flags_is_denied(self):
        for command in ("A='X --kind closed'; ah task dispose --agent $A",
                        "ah task dispose --agent $(cat /x/agent-id)" + self.WAIT,
                        "ah task dispose --agent X ${F}",
                        'ah task dispose --agent X "$F"' + self.WAIT,
                        "ah task dispose --agent X --until=$(date -u +%FT%TZ) --kind waiting --ref wa5b00000006",
                        '"$AH" task dispose --agent X "$F"'):
            with self.subTest(command=command):
                self.assertTrue(dropped_gate.acknowledges(command))

    def test_computed_task_and_dispose_words_are_denied(self):
        for command in ('$AH "$T" "$D" --agent X --kind closed',
                        "$AH task $(printf dis)pose --agent X --kind resumed",
                        '"$(command -v ah)" "$T" dispose --agent X --kind "$K"',
                        'python3 "$AHPY" task "$(echo dispose)" --agent X --kind closed',
                        '${AH} task dispose --agent X --kind "${K}"',
                        'ah task "$D" --agent X --kind waiting --ref wa5b00000006 --until X',
                        "X='ah task dispose --agent Y --kind closed'; $X",
                        "X='ah task dispose --agent Y --kind closed'; eval \"$X\""):
            with self.subTest(command=command):
                self.assertTrue(dropped_gate.acknowledges(command))

    def test_ansi_c_quoting_is_a_computed_word_not_a_hole(self):
        for command in ("ah task dispose --agent X --kind $'\\x63losed'",
                        "ah task $'dis'pose --agent X --kind $'clo'sed",
                        "$'\\x61h' task dispose --agent X --kind $'resumed'",
                        "ah task dispose --agent X $'--kind=\\x63losed'"):
            with self.subTest(command=command):
                self.assertTrue(dropped_gate.acknowledges(command))
        import shellwords
        self.assertIsNone(shellwords.split_commands("echo $'x'"))  # the strict tokenizer still refuses it
        word = shellwords.split_commands("echo $'a b'", lenient=True)[0][1]
        self.assertTrue(word.computed)
        self.assertFalse(word.splits)  # quoted: one word

    def test_text_piped_or_here_stringed_into_a_shell_or_python_is_code(self):
        code = 'import os; os.system("ah task dispose --agent X --kind closed")'
        for command in ("printf '%s' '" + code + "' | python3",
                        "printf 'ah task dispose --agent X --kind closed\\n' | sh",
                        "echo 'ah task dispose --agent X --kind resumed' | bash -s",
                        "echo ah task dispose --agent X --kind resumed | zsh",
                        "echo 'ah task dispose --agent X --kind closed' | source /dev/stdin",
                        "echo 'ah task dispose --agent X --kind closed' |& sh",
                        "echo 'ah task dispose --agent X --kind closed' | \"$SHELL\"",
                        "bash <<< 'ah task dispose --agent X --kind closed'",
                        "python3 <<< '" + code + "'"):
            with self.subTest(command=command[:60]):
                self.assertTrue(dropped_gate.acknowledges(command))

    def test_harmless_forms_stay_allowed(self):
        for command in ("git commit -m \"$(cat <<'EOF'\nfix(dropped-gate): dispose acks are closed to sub-agents\nEOF\n)\"",
                        "git commit -F - <<'EOF'\nfix: ah task dispose --kind closed is main's\nEOF",
                        "echo dispose closed", "printf '%s\\n' 'ah task dispose --agent X --kind closed'",
                        'echo "$(date) dispose closed"', "echo $HOME dispose resumed",
                        "ah task dispose --agent X --kind waiting --ref wa5b00000006 --until \"$(date -u +%FT%TZ)\"",
                        'ah task dispose --agent "$(cat /x/agent-id)"' + self.WAIT,
                        '"$AH" task dispose --agent X' + self.WAIT,
                        "$AH task dispose --agent X --kind waiting --ref wa5b00000006 --until \"$(date)\"",
                        'ah ticket comment goodqa#1 --body "$(cat /x/note.md)"',
                        'ah ticket comment goodqa#1 --body "$(cat /x/note.md)" --note closed',
                        'ah ticket comment goodqa#1 --body "$(cat /x/dispose-plan.md)"',
                        '"$PY" -m pytest "$T"', "$HOME/bin/tool --flag value",
                        "printf 'echo hi\\n' | sh", "cat notes.txt | python3 x.py",
                        "cat <<< 'ah task dispose --agent X --kind closed'",
                        "grep -c dispose log.txt | sh -c 'read n; echo $n'"):
            with self.subTest(command=command[:60]):
                self.assertFalse(dropped_gate.acknowledges(command))

    def test_a_body_that_expands_a_variable_set_on_the_line_is_judged_with_it(self):
        # receipt r1 at 37f481d F1: the nested judgement of a here-string or here-document body lost the line's X=...
        shell_x = "X='ah task dispose --agent Y --kind closed'; "
        py_x = "X='import os; os.system(\"ah task dispose --agent Y --kind closed\")'; "
        for command in (shell_x + 'bash <<< "$X"', py_x + 'python3 <<< "$X"', shell_x + '. /dev/stdin <<< "$X"',
                        shell_x + "bash <<EOF\n$X\nEOF", shell_x + "sh <<< `echo $X`",
                        shell_x + 'bash -c "eval \\"$X\\""', shell_x + 'echo "$(eval "$X")"',
                        shell_x + "bash -c 'bash <<< \"$X\"'"):
            with self.subTest(command=command):
                self.assertTrue(dropped_gate.acknowledges(command))
        for command in (shell_x + 'cat <<< "$X"', shell_x + "cat <<EOF\n$X\nEOF", 'bash <<< "$HOME"',
                        "N=3; bash <<EOF\necho $N\nEOF", "git commit -F - <<EOF\nfix: dispose is closed to $USER\nEOF"):
            with self.subTest(command=command):
                self.assertFalse(dropped_gate.acknowledges(command))

    def test_main_ack_handoff_with_a_literal_until_is_still_stamped(self):
        command = ("ah task dispose --agent A --kind waiting --ack-handoff --ref wa5b00000006 "
                   "--until 2026-11-12T00:00:00Z")
        self.assertEqual(self.stamped(command, ["A"]), ["A"])
        self.assertEqual(self.stamped(command.replace("2026-11-12T00:00:00Z", '"$(date -u +%FT%TZ)"'), ["A"]), ["A"])


if __name__ == "__main__":
    unittest.main()
