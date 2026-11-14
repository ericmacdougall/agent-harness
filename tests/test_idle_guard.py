"""Main-idle guard (GoodQA goodqa#15943). These tests fail against main c82ad2a: there is no idle_guard module, no
agents_active_1h, no ask ownership check and no idle-guard ops-watch check."""
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import ah  # noqa: E402
import ops_watch  # noqa: E402

NOW = 1_800_000_000.0
SESSION = "sess-idle-0001"
HOUR = 3600


def iso(ts):
    return time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(ts))


def jl(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a") as fh:
        for r in rows:
            fh.write((r if isinstance(r, str) else json.dumps(r)) + "\n")


class Base(unittest.TestCase):
    """Two owners: `tick` (stopped without a result) and `done1` (returned a result 4 h ago, nobody took it)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        for p in (mock.patch.dict(os.environ, {"AH_HOME": str(self.home), "HOME": str(self.home)}),
                  mock.patch.object(ah, "server_now", side_effect=lambda: iso(NOW))):
            p.start()
            self.addCleanup(p.stop)
        for k in ("CLAUDE_CODE_CHILD_SESSION", "AH_AGENT_ID", "AGENT_ID", "CLAUDE_CONFIG_DIR", "CLAUDE_CODE_ENTRYPOINT",
                  "AH_IDLE_GUARD_MIN"):
            os.environ.pop(k, None)
        import idle_guard  # noqa: PLC0415 - missing at c82ad2a, so every test fails first
        self.ig = idle_guard
        self.w = self.home / ".claude" / "wals" / SESSION
        old = NOW - 4 * HOUR
        jl(self.w / "main.jsonl", [
            {"at": iso(old), "event": "subagent", "agent_id": "tick", "agent_type": "task-owner"},
            {"at": iso(old), "event": "subagent", "agent_id": "done1", "agent_type": "task-owner"},
            {"at": iso(old + 60), "event": "subagent_stop", "agent_id": "done1", "agent_type": "task-owner"},
            {"at": iso(old + 60), "event": "subagent_stop", "agent_id": "tick", "agent_type": "task-owner"},
            {"at": iso(old + 90), "event": "ask", "id": "wa5b00000001", "note": "need a key", "source": "user:x/y \"w\""},
            {"at": iso(old + 120), "event": "check", "note": "last real progress"},
        ])
        jl(self.w / "agent-tick.jsonl", [{"at": iso(old), "event": "intent", "note": "GoodQA goodqa#15943 work"}])
        jl(self.w / "agent-done1.jsonl", [{"at": iso(old), "event": "intent", "note": "GoodQA goodqa#15944 work"},
                                          {"at": iso(old + 60), "event": "result", "note": "to main: result ready"}])

    def dispose(self, agent, kind, key, **extra):
        args = {"agent": agent, "session": SESSION, "kind": kind, "at": iso(NOW)}
        args.update(extra)
        return ah.write(self.home, "task.dispose", args, SESSION, key)

    def assess(self, **kw):
        return self.ig.assess(self.home, SESSION, NOW, **kw)

    def park_tick_on_ticket(self):
        self.dispose("tick", "waiting", "tick-ticket", until=iso(NOW + 3 * HOUR), ref="GoodQA goodqa#15943")

    def park_tick_on_ask(self):
        self.dispose("tick", "waiting", "tick-ask", until=iso(NOW + 3 * HOUR), ref="wa5b00000001")

    def close_done1(self):  # done1 waits on its own user ask
        jl(self.w / "main.jsonl", [{"at": iso(NOW - 3 * HOUR), "event": "ask", "id": "wa5b00000003", "owner": "done1",
                                    "note": "need approval", "source": "user:x/y \"w\""}])
        self.dispose("done1", "waiting", "done1-wait-ask", until=iso(NOW + 3 * HOUR), ref="wa5b00000003")


class AssessTests(Base):
    def test_idle_with_a_ticket_wait_and_an_untaken_result(self):  # AC-1, AC-2
        self.park_tick_on_ticket()
        a = self.assess()
        self.assertTrue(a["idle"])
        self.assertEqual({s["agent"] for s in a["streams"]}, {"tick", "done1"})
        self.assertGreaterEqual(a["idle_s"], 4 * HOUR - 300)

    def test_threshold_is_configurable(self):  # AC-1
        self.park_tick_on_ticket()
        self.assertFalse(self.assess(idle_minutes=6 * 60)["idle"])
        os.environ["AH_IDLE_GUARD_MIN"] = "10"
        self.assertTrue(self.ig.assess(self.home, SESSION, NOW)["idle"])

    def test_nothing_actionable_when_everything_needs_the_user(self):  # NEG-1
        self.park_tick_on_ask()
        self.close_done1()
        a = self.assess()
        self.assertFalse(a["idle"])
        self.assertEqual(a["streams"], [])

    def test_recent_progress_suppresses(self):  # NEG-2
        self.park_tick_on_ticket()
        jl(self.w / "main.jsonl", [{"at": iso(NOW - 5 * 60), "event": "commit", "note": "feat: x"}])
        self.assertFalse(self.assess()["idle"])

    def test_main_bash_pretool_rows_are_not_progress(self):  # NEG-2: the checkpoint script is Bash
        self.park_tick_on_ticket()
        jl(self.w / "main.jsonl", [{"at": iso(NOW - 60), "event": "pretool", "tool": "Bash"}])
        self.assertTrue(self.assess()["idle"])
        jl(self.w / "main.jsonl", [{"at": iso(NOW - 60), "event": "pretool", "tool": "Agent"}])
        self.assertFalse(self.assess()["idle"])

    def test_owner_activity_is_progress(self):  # AC-1
        self.park_tick_on_ticket()
        jl(self.w / "agent-tick.jsonl", [{"at": iso(NOW - 120), "event": "status", "note": "building"}])
        self.assertFalse(self.assess()["idle"])

    def test_hostile_wal_lines_do_not_break_the_scan(self):  # NEG-3
        self.park_tick_on_ticket()
        jl(self.w / "main.jsonl", ["{not json", "[1,2]", json.dumps({"event": "check", "at": 5})])
        self.assertTrue(self.assess()["idle"])


class StopHookTests(Base):
    def stop(self, **payload):
        body = {"session_id": SESSION, "hook_event_name": "Stop", "stop_hook_active": False}
        body.update(payload)
        return self.ig.cmd_stop(body, now=NOW)

    def test_blocks_with_named_streams_then_is_bounded(self):  # AC-3, NEG-4
        self.park_tick_on_ticket()
        out = self.stop()
        self.assertEqual(out["decision"], "block")
        self.assertIn("tick", out["reason"])
        self.assertIn("done1", out["reason"])
        self.assertIn(self.ig.REMINDER, out["reason"])
        self.assertEqual(self.stop()["decision"], "block")  # second block of the bound
        self.assertNotIn("decision", self.stop())  # bound reached: message only
        self.assertNotIn("decision", self.stop(stop_hook_active=True))

    def test_silent_when_all_needs_the_user(self):  # NEG-1
        self.park_tick_on_ask()
        self.close_done1()
        self.assertEqual(self.stop(), {})

    def test_sub_agent_and_headless_never_block(self):  # NEG-3
        self.park_tick_on_ticket()
        self.assertEqual(self.stop(agent_id="x"), {})
        with mock.patch.dict(os.environ, {"CLAUDE_CODE_ENTRYPOINT": "sdk-cli"}):
            self.assertEqual(self.stop(), {})

    def test_missing_wal_fails_open(self):  # NEG-3
        self.assertEqual(self.ig.cmd_stop({"session_id": "nope", "stop_hook_active": False}, now=NOW), {})

    def test_every_owner_waiting_on_user_asks_while_a_result_sits_untaken(self):  # AC-6 (no idle time needed)
        self.park_tick_on_ask()
        jl(self.w / "main.jsonl", [{"at": iso(NOW - 60), "event": "commit", "note": "fresh progress"}])
        self.assertFalse(self.assess()["idle"])
        out = self.stop()
        self.assertEqual(out["decision"], "block")
        self.assertIn("done1", out["reason"])
        self.assertIn("waits on a user ask", out["reason"])

    def test_rejection_this_turn_with_independent_work_blocks(self):  # AC-7 (Stop side)
        self.park_tick_on_ask()
        jl(self.w / "main.jsonl", [{"at": iso(NOW - 60), "event": "commit", "note": "fresh progress"}])
        self.close_done1()
        self.assertEqual(self.stop(), {})
        t = self.home / "t.jsonl"
        jl(t, [{"type": "user", "message": {"role": "user", "content": "go"}},
               {"type": "user", "message": {"role": "user", "content": [{"type": "tool_result", "is_error": True,
                "content": "The user doesn't want to proceed with this tool use. STOP"}]}, "toolDenialKind": "user-rejected"}])
        jl(self.w / "agent-done1.jsonl", [{"at": iso(NOW - 30), "event": "result", "note": "again"}])
        self.dispose("done1", "waiting", "done1-wait-1", until=iso(NOW + HOUR), ref="GoodQA goodqa#15944")
        out = self.stop(transcript_path=str(t))
        self.assertEqual(out["decision"], "block")
        self.assertIn("rejected", out["reason"])


class ReminderTests(Base):
    def test_rejection_injects_the_exact_line(self):  # AC-7
        out = self.ig.cmd_reject({"hook_event_name": "PostToolUseFailure", "tool_name": "AskUserQuestion",
                                  "error": "The user doesn't want to proceed with this tool use."})
        self.assertEqual(out["hookSpecificOutput"]["additionalContext"],
                         "A rejected question pauses only that question; keep every independent stream moving.")

    def test_ordinary_failure_injects_nothing(self):  # NEG-6
        self.assertEqual(self.ig.cmd_reject({"hook_event_name": "PostToolUseFailure", "error": "exit 1: no such file"}), {})

    def test_next_prompt_after_a_rejected_turn_gets_it(self):  # AC-7 (a rejection may get no Post event)
        t = self.home / "t2.jsonl"
        jl(t, [{"type": "user", "message": {"role": "user", "content": [{"type": "tool_result", "is_error": True,
                "content": "The user doesn't want to proceed with this tool use."}]}}])
        out = self.ig.cmd_reject({"hook_event_name": "UserPromptSubmit", "transcript_path": str(t)})
        self.assertIn("pauses only that question", out["hookSpecificOutput"]["additionalContext"])
        self.assertEqual(self.ig.cmd_reject({"hook_event_name": "UserPromptSubmit", "transcript_path": str(self.home / "none")}), {})


class OpsWatchTests(Base):
    def alerts(self):
        os.utime(self.w / "main.jsonl", (NOW, NOW))  # the check skips sessions whose main WAL is old (clock is faked)
        cfg = ops_watch.load_config(self.home)
        return ops_watch.check_idle_guard(cfg, {}, None, NOW)

    def test_raises_a_high_alert_and_clears(self):  # AC-4
        self.park_tick_on_ticket()
        out = self.alerts()
        self.assertEqual([a["key"] for a in out], ["idle-guard:" + SESSION[:8]])
        self.assertEqual(out[0]["severity"], "high")
        self.assertIn("tick", out[0]["message"])
        jl(self.w / "main.jsonl", [{"at": iso(NOW - 60), "event": "commit", "note": "x"}])
        self.assertEqual(self.alerts(), [])

    def test_no_alert_when_only_the_user_can_act(self):  # NEG-1
        self.park_tick_on_ask()
        self.close_done1()
        self.assertEqual(self.alerts(), [])


class NoteWaitTests(Base):
    """Receipt r1 F1/F2: waits recorded in WAL notes (no disposition) must not hide idleness or bypass ask ownership."""

    def note_wait(self, agent, target):
        # written before the owner's stop row (old+60) so the owner stays stopped and the note is its last entry
        jl(self.w / f"agent-{agent}.jsonl", [{"at": iso(NOW - 4 * HOUR + 30), "event": "status",
                                              "note": f"blocked, waiting on {target}"}])

    def by(self):
        return {r["agent_id"]: r for r in ah.owners(self.home, SESSION, now=NOW)["owners"]}

    def test_stopped_owner_waiting_on_a_ticket_by_note_is_actionable(self):  # F1
        self.note_wait("tick", "GoodQA goodqa#15943")
        self.assertTrue(self.by()["tick"]["state"].startswith("waiting-on-GoodQA"))
        a = self.assess()
        self.assertTrue(a["idle"])
        self.assertIn("tick", {s["agent"] for s in a["streams"]})

    def test_task_wal_waiting_on_a_ticket_by_note_is_actionable(self):  # F1
        jl(self.w / "taskwal.jsonl", [{"at": iso(NOW - 3 * HOUR), "event": "status",
                                       "note": "waiting on GoodQA goodqa#15943"}])
        os.utime(self.w / "taskwal.jsonl", (NOW - 3 * HOUR, NOW - 3 * HOUR))  # the clock is faked; the window reads mtime
        a = self.assess()
        self.assertIn("taskwal", {s["agent"] for s in a["streams"]})

    def test_terminal_disposition_stays_terminal(self):  # F1: a retired owner is not a stream
        self.note_wait("tick", "GoodQA goodqa#15943")
        with mock.patch.object(ah, "_ticket_exists", return_value=True):
            self.dispose("tick", "wontdo", "tick-wontdo-1", ref="GoodQA goodqa#15943",
                         reason="verified that nobody will do this and the scope was dropped by main")
        self.assertNotIn("tick", {s["agent"] for s in self.assess()["streams"]})

    def test_note_wait_on_own_open_ask_needs_only_the_user(self):  # NEG-1 via notes
        self.note_wait("tick", "wa5b00000001")
        self.close_done1()
        a = self.assess()
        self.assertFalse(a["idle"])
        self.assertEqual(a["streams"], [])

    def test_note_wait_on_another_owners_ask_is_invalid(self):  # F2
        jl(self.w / "main.jsonl", [{"at": iso(NOW - 3 * HOUR), "event": "ask", "id": "wa5b00000002", "owner": "done1",
                                    "note": "need approval", "source": "user:x/y \"w\""}])
        self.note_wait("tick", "wa5b00000002")
        row = self.by()["tick"]
        self.assertIn("wait-ask-foreign", row["flags"])
        self.assertIn("wait-invalid", row["attention"])
        self.assertIn("tick", ah.owners(self.home, SESSION, now=NOW)["attention"])
        self.assertIn("tick", {s["agent"] for s in self.assess()["streams"]})

    def test_two_owners_citing_one_ask_only_the_first_holds_it(self):  # F2
        old = NOW - 4 * HOUR
        jl(self.w / "main.jsonl", [{"at": iso(old), "event": "subagent", "agent_id": "tock", "agent_type": "task-owner"},
                                   {"at": iso(old + 60), "event": "subagent_stop", "agent_id": "tock", "agent_type": "task-owner"}])
        jl(self.w / "agent-tock.jsonl", [{"at": iso(old), "event": "intent", "note": "GoodQA goodqa#15945 work"}])
        self.note_wait("tick", "wa5b00000001")
        self.note_wait("tock", "wa5b00000001")
        rows = self.by()
        flagged = [a for a in ("tick", "tock") if "wait-ask-shared" in rows[a]["flags"]]
        self.assertEqual(len(flagged), 1)
        self.assertIn(flagged[0], {s["agent"] for s in self.assess()["streams"]})


class DisposeNarrowTests(Base):
    def test_ask_naming_another_owner_is_refused(self):  # AC-5
        jl(self.w / "main.jsonl", [{"at": iso(NOW - 50), "event": "ask", "id": "wa5b00000002", "owner": "done1",
                                    "note": "need approval", "source": "user:x/y \"w\""}])
        with self.assertRaises(ah.AhError) as cm:
            self.dispose("tick", "waiting", "wait-other-1", until=iso(NOW + HOUR), ref="wa5b00000002")
        self.assertIn("belongs to done1", str(cm.exception))
        self.dispose("done1", "waiting", "wait-own-01", until=iso(NOW + HOUR), ref="wa5b00000002")

    def test_one_ask_does_not_excuse_two_owners(self):  # AC-5
        self.park_tick_on_ask()
        with self.assertRaises(ah.AhError) as cm:
            self.dispose("done1", "waiting", "wait-second-1", until=iso(NOW + HOUR), ref="wa5b00000001")
        self.assertIn("already tick's wait", str(cm.exception))

    def test_unowned_unused_ask_still_works(self):  # NEG-5
        self.park_tick_on_ask()


class StatusVisibilityTests(Base):
    def test_agents_active_1h_counts_agents_that_wrote(self):  # AC-8
        self.assertEqual(ah.owners(self.home, SESSION, now=NOW)["agents_active_1h"], 0)
        jl(self.w / "agent-tick.jsonl", [{"at": iso(NOW - 600), "event": "status", "note": "building"}])
        data = ah.owners(self.home, SESSION, now=NOW)
        self.assertEqual(data["agents_active_1h"], 1)
        rep = ah.status_report(self.home, SESSION, 6 * HOUR, now=NOW)
        self.assertEqual(rep["owners"]["agents_active_1h"], 1)

    def test_a_dangling_transcript_symlink_hides_nothing(self):  # one bad file never fails the section
        sub = self.home / ".claude" / "projects" / "p" / SESSION / "subagents"
        sub.mkdir(parents=True)
        os.symlink(self.home / "gone", sub / "agent-tick.jsonl")
        (sub / "agent-done1.jsonl").write_text("{}\n")
        os.utime(sub / "agent-done1.jsonl", (NOW - 60, NOW - 60))
        data = ah.owners(self.home, SESSION, now=NOW)
        self.assertEqual(data["agents_active_1h"], 1)


if __name__ == "__main__":
    unittest.main()
