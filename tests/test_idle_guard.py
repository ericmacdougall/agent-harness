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
        with mock.patch.object(ah, "server_now", side_effect=lambda: args["at"]):  # the ledger stamps its own clock
            return ah.write(self.home, "task.dispose", args, SESSION, key)

    def assess(self, **kw):
        return self.ig.assess(self.home, SESSION, NOW, **kw)

    def park_tick_on_ticket(self):
        self.dispose("tick", "waiting", "tick-ticket", until=iso(NOW + 3 * HOUR), ref="GoodQA goodqa#15943")

    def park_tick_on_ask(self):
        self.dispose("tick", "waiting", "tick-ask", until=iso(NOW + 3 * HOUR), ref="wa5b00000001")

    def close_done1(self):  # main took done1's result (--ack-handoff) and done1 now waits on its own user ask
        # receipt r4: only main's acknowledged wait takes a returned result; a plain wait would leave it actionable
        import caller_identity  # noqa: PLC0415
        jl(self.w / "main.jsonl", [{"at": iso(NOW - 3 * HOUR), "event": "ask", "id": "wa5b00000003", "owner": "done1",
                                    "note": "need approval", "source": "user:x/y \"w\""}])
        caller_identity.put_stamp("ack-handoff", ["done1"], home=self.home)  # what main's hook writes
        self.dispose("done1", "waiting", "done1-wait-ask", until=iso(NOW + 3 * HOUR), ref="wa5b00000003",
                     ack_handoff=True)


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


class TurnBoundaryTests(Base):
    """Receipt r6 F1: turn boundaries follow provenance.user_authorship(): a human prompt in any supported format ends
    the rejected turn; injected notifications, reminders and tool results do not."""

    REJECT = {"type": "user", "toolDenialKind": "user-rejected", "message": {"role": "user", "content": [
        {"type": "tool_result", "is_error": True, "content": "The user doesn't want to proceed with this tool use."}]}}

    def setUp(self):
        super().setUp()
        self.park_tick_on_ask()
        jl(self.w / "main.jsonl", [{"at": iso(NOW - 60), "event": "commit", "note": "fresh progress"}])
        self.close_done1()
        jl(self.w / "agent-done1.jsonl", [{"at": iso(NOW - 30), "event": "result", "note": "again"}])
        self.dispose("done1", "waiting", "done1-wait-tb", until=iso(NOW + HOUR), ref="GoodQA goodqa#15944")
        self.assertFalse(self.assess()["idle"])  # only the rejection rule can block here
        self.assertTrue(self.assess()["streams"])

    def stop_after(self, *records):
        t = self.home / "tb.jsonl"
        if t.exists():
            t.unlink()
        jl(t, [{"type": "user", "origin": {"kind": "human"}, "message": {"role": "user", "content": "go"}},
               self.REJECT, *records])
        return self.ig.cmd_stop({"session_id": SESSION, "stop_hook_active": False, "transcript_path": str(t)}, now=NOW)

    def test_a_text_block_human_prompt_ends_the_rejected_turn(self):
        prompt = {"type": "user", "origin": {"kind": "human"},
                  "message": {"role": "user", "content": [{"type": "text", "text": "now do the next thing"}]}}
        self.assertEqual(self.stop_after(prompt), {})
        self.assertFalse(self.ig.rejected_this_turn(str(self.home / "tb.jsonl")))

    def test_a_string_human_prompt_ends_the_rejected_turn(self):
        self.assertEqual(self.stop_after({"type": "user", "origin": {"kind": "human"},
                                          "message": {"role": "user", "content": "next"}}), {})

    def test_injected_records_do_not_end_the_rejected_turn(self):
        injected = {
            "task-notification": {"type": "user", "origin": {"kind": "task-notification"}, "message": {"role": "user",
                                  "content": [{"type": "text", "text": "<task-notification>agent done</task-notification>"}]}},
            "unmarked wrapper": {"type": "user", "message": {"role": "user",
                                 "content": "<task-notification>agent done</task-notification>"}},
            "system reminder": {"type": "user", "isMeta": True, "origin": {"kind": "human"}, "message": {"role": "user",
                                "content": [{"type": "text", "text": "<system-reminder>x</system-reminder>"}]}},
            "peer message": {"type": "user", "origin": {"kind": "peer", "from": "a1"},
                             "message": {"role": "user", "content": "checkpoint"}},
            "tool result": {"type": "user", "origin": {"kind": "human"}, "toolUseResult": {},
                            "message": {"role": "user", "content": [{"type": "tool_result", "content": "ok"}]}},
        }
        for name, rec in injected.items():
            with self.subTest(name):
                out = self.stop_after(rec)
                self.assertIn("rejected", out.get("reason") or out.get("systemMessage") or "")


class Goodqa15949Tests(Base):
    """goodqa#15949: a quoted phrase is not a rejection, the Stop signature ignores progress, the counter keeps history."""

    def _transcript(self, *records):
        t = self.home / "q.jsonl"
        if t.exists():
            t.unlink()
        jl(t, [{"type": "user", "origin": {"kind": "human"}, "message": {"role": "user", "content": "go"}}, *records])
        return str(t)

    def test_a_successful_tool_result_quoting_the_phrase_is_not_a_rejection(self):
        quoted = {"type": "user", "toolUseResult": {}, "message": {"role": "user", "content": [
            {"type": "tool_result", "content": "grep: The user doesn't want to proceed with this tool use. (user-rejected)"}]}}
        self.assertFalse(self.ig.rejected_this_turn(self._transcript(quoted)))
        mid = {"type": "user", "message": {"role": "user", "content": [
            {"type": "tool_result", "is_error": True, "content": "exit 1: log says The user doesn't want to proceed with this tool use"}]}}
        self.assertFalse(self.ig.rejected_this_turn(self._transcript(mid)))

    def test_a_real_denial_is_a_rejection(self):
        denial = {"type": "user", "toolDenialKind": "user-rejected", "message": {"role": "user", "content": [
            {"type": "tool_result", "is_error": True, "content": "x"}]}}
        self.assertTrue(self.ig.rejected_this_turn(self._transcript(denial)))
        text = {"type": "user", "message": {"role": "user", "content": [{"type": "tool_result", "is_error": True,
                "content": [{"type": "text", "text": "The user doesn't want to proceed with this tool use. STOP"}]}]}}
        self.assertTrue(self.ig.rejected_this_turn(self._transcript(text)))

    def test_same_streams_with_changing_progress_block_at_most_the_cap(self):
        self.park_tick_on_ticket()
        blocks = 0
        for i in range(8):
            jl(self.w / "main.jsonl", [{"at": iso(NOW - 1000 + i), "event": "check", "note": f"turn {i}"}])
            out = self.ig.cmd_stop({"session_id": SESSION, "stop_hook_active": False}, now=NOW + 4 * HOUR + i)
            blocks += out.get("decision") == "block"
        self.assertEqual(blocks, self.ig.MAX_STOP_BLOCKS)

    def test_alternating_signatures_do_not_reset_each_other(self):
        for sig in ("A", "B", "A"):
            self.ig._count(SESSION, sig, bump=True)
        self.assertEqual(self.ig._count(SESSION, "A", bump=False), 2)
        self.assertEqual(self.ig._count(SESSION, "B", bump=False), 1)

    def test_counter_retention_is_bounded(self):
        for i in range(self.ig.MAX_SIGS + 20):
            self.ig._count(SESSION, f"s{i}", bump=True)
        blocks = json.loads(self.ig.state_path(SESSION).read_text())["blocks"]
        self.assertLessEqual(len(blocks), self.ig.MAX_SIGS)
        self.assertEqual(self.ig._count(SESSION, f"s{self.ig.MAX_SIGS + 19}", bump=False), 1)


    def tick_streams(self):
        return [x["agent"] for x in self.assess()["streams"]]

    def test_external_wait_is_excused_until_it_expires(self):  # goodqa#15949 item 1
        self.dispose("tick", "waiting", "tick-ext", until=iso(NOW + 3 * HOUR), ref="GoodQA goodqa#15643",
                     external="Codex quota resets 2026-11-16")
        self.assertNotIn("tick", self.tick_streams())
        late = self.ig.assess(self.home, SESSION, NOW + 4 * HOUR)
        self.assertIn("tick", [x["agent"] for x in late["streams"]])  # expired: flagged again

    def test_ordinary_ticket_wait_stays_actionable(self):
        self.park_tick_on_ticket()
        self.assertIn("tick", self.tick_streams())

    def test_external_needs_a_reason_and_a_waiting_kind(self):
        for kind, ext in (("waiting", "short"), ("legacy", "Codex quota resets 11-16")):
            with self.subTest(kind):
                with self.assertRaises(ah.AhError):
                    self.dispose("tick", kind, "tick-bad-key1", until=iso(NOW + HOUR), ref="GoodQA goodqa#15643", external=ext)

    def test_quota_ref_only_with_external(self):
        self.dispose("tick", "waiting", "tick-quota-1", until=iso(NOW + HOUR), ref="quota:codex", external="Codex quota resets 11-16")
        with self.assertRaises(ah.AhError):
            self.dispose("done1", "waiting", "done1-quota-1", until=iso(NOW + HOUR), ref="quota:codex")

    def test_an_owner_working_after_its_wait_is_not_a_ticket_wait_stream(self):  # goodqa#15949 item 2
        self.dispose("tick", "waiting", "tick-old-wait", until=iso(NOW + 3 * HOUR), ref="GoodQA goodqa#15943", at=iso(NOW - 600))
        self.assertIn("tick", self.tick_streams())  # activity before the wait does not lift it
        jl(self.w / "main.jsonl", [{"at": iso(NOW - 120), "event": "subagent", "agent_id": "tick", "agent_type": "task-owner"}])
        jl(self.w / "agent-tick.jsonl", [{"at": iso(NOW - 20), "event": "check", "note": "back and working"}])
        self.assertNotIn("tick", self.tick_streams())


    def test_fresh_transcript_with_a_stale_wal_clears_the_wait(self):  # receipt r1 F1: resumed by SendMessage
        self.dispose("tick", "waiting", "tick-tr-wait", until=iso(NOW + 3 * HOUR), ref="GoodQA goodqa#15943", at=iso(NOW - 600))
        self.assertIn("tick", self.tick_streams())
        sub = self.home / ".claude" / "projects" / "p" / SESSION / "subagents"
        sub.mkdir(parents=True)
        (sub / "agent-tick.jsonl").write_text("{}\n")  # the WAL stays as it was, before the wait
        os.utime(sub / "agent-tick.jsonl", (NOW - 20, NOW - 20))
        row = [r for r in ah.owners(self.home, SESSION, now=NOW)["owners"] if r["agent_id"] == "tick"][0]
        self.assertIsNone(row["wait_on"], row)
        self.assertNotIn("tick", self.tick_streams())


    def _resumed_then_aged(self, **wait):  # receipt r2 F1: a wait, activity 10 min later, then the clock moves on
        self.dispose("tick", "waiting", wait.pop("key"), until=iso(NOW + 3 * HOUR), at=iso(NOW - 700), **wait)
        jl(self.w / "agent-tick.jsonl", [{"at": iso(NOW - 100), "event": "check", "note": "resumed and working"}])
        out = {}
        for label, later in (("fresh", 0), ("silent", 45 * 60), ("hours", 7 * HOUR)):  # past the live and SILENT windows and the undisposed-silent report
            data = ah.owners(self.home, SESSION, now=NOW + later)
            row = [r for r in data["owners"] if r["agent_id"] == "tick"][0]
            out[label] = (row, "tick" in [x["agent"] for x in self.ig.assess(self.home, SESSION, NOW + later)["streams"]])
        return out

    def test_activity_supersedes_an_ordinary_ticket_wait_as_it_ages(self):
        for label, (row, _listed) in self._resumed_then_aged(key="tick-r2-ordinary", ref="GoodQA goodqa#15943").items():
            with self.subTest(label):
                self.assertIsNone(row["disposition"], row)
                self.assertIsNone(row["wait_on"], row)

    def test_activity_supersedes_an_external_wait_as_it_ages(self):
        out = self._resumed_then_aged(key="tick-r2-external", ref="GoodQA goodqa#15643", external="Codex quota resets 11-16")
        for label, (row, _listed) in out.items():
            with self.subTest(label):
                self.assertIsNone(row["disposition"], row)
                self.assertNotIn("wait-not-user", row["attention"])
        self.assertTrue(out["hours"][1], "a silent resumed owner is no longer excused by the old external wait")

    def test_activity_supersedes_an_open_ask_wait_as_it_ages(self):
        for label, (row, _listed) in self._resumed_then_aged(key="tick-r2-ask", ref="wa5b00000001").items():
            with self.subTest(label):
                self.assertIsNone(row["disposition"], row)
                self.assertIsNone(row["wait_on"], row)


class WaitRestoreTests(Base):
    """goodqa#15949 receipt r3 F1: one rule decides whether a wait is current. A wait, from a disposition or a WAL note,
    holds only while no qualifying activity has come after it, and no other path (the note fallback, an older note under
    an expired disposition, the 24 h note cap) may bring a superseded wait back."""

    WAITS = {"ordinary": {"ref": "GoodQA goodqa#15943"},
             "external": {"ref": "GoodQA goodqa#15643", "external": "Codex quota resets 2026-11-16"},
             "ask": {"ref": "wa5b00000001"}}
    AGES = (("fresh", 0), ("45m", 45 * 60), ("7h", 7 * HOUR))

    def look(self, later=0.0):
        rows = {r["agent_id"]: r for r in ah.owners(self.home, SESSION, now=NOW + later)["owners"]}
        streams = [s["agent"] for s in self.ig.assess(self.home, SESSION, NOW + later)["streams"]]
        return rows, streams

    def stop(self, agent, at):  # wal.py writes the stop row to both the main and the owner's WAL
        row = {"at": iso(at), "event": "subagent_stop", "agent_id": agent, "agent_type": "task-owner"}
        jl(self.w / "main.jsonl", [row])
        jl(self.w / f"agent-{agent}.jsonl", [row])

    def wait_note_then(self, agent, kind, key, then_event, then_at, wait_at):
        """A `waiting on <ref>` note, a waiting disposition a minute later (live past +7 h), then `then_event`."""
        wait = dict(self.WAITS[kind])
        wal = self.w / f"{agent}.jsonl" if agent.startswith("tw") else self.w / f"agent-{agent}.jsonl"
        jl(wal, [{"at": iso(wait_at), "event": "status", "note": f"blocked, waiting on {wait['ref']}"}])
        self.dispose(agent, "waiting", key, until=iso(NOW + 8 * HOUR), at=iso(wait_at + 60), **wait)
        jl(wal, [{"at": iso(then_at), "event": then_event, "note": "back on it: next slice"}])
        return wal

    def test_stopped_owner_resumed_after_a_note_and_disposition_is_not_excused(self):  # r3 F1, sub-agent row
        for kind in self.WAITS:
            for then in ("intent", "check"):
                with self.subTest(kind=kind, then=then):
                    self.setUp()
                    self.wait_note_then("tick", kind, f"tick-r3-{kind}-{then}", then, NOW - 2 * HOUR, NOW - 3 * HOUR)
                    self.stop("tick", NOW - 2 * HOUR + 30)
                    for label, later in self.AGES:
                        rows, streams = self.look(later)
                        row = rows["tick"]
                        with self.subTest(age=label):
                            self.assertIsNone(row["wait_on"], row)
                            self.assertIsNone(row["disposition"], row)
                            self.assertEqual(row["state"], "DROPPED", row)
                            self.assertTrue(row["decision_required"], row)
                            self.assertIn("tick", streams)

    def test_task_wal_resumed_after_a_note_and_disposition_is_not_excused(self):  # r3 F1, the reviewer's repro
        for kind in self.WAITS:
            for then in ("intent", "check"):
                with self.subTest(kind=kind, then=then):
                    self.setUp()
                    wal = self.wait_note_then("tw15949", kind, f"tw-r3-{kind}-{then}", then, NOW - 120, NOW - 3 * HOUR)
                    os.utime(wal, (NOW - 120, NOW - 120))  # the clock is faked; the task-WAL window reads mtime
                    for label, later in self.AGES:
                        rows, streams = self.look(later)
                        row = rows["tw15949"]
                        with self.subTest(age=label):
                            self.assertIsNone(row["wait_on"], row)
                            self.assertIsNone(row["disposition"], row)
                            self.assertFalse(row["state"].startswith("waiting-on-"), row)
                            if label == "7h":  # past TASK_ABANDON_S: no stale wait keeps it out of the dropped scan
                                self.assertEqual(row["state"], "DROPPED", row)
                                self.assertTrue(row["decision_required"], row)
                                self.assertIn("tw15949", streams)

    def test_an_expired_disposition_does_not_fall_back_to_an_older_note(self):  # newest wait wins
        jl(self.w / "agent-tick.jsonl", [{"at": iso(NOW - 3 * HOUR), "event": "status", "note": "waiting on wa5b00000001"}])
        self.stop("tick", NOW - 3 * HOUR + 30)
        self.dispose("tick", "waiting", "tick-newer-wait", until=iso(NOW - HOUR), at=iso(NOW - 2 * HOUR),
                     ref="GoodQA goodqa#15943")
        rows, streams = self.look()
        self.assertIsNone(rows["tick"]["wait_on"], rows["tick"])
        self.assertTrue(rows["tick"]["decision_required"], rows["tick"])
        self.assertIn("tick", streams)

    def test_the_note_cap_runs_from_the_note_not_from_later_hook_rows(self):  # 24 h from the note's own time
        jl(self.w / "agent-tick.jsonl", [{"at": iso(NOW - 4 * HOUR + 30), "event": "status",
                                          "note": "waiting on GoodQA goodqa#15943"},
                                         {"at": iso(NOW - 3 * HOUR), "event": "pretool", "agent_id": "tick", "tool": "Bash"}])
        self.stop("tick", NOW - 3 * HOUR + 20)
        rows, _ = self.look(21 * HOUR)  # 25 h after the note, under 24 h after the last hook row
        self.assertIsNone(rows["tick"]["wait_on"], rows["tick"])
        self.assertEqual(rows["tick"]["state"], "DROPPED", rows["tick"])

    # ---- controls: these hold at 79ebb269 too, except where noted, and must keep holding

    def closing_tail(self, agent, start):
        """What follows an owner's own wait in a real turn: tool rows (a ticket post), the stop row, the last
        transcript write, all within a few minutes and none of it new work."""
        jl(self.w / f"agent-{agent}.jsonl", [{"at": iso(start + 90), "event": "pretool", "agent_id": agent, "tool": "Bash"},
                                             {"at": iso(start + 150), "event": "pretool", "agent_id": agent, "tool": "Bash"}])
        self.stop(agent, start + 200)
        sub = self.home / ".claude" / "projects" / "p" / SESSION / "subagents"
        sub.mkdir(parents=True, exist_ok=True)
        (sub / f"agent-{agent}.jsonl").write_text("{}\n")
        os.utime(sub / f"agent-{agent}.jsonl", (start + 200, start + 200))

    def test_a_note_wait_followed_by_its_own_closing_tail_holds(self):
        jl(self.w / "agent-tick.jsonl", [{"at": iso(NOW - 3 * HOUR), "event": "status", "note": "waiting on GoodQA goodqa#15943"}])
        self.closing_tail("tick", NOW - 3 * HOUR)
        for label, later in self.AGES:
            with self.subTest(age=label):
                row = self.look(later)[0]["tick"]
                self.assertEqual(row["wait_on"], "GoodQA goodqa#15943", row)
                self.assertFalse(row["decision_required"], row)

    def test_an_owners_own_disposition_followed_by_its_closing_tail_holds(self):  # fails at 79ebb269: false DROPPED
        jl(self.w / "agent-tick.jsonl", [{"at": iso(NOW - 3 * HOUR - 30), "event": "intent", "note": "park on the ask"}])
        self.dispose("tick", "waiting", "tick-own-wait", until=iso(NOW + 8 * HOUR), at=iso(NOW - 3 * HOUR), ref="wa5b00000001")
        self.closing_tail("tick", NOW - 3 * HOUR)
        for label, later in self.AGES:
            with self.subTest(age=label):
                rows, streams = self.look(later)
                self.assertEqual(rows["tick"]["wait_on"], "wa5b00000001", rows["tick"])
                self.assertTrue(rows["tick"]["disposition"]["live"], rows["tick"])
                self.assertFalse(rows["tick"]["decision_required"], rows["tick"])
                self.assertNotIn("tick", streams)

    def test_a_wait_written_after_resuming_holds_from_its_own_time(self):
        jl(self.w / "agent-tick.jsonl", [
            {"at": iso(NOW - 3 * HOUR), "event": "status", "note": "waiting on GoodQA goodqa#15943"},
            {"at": iso(NOW - 2 * HOUR), "event": "intent", "note": "resumed"},
            {"at": iso(NOW - 2 * HOUR + 60), "event": "status", "note": "blocked again, waiting on wa5b00000001"}])
        self.stop("tick", NOW - 2 * HOUR + 90)
        for label, later in self.AGES:
            with self.subTest(age=label):
                rows, streams = self.look(later)
                self.assertEqual(rows["tick"]["wait_on"], "wa5b00000001", rows["tick"])
                self.assertNotIn("tick", streams)

    def test_a_record_written_by_another_actor_does_not_supersede(self):
        wal = self.w / "tw15950.jsonl"
        jl(wal, [{"at": iso(NOW - 3 * HOUR), "event": "status", "note": "waiting on wa5b00000001"},
                 {"at": iso(NOW - 120), "event": "check", "by": "ah-sweeper", "note": "swept"}])
        os.utime(wal, (NOW - 120, NOW - 120))
        self.assertEqual(self.look()[0]["tw15950"]["wait_on"], "wa5b00000001")

    def test_main_acknowledged_handoff_wait_survives_later_notes(self):
        self.close_done1()
        jl(self.w / "agent-done1.jsonl", [{"at": iso(NOW + 300), "event": "check", "note": "tidying after the handoff"}])
        rows, streams = self.look(600)
        self.assertEqual(rows["done1"]["disposition"]["kind"], "waiting", rows["done1"])
        self.assertNotIn("done1", streams)

    def test_an_index_written_before_note_times_is_rescanned(self):
        wal = self.w / "tw15951.jsonl"
        jl(wal, [{"at": iso(NOW - 3 * HOUR), "event": "status", "note": "waiting on wa5b00000001"},
                 {"at": iso(NOW - 2 * HOUR), "event": "intent", "note": "resumed"}])
        index = ah.state_dir(self.home, "ah-index")
        ah.summarize_agent_wal(wal, index)
        for cache in index.glob("wal-*.json"):
            doc = json.loads(cache.read_text())
            for k in ("note_at", "work_at"):
                doc.pop(k, None)
            cache.write_text(json.dumps(doc))
        summary = ah.summarize_agent_wal(wal, index)
        self.assertEqual(summary.get("note_at"), ah.parse_ts(iso(NOW - 3 * HOUR)))
        self.assertEqual(summary.get("work_at"), ah.parse_ts(iso(NOW - 2 * HOUR)))


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


class LaterResultTests(Base):
    """Receipt r2 F1: only a disposition at or after a result acknowledges it."""

    def resume_then_new_result(self, kind="resumed"):
        self.park_tick_on_ask()  # the other owner waits on its own user ask
        extra = {"until": iso(NOW + 3 * HOUR), "ref": "wa5b00000003"} if kind == "waiting" else {}
        if kind == "waiting":
            jl(self.w / "main.jsonl", [{"at": iso(NOW - 3 * HOUR), "event": "ask", "id": "wa5b00000003", "owner": "done1",
                                        "note": "need approval", "source": "user:x/y \"w\""}])
        self.dispose("done1", kind, "done1-early-" + kind, at=iso(NOW - 3 * HOUR), **extra)
        jl(self.w / "agent-done1.jsonl", [{"at": iso(NOW - 3 * HOUR + 60), "event": "intent", "note": "new work GoodQA goodqa#15944"},
                                          {"at": iso(NOW - 2 * HOUR), "event": "result", "note": "to main: second result ready"}])
        jl(self.w / "main.jsonl", [{"at": iso(NOW - 2 * HOUR + 5), "event": "subagent_stop", "agent_id": "done1",
                                    "agent_type": "task-owner"}])

    def check(self):
        a = self.assess()
        self.assertIn("done1", {s["agent"] for s in a["returned"]})
        self.assertTrue(a["all_waiting_on_user"])
        out = self.ig.cmd_stop({"session_id": SESSION, "stop_hook_active": False}, now=NOW)
        self.assertEqual(out.get("decision"), "block")
        self.assertIn("done1", out["reason"])

    def test_earlier_resume_does_not_acknowledge_a_later_result(self):
        self.resume_then_new_result("resumed")
        self.check()

    def test_earlier_wait_does_not_acknowledge_a_later_result(self):
        self.resume_then_new_result("waiting")
        self.check()

    def test_a_disposition_after_the_result_does_acknowledge_it(self):
        self.resume_then_new_result("resumed")
        self.dispose("done1", "resumed", "done1-late-res", at=iso(NOW - 60))
        self.assertNotIn("done1", {s["agent"] for s in self.assess()["returned"]})


class OwnWaitHandoffTests(Base):
    """Receipt r4 F1: an owner's own `waiting` disposition (no --ack-handoff) never hides an unacknowledged handoff;
    main's acknowledgement does. ah.owners() and assess() must agree."""

    def handoff_then_own_wait(self):
        self.park_tick_on_ask()  # the other owner waits on its own user ask
        jl(self.w / "main.jsonl", [{"at": iso(NOW - 3 * HOUR), "event": "ask", "id": "wa5b00000003", "owner": "done1",
                                    "note": "need approval", "source": "user:x/y \"w\""}])
        jl(self.w / "agent-done1.jsonl", [{"at": iso(NOW - 2 * HOUR), "event": "handoff", "note": "to main: PR ready"}])
        jl(self.w / "main.jsonl", [{"at": iso(NOW - 2 * HOUR + 5), "event": "subagent_stop", "agent_id": "done1",
                                    "agent_type": "task-owner"}])
        with mock.patch.dict(os.environ, {"AH_AGENT_ID": "done1"}):  # the owner records its own wait
            self.dispose("done1", "waiting", "done1-own-wait", at=iso(NOW - 2 * HOUR + 60), until=iso(NOW + 3 * HOUR),
                         ref="wa5b00000003")

    def row(self, now=NOW):
        return {r["agent_id"]: r for r in ah.owners(self.home, SESSION, now=now)["owners"]}["done1"]

    def stop(self):
        return self.ig.cmd_stop({"session_id": SESSION, "stop_hook_active": False}, now=NOW)

    def alerts(self):
        os.utime(self.w / "main.jsonl", (NOW, NOW))
        return ops_watch.check_idle_guard(ops_watch.load_config(self.home), {}, None, NOW)

    def test_own_wait_does_not_suppress_the_stop_block_or_the_idle_alert(self):
        self.handoff_then_own_wait()
        row = self.row()
        self.assertIn("handoff-unacked", row["flags"])
        self.assertTrue(row["decision_required"])
        a = self.assess()
        self.assertIn("done1", {s["agent"] for s in a["streams"]})
        self.assertTrue(a["idle"])
        out = self.stop()
        self.assertEqual(out.get("decision"), "block")
        self.assertIn("done1", out["reason"])
        self.assertEqual([x["key"] for x in self.alerts()], ["idle-guard:" + SESSION[:8]])

    def test_own_wait_does_not_suppress_a_fresh_handoff_either(self):  # before HANDOFF_ACK_S: attention, not a drop
        self.handoff_then_own_wait()
        later = NOW - 2 * HOUR + 600
        row = self.row(later)
        self.assertFalse(row["decision_required"])
        self.assertIn("result-unacked", row["attention"])
        self.assertIn("done1", {s["agent"] for s in self.ig.assess(self.home, SESSION, later)["returned"]})

    def test_mains_ack_suppresses_both(self):
        self.handoff_then_own_wait()
        import caller_identity  # noqa: PLC0415
        caller_identity.put_stamp("ack-handoff", ["done1"], home=self.home)  # what main's hook writes
        self.dispose("done1", "waiting", "done1-main-ack", at=iso(NOW - 60), until=iso(NOW + 3 * HOUR),
                     ref="wa5b00000003", ack_handoff=True)
        row = self.row()
        self.assertFalse(row["decision_required"])
        self.assertEqual(row["attention"], [])
        a = self.assess()
        self.assertEqual(a["streams"], [])
        self.assertEqual(a["user_waiters"], 2)
        self.assertEqual(self.stop(), {})
        self.assertEqual(self.alerts(), [])

    def test_own_wait_does_not_take_a_done_result(self):  # the same rule for a `result` (done), not only a handoff
        self.park_tick_on_ask()
        jl(self.w / "main.jsonl", [{"at": iso(NOW - 3 * HOUR), "event": "ask", "id": "wa5b00000003", "owner": "done1",
                                    "note": "need approval", "source": "user:x/y \"w\""}])
        with mock.patch.dict(os.environ, {"AH_AGENT_ID": "done1"}):
            self.dispose("done1", "waiting", "done1-own-wait2", until=iso(NOW + 3 * HOUR), ref="wa5b00000003")
        self.assertIn("result-unacked", self.row()["attention"])
        self.assertIn("done1", {s["agent"] for s in self.assess()["returned"]})
        self.assertEqual(self.stop().get("decision"), "block")


class OwnersAgreementPropertyTests(Base):
    """For a table of owner states, assess() reports an owner actionable exactly when ah.owners() marks it
    decision_required or gives it attention, and counts it as a user wait exactly when it is not actionable and waits
    on an open ask. The expected column proves the table spans both sides of the property."""

    def owner(self, agent, rows, stop=True):
        first = min(ah.parse_ts(r["at"]) for r in rows)
        last = max(ah.parse_ts(r["at"]) for r in rows)
        main = [{"at": iso(first - 30), "event": "subagent", "agent_id": agent, "agent_type": "task-owner"}]
        if stop:
            main.append({"at": iso(last + 5), "event": "subagent_stop", "agent_id": agent, "agent_type": "task-owner"})
        jl(self.w / "main.jsonl", main)
        jl(self.w / f"agent-{agent}.jsonl", rows)

    def ask(self, ask_id, owner):
        jl(self.w / "main.jsonl", [{"at": iso(NOW - 5 * HOUR), "event": "ask", "id": ask_id, "owner": owner,
                                    "note": "need approval", "source": "user:x/y \"w\""}])

    def main_ack(self, agent, key, ref):
        import caller_identity  # noqa: PLC0415
        caller_identity.put_stamp("ack-handoff", [agent], home=self.home)
        self.dispose(agent, "waiting", key, until=iso(NOW + 3 * HOUR), ref=ref, ack_handoff=True)

    def build(self):
        h = HOUR
        intent = lambda at, t="GoodQA goodqa#15950 work": {"at": iso(at), "event": "intent", "note": t}  # noqa: E731
        # tick (Base): stopped with no result -> DROPPED; done1 (Base): result 4 h ago, untaken
        self.owner("h_own", [intent(NOW - 3 * h), {"at": iso(NOW - 2 * h), "event": "handoff", "note": "to main: PR"}])
        self.ask("wa5b0000000a", "h_own")
        with mock.patch.dict(os.environ, {"AH_AGENT_ID": "h_own"}):
            self.dispose("h_own", "waiting", "h-own-wait-1", until=iso(NOW + 3 * h), ref="wa5b0000000a")
        self.owner("h_fresh", [intent(NOW - h), {"at": iso(NOW - 600), "event": "handoff", "note": "to main: PR"}])
        self.owner("d_acked", [intent(NOW - 3 * h), {"at": iso(NOW - 2 * h), "event": "result", "note": "to main: ok"}])
        self.ask("wa5b0000000b", "d_acked")
        self.main_ack("d_acked", "d-acked-ack-1", "wa5b0000000b")
        self.owner("d_old", [intent(NOW - 31 * h), {"at": iso(NOW - 30 * h), "event": "result", "note": "old"}])
        self.owner("t_disp", [intent(NOW - 3 * h)])
        self.dispose("t_disp", "waiting", "t-disp-wait-1", until=iso(NOW + 3 * h), ref="GoodQA goodqa#15943")
        self.owner("t_note", [intent(NOW - 3 * h), {"at": iso(NOW - 3 * h + 30), "event": "status",
                                                     "note": "blocked, waiting on GoodQA goodqa#15943"}])
        self.ask("wa5b0000000c", "a_own")
        self.owner("a_own", [intent(NOW - 3 * h), {"at": iso(NOW - 3 * h + 30), "event": "status",
                                                    "note": "blocked, waiting on wa5b0000000c"}])
        self.owner("a_foreign", [intent(NOW - 3 * h), {"at": iso(NOW - 3 * h + 30), "event": "status",
                                                        "note": "blocked, waiting on wa5b0000000b"}])
        self.owner("live1", [intent(NOW - 60)], stop=False)
        self.owner("retired", [intent(NOW - 3 * h), {"at": iso(NOW - 3 * h + 30), "event": "status",
                                                      "note": "blocked, waiting on GoodQA goodqa#15943"}])
        with mock.patch.object(ah, "_ticket_exists", return_value=True):
            self.dispose("retired", "wontdo", "retired-wontdo-1", ref="GoodQA goodqa#15943",
                         reason="verified that nobody will do this and the scope was dropped by main")
        self.owner("r_later", [intent(NOW - 4 * h)])
        self.dispose("r_later", "resumed", "r-later-res-1", at=iso(NOW - 3 * h))
        jl(self.w / "agent-r_later.jsonl", [{"at": iso(NOW - 2 * h), "event": "result", "note": "to main: second"}])
        jl(self.w / "main.jsonl", [{"at": iso(NOW - 2 * h + 5), "event": "subagent_stop", "agent_id": "r_later",
                                    "agent_type": "task-owner"}])
        # expected: (actionable, user wait)
        return {"tick": (True, False), "done1": (True, False), "h_own": (True, False), "h_fresh": (True, False),
                "d_acked": (False, True), "d_old": (False, False), "t_disp": (True, False), "t_note": (True, False),
                "a_own": (False, True), "a_foreign": (True, False), "live1": (False, False), "retired": (False, False),
                "r_later": (True, False)}

    def test_assess_agrees_with_owners_for_every_row(self):
        expected = self.build()
        rows = {r["agent_id"]: r for r in ah.owners(self.home, SESSION, now=NOW)["owners"] if r["owner"]}
        self.assertEqual(set(rows), set(expected))
        a = self.assess()
        streams = {s["agent"] for s in a["streams"]}
        for agent, r in rows.items():
            with self.subTest(agent=agent, state=r["state"], attention=r["attention"], flags=r["flags"]):
                says = bool(r["decision_required"] or r["attention"])
                self.assertEqual(agent in streams, says)  # the property
                self.assertEqual(says, expected[agent][0])  # the table is what it claims to be
                user_wait = not says and bool(r.get("wait_on")) and bool(ah.ASK_ID_RE.match(r["wait_on"]))
                self.assertEqual(user_wait, expected[agent][1])
        self.assertEqual(a["user_waiters"], sum(1 for v in expected.values() if v[1]))
        self.assertEqual({s["agent"] for s in a["returned"]}, {"done1", "h_own", "h_fresh", "r_later"})


class OwnersAckOrderingTests(Base):
    """Receipt r5: ah.owners() direct cases from raw WAL and ledger records (assess() consumes owners(), so the
    agreement property cannot catch an ordering bug). F1: only a disposition at or after the specific result takes
    it. F2: the result's own time, not the owner's latest activity, orders the ack and ages the result."""

    def owner(self, agent, rows, stop_at):
        first = min(ah.parse_ts(r["at"]) for r in rows)
        jl(self.w / "main.jsonl", [{"at": iso(first - 30), "event": "subagent", "agent_id": agent, "agent_type": "task-owner"},
                                   {"at": iso(stop_at), "event": "subagent_stop", "agent_id": agent, "agent_type": "task-owner"}])
        jl(self.w / f"agent-{agent}.jsonl", rows)

    def rows(self):
        return {r["agent_id"]: r for r in ah.owners(self.home, SESSION, now=NOW)["owners"]}

    def test_a_disposition_before_the_result_never_takes_it(self):  # F1 boundaries
        result = NOW - 2 * HOUR
        cases = {"b1": (-1, "result"), "b5": (-5, "result"), "b10": (-10, "result"), "h5": (-5, "handoff"),
                 "a0": (0, "result"), "a1": (1, "result"), "ha0": (0, "handoff")}
        for agent, (delta, event) in cases.items():
            self.owner(agent, [{"at": iso(result - 3600), "event": "intent", "note": "GoodQA goodqa#15951 work"},
                               {"at": iso(result), "event": event, "note": "to main: ready"}], stop_at=result + 20)
            self.dispose(agent, "resumed", f"{agent}-res-ack-1", at=iso(result + delta))
        rows = self.rows()
        for agent, (delta, event) in cases.items():
            with self.subTest(agent=agent, delta=delta, event=event):
                r = rows[agent]
                self.assertEqual(r["state"], "done" if event == "result" else "handoff")
                if delta < 0:
                    self.assertIn("result-unacked", r["attention"])
                    if event == "handoff":
                        self.assertTrue(r["decision_required"])
                else:
                    self.assertNotIn("result-unacked", r["attention"])
                    self.assertFalse(r["decision_required"])
        streams = {s["agent"] for s in self.assess()["streams"]}
        self.assertTrue({"b1", "b5", "b10", "h5"} <= streams)
        self.assertFalse({"a0", "a1", "ha0"} & streams)

    def test_a_later_owner_note_does_not_revoke_mains_ack(self):  # F2
        t = NOW - 2 * HOUR
        self.owner("acked", [{"at": iso(t - 3600), "event": "intent", "note": "GoodQA goodqa#15952 work"},
                             {"at": iso(t), "event": "result", "note": "to main: ready"},
                             {"at": iso(t + 60), "event": "status", "note": "notes tidied"}], stop_at=t + 65)
        self.dispose("acked", "resumed", "acked-res-ack-1", at=iso(t + 30))
        r = self.rows()["acked"]
        self.assertEqual(r["state"], "done")
        self.assertEqual(r["attention"], [])
        self.assertEqual(r["result_at"], ah.iso(t))
        self.assertNotIn("acked", {s["agent"] for s in self.assess()["streams"]})

    def test_a_later_owner_note_does_not_revoke_mains_handoff_ack(self):  # F2 for a handoff and main's --ack-handoff
        import caller_identity  # noqa: PLC0415
        t = NOW - 2 * HOUR
        self.owner("hacked", [{"at": iso(t - 3600), "event": "intent", "note": "GoodQA goodqa#15953 work"},
                              {"at": iso(t), "event": "handoff", "note": "to main: PR"},
                              {"at": iso(t + 60), "event": "check", "note": "lint ok"}], stop_at=t + 65)
        jl(self.w / "main.jsonl", [{"at": iso(t - 600), "event": "ask", "id": "wa5b0000000d", "owner": "hacked",
                                    "note": "need approval", "source": "user:x/y \"w\""}])
        caller_identity.put_stamp("ack-handoff", ["hacked"], home=self.home)
        self.dispose("hacked", "waiting", "hacked-ack-1", at=iso(t + 30), until=iso(NOW + HOUR), ref="wa5b0000000d",
                     ack_handoff=True)
        r = self.rows()["hacked"]
        self.assertEqual(r["attention"], [])
        self.assertFalse(r["decision_required"])

    def test_an_old_result_stays_old_after_a_later_note(self):  # F2: the 24 h window runs from the result
        t = NOW - 30 * HOUR
        self.owner("stale", [{"at": iso(t - 3600), "event": "intent", "note": "GoodQA goodqa#15954 work"},
                             {"at": iso(t), "event": "result", "note": "to main: ready"},
                             {"at": iso(NOW - HOUR), "event": "status", "note": "still here"}], stop_at=NOW - HOUR + 5)
        r = self.rows()["stale"]
        self.assertEqual(r["state"], "done")
        self.assertNotIn("result-unacked", r["attention"])

    def test_a_cached_summary_from_before_result_at_is_rebuilt(self):  # an upgrade keeps no stale index
        t = NOW - 2 * HOUR
        self.owner("cached", [{"at": iso(t - 3600), "event": "intent", "note": "GoodQA goodqa#15955 work"},
                              {"at": iso(t), "event": "result", "note": "to main: ready"}], stop_at=t + 20)
        self.rows()
        for f in ah.state_dir(self.home, "ah-index").glob("wal-*.json"):
            s = json.loads(f.read_text())
            s.pop("outcome_at", None)
            f.write_text(json.dumps(s))
        self.assertEqual(self.rows()["cached"]["result_at"], ah.iso(t))

    def test_sub_second_result_time_is_compared_at_ledger_precision(self):  # like with like (ledger: whole seconds)
        t = NOW - 2 * HOUR
        for agent, delta in (("same_sec", 0), ("prev_sec", -1)):
            self.owner(agent, [{"at": iso(t - 3600), "event": "intent", "note": "GoodQA goodqa#15956 work"},
                               {"at": iso(t).replace("+00:00", ".700000+00:00"), "event": "result", "note": "ready"}],
                       stop_at=t + 20)
            self.dispose(agent, "resumed", f"{agent}-res-1", at=iso(t + delta))
        rows = self.rows()
        self.assertEqual(rows["same_sec"]["attention"], [])  # same second: cannot be ordered, counts as after
        self.assertIn("result-unacked", rows["prev_sec"]["attention"])


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
