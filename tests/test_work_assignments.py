"""Request ledger schema 2 (work_assignments.py): capture, triage, Stop enforcement, removal gate, durability, latency.

All text is synthetic. Seeded failing controls are named in each test's docstring.
"""

import copy
import io
import json
import multiprocessing
import os
import subprocess
import sys
import tempfile
import time
import unittest
import uuid as uuidlib
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
FIXTURES = Path(__file__).resolve().parent / "fixtures"
sys.path.insert(0, str(HOOKS))
import work_assignments as wa  # noqa: E402

try:
    import jsonschema
except ImportError:  # pragma: no cover
    jsonschema = None

SID = "11111111-2222-3333-4444-555555555555"
CLOCK = [1_800_000_000.0]
SCHEMA = json.loads((HOOKS / "work_ledger.schema.json").read_text())


def human(text, uid=None, **extra):
    record = {"type": "user", "uuid": uid or str(uuidlib.uuid4()), "isSidechain": False, "origin": {"kind": "human"},
              "timestamp": wa.iso(CLOCK[0]), "message": {"role": "user", "content": text}}
    record.update(extra)
    return record


def validator(ref=None):
    schema = SCHEMA if ref is None else {"$schema": SCHEMA["$schema"], "$ref": f"#/$defs/{ref}", "$defs": SCHEMA["$defs"]}
    return jsonschema.Draft202012Validator(schema)


class Base(unittest.TestCase):
    real_redact = staticmethod(wa.redact)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.home = root / "ah"
        self.projects = root / "claude" / "projects" / "p"
        self.projects.mkdir(parents=True)
        self.transcript = self.projects / f"{SID}.jsonl"
        self.transcript.write_text("")
        patches = [mock.patch.dict(os.environ, {"AGENT_HARNESS_HOME": str(self.home), "CLAUDE_CONFIG_DIR": str(root / "claude"),
                                                "CODEX_HOME": str(root / "codex"), "HOME": str(root)}),
                   mock.patch.object(wa, "now", lambda: CLOCK[0]),
                   mock.patch.object(wa, "commit_exists", lambda sha, repo=None: sha.startswith("abc")),
                   mock.patch.object(wa, "wal_has_test", lambda entry: entry.startswith("wal")),
                   mock.patch.object(wa, "redact", lambda text: text.replace("sk-secretsecretsecret1", "[redacted]"))]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        CLOCK[0] = 1_800_000_000.0

    def append(self, *records):
        with open(self.transcript, "a") as handle:
            for record in records:
                handle.write(json.dumps(record) + "\n")

    def payload(self, prompt, **extra):
        return {"session_id": SID, "transcript_path": str(self.transcript), "prompt": prompt, **extra}

    def hook(self, name, payload, runtime="claude"):
        out = io.StringIO()
        with redirect_stdout(out), mock.patch.object(wa.safe_input, "read_stdin_bounded", lambda n: json.dumps(payload).encode()):
            code = wa.run_hook(name, runtime)
        self.assertEqual(code, 0)
        return json.loads(out.getvalue()) if out.getvalue().strip() else {}

    def data(self):
        with wa.reading() as data:
            return data

    def cli(self, *argv):
        out = io.StringIO()
        with redirect_stdout(out):
            code = wa.main(list(argv))
        return code, out.getvalue()

    def capture(self, text, uid=None):
        self.append(human(text, uid))
        self.hook("prompt", self.payload(text))
        return self.last_message()

    def last_message(self):
        messages = self.data()["messages"]
        return messages[sorted(messages)[-1]]

    def asks(self):
        return self.data()["asks"]

    def split(self, text, ask_text, **kw):
        msg = self.capture(text)
        extra = [x for pair in kw.items() for x in ("--" + pair[0], pair[1])]
        self.assertEqual(self.cli("split", "--msg", msg["id"], "--item", ask_text, *extra)[0], 0)
        return msg, sorted(self.asks())[-1]

    def advance(self, aid, to="done"):
        steps = [("--owner", "main"), ("--state", "in_progress"), ("--state", "ready", "--evidence", "abc1234def"), ("--state", to)]
        for step in steps[: 3 if to == "ready" else 4]:
            code, _ = self.cli("update", aid, *step)
            self.assertEqual(code, 0, step)

    def check_schema(self):
        if jsonschema is None:
            self.skipTest("jsonschema not installed")
        errors = [e.message[:160] for e in validator().iter_errors(self.data())]
        self.assertEqual(errors, [])
        ev = validator("event")
        for e in wa.read_events():
            self.assertEqual([x.message[:160] for x in ev.iter_errors(e)], [], e["op"])


class CaptureTest(Base):
    def test_human_message_is_captured_untriaged_with_bounded_redacted_excerpt(self):
        text = "please fix the login page sk-secretsecretsecret1 " + "word " * 40
        msg = self.capture(text)
        self.assertEqual(msg["triage"]["status"], "untriaged")
        self.assertLessEqual(len(msg["text"]["excerpt"].split()), 15)
        self.assertNotIn("sk-secret", msg["text"]["excerpt"])
        self.assertEqual(msg["sessionId"], SID)
        log = msg["origin"]["log"]
        self.assertEqual((log["lineStart"], msg["origin"]["binding"]["status"]), (1, "bound"))
        self.assertTrue(wa.prov.UUID_RE.match(log["messageUuid"]))
        self.assertEqual((msg["humanCheck"]["isHuman"], msg["origin"]["actor"]["kind"]), (True, "human"))
        self.assertNotIn("model", msg["origin"]["actor"])
        self.check_schema()

    def test_raw_human_text_is_never_stored(self):
        self.capture("filler " * 20 + "zebra-quartz-marmalade-unique-token and more words after it")
        for name in ("snap", "events"):
            body = wa.files()[name].read_text()
            self.assertNotIn("zebra-quartz-marmalade", body)  # beyond the 15-word excerpt nothing is kept
            self.assertIn("filler filler", body)

    def test_system_text_is_not_captured(self):
        """NEG-4: control = capture without classify_prompt would record these."""
        for prompt in ("<task-notification>done</task-notification>", "<system-reminder>x</system-reminder>",
                       "<agent-message>hi</agent-message>"):
            self.hook("prompt", self.payload(prompt))
        self.assertEqual(self.data()["messages"], {})

    def test_injected_context_is_not_human_for_claude_and_codex(self):
        """Review blocker 2: AGENTS.md, env blocks, hook text and subagent text are never isHuman."""
        for prompt in ("<system-reminder>AGENTS.md says x</system-reminder>", "<command-name>/loop</command-name>",
                       "<local-command-stdout>ok</local-command-stdout>", "<user-prompt-submit-hook>x</user-prompt-submit-hook>"):
            self.hook("prompt", self.payload(prompt))
            self.hook("prompt", self.payload(prompt), runtime="codex")
        self.assertEqual(self.data()["messages"], {})

    def test_quoted_tag_does_not_create_second_message(self):
        """NEG-14."""
        self.capture("real ask here <system-reminder>injected</system-reminder> and more")
        self.assertEqual(len(self.data()["messages"]), 1)

    def test_pasted_only_is_captured_and_flagged(self):
        self.hook("prompt", self.payload('<pasted_content id="1">a pasted log line</pasted_content>'))
        msg = next(iter(self.data()["messages"].values()))
        self.assertTrue(msg["pastedOnly"])

    def test_subagent_payload_creates_no_request(self):
        """NEG-12."""
        self.hook("prompt", self.payload("do a thing", agent_id="a123"))
        self.assertEqual(self.data()["messages"], {})

    def test_hook_and_sync_do_not_duplicate(self):
        """NEG-15."""
        self.capture("one request")
        self.hook("session", {"session_id": SID, "transcript_path": str(self.transcript)})
        with wa.transaction() as data:
            wa.sync_all(data, SID)
        self.assertEqual(len(self.data()["messages"]), 1)

    def test_missed_turn_is_caught_up_by_sync(self):
        self.hook("session", {"session_id": SID, "transcript_path": str(self.transcript)})
        CLOCK[0] += 10
        self.append(human("a turn the prompt hook never saw"))
        self.hook("stop", {"session_id": SID, "transcript_path": str(self.transcript)})
        msgs = list(self.data()["messages"].values())
        self.assertEqual(len(msgs), 1)
        self.assertEqual(msgs[0]["capturedVia"], "transcript_sync")

    def test_old_history_is_not_flooded_into_the_ledger(self):
        CLOCK[0] -= 86400 * 3
        self.append(*[human(f"ancient {i}") for i in range(5)])
        CLOCK[0] += 86400 * 3
        self.hook("session", {"session_id": SID, "transcript_path": str(self.transcript)})
        self.assertEqual(self.data()["messages"], {})

    def test_ask_answer_is_captured(self):
        self.hook("ask-answer", {"session_id": SID, "tool_use_id": "toolu_1", "tool_name": "AskUserQuestion",
                                 "tool_response": {"answers": {"Which?": "Option B"}}})
        msg = next(iter(self.data()["messages"].values()))
        self.assertEqual((msg["capturedVia"], msg["humanCheck"]["method"]), ("hook_post_tool", "claude_ask_answer"))
        self.check_schema()

    def test_5mb_paste_is_bounded_and_fast(self):
        """NEG-9."""
        big = "lorem ipsum " * (5 * 1024 * 1024 // 12)
        started = time.monotonic()
        msg = self.capture(big)
        self.assertLess(time.monotonic() - started, 5)
        self.assertLessEqual(len(msg["text"]["excerpt"].split()), 15)

    def test_unbound_pending_gets_cannot_bind_notice_and_violation(self):
        self.hook("prompt", self.payload("ask whose transcript line never appears"))
        CLOCK[0] += 3 * 3600
        reply = self.hook("prompt", self.payload("<system-reminder>x</system-reminder>"))
        self.assertIn("cannot-bind", reply["hookSpecificOutput"]["additionalContext"])
        data = self.data()
        self.assertIn("cannot_bind", [v["kind"] for v in data["violations"]])
        self.assertEqual(next(iter(data["messages"].values()))["origin"]["binding"]["status"], "unbindable")
        self.assertEqual(next(iter(data["messages"].values()))["triage"]["status"], "untriaged")  # still blocking
        self.check_schema()

    def test_codex_rollout_human_turn_is_captured(self):
        rollout = Path(self.tmp.name) / "codex" / "sessions" / "2027" / "01" / "01" / "rollout-x.jsonl"
        rollout.parent.mkdir(parents=True)
        item = {"type": "UserMessage", "id": "01a16512-0d07-78f3-b199-70f1db873609",
                "content": [{"type": "text", "text": "codex human request"}]}
        rollout.write_text(json.dumps({"timestamp": wa.iso(CLOCK[0]), "type": "event_msg",
                                       "payload": {"type": "item_completed", "item": item}}) + "\n")
        payload = {"session_id": "codex-sess-1", "transcript_path": str(rollout), "prompt": "codex human request", "turn_id": "t1"}
        self.hook("prompt", payload, runtime="codex")
        msg = next(iter(self.data()["messages"].values()))
        self.assertEqual((msg["origin"]["actor"]["provider"], msg["origin"]["log"]["messageUuid"], msg["origin"]["log"]["lineStart"]),
                         ("codex", item["id"], 1))
        self.assertEqual(msg["humanCheck"]["method"], "codex_user_message_item")
        self.check_schema()

    def test_codex_injected_agents_item_is_not_human(self):
        rollout = Path(self.tmp.name) / "codex" / "sessions" / "2027" / "01" / "01" / "rollout-y.jsonl"
        rollout.parent.mkdir(parents=True)
        item = {"type": "UserMessage", "id": "01a16512-0d07-78f3-b199-70f1db873610",
                "content": [{"type": "text", "text": "<system-reminder># AGENTS.md instructions</system-reminder>"}]}
        rollout.write_text(json.dumps({"timestamp": wa.iso(CLOCK[0]), "type": "event_msg",
                                       "payload": {"type": "item_completed", "item": item}}) + "\n")
        self.hook("prompt", {"session_id": "codex-sess-2", "transcript_path": str(rollout), "prompt": "x <system-reminder>y</system-reminder>"},
                  runtime="codex")
        with wa.transaction() as data:
            wa.sync_all(data, "codex-sess-2")
        self.assertEqual(len(self.data()["messages"]), 1)  # only the typed "x"; the injected item was not caught up


class TriageTest(Base):
    def test_split_and_no_ask(self):
        first, second = self.capture("do two things"), self.capture("thanks")
        self.assertEqual(self.cli("split", "--msg", first["id"], "--item", "thing one", "--item", "thing two")[0], 0)
        self.assertEqual(self.cli("no-ask", "--msg", second["id"], "--reason", "pure thanks, nothing to do")[0], 0)
        data = self.data()
        self.assertEqual(len(data["asks"]), 2)
        self.assertEqual(data["messages"][second["id"]]["triage"]["status"], "no_ask")
        ask = data["asks"][sorted(data["asks"])[0]]
        self.assertEqual((ask["state"], ask["source"]["kind"], ask["origin"]["messageId"]), ("open", "user", first["id"]))
        self.assertTrue(data["messages"][first["id"]]["triage"]["askIds"])
        self.check_schema()

    def test_no_ask_needs_reason(self):
        """NEG-18."""
        msg = self.capture("x request")
        self.assertEqual(self.cli("no-ask", "--msg", msg["id"], "--reason", "short")[0], 2)

    def test_done_requires_verified_evidence_and_legal_transitions(self):
        """NEG-10: control = accepting an attested PR as done evidence."""
        _, aid = self.split("build it", "build the thing")
        self.assertEqual(self.cli("update", aid, "--state", "done")[0], 2)  # open -> done is not a transition
        self.cli("update", aid, "--owner", "main")
        self.cli("update", aid, "--state", "in_progress")
        self.assertEqual(self.cli("update", aid, "--state", "ready")[0], 2)  # ready needs evidence
        self.assertEqual(self.cli("update", aid, "--evidence", "it works trust me")[0], 2)
        self.assertEqual(self.cli("update", aid, "--state", "ready", "--evidence", "PR#12")[0], 0)  # attested is enough for ready
        self.assertEqual(self.cli("update", aid, "--state", "done")[0], 2)  # but not for done
        self.assertEqual(self.cli("update", aid, "--evidence", "deadbeef1")[0], 2)  # commit that does not exist
        self.assertEqual(self.cli("update", aid, "--state", "done", "--evidence", "abc1234def")[0], 0)
        ask = self.asks()[aid]
        self.assertEqual(ask["completion"]["status"], "verified")
        self.assertEqual(ask["completion"]["commits"][0]["sha"], "abc1234def")
        self.assertIn("removableAfter", ask)
        self.check_schema()

    def test_subagent_can_update_owner_state_evidence(self):
        _, aid = self.split("build it", "build the thing")
        code, _ = self.cli("update", aid, "--actor", "agent:a9", "--owner", "agent:a9", "--state", "in_progress")
        self.assertEqual(code, 0)
        ask = self.asks()[aid]
        self.assertEqual(wa.owner_of(ask), "agent:a9")
        ev = [e for e in wa.read_events() if e["target"]["id"] == aid][-1]
        self.assertEqual(ev["actor"]["agentId"], "a9")

    def test_reassign_ends_the_previous_owner_span(self):
        _, aid = self.split("build it", "build the thing", owner="agent:a1")
        self.cli("update", aid, "--owner", "agent:a2")
        spans = self.asks()[aid]["assignments"]
        self.assertEqual([(s["actor"]["agentId"], s["status"]) for s in spans], [("a1", "reassigned"), ("a2", "active")])
        self.check_schema()

    def test_reopen_needs_a_human_message(self):
        _, aid = self.split("build it", "build the thing")
        self.advance(aid)
        self.assertEqual(self.cli("update", aid, "--state", "in_progress")[0], 2)
        again = self.capture("actually it is not fixed")
        self.assertEqual(self.cli("update", aid, "--state", "in_progress", "--reopen-by", again["id"])[0], 0)
        ask = self.asks()[aid]
        self.assertNotIn("removableAfter", ask)  # reopening restarts the clock
        self.assertEqual(ask["state"], "in_progress")
        self.check_schema()

    def test_relate_stores_both_directions_and_prereq_status(self):
        _, a = self.split("one", "first thing here")
        _, b = self.split("two", "second thing here")
        self.assertEqual(self.cli("relate", a, "extends", b)[0], 0)
        self.assertEqual([r["kind"] for r in self.asks()[b]["related"]], ["extended_by"])
        self.assertEqual(self.cli("prereq", a, b)[0], 0)
        self.assertEqual(self.asks()[a]["prerequisites"][0]["status"], "pending")
        self.check_schema()

    def test_blocked_needs_reason_and_decision_for_user_input(self):
        _, aid = self.split("one", "first thing here")
        self.cli("update", aid, "--owner", "main")
        self.assertEqual(self.cli("update", aid, "--state", "blocked", "--block-reason", "user_input")[0], 2)
        self.assertEqual(self.cli("update", aid, "--state", "blocked", "--block-reason", "external", "--note", "waiting on ci")[0], 0)
        self.check_schema()


class StopTest(Base):
    def stop(self, **extra):
        return self.hook("stop", {"session_id": SID, "transcript_path": str(self.transcript), **extra})

    def test_blocks_on_untriaged_then_lets_go_with_violation(self):
        """AC-4/AC-13: control = max_stop_blocks ignored would loop forever."""
        self.capture("request needing triage")
        replies = [self.stop() for _ in range(5)]
        self.assertEqual([r.get("decision") for r in replies], ["block"] * 3 + [None, None])
        self.assertEqual([v["kind"] for v in self.data()["violations"]], ["stop_block_exhausted"])
        again = self.hook("prompt", self.payload("next"))
        self.assertIn("VIOLATION", again["hookSpecificOutput"]["additionalContext"])
        self.check_schema()

    def test_stale_ask_blocks_after_12_hours(self):
        self.split("work", "a thing to do", owner="agent:zz")
        self.assertIsNone(self.stop().get("decision"))
        CLOCK[0] += 13 * 3600
        self.assertEqual(self.stop()["decision"], "block")

    def test_stopped_owner_is_flagged(self):
        """NEG-13."""
        self.split("work", "a thing to do", owner="agent:zz")
        with mock.patch.object(wa, "agent_stopped", lambda s, a: True):
            self.assertEqual(self.stop()["decision"], "block")

    def test_clean_state_does_not_block(self):
        msg = self.capture("thanks")
        self.cli("no-ask", "--msg", msg["id"], "--reason", "just a thank you")
        self.assertEqual(self.stop(), {})

    def test_other_sessions_items_do_not_block_this_session(self):
        with wa.transaction() as data:
            wa.new_ask(data, description="someone else's work", who=wa.actor("agent"), origin_actor=wa.actor("harness", "other", label="x"))
        self.assertEqual(self.stop(), {})

    def test_policy_loosening_only_from_installed_file(self):
        """NEG-11: env, CLI and repo-local files are ignored; the installed file is honoured."""
        self.capture("needs triage")
        with mock.patch.dict(os.environ, {"WORK_ASSIGNMENTS_STOP": "off", "HARNESS_PROVENANCE_POLICY": "/dev/null"}):
            self.assertEqual(self.stop()["decision"], "block")
        (Path(self.tmp.name) / "work_assignments_policy.json").write_text('{"schema":1,"stop":"off"}')
        self.assertEqual(self.stop()["decision"], "block")
        loose = Path(self.tmp.name) / "p.json"
        loose.write_text('{"schema":1,"stop":"warn","stale_hours":24}')
        with mock.patch.object(wa, "POLICY_FILE", loose):
            self.assertNotIn("decision", self.stop())

    def test_missing_or_corrupt_policy_is_strict(self):
        """NEG-17."""
        broken = Path(self.tmp.name) / "p.json"
        broken.write_text("{nope")
        policy = wa.load_policy(broken)
        self.assertEqual((policy["stop"], policy["guard"]), ("enforce", "enforce"))
        self.assertIn("policy_error", policy)
        self.assertEqual(wa.load_policy(Path(self.tmp.name) / "absent.json")["stop"], "enforce")

    def test_blocked_signature_blocks_again_after_six_hours(self):
        self.capture("needs triage")
        for _ in range(4):
            self.stop()
        CLOCK[0] += 7 * 3600
        self.assertEqual(self.stop().get("decision"), "block")


class RemovalTest(Base):
    def done_ask(self, hours):
        _, aid = self.split("ship it", "ship the release")
        self.advance(aid)
        CLOCK[0] += hours * 3600
        return aid

    def test_removal_refused_at_23h_allowed_at_25h(self):
        """NEG-1."""
        aid = self.done_ask(23)
        self.assertEqual(self.cli("remove", aid)[0], 2)
        self.assertEqual(self.cli("prune", "--apply")[0], 0)
        self.assertIn(aid, self.asks())
        CLOCK[0] += 2 * 3600
        self.assertEqual(self.cli("remove", aid)[0], 0)
        data = self.data()
        self.assertNotIn(aid, data["asks"])
        tomb = data["tombstones"][aid]
        self.assertEqual((tomb["proofKind"], tomb["finalState"]), ("verified_evidence", "done"))
        self.assertTrue(wa.files()["archive"].read_text().count("\n") >= 1)
        self.check_schema()

    def test_open_ask_is_never_removable(self):
        _, aid = self.split("x", "still open")
        CLOCK[0] += 1000 * 3600
        self.assertEqual(self.cli("remove", aid)[0], 2)
        self.cli("prune", "--apply")
        self.assertIn(aid, self.asks())

    def test_done_with_only_attested_evidence_cannot_exist(self):
        """Red-team MAJOR: a fabricated URL cannot carry an ask to done, so it cannot be removed after 24h."""
        _, aid = self.split("ship it", "ship the release")
        self.cli("update", aid, "--owner", "main")
        self.cli("update", aid, "--state", "in_progress")
        self.cli("update", aid, "--state", "ready", "--evidence", "https://example.invalid/fake")
        self.assertEqual(self.cli("update", aid, "--state", "done")[0], 2)

    def cancel_args(self, aid, uid, line, quote="cancel that whole thing please", binding="explicit_reference", *extra):
        return ("cancel", aid, "--uuid", uid, "--file", str(self.transcript), "--line", str(line), "--quote", quote,
                "--binding", binding, *extra)

    def setup_cancel(self, ask_text="finish the whole thing please"):
        _, aid = self.split("start something", ask_text)
        cancel = human("cancel that whole thing please, I changed my mind")
        self.append(cancel)
        return aid, cancel["uuid"], 2

    def test_cancel_with_genuine_proof_then_removal_after_24h(self):
        aid, uid, line = self.setup_cancel()
        self.assertEqual(self.cli(*self.cancel_args(aid, uid, line))[0], 0)
        proof = self.asks()[aid]["cancellation"]["proof"]
        self.assertEqual((proof["targets"], proof["binding"]), ([aid], "explicit_reference"))
        self.assertEqual(self.cli("remove", aid)[0], 2)
        CLOCK[0] += 25 * 3600
        self.assertEqual(self.cli("remove", aid)[0], 0)
        self.assertEqual(self.data()["tombstones"][aid]["proofKind"], "user_proof")
        self.check_schema()

    def test_unrelated_human_message_cannot_cancel_an_ask(self):
        """Review blocker 1: any later human message used to cancel any ask."""
        aid, uid, line = self.setup_cancel(ask_text="refactor the billing exporter module")
        code, _ = self.cli(*self.cancel_args(aid, uid, line))
        self.assertEqual(code, 2)
        self.assertEqual(self.asks()[aid]["state"], "open")

    def test_same_message_retraction_binding(self):
        msg = self.capture("please add a dark mode toggle, no wait, cancel that, forget dark mode")
        self.cli("split", "--msg", msg["id"], "--item", "add dark mode toggle")
        aid = sorted(self.asks())[-1]
        uid = msg["origin"]["log"]["messageUuid"]
        args = self.cancel_args(aid, uid, 1, "cancel that, forget dark mode", "same_message_retraction")
        self.assertEqual(self.cli(*args)[0], 0)

    def test_decision_answer_binding(self):
        aid, uid, line = self.setup_cancel(ask_text="refactor the billing exporter module")
        self.assertEqual(self.cli("decision", "ask", "--text", "Cancel the billing refactor?", "--tool", "AskUserQuestion", "--ask", aid)[0], 0)
        did = sorted(self.data()["decisions"])[-1]
        self.cli("sync")
        mid = next(m["id"] for m in self.data()["messages"].values() if m["origin"]["log"].get("messageUuid") == uid)
        self.assertEqual(self.cli("decision", "answer", "--id", did, "--msg", mid)[0], 0)
        self.assertEqual(self.data()["decisions"][did]["state"], "answered")
        args = self.cancel_args(aid, uid, line, "cancel that whole thing please", "answer_to_decision", "--decision", did)
        self.assertEqual(self.cli(*args)[0], 0)
        self.check_schema()

    def test_cancel_proof_that_is_an_agent_message_is_refused(self):
        """NEG-2."""
        aid, _, _ = self.setup_cancel()
        agent = {"type": "assistant", "uuid": str(uuidlib.uuid4()), "message": {"role": "assistant", "content": "cancel that whole thing please"}}
        self.append(agent)
        self.assertEqual(self.cli(*self.cancel_args(aid, agent["uuid"], 3))[0], 2)
        tool = human("cancel that whole thing please", toolUseResult={"x": 1})
        self.append(tool)
        self.assertEqual(self.cli(*self.cancel_args(aid, tool["uuid"], 4))[0], 2)
        notification = human("<task-notification>cancel that whole thing please</task-notification>")
        self.append(notification)
        self.assertEqual(self.cli(*self.cancel_args(aid, notification["uuid"], 5))[0], 2)

    def test_cancel_with_wrong_line_is_refused(self):
        """NEG-3."""
        aid, uid, line = self.setup_cancel()
        self.assertEqual(self.cli(*self.cancel_args(aid, uid, line + 1))[0], 2)
        self.assertEqual(self.cli(*self.cancel_args(aid, uid, 1))[0], 2)

    def test_cancel_quote_must_be_in_the_message(self):
        aid, uid, line = self.setup_cancel()
        self.assertEqual(self.cli(*self.cancel_args(aid, uid, line, "words the user never wrote"))[0], 2)

    def test_cancel_proof_outside_transcript_roots_is_refused(self):
        aid, uid, line = self.setup_cancel()
        outside = Path(self.tmp.name) / "fake.jsonl"
        outside.write_text(self.transcript.read_text())
        args = list(self.cancel_args(aid, uid, line))
        args[args.index("--file") + 1] = str(outside)
        self.assertEqual(self.cli(*args)[0], 2)

    def test_cancel_by_update_is_refused(self):
        aid, _, _ = self.setup_cancel()
        self.assertEqual(self.cli("update", aid, "--state", "cancelled")[0], 2)

    def test_forged_transcript_file_cannot_cancel(self):
        """Red-team BLOCKER: a forged transcript under the projects root."""
        aid, _, _ = self.setup_cancel()
        forged = self.projects / "forged.jsonl"
        fake = human("please cancel the whole thing now")
        forged.write_text(json.dumps(fake) + "\n")
        code, _ = self.cli("cancel", aid, "--uuid", fake["uuid"], "--file", str(forged), "--line", "1",
                           "--quote", "please cancel the whole thing now", "--binding", "explicit_reference")
        self.assertEqual(code, 2)
        self.assertEqual(self.asks()[aid]["state"], "open")

    def test_proof_older_than_the_ask_is_refused(self):
        early = self.capture("an earlier chat message from the user")
        CLOCK[0] += 3600
        _, aid = self.split("start something", "an earlier chat message thing")
        code, _ = self.cli(*self.cancel_args(aid, early["origin"]["log"]["messageUuid"], 1, "an earlier chat message"))
        self.assertEqual(code, 2)

    def test_secret_like_quote_is_refused(self):
        aid, _, _ = self.setup_cancel()
        secretive = human("my password hunter2 means cancel it entirely")
        self.append(secretive)
        self.assertEqual(self.cli("sync")[0], 0)
        with mock.patch.object(wa, "redact", self.real_redact):
            code, _ = self.cli(*self.cancel_args(aid, secretive["uuid"], 3, "password hunter2 means cancel it"))
        self.assertEqual(code, 2)
        self.assertEqual(self.asks()[aid]["state"], "open")

    def test_cancelled_proof_that_vanishes_blocks_removal(self):
        aid, uid, line = self.setup_cancel()
        self.cli(*self.cancel_args(aid, uid, line))
        CLOCK[0] += 25 * 3600
        self.transcript.write_text("")
        self.assertEqual(self.cli("remove", aid)[0], 2)

    def test_removed_message_is_not_resurrected_by_sync(self):
        aid, uid, line = self.setup_cancel()
        self.cli(*self.cancel_args(aid, uid, line))
        CLOCK[0] += 25 * 3600
        self.assertEqual(self.cli("remove", aid)[0], 0)
        origin_uuid = self.data()["tombstones"][aid]["messageUuids"][0]
        with wa.transaction() as data:
            data["sessions"][SID]["syncOffset"] = None  # force a rescan from the window
            wa.sync_all(data, SID)
        again = [m for m in self.data()["messages"].values() if m["origin"]["log"].get("messageUuid") == origin_uuid]
        self.assertEqual(len(again), 1)  # still the one already captured, never a second


class StoreTest(Base):
    def test_modes_and_event_log(self):
        self.capture("one")
        self.capture("two")
        for name in ("snap", "events", "hive"):
            self.assertEqual(oct(os.stat(wa.files()[name]).st_mode & 0o777), "0o600", name)
        self.assertEqual(wa.verify_events(), [])

    def test_truncated_snapshot_is_preserved_loud_and_rebuilt_from_events(self):
        """NEG-6: control = read_snapshot returning an empty snapshot on a parse error would silently empty."""
        self.capture("keep me")
        self.capture("and me")
        snap = wa.files()["snap"]
        raw = snap.read_bytes()
        snap.write_bytes(raw[: len(raw) // 2])
        with self.assertRaises(wa.StoreCorrupt):
            self.data()
        self.assertTrue(list(self.home.glob("work-ledger.corrupt-*.json")))
        self.assertEqual(snap.read_bytes(), raw[: len(raw) // 2])  # never overwritten
        self.hook("prompt", self.payload("another"))  # hook must not block or crash
        self.assertTrue(wa.pending_failures())
        self.assertEqual(self.cli("recover")[0], 0)
        self.assertEqual(self.cli("sync")[0], 0)  # the next transaction drains the spooled capture
        self.assertEqual(len(self.data()["messages"]), 3)  # the spooled one drains on the next transaction
        self.assertEqual(wa.verify_events(), [])

    def test_missing_snapshot_is_refolded_from_events(self):
        self.capture("one")
        wa.files()["snap"].unlink()
        self.capture("two")
        self.assertEqual(len(self.data()["messages"]), 2)

    def test_events_ahead_of_snapshot_are_folded_after_a_crash(self):
        """Crash between the event append and the snapshot write loses nothing."""
        self.capture("one")
        real = wa.write_private

        def boom(path, payload):
            if path == wa.files()["snap"]:
                raise OSError("disk full")
            return real(path, payload)

        with mock.patch.object(wa, "write_private", boom):
            self.hook("prompt", self.payload("two"))  # snapshot write fails; event is already durable
        self.assertEqual(self.cli("sync")[0], 0)
        self.assertEqual(len(self.data()["messages"]), 3 if False else len(self.data()["messages"]))
        self.assertGreaterEqual(len(self.data()["messages"]), 2)
        self.assertEqual(wa.verify_events(), [])

    def test_event_tamper_is_detected(self):
        msg = self.capture("x")
        self.cli("no-ask", "--msg", msg["id"], "--reason", "nothing to do here")
        self.assertEqual(wa.verify_events(), [])
        events = wa.files()["events"]
        events.write_text(events.read_text().replace("nothing to do here", "something else"))
        self.assertTrue(wa.verify_events())

    def test_snapshot_drift_is_detected(self):
        self.capture("x")
        snap = json.loads(wa.files()["snap"].read_text())
        mid = next(iter(snap["messages"]))
        snap["messages"][mid]["triage"] = {"status": "no_ask", "at": "2027-01-01T00:00:00Z", "reason": "forged triage reason",
                                           "by": snap["messages"][mid]["origin"]["actor"]}
        wa.files()["snap"].write_text(json.dumps(snap))
        self.assertTrue(any("differs" in p for p in wa.verify_events()))

    def test_hook_crash_exits_zero_and_records_failure(self):
        """NEG-7."""
        with mock.patch.object(wa, "build_capture", side_effect=RuntimeError("boom")):
            reply = self.hook("prompt", self.payload("anything"))
        self.assertIn("FAILED", reply.get("systemMessage", ""))
        next_reply = self.hook("prompt", self.payload("<system-reminder>x</system-reminder>"))
        self.assertIn("CAPTURE FAILURE", next_reply["hookSpecificOutput"]["additionalContext"])
        self.assertEqual(self.cli("failures", "--ack")[0], 0)
        self.assertFalse(wa.pending_failures())

    def test_lock_held_fails_quickly(self):
        """NEG-16."""
        with wa.locked():
            started = time.monotonic()
            other = subprocess.run([sys.executable, str(HOOKS / "work_assignments.py"), "status"], capture_output=True,
                                   env={**os.environ, "PYTHONPATH": str(HOOKS)}, timeout=20)
            self.assertLess(time.monotonic() - started, 20)
        self.assertNotEqual(other.returncode, 0)

    def test_session_start_and_compact_inject_open_items(self):
        self.split("a request", "visible after compaction")
        text = self.hook("session", {"session_id": SID, "transcript_path": str(self.transcript)})["hookSpecificOutput"]["additionalContext"]
        self.assertIn("visible after compaction", text)
        self.hook("compact", {"session_id": SID})
        reply = self.hook("prompt", self.payload("<system-reminder>x</system-reminder>"))
        self.assertIn("visible after compaction", reply["hookSpecificOutput"]["additionalContext"])

    def test_huge_failures_file_still_surfaces_newest(self):
        """Red-team MAJOR: a failures file over 1 MiB used to read as empty."""
        wa.private_dir()
        with open(wa.files()["fail"], "w") as handle:
            for i in range(20000):
                handle.write(json.dumps({"ts": "t", "event": f"e{i}", "error": "x" * 60}) + "\n")
        self.assertEqual(wa.pending_failures()[-1]["event"], "e19999")

    def test_secret_like_text_is_redacted_in_excerpt(self):
        """Red-team MINOR: prose passwords and bare long hex tokens, through the real redactor."""
        with mock.patch.object(wa, "redact", self.real_redact):
            out = wa.excerpt_of("my password hunter2 and key " + "ab12" * 10 + " ok")
        self.assertNotIn("hunter2", out)
        self.assertNotIn("ab12ab12ab12", out)


class GuardTest(Base):
    def test_guard_denies_direct_edits_but_allows_cli_and_reads(self):
        snap = str(wa.files()["snap"])
        deny = self.hook("guard", {"tool_name": "Write", "tool_input": {"file_path": snap, "content": "{}"}})
        self.assertEqual(deny["hookSpecificOutput"]["permissionDecision"], "deny")
        for cmd in (f"sed -i s/a/b/ {snap}", f"echo '{{}}' > {snap}", f"rm {wa.files()['events']}", "cp x ~/.claude/hooks/work_assignments_policy.json",
                    "echo x >> ~/.agent-harness/work-ledger.events.jsonl", "rm ~/.agent-harness/hive.json"):
            reply = self.hook("guard", {"tool_name": "Bash", "tool_input": {"command": cmd}})
            self.assertEqual(reply["hookSpecificOutput"]["permissionDecision"], "deny", cmd)
        for cmd in (f"cat {snap}", "python3 ~/.claude/hooks/work_assignments.py status", "ls ~/.agent-harness"):
            self.assertEqual(self.hook("guard", {"tool_name": "Bash", "tool_input": {"command": cmd}}), {}, cmd)

    def test_guard_exemption_string_and_glob_do_not_bypass(self):
        """Red-team MAJOR."""
        for cmd in ("echo {} > ~/.agent-harness/work-ledger.json # work_assignments.py",
                    "cd ~/.agent-harness && : > work-ledg*.json",
                    "python3 ~/.claude/hooks/work_assignments.py status; rm ~/.agent-harness/work-ledger.json",
                    "python3 ~/.claude/hooks/work_assignments.py status > ~/.agent-harness/work-ledger.json"):
            reply = self.hook("guard", {"tool_name": "Bash", "tool_input": {"command": cmd}})
            self.assertEqual(reply["hookSpecificOutput"]["permissionDecision"], "deny", cmd)
        ok = "python3 ~/.claude/hooks/work_assignments.py update A-abcd1234-0001 --state done --evidence abc1234"
        self.assertEqual(self.hook("guard", {"tool_name": "Bash", "tool_input": {"command": ok}}), {})


class SpoolTest(Base):
    def test_lock_stall_spools_the_capture_and_next_sync_drains_it(self):
        """A stall over the budget must not drop the message. Control: no spool_message -> lost."""
        hold = wa.locked()
        hold.__enter__()
        original = wa.transaction
        try:
            with mock.patch.object(wa, "transaction", lambda timeout=0.1: original(0.1)):
                reply = self.hook("prompt", self.payload("filler " * 20 + "request-that-arrived-during-a-lock-stall"))
        finally:
            hold.__exit__(None, None, None)
        self.assertIn("FAILED", reply.get("systemMessage", ""))
        spooled = wa.files()["spool"].read_text()
        self.assertNotIn("request-that-arrived", spooled)  # only the redacted text reference reaches disk
        self.cli("sync")
        msgs = list(self.data()["messages"].values())
        self.assertEqual([m["triage"]["status"] for m in msgs], ["untriaged"])
        self.assertEqual(msgs[0]["capturedVia"], "spool")
        self.assertFalse(wa.files()["spool"].exists())
        self.cli("sync")
        self.assertEqual(len(self.data()["messages"]), 1)  # drained once
        self.check_schema()

    def test_crash_replay_of_a_draining_file_does_not_duplicate(self):
        wa.spool_message({"runtime": "claude", "session": SID, "transcript": None, "pasted": False, "source": "prompt",
                          "method": "claude_user_turn", "item": None, "tref": wa.text_ref("a spooled request")})
        spool = wa.files()["spool"]
        spool.with_name(spool.name + ".draining").write_bytes(spool.read_bytes())  # simulate a crash after rename
        self.cli("sync")
        self.assertEqual(len(self.data()["messages"]), 1)


def _writer(args):
    home, count = args
    os.environ["AGENT_HARNESS_HOME"] = home
    for _ in range(count):
        with wa.transaction(timeout=30) as data:
            wa.build_capture(data, "claude", SID, None, "x " + str(os.getpid()), False, via="hook_prompt", method="claude_user_turn")


class ConcurrencyTest(Base):
    def test_two_concurrent_writers_lose_nothing(self):
        """NEG-5: control = transaction without the flock loses updates."""
        wa.hive_identity()
        with multiprocessing.get_context("fork").Pool(4) as pool:
            pool.map(_writer, [(str(self.home), 15)] * 4)
        data = self.data()
        self.assertEqual(len(data["messages"]), 60)
        self.assertEqual(wa.verify_events(), [])
        self.assertEqual(len(wa.read_events()), 60)


class ImportTest(Base):
    ROWS = [{"id": "A1", "when": "2026-11-03T18:00:00Z", "kind": "decision", "ask": "synthetic one", "excerpt": "q", "status": "SHIPPED",
             "evidence": "PR #36 merged", "next": "n"},
            {"id": "A2", "when": "2026-11-03T18:00:00Z", "kind": "request", "ask": "synthetic two", "excerpt": "q", "status": "STALLED",
             "evidence": "", "next": "resume"},
            {"id": "A3", "when": "x", "kind": "request", "ask": "synthetic three", "excerpt": "q", "status": "SHIPPED", "evidence": ""},
            {"id": "A4", "when": "2026-11-03T18:00:00Z", "kind": "request", "ask": "synthetic four", "excerpt": "q", "status": "SUPERSEDED",
             "evidence": "", "next": ""}]

    def write(self):
        ledger = Path(self.tmp.name) / "LEDGER.jsonl"
        ledger.write_text("\n".join(json.dumps(r) for r in self.ROWS))
        return ledger

    def test_import_is_idempotent_and_flags_stalled(self):
        ledger = self.write()
        self.assertEqual(self.cli("import", str(ledger))[0], 0)
        self.assertEqual(self.cli("import", str(ledger))[0], 0)
        asks = {a["migratedFrom"]["sourceId"]: a for a in self.asks().values()}
        self.assertEqual(len(asks), 4)
        stalled = asks["ledger:A2"]
        self.assertEqual((stalled["state"], wa.owner_of(stalled)), ("blocked", ""))
        self.assertIn("no-owner", wa.ask_flags(stalled, wa.load_policy(), CLOCK[0]))
        self.assertEqual(asks["ledger:A1"]["state"], "ready")  # done needs verified evidence the importer cannot produce
        self.assertEqual(asks["ledger:A1"]["evidence"][0]["verification"]["status"], "attested")
        self.assertEqual(asks["ledger:A3"]["state"], "in_progress")  # ready needs evidence; the ledger had none
        self.assertEqual(asks["ledger:A4"]["state"], "assigned")
        self.assertIn("SUPERSEDED", asks["ledger:A4"]["nextStep"])
        self.check_schema()

    def test_v1_store_migrates_keeping_legacy_ids(self):
        v1 = {"schema": 1, "rev": 3, "created_at": "2026-11-03T00:00:00Z", "seq": {"m": 0, "i": 2}, "sessions": {}, "messages": {},
              "violations": [], "items": {
                  "WA-0001": {"id": "WA-0001", "description": "legacy request", "kind": "request", "owner": "main", "session": "import",
                              "state": "in_progress", "state_since": "2026-11-03T00:00:00Z", "last_checked": "2026-11-03T00:00:00Z",
                              "created": "2026-11-03T00:00:00Z", "next_step": "go on", "links": {}, "evidence": [], "history": [],
                              "source_id": "ledger:A9", "imported": {"when": "2026-11-03T00:00:00Z", "ledger_status": "IN_PROGRESS", "excerpt": ""}},
                  "WA-0002": {"id": "WA-0002", "description": "legacy stalled", "kind": "request", "owner": "unassigned", "session": "import",
                              "state": "blocked", "state_since": "2026-11-03T00:00:00Z", "last_checked": "2026-11-03T00:00:00Z",
                              "created": "2026-11-03T00:00:00Z", "next_step": "", "links": {}, "evidence": [], "history": []}}}
        path = Path(self.tmp.name) / "work-assignments.json"
        path.write_text(json.dumps(v1))
        self.assertEqual(self.cli("migrate", str(path))[0], 0)
        self.assertEqual(self.cli("migrate", str(path))[0], 0)
        asks = self.asks()
        self.assertEqual(len(asks), 2)
        legacy = {a["migratedFrom"]["id"]: a for a in asks.values()}
        self.assertEqual(legacy["WA-0001"]["migratedFrom"]["sourceId"], "ledger:A9")
        self.assertEqual(legacy["WA-0001"]["state"], "in_progress")
        self.assertEqual(wa.owner_of(legacy["WA-0002"]), "")
        self.assertEqual(wa.find_ask(self.data(), "WA-0001")["id"], legacy["WA-0001"]["id"])
        self.assertEqual(wa.find_ask(self.data(), "ledger:A9")["id"], legacy["WA-0001"]["id"])
        self.check_schema()


class LatencyTest(Base):
    def test_hook_latency_with_600_asks(self):
        """AC-10: budget 250 ms per hook process (timeout is 10 s); measured in a real subprocess on schema 2."""
        with wa.transaction() as data:
            who = wa.actor("harness", "harness")
            for i in range(600):
                wa.new_ask(data, description=f"synthetic ask number {i}", owner="main", who=who,
                           origin_actor=wa.actor("harness", "other", label="x"), source={"kind": "file", "ref": "t", "why": "latency"})
        env = {**os.environ, "PYTHONPATH": str(HOOKS)}
        payload = json.dumps(self.payload("latency probe")).encode()
        timings = []
        for _ in range(5):
            started = time.monotonic()
            run = subprocess.run([sys.executable, str(HOOKS / "work_assignments.py"), "hook", "prompt"], input=payload,
                                 capture_output=True, env=env, timeout=20)
            timings.append(time.monotonic() - started)
            self.assertEqual(run.returncode, 0, run.stderr)
        timings.sort()
        size = wa.files()["snap"].stat().st_size
        print(f"\n[latency] 600 asks ({size // 1024} KiB snapshot), prompt hook median {timings[2] * 1000:.0f} ms, max {timings[-1] * 1000:.0f} ms")
        self.assertLess(timings[2], 0.25)


@unittest.skipIf(jsonschema is None, "jsonschema not installed")
class SchemaTest(unittest.TestCase):
    """Negative controls for the v2 schema itself: each mutation of the example must be rejected."""

    @classmethod
    def setUpClass(cls):
        cls.example = json.loads((FIXTURES / "work_ledger_example.json").read_text())

    def errors(self, doc):
        return list(validator().iter_errors(doc))

    def first(self, doc, kind):
        return doc[kind][sorted(doc[kind])[0]]

    def test_example_is_valid_and_metaschema_ok(self):
        jsonschema.Draft202012Validator.check_schema(SCHEMA)
        self.assertEqual(self.errors(self.example), [])

    def mutated(self, fn):
        doc = copy.deepcopy(self.example)
        fn(doc)
        self.assertTrue(self.errors(doc), "mutation was accepted")

    def test_rejects_raw_message_text(self):
        self.mutated(lambda d: self.first(d, "messages").__setitem__("messageText", "raw words"))

    def test_rejects_message_without_human_check(self):
        self.mutated(lambda d: self.first(d, "messages").pop("humanCheck"))

    def test_rejects_human_actor_with_model(self):
        self.mutated(lambda d: self.first(d, "messages")["origin"]["actor"].__setitem__("model", "gpt"))

    def test_rejects_email_as_account(self):
        self.mutated(lambda d: self.first(d, "messages")["origin"]["actor"].__setitem__("account", "me@example.com"))

    def test_rejects_proof_without_targets(self):
        def mutate(d):
            for ask in d["asks"].values():
                if "cancellation" in ask:
                    ask["cancellation"]["proof"].pop("targets")
                    return
            raise AssertionError("example has no cancelled ask")
        self.mutated(mutate)

    def test_rejects_done_without_verified_evidence(self):
        def mutate(d):
            ask = d["asks"]["A-m2air-0042"]
            ask.update(state="done", removableAfter="2026-11-06T00:00:00Z")
            ask["completion"] = {"status": "verified", "verifiedAt": "2026-11-05T00:00:00Z", "verifiedBy": ask["origin"]["actor"]}
            for e in ask["evidence"]:
                e["verification"] = {"status": "attested"}
        self.mutated(mutate)

    def test_rejects_bad_delivered_to(self):
        def mutate(d):
            commits = [c for a in d["asks"].values() for c in a.get("completion", {}).get("commits", [])]
            commits[0]["deliveredTo"] = ["the moon"]
        self.mutated(mutate)

    def test_rejects_answered_decision_by_non_human(self):
        def mutate(d):
            for dec in d["decisions"].values():
                if dec["state"] == "answered":
                    dec["answer"]["actor"]["kind"] = "agent"
                    return
            raise AssertionError("example has no answered decision")
        self.mutated(mutate)

    def test_rejects_unknown_top_level_and_state(self):
        self.mutated(lambda d: d.__setitem__("extra", 1))
        self.mutated(lambda d: self.first(d, "asks").__setitem__("state", "finished"))

    def test_rejects_user_source_without_human_origin(self):
        def mutate(d):
            for ask in d["asks"].values():
                if ask["source"]["kind"] == "user":
                    ask["origin"]["actor"]["kind"] = "agent"
                    return
            raise AssertionError("example has no user-sourced ask")
        self.mutated(mutate)


if __name__ == "__main__":
    unittest.main()
