"""Request ledger (work_assignments.py): capture, triage, Stop enforcement, removal gate, durability, latency.

All text here is synthetic. Seeded failing controls are named in each test's docstring.
"""

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
sys.path.insert(0, str(HOOKS))
import work_assignments as wa  # noqa: E402

SID = "11111111-2222-3333-4444-555555555555"
CLOCK = [1_800_000_000.0]


def human(text, uid=None, **extra):
    record = {"type": "user", "uuid": uid or str(uuidlib.uuid4()), "isSidechain": False, "origin": {"kind": "human"},
              "timestamp": wa.iso(CLOCK[0]), "message": {"role": "user", "content": text}}
    record.update(extra)
    return record


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
        with redirect_stdout(out), mock.patch("sys.stdin", io.TextIOWrapper(io.BytesIO(json.dumps(payload).encode()))), \
                mock.patch.object(wa.safe_input, "read_stdin_bounded", lambda n: json.dumps(payload).encode()):
            code = wa.run_hook(name, runtime)
        self.assertEqual(code, 0)
        return json.loads(out.getvalue()) if out.getvalue().strip() else {}

    def data(self):
        with wa.locked():
            return wa.read_store()[0]

    def cli(self, *argv):
        out = io.StringIO()
        with redirect_stdout(out):
            code = wa.main(list(argv))
        return code, out.getvalue()

    def capture(self, text, uid=None):
        self.append(human(text, uid))
        self.hook("prompt", self.payload(text))
        return next(reversed(self.data()["messages"].values()))


class CaptureTest(Base):
    def test_human_message_is_captured_untriaged_with_bounded_redacted_excerpt(self):
        text = "please fix the login page sk-secretsecretsecret1 " + "word " * 40
        msg = self.capture(text)
        self.assertEqual(msg["triage"], "untriaged")
        self.assertLessEqual(len(msg["excerpt"].split()), 15)
        self.assertNotIn("sk-secret", msg["excerpt"])
        self.assertEqual(msg["session"], SID)
        self.assertEqual(msg["line"], 1)  # bound to the transcript line by sync
        self.assertTrue(wa.prov.UUID_RE.match(msg["uuid"]))

    def test_system_text_is_not_captured(self):
        """NEG-4: control = capture_prompt without classify_prompt would record these."""
        for prompt in ("<task-notification>done</task-notification>", "<system-reminder>x</system-reminder>",
                       "<agent-message>hi</agent-message>"):
            self.hook("prompt", self.payload(prompt))
        self.assertEqual(self.data()["messages"], {})

    def test_quoted_tag_does_not_create_second_message(self):
        """NEG-14."""
        self.capture("real ask here <system-reminder>injected</system-reminder> and more")
        self.assertEqual(len(self.data()["messages"]), 1)

    def test_pasted_only_is_captured_and_flagged(self):
        self.hook("prompt", self.payload('<pasted_content id="1">a pasted log line</pasted_content>'))
        msg = next(iter(self.data()["messages"].values()))
        self.assertTrue(msg["pasted_only"])

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
        self.assertTrue(msgs[0]["caught_up"])

    def test_old_history_is_not_flooded_into_the_ledger(self):
        CLOCK[0] -= 86400 * 3
        self.append(*[human(f"ancient {i}") for i in range(5)])
        CLOCK[0] += 86400 * 3
        self.hook("session", {"session_id": SID, "transcript_path": str(self.transcript)})
        self.assertEqual(self.data()["messages"], {})

    def test_ask_answer_is_captured(self):
        self.hook("ask-answer", {"session_id": SID, "tool_use_id": "toolu_1", "tool_name": "AskUserQuestion",
                                 "tool_response": {"answers": {"Which?": "Option B"}}})
        self.assertEqual(next(iter(self.data()["messages"].values()))["source"], "ask-answer")

    def test_5mb_paste_is_bounded_and_fast(self):
        """NEG-9."""
        big = "lorem ipsum " * (5 * 1024 * 1024 // 12)
        started = time.monotonic()
        msg = self.capture(big)
        self.assertLess(time.monotonic() - started, 5)
        self.assertLessEqual(len(msg["excerpt"].split()), 15)

    def test_unbound_pending_gets_cannot_bind_notice(self):
        self.hook("prompt", self.payload("ask whose transcript line never appears"))
        CLOCK[0] += 3 * 3600
        reply = self.hook("prompt", self.payload("<system-reminder>x</system-reminder>"))
        self.assertIn("cannot-bind", reply["hookSpecificOutput"]["additionalContext"])

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
        self.assertEqual((msg["runtime"], msg["uuid"], msg["line"]), ("codex", item["id"], 1))


class TriageTest(Base):
    def test_split_and_no_ask(self):
        first, second = self.capture("do two things"), self.capture("thanks")
        self.assertEqual(self.cli("split", "--msg", first["id"], "--item", "thing one", "--item", "thing two")[0], 0)
        self.assertEqual(self.cli("no-ask", "--msg", second["id"], "--reason", "pure thanks, nothing to do")[0], 0)
        data = self.data()
        self.assertEqual(len(data["items"]), 2)
        self.assertEqual(data["messages"][second["id"]]["triage"], "no-ask")
        item = data["items"]["WA-0001"]
        self.assertEqual(item["state"], "open")
        self.assertTrue(item["history"])

    def test_no_ask_needs_reason(self):
        """NEG-18."""
        msg = self.capture("x request")
        self.assertEqual(self.cli("no-ask", "--msg", msg["id"], "--reason", "short")[0], 2)

    def test_done_requires_valid_evidence(self):
        """NEG-10."""
        msg = self.capture("build it")
        self.cli("split", "--msg", msg["id"], "--item", "build")
        self.assertEqual(self.cli("update", "WA-0001", "--state", "done")[0], 2)
        self.assertEqual(self.cli("update", "WA-0001", "--state", "done", "--evidence", "it works trust me")[0], 2)
        self.assertEqual(self.cli("update", "WA-0001", "--state", "done", "--evidence", "abc1234def")[0], 0)

    def test_subagent_can_update_owner_state_evidence(self):
        msg = self.capture("build it")
        self.cli("split", "--msg", msg["id"], "--item", "build")
        code, _ = self.cli("update", "WA-0001", "--actor", "agent:a9", "--owner", "agent:a9", "--state", "in_progress")
        self.assertEqual(code, 0)
        self.assertEqual(self.data()["items"]["WA-0001"]["history"][-1]["actor"], "agent:a9")


class StopTest(Base):
    def stop(self, **extra):
        return self.hook("stop", {"session_id": SID, "transcript_path": str(self.transcript), **extra})

    def test_blocks_on_untriaged_then_lets_go_with_violation(self):
        """AC-4/AC-13: control = max_stop_blocks ignored would loop forever."""
        self.capture("request needing triage")
        replies = [self.stop() for _ in range(5)]
        self.assertEqual([r.get("decision") for r in replies], ["block"] * 3 + [None, None])
        self.assertEqual(len(self.data()["violations"]), 1)
        again = self.hook("prompt", self.payload("next"))
        self.assertIn("VIOLATION", again["hookSpecificOutput"]["additionalContext"])

    def test_stale_item_and_stopped_owner_block(self):
        msg = self.capture("work")
        self.cli("split", "--msg", msg["id"], "--item", "a thing", "--owner", "agent:zz")
        self.assertEqual(self.stop().get("decision"), None)
        CLOCK[0] += 13 * 3600
        self.assertEqual(self.stop()["decision"], "block")

    def test_stopped_owner_is_flagged(self):
        """NEG-13."""
        msg = self.capture("work")
        self.cli("split", "--msg", msg["id"], "--item", "a thing", "--owner", "agent:zz")
        with mock.patch.object(wa, "agent_stopped", lambda s, a: True):
            self.assertEqual(self.stop()["decision"], "block")

    def test_clean_state_does_not_block(self):
        msg = self.capture("thanks")
        self.cli("no-ask", "--msg", msg["id"], "--reason", "just a thank you")
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


class RemovalTest(Base):
    def done_item(self, hours):
        msg = self.capture("ship it")
        self.cli("split", "--msg", msg["id"], "--item", "ship")
        self.cli("update", "WA-0001", "--state", "done", "--evidence", "abc1234def")
        CLOCK[0] += hours * 3600

    def test_removal_refused_at_23h_allowed_at_25h(self):
        """NEG-1."""
        self.done_item(23)
        self.assertEqual(self.cli("remove", "WA-0001")[0], 2)
        self.assertEqual(self.cli("prune", "--apply")[0], 0)
        self.assertIn("WA-0001", self.data()["items"])
        CLOCK[0] += 2 * 3600
        self.assertEqual(self.cli("remove", "WA-0001")[0], 0)
        self.assertNotIn("WA-0001", self.data()["items"])

    def test_open_item_is_never_removable(self):
        msg = self.capture("x")
        self.cli("split", "--msg", msg["id"], "--item", "still open")
        CLOCK[0] += 1000 * 3600
        self.assertEqual(self.cli("remove", "WA-0001")[0], 2)
        self.cli("prune", "--apply")
        self.assertIn("WA-0001", self.data()["items"])

    def cancel_args(self, uid, line, quote="cancel that whole thing please"):
        return ("cancel", "WA-0001", "--uuid", uid, "--file", str(self.transcript), "--line", str(line), "--quote", quote)

    def setup_cancel(self):
        msg = self.capture("start something")
        self.cli("split", "--msg", msg["id"], "--item", "something")
        cancel = human("cancel that whole thing please, I changed my mind")
        self.append(cancel)
        return cancel["uuid"], 2

    def test_cancel_with_genuine_proof_then_removal_after_24h(self):
        uid, line = self.setup_cancel()
        self.assertEqual(self.cli(*self.cancel_args(uid, line))[0], 0)
        self.assertEqual(self.cli("remove", "WA-0001")[0], 2)
        CLOCK[0] += 25 * 3600
        self.assertEqual(self.cli("remove", "WA-0001")[0], 0)

    def test_cancel_proof_that_is_an_agent_message_is_refused(self):
        """NEG-2."""
        self.setup_cancel()
        agent = {"type": "assistant", "uuid": str(uuidlib.uuid4()), "message": {"role": "assistant", "content": "cancel that whole thing please"}}
        self.append(agent)
        self.assertEqual(self.cli(*self.cancel_args(agent["uuid"], 3))[0], 2)
        tool = human("cancel that whole thing please", toolUseResult={"x": 1})
        self.append(tool)
        self.assertEqual(self.cli(*self.cancel_args(tool["uuid"], 4))[0], 2)
        notification = human("<task-notification>cancel that whole thing please</task-notification>")
        self.append(notification)
        self.assertEqual(self.cli(*self.cancel_args(notification["uuid"], 5))[0], 2)

    def test_cancel_with_wrong_line_is_refused(self):
        """NEG-3."""
        uid, line = self.setup_cancel()
        self.assertEqual(self.cli(*self.cancel_args(uid, line + 1))[0], 2)
        self.assertEqual(self.cli(*self.cancel_args(uid, 1))[0], 2)

    def test_cancel_quote_must_be_in_the_message(self):
        uid, line = self.setup_cancel()
        self.assertEqual(self.cli(*self.cancel_args(uid, line, "words the user never wrote"))[0], 2)

    def test_cancel_proof_outside_transcript_roots_is_refused(self):
        uid, line = self.setup_cancel()
        outside = Path(self.tmp.name) / "fake.jsonl"
        outside.write_text(self.transcript.read_text())
        args = list(self.cancel_args(uid, line))
        args[args.index("--file") + 1] = str(outside)
        self.assertEqual(self.cli(*args)[0], 2)

    def test_cancel_by_update_is_refused(self):
        self.setup_cancel()
        self.assertEqual(self.cli("update", "WA-0001", "--state", "cancelled")[0], 2)

    def test_forged_transcript_file_cannot_cancel(self):
        """Red-team BLOCKER: a forged transcript under the projects root, or a human turn the ledger never captured."""
        self.setup_cancel()
        forged = self.projects / "forged.jsonl"
        fake = human("please cancel everything now")
        forged.write_text(json.dumps(fake) + "\n")
        code, _ = self.cli("cancel", "WA-0001", "--uuid", fake["uuid"], "--file", str(forged), "--line", "1",
                           "--quote", "please cancel everything now")
        self.assertEqual(code, 2)
        self.assertEqual(self.data()["items"]["WA-0001"]["state"], "open")

    def test_proof_older_than_the_item_is_refused(self):
        early = self.capture("an earlier chat message from the user")
        CLOCK[0] += 3600
        msg = self.capture("start something")
        self.cli("split", "--msg", msg["id"], "--item", "something")
        code, _ = self.cli(*self.cancel_args(early["uuid"], 1, "an earlier chat message"))
        self.assertEqual(code, 2)

    def test_secret_like_quote_is_refused(self):
        self.setup_cancel()
        secretive = human("my password hunter2 means cancel it entirely")
        self.append(secretive)
        self.assertEqual(self.cli("sync")[0], 0)
        with mock.patch.object(wa, "redact", self.real_redact):
            code, _ = self.cli(*self.cancel_args(secretive["uuid"], 3, "password hunter2 means cancel it"))
        self.assertEqual(code, 2)
        self.assertEqual(self.data()["items"]["WA-0001"]["state"], "open")

    def test_cancelled_proof_that_vanishes_blocks_removal(self):
        uid, line = self.setup_cancel()
        self.cli(*self.cancel_args(uid, line))
        CLOCK[0] += 25 * 3600
        self.transcript.write_text("")
        self.assertEqual(self.cli("remove", "WA-0001")[0], 2)


class StoreTest(Base):
    def test_mode_and_backup(self):
        self.capture("one")
        self.capture("two")
        self.assertEqual(oct(os.stat(wa.files()["store"]).st_mode & 0o777), "0o600")
        self.assertTrue(wa.files()["bak"].exists())
        self.assertEqual(oct(os.stat(wa.files()["audit"]).st_mode & 0o777) if wa.files()["audit"].exists() else "0o600", "0o600")

    def test_truncated_file_is_preserved_and_loud(self):
        """NEG-6: control = read_store returning new_store() on a parse error would silently empty."""
        self.capture("keep me")
        self.capture("and me")
        store = wa.files()["store"]
        raw = store.read_bytes()
        store.write_bytes(raw[: len(raw) // 2])
        with self.assertRaises(wa.StoreCorrupt):
            self.data()
        self.assertTrue(list(self.home.glob("work-assignments.corrupt-*.json")))
        self.assertEqual(store.read_bytes(), raw[: len(raw) // 2])  # never overwritten
        self.hook("prompt", self.payload("another"))  # hook must not block or crash
        self.assertTrue(wa.pending_failures())
        self.assertEqual(self.cli("recover")[0], 0)
        self.assertEqual(len(self.data()["messages"]), 1)

    def test_hook_crash_exits_zero_and_records_failure(self):
        """NEG-7."""
        with mock.patch.object(wa, "capture_prompt", side_effect=RuntimeError("boom")):
            reply = self.hook("prompt", self.payload("anything"))
        self.assertIn("FAILED", reply.get("systemMessage", ""))
        next_reply = self.hook("prompt", self.payload("<system-reminder>x</system-reminder>"))
        self.assertIn("CAPTURE FAILURE", next_reply["hookSpecificOutput"]["additionalContext"])
        self.assertEqual(self.cli("failures", "--ack")[0], 0)
        self.assertFalse(wa.pending_failures())

    def test_lock_held_records_failure_quickly(self):
        """NEG-16."""
        with wa.locked():
            started = time.monotonic()
            with mock.patch.object(wa, "LOCK_SECONDS", 0.2):
                other = subprocess.run([sys.executable, str(HOOKS / "work_assignments.py"), "status"], capture_output=True,
                                       env={**os.environ, "PYTHONPATH": str(HOOKS)}, timeout=20)
            self.assertLess(time.monotonic() - started, 20)
        self.assertNotEqual(other.returncode, 0)

    def test_guard_exemption_string_and_glob_do_not_bypass(self):
        """Red-team MAJOR: naming work_assignments.py in a comment, or globbing the file name."""
        for cmd in ("echo {} > ~/.agent-harness/work-assignments.json # work_assignments.py",
                    "cd ~/.agent-harness && : > work-assign*.json",
                    "python3 ~/.claude/hooks/work_assignments.py status; rm ~/.agent-harness/work-assignments.json",
                    "python3 ~/.claude/hooks/work_assignments.py status > ~/.agent-harness/work-assignments.json"):
            reply = self.hook("guard", {"tool_name": "Bash", "tool_input": {"command": cmd}})
            self.assertEqual(reply["hookSpecificOutput"]["permissionDecision"], "deny", cmd)
        ok = "python3 ~/.claude/hooks/work_assignments.py update WA-0001 --state done --evidence abc1234"
        self.assertEqual(self.hook("guard", {"tool_name": "Bash", "tool_input": {"command": ok}}), {})

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

    def test_removed_no_ask_message_is_not_resurrected_by_sync(self):
        msg = self.capture("thanks a lot")
        self.cli("no-ask", "--msg", msg["id"], "--reason", "pure thanks to the agent")
        CLOCK[0] += 25 * 3600
        self.cli("prune", "--apply")
        self.assertEqual(self.data()["messages"], {})
        with wa.transaction() as data:
            data["sessions"][SID]["offset"] = None  # force a rescan from the window
            wa.sync_all(data, SID)
        self.assertEqual(self.data()["messages"], {})

    def test_audit_chain_detects_tampering(self):
        msg = self.capture("x")
        self.cli("no-ask", "--msg", msg["id"], "--reason", "nothing to do here")
        self.assertEqual(wa.verify_audit(), [])
        audit = wa.files()["audit"]
        audit.write_text(audit.read_text().replace("nothing to do here", "something else"))
        self.assertTrue(wa.verify_audit())

    def test_guard_denies_direct_edits_but_allows_cli_and_reads(self):
        store = str(wa.files()["store"])
        deny = self.hook("guard", {"tool_name": "Write", "tool_input": {"file_path": store, "content": "{}"}})
        self.assertEqual(deny["hookSpecificOutput"]["permissionDecision"], "deny")
        for cmd in (f"sed -i s/a/b/ {store}", f"echo '{{}}' > {store}", f"rm {store}.bak", "cp x ~/.claude/hooks/work_assignments_policy.json"):
            reply = self.hook("guard", {"tool_name": "Bash", "tool_input": {"command": cmd}})
            self.assertEqual(reply["hookSpecificOutput"]["permissionDecision"], "deny", cmd)
        for cmd in (f"cat {store}", f"python3 ~/.claude/hooks/work_assignments.py status", "ls ~/.agent-harness"):
            self.assertEqual(self.hook("guard", {"tool_name": "Bash", "tool_input": {"command": cmd}}), {}, cmd)

    def test_session_start_and_compact_inject_open_items(self):
        msg = self.capture("a request")
        self.cli("split", "--msg", msg["id"], "--item", "visible after compaction")
        text = self.hook("session", {"session_id": SID, "transcript_path": str(self.transcript)})["hookSpecificOutput"]["additionalContext"]
        self.assertIn("visible after compaction", text)
        self.hook("compact", {"session_id": SID})
        reply = self.hook("prompt", self.payload("<system-reminder>x</system-reminder>"))
        self.assertIn("visible after compaction", reply["hookSpecificOutput"]["additionalContext"])


def _writer(args):
    home, count = args
    os.environ["AGENT_HARNESS_HOME"] = home
    for _ in range(count):
        with wa.transaction(timeout=30) as data:
            wa.add_message(data, runtime="claude", session=SID, transcript=None, text="x " + str(os.getpid()), pasted=False)


class ConcurrencyTest(Base):
    def test_two_concurrent_writers_lose_nothing(self):
        """NEG-5: control = transaction without the flock loses updates."""
        with multiprocessing.get_context("fork").Pool(4) as pool:
            pool.map(_writer, [(str(self.home), 15)] * 4)
        self.assertEqual(len(self.data()["messages"]), 60)


class ImportTest(Base):
    def test_import_is_idempotent_and_flags_stalled(self):
        ledger = Path(self.tmp.name) / "LEDGER.jsonl"
        rows = [{"id": "A1", "when": "2026-11-03T18:00:00Z", "kind": "decision", "ask": "synthetic one", "excerpt": "q", "status": "SHIPPED",
                 "evidence": "PR #36 merged", "next": "n"},
                {"id": "A2", "when": "2026-11-03T18:00:00Z", "kind": "request", "ask": "synthetic two", "excerpt": "q", "status": "STALLED",
                 "evidence": "", "next": "resume"},
                {"id": "A3", "when": "x", "kind": "request", "ask": "synthetic three", "excerpt": "q", "status": "SHIPPED", "evidence": ""}]
        ledger.write_text("\n".join(json.dumps(r) for r in rows))
        self.assertEqual(self.cli("import", str(ledger))[0], 0)
        self.assertEqual(self.cli("import", str(ledger))[0], 0)
        items = self.data()["items"]
        self.assertEqual(len(items), 3)
        stalled = next(i for i in items.values() if i["source_id"] == "ledger:A2")
        self.assertEqual((stalled["state"], stalled["owner"]), ("blocked", "unassigned"))
        self.assertIn("no-owner", wa.item_flags(stalled, wa.load_policy(), CLOCK[0]))
        self.assertEqual(next(i for i in items.values() if i["source_id"] == "ledger:A3")["state"], "ready")  # done needs evidence
        self.assertEqual(next(i for i in items.values() if i["source_id"] == "ledger:A1")["state"], "done")


class LatencyTest(Base):
    def test_hook_latency_with_600_items(self):
        """AC-10: budget 250 ms per hook process (timeout is 10 s); measured in a real subprocess."""
        with wa.transaction() as data:
            for i in range(600):
                wa.new_item(data, description=f"synthetic item {i}", owner="main", session="other")
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
        print(f"\n[latency] 600 items, prompt hook median {timings[2] * 1000:.0f} ms, max {timings[-1] * 1000:.0f} ms")
        self.assertLess(timings[2], 0.25)


if __name__ == "__main__":
    unittest.main()
