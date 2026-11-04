"""AskUserQuestion gate, Stop lint and the ask-list detector (provenance_hooks.py)."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_provenance as base  # noqa: E402
from test_provenance import HOOKS, HUMAN, QUOTE, SID  # noqa: E402

sys.path.insert(0, str(HOOKS))
import provenance_hooks as hooks  # noqa: E402


class Detector(unittest.TestCase):
    def flagged(self, text):
        return [item["text"] for item in hooks.detect(text)]

    def test_sections_and_inline_asks_are_found(self):
        text = "Status.\n\n**What I need from you:**\n- the staging key\n- a go/no-go on the release\n\nDone.\n"
        self.assertEqual(self.flagged(text), ["the staging key", "a go/no-go on the release"])
        self.assertEqual(len(self.flagged("Decisions needed:\n1. Which region?\n2. Which plan?\n")), 2)
        self.assertEqual(len(self.flagged("Your call: pick A or B.")), 1)
        self.assertEqual(len(self.flagged("Please provide the OpenRouter key.")), 1)
        self.assertEqual(len(self.flagged("Tell me if you want it moved into Applications.")), 1)

    def test_status_updates_are_not_flagged(self):
        for text in ("Nothing needs you.", "Two decisions came up and I made both, so nothing is waiting on you.",
                     "I don't need anything from you.", "Nothing is needed from you.", "No action is needed from you.",
                     "The deploy is done. Nothing needs you for that. Tests pass.", "All green; merged at abc123.",
                     "```\nWhat I need from you:\n- x\n```", "The agent needs the key from the vault."):
            self.assertEqual(self.flagged(text), [], text)
        self.assertEqual(len(self.flagged("The MSI is still waiting for you to sign in. Nothing needs you for the rest.")), 1)


class Hooks(base.Env):
    def setUp(self):
        super().setUp()
        self.policy = self.home / "policy.json"
        self.set_policy()
        self.env = dict(os.environ, HOME=str(self.home), HARNESS_PROVENANCE_POLICY=str(self.policy))
        main = self.wals / "main.jsonl"
        note = [sys.executable, str(HOOKS / "wal_note.py"), "--wal", str(main), "--event", "ask", "--note", "Confirm the staging key",
                "--reason", "release needs it", "--source", self.user(HUMAN, QUOTE)]
        self.ask_id = json.loads(subprocess.run(note, capture_output=True, text=True, env=self.env, check=True).stdout)["id"]

    def set_policy(self, **modes):
        data = {"schema": 1, "spec": "enforce", "plan_packet": "warn", "ask_user_question": "enforce", "stop_lint": "warn",
                "wal": {"requirement": "enforce", "ask": "enforce", "blocker": "warn", "scope": "warn", "decision": "warn"}}
        data.update(modes)
        self.policy.write_text(json.dumps(data))

    def run_hook(self, name, payload, raw=None):
        run = subprocess.run([sys.executable, str(HOOKS / "provenance_hooks.py"), name], input=raw if raw is not None else json.dumps(payload),
                             capture_output=True, text=True, env=self.env)
        self.assertEqual(run.returncode, 0, run.stderr)
        return json.loads(run.stdout) if run.stdout.strip() else {}

    def ask_payload(self, text):
        return {"session_id": SID, "tool_name": "AskUserQuestion", "tool_input": {"questions": [{"question": text, "header": "h", "options": []}]}}

    def test_ask_gate(self):
        denied = self.run_hook("ask-gate", self.ask_payload("Which key should I use?"))
        self.assertEqual(denied["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertIn("no [ask:<id>]", denied["hookSpecificOutput"]["permissionDecisionReason"])
        fake = self.run_hook("ask-gate", self.ask_payload("Which key? [ask:wnotreal0001]"))
        self.assertIn("not in this session's ledger", fake["hookSpecificOutput"]["permissionDecisionReason"])
        self.assertEqual(self.run_hook("ask-gate", self.ask_payload(f"Which key? [ask:{self.ask_id}]")), {})
        self.set_policy(ask_user_question="warn")
        warn = self.run_hook("ask-gate", self.ask_payload("Which key?"))
        self.assertNotIn("permissionDecision", warn["hookSpecificOutput"])
        self.set_policy(ask_user_question="off")
        self.assertEqual(self.run_hook("ask-gate", self.ask_payload("Which key?")), {})
        self.assertEqual(self.run_hook("ask-gate", {"session_id": SID, "tool_name": "Bash"}), {})

    def test_ask_gate_rejects_ledger_ask_with_untraceable_source(self):
        main = self.wals / "main.jsonl"
        bad = {"id": "wbadsrc0001", "event": "ask", "note": "n", "source": self.user(HUMAN, "words never said by the user")}
        with open(main, "a") as handle:
            handle.write(json.dumps(bad, separators=(",", ":")) + "\n")
        out = self.run_hook("ask-gate", self.ask_payload("Which? [ask:wbadsrc0001]"))
        self.assertIn("untraceable source", out["hookSpecificOutput"]["permissionDecisionReason"])

    def stop_payload(self, text):
        return {"session_id": SID, "last_assistant_message": text, "stop_hook_active": False}

    def test_stop_lint_modes(self):
        message = "Update.\n\nWhat I need from you:\n- the OpenRouter key\n- " + f"approve the plan [ask:{self.ask_id}]\n"
        warn = self.run_hook("stop-lint", self.stop_payload(message))
        self.assertIn("provenance warning", warn["systemMessage"])
        prompt = self.run_hook("prompt", {"session_id": SID})
        self.assertIn("the OpenRouter key", prompt["hookSpecificOutput"]["additionalContext"])
        self.assertNotIn(self.ask_id, prompt["hookSpecificOutput"]["additionalContext"])
        self.assertEqual(self.run_hook("prompt", {"session_id": SID}), {})  # delivered once
        self.set_policy(stop_lint="enforce")
        blocked = self.run_hook("stop-lint", self.stop_payload(message))
        self.assertEqual(blocked["decision"], "block")
        self.assertIn("the OpenRouter key", blocked["reason"])
        again = self.run_hook("stop-lint", dict(self.stop_payload(message), stop_hook_active=True))
        self.assertNotIn("decision", again)  # never loops
        fine = "What I need from you:\n- " + f"approve the plan [ask:{self.ask_id}]\n- pick one [src: {self.user(HUMAN, QUOTE)}]\n"
        self.assertEqual(self.run_hook("stop-lint", self.stop_payload(fine)), {})
        self.assertEqual(self.run_hook("stop-lint", self.stop_payload("Nothing needs you.")), {})
        self.set_policy(stop_lint="off")
        self.assertEqual(self.run_hook("stop-lint", self.stop_payload(message)), {})

    def test_stop_lint_reads_the_transcript_tail_and_fails_open(self):
        record = {"type": "assistant", "uuid": "u", "message": {"content": [{"type": "text", "text": "Decisions needed:\n- the region\n"}]}}
        path = self.home / "t.jsonl"
        path.write_text(json.dumps({"type": "user"}) + "\n" + json.dumps(record, separators=(",", ":")) + "\n" + "{garbage\n")
        self.set_policy(stop_lint="enforce")
        out = self.run_hook("stop-lint", {"session_id": SID, "transcript_path": str(path)})
        self.assertEqual(out["decision"], "block")
        self.assertEqual(self.run_hook("stop-lint", None, raw="{not json"), {})
        self.assertEqual(self.run_hook("stop-lint", None, raw="[" * 5000 + "]" * 5000), {})
        self.assertEqual(self.run_hook("ask-gate", None, raw=""), {})


if __name__ == "__main__":
    unittest.main()
