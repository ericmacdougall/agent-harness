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

from hostile_inputs import run_capped  # noqa: E402

sys.path.insert(0, str(HOOKS))
import provenance_hooks as hooks  # noqa: E402
from provenance import inline_source as provenance_inline  # noqa: E402


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


class DetectorRegressions(unittest.TestCase):
    """Findings of the delta red-team: enforce must not nag on ordinary status text."""

    def flagged(self, text):
        return [item["text"] for item in hooks.detect(text)]

    def test_status_text_is_quiet(self):
        for text in ("Done. Tell me if you want more detail on any of it.", "Decisions made:\n- chose sqlite",
                     "Decisions:\n- used sqlite\n- skipped tests", "Open questions:\n- none", "Blocked on you: nothing.",
                     "Waiting on you: nothing", "You asked me to 'please send the report'.",
                     'The log says: please provide credentials', "Questions for you:\n- n/a\n"):
            self.assertEqual(self.flagged(text), [], text)

    def test_cited_items_with_sub_bullets_and_wrapped_lines_are_one_item(self):
        text = "What I need from you:\n- key [ask:wgood00001]\n  - why: because\n  - how: via vault\n- the production deploy key for\n  the staging box [ask:wgood00002]\n"
        items = hooks.detect(text)
        self.assertEqual(len(items), 2)
        self.assertIn("[ask:wgood00001]", items[0]["text"])
        self.assertIn("[ask:wgood00002]", items[1]["text"])

    def test_adversarial_long_lines_stay_fast_and_closers_are_quiet(self):
        import time
        for text in ("a" + "." * 100_000 + "a", "- " + " " * 100_000 + "x", "#" * 100_000, "What I need from you:\n- " + "y " * 50_000):
            start = time.perf_counter()
            hooks.detect(text)
            self.assertLess(time.perf_counter() - start, 1.0, text[:20])
        for text in ("Let me know if you have any questions.", "Let me know if you run into issues.", "Let me know when you're ready.",
                     "I don\u2019t need anything from you."):
            self.assertEqual(self.flagged(text), [], text)

    def test_fences_cannot_hide_asks(self):
        self.assertEqual(len(self.flagged("```x```\nWhat I need from you:\n- the key\n")), 1)
        self.assertEqual(len(self.flagged("```\nunclosed fence\nWhat I need from you:\n- the key\n")), 1)
        self.assertEqual(self.flagged("```\nWhat I need from you:\n- the key\n```\nDone.\n"), [])
        self.assertEqual(len(hooks.detect("What I need from you:\n" + "- x item\n" * 500)), hooks.MAX_ITEMS)


class SlowInputs(base.Env):
    def test_huge_numbers_and_long_messages_exit_quickly(self):
        env = dict(os.environ, HOME=str(self.home))
        for payload in ('{"session_id":"%s","x":%s}' % (SID, "9" * 3_000_000),
                        json.dumps({"session_id": SID, "last_assistant_message": "a" + "." * 100_000 + "a"})):
            code, out, err, seconds, peak = run_capped([str(HOOKS / "provenance_hooks.py"), "stop-lint"], payload, env, timeout=10.0)
            self.assertEqual(code, 0, err[-200:])
            self.assertLess(seconds, 3.0)

    def test_usage_errors_do_not_crash(self):
        for args in (["show-message"], ["calibrate"], ["show-message", "x"]):
            code, out, err, seconds, peak = run_capped([str(HOOKS / "provenance_hooks.py"), *args], timeout=10.0)
            self.assertEqual(code, 3, err[-200:])


class Hooks(base.Env):
    def setUp(self):
        super().setUp()
        self.env = dict(os.environ, HOME=str(self.home))
        self.sandbox_dir = self.sandbox()  # copy of the hooks whose installed policy this test controls (env can only tighten)
        main = self.wals / "main.jsonl"
        note = [sys.executable, str(self.sandbox_dir / "wal_note.py"), "--wal", str(main), "--event", "ask", "--note", "Confirm the staging key",
                "--reason", "release needs it", "--source", self.user(HUMAN, QUOTE)]
        self.ask_id = json.loads(subprocess.run(note, capture_output=True, text=True, env=self.env, check=True).stdout)["id"]

    def set_policy(self, **modes):
        self.sandbox_dir = self.sandbox(**modes)

    def run_hook(self, name, payload, raw=None):
        run = subprocess.run([sys.executable, str(self.sandbox_dir / "provenance_hooks.py"), name], input=raw if raw is not None else json.dumps(payload),
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
        allowed = self.run_hook("ask-gate", self.ask_payload(f"Which key? [ask:{self.ask_id}]"))
        self.assertNotIn("permissionDecision", allowed["hookSpecificOutput"])
        self.assertIn("Confirm the staging key", allowed["hookSpecificOutput"]["additionalContext"])  # the ask's note is shown
        self.set_policy(ask_user_question="warn")
        warn = self.run_hook("ask-gate", self.ask_payload("Which key?"))
        self.assertNotIn("permissionDecision", warn["hookSpecificOutput"])
        self.set_policy(ask_user_question="off")
        self.assertEqual(self.run_hook("ask-gate", self.ask_payload("Which key?")), {})
        self.assertEqual(self.run_hook("ask-gate", {"session_id": SID, "tool_name": "Bash"}), {})

    def test_inline_src_with_trailing_brackets_and_options(self):
        self.assertEqual(provenance_inline(f'x [src: {self.user(HUMAN, QUOTE)}] (see [docs])'), self.user(HUMAN, QUOTE))
        payload = self.ask_payload(f"Which? [src: {self.user(HUMAN, QUOTE)}]")
        payload["tool_input"]["questions"][0]["options"] = [{"label": "a [x]"}, {"label": "b"}]
        self.assertEqual(self.run_hook("ask-gate", payload), {})
        stop = "Decisions needed:\n- pick [src: " + self.user(HUMAN, QUOTE) + "] (see [docs])\n"
        self.assertEqual(self.run_hook("stop-lint", self.stop_payload(stop)), {})

    def test_ask_gate_rejects_ledger_ask_with_untraceable_source(self):
        main = self.wals / "main.jsonl"
        bad = {"id": "wbadsrc0001", "event": "ask", "note": "n", "source": self.user(HUMAN, "words never said by the user")}
        with open(main, "a") as handle:
            handle.write(json.dumps(bad, separators=(",", ":")) + "\n")
        out = self.run_hook("ask-gate", self.ask_payload("Which? [ask:wbadsrc0001]"))
        self.assertIn("untraceable source", out["hookSpecificOutput"]["permissionDecisionReason"])

    def stop_payload(self, text):
        return {"session_id": SID, "last_assistant_message": text, "stop_hook_active": False}

    def test_reminder_lifecycle_and_session_ids(self):
        message = "What I need from you:\n- the OpenRouter key\n"
        self.run_hook("stop-lint", self.stop_payload(message))
        self.assertTrue(hooks.reminder_path(SID).exists())
        self.run_hook("stop-lint", self.stop_payload("All done."))  # a clean message clears the stale reminder
        self.assertFalse(hooks.reminder_path(SID).exists())
        for bad in ("..", ".", "../../etc"):
            self.assertEqual(self.run_hook("stop-lint", {"session_id": bad, "last_assistant_message": message}), {})
            self.assertEqual(self.run_hook("prompt", {"session_id": bad}), {})
        self.assertEqual(self.run_hook("ask-gate", {"session_id": SID, "tool_name": "AskUserQuestion", "tool_input": "x"}), {})

    def test_config_dir_override_and_claimed_reminder_cleanup(self):
        import provenance
        saved = os.environ.get("CLAUDE_CONFIG_DIR")
        os.environ["CLAUDE_CONFIG_DIR"] = str(self.home / "cfg")
        try:
            self.assertEqual(provenance.claude_home(), self.home / "cfg")
        finally:
            os.environ.pop("CLAUDE_CONFIG_DIR") if saved is None else os.environ.__setitem__("CLAUDE_CONFIG_DIR", saved)
        path = hooks.reminder_path(SID)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("x" * (1 << 17))  # larger than the read cap: the read fails, the claimed file must still go away
        self.assertEqual(self.run_hook("prompt", {"session_id": SID}), {})
        self.assertEqual([p.name for p in path.parent.iterdir() if p.name.startswith("provenance-reminder")], [])

    def test_ask_gate_fails_open_when_the_ledger_is_unavailable(self):
        import shutil
        shutil.rmtree(self.wals)
        out = self.run_hook("ask-gate", self.ask_payload("Which key? [ask:wnotreal0001]"))
        self.assertEqual(out, {})  # no WAL directory at all: misconfiguration, not a reason to deny

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
        path = self.home / ".claude" / "projects" / "-proj" / "t.jsonl"
        path.write_text(json.dumps({"type": "user", "toolUseResult": {}}) + "\n" + json.dumps(record, separators=(",", ":")) + "\n" + "{garbage\n")
        self.set_policy(stop_lint="enforce")
        out = self.run_hook("stop-lint", {"session_id": SID, "transcript_path": str(path)})
        self.assertEqual(out["decision"], "block")
        user_after = json.dumps({"type": "user", "message": {"content": "thanks"}}, separators=(",", ":"))
        path.write_text(path.read_text().replace("{garbage\n", "") + user_after + "\n")
        self.assertEqual(self.run_hook("stop-lint", {"session_id": SID, "transcript_path": str(path)}), {})  # stale message
        self.assertEqual(self.run_hook("stop-lint", None, raw="{not json"), {})
        self.assertEqual(self.run_hook("stop-lint", None, raw="[" * 5000 + "]" * 5000), {})
        self.assertEqual(self.run_hook("ask-gate", None, raw=""), {})


if __name__ == "__main__":
    unittest.main()


class DeviceAndHugeInputs(base.Env):
    """transcript_path pointing at devices, FIFOs, symlinks and huge files must never be read unbounded (P0)."""

    def setUp(self):
        super().setUp()
        self.env = dict(os.environ, HOME=str(self.home))
        policy = self.home / "policy.json"
        policy.write_text(json.dumps({"schema": 1, "spec": "enforce", "plan_packet": "warn", "ask_user_question": "enforce",
                                      "stop_lint": "enforce", "wal": {}}))
        self.env["HARNESS_PROVENANCE_POLICY"] = str(policy)
        self.projects = self.home / ".claude" / "projects" / "-proj"

    def hook(self, transcript_path):
        payload = json.dumps({"session_id": SID, "transcript_path": str(transcript_path), "stop_hook_active": False})
        return run_capped([str(HOOKS / "provenance_hooks.py"), "stop-lint"], payload, self.env, timeout=8.0)

    def assert_safe(self, path, label):
        code, out, err, seconds, peak = self.hook(path)
        self.assertEqual(code, 0, f"{label}: rc={code} err={err[:200]}")
        self.assertNotIn("decision", out, label)
        self.assertLess(seconds, 1.5, f"{label}: took {seconds:.2f}s")
        self.assertLess(peak, 100 * 1024 * 1024, f"{label}: peak RSS {peak >> 20} MiB")
        return err

    def test_devices_are_rejected_quickly_and_cheaply(self):
        for device in ("/dev/zero", "/dev/urandom", "/dev/null", "/dev/tty"):
            if os.path.exists(device):
                err = self.assert_safe(device, device)
                self.assertIn("rejected", err)

    def test_fifo_directory_and_symlinked_device(self):
        fifo = self.home / "pipe"
        os.mkfifo(fifo)
        self.assertIn("rejected", self.assert_safe(fifo, "fifo"))
        self.assertIn("rejected", self.assert_safe(self.projects, "directory"))
        link = self.projects / "link.jsonl"
        os.symlink("/dev/zero", link)
        self.assertIn("rejected", self.assert_safe(link, "symlink to /dev/zero"))
        outside = self.home / "outside.jsonl"
        outside.write_text('{"type":"assistant","message":{"content":[{"type":"text","text":"Decisions needed:\\n- x\\n"}]}}\\n')
        self.assertIn("outside", self.assert_safe(outside, "regular file outside ~/.claude/projects"))

    def test_five_gigabyte_sparse_file_reads_only_a_tail_window(self):
        big = self.projects / "huge.jsonl"
        with open(big, "wb") as handle:
            handle.truncate(5 * 1024 ** 3)
            handle.seek(-200, os.SEEK_END)
            handle.write(b'\n{"type":"assistant","message":{"content":[{"type":"text","text":"Decisions needed:\\n- the region\\n"}]}}\n')
        code, out, err, seconds, peak = self.hook(big)
        self.assertEqual(code, 0, err[:200])
        self.assertEqual(json.loads(out)["decision"], "block")  # the tail was read and linted
        self.assertLess(seconds, 1.5)
        self.assertLess(peak, 100 * 1024 * 1024, f"peak RSS {peak >> 20} MiB")

    def test_resolver_scans_are_bounded_too(self):
        import provenance
        link = self.projects / "dev.jsonl"
        os.symlink("/dev/zero", link)
        for call in (lambda: provenance.read_small("/dev/zero"), lambda: provenance.read_tail("/dev/zero", 1024),
                     lambda: list(provenance._lines_containing(Path("/dev/zero"), b"x"))):
            with self.assertRaises(provenance.Problem) as caught:
                call()
            self.assertEqual(caught.exception.code, "file-not-regular")
        with self.assertRaises(provenance.Problem):
            provenance.read_small(self.transcript, 100)  # larger than its limit
        self.assertEqual(provenance.wal_entry(Path("/dev/zero"), "L5"), "malformed")
        result = provenance.resolve(f'wal:{self.wals}/x.jsonl#wabcd1234')
        self.assertFalse(result["ok"])

    def test_watchdog_exits_zero_when_memory_runs_away(self):
        code = ("import sys,time; sys.path.insert(0, %r); import provenance_hooks as h; "
                "h.install_limits(rss_limit=150*1024*1024, wall_limit=20); keep=[]\n"
                "for i in range(8):\n keep.append(bytearray(50*1024*1024)); time.sleep(0.05)\nprint('SURVIVED')" % str(HOOKS))
        rc, out, err, seconds, peak = run_capped(["-c", code], env=self.env, timeout=20.0)
        self.assertEqual(rc, 0)
        self.assertNotIn("SURVIVED", out)
        self.assertIn("limit exceeded", err)
        self.assertLess(peak, 400 * 1024 * 1024)
