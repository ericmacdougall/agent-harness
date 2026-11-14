"""S1 (GoodQA goodqa#15946): the lane stamp hook is registered once by the installer and stamps only main.

Covers AC-9 and NEG-87 of software-factory/s1/spec.md. Bounded: at most 6 short subprocesses (the hook itself),
two temp-home installs, no network.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOOK = ROOT / "harness" / "hooks" / "lane_stamp.py"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "harness" / "hooks"))
import install  # noqa: E402

LANE = "lane_01ARZ3NDEKTSV4RRFFQ69G5FAV"
SESSION = "11111111-2222-4333-8444-555555555555"


def lane_stamp_entries(settings):
    found = []
    for groups in (settings.get("hooks") or {}).values():
        for group in groups:
            for hook in group.get("hooks", []):
                if any(str(a).endswith("lane_stamp.py") for a in hook.get("args", [])):
                    found.append((group.get("matcher"), hook))
    return found


class RegistrationTests(unittest.TestCase):
    def test_managed_hooks_register_the_stamp_hook_once_on_bash_and_it_fails_open(self):
        claude = Path("/home/x/.claude")
        entries = lane_stamp_entries({"hooks": install.managed_hooks(claude)})
        self.assertEqual(len(entries), 1)
        matcher, hook = entries[0]
        self.assertEqual(matcher, "Bash")
        self.assertNotIn("onFailure", hook)  # a stamp bug must never block a Bash call
        self.assertIn(str(claude / "hooks" / "lane_stamp.py"), install.managed_scripts(claude))

    def test_reinstall_adds_no_duplicates(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            install.install(home, True)
            first = json.loads((home / ".claude" / "settings.json").read_text())
            install.install(home, True)
            second = json.loads((home / ".claude" / "settings.json").read_text())
            self.assertEqual(len(lane_stamp_entries(first)), 1)
            self.assertEqual(len(lane_stamp_entries(second)), 1)
            self.assertEqual(first["hooks"]["PreToolUse"], second["hooks"]["PreToolUse"])
            self.assertTrue((home / ".claude" / "hooks" / "lane_stamp.py").is_file())


class HookBehaviourTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name)
        proj = self.home / ".claude" / "projects" / "p"
        proj.mkdir(parents=True)
        self.transcript = proj / (SESSION + ".jsonl")
        self.transcript.write_text("{}\n")
        self.env = dict(os.environ, HOME=str(self.home), CLAUDE_CONFIG_DIR=str(self.home / ".claude"))

    def tearDown(self):
        self.tmp.cleanup()

    def run_hook(self, payload, raw=None):
        return subprocess.run([sys.executable, str(HOOK)], input=raw if raw is not None else json.dumps(payload),
                              capture_output=True, text=True, env=self.env, timeout=30)

    def stamps(self):
        d = self.home / ".agent-harness" / "state"
        return sorted(p.name for p in d.rglob("*.json")) if d.exists() else []

    def payload(self, command, **extra):
        return dict({"tool_name": "Bash", "tool_input": {"command": command}, "session_id": SESSION,
                     "transcript_path": str(self.transcript), "tool_use_id": "toolu_" + "a" * 20}, **extra)

    def test_main_plain_command_is_stamped_silently(self):
        done = self.run_hook(self.payload("python3 ~/.claude/hooks/ah.py lane start --lane %s" % LANE))
        self.assertEqual((done.returncode, done.stdout, done.stderr), (0, "", ""))
        self.assertEqual(len(self.stamps()), 1)

    def test_subagent_payload_gets_no_main_stamp(self):  # NEG-87
        done = self.run_hook(self.payload("python3 ah.py lane start --lane %s" % LANE, agent_id="A1",
                                          agent_type="task-owner"))
        self.assertEqual(done.returncode, 0)
        self.assertEqual(self.stamps(), [])

    def test_subagent_checkpoint_gets_only_a_holder_stamp(self):
        self.run_hook(self.payload("python3 ah.py lane checkpoint --lane %s --kind plan --note x" % LANE, agent_id="A1"))
        self.assertEqual(len(self.stamps()), 1)
        from lane import auth
        self.assertIsNone(auth.holder_identity("lane_OTHER", home=self.home))
        self.assertEqual(auth.holder_identity(LANE, home=self.home), "A1")
        self.assertFalse(auth.is_main("checkpoint", LANE, home=self.home))

    def test_shell_syntax_and_other_commands_are_not_stamped(self):
        for cmd in ("python3 ah.py lane start --lane %s; echo hi" % LANE, "python3 ah.py lane start --lane %s | cat" % LANE,
                    "echo $(python3 ah.py lane start --lane %s)" % LANE, "python3 ah.py status", "ls"):
            with self.subTest(cmd=cmd):
                self.run_hook(self.payload(cmd))
        self.assertEqual(self.stamps(), [])

    def test_garbage_or_oversized_input_fails_open_silently(self):
        for raw in ("not json", "", "{" * 10, " " * ((1 << 20) + 10)):
            done = self.run_hook(None, raw=raw)
            self.assertEqual((done.returncode, done.stdout), (0, ""))
        self.assertEqual(self.stamps(), [])


if __name__ == "__main__":
    unittest.main()
