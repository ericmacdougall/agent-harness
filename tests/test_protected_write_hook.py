"""goodqa#17155: Write, Edit, MultiEdit and NotebookEdit may not change ~/.claude/CLAUDE.md, ~/.claude/settings*.json,
~/.codex/config.toml or ~/.codex/hooks.json. One list (protected_paths.py) serves the hook and any later importer.
Reads stay allowed and ordinary files are unaffected. Everything lives in a temporary HOME."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HOOKS = Path(__file__).resolve().parents[1] / "harness/hooks"
HOOK = HOOKS / "protected_write_hook.py"
sys.path.insert(0, str(HOOKS))

PROTECTED = (".claude/CLAUDE.md", ".claude/settings.json", ".claude/settings.local.json",
             ".codex/config.toml", ".codex/hooks.json")
ORDINARY = (".claude/notes.md", ".claude/settings/extra.json", ".claude/projects/p/memory/CLAUDE.md", "proj/CLAUDE.md",
            "proj/.claude/CLAUDE.md", "proj/.claude/settings.json", ".codex/config.toml.example", ".codex/prompts/x.toml",
            ".config/settings.json")


class ProtectedWrite(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name).resolve()
        for rel in PROTECTED:
            path = self.home / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("original\n")
        self.env = {**os.environ, "HOME": str(self.home)}

    def run_hook(self, tool, **tool_input):
        payload = {"tool_name": tool, "tool_input": tool_input, "cwd": str(self.home)}
        return subprocess.run([sys.executable, str(HOOK)], input=json.dumps(payload), text=True, capture_output=True,
                              env=self.env)

    def test_every_edit_tool_is_refused_on_every_protected_file(self):
        for rel in PROTECTED:
            for tool, key in (("Write", "file_path"), ("Edit", "file_path"), ("MultiEdit", "file_path"),
                              ("NotebookEdit", "notebook_path")):
                with self.subTest(tool=tool, path=rel):
                    result = self.run_hook(tool, **{key: str(self.home / rel)})
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertIn("protected_write BLOCKED", result.stderr)
                    self.assertIn("only the user changes", result.stderr)

    def test_spellings_that_reach_the_same_file_are_refused(self):
        os.symlink(self.home / ".claude/CLAUDE.md", self.home / "alias.md")
        os.link(self.home / ".codex/config.toml", self.home / "hard.toml")
        for spelled in ("~/.claude/CLAUDE.md", str(self.home / ".claude/../.claude/CLAUDE.md"),
                        str(self.home / ".claude/./settings.json"), str(self.home / ".CLAUDE/claude.md"),
                        "alias.md", "hard.toml", str(self.home / "alias.md"), ".claude/settings.local.json"):
            with self.subTest(path=spelled):
                result = self.run_hook("Write", file_path=spelled)
                self.assertEqual(result.returncode, 2, result.stderr)

    def test_the_real_target_of_a_protected_symlink_is_protected_too(self):
        dotfiles = self.home / "dotfiles"
        dotfiles.mkdir()
        (dotfiles / "CLAUDE.md").write_text("real\n")
        (self.home / ".claude/CLAUDE.md").unlink()
        os.symlink(dotfiles / "CLAUDE.md", self.home / ".claude/CLAUDE.md")
        self.assertEqual(self.run_hook("Write", file_path=str(dotfiles / "CLAUDE.md")).returncode, 2)
        self.assertEqual(self.run_hook("Write", file_path=str(dotfiles / "other.md")).returncode, 0)

    def test_a_huge_payload_is_still_judged(self):
        result = self.run_hook("Write", file_path=str(self.home / ".claude/settings.json"), content="x" * (9 * 1024 * 1024))
        self.assertEqual(result.returncode, 2, result.stderr[:200])

    def test_a_new_protected_file_that_does_not_exist_yet_is_refused(self):
        result = self.run_hook("Write", file_path=str(self.home / ".claude/settings.team.json"))
        self.assertEqual(result.returncode, 2, result.stderr)

    def test_ordinary_files_and_other_tools_are_allowed(self):
        for rel in ORDINARY:
            with self.subTest(path=rel):
                self.assertEqual(self.run_hook("Write", file_path=str(self.home / rel)).returncode, 0)
        for tool in ("Read", "Bash", "Grep", "Glob"):
            with self.subTest(tool=tool):
                result = self.run_hook(tool, file_path=str(self.home / ".claude/CLAUDE.md"),
                                       command="cat ~/.claude/CLAUDE.md")
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_the_hook_never_changes_a_file_and_reads_are_not_touched(self):
        self.run_hook("Write", file_path=str(self.home / ".claude/CLAUDE.md"))
        self.assertEqual((self.home / ".claude/CLAUDE.md").read_text(), "original\n")

    def test_bad_input_fails_open_with_a_note_and_never_locks_out(self):
        for raw in ("", "not json", "[]", json.dumps({"tool_name": "Write", "tool_input": "x"})):
            with self.subTest(raw=raw[:12]):
                result = subprocess.run([sys.executable, str(HOOK)], input=raw, text=True, capture_output=True,
                                        env=self.env)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_the_path_list_is_one_module_a_command_guard_relation_can_import(self):
        import protected_paths
        self.assertEqual(set(protected_paths.PROTECTED_WRITE_GLOBS), {
            ".claude/CLAUDE.md", ".claude/settings*.json", ".codex/config.toml", ".codex/hooks.json"})
        self.assertIsNone(protected_paths.protected_write_refusal(str(self.home / "proj/CLAUDE.md"), home=str(self.home)))
        self.assertTrue(protected_paths.protected_write_refusal("~/.claude/CLAUDE.md", home=str(self.home)))


if __name__ == "__main__":
    unittest.main()
