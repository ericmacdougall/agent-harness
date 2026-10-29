import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from install import END, START, install


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.claude = self.home / ".claude"
        self.claude.mkdir()

    def test_preview_does_not_write(self):
        paths = install(self.home, apply=False)
        self.assertGreater(len(paths), 10)
        self.assertEqual(list(self.claude.iterdir()), [])

    def test_preserves_settings_and_is_idempotent(self):
        original = {
            "model": "sonnet",
            "permissions": {"deny": ["Read(**/.env)"]},
            "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "other-hook"}]}]},
        }
        (self.claude / "settings.json").write_text(json.dumps(original))
        (self.claude / "CLAUDE.md").write_text("My existing instructions.\n")
        install(self.home, apply=True)
        first = json.loads((self.claude / "settings.json").read_text())
        self.assertEqual(first["model"], "sonnet")
        self.assertEqual(first["permissions"]["deny"], ["Read(**/.env)"])
        self.assertEqual(len(first["hooks"]["PreToolUse"]), 2)
        self.assertNotIn("skipDangerousModePermissionPrompt", first)
        self.assertIn("My existing instructions.", (self.claude / "CLAUDE.md").read_text())
        self.assertEqual((self.claude / "CLAUDE.md").read_text().count(START), 1)
        install(self.home, apply=True)
        second = json.loads((self.claude / "settings.json").read_text())
        self.assertEqual(first, second)
        self.assertEqual((self.claude / "CLAUDE.md").read_text().count(START), 1)
        self.assertTrue(list((self.claude / "agent-harness-backups").rglob("settings.json")))

    def test_tolerates_user_hook_with_empty_args(self):
        (self.claude / "settings.json").write_text(json.dumps(
            {"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "python3", "args": []}]}]}}
        ))
        install(self.home, apply=True)
        settings = json.loads((self.claude / "settings.json").read_text())
        self.assertEqual(len(settings["hooks"]["PreToolUse"]), 2)
        self.assertEqual(settings["hooks"]["PreToolUse"][0]["hooks"][0]["args"], [])

    def test_backups_are_private(self):
        (self.claude / "settings.json").write_text(json.dumps({"env": {"EXAMPLE": "value"}}))
        install(self.home, apply=True)
        root = self.claude / "agent-harness-backups"
        for folder in (root, *root.iterdir()):
            self.assertEqual(stat.S_IMODE(os.stat(folder).st_mode), 0o700, folder)
        self.assertEqual(stat.S_IMODE((next(root.rglob("settings.json"))).stat().st_mode), 0o600)

    def test_refuses_symlinked_destination(self):
        outside = self.home / "outside"
        outside.write_text("preserve")
        (self.claude / "settings.json").symlink_to(outside)
        with self.assertRaises(ValueError):
            install(self.home, apply=True)
        self.assertEqual(outside.read_text(), "preserve")

    def test_rejects_bad_markers_before_writing(self):
        (self.claude / "CLAUDE.md").write_text(END)
        with self.assertRaises(ValueError):
            install(self.home, apply=True)
        self.assertFalse((self.claude / "settings.json").exists())


if __name__ == "__main__":
    unittest.main()
