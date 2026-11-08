"""--hooks-only installs never touch the user's instruction and settings files, and a full install keeps the user's
text outside the managed block (the secure-login section)."""

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import install  # noqa: E402
import install_codex  # noqa: E402

SECURE_LOGIN = """## User-authorized secure login

- When the user asks you to log in, complete the ordinary navigation and non-secret fields with the existing browser or computer-control tools. Never ask the user to paste a password into chat, and never put a password in a command, environment variable, WAL, ticket, screenshot description, or log.
- For a GoodQA remote-desktop login without native credential-reference support, keep the GoodQA remote viewer frontmost and call `type_password` with the `goodqa-remote` profile.
"""


class HooksOnly(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp(prefix="hooks-only-")).resolve()
        self.addCleanup(shutil.rmtree, self.home, True)

    def test_claude_hooks_only_leaves_claude_md_and_settings_byte_identical(self):
        claude = self.home / ".claude"
        claude.mkdir()
        user_md = b"# my rules\n\nnot a harness block \xe2\x80\x94 keep me\n"
        user_settings = b'{"theme": "dark",  "env": {"X": "1"}}'  # odd spacing: any rewrite would show
        (claude / "CLAUDE.md").write_bytes(user_md)
        (claude / "settings.json").write_bytes(user_settings)
        preview = install.install(self.home, False, hooks_only=True)
        self.assertNotIn(str(claude / "CLAUDE.md"), preview)
        self.assertNotIn(str(claude / "settings.json"), preview)
        install.install(self.home, True, hooks_only=True)
        self.assertEqual((claude / "CLAUDE.md").read_bytes(), user_md)
        self.assertEqual((claude / "settings.json").read_bytes(), user_settings)
        self.assertTrue((claude / "hooks" / "commit_policy.py").is_file())
        self.assertTrue((claude / "hooks" / "ah_kill.py").is_file())
        # a second hooks-only run backs up the replaced hook files
        install.install(self.home, True, hooks_only=True)
        backups = list((claude / "agent-harness-backups").glob("*/hooks/commit_policy.py"))
        self.assertTrue(backups)
        self.assertEqual((claude / "CLAUDE.md").read_bytes(), user_md)

    def test_control_full_install_does_rewrite_them(self):
        # failing control: without --hooks-only both files change
        claude = self.home / ".claude"
        claude.mkdir()
        (claude / "CLAUDE.md").write_bytes(b"# my rules\n")
        (claude / "settings.json").write_bytes(b'{"theme": "dark"}')
        install.install(self.home, True)
        self.assertNotEqual((claude / "CLAUDE.md").read_bytes(), b"# my rules\n")
        self.assertNotEqual((claude / "settings.json").read_bytes(), b'{"theme": "dark"}')

    def test_codex_hooks_only_leaves_agents_hooks_and_config_byte_identical(self):
        codex = self.home / ".codex"
        codex.mkdir()
        files = {"AGENTS.md": b"Existing user instructions.\n", "hooks.json": b'{"hooks": {}}',
                 "config.toml": b'model = "x"\n'}
        for name, data in files.items():
            (codex / name).write_bytes(data)
        preview = install_codex.install(self.home, False, hooks_only=True)
        for name in files:
            self.assertNotIn(str(codex / name), preview)
        install_codex.install(self.home, True, hooks_only=True)
        for name, data in files.items():
            self.assertEqual((codex / name).read_bytes(), data, name)
        self.assertTrue((codex / "agent-harness" / "wal.py").is_file())

    def test_full_install_keeps_the_secure_login_section(self):
        # the user's secure-login rules live after the managed block; a full install must keep them verbatim
        harness = (ROOT / "HARNESS.md").read_text()
        current = install.START + "\n# Agent Harness engineering workflow\nold\n" + install.END + "\n\n" + SECURE_LOGIN
        merged = install.merged_instructions(current, harness)
        self.assertIn(SECURE_LOGIN, merged)
        self.assertEqual(merged.count("## User-authorized secure login"), 1)
        self.assertNotIn("## User-authorized secure login", harness)  # no duplicate inside the managed block


if __name__ == "__main__":
    unittest.main()
