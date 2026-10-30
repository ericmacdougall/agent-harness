import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from install import END, START, ROOT, install


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name).resolve()
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
        for name in ('report_file.py', 'peer_review.py', 'rescue.py'):
            self.assertEqual((self.claude / 'hooks' / name).read_bytes(),
                             (ROOT / 'harness/hooks' / name).read_bytes())
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

    def test_preserves_foreign_hook_in_a_managed_group(self):
        foreign = {"type": "command", "command": "keep-my-hook"}
        managed = {"type": "command", "command": "python3",
                   "args": [str(self.claude / "hooks/wal.py"), "pretool"]}
        group = {"matcher": "Write", "hooks": [managed, foreign], "timeout": 42}
        (self.claude / "settings.json").write_text(json.dumps({"hooks": {"PreToolUse": [group]}}))
        install(self.home, apply=True)
        install(self.home, apply=True)
        groups = json.loads((self.claude / "settings.json").read_text())["hooks"]["PreToolUse"]
        self.assertEqual(groups[0], {**group, "hooks": [foreign]})
        self.assertEqual(len(groups), 2)

    def test_refuses_symlinked_parent_directories_before_writing(self):
        for name in ("agents", "hooks", "tools", "agent-harness-backups", ".claude"):
            for apply in (False, True):
                with self.subTest(name=name, apply=apply), tempfile.TemporaryDirectory() as temp:
                    home = Path(temp)
                    claude = home / ".claude"
                    claude.mkdir()
                    outside = home / "outside"
                    outside.mkdir(mode=0o755)
                    sentinel = outside / "sentinel"
                    sentinel.write_text("unchanged")
                    destination = claude if name == ".claude" else claude / name
                    if name == ".claude":
                        claude.rmdir()
                    destination.symlink_to(outside, target_is_directory=True)
                    with self.assertRaises(ValueError):
                        install(home, apply=apply)
                    self.assertEqual(list(outside.iterdir()), [sentinel])
                    self.assertEqual(sentinel.read_text(), "unchanged")
                    self.assertEqual(stat.S_IMODE(outside.stat().st_mode), 0o755)

    def test_installed_delivery_helpers_can_start(self):
        import subprocess
        import sys
        install(self.home, apply=True)
        for name in ("publish_feature.py", "integrate_local.py", "peer_review.py", "rescue.py"):
            result = subprocess.run([sys.executable, str(self.claude / "hooks" / name), "--help"],
                                    text=True, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
        watched = subprocess.run([sys.executable, str(self.claude / 'tools/watch-tests.py'),
                                  '--root', str(self.home), '--once', '--', sys.executable, '-c', 'pass'],
                                 text=True, capture_output=True, timeout=10)
        self.assertEqual(watched.returncode, 0, watched.stdout + watched.stderr)

    def test_rejects_bad_markers_before_writing(self):
        (self.claude / "CLAUDE.md").write_text(END)
        with self.assertRaises(ValueError):
            install(self.home, apply=True)
        self.assertFalse((self.claude / "settings.json").exists())

    def managed_snapshot(self):
        return {str(path.relative_to(self.claude)): (path.read_bytes(), stat.S_IMODE(path.stat().st_mode))
                for path in self.claude.rglob('*')
                if path.is_file() and 'agent-harness-backups' not in path.parts}

    def seed_existing_installation(self):
        (self.claude / 'agents').mkdir()
        (self.claude / 'agents/task-owner.md').write_text('old owner\n')
        (self.claude / 'agents/task-owner.md').chmod(0o640)
        (self.claude / 'CLAUDE.md').write_text('user instructions\n')
        (self.claude / 'settings.json').write_text('{"model": "keep-me"}\n')

    def test_missing_payload_is_detected_before_any_installation_write(self):
        self.seed_existing_installation()
        before = self.managed_snapshot()
        read_bytes = Path.read_bytes
        def missing_payload(path):
            if path == ROOT / 'harness/tools/watch-tests.py':
                raise FileNotFoundError('fixture: final payload missing')
            return read_bytes(path)
        with patch.object(Path, 'read_bytes', missing_payload), self.assertRaises(FileNotFoundError):
            install(self.home, apply=True)
        self.assertEqual(self.managed_snapshot(), before)
        self.assertFalse((self.claude / 'agent-harness-backups').exists())

    def test_fifo_destinations_are_rejected_without_opening_them(self):
        for name in ('settings.json', 'agents/task-owner.md'):
            for apply in (False, True):
                with self.subTest(name=name, apply=apply):
                    path = self.claude / name
                    path.parent.mkdir(exist_ok=True)
                    os.mkfifo(path)
                    try:
                        try:
                            result = subprocess.run([sys.executable, str(ROOT / 'install.py'),
                                                     '--home', str(self.home), *(['--apply'] if apply else [])],
                                                    text=True, capture_output=True, timeout=2)
                        except subprocess.TimeoutExpired:
                            self.fail('installer blocked opening a FIFO')
                        self.assertNotEqual(result.returncode, 0)
                        self.assertIn('regular file', result.stderr)
                        self.assertFalse((self.claude / 'agent-harness-backups').exists())
                    finally:
                        path.unlink()

    def test_file_in_place_of_managed_directory_is_rejected_before_writing(self):
        (self.claude / 'hooks').write_text('preserve this file')
        before = self.managed_snapshot()
        with self.assertRaisesRegex(ValueError, 'directory'):
            install(self.home, apply=True)
        self.assertEqual(self.managed_snapshot(), before)
        self.assertFalse((self.claude / 'agent-harness-backups').exists())

    def test_failed_replacement_restores_existing_files_and_removes_new_files(self):
        self.seed_existing_installation()
        before = self.managed_snapshot()
        replace = os.replace
        failed = False
        def fail_once(source, destination):
            nonlocal failed
            if Path(destination) == self.claude / 'settings.json' and not failed:
                failed = True
                raise OSError('fixture: settings replacement failed')
            return replace(source, destination)
        with patch('install.os.replace', side_effect=fail_once), self.assertRaisesRegex(OSError, 'fixture'):
            install(self.home, apply=True)
        self.assertTrue(failed)
        self.assertEqual(self.managed_snapshot(), before)
        self.assertFalse(list(self.claude.rglob('.agent-harness-*')))
        saved, = (self.claude / 'agent-harness-backups').rglob('settings.json')
        self.assertEqual(saved.read_bytes(), before['settings.json'][0])
        self.assertEqual(stat.S_IMODE(saved.stat().st_mode), 0o600)

    def test_rollback_failure_is_reported_and_other_files_are_still_restored(self):
        self.seed_existing_installation()
        before = self.managed_snapshot()
        replace = os.replace
        failed = False
        def fail_install_and_one_restore(source, destination):
            nonlocal failed
            path = Path(destination)
            if path == self.claude / 'settings.json':
                failed = True
                raise OSError('fixture: write failure')
            if failed and path == self.claude / 'agents/task-owner.md':
                raise OSError('fixture: restore failure')
            return replace(source, destination)
        with patch('install.os.replace', side_effect=fail_install_and_one_restore):
            with self.assertRaisesRegex(RuntimeError, 'rollback incomplete') as raised:
                install(self.home, apply=True)
        self.assertIn('agents/task-owner.md', str(raised.exception))
        self.assertIn('agent-harness-backups', str(raised.exception))
        after = self.managed_snapshot()
        self.assertEqual(after.pop('CLAUDE.md'), before['CLAUDE.md'])
        self.assertEqual(after.pop('settings.json'), before['settings.json'])
        self.assertEqual(set(after), {'agents/task-owner.md'})


if __name__ == "__main__":
    unittest.main()
