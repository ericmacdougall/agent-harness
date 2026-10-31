import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from install import END, START, ROOT, install, merged_instructions


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

    def test_inline_marker_text_is_preserved(self):
        original = f'Keep this example: {START} user text {END} forever.\n'
        merged = merged_instructions(original, 'Managed instructions.')
        self.assertIn(original.rstrip(), merged)
        self.assertIn('Managed instructions.', merged)

    def test_fenced_marker_example_is_preserved(self):
        example = f'```md\n{START}\n# Agent Harness engineering workflow\nExample.\n{END}\n```\n'
        merged = merged_instructions(example, 'Managed instructions.')
        self.assertIn(example, merged)
        self.assertIn('Managed instructions.', merged)

    def test_replacement_preserves_end_marker_newline_and_suffix(self):
        existing = (f'{START}\n# Agent Harness engineering workflow\nOld.\n{END}\n'
                    'User instructions after block.\n')
        merged = merged_instructions(existing, '# Agent Harness engineering workflow\nNew.')
        self.assertIn(f'{END}\nUser instructions after block.\n', merged)
        self.assertEqual(merged_instructions(merged, '# Agent Harness engineering workflow\nNew.'), merged)

    def test_same_inode_edit_during_backup_is_preserved(self):
        target = self.claude / 'CLAUDE.md'
        target.write_text('original\n')
        from install import atomic_write
        changed = False

        def edit_during_backup(path, data, mode=0o600, **kwargs):
            nonlocal changed
            if not changed and 'agent-harness-backups' in path.parts:
                changed = True
                target.write_text('concurrent user edit\n')
            return atomic_write(path, data, mode, **kwargs)

        with patch('install.atomic_write', side_effect=edit_during_backup):
            with self.assertRaises(OSError):
                install(self.home, apply=True)
        self.assertTrue(changed)
        self.assertEqual(target.read_text(), 'concurrent user edit\n')

    def test_rollback_preserves_same_inode_edit_to_published_file(self):
        from install import atomic_write
        for existed in (False, True):
            with self.subTest(existed=existed), tempfile.TemporaryDirectory() as temporary:
                home = Path(temporary).resolve()
                agents = home / '.claude' / 'agents'
                agents.mkdir(parents=True)
                owner = agents / 'task-owner.md'
                if existed:
                    owner.write_text('original owner\n')
                changed = False

                def edit_then_fail(path, data, mode=0o600, **kwargs):
                    nonlocal changed
                    if path == agents / 'click-tester.md' and not changed:
                        changed = True
                        owner.write_text('concurrent published edit\n')
                        raise OSError('fixture: stop after edit')
                    return atomic_write(path, data, mode, **kwargs)

                with patch('install.atomic_write', side_effect=edit_then_fail):
                    with self.assertRaisesRegex(RuntimeError, 'rollback incomplete'):
                        install(home, apply=True)
                self.assertTrue(changed)
                self.assertEqual(owner.read_text(), 'concurrent published edit\n')

    def test_preserves_settings_and_is_idempotent(self):
        original = {
            "model": "sonnet",
            "permissions": {"deny": ["Read(**/.env)"]},
            "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "other-hook"}]}]},
        }
        (self.claude / "settings.json").write_text(json.dumps(original))
        (self.claude / "CLAUDE.md").write_text("My existing instructions.\n")
        install(self.home, apply=True)
        for name in ('git_safety.py', 'report_file.py', 'peer_review.py', 'rescue.py'):
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

    def test_directory_swap_after_preflight_never_writes_or_removes_outside_files(self):
        outside = self.home / 'outside'
        outside.mkdir()
        (self.claude / 'agents').mkdir()
        sentinel = outside / 'task-owner.md'
        sentinel.write_text('outside fixture')
        from install import atomic_write
        swapped = False

        def swap_before_first_write(path, data, mode=0o600, **kwargs):
            nonlocal swapped
            if not swapped:
                swapped = True
                (self.claude / 'agents').rename(self.claude / 'agents-moved')
                (self.claude / 'agents').symlink_to(outside, target_is_directory=True)
            return atomic_write(path, data, mode, **kwargs)

        with patch('install.atomic_write', side_effect=swap_before_first_write):
            with self.assertRaises((OSError, ValueError, RuntimeError)):
                install(self.home, apply=True)
        self.assertTrue(swapped)
        self.assertEqual(sentinel.read_text(), 'outside fixture')
        self.assertEqual(list(outside.iterdir()), [sentinel])

    def test_backup_uses_original_snapshot_when_parent_is_swapped(self):
        self.seed_existing_installation()
        outside = self.home / 'outside'
        outside.mkdir()
        sentinel = outside / 'task-owner.md'
        sentinel.write_text('outside private fixture')
        from install import atomic_write
        swapped = False

        def swap_before_backup(path, data, mode=0o600, **kwargs):
            nonlocal swapped
            if not swapped and 'agent-harness-backups' in path.parts:
                swapped = True
                (self.claude / 'agents').rename(self.claude / 'agents-moved')
                outside.rename(self.claude / 'agents')
            return atomic_write(path, data, mode, **kwargs)

        with patch('install.atomic_write', side_effect=swap_before_backup):
            with self.assertRaises((OSError, RuntimeError)):
                install(self.home, apply=True)
        self.assertTrue(swapped, 'backup mutation must actually run')
        self.assertEqual((self.claude / 'agents/task-owner.md').read_text(), 'outside private fixture')
        saved, = (self.claude / 'agent-harness-backups').rglob('task-owner.md')
        self.assertEqual(saved.read_text(), 'old owner\n')

    def test_real_directory_replacement_after_backups_never_overwrites_unrelated_files(self):
        self.seed_existing_installation()
        outside = self.home / 'outside'
        outside.mkdir()
        sentinel = outside / 'task-owner.md'
        sentinel.write_text('unrelated outside file')
        from install import atomic_write
        swapped = False

        def swap_after_backups(path, data, mode=0o600, **kwargs):
            nonlocal swapped
            if not swapped and path == self.claude / 'agents/task-owner.md':
                swapped = True
                (self.claude / 'agents').rename(self.claude / 'agents-moved')
                outside.rename(self.claude / 'agents')
            return atomic_write(path, data, mode, **kwargs)

        with patch('install.atomic_write', side_effect=swap_after_backups):
            with self.assertRaises((OSError, RuntimeError)):
                install(self.home, apply=True)
        self.assertTrue(swapped)
        self.assertEqual((self.claude / 'agents/task-owner.md').read_text(), 'unrelated outside file')

    def test_rollback_refuses_a_real_directory_replacement_after_one_write(self):
        self.seed_existing_installation()
        outside = self.home / 'outside'
        outside.mkdir()
        (outside / 'task-owner.md').write_text('unrelated owner')
        from install import atomic_write
        swapped = False

        def swap_on_second_managed_write(path, data, mode=0o600, **kwargs):
            nonlocal swapped
            if not swapped and path == self.claude / 'agents/click-tester.md':
                swapped = True
                (self.claude / 'agents').rename(self.claude / 'agents-moved')
                outside.rename(self.claude / 'agents')
            return atomic_write(path, data, mode, **kwargs)

        with patch('install.atomic_write', side_effect=swap_on_second_managed_write):
            with self.assertRaisesRegex(RuntimeError, 'rollback incomplete'):
                install(self.home, apply=True)
        self.assertTrue(swapped)
        self.assertEqual((self.claude / 'agents/task-owner.md').read_text(), 'unrelated owner')
        self.assertFalse((self.claude / 'agents/click-tester.md').exists())

    def test_real_file_replacement_after_snapshot_is_not_overwritten(self):
        self.seed_existing_installation()
        outsider = self.home / 'unrelated-owner.md'
        outsider.write_text('unrelated leaf')
        from install import atomic_write
        swapped = False

        def swap_leaf_before_write(path, data, mode=0o600, **kwargs):
            nonlocal swapped
            if not swapped and path == self.claude / 'agents/task-owner.md':
                swapped = True
                path.rename(path.with_name('old-owner.md'))
                outsider.rename(path)
            return atomic_write(path, data, mode, **kwargs)

        with patch('install.atomic_write', side_effect=swap_leaf_before_write):
            with self.assertRaises((OSError, RuntimeError)):
                install(self.home, apply=True)
        self.assertTrue(swapped)
        self.assertEqual((self.claude / 'agents/task-owner.md').read_text(), 'unrelated leaf')

    def test_rollback_refuses_a_new_leaf_replacing_an_installed_file(self):
        self.seed_existing_installation()
        outsider = self.home / 'unrelated-owner.md'
        outsider.write_text('unrelated rollback leaf')
        from install import atomic_write
        swapped = False

        def swap_leaf_before_failure(path, data, mode=0o600, **kwargs):
            nonlocal swapped
            if not swapped and path == self.claude / 'agents/click-tester.md':
                swapped = True
                owner = self.claude / 'agents/task-owner.md'
                owner.rename(owner.with_name('installed-owner.md'))
                outsider.rename(owner)
                raise OSError('fixture: interrupt after leaf swap')
            return atomic_write(path, data, mode, **kwargs)

        with patch('install.atomic_write', side_effect=swap_leaf_before_failure):
            with self.assertRaisesRegex(RuntimeError, 'rollback incomplete'):
                install(self.home, apply=True)
        self.assertTrue(swapped)
        self.assertEqual((self.claude / 'agents/task-owner.md').read_text(), 'unrelated rollback leaf')

    def test_rollback_pins_published_inode_after_unlink_and_recreation(self):
        from install import atomic_write
        for existing in (False, True):
            with self.subTest(existing=existing), tempfile.TemporaryDirectory() as temporary:
                home = Path(temporary).resolve()
                claude = home / '.claude'
                agents = claude / 'agents'
                agents.mkdir(parents=True)
                owner = agents / 'task-owner.md'
                if existing:
                    owner.write_text('original owner\n')
                original = owner.read_bytes() if existing else None
                retained = False
                injected = False

                def replace_then_fail(path, data, mode=0o600, **kwargs):
                    nonlocal retained, injected
                    if path == agents / 'click-tester.md' and not injected:
                        injected = True
                        published = owner.stat()
                        for name in os.listdir('/dev/fd'):
                            if not name.isdigit():
                                continue
                            try:
                                opened = os.fstat(int(name))
                            except OSError:
                                continue
                            if (opened.st_dev, opened.st_ino) == (published.st_dev, published.st_ino):
                                retained = True
                                break
                        owner.unlink()
                        owner.write_text('unrelated recreated owner\n')
                        raise OSError('fixture: interrupt after unlink and recreation')
                    return atomic_write(path, data, mode, **kwargs)

                with patch('install.atomic_write', side_effect=replace_then_fail):
                    with self.assertRaisesRegex(RuntimeError, 'rollback incomplete'):
                        install(home, apply=True)
                self.assertTrue(injected)
                self.assertTrue(retained, 'the published inode must remain open through rollback')
                self.assertEqual(owner.read_text(), 'unrelated recreated owner\n')
                self.assertEqual(original, b'original owner\n' if existing else None)

    def test_file_replacement_during_final_publish_cannot_report_success(self):
        outsider = self.home / 'unrelated-owner.md'
        outsider.write_text('unrelated final leaf')
        replace = os.replace
        swapped = False

        def swap_after_replace(source, destination, **kwargs):
            nonlocal swapped
            result = replace(source, destination, **kwargs)
            if destination == 'task-owner.md' and not swapped:
                swapped = True
                owner = self.claude / 'agents/task-owner.md'
                owner.rename(owner.with_name('installed-owner.md'))
                outsider.rename(owner)
            return result

        with patch('install.os.replace', side_effect=swap_after_replace):
            with self.assertRaisesRegex(RuntimeError, 'rollback incomplete'):
                install(self.home, apply=True)
        self.assertTrue(swapped)
        self.assertEqual((self.claude / 'agents/task-owner.md').read_text(), 'unrelated final leaf')

    def test_new_directory_swap_between_creation_and_open_is_refused(self):
        from install import DirectoryPins
        for name in ('agents', 'agent-harness-backups'):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                home = Path(temporary).resolve()
                claude = home / '.claude'
                claude.mkdir()
                (claude / 'settings.json').write_text('{"model":"keep"}\n')
                outside = home / 'outside'
                outside.mkdir(mode=0o755)
                (outside / 'marker').write_text('unrelated')
                if name == 'agents':
                    (outside / 'task-owner.md').write_text('unrelated owner')
                outside_mode = stat.S_IMODE(outside.stat().st_mode)
                original_create = DirectoryPins.create
                original_mkdir = os.mkdir
                active = None
                swapped = False
                injected_path = None

                def track_create(pins, path, **kwargs):
                    nonlocal active
                    active = path
                    try:
                        return original_create(pins, path, **kwargs)
                    finally:
                        active = None

                def swap_created(name_to_make, *args, **kwargs):
                    nonlocal swapped, injected_path
                    result = original_mkdir(name_to_make, *args, **kwargs)
                    if active == claude / name and not swapped:
                        created = active.parent / name_to_make
                        created.rename(created.with_name(created.name + '-moved'))
                        outside.rename(created)
                        swapped = True
                        injected_path = created
                    return result

                with patch('install.DirectoryPins.create', track_create), \
                     patch('install.os.mkdir', side_effect=swap_created):
                    with self.assertRaises((OSError, RuntimeError)):
                        install(home, apply=True)
                self.assertTrue(swapped)
                replacement = injected_path
                self.assertEqual((replacement / 'marker').read_text(), 'unrelated')
                self.assertEqual(stat.S_IMODE(replacement.stat().st_mode), outside_mode)
                if name == 'agents':
                    self.assertEqual((replacement / 'task-owner.md').read_text(), 'unrelated owner')
                else:
                    self.assertEqual([path.name for path in replacement.iterdir()], ['marker'])

    def test_post_replace_fsync_error_rolls_back_the_published_file(self):
        for existing in (False, True):
            with self.subTest(existing=existing), tempfile.TemporaryDirectory() as temporary:
                home = Path(temporary).resolve()
                claude = home / '.claude'
                claude.mkdir()
                if existing:
                    agents = claude / 'agents'
                    agents.mkdir()
                    (agents / 'task-owner.md').write_text('original owner\n')
                    (agents / 'task-owner.md').chmod(0o640)
                before = {str(path.relative_to(claude)): (path.read_bytes(), stat.S_IMODE(path.stat().st_mode))
                          for path in claude.rglob('*') if path.is_file()}
                replace = os.replace
                fsync = os.fsync
                published = False
                failed = False

                def record_replace(source, destination, **kwargs):
                    nonlocal published
                    result = replace(source, destination, **kwargs)
                    if destination == 'task-owner.md' and not published:
                        published = True
                    return result

                def fail_directory_fsync(fd):
                    nonlocal failed
                    if published and not failed and stat.S_ISDIR(os.fstat(fd).st_mode):
                        failed = True
                        raise OSError('fixture: directory fsync failed after replace')
                    return fsync(fd)

                with patch('install.os.replace', side_effect=record_replace), \
                     patch('install.os.fsync', side_effect=fail_directory_fsync):
                    with self.assertRaisesRegex(OSError, 'fixture: directory fsync failed'):
                        install(home, apply=True)
                self.assertTrue(published)
                self.assertTrue(failed)
                after = {str(path.relative_to(claude)): (path.read_bytes(), stat.S_IMODE(path.stat().st_mode))
                         for path in claude.rglob('*') if path.is_file() and 'agent-harness-backups' not in path.parts}
                self.assertEqual(after, before)

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
                                                    text=True, capture_output=True, timeout=15)
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
        def fail_once(source, destination, **kwargs):
            nonlocal failed
            in_claude = os.fstat(kwargs['dst_dir_fd']).st_ino == self.claude.stat().st_ino
            if destination == 'settings.json' and in_claude and not failed:
                failed = True
                raise OSError('fixture: settings replacement failed')
            return replace(source, destination, **kwargs)
        with patch('install.os.replace', side_effect=fail_once), self.assertRaisesRegex(OSError, 'fixture'):
            install(self.home, apply=True)
        self.assertTrue(failed)
        self.assertEqual(self.managed_snapshot(), before)
        self.assertFalse(list(self.claude.rglob('.agent-harness-*')))
        saved, = (self.claude / 'agent-harness-backups').rglob('settings.json')
        self.assertEqual(saved.read_bytes(), before['settings.json'][0])
        self.assertEqual(stat.S_IMODE(saved.stat().st_mode), 0o600)

    def test_every_managed_write_boundary_rolls_back_to_exact_originals(self):
        from install import atomic_write, AGENTS, HOOKS, TOOLS
        total = len(AGENTS) + len(HOOKS) + len(TOOLS) + 2
        for boundary in range(total):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as temporary:
                home = Path(temporary).resolve()
                claude = home / '.claude'
                claude.mkdir()
                (claude / 'CLAUDE.md').write_text('existing instructions\n')
                (claude / 'settings.json').write_text('{"model":"keep"}\n')
                before = {path.name: (path.read_bytes(), stat.S_IMODE(path.stat().st_mode))
                          for path in (claude / 'CLAUDE.md', claude / 'settings.json')}
                writes = 0
                fired = False

                def fail_at_boundary(path, data, mode=0o600, **kwargs):
                    nonlocal writes, fired
                    if 'agent-harness-backups' not in path.parts and not fired:
                        if writes == boundary and not fired:
                            fired = True
                            raise OSError('fixture: interrupted managed write')
                        writes += 1
                    return atomic_write(path, data, mode, **kwargs)

                with patch('install.atomic_write', side_effect=fail_at_boundary):
                    with self.assertRaisesRegex(OSError, 'interrupted managed write'):
                        install(home, apply=True)
                self.assertEqual(writes, boundary)
                self.assertEqual({path.name: (path.read_bytes(), stat.S_IMODE(path.stat().st_mode))
                                  for path in (claude / 'CLAUDE.md', claude / 'settings.json')}, before)
                for folder in ('agents', 'hooks', 'tools'):
                    self.assertEqual(list((claude / folder).iterdir()) if (claude / folder).exists() else [], [])
                self.assertFalse(list(claude.rglob('.agent-harness-*')))

    def test_swapped_ancestor_at_each_write_stage_cannot_redirect_install(self):
        from install import atomic_write
        for name in ('agents', 'hooks', 'tools', '.claude'):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                home = Path(temporary).resolve()
                claude = home / '.claude'
                claude.mkdir()
                for folder in ('agents', 'hooks', 'tools'):
                    (claude / folder).mkdir()
                outside = home / 'outside'
                outside.mkdir()
                marker = outside / 'marker'
                marker.write_text('unchanged')
                swapped = False

                def swap_before_target(path, data, mode=0o600, **kwargs):
                    nonlocal swapped
                    target = claude if name == '.claude' else claude / name
                    if not swapped and (name == '.claude' or path.parent == target):
                        swapped = True
                        target.rename(target.with_name(target.name + '-moved'))
                        target.symlink_to(outside, target_is_directory=True)
                    return atomic_write(path, data, mode, **kwargs)

                with patch('install.atomic_write', side_effect=swap_before_target):
                    with self.assertRaises((OSError, RuntimeError)):
                        install(home, apply=True)
                self.assertTrue(swapped)
                self.assertEqual(list(outside.iterdir()), [marker])
                self.assertEqual(marker.read_text(), 'unchanged')

    def test_final_parent_swap_during_replace_cannot_report_installed(self):
        outside = self.home / 'outside'
        outside.mkdir()
        marker = outside / 'marker'
        marker.write_text('unchanged')
        replace = os.replace
        swapped = False

        def swap_during_last_replace(source, destination, **kwargs):
            nonlocal swapped
            if Path(destination).name == 'settings.json' and not swapped:
                swapped = True
                self.claude.rename(self.home / 'claude-moved')
                self.claude.symlink_to(outside, target_is_directory=True)
            return replace(source, destination, **kwargs)

        with patch('install.os.replace', side_effect=swap_during_last_replace):
            with self.assertRaises((OSError, RuntimeError)):
                install(self.home, apply=True)
        self.assertTrue(swapped)
        self.assertEqual(list(outside.iterdir()), [marker])

    def test_backup_directory_swap_cannot_redirect_private_snapshot(self):
        self.seed_existing_installation()
        outside = self.home / 'outside'
        outside.mkdir()
        marker = outside / 'marker'
        marker.write_text('unchanged')
        from install import atomic_write
        swapped = False

        def swap_before_backup(path, data, mode=0o600, **kwargs):
            nonlocal swapped
            backup_root = self.claude / 'agent-harness-backups'
            if not swapped and backup_root in path.parents:
                swapped = True
                backup_root.rename(self.claude / 'backups-moved')
                backup_root.symlink_to(outside, target_is_directory=True)
            return atomic_write(path, data, mode, **kwargs)

        with patch('install.atomic_write', side_effect=swap_before_backup):
            with self.assertRaises(OSError):
                install(self.home, apply=True)
        self.assertTrue(swapped)
        self.assertEqual(list(outside.iterdir()), [marker])
        self.assertEqual(marker.read_text(), 'unchanged')

    def test_rollback_failure_is_reported_and_other_files_are_still_restored(self):
        self.seed_existing_installation()
        before = self.managed_snapshot()
        replace = os.replace
        failed = False
        def fail_install_and_one_restore(source, destination, **kwargs):
            nonlocal failed
            in_claude = os.fstat(kwargs['dst_dir_fd']).st_ino == self.claude.stat().st_ino
            in_agents = os.fstat(kwargs['dst_dir_fd']).st_ino == (self.claude / 'agents').stat().st_ino
            if destination == 'settings.json' and in_claude:
                failed = True
                raise OSError('fixture: write failure')
            if failed and destination == 'task-owner.md' and in_agents:
                raise OSError('fixture: restore failure')
            return replace(source, destination, **kwargs)
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
