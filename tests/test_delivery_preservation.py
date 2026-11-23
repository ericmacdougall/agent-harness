"""Real Git preservation controls; only GitHub transport is fixture-owned."""
import json
from pathlib import Path
import tempfile
import sys
import os
import unittest
from unittest import mock

import test_delivery_workflow as fixture
from commit_messages import message

sys.path.insert(0, str(fixture.DELIVER.parent))
from git_safety import UntrackedPreservation
from integrate_local import OriginalScope, ExternalApplyError


class Preservation(unittest.TestCase):
    def setUp(self):
        self.f = fixture.DeliveryWorkflow(methodName='runTest')
        native_temp = tempfile.TemporaryDirectory
        def physical(*args, **kwargs):
            return native_temp(*args, **kwargs, dir=str(Path(tempfile.gettempdir()).resolve()))
        with mock.patch.object(fixture.tempfile, 'TemporaryDirectory', physical):
            self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.f.configure_github()
        (self.f.bin / 'python3').symlink_to(sys.executable)
        self.manifest = self.f.root / 'preservation.json'

    def inventory(self):
        return self.f.invoke('inventory', '--original', str(self.f.original),
                             '--original-branch', 'main', '--expected-original-head', self.f.base,
                             '--source', str(self.f.source), '--expected-source-head', self.f.head,
                             '--out', str(self.manifest))

    def prepare_preserved(self):
        result, captured = self.inventory()
        self.assertEqual((result.returncode, captured.get('status')), (0, 'INVENTORIED'), result.stdout)
        return self.f.invoke(*self.f.prepare_args(), '--preserve-untracked-manifest', str(self.manifest),
                             '--preservation-sha256', captured['preservation_sha256'])

    def proof(self):
        with mock.patch.dict(os.environ, self.f.env, clear=True):
            return UntrackedPreservation.capture(self.f.original, 'main', self.f.base, self.f.source, self.f.head)

    def assert_no_publication(self):
        self.assertFalse(json.loads(self.f.github_state.read_text())['created'])
        rows = [json.loads(l) for l in self.f.events.read_text().splitlines()]
        self.assertFalse(any('push' in r for r in rows), 'UNEXPECTED_PUBLICATION')

    def test_default_still_refuses_same_original(self):
        (self.f.original / 'personal').write_text('synthetic retained bytes')
        result, denied = self.f.invoke(*self.f.prepare_args())
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(denied['status'], 'BLOCKED_LOCAL')
        self.assertFalse(json.loads(self.f.github_state.read_text())['created'])

    def test_noncolliding_preserved_remote_delivery(self):
        note = self.f.original / 'personal'
        note.write_text('synthetic retained bytes')
        empty = self.f.original / 'empty'
        empty.mkdir()
        before = (note.stat(), empty.stat())
        result, prepared = self.prepare_preserved()
        self.assertEqual((result.returncode, prepared['status']), (0, 'PR_READY'), result.stdout)
        target = self.f.merge_remote()
        result, delivered = self.f.invoke(*self.f.finish_args())
        self.assertEqual((result.returncode, delivered['status']), (0, 'DELIVERED'), result.stdout)
        self.assertEqual(note.read_text(), 'synthetic retained bytes')
        self.assertEqual(list(empty.iterdir()), [])
        def metadata(s):
            return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_nlink,
                    s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        self.assertEqual(metadata(note.stat()), metadata(before[0]))
        self.assertEqual(metadata(empty.stat()), metadata(before[1]))
        self.assertEqual(fixture.command('git', 'rev-parse', 'HEAD', cwd=self.f.original,
                                          env=self.f.env).stdout.strip(), target)

    def test_shared_tracked_parent_and_ignored_entry_are_preserved(self):
        note = self.f.original / 'tests/personal'
        note.write_text('known sibling fixture')
        ignored = self.f.original / 'ignored-note'
        ignored.write_text('known ignored fixture')
        exclude = self.f.original / '.git/info/exclude'
        with exclude.open('a') as f:
            f.write('\nignored-note\n')
        result, prepared = self.prepare_preserved()
        self.assertEqual((result.returncode, prepared['status']), (0, 'PR_READY'), result.stdout)
        target = self.f.merge_remote()
        result, delivered = self.f.invoke(*self.f.finish_args())
        self.assertEqual((result.returncode, delivered['status']), (0, 'DELIVERED'), result.stdout)
        self.assertEqual(note.read_text(), 'known sibling fixture')
        self.assertEqual(ignored.read_text(), 'known ignored fixture')
        self.assertTrue((self.f.original / 'tests/test_change.py').is_file())
        self.assertEqual(fixture.command('git', 'rev-parse', 'HEAD', cwd=self.f.original,
                                          env=self.f.env).stdout.strip(), target)

    def test_actual_target_collision_refuses_before_publication(self):
        note = self.f.original / 'tests/test_change.py'
        note.write_text('known personal bytes')
        with self.assertRaisesRegex(OSError, 'target collision'):
            self.proof()
        self.assert_no_publication()
        self.assertEqual(note.read_text(), 'known personal bytes')
        # The actual lower Git layer also refuses this untracked overwrite.
        result = fixture.command('git', 'merge', '--ff-only', '--no-overwrite-ignore', self.f.head,
                                 cwd=self.f.original, env=self.f.env, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(note.read_text(), 'known personal bytes')

    def test_case_collision_refuses_on_real_filesystem(self):
        folder = self.f.original / 'TESTS'
        folder.mkdir(exist_ok=True)
        note = folder / 'test_change.py'
        note.write_text('known case fixture')
        with self.assertRaisesRegex(OSError, 'target collision'):
            self.proof()
        self.assert_no_publication()
        self.assertEqual(note.read_text(), 'known case fixture')

    def test_hardlink_alias_of_tracked_target_refuses(self):
        alias = self.f.original / 'personal-alias'
        os.link(self.f.original / 'app.txt', alias)
        with self.assertRaisesRegex(OSError, 'hardlink'):
            self.proof()
        self.assert_no_publication()
        self.assertEqual(alias.read_text(), 'base\n')

    def test_unknown_control_file_refuses_without_opening_it(self):
        note = self.f.original / '.gitattributes'
        note.write_text('known synthetic control fixture')
        native_open = os.open
        def checked_open(path, flags, *args, **kwargs):
            self.assertNotEqual(str(path), '.gitattributes', 'UNKNOWN_LEAF_OPENED')
            self.assertNotEqual(str(path), str(note), 'UNKNOWN_LEAF_OPENED')
            return native_open(path, flags, *args, **kwargs)
        with mock.patch('git_safety.os.open', side_effect=checked_open):
            with self.assertRaisesRegex(OSError, 'Git control file'):
                self.proof()
        self.assert_no_publication()

    def test_inventory_drift_is_not_recaptured(self):
        note = self.f.original / 'personal'
        note.write_text('known before')
        proof = self.proof()
        with mock.patch.dict(os.environ, self.f.env, clear=True):
            proof.verify(self.f.original, 'main')
            note.write_text('known changed')
            with self.assertRaisesRegex(OSError, 'inventory changed', msg='INVENTORY_DRIFT_ADMITTED'):
                proof.verify(self.f.original, 'main')
        self.assert_no_publication()

    def test_lower_external_guard_binds_inventory(self):
        (self.f.original / 'personal').write_text('known lower-guard fixture')
        proof = self.proof()
        with mock.patch.dict(os.environ, self.f.env, clear=True):
            with OriginalScope(self.f.original, 'main', preservation=proof) as scope:
                guard = scope.reserve_external(base=self.f.base, target=self.f.head, task_digest='a' * 64)
                self.assertEqual(guard.record['preservation_sha256'], proof.digest)
                key = guard.key
            with OriginalScope(self.f.original, 'main') as scope:
                with self.assertRaises(ExternalApplyError, msg='UNBOUND_GUARD_ACCEPTED'):
                    scope.load_external(key, 'a' * 64)
            with OriginalScope(self.f.original, 'main', preservation=proof) as scope:
                self.assertEqual(scope.load_external(key, 'a' * 64).key, key)

    def test_generation_manifest_tamper_refuses_before_checkout(self):
        note = self.f.original / 'personal'
        note.write_text('known unchanged')
        result, prepared = self.prepare_preserved()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.f.merge_remote()
        copy = Path(prepared['state']).parent / 'preservation.json'
        with copy.open('ab') as f:
            f.write(b'\n')
        result, refused = self.f.invoke(*self.f.finish_args())
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(refused['status'], 'RECOVERY_REQUIRED')
        self.assertEqual(note.read_text(), 'known unchanged')
        self.assertEqual(fixture.command('git', 'rev-parse', 'HEAD', cwd=self.f.original,
                                          env=self.f.env).stdout.strip(), self.f.base)

    def test_eventual_merged_target_collision_refuses(self):
        note = self.f.original / 'personal'
        note.write_text('known retained')
        result, prepared = self.prepare_preserved()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.f.merge_remote()
        (self.f.merged / 'personal').write_text('new remote tracked content')
        fixture.command('git', 'add', 'personal', cwd=self.f.merged, env=self.f.env)
        fixture.command('git', 'commit', '-qm', message('add another remote change'), cwd=self.f.merged, env=self.f.env)
        target = fixture.command('git', 'rev-parse', 'HEAD', cwd=self.f.merged, env=self.f.env).stdout.strip()
        fixture.command('git', 'push', '-q', str(self.f.remote), target + ':refs/heads/main',
                        cwd=self.f.merged, env=self.f.env)
        self.f.change_github(target=target)
        result, refused = self.f.invoke(*self.f.finish_args())
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(refused['status'], 'RECOVERY_REQUIRED')
        self.assertEqual(note.read_text(), 'known retained')
        self.assertEqual(fixture.command('git', 'rev-parse', 'HEAD', cwd=self.f.original,
                                          env=self.f.env).stdout.strip(), self.f.base)


if __name__ == '__main__':
    unittest.main()
