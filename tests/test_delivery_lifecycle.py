"""Real disposable delivery and explicit recovery lifecycle controls."""

import importlib.util
import json
import os
import shutil
import sys
import unittest
from pathlib import Path
from unittest import mock

import test_scratch_recovery as fixtures


class DeliveryLifecycle(unittest.TestCase):
    setUp = fixtures.ScratchRecovery.setUp
    head = fixtures.ScratchRecovery.head
    invoke = fixtures.ScratchRecovery.invoke

    def commit_feature(self, text, *, test=None):
        (self.feature / 'app.txt').write_text(text)
        if test is not None:
            (self.feature / 'tests/test_ok.py').write_text(test)
        fixtures.command('git', 'add', 'app.txt', 'tests/test_ok.py', cwd=self.feature, env=self.env)
        fixtures.command('git', 'commit', '-qm', 'next feature', cwd=self.feature, env=self.env)
        self.feature_head = self.head(self.feature)

    def resolve(self, key, *, expected=None, env=None, check=None):
        result = fixtures.command(sys.executable, str(fixtures.INTEGRATE),
                                  '--repo', str(self.original), '--original-branch', 'main',
                                  '--expected-head', expected or self.head(self.original),
                                  '--resolve-journal', key, '--check', check or fixtures.CHECK,
                                  env=self.env if env is None else env, check=False)
        return result, json.loads(result.stdout) if result.stdout else {}

    def test_scratch_check_runs_outside_vcs_path_components(self):
        self.commit_feature('feature\n', test=
            'import unittest\nfrom pathlib import Path\nclass Check(unittest.TestCase):\n'
            ' def test_visible_worktree(self):\n'
            '  self.assertFalse(set(Path.cwd().parts) & {".git", ".hg", ".sl"})\n')
        result, data = self.invoke()
        self.assertEqual((result.returncode, data['status']), (0, 'INTEGRATED'), result.stdout)

    def test_natural_cleanup_does_not_block_next_feature(self):
        fixtures.command('git', 'config', 'core.hooksPath', '/dev/null', cwd=self.original, env=self.env)
        (self.feature / '.gitignore').write_text('scratch-result.tmp\n')
        self.commit_feature('feature\n', test=
            'import unittest\nfrom pathlib import Path\nclass Check(unittest.TestCase):\n'
            ' def test_artifact(self):\n'
            '  self.assertTrue(Path("app.txt").exists())\n'
            f'  if Path.cwd().resolve()!=Path({str(self.original)!r}).resolve():\n'
            '   Path("scratch-result.tmp").write_text("retain")\n')
        fixtures.command('git', 'add', '.gitignore', cwd=self.feature, env=self.env)
        fixtures.command('git', 'commit', '-qm', 'ignore artifact', cwd=self.feature, env=self.env)
        self.feature_head = self.head(self.feature)
        result, data = self.invoke()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertTrue(data['cleanup_pending'])
        record = json.loads(Path(data['journal']).read_text())
        scratch = Path(record['scratch'])
        (scratch / 'scratch-result.tmp').unlink()
        fixtures.command('git', 'worktree', 'remove', str(scratch), cwd=self.original, env=self.env)
        fixtures.command('git', 'update-ref', '-d', record['ref'], data['head'], cwd=self.original, env=self.env)
        Path(record['container']).rmdir()
        repeat, repeated = self.invoke()
        self.assertEqual((repeat.returncode, repeated['status']), (0, 'ALREADY_INTEGRATED'), repeat.stdout)
        self.assertFalse(repeated['cleanup_pending'])
        self.base = self.head(self.original)
        self.commit_feature('next feature\n')
        next_result, next_data = self.invoke()
        self.assertEqual((next_result.returncode, next_data['status']), (0, 'INTEGRATED'), next_result.stdout)

    def test_resolve_preapply_failure_preserves_artifacts_and_allows_corrected_feature(self):
        self.commit_feature('feature\n', test='import unittest\nclass Check(unittest.TestCase):\n def test_fail(self): self.fail("control")\n')
        failed, data = self.invoke()
        self.assertEqual(failed.returncode, 3, failed.stdout)
        self.assertEqual(self.head(self.original), self.base)
        journal = Path(data['journal'])
        before = json.loads(journal.read_text())
        resolved, resolution = self.resolve(before['key'])
        self.assertEqual((resolved.returncode, resolution.get('status')), (0, 'RESOLVED'), resolved.stdout + resolved.stderr)
        self.assertTrue(Path(before['scratch']).exists(), 'resolver deleted retained scratch')
        self.assertEqual(self.head(self.original), self.base)
        self.commit_feature('corrected\n', test='import unittest\nclass Check(unittest.TestCase):\n def test_ok(self): self.assertEqual(2+2,4)\n')
        fixed, fixed_data = self.invoke()
        self.assertEqual((fixed.returncode, fixed_data['status']), (0, 'INTEGRATED'), fixed.stdout)

    def test_resolve_journal_accepts_focused_check_only_when_it_runs_a_test(self):
        # GoodQA #14729: the focused form reaches --resolve-journal; a pattern that runs no test must not resolve.
        self.commit_feature('feature\n', test='import unittest\nclass Check(unittest.TestCase):\n def test_fail(self): self.fail("control")\n')
        failed, data = self.invoke()
        self.assertEqual(failed.returncode, 3, failed.stdout)
        journal = Path(data['journal'])
        key = json.loads(journal.read_text())['key']
        focused = 'python3 -m unittest discover -s tests -p '
        empty, outcome = self.resolve(key, check=focused + 'test_missing.py')
        self.assertEqual((empty.returncode, outcome.get('status')), (3, 'RECOVERY_REQUIRED'), empty.stdout + empty.stderr)
        self.assertNotEqual(json.loads(journal.read_text())['phase'], 'resolved')
        globbed, outcome = self.resolve(key, check=focused + "'test_*.py'")
        self.assertEqual((globbed.returncode, outcome.get('status')), (2, 'BLOCKED_POLICY'), globbed.stdout)
        self.assertNotEqual(json.loads(journal.read_text())['phase'], 'resolved')
        passed, outcome = self.resolve(key, check=focused + 'test_ok.py')
        self.assertEqual((passed.returncode, outcome.get('status')), (0, 'RESOLVED'), passed.stdout + passed.stderr)

    def test_resolver_rejects_wrong_head_and_wrong_scope_without_retiring(self):
        self.commit_feature('feature\n', test='import unittest\nclass Check(unittest.TestCase):\n def test_fail(self): self.fail("control")\n')
        _, data = self.invoke()
        journal = Path(data['journal'])
        record = json.loads(journal.read_text())
        result, _ = self.resolve(record['key'], expected=self.feature_head)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotEqual(json.loads(journal.read_text())['phase'], 'resolved')

    def module(self):
        spec = importlib.util.spec_from_file_location('delivery_lifecycle_probe', fixtures.INTEGRATE)
        module = importlib.util.module_from_spec(spec)
        with mock.patch.object(sys, 'path', [str(fixtures.INTEGRATE.parent), *sys.path]):
            spec.loader.exec_module(module)
        return module

    def test_more_than_4096_archived_deliveries_do_not_scan_history(self):
        first, delivered = self.invoke()
        self.assertEqual(first.returncode, 0, first.stdout)
        record = json.loads(Path(delivered['journal']).read_text())
        archive = Path(delivered['journal']).parent.parent
        self.assertEqual(archive.name, 'archive')
        module = self.module()
        identity = module.checkout_identity(self.original)
        for index in range(4100):
            historic = {**record, 'source_branch': f'feat/history-{index}'}
            key = module.journal_key(identity, 'main', record['base'],
                                     historic['source_branch'], record['source'])
            historic['key'] = key
            directory = archive / key
            directory.mkdir(mode=0o700)
            module.write_journal(directory, historic, first=True)
        self.assertGreater(len(list(archive.iterdir())), 4096)
        self.base = self.head(self.original)
        self.commit_feature('next after history\n')
        root, _, _, _ = module.scratch_journal_root(self.original, 30)
        key = module.journal_key(identity, 'main', self.base, 'feat/recovery', self.feature_head)
        with mock.patch.object(module, 'read_journal', side_effect=AssertionError('archived history was scanned')), \
                mock.patch.object(module, 'inspect_git', side_effect=AssertionError('history started Git')):
            self.assertEqual(module.scan_journals(root, self.original, identity, 'main', key, 30),
                             (None, None, None))
        result, data = self.invoke()
        self.assertEqual((result.returncode, data['status']), (0, 'INTEGRATED'), result.stdout)

    def test_other_linked_worktree_partial_reservation_is_not_scanned(self):
        module = self.module()
        root, _, _, _ = module.scratch_journal_root(self.original, 30)
        other = module.scope_directory(root, module.checkout_identity(self.feature), 'feat/recovery')
        (other / 'active' / ('e' * 64)).mkdir(mode=0o700)  # Journal not written yet.
        result, data = self.invoke()
        self.assertEqual((result.returncode, data['status']), (0, 'INTEGRATED'), result.stdout)
        self.assertFalse((other / 'active' / ('e' * 64) / 'journal.json').exists())

    def test_aggregate_scan_deadline_stops_before_new_git_work(self):
        first, delivered = self.invoke()
        self.assertEqual(first.returncode, 0, first.stdout)
        module = self.module()
        identity = module.checkout_identity(self.original)
        root, _, _, _ = module.scratch_journal_root(self.original, 30)
        key = module.journal_key(identity, 'main', self.base, 'feat/recovery', self.feature_head)
        archived = Path(delivered['journal']).parent
        directory = archived.parent.parent / 'active' / archived.name
        archived.rename(directory)  # Crash before terminal metadata archival.
        # The real metadata read consumes the aggregate budget. No record is
        # discarded and no repository test/merge is allowed after expiry.
        clock = [0.0]
        real_read = module.read_journal
        def slow_read(path):
            value = real_read(path)
            clock[0] = 31.0
            return value
        with mock.patch.object(module.time, 'monotonic', side_effect=lambda: clock[0]), \
                mock.patch.object(module, 'read_journal', side_effect=slow_read), \
                mock.patch.object(module, 'inspect_git', side_effect=AssertionError('scan started Git')):
            blocked, _, _ = module.scan_journals(root, self.original, identity, 'main', key, 30)
        self.assertEqual(blocked, directory)
        self.assertEqual(self.head(self.original), delivered['head'])
        self.assertTrue((directory / 'journal.json').is_file())

    def test_resolution_rejects_hardlinked_journal_and_keeps_original(self):
        self.commit_feature('feature\n', test='import unittest\nclass Check(unittest.TestCase):\n def test_fail(self): self.fail("control")\n')
        _, data = self.invoke()
        journal = Path(data['journal'])
        record = json.loads(journal.read_text())
        os.link(journal, self.root / 'journal-alias')
        result, _ = self.resolve(record['key'])
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.head(self.original), self.base)
        self.assertNotEqual(json.loads(journal.read_text())['phase'], 'resolved')

    def test_failed_delivered_check_cannot_be_resolved_without_passing_checks(self):
        self.commit_feature('feature\n', test=
            'import unittest\nfrom pathlib import Path\nclass Check(unittest.TestCase):\n'
            ' def test_original_control(self):\n'
            f'  self.assertNotEqual(Path.cwd().resolve(),Path({str(self.original)!r}).resolve())\n')
        failed, data = self.invoke()
        self.assertEqual((failed.returncode, data['status']), (3, 'DELIVERED_CHECK_FAILED'), failed.stdout)
        record = json.loads(Path(data['journal']).read_text())
        result, resolution = self.resolve(record['key'])
        self.assertEqual((result.returncode, resolution['status']), (3, 'RECOVERY_REQUIRED'), result.stdout)
        self.assertNotEqual(json.loads(Path(data['journal']).read_text())['phase'], 'resolved')
        self.assertEqual(self.head(self.original), data['candidate'])
        self.assertTrue(Path(record['scratch']).exists())
        self.assertEqual(fixtures.command('git', 'rev-parse', record['ref'], cwd=self.original,
                                         env=self.env).stdout.strip(), data['candidate'])

    def test_resolver_rejects_other_linked_worktree_scope(self):
        self.commit_feature('feature\n', test='import unittest\nclass Check(unittest.TestCase):\n def test_fail(self): self.fail("control")\n')
        _, data = self.invoke()
        journal = Path(data['journal'])
        record = json.loads(journal.read_text())
        result = fixtures.command(sys.executable, str(fixtures.INTEGRATE), '--repo', str(self.feature),
                                  '--original-branch', 'feat/recovery', '--expected-head', self.feature_head,
                                  '--resolve-journal', record['key'], '--check', fixtures.CHECK,
                                  env=self.env, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotEqual(json.loads(journal.read_text())['phase'], 'resolved')

    def test_archive_refuses_existing_destination_without_replacement(self):
        module = self.module()
        root, _, _, _ = module.scratch_journal_root(self.original, 30)
        identity = module.checkout_identity(self.original)
        directory, record = module.reserve_scratch(root, self.original, identity, 'main', self.base,
                                                    'feat/recovery', self.feature_head)
        self.addCleanup(lambda: Path(record['container']).rmdir())
        destination = directory.parent.parent / 'archive' / directory.name
        destination.mkdir(mode=0o700)
        marker = destination / 'keep.txt'
        marker.write_text('prior archive must survive')
        with self.assertRaises(OSError):
            module.archive_journal(directory)
        self.assertEqual(marker.read_text(), 'prior archive must survive')
        self.assertTrue((directory / 'journal.json').is_file())

    def test_explicit_resolution_handles_crash_before_first_journal_write(self):
        module = self.module()
        root, _, _, _ = module.scratch_journal_root(self.original, 30)
        scope = module.scope_directory(root, module.checkout_identity(self.original), 'main')
        key = 'e' * 64
        (scope / 'active' / key).mkdir(mode=0o700)
        blocked, data = self.invoke()
        self.assertEqual((blocked.returncode, data['status']), (3, 'RECOVERY_REQUIRED'), blocked.stdout)
        resolved, data = self.resolve(key)
        self.assertEqual((resolved.returncode, data['status']), (0, 'RESOLVED'), resolved.stdout)
        self.assertTrue(data['artifacts_unknown'])
        self.assertEqual(json.loads(Path(data['journal']).read_text())['resolved_head'], self.base)
        delivered, data = self.invoke()
        self.assertEqual((delivered.returncode, data['status']), (0, 'INTEGRATED'), delivered.stdout)

    def test_terminal_reconciliation_does_not_block_a_new_feature(self):
        first, data = self.invoke()
        self.assertEqual(first.returncode, 0, first.stdout)
        # Model an explicit remote-history reconciliation in a disposable repo.
        # The prior local merge is deliberately no longer an ancestor.
        fixtures.command('git', 'reset', '--hard', self.base, cwd=self.original, env=self.env)
        self.commit_feature('next after reconciliation\n')
        result, data = self.invoke()
        self.assertEqual((result.returncode, data['status']), (0, 'INTEGRATED'), result.stdout)

    def test_unresolved_substituted_container_blocks_new_work(self):
        self.commit_feature('feature\n', test='import unittest\nclass Check(unittest.TestCase):\n def test_fail(self): self.fail("control")\n')
        _, data = self.invoke()
        record = json.loads(Path(data['journal']).read_text())
        container = Path(record['container'])
        saved = container.with_name(container.name + '-saved')
        container.rename(saved)
        container.mkdir(mode=0o700)
        self.addCleanup(container.rmdir)
        self.addCleanup(lambda: shutil.rmtree(saved))
        blocked, blocked_data = self.invoke()
        self.assertEqual((blocked.returncode, blocked_data['status']), (3, 'RECOVERY_REQUIRED'), blocked.stdout)
        self.assertEqual(self.head(self.original), self.base)

    def test_exact_verification_uses_one_shared_scan_deadline(self):
        first, data = self.invoke()
        self.assertEqual(first.returncode, 0, first.stdout)
        module = self.module()
        directory = Path(data['journal']).parent
        record = module.read_journal(directory)
        clock = [0.0]
        real_inspect = module.inspect_git
        calls = []
        def timed_inspect(*args, **kwargs):
            calls.append(kwargs['timeout'])
            result = real_inspect(*args, **kwargs)
            clock[0] += 20
            return result
        with mock.patch.object(module.time, 'monotonic', side_effect=lambda: clock[0]), \
                mock.patch.object(module, 'inspect_git', side_effect=timed_inspect), \
                mock.patch.object(module, 'safe_source'), mock.patch.object(module, 'index_unflagged'):
            with self.assertRaises(OSError):
                module.completed_journal_is_verified(self.original, module.checkout_identity(self.original),
                                                     'main', directory, record, 600, deadline=30)
        self.assertEqual(calls, [30, 10])

    def test_legacy_journal_can_be_resolved_without_moving_its_worktree(self):
        module = self.module()
        root, _, _, _ = module.scratch_journal_root(self.original, 30)
        identity = module.checkout_identity(self.original)
        key = module.journal_key(identity, 'main', self.base, 'feat/old', self.feature_head)
        directory = root / key
        directory.mkdir(mode=0o700)
        scratch = directory / 'worktree'
        scratch.mkdir(mode=0o700)
        (scratch / 'keep.txt').write_text('retained legacy data')
        record = {'schema': 1, 'phase': 'started', 'key': key, 'original': str(self.original),
                  'original_dev': identity[0], 'original_ino': identity[1], 'branch': 'main',
                  'base': self.base, 'source_branch': 'feat/old', 'source': self.feature_head,
                  'scratch': str(scratch)}
        module.write_journal(directory, record, first=True)
        result, data = self.resolve(key)
        self.assertEqual((result.returncode, data['status']), (0, 'RESOLVED'), result.stdout)
        self.assertEqual(Path(data['journal']), directory / 'journal.json')
        self.assertEqual((scratch / 'keep.txt').read_text(), 'retained legacy data')
        result, data = self.invoke()
        self.assertEqual((result.returncode, data['status']), (0, 'INTEGRATED'), result.stdout)

    def test_nested_source_preflight_shares_the_remaining_deadline(self):
        module = self.module()
        clock = [0.0]
        calls = []
        def bounded(repo, args, env, *, timeout, limit):
            calls.append(timeout)
            clock[0] += 20
            if args[:2] == ['ls-files', '--stage']:
                return 0, b'100644 ' + b'a' * 40 + b' 0\tapp.txt\0'
            if args[:2] == ['ls-files', '-v']:
                return 0, b'H app.txt\0'
            return 1, b''
        with mock.patch.object(module.time, 'monotonic', side_effect=lambda: clock[0]), \
                mock.patch.dict(module.require_safe_source.__globals__, {'_bounded_git': bounded}):
            with self.assertRaises((OSError, module.IndexInspectionError)):
                module.checked_original(self.original, 'main', self.base, 600, deadline=30)
        self.assertEqual(calls, [30, 10], 'nested commands each received a fresh whole scan budget')

    def test_resolved_same_source_can_retry_after_external_failure_is_fixed(self):
        marker = self.root / 'external-ready'
        self.commit_feature('feature\n', test=
            'import unittest\nfrom pathlib import Path\nclass Check(unittest.TestCase):\n'
            ' def test_external(self):\n'
            f'  self.assertTrue(Path({str(marker)!r}).exists())\n')
        failed, data = self.invoke()
        self.assertEqual(failed.returncode, 3, failed.stdout)
        record = json.loads(Path(data['journal']).read_text())
        resolved, resolution = self.resolve(record['key'])
        self.assertEqual(resolved.returncode, 0, resolved.stdout)
        prior_journal = Path(resolution['journal'])
        marker.write_text('ready')
        result, data = self.invoke()
        self.assertEqual((result.returncode, data['status']), (0, 'INTEGRATED'), result.stdout)
        self.assertEqual(self.head(self.original), data['head'])
        archived_history = list(prior_journal.parent.parent.glob('history/*/*/journal.json'))
        self.assertEqual(len(archived_history), 1, 'prior explicit resolution was not retained')
        self.assertEqual(json.loads(archived_history[0].read_text())['phase'], 'resolved')

    def test_malformed_json_fields_return_structured_recovery_before_merge(self):
        module = self.module()
        root, _, _, _ = module.scratch_journal_root(self.original, 30)
        directory, record = module.reserve_scratch(root, self.original, module.checkout_identity(self.original),
                                                    'main', self.base, 'feat/recovery', self.feature_head)
        self.addCleanup(lambda: Path(record['container']).rmdir())
        for field, value in (('container', None), ('container', 7), ('phase', []),
                             ('phase', True), ('key', 7), ('ref', False), ('schema', True),
                             ('source_branch', 'bad\ud800'), ('branch', 'bad\ud800'),
                             ('container', '/tmp/bad\ud800'), ('ref', 'bad\ud800'),
                             ('phase', 'bad\ud800'), ('source_branch', 'bad\0name'),
                             ('container', '/tmp/bad\0name'), ('ref', 'bad\0name')):
            with self.subTest(field=field):
                module.write_journal(directory, {**record, field: value})
                result, data = self.invoke()
                self.assertEqual((result.returncode, data['status']), (3, 'RECOVERY_REQUIRED'),
                                 result.stdout + result.stderr)
                self.assertNotIn('Traceback', result.stderr)
                self.assertEqual(self.head(self.original), self.base)

    def test_resolved_pinned_attempt_retries_without_reusing_or_deleting_old_ref(self):
        (self.original / '.gitignore').write_text('cache.txt\n')
        fixtures.command('git', 'add', '.gitignore', cwd=self.original, env=self.env)
        fixtures.command('git', 'commit', '-qm', 'ignore cache', cwd=self.original, env=self.env)
        self.base = self.head(self.original)
        (self.feature / 'cache.txt').write_text('tracked feature cache')
        fixtures.command('git', 'add', 'cache.txt', cwd=self.feature, env=self.env)
        fixtures.command('git', 'commit', '-qm', 'track cache', cwd=self.feature, env=self.env)
        self.feature_head = self.head(self.feature)
        cache = self.original / 'cache.txt'
        cache.write_text('ignored user cache')
        failed, data = self.invoke()
        self.assertEqual((failed.returncode, data['phase']), (3, 'apply'), failed.stdout)
        record = json.loads(Path(data['journal']).read_text())
        old_candidate = data['candidate']
        legacy_ref = 'refs/agent-harness/delivery/' + record['key']
        fixtures.command('git', 'update-ref', legacy_ref, old_candidate, cwd=self.original, env=self.env)
        resolved, resolution = self.resolve(record['key'])
        self.assertEqual((resolved.returncode, resolution['status']), (0, 'RESOLVED'), resolved.stdout)
        cache.unlink()  # User has preserved and removed the known collision.
        retried, delivered = self.invoke()
        self.assertEqual((retried.returncode, delivered['status']), (0, 'INTEGRATED'), retried.stdout)
        for ref in {record['ref'], legacy_ref}:
            self.assertEqual(fixtures.command('git', 'rev-parse', ref, cwd=self.original,
                                             env=self.env).stdout.strip(), old_candidate)
        self.assertEqual(self.head(self.original), delivered['head'])

    def test_resolved_archive_read_cannot_exceed_scan_deadline(self):
        self.commit_feature('feature\n', test='import unittest\nclass Check(unittest.TestCase):\n def test_fail(self): self.fail("control")\n')
        _, failed = self.invoke()
        key = json.loads(Path(failed['journal']).read_text())['key']
        resolved, data = self.resolve(key)
        self.assertEqual(resolved.returncode, 0, resolved.stdout)
        module = self.module()
        root, _, _, _ = module.scratch_journal_root(self.original, 30)
        clock = [0.0]
        real_read = module.read_journal
        def slow_read(directory):
            record = real_read(directory)
            clock[0] = 31
            return record
        with mock.patch.object(module.time, 'monotonic', side_effect=lambda: clock[0]), \
                mock.patch.object(module, 'read_journal', side_effect=slow_read):
            with self.assertRaises(OSError):
                module.scan_journals(root, self.original, module.checkout_identity(self.original), 'main', key, 30)
        self.assertEqual(self.head(self.original), self.base)

    def test_valid_utf8_feature_branch_remains_supported(self):
        branch = 'feat/café-🦆'
        fixtures.command('git', 'branch', '-m', 'feat/recovery', branch,
                         cwd=self.feature, env=self.env)
        result = fixtures.command(sys.executable, str(fixtures.INTEGRATE), '--repo', str(self.original),
                                  '--original-branch', 'main', '--expected-head', self.base,
                                  '--source', branch, '--expected-source-head', self.feature_head,
                                  '--check', fixtures.CHECK, env=self.env, check=False)
        data = json.loads(result.stdout)
        self.assertEqual((result.returncode, data['status']), (0, 'INTEGRATED'), result.stdout + result.stderr)
        self.assertEqual((self.original / 'app.txt').read_text(), 'feature\n')
        self.assertTrue(self.module().valid_identity_text('/tmp/café-🦆'))


if __name__ == '__main__':
    unittest.main()
