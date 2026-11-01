"""Disposable Git proof for the shared external-apply recovery barrier."""

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

import test_scratch_recovery as fixtures


HOOKS = fixtures.INTEGRATE.parent
if str(HOOKS) not in sys.path:
    sys.path.insert(0, str(HOOKS))
spec = importlib.util.spec_from_file_location('external_apply_integration', fixtures.INTEGRATE)
integration = importlib.util.module_from_spec(spec)
spec.loader.exec_module(integration)
TASK = 'a' * 64


class ExternalApply(unittest.TestCase):
    setUp = fixtures.ScratchRecovery.setUp
    head = fixtures.ScratchRecovery.head
    invoke = fixtures.ScratchRecovery.invoke

    def target(self):
        tree = fixtures.command('git', 'rev-parse', self.feature_head + '^{tree}',
                                cwd=self.original, env=self.env).stdout.strip()
        return fixtures.command('git', 'commit-tree', tree, '-p', self.base, '-p', self.feature_head,
                                '-m', 'external checked candidate', cwd=self.original,
                                env=self.env).stdout.strip()

    def ff(self, target):
        fixtures.command('git', '-c', 'core.hooksPath=/dev/null', 'merge', '--ff-only',
                         '--no-overwrite-ignore', '--no-autostash', target,
                         cwd=self.original, env=self.env)

    def scope(self, **kwargs):
        return integration.OriginalScope(self.original, 'main', timeout=15, **kwargs)

    def resolve(self, key):
        return fixtures.command(sys.executable, str(fixtures.INTEGRATE), '--repo', str(self.original),
                                '--original-branch', 'main', '--expected-head', self.head(self.original),
                                '--resolve-journal', key, '--check', fixtures.CHECK, '--timeout', '15',
                                env=self.env, check=False)

    def test_unprotected_failed_check_control_can_claim_already_integrated(self):
        # This is the control: clean advanced HEAD alone cannot prove a passed check.
        target = self.target()
        self.ff(target)
        failed = fixtures.command(sys.executable, '-c', 'raise SystemExit(1)',
                                  cwd=self.original, env=self.env, check=False)
        self.assertEqual(failed.returncode, 1)
        self.base = target
        result, record = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(record['status'], 'ALREADY_INTEGRATED')

    def test_guard_blocks_direct_local_after_external_check_failed(self):
        target = self.target()
        with patch.dict(os.environ, self.env, clear=True), self.scope() as scope:
            guard = scope.reserve_external(base=self.base, target=target, task_digest=TASK)
            self.ff(target)
            failed = fixtures.command(sys.executable, '-c', 'raise SystemExit(1)',
                                      cwd=self.original, env=self.env, check=False)
            self.assertEqual(failed.returncode, 1)
        self.base = target
        result, record = self.invoke()
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertEqual(record['status'], 'RECOVERY_REQUIRED')
        self.assertEqual(Path(record['journal']), guard.journal)
        self.assertEqual(integration.read_journal(guard.journal.parent)['phase'], 'applying')
        # A broken scanner must reproduce the false success even with the same
        # guard bytes present. This falsifies a vacuous metadata-only assertion.
        mutant = self.root / 'ignore_recovery.py'
        mutant.write_text('import sys\n'
                          f'sys.path.insert(0, {str(HOOKS)!r})\n'
                          'import integrate_local as helper\n'
                          'helper.scan_journals = lambda *a, **k: (None, None, None)\n'
                          'raise SystemExit(helper.main())\n')
        with patch.object(fixtures, 'INTEGRATE', mutant):
            broken, false_success = self.invoke()
        self.assertEqual((broken.returncode, false_success['status']), (0, 'ALREADY_INTEGRATED'))
        self.assertTrue(guard.journal.is_file())

    def test_failed_ff_before_advance_keeps_guard_and_ignored_user_bytes(self):
        (self.feature / 'cache.txt').write_text('feature cache\n')
        fixtures.command('git', 'add', 'cache.txt', cwd=self.feature, env=self.env)
        fixtures.command('git', 'commit', '-qm', 'tracked feature cache', cwd=self.feature, env=self.env)
        self.feature_head = self.head(self.feature)
        target = self.target()
        (self.original / '.git/info/exclude').write_text('cache.txt\n')
        (self.original / 'cache.txt').write_text('owned user bytes\n')
        with patch.dict(os.environ, self.env, clear=True), self.scope() as scope:
            guard = scope.reserve_external(base=self.base, target=target, task_digest=TASK)
            result = fixtures.command('git', '-c', 'core.hooksPath=/dev/null', 'merge', '--ff-only',
                       '--no-overwrite-ignore', '--no-autostash', target, cwd=self.original,
                       env=self.env, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(self.head(self.original), self.base)
        result, report = self.invoke()
        self.assertEqual((result.returncode, report['status']), (3, 'RECOVERY_REQUIRED'))
        self.assertEqual((self.original / 'cache.txt').read_text(), 'owned user bytes\n')
        self.assertEqual(integration.read_journal(guard.journal.parent)['phase'], 'applying')

    def test_complete_archives_without_claiming_delivery_and_retains_pin(self):
        target = self.target()
        with patch.dict(os.environ, self.env, clear=True), self.scope() as scope:
            guard = scope.reserve_external(base=self.base, target=target, task_digest=TASK)
            self.assertEqual(guard.record['phase'], 'applying')
            self.assertNotIn('scratch', guard.record)
            edited = guard.record
            edited['phase'] = 'resolved'
            self.assertEqual(guard.record['phase'], 'applying')
            self.ff(target)
            fixtures.command(sys.executable, '-m', 'unittest', 'discover', '-s', 'tests',
                             cwd=self.original, env=self.env)
            complete = scope.complete_external(guard)
            self.assertEqual(complete.record['phase'], 'resolved')
            self.assertEqual(complete.record['resolved_by'], 'workflow')
            self.assertEqual(complete.record['resolved_head'], target)
            self.assertEqual(complete.journal.parent.parent.name, 'archive')
            self.assertNotIn('status', complete.record)
            self.assertEqual(fixtures.command('git', 'rev-parse', complete.ref,
                                             cwd=self.original, env=self.env).stdout.strip(), target)
            loaded = scope.load_external(complete.key, TASK)
            self.assertEqual(loaded.record, complete.record)

    def test_closed_wrong_and_concurrent_scope_are_rejected(self):
        target = self.target()
        with patch.dict(os.environ, self.env, clear=True):
            with self.scope() as first:
                guard = first.reserve_external(base=self.base, target=target, task_digest=TASK)
                with self.assertRaises(integration.ExternalApplyError), self.scope():
                    self.fail('same original scope was not serialized')
            with self.assertRaises(integration.ExternalApplyError):
                first.complete_external(guard)
            with self.scope() as second:
                with self.assertRaises(integration.ExternalApplyError):
                    second.complete_external(guard)
                with self.assertRaises(integration.ExternalApplyError):
                    second.load_external(guard.key, 'b' * 64)
                loaded = second.load_external(guard.key, TASK)
                self.assertEqual(loaded.record, guard.record)
                with self.assertRaises(integration.ExternalApplyError):
                    second.complete_external(loaded)  # Original is still base, not target.

    def test_wrong_object_format_rejected_before_reservation(self):
        with patch.dict(os.environ, self.env, clear=True), self.scope() as scope:
            with self.assertRaises(integration.ExternalApplyError):
                scope.reserve_external(base=self.base, target='1' * 64, task_digest=TASK)
            self.assertEqual(list(integration.scope_directory(scope.root, scope.identity,
                                                              scope.branch).joinpath('active').iterdir()), [])

    def test_wrong_record_format_cannot_be_resolved_using_other_format_head(self):
        target = self.target()
        with patch.dict(os.environ, self.env, clear=True), self.scope() as scope:
            guard = scope.reserve_external(base=self.base, target=target, task_digest=TASK)
            forged = guard.record
            forged.update(object_format='sha256', base='1' * 64, target='2' * 64)
            forged['key'] = integration.external_key(forged)
            forged['ref'] = integration.external_ref(forged)
            integration.write_journal(guard.journal.parent, forged)
            moved = guard.journal.parent.with_name(forged['key'])
            guard.journal.parent.rename(moved)
            self.assertEqual(integration.read_journal(moved)['object_format'], 'sha256')
        result = self.resolve(forged['key'])
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertEqual(json.loads(result.stdout)['status'], 'RECOVERY_REQUIRED')
        self.assertEqual(integration.read_journal(moved)['phase'], 'applying')

    def test_complete_revalidates_record_scope_even_for_rewrapped_guard(self):
        target = self.target()
        with patch.dict(os.environ, self.env, clear=True):
            with integration.OriginalScope(self.feature, 'feat/recovery', 15) as feature_scope:
                foreign = feature_scope.reserve_external(base=self.feature_head, target=target, task_digest=TASK)
            self.ff(target)
            with self.scope() as scope:
                wrong = integration.ExternalApplyGuard(scope, foreign.journal.parent, foreign.record)
                with self.assertRaises(integration.ExternalApplyError):
                    scope.complete_external(wrong)
            self.assertEqual(integration.read_journal(foreign.journal.parent)['phase'], 'applying')

    def test_operator_resolution_retains_matching_target_pin(self):
        target = self.target()
        with patch.dict(os.environ, self.env, clear=True), self.scope() as scope:
            guard = scope.reserve_external(base=self.base, target=target, task_digest=TASK)
        result = self.resolve(guard.key)
        self.assertEqual(result.returncode, 0, result.stderr)
        record = json.loads(result.stdout)
        self.assertEqual(record['status'], 'RESOLVED')
        self.assertEqual(record['pin_state'], 'matches_target')
        self.assertTrue(record['target_pin_verified'])
        saved = integration.read_journal(Path(record['journal']).parent)
        self.assertEqual(saved['resolved_by'], 'operator')
        self.assertEqual(saved['resolved_head'], self.base)
        self.assertEqual(fixtures.command('git', 'rev-parse', guard.ref,
                                         cwd=self.original, env=self.env).stdout.strip(), target)

    def test_pin_failure_leaves_barrier_and_resolver_reports_missing(self):
        target = self.target()
        failed_pin = subprocess.CompletedProcess([], 1, '', '')
        with patch.dict(os.environ, self.env, clear=True), self.scope() as scope:
            with patch.object(integration, 'run_git_nohooks', return_value=failed_pin):
                with self.assertRaises(integration.ExternalApplyError) as caught:
                    scope.reserve_external(base=self.base, target=target, task_digest=TASK)
            journal = caught.exception.journal
            saved = integration.read_journal(journal.parent)
            self.assertEqual(saved['phase'], 'reserved')
        result, report = self.invoke()
        self.assertEqual((result.returncode, report['status']), (3, 'RECOVERY_REQUIRED'))
        result = self.resolve(saved['key'])
        self.assertEqual(result.returncode, 0, result.stderr)
        record = json.loads(result.stdout)
        self.assertEqual(record['pin_state'], 'missing')
        self.assertFalse(record['target_pin_verified'])
        self.assertNotEqual(fixtures.command('git', 'show-ref', '--verify', saved['ref'],
                                            cwd=self.original, env=self.env, check=False).returncode, 0)

    def test_moved_pin_blocks_complete_but_operator_resolution_is_truthful(self):
        target = self.target()
        with patch.dict(os.environ, self.env, clear=True), self.scope() as scope:
            guard = scope.reserve_external(base=self.base, target=target, task_digest=TASK)
            self.ff(target)
            fixtures.command('git', 'update-ref', guard.ref, self.base,
                             cwd=self.original, env=self.env)
            with self.assertRaises(integration.ExternalApplyError):
                scope.complete_external(guard)
            self.assertEqual(integration.read_journal(guard.journal.parent)['phase'], 'applying')
        result = self.resolve(guard.key)
        self.assertEqual(result.returncode, 0, result.stderr)
        record = json.loads(result.stdout)
        self.assertEqual(record['pin_state'], 'moved')
        self.assertFalse(record['target_pin_verified'])
        self.assertEqual(fixtures.command('git', 'rev-parse', guard.ref,
                                         cwd=self.original, env=self.env).stdout.strip(), self.base)

    def test_malformed_schema3_is_structured_recovery_and_preserves_state(self):
        target = self.target()
        with patch.dict(os.environ, self.env, clear=True), self.scope() as scope:
            guard = scope.reserve_external(base=self.base, target=target, task_digest=TASK)
        valid = guard.record
        mutations = [('schema', True), ('kind', None), ('kind', 'scratch'), ('phase', 'delivered'),
                     ('phase', False), ('key', None), ('original_dev', True), ('target', '1' * 64),
                     ('object_format', 'sha256'), ('object_format', None), ('task_digest', False),
                     ('ref', 'refs/heads/main'), ('attempt', None), ('source', self.feature_head),
                     ('original', 'bad\0path'), ('branch', 'bad\ud800'), ('resolved_by', 'workflow')]
        for field, value in mutations:
            with self.subTest(field=field, value=repr(value)):
                malformed = dict(valid, **{field: value})
                integration.write_journal(guard.journal.parent, malformed)
                result, report = self.invoke()
                self.assertEqual(result.returncode, 3, result.stderr)
                self.assertEqual(report['status'], 'RECOVERY_REQUIRED')
                self.assertNotIn('Traceback', result.stderr)
                self.assertEqual(json.loads(guard.journal.read_text()), malformed)
        integration.write_journal(guard.journal.parent, valid)

    def test_reserved_and_applying_write_failures_leave_recovery_barrier(self):
        target = self.target()
        for fail_phase in ('reserved', 'applying'):
            with self.subTest(phase=fail_phase), patch.dict(os.environ, self.env, clear=True):
                write = integration.write_journal
                def fail(directory, record, **kwargs):
                    if record['phase'] == fail_phase:
                        raise OSError('injected metadata failure')
                    return write(directory, record, **kwargs)
                with self.scope() as scope, patch.object(integration, 'write_journal', side_effect=fail):
                    with self.assertRaises(integration.ExternalApplyError) as caught:
                        scope.reserve_external(base=self.base, target=target, task_digest=TASK)
                self.assertEqual(self.head(self.original), self.base)
                self.assertTrue(caught.exception.journal.parent.is_dir())
                result, report = self.invoke()
                self.assertEqual((result.returncode, report['status']), (3, 'RECOVERY_REQUIRED'))
                result = self.resolve(caught.exception.journal.parent.name)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_resolved_before_archive_crash_is_retired_without_scratch_proof(self):
        target = self.target()
        with patch.dict(os.environ, self.env, clear=True), self.scope() as scope:
            guard = scope.reserve_external(base=self.base, target=target, task_digest=TASK)
            self.ff(target)
            with patch.object(integration, 'archive_journal', side_effect=OSError('injected archive failure')):
                with self.assertRaises(integration.ExternalApplyError):
                    scope.complete_external(guard)
            self.assertEqual(integration.read_journal(guard.journal.parent)['phase'], 'resolved')
            with patch.object(integration, 'completed_journal_is_verified',
                              side_effect=AssertionError('external guard is not a scratch candidate')):
                blocking, _, completed = integration.scan_journals(scope.root, self.original,
                                  scope.identity, 'main', 'f' * 64, 15)
            self.assertIsNone(blocking)
            self.assertIsNone(completed)
            self.assertFalse(guard.journal.exists())
            self.assertTrue((guard.journal.parent.parent.parent / 'archive' / guard.key / 'journal.json').is_file())

    def test_resolved_write_failure_keeps_cross_tool_barrier(self):
        target = self.target()
        with patch.dict(os.environ, self.env, clear=True), self.scope() as scope:
            guard = scope.reserve_external(base=self.base, target=target, task_digest=TASK)
            self.ff(target)
            with patch.object(integration, 'write_journal', side_effect=OSError('injected resolution write failure')):
                with self.assertRaises(integration.ExternalApplyError):
                    scope.complete_external(guard)
            self.assertEqual(integration.read_journal(guard.journal.parent)['phase'], 'applying')
        self.base = target
        result, report = self.invoke()
        self.assertEqual((result.returncode, report['status']), (3, 'RECOVERY_REQUIRED'))

    def test_new_attempt_is_distinct_and_retains_prior_pin(self):
        target = self.target()
        with patch.dict(os.environ, self.env, clear=True), self.scope() as scope:
            first = scope.reserve_external(base=self.base, target=target, task_digest=TASK)
        result = self.resolve(first.key)
        self.assertEqual(result.returncode, 0, result.stderr)
        with patch.dict(os.environ, self.env, clear=True), self.scope() as scope:
            second = scope.reserve_external(base=self.base, target=target, task_digest=TASK)
            self.assertNotEqual(first.key, second.key)
            self.assertNotEqual(first.ref, second.ref)
            for guard in (first, second):
                self.assertEqual(fixtures.command('git', 'rev-parse', guard.ref,
                                 cwd=self.original, env=self.env).stdout.strip(), target)

    def test_external_record_legacy_placement_is_refused(self):
        target = self.target()
        with patch.dict(os.environ, self.env, clear=True), self.scope() as scope:
            guard = scope.reserve_external(base=self.base, target=target, task_digest=TASK)
            legacy = scope.root / guard.key
            guard.journal.parent.rename(legacy)
            with self.assertRaises(OSError):
                integration.read_journal(legacy)
        result, report = self.invoke()
        self.assertEqual((result.returncode, report['status']), (3, 'RECOVERY_REQUIRED'))

    def test_pin_observation_failure_is_unverifiable(self):
        target = self.target()
        with patch.dict(os.environ, self.env, clear=True), self.scope() as scope:
            guard = scope.reserve_external(base=self.base, target=target, task_digest=TASK)
            with patch.object(integration, 'inspect_git', side_effect=OSError('private transport output')):
                self.assertEqual(integration.external_pin_state(self.original, guard.record, 15),
                                 ('unverifiable', False))

    def test_valid_unicode_path_and_branch_are_supported(self):
        moved = self.root / 'café-🦆'
        self.original.rename(moved)
        self.original = moved
        branch = 'café-🦆'
        fixtures.command('git', 'branch', '-m', branch, cwd=moved, env=self.env)
        target = self.target()
        with patch.dict(os.environ, self.env, clear=True), integration.OriginalScope(moved, branch, 15) as scope:
            guard = scope.reserve_external(base=self.base, target=target, task_digest=TASK)
            self.assertEqual(integration.read_journal(guard.journal.parent)['branch'], branch)
            self.ff(target)
            self.assertEqual(scope.complete_external(guard).record['resolved_head'], target)

    def test_sha256_repository_has_matching_object_and_zero_cas_lengths(self):
        repo = self.root / 'sha256'
        fixtures.command('git', 'init', '-q', '-b', 'main', '--object-format=sha256', str(repo), env=self.env)
        for key, value in (('user.name', 'Harness Test'), ('user.email', 'test@example.invalid')):
            fixtures.command('git', 'config', key, value, cwd=repo, env=self.env)
        (repo / 'app.txt').write_text('sha256 base\n')
        fixtures.command('git', 'add', 'app.txt', cwd=repo, env=self.env)
        fixtures.command('git', 'commit', '-qm', 'sha256 base', cwd=repo, env=self.env)
        base = self.head(repo)
        fixtures.command('git', 'checkout', '-qb', 'feature', cwd=repo, env=self.env)
        (repo / 'app.txt').write_text('sha256 feature\n')
        fixtures.command('git', 'commit', '-qam', 'sha256 feature', cwd=repo, env=self.env)
        target = self.head(repo)
        fixtures.command('git', 'checkout', '-q', 'main', cwd=repo, env=self.env)
        with patch.dict(os.environ, self.env, clear=True), integration.OriginalScope(repo, 'main', 15) as scope:
            self.assertEqual(scope.object_format, 'sha256')
            with self.assertRaises(integration.ExternalApplyError):
                scope.reserve_external(base=base, target=self.base, task_digest=TASK)
            guard = scope.reserve_external(base=base, target=target, task_digest=TASK)
            fixtures.command('git', '-c', 'core.hooksPath=/dev/null', 'merge', '--ff-only',
                             '--no-overwrite-ignore', '--no-autostash', target, cwd=repo, env=self.env)
            self.assertEqual(len(guard.record['target']), 64)
            self.assertEqual(scope.complete_external(guard).record['resolved_head'], target)


if __name__ == '__main__':
    unittest.main()
