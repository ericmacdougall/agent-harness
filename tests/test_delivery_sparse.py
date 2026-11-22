"""Native CLI with real Git; fixture GitHub transport is simulated."""
import json
from pathlib import Path
import unittest
import tempfile
from unittest import mock
import test_delivery_workflow as fixture
from commit_messages import message


class SparseDelivery(fixture.DeliveryWorkflow):
    def setUp(self):
        native_temp = tempfile.TemporaryDirectory
        def physical_temp(*args, **kwargs):
            return native_temp(*args, **kwargs, dir=str(Path(tempfile.gettempdir()).resolve()))
        with mock.patch.object(fixture.tempfile, 'TemporaryDirectory', physical_temp):
            super().setUp()
        # Physical roots avoid the macOS /var temporary-directory alias.
        self.original = self.original.resolve()
        self.source = self.source.resolve()
        (self.source / 'omitted').mkdir()
        (self.source / 'omitted/new.txt').write_text('excluded feature\n')
        fixture.command('git', 'add', 'omitted', cwd=self.source, env=self.env)
        fixture.command('git', 'commit', '-qm', message('add excluded fixture'),
                        cwd=self.source, env=self.env)
        self.head = fixture.command('git', 'rev-parse', 'HEAD', cwd=self.source, env=self.env).stdout.strip()
        for repo in (self.original, self.source):
            fixture.command('git', 'sparse-checkout', 'set', '--no-cone', '/app.txt', '/tests/',
                            cwd=repo, env=self.env)
        self.configure_github()

    def test_sparse_native_remote_fast_forward(self):
        sentinel = self.original / 'personal-note'
        sentinel.write_text('keep user bytes')
        # Ignored user data, since an ordinary untracked path blocks clean delivery.
        exclude = self.original / '.git/info/exclude'
        with exclude.open('a') as handle: handle.write('\npersonal-note\n')
        result, prepared = self.invoke(*self.prepare_args())
        self.assertEqual((result.returncode, prepared['status']), (0, 'PR_READY'), result.stdout)
        state = json.loads(Path(prepared['state']).read_text())
        self.assertEqual(state['schema'], 2)
        target = self.merge_remote()
        result, delivered = self.invoke(*self.finish_args())
        self.assertEqual((result.returncode, delivered['status']), (0, 'DELIVERED'), result.stdout)
        self.assertEqual(fixture.command('git', 'rev-parse', 'HEAD', cwd=self.original,
                                         env=self.env).stdout.strip(), target)
        self.assertFalse((self.original / 'omitted/new.txt').exists())
        self.assertEqual(sentinel.read_text(), 'keep user bytes')
        self.assertEqual((self.original / 'app.txt').read_text(), 'feature\n')
        self.assertEqual(json.loads(Path(prepared['state']).read_text())['original_layout'], state['original_layout'])

    def test_sparse_to_ordinary_same_head_refused(self):
        result, prepared = self.invoke(*self.prepare_args())
        self.assertEqual(result.returncode, 0, result.stdout)
        fixture.command('git', 'sparse-checkout', 'disable', cwd=self.original, env=self.env)
        result, denied = self.invoke(*self.finish_args())
        self.assertEqual(denied['status'], 'RECHECK_REQUIRED', result.stdout)

    def test_missing_required_layout_refused(self):
        result, prepared = self.invoke(*self.prepare_args())
        self.assertEqual(result.returncode, 0, result.stdout)
        path = Path(prepared['state'])
        state = json.loads(path.read_text())
        state.pop('original_layout')
        path.write_text(json.dumps(state))
        for repo in (self.source, self.original):
            fixture.command('git', 'sparse-checkout', 'disable', cwd=repo, env=self.env)
        result, denied = self.invoke(*self.finish_args())
        self.assertEqual(denied['status'], 'RECOVERY_REQUIRED', result.stdout)

    def test_valid_layout_drift_at_same_head_refused(self):
        result, prepared = self.invoke(*self.prepare_args())
        self.assertEqual(result.returncode, 0, result.stdout)
        fixture.command('git', 'sparse-checkout', 'set', '--no-cone', '/app.txt', '/tests/', '/future',
                        cwd=self.source, env=self.env)
        result, denied = self.invoke(*self.prepare_args())
        self.assertEqual(denied['status'], 'RECHECK_REQUIRED', result.stdout)
        result, denied = self.invoke(*self.finish_args())
        self.assertEqual(denied['status'], 'RECHECK_REQUIRED', result.stdout)

    def test_unresolved_phase_cannot_recapture_changed_layout(self):
        result, prepared = self.invoke(*self.prepare_args())
        self.assertEqual(result.returncode, 0, result.stdout)
        path = Path(prepared['state'])
        state = json.loads(path.read_text())
        state['phase'] = 'REMOTE_UNCERTAIN'
        path.write_text(json.dumps(state))
        fixture.command('git', 'sparse-checkout', 'disable', cwd=self.original, env=self.env)
        result, denied = self.invoke(*self.prepare_args(), '--new-generation')
        self.assertEqual(denied['status'], 'RECHECK_REQUIRED', result.stdout)
        self.assertEqual(json.loads(path.read_text())['generation'], prepared['generation'])

    def test_legacy_ordinary_journal_remains_usable(self):
        for repo in (self.original, self.source):
            fixture.command('git', 'sparse-checkout', 'disable', cwd=repo, env=self.env)
        result, prepared = self.invoke(*self.prepare_args())
        self.assertEqual(result.returncode, 0, result.stdout)
        path = Path(prepared['state'])
        state = json.loads(path.read_text())
        self.assertEqual(state['source_layout'], 'ordinary')
        state['schema'] = 1
        state.pop('source_layout')
        state.pop('original_layout')
        path.write_text(json.dumps(state))
        result, repeated = self.invoke(*self.prepare_args())
        self.assertEqual((result.returncode, repeated['status']), (0, 'PR_READY'), result.stdout)

    def test_advanced_sparse_recovery_completes_same_generation(self):
        result, prepared = self.invoke(*self.prepare_args())
        self.assertEqual(result.returncode, 0, result.stdout)
        target = self.merge_remote()
        def failed_completion(module):
            return mock.patch.object(module.OriginalScope, 'complete_external',
                                     side_effect=module.ExternalApplyError('fixture interruption'))
        code, interrupted = self.direct_finish(failed_completion)
        self.assertEqual((code, interrupted['status'], interrupted.get('head')),
                         (3, 'RECOVERY_REQUIRED', target), interrupted)
        before = json.loads(Path(prepared['state']).read_text())
        self.assertEqual(before['phase'], 'REMOTE_APPLYING')
        result, delivered = self.invoke(*self.finish_args(generation=prepared['generation']),
                                        '--resume', '--resume-reason', 'Fixture completion interruption',
                                        '--kit-file', str(self.kit))
        self.assertEqual((result.returncode, delivered['status']), (0, 'DELIVERED'), result.stdout)
        self.assertEqual(delivered['generation'], prepared['generation'])


def load_tests(loader, tests, pattern):
    return unittest.TestSuite(SparseDelivery(name) for name in loader.getTestCaseNames(SparseDelivery)
                              if name in SparseDelivery.__dict__)
