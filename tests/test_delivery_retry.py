"""Cross-generation delivery recovery with real Git and explicit resolution."""

import json
import contextlib
from pathlib import Path
import shutil
import sys
import unittest
from unittest import mock

import test_delivery_workflow as workflow


class LocalGenerationRetry(unittest.TestCase):
    def setUp(self):
        self.fixture = workflow.DeliveryWorkflow()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.addCleanup(self.cleanup_preserved_history)

    def cleanup_preserved_history(self):
        root = self.fixture.original / '.git' / 'agent-harness' / 'delivery-scratch'
        for journal in root.glob('scopes/*/archive/history/*/*/journal.json'):
            record = json.loads(journal.read_text())
            if record.get('schema') != 2 or 'container' not in record:
                continue
            container = Path(record['container'])
            if not container.exists():
                continue
            info = container.stat()
            self.assertTrue(container.name.startswith('agent-harness-delivery-scratch-'))
            self.assertEqual((info.st_dev, info.st_ino), (record['container_dev'], record['container_ino']))
            shutil.rmtree(container)

    def test_same_tuple_new_generation_retries_after_explicit_resolution(self):
        fixture = self.fixture
        prepared, first = fixture.invoke(*fixture.prepare_args(), '--local-only')
        self.assertEqual((prepared.returncode, first['status']), (0, 'LOCAL_READY'), prepared.stdout)
        fixture.env['FIXTURE_DEPENDENCY'] = 'unavailable'
        failed, outcome = fixture.invoke(*fixture.finish_args('local'))
        self.assertEqual((failed.returncode, outcome['status']), (3, 'RECOVERY_REQUIRED'), failed.stdout)
        self.assertEqual(workflow.command('git', 'rev-parse', 'HEAD', cwd=fixture.original,
                                          env=fixture.env).stdout.strip(), fixture.base)
        root = fixture.original / '.git' / 'agent-harness' / 'delivery-scratch'
        active = list(root.glob('scopes/*/active/*/journal.json'))
        self.assertEqual(len(active), 1)
        key = active[0].parent.name
        fixture.env.pop('FIXTURE_DEPENDENCY')
        resolved = workflow.command(sys.executable, str(workflow.DELIVER.with_name('integrate_local.py')),
                    '--repo', str(fixture.original), '--original-branch', 'main', '--expected-head', fixture.base,
                    '--resolve-journal', key, '--check', workflow.CHECK, env=fixture.env, check=False)
        self.assertEqual((resolved.returncode, json.loads(resolved.stdout)['status']), (0, 'RESOLVED'), resolved.stdout)
        baseline, accepted = fixture.invoke(*fixture.baseline_args(fixture.base))
        self.assertEqual((baseline.returncode, accepted['status']), (0, 'RESOLVED_BASELINE'), baseline.stdout)
        archived = list(root.glob('scopes/*/archive/' + key + '/journal.json'))
        self.assertEqual(len(archived), 1)
        old_record = archived[0].read_bytes()
        again, second = fixture.invoke(*fixture.prepare_args(), '--local-only', '--new-generation')
        self.assertEqual((again.returncode, second['status']), (0, 'LOCAL_READY'), again.stdout)
        self.assertNotEqual(second['generation'], first['generation'])
        delivered, final = fixture.invoke(*fixture.finish_args('local', second['generation']))
        self.assertEqual((delivered.returncode, final['status']), (0, 'LOCAL_DELIVERED'), delivered.stdout)
        self.assertEqual((fixture.original / 'app.txt').read_text(), 'feature\n')
        self.assertEqual(workflow.command('git', 'status', '--porcelain', cwd=fixture.original,
                                          env=fixture.env).stdout, '')
        retained = [path.read_bytes() for path in root.glob('scopes/*/archive/history/*/' + key + '/journal.json')]
        self.assertIn(old_record, retained)


class RemoteLifecycleRetry(unittest.TestCase):
    def setUp(self):
        self.fixture = workflow.DeliveryWorkflow()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.configure_github()

    def prepared_merge(self):
        result, state = self.fixture.invoke(*self.fixture.prepare_args())
        self.assertEqual(result.returncode, 0, result.stdout)
        return state, self.fixture.merge_remote()

    def advance_remote(self):
        fixture = self.fixture
        independent = fixture.root / 'independent-advance'
        workflow.command('git', 'clone', '-q', str(fixture.remote), str(independent), env=fixture.env)
        (independent / 'later.txt').write_text('later independently merged work\n')
        workflow.command('git', 'add', 'later.txt', cwd=independent, env=fixture.env)
        workflow.command('git', '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                         'commit', '-qm', 'Later merge', cwd=independent, env=fixture.env)
        tip = workflow.command('git', 'rev-parse', 'HEAD', cwd=independent, env=fixture.env).stdout.strip()
        workflow.command('git', 'push', '-q', str(fixture.remote), tip + ':refs/heads/main',
                         cwd=independent, env=fixture.env)
        fixture.change_github(target=tip)
        self.assertNotEqual(workflow.command('git', 'cat-file', '-e', tip, cwd=fixture.original,
                                             env=fixture.env, check=False).returncode, 0)
        return tip

    def test_main_advance_during_checks_keeps_only_pinned_tested_target(self):
        fixture = self.fixture
        _, target = self.prepared_merge()
        later = []
        def concurrent_merge(module):
            checks = module.run_checks
            def run(*args):
                checks(*args)
                later.append(self.advance_remote())
            return mock.patch.object(module, 'run_checks', side_effect=run)
        code, result = fixture.direct_finish(concurrent_merge)
        self.assertEqual((code, result['status'], result.get('head')), (0, 'DELIVERED', target), result)
        self.assertEqual(result.get('remote_observed_head'), later[0])
        self.assertFalse((fixture.original / 'later.txt').exists())
        self.assertEqual(json.loads(Path(result['receipt']).read_text())['head'], target)
        self.assertFalse(list((fixture.original / '.git' / 'agent-harness' / 'delivery-scratch').glob('scopes/*/active/*')))

    def test_resolved_guard_resume_allows_later_descendant_without_new_checkout_work(self):
        fixture = self.fixture
        _, target = self.prepared_merge()
        code, failed = fixture.direct_finish(lambda module: mock.patch.object(module.Workflow, 'complete',
                                                         side_effect=OSError('fixture receipt interruption')))
        self.assertEqual((code, failed['status']), (3, 'RECOVERY_REQUIRED'))
        later = self.advance_remote()
        result, completed = fixture.invoke(*fixture.finish_args())
        self.assertEqual((result.returncode, completed['status'], completed.get('head')), (0, 'DELIVERED', target), result.stdout)
        self.assertEqual(completed.get('remote_observed_head'), later)
        self.assertFalse((fixture.original / 'later.txt').exists())

    def test_non_descendant_remote_tip_keeps_recovery_barrier(self):
        fixture = self.fixture
        _, target = self.prepared_merge()
        def rewritten_remote(module):
            checks = module.run_checks
            def run(*args):
                checks(*args)
                workflow.command('git', 'update-ref', 'refs/heads/main', fixture.base,
                                 cwd=fixture.remote, env=fixture.env)
                fixture.change_github(target=fixture.base)
            return mock.patch.object(module, 'run_checks', side_effect=run)
        code, result = fixture.direct_finish(rewritten_remote)
        self.assertEqual((code, result['status'], result.get('head')), (3, 'RECOVERY_REQUIRED', target), result)
        self.assertTrue(list((fixture.original / '.git' / 'agent-harness' / 'delivery-scratch').glob('scopes/*/active/*')))

    def test_merged_pr_delivery_does_not_require_feature_worktree(self):
        fixture = self.fixture
        _, target = self.prepared_merge()
        workflow.command('git', 'worktree', 'remove', str(fixture.source), cwd=fixture.original, env=fixture.env)
        result, completed = fixture.invoke(*fixture.finish_args())
        self.assertEqual((result.returncode, completed['status'], completed.get('head')), (0, 'DELIVERED', target), result.stdout)

    def test_foreign_barrier_refusal_can_retry_same_generation_after_resolution(self):
        fixture = self.fixture
        state, target = self.prepared_merge()
        foreign = []
        def reserve_other(module):
            with module.OriginalScope(fixture.original, 'main', 30) as scope:
                foreign.append(scope.reserve_external(base=fixture.base, target=fixture.base, task_digest='f' * 64))
            return contextlib.nullcontext()
        code, failure = fixture.direct_finish(reserve_other)
        self.assertEqual((code, failure['status']), (3, 'RECOVERY_REQUIRED'))
        self.assertEqual(json.loads(Path(state['state']).read_text())['phase'], 'PR_READY')
        resolved = workflow.command(sys.executable, str(workflow.DELIVER.with_name('integrate_local.py')),
                    '--repo', str(fixture.original), '--original-branch', 'main', '--expected-head', fixture.base,
                    '--resolve-journal', foreign[0].key, '--check', workflow.CHECK, env=fixture.env, check=False)
        self.assertEqual((resolved.returncode, json.loads(resolved.stdout)['status']), (0, 'RESOLVED'), resolved.stdout)
        result, completed = fixture.invoke(*fixture.finish_args(generation=state['generation']))
        self.assertEqual((result.returncode, completed['status'], completed.get('head')), (0, 'DELIVERED', target), result.stdout)

    def publisher_duration_model(self, module, *, legacy=False):
        bounded = module.bounded
        def run(command, **kwargs):
            if len(command) > 1 and Path(command[1]).name == 'publish_feature.py':
                step_budget = int(command[command.index('--timeout') + 1])
                elapsed = 0.7 * step_budget + 0.7 * step_budget
                parent_budget = min(kwargs['timeout'], step_budget + 15) if legacy else kwargs['timeout']
                if parent_budget < elapsed:
                    raise module.DeliveryError('BLOCKED_LOCAL', 'Synthetic sequential stage deadline')
            return bounded(command, **kwargs)
        return mock.patch.object(module, 'bounded', side_effect=run)

    def test_parent_budget_admits_two_legitimate_sequential_publisher_stages(self):
        fixture = self.fixture
        code, result = fixture.direct_finish(lambda module: self.publisher_duration_model(module),
                                             (*fixture.prepare_args(), '--timeout', '100'))
        self.assertEqual((code, result['status']), (0, 'PR_READY'), result)

    def test_legacy_parent_budget_control_blocks_before_publication(self):
        fixture = self.fixture
        code, result = fixture.direct_finish(lambda module: self.publisher_duration_model(module, legacy=True),
                                             (*fixture.prepare_args(), '--timeout', '100'))
        self.assertEqual((code, result['status']), (4, 'REMOTE_UNCERTAIN'), result)
        self.assertNotEqual(workflow.command('git', 'show-ref', '--verify', 'refs/heads/codex/feature',
                                            cwd=fixture.remote, env=fixture.env, check=False).returncode, 0)
        local, refusal = fixture.invoke(*fixture.finish_args('local'))
        self.assertEqual((local.returncode, refusal['status']), (2, 'BLOCKED_POLICY'))


if __name__ == '__main__':
    unittest.main()
