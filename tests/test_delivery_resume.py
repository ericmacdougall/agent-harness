"""Explicit interrupted-delivery resume in owned disposable repositories."""

import json
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

import test_delivery_workflow as workflow


class RemoteResume(unittest.TestCase):
    def setUp(self):
        self.fixture = workflow.DeliveryWorkflow()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.counter = self.fixture.root / 'checks-executed'
        self.fixture.env['FIXTURE_RESUME_COUNTER'] = str(self.counter)
        self.fixture.replace_feature_tests(
            'import os,time,unittest\nfrom pathlib import Path\n'
            'class ResumeCheck(unittest.TestCase):\n'
            '    def test_feature(self):\n'
            '        p=Path(os.environ["FIXTURE_RESUME_COUNTER"])\n'
            '        p.write_text(str(int(p.read_text())+1) if p.exists() else "1")\n'
            '        if os.environ.get("FIXTURE_RESUME_RELEASE"):\n'
            '            release=Path(os.environ["FIXTURE_RESUME_RELEASE"]);deadline=time.monotonic()+20\n'
            '            while not release.exists() and time.monotonic()<deadline: time.sleep(.02)\n'
            '            self.assertTrue(release.exists())\n'
            '        self.assertFalse(os.environ.get("FIXTURE_RESUME_FAIL"))\n'
            '        self.assertEqual(Path("app.txt").read_text(), "feature\\n")\n')
        self.fixture.configure_github()

    def pending(self, *, preparations=()):
        fixture = self.fixture
        prepared, data = fixture.invoke(*fixture.prepare_args())
        self.assertEqual(prepared.returncode, 0, prepared.stdout)
        self.generation = data['generation']
        self.target = fixture.merge_remote()
        arguments = fixture.finish_args('remote', self.generation)
        for command in preparations:
            arguments.extend(('--prepare', command))
        code, failed = fixture.direct_finish(
            lambda module: mock.patch.object(module, 'run_checks', side_effect=
                module.DeliveryError('DELIVERED_CHECK_FAILED', 'Fixture interrupted checks')),
            arguments=arguments)
        self.assertEqual((code, failed['status']), (3, 'RECOVERY_REQUIRED'), failed)
        self.state_path = Path(failed['state'])
        self.guard_path = Path(failed['recovery_journal'])
        self.assertEqual(json.loads(self.guard_path.read_text())['phase'], 'applying')
        self.assertFalse(self.counter.exists())

    def resume_args(self):
        return [*self.fixture.finish_args('remote', self.generation), '--resume',
                '--resume-reason', 'Fixture supervisor interruption',
                '--kit-file', str(self.fixture.kit)]

    def test_explicit_pending_resume_runs_one_fresh_check(self):
        self.pending()
        fixture = self.fixture
        old, refusal = fixture.invoke(*fixture.finish_args('remote', self.generation))
        self.assertEqual((old.returncode, refusal['status']), (3, 'RECOVERY_REQUIRED'))
        self.assertFalse(self.counter.exists())
        broken, blocked = fixture.direct_finish(
            lambda module: mock.patch.object(module, 'resume_remote_finish',
                side_effect=lambda flow, preparations, checks: module.remote_finish(flow, preparations, checks)),
            arguments=self.resume_args())
        self.assertEqual((broken, blocked['status']), (3, 'RECOVERY_REQUIRED'))
        self.assertFalse(self.counter.exists(), 'The old pending-refusal path cannot claim fresh verification')
        result = workflow.command(sys.executable, str(workflow.DELIVER), *self.resume_args(),
                                  env=fixture.env, check=False)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        outcome = json.loads(result.stdout)
        self.assertEqual((outcome['status'], outcome['head']), ('DELIVERED', self.target))
        self.assertEqual(self.counter.read_text(), '1')
        self.assertEqual(workflow.command('git', 'status', '--porcelain', cwd=fixture.original,
                                          env=fixture.env).stdout, '')
        self.assertEqual(json.loads(self.state_path.read_text())['source_head'], fixture.head)
        self.assertTrue(Path(outcome['resume_record']).is_file())

    def refused_without_check(self, arguments=None):
        code, data = self.fixture.direct_finish(
            lambda module: mock.patch.object(module, 'run_checks',
                side_effect=AssertionError('Invalid resume launched a costly check')),
            arguments=arguments or self.resume_args())
        self.assertNotEqual(code, 0, data)
        self.assertNotEqual(data['status'], 'DELIVERED')
        self.assertFalse(self.counter.exists())

    def test_invalid_saved_tuple_cannot_launch_checks(self):
        self.pending()
        before = self.state_path.read_bytes()
        state = json.loads(before)
        mutations = [('phase', 'PR_READY'), ('source_head', self.fixture.base),
                     ('source_branch', 'codex/other'), ('repository', 'fixture/elsewhere'),
                     ('pr_number', 27), ('merge_head', self.fixture.base),
                     ('target', self.fixture.base), ('apply_base', self.target),
                     ('baseline', self.target), ('checks_digest', '0' * 64),
                     ('kit_digest', '0' * 64), ('guard_key', '0' * 64)]
        try:
            for name, value in mutations:
                with self.subTest(field=name):
                    self.state_path.write_text(json.dumps({**state, name: value}))
                    self.refused_without_check()
                    self.assertEqual(json.loads(self.state_path.read_text()), {**state, name: value})
        finally:
            self.state_path.write_bytes(before)

    def test_invalid_guard_pin_barrier_dirty_target_kit_and_checks_refuse(self):
        self.pending()
        fixture = self.fixture
        guard = json.loads(self.guard_path.read_text())
        before = self.guard_path.read_bytes()
        try:
            for updates in ({'schema': 99}, {'task_digest': '0' * 64},
                            {'phase': 'resolved', 'resolved_by': 'operator',
                             'resolved_head': self.target, 'previous_phase': 'applying'},
                            {'phase': 'resolved', 'resolved_by': 'workflow',
                             'resolved_head': self.target, 'previous_phase': 'applying'}):
                with self.subTest(guard=updates):
                    self.guard_path.write_text(json.dumps({**guard, **updates}))
                    self.refused_without_check()
        finally:
            self.guard_path.write_bytes(before)
        for pin in (None, fixture.base):
            with self.subTest(pin=pin):
                if pin is None:
                    workflow.command('git', 'update-ref', '-d', guard['ref'], cwd=fixture.original, env=fixture.env)
                else:
                    workflow.command('git', 'update-ref', guard['ref'], pin, cwd=fixture.original, env=fixture.env)
                self.refused_without_check()
        workflow.command('git', 'update-ref', guard['ref'], self.target, cwd=fixture.original, env=fixture.env)
        barrier = self.guard_path.parent.parent / ('0' * 64)
        barrier.mkdir(mode=0o700)
        try:
            self.refused_without_check()
            self.assertTrue(barrier.is_dir(), 'Prevalidation must preserve other recovery state')
        finally:
            barrier.rmdir()
        (fixture.original / 'app.txt').write_text('dirty\n')
        self.refused_without_check()
        (fixture.original / 'app.txt').write_text('feature\n')
        kit = fixture.kit.read_bytes()
        fixture.kit.write_text(json.dumps({'run': 'changed', 'test': 'changed', 'watch': 'changed'}))
        self.refused_without_check()
        fixture.kit.write_bytes(kit)
        changed = self.resume_args()
        changed[changed.index(workflow.CHECK)] = 'python3 -m pytest'
        self.refused_without_check(changed)

    def test_missing_resume_namespace_is_not_recreated_or_checked(self):
        self.pending()
        archive = self.guard_path.parent.parent.parent / 'archive'
        archive.rmdir()
        calls = []
        def stop_check(module):
            def costly(*args):
                calls.append('check')
                raise module.DeliveryError('DELIVERED_CHECK_FAILED', 'Fixture reached a costly check')
            return mock.patch.object(module, 'run_checks', side_effect=costly)
        code, data = self.fixture.direct_finish(stop_check, arguments=self.resume_args())
        self.assertEqual((code, data['status']), (3, 'RECOVERY_REQUIRED'))
        self.assertEqual((archive.exists(), calls), (False, []),
                         'Missing namespace must remain missing and refuse before checks')
        self.assertFalse(self.counter.exists())

    def test_proof_boundary_mutation_prevents_test_launch(self):
        self.pending()
        def mutate(module):
            fetch = module.fetch_target
            def changed(*args):
                fetch(*args)
                self.fixture.kit.write_text('{}')
            return mock.patch.object(module, 'fetch_target', side_effect=changed)
        code, data = self.fixture.direct_finish(mutate, arguments=self.resume_args())
        self.assertNotEqual(code, 0, data)
        self.assertFalse(self.counter.exists())
        self.assertEqual(json.loads(self.guard_path.read_text())['phase'], 'applying')

    def test_state_mutation_after_checks_and_interruption_never_deliver(self):
        self.pending()
        def mutate(module):
            check = module.run_checks
            def changed(*args):
                check(*args)
                state = json.loads(self.state_path.read_text())
                self.state_path.write_text(json.dumps({**state, 'source_head': self.fixture.base}))
            return mock.patch.object(module, 'run_checks', side_effect=changed)
        code, result = self.fixture.direct_finish(mutate, arguments=self.resume_args())
        self.assertEqual((code, result['status']), (3, 'RECOVERY_REQUIRED'))
        self.assertEqual(self.counter.read_text(), '1')
        self.assertEqual(json.loads(self.guard_path.read_text())['phase'], 'applying')

    def test_failed_check_preserves_pending_guard(self):
        self.pending()
        self.fixture.env['FIXTURE_RESUME_FAIL'] = '1'
        result, data = self.fixture.invoke(*self.resume_args())
        self.assertEqual((result.returncode, data['status']), (3, 'RECOVERY_REQUIRED'))
        self.assertEqual(self.counter.read_text(), '1')
        self.assertEqual(json.loads(self.guard_path.read_text())['phase'], 'applying')
        self.assertEqual(json.loads(self.state_path.read_text())['phase'], 'REMOTE_APPLYING')

    def test_kit_mutation_at_completion_cannot_record_delivery(self):
        self.pending()
        kit = self.fixture.kit.read_bytes()
        def mutate(module):
            complete = module.OriginalScope.complete_external
            def changed(scope, guard):
                result = complete(scope, guard)
                self.fixture.kit.write_text('{}')
                return result
            return mock.patch.object(module.OriginalScope, 'complete_external', changed)
        code, result = self.fixture.direct_finish(mutate, arguments=self.resume_args())
        self.assertEqual((code, result['status']), (3, 'RECOVERY_REQUIRED'))
        self.assertEqual(self.counter.read_text(), '1')
        self.assertEqual(json.loads(self.state_path.read_text())['phase'], 'REMOTE_APPLYING')
        self.assertFalse((self.state_path.parent / 'receipt' / 'journal.json').exists())
        self.fixture.kit.write_bytes(kit)
        code, result = self.fixture.direct_finish(
            lambda module: mock.patch.object(module, 'run_checks',
                side_effect=AssertionError('A new resume must not reinterpret partial completion')),
            arguments=self.resume_args())
        self.assertEqual((code, result['status']), (3, 'RECOVERY_REQUIRED'))
        self.assertEqual(self.counter.read_text(), '1')

    def test_resume_requires_remote_mode_generation_kit_and_bounded_reason(self):
        self.generation = 'a' * 32
        valid = self.resume_args()
        invalid = []
        for flag in ('--generation', '--kit-file', '--resume-reason'):
            args = valid.copy()
            at = args.index(flag)
            del args[at:at + 2]
            invalid.append(args)
        local = valid.copy()
        local[local.index('remote')] = 'local'
        invalid.append(local)
        for reason in ('', 'x' * 513, 'bad\nreason'):
            args = valid.copy()
            args[args.index('--resume-reason') + 1] = reason
            invalid.append(args)
        for args in invalid:
            with self.subTest(arguments=args):
                result = workflow.command(sys.executable, str(workflow.DELIVER), *args,
                                          env=self.fixture.env, check=False)
                self.assertEqual(result.returncode, 2, result.stdout)
                self.assertFalse(self.counter.exists())

    def test_interruption_preserves_pending_guard_and_unknown_attempt(self):
        self.pending()
        with self.assertRaises(KeyboardInterrupt):
            self.fixture.direct_finish(lambda module: mock.patch.object(module, 'run_checks',
                                       side_effect=KeyboardInterrupt), arguments=self.resume_args())
        self.assertEqual(json.loads(self.guard_path.read_text())['phase'], 'applying')
        self.assertEqual(json.loads(self.state_path.read_text())['phase'], 'REMOTE_APPLYING')
        self.assertFalse(self.counter.exists())
        self.assertTrue(list(self.state_path.parent.glob('resumes/*/start/journal.json')))
        self.assertFalse(list(self.state_path.parent.glob('resumes/*/final/journal.json')))

    def test_failed_declared_prerequisite_stops_before_test_child(self):
        self.pending(preparations=('npm ci --prefer-offline',))
        marker = self.fixture.root / 'prerequisite-ran'
        npm = self.fixture.bin / 'npm'
        npm.write_text('#!' + sys.executable + '\nfrom pathlib import Path\n'
                       f'Path({str(marker)!r}).write_text("failed prerequisite")\nraise SystemExit(17)\n')
        npm.chmod(0o700)
        result, data = self.fixture.invoke(*self.resume_args(), '--prepare', 'npm ci --prefer-offline')
        self.assertEqual((result.returncode, data['status']), (3, 'RECOVERY_REQUIRED'))
        self.assertTrue(marker.exists())
        self.assertFalse(self.counter.exists())
        self.assertEqual(json.loads(self.guard_path.read_text())['phase'], 'applying')

    def test_live_resume_holds_scope_against_another_process(self):
        self.pending()
        fixture = self.fixture
        release = fixture.root / 'release-check'
        fixture.env['FIXTURE_RESUME_RELEASE'] = str(release)
        process = subprocess.Popen([sys.executable, str(workflow.DELIVER), *self.resume_args()],
                                   env=fixture.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 45
            while not self.counter.exists() and process.poll() is None and time.monotonic() < deadline:
                time.sleep(.05)
            self.assertTrue(self.counter.exists(), 'Actual check must be running before the concurrent attempt')
            probe = ('import sys\n'
                     f'sys.path.insert(0,{str(workflow.DELIVER.parent)!r})\n'
                     'from integrate_local import OriginalScope,ExternalApplyError\n'
                     'try:\n'
                     f'    with OriginalScope({str(fixture.original)!r},"main",15): raise SystemExit(7)\n'
                     'except ExternalApplyError: raise SystemExit(0)\n')
            blocked = workflow.command(sys.executable, '-c', probe, env=fixture.env, check=False)
            self.assertEqual(blocked.returncode, 0, blocked.stderr)
        finally:
            release.touch()
            stdout, stderr = process.communicate(timeout=35)
        self.assertEqual(process.returncode, 0, stdout + stderr)
        self.assertEqual(json.loads(stdout)['status'], 'DELIVERED')
        self.assertEqual(self.counter.read_text(), '1')


class ExecutorProvenance(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='harness-executor-')
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        workflow.command('git', 'init', '-q', '-b', 'main', str(self.repo))
        workflow.command('git', '-C', str(self.repo), 'config', 'user.name', 'Fixture')
        workflow.command('git', '-C', str(self.repo), 'config', 'user.email', 'fixture@example.invalid')
        (self.repo / 'README.md').write_text('Owned provenance fixture\n')
        self.hooks = self.repo / 'harness' / 'hooks'
        self.hooks.mkdir(parents=True)
        for name in ('deliver.py', 'integrate_local.py', 'process.py', 'git_safety.py'):
            (self.hooks / name).write_bytes((workflow.DELIVER.parent / name).read_bytes())
        workflow.command('git', 'add', 'README.md', cwd=self.repo)
        workflow.command('git', 'commit', '-qm', 'fixture baseline', cwd=self.repo)
        spec = importlib.util.spec_from_file_location('provenance_fixture', workflow.DELIVER)
        self.module = importlib.util.module_from_spec(spec)
        with mock.patch.object(sys, 'path', [str(workflow.DELIVER.parent), *sys.path]):
            spec.loader.exec_module(self.module)

    def identity(self):
        with mock.patch.object(self.module, '__file__', str(self.hooks / 'deliver.py')):
            return self.module.resume_executor()

    def test_untracked_and_ignored_helpers_cannot_claim_revision(self):
        self.assertIsNone(self.identity()['revision'])
        (self.repo / '.gitignore').write_text('harness/\n')
        workflow.command('git', 'add', '.gitignore', cwd=self.repo)
        workflow.command('git', 'commit', '-qm', 'ignore owned fixture helpers', cwd=self.repo)
        self.assertIsNone(self.identity()['revision'])

    def test_clean_tracked_helpers_bind_revision_but_dirty_bytes_do_not(self):
        workflow.command('git', 'add', 'harness', cwd=self.repo)
        workflow.command('git', 'commit', '-qm', 'track fixture helpers', cwd=self.repo)
        head = workflow.command('git', 'rev-parse', 'HEAD', cwd=self.repo).stdout.strip()
        clean = self.identity()
        self.assertEqual(clean['revision'], head)
        with (self.hooks / 'deliver.py').open('ab') as changed:
            changed.write(b'\n# modified fixture executor\n')
        dirty = self.identity()
        self.assertIsNone(dirty['revision'])
        self.assertNotEqual(dirty['helpers_sha256'], clean['helpers_sha256'])
