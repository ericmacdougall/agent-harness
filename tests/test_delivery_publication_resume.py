"""Explicit identical-write recovery, using real Git and the local GitHub shim."""
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

import test_delivery_workflow as workflow


class PublicationResume(unittest.TestCase):
    def setUp(self):
        self.fixture = workflow.DeliveryWorkflow()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.configure_github()

    def pending(self):
        fixture = self.fixture
        def boundary(module):
            original = module.bounded
            def stopped(command, **kwargs):
                if len(command) > 1 and Path(command[1]).name == 'publish_feature.py':
                    raise module.DeliveryError('REMOTE_UNCERTAIN', 'legacy publisher result lost')
                return original(command, **kwargs)
            return mock.patch.object(module, 'bounded', side_effect=stopped)
        code, data = fixture.direct_finish(boundary, fixture.prepare_args())
        self.assertEqual((code, data['status']), (4, 'REMOTE_UNCERTAIN'), data)
        self.state_path = Path(data['state'])
        self.state = json.loads(self.state_path.read_text())
        self.assertEqual(self.state['phase'], 'PUBLISHING')
        # Legacy generation has no trusted process/lease metadata.
        lease = self.state_path.parent / 'publication.lock'
        if lease.exists():
            lease.unlink()
        return data

    def resume_args(self):
        return [*self.fixture.prepare_args(), '--resume-publication', '--generation', self.state['generation'],
                '--resume-reason', 'Reauthorize the identical pinned publication; prior outcome remains unknown.']

    def pushes(self):
        return [json.loads(line) for line in self.fixture.events.read_text().splitlines()
                if 'push' in json.loads(line)]

    def assert_original_untouched(self):
        fixture = self.fixture
        self.assertEqual(workflow.command('git', 'rev-parse', 'HEAD', cwd=fixture.original, env=fixture.env).stdout.strip(), fixture.base)
        self.assertEqual(workflow.command('git', 'rev-parse', 'refs/heads/main', cwd=fixture.remote, env=fixture.env).stdout.strip(), fixture.base)
        self.assertEqual(workflow.command('git', 'rev-parse', 'refs/heads/codex/feature', cwd=fixture.remote, env=fixture.env).stdout.strip(), fixture.head)

    def test_explicit_absent_ref_retries_once_without_resetting_generation(self):
        self.pending()
        result, ready = self.fixture.invoke(*self.resume_args())
        self.assertEqual((result.returncode, ready['status']), (0, 'PR_READY'), result.stdout)
        self.assertEqual(ready['generation'], self.state['generation'])
        self.assertEqual(len(self.pushes()), 1)
        self.assertEqual(json.loads(self.fixture.github_state.read_text())['creates'], 1)
        records = list(self.state_path.parent.glob('publication-resume-*.json'))
        self.assertEqual(len(records), 1)
        self.assertEqual(json.loads(records[0].read_text())['prior_outcome'], 'UNKNOWN')
        self.assert_original_untouched()

    def test_legacy_unknown_original_still_alive_can_complete_same_write_later(self):
        self.pending()
        fixture = self.fixture
        script = "import subprocess,sys; print('ready',flush=True); sys.stdin.readline(); subprocess.run(sys.argv[1:],check=True)"
        child = subprocess.Popen([sys.executable, '-c', script, fixture.env['FIXTURE_REAL_GIT'], '-C', str(fixture.source),
                                  'push', '--porcelain', str(fixture.remote), fixture.head + ':refs/heads/codex/feature'],
                                 env=fixture.env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            self.assertEqual(child.stdout.readline().strip(), 'ready')
            self.assertIsNone(child.poll())
            result, ready = fixture.invoke(*self.resume_args())
            self.assertEqual((result.returncode, ready['status']), (0, 'PR_READY'), result.stdout)
            self.assertIsNone(child.poll(), 'original publisher remains alive through retry')
        finally:
            output, error = child.communicate('continue\n', timeout=15)
        self.assertEqual(child.returncode, 0, error)
        self.assertIn('up to date', output.lower())
        self.assert_original_untouched()
        self.assertEqual(json.loads(fixture.github_state.read_text())['creates'], 1)

    def test_exact_ref_reconciles_without_retry(self):
        self.pending()
        fixture = self.fixture
        workflow.command(fixture.env['FIXTURE_REAL_GIT'], '-C', str(fixture.source), 'push', str(fixture.remote), fixture.head + ':refs/heads/codex/feature', env=fixture.env)
        before = len(self.pushes())
        result, ready = fixture.invoke(*self.resume_args())
        self.assertEqual((result.returncode, ready['status']), (0, 'PR_READY'), result.stdout)
        self.assertEqual(len(self.pushes()), before)
        self.assertFalse(list(self.state_path.parent.glob('publication-resume-*.json')))

    def test_different_remote_ref_refuses_without_push_or_phase_reset(self):
        self.pending()
        fixture = self.fixture
        workflow.command(fixture.env['FIXTURE_REAL_GIT'], '-C', str(fixture.source), 'push', str(fixture.remote), fixture.base + ':refs/heads/codex/feature', env=fixture.env)
        before = len(self.pushes())
        result, failed = fixture.invoke(*self.resume_args())
        self.assertEqual((result.returncode, failed['status']), (2, 'BLOCKED_POLICY'), result.stdout)
        self.assertEqual(len(self.pushes()), before)
        self.assertEqual(json.loads(self.state_path.read_text())['phase'], 'PUBLISHING')

    def test_without_flag_stays_uncertain_and_source_drift_refuses_retry(self):
        self.pending()
        result, failed = self.fixture.invoke(*self.fixture.prepare_args())
        self.assertEqual((result.returncode, failed['status']), (4, 'REMOTE_UNCERTAIN'))
        (self.fixture.source / 'app.txt').write_text('unreviewed\n')
        result, failed = self.fixture.invoke(*self.resume_args())
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.pushes(), [])

    def test_pr_create_uncertainty_cannot_enter_publication_retry(self):
        self.fixture.change_github(fail_list_after_create=True)
        result, failed = self.fixture.invoke(*self.fixture.prepare_args())
        self.assertEqual((result.returncode, failed['status']), (4, 'REMOTE_UNCERTAIN'))
        self.state = json.loads(Path(failed['state']).read_text())
        before = len(self.pushes())
        result, failed = self.fixture.invoke(*self.resume_args())
        self.assertEqual((result.returncode, failed['status']), (2, 'BLOCKED_POLICY'), result.stdout)
        self.assertEqual(len(self.pushes()), before)
        self.assertEqual(json.loads(self.fixture.github_state.read_text())['creates'], 1)

    def test_actual_native_publisher_retains_lease_after_coordinator_returns(self):
        fixture = self.fixture
        launcher = fixture.bin / 'git'
        original = fixture.bin / 'git-before-pause'
        launcher.rename(original)
        marker, release = fixture.root / 'publisher-started', fixture.root / 'publisher-release'
        launcher.write_text('#!' + sys.executable + '\n' + '''import os,sys,time
from pathlib import Path
if os.environ.get('FIXTURE_PAUSE_NATIVE') and 'check-ref-format' in sys.argv:
    Path(os.environ['FIXTURE_PAUSE_MARKER']).touch()
    deadline=time.monotonic()+10
    while not Path(os.environ['FIXTURE_PAUSE_RELEASE']).exists() and time.monotonic()<deadline:
        time.sleep(.01)
os.execv(''' + repr(str(original)) + ", [" + repr(str(original)) + ", *sys.argv[1:]])\n")
        launcher.chmod(0o700)
        children = []
        def boundary(module):
            bounded = module.bounded
            def orphan(command, **kwargs):
                if len(command) > 1 and Path(command[1]).name == 'publish_feature.py':
                    env = {**fixture.env, 'FIXTURE_PAUSE_NATIVE': '1', 'FIXTURE_PAUSE_MARKER': str(marker),
                           'FIXTURE_PAUSE_RELEASE': str(release)}
                    child = subprocess.Popen(command, env=env, pass_fds=kwargs['pass_fds'], stdout=subprocess.PIPE,
                                             stderr=subprocess.PIPE, text=True)
                    children.append(child)
                    import time
                    deadline = time.monotonic() + 5
                    while not marker.exists() and child.poll() is None and time.monotonic() < deadline:
                        time.sleep(.01)
                    self.assertTrue(marker.exists(), 'actual native publisher must reach paused Git child')
                    raise module.DeliveryError('REMOTE_UNCERTAIN', 'coordinator result lost')
                return bounded(command, **kwargs)
            return mock.patch.object(module, 'bounded', side_effect=orphan)
        try:
            code, failed = fixture.direct_finish(boundary, fixture.prepare_args())
            self.assertEqual((code, failed['status']), (4, 'REMOTE_UNCERTAIN'), failed)
            self.state_path = Path(failed['state'])
            self.state = json.loads(self.state_path.read_text())
            self.assertIsNone(children[0].poll())
            result, busy = fixture.invoke(*self.resume_args())
            self.assertEqual(busy['status'], 'BUSY', result.stdout)
            self.assertEqual(self.pushes(), [])
        finally:
            release.touch()
            for child in children:
                output, error = child.communicate(timeout=20)
                self.assertEqual(child.returncode, 0, (output, error))
        result, ready = fixture.invoke(*self.resume_args())
        self.assertEqual((result.returncode, ready['status']), (0, 'PR_READY'), result.stdout)
        self.assertEqual(json.loads(fixture.github_state.read_text())['creates'], 1)
        self.assertEqual(len(self.pushes()), 1)
        self.assert_original_untouched()

    def test_late_original_writes_between_absent_query_and_retry(self):
        self.pending()
        fixture = self.fixture
        def boundary(module):
            original = module.bounded
            def late(command, **kwargs):
                if len(command) > 1 and Path(command[1]).name == 'publish_feature.py':
                    workflow.command(fixture.env['FIXTURE_REAL_GIT'], '-C', str(fixture.source), 'push',
                                     str(fixture.remote), fixture.head + ':refs/heads/codex/feature', env=fixture.env)
                return original(command, **kwargs)
            return mock.patch.object(module, 'bounded', side_effect=late)
        code, ready = fixture.direct_finish(boundary, self.resume_args())
        self.assertEqual((code, ready['status']), (0, 'PR_READY'), ready)
        self.assertEqual(len(self.pushes()), 1)
        self.assert_original_untouched()
        self.assertEqual(json.loads(fixture.github_state.read_text())['creates'], 1)

    def test_divergent_remote_race_never_rewrites_or_creates_pr(self):
        self.pending()
        fixture = self.fixture
        def boundary(module):
            original = module.bounded
            def advanced(command, **kwargs):
                if len(command) > 1 and Path(command[1]).name == 'publish_feature.py':
                    new = workflow.command(fixture.env['FIXTURE_REAL_GIT'], '-C', str(fixture.source), 'commit-tree',
                                           'HEAD^{tree}', '-p', fixture.head, '-m', 'concurrent advance', env=fixture.env).stdout.strip()
                    self.concurrent = new
                    workflow.command(fixture.env['FIXTURE_REAL_GIT'], '-C', str(fixture.source), 'push',
                                     str(fixture.remote), new + ':refs/heads/codex/feature', env=fixture.env)
                return original(command, **kwargs)
            return mock.patch.object(module, 'bounded', side_effect=advanced)
        code, blocked = fixture.direct_finish(boundary, self.resume_args())
        self.assertEqual((code, blocked['status']), (2, 'BLOCKED_POLICY'), blocked)
        remote = workflow.command('git', 'rev-parse', 'refs/heads/codex/feature', cwd=fixture.remote, env=fixture.env).stdout.strip()
        self.assertEqual(remote, self.concurrent)
        self.assertEqual(json.loads(self.state_path.read_text())['phase'], 'PUBLISHING')
        self.assertEqual(json.loads(fixture.github_state.read_text())['creates'], 0)
        self.assertTrue(all(not any(a.startswith('--force') or a.startswith('+') for a in event) for event in self.pushes()))

    def test_remote_lookup_failure_never_retries(self):
        self.pending()
        fixture = self.fixture
        def boundary(module):
            return mock.patch.object(module, 'published_ref', side_effect=module.DeliveryError('REMOTE_UNCERTAIN', 'lookup unavailable', code=4))
        code, failed = fixture.direct_finish(boundary, self.resume_args())
        self.assertEqual((code, failed['status']), (4, 'REMOTE_UNCERTAIN'))
        self.assertEqual(self.pushes(), [])
        self.assertFalse(list(self.state_path.parent.glob('publication-resume-*.json')))

    def test_failed_retry_preflight_does_not_settle_unknown_legacy_attempt(self):
        self.pending()
        fixture = self.fixture
        def boundary(module):
            bounded = module.bounded
            def no_push(command, **kwargs):
                if len(command) > 1 and Path(command[1]).name == 'publish_feature.py':
                    return 4, json.dumps({'status': 'BLOCKED_REMOTE', 'push_attempted': False})
                return bounded(command, **kwargs)
            return mock.patch.object(module, 'bounded', side_effect=no_push)
        code, unknown = fixture.direct_finish(boundary, self.resume_args())
        self.assertEqual((code, unknown['status']), (4, 'REMOTE_UNCERTAIN'))
        self.assertEqual(json.loads(self.state_path.read_text())['phase'], 'PUBLISHING')
        result, refused = fixture.invoke(*fixture.finish_args('local'))
        self.assertEqual((result.returncode, refused['status']), (2, 'BLOCKED_POLICY'))

    def test_reason_generation_and_mode_constraints_fail_before_publication(self):
        self.pending()
        args = self.resume_args()
        variants = []
        for flag in ('--generation', '--resume-reason'):
            index = args.index(flag)
            variants.append(args[:index] + args[index + 2:])
        variants.extend(args + [flag] for flag in ('--new-generation', '--local-only', '--reconcile-only'))
        for variant in variants:
            with self.subTest(argv=variant):
                result = workflow.command(sys.executable, str(workflow.DELIVER), *variant, env=self.fixture.env, check=False)
                self.assertEqual(result.returncode, 2)
        self.assertEqual(self.pushes(), [])

    def test_original_kit_repository_and_stale_generation_drift_refuse(self):
        self.pending()
        fixture = self.fixture
        originals = [(fixture.original / 'app.txt', 'changed original\n'), (fixture.kit, '{"changed":"kit"}')]
        for path, changed in originals:
            with self.subTest(path=path.name):
                before = path.read_text()
                path.write_text(changed)
                result, failed = fixture.invoke(*self.resume_args())
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.pushes(), [])
                path.write_text(before)
        args = self.resume_args()
        args[args.index('--generation') + 1] = 'f' * 32
        result, failed = fixture.invoke(*args)
        self.assertEqual(failed['status'], 'STALE_GENERATION')
        workflow.command('git', 'remote', 'set-url', 'origin', 'https://github.com/another/project.git', cwd=fixture.original, env=fixture.env)
        result, failed = fixture.invoke(*self.resume_args())
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.pushes(), [])

    def test_lease_alias_and_replacement_refuse_before_retry(self):
        self.pending()
        fixture = self.fixture
        lease = self.state_path.parent / 'publication.lock'
        target = fixture.root / 'lease-target'
        target.write_text('preserve')
        target.chmod(0o600)
        for kind in ('symlink', 'hardlink'):
            with self.subTest(kind=kind):
                lease.symlink_to(target) if kind == 'symlink' else os.link(target, lease)
                result, failed = fixture.invoke(*self.resume_args())
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.pushes(), [])
                lease.unlink()
        self.assertEqual(target.read_text(), 'preserve')
        def boundary(module):
            query = module.published_ref
            def replace(*args, **kwargs):
                observed = query(*args, **kwargs)
                lease.rename(lease.with_suffix('.prior'))
                lease.write_text('replacement')
                lease.chmod(0o600)
                return observed
            return mock.patch.object(module, 'published_ref', side_effect=replace)
        code, failed = fixture.direct_finish(boundary, self.resume_args())
        self.assertEqual((code, failed['status']), (3, 'RECOVERY_REQUIRED'), failed)
        self.assertEqual(self.pushes(), [])
        self.assertFalse(list(self.state_path.parent.glob('publication-resume-*.json')))


    def test_concurrent_ancestor_is_only_fast_forwarded_without_force(self):
        self.pending()
        fixture = self.fixture
        def boundary(module):
            bounded = module.bounded
            def ancestor(command, **kwargs):
                if len(command) > 1 and Path(command[1]).name == 'publish_feature.py':
                    workflow.command(fixture.env['FIXTURE_REAL_GIT'], '-C', str(fixture.source), 'push',
                                     str(fixture.remote), fixture.base + ':refs/heads/codex/feature', env=fixture.env)
                return bounded(command, **kwargs)
            return mock.patch.object(module, 'bounded', side_effect=ancestor)
        code, ready = fixture.direct_finish(boundary, self.resume_args())
        self.assertEqual((code, ready['status']), (0, 'PR_READY'), ready)
        self.assert_original_untouched()
        self.assertTrue(all(not any(a.startswith('--force') or a.startswith('+') for a in event) for event in self.pushes()))



if __name__ == '__main__':
    unittest.main()
