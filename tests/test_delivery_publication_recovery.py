"""Publication recovery contracts using real Git and a local-only GitHub shim."""

import json
import sys
import unittest
from unittest import mock

import test_delivery_workflow as workflow


class PublicationRecovery(unittest.TestCase):
    """Compose the repository fixture without inheriting its existing tests."""

    def setUp(self):
        self.fixture = workflow.DeliveryWorkflow()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.configure_github()

    def current_state(self):
        pointers = list((self.fixture.original / '.git' / 'agent-harness' /
                         'delivery-workflows').glob('*/*/journal.json'))
        self.assertEqual(len(pointers), 1, pointers)
        generation = json.loads(pointers[0].read_text())['generation']
        journal = pointers[0].parent / 'generations' / generation / 'journal.json'
        return json.loads(journal.read_text())

    def reconcile(self):
        fixture = self.fixture
        return fixture.invoke('prepare', '--task', 'fixture', '--original', str(fixture.original),
                              '--original-branch', 'main', '--reconcile-only')

    def assert_original_untouched(self):
        fixture = self.fixture
        self.assertEqual(workflow.command('git', 'rev-parse', 'HEAD', cwd=fixture.original,
                                          env=fixture.env).stdout.strip(), fixture.base)
        self.assertEqual(workflow.command('git', 'status', '--porcelain', cwd=fixture.original,
                                          env=fixture.env).stdout, '')
        self.assertEqual(workflow.command('git', 'rev-parse', 'refs/heads/main', cwd=fixture.remote,
                                          env=fixture.env).stdout.strip(), fixture.base)

    def assert_remote_feature(self, branch, head):
        self.assertEqual(workflow.command('git', 'rev-parse', 'refs/heads/' + branch,
                                          cwd=self.fixture.remote, env=self.fixture.env).stdout.strip(), head)

    def assert_local_refused(self):
        result, data = self.fixture.invoke(*self.fixture.finish_args('local'))
        self.assertEqual((result.returncode, data['status']), (2, 'BLOCKED_POLICY'), result.stdout)
        self.assert_original_untouched()

    def install_uncertain_create(self, mode):
        """A client dies before the shim can reveal an accepted remote create."""
        fixture = self.fixture
        fixture.change_github(uncertain_create=mode)
        path = fixture.bin / 'gh'
        source = path.read_text()
        anchor = "if a[:2]==['pr','list']:\n"
        self.assertEqual(source.count(anchor), 1)
        source = source.replace(anchor,
            "if a[:2]==['pr','create'] and s.get('uncertain_create'):\n"
            "    import time\n"
            "    s['creates']+=1;s['create_pending']=True;p.write_text(json.dumps(s))\n"
            "    if s['uncertain_create']=='output':\n"
            "        sys.stdout.write('x'*1000001);sys.stdout.flush()\n"
            "    time.sleep(10)\n"
            "    sys.exit(0)\n" + anchor)
        path.write_text(source)

    def assert_uncertain_until_positive(self, result, data):
        fixture = self.fixture
        self.assertEqual((result.returncode, data['status']), (4, 'REMOTE_UNCERTAIN'), result.stdout)
        self.assertEqual(self.current_state()['phase'], 'REMOTE_UNCERTAIN')
        self.assert_remote_feature('codex/feature', fixture.head)
        self.assert_local_refused()
        repeated, absent = self.reconcile()
        self.assertEqual((repeated.returncode, absent['status']), (4, 'REMOTE_UNCERTAIN'), repeated.stdout)
        self.assert_local_refused()
        fixture.change_github(created=True, uncertain_create=None, create_pending=False)
        reconciled, ready = self.reconcile()
        self.assertEqual((reconciled.returncode, ready['status']), (0, 'PR_READY'), reconciled.stdout)
        self.assertEqual(json.loads(fixture.github_state.read_text())['creates'], 1)
        self.assert_original_untouched()

    def test_timed_out_create_absence_stays_uncertain_until_positive(self):
        self.install_uncertain_create('timeout')
        result, data = self.fixture.invoke(*self.fixture.prepare_args(), '--timeout', '2')
        self.assertTrue(json.loads(self.fixture.github_state.read_text()).get('create_pending'))
        self.assert_uncertain_until_positive(result, data)

    def test_publisher_preflight_timeout_allows_definite_local_fallback(self):
        fixture = self.fixture
        launcher = fixture.bin / 'git'
        original = fixture.bin / 'git-fixture-original'
        launcher.rename(original)
        marker = fixture.root / 'publisher-preflight-reached'
        # Keep actual Git and the existing owned transport shim; stall only the
        # publisher's local inspection, before it can invoke any push command.
        launcher.write_text('#!' + sys.executable + '\n' + f'''import os,subprocess,sys,time
args=sys.argv[1:]
parent=subprocess.check_output(['ps','-p',str(os.getppid()),'-o','command='],text=True)
if 'check-ref-format' in args and 'publish_feature.py' in parent:
    open({str(marker)!r},'w').write('publisher-only preflight reached')
    time.sleep(4)
os.execv({str(original)!r},[{str(original)!r},*args])
''')
        launcher.chmod(0o700)
        result, data = fixture.invoke(*fixture.prepare_args(), '--timeout', '1')
        self.assertTrue(marker.exists(), 'The real publisher preflight must be exercised')
        self.assertEqual((result.returncode, data['status']), (4, 'REMOTE_BLOCKED'), result.stdout)
        self.assertEqual(self.current_state()['phase'], 'REMOTE_BLOCKED')
        self.assert_original_untouched()
        remote = workflow.command(fixture.env['FIXTURE_REAL_GIT'], '-C', str(fixture.remote),
                                  'show-ref', '--verify', 'refs/heads/codex/feature',
                                  env=fixture.env, check=False)
        self.assertNotEqual(remote.returncode, 0)
        self.assertEqual(json.loads(fixture.github_state.read_text())['creates'], 0)
        delivered, completion = fixture.invoke(*fixture.finish_args('local'))
        self.assertEqual((delivered.returncode, completion['status']), (0, 'LOCAL_DELIVERED'),
                         delivered.stdout)
        self.assertEqual((fixture.original / 'app.txt').read_text(), 'feature\n')
        self.assertEqual(workflow.command('git', 'status', '--porcelain', cwd=fixture.original,
                                          env=fixture.env).stdout, '')

    def test_output_overrun_create_absence_stays_uncertain_until_positive(self):
        self.install_uncertain_create('output')
        result, data = self.fixture.invoke(*self.fixture.prepare_args(), '--timeout', '2')
        self.assertTrue(json.loads(self.fixture.github_state.read_text()).get('create_pending'))
        self.assert_uncertain_until_positive(result, data)

    def test_create_delivery_error_absence_stays_uncertain_until_positive(self):
        fixture = self.fixture

        def fail_create(module):
            gh = module.gh

            def uncertain(*args, **kwargs):
                if args[:2] == ('pr', 'create'):
                    fixture.change_github(creates=1, create_pending=True)
                    raise module.DeliveryError('REMOTE_UNCERTAIN', 'Fixture uncertain create', code=4)
                return gh(*args, **kwargs)

            return mock.patch.object(module, 'gh', side_effect=uncertain)

        code, data = fixture.direct_finish(fail_create, fixture.prepare_args())
        result = type('Result', (), {'returncode': code, 'stdout': json.dumps(data)})()
        self.assert_uncertain_until_positive(result, data)

    def test_interrupted_create_absence_stays_uncertain_until_positive(self):
        fixture = self.fixture

        class Interrupted(Exception):
            pass

        def crash_create(module):
            gh = module.gh

            def interrupted(*args, **kwargs):
                if args[:2] == ('pr', 'create'):
                    fixture.change_github(creates=1, create_pending=True)
                    raise Interrupted
                return gh(*args, **kwargs)

            return mock.patch.object(module, 'gh', side_effect=interrupted)

        with self.assertRaises(Interrupted):
            fixture.direct_finish(crash_create, fixture.prepare_args())
        self.assertEqual(self.current_state()['phase'], 'PR_CREATING')
        result, data = self.reconcile()
        self.assert_uncertain_until_positive(result, data)

    def test_malformed_lookup_cannot_settle_unknown_create(self):
        fixture = self.fixture
        def fail_create(module):
            gh = module.gh
            def uncertain(*args, **kwargs):
                if args[:2] == ('pr', 'create'):
                    fixture.change_github(creates=1, create_pending=True)
                    raise module.DeliveryError('REMOTE_UNCERTAIN', 'Fixture uncertain create', code=4)
                return gh(*args, **kwargs)
            return mock.patch.object(module, 'gh', side_effect=uncertain)
        code, data = fixture.direct_finish(fail_create, fixture.prepare_args())
        self.assertEqual((code, data['status']), (4, 'REMOTE_UNCERTAIN'))
        fixture.change_github(listing=[{'state': 'malformed'}])
        result, unknown = self.reconcile()
        self.assertEqual((result.returncode, unknown['status']), (4, 'REMOTE_UNCERTAIN'), result.stdout)
        self.assertEqual(self.current_state()['phase'], 'REMOTE_UNCERTAIN')
        self.assert_local_refused()
        fresh, blocked = fixture.invoke(*fixture.prepare_args(), '--new-generation')
        self.assertEqual((fresh.returncode, blocked['status']), (3, 'RECOVERY_REQUIRED'), fresh.stdout)
        state = fixture.change_github(created=True)
        state.pop('listing')
        fixture.write_github(state)
        result, ready = self.reconcile()
        self.assertEqual((result.returncode, ready['status']), (0, 'PR_READY'), result.stdout)

    def test_foreign_same_name_prs_do_not_hide_exact_owned_pr(self):
        fixture = self.fixture
        owned = json.loads(fixture.github_state.read_text())['pr']
        fork = {**owned, 'number': 2, 'url': 'https://github.com/fixture/project/pull/2',
                'isCrossRepository': True, 'headRepositoryOwner': {'login': 'foreign'}}
        foreign = {**owned, 'number': 3, 'url': 'https://github.com/fixture/project/pull/3',
                   'headRepository': {'name': 'another'}, 'headRepositoryOwner': {'login': 'foreign'}}
        fixture.change_github(created=True, listing=[fork, owned, foreign])
        result, data = fixture.invoke(*fixture.prepare_args())
        self.assertEqual((result.returncode, data['status']), (0, 'PR_READY'), result.stdout)
        self.assertEqual(self.current_state()['pr_number'], owned['number'])
        self.assertEqual(json.loads(fixture.github_state.read_text())['creates'], 0)
        self.assert_remote_feature('codex/feature', fixture.head)
        self.assert_original_untouched()

    def assert_settled_refusal_can_start_new_branch(self, result, data):
        fixture = self.fixture
        self.assertEqual((result.returncode, data['status']), (2, 'BLOCKED_POLICY'), result.stdout)
        old = self.current_state()
        self.assertEqual(old['phase'], 'POLICY_BLOCKED', old)
        self.assert_local_refused()
        workflow.command('git', 'switch', '-qc', 'codex/reviewed-again', cwd=fixture.source, env=fixture.env)
        state = fixture.change_github(created=False, listing=None)
        state.pop('listing')
        state['pr']['headRefName'] = 'codex/reviewed-again'
        fixture.write_github(state)
        fresh, ready = fixture.invoke(*fixture.prepare_args(), '--new-generation')
        self.assertEqual((fresh.returncode, ready['status']), (0, 'PR_READY'), fresh.stdout)
        self.assertNotEqual(ready['generation'], old['generation'])
        self.assert_remote_feature('codex/reviewed-again', fixture.head)
        self.assert_original_untouched()

    def test_invalid_owned_pr_listing_settles_without_local_fallback(self):
        fixture = self.fixture
        owned = json.loads(fixture.github_state.read_text())['pr']
        fixture.change_github(listing=[{**owned, 'state': 'BROKEN'}])
        result, data = fixture.invoke(*fixture.prepare_args())
        self.assert_settled_refusal_can_start_new_branch(result, data)
        self.assert_remote_feature('codex/feature', fixture.head)

    def test_oversized_owned_pr_listing_settles_without_local_fallback(self):
        fixture = self.fixture
        owned = json.loads(fixture.github_state.read_text())['pr']
        fixture.change_github(listing=[owned] * 101)
        result, data = fixture.invoke(*fixture.prepare_args())
        self.assert_settled_refusal_can_start_new_branch(result, data)
        self.assert_remote_feature('codex/feature', fixture.head)

    def test_divergent_remote_tip_settles_without_forcing_or_local_fallback(self):
        fixture = self.fixture
        divergent = fixture.root / 'divergent'
        workflow.command('git', 'worktree', 'add', '-q', '--detach', str(divergent), fixture.base,
                         cwd=fixture.original, env=fixture.env)
        (divergent / 'app.txt').write_text('different reviewed work\n')
        workflow.command('git', 'commit', '-qam', 'Divergent remote work', cwd=divergent, env=fixture.env)
        prior = workflow.command('git', 'rev-parse', 'HEAD', cwd=divergent, env=fixture.env).stdout.strip()
        self.assertNotEqual(prior, fixture.head)
        workflow.command('git', 'push', '-q', str(fixture.remote), prior + ':refs/heads/codex/feature',
                         cwd=divergent, env=fixture.env)
        result, data = fixture.invoke(*fixture.prepare_args())
        self.assert_remote_feature('codex/feature', prior)
        self.assert_settled_refusal_can_start_new_branch(result, data)
        self.assert_remote_feature('codex/feature', prior)


if __name__ == '__main__':
    unittest.main()
