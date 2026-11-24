"""GoodQA work-tracker-automatic#35905: deliver from a remote branch named unlike the local original branch."""

import json
import os
import sys
import unittest

import test_delivery_workflow as base
from commit_messages import message

REMOTE = 'release/owned-sandbox'


class RemoteBranchCases(unittest.TestCase):
    """Wraps the shared disposable-repo fixture; the bare remote's only branch is renamed to REMOTE."""

    def setUp(self):
        self.fx = base.DeliveryWorkflow('test_unsupported_origin_is_rejected_before_any_publication')
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        fx = self.fx
        fx.configure_github()
        base.command('git', 'branch', '-m', 'main', REMOTE, cwd=fx.remote, env=fx.env)
        base.command('git', 'symbolic-ref', 'HEAD', 'refs/heads/' + REMOTE, cwd=fx.remote, env=fx.env)
        state = fx.change_github()
        state['pr']['baseRefName'] = REMOTE
        fx.write_github(state)
        # The delivered checkout's check needs the interpreter running this test, not an older PATH python3.
        os.symlink(sys.executable, fx.bin / 'python3')
        # Log every gh call so the PR base can be asserted.
        gh = fx.bin / 'gh'
        text = gh.read_text().replace(
            "a=sys.argv[1:]\n",
            "a=sys.argv[1:]\nopen(os.environ['FIXTURE_EVENTS'],'a').write(json.dumps(['gh']+a)+'\\n')\n", 1)
        gh.write_text(text)

    def prepare(self, *extra, flag=True):
        args = list(self.fx.prepare_args()) + (['--remote-branch', REMOTE] if flag else []) + list(extra)
        return self.fx.invoke(*args)

    def finish(self, *extra, generation=None, flag=True):
        args = self.fx.finish_args(generation=generation) + (['--remote-branch', REMOTE] if flag else []) + list(extra)
        return self.fx.invoke(*args)

    def merge(self):
        fx = self.fx
        fx.merged = fx.root / 'merged'
        base.command('git', 'worktree', 'add', '-q', '--detach', str(fx.merged), fx.base, cwd=fx.original, env=fx.env)
        base.command('git', 'merge', '--no-ff', '--no-edit', 'codex/feature', cwd=fx.merged, env=fx.env)
        target = base.command('git', 'rev-parse', 'HEAD', cwd=fx.merged, env=fx.env).stdout.strip()
        base.command('git', 'push', '-q', str(fx.remote), target + ':refs/heads/' + REMOTE, cwd=fx.merged, env=fx.env)
        state = fx.change_github(target=target)
        state['pr'].update(state='MERGED', mergeCommit={'oid': target}, isDraft=False)
        fx.write_github(state)
        return target

    def head(self):
        return base.command('git', 'rev-parse', 'HEAD', cwd=self.fx.original, env=self.fx.env).stdout.strip()

    def pr_bases(self):
        rows = [json.loads(line) for line in self.fx.events.read_text().splitlines() if line]
        return [row[row.index('--base') + 1] for row in rows if row[:3] == ['gh', 'pr', 'create']]

    def test_prepare_and_finish_deliver_through_differently_named_remote_branch(self):
        prepared, data = self.prepare()
        self.assertEqual((prepared.returncode, data['status']), (0, 'PR_READY'), prepared.stdout)
        self.assertEqual(self.pr_bases(), [REMOTE])
        target = self.merge()
        finished, outcome = self.finish(generation=data['generation'])
        self.assertEqual((finished.returncode, outcome['status'], outcome.get('head')), (0, 'DELIVERED', target),
                         finished.stdout)
        self.assertEqual(self.head(), target)
        self.assertEqual(base.command('git', 'branch', '--show-current', cwd=self.fx.original,
                                      env=self.fx.env).stdout.strip(), 'main')

    def test_finish_reuses_the_prepared_remote_branch_without_the_flag(self):
        prepared, data = self.prepare()
        self.assertEqual(prepared.returncode, 0, prepared.stdout)
        target = self.merge()
        finished, outcome = self.finish(flag=False)
        self.assertEqual((finished.returncode, outcome['status'], outcome.get('head')), (0, 'DELIVERED', target),
                         finished.stdout)

    def test_upstream_of_original_branch_selects_the_remote_branch(self):
        fx = self.fx
        base.command('git', 'config', 'branch.main.remote', 'origin', cwd=fx.original, env=fx.env)
        base.command('git', 'config', 'branch.main.merge', 'refs/heads/' + REMOTE, cwd=fx.original, env=fx.env)
        prepared, data = self.prepare(flag=False)
        self.assertEqual((prepared.returncode, data['status']), (0, 'PR_READY'), prepared.stdout)
        self.assertEqual(self.pr_bases(), [REMOTE])
        target = self.merge()
        finished, outcome = self.finish(flag=False)
        self.assertEqual((finished.returncode, outcome['status'], outcome.get('head')), (0, 'DELIVERED', target),
                         finished.stdout)

    def test_missing_remote_branch_is_refused_before_publication(self):
        prepared, data = self.fx.invoke(*self.fx.prepare_args(), '--remote-branch', 'does/not-exist')
        self.assertEqual((prepared.returncode, data['status'], data.get('reason')),
                         (2, 'BLOCKED_POLICY', 'BASE_BRANCH_MISSING'), prepared.stdout)
        self.assertEqual(self.pr_bases(), [])

    def test_wrong_remote_branch_on_finish_is_refused_and_changes_nothing(self):
        prepared, data = self.prepare()
        self.assertEqual(prepared.returncode, 0, prepared.stdout)
        self.merge()
        before = self.head()
        finished, outcome = self.fx.invoke(*self.fx.finish_args(), '--remote-branch', 'main')
        self.assertEqual((finished.returncode, outcome['status'], outcome.get('reason')),
                         (2, 'BLOCKED_POLICY', 'REMOTE_BRANCH_MISMATCH'), finished.stdout)
        self.assertEqual(self.head(), before)

    def test_pr_targeting_another_base_is_refused(self):
        prepared, data = self.prepare()
        self.assertEqual(prepared.returncode, 0, prepared.stdout)
        self.merge()
        state = self.fx.change_github()
        state['pr']['baseRefName'] = 'main'
        self.fx.write_github(state)
        before = self.head()
        finished, outcome = self.finish()
        self.assertEqual((finished.returncode, outcome['status']), (2, 'BLOCKED_POLICY'), finished.stdout)
        self.assertEqual(self.head(), before)

    def test_remote_target_without_the_merge_commit_is_refused(self):
        prepared, data = self.prepare()
        self.assertEqual(prepared.returncode, 0, prepared.stdout)
        self.merge()
        self.fx.change_github(target=self.fx.base)  # the branch head moved to a commit lacking the merge
        before = self.head()
        finished, outcome = self.finish()
        self.assertEqual((finished.returncode, outcome['status']), (2, 'BLOCKED_POLICY'), finished.stdout)
        self.assertEqual(self.head(), before)

    def test_diverged_original_checkout_is_refused(self):
        fx = self.fx
        prepared, data = self.prepare()
        self.assertEqual(prepared.returncode, 0, prepared.stdout)
        self.merge()
        (fx.original / 'local.txt').write_text('unpublished local work\n')
        base.command('git', 'add', 'local.txt', cwd=fx.original, env=fx.env)
        base.command('git', 'commit', '-qm', message('record unpublished local work'), cwd=fx.original, env=fx.env)
        before = self.head()
        finished, outcome = self.finish()
        self.assertEqual((finished.returncode, outcome['status']), (3, 'BLOCKED_LOCAL'), finished.stdout)
        self.assertEqual(self.head(), before)

    def test_dirty_original_checkout_is_refused(self):
        fx = self.fx
        prepared, data = self.prepare()
        self.assertEqual(prepared.returncode, 0, prepared.stdout)
        self.merge()
        (fx.original / 'app.txt').write_text('uncommitted edit\n')
        before = self.head()
        finished, outcome = self.finish()
        self.assertNotEqual(finished.returncode, 0, finished.stdout)
        self.assertNotEqual(outcome['status'], 'DELIVERED')
        self.assertEqual(self.head(), before)
        self.assertEqual((fx.original / 'app.txt').read_text(), 'uncommitted edit\n')

    def test_reports_effective_remote_branch_and_its_source(self):
        fx = self.fx
        prepared, data = self.prepare()
        self.assertEqual((data['status'], data['remote_branch'], data['remote_branch_source']),
                         ('PR_READY', REMOTE, 'flag'), prepared.stdout)
        self.assertNotIn('remote_branch_warning', data)
        base.command('git', 'config', 'branch.main.remote', 'origin', cwd=fx.original, env=fx.env)
        base.command('git', 'config', 'branch.main.merge', 'refs/heads/' + REMOTE, cwd=fx.original, env=fx.env)
        local = self.fx.invoke(*[a for a in fx.prepare_args()], '--local-only', '--new-generation')
        self.assertEqual((local[1]['status'], local[1]['remote_branch'], local[1]['remote_branch_source']),
                         ('LOCAL_READY', REMOTE, 'upstream'), local[0].stdout)
        self.assertIn('--remote-branch', local[1]['remote_branch_warning'])
        self.assertIn('WARNING: remote base', local[0].stderr)

    def test_reports_local_name_when_nothing_else_names_a_base(self):
        prepared, data = self.fx.invoke(*self.fx.prepare_args(), '--local-only')
        self.assertEqual((data['remote_branch'], data['remote_branch_source']), ('main', 'local'), prepared.stdout)

    def test_resumed_generation_uses_stored_base_when_upstream_changes(self):
        fx = self.fx
        prepared, data = self.prepare()
        self.assertEqual(prepared.returncode, 0, prepared.stdout)
        # Upstream now names the source branch; re-resolving it would refuse the resume as source==base.
        base.command('git', 'config', 'branch.main.remote', 'origin', cwd=fx.original, env=fx.env)
        base.command('git', 'config', 'branch.main.merge', 'refs/heads/codex/feature', cwd=fx.original, env=fx.env)
        again, repeated = self.fx.invoke(*fx.prepare_args())
        self.assertEqual((again.returncode, repeated['status'], repeated['remote_branch'],
                          repeated['remote_branch_source']), (0, 'PR_READY', REMOTE, 'prepared'), again.stdout)
        target = self.merge()
        finished, outcome = self.fx.invoke(*fx.finish_args())
        self.assertEqual((finished.returncode, outcome['status'], outcome.get('head')), (0, 'DELIVERED', target),
                         finished.stdout)

    def test_check_ref_format_runs_in_the_original_checkout_not_cwd(self):
        import argparse
        import importlib.util
        from unittest import mock
        spec = importlib.util.spec_from_file_location('remote_branch_fixture_target', base.DELIVER)
        module = importlib.util.module_from_spec(spec)
        with mock.patch.object(sys, 'path', [str(base.DELIVER.parent), *sys.path]):
            spec.loader.exec_module(module)
        gone, here = self.fx.root / 'gone', os.getcwd()
        gone.mkdir()
        os.chdir(gone)
        try:
            gone.rmdir()
            args = argparse.Namespace(original=self.fx.original, remote_branch=REMOTE)
            self.assertEqual(module.explicit_remote_branch(args), REMOTE)
        finally:
            os.chdir(here)

    def test_source_branch_may_not_be_the_remote_base(self):
        fx = self.fx
        base.command('git', 'branch', '-m', 'codex/feature', REMOTE, cwd=fx.source, env=fx.env)
        prepared, data = self.prepare()
        self.assertEqual((prepared.returncode, data['status']), (2, 'BLOCKED_POLICY'), prepared.stdout)


if __name__ == '__main__':
    unittest.main()
