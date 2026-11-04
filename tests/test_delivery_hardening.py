"""Delivery hardening: gh create verdicts (D01), remote base (D02), target sanity (D03), waivers (D06)."""

import contextlib
import importlib.util
import io
import json
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

import test_delivery_workflow as workflow
from test_delivery_workflow import command


def load_deliver():
    spec = importlib.util.spec_from_file_location('hardening_deliver', workflow.DELIVER)
    module = importlib.util.module_from_spec(spec)
    with mock.patch.object(sys, 'path', [str(workflow.DELIVER.parent), *sys.path]):
        spec.loader.exec_module(module)
    return module


def own_tests_only(cls):
    """Reuse the delivery fixture without re-collecting the inherited suite."""
    for name in dir(workflow.DeliveryWorkflow):
        if name.startswith('test_'):
            setattr(cls, name, None)
    return cls


@own_tests_only
class GhCreateVerdict(workflow.DeliveryWorkflow):
    def failing_create(self, stderr, code=1, **extra):
        self.configure_github()
        self.change_github(create_exit=code, create_absent=True, create_stderr=stderr, **extra)
        return self.invoke(*self.prepare_args())

    CASES = {
        'auth': ('To get started with GitHub CLI, please run:  gh auth login', 'REMOTE_BLOCKED', 'gh auth login'),
        'base': ('GraphQL: Base ref must be a branch (createPullRequest)', 'REMOTE_BLOCKED', 'base branch'),
        'validation': ('GraphQL: Validation Failed: No commits between main and feature', 'REMOTE_BLOCKED', 'invalid'),
        'forbidden': ('HTTP 403: Resource not accessible by integration', 'REMOTE_BLOCKED', 'write access'),
        'empty': ('', 'REMOTE_UNCERTAIN', None),
        'odd': ('something odd happened', 'REMOTE_UNCERTAIN', None),
        'gateway': ('HTTP 502: Bad Gateway', 'REMOTE_UNCERTAIN', None),
        'reset': ('dial tcp: connection reset by peer', 'REMOTE_UNCERTAIN', None),
        'mixed': ('HTTP 404 but also i/o timeout', 'REMOTE_UNCERTAIN', None),
        'deadline': ('Post graphql: context deadline exceeded; repository not found', 'REMOTE_UNCERTAIN', None),
        'eof': ('Post https://api.github.com/graphql: EOF permission', 'REMOTE_UNCERTAIN', None),
        'label': ("pull request create failed: could not add label: 'x' not found", 'REMOTE_UNCERTAIN', None),
        'echoed_branch': ('Creating draft pull request for fix/permission-denied-not-found into main in o/r',
                          'REMOTE_UNCERTAIN', None),
        'rate': ('HTTP 429: Too Many Requests; not found', 'REMOTE_UNCERTAIN', None),
    }

    def test_a_create_that_landed_despite_nonzero_exit_is_adopted(self):
        self.configure_github()
        # Exit 1 after GitHub created the PR: the follow-up lookup must find and adopt it.
        self.change_github(create_exit=1, create_stderr='GraphQL: Validation Failed')
        result, data = self.invoke(*self.prepare_args())
        self.assertEqual((result.returncode, data['status']), (0, 'PR_READY'), result.stdout)

    def test_hostile_stderr_is_bounded_and_redacted(self):
        secret = 'ghp_' + 'A' * 36
        stderr = '\x1b[31mHTTP 401\x1b[0m token ' + secret + '\x00\x07\r' + 'y' * 5000
        result, data = self.failing_create(stderr, create_stderr_flood=64)  # 4 MiB flood after
        self.assertEqual(data['status'], 'REMOTE_BLOCKED', result.stdout)
        text = json.dumps(data)
        self.assertNotIn(secret, text)
        self.assertNotIn('\x1b', text)
        self.assertLessEqual(len(data['gh_error']), 300)

    def test_controls_cannot_split_a_token_past_redaction(self):
        module = load_deliver()
        text = module.sanitize_gh_text('ghp_abcdef\x01ghijklmnopSECRETTAIL0123456789')
        self.assertNotIn('SECRETTAIL', text)

    def test_missing_gh_executable_is_blocked_not_uncertain(self):
        self.configure_github()
        (self.bin / 'gh').unlink()
        self.env['PATH'] = str(self.bin) + os.pathsep + '/usr/nonexistent'
        result, data = self.invoke(*self.prepare_args())
        # git is still reachable through the launcher's absolute real-git path.
        self.assertIn(data['status'], {'REMOTE_BLOCKED'}, result.stdout)


def _case(stderr, status, hint):
    def test(self):
        result, data = self.failing_create(stderr)
        self.assertEqual(data['status'], status, result.stdout)
        self.assertEqual(result.returncode, 4)
        self.assertEqual(data['gh_exit'], 1)
        if hint:
            self.assertIn(hint, data['hint'].lower())
    return test


for _name, (_stderr, _status, _hint) in GhCreateVerdict.CASES.items():
    setattr(GhCreateVerdict, 'test_create_failure_' + _name, _case(_stderr, _status, _hint))


@own_tests_only
class RemoteBase(workflow.DeliveryWorkflow):
    def test_missing_remote_base_refuses_before_push_or_pr(self):
        self.configure_github()
        command('git', 'update-ref', '-d', 'refs/heads/main', cwd=self.remote, env=self.env)
        result, data = self.invoke(*self.prepare_args())
        self.assertEqual((result.returncode, data['status'], data['reason']), (2, 'BLOCKED_POLICY', 'BASE_BRANCH_MISSING'),
                         result.stdout)
        self.assertIn('--original-branch', data['hint'])
        pushed = command('git', 'show-ref', '--verify', 'refs/heads/codex/feature', cwd=self.remote,
                         env=self.env, check=False).returncode == 0
        self.assertFalse(pushed)
        self.assertEqual(json.loads(self.github_state.read_text())['creates'], 0)

    def test_suffix_named_branch_does_not_satisfy_the_base(self):
        # ls-remote tail-matches: refs/heads/team/main must not count as main.
        self.configure_github()
        command('git', 'push', '-q', str(self.remote), self.base + ':refs/heads/team/main', cwd=self.original, env=self.env)
        command('git', 'update-ref', '-d', 'refs/heads/main', cwd=self.remote, env=self.env)
        result, data = self.invoke(*self.prepare_args())
        self.assertEqual(data.get('reason'), 'BASE_BRANCH_MISSING', result.stdout)

    def test_present_base_proceeds(self):
        self.configure_github()
        result, data = self.invoke(*self.prepare_args())
        self.assertEqual(data['status'], 'PR_READY', result.stdout)


@own_tests_only
class TargetSanity(workflow.DeliveryWorkflow):
    def run_prepare(self, **policy):
        module = load_deliver()
        out = io.StringIO()
        with mock.patch.dict(os.environ, self.env, clear=True), contextlib.redirect_stdout(out), \
                mock.patch.dict(module.TARGET_POLICY, policy), \
                mock.patch.object(sys, 'argv', [str(workflow.DELIVER), *self.prepare_args(), '--local-only']):
            code = module.main()
        return code, json.loads(out.getvalue())

    def test_huge_staged_set_gets_a_specific_refusal(self):
        for index in range(6):
            (self.original / f'staged{index}.txt').write_text('x')
        command('git', 'add', '.', cwd=self.original, env=self.env)
        code, data = self.run_prepare(max_staged=3)
        self.assertEqual((code, data['status'], data['reason']), (2, 'BLOCKED_POLICY', 'HUGE_STAGED'), data)
        self.assertIn('staged', data['message'])

    def test_huge_untracked_set_gets_a_specific_refusal(self):
        for index in range(6):
            (self.original / f'loose{index}.txt').write_text('x')
        code, data = self.run_prepare(max_untracked=3)
        self.assertEqual((code, data['reason']), (2, 'HUGE_UNTRACKED'), data)

    def test_far_behind_origin_is_refused(self):
        clone = self.root / 'clone'
        command('git', 'clone', '-q', str(self.remote), str(clone), env=self.env)
        command('git', 'config', 'user.name', 'T', cwd=clone, env=self.env)
        command('git', 'config', 'user.email', 't@example.invalid', cwd=clone, env=self.env)
        for index in range(4):
            command('git', 'commit', '-q', '--allow-empty', '-m', f'chore: upstream {index}', cwd=clone, env=self.env)
        command('git', 'push', '-q', 'origin', 'main', cwd=clone, env=self.env)
        command('git', 'fetch', '-q', 'origin', cwd=self.original, env=self.env)
        code, data = self.run_prepare(max_behind=2)
        self.assertEqual((code, data['reason']), (2, 'ORIGINAL_BEHIND'), data)
        self.assertIn('pull --ff-only', data['hint'])

    def test_warn_mode_continues(self):
        for index in range(6):
            (self.original / f'loose{index}.txt').write_text('x')
        code, data = self.run_prepare(max_untracked=3, mode='warn')
        # Warn mode proceeds to the strict clean check, which still refuses a dirty target.
        self.assertNotEqual(data.get('reason'), 'HUGE_UNTRACKED', data)

    def test_sane_checkout_and_odd_branch_names_pass_preflight(self):
        module = load_deliver()
        module.target_preflight(self.original, 'main')
        for branch in ('--upload-pack=x', 'ünï/cødé', 'a b'):
            module.target_preflight(self.original, branch)  # must neither raise nor run an option


@own_tests_only
class WaiverVisibility(workflow.DeliveryWorkflow):
    def prepare_with(self, waivers):
        module = load_deliver()
        record = {'exclude': [], 'waivers': waivers, 'warnings': [], 'tickets': []}
        out = io.StringIO()
        with mock.patch.dict(os.environ, self.env, clear=True), contextlib.redirect_stdout(out), \
                mock.patch.object(module, 'commit_policy_gate', return_value=record), \
                mock.patch.object(sys, 'argv', [str(workflow.DELIVER), *self.prepare_args(), '--local-only']):
            code = module.main()
        return code, json.loads(out.getvalue())

    def test_waivers_used_in_the_range_are_listed_in_prepare_output(self):
        waiver = {'kind': 'commit', 'subject': 'a' * 40, 'id': 'w123', 'wal': '/x/wal.jsonl'}
        code, data = self.prepare_with([waiver])
        self.assertEqual((code, data['status']), (0, 'LOCAL_READY'), data)
        self.assertEqual([item['id'] for item in data['commit_policy_waivers']], ['w123'])
        self.assertEqual(data['commit_policy_waivers'][0]['wal'], 'wal.jsonl')

    def test_no_waivers_means_no_key(self):
        code, data = self.prepare_with([])
        self.assertEqual(code, 0, data)
        self.assertNotIn('commit_policy_waivers', data)


if __name__ == '__main__':
    unittest.main()
