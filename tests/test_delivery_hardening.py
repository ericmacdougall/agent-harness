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
        # A PR that already exists is evidence of a create even when the list lags (spec NEG-9).
        'already_exists': ('GraphQL: Validation Failed: A pull request already exists for '
                           'fixture:codex/feature.', 'REMOTE_UNCERTAIN', None),
        'already_exists_prefixed': ('pull request create failed: GraphQL: A pull request already exists for '
                                    'fixture:codex/feature.', 'REMOTE_UNCERTAIN', None),
        # Definite phrases mid-line (next to echoed names or other text) are not gh verdicts (NEG-10).
        'midline_phrases': ('unexpected reply for head no-commits: no commits between; base ref must be a branch',
                            'REMOTE_UNCERTAIN', None),
        'midline_auth': ('warning from hook: please run gh auth login later', 'REMOTE_UNCERTAIN', None),
        'prefixed_definite': ('pull request create failed: GraphQL: No commits between main and codex/feature',
                              'REMOTE_BLOCKED', 'invalid'),
    }

    def test_already_exists_with_visible_pr_is_adopted(self):
        self.configure_github()
        self.change_github(create_exit=1, create_stderr='GraphQL: Validation Failed: A pull request already exists')
        result, data = self.invoke(*self.prepare_args())
        self.assertEqual((result.returncode, data['status']), (0, 'PR_READY'), result.stdout)

    def test_definite_verdict_needs_a_successful_absence_lookup(self):
        # A definite stderr with a failing `gh pr list` cannot prove absence: stay uncertain.
        self.configure_github()
        self.change_github(create_exit=1, create_absent=True, fail_list_after_create=True,
                           create_stderr='HTTP 403: Resource not accessible by integration')
        result, data = self.invoke(*self.prepare_args())
        self.assertEqual((result.returncode, data['status']), (4, 'REMOTE_UNCERTAIN'), result.stdout)
        self.assertIn('Likely cause', data['hint'])

    def test_auth_failure_that_also_breaks_the_lookup_stays_uncertain_with_cause(self):
        # The realistic path: bad credentials fail the create and the follow-up list alike.
        self.configure_github()
        self.change_github(create_exit=4, create_absent=True, fail_list_after_create=True,
                           create_stderr='HTTP 401: Bad credentials (https://api.github.com/graphql)')
        result, data = self.invoke(*self.prepare_args())
        self.assertEqual((result.returncode, data['status'], data['gh_exit']), (4, 'REMOTE_UNCERTAIN', 4),
                         result.stdout)
        self.assertIn('gh auth login', data['hint'])
        self.assertNotIn('--new-generation', data['hint'])  # an uncertain generation cannot be superseded
        result, refused = self.invoke(*self.finish_args('local'))
        self.assertNotEqual(refused['status'], 'LOCAL_DELIVERED', result.stdout)

    def test_exit_4_is_gh_auth_code_even_without_stderr(self):
        result, data = self.failing_create('', code=4)
        self.assertEqual(data['status'], 'REMOTE_BLOCKED', result.stdout)
        self.assertIn('gh auth login', data['hint'])

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

    def test_classifier_line_rules(self):
        module = load_deliver()
        classify = module.classify_gh_failure
        # A transient phrase on the echoed "Creating" line still keeps the outcome uncertain.
        self.assertIsNone(classify(1, 'Creating pull request for a into main: i/o timeout\nHTTP 403: Forbidden'))
        # Separators other than "\n" never promote a mid-line phrase to a line start.
        for separator in ('\r', '\x0b', '\x0c', '\x1c', '\x85', ' '):
            self.assertIsNone(classify(1, 'unexpected reply' + separator + 'HTTP 403: Forbidden'), repr(separator))
        self.assertIsNotNone(classify(1, 'unexpected reply\nHTTP 403: Forbidden'))

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

    def test_unreachable_remote_is_not_absence_and_settles_nothing(self):
        # NEG-11: an ls-remote error is not "branch missing"; nothing is pushed or settled.
        self.configure_github()
        def factory(module):
            real = module.transport

            def failing(repo, url, repository, args, timeout, **kwargs):
                if args[:1] == ['ls-remote']:
                    return 128, ''
                return real(repo, url, repository, args, timeout, **kwargs)

            stack = contextlib.ExitStack()
            # The commit-policy gate imports its sibling module at run time.
            stack.enter_context(mock.patch.object(sys, 'path', [str(workflow.DELIVER.parent), *sys.path]))
            stack.enter_context(mock.patch.object(module, 'transport', side_effect=failing))
            return stack

        code, data = self.direct_finish(factory, self.prepare_args())
        self.assertEqual((code, data['status'], data.get('reason')), (4, 'REMOTE_BLOCKED', 'BASE_CHECK_UNAVAILABLE'),
                         data)
        pushed = command('git', 'show-ref', '--verify', 'refs/heads/codex/feature', cwd=self.remote,
                         env=self.env, check=False).returncode == 0
        self.assertFalse(pushed)
        self.assertEqual(json.loads(self.github_state.read_text())['creates'], 0)
        # Read-only and before any push: a settled, definite block, like a failed publisher preflight,
        # so REMOTE_BLOCKED keeps its one meaning (reviewed local delivery is available).
        result, delivered = self.invoke(*self.finish_args('local'))
        self.assertEqual((result.returncode, delivered['status']), (0, 'LOCAL_DELIVERED'), result.stdout)

    def test_missing_base_is_not_settled_and_can_be_retried(self):
        self.configure_github()
        command('git', 'update-ref', '-d', 'refs/heads/main', cwd=self.remote, env=self.env)
        result, data = self.invoke(*self.prepare_args())
        self.assertEqual(data.get('reason'), 'BASE_BRANCH_MISSING', result.stdout)
        result, refused = self.invoke(*self.finish_args('local'))
        self.assertNotEqual(refused['status'], 'LOCAL_DELIVERED', result.stdout)
        command('git', 'push', '-q', str(self.remote), self.base + ':refs/heads/main', cwd=self.original, env=self.env)
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

    def test_operator_can_choose_warn_on_the_command_line(self):
        for index in range(6):
            (self.original / f'staged{index}.txt').write_text('x')
        command('git', 'add', '.', cwd=self.original, env=self.env)
        module = load_deliver()
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, self.env, clear=True), contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(err), mock.patch.dict(module.TARGET_POLICY, {'max_staged': 3}), \
                mock.patch.object(sys, 'argv', [str(workflow.DELIVER), *self.prepare_args(), '--local-only',
                                                '--target-policy', 'warn']):
            module.main()
        data = json.loads(out.getvalue())
        self.assertIn('6 staged paths', err.getvalue())
        self.assertNotEqual(data.get('reason'), 'HUGE_STAGED', data)

    def test_git_listing_error_is_refused_not_read_as_zero(self):
        # NEG-12: a git error in the preflight listing must not pass as "0 staged".
        module = load_deliver()
        with mock.patch.object(module, 'bounded', return_value=(128, '')):
            with self.assertRaises(module.DeliveryError) as raised:
                module.target_preflight(self.original, 'main')
        self.assertEqual(raised.exception.facts.get('reason'), 'TARGET_UNREADABLE')

    def test_missing_tracking_ref_warns_instead_of_passing_silently(self):
        module = load_deliver()
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            module.target_preflight(self.original, 'no-such-branch')
        self.assertIn('behind-origin check skipped', err.getvalue())

    def test_limits_are_inclusive(self):
        for index in range(3):
            (self.original / f'loose{index}.txt').write_text('x')
        module = load_deliver()
        with mock.patch.dict(module.TARGET_POLICY, {'max_untracked': 3}):
            module.target_preflight(self.original, 'main')  # exactly at the limit passes
        (self.original / 'loose3.txt').write_text('x')
        with mock.patch.dict(module.TARGET_POLICY, {'max_untracked': 3}):
            with self.assertRaises(module.DeliveryError):
                module.target_preflight(self.original, 'main')

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
        self.assertNotIn('commit_policy_waivers_unreadable', data)

    def test_hostile_waiver_fields_are_sanitised(self):
        # NEG-13: waiver fields are a display channel; escapes, controls, tokens and paths are cleaned.
        secret = 'ghp_' + 'B' * 36
        waiver = {'kind': 'commit\x1b[2J', 'subject': 'x \x1b]0;title\x07 ' + secret + '\r\n',
                  'id': 'w\x00id', 'wal': '/Users/someone/.claude/wals/s/../../secret/main.jsonl'}
        code, data = self.prepare_with([waiver] * 60)
        self.assertEqual(code, 0, data)
        text = json.dumps(data['commit_policy_waivers'])
        self.assertNotIn(secret, text)
        for bad in ('\\u001b', '\\u0000', '\\u0007', '\\r', '\\n', '/Users/'):
            self.assertNotIn(bad, text)
        self.assertEqual(len(data['commit_policy_waivers']), 50)
        self.assertEqual(data['commit_policy_waivers_total'], 60)
        self.assertEqual(data['commit_policy_waivers'][0]['wal'], 'main.jsonl')

    def test_malformed_waiver_item_marks_the_record_unreadable(self):
        code, data = self.prepare_with([{'kind': 'commit', 'id': 'w1'}, 'not-a-dict'])
        self.assertEqual(code, 0, data)
        self.assertTrue(data.get('commit_policy_waivers_unreadable'), data)
        self.assertNotIn('commit_policy_waivers', data)

    def test_unreadable_record_is_flagged_not_hidden(self):
        module = load_deliver()
        out = io.StringIO()
        with mock.patch.dict(os.environ, self.env, clear=True), contextlib.redirect_stdout(out), \
                mock.patch.object(module, 'commit_policy_gate', return_value={'waivers': 'not-a-list'}), \
                mock.patch.object(sys, 'argv', [str(workflow.DELIVER), *self.prepare_args(), '--local-only']):
            module.main()
        data = json.loads(out.getvalue())
        self.assertTrue(data.get('commit_policy_waivers_unreadable'), data)
        self.assertNotIn('commit_policy_waivers', data)


if __name__ == '__main__':
    unittest.main()
