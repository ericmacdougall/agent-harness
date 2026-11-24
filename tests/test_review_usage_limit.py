"""goodqa#16811 H4: a subscription usage limit (weekly or session wording) is QUOTA, shows its reset time on the
first failure, spends no repeat only when the transcript proves no work, and a refused duplicate names what was
counted and the exact next step.

The records are genericized from real Claude results (a limit hit on the first call, and one hit partway through a
paid review): no account, host, session or time zone from those runs appears here.
"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
HOOKS = ROOT / 'harness' / 'hooks'
sys.path.insert(0, str(HOOKS))
sys.path.insert(0, str(ROOT / 'tests'))
import hermetic  # noqa: E402

hermetic.install()
import peer_review as pr  # noqa: E402
import review_diagnostics as rd  # noqa: E402
import usage_guard as guard  # noqa: E402

WEEKLY = "You've hit your weekly limit · resets Nov 29 at 6pm (UTC)"
_OFFLINE = None


def setUpModule():  # the review path never calls the ticket tracker in these tests
    global _OFFLINE
    _OFFLINE = patch.dict(os.environ, {'HARNESS_PROVENANCE_OFFLINE': '1'})
    _OFFLINE.start()


def tearDownModule():
    _OFFLINE.stop()


def limit_record(text=WEEKLY, **changes):
    """The shape Claude prints when the limit refuses the first call: zero counters plus descriptive labels."""
    record = {
        'type': 'result', 'subtype': 'success', 'is_error': True, 'api_error': 'usage_limit_reached',
        'api_error_status': 429, 'api_error_type': 'rate_limit_error', 'terminal_reason': 'api_error',
        'stop_reason': 'stop_sequence', 'num_turns': 1, 'duration_ms': 380, 'duration_api_ms': 0,
        'total_cost_usd': 0, 'modelUsage': {}, 'permission_denials': [], 'result': text,
        'usage': {'input_tokens': 0, 'cache_creation_input_tokens': 0, 'cache_read_input_tokens': 0,
                  'output_tokens': 0, 'server_tool_use': {'web_search_requests': 0, 'web_fetch_requests': 0},
                  'service_tier': 'standard', 'speed': 'standard', 'inference_geo': '', 'iterations': [],
                  'cache_creation': {'ephemeral_1h_input_tokens': 0, 'ephemeral_5m_input_tokens': 0}}}
    record.update(changes)
    return record


def mid_run_record():
    """The same limit after the reviewer already worked and was billed."""
    return limit_record(num_turns=3, duration_api_ms=41000, total_cost_usd=0.117421,
                        modelUsage={'fixture-model': {'outputTokens': 483, 'costUSD': 0.117421}},
                        usage={**limit_record()['usage'], 'input_tokens': 1200, 'output_tokens': 483})


PHRASES = ["You've hit your weekly limit · resets 6pm (UTC)", 'Weekly limit reached · resets Monday 9am (UTC)',
           "You've hit your session limit · resets 3am (UTC)", 'Session limit reached ∙ resets 3am (UTC)']


class UsageLimitClassification(unittest.TestCase):
    def outcome(self, provider, code, stdout='', stderr='', last=''):
        return pr.normalize_provider(provider, code, stdout, stderr, last, 'pr')

    def test_a_weekly_limit_before_any_work_is_quota_and_reports_no_usage(self):
        outcome = self.outcome('claude', 1, json.dumps(limit_record()))
        self.assertEqual(outcome['reason'], 'QUOTA')
        self.assertIs(outcome['provider_refused'], True)
        self.assertIsNone(outcome['usage'])
        self.assertTrue(outcome['fallback_allowed'])
        # Prose never writes an account-pool cooldown or a parsed reset time.
        self.assertEqual((outcome['account_cooldown'], outcome['reset_at']), (False, None))
        self.assertEqual(outcome['reset_hint'], 'Nov 29 at 6pm (UTC)')

    def test_a_limit_hit_partway_through_a_paid_review_still_counts(self):
        outcome = self.outcome('claude', 1, json.dumps(mid_run_record()))
        self.assertEqual(outcome['reason'], 'QUOTA')
        self.assertIs(outcome['provider_refused'], False)
        self.assertEqual(outcome['usage']['cost_usd'], 0.117421)

    def test_every_policy_phrase_is_quota_on_both_providers(self):
        phrases = pr.review_policy()['usage_limit_phrases']
        for wording in ('hit your weekly limit', 'weekly limit reached', 'hit your session limit', 'session limit reached'):
            self.assertIn(wording, phrases)  # data in the shipped policy, not code
        for text in PHRASES:
            with self.subTest(text=text):
                claude = self.outcome('claude', 1, json.dumps(limit_record(text)))
                codex_stderr = self.outcome('codex', 1, '', 'starting\n' + text)
                codex_record = self.outcome('codex', 1, json.dumps({'type': 'turn.failed', 'error': {'message': text}}))
                self.assertEqual([claude['reason'], codex_stderr['reason'], codex_record['reason']], ['QUOTA'] * 3)
                self.assertTrue(claude['reset_hint'])

    def test_ordinary_failures_are_still_invalid_output(self):
        # Must-fail control: the new phrases cannot widen into "any text with weekly, session or limit".
        cases = {
            'claude-error': ('claude', 1, json.dumps(limit_record('Internal error while streaming')), ''),
            'claude-weekly-word': ('claude', 1, json.dumps(limit_record('Your weekly summary failed to render')), ''),
            'claude-context-limit': ('claude', 1, json.dumps(limit_record('Prompt exceeds the context limit')), ''),
            'codex-stderr': ('codex', 1, '', 'error: stream disconnected before completion'),
            'codex-session-word': ('codex', 1, '', 'error: session expired, sign in again later'),
            'codex-earlier-line': ('codex', 1, '', "You've hit your weekly limit\nerror: unexpected end of stream"),
            'garbage': ('claude', 1, 'not json at all', ''),
        }
        for label, (provider, code, stdout, stderr) in cases.items():
            with self.subTest(label):
                self.assertEqual(self.outcome(provider, code, stdout, stderr)['reason'], 'INVALID_OUTPUT')

    def test_limit_wording_inside_a_successful_review_is_not_quota(self):
        report = 'VERDICT: PASS\n\nThe packet quotes the CLI: ' + WEEKLY
        claude = {'type': 'result', 'subtype': 'success', 'is_error': False, 'result': report,
                  'stop_reason': 'end_turn', 'num_turns': 4, 'total_cost_usd': 0.2}
        self.assertEqual(self.outcome('claude', 0, json.dumps(claude))['reason'], 'NONE')
        stream = '\n'.join(json.dumps(record) for record in (
            {'type': 'thread.started'}, {'type': 'turn.started'},
            {'type': 'item.completed', 'item': {'type': 'agent_message', 'text': report}},
            {'type': 'turn.completed', 'usage': {'input_tokens': 10, 'output_tokens': 5}}))
        self.assertEqual(self.outcome('codex', 0, stream, WEEKLY)['reason'], 'NONE')

    def test_the_reset_hint_is_bounded_single_line_display_text(self):
        self.assertIsNone(rd.usage_limit_reset_hint("You've hit your weekly limit"))
        self.assertIsNone(rd.usage_limit_reset_hint(None))
        hint = rd.usage_limit_reset_hint("You've hit your weekly limit · resets " + 'x‮' * 200 + '\nsecond line')
        self.assertLessEqual(len(hint), 80)
        self.assertNotIn('\n', hint)
        self.assertNotIn('‮', hint)

    def test_only_short_labels_directly_inside_usage_are_not_work(self):
        def refused(record):
            return pr.refusal_before_work('claude', json.dumps(record))
        self.assertTrue(refused(limit_record()))
        usage = limit_record()['usage']
        controls = {
            'label-plus-counter': limit_record(usage={**usage, 'output_tokens': 1}),
            'long-label': limit_record(usage={**usage, 'service_tier': 's' * 33}),
            'unknown-text-key': limit_record(usage={**usage, 'note': 'standard'}),
            'label-under-model-usage': limit_record(modelUsage={'m': {'speed': 'standard'}}),
            'two-turns': limit_record(num_turns=2),
            'api-time': limit_record(duration_api_ms=5),
        }
        for label, record in controls.items():
            with self.subTest(label):
                self.assertFalse(refused(record))


class FirstFailureShowsReset(unittest.TestCase):
    """The whole review attempt path: the diagnostic printed on the first failure carries the reset time."""
    HOLDER = 'f' * 32

    class Store:
        def __init__(self, refusals):
            self.refusals = refusals

        def acquire_pool(self, provider, pool, run_id):
            if provider in self.refusals:
                raise self.refusals[provider]

        def release_pool(self, provider, pool, run_id, **kwargs):
            pass

    def review(self, refused_provider, run_result):
        refusal = guard.PoolUnavailable('TRANSIENT_INFRA', 'Provider pool has an active or unreconciled owner; no '
                                        'provider was launched', holder=self.HOLDER, kind='active')
        refusals = {refused_provider: refusal} if refused_provider else {}
        results = run_result if isinstance(run_result, dict) else None

        def fake_run(command, *a, **k):
            if results is None:
                return run_result
            return next(value for name, value in results.items()
                        if any(str(part).endswith('/' + name) for part in command))

        record = type('Record', (), {'run_id': 'r' * 32, 'timeout': 1440, 'note_child': staticmethod(lambda child: None)})()
        options = {'store': self.Store(refusals), 'run_record': record}
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(pr.diagnostics, 'discover_executable',
                          side_effect=lambda name, **_: {'name': name, 'path': '/fixture/' + name, 'source': 'PATH', 'rejected': []}), \
             patch.object(pr, 'run', side_effect=fake_run):
            with self.assertRaises(pr.ReviewFailure):
                pr.review_snapshot(Path(temporary), 'a' * 40, 'pr', 'Review', 'Evidence', options)
        final = {'execution': 'COMPLETED', 'reason': 'QUOTA', 'usage': {
            'provider_launches': options['launches'], 'reported': options['usage'],
            'provider_attempts': options['attempt_summary']}}
        return options, guard.zero_launch_attempt(final)

    def test_claude_weekly_limit_prints_the_reset_and_spends_no_repeat(self):
        options, zero_launch = self.review('codex', (1, json.dumps(limit_record()), ''))
        rendered = rd.render(rd.final_diagnostic(options['attempts'], None))
        self.assertIn('code=PROVIDER_USAGE_LIMIT', rendered)
        self.assertIn('resets Nov 29 at 6pm (UTC)', rendered)
        self.assertEqual(options['attempt_summary'][-1],
                         {'provider': 'claude', 'launched': 1, 'reason': 'QUOTA', 'refused_before_work': True})
        self.assertTrue(zero_launch)

    def test_codex_session_limit_on_stderr_prints_the_reset(self):
        options, zero_launch = self.review('claude', (1, '', PHRASES[2]))
        rendered = rd.render(options['attempts'][0])
        self.assertIn('code=PROVIDER_USAGE_LIMIT', rendered)
        self.assertIn('resets 3am (UTC)', rendered)
        self.assertTrue(zero_launch)

    def test_a_mid_run_limit_counts_as_a_spent_attempt(self):
        options, zero_launch = self.review('codex', (1, json.dumps(mid_run_record()), ''))
        self.assertIs(options['attempt_summary'][-1]['refused_before_work'], False)
        self.assertFalse(zero_launch)

    def test_the_primary_reset_survives_a_fallback_that_fails_another_way(self):
        # Round 1 (L2): only the final diagnostic is printed, and it used to be the fallback's alone.
        options, _ = self.review(None, {'codex': (1, '', PHRASES[2]), 'claude': (0, 'not json', '')})
        self.assertEqual([attempt['provider'] for attempt in options['attempts']], ['codex', 'claude'])
        rendered = rd.render(rd.final_diagnostic(options['attempts'], None))
        self.assertNotIn('code=PROVIDER_USAGE_LIMIT', rendered)
        self.assertIn('earlier codex usage limit resets 3am (UTC)', rendered)

    def test_both_reset_times_are_shown_when_both_providers_are_limited(self):
        options, _ = self.review(None, {'codex': (1, '', PHRASES[2]), 'claude': (1, json.dumps(limit_record()), '')})
        rendered = rd.render(rd.final_diagnostic(options['attempts'], None))
        self.assertIn('code=PROVIDER_USAGE_LIMIT', rendered)
        self.assertIn('resets Nov 29 at 6pm (UTC)', rendered)
        self.assertIn('earlier codex usage limit resets 3am (UTC)', rendered)

    def test_a_single_limited_attempt_is_not_repeated_on_its_detail_line(self):
        # Control: with no earlier attempt the Detail line is unchanged.
        options, _ = self.review('codex', (1, json.dumps(limit_record()), ''))
        detail = rd.final_diagnostic(options['attempts'], None)['detail']
        self.assertEqual(detail.count('resets'), 1, detail)
        self.assertNotIn('earlier', detail)


class DuplicateRefusalNamesTheNextStep(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='usage-limit-')
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        repo = root / 'repo'
        repo.mkdir()
        self.store = guard.UsageStore(root / 'private')
        self.subject = guard.Subject(schema=1, fingerprint='a' * 64, reusable=True, head='b' * 40, tree='c' * 40)
        self.subject.repo, self.subject.manifest = repo, {}
        self.subject.probe = lambda: self.subject
        self.identity = guard.invocation_identity(self.subject, purpose='peer-review-pr', argv=['review'], cwd=repo)

    def begin(self, **options):
        return self.store.begin(self.subject, self.identity, owner='fixture', label='peer-review-pr', timeout=10,
                                kind='review', minimum_bytes=0, aggregate_timeout=60, **options)

    def spend(self, run, reason='INVALID_OUTPUT'):
        run.finish(execution='COMPLETED', result='NO_RESULT', reason=reason,
                   usage={'provider_launches': 1, 'reported': []})

    def refusal(self, **options):
        with self.assertRaises(guard.GuardError) as caught:
            self.begin(**options)
        self.assertEqual(caught.exception.reason, 'BUDGET_EXHAUSTED')
        return caught.exception

    def test_the_refusal_names_the_counted_run_and_how_to_repeat_once(self):
        first = self.begin()
        self.spend(first)
        error = self.refusal()
        self.assertIn('run %s ended INVALID_OUTPUT' % first.run_id[:8], error.message)
        self.assertIn('counted attempts: 1', error.message)
        self.assertIn('--repeat-reason', error.message)
        diagnosis = rd.final_diagnostic([], error)
        self.assertEqual((diagnosis['code'], diagnosis['reason']), ('REVIEW_REPEAT_REQUIRED', 'BUDGET_EXHAUSTED'))
        rendered = rd.render(diagnosis)
        self.assertIn("--repeat-reason '<why, in plain words>' in single quotes", rendered)
        self.assertIn(first.run_id[:8], rendered)

    def test_after_the_one_repeat_the_refusal_says_change_the_packet(self):
        self.spend(self.begin())
        second = self.begin(repeat_reason='provider outage confirmed')
        self.spend(second, reason='CODE_FINDINGS')
        for options in ({}, {'repeat_reason': 'try again'}):
            with self.subTest(options=options):
                error = self.refusal(**options)
                self.assertIn('the one declared repeat is already used', error.message)
                self.assertIn('run %s ended CODE_FINDINGS' % second.run_id[:8], error.message)
                self.assertIn('counted attempts: 2', error.message)

    def test_a_reconciled_run_without_a_final_is_counted_and_named(self):
        # Round 1 (L3): the refusal branch for a reservation that was reconciled but never wrote a FINAL.
        run = self.begin()
        self.store.reconcile(run.run_id, actor='fixture', reason='owner exited without a final',
                             evidence='fixture process table')
        error = self.refusal()
        self.assertIn('run %s has no final receipt (reconciled)' % run.run_id[:8], error.message)
        self.assertIn('counted attempts: 1', error.message)
        self.assertIn('--repeat-reason', error.message)

    def test_a_proven_no_work_limit_does_not_need_a_repeat(self):
        # Control for the PR 318 rule: an attempt summarised as refused before work is not counted.
        run = self.begin()
        run.finish(execution='COMPLETED', result='NO_RESULT', reason='QUOTA', usage={
            'provider_launches': 1, 'reported': [],
            'provider_attempts': [{'provider': 'claude', 'launched': 1, 'reason': 'QUOTA', 'refused_before_work': True}]})
        self.spend(self.begin())


if __name__ == '__main__':
    unittest.main()
