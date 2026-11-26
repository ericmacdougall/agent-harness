"""Review deadlines by reviewer rung and effort, the timeout message, and how a timeout counts (GoodQA goodqa#16947).

Failing first: against 39f0735e every test here fails except the three marked "guard" (they pin what already held at
that commit: a medium reviewer keeps 720/1440/2880, a daemon-shaped call stays inside the ahc review wall, and a real
timeout receipt is NOT_COUNTED on the ladder).

The step-timing follow-up (the Kimi fallback step, and a step that raised after its spawn) fails first against 9822b621,
except its guard: a step that never launched is not timed."""
import contextlib
import importlib.util
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
HOOKS = HERE.parent / 'harness/hooks'
sys.path.insert(0, str(HOOKS))
sys.path.insert(0, str(HERE))

import escalation as esc  # noqa: E402
import model_tiers as tiers  # noqa: E402
import review_diagnostics as rd  # noqa: E402
import test_peer_review as tpr  # noqa: E402
import usage_guard  # noqa: E402

QUOTA = json.dumps({'type': 'turn.failed', 'error': {'code': 'insufficient_quota'}})


def setUpModule():
    tpr.setUpModule()


def tearDownModule():
    tpr.tearDownModule()


def load_peer_review():
    spec = importlib.util.spec_from_file_location('peer_review_deadline_unit', HOOKS / 'peer_review.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def private_policy(directory, table):
    path = Path(directory) / 'review-policy.json'
    path.write_text(json.dumps({'schema': 1, 'provider_timeout': table}))
    path.chmod(0o600)
    return path


class PolicyTable(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

    def load(self, table):
        return rd.load_policy(private_policy(self.temp.name, table))['provider_timeout']

    def test_shipped_file_states_the_same_table_as_the_code(self):
        shipped = json.loads((HOOKS / 'review_policy.json').read_text())['provider_timeout']
        shipped.pop('_comment', None)
        self.assertEqual(shipped, rd.DEFAULT_POLICY['provider_timeout'])
        self.assertEqual(rd.load_policy(HOOKS / 'review_policy.json')['provider_timeout'], shipped)

    def test_medium_keeps_720_and_larger_efforts_get_their_stated_budgets(self):
        policy = rd.load_policy(HOOKS / 'review_policy.json')
        tier_table = tiers.load_policy()
        expected = {'R0': 720, 'R1': 720, 'R2': 1200, 'R3': 1800, 'R4': 2700, 'R5': 720, 'R6': 1200}
        for rung, entry in tier_table['rungs'].items():
            with self.subTest(rung=rung):
                seconds, basis = rd.provider_deadline(policy, rung, entry['effort'])
                self.assertEqual(seconds, expected[rung])
                self.assertEqual(basis, 'provider_timeout by_effort ' + entry['effort'])
                self.assertLessEqual(seconds, rd.PROVIDER_TIMEOUT_CEILING)
        self.assertEqual(rd.PROVIDER_TIMEOUT_CEILING, 3600)

    def test_malformed_entries_fall_back_to_720_never_to_the_ceiling(self):
        # NEG-1 (AC-4): an out-of-range, non-integer or boolean entry is malformed, not clamped to the ceiling.
        table = self.load({'by_effort': {'max': 99999, 'xhigh': 'abc', 'high': True, 'medium': 0, 'low': 1200.5},
                           'default_seconds': -1, 'ceiling_seconds': 99999})
        self.assertEqual(table['by_effort'], {'low': 720, 'medium': 720, 'high': 720, 'xhigh': 720, 'max': 720})
        self.assertEqual((table['default_seconds'], table['ceiling_seconds']), (720, 3600))

    def test_a_file_cannot_widen_the_code_ceiling(self):
        table = self.load({'by_rung': {'R4': 3601}, 'by_effort': {'max': 3600}, 'ceiling_seconds': 7200})
        self.assertEqual(table['ceiling_seconds'], 3600)
        self.assertEqual(table['by_rung'], {'R4': 720})
        self.assertEqual(table['by_effort']['max'], 3600)
        self.assertEqual(rd.provider_deadline({'provider_timeout': table}, 'R4', 'max')[0], 720)

    def test_a_lower_file_ceiling_caps_the_built_in_entries(self):
        table = self.load({'ceiling_seconds': 1000, 'by_effort': {'xhigh': 1800}})
        self.assertEqual(table['by_effort']['max'], 1000)  # the built-in 2700 is held under the stated ceiling
        self.assertEqual(table['by_effort']['xhigh'], 720)  # an entry above its own file ceiling is malformed
        self.assertEqual(table['by_effort']['medium'], 720)

    def test_by_rung_wins_and_only_rung_keys_are_read(self):
        table = self.load({'by_rung': {'R4': 3000, '../x': 5, 'r4': 9, 'R100': 7, 'R2': 900}})
        self.assertEqual(table['by_rung'], {'R4': 3000, 'R2': 900})
        policy = {'provider_timeout': table}
        self.assertEqual(rd.provider_deadline(policy, 'R4', 'max'), (3000, 'provider_timeout by_rung R4'))
        self.assertEqual(rd.provider_deadline(policy, 'R3', 'xhigh'), (1800, 'provider_timeout by_effort xhigh'))
        self.assertEqual(rd.provider_deadline(policy, 'R9', 'unheard'), (720, 'provider_timeout default_seconds'))

    def test_an_explicit_timeout_only_lowers(self):
        policy = rd.load_policy(HOOKS / 'review_policy.json')
        self.assertEqual(rd.provider_deadline(policy, 'R4', 'max', requested=900)[0], 900)
        self.assertIn('allows 2700', rd.provider_deadline(policy, 'R4', 'max', requested=900)[1])
        self.assertEqual(rd.provider_deadline(policy, 'R1', 'medium', requested=3000)[0], 720)

    def test_an_unsafe_override_file_keeps_the_built_in_table(self):
        path = private_policy(self.temp.name, {'by_effort': {'medium': 3600}})
        path.chmod(0o666)
        self.assertEqual(rd.load_policy(path)['provider_timeout'], rd.DEFAULT_POLICY['provider_timeout'])


class DeadlineReachesTheProvider(unittest.TestCase):
    """AC-1 and AC-2: what the provider call and the usage reservation actually receive, through main()."""
    setUp = tpr.PeerReviewTests.setUp
    fake = tpr.PeerReviewTests.fake
    evidence = staticmethod(tpr.PeerReviewTests.evidence)

    def review(self, *extra, provider_result=None, kimi=None, refuse_pool=None):
        """main() in process. provider_result(name) may return a (code, stdout, stderr) tuple or an exception to raise
        after the spawn; kimi replaces kimi_attempt (the subscription CLI is never called); refuse_pool names a
        provider whose pool lease is refused before any launch."""
        module = load_peer_review()
        head = subprocess.check_output(['git', '-C', str(self.repo), 'rev-parse', 'HEAD'], text=True).strip()
        if rd.lint_packet('code-inspection', self.packet.read_text(errors='replace'), head):
            with self.packet.open('a') as handle:
                handle.write(self.evidence(head))
        seen = {'run': [], 'begin': [], 'kimi': []}
        real_run, real_begin, real_acquire = module.run, usage_guard.UsageStore.begin, usage_guard.UsageStore.acquire_pool

        def spy_run(cmd, prompt, cwd, timeout, **keywords):
            name = Path(cmd[0]).name
            seen['run'].append((name, timeout))
            forced = provider_result(name) if provider_result else None
            if isinstance(forced, BaseException):
                raise forced
            return forced if forced is not None else real_run(cmd, prompt, cwd, timeout, **keywords)

        def spy_begin(store, *arguments, **keywords):
            seen['begin'].append((keywords['timeout'], keywords['aggregate_timeout']))
            return real_begin(store, *arguments, **keywords)

        def spy_acquire(store, provider, *arguments, **keywords):
            if provider == refuse_pool:
                raise usage_guard.PoolUnavailable('TRANSIENT_INFRA', 'Provider pool has an active or unreconciled owner; '
                                                  'no provider was launched')
            return real_acquire(store, provider, *arguments, **keywords)

        def spy_kimi(prompt, packet_path, timeout):
            seen['kimi'].append(timeout)
            if kimi is None:
                raise AssertionError('the Kimi fallback was not expected here')
            answer = kimi(timeout)
            if isinstance(answer, BaseException):
                raise answer
            return answer

        output, errors = io.StringIO(), io.StringIO()
        with patch.object(sys, 'argv', ['review', 'code-inspection', '--repo', str(self.repo), '--packet', str(self.packet),
                                        '--output', str(self.output), '--expected-head', head, *extra]), \
             patch.dict(os.environ, {'PATH': str(self.bin) + os.pathsep + tpr.system_path()}), \
             patch.object(module, 'run', side_effect=spy_run), \
             patch.object(module, 'kimi_attempt', side_effect=spy_kimi), \
             patch.object(usage_guard.UsageStore, 'begin', spy_begin), \
             patch.object(usage_guard.UsageStore, 'acquire_pool', spy_acquire), \
             contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            try:
                code = module.main()
            except SystemExit as stop:
                code = stop.code
        return code, seen, output.getvalue(), errors.getvalue()

    def final_receipt(self):
        runs = sorted((self.root / 'usage-state' / 'runs').iterdir())
        self.assertEqual(len(runs), 1)
        return runs[0].name, json.loads((runs[0] / 'final.json').read_text())

    def test_guard_a_medium_reviewer_keeps_720_and_the_1440_run_budget(self):
        # Guard (holds at base too): the unknown-author reviewer is R1 medium.
        code, seen, out, err = self.review()
        self.assertEqual(code, 0, err)
        self.assertEqual(seen['run'], [('codex', 720)])
        self.assertEqual(seen['begin'], [(1440, 2880)])

    def test_a_max_reviewer_gets_its_larger_deadline_and_run_budget(self):
        code, seen, out, err = self.review('--author-rung', 'R3')
        self.assertEqual(code, 0, err)
        self.assertEqual(seen['run'], [('codex', 2700)])
        self.assertEqual(seen['begin'], [(5400, 10800)])
        run_id, final = self.final_receipt()
        timing = final['usage']['timing']
        self.assertEqual((timing['run_id'], timing['rung'], timing['effort'], timing['deadline']), (run_id, 'R4', 'max', 2700))
        self.assertEqual(timing['basis'], 'provider_timeout by_effort max')
        self.assertEqual([step['provider'] for step in timing['providers']], ['codex'])
        self.assertIsInstance(timing['snapshot_seconds'], float)

    def test_the_timeout_flag_lowers_but_never_raises(self):
        code, seen, out, err = self.review('--author-rung', 'R3', '--timeout', '900')
        self.assertEqual(code, 0, err)
        self.assertEqual((seen['run'], seen['begin']), ([('codex', 900)], [(1800, 3600)]))

    def test_the_timeout_flag_cannot_raise_a_medium_reviewer(self):
        # NEG-3 (AC-2): above the rung deadline is refused before any reservation, as above 720 always was; the
        # same value is accepted for a max reviewer, whose deadline is larger.
        code, seen, out, err = self.review('--timeout', '1000')
        self.assertEqual(code, 2)
        self.assertIn('Review refused: --timeout 1000 is above the 720 second per-provider deadline that '
                      'provider_timeout by_effort medium sets for reviewer rung R1 medium', err)
        self.assertEqual((seen['run'], seen['begin']), ([], []))
        code, seen, out, err = self.review('--author-rung', 'R3', '--timeout', '1000')
        self.assertEqual(code, 0, err)
        self.assertEqual((seen['run'], seen['begin']), ([('codex', 1000)], [(2000, 4000)]))

    def test_a_timeout_above_the_ceiling_is_refused_before_any_reservation(self):
        # NEG-2 (AC-1).
        code, seen, out, err = self.review('--author-rung', 'R3', '--timeout', '3601')
        self.assertEqual(code, 2)
        self.assertIn('--timeout must be between 1 and 3600', err)
        self.assertEqual((seen['run'], seen['begin']), ([], []))

    def test_the_timeout_message_names_run_rung_provider_and_both_steps(self):
        # AC-3, from the dominant real shape: Codex hit its usage limit, then the Claude fallback timed out.
        def outcome(name):
            return (1, QUOTA, '') if name == 'codex' else (124, '', 'HARNESS_PROVIDER_TIMEOUT')
        code, seen, out, err = self.review('--author-rung', 'R3', '--task', 'h22-timeout', provider_result=outcome)
        self.assertEqual(code, 2, err)
        self.assertEqual([name for name, _ in seen['run']], ['codex', 'claude'])
        self.assertEqual(seen['run'][1][1], 2700)
        run_id, final = self.final_receipt()
        self.assertEqual((final['reason'], final['execution']), ('TIMEOUT', 'INTERRUPTED'))
        self.assertIn('REVIEW_DIAGNOSTIC code=PROVIDER_TIMEOUT reason=TIMEOUT provider=claude', err)
        timing = next(line for line in err.splitlines() if line.startswith('Timing: '))
        self.assertIn('run ' + run_id, timing)
        self.assertIn('reviewer rung R4 max', timing)
        self.assertRegex(timing, r'codex ran \d+ s of its 2700 s deadline')
        self.assertRegex(timing, r'claude ran \d+ s of its 2700 s deadline')
        self.assertIn('per-provider deadline 2700 s from provider_timeout by_effort max', timing)
        self.assertRegex(timing, r'snapshot step \d+ s of its \d+ s deadline')
        self.assertEqual(final['usage']['timing']['run_id'], run_id)
        self.assertIn('A timeout is not counted as a ladder failure', err)
        ladder_line = next(line for line in err.splitlines() if line.startswith('Ladder: '))
        self.assertIn('NOT_COUNTED (infrastructure or uncertain result (TIMEOUT))', ladder_line)
        self.assertIn('a timeout is not counted as a ladder failure, but it spent review launch 1 of 8', ladder_line)
        self.assertNotIn('Ladder limit:', err)

    # Every started provider step is timed (PR 339 review follow-up): the Kimi fallback step too, and a step whose
    # call raised after the spawn. Failing first against 9822b621, except the guard.

    def steps(self, final):
        return [(step['provider'], step['deadline']) for step in final['usage']['timing']['providers']]

    def test_a_kimi_fallback_answer_has_its_step_in_the_advisory_receipt(self):
        code, seen, out, err = self.review(
            '--author-rung', 'R3', '--secondary', 'kimi', provider_result=lambda name: (1, QUOTA, ''),
            kimi=lambda timeout: (0, 'KIMI_ADVISORY: BLOCK\nThe packet needs work.', '', 1))
        self.assertEqual(code, 4, err)
        self.assertEqual(([name for name, _ in seen['run']], seen['kimi']), (['codex'], [2700]))
        run_id, final = self.final_receipt()
        self.assertEqual(final['reason'], 'ADVISORY')
        self.assertEqual(self.steps(final), [('codex', 2700), ('kimi', 2700)])
        self.assertEqual(final['usage']['timing']['run_id'], run_id)
        self.assertIsInstance(final['usage']['timing']['providers'][1]['seconds'], float)

    def test_a_kimi_fallback_failure_has_its_step_in_the_timing(self):
        code, seen, out, err = self.review(
            '--author-rung', 'R3', '--secondary', 'kimi', provider_result=lambda name: (1, QUOTA, ''),
            kimi=lambda timeout: (1, '', 'kimi timed out after 2700 seconds; not retried', 1))
        self.assertEqual(code, 2, err)
        run_id, final = self.final_receipt()
        self.assertEqual(self.steps(final), [('codex', 2700), ('kimi', 2700)])

    def test_a_kimi_step_that_raises_is_still_timed(self):
        # NEG-1: a raise inside the Kimi step still leaves its time in the receipt.
        code, seen, out, err = self.review(
            '--author-rung', 'R3', '--secondary', 'kimi', provider_result=lambda name: (1, QUOTA, ''),
            kimi=lambda timeout: OSError('kimi transport broke'))
        self.assertEqual(code, 2, err)
        run_id, final = self.final_receipt()
        self.assertEqual(self.steps(final), [('codex', 2700), ('kimi', 2700)])

    def test_a_raise_after_spawn_keeps_the_step_time(self):
        # NEG-1: run() raises GuardError UNKNOWN when the child record failed and its group could not be proven
        # stopped. That step ran; its time must reach the Timing data, and no fallback follows an UNKNOWN end.
        def outcome(name):
            return usage_guard.GuardError('UNKNOWN', 'The child record failed and the child could not be proven '
                                                     'stopped: OSError')
        code, seen, out, err = self.review('--author-rung', 'R3', provider_result=outcome)
        self.assertEqual(code, 2, err)
        self.assertEqual(seen['run'], [('codex', 2700)])
        run_id, final = self.final_receipt()
        self.assertEqual(final['reason'], 'UNKNOWN')
        self.assertEqual(self.steps(final), [('codex', 2700)])

    def test_guard_a_step_that_never_launched_is_not_timed(self):
        # Guard (holds at base too), NEG-2: the fallback's pool lease is refused before any launch, so only the
        # primary step is recorded, once.
        code, seen, out, err = self.review('--author-rung', 'R3', provider_result=lambda name: (1, QUOTA, ''),
                                           refuse_pool='claude')
        self.assertEqual(code, 2, err)
        self.assertEqual(seen['run'], [('codex', 2700)])
        run_id, final = self.final_receipt()
        self.assertEqual(self.steps(final), [('codex', 2700)])


class TimingLine(unittest.TestCase):
    TIMING = {'run_id': 'f' * 32, 'rung': 'R4', 'effort': 'max', 'deadline': 2700,
              'basis': 'provider_timeout by_effort max', 'run_timeout': 5400,
              'providers': [{'provider': 'codex', 'seconds': 3.2, 'deadline': 2700},
                            {'provider': 'claude', 'seconds': 2700.4, 'deadline': 2700}],
              'snapshot_seconds': 41.0, 'snapshot_deadline': 1860}

    def attempts(self):
        codex = rd.provider_attempt('codex', {'path': '/x/codex'}, 1, '', 'limit', {'reason': 'QUOTA',
                                    'reset_hint': 'Nov 29 at 6pm (UTC)'})
        claude = rd.provider_attempt('claude', {'path': '/x/claude'}, 124, '', 'HARNESS_PROVIDER_TIMEOUT', {'reason': 'TIMEOUT'})
        return [codex, claude]

    def test_rendered_timeout_keeps_the_reset_note_and_adds_the_timing_line(self):
        diag = rd.with_timing(rd.final_diagnostic(self.attempts(), OSError('review failed')), self.TIMING)
        text = rd.render(diag, stage='pr', head='a' * 40)
        self.assertIn('code=PROVIDER_TIMEOUT reason=TIMEOUT provider=claude', text)
        self.assertIn('earlier codex usage limit resets Nov 29 at 6pm (UTC)', text)
        self.assertIn('Timing: run ' + 'f' * 32 + '; reviewer rung R4 max; codex ran 3 s of its 2700 s deadline; '
                      'claude ran 2700 s of its 2700 s deadline; per-provider deadline 2700 s from provider_timeout '
                      'by_effort max; snapshot step 41 s of its 1860 s deadline', text)
        self.assertLessEqual(len(diag['detail']), 600)

    def test_an_exhausted_run_budget_carries_the_timing_line_too(self):
        text = rd.render(rd.with_timing(rd.diagnostic('BUDGET_EXHAUSTED', provider='claude'), self.TIMING))
        self.assertIn('Timing: run ' + 'f' * 32, text)
        self.assertIn('two per-provider deadlines', text)

    def test_other_codes_get_no_timing_line(self):
        # Positive control: the line belongs to timeouts and exhausted budgets only.
        for code in ('PROVIDER_AUTH', 'PROVIDER_USAGE_LIMIT', 'SNAPSHOT_TIMEOUT', 'ISOLATION_FAILED'):
            with self.subTest(code=code):
                self.assertNotIn('Timing:', rd.render(rd.with_timing(rd.diagnostic(code), self.TIMING)))

    def test_hostile_or_missing_values_stay_one_bounded_line(self):
        line = rd.timing_line({'run_id': 'x\n$(id)\x1b[31m' * 80, 'providers': [{'seconds': float('nan')}, 'junk']})
        self.assertNotIn('\n', line)
        self.assertNotIn('\x1b', line)
        self.assertLessEqual(len(line), 400)
        self.assertEqual(rd.timing_line(None).split('; ')[0], 'run unknown')


def timeout_receipt(salt, *, launches=2):
    """A FINAL receipt shaped like the real timed-out ones (codex QUOTA, then a claude TIMEOUT)."""
    return json.dumps({'schema': 1, 'kind': 'final', 'run_id': 'c' * 32, 'evidence': 'EXECUTED', 'subject': {'head': 'a' * 40},
                       'invocation': {}, 'execution': 'INTERRUPTED', 'result': 'NO_RESULT', 'reason': 'TIMEOUT',
                       'usage': {'provider_launches': launches, 'reported': [],
                                 'provider_attempts': [{'provider': 'codex', 'launched': 1, 'reason': 'QUOTA',
                                                        'refused_before_work': False},
                                                       {'provider': 'claude', 'launched': 1, 'reason': 'TIMEOUT',
                                                        'refused_before_work': False}],
                                 'diagnostic': 'PROVIDER_TIMEOUT'},
                       'review': None, 'salt': salt}, sort_keys=True).encode()


def block_receipt(salt):
    return json.dumps({'schema': 1, 'kind': 'final', 'run_id': 'd' * 32, 'evidence': 'EXECUTED',
                       'subject': {'head': ('%040x' % (int(salt) + 1))}, 'invocation': {}, 'execution': 'COMPLETED',
                       'result': 'NO_RESULT', 'reason': 'CODE_FINDINGS', 'usage': {'provider_launches': 1, 'reported': []},
                       'review': {'stage': 'PR', 'verdict': 'BLOCK', 'findings': ['F%s:a.py:logic' % salt]}, 'salt': salt},
                      sort_keys=True).encode()


class TimeoutsOnTheLadder(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ladder-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'state'
        self.root.mkdir(mode=0o700)
        self.policy = tiers.load_policy()
        self.ledger = esc.Ledger(self.root, self.policy)
        environment = patch.dict(os.environ, {'AGENT_HARNESS_ESCALATION_DIR': str(self.root)})
        environment.start()
        self.addCleanup(environment.stop)

    def test_guard_a_real_timeout_receipt_is_never_a_ladder_failure(self):
        # Guard (holds at base too): three timeouts never climb, but each one spends a launch.
        for salt in range(3):
            status = self.ledger.record('h22-t', timeout_receipt(str(salt)), kind='review', source='test')
            self.assertEqual((status['rung'], status['failures_at_rung'], status['climbs']), ('R0', 0, 0))
        state = self.ledger.load('h22-t')
        self.assertEqual({event['class'] for event in state['events']}, {'NOT_COUNTED'})
        self.assertEqual(state['launches'], 3)

    def test_the_ladder_line_says_a_timeout_is_not_a_failure_but_spent_a_launch(self):
        status = self.ledger.record('h22-n', timeout_receipt('1'), kind='review', source='test')
        note = esc.event_note(status, self.policy)
        self.assertIn('NOT_COUNTED (infrastructure or uncertain result (TIMEOUT))', note)
        self.assertIn('not counted as a ladder failure, but it spent review launch 1 of 8', note)
        self.assertIn('($5 of $60)', note)
        block = self.ledger.record('h22-n', block_receipt('2'), kind='review', source='test')
        self.assertNotIn('timeout', esc.event_note(block, self.policy))  # positive control

    def test_findings_at_the_launch_ceiling_do_not_mention_timeouts(self):
        # Positive control: eight distinct findings spend the same ceiling without a timeout sentence.
        for salt in range(8):
            status = self.ledger.record('h22-f', block_receipt(str(salt)), kind='review', source='test')
        self.assertIn('max_review_launches', status['blocked_by'])
        self.assertEqual(status['timeout_launches'], 0)
        note = esc.limit_note(status, self.policy)
        self.assertNotIn('timeout', note)
        self.assertIn('human sign-off needed', note)

    def test_timeouts_at_the_spend_ceiling_say_so(self):
        policy = {**self.policy, 'ladder_limits': {**self.policy['ladder_limits'], 'max_review_launches': 100}}
        ledger = esc.Ledger(self.root, policy)
        for salt in range(12):
            status = ledger.record('h22-s', timeout_receipt(str(salt)), kind='review', source='test')
        self.assertEqual(status['blocked_by'], ['max_total_review_usd'])
        note = esc.limit_note(status, policy)
        self.assertIn('$60 of $60 review budget spent', note)
        self.assertIn('12 of the 12 spent launches were reviewer timeouts', note)

    def test_a_task_below_every_limit_gets_no_note(self):
        status = self.ledger.record('h22-ok', timeout_receipt('1'), kind='review', source='test')
        self.assertEqual(esc.limit_note(status, self.policy), '')


if __name__ == '__main__':
    unittest.main()
