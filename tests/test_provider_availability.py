"""goodqa#17108: a provider that refused for a usage limit is recorded per (provider, pool) and skipped by later runs
until its reset time or a bounded re-probe; a skip never launches, never counts and never passes. goodqa#17102: every
provider attempt gets its own line. Scope addition: a pool held by a live run is waited for (bounded) with a plain
"pool busy" message instead of reconcile advice.

Provider records are genericized fixtures; no account, host or time zone from a real run appears here.
"""
import io
import json
import os
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'harness' / 'hooks'))
sys.path.insert(0, str(ROOT / 'tests'))
import hermetic  # noqa: E402

hermetic.install()
import peer_review as pr  # noqa: E402
import usage_guard as guard  # noqa: E402
import review_diagnostics as rd  # noqa: E402
from tests import test_peer_review as fixtures  # noqa: E402

NOW = 1_900_000_000.0
PROSE = "You've hit your usage limit. Try again later."
WEEKLY = "You've hit your weekly limit · resets Nov 29 at 6pm (UTC)"
PASS = json.dumps({'type': 'result', 'subtype': 'success', 'is_error': False, 'result': 'VERDICT: PASS'})


def codex_quota(message=PROSE):
    return '\n'.join(json.dumps(r) for r in (
        {'type': 'thread.started', 'thread_id': 't'}, {'type': 'turn.started'},
        {'type': 'error', 'message': message}, {'type': 'turn.failed', 'error': {'message': message}}))


def claude_limit(text=WEEKLY):
    """Claude's refusal on the first call: zero counters plus labels (as in test_review_usage_limit)."""
    return json.dumps({
        'type': 'result', 'subtype': 'success', 'is_error': True, 'api_error': 'usage_limit_reached',
        'num_turns': 1, 'duration_api_ms': 0, 'total_cost_usd': 0, 'modelUsage': {}, 'result': text,
        'usage': {'input_tokens': 0, 'output_tokens': 0, 'service_tier': 'standard'}})


CLAUDE_STRUCTURED_QUOTA = json.dumps({'type': 'result', 'is_error': True, 'subtype': 'error',
                                      'error': {'code': 'insufficient_quota', 'reset_at': NOW + 3600}})
CLAUDE_STRUCTURED_AUTH = json.dumps({'type': 'result', 'is_error': True, 'subtype': 'error',
                                     'error': {'code': 'authentication_error'}})


class Established(unittest.TestCase):
    """An established usage store in a private temp root, plus its availability records."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='availability-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'usage'
        guard.UsageStore(self.root)
        self.records = guard.ProviderAvailability(self.root)

    def path(self, provider, pool):
        return self.records.directory / self.records._name(provider, pool)


class StoreTests(Established):
    def test_a_record_is_private_atomic_and_read_back(self):
        value = self.records.record('codex', 'codex-harness', now=NOW)
        self.assertEqual((value['basis'], value['until']), ('reprobe_interval', NOW + guard.AVAILABILITY_REPROBE_SECONDS))
        path = self.path('codex', 'codex-harness')
        self.assertEqual(oct(path.stat().st_mode & 0o777), '0o600')
        self.assertEqual(oct(self.records.directory.stat().st_mode & 0o777), '0o700')
        self.assertEqual([p.name for p in self.records.directory.iterdir()], [path.name])  # no stage file left
        self.assertEqual(self.records.active('codex', 'codex-harness', now=NOW + 1)['until'], value['until'])
        self.assertEqual(self.path('codex', 'codex-harness').parent.parent, self.root)  # usage root, never a WAL

    def test_an_expired_record_is_no_record(self):
        self.records.record('claude', 'default', now=NOW)
        self.assertIsNotNone(self.records.active('claude', 'default', now=NOW + 1799))
        self.assertIsNone(self.records.active('claude', 'default', now=NOW + 1800))

    def test_pools_and_providers_are_kept_apart(self):
        self.records.record('codex', 'codex-harness', now=NOW)
        self.assertIsNone(self.records.active('codex', 'codex-aingel', now=NOW))
        self.assertIsNone(self.records.active('claude', 'codex-harness', now=NOW))
        self.assertIsNotNone(self.records.active('codex', 'codex-harness', now=NOW))

    def test_corrupt_foreign_or_unsafe_records_read_as_no_record(self):
        good = self.records.record('codex', 'p', now=NOW)
        path = self.path('codex', 'p')

        def rewrite(body, mode=0o600):
            path.unlink(missing_ok=True); path.write_bytes(body if isinstance(body, bytes) else json.dumps(body).encode())
            path.chmod(mode)
        cases = {
            'not json': b'{not json',
            'extra key': {**good, 'extra': 1},
            'missing key': {k: v for k, v in good.items() if k != 'hint'},
            'other provider in this file': {**good, 'provider': 'claude'},
            'other pool in this file': {**good, 'pool': 'q'},
            'from the future': {**good, 'recorded_at': NOW + 3600, 'until': NOW + 3700},
            'longer than the cap': {**good, 'until': NOW + guard.AVAILABILITY_MAX_SKIP_SECONDS + 60},
            'not quota': {**good, 'reason': 'AUTH'},
            'unknown basis': {**good, 'basis': 'forever'},
            'bool time': {**good, 'until': True},
            'nan text': b'{"until": NaN}',
            'oversized': b' ' * (guard.AVAILABILITY_MAX_RECORD + 1),
        }
        for label, body in cases.items():
            with self.subTest(label):
                rewrite(body)
                self.assertIsNone(self.records.active('codex', 'p', now=NOW + 1))
        rewrite(good, mode=0o644)
        self.assertIsNone(self.records.active('codex', 'p', now=NOW + 1), 'a world-readable record is not trusted')
        path.unlink()
        target = Path(self.temp.name) / 'elsewhere.json'
        target.write_text(json.dumps(good)); target.chmod(0o600)
        path.symlink_to(target)
        self.assertIsNone(self.records.active('codex', 'p', now=NOW + 1), 'a symlinked record is not followed')
        path.unlink(); rewrite(good)
        self.assertIsNotNone(self.records.active('codex', 'p', now=NOW + 1))  # positive control
        self.records.directory.chmod(0o755)
        self.addCleanup(self.records.directory.chmod, 0o700)
        self.assertIsNone(self.records.active('codex', 'p', now=NOW + 1), 'an unsafe directory is not trusted')

    def test_a_skip_never_outlasts_the_cap_even_from_a_valid_record(self):
        self.records.record('kimi', 'kimi', reset_at=NOW + 10 * 86400, now=NOW)
        record = self.records.active('kimi', 'kimi', now=NOW)
        self.assertEqual(record['basis'], 'capped')
        self.assertLessEqual(record['until'], NOW + guard.AVAILABILITY_MAX_SKIP_SECONDS)
        self.assertIsNone(self.records.active('kimi', 'kimi', now=NOW + guard.AVAILABILITY_MAX_SKIP_SECONDS))

    def test_a_near_future_record_is_still_clamped_to_the_cap_from_now(self):
        # recorded within the clock-skew allowance, so it is valid, but its until is past now + cap
        value = self.records.record('codex', 'p', now=NOW + 200)
        self.assertEqual(value['until'], NOW + 200 + guard.AVAILABILITY_REPROBE_SECONDS)
        path = self.path('codex', 'p'); path.unlink()
        path.write_text(json.dumps({**value, 'until': NOW + 200 + guard.AVAILABILITY_MAX_SKIP_SECONDS})); path.chmod(0o600)
        self.assertEqual(self.records.active('codex', 'p', now=NOW)['until'], NOW + guard.AVAILABILITY_MAX_SKIP_SECONDS)

    def test_an_uninitialized_root_is_never_created_by_a_record(self):
        empty = Path(self.temp.name) / 'empty'
        empty.mkdir(mode=0o700)
        with self.assertRaises(guard.GuardError):
            guard.ProviderAvailability(empty).record('codex', 'p', now=NOW)
        self.assertEqual(list(empty.iterdir()), [])
        guard.UsageStore(empty)  # still a valid place for a new store

    def test_clear_and_listing(self):
        self.records.record('codex', 'p', now=time.time())
        rows = self.records.listing()
        self.assertEqual([(r['provider'], r['pool'], r['active']) for r in rows], [('codex', 'p', True)])
        self.assertTrue(self.records.clear('codex', 'p'))
        self.assertFalse(self.records.clear('codex', 'p'))
        self.assertIsNone(self.records.active('codex', 'p'))

    def test_unsafe_labels_never_reach_a_path(self):
        for label in ('../x', 'a b', '', 'x' * 200):
            with self.subTest(label=label):
                self.assertIsNone(self.records.active('codex', label, now=NOW))
                with self.assertRaises(guard.GuardError):
                    self.records.record('codex', label, now=NOW)


class ResetParsing(unittest.TestCase):
    def window(self, reset_at=None, hint=None):
        return guard.availability_window(reset_at, hint, NOW)

    def test_reliable_shapes_give_the_provider_reset(self):
        cases = {
            'structured epoch': (NOW + 3600, None, NOW + 3600),
            'iso utc': (None, '2030-03-17T18:46:40Z', NOW + 3600),
            'iso offset': (None, 'at 2030-03-17T11:46:40-07:00 please', NOW + 3600),
            'relative hours and minutes': (None, 'in 2 hours 13 minutes.', NOW + 2 * 3600 + 13 * 60),
            'relative short': (None, 'in 1h 30m', NOW + 5400),
            'relative with and': (None, 'in 3 hours and 5 minutes', NOW + 3 * 3600 + 300),
        }
        self.assertEqual(guard.datetime.fromtimestamp(NOW + 3600, guard.timezone.utc).isoformat(),
                         '2030-03-17T18:46:40+00:00')  # the fixture times above are NOW + 1 h
        for label, (reset_at, hint, expected) in cases.items():
            with self.subTest(label):
                self.assertEqual(self.window(reset_at, hint), (expected, 'provider_reset'))

    def test_unreliable_or_past_times_get_the_reprobe_interval(self):
        reprobe = (NOW + guard.AVAILABILITY_REPROBE_SECONDS, 'reprobe_interval')
        for label, (reset_at, hint) in {
            'month day and zone name': (None, 'Nov 29 at 6pm (UTC)'),
            'weekday': (None, 'Monday 9am (UTC)'),
            'iso without zone': (None, '2030-03-17T19:46:40'),
            'past structured': (NOW - 5, None),
            'past iso': (None, '2001-01-01T00:00:00Z'),
            'relative zero': (None, 'in 0 minutes'),
            'relative not at start': (None, 'soon, in 2 hours'),
            'unknown unit': (None, 'in 2 weeks'),
            'nothing': (None, None),
            'bool': (True, None),
            'nan': (float('nan'), None),
        }.items():
            with self.subTest(label):
                self.assertEqual(self.window(reset_at, hint), reprobe)

    def test_a_far_reset_is_clamped_to_the_cap(self):
        self.assertEqual(self.window(None, 'in 4 days 3 hours'),
                         (NOW + guard.AVAILABILITY_MAX_SKIP_SECONDS, 'capped'))
        self.assertEqual(self.window(NOW * 1000, None), (NOW + guard.AVAILABILITY_MAX_SKIP_SECONDS, 'capped'))


class LoopFixture(Established):
    """review_snapshot with fake providers, a recording store and real availability records."""
    class Store:
        def __init__(self, refusals=None, status=None):
            self.refusals, self.status = refusals or {}, status
            self.leases, self.released, self.acquires = [], [], 0

        def acquire_pool(self, provider, pool, run_id):
            self.acquires += 1
            refusal = self.refusals.get(provider)
            if callable(refusal):
                refusal = refusal(self.acquires)
            if refusal is not None:
                raise refusal
            self.leases.append(provider)

        def release_pool(self, provider, pool, run_id, **kwargs):
            self.released.append((provider, kwargs))

    def setUp(self):
        super().setUp()
        self.calls = []
        self.results = {}
        self.policy = pr.tiers.load_policy()

    def options(self, store=None, *, author='claude', reviewer='auto', secondary='default', **extra):
        selection = pr.tiers.reviewer_for(self.policy, 'R0', author)
        return {'reviewer': reviewer, 'secondary': secondary, 'selection': selection,
                'codex_model': self.policy['rungs'][selection['rung']]['models']['openai'],
                'claude_model': self.policy['rungs'][selection['rung']]['models']['claude'],
                'resolutions': {'codex': {'path': '/fixture/codex'}, 'claude': {'path': '/fixture/claude'}},
                'store': store if store is not None else self.Store(), 'availability': self.records,
                'pool': 'codex-harness', 'fallback_pool': 'claude-harness',
                'run_record': SimpleNamespace(timeout=1440, run_id='f' * 32, note_child=lambda pid: None), **extra}

    def run_fake(self, command, prompt, cwd, timeout, **kwargs):
        provider = Path(command[0]).name
        self.calls.append(provider)
        answer = self.results.get(provider, (0, PASS, ''))
        if provider == 'codex' and answer == (0, PASS, ''):
            text = 'VERDICT: PASS'
            Path(command[command.index('--output-last-message') + 1]).write_text(text)
            return 0, '\n'.join(json.dumps(r) for r in (
                {'type': 'item.completed', 'item': {'type': 'agent_message', 'text': text}},
                {'type': 'turn.completed'})), ''
        return answer

    def review(self, options):
        errors = io.StringIO()
        with mock.patch.object(pr, 'run', side_effect=self.run_fake), redirect_stderr(errors):
            try:
                result = pr.review_snapshot(Path(self.temp.name), 'a' * 40, 'pr', 'Rules', 'Packet', options)
                return result, None, errors.getvalue()
            except pr.ReviewFailure as error:
                return None, error, errors.getvalue()


class RecordOnQuota(LoopFixture):
    def test_a_launched_codex_quota_records_and_the_next_run_skips_codex(self):
        self.results['codex'] = (1, codex_quota(), '')
        result, error, _ = self.review(self.options())
        self.assertIsNone(error)
        self.assertEqual(self.calls, ['codex', 'claude'])
        record = self.records.active('codex', 'codex-harness')
        self.assertEqual((record['provider'], record['pool'], record['basis']), ('codex', 'codex-harness', 'reprobe_interval'))
        self.assertIsNone(self.records.active('claude', 'claude-harness'))  # a verdict leaves claude unrecorded
        self.calls.clear()
        options = self.options()
        result, error, stderr = self.review(options)
        self.assertIsNone(error)
        self.assertEqual(self.calls, ['claude'], 'the recorded provider is not launched again')
        self.assertIn('Provider skipped: codex pool codex-harness is out of quota', stderr)
        self.assertIn('skipped until', stderr)
        self.assertEqual(options['attempt_summary'][0], {'provider': 'codex', 'launched': 0, 'reason': 'QUOTA',
                                                         'refused_before_work': False})
        self.assertIn('Primary reviewer skipped (codex pool codex-harness out of quota', result[2])
        self.assertEqual(options['actual_reviewer'], 'claude')

    def test_claude_and_kimi_record_the_same_way(self):
        shapes = {'claude prose': ('claude', (1, claude_limit(), ''), 'reprobe_interval'),
                  'claude structured': ('claude', (1, CLAUDE_STRUCTURED_QUOTA.replace(str(NOW + 3600),
                                                                                   str(time.time() + 3600)), ''),
                                        'provider_reset')}
        for label, (provider, answer, basis) in shapes.items():
            with self.subTest(label):
                self.records.clear('claude', 'claude-harness')
                self.calls.clear()
                self.results = {'claude': answer}
                _, error, _ = self.review(self.options(author='openai'))  # Claude is the primary here
                self.assertIsNone(error)
                self.assertEqual(self.calls, ['claude', 'codex'])
                self.assertEqual(self.records.active('claude', 'claude-harness')['basis'], basis)
        with mock.patch.object(pr, 'kimi_attempt', return_value=(1, '', 'Error: ACCOUNT_QUOTA_EXCEEDED', 1)):
            self.results = {'codex': (1, codex_quota(), '')}
            self.records.clear('codex', 'codex-harness')
            _, error, _ = self.review(self.options(secondary='kimi'))
        self.assertIsNotNone(error)
        self.assertIsNotNone(self.records.active('kimi', 'kimi'))
        self.assertIsNotNone(self.records.active('codex', 'codex-harness'))

    def test_local_refusals_and_auth_record_nothing(self):
        # Kimi's own cooldown refuses without launching (launched 0): not provider evidence.
        with mock.patch.object(pr, 'kimi_attempt', return_value=(1, '', 'Error: ACCOUNT_QUOTA_EXCEEDED', 0)):
            self.results = {'codex': (1, json.dumps({'type': 'turn.failed', 'error': {'code': 'model_unavailable'}}), '')}
            self.review(self.options(secondary='kimi'))
        self.assertIsNone(self.records.active('kimi', 'kimi'))
        # A pool lease refusal (cooldown) before any launch.
        store = self.Store({'codex': guard.PoolUnavailable('QUOTA', 'cooling down', kind='cooldown')})
        self.calls.clear(); self.results = {}
        self.review(self.options(store))
        self.assertIsNone(self.records.active('codex', 'codex-harness'))
        # A structured auth failure is not quota.
        self.calls.clear(); self.results = {'claude': (1, CLAUDE_STRUCTURED_AUTH, '')}
        self.review(self.options(author='openai'))
        self.assertEqual(self.calls, ['claude', 'codex'])
        self.assertIsNone(self.records.active('claude', 'claude-harness'))
        self.assertEqual(list(self.records.directory.iterdir()) if self.records.directory.exists() else [], [])

    def test_a_structured_quota_is_one_bounded_cooldown_not_an_ack_forever_pool_cooldown(self):
        store = self.Store()
        self.results = {'claude': (1, CLAUDE_STRUCTURED_QUOTA, '')}
        self.review(self.options(store, author='openai'))
        claude = [kwargs for provider, kwargs in store.released if provider == 'claude']
        self.assertEqual(claude[0]['reason'], 'QUOTA')
        self.assertIs(claude[0]['account_cooldown'], False)
        self.assertIsNotNone(self.records.active('claude', 'claude-harness'))

    def test_a_verdict_clears_an_old_record(self):
        self.records.record('codex', 'codex-harness', now=time.time() - 3 * 3600)  # expired, so codex is probed
        _, error, _ = self.review(self.options())
        self.assertIsNone(error)
        self.assertEqual(self.calls, ['codex'])
        self.assertFalse(self.path('codex', 'codex-harness').exists())


class LoopSkip(LoopFixture):
    def test_neg_an_expired_record_reprobes(self):
        self.records.record('codex', 'codex-harness', now=time.time() - guard.AVAILABILITY_REPROBE_SECONDS - 1)
        self.results['codex'] = (1, codex_quota(), '')
        _, error, stderr = self.review(self.options())
        self.assertIsNone(error)
        self.assertEqual(self.calls, ['codex', 'claude'], 'the expired provider is launched again')
        self.assertNotIn('Provider skipped', stderr)
        self.assertGreater(self.records.active('codex', 'codex-harness')['until'], time.time())  # re-recorded

    def test_neg_a_skipped_fallback_never_turns_into_a_pass(self):
        self.records.record('claude', 'claude-harness', now=time.time())
        self.results['codex'] = (1, codex_quota(), '')
        options = self.options()
        result, error, stderr = self.review(options)
        self.assertIsNone(result)
        self.assertEqual(error.outcome['result'], 'NO_RESULT')
        self.assertEqual(error.outcome['reason'], 'QUOTA')
        self.assertEqual(self.calls, ['codex'])
        self.assertNotIn('actual_reviewer', options)
        self.assertNotIn('outcome', options)
        self.assertIn('Provider skipped: claude pool claude-harness', stderr)
        final = {'execution': 'COMPLETED', 'reason': 'QUOTA', 'usage': {
            'provider_launches': options['launches'], 'reported': options['usage'],
            'provider_attempts': options['attempt_summary']}}
        self.assertTrue(guard.zero_launch_attempt(final), 'a refusal plus a skip spends no repeat')

    def test_neg_a_skipped_only_provider_never_passes(self):
        self.records.record('codex', 'codex-harness', now=time.time())
        options = self.options(reviewer='codex-only', author='claude')
        result, error, _ = self.review(options)
        self.assertIsNone(result)
        self.assertEqual((error.outcome['reason'], options['launches'], self.calls), ('QUOTA', 0, []))

    def test_neg_availability_failures_never_change_the_outcome(self):
        class Broken:
            def active(self, *args, **kwargs): raise OSError('disk')
            def record(self, *args, **kwargs): raise OSError('disk')
            def clear(self, *args, **kwargs): raise OSError('disk')
        self.results['codex'] = (1, codex_quota(), '')
        result, error, stderr = self.review(self.options(availability=Broken()))
        self.assertIsNone(error)
        self.assertTrue(result[1].startswith('VERDICT: PASS'))
        self.assertIn('Provider availability could not be updated (OSError)', stderr)


class AttemptLines(LoopFixture):
    def test_every_attempt_has_a_line(self):
        self.results = {'codex': (1, codex_quota(), ''), 'claude': (1, claude_limit(), '')}
        options = self.options()
        _, error, _ = self.review(options)
        self.assertIsNotNone(error)
        lines = options['attempt_lines']
        self.assertEqual(len(lines), 2)
        self.assertTrue(lines[0].startswith('codex pool codex-harness: QUOTA (PROVIDER_USAGE_LIMIT), launched'), lines[0])
        self.assertTrue(lines[1].startswith('claude pool claude-harness: QUOTA (PROVIDER_USAGE_LIMIT), launched'), lines[1])
        self.assertIn('resets Nov 29 at 6pm (UTC)', lines[1])
        printed = io.StringIO()
        with redirect_stderr(printed):
            pr.print_attempt_lines(options, always=True)
        self.assertEqual(printed.getvalue().count('Provider attempt '), 2)


class BusyPool(LoopFixture):
    HOLDER = '2e8757e1' + '0' * 24

    def busy(self, alive=True, **changes):
        return {'run_id': self.HOLDER, 'busy': alive, 'state': 'ALIVE' if alive else 'DEAD', 'why': 'fixture',
                'finished': False, 'past_deadline': False, 'started_at': '2026-11-24T17:19:00+00:00',
                'deadline': '2026-11-24T17:46:00+00:00', 'label': 'peer-review-pr', **changes}

    def held(self, until_acquire=None):
        """A refusal by the fixture holder; with until_acquire=N the pool frees on the Nth acquire."""
        def refusal(number):
            if until_acquire is not None and number >= until_acquire:
                return None
            return guard.PoolUnavailable('TRANSIENT_INFRA', 'Provider pool has an active or unreconciled owner; no '
                                         'provider was launched', holder=self.HOLDER, kind='active')
        return refusal

    def store(self, refusals, status):
        store = self.Store(refusals)
        store.holder_status = lambda run_id: dict(status)
        return store

    def test_a_live_holder_of_the_last_pool_is_waited_for_and_the_gate_proceeds(self):
        sleeps = []
        store = self.store({'codex': self.held(until_acquire=3)}, self.busy())
        with mock.patch.object(pr, '_pool_sleep', side_effect=sleeps.append):
            result, error, stderr = self.review(self.options(store, reviewer='codex-only'))
        self.assertIsNone(error)
        self.assertEqual(self.calls, ['codex'])
        self.assertEqual(sleeps, [5, 10])
        self.assertIn('pool busy: codex/codex-harness held by run ' + self.HOLDER, stderr)
        self.assertIn('deadline 2026-11-24T17:46:00+00:00', stderr)
        self.assertIn('Pool free after 15 s', stderr)
        self.assertNotIn('Reconcile', stderr)
        self.assertNotIn('reconcile --run', stderr)

    def test_a_live_holder_that_never_leaves_ends_pool_busy_not_counted(self):
        sleeps = []
        store = self.store({'codex': self.held()}, self.busy())
        options = self.options(store, reviewer='codex-only')
        with mock.patch.object(pr, '_pool_sleep', side_effect=sleeps.append):
            result, error, stderr = self.review(options)
        self.assertEqual(error.outcome['reason'], 'POOL_BUSY')
        self.assertEqual(sum(sleeps), pr.POOL_WAIT_SECONDS)
        self.assertEqual(self.calls, [])
        diag = options['attempts'][-1]
        self.assertEqual(diag['code'], 'POOL_BUSY')
        rendered = rd.render(diag, stage='pr', head='a' * 40)
        self.assertNotIn('reconcile --run', rendered)
        final = {'execution': 'NOT_STARTED', 'reason': 'POOL_BUSY', 'usage': {
            'provider_launches': 0, 'reported': [], 'provider_attempts': options['attempt_summary']}}
        self.assertTrue(guard.zero_launch_attempt(final))
        self.assertEqual(pr.ladder.classify({**final, 'kind': 'final', 'evidence': 'EXECUTED'}, kind='review')[0],
                         'NOT_COUNTED')

    def test_the_wait_never_eats_the_launch_deadline(self):
        sleeps = []
        store = self.store({'codex': self.held()}, self.busy())
        options = self.options(store, reviewer='codex-only', timeout=720)
        options['run_record'] = SimpleNamespace(timeout=1000, run_id='f' * 32, note_child=lambda pid: None)
        with mock.patch.object(pr, '_pool_sleep', side_effect=sleeps.append):
            self.review(options)
        self.assertLessEqual(sum(sleeps), 1000 - 720)

    def test_a_dead_holder_keeps_the_reconcile_advice_and_does_not_wait(self):
        sleeps = []
        store = self.store({'codex': self.held()}, self.busy(alive=False))
        options = self.options(store, reviewer='codex-only')
        with mock.patch.object(pr, '_pool_sleep', side_effect=sleeps.append):
            _, error, _ = self.review(options)
        self.assertEqual(sleeps, [])
        self.assertIn('usage_guard.py reconcile --run ' + self.HOLDER, rd.render(options['attempts'][-1]))
        self.assertNotEqual(error.outcome['reason'], 'POOL_BUSY')

    def test_a_busy_primary_with_an_open_fallback_falls_back_at_once_without_reconcile_advice(self):
        sleeps = []
        store = self.store({'codex': self.held()}, self.busy())
        options = self.options(store)
        with mock.patch.object(pr, '_pool_sleep', side_effect=sleeps.append):
            result, error, _ = self.review(options)
        self.assertIsNone(error)
        self.assertEqual((sleeps, self.calls), ([], ['claude']))
        self.assertIn('busy with live run ' + self.HOLDER, result[2])
        self.assertEqual(options['attempts'][0]['code'], 'POOL_BUSY')
        self.assertNotIn('reconcile --run', rd.render(options['attempts'][0]))

    def test_a_busy_primary_whose_fallback_is_skipped_waits(self):
        sleeps = []
        self.records.record('claude', 'claude-harness', now=time.time())
        store = self.store({'codex': self.held(until_acquire=2)}, self.busy())
        with mock.patch.object(pr, '_pool_sleep', side_effect=sleeps.append):
            result, error, _ = self.review(self.options(store))
        self.assertIsNone(error)
        self.assertEqual((sleeps, self.calls), ([5], ['codex']))

    def test_a_limit_recorded_while_waiting_is_not_launched_into(self):
        store = self.store({'codex': self.held(until_acquire=2)}, self.busy())

        def sleep(seconds):  # the holder records Codex out of quota while this run waits
            self.records.record('codex', 'codex-harness')
        options = self.options(store, reviewer='codex-only')
        with mock.patch.object(pr, '_pool_sleep', side_effect=sleep):
            result, error, stderr = self.review(options)
        self.assertIsNone(result)
        self.assertEqual((error.outcome['reason'], self.calls), ('QUOTA', []))
        self.assertEqual(store.released, [('codex', {'reason': 'NONE'})])
        self.assertIn('Provider skipped: codex pool codex-harness', stderr)

    def test_the_busy_message_names_the_holder_repo_and_pr(self):
        selections = pr.ladder.state_root() / 'selections'
        selections.mkdir(mode=0o700, exist_ok=True)
        path = selections / (self.HOLDER + '.json')
        path.write_text(json.dumps({'run_id': self.HOLDER, 'github_repo': 'example/decisions', 'pr': 7,
                                    'stage': 'pr', 'task': 'dm-7'}))
        self.addCleanup(path.unlink)
        status = pr.holder_status(self.store({}, self.busy()), self.HOLDER)
        text = pr.busy_text('claude', 'default', status)
        self.assertIn('pool busy: claude/default held by run %s (example/decisions PR 7, stage pr, task dm-7, '
                      'started 2026-11-24T17:19:00+00:00, deadline 2026-11-24T17:46:00+00:00)' % self.HOLDER, text)


class HolderStatusStore(unittest.TestCase):
    """UsageStore.holder_status on real runs: this live process is busy; past its deadline it is not."""
    def setUp(self):
        fixture = __import__('test_usage_guard').StoreFixture(methodName='begin')
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture

    def test_a_live_run_is_busy_and_a_past_deadline_run_is_not(self):
        run = self.fixture.begin()
        status = self.fixture.store.holder_status(run.run_id)
        self.assertTrue(status['busy'], status)
        self.assertEqual(status['state'], 'ALIVE')
        later = guard.now_utc() + guard.timedelta(hours=2)
        with mock.patch.object(guard, 'now_utc', return_value=later):
            status = self.fixture.store.holder_status(run.run_id)
        self.assertFalse(status['busy'])
        self.assertTrue(status['past_deadline'])
        with mock.patch.object(guard, 'owner_liveness', return_value={'state': 'DEAD', 'past_deadline': False,
                                                                     'why': 'fixture', 'deadline': 'x'}):
            self.assertFalse(self.fixture.store.holder_status(run.run_id)['busy'])
        # Facts without a parseable deadline can never be waited on: the reconcile advice stays.
        with mock.patch.object(guard, 'owner_liveness', return_value={'state': 'UNCERTAIN', 'past_deadline': False,
                                                                     'why': 'owner facts missing or malformed'}):
            self.assertFalse(self.fixture.store.holder_status(run.run_id)['busy'])

    def test_a_finished_holder_is_not_busy(self):
        run = self.fixture.begin()
        self.fixture.finish(run)
        self.assertFalse(self.fixture.store.holder_status(run.run_id)['busy'])

    def test_a_run_that_launched_nothing_spends_no_aggregate_time(self):
        run = self.fixture.begin(aggregate_timeout=20)
        with mock.patch.object(guard.time, 'monotonic', return_value=run.began + 15):
            run.finish(execution='NOT_STARTED', result='NO_RESULT', reason='POOL_BUSY',
                       usage={'provider_launches': 0, 'reported': []})
        again = self.fixture.begin(aggregate_timeout=20)
        self.assertEqual(again.timeout, 10, 'a 15 s pool wait that launched nothing must not shrink the next run')


class AhcDaemonClasses(unittest.TestCase):
    """red-team F1: the ahc daemon must keep retrying on the new codes (quota defers to the reset; busy relaunches)."""
    INTENTIONALLY_UNKNOWN = {'ISOLATION_FAILED', 'PROVIDER_IO_UNKNOWN', 'PROVIDER_OUTPUT_TOO_LARGE',
                             'REVIEW_LAUNCH_UNCONFIRMED', 'REVIEW_REPEAT_REQUIRED', 'WORKTREE_SCAN_LIMIT',
                             'WORKTREE_SPECIAL_ENTRY'}

    def setUp(self):
        self.runner = __import__('ahc_runner')

    def test_new_codes_have_retry_classes(self):
        line = ('REVIEW_DIAGNOSTIC code=PROVIDER_SKIPPED reason=QUOTA: every reviewer provider is skipped until the '
                'earliest resets at 2030-03-17T18:46:40Z, so nothing was launched')
        self.assertEqual(self.runner.classify_review_failure(line, 2), ('quota', 'PROVIDER_SKIPPED'))
        # ahc's own parser uses mktime minus time.timezone, an hour off in daylight time on a non-UTC host (a separate
        # ahc bug, ticketed); only that the reset time is readable is asserted here.
        self.assertLessEqual(abs(self.runner._reset_time(line) - (NOW + 3600)), 3600)
        self.assertEqual(self.runner.classify_review_failure('REVIEW_DIAGNOSTIC code=POOL_BUSY reason=POOL_BUSY', 2),
                         ('contention', 'POOL_BUSY'))
        record = {'until': NOW + 3600, 'recorded_at': NOW, 'basis': 'provider_reset', 'hint': 'in 1 hour'}
        self.assertLessEqual(abs(self.runner._reset_time(pr.skip_text('codex', 'p', record)) - (NOW + 3600)), 3600)

    def test_every_diagnostic_code_is_classified_on_purpose(self):
        unknown = {code for code in rd.CONTRACT if self.runner.classify_review_failure(
            'REVIEW_DIAGNOSTIC code=%s reason=x' % code, 2)[0] == 'unknown-outcome'}
        self.assertEqual(unknown, self.INTENTIONALLY_UNKNOWN,
                         'a new diagnostic code needs an ahc retry class, or a deliberate entry here')


class CommandLine(unittest.TestCase):
    """The CLI end to end with fake reviewer CLIs (test_peer_review fixtures) and a private usage root."""
    fake = fixtures.PeerReviewTests.fake
    invoke = fixtures.PeerReviewTests.invoke
    evidence = staticmethod(fixtures.PeerReviewTests.evidence)

    def setUp(self):
        fixtures.PeerReviewTests.setUp(self)
        self.launches = self.root / 'launches.txt'
        patch = mock.patch.dict('os.environ', {'HARNESS_PROVENANCE_OFFLINE': '1'})
        patch.start(); self.addCleanup(patch.stop)

    def execute(self, output, **env):
        return self.invoke(stage='code-inspection', output=output,
                           env={'PROVIDER_LAUNCH_LOG': str(self.launches), **env})

    def test_a_quota_refusal_makes_the_next_run_skip_that_provider(self):
        first = self.execute(self.root / 'one.md', CODEX_EVENTS=codex_quota(), CODEX_EXIT='1')
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(self.launches.read_text().split(), ['codex', 'claude'])
        self.assertIn('Provider attempt 1 of 2: codex pool default: QUOTA', first.stderr)
        self.assertIn('codex pool default recorded out of quota', first.stderr)
        self.launches.unlink()
        self.packet.write_text('A second disposable review (a new packet, so not a repeat).')
        second = self.execute(self.root / 'two.md', CODEX_EVENTS=codex_quota(), CODEX_EXIT='1')
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(self.launches.read_text().split(), ['claude'])
        self.assertIn('Provider skipped: codex pool default is out of quota', second.stderr)
        finals = [json.loads(p.read_text()) for p in (self.root / 'usage-state' / 'runs').glob('*/final.json')]
        skipped = [f for f in finals if f['usage'].get('provider_skips')]
        self.assertEqual(len(skipped), 1)
        self.assertEqual(skipped[0]['usage']['provider_skips'][0]['provider'], 'codex')

    def test_neg_every_provider_skipped_launches_nothing_and_never_passes(self):
        guard.UsageStore(self.root / 'usage-state')
        records = guard.ProviderAvailability(self.root / 'usage-state')
        records.record('codex', 'default'); records.record('claude', 'default')
        output = self.root / 'skipped.md'
        result = self.execute(output)
        self.assertEqual(result.returncode, 2, result.stderr)
        lines = [line for line in result.stderr.splitlines() if 'PROVIDER_SKIPPED' in line]
        self.assertEqual(len(lines), 1, result.stderr)
        self.assertIn('NOT_COUNTED', lines[0])
        self.assertIn('codex pool default', lines[0]); self.assertIn('claude pool default', lines[0])
        self.assertFalse(self.launches.exists())
        self.assertFalse(output.exists())
        self.assertEqual(list((self.root / 'usage-state' / 'runs').iterdir()), [])
        self.assertNotIn('PASS', result.stdout)

    def test_both_providers_refusing_prints_both_attempts(self):
        result = self.execute(self.root / 'both.md', CODEX_EVENTS=codex_quota(), CODEX_EXIT='1',
                              CLAUDE_VERDICT=claude_limit(), CLAUDE_EXIT='1')
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn('Provider attempt 1 of 2: codex pool default: QUOTA (PROVIDER_USAGE_LIMIT), launched', result.stderr)
        self.assertIn('Provider attempt 2 of 2: claude pool default: QUOTA (PROVIDER_USAGE_LIMIT), launched', result.stderr)
        self.assertLess(result.stderr.index('Provider attempt 2 of 2'), result.stderr.index('REVIEW_DIAGNOSTIC'))


if __name__ == '__main__':
    unittest.main()
