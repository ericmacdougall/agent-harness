"""Run the actual Codex command hook wire protocol in an isolated home."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


HOOK = Path(__file__).resolve().parents[1] / 'codex/hooks/wal.py'
# Hang guard for one hook process, not a latency assertion: the hook never
# waits on locks, but interpreter start-up can take seconds on a loaded runner.
HOOK_WATCHDOG_SECONDS = 60


class ContinuationTests(unittest.TestCase):
    def setUp(self):
        home = tempfile.TemporaryDirectory()
        self.addCleanup(home.cleanup)
        self.home = Path(home.name)
        self.env = {**os.environ, 'HOME': home.name}
        self.wal = self.home / '.agent-harness/codex-wals/session/main.jsonl'
        self.hook = HOOK

    def invoke(self, *args, payload=None, error=None):
        result = subprocess.run(
            [sys.executable, str(self.hook), *args],
            input=json.dumps(payload) if payload is not None else '',
            env=self.env, capture_output=True, text=True, timeout=HOOK_WATCHDOG_SECONDS,
        )
        if error is not None:
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn(error, result.stderr)
            return
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def event(self, name, **fields):
        return self.invoke('hook', payload={
            'hook_event_name': name, 'session_id': 'session', **fields,
        })

    def state(self, status, budget=None, error=None):
        option = () if budget is None else ('--max-continuations', str(budget))
        return self.invoke('continuation', '--wal', str(self.wal), status, *option, error=error)

    def stop(self, turn_id, **fields):
        return self.event('Stop', turn_id=turn_id, **{'stop_hook_active': False, **fields})

    def test_opt_in_installed_hook_continues_native_same_turn(self):
        import shutil

        self.hook = self.home / '.codex/agent-harness/wal.py'
        self.hook.parent.mkdir(parents=True)
        shutil.copyfile(HOOK, self.hook)
        self.assertEqual(self.state('active', 4)['remaining'], 4)
        # The native Codex Stop loop keeps one turn ID and sets
        # stop_hook_active on each invocation after the first block.
        turn_id = 'private-turn'
        for index in range(4):
            output = f'private response {index}'
            fields = {'stop_hook_active': index > 0, 'last_assistant_message': output}
            self.assertEqual(self.stop(turn_id, **fields)['decision'], 'block')
            self.assertNotIn('decision', self.stop(turn_id, **fields))
            self.assertEqual(self.state('status')['remaining'], 3 - index)
            state = self.wal.with_name('continuation.json').read_text()
            self.assertNotIn(turn_id, state)
            self.assertNotIn(output, state)
            self.state('active')
        self.assertNotIn('decision', self.stop(
            turn_id, stop_hook_active=True, last_assistant_message='over budget'))
        self.assertTrue(self.state('status')['used'])
        self.assertEqual(self.state('status')['limit'], 4)

    def test_concurrent_repeated_stops_spend_only_one_pass(self):
        from concurrent.futures import ThreadPoolExecutor

        self.state('active', 3)
        self.assertEqual(self.stop('same-turn', last_assistant_message='first')['decision'], 'block')
        with ThreadPoolExecutor(max_workers=2) as pool:
            stops = [pool.submit(self.stop, 'same-turn', stop_hook_active=True,
                                 last_assistant_message='second') for _ in range(2)]
        self.assertEqual(sum(stop.result().get('decision') == 'block' for stop in stops), 1)
        self.assertEqual(self.state('status')['remaining'], 1)
        self.assertEqual(self.stop('different-turn')['decision'], 'block')

    def test_extra_passes_do_not_refill_across_transitions_or_interrupt(self):
        self.state('active', 2)
        self.assertEqual(self.stop('spent', last_assistant_message='first')['decision'], 'block')
        for held in ('paused', 'blocked', 'handoff', 'complete', 'interrupt'):
            if held == 'interrupt':
                self.event('Interrupt', turn_id='spent')
                self.assertEqual(self.state('status')['state'], 'paused')
            else:
                self.state(held)
            self.assertEqual(self.stop('spent', stop_hook_active=True, last_assistant_message='second'), {})
            self.assertEqual(self.state('active', 2)['remaining'], 1)
            self.assertNotIn('decision', self.stop('spent'))
            self.assertNotIn('decision', self.stop('spent', stop_hook_active=True, last_assistant_message='second'))
        self.assertEqual(self.stop('second')['decision'], 'block')
        self.assertNotIn('decision', self.stop('third'))

    def test_repeated_stop_requires_a_fresh_response_after_own_claim(self):
        self.state('active', 4)
        self.assertNotIn('decision', self.stop('initial', stop_hook_active=True, last_assistant_message='another hook'))
        self.assertEqual(self.stop('initial', last_assistant_message='response A')['decision'], 'block')
        self.assertNotIn('decision', self.stop('initial', last_assistant_message='old flag'))
        self.assertNotIn('decision', self.stop('initial', stop_hook_active=True, last_assistant_message=' response A\n'))
        self.assertEqual(self.stop('initial', stop_hook_active=True, last_assistant_message='response B')['decision'],
                         'block')
        self.assertNotIn('decision', self.stop('initial', stop_hook_active=True, last_assistant_message='response A'))
        self.assertEqual(self.stop('new-turn', last_assistant_message='response A')['decision'], 'block')
        self.assertNotIn('decision', self.stop('initial', stop_hook_active=True, last_assistant_message='late response'))
        self.assertEqual(self.state('status')['remaining'], 1)

    def test_unavailable_responses_do_not_unlock_repeat(self):
        self.state('active', 3)
        self.assertEqual(self.stop('no-first-output')['decision'], 'block')
        self.assertNotIn('decision', self.stop(
            'no-first-output', stop_hook_active=True, last_assistant_message='has second output'))
        self.assertEqual(self.stop('new-turn', last_assistant_message='first output')['decision'], 'block')
        for output in (None, '', ' \n\t ', {'text': 'invalid'}, '\ud800', 'a' * 65537):
            self.assertNotIn('decision', self.stop('new-turn', stop_hook_active=True, last_assistant_message=output))
        self.assertEqual(self.state('status')['remaining'], 1)
        self.assertEqual(self.stop('new-turn', stop_hook_active=True, last_assistant_message='fresh output')['decision'],
                         'block')

    def test_invalid_or_changed_budget_refuses_without_writing(self):
        state_file = self.wal.with_name('continuation.json')
        for invalid in (0, 5, 'unused'):
            self.state('active', invalid, error='--max-continuations')
        self.state('blocked', 2, error='requires active')
        self.assertFalse(state_file.exists())
        self.state('active', 2)
        original = state_file.read_bytes()
        for changed in (1, 3):
            self.state('active', changed, error='cannot change')
        self.assertEqual(state_file.read_bytes(), original)
        self.assertEqual(self.state('active', 2)['remaining'], 2)

    def test_legacy_checkpoint_can_only_opt_in_before_its_one_pass(self):
        state_file = self.wal.with_name('continuation.json')
        self.state('active')
        legacy = {'state': 'active', 'used': False, 'interrupt': None}
        state_file.write_text(json.dumps(legacy))
        self.assertEqual(self.state('active', 3)['remaining'], 3)
        legacy['used'] = True
        state_file.write_text(json.dumps(legacy))
        original = state_file.read_bytes()
        self.assertEqual(self.state('status')['remaining'], 0)
        self.state('active', 3, error='cannot change')
        self.assertEqual(state_file.read_bytes(), original)
        self.assertNotIn('decision', self.stop('new-turn'))

    def test_extra_budget_requires_valid_top_level_stop_fields(self):
        self.state('active', 2)
        for turn_id in (None, '', 'a' * 257, {'id': 'opaque'}, 'a\nb'):
            self.assertNotIn('decision', self.stop(turn_id))
        for scoped in ({'agent_id': 'worker'}, {'agent_type': 'worker'},
                       {'stop_hook_active': True}, {'stop_hook_active': 0}):
            self.assertNotIn('decision', self.stop('legitimate-turn', **scoped))
        self.assertEqual(self.state('status')['remaining'], 2)
        self.assertEqual(self.stop('legitimate-turn')['decision'], 'block')

    def test_corrupt_explicit_budget_cannot_continue(self):
        self.state('active', 2)
        path = self.wal.with_name('continuation.json')
        valid = json.loads(path.read_text())
        claim = ['a' * 64, 'b' * 64]
        for corrupt in ({'limit': 5}, {'limit': True}, {'claims': [claim] * 2},
                        {'claims': [claim, ['c' * 64, 'd' * 64], ['e' * 64, 'f' * 64]]},
                        {'claims': [['a' * 64, 'private invalid digest']]}, {'claims': {'a': 1}},
                        {'repeat_open': True},
                        {'used': False}):
            path.write_text(json.dumps({**valid, **corrupt}))
            stopped = self.stop('new-turn')
            self.assertNotIn('decision', stopped)
            self.assertIn('could not', stopped['systemMessage'])
            self.assertNotIn('private invalid digest', json.dumps(stopped))
        path.write_text(json.dumps(valid)[:-1] + ', "limit": 2}')
        self.assertIn('could not', self.stop('new-turn')['systemMessage'])

    def test_one_shot_spans_codex_generated_continuation_turn(self):
        self.assertEqual(self.event('Stop', turn_id='initial', stop_hook_active=False), {})
        self.state('active')
        first = self.event('Stop', turn_id='initial', stop_hook_active=False)
        self.assertEqual(first['decision'], 'block')
        self.event('UserPromptSubmit', prompt='a different turn')
        self.state('active')  # Idempotent, not a refill.
        second = self.event('Stop', turn_id='new-turn', stop_hook_active=False)
        self.assertNotIn('decision', second)
        self.assertIn('unfinished', second['systemMessage'])
        self.assertEqual(self.state('status')['state'], 'active')

    def test_interrupt_and_reopen(self):
        self.state('active')
        self.event('Interrupt', turn_id='initial')
        self.assertEqual(self.state('status')['state'], 'paused')
        self.assertEqual(self.event('Stop', turn_id='initial', stop_hook_active=False), {})
        self.state('active')
        self.assertEqual(self.event('Stop', turn_id='reopen', stop_hook_active=False)['decision'], 'block')
        self.state('complete')
        self.assertEqual(self.event('Stop', turn_id='reopen', stop_hook_active=False), {})

    def test_delayed_first_stop_cannot_claim_after_interrupt_and_resume(self):
        self.state('active', 2)
        self.event('Interrupt', turn_id='interrupted-turn')
        self.assertEqual(self.state('status')['state'], 'paused')
        self.assertEqual(self.state('active')['remaining'], 2)
        self.assertNotIn('decision', self.stop('interrupted-turn', last_assistant_message='late response'))
        self.assertEqual(self.state('status')['remaining'], 2)
        marker = self.wal.with_name('continuation.interrupt').read_text()
        self.assertRegex(marker, r'^[0-9a-f]{32}:[0-9a-f]{64}$')
        self.assertNotIn('interrupted-turn', marker)
        self.assertEqual(self.stop('fresh-turn', last_assistant_message='fresh response')['decision'], 'block')
        self.assertEqual(self.state('status')['remaining'], 1)

    def test_legacy_interrupt_marker_pauses_and_can_be_acknowledged(self):
        self.state('active', 2)
        path = self.wal.with_name('continuation.interrupt')
        path.write_bytes(b'a' * 32)
        path.chmod(0o600)
        self.assertEqual(self.state('status')['state'], 'paused')
        self.assertEqual(self.stop('pending-turn'), {})
        self.assertEqual(self.state('active')['remaining'], 2)
        self.assertEqual(self.stop('fresh-turn')['decision'], 'block')

    def test_interrupt_without_valid_turn_still_rotates_generation(self):
        self.state('active', 3)
        for turn_id in (None, '', {'id': 'malformed'}, 'x' * 257):
            self.event('Interrupt', turn_id=turn_id)
            self.assertEqual(self.state('status')['state'], 'paused')
            marker = self.wal.with_name('continuation.interrupt').read_text()
            self.assertRegex(marker, r'^[0-9a-f]{32}$')
            self.assertEqual(self.state('active')['remaining'], 3)

    def test_other_session_and_missing_protocol_fields_do_not_continue(self):
        self.state('active')
        self.assertEqual(self.invoke('hook', payload={
            'hook_event_name': 'Stop', 'session_id': 'other',
            'turn_id': 'different', 'stop_hook_active': False,
        }), {})
        self.assertNotIn('decision', self.event('Stop', turn_id='initial'))
        self.assertNotIn('decision', self.event('Stop', stop_hook_active=False))
        self.assertNotIn('decision', self.event('Stop', turn_id='initial', stop_hook_active=True))
        self.assertNotIn('decision', self.stop('initial', stop_hook_active=True, last_assistant_message='other hook'))
        self.assertEqual(self.event('Stop', turn_id='initial', stop_hook_active=False)['decision'], 'block')

    def test_two_concurrent_stop_events_can_only_claim_once(self):
        import concurrent.futures
        self.state('active')
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            calls = [pool.submit(self.event, 'Stop', turn_id=turn, stop_hook_active=False)
                     for turn in ('one', 'two')]
            results = [call.result() for call in calls]
        self.assertEqual(sum(item.get('decision') == 'block' for item in results), 1)

    def test_corrupt_symlinked_or_busy_state_cannot_instruct_codex(self):
        import fcntl
        self.state('active')
        checkpoint = self.wal.with_name('continuation.json')
        private = 'private fixture transcript'
        for invalid in (private, 'x' * 513):
            checkpoint.write_text(invalid)
            result = self.event('Stop', turn_id='one', stop_hook_active=False)
            self.assertNotIn('decision', result)
            self.assertNotIn(private, json.dumps(result))
            self.assertIn('could not', result['systemMessage'])
        checkpoint.unlink()
        target = self.home / 'unrelated'
        target.write_text(private)
        checkpoint.symlink_to(target)
        self.assertNotIn('decision', self.event('Stop', turn_id='one', stop_hook_active=False))
        self.assertEqual(target.read_text(), private)
        checkpoint.unlink()
        self.state('active')
        with self.wal.with_name('continuation.lock').open('r+') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            result = self.event('Stop', turn_id='one', stop_hook_active=False)
        self.assertNotIn('decision', result)
        self.assertFalse(self.state('status')['used'])

    def test_spent_budget_survives_every_transition_and_interrupt(self):
        self.state('active')
        self.assertEqual(self.event('Stop', turn_id='original', stop_hook_active=False)['decision'], 'block')
        for terminal in ('blocked', 'handoff', 'paused', 'complete', 'interrupt'):
            if terminal == 'interrupt':
                self.event('Interrupt', turn_id='original')
            else:
                self.state(terminal)
            self.assertTrue(self.state('status')['used'])
            self.state('active')
            self.assertNotIn('decision', self.event('Stop', turn_id='again', stop_hook_active=False))

    def test_interrupt_is_durable_even_if_checkpoint_lock_is_busy(self):
        import fcntl
        self.state('active')
        with self.wal.with_name('continuation.lock').open('r+') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            self.event('Interrupt', turn_id='interrupted')
            self.assertEqual(self.state('status')['state'], 'paused')
            self.assertEqual(self.event('Stop', turn_id='interrupted', stop_hook_active=False), {})
        self.assertEqual(self.state('status')['state'], 'paused')
        self.assertEqual(self.event('Stop', turn_id='later', stop_hook_active=False), {})
        self.state('active')
        self.assertEqual(self.event('Stop', turn_id='later', stop_hook_active=False)['decision'], 'block')


class AlertParityAndDegrade(unittest.TestCase):
    """goodqa#14613 M9: the Codex hook injects active ops-watch alerts and degrades instead of blocking on ENOSPC."""

    def setUp(self):
        self.home = tempfile.TemporaryDirectory(); self.addCleanup(self.home.cleanup)
        self.env = {**os.environ, 'HOME': self.home.name}
        self.hook = Path(__file__).resolve().parents[1] / 'codex' / 'hooks' / 'wal.py'

    def run_hook(self, payload):
        return subprocess.run([sys.executable, str(self.hook), 'hook'], input=json.dumps(payload), text=True,
                              capture_output=True, env=self.env, timeout=30)

    def test_active_alert_reaches_prompt_session_and_subagent_context(self):
        # Run an installed-style copy (hook + ops_watch.py beside it, as install_codex ships them) so the positive
        # path is proven without the checkout-relative candidate; the test then passes from an archive without .git.
        import shutil
        install_dir = Path(self.home.name) / '.codex' / 'agent-harness'; install_dir.mkdir(parents=True)
        shutil.copy(self.hook, install_dir / 'wal.py')
        shutil.copy(Path(__file__).resolve().parents[1] / 'harness' / 'hooks' / 'ops_watch.py', install_dir / 'ops_watch.py')
        self.hook = install_dir / 'wal.py'
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'harness' / 'hooks'))
        import ops_watch
        ops_watch.emit({'schema': 1, 'at': '2026-11-05T08:00:00+00:00', 'host': 'testhost', 'source': 'test-alert',
                        'event': 'raise', 'severity': 'high', 'key': 'disk:volume:/', 'message': 'ALERT-MARKER-41 disk 97 percent'},
                       home=Path(self.home.name))
        for payload in ({'hook_event_name': 'SessionStart', 'session_id': 'alerts', 'source': 'startup'},
                        {'hook_event_name': 'UserPromptSubmit', 'session_id': 'alerts', 'prompt': 'hi'},
                        {'hook_event_name': 'SubagentStart', 'session_id': 'alerts', 'agent_id': 'a1', 'agent_type': 'general-purpose'}):
            result = self.run_hook(payload)
            self.assertEqual(result.returncode, 0, result.stderr)
            context = json.loads(result.stdout)['hookSpecificOutput']['additionalContext']
            self.assertIn('ALERT-MARKER-41', context, payload['hook_event_name'])

    def test_checkout_loader_candidate_is_not_used_from_an_install_dir(self):
        # Installed under <home>/.codex/agent-harness the checkout-relative candidate would be <home>/harness/hooks;
        # it must only apply inside a git checkout, so an installed copy with no ops_watch beside it injects nothing.
        import shutil
        install_dir = Path(self.home.name) / '.codex' / 'agent-harness'; install_dir.mkdir(parents=True)
        shutil.copy(self.hook, install_dir / 'wal.py')
        decoy = Path(self.home.name) / 'harness' / 'hooks'; decoy.mkdir(parents=True)
        (decoy / 'ops_watch.py').write_text('def injection_text(home, max_chars=700):\n    return " DECOY-LOADED"\n')
        result = subprocess.run([sys.executable, str(install_dir / 'wal.py'), 'hook'],
                                input=json.dumps({'hook_event_name': 'UserPromptSubmit', 'session_id': 'ld', 'prompt': 'hi'}),
                                text=True, capture_output=True, env=self.env, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('DECOY-LOADED', json.loads(result.stdout)['hookSpecificOutput']['additionalContext'])

    def test_unwritable_wal_dir_degrades_to_a_note_instead_of_blocking(self):
        first = self.run_hook({'hook_event_name': 'UserPromptSubmit', 'session_id': 'ro', 'prompt': 'hi'})
        self.assertEqual(first.returncode, 0, first.stderr)
        session_dir = Path(self.home.name, '.agent-harness') / 'codex-wals' / 'ro'
        self.assertTrue(session_dir.is_dir(), sorted(str(p) for p in (Path(self.home.name) / '.agent-harness').rglob('*'))[:10])
        wal_file = session_dir / 'main.jsonl'
        os.chmod(wal_file, 0o400); self.addCleanup(lambda: os.chmod(wal_file, 0o600))
        result = self.run_hook({'hook_event_name': 'UserPromptSubmit', 'session_id': 'ro', 'prompt': 'again'})
        self.assertEqual(result.returncode, 0, result.stderr)
        context = json.loads(result.stdout)['hookSpecificOutput']['additionalContext']
        self.assertIn('WAL append failed', context); self.assertIn('EACCES', context)
        self.assertNotIn('"decision"', result.stdout)


class ContinuationOwner(unittest.TestCase):
    """C1 is gone: wal.py no longer works out a caller (no ancestry, no environment). A `complete` written into another
    session's checkpoint counts only as a claim and restarts its quiet window (test_takeover_identity)."""

    def test_no_caller_derivation_is_left_in_wal_py(self):
        text = HOOK.read_text()
        for gone in ('continuation_owner_refusal', '_takeover_caller', 'caller_of', 'CODEX_THREAD_ID'):
            self.assertNotIn(gone, text)
