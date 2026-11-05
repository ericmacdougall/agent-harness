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

    def invoke(self, *args, payload=None):
        result = subprocess.run(
            [sys.executable, str(HOOK), *args],
            input=json.dumps(payload) if payload is not None else '',
            env=self.env, capture_output=True, text=True, timeout=HOOK_WATCHDOG_SECONDS,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def event(self, name, **fields):
        return self.invoke('hook', payload={
            'hook_event_name': name, 'session_id': 'session', **fields,
        })

    def state(self, status):
        return self.invoke('continuation', '--wal', str(self.wal), status)

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

    def test_other_session_and_missing_protocol_fields_do_not_continue(self):
        self.state('active')
        self.assertEqual(self.invoke('hook', payload={
            'hook_event_name': 'Stop', 'session_id': 'other',
            'turn_id': 'different', 'stop_hook_active': False,
        }), {})
        self.assertNotIn('decision', self.event('Stop', turn_id='initial'))
        self.assertNotIn('decision', self.event('Stop', stop_hook_active=False))
        self.assertNotIn('decision', self.event('Stop', turn_id='initial', stop_hook_active=True))
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
