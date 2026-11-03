"""Run the actual Codex command hook wire protocol in an isolated home."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


HOOK = Path(__file__).resolve().parents[1] / 'codex/hooks/wal.py'


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
            env=self.env, capture_output=True, text=True, timeout=4,
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
