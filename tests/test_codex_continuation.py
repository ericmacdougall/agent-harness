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
