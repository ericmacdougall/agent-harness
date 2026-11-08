"""Scenario B3.9: provenance refusals that each cost a retry on 2026-11-06/07.

- `ah user-msg` prints `uuid:` ids while sources had to say `user:`.
- a `wal:` pointer at a grandfathered entry was refused outright instead of counting as an assumption.
- self-scheduled wakeup prompts were extracted as human turns by the audit."""

import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

HOOKS = Path(__file__).resolve().parents[1] / 'harness/hooks'
sys.path.insert(0, str(HOOKS))
import provenance  # noqa: E402

SESSION = '11111111-2222-4333-8444-555555555555'
UID = '00000000-0000-4000-8000-000000000001'


class Ergonomics(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='prov-'); self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        t = self.home / '.claude' / 'projects' / '-proj' / (SESSION + '.jsonl')
        t.parent.mkdir(parents=True)
        rows = [
            {'type': 'user', 'uuid': UID, 'timestamp': '2026-11-08T04:42:00.000Z', 'origin': {'kind': 'human'},
             'message': {'role': 'user', 'content': 'pass it all and the transcripts to fable'}},
            {'type': 'user', 'uuid': '00000000-0000-4000-8000-0000000000e2', 'timestamp': '2026-11-08T04:44:00.000Z', 'isMeta': True,
             'promptSource': 'system', 'wakeupSource': 'schedule_wakeup', 'origin': {'kind': 'human'},
             'message': {'role': 'user', 'content': 'Prod move T-60 checkpoint: resume the owner'}},
            {'type': 'user', 'uuid': '00000000-0000-4000-8000-0000000000e3', 'timestamp': '2026-11-08T04:45:00.000Z',
             'promptSource': 'system', 'scheduledTaskId': 'sched-1', 'origin': {'kind': 'human'},
             'message': {'role': 'user', 'content': 'T0 checkpoint: run the gate check'}},
        ]
        t.write_text(''.join(json.dumps(r) + '\n' for r in rows))
        self.env = mock.patch.dict(os.environ, {'HOME': str(self.home)})
        self.env.start(); self.addCleanup(self.env.stop)
        self.wals = self.home / '.claude' / 'wals' / SESSION; self.wals.mkdir(parents=True)

    def test_uuid_prefix_is_the_same_source_as_user(self):
        a = provenance.parse_source('uuid:%s/%s "pass it all"' % (SESSION, UID))
        b = provenance.parse_source('user:%s/%s "pass it all"' % (SESSION, UID))
        self.assertEqual(a, b); self.assertEqual(a['kind'], 'user')
        res = provenance.resolve('uuid:%s/%s "pass it all and the transcripts"' % (SESSION, UID), {'home': self.home / '.claude'})
        self.assertTrue(res['ok'], res)

    def test_wakeup_and_scheduled_prompts_are_never_human_turns(self):
        for uid in ('00000000-0000-4000-8000-0000000000e2', '00000000-0000-4000-8000-0000000000e3'):
            with self.assertRaises(provenance.Problem) as caught:
                provenance.user_turn(SESSION, uid, self.home / '.claude')
            self.assertEqual(caught.exception.code, 'not-user-authored')
        self.assertIn('wakeup', caught.exception.message)  # the non-meta scheduled prompt is caught by the new rule
        self.assertEqual([m['uuid'] for m in provenance.find_user(SESSION, 'T-60 checkpoint: resume', self.home / '.claude')], [])

    def test_wal_pointer_to_an_unsourced_entry_is_an_assumption_not_a_refusal(self):
        wal = self.wals / 'main.jsonl'
        wal.write_text(json.dumps({'id': 'w0000000aaaa', 'event': 'decision', 'note': 'legacy decision, pre-provenance', 'at': 't'}) + '\n')
        res = provenance.resolve('wal:%s#w0000000aaaa' % wal, {'home': self.home / '.claude'})
        self.assertTrue(res['ok']); self.assertTrue(res['assumption']); self.assertTrue(res['weak'])
        self.assertFalse(res['backed'])
        self.assertEqual([p['code'] for p in res['problems']], ['wal-unsourced'])
        self.assertEqual(res['chain'][0]['status'], 'legacy-unsourced')
        # A sourced entry still resolves through to its user origin and is not an assumption.
        wal.write_text(json.dumps({'id': 'w0000000bbbb', 'event': 'scope', 'note': 'x', 'at': 't',
                                   'source': 'user:%s/%s "pass it all and the transcripts"' % (SESSION, UID)}) + '\n')
        res = provenance.resolve('wal:%s#w0000000bbbb' % wal, {'home': self.home / '.claude'})
        self.assertTrue(res['ok']); self.assertFalse(res['assumption']); self.assertEqual(res['origin'], 'user')


if __name__ == '__main__':
    unittest.main()
