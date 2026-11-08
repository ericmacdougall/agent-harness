"""goodqa#15322 (defect 8): critical/high liveness alerts stayed up for owners that main had already disposed (reassigned,
closed, superseded, wontdo, legacy). A disposed owner raises no liveness alert; an undisposed one, an expired wait and a
disposition that is only a time-boxed resume still do. Rows are shapes of real `ah owners` output."""

import os
from pathlib import Path
import sys
import time
import unittest
from unittest import mock

HOOKS = Path(__file__).resolve().parents[1] / 'harness/hooks'
sys.path.insert(0, str(HOOKS))
import ahd  # noqa: E402
import ah  # noqa: E402
import ops_watch as ow  # noqa: E402

SESSION = 'baab765b-d85c-46b4-b7b9-588eb912c770'


def row(agent, kind=None, live=False, state='SILENT-HIGH', decision=False):
    disp = {'kind': kind, 'at': 1.0, 'ref': 'a4ea0e3098d9568e1', 'live': live} if kind else None
    return {'agent_id': agent, 'type': 'general-purpose', 'owner': True, 'state': state, 'severity': 'high',
            'idle_s': 200000, 'last_activity': '2026-11-06T01:14:38Z', 'disposition': disp, 'decision_required': decision,
            'ticket': None, 'task': 't'}


ROWS = [row('a1000001', 'reassigned'), row('a2000002', 'closed'), row('a3000003', 'superseded'), row('a4000004', 'wontdo'),
        row('a5000005', 'legacy'), row('a6000006', None), row('a7000007', 'waiting'), row('a8000008', 'resumed'),
        row('a9000009', 'reassigned', state='DROPPED', decision=True)]
STILL = ['a6000006', 'a7000007', 'a8000008', 'a9000009']


class NoTickets:
    def quiet_h(self, ref):
        return 0


class DisposedOwners(unittest.TestCase):
    def test_ahd_clears_disposed_owners(self):
        got = ahd.liveness_alerts({SESSION: {'owners': ROWS}}, ahd.load_policy())
        self.assertEqual(sorted(f['detail']['agent'] for f in got.values()), STILL)

    def test_ops_watch_clears_disposed_owners(self):
        with mock.patch.object(ah, 'owners', return_value={'owners': ROWS}):
            got = ow._owner_alerts(Path('/nonexistent'), SESSION, NoTickets(), time.time())
        self.assertEqual(sorted(a['detail']['agent'] for a in got), STILL)


if __name__ == '__main__':
    unittest.main()
