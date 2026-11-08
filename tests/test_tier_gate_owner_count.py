"""goodqa#15320 (defect 7): the owner cap counted every idle-helper (hundreds of long-dead agents), and the scan that did it
was slow enough to time the PreToolUse hook out, which blocks every spawn (fail closed). The count must match `ah owners`
(dead, returned, idle and disposed agents free their slot), and the scan has a deadline. Synthetic home; no real WALs."""

import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest import mock

HOOKS = Path(__file__).resolve().parents[1] / 'harness/hooks'
sys.path.insert(0, str(HOOKS))
import ah  # noqa: E402
import model_tiers as tiers  # noqa: E402
import tier_gate as gate  # noqa: E402

SID = '22222222-3333-4444-5555-666666666666'
N_DEAD = 600


def iso(offset_s):
    return time.strftime('%Y-%m-%dT%H:%M:%S+00:00', time.gmtime(time.time() - offset_s))


class OwnerCount(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        self.home = Path(tmp.name)
        wal = self.home / '.claude/wals' / SID
        wal.mkdir(parents=True)
        (self.home / '.claude/projects/-p' / SID / 'subagents').mkdir(parents=True)
        old = time.time() - 80 * 3600
        lines = []
        for i in range(N_DEAD):
            agent = 'a%031x' % i
            lines.append({'at': iso(80 * 3600), 'event': 'subagent', 'agent_id': agent, 'agent_type': 'general-purpose'})
            path = wal / ('agent-%s.jsonl' % agent)
            path.write_text(json.dumps({'at': iso(80 * 3600), 'event': 'intent', 'note': 'old helper'}) + '\n')
            os.utime(path, (old, old))
        for agent in ('b' * 32, 'c' * 32):
            lines.append({'at': iso(30), 'event': 'subagent', 'agent_id': agent, 'agent_type': 'task-owner'})
            (wal / ('agent-%s.jsonl' % agent)).write_text(json.dumps({'at': iso(20), 'event': 'intent', 'note': 'working'}) + '\n')
        (wal / 'main.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in lines))
        p = mock.patch.dict(os.environ, {'AH_HOME': str(self.home), 'HOME': str(self.home)}); p.start(); self.addCleanup(p.stop)
        self.policy = tiers.load_policy()

    def test_only_live_owners_count_and_the_scan_is_fast(self):
        started = time.monotonic()
        ids = gate.live_owner_ids(SID, self.policy)
        elapsed = time.monotonic() - started
        self.assertEqual(ids, ['b' * 32, 'c' * 32], 'dead idle helpers counted: %d ids' % len(ids))
        self.assertLess(elapsed, 3.0, 'owner scan took %.1fs for %d agents (hook timeout is 10s)' % (elapsed, N_DEAD + 2))

    def test_a_disposed_silent_owner_frees_its_slot(self):
        rows = {'owners': [{'agent_id': 'x' * 32, 'type': 'task-owner', 'owner': True, 'state': 'SILENT-HIGH', 'disposition': None},
                           {'agent_id': 'y' * 32, 'type': 'task-owner', 'owner': True, 'state': 'SILENT-HIGH',
                            'disposition': {'kind': 'closed', 'live': True}},
                           {'agent_id': 'z' * 32, 'type': 'task-owner', 'owner': True, 'state': 'idle-helper', 'disposition': None}]}
        with mock.patch.object(ah, 'owners', return_value=rows):
            self.assertEqual(gate.live_owner_ids(SID, self.policy), ['x' * 32])

    def test_scan_past_its_deadline_falls_back_instead_of_hanging(self):
        def slow(*_a, **_k):
            time.sleep(5)
        started = time.monotonic()
        with mock.patch.object(ah, 'owners', slow), mock.patch.object(gate, 'OWNER_COUNT_DEADLINE_S', 0.3):
            ids = gate.live_owner_ids(SID, self.policy)
        self.assertLess(time.monotonic() - started, 2.0)
        self.assertEqual(ids, [])  # no SubagentStart live map in this fixture


if __name__ == '__main__':
    unittest.main()
