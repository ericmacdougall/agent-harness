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

    def test_running_owners_count_whatever_their_disposition(self):
        # red-team C3: `ah owners` gives a disposition dict to resumed and reassigned owners that are still running
        rows = {'owners': [
            {'agent_id': 'p' * 32, 'type': 'task-owner', 'owner': True, 'state': 'live', 'disposition': {'kind': 'resumed', 'live': True}},
            {'agent_id': 'q' * 32, 'type': 'task-owner', 'owner': True, 'state': 'working', 'disposition': {'kind': 'reassigned', 'live': False}},
            {'agent_id': 'r' * 32, 'type': 'task-owner', 'owner': True, 'state': 'SILENT', 'disposition': {'kind': 'waiting', 'live': False}},
            {'agent_id': 's' * 32, 'type': 'task-owner', 'owner': True, 'state': 'SILENT', 'disposition': {'kind': 'closed', 'live': True}}]}
        with mock.patch.object(ah, 'owners', return_value=rows):
            self.assertEqual(gate.live_owner_ids(SID, self.policy), ['p' * 32, 'q' * 32, 'r' * 32])

    def test_disposed_silent_owners_free_their_slots_as_the_alerts_do(self):
        # GoodQA #15565: af265a5 (reassigned, successor not live) and a0680533 (live named wait) held slots while SILENT-HIGH.
        silent = lambda ch, disp, state='SILENT-HIGH': {'agent_id': ch * 32, 'type': 'task-owner', 'owner': True,  # noqa: E731
                                                       'state': state, 'disposition': disp}
        rows = {'owners': [silent('a', {'kind': 'reassigned', 'live': False}), silent('b', {'kind': 'waiting', 'live': True}),
                           silent('c', {'kind': 'superseded', 'live': True}), silent('d', {'kind': 'wontdo', 'live': True}),
                           silent('e', {'kind': 'waiting', 'live': False}), silent('f', {'kind': 'resumed', 'live': True}),
                           silent('g', None), silent('h', {'kind': 'reassigned', 'live': False}, state='live')]}
        rows['owners'][6]['decision_required'] = False
        with mock.patch.object(ah, 'owners', return_value=rows):
            self.assertEqual(gate.live_owner_ids(SID, self.policy), ['e' * 32, 'f' * 32, 'g' * 32, 'h' * 32])
        rows['owners'][0]['decision_required'] = True  # ah still wants a decision: the slot stays held
        with mock.patch.object(ah, 'owners', return_value=rows):
            self.assertIn('a' * 32, gate.live_owner_ids(SID, self.policy))

    def test_quiet_general_purpose_owner_counts_but_a_stale_or_unknown_idle_helper_does_not(self):
        rows = {'owners': [
            {'agent_id': 'p' * 32, 'type': 'general-purpose', 'owner': False, 'state': 'idle-helper', 'idle_s': 1500, 'disposition': None},
            {'agent_id': 'q' * 32, 'type': 'general-purpose', 'owner': False, 'state': 'idle-helper', 'idle_s': 2 * 3600, 'disposition': None},
            {'agent_id': 'r' * 32, 'type': 'red-team', 'owner': False, 'state': 'idle-helper', 'idle_s': 100, 'disposition': None},
            {'agent_id': 's' * 32, 'type': 'general-purpose', 'owner': False, 'state': 'idle-helper', 'disposition': None}]}
        with mock.patch.object(ah, 'owners', return_value=rows):
            self.assertEqual(gate.live_owner_ids(SID, self.policy), ['p' * 32])

    def test_deadline_is_not_swallowed_by_a_broad_except(self):
        self.assertTrue(issubclass(gate._Deadline, BaseException) and not issubclass(gate._Deadline, Exception))

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
