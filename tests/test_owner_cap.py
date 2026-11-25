"""The one owner cap (resource_limits.json max_live_owners, read by resource_budget.owner_cap; the spawn-time check is
agent_gate.py). tier_gate.live_owner_ids still counts live owners for successor and Mission Control: helpers never
count, an unknown label is an owner. tier_gate itself no longer denies or warns on the owner count."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HOOKS = Path(__file__).resolve().parents[1] / 'harness/hooks'
sys.path.insert(0, str(HOOKS))
import model_tiers as tiers  # noqa: E402
import tier_gate as gate  # noqa: E402


class OwnerCap(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='owner-cap-'); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'state'; self.root.mkdir(mode=0o700)
        self.home = Path(self.temp.name) / 'home'; self.home.mkdir()  # no main WAL: the live map decides
        self.policy = tiers.load_policy()
        self.env = mock.patch.dict(os.environ, {'AGENT_HARNESS_ESCALATION_DIR': str(self.root), 'AH_HOME': str(self.home)})
        self.env.start(); self.addCleanup(self.env.stop)

    def test_shipped_cap_is_one_number_and_the_policy_carries_it(self):
        import resource_budget  # noqa: PLC0415
        with mock.patch.dict(os.environ, {'AH_HOME': str(self.home)}):
            self.assertEqual(resource_budget.owner_cap(), {'max': 16, 'enforce': False})
            caps = tiers.load_policy()['caps']
        self.assertEqual(caps['session_owner_agents'], 16)  # copied from the one cap for older readers
        self.assertNotIn('session_live_agents', caps)  # retired: helpers are never counted
        self.assertIn('task-owner', caps['owner_types']); self.assertNotIn('red-team', caps['owner_types'])
        raw = json.loads((HOOKS / 'model_tiers.json').read_text())['caps']
        self.assertNotIn('session_owner_agents', raw); self.assertNotIn('session_live_agents', raw)

    def test_live_owner_ids_count_owners_only_and_unknown_labels_are_owners(self):
        for n in range(8):
            gate.live_update('s7', 'owner-%d' % n, start=True, agent_type='task-owner')
        gate.live_update('s7', 'reviewer-1', start=True, agent_type='red-team')  # a helper never counts as an owner
        gate.live_update('s7', 'invented-1', start=True, agent_type='owner-lite')  # an unknown label is an owner
        self.assertEqual(gate.live_owner_ids('s7', self.policy), ['invented-1'] + ['owner-%d' % n for n in range(8)])
        self.assertFalse(hasattr(gate, 'owner_cap_decision'))  # one cap: no second owner cap in tier_gate
        gate.live_update('s7', 'owner-2', start=False)
        self.assertNotIn('owner-2', gate.live_owner_ids('s7', self.policy))

    def test_owner_count_prefers_wal_liveness_over_the_expiring_live_map(self):
        # Kimi round 1 (HIGH): the live map forgets an owner after 30 minutes without a start/stop; ah owners does not.
        rows = [{'agent_id': 'longrunner%d' % n, 'owner': True, 'state': 'live'} for n in range(8)]
        rows.append({'agent_id': 'helper1', 'type': 'red-team', 'owner': False, 'state': 'live'})
        rows.append({'agent_id': 'finished1', 'owner': True, 'state': 'done'})
        with mock.patch('ah.owners', return_value={'owners': rows}):
            self.assertEqual(gate.live_owner_ids('s8', self.policy), ['longrunner%d' % n for n in range(8)])

    def test_unmocked_owner_count_includes_general_purpose_and_quiet_owners(self):
        # Review F3: ah owners flags only task-owner agents, so six live general-purpose owners counted zero. This test
        # writes real session WALs and lets ah.owners classify them (no mock).
        import json as _json
        import time as _time
        now = _time.time()
        iso = lambda ts: _time.strftime('%Y-%m-%dT%H:%M:%S+00:00', _time.gmtime(ts))
        wals = self.home / '.claude' / 'wals' / 's10'; wals.mkdir(parents=True)
        main = [{'at': iso(now - 3000), 'event': 'subagent', 'agent_id': 'gp%d' % n, 'agent_type': 'general-purpose'} for n in range(10)]
        main.append({'at': iso(now - 3000), 'event': 'subagent', 'agent_id': 'rt1', 'agent_type': 'red-team'})
        main.append({'at': iso(now - 3000), 'event': 'subagent', 'agent_id': 'done1', 'agent_type': 'general-purpose'})
        main.append({'at': iso(now - 100), 'event': 'subagent_stop', 'agent_id': 'done1', 'agent_type': 'general-purpose'})
        (wals / 'main.jsonl').write_text(''.join(_json.dumps(r) + '\n' for r in main))
        for n in range(10):  # gp5 has been quiet for 9 minutes: still running, still an owner
            age = 540 if n == 5 else 60  # 9 min quiet: still inside the idle window on main and after #157
            (wals / ('agent-gp%d.jsonl' % n)).write_text(_json.dumps({'at': iso(now - age), 'event': 'intent', 'note': 'work'}) + '\n')
        (wals / 'agent-rt1.jsonl').write_text(_json.dumps({'at': iso(now - 60), 'event': 'intent', 'note': 'review'}) + '\n')
        (wals / 'agent-done1.jsonl').write_text(_json.dumps({'at': iso(now - 200), 'event': 'result', 'note': 'finished'}) + '\n')
        owners = gate.live_owner_ids('s10', self.policy)
        self.assertEqual(owners, ['gp%d' % n for n in range(10)])

    def test_tier_gate_never_denies_or_warns_on_the_owner_count(self):
        for n in range(20):
            gate.live_update('s9', 'owner-%d' % n, start=True, agent_type='general-purpose')

        def run_hook(data, mode):
            policy = dict(self.policy); policy['mode'] = mode
            path = Path(self.temp.name) / 'tiers.json'; path.write_text(json.dumps(policy))
            env = {**os.environ, 'AGENT_HARNESS_TIER_POLICY': str(path)}
            result = subprocess.run([sys.executable, str(HOOKS / 'tier_gate.py'), 'hook'], input=json.dumps(data),
                                    capture_output=True, text=True, timeout=20, env=env)
            self.assertEqual(result.returncode, 0, result.stderr[-300:])
            return json.loads(result.stdout)['hookSpecificOutput'] if result.stdout.strip() else None

        spawn = {'tool_name': 'Agent', 'tool_input': {'prompt': 'x [task:k20]', 'subagent_type': 'task-owner', 'model': 'sonnet'}, 'session_id': 's9'}
        self.assertIsNone(run_hook(spawn, 'enforce'))  # 20 live owners: the advisory is agent_gate's, not this hook's
        self.assertIsNone(run_hook(spawn, 'warn'))
        helper = dict(spawn, tool_input={**spawn['tool_input'], 'subagent_type': 'fixer'})
        self.assertIsNone(run_hook(helper, 'warn'))


if __name__ == '__main__':
    unittest.main()
