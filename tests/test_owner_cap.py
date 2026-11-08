"""Scenario B3.17: the owner cap (memory: at most 4 active owners) is enforced by the spawn hook, helpers are exempt,
and warn mode no longer narrates allowed spawns (B24: enforce it or say nothing)."""

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

    def test_shipped_caps_match_the_user_rule(self):
        caps = self.policy['caps']
        self.assertEqual(caps['session_owner_agents'], 4)
        self.assertLessEqual(caps['session_live_agents'], 12)
        self.assertIn('task-owner', caps['owner_types']); self.assertNotIn('red-team', caps['owner_types'])

    def test_fifth_owner_is_denied_with_the_live_ids_and_helpers_still_pass(self):
        for n in range(4):
            gate.live_update('s7', 'owner-%d' % n, start=True, agent_type='task-owner')
        gate.live_update('s7', 'reviewer-1', start=True, agent_type='red-team')  # a helper never counts as an owner
        self.assertEqual(gate.live_owner_ids('s7', self.policy), ['owner-0', 'owner-1', 'owner-2', 'owner-3'])
        reason, owners = gate.owner_cap_decision('s7', {'subagent_type': 'task-owner'}, self.policy)
        self.assertIn('owner cap 4 reached', reason); self.assertIn('owner-0', reason); self.assertIn('ah.py owners', reason)
        for helper in ('red-team', 'click-tester', 'fixer', 'Explore', 'Plan'):
            self.assertEqual(gate.owner_cap_decision('s7', {'subagent_type': helper}, self.policy)[0], None, helper)
        for invented in ('helper', 'assistant', 'owner-lite'):  # round 2: an unknown label is an owner, not an exemption
            self.assertIn('owner cap 4 reached', gate.owner_cap_decision('s7', {'subagent_type': invented}, self.policy)[0] or '', invented)
        gate.live_update('s7', 'owner-2', start=False)
        self.assertIsNone(gate.owner_cap_decision('s7', {'subagent_type': 'general-purpose'}, self.policy)[0])

    def test_owner_count_prefers_wal_liveness_over_the_expiring_live_map(self):
        # Kimi round 1 (HIGH): the live map forgets an owner after 30 minutes without a start/stop; ah owners does not.
        rows = [{'agent_id': 'longrunner%d' % n, 'owner': True, 'state': 'live'} for n in range(4)]
        rows.append({'agent_id': 'helper1', 'type': 'red-team', 'owner': False, 'state': 'live'})
        rows.append({'agent_id': 'finished1', 'owner': True, 'state': 'done'})
        with mock.patch('ah.owners', return_value={'owners': rows}):
            self.assertEqual(gate.live_owner_ids('s8', self.policy), ['longrunner0', 'longrunner1', 'longrunner2', 'longrunner3'])
            self.assertIsNotNone(gate.owner_cap_decision('s8', {'subagent_type': 'task-owner'}, self.policy)[0])

    def test_unmocked_owner_count_includes_general_purpose_and_quiet_owners(self):
        # Review F3: ah owners flags only task-owner agents, so six live general-purpose owners counted zero. This test
        # writes real session WALs and lets ah.owners classify them (no mock).
        import json as _json
        import time as _time
        now = _time.time()
        iso = lambda ts: _time.strftime('%Y-%m-%dT%H:%M:%S+00:00', _time.gmtime(ts))
        wals = self.home / '.claude' / 'wals' / 's10'; wals.mkdir(parents=True)
        main = [{'at': iso(now - 3000), 'event': 'subagent', 'agent_id': 'gp%d' % n, 'agent_type': 'general-purpose'} for n in range(6)]
        main.append({'at': iso(now - 3000), 'event': 'subagent', 'agent_id': 'rt1', 'agent_type': 'red-team'})
        main.append({'at': iso(now - 3000), 'event': 'subagent', 'agent_id': 'done1', 'agent_type': 'general-purpose'})
        main.append({'at': iso(now - 100), 'event': 'subagent_stop', 'agent_id': 'done1', 'agent_type': 'general-purpose'})
        (wals / 'main.jsonl').write_text(''.join(_json.dumps(r) + '\n' for r in main))
        for n in range(6):  # gp5 has been quiet for 25 minutes: still running, still an owner
            age = 1500 if n == 5 else 60
            (wals / ('agent-gp%d.jsonl' % n)).write_text(_json.dumps({'at': iso(now - age), 'event': 'intent', 'note': 'work'}) + '\n')
        (wals / 'agent-rt1.jsonl').write_text(_json.dumps({'at': iso(now - 60), 'event': 'intent', 'note': 'review'}) + '\n')
        (wals / 'agent-done1.jsonl').write_text(_json.dumps({'at': iso(now - 200), 'event': 'result', 'note': 'finished'}) + '\n')
        owners = gate.live_owner_ids('s10', self.policy)
        self.assertEqual(owners, ['gp0', 'gp1', 'gp2', 'gp3', 'gp4', 'gp5'])
        reason, _ = gate.owner_cap_decision('s10', {'subagent_type': 'general-purpose'}, self.policy)
        self.assertIn('owner cap 4 reached', reason or '')
        self.assertIsNone(gate.owner_cap_decision('s10', {'subagent_type': 'red-team'}, self.policy)[0])

    def test_hook_denies_in_enforce_and_warn_mode_is_silent_on_allowed_spawns(self):
        for n in range(4):
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
        self.assertEqual(run_hook(spawn, 'enforce')['permissionDecision'], 'deny')
        self.assertIn('would deny: owner cap', run_hook(spawn, 'warn')['additionalContext'])
        helper = dict(spawn, tool_input={**spawn['tool_input'], 'subagent_type': 'fixer'})  # a helper at the matching rung
        self.assertIsNone(run_hook(helper, 'warn'))  # allowed: warn mode says nothing (no "would apply updatedInput")
        allowed = run_hook(helper, 'enforce')
        self.assertTrue(allowed is None or allowed.get('permissionDecision') == 'allow')


if __name__ == '__main__':
    unittest.main()
