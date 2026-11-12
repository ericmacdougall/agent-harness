"""Dispatch records (GoodQA goodqa#15794, pi-dev-port H17): what a spawn actually ran on, and failures from
below-rung writing runs no longer climbing the model ladder. Spec: h17-spec-r6 (core e8b4b287)."""

import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
HOOKS = ROOT / 'harness/hooks'
sys.path.insert(0, str(HOOKS))
import escalation as esc  # noqa: E402
import model_tiers as tiers  # noqa: E402
import tier_gate as gate  # noqa: E402

SONNET, OPUS, MYSTERY = 'claude-sonnet-4-5', 'claude-opus-5-5', 'gpt-9-mystery'


def final(salt, *, verdict='BLOCK', findings=('F1',)):
    """A usage-guard FINAL review receipt with a new HEAD per salt, so each one is a genuine failure."""
    head = hashlib.sha256(str(salt).encode()).hexdigest()[:40]
    return json.dumps({'schema': 1, 'kind': 'final', 'run_id': 'b' * 32, 'evidence': 'EXECUTED', 'subject': {'head': head},
                       'invocation': {}, 'execution': 'COMPLETED', 'result': 'NO_RESULT', 'reason': 'CODE_FINDINGS',
                       'usage': {'provider_launches': 1, 'reported': []},
                       'review': {'stage': 'CODE_INSPECTION', 'verdict': verdict, 'findings': list(findings)},
                       'salt': str(salt)}).encode()


class Fixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='dispatch-'); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'state'; self.root.mkdir(mode=0o700)
        self.policy = tiers.load_policy()
        self.policy.setdefault('caps', {})['dispatch_exclude_below_rung'] = True  # PR 225 F1: off by default
        self.ledger = esc.Ledger(self.root, self.policy)
        env = mock.patch.dict(os.environ, {'AGENT_HARNESS_ESCALATION_DIR': str(self.root)})
        env.start(); self.addCleanup(env.stop)
        self.salt = 0

    # -- ledger helpers (in process)
    def fail_once(self, task):
        self.salt += 1
        return self.ledger.record(task, final('%s-%d' % (task, self.salt)), kind='review', source='test')

    def climb_to(self, task, rung):
        while self.ledger.status(task)['rung'] != rung:
            self.fail_once(task)
            self.assertLess(self.salt, 60, 'ladder did not reach ' + rung)

    def owner(self, task, tool_use_id, model, *, subagent_type='task-owner', status='async_launched', agent_id=None,
              models_used=None, close=True, kind='agent', requested_rung=None):
        self.ledger.open_dispatch(task, {'tool_use_id': tool_use_id, 'subagent_type': subagent_type, 'kind': kind,
                                         'owner': kind == 'agent' and gate.counts_as_owner(subagent_type, self.policy),
                                         'reviewer': subagent_type in gate.REVIEWER_TYPES,
                                         'requested': {'model': 'sonnet', 'effort': None, 'rung': requested_rung},
                                         'selected': {'model': 'sonnet', 'effort': None, 'rung': requested_rung}})
        if close:
            agent = agent_id or ('ag' + tool_use_id)
            self.ledger.close_dispatch(task, tool_use_id, status=status, agent_id=agent, resolved_model=model,
                                       models_used=models_used or [])
            esc.index_agent(self.root, agent, task)

    def match(self, d, rung='R2'):
        return esc.match_of(d.get('candidates'), rung, self.policy)

    # -- hook helpers (subprocess, the installed entry points)
    def policy_file(self, mode, **caps):
        policy = json.loads(json.dumps(self.policy)); policy['mode'] = mode
        policy.setdefault('caps', {}).update(caps)
        path = Path(self.temp.name) / ('tiers-%s-%d.json' % (mode, len(caps)))
        path.write_text(json.dumps(policy))
        return path

    def hook(self, action, data, mode='warn', raw=None, **caps):
        env = {**os.environ, 'AGENT_HARNESS_TIER_POLICY': str(self.policy_file(mode, **caps)),
               'AGENT_HARNESS_ESCALATION_DIR': str(self.root)}
        stdin = raw if raw is not None else json.dumps(data)
        result = subprocess.run([sys.executable, str(HOOKS / 'tier_gate.py'), action], input=stdin,
                                capture_output=True, text=True, timeout=30, env=env)
        self.assertEqual(result.returncode, 0, result.stderr[-400:])
        return result

    def pre(self, prompt, *, model='sonnet', subagent_type='task-owner', tool_use_id='tu1', mode='warn', tool='Agent',
            effort=None):
        tool_input = {'prompt': prompt, 'description': 'probe', 'subagent_type': subagent_type}
        if model is not None:
            tool_input['model'] = model
        if effort is not None:
            tool_input['effort'] = effort
        return self.hook('hook', {'tool_name': tool, 'tool_input': tool_input, 'session_id': 'sdisp',
                                  'tool_use_id': tool_use_id, 'hook_event_name': 'PreToolUse'}, mode=mode)

    def post(self, prompt, *, tool_use_id='tu1', status='async_launched', agent_id='a1b2c3', resolved=SONNET,
             models_used=None, extra=None, subagent_type='task-owner', model='sonnet'):
        response = {'status': status, 'agentId': agent_id, 'resolvedModel': resolved}
        if models_used is not None:
            response['modelsUsed'] = models_used
        response.update(extra or {})
        tool_input = {'prompt': prompt, 'description': 'probe', 'subagent_type': subagent_type, 'model': model}
        return self.hook('dispatch', {'tool_name': 'Agent', 'tool_input': tool_input, 'tool_response': response,
                                      'session_id': 'sdisp', 'tool_use_id': tool_use_id,
                                      'hook_event_name': 'PostToolUse'})

    def stop(self, agent_id, effort=None, **caps):
        data = {'agent_id': agent_id, 'agent_type': 'task-owner', 'session_id': 'sdisp', 'hook_event_name': 'SubagentStop'}
        if effort is not None:
            data['effort'] = {'level': effort}
        return self.hook('stop', data, **caps)

    def dispatches(self, task):
        return self.ledger.load(task).get('dispatches', [])

    def gate_lines(self):
        path = self.root / 'gate.jsonl'
        return [json.loads(l) for l in path.read_text().splitlines()] if path.exists() else []

    def positive(self, task):
        """The AC-3 positive setup: R2 reached with no earlier dispatch, then one closed Sonnet owner in the window."""
        self.climb_to(task, 'R2')
        self.owner(task, 'pos-' + task, SONNET)


class OpenAndClose(Fixture):
    def test_open_then_close_async(self):
        self.climb_to('k1', 'R2')
        self.pre('work [task:k1] [rung-below:probe]')
        [opened] = self.dispatches('k1')  # after PreToolUse alone
        self.assertEqual((opened['phase'], opened['tool_use_id'], opened['owner']), ('open', 'tu1', True))
        self.assertEqual((opened['requested']['rung'], opened['selected']['rung']), ('R0', 'R0'))
        result = self.post('work [task:k1] [rung-below:probe]')
        self.assertEqual(result.stdout.strip(), '')
        [d] = self.dispatches('k1')
        self.assertEqual((d['phase'], d['agent_id'], d['resolved_model']), ('closed', 'a1b2c3', SONNET))
        self.assertEqual((d['candidates'], self.match(d)), (['R0'], 'below'))
        self.assertNotIn('ended_at', d)  # a background agent is still running after its launch returns
        self.assertTrue(any(l.get('decision') == 'dispatch' and l.get('result') == 'closed' for l in self.gate_lines()))

    def test_completed_union_models_used_no_content(self):
        self.climb_to('k2', 'R2')
        self.pre('work [task:k2]', model='opus', effort='high')
        many = [SONNET, OPUS] + ['claude-sonnet-4-%d' % i for i in range(20)]
        self.post('work [task:k2]', status='completed', resolved=SONNET, models_used=many, model='opus',
                  extra={'content': [{'type': 'text', 'text': 'SECRET_RESULT_TEXT'}], 'usage': {'input_tokens': 7},
                         'totalTokens': 9})
        [d] = self.dispatches('k2')
        self.assertEqual(d['candidates'], ['R0', 'R1', 'R2', 'R3', 'R4'])
        self.assertEqual(self.match(d), 'match')
        self.assertLessEqual(len(d['models_used']), 8)
        self.assertIn('ended_at', d)  # a completed foreground run has ended
        text = (self.root / 'k2.json').read_text()
        self.assertNotIn('SECRET_RESULT_TEXT', text)
        self.assertNotIn('input_tokens', text)


class Counting(Fixture):
    def test_below_rung_fail_not_counted(self):
        self.positive('k3')
        for _ in range(3):
            status = self.fail_once('k3')
            self.assertEqual(status['event']['class'], 'NOT_COUNTED')
            self.assertTrue(status['event']['why'].startswith('dispatched below rung'), status['event']['why'])
        self.assertEqual(self.ledger.status('k3')['rung'], 'R2')

    def test_control_climbs_to_r3(self):
        self.climb_to('k4', 'R2')
        for _ in range(2):
            self.assertEqual(self.fail_once('k4')['event']['class'], 'FAIL')
        self.assertEqual(self.ledger.status('k4')['rung'], 'R3')

    def test_window_cases_keep_counting(self):
        """Each case is the AC-3 positive setup plus exactly one change; the unchanged setup is excluded (anchor)."""
        self.positive('kw-anchor')
        self.assertEqual(self.fail_once('kw-anchor')['event']['class'], 'NOT_COUNTED')
        cases = {
            'a': None,  # an opus owner launched before the window and still live
            'b': lambda t: self.owner(t, 'open-' + t, SONNET, close=False),
            'c': None,  # only helpers and reviewers instead of the Sonnet owner
            'd': lambda t: self.owner(t, 'unk-' + t, MYSTERY),
            'e': None,  # the owner's model is opus instead of Sonnet
            'f': lambda t: self.owner(t, 'fix-' + t, OPUS, subagent_type='fixer'),  # M1: an at-rung fixer
        }
        for name, change in cases.items():
            with self.subTest(case=name):
                task = 'kw' + name
                if name == 'a':
                    self.owner(task, 'early-opus', OPUS)
                    self.positive(task)
                elif name == 'c':
                    self.climb_to(task, 'R2')
                    for i, kind in enumerate(('Explore', 'Plan', 'fixer', 'red-team', 'click-tester')):
                        self.owner(task, 'h%d' % i, SONNET, subagent_type=kind)
                elif name == 'e':
                    self.climb_to(task, 'R2')
                    self.owner(task, 'opus-' + task, OPUS)
                else:
                    self.positive(task)
                    change(task)
                self.assertEqual(self.fail_once(task)['event']['class'], 'FAIL')
                self.assertEqual(self.fail_once(task)['event']['class'], 'FAIL')
                self.assertEqual(self.ledger.status(task)['rung'], 'R3')

    def test_fixer_at_rung_blocks_exclusion(self):
        self.positive('kfx')
        self.owner('kfx', 'fixer-opus', OPUS, subagent_type='fixer')
        event = self.fail_once('kfx')['event']
        self.assertEqual(event['class'], 'FAIL')
        self.assertEqual(event['dispatch_check']['decision'], 'counted')


class StatusAndCompat(Fixture):
    def test_status_shows_exclusions(self):
        self.positive('k5')
        self.fail_once('k5')
        status = self.ledger.status('k5')
        self.assertEqual(status['last_dispatch']['resolved_model'], SONNET)
        self.assertEqual(status['excluded_below_rung']['count'], 1)
        self.assertIn('dispatched below rung', status['excluded_below_rung']['latest']['reason'])
        self.assertEqual(status['below_rung_dispatches'], 1)
        self.assertEqual([d['tool_use_id'] for d in status['window_dispatches']], ['pos-k5'])
        for i in range(12):
            self.owner('k5', 'more%d' % i, SONNET)
        self.assertEqual(len(self.ledger.status('k5')['window_dispatches']), 8)
        out = subprocess.run([sys.executable, str(HOOKS / 'escalation.py'), '--root', str(self.root), 'status',
                              '--task', 'k5'], capture_output=True, text=True, timeout=30)
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertEqual(json.loads(out.stdout)['excluded_below_rung']['count'], 1)

    def test_counted_requested_below_visible(self):
        self.climb_to('kq', 'R2')
        self.owner('kq', 'opus-r1', OPUS, requested_rung='R1')  # asked for R1 at R2, family-only "match"
        event = self.fail_once('kq')['event']
        self.assertEqual(event['class'], 'FAIL')
        self.assertTrue(event['dispatch_check']['requested_below'])
        status = self.ledger.status('kq')
        self.assertEqual(status['counted_requested_below']['count'], 1)
        self.assertIn('effort unverified', status['counted_requested_below']['latest']['note'])

    def test_old_ledger_without_dispatches(self):
        self.climb_to('k6', 'R1')
        path = self.root / 'k6.json'
        state = json.loads(path.read_text()); state.pop('dispatches', None); state.pop('side', None)
        path.write_text(json.dumps(state)); os.chmod(path, 0o600)
        status = self.ledger.status('k6')
        self.assertIsNone(status['last_dispatch'])
        self.assertEqual(status['excluded_below_rung']['count'], 0)
        self.assertEqual(self.fail_once('k6')['event']['class'], 'FAIL')


class Negatives(Fixture):
    def test_hostile_payloads_fail_open(self):
        self.climb_to('kh', 'R1')
        prompt = 'work [task:kh]'
        hostile = [
            {'tool_name': 'Agent', 'tool_input': 'not a dict', 'tool_response': {'agentId': 'x'}},
            {'tool_name': 'Agent', 'tool_input': {'prompt': prompt}, 'tool_response': ['list']},
            {'tool_name': 'Agent', 'tool_input': {'prompt': prompt}, 'tool_use_id': 'h1',
             'tool_response': {'agentId': 'a/b\nc' + 'x' * 10000, 'resolvedModel': ['opus'],
                               'modelsUsed': ['m%d' % i for i in range(10000)]}},
            {'tool_name': 'Agent', 'tool_input': {'prompt': prompt}, 'tool_use_id': 'h2',
             'tool_response': {'agentId': 'ok', 'resolvedModel': 'claude-sonnet\x00\x1b[31m' + 'z' * 10000}},
        ]
        for data in hostile:
            self.assertEqual(self.hook('dispatch', data).stdout.strip(), '')
        self.assertEqual(self.hook('dispatch', None, raw='not json').stdout.strip(), '')
        self.assertEqual(self.hook('dispatch', None, raw='{"a": "' + 'x' * (5 << 20) + '"}').stdout.strip(), '')
        self.assertEqual(self.stop('ok', effort='ludicrous').stdout.strip(), '')
        for d in self.dispatches('kh'):
            self.assertLessEqual(len(json.dumps(d, separators=(',', ':'))), esc.DISPATCH_BYTES)
            self.assertTrue(d.get('agent_id') is None or re.fullmatch(r'[A-Za-z0-9_-]{1,64}', d['agent_id']))
            self.assertNotEqual(d.get('observed_effort'), 'ludicrous')
        # an unreadable tier table: still silent, exit 0
        env = {**os.environ, 'AGENT_HARNESS_TIER_POLICY': str(Path(self.temp.name) / 'missing.json')}
        result = subprocess.run([sys.executable, str(HOOKS / 'tier_gate.py'), 'dispatch'], input=json.dumps(hostile[2]),
                                capture_output=True, text=True, timeout=30, env=env)
        self.assertEqual((result.returncode, result.stdout.strip()), (0, ''))
        # decide_spawn and the owner scan never run on the dispatch path
        data = {'tool_name': 'Agent', 'tool_input': {'prompt': prompt}, 'tool_use_id': 'h3',
                'tool_response': {'status': 'async_launched', 'agentId': 'a9', 'resolvedModel': SONNET}}
        with mock.patch.object(gate, 'decide_spawn', side_effect=AssertionError('decide_spawn ran')), \
                mock.patch.object(gate, 'owner_cap_decision', side_effect=AssertionError('owner scan ran')), \
                mock.patch.object(gate.safe_input, 'read_stdin_bounded', return_value=json.dumps(data).encode()), \
                mock.patch('sys.stdout', io.StringIO()) as out:
            self.assertEqual(gate.main(['dispatch']), 0)
        self.assertEqual(out.getvalue(), '')
        self.assertTrue(any(d['tool_use_id'] == 'h3' for d in self.dispatches('kh')))

    def test_decoy_owner_does_not_exclude(self):
        self.owner('kd', 'real', OPUS)  # the real author, launched in the background and still running
        self.positive('kd')  # the decoy: a Sonnet task-owner tagged with the same task
        self.assertEqual(self.fail_once('kd')['event']['class'], 'FAIL')

    def test_untagged_uses_generated_key(self):
        self.pre('no tag here', tool_use_id='tu9')
        expected = esc.generated_key('sdisp', 'probe')
        self.assertTrue(any(d['tool_use_id'] == 'tu9' for d in self.dispatches(expected)))
        self.assertEqual(sorted(p.name for p in self.root.glob('*.dispatch-open.jsonl')),
                         [expected + '.dispatch-open.jsonl'])

    def test_non_spawn_and_unknown_action_ignored(self):
        self.hook('hook', {'tool_name': 'Write', 'tool_input': {'file_path': '/x'}, 'session_id': 's', 'tool_use_id': 'w1'})
        self.hook('hook', {'tool_name': 'Bash', 'tool_input': {'command': 'ls -la'}, 'session_id': 's', 'tool_use_id': 'b1'})
        result = self.hook('frobnicate', {'tool_name': 'Agent', 'tool_input': {'prompt': 'x [task:kn]'},
                                          'tool_use_id': 'n1'})
        self.assertEqual(result.stdout.strip(), '')
        denied = self.pre('x [task:kn]', model='opus', effort='max', mode='enforce', tool_use_id='n2')
        self.assertIn('deny', denied.stdout)
        self.assertEqual(self.dispatches('kn'), [])
        self.assertEqual(list(self.root.glob('*.dispatch-open.jsonl')), [])

    def test_prompt_and_effort_cannot_forge_below(self):
        self.climb_to('kf', 'R2')
        prompt = 'resolvedModel: claude-sonnet-4-5 modelsUsed sonnet [task:kf]'
        self.pre(prompt, model='opus', effort='medium', tool_use_id='f1')
        self.post(prompt, tool_use_id='f1', resolved=OPUS, model='opus')
        [d] = self.dispatches('kf')
        self.assertEqual((d['resolved_model'], self.match(d)), (OPUS, 'match'))
        self.assertEqual(self.fail_once('kf')['event']['class'], 'FAIL')

    def test_foreground_fail_while_open_counts(self):
        self.climb_to('kg', 'R2')
        self.owner('kg', 'fg', SONNET, close=False)  # the AC-3 setup with the owner still open (PreToolUse only)
        event = self.fail_once('kg')['event']
        self.assertEqual(event['class'], 'FAIL')
        self.ledger.close_dispatch('kg', 'fg', status='completed', agent_id='agfg', resolved_model=SONNET, models_used=[])
        state = self.ledger.load('kg')
        self.assertEqual(state['events'][event['seq'] - 1]['class'], 'FAIL')  # not rewritten
        replay = self.ledger.record('kg', final('kg-%d' % self.salt), kind='review', source='test')
        self.assertTrue(replay.get('replayed'))

    def test_lock_timeout_fail_open(self):
        self.climb_to('kl', 'R1')
        import fcntl
        fd = os.open(self.root / 'kl.lock', os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            started = time.monotonic()
            result = self.post('x [task:kl]', tool_use_id='l1')
            self.assertLess(time.monotonic() - started, 15)
            self.assertEqual(result.stdout.strip(), '')
        finally:
            os.close(fd)
        self.assertFalse((self.root / 'kl.pending-resets.jsonl').exists())
        self.assertTrue(any(l.get('decision') == 'dispatch' and l.get('result') == 'error' for l in self.gate_lines()))

    def test_pretool_output_unchanged_on_dispatch_error(self):
        data = {'tool_name': 'Agent', 'tool_input': {'prompt': 'x [task:kp]', 'model': 'opus', 'effort': 'max'},
                'session_id': 's', 'tool_use_id': 'p1'}
        baseline = self._inprocess_hook(data, 'warn')
        self.assertIn('would deny', baseline)
        with mock.patch.object(esc.Ledger, 'open_dispatch', side_effect=OSError('disk full')):
            out = self._inprocess_hook(data, 'warn')
        self.assertEqual(out, baseline)
        self.assertTrue(any(l.get('decision') == 'dispatch_open_failed' for l in self.gate_lines()))

    def _inprocess_hook(self, data, mode):
        policy = json.loads(json.dumps(self.policy)); policy['mode'] = mode
        buffer = io.StringIO()
        with mock.patch.object(gate.safe_input, 'read_stdin_bounded', return_value=json.dumps(data).encode()), \
                mock.patch.object(tiers, 'load_policy', return_value=policy), mock.patch('sys.stdout', buffer):
            self.assertEqual(gate.main(['hook']), 0)
        return buffer.getvalue()

    def _cap_policy(self):
        policy = json.loads(json.dumps(self.policy)); policy['mode'] = 'warn'
        policy.setdefault('caps', {})['session_owner_agents'] = 1
        return policy

    def test_pretool_does_not_wait_on_lock(self):
        data = {'tool_name': 'Agent', 'tool_input': {'prompt': 'x [task:kc]', 'subagent_type': 'task-owner'},
                'session_id': 's', 'tool_use_id': 'c1'}
        import fcntl
        fd = os.open(self.root / 'kc.lock', os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            buffer = io.StringIO()
            started = time.monotonic()
            with mock.patch.object(gate.safe_input, 'read_stdin_bounded', return_value=json.dumps(data).encode()), \
                    mock.patch.object(tiers, 'load_policy', return_value=self._cap_policy()), \
                    mock.patch.object(gate, 'live_owner_ids', return_value=['other-owner']), \
                    mock.patch.object(esc.Ledger, 'status', side_effect=AssertionError('ledger.status on cap path')), \
                    mock.patch('sys.stdout', buffer):
                self.assertEqual(gate.main(['hook']), 0)
            self.assertLess(time.monotonic() - started, 1.0)
        finally:
            os.close(fd)
        self.assertIn('owner cap', buffer.getvalue())
        lines = (self.root / 'kc.dispatch-open.jsonl').read_text().splitlines()
        self.assertEqual(json.loads(lines[0])['tool_use_id'], 'c1')

    def test_warn_cap_deny_opens_dispatch(self):
        self.climb_to('kcap', 'R2')
        data = {'tool_name': 'Agent', 'tool_input': {'prompt': 'w [task:kcap]', 'subagent_type': 'task-owner',
                                                     'model': 'opus', 'effort': 'high'},
                'session_id': 's', 'tool_use_id': 'cap1'}
        with mock.patch.object(gate.safe_input, 'read_stdin_bounded', return_value=json.dumps(data).encode()), \
                mock.patch.object(tiers, 'load_policy', return_value=self._cap_policy()), \
                mock.patch.object(gate, 'live_owner_ids', return_value=['other-owner']), \
                mock.patch('sys.stdout', io.StringIO()):
            gate.main(['hook'])
        [d] = [d for d in self.dispatches('kcap') if d['tool_use_id'] == 'cap1']
        self.assertEqual((d['phase'], d['owner'], d['requested']['rung']), ('open', True, 'R2'))
        self.owner('kcap', 'snt', SONNET)
        self.assertEqual(self.fail_once('kcap')['event']['class'], 'FAIL')

    def test_dispatch_bound_and_near_full_ledger(self):
        for i in range(200):
            self.owner('kb', 'b%03d' % i, SONNET, status='completed')
        ds = self.dispatches('kb')
        self.assertEqual(len(ds), esc.MAX_DISPATCHES)
        self.assertEqual(ds[-1]['tool_use_id'], 'b199')
        for d in ds:
            self.assertLessEqual(len(json.dumps(d, separators=(',', ':'))), esc.DISPATCH_BYTES)
        # eviction removes ended or stale records before any live one
        self.owner('kv', 'live-opus', OPUS)
        for i in range(esc.MAX_DISPATCHES + 10):
            self.owner('kv', 'e%03d' % i, SONNET, status='completed')
        self.assertTrue(any(d['tool_use_id'] == 'live-opus' for d in self.dispatches('kv')))
        # a maximal dispatch (long ids and models, 8 models used) stays within DISPATCH_BYTES
        long_models = ['claude-sonnet-' + 'x' * 80 for _ in range(12)]
        self.ledger.open_dispatch('km', {'tool_use_id': 'u' * 200, 'subagent_type': 's' * 200, 'owner': True,
                                         'requested': {'model': 'm' * 200, 'effort': 'e' * 200, 'rung': 'R' * 50},
                                         'selected': {'model': 'm' * 200, 'effort': 'e' * 200, 'rung': 'R' * 50}})
        big = self.ledger.close_dispatch('km', 'u' * 200, status='s' * 200, agent_id='a' * 64,
                                         resolved_model=long_models[0], models_used=long_models)
        self.assertLessEqual(len(json.dumps(big, separators=(',', ':'))), esc.DISPATCH_BYTES)
        # a ledger 100 KiB under MAX_STATE still accepts 64 maximal dispatches and a FAIL with its check
        state = self.ledger.load('km')
        state['dispatches'] = [dict(big, tool_use_id=('%064d' % i)) for i in range(esc.MAX_DISPATCHES)]
        used = len(json.dumps(state, sort_keys=True, separators=(',', ':')))
        state['filler_for_test'] = 'x' * max(0, esc.MAX_STATE - 100 * 1024 - used)
        self.ledger._write('km', state)
        event = self.fail_once('km')['event']
        self.assertLessEqual(len(json.dumps(event['dispatch_check'], separators=(',', ':'))), 256)

    def test_stale_open_dispatch(self):
        self.owner('ks', 'old', OPUS)  # a live opus owner from before the climb
        self.positive('ks')
        self.assertEqual(self.fail_once('ks')['event']['class'], 'FAIL')
        later = time.time() + esc.DISPATCH_LIVE_SECONDS + 60
        with mock.patch.object(esc, 'epoch', return_value=later):
            self.assertEqual(self.fail_once('ks')['event']['class'], 'NOT_COUNTED')  # the opus run is presumed ended

    def test_review_mark_does_not_hide_owner(self):
        self.climb_to('kr', 'R2')
        self.pre('[review:self] work [task:kr]', model='opus', effort='high', tool_use_id='r1')
        self.post('[review:self] work [task:kr]', tool_use_id='r1', resolved=OPUS, model='opus')
        self.owner('kr', 'r2', SONNET)
        [first] = [d for d in self.dispatches('kr') if d['tool_use_id'] == 'r1']
        self.assertEqual((first['owner'], first['reviewer']), (True, False))
        self.assertEqual(self.fail_once('kr')['event']['class'], 'FAIL')

    def test_live_background_owner_blocks_exclusion(self):
        self.owner('k9', 'opus-bg', OPUS, agent_id='agopus')
        self.owner('k9', 'sonnet-gp', SONNET, subagent_type='general-purpose', agent_id='aggp')
        self.positive('k9')
        self.assertEqual(self.fail_once('k9')['event']['class'], 'FAIL')
        self.stop('agopus')
        self.stop('aggp')
        [opus] = [d for d in self.dispatches('k9') if d['tool_use_id'] == 'opus-bg']
        self.assertIn('ended_at', opus)
        # inspection F4 (spec r7 NEG-9): the opus run ended inside this R2 window, so the window keeps counting
        self.assertEqual(opus['ended_seq'], len(self.ledger.load('k9')['events']))
        self.assertEqual(self.fail_once('k9')['event']['class'], 'FAIL')

    def test_warn_deny_spawn_opens_dispatch(self):
        self.climb_to('kx', 'R2')
        self.pre('work [task:kx]', model='opus', effort='max', mode='warn', tool_use_id='x1')  # would deny, still runs
        [d] = self.dispatches('kx')
        self.assertEqual(d['phase'], 'open')
        self.owner('kx', 'x2', SONNET)
        self.assertEqual(self.fail_once('kx')['event']['class'], 'FAIL')

    def test_workflow_and_bash_dispatch_block_exclusion(self):
        self.climb_to('ky', 'R2')
        self.pre('flow [task:ky]', tool='Workflow', model=None, subagent_type='', tool_use_id='y1')
        self.climb_to('kz', 'R2')
        self.hook('hook', {'tool_name': 'Bash', 'tool_input': {'command': 'codex exec --task kz "build it"'},
                           'session_id': 's', 'tool_use_id': 'z1'})
        for task in ('ky', 'kz'):
            with self.subTest(task=task):
                kinds = {d.get('kind') for d in self.dispatches(task)}
                self.assertTrue(kinds & {'workflow', 'bash'}, kinds)
                self.owner(task, 's-' + task, SONNET)
                self.assertEqual(self.fail_once(task)['event']['class'], 'FAIL')

    def test_reset_keeps_only_live_dispatches(self):
        self.owner('kz2', 'opus-live', OPUS)
        self.owner('kz2', 'sonnet-ended', SONNET, status='completed')
        self.ledger.reset('kz2', 'state_corrupt', 'test reset')
        ds = self.dispatches('kz2')
        self.assertEqual([d['tool_use_id'] for d in ds], ['opus-live'])
        self.assertEqual(ds[0]['after_seq'], 0)
        self.climb_to('kz2', 'R2')
        self.owner('kz2', 'sonnet-new', SONNET)
        self.assertEqual(self.fail_once('kz2')['event']['class'], 'FAIL')  # the live opus owner still blocks


class SideFile(Fixture):
    def test_append_interleaved_with_merge_survives(self):
        self.climb_to('ki', 'R2')
        self.owner('ki', 'first', SONNET)
        state = {'done': False}

        def append_now(ledger, task):
            if task == 'ki' and not state['done']:
                state['done'] = True  # appends land after this merge read the file, before the ledger write
                ledger.open_dispatch('ki', {'tool_use_id': 'raced', 'kind': 'agent', 'subagent_type': 'task-owner',
                                            'owner': True})
                with open(self.root / 'ki.dispatch-open.jsonl', 'ab') as handle:
                    handle.write(b'{"tool_use_id":"partial","owner":true')  # an append still in progress
        self.ledger.open_dispatch('ki', {'tool_use_id': 'before', 'kind': 'agent', 'owner': False})
        with mock.patch.object(esc.Ledger, '_after_side_read', append_now):
            self.ledger.load('ki')
        self.assertTrue(state['done'])
        with open(self.root / 'ki.dispatch-open.jsonl', 'ab') as handle:
            handle.write(b',"kind":"agent"}\n')  # the partial append completes
        ids = {d['tool_use_id']: d for d in self.dispatches('ki')}
        self.assertIn('before', ids)
        self.assertIn('raced', ids)
        self.assertIn('partial', ids)
        self.assertEqual(ids['raced']['phase'], 'open')
        self.assertFalse(any(d.get('kind') == 'unknown' for d in ids.values()))
        self.assertEqual(self.fail_once('ki')['event']['class'], 'FAIL')

    def test_side_file_overflow_blocks_exclusion(self):
        self.positive('ko')
        with open(self.root / 'ko.dispatch-open.jsonl', 'ab') as handle:
            for i in range(200):
                handle.write(json.dumps({'tool_use_id': 'pad%d' % i, 'owner': False, 'kind': 'agent',
                                         'subagent_type': 'Explore', 'x': 'p' * 1500}).encode()[:1900] + b'\n')
        self.assertGreater(os.path.getsize(self.root / 'ko.dispatch-open.jsonl'), esc.SIDE_LIMIT)
        status = self.ledger.status('ko')
        unknown = [d for d in self.dispatches('ko') if d.get('kind') == 'unknown']
        self.assertTrue(any(d.get('reason') == 'side_overflow' for d in unknown), unknown)
        self.assertTrue(any(d.get('reason') == 'side_overflow' for d in status['window_dispatches']))
        self.assertFalse((self.root / 'ko.dispatch-open.jsonl').exists())  # renamed after the ledger write
        self.assertEqual(len(list(self.root.glob('ko.dispatch-open.*.old'))), 1)
        self.assertEqual(self.fail_once('ko')['event']['class'], 'FAIL')
        # a garbled line also merges as an unknown that blocks exclusion
        self.positive('kgb')
        with open(self.root / 'kgb.dispatch-open.jsonl', 'ab') as handle:
            handle.write(b'{"tool_use_id": "torn", "own{"tool_use_id":"next"}\n')
        self.assertEqual(self.fail_once('kgb')['event']['class'], 'FAIL')
        self.assertTrue(any(d.get('reason') == 'side_garbled' for d in self.dispatches('kgb')))
        # an offset past the file size on the same inode counts as a rewrite
        self.positive('krw')
        self.ledger.load('krw')
        with open(self.root / 'krw.dispatch-open.jsonl', 'r+b') as handle:
            handle.truncate(0)
        self.assertTrue(any(d.get('reason') == 'side_rewritten' for d in self.dispatches('krw')))

    def test_side_file_whitelist_and_symlink(self):
        self.positive('kwl')
        forged = {'tool_use_id': 'forged', 'phase': 'closed', 'candidates': ['R0'], 'ended_at': 'x', 'after_seq': -5,
                  'agent_id': 'evil', 'resolved_model': SONNET, 'owner': True, 'kind': 'agent'}
        with open(self.root / 'kwl.dispatch-open.jsonl', 'ab') as handle:
            handle.write(json.dumps(forged).encode() + b'\n' + json.dumps(dict(forged, phase='open')).encode() + b'\n')
        forged_records = [d for d in self.dispatches('kwl') if d['tool_use_id'] == 'forged']
        self.assertEqual(len(forged_records), 1)  # the duplicate tool_use_id is skipped
        [d] = forged_records
        self.assertEqual(d['phase'], 'open')
        for key in ('candidates', 'ended_at', 'agent_id', 'resolved_model'):
            self.assertNotIn(key, d)
        self.assertGreaterEqual(d['after_seq'], 0)
        self.assertEqual(self.fail_once('kwl')['event']['class'], 'FAIL')
        # a planted symlink: PreToolUse refuses it (logged), and the merge treats it as one unknown
        self.positive('ksl')
        self.ledger.load('ksl')
        os.unlink(self.root / 'ksl.dispatch-open.jsonl')
        target = Path(self.temp.name) / 'elsewhere.jsonl'; target.write_text('')
        os.symlink(target, self.root / 'ksl.dispatch-open.jsonl')
        self.pre('w [task:ksl] [rung-below:t]', tool_use_id='sl1')
        self.assertEqual(target.read_text(), '')
        self.assertTrue(any(l.get('decision') == 'dispatch_open_failed' for l in self.gate_lines()))
        self.assertTrue(any(d.get('reason') == 'side_not_regular' for d in self.dispatches('ksl')))
        self.assertEqual(self.fail_once('ksl')['event']['class'], 'FAIL')


class StopEffort(Fixture):
    def opus_owner(self, task):
        agent = 'ag' + task.replace('-', '')
        self.climb_to(task, 'R2')
        self.owner(task, 'op-' + task, OPUS, agent_id=agent)
        self.assertEqual(self.fail_once(task)['event']['class'], 'FAIL')  # before its stop: family-only "match"
        return agent

    def test_stop_effort_recorded_not_narrowed_by_default(self):
        agent = self.opus_owner('ke1')
        self.stop(agent, effort='medium')
        [d] = self.dispatches('ke1')
        self.assertEqual((d['observed_effort'], d['candidates']), ('medium', ['R1', 'R2', 'R3', 'R4']))
        self.assertEqual(self.fail_once('ke1')['event']['class'], 'FAIL')

    def test_stop_effort_narrows_candidates_with_flag(self):
        agent = self.opus_owner('ke2')
        self.stop(agent, effort='medium', dispatch_narrow_by_stop_effort=True)
        [d] = self.dispatches('ke2')
        self.assertEqual(d['candidates'], ['R1'])
        self.assertEqual(self.fail_once('ke2')['event']['class'], 'NOT_COUNTED')
        control = self.opus_owner('ke3')
        self.stop(control, effort='high', dispatch_narrow_by_stop_effort=True)
        self.assertEqual(self.fail_once('ke3')['event']['class'], 'FAIL')

    def test_foreground_stop_before_close_applies(self):
        self.climb_to('kfg', 'R2')
        self.pre('fg [task:kfg]', model='opus', effort='medium', tool_use_id='fg1')
        self.stop('agfg1', effort='medium')  # SubagentStop fires before the foreground PostToolUse
        self.post('fg [task:kfg]', tool_use_id='fg1', status='completed', agent_id='agfg1', resolved=OPUS, model='opus')
        [d] = self.dispatches('kfg')
        self.assertEqual((d['observed_effort'], bool(d.get('ended_at'))), ('medium', True))
        index = json.loads((self.root / 'dispatch_index.json').read_text())
        self.assertEqual(index.get('agfg1'), 'kfg')  # the pending stop was consumed


class Index(Fixture):
    def test_index_is_private_bounded_and_corruption_is_a_noop(self):
        limit = mock.patch.object(esc, 'INDEX_LIMIT', 512)  # the bound logic, at a size this test can fill quickly
        limit.start(); self.addCleanup(limit.stop)
        for i in range(600):
            esc.index_agent(self.root, 'ag%04d' % i, 'kidx')
        for i in range(100):
            esc.note_pending_stop(self.root, 'pend%03d' % i, 'high')
        path = self.root / 'dispatch_index.json'
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
        index = json.loads(path.read_text())
        self.assertEqual(sum(1 for v in index.values() if isinstance(v, str)), esc.INDEX_LIMIT)
        self.assertLessEqual(sum(1 for v in index.values() if isinstance(v, dict)), esc.PENDING_STOP_LIMIT)
        self.assertIn('ag0599', index)
        self.assertNotIn('ag0000', index)
        later = time.time() + esc.PENDING_STOP_SECONDS + 5
        with mock.patch.object(esc, 'epoch', return_value=later):
            esc.index_agent(self.root, 'agnew', 'kidx')
        self.assertFalse(any(isinstance(v, dict) for v in json.loads(path.read_text()).values()))
        self.assertFalse(list(self.root.glob('*.tmp')))
        path.write_text('{not json')
        self.assertEqual(self.stop('ag0599').stdout.strip(), '')
        path.write_text(json.dumps({'ag1': '../../etc/passwd'}))
        self.stop('ag1')
        self.assertIsNone(esc.lookup_agent(self.root, 'ag1'))
        self.assertFalse((self.root.parent / 'etc').exists())


class InspectionRound1(Fixture):
    """Code inspection a0dd5f0a (BLOCK on 0686124c): findings F1-F9, each failing before its fix."""

    def side(self, task):
        return self.root / (task + '.dispatch-open.jsonl')

    def test_f1_near_full_merge_never_resets(self):
        self.climb_to('n1', 'R2')
        state = self.ledger.load('n1')
        used = len(json.dumps(state, sort_keys=True, separators=(',', ':')))
        state['filler_for_test'] = 'x' * (esc.MAX_STATE - used - 120)
        self.ledger._write('n1', state)
        self.ledger.open_dispatch('n1', {'tool_use_id': 'near-full', 'owner': True, 'subagent_type': 'task-owner'})
        decision = gate.decide_spawn({'tool_name': 'Agent', 'session_id': 's',
                                      'tool_input': {'prompt': 'x [task:n1]', 'description': 'd',
                                                     'subagent_type': 'task-owner', 'model': 'sonnet'}},
                                     self.policy, self.ledger, session_id='s')
        self.assertNotIn('reset', json.dumps(decision[3]))
        status = self.ledger.status('n1')
        self.assertEqual(status['rung'], 'R2')
        self.assertFalse([r for r in self.ledger.load('n1')['resets'] if r.get('code') == 'state_corrupt'])

    def test_f1_shed_dispatch_taints_window(self):
        self.climb_to('n1b', 'R2')
        self.owner('n1b', 'opus-w', OPUS, status='completed')
        self.owner('n1b', 'son-w', SONNET)
        state = self.ledger.load('n1b')
        used = len(json.dumps(state, sort_keys=True, separators=(',', ':')))
        state['filler_for_test'] = 'x' * (esc.MAX_STATE - used + 40)  # only shedding a dispatch makes it fit
        self.ledger._write('n1b', state)
        self.assertEqual(self.fail_once('n1b')['event']['class'], 'FAIL')

    def test_f2_deep_json_line_is_garbled(self):
        self.positive('n2')
        with open(self.side('n2'), 'ab') as handle:
            handle.write(b'[' * 1000 + b']' * 1000 + b'\n')
        reasons = [d.get('reason') for d in self.dispatches('n2')]
        self.assertIn('side_garbled', reasons)
        self.assertEqual(self.fail_once('n2')['event']['class'], 'FAIL')
        self.assertEqual(self.ledger.load('n2')['side']['offset'], self.side('n2').stat().st_size)

    def test_f3_reviewer_flood_keeps_window_writer(self):
        self.climb_to('n3', 'R2')
        self.owner('n3', 'opus-done', OPUS, status='completed')
        for i in range(esc.MAX_DISPATCHES - 1):
            self.owner('n3', 'rt%02d' % i, SONNET, subagent_type='red-team', status='completed')
        self.owner('n3', 'son', SONNET)
        self.assertIn('opus-done', [d['tool_use_id'] for d in self.dispatches('n3')])
        self.assertEqual(self.fail_once('n3')['event']['class'], 'FAIL')

    def test_f3_evicted_window_writer_taints(self):
        """Harmless below-rung records go first (they never hide anything); when an at-rung record must go, a
        durable taint keeps the window counting. 64 open records arrive in one merge to force that eviction."""
        for task, with_opus in (('n3b', True), ('n3c', False)):
            with self.subTest(with_opus=with_opus):
                self.climb_to(task, 'R2')
                if with_opus:
                    self.owner(task, 'opus-done', OPUS, status='completed')
                for i in range(esc.MAX_DISPATCHES):
                    self.owner(task, 's%02d' % i, SONNET, close=False)
                ids = [d['tool_use_id'] for d in self.dispatches(task)]
                self.assertEqual(len(ids), esc.MAX_DISPATCHES)
                self.assertNotIn('opus-done', ids)
                for i in range(esc.MAX_DISPATCHES):
                    self.ledger.close_dispatch(task, 's%02d' % i, status='completed', agent_id='ag%s%02d' % (task, i),
                                               resolved_model=SONNET, models_used=[])
                expected = 'FAIL' if with_opus else 'NOT_COUNTED'
                event = self.fail_once(task)['event']
                self.assertEqual(event['class'], expected)
                self.assertEqual(event['dispatch_check'].get('tainted', False), with_opus)

    def test_f4_owner_ended_before_window_is_ignored(self):
        self.owner('n4', 'opus-early', OPUS, agent_id='agearly')
        self.stop('agearly')
        self.positive('n4')
        self.assertEqual(self.fail_once('n4')['event']['class'], 'NOT_COUNTED')

    def test_f5_resume_reopens_dispatch(self):
        for task, how in (('n5', 'start'), ('n5b', 'send'), ('n5c', None)):
            with self.subTest(how=how):
                self.owner(task, 'opus-' + task, OPUS, status='completed', agent_id='ag' + task)
                self.positive(task)
                if how == 'start':
                    self.hook('start', {'agent_id': 'ag' + task, 'agent_type': 'task-owner', 'session_id': 'sdisp',
                                        'hook_event_name': 'SubagentStart'})
                elif how == 'send':
                    self.hook('dispatch', {'tool_name': 'SendMessage', 'tool_input': {'to': 'ag' + task, 'message': 'm'},
                                           'tool_response': {}, 'session_id': 'sdisp', 'tool_use_id': 'sm1',
                                           'hook_event_name': 'PostToolUse'})
                expected = 'NOT_COUNTED' if how is None else 'FAIL'
                self.assertEqual(self.fail_once(task)['event']['class'], expected)

    def test_f5_resume_of_evicted_agent_is_unknown(self):
        esc.index_agent(self.root, 'aggone', 'n5d')
        self.positive('n5d')
        self.hook('start', {'agent_id': 'aggone', 'agent_type': 'task-owner', 'session_id': 'sdisp',
                            'hook_event_name': 'SubagentStart'})
        self.assertIn('resumed_unknown', [d.get('reason') for d in self.dispatches('n5d')])
        self.assertEqual(self.fail_once('n5d')['event']['class'], 'FAIL')

    def test_f6_bash_launch_beside_peer_review_opens_dispatch(self):
        for task, command in (('n6', 'claude --model sonnet -p "fix [task:n6]" && python3 peer_review.py pr --task n6'),
                              ('n6b', 'claude --version && claude -p "fix it [task:n6b]"'),
                              ('n6d', 'claude -p "fix it, then run peer_review.py [task:n6d]"')):
            with self.subTest(command=command):
                self.climb_to(task, 'R2')
                self.hook('hook', {'tool_name': 'Bash', 'tool_input': {'command': command}, 'session_id': 's',
                                   'tool_use_id': 'b-' + task})
                self.assertIn('bash', [d.get('kind') for d in self.dispatches(task)])
        self.climb_to('n6c', 'R2')
        self.hook('hook', {'tool_name': 'Bash', 'tool_input': {'command': 'python3 peer_review.py pr --task n6c'},
                           'session_id': 's', 'tool_use_id': 'b-n6c'})
        self.assertNotIn('bash', [d.get('kind') for d in self.dispatches('n6c')])

    def test_f7_garbled_flood_is_one_synthetic_and_fast(self):
        self.positive('n7')
        self.side('n7').write_bytes(b'x\n' * 20000)
        started = time.monotonic()
        garbled = [d for d in self.dispatches('n7') if d.get('reason') == 'side_garbled']
        self.assertLess(time.monotonic() - started, 2.0)
        self.assertEqual(len(garbled), 1)
        self.assertEqual(self.fail_once('n7')['event']['class'], 'FAIL')

    def test_f8_fifo_paths_never_block(self):
        import threading
        os.mkfifo(self.side('n8'))
        os.mkfifo(self.root / 'dispatch_index.tmp')
        outcome = {}

        def run():
            try:
                self.ledger.open_dispatch('n8', {'tool_use_id': 'f1', 'owner': True})
                outcome['open'] = 'returned'
            except OSError as error:
                outcome['open'] = type(error).__name__
            outcome['index'] = esc.index_agent(self.root, 'agfifo', 'n8')
            outcome['done'] = True
        worker = threading.Thread(target=run, daemon=True)
        worker.start(); worker.join(5)
        self.assertTrue(outcome.get('done'), outcome)
        self.assertNotEqual(outcome['open'], 'returned')
        self.assertIn('side_not_regular', [d.get('reason') for d in self.dispatches('n8')])

    def test_d1_fifo_ledger_tmp_never_blocks(self):
        """Delta inspection D1: a merge makes status() write the ledger on the spawn path; a FIFO at <task>.tmp must
        fail the write at once instead of hanging the PreToolUse hook."""
        import threading
        self.climb_to('n8d', 'R1')
        os.mkfifo(self.root / 'n8d.tmp')
        self.ledger.open_dispatch('n8d', {'tool_use_id': 'd1', 'owner': True})
        outcome = {}

        def run():
            try:
                outcome['rung'] = self.ledger.status('n8d')['rung']
            except Exception as error:  # noqa: BLE001
                outcome['error'] = type(error).__name__
            outcome['done'] = True
        worker = threading.Thread(target=run, daemon=True)
        worker.start(); worker.join(5)
        self.assertTrue(outcome.get('done'), 'status() blocked on a FIFO at the ledger tmp path')
        self.assertEqual(outcome.get('rung'), 'R1')
        self.assertEqual(self.fail_once('n8d')['event']['rung_at'], 'R1')

    def test_m2_bash_task_from_launch_not_review(self):
        self.climb_to('kj', 'R1')
        self.hook('hook', {'tool_name': 'Bash', 'session_id': 's', 'tool_use_id': 'bm2',
                           'tool_input': {'command': 'python3 peer_review.py pr --task kk && claude -p "go [task:kj]"'}})
        self.assertIn('bash', [d.get('kind') for d in self.dispatches('kj')])

    def test_f9_dispatch_action_exit0_with_symlinked_state(self):
        link = Path(self.temp.name) / 'state-link'
        link.symlink_to(self.root)
        env = {**os.environ, 'AGENT_HARNESS_ESCALATION_DIR': str(link)}
        for raw in ('not json', json.dumps({'tool_name': 'Agent', 'tool_input': {}, 'tool_response': {'status': 'x'},
                                            'tool_use_id': 't'})):
            result = subprocess.run([sys.executable, str(HOOKS / 'tier_gate.py'), 'dispatch'], input=raw,
                                    capture_output=True, text=True, timeout=30, env=env)
            self.assertEqual((result.returncode, result.stdout, result.stderr), (0, '', ''))


class ResumeHookPath(Fixture):
    """Spec r7 AC-10: the resume path (SubagentStart, PostToolUse SendMessage) never waits on the ledger lock, adds
    nothing to stdout, and fails open; Agent/Task calls still run exactly one PostToolUse tier_gate entry."""

    def side(self, task):
        return self.root / (task + '.dispatch-open.jsonl')

    def held(self, task):
        import fcntl
        fd = os.open(self.root / (task + '.lock'), os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        self.addCleanup(os.close, fd)

    def test_resume_never_waits_on_lock(self):
        self.owner('r10', 'opus-r10', OPUS, status='completed', agent_id='agr10')
        self.held('r10')
        for action, data in (
                ('start', {'agent_id': 'agr10', 'agent_type': 'task-owner', 'session_id': 'sdisp',
                           'hook_event_name': 'SubagentStart'}),
                ('dispatch', {'tool_name': 'SendMessage', 'tool_input': {'to': 'agr10', 'message': 'm'},
                              'tool_response': {}, 'session_id': 'sdisp', 'tool_use_id': 'sm2',
                              'hook_event_name': 'PostToolUse'})):
            with self.subTest(action=action):
                started = time.monotonic()
                result = self.hook(action, data)
                self.assertLess(time.monotonic() - started, 0.5 * esc.LOCK_SECONDS)  # r7 m7
                self.assertEqual(result.stdout, '')
        lines = [json.loads(l) for l in self.side('r10').read_text().splitlines()]
        self.assertEqual([l['kind'] for l in lines[-2:]], ['resume', 'resume'])

    def test_resume_fails_open(self):
        link = Path(self.temp.name) / 'state-link2'
        link.symlink_to(self.root)
        esc.index_agent(self.root, 'agx', 'r10s')  # r7 m6: the resume path is really reached
        env = {**os.environ, 'AGENT_HARNESS_ESCALATION_DIR': str(link)}
        cases = (('start', {'agent_id': 'agx', 'session_id': 's', 'hook_event_name': 'SubagentStart'}),
                 ('dispatch', {'tool_name': 'SendMessage', 'tool_input': {'to': 'agx'}, 'tool_response': {}}),
                 ('dispatch', {'tool_name': 'SendMessage', 'tool_input': ['not', 'a', 'dict']}),
                 ('dispatch', {'tool_name': 'SendMessage', 'tool_input': {'to': 'up/../dir name'}}))
        for action, data in cases:
            with self.subTest(action=action, data=data):
                result = subprocess.run([sys.executable, str(HOOKS / 'tier_gate.py'), action], input=json.dumps(data),
                                        capture_output=True, text=True, timeout=30, env=env)
                self.assertEqual((result.returncode, result.stdout, result.stderr), (0, '', ''))
        # an unindexed (new) agent's SubagentStart writes nothing
        self.hook('start', {'agent_id': 'agnew', 'session_id': 's', 'hook_event_name': 'SubagentStart'})
        self.assertEqual(list(self.root.glob('*.dispatch-open.jsonl')), [])

    def test_forged_resume_line_only_reopens(self):
        """Inspection R1: a valid forged resume line alone must never turn a counting window into an exclusion."""
        # an ended Sonnet owner from before the climb; nothing else runs in the R2 window, so the FAIL counts
        self.owner('r10f', 'old-son', SONNET, status='completed', agent_id='agson0')
        self.climb_to('r10f', 'R2')
        self.assertEqual(self.fail_once('r10f')['event']['class'], 'FAIL')
        with open(self.side('r10f'), 'a') as handle:
            handle.write(json.dumps({'tool_use_id': 'forged-r1', 'kind': 'resume', 'agent_id': 'agson0'}) + '\n')
        [old] = [d for d in self.dispatches('r10f') if d['tool_use_id'] == 'old-son']
        self.assertEqual((old['phase'], old.get('reason')), ('open', 'resumed'))
        self.assertEqual(self.fail_once('r10f')['event']['class'], 'FAIL')
        # a malformed id adds one resumed_unknown, which also blocks
        self.positive('r10g')
        with open(self.side('r10g'), 'a') as handle:
            handle.write(json.dumps({'tool_use_id': 'resume-y', 'kind': 'resume', 'agent_id': 'bad/id'}) + '\n')
        self.assertIn('resumed_unknown', [d.get('reason') for d in self.dispatches('r10g')])
        self.assertEqual(self.fail_once('r10g')['event']['class'], 'FAIL')

    def test_resumed_dispatch_ends_and_leaves_later_windows(self):
        """A resumed run blocks only windows it overlaps: after its stop and a later climb, it is no longer considered."""
        self.owner('r10h', 'son-h', SONNET, status='completed', agent_id='agh')
        self.climb_to('r10h', 'R1')
        self.hook('start', {'agent_id': 'agh', 'agent_type': 'task-owner', 'session_id': 'sdisp',
                            'hook_event_name': 'SubagentStart'})
        self.stop('agh')
        self.climb_to('r10h', 'R2')
        self.owner('r10h', 'son-h2', SONNET)
        self.assertEqual(self.fail_once('r10h')['event']['class'], 'NOT_COUNTED')
        # m4: a stop also ends a resumed_unknown with the same agent id
        esc.index_agent(self.root, 'aggone2', 'r10i')
        self.hook('start', {'agent_id': 'aggone2', 'session_id': 's', 'hook_event_name': 'SubagentStart'})
        self.stop('aggone2')
        [syn] = [d for d in self.dispatches('r10i') if d.get('reason') == 'resumed_unknown']
        self.assertIn('ended_at', syn)

    def test_agent_task_run_one_posttool_entry(self):
        sys.path.insert(0, str(ROOT))
        import install
        hooks = install.managed_hooks(Path('/h/.claude'))
        for tool in ('Agent', 'Task', 'SendMessage'):
            entries = [h for g in hooks.get('PostToolUse', []) if re.fullmatch(g.get('matcher', '.*'), tool)
                       for h in g['hooks'] if 'tier_gate.py' in json.dumps(h)]
            self.assertEqual(len(entries), 1, tool)
            self.assertNotIn('onFailure', entries[0])


class SpecR7Review(Fixture):
    """Spec r7 adversarial review a7939032 (BLOCK): M1 and minors m1, m2, m3, m8, m9."""

    def side(self, task):
        return self.root / (task + '.dispatch-open.jsonl')

    def test_m1_send_by_name_resolves_through_response(self):
        self.owner('s1', 'opus-s1', OPUS, status='completed', agent_id='ags1')
        self.positive('s1')
        self.hook('dispatch', {'tool_name': 'SendMessage', 'tool_input': {'to': 'owner name', 'message': 'm'},
                               'tool_response': {'success': True, 'resumedAgentId': 'ags1', 'message': 'x'},
                               'session_id': 'sdisp', 'tool_use_id': 'smn', 'hook_event_name': 'PostToolUse'})
        self.assertEqual(self.fail_once('s1')['event']['class'], 'FAIL')
        [line] = [l for l in self.gate_lines() if l.get('tool') == 'SendMessage']
        self.assertEqual((line['result'], line['response_keys']), ('reopened', ['message', 'resumedAgentId', 'success']))
        self.assertNotIn('ags1', json.dumps(line.get('response_keys')))

    def test_m1_late_resume_after_stop_is_stale(self):
        self.owner('s2', 'son-s2', SONNET, status='completed', agent_id='ags2')
        written = time.time()
        with open(self.side('s2'), 'a') as handle:
            handle.write(json.dumps({'tool_use_id': 'resume-a', 'kind': 'resume', 'agent_id': 'ags2', 'at': written}) + '\n')
        self.dispatches('s2')  # the merge reopens it
        self.ledger.end_dispatch('s2', 'ags2')
        with open(self.side('s2'), 'a') as handle:  # the SendMessage line, written before the stop, merged after it
            handle.write(json.dumps({'tool_use_id': 'resume-b', 'kind': 'resume', 'agent_id': 'ags2', 'at': written}) + '\n')
        [d] = [d for d in self.dispatches('s2') if d['tool_use_id'] == 'son-s2']
        self.assertTrue(d.get('ended_at'), d)

    def test_m2_reset_rebases_resumed_seq(self):
        self.owner('s3', 'opus-s3', OPUS, agent_id='ags3')
        self.climb_to('s3', 'R1')
        with open(self.side('s3'), 'a') as handle:
            handle.write(json.dumps({'tool_use_id': 'resume-c', 'kind': 'resume', 'agent_id': 'ags3', 'at': time.time()}) + '\n')
        self.dispatches('s3')
        self.ledger.reset('s3', 'state_corrupt', 'test reset')
        [d] = self.dispatches('s3')
        self.assertEqual((d['after_seq'], d.get('resumed_seq')), (0, 0))
        self.assertNotIn('ended_seq', d)

    def test_m3_index_keeps_old_owner(self):
        esc.index_agent(self.root, 'agold', 's4')
        for i in range(600):
            esc.index_agent(self.root, 'agn%03d' % i, 's4x')
        self.assertEqual(esc.lookup_agent(self.root, 'agold'), 's4')

    def test_m9_index_fifo_never_blocks(self):
        import threading
        os.mkfifo(self.root / 'dispatch_index.json')
        outcome = {}

        def run():
            outcome['task'] = esc.lookup_agent(self.root, 'agz')
            outcome['done'] = True
        worker = threading.Thread(target=run, daemon=True)
        worker.start(); worker.join(3)
        self.assertTrue(outcome.get('done'))
        self.assertIsNone(outcome['task'])

    def test_m8_other_task_tools_ignored(self):
        for tool in ('TaskStop', 'TaskOutput', 'TaskCreate'):
            result = self.hook('dispatch', {'tool_name': tool, 'tool_input': {}, 'tool_response': {'ok': True},
                                            'session_id': 's', 'tool_use_id': 'x-' + tool})
            self.assertEqual(result.stdout, '')
        results = [l.get('result') for l in self.gate_lines() if l.get('tool', '').startswith('Task')]
        self.assertEqual(results, ['ignored'] * 3)
        self.assertEqual(list(self.root.glob('*.dispatch-open.jsonl')), [])


class ShippedDefault(Fixture):
    """PR 225 receipt F1: the shipped tier table never excludes; it records the would-be decision only."""

    def setUp(self):
        super().setUp()
        self.policy = tiers.load_policy()  # the shipped table, unmodified
        self.ledger = esc.Ledger(self.root, self.policy)

    def test_shipped_cap_is_false(self):
        self.assertIs(self.policy['caps'].get('dispatch_exclude_below_rung'), False)

    def test_default_never_excludes_but_records_would_exclude(self):
        self.positive('sd1')
        status = self.fail_once('sd1')
        event = status['event']
        self.assertEqual(event['class'], 'FAIL')
        self.assertEqual(event['dispatch_check']['decision'], 'would_exclude')
        state = self.ledger.load('sd1')
        self.assertFalse([e for e in state['events'] if (e.get('dispatch_check') or {}).get('decision') == 'excluded'])
        summary = self.ledger.status('sd1')
        self.assertEqual(summary['excluded_below_rung']['count'], 0)
        self.assertEqual(summary['would_exclude_below_rung']['count'], 1)

    def test_default_hook_path_never_excludes(self):
        self.climb_to('sd2', 'R2')
        self.pre('work [task:sd2]', tool_use_id='h1')
        self.post('work [task:sd2]', tool_use_id='h1', agent_id='agsd2')
        self.assertEqual(self.fail_once('sd2')['event']['class'], 'FAIL')


class OverflowCleanup(Fixture):
    """PR 225 receipt F4: renamed overflow side files keep one generation per task."""

    def test_one_old_generation_kept(self):
        side = self.root / 'ov.dispatch-open.jsonl'
        for round_ in range(3):
            side.write_bytes(b'x\n' * (esc.SIDE_LIMIT // 2 + 10))
            with mock.patch.object(esc, 'epoch', return_value=time.time() + round_):
                self.ledger.load('ov')
        olds = sorted(self.root.glob('ov.dispatch-open.*.old'))
        self.assertEqual(len(olds), 1, olds)
        self.assertEqual(list(self.root.glob('other.dispatch-open.*.old')), [])


class WiringAndDocs(unittest.TestCase):
    def test_install_wires_dispatch(self):
        sys.path.insert(0, str(ROOT))
        import install
        hooks = install.managed_hooks(Path('/h/.claude'))
        groups = [g for g in hooks.get('PostToolUse', [])
                  if any('tier_gate.py' in json.dumps(h) for h in g['hooks'])]
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]['matcher'], 'Agent|Task|SendMessage')
        [hook] = groups[0]['hooks']
        self.assertIn('dispatch', json.dumps(hook))
        self.assertNotIn('onFailure', hook)
        manifest = json.loads((HOOKS / 'hooks_manifest.json').read_text())
        entries = manifest if isinstance(manifest, list) else manifest.get('hooks', manifest.get('entries', []))
        [entry] = [e for e in entries if e.get('id') == 'tier_gate:dispatch']
        self.assertEqual(entry['event'], 'PostToolUse')

    def test_install_copies_before_settings(self):
        """A partial install must never leave new settings pointing at an old tier_gate.py: scripts are written first."""
        sys.path.insert(0, str(ROOT))
        import install
        order = []
        real = install.atomic_write

        def spy(path, *args, **kwargs):
            order.append(Path(path).name)
            return real(path, *args, **kwargs)
        with tempfile.TemporaryDirectory() as home, mock.patch.object(install, 'atomic_write', spy):
            install.install(Path(home), apply=True)
        self.assertIn('tier_gate.py', order)
        self.assertIn('settings.json', order)
        self.assertLess(order.index('tier_gate.py'), order.index('settings.json'))
        self.assertLess(order.index('escalation.py'), order.index('settings.json'))

    def test_docs_mention_dispatch(self):
        reference = (ROOT / 'docs/harness-reference.md').read_text()
        operations = (ROOT / 'docs/operations.md').read_text()
        line = reference[reference.index('`tier_gate.py`'):][:1500]
        for word in ('PostToolUse', 'SubagentStop', 'Workflow'):
            self.assertIn(word, line)
        section = operations[operations.index('Dispatch records'):operations.index('## Review and rescue')]
        for word in ('excluded_below_rung', 'counted_requested_below', 'window_dispatches', '24 hours',
                     'dispatch_narrow_by_stop_effort', 'dispatch_exclude_below_rung', 'would_exclude', 'main',
                     'ASSUMPTION'):
            self.assertIn(word, section)


if __name__ == '__main__':
    unittest.main()
