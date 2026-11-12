"""Dispatch records (GoodQA goodqa#15794, pi-dev-port H17): what a spawn actually ran on, and failures by
below-rung owner runs no longer climbing the model ladder. Spec: h17-spec-r3 (core 107b8cb8)."""

import hashlib
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

SONNET, OPUS, HAIKU = 'claude-sonnet-4-5', 'claude-opus-5-5', 'claude-haiku-4-5'


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
        self.ledger = esc.Ledger(self.root, self.policy)
        env = mock.patch.dict(os.environ, {'AGENT_HARNESS_ESCALATION_DIR': str(self.root)})
        env.start(); self.addCleanup(env.stop)
        self.salt = 0

    # -- ledger helpers (in process)
    def fail(self, task):
        self.salt += 1
        return self.ledger.record(task, final('%s-%d' % (task, self.salt)), kind='review', source='test')

    def climb_to(self, task, rung):
        while self.ledger.status(task)['rung'] != rung:
            self.fail(task)
            self.assertLess(self.salt, 40, 'ladder did not reach ' + rung)

    def owner(self, task, tool_use_id, model, *, subagent_type='task-owner', status='async_launched', agent_id=None,
              models_used=None, close=True, kind='agent'):
        self.ledger.open_dispatch(task, {'tool_use_id': tool_use_id, 'subagent_type': subagent_type, 'kind': kind,
                                         'owner': gate.counts_as_owner(subagent_type, self.policy) if kind == 'agent' else False,
                                         'requested': {'model': 'sonnet', 'effort': None},
                                         'selected': {'model': 'sonnet', 'effort': None}})
        if close:
            self.ledger.close_dispatch(task, tool_use_id, status=status, agent_id=agent_id or ('ag' + tool_use_id),
                                       resolved_model=model, models_used=models_used or [])

    # -- hook helpers (subprocess, the installed entry points)
    def policy_file(self, mode):
        policy = dict(self.policy); policy['mode'] = mode
        path = Path(self.temp.name) / ('tiers-%s.json' % mode)
        path.write_text(json.dumps(policy))
        return path

    def hook(self, action, data, mode='warn', raw=None):
        env = {**os.environ, 'AGENT_HARNESS_TIER_POLICY': str(self.policy_file(mode)),
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

    def dispatches(self, task):
        return self.ledger.load(task).get('dispatches', [])

    def gate_lines(self):
        path = self.root / 'gate.jsonl'
        return [json.loads(l) for l in path.read_text().splitlines()] if path.exists() else []


class OpenAndClose(Fixture):
    def test_open_then_close_async(self):
        self.climb_to('k1', 'R2')
        self.pre('work [task:k1] [rung-below:probe]')
        opened = self.dispatches('k1')
        self.assertEqual(len(opened), 1)
        self.assertEqual((opened[0]['phase'], opened[0]['tool_use_id'], opened[0]['owner']), ('open', 'tu1', True))
        self.assertIn('selected', opened[0])
        result = self.post('work [task:k1] [rung-below:probe]')
        self.assertEqual(result.stdout.strip(), '')
        [d] = self.dispatches('k1')
        self.assertEqual((d['phase'], d['agent_id'], d['resolved_model']), ('closed', 'a1b2c3', SONNET))
        self.assertEqual((d['candidates'], d['match']), (['R0'], 'below'))
        self.assertNotIn('ended_at', d)  # a background agent is still running after its launch returns
        self.assertTrue(any(l.get('decision') == 'dispatch' for l in self.gate_lines()))

    def test_completed_union_models_used_no_content(self):
        self.climb_to('k2', 'R2')
        self.pre('work [task:k2]', model='opus', effort='high')
        many = [SONNET, OPUS] + ['claude-sonnet-4-%d' % i for i in range(20)]
        self.post('work [task:k2]', status='completed', resolved=SONNET, models_used=many, model='opus',
                  extra={'content': [{'type': 'text', 'text': 'SECRET_RESULT_TEXT'}], 'usage': {'input_tokens': 7},
                         'totalTokens': 9})
        [d] = self.dispatches('k2')
        self.assertEqual(d['candidates'], ['R0', 'R1', 'R2', 'R3', 'R4'])
        self.assertEqual(d['match'], 'match')
        self.assertLessEqual(len(d['models_used']), 8)
        self.assertIn('ended_at', d)  # a completed foreground run has ended
        text = (self.root / 'k2.json').read_text()
        self.assertNotIn('SECRET_RESULT_TEXT', text)
        self.assertNotIn('input_tokens', text)


class Counting(Fixture):
    def test_below_rung_fail_not_counted(self):
        self.climb_to('k3', 'R2')
        self.owner('k3', 'tu1', SONNET)
        for _ in range(3):
            status = self.fail('k3')
            self.assertEqual(status['event']['class'], 'NOT_COUNTED')
            self.assertTrue(status['event']['why'].startswith('dispatched below rung'), status['event']['why'])
        self.assertEqual(self.ledger.status('k3')['rung'], 'R2')

    def test_control_climbs_to_r3(self):
        self.climb_to('k4', 'R2')
        for _ in range(2):
            self.assertEqual(self.fail('k4')['event']['class'], 'FAIL')
        self.assertEqual(self.ledger.status('k4')['rung'], 'R3')

    def test_window_cases_keep_counting(self):
        cases = {
            'a': lambda t: (self.owner(t, 'o1', OPUS), None),  # a live opus owner launched before the window
            'b': lambda t: (self.owner(t, 'o2', SONNET), self.owner(t, 'o3', SONNET, close=False)),
            'c': lambda t: [self.owner(t, 'h%d' % i, SONNET, subagent_type=kind)
                            for i, kind in enumerate(('Explore', 'Plan', 'fixer', 'red-team'))],
            'd': lambda t: self.owner(t, 'u1', HAIKU),
            'e': lambda t: self.owner(t, 'm1', OPUS),
        }
        for name, setup in cases.items():
            with self.subTest(case=name):
                task = 'kw' + name
                if name == 'a':
                    self.owner(task, 'o1', OPUS)  # before the climb: outside the window but still live
                    self.climb_to(task, 'R2')
                    self.owner(task, 'o1b', SONNET)
                else:
                    self.climb_to(task, 'R2')
                    setup(task)
                self.assertEqual(self.fail(task)['event']['class'], 'FAIL')
                self.assertEqual(self.fail(task)['event']['class'], 'FAIL')
                self.assertEqual(self.ledger.status(task)['rung'], 'R3')


class StatusAndCompat(Fixture):
    def test_status_shows_exclusions(self):
        self.climb_to('k5', 'R2')
        self.owner('k5', 'tu1', SONNET)
        self.fail('k5')
        status = self.ledger.status('k5')
        self.assertEqual(status['last_dispatch']['resolved_model'], SONNET)
        self.assertEqual(status['excluded_below_rung']['count'], 1)
        self.assertIn('dispatched below rung', status['excluded_below_rung']['latest']['reason'])
        self.assertEqual(status['below_rung_dispatches'], 1)
        out = subprocess.run([sys.executable, str(HOOKS / 'escalation.py'), '--root', str(self.root), 'status',
                              '--task', 'k5'], capture_output=True, text=True, timeout=30)
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertEqual(json.loads(out.stdout)['excluded_below_rung']['count'], 1)

    def test_old_ledger_without_dispatches(self):
        self.climb_to('k6', 'R1')
        path = self.root / 'k6.json'
        state = json.loads(path.read_text()); state.pop('dispatches', None)
        path.write_text(json.dumps(state)); os.chmod(path, 0o600)
        status = self.ledger.status('k6')
        self.assertIsNone(status['last_dispatch'])
        self.assertEqual(status['excluded_below_rung']['count'], 0)
        self.assertEqual(self.fail('k6')['event']['class'], 'FAIL')


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
            result = self.hook('dispatch', data)
            self.assertEqual(result.stdout.strip(), '')
        self.assertEqual(self.hook('dispatch', None, raw='not json').stdout.strip(), '')
        self.assertEqual(self.hook('dispatch', None, raw='{"a": "' + 'x' * (5 << 20) + '"}').stdout.strip(), '')
        for d in self.dispatches('kh'):
            self.assertLessEqual(len(json.dumps(d)), 2048)
            self.assertTrue(d.get('agent_id') is None or re.fullmatch(r'[A-Za-z0-9_-]{1,64}', d['agent_id']))
        # an unreadable tier table: still silent, exit 0, and decide_spawn / the owner scan never run
        env = {**os.environ, 'AGENT_HARNESS_TIER_POLICY': str(Path(self.temp.name) / 'missing.json')}
        result = subprocess.run([sys.executable, str(HOOKS / 'tier_gate.py'), 'dispatch'], input=json.dumps(hostile[2]),
                                capture_output=True, text=True, timeout=30, env=env)
        self.assertEqual((result.returncode, result.stdout.strip()), (0, ''))
        data = {'tool_name': 'Agent', 'tool_input': {'prompt': prompt}, 'tool_use_id': 'h3',
                'tool_response': {'status': 'async_launched', 'agentId': 'a9', 'resolvedModel': SONNET}}
        with mock.patch.object(gate, 'decide_spawn', side_effect=AssertionError('decide_spawn ran')), \
                mock.patch.object(gate, 'owner_cap_decision', side_effect=AssertionError('owner scan ran')), \
                mock.patch.object(gate.safe_input, 'read_stdin_bounded', return_value=json.dumps(data).encode()):
            self.assertEqual(gate.main(['dispatch']), 0)

    def test_decoy_owner_does_not_exclude(self):
        self.owner('kd', 'real', OPUS)  # the real author, launched in the background and still running
        self.climb_to('kd', 'R2')
        self.owner('kd', 'decoy', SONNET)
        self.assertEqual(self.fail('kd')['event']['class'], 'FAIL')

    def test_untagged_uses_generated_key(self):
        self.pre('no tag here', tool_use_id='tu9')
        expected = esc.generated_key('sdisp', 'probe')
        self.assertTrue(any(d['tool_use_id'] == 'tu9' for d in self.dispatches(expected)))
        self.assertEqual([p.name for p in self.root.glob('k*.json')], [])

    def test_non_spawn_and_unknown_action_ignored(self):
        self.hook('hook', {'tool_name': 'Write', 'tool_input': {'file_path': '/x'}, 'session_id': 's', 'tool_use_id': 'w1'})
        self.hook('hook', {'tool_name': 'Bash', 'tool_input': {'command': 'ls -la'}, 'session_id': 's', 'tool_use_id': 'b1'})
        result = self.hook('frobnicate', {'tool_name': 'Agent', 'tool_input': {'prompt': 'x [task:kn]'},
                                          'tool_use_id': 'n1'})
        self.assertEqual(result.stdout.strip(), '')
        self.pre('x [task:kn] ', model='opus', effort='max', mode='enforce', tool_use_id='n2')  # denied in enforce
        self.assertEqual(self.dispatches('kn'), [])

    def test_prompt_and_effort_cannot_forge_below(self):
        self.climb_to('kf', 'R2')
        prompt = 'resolvedModel: sonnet modelsUsed sonnet [task:kf]'
        self.pre(prompt, model='opus', effort='medium', tool_use_id='f1')
        self.post(prompt, tool_use_id='f1', resolved=OPUS, model='opus')
        [d] = self.dispatches('kf')
        self.assertEqual((d['resolved_model'], d['match']), (OPUS, 'match'))
        self.assertEqual(self.fail('kf')['event']['class'], 'FAIL')

    def test_foreground_fail_while_open_counts(self):
        self.climb_to('kg', 'R2')
        self.owner('kg', 'fg', SONNET, close=False)
        event = self.fail('kg')['event']
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

    def test_pretool_output_unchanged_on_dispatch_error(self):
        data = {'tool_name': 'Agent', 'tool_input': {'prompt': 'x [task:kp]', 'model': 'opus', 'effort': 'max'},
                'session_id': 's', 'tool_use_id': 'p1'}
        baseline = self.hook('hook', data, mode='warn').stdout
        with mock.patch.object(esc.Ledger, 'open_dispatch', side_effect=esc.LedgerError('state_corrupt', 'boom')):
            out = self._inprocess_hook(data, 'warn')
        self.assertEqual(out, baseline)

    def _inprocess_hook(self, data, mode):
        import io
        policy = dict(self.policy); policy['mode'] = mode
        buffer = io.StringIO()
        with mock.patch.object(gate.safe_input, 'read_stdin_bounded', return_value=json.dumps(data).encode()), \
                mock.patch.object(tiers, 'load_policy', return_value=policy), mock.patch('sys.stdout', buffer):
            self.assertEqual(gate.main(['hook']), 0)
        return buffer.getvalue()

    def test_dispatch_bound_and_near_full_ledger(self):
        for i in range(200):
            self.owner('kb', 'b%03d' % i, SONNET, status='completed')
        ds = self.dispatches('kb')
        self.assertEqual(len(ds), esc.MAX_DISPATCHES)
        self.assertEqual(ds[-1]['tool_use_id'], 'b199')
        # eviction removes ended or stale records before any live one
        self.owner('kv', 'live-opus', OPUS)
        for i in range(esc.MAX_DISPATCHES + 10):
            self.owner('kv', 'e%03d' % i, SONNET, status='completed')
        self.assertTrue(any(d['tool_use_id'] == 'live-opus' for d in self.dispatches('kv')))
        # a near-full ledger: 4,000 events plus 64 dispatches with per-event checks stays under MAX_STATE
        state = self.ledger.load('kb')
        state['events'] = [{'seq': n + 1, 'at': esc.now(), 'kind': 'review', 'class': 'NOT_COUNTED', 'why': 'x' * 40,
                            'fingerprint': None, 'receipt_sha256': '%064x' % n, 'source': 'test', 'head': None,
                            'rung_at': 'R0', 'dispatch_check': {'decision': 'counted', 'ids': ['b%03d' % i for i in range(4)],
                                                                'models': [SONNET] * 4}} for n in range(4000)]
        self.assertLess(len(json.dumps(state, separators=(',', ':'))), esc.MAX_STATE)

    def test_stale_open_dispatch(self):
        self.owner('ks', 'old', OPUS)  # live opus owner
        self.climb_to('ks', 'R2')
        self.owner('ks', 'new', SONNET)
        self.assertEqual(self.fail('ks')['event']['class'], 'FAIL')
        later = time.time() + esc.DISPATCH_LIVE_SECONDS + 60
        with mock.patch.object(esc, 'epoch', return_value=later):
            self.assertEqual(self.fail('ks')['event']['class'], 'NOT_COUNTED')  # the opus run is presumed ended

    def test_review_mark_does_not_hide_owner(self):
        self.climb_to('kr', 'R2')
        self.pre('[review:self] work [task:kr]', model='opus', effort='high', tool_use_id='r1')
        self.post('[review:self] work [task:kr]', tool_use_id='r1', resolved=OPUS, model='opus')
        self.owner('kr', 'r2', SONNET)
        [first] = [d for d in self.dispatches('kr') if d['tool_use_id'] == 'r1']
        self.assertTrue(first['owner'])
        self.assertEqual(self.fail('kr')['event']['class'], 'FAIL')

    def test_live_background_owner_blocks_exclusion(self):
        self.owner('k9', 'opus-bg', OPUS, agent_id='agopus')
        self.owner('k9', 'sonnet-gp', SONNET, subagent_type='general-purpose')
        self.climb_to('k9', 'R2')
        self.owner('k9', 'sonnet-2', SONNET)
        self.assertEqual(self.fail('k9')['event']['class'], 'FAIL')
        self.climb_to('k9', 'R2')  # still R2 after one failure
        # SubagentStop for the opus agent ends its dispatch; the next failure is then excluded
        self.hook('stop', {'agent_id': 'agopus', 'agent_type': 'task-owner', 'session_id': 'sdisp',
                           'hook_event_name': 'SubagentStop'})
        [opus] = [d for d in self.dispatches('k9') if d['tool_use_id'] == 'opus-bg']
        self.assertIn('ended_at', opus)
        self.ledger.end_dispatch('k9', 'agsonnet-gp')
        self.assertEqual(self.fail('k9')['event']['class'], 'NOT_COUNTED')

    def test_warn_deny_spawn_opens_dispatch(self):
        self.climb_to('kx', 'R2')
        self.pre('work [task:kx]', model='opus', effort='max', mode='warn', tool_use_id='x1')  # would deny, still runs
        [d] = self.dispatches('kx')
        self.assertEqual(d['phase'], 'open')
        self.owner('kx', 'x2', SONNET)
        self.assertEqual(self.fail('kx')['event']['class'], 'FAIL')

    def test_workflow_and_bash_dispatch_block_exclusion(self):
        self.climb_to('ky', 'R2')
        self.pre('flow [task:ky]', tool='Workflow', model=None, subagent_type='', tool_use_id='y1')
        self.hook('hook', {'tool_name': 'Bash', 'tool_input': {'command': 'codex exec --task kz "build it"'},
                           'session_id': 's', 'tool_use_id': 'z1'})
        self.climb_to('kz', 'R2')
        for task in ('ky', 'kz'):
            with self.subTest(task=task):
                kinds = {d.get('kind') for d in self.dispatches(task)}
                self.assertTrue(kinds & {'workflow', 'bash'}, kinds)
                self.owner(task, 's-' + task, SONNET)
                self.assertEqual(self.fail(task)['event']['class'], 'FAIL')

    def test_reset_keeps_dispatches(self):
        self.owner('kz2', 'opus-live', OPUS)
        self.ledger.reset('kz2', 'state_corrupt', 'test reset')
        self.assertTrue(any(d['tool_use_id'] == 'opus-live' for d in self.dispatches('kz2')))


class Index(Fixture):
    def test_index_is_private_bounded_and_corruption_is_a_noop(self):
        for i in range(600):
            esc.index_agent(self.root, 'ag%04d' % i, 'kidx')
        path = self.root / 'dispatch_index.json'
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
        index = json.loads(path.read_text())
        self.assertEqual(len(index), esc.INDEX_LIMIT)
        self.assertIn('ag0599', index)
        self.assertNotIn('ag0000', index)
        path.write_text('{not json')
        result = self.hook('stop', {'agent_id': 'ag0599', 'agent_type': 'task-owner', 'session_id': 's'})
        self.assertEqual(result.stdout.strip(), '')
        path.write_text(json.dumps({'ag1': '../../etc/passwd'}))
        self.hook('stop', {'agent_id': 'ag1', 'agent_type': 'task-owner', 'session_id': 's'})
        self.assertFalse((self.root.parent / 'etc').exists())


class WiringAndDocs(unittest.TestCase):
    def test_install_wires_dispatch(self):
        sys.path.insert(0, str(ROOT))
        import install
        hooks = install.managed_hooks(Path('/h/.claude'))
        groups = [g for g in hooks.get('PostToolUse', [])
                  if any(str(h.get('args', [''])[0]).endswith('tier_gate.py') for h in g['hooks'])]
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]['matcher'], 'Agent|Task')
        [hook] = groups[0]['hooks']
        self.assertEqual(hook['args'][1], 'dispatch')
        self.assertNotIn('onFailure', hook)
        manifest = json.loads((HOOKS / 'hooks_manifest.json').read_text())
        entries = manifest if isinstance(manifest, list) else manifest.get('hooks', manifest.get('entries', []))
        [entry] = [e for e in entries if e.get('id') == 'tier_gate:dispatch']
        self.assertEqual((entry['event'], entry['arg'], entry['flavors']), ('PostToolUse', 'dispatch', ['claude']))

    def test_install_copies_before_settings(self):
        sys.path.insert(0, str(ROOT))
        import install
        source = (ROOT / 'install.py').read_text()
        body = source[source.index('def install('):]
        body = body[:body.index('\ndef ', 10)]
        copy_at = min(i for i in (body.find('copy'), body.find('hooks_dir')) if i != -1)
        settings_at = body.find('settings.json')
        self.assertNotEqual(settings_at, -1)
        self.assertLess(copy_at, settings_at)

    def test_docs_mention_dispatch(self):
        reference = (ROOT / 'docs/harness-reference.md').read_text()
        operations = (ROOT / 'docs/operations.md').read_text()
        self.assertIn('PostToolUse', reference[reference.index('`tier_gate.py`'):][:800])
        self.assertIn('Workflow', reference[reference.index('`tier_gate.py`'):][:1200])
        self.assertIn('Dispatch records', operations)
        self.assertIn('excluded_below_rung', operations)


if __name__ == '__main__':
    unittest.main()
