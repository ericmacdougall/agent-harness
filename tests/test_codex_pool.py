"""Focused tests for harness/hooks/codex_pool.py using a fake codex, a fake gcloud and a fake API server.

Set CODEX_POOL_UNDER_TEST to a mutated copy of codex_pool.py to prove the tests fail against a broken variant.
"""
import http.server
import json
import os
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOOKS = ROOT / 'harness' / 'hooks'
SCRIPT = Path(os.environ.get('CODEX_POOL_UNDER_TEST') or HOOKS / 'codex_pool.py')
REAL_POLICY = json.loads((HOOKS / 'codex_pool_policy.json').read_text())

FAKE_CODEX = r'''#!/usr/bin/env python3
import json, os, sys, time
log = os.environ.get('FAKE_LOG')
args = sys.argv[1:]
if log:
    with open(log, 'a') as h:
        h.write(json.dumps({'argv': args, 'env': dict(os.environ), 'cwd_home': os.environ.get('CODEX_HOME')}) + '\n')
home = os.environ.get('CODEX_HOME')
prompt = sys.stdin.read()
key = os.environ.get('CODEX_API_KEY', '')
if key:
    if os.environ.get('FAKE_MODE_DIR_CHECK'):
        mode = os.stat(home).st_mode & 0o777
        open(os.environ['FAKE_MODE_DIR_CHECK'], 'w').write(oct(mode))
    if 'BAD401' in key:
        print(json.dumps({'type': 'error', 'message': 'Incorrect API key provided (invalid_api_key) 401'}))
        sys.exit(1)
    if 'RESTRICTED' in key:
        print(json.dumps({'type': 'error', 'message': 'codex_byok_restricted_by_api_credit_promo: cannot be used for Codex'}))
        sys.exit(1)
    if 'NOQUOTA' in key:
        print(json.dumps({'type': 'error', 'message': 'You exceeded your current quota (insufficient_quota)'}))
        sys.exit(1)
else:
    mode = os.environ.get('FAKE_SUB', 'ok')
    if mode == 'limit':
        print(json.dumps({'type': 'error', 'message': 'You have hit your usage limit. Try again at Nov 9th, 7:37 PM.'}))
        sys.exit(1)
if os.environ.get('FAKE_ECHO_KEY'):
    import base64
    print('leak: ' + key)
    print('b64: ' + base64.b64encode(key.encode()).decode() + ' rev: ' + key[::-1] + ' hex: ' + key.encode().hex())
    sys.stderr.write('leak-err: ' + key + '\n')
if os.environ.get('FAKE_SLEEP_MARK'):
    open(os.environ['FAKE_SLEEP_MARK'], 'w').write('started')
if os.environ.get('FAKE_SLEEP'):
    time.sleep(float(os.environ['FAKE_SLEEP']))
if os.environ.get('FAKE_STDERR_401'):
    sys.stderr.write('request failed: 401 unauthorized billing rate limit\n')
    print(json.dumps({'type': 'item.completed', 'item': {'type': 'agent_message', 'text': 'did work'}}))
    sys.exit(1)
if os.environ.get('FAKE_NO_JSON'):
    print('plain text answer')
    sys.exit(0)
if os.environ.get('FAKE_CRASH'):
    sys.exit(1)
usage = {'input_tokens': 1000, 'cached_input_tokens': 0, 'output_tokens': int(os.environ.get('FAKE_OUT', '100'))}
print(json.dumps({'type': 'turn.completed', 'usage': usage}))
'''

FAKE_GCLOUD = r'''#!/usr/bin/env python3
import os, sys
secret = [a for a in sys.argv if a.startswith('--secret=')][0].split('=', 1)[1]
alias = secret.replace('openai-codex-key-', '')
with open(os.environ['FAKE_GCLOUD_LOG'], 'a') as h:
    h.write(alias + '\n')
prefix = 'sk-RESTRICTED' if 'restricted' in alias else 'sk-BAD401' if 'bad' in alias else ('sk-NOQUOTA' if 'noquota' in alias else 'sk-GOOD')
sys.stdout.write(prefix + 'xxxxxxxxxxxxxxxxxxxxxxxx' + alias.replace('-', '') + 'SECRETTAIL\n')
'''


def make_exec(path, body):
    path.write_text(body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


class Base(unittest.TestCase):
    aliases = ['aaa', 'bbb']

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = Path(self.tmp.name)
        self.t = t
        for name in ('home', 'state', 'tmp', 'sub'):
            (t / name).mkdir()
        self.codex, self.gcloud = t / 'codex', t / 'gcloud'
        make_exec(self.codex, FAKE_CODEX)
        make_exec(self.gcloud, FAKE_GCLOUD)
        self.codex_log, self.gcloud_log = t / 'codex.log', t / 'gcloud.log'
        self.policy = json.loads(json.dumps(REAL_POLICY))
        self.policy['keys'] = [{'alias': a, 'enabled': True} for a in self.aliases]
        self.env_extra = {}

    def tearDown(self):
        self.tmp.cleanup()

    def write_policy(self):
        (self.t / 'policy.json').write_text(json.dumps(self.policy))

    def env(self, **extra):
        self.write_policy()
        env = {'PATH': '/usr/bin:/bin', 'HOME': str(self.t / 'home'), 'TMPDIR': str(self.t / 'tmp'),
               'CODEX_POOL_STATE_DIR': str(self.t / 'state'), 'CODEX_POOL_POLICY': str(self.t / 'policy.json'),
               'CODEX_POOL_CODEX_BIN': str(self.codex), 'CODEX_POOL_GCLOUD_BIN': str(self.gcloud),
               'FAKE_LOG': str(self.codex_log), 'FAKE_GCLOUD_LOG': str(self.gcloud_log),
               'AGENT_HARNESS_ESCALATION_DIR': str(self.t / 'esc')}
        env.update(self.env_extra)
        env.update(extra)
        return env

    def pool(self, *args, stdin='prompt text', **extra):
        return subprocess.run([sys.executable, '-I', str(SCRIPT), *args], input=stdin, capture_output=True, text=True,
                              env=self.env(**extra), timeout=60)

    def run_review(self, model='gpt-6.1-terra', *more, **extra):
        return self.pool('run', '--purpose', 'review', '--model', model, '--effort', 'medium', '--keys-only', *more,
                         '--', 'exec', '--json', '-', **extra)

    def ledger(self):
        path = self.t / 'state' / 'ledger.jsonl'
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def codex_calls(self):
        return [json.loads(line) for line in self.codex_log.read_text().splitlines()] if self.codex_log.exists() else []

    def gcloud_calls(self):
        return self.gcloud_log.read_text().split() if self.gcloud_log.exists() else []


class KeyHandling(Base):
    def test_key_never_in_argv_env_output_ledger_state_and_home_removed(self):
        result = self.run_review(FAKE_ECHO_KEY='1', FAKE_MODE_DIR_CHECK=str(self.t / 'mode.txt'))
        self.assertEqual(result.returncode, 0, result.stderr)
        key_part = 'SECRETTAIL'
        self.assertEqual(len(self.codex_calls()), 1)  # a single exec: no login step and no key file
        for call in self.codex_calls():
            self.assertNotIn(key_part, json.dumps(call['argv']))
            holders = [name for name, value in call['env'].items() if key_part in value]
            self.assertEqual(holders, ['CODEX_API_KEY'])  # only the one child env var, nothing else
        for blob in (result.stdout, result.stderr,
                     (self.t / 'state' / 'ledger.jsonl').read_text(),
                     (self.t / 'state' / 'state.json').read_text() if (self.t / 'state' / 'state.json').exists() else ''):
            self.assertNotIn(key_part, blob)
        self.assertIn('[REDACTED]', result.stdout)
        self.assertEqual((self.t / 'mode.txt').read_text(), '0o700')
        self.assertEqual(list((self.t / 'state' / 'homes').glob('codex-pool-home-*')), [])

    def test_passthrough_cannot_redirect_or_swap_model(self):
        for bad in (['exec', '--model', 'gpt-6-astra'], ['exec', '-c', 'model_provider=evil'], ['exec', '-cchatgpt_base_url=x'],
                    ['exec', '--config=openai_base_url=http://evil'], ['login', '--with-api-key'], ['exec', '-m', 'x']):
            result = self.pool('run', '--purpose', 'review', '--model', 'gpt-6.1-terra', '--keys-only', '--', *bad)
            self.assertEqual(result.returncode, 3, (bad, result.stderr))
        self.assertEqual(self.codex_calls(), [])
        self.assertEqual(self.gcloud_calls(), [])


class Rotation(Base):
    aliases = ['a-bad', 'aaa', 'bbb']

    def test_401_key_is_skipped_and_never_fetched_again(self):
        first = self.run_review()
        self.assertEqual(first.returncode, 0, first.stderr)
        state = json.loads((self.t / 'state' / 'state.json').read_text())
        self.assertEqual(state['keys']['a-bad']['health']['result'], '401')
        before = self.gcloud_calls().count('a-bad')
        self.assertEqual(before, 1)
        second = self.run_review()
        self.assertEqual(second.returncode, 0)
        self.assertEqual(self.gcloud_calls().count('a-bad'), before)

    def test_disabled_key_is_skipped_and_least_spent_wins(self):
        self.assertEqual(self.pool('disable', '--alias', 'a-bad').returncode, 0)
        self.assertEqual(self.run_review().returncode, 0)
        self.assertEqual(self.run_review().returncode, 0)
        self.assertNotIn('a-bad', self.gcloud_calls())
        self.assertEqual(sorted(set(self.gcloud_calls())), ['aaa', 'bbb'])  # alternates by spend

    def test_codex_restricted_key_is_skipped_and_enable_clears_mark(self):
        self.aliases = ['a-restricted', 'aaa']
        self.policy['keys'] = [{'alias': a, 'enabled': True} for a in self.aliases]
        self.assertEqual(self.run_review().returncode, 0)
        state = json.loads((self.t / 'state' / 'state.json').read_text())
        self.assertEqual(state['keys']['a-restricted']['health']['result'], 'codex-restricted')
        self.run_review()
        self.assertEqual(self.gcloud_calls().count('a-restricted'), 1)
        self.pool('enable', '--alias', 'a-restricted')
        state = json.loads((self.t / 'state' / 'state.json').read_text())
        self.assertNotIn('health', state['keys']['a-restricted'])

    def test_insufficient_quota_marks_key(self):
        self.aliases = ['a-noquota', 'aaa']
        self.policy['keys'] = [{'alias': a, 'enabled': True} for a in self.aliases]
        self.assertEqual(self.run_review().returncode, 0)
        state = json.loads((self.t / 'state' / 'state.json').read_text())
        self.assertEqual(state['keys']['a-noquota']['health']['result'], 'insufficient_quota')


class Caps(Base):
    def test_total_day_cap_refuses_without_launching(self):
        self.policy['caps_usd']['total_day'] = 1.0
        result = self.run_review()
        self.assertEqual(result.returncode, 3)
        self.assertIn('REFUSED', result.stderr)
        self.assertEqual(self.codex_calls(), [])
        self.assertEqual(self.ledger(), [])

    def test_per_key_cap_refuses(self):
        self.policy['caps_usd']['per_key_day'] = 1.0
        self.assertEqual(self.run_review().returncode, 3)
        self.assertEqual(self.codex_calls(), [])

    def test_reserve_above_per_run_cap_refused(self):
        self.policy['caps_usd']['per_run'] = 1.0
        self.assertEqual(self.run_review().returncode, 3)

    def test_unpriced_model_refused(self):
        self.assertEqual(self.run_review('gpt-9-mystery').returncode, 3)

    def test_concurrent_runs_cannot_overspend_total_cap(self):
        self.policy['caps_usd']['total_day'] = 3.0
        self.policy['caps_usd']['per_key_day'] = 3.0
        # 140000 output tokens at $10/M = $1.40 per run; two reserves of $1.50 fit under $3.00, a third cannot.
        with ThreadPoolExecutor(5) as pool:
            results = list(pool.map(lambda _: self.run_review(FAKE_OUT='140000', FAKE_SLEEP='0.6'), range(5)))
        ok = [r for r in results if r.returncode == 0]
        refused = [r for r in results if r.returncode == 3]
        self.assertEqual(len(ok) + len(refused), 5, [r.stderr for r in results])
        self.assertEqual(len(ok), 2)
        total = sum(row['usd'] for row in self.ledger() if row['type'] == 'settle')
        self.assertLessEqual(total, 3.0)
        self.assertAlmostEqual(total, 2.8, delta=0.02)

    def test_corrupt_ledger_fails_closed(self):
        (self.t / 'state' / 'ledger.jsonl').write_text('{not json\n')
        result = self.run_review()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.codex_calls(), [])


class Models(Base):
    def test_astra_refused_without_approve_top_and_allowed_with_it(self):
        refused = self.run_review('gpt-6-astra', '--task', 'task1')
        self.assertEqual(refused.returncode, 3, refused.stderr)
        self.assertEqual(self.codex_calls(), [])
        sys.path.insert(0, str(HOOKS))
        import escalation
        import model_tiers
        led = escalation.Ledger(root=self.t / 'esc', policy=model_tiers.load_policy())
        (self.t / 'esc').mkdir(mode=0o700, exist_ok=True)
        state = led.fresh('task1')
        state['permission'] = {'ask_id': 'x', 'wal': 'x', 'at': 'x', 'source': 'user:test'}
        led._write('task1', state)
        allowed = self.run_review('gpt-6-astra', '--task', 'task1')
        self.assertEqual(allowed.returncode, 0, allowed.stderr)

    def test_astra_refused_when_no_task(self):
        self.assertEqual(self.run_review('gpt-6-astra').returncode, 3)

    def test_daybreak_only_for_redteam_on_key_with_access(self):
        refused = self.pool('run', '--purpose', 'review', '--model', 'gpt-5.6-cyber', '--', 'exec', '-')
        self.assertEqual(refused.returncode, 3)
        none = self.pool('run', '--purpose', 'redteam', '--model', 'gpt-5.6-cyber', '--', 'exec', '-')
        self.assertEqual(none.returncode, 4)  # no key has probed access
        self.assertEqual(self.codex_calls(), [])
        state = {'schema': 1, 'subscription': {}, 'keys': {'bbb': {'probe': {'daybreak': ['gpt-5.6-cyber'], 'result': 'ok'}}}}
        (self.t / 'state' / 'state.json').write_text(json.dumps(state))
        granted = self.pool('run', '--purpose', 'redteam', '--model', 'gpt-5.6-cyber', '--', 'exec', '-')
        self.assertEqual(granted.returncode, 0, granted.stderr)
        self.assertEqual(self.gcloud_calls(), ['bbb'])


class Subscription(Base):
    def sub_env(self):
        (self.t / 'sub' / 'auth.json').write_text('{}')
        return {'CODEX_HOME': str(self.t / 'sub')}

    def test_subscription_is_first_and_keys_untouched(self):
        result = self.pool('run', '--purpose', 'review', '--model', 'gpt-6.1-terra', '--', 'exec', '--json', '-', **self.sub_env())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.gcloud_calls(), [])
        rows = self.ledger()
        self.assertEqual([r['alias'] for r in rows], ['subscription'])
        self.assertEqual(rows[0]['usd'], 0)

    def test_usage_limit_falls_back_to_key_and_blocks_subscription(self):
        env = {**self.sub_env(), 'FAKE_SUB': 'limit'}
        result = self.pool('run', '--purpose', 'review', '--model', 'gpt-6.1-terra', '--', 'exec', '--json', '-', **env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(self.gcloud_calls()), 1)
        state = json.loads((self.t / 'state' / 'state.json').read_text())
        self.assertTrue(state['subscription']['blocked_until'])
        calls_before = len(self.codex_calls())
        again = self.pool('run', '--purpose', 'review', '--model', 'gpt-6.1-terra', '--', 'exec', '--json', '-', **env)
        self.assertEqual(again.returncode, 0)
        new_calls = self.codex_calls()[calls_before:]
        self.assertTrue(all(c['cwd_home'] != str(self.t / 'sub') for c in new_calls))  # no subscription attempt while blocked

    def test_manual_block_and_clear(self):
        self.assertEqual(self.pool('subscription-block', '--until', '2999-01-01T00:00:00Z').returncode, 0)
        status = self.pool('status')
        self.assertIn('BLOCKED until 2999-01-01', status.stdout)
        self.pool('subscription-block', '--clear')
        self.assertIn('available', self.pool('status').stdout)


class Crash(Base):
    def test_ledger_row_settled_at_full_reserve_when_child_crashes(self):
        result = self.run_review(FAKE_CRASH='1')
        self.assertEqual(result.returncode, 1)
        rows = self.ledger()
        self.assertEqual([r['type'] for r in rows], ['reserve', 'settle'])
        self.assertEqual(rows[1]['usd'], rows[0]['usd'])  # unknown usage is never treated as free
        self.assertEqual(rows[1]['status'], 'failed_unknown_usage')

    def test_sigterm_mid_run_settles_and_removes_home(self):
        mark = self.t / 'mark'
        proc = subprocess.Popen([sys.executable, '-I', str(SCRIPT), 'run', '--purpose', 'review', '--model', 'gpt-6.1-terra',
                                 '--keys-only', '--', 'exec', '--json', '-'], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, env=self.env(FAKE_SLEEP='30', FAKE_SLEEP_MARK=str(mark)))
        proc.stdin.write('x')
        proc.stdin.close()
        for _ in range(100):
            if mark.exists():
                break
            time.sleep(0.1)
        self.assertTrue(mark.exists())
        proc.send_signal(signal.SIGTERM)
        self.assertEqual(proc.wait(timeout=20), 143)
        rows = self.ledger()
        self.assertEqual([r['type'] for r in rows], ['reserve', 'settle'])
        self.assertEqual(rows[1]['status'], 'terminated_unknown_usage')
        self.assertEqual(list((self.t / 'state' / 'homes').glob('codex-pool-home-*')), [])


class Hardening(Base):
    def test_encoded_key_forms_are_scrubbed(self):
        result = self.run_review(FAKE_ECHO_KEY='1')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('SECRETTAIL', result.stdout)
        self.assertNotIn('LIATTERCES', result.stdout)  # reversed tail
        self.assertNotIn('U0VDUkVUVEFJT', result.stdout)  # base64 of the tail
        self.assertNotIn('534543524554544149', result.stdout)  # hex of the tail
        self.assertNotIn('xxxxxxxxxxxxxxxxxxxxxxxx', result.stdout)

    def test_success_without_json_is_never_retried_or_free(self):
        result = self.pool('run', '--purpose', 'review', '--model', 'gpt-6.1-terra', '--keys-only', '--', 'exec', '-',
                           FAKE_NO_JSON='1')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(self.gcloud_calls()), 1)
        rows = self.ledger()
        self.assertEqual(rows[-1]['usd'], rows[0]['usd'])
        self.assertEqual(rows[-1]['status'], 'ok_no_usage')

    def test_stderr_prose_after_work_is_not_a_key_failure(self):
        result = self.run_review(FAKE_STDERR_401='1')
        self.assertEqual(result.returncode, 1)
        self.assertEqual(len(self.gcloud_calls()), 1)  # no retry on other keys
        self.assertFalse((self.t / 'state' / 'state.json').exists())  # no key was marked unhealthy
        rows = self.ledger()
        self.assertEqual(rows[-1]['usd'], rows[0]['usd'])

    def test_dangerous_passthrough_is_refused(self):
        for bad in (['exec', '--sandbox', 'danger-full-access', '-'], ['exec', '--dangerously-bypass-approvals-and-sandbox'],
                    ['exec', '--add-dir', '/'], ['exec', '-c', 'sandbox_workspace_write.network_access=true'],
                    ['exec', '-c', 'model_reasoning_effort=xhigh'], ['exec', '-c', 'review_model=gpt-6-astra'],
                    ['exec', 'review'], ['exec', '--full-auto'], ['exec', '-c', 'shell_environment_policy.inherit=all']):
            result = self.pool('run', '--purpose', 'review', '--model', 'gpt-6.1-terra', '--keys-only', '--', *bad)
            self.assertEqual(result.returncode, 3, (bad, result.stderr))
        self.assertEqual(self.codex_calls(), [])

    def test_refusal_prints_prose_usage_limit_record_for_json_callers(self):
        self.policy['caps_usd']['total_day'] = 1.0
        result = self.run_review()
        self.assertEqual(result.returncode, 3)
        record = json.loads(result.stdout.strip().splitlines()[-1])
        self.assertEqual(record['type'], 'error')
        self.assertNotIn('code', record)  # unstructured: callers may fall back but no account cooldown is placed
        self.assertIn('usage limit', record['message'])

    def test_group_writable_codex_binary_is_not_given_a_key(self):
        os.chmod(self.codex, 0o775)
        result = self.run_review()
        self.assertEqual(result.returncode, 4)
        self.assertEqual(self.gcloud_calls(), [])

    def test_termination_during_subscription_run_reaps_the_child(self):
        mark = self.t / 'submark'
        (self.t / 'sub' / 'auth.json').write_text('{}')
        env = self.env(FAKE_SLEEP='30', FAKE_SLEEP_MARK=str(mark), CODEX_HOME=str(self.t / 'sub'))
        proc = subprocess.Popen([sys.executable, '-I', str(SCRIPT), 'run', '--purpose', 'review', '--model', 'gpt-6.1-terra',
                                 '--', 'exec', '--json', '-'], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, env=env)
        proc.stdin.write('x')
        proc.stdin.close()
        for _ in range(100):
            if mark.exists():
                break
            time.sleep(0.1)
        self.assertTrue(mark.exists())
        proc.send_signal(signal.SIGTERM)
        self.assertEqual(proc.wait(timeout=20), 143)
        time.sleep(0.3)
        left = subprocess.run(['pgrep', '-f', 'FAKE_SLEEP_MARKER_NONE|' + str(self.codex)], capture_output=True, text=True)
        self.assertEqual(left.stdout.strip(), '')

    def test_probe_network_error_keeps_failure_mark(self):
        (self.t / 'state' / 'state.json').write_text(json.dumps(
            {'schema': 1, 'subscription': {}, 'keys': {'aaa': {'health': {'result': '401', 'at': 'x'}}}}))
        self.pool('probe', '--alias', 'aaa', CODEX_POOL_API_BASE='http://127.0.0.1:9')
        state = json.loads((self.t / 'state' / 'state.json').read_text())
        self.assertEqual(state['keys']['aaa']['health']['result'], '401')


class FakeApi(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        self.reply(*self.route())

    def do_POST(self):
        self.rfile.read(int(self.headers.get('Content-Length', 0)))
        self.reply(*self.route())

    def route(self):
        key = self.headers.get('Authorization', '')
        if 'BAD401' in key:
            return 401, {'error': {'code': 'invalid_api_key'}}
        if self.path == '/v1/models':
            return 200, {'data': [{'id': 'gpt-6.1-terra'}, {'id': 'gpt-6.1-sol'}, {'id': 'gpt-6-astra'}, {'id': 'other'}]}
        if self.path == '/v1/models/gpt-5.6-cyber':
            return (200, {'id': 'gpt-5.6-cyber'}) if 'DAYBREAK' in key else (404, {'error': {'code': 'model_not_found'}})
        if self.path.startswith('/v1/models/'):
            return 404, {'error': {'code': 'model_not_found'}}
        if self.path == '/v1/responses':
            if 'NOQUOTA' in key:
                return 429, {'error': {'code': 'insufficient_quota'}}
            return 200, {'usage': {'input_tokens': 8, 'output_tokens': 16}}
        return 404, {}

    def reply(self, status, body):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class Probe(Base):
    aliases = ['a-bad', 'aaa', 'a-noquota']

    def test_probe_records_results_and_daybreak_without_printing_keys(self):
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), FakeApi)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            result = self.pool('probe', CODEX_POOL_API_BASE='http://127.0.0.1:%d' % server.server_port)
        finally:
            server.shutdown()
        self.assertEqual(result.returncode, 0, result.stderr)
        state = json.loads((self.t / 'state' / 'state.json').read_text())
        self.assertEqual(state['keys']['a-bad']['probe']['result'], '401')
        self.assertEqual(state['keys']['aaa']['probe']['result'], 'ok')
        self.assertEqual(state['keys']['aaa']['probe']['daybreak'], [])
        self.assertEqual(state['keys']['a-noquota']['probe']['result'], 'insufficient_quota')
        self.assertIn('gpt-6.1-sol', state['keys']['aaa']['probe']['relevant'])
        self.assertNotIn('SECRETTAIL', result.stdout + json.dumps(state))
        status = self.pool('status')
        self.assertEqual(status.returncode, 0)
        self.assertIn('401', status.stdout)
        self.assertNotIn('SECRETTAIL', status.stdout)


class Integration(Base):
    """peer_review / rescue launch through codex-pool only while the subscription is recorded as blocked."""

    def load(self):
        sys.path.insert(0, str(HOOKS))
        os.environ['CODEX_POOL_STATE_DIR'] = str(self.t / 'state')
        self.addCleanup(os.environ.pop, 'CODEX_POOL_STATE_DIR', None)
        import importlib
        import codex_pool
        import peer_review
        import rescue
        for module in (codex_pool, peer_review, rescue):
            importlib.reload(module)
        return codex_pool, peer_review, rescue

    def test_direct_launch_when_subscription_available_and_pool_launch_when_blocked(self):
        pool, review, rescue = self.load()
        direct = ['/bin/codex', 'exec', '--ephemeral', '--json', '--model', 'm', '-c', 'model_reasoning_effort=high', '--sandbox', 'read-only', '-']
        self.assertEqual(review.pool_launch(direct, '/bin/codex', 'm', 'high', None), direct)
        pool.mark_subscription_blocked('2999-01-01T00:00:00Z')
        pooled = review.pool_launch(direct, '/bin/codex', 'gpt-6.1-sol', 'high', 'task1')
        self.assertTrue(review._via_pool(pooled))
        tail = pooled[pooled.index('--') + 1:]
        self.assertEqual(tail, ['exec', '--ephemeral', '--json', '--sandbox', 'read-only', '-'])
        self.assertIn('--keys-only', pooled)
        self.assertEqual(pooled[pooled.index('--task') + 1], 'task1')
        spec = {'model': 'gpt-6.1-sol', 'effort': 'high'}
        self.assertTrue(rescue.launch_command('openai', spec, Path('/r'), Path('/l'), 't')[2].endswith('codex_pool.py'))
        pool.mark_subscription_blocked('2000-01-01T00:00:00Z')
        self.assertEqual(rescue.launch_command('openai', spec, Path('/r'), Path('/l'))[0], 'codex')

    def test_trusted_quota_failure_marks_subscription_blocked(self):
        pool, review, _ = self.load()
        self.assertFalse(pool.subscription_blocked())
        review.note_subscription_quota(None)
        self.assertTrue(pool.subscription_blocked())


if __name__ == '__main__':
    unittest.main()
