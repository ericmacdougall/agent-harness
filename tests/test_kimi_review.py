"""Failing-first tests for kimi_review.py (GoodQA goodqa#15201): egress gate, isolation, quota handling, headers.

KIMI_REVIEW_UNDER_TEST points the suite at a mutated copy so each control can be shown to fail when stubbed out.
"""
import hashlib
import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

DEFAULT = Path(__file__).resolve().parents[1] / 'harness/hooks/kimi_review.py'
KIMI = Path(os.environ.get('KIMI_REVIEW_UNDER_TEST') or DEFAULT)
HEAD = 'a' * 40
MODEL = 'kimi-code/k3.1-pro-highspeed'

CONFIG = '''default_model = "kimi-code/kimi-for-coding"
default_permission_mode = "auto"

[providers."managed:kimi-code"]
base_url = "https://api.kimi.ai/coding/v1"
type = "kimi"
api_key = "SENTINEL-APIKEY-IN-CONFIG"

[providers."managed:kimi-code".oauth]
storage = "file"
key = "oauth/kimi-code-env-test"
oauth_host = "https://auth.kimi.ai"

[models."kimi-code/k3.1-pro-highspeed"]
provider = "managed:kimi-code"
model = "k3.1-pro-highspeed"

[models."kimi-code/k3-256k"]
provider = "managed:kimi-code"
model = "k3-256k"

[[hooks]]
event = "TurnStarted"
command = "echo kimi-cu-plugin-hook"

[plugins."kimi-cu"]
enabled = true
'''

FAKE = '''import json, os, sys
from pathlib import Path
state = Path(os.environ['FAKE_STATE'])
argv = sys.argv[1:]
if argv == ['--version']:
    with (state / 'versions').open('a') as handle:
        handle.write('v\\n')
    print(os.environ.get('FAKE_VERSION', '2.5.9'))
    sys.exit(0)
with (state / 'launches').open('a') as handle:
    handle.write('launch\\n')
prompt = next(a for a in argv if a.startswith('--prompt='))[len('--prompt='):]
agent = Path(argv[argv.index('--agent-file') + 1]).read_text()
kimi_home = Path(os.environ['KIMI_CODE_HOME'])
(state / 'capture.json').write_text(json.dumps({
    'prompt': prompt, 'model': argv[argv.index('--model') + 1], 'agent': agent, 'cwd_entries': os.listdir(os.getcwd()),
    'format': argv[argv.index('--output-format') + 1], 'argv_flags': [a for a in argv if not a.startswith('--prompt=')],
    'env': dict(os.environ), 'config': (kimi_home / 'config.toml').read_text(),
    'cred_links': {n: os.path.islink(kimi_home / n) and os.readlink(kimi_home / n) for n in ('credentials', 'oauth', 'device_id')},
    'kimi_home_entries': sorted(os.listdir(kimi_home))}))
mode = os.environ.get('FAKE_MODE', 'ok')
if mode == 'quota':
    sys.stderr.write('Error: 429 rate limit: your plan quota is exhausted\\n'); sys.exit(1)
if mode == 'login':
    sys.stderr.write('Error: not logged in, run kimi login\\n'); sys.exit(1)
if mode == 'empty':
    sys.exit(0)
print(json.dumps({'role': 'meta', 'type': 'system.version', 'version': 'fake'}))
if mode == 'toolcall':
    print(json.dumps({'role': 'assistant', 'tool_calls': [{'type': 'function', 'id': 't1', 'function': {'name': 'Bash', 'arguments': '{}'}}]}))
    print(json.dumps({'role': 'tool', 'tool_call_id': 't1', 'content': 'ran'}))
print(json.dumps({'role': 'assistant', 'content': 'KIMI_ADVISORY: BLOCK\\nF1: fixture finding.'}))
print(json.dumps({'role': 'meta', 'type': 'session.resume_hint', 'session_id': 'session_fake-123', 'content': 'x'}))
'''


def load_module():
    sys.path.insert(0, str(KIMI.parent))
    spec = importlib.util.spec_from_file_location('kimi_review_under_test', KIMI)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class KimiReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.home = self.root / 'home'
        for private in ('.claude/wals/s', '.claude/projects/p', '.kimi-code/credentials', '.kimi-code/oauth',
                        '.codex', '.config/gh', '.claude/shell-snapshots', '.agent-harness/codex-wals'):
            (self.home / private).mkdir(parents=True)
        self.sentinel = 'SENTINEL-CRED-DO-NOT-LEAK-12345'
        (self.home / '.kimi-code' / 'credentials' / 'kimi-code.json').write_text(self.sentinel)
        (self.home / '.kimi-code' / 'oauth' / 'kimi-code-env-test').write_text(self.sentinel)
        (self.home / '.kimi-code' / 'device_id').write_text('device')
        (self.home / '.kimi-code' / 'config.toml').write_text(CONFIG)
        self.state = self.root / 'state'
        self.state.mkdir()
        self.fake = self.root / 'fakebin' / 'kimi'
        self.fake.parent.mkdir()
        self.fake.write_text('#!%s\n%s' % (sys.executable, FAKE))
        self.fake.chmod(0o700)
        self.work = self.root / 'work'
        self.work.mkdir()
        self.packet = self.work / 'packet.md'
        self.packet.write_text('Scope: review the handler change. Evidence: tests pass.\n')
        self.output = self.work / 'report.md'
        self.kimi_home = self.root / 'kimi-home'

    def launches(self):
        path = self.state / 'launches'
        return len(path.read_text().splitlines()) if path.exists() else 0

    def ledger_calls(self):
        path = self.kimi_home / 'ledger.jsonl'
        return len(path.read_text().splitlines()) if path.exists() else 0

    def run_kimi(self, *extra, packet=None, output=None, env=None, head=HEAD, cwd=None):
        environment = {**os.environ, 'HOME': str(self.home), 'KIMI_REVIEW_TEST_MODE': '1',
                       'KIMI_REVIEW_BIN': str(self.fake), 'KIMI_REVIEW_HOME': str(self.kimi_home),
                       'FAKE_STATE': str(self.state), 'AWS_SECRET_ACCESS_KEY': 'SENTINEL-ENV-SECRET',
                       'SOME_AGENT_TOKEN': 'SENTINEL-ENV-TOKEN', **(env or {})}
        command = [sys.executable, str(KIMI), '--packet', str(packet or self.packet),
                   '--output', str(output or self.output), *(['--head', head] if head else []), *extra]
        return subprocess.run(command, text=True, capture_output=True, env=environment, timeout=120, cwd=cwd)

    def capture(self):
        return json.loads((self.state / 'capture.json').read_text())

    def assertRefused(self, result, label=''):
        self.assertEqual(result.returncode, 3, '%s: %s%s' % (label, result.stdout, result.stderr))
        self.assertEqual(self.launches(), 0, '%s: kimi was launched despite refusal' % label)
        self.assertEqual(self.ledger_calls(), 0, '%s: a refused call was counted' % label)
        self.assertFalse(self.output.exists(), label)

    # -- happy path and report headers ------------------------------------------------------------

    def test_report_headers_state_that_it_is_advisory_packet_only_and_unranked(self):
        result = self.run_kimi()
        self.assertEqual(result.returncode, 0, result.stderr)
        report = self.output.read_text()
        sha = hashlib.sha256(self.packet.read_bytes()).hexdigest()
        for line in ('Reviewed-Model: ' + MODEL, 'Reviewer: ' + MODEL + ' (Kimi subscription, kimi-code CLI)',
                     'Reviewer-Rung: n/a', 'Review-Input: packet text only (no repository snapshot, no tools)',
                     'Advisory: yes; not a PR sign-off and never a pass marker',
                     'Reviewed-Packet-SHA256: ' + sha, 'Reviewed-HEAD: ' + HEAD,
                     'Request-Id: session_fake-123', 'Egress-Emails-Redacted: 0'):
            self.assertIn(line + '\n', report)
        for prefix in ('Tokens-In-Estimate: ', 'Tokens-Out-Estimate: ', 'Cost-USD: 0 (subscription'):
            self.assertIn(prefix, report)
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o600)
        self.assertEqual(self.launches(), 1)
        self.assertEqual(self.ledger_calls(), 1)

    def test_default_command_is_k31_pro_fast_and_never_requests_swarm(self):
        self.assertEqual(self.run_kimi().returncode, 0)
        capture = self.capture()
        self.assertEqual(capture['model'], MODEL)
        self.assertEqual(capture['format'], 'stream-json')
        self.assertNotIn('swarm', ' '.join(capture['argv_flags']).lower())
        self.assertNotIn('/swarm', capture['prompt'])
        self.assertNotIn('AgentSwarm', capture['agent'])

    def test_model_is_limited_to_kimi_code_aliases(self):
        self.assertRefused(self.run_kimi('--model', 'moonshotai/kimi-k3.1-pro'), 'model')
        ok = self.run_kimi('--model', 'kimi-code/k3-256k')
        self.assertEqual(ok.returncode, 0, ok.stderr)
        self.assertEqual(self.capture()['model'], 'kimi-code/k3-256k')

    def test_existing_output_is_preserved(self):
        self.output.write_text('stale')
        result = self.run_kimi()
        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.output.read_text(), 'stale')
        self.assertEqual(self.launches(), 0)

    # -- M2: tools disabled structurally, isolation, version pin ----------------------------------

    def test_agent_file_disables_every_tool_structurally(self):
        module = load_module()
        self.assertEqual(self.run_kimi().returncode, 0)
        self.assertEqual(module.agent_tools(self.capture()['agent']), [])
        # the structural parser rejects the shapes a substring check would accept
        self.assertNotEqual(module.agent_tools('---\ntools: ["*"]  # tools: []\n---\nbody'), [])
        self.assertIsNone(module.agent_tools('---\n# tools: []\nname: x\n---\nbody'))
        self.assertIsNone(module.agent_tools('---\ntools: []\ntools: ["*"]\n---\nbody'))
        self.assertNotEqual(module.agent_tools('---\ntools:\n  - Bash\n---\nbody'), [])

    def test_any_tool_activity_in_the_output_fails_closed(self):
        result = self.run_kimi(env={'FAKE_MODE': 'toolcall'})
        self.assertEqual(result.returncode, 6, result.stderr)
        self.assertIn('tool activity', result.stderr)
        self.assertFalse(self.output.exists())

    def test_child_gets_a_minimal_environment_and_scratch_home(self):
        self.assertEqual(self.run_kimi().returncode, 0)
        env = self.capture()['env']
        allowed = {'HOME', 'XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_CACHE_HOME', 'TMPDIR', 'PATH', 'LANG',
                   'KIMI_CODE_HOME', 'KIMI_CODE_NO_AUTO_UPDATE', 'KIMI_CLI_NO_AUTO_UPDATE',
                   'KIMI_LOOP_MAX_STEPS_PER_TURN', 'KIMI_LOOP_MAX_ATTEMPTS_PER_STEP',
                   'FAKE_STATE', 'FAKE_MODE', 'FAKE_VERSION', 'LC_CTYPE', '__CF_USER_TEXT_ENCODING'}
        self.assertEqual(sorted(set(env) - allowed), [])
        blob = json.dumps(env)
        self.assertNotIn('SENTINEL-ENV', blob)
        self.assertNotEqual(env['HOME'], str(self.home))
        self.assertNotIn(str(self.home), env['KIMI_CODE_HOME'])
        self.assertEqual(env['KIMI_LOOP_MAX_STEPS_PER_TURN'], '1')
        self.assertEqual(env['KIMI_LOOP_MAX_ATTEMPTS_PER_STEP'], '1')
        self.assertEqual(self.capture()['cwd_entries'], [])

    def test_scratch_config_carries_only_the_model_and_login_pointers(self):
        self.assertEqual(self.run_kimi().returncode, 0)
        capture = self.capture()
        config = capture['config']
        self.assertIn('[models."%s"]' % MODEL, config)
        self.assertIn('[providers."managed:kimi-code".oauth]', config)
        self.assertNotIn('k3-256k', config)
        for leaked in ('hooks', 'kimi-cu', 'plugins', 'SENTINEL-APIKEY', 'permission_mode = "auto"'):
            self.assertNotIn(leaked, config)
        self.assertIn('default_permission_mode = "manual"', config)
        self.assertTrue(all(capture['cred_links'][n] for n in ('credentials', 'oauth')))  # linked, not copied
        self.assertEqual(sorted(capture['kimi_home_entries']), ['config.toml', 'credentials', 'device_id', 'oauth'])

    def test_unsupported_cli_version_is_refused_before_the_call(self):
        result = self.run_kimi(env={'FAKE_VERSION': '3.0.1'})
        self.assertRefused(result, 'version')
        self.assertIn('3.0.1', result.stderr)

    # -- egress gate: paths -----------------------------------------------------------------------

    def test_sensitive_paths_are_refused(self):
        cases = {}
        for label, relative in {
                'wals': '.claude/wals/s/main.md', 'projects': '.claude/projects/p/notes.md',
                'claude json': '.claude.json', 'codex': '.codex/auth.md', 'gh': '.config/gh/hosts.md',
                'shell snapshots': '.claude/shell-snapshots/snap.md', 'denylist': '.agent-harness/leak-denylist.txt',
                'codex wals': '.agent-harness/codex-wals/w.md', 'kimi credentials': '.kimi-code/credentials/c.md',
                'upper claude': '.CLAUDE/Projects/p/m.md', 'upper ssh': '.SSH/config', 'mixed kimi': '.Kimi-Code/config.md'}.items():
            path = self.home / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            # the denylist file is itself a case; keep its body a comment so it never matches other files
            path.write_text('# comment only\n' if label == 'denylist' else 'ordinary harmless prose %s\n' % label)
            cases[label] = path
        jsonl = self.work / 'session.jsonl'
        jsonl.write_text('{"a":1}\n')
        cases['jsonl'] = jsonl
        for name in ('.env.local', 'my-secret-notes.md', 'api_token_list.md', 'deploy.pem', 'id_ed25519',
                     'login.keychain-db', 'session-transcript.md', 'granola-notes.md'):
            path = self.work / name
            path.write_text('x\n')
            cases[name] = path
        for label, path in cases.items():
            self.assertRefused(self.run_kimi('--snapshot', str(path)), label)
            self.assertRefused(self.run_kimi(packet=path), 'packet ' + label)

    def test_symlink_and_hard_link_into_private_files_are_refused(self):
        wal = self.home / '.claude' / 'wals' / 's' / 'main.md'
        wal.write_text('harmless words\n')
        link = self.work / 'innocent.md'
        link.symlink_to(wal)
        hard = self.work / 'hard.md'
        os.link(wal, hard)
        for label, path in {'symlink': link, 'hard link': hard}.items():
            self.assertRefused(self.run_kimi('--snapshot', str(path)), label + ' snapshot')
            self.assertRefused(self.run_kimi(packet=path), label + ' packet')

    def test_any_file_with_several_hard_links_is_refused(self):
        other = self.work / 'other.md'
        other.write_text('ordinary text\n')
        os.link(other, self.work / 'other-copy.md')
        self.assertRefused(self.run_kimi('--snapshot', str(other)), 'nlink')

    def test_directory_snapshot_refuses_a_sensitive_member(self):
        tree = self.work / 'tree'
        tree.mkdir()
        (tree / 'ok.py').write_text('print(1)\n')
        (tree / '.env').write_text('A=1\n')
        self.assertRefused(self.run_kimi('--snapshot', str(tree)), 'dir with .env')

    # -- egress gate: content ---------------------------------------------------------------------

    def test_secret_shapes_are_refused(self):
        samples = {
            'anthropic': 'key = sk-ant-api03-' + 'a1B2c3D4' * 4,
            'github': 'token ghp_' + 'A1b2C3d4E5' * 4,
            'aws': 'AKIA' + 'ABCDEFGHIJKLMNOP',
            'private key': '-----BEGIN OPENSSH PRIVATE KEY-----',
            'slack': 'xoxb-' + '1234567890-abcdefghij',
            'google': 'AIza' + 'SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6',
            'random base64': 'blob ' + 'Zk9xTf3Lw8Qp2Vn7RbYc4HsJm6Ud1GaXe5Ni0KoWt9Pz',
            'odd hex': 'digest ' + 'deadbeefcafebabe' * 2 + 'ab',
            'bearer': 'Authorization: Bearer ' + 'abcdefghij0123456789ABCDEFGH',
            'stripe': 'billing sk_live_' + '4eC39HqLyjWDarjtT1zdp7dc',
            'short key': 'cfg ' + 'kT9mQ2xLw8Rb5NvZc3HjP7sD',
            'password assignment': 'DB_PASSWORD=hunter2hunter2',
            'credential url': 'dsn postgres://app:pa55w0rd@db.internal:5432/app',
            'dropbox shape (redact.py only)': 'dbx sl.' + 'ghij' * 10 + 'gh',
            'base32 seed': 'otp ' + 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP',
            'split github token': 'tok ghp_' + 'A1b2C3d4E5\nF6g7H8i9J0' + 'k1L2m3N4o5',
            'split anthropic': 'sk-an\nt-' + 'api03aB1cD2eF3gH4iJ5',
        }
        for label, line in samples.items():
            self.packet.write_text('Evidence follows.\n%s\n' % line)
            result = self.run_kimi()
            self.assertRefused(result, label)
            for fragment in line.split()[-1:]:
                self.assertNotIn(fragment, result.stderr, label + ': refusal must not echo the match')

    def test_forbidden_topics_survive_unicode_tricks(self):
        cases = {'yates': 'the yates-cloud deploy', 'cyrillic': 'the yаtes deploy', 'zero width': 'the ya​tes deploy',
                 'fullwidth': 'the ｙａｔｅｓ deploy', 'dotted': 'the y.a.t.e.s deploy',
                 'apex': 'see apex_app_pos tables', 'apex dots': 'see apex.app.pos tables', 'apex slash': 'apex/app_pos',
                 'granola': 'from the Granola export', 'interview': 'Interview transcript for Dana',
                 'candidate interview': 'a candidate interview', 'solve': 'a Solve transcript excerpt',
                 'solve log': 'the Solve session log'}
        for label, line in cases.items():
            self.packet.write_text('Evidence.\n%s\n' % line)
            self.assertRefused(self.run_kimi(), label)

    def test_wal_and_transcript_shaped_json_is_refused_inside_any_file(self):
        shapes = {'wal': '{"at":"2026-11-08T00:00:00Z","event":"status","note":"did a thing","id":"w1"}',
                  'transcript': '{"parentUuid":null,"sessionId":"abc","type":"user","message":{"role":"user"}}'}
        for label, line in shapes.items():
            note = self.work / ('notes-%s.md' % label)
            note.write_text('Pasted from somewhere:\n%s\n' % line)
            self.assertRefused(self.run_kimi('--snapshot', str(note)), label)

    def test_private_leak_denylist_is_applied_and_fails_closed(self):
        denylist = self.home / '.agent-harness' / 'leak-denylist.txt'
        denylist.write_text('# comment\n(?x)zebra\\-quartz\\-77\n')
        self.packet.write_text('Evidence mentions zebra-quartz-77 here.\n')
        self.assertRefused(self.run_kimi(), 'denylist hit')
        self.packet.write_text('Clean evidence.\n')
        self.assertEqual(self.run_kimi().returncode, 0)
        denylist.write_text('(unclosed\n')
        self.output.unlink()
        broken = self.run_kimi()
        self.assertEqual(broken.returncode, 3, broken.stderr)
        self.assertIn('denylist', broken.stderr)

    def test_ordinary_text_and_user_work_instruction_quotes_are_allowed(self):
        self.packet.write_text('Reviewed by a test of the handler.\n'
                               'Source: user:baab765b-d85c-46b4-b7b9-588eb912c770/9f1c2d3e-aaaa-bbbb-cccc-1234567890ab '
                               '"use kimi 3.1 pro fast mode when you ask it for things"\n'
                               'Commit %s and sha256 %s in /Users/eric/.agent-harness/work/baab765b/'
                               'agent-a49cb658ed4738957/kimi-tool/some_long_snake_case_identifier_name.py\n'
                               % ('1f' * 20, 'ab' * 32))
        result = self.run_kimi()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_lockfiles_are_allowed_but_size_capped(self):
        tree = self.work / 'tree'
        tree.mkdir()
        line = '      "integrity": "sha512-%s",\n' % 'Zk9xTf3Lw8Qp2Vn7RbYc4HsJm6Ud1GaXe5Ni0KoWt9PzAq1Sw2De3Fr4Gt5Hy6Ju7Ki8Lo9=='
        (tree / 'package-lock.json').write_text(line * 20)
        self.assertEqual(self.run_kimi('--snapshot', str(tree)).returncode, 0)
        self.output.unlink()
        (self.state / 'launches').unlink()
        (self.kimi_home / 'ledger.jsonl').unlink()
        (tree / 'package-lock.json').write_text(line * 3000)  # over the 200 KB lockfile allowance
        self.assertRefused(self.run_kimi('--snapshot', str(tree)), 'oversize lockfile')

    def test_oversize_payload_is_refused(self):
        self.packet.write_text(('plain filler words\n' * 90000))
        self.assertGreater(self.packet.stat().st_size, 1_500_000)
        result = self.run_kimi()
        self.assertRefused(result, 'over 1.5 MB')
        self.assertIn('1500000', result.stderr)  # the 1.5 MB cap itself, not the narrower argv limit

    def test_payload_over_the_argument_limit_is_refused_before_launch(self):
        self.packet.write_text('plain filler words\n' * 40000)  # 760 KB: under 1.5 MB, over the argv limit
        self.assertRefused(self.run_kimi(), 'argv limit')

    def test_snapshot_collection_stops_at_the_cap_instead_of_reading_everything(self):
        tree = self.work / 'tree'
        tree.mkdir()
        for index in range(40):
            (tree / ('part%02d.txt' % index)).write_text(('ordinary filler words\n' * 5000))  # ~105 KB each
        started = time.monotonic()
        result = self.run_kimi('--snapshot', str(tree))
        self.assertRefused(result, 'stream cap')
        self.assertIn('exceeds', result.stderr)
        self.assertLess(time.monotonic() - started, 15)

    def test_long_runs_without_an_at_sign_do_not_trigger_quadratic_email_scanning(self):
        self.packet.write_text('word ' * 20000)  # 100 KB with no address: the old pattern took ~25 s
        started = time.monotonic()
        self.assertEqual(self.run_kimi().returncode, 0)
        self.assertLess(time.monotonic() - started, 15)

    def test_gate_has_a_time_limit(self):
        module = load_module()
        with self.assertRaises(module.Refused):
            module.Deadline(-1).check()

    def test_emails_are_redacted_before_launch(self):
        self.packet.write_text('Reported by dana@example.com and CC lee.o@corp.example.org\n'
                               'also root@localhost, dána@exämple.org and '
                               'full＠width.example.io\n'
                               'escaped dana%40example.net\n')
        result = self.run_kimi()
        self.assertEqual(result.returncode, 0, result.stderr)
        prompt = self.capture()['prompt']
        for leaked in ('example.com', 'corp.example.org', '@localhost', 'exämple', '%40', 'width.example.io'):
            self.assertNotIn(leaked, prompt)
        self.assertIn('[redacted-email]', prompt)
        self.assertIn('Egress-Emails-Redacted: 6\n', self.output.read_text())
        self.assertIn(hashlib.sha256(self.packet.read_bytes()).hexdigest(), self.output.read_text())

    # -- credential handling ----------------------------------------------------------------------

    def test_stored_credentials_are_never_read_or_echoed(self):
        result = self.run_kimi()
        self.assertEqual(result.returncode, 0, result.stderr)
        seen = result.stdout + result.stderr + self.output.read_text() + json.dumps(self.capture()['prompt'])
        self.assertNotIn(self.sentinel, seen)
        self.assertNotIn(self.sentinel, self.capture()['config'])

    # -- quota, state, overrides ------------------------------------------------------------------

    def test_quota_failure_stops_without_retry_and_sets_a_cooldown(self):
        first = self.run_kimi(env={'FAKE_MODE': 'quota'})
        self.assertEqual(first.returncode, 7, first.stderr)
        self.assertIn('quota', first.stderr.lower())
        self.assertEqual(self.launches(), 1, 'quota failure must not be retried')
        self.assertFalse(self.output.exists())
        second = self.run_kimi(env={'FAKE_MODE': 'ok'})
        self.assertEqual(second.returncode, 7, second.stderr)
        self.assertIn('cooldown', second.stderr)
        self.assertEqual(self.launches(), 1, 'cooldown must stop the next call before launch')

    def test_login_failure_reports_kimi_login_and_is_not_retried(self):
        result = self.run_kimi(env={'FAKE_MODE': 'login'})
        self.assertEqual(result.returncode, 5, result.stderr)
        self.assertIn('kimi login', result.stderr)
        self.assertEqual(self.launches(), 1)

    def test_empty_reply_is_an_error_not_a_review(self):
        result = self.run_kimi(env={'FAKE_MODE': 'empty'})
        self.assertEqual(result.returncode, 6, result.stderr)
        self.assertFalse(self.output.exists())

    def test_daily_call_cap_and_the_main_only_override(self):
        module = load_module()
        self.kimi_home.mkdir(mode=0o700)
        today = time.strftime('%Y-%m-%d', time.gmtime())
        (self.kimi_home / 'ledger.jsonl').write_text(
            ''.join(json.dumps({'date': today, 'kind': 'call', 'model': MODEL}) + '\n' for _ in range(module.DEFAULT_DAILY_CALLS)))
        capped = self.run_kimi()
        self.assertEqual(capped.returncode, 4, capped.stderr)
        self.assertEqual(self.launches(), 0)
        refused_flag = self.run_kimi('--daily-calls', '1000', output=self.work / 'x.md')
        self.assertEqual(refused_flag.returncode, 2)  # the old caller-facing cap flag no longer exists
        allowed = self.run_kimi('--main-override-daily-calls', '1000', output=self.work / 'y.md')
        self.assertEqual(allowed.returncode, 0, allowed.stderr)

    def test_unreadable_or_corrupt_state_fails_closed(self):
        self.kimi_home.mkdir(mode=0o700)
        for name, content, code in (('ledger.jsonl', 'not json\n', 4), ('cooldown.json', 'garbage', 7),
                                    ('cooldown.json', '{"until": Infinity}', 7), ('cooldown.json', '{"until": "x"}', 7)):
            path = self.kimi_home / name
            path.write_text(content)
            result = self.run_kimi(output=self.work / ('o-%s-%d.md' % (name, code)))
            self.assertEqual(result.returncode, code, '%s: %s' % (name, result.stderr))
            self.assertEqual(self.launches(), 0, name)
            path.unlink()

    def test_state_home_and_binary_overrides_only_work_in_test_mode(self):
        result = self.run_kimi(env={'KIMI_REVIEW_TEST_MODE': ''})
        self.assertEqual(result.returncode, 5, result.stderr)  # the fake binary override is ignored: no trusted kimi
        self.assertEqual(self.launches(), 0)
        self.assertFalse(self.kimi_home.exists())

    def test_state_home_override_is_ignored_outside_test_mode(self):
        module = load_module()
        names = ('HOME', 'KIMI_REVIEW_HOME', 'KIMI_REVIEW_TEST_MODE')
        saved = {name: os.environ.get(name) for name in names}
        try:
            os.environ['HOME'] = str(self.home)
            os.environ['KIMI_REVIEW_HOME'] = str(self.kimi_home)
            os.environ.pop('KIMI_REVIEW_TEST_MODE', None)
            self.assertEqual(module.home_dir(), self.home / '.agent-harness' / 'kimi')
            os.environ['KIMI_REVIEW_TEST_MODE'] = '1'
            self.assertEqual(module.home_dir(), self.kimi_home)
        finally:
            for name, value in saved.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value

    def test_kimi_binary_must_pass_the_trust_checks(self):
        planted = self.work / 'kimi'
        planted.write_text('#!/bin/sh\necho 2.5.9\n')
        planted.chmod(0o700)
        result = self.run_kimi(env={'KIMI_REVIEW_TEST_MODE': '', 'PATH': str(self.work)}, cwd=self.work)
        self.assertEqual(result.returncode, 5, result.stderr)
        self.assertIn('inside the repository, snapshot or working directory', result.stderr)

    def test_scratch_directory_inside_a_repository_is_refused(self):
        repo = self.root / 'repo'
        (repo / '.git').mkdir(parents=True)
        (repo / 'tmp').mkdir()
        result = self.run_kimi(env={'TMPDIR': str(repo / 'tmp')})
        self.assertRefused(result, 'tmp in repo')
        self.assertIn('repository', result.stderr)

    def test_missing_cli_names_the_install_and_login_step(self):
        result = self.run_kimi(env={'KIMI_REVIEW_TEST_MODE': '', 'PATH': '/nonexistent'})
        self.assertEqual(result.returncode, 5, result.stderr)
        self.assertIn('kimi login', result.stderr)


if __name__ == '__main__':
    unittest.main()
