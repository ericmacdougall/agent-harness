"""Failing-first tests for kimi_review.py (GoodQA goodqa#15201): egress gate, quota handling, report headers.

KIMI_REVIEW_UNDER_TEST points the suite at a mutated copy so each gate can be shown to fail when stubbed out.
"""
import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

DEFAULT = Path(__file__).resolve().parents[1] / 'harness/hooks/kimi_review.py'
KIMI = Path(os.environ.get('KIMI_REVIEW_UNDER_TEST') or DEFAULT)
HEAD = 'a' * 40

FAKE = '''import json, os, sys
from pathlib import Path
state = Path(os.environ['FAKE_STATE'])
with (state / 'launches').open('a') as handle:
    handle.write('launch\\n')
argv = sys.argv[1:]
prompt = next(a for a in argv if a.startswith('--prompt='))[len('--prompt='):]
agent = Path(argv[argv.index('--agent-file') + 1]).read_text()
(state / 'capture.json').write_text(json.dumps({
    'prompt': prompt, 'model': argv[argv.index('--model') + 1], 'agent': agent, 'cwd_entries': os.listdir(os.getcwd()),
    'format': argv[argv.index('--output-format') + 1], 'env_has_key': any('KEY' in k and 'OPENROUTER' in k for k in os.environ)}))
mode = os.environ.get('FAKE_MODE', 'ok')
if mode == 'quota':
    sys.stderr.write('Error: 429 rate limit: your plan quota is exhausted\\n'); sys.exit(1)
if mode == 'login':
    sys.stderr.write('Error: not logged in, run kimi login\\n'); sys.exit(1)
if mode == 'empty':
    sys.exit(0)
print(json.dumps({'role': 'meta', 'type': 'system.version', 'version': 'fake'}))
print(json.dumps({'role': 'assistant', 'content': 'F1: fixture finding.\\nKIMI_VERDICT: BLOCK'}))
print(json.dumps({'role': 'meta', 'type': 'session.resume_hint', 'session_id': 'session_fake-123', 'content': 'x'}))
'''


class KimiReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.home = self.root / 'home'
        (self.home / '.claude' / 'wals' / 's').mkdir(parents=True)
        (self.home / '.claude' / 'projects' / 'p').mkdir(parents=True)
        (self.home / '.kimi-code' / 'credentials').mkdir(parents=True)
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

    def run_kimi(self, *extra, packet=None, output=None, env=None, head=HEAD):
        environment = {**os.environ, 'HOME': str(self.home), 'KIMI_REVIEW_BIN': str(self.fake),
                       'KIMI_REVIEW_HOME': str(self.kimi_home), 'FAKE_STATE': str(self.state), **(env or {})}
        command = [sys.executable, str(KIMI), '--packet', str(packet or self.packet),
                   '--output', str(output or self.output), *(['--head', head] if head else []), *extra]
        return subprocess.run(command, text=True, capture_output=True, env=environment, timeout=60)

    def assertRefused(self, result, label=''):
        self.assertEqual(result.returncode, 3, '%s: %s%s' % (label, result.stdout, result.stderr))
        self.assertEqual(self.launches(), 0, '%s: kimi was launched despite refusal' % label)
        self.assertFalse(self.output.exists(), label)

    # -- happy path -------------------------------------------------------------------------------

    def test_report_headers_and_tool_less_isolated_launch(self):
        result = self.run_kimi()
        self.assertEqual(result.returncode, 0, result.stderr)
        report = self.output.read_text()
        sha = hashlib.sha256(self.packet.read_bytes()).hexdigest()
        for line in ('Reviewed-Model: kimi-code/k3.1-pro', 'Reviewed-Packet-SHA256: ' + sha, 'Reviewed-HEAD: ' + HEAD,
                     'Request-Id: session_fake-123', 'Egress-Emails-Redacted: 0'):
            self.assertIn(line + '\n', report)
        for prefix in ('Tokens-In-Estimate: ', 'Tokens-Out-Estimate: ', 'Cost-USD: 0 (subscription'):
            self.assertIn(prefix, report)
        self.assertIn('KIMI_VERDICT: BLOCK', report)
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o600)
        capture = json.loads((self.state / 'capture.json').read_text())
        self.assertIn('tools: []', capture['agent'])           # every tool disabled
        self.assertEqual(capture['cwd_entries'], [])            # runs in an empty directory
        self.assertEqual(capture['model'], 'kimi-code/k3.1-pro')
        self.assertEqual(capture['format'], 'stream-json')
        self.assertIn('Scope: review the handler change.', capture['prompt'])
        self.assertEqual(self.launches(), 1)

    def test_model_is_limited_to_kimi_code_aliases(self):
        result = self.run_kimi('--model', 'moonshotai/kimi-k3.1-pro')
        self.assertRefused(result, 'model')
        ok = self.run_kimi('--model', 'kimi-code/k3-256k')
        self.assertEqual(ok.returncode, 0, ok.stderr)
        self.assertEqual(json.loads((self.state / 'capture.json').read_text())['model'], 'kimi-code/k3-256k')

    def test_existing_output_is_preserved(self):
        self.output.write_text('stale')
        result = self.run_kimi()
        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.output.read_text(), 'stale')
        self.assertEqual(self.launches(), 0)

    # -- egress gate: one case per class ----------------------------------------------------------

    def test_sensitive_paths_are_refused(self):
        wal = self.home / '.claude' / 'wals' / 's' / 'main.jsonl'
        wal.write_text('{"event":"x"}\n')
        transcript = self.home / '.claude' / 'projects' / 'p' / 'notes.md'
        transcript.write_text('plain text but under the transcript tree\n')
        jsonl = self.work / 'session.jsonl'
        jsonl.write_text('{"a":1}\n')
        cases = {'wals': wal, 'projects': transcript, 'jsonl': jsonl}
        for name, content in {'.env.local': 'A=1\n', 'my-secret-notes.md': 'x\n', 'api_token_list.md': 'x\n',
                              'deploy.pem': 'x\n', 'id_ed25519': 'x\n', 'login.keychain-db': 'x\n',
                              'session-transcript.md': 'x\n', 'granola-notes.md': 'x\n'}.items():
            path = self.work / name
            path.write_text(content)
            cases[name] = path
        cases['kimi credentials'] = self.home / '.kimi-code' / 'credentials' / 'c.md'
        cases['kimi credentials'].write_text('x\n')
        for label, path in cases.items():
            self.assertRefused(self.run_kimi('--snapshot', str(path)), label)
            self.assertRefused(self.run_kimi(packet=path), 'packet ' + label)

    def test_symlink_into_wals_is_refused_by_real_path(self):
        wal = self.home / '.claude' / 'wals' / 's' / 'main.md'
        wal.write_text('harmless words\n')
        link = self.work / 'innocent.md'
        link.symlink_to(wal)
        self.assertRefused(self.run_kimi('--snapshot', str(link)), 'symlink snapshot')
        self.assertRefused(self.run_kimi(packet=link), 'symlink packet')

    def test_directory_snapshot_refuses_a_sensitive_member_and_skips_nothing_silently(self):
        tree = self.work / 'tree'
        tree.mkdir()
        (tree / 'ok.py').write_text('print(1)\n')
        (tree / '.env').write_text('A=1\n')
        self.assertRefused(self.run_kimi('--snapshot', str(tree)), 'dir with .env')

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
        }
        for label, line in samples.items():
            self.packet.write_text('Evidence follows.\n%s\n' % line)
            result = self.run_kimi()
            self.assertRefused(result, label)
            self.assertNotIn(line.split()[-1], result.stderr, label + ': refusal must not echo the match')

    def test_git_shas_and_ordinary_long_paths_are_not_secrets(self):
        self.packet.write_text('Commit %s and sha256 %s in /Users/eric/.agent-harness/work/baab765b/'
                               'agent-a49cb658ed4738957/kimi-tool/some_long_snake_case_identifier_name.py\n'
                               % ('1f' * 20, 'ab' * 32))
        result = self.run_kimi()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_forbidden_topics_are_refused(self):
        for label, line in {'yates': 'the yates-cloud deploy', 'apex': 'see apex_app_pos tables',
                            'granola': 'from the Granola export', 'interview': 'Interview transcript for Dana',
                            'solve': 'a Solve transcript excerpt'}.items():
            self.packet.write_text('Evidence.\n%s\n' % line)
            self.assertRefused(self.run_kimi(), label)

    def test_oversize_payload_is_refused(self):
        self.packet.write_text(('plain filler words\n' * 90000))
        self.assertGreater(self.packet.stat().st_size, 1_500_000)
        result = self.run_kimi()
        self.assertRefused(result, 'over 1.5 MB')
        self.assertIn('1500000', result.stderr)  # the 1.5 MB cap itself, not the narrower argv limit

    def test_payload_over_the_argument_limit_is_refused_before_launch(self):
        self.packet.write_text('plain filler words\n' * 40000)  # 760 KB: under 1.5 MB, over the argv limit
        self.assertRefused(self.run_kimi(), 'argv limit')

    def test_emails_are_redacted_before_launch(self):
        self.packet.write_text('Reported by dana@example.com and CC lee.o@corp.example.org\n')
        result = self.run_kimi()
        self.assertEqual(result.returncode, 0, result.stderr)
        prompt = json.loads((self.state / 'capture.json').read_text())['prompt']
        self.assertNotIn('example.com', prompt)
        self.assertNotIn('corp.example.org', prompt)
        self.assertIn('[redacted-email]', prompt)
        self.assertIn('Egress-Emails-Redacted: 2\n', self.output.read_text())
        # the packet hash is of the original bytes, so the signoff binds to the real packet
        self.assertIn(hashlib.sha256(self.packet.read_bytes()).hexdigest(), self.output.read_text())

    # -- credential handling ----------------------------------------------------------------------

    def test_stored_credentials_are_never_read_or_echoed(self):
        sentinel = 'SENTINEL-CRED-DO-NOT-LEAK-12345'
        (self.home / '.kimi-code' / 'credentials' / 'kimi-code.json').write_text(sentinel)
        result = self.run_kimi()
        self.assertEqual(result.returncode, 0, result.stderr)
        seen = result.stdout + result.stderr + self.output.read_text() + (self.state / 'capture.json').read_text()
        self.assertNotIn(sentinel, seen)
        self.assertFalse(json.loads((self.state / 'capture.json').read_text())['env_has_key'])

    # -- subscription quota -----------------------------------------------------------------------

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

    def test_daily_call_cap(self):
        self.assertEqual(self.run_kimi('--daily-calls', '1').returncode, 0)
        second = self.run_kimi('--daily-calls', '1', output=self.work / 'second.md')
        self.assertEqual(second.returncode, 4, second.stderr)
        self.assertEqual(self.launches(), 1)

    def test_missing_cli_names_the_install_and_login_step(self):
        result = self.run_kimi(env={'KIMI_REVIEW_BIN': '', 'PATH': '/nonexistent'})
        self.assertEqual(result.returncode, 5, result.stderr)
        self.assertIn('kimi login', result.stderr)


if __name__ == '__main__':
    unittest.main()
