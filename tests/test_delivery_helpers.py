import json
import os
import pty
import select
import socket
import subprocess
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


PUBLISH = Path(__file__).resolve().parents[1] / 'harness/hooks/publish_feature.py'
INTEGRATE = Path(__file__).resolve().parents[1] / 'harness/hooks/integrate_local.py'


def isolated_env():
    # User-level Git configuration (gpgsign, hooksPath, credential helpers, askpass) must not leak in.
    env = {**os.environ, 'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_CONFIG_NOSYSTEM': '1'}
    for name in ('GIT_ASKPASS', 'SSH_ASKPASS', 'GIT_TERMINAL_PROMPT'):
        env.pop(name, None)
    return env


def cmd(*args, cwd=None, check=True):
    p = subprocess.run(args, cwd=cwd, text=True, capture_output=True, env=isolated_env())
    if check and p.returncode:
        raise AssertionError(f'{args}: {p.stdout}\n{p.stderr}')
    return p


class DeliveryHelpers(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / 'repo'
        self.repo.mkdir()
        cmd('git', 'init', '-q', '-b', 'main', str(self.repo))
        cmd('git', 'config', 'user.email', 'test@example.invalid', cwd=self.repo)
        cmd('git', 'config', 'user.name', 'Harness test', cwd=self.repo)
        (self.repo / 'app.txt').write_text('base\n')
        cmd('git', 'add', 'app.txt', cwd=self.repo)
        cmd('git', 'commit', '-qm', 'base', cwd=self.repo)
        self.base = cmd('git', 'rev-parse', 'HEAD', cwd=self.repo).stdout.strip()
        self.feature = self.root / 'feature'
        cmd('git', 'worktree', 'add', '-qb', 'feat/app', str(self.feature), cwd=self.repo)
        (self.feature / 'app.txt').write_text('feature\n')
        cmd('git', 'commit', '-qam', 'feature', cwd=self.feature)
        self.feature_head = cmd('git', 'rev-parse', 'HEAD', cwd=self.feature).stdout.strip()

    def invoke(self, helper, *args):
        p = cmd('python3', str(helper), *args, check=False)
        return p, json.loads(p.stdout)

    def test_publish_success_and_protected_branch(self):
        remote = self.root / 'origin.git'
        cmd('git', 'init', '-q', '--bare', str(remote))
        cmd('git', 'remote', 'add', 'origin', str(remote), cwd=self.repo)
        p, data = self.invoke(PUBLISH, '--repo', str(self.feature), '--branch', 'feat/app', '--original-branch', 'main', '--expected-head', self.feature_head)
        self.assertEqual((p.returncode, data['status']), (0, 'PUSHED'))
        self.assertEqual(cmd('git', 'show-ref', '--verify', 'refs/heads/feat/app', cwd=remote).returncode, 0)
        self.assertNotEqual(cmd('git', 'show-ref', '--verify', 'refs/heads/main', cwd=remote, check=False).returncode, 0)
        p, data = self.invoke(PUBLISH, '--repo', str(self.repo), '--branch', 'main', '--original-branch', 'main', '--expected-head', self.base)
        self.assertEqual((p.returncode, data['status']), (2, 'BLOCKED_POLICY'))

    def test_failed_check_restores_original(self):
        tests = self.feature / 'tests'
        tests.mkdir()
        (tests / 'test_failure.py').write_text('import unittest\nclass Failure(unittest.TestCase):\n    def test_fails(self):\n        self.fail("intentional")\n')
        cmd('git', 'add', 'tests/test_failure.py', cwd=self.feature)
        cmd('git', 'commit', '-qm', 'add failing control', cwd=self.feature)
        self.feature_head = cmd('git', 'rev-parse', 'HEAD', cwd=self.feature).stdout.strip()
        p, data = self.invoke(INTEGRATE, '--repo', str(self.repo), '--original-branch', 'main', '--expected-head', self.base,
                              '--source', 'feat/app', '--expected-source-head', self.feature_head, '--check', 'python3 -m unittest discover -s tests -v')
        self.assertEqual((p.returncode, data['status']), (3, 'BLOCKED_LOCAL'))
        self.assertEqual(cmd('git', 'rev-parse', 'HEAD', cwd=self.repo).stdout.strip(), self.base)
        self.assertFalse(cmd('git', 'status', '--porcelain', cwd=self.repo).stdout.strip())

    def test_conflict_restores_original(self):
        (self.repo / 'app.txt').write_text('main divergent\n')
        cmd('git', 'commit', '-qam', 'diverge', cwd=self.repo)
        head = cmd('git', 'rev-parse', 'HEAD', cwd=self.repo).stdout.strip()
        p, data = self.invoke(INTEGRATE, '--repo', str(self.repo), '--original-branch', 'main', '--expected-head', head,
                              '--source', 'feat/app', '--expected-source-head', self.feature_head, '--check', 'python3 -m unittest discover -s tests -v')
        self.assertEqual((p.returncode, data['status']), (3, 'BLOCKED_LOCAL'))
        self.assertEqual(cmd('git', 'rev-parse', 'HEAD', cwd=self.repo).stdout.strip(), head)
        self.assertFalse(cmd('git', 'status', '--porcelain', cwd=self.repo).stdout.strip())

    def test_stale_feature_and_unapproved_check_are_rejected(self):
        p, data = self.invoke(PUBLISH, '--repo', str(self.feature), '--branch', 'feat/app', '--original-branch', 'main', '--expected-head', self.base)
        self.assertEqual((p.returncode, data['status']), (2, 'BLOCKED_POLICY'))
        p, data = self.invoke(INTEGRATE, '--repo', str(self.repo), '--original-branch', 'main', '--expected-head', self.base,
                              '--source', 'feat/app', '--expected-source-head', self.base, '--check', 'python3 -m unittest discover -s tests -v')
        self.assertEqual((p.returncode, data['status']), (2, 'BLOCKED_POLICY'))
        p, data = self.invoke(INTEGRATE, '--repo', str(self.repo), '--original-branch', 'main', '--expected-head', self.base,
                              '--source', 'feat/app', '--expected-source-head', self.feature_head, '--check', 'python3 -c "print(1)"')
        self.assertEqual((p.returncode, data['status']), (2, 'BLOCKED_POLICY'))
        self.assertEqual(cmd('git', 'rev-parse', 'HEAD', cwd=self.repo).stdout.strip(), self.base)

    def test_unparseable_check_is_a_policy_report_not_a_traceback(self):
        p, data = self.invoke(INTEGRATE, '--repo', str(self.repo), '--original-branch', 'main', '--expected-head', self.base,
                              '--source', 'feat/app', '--expected-source-head', self.feature_head, '--check', "python3 -m unittest 'unterminated")
        self.assertEqual((p.returncode, data['status']), (2, 'BLOCKED_POLICY'))
        self.assertEqual(cmd('git', 'rev-parse', 'HEAD', cwd=self.repo).stdout.strip(), self.base)

    def test_subdirectory_repo_is_rejected_before_merge(self):
        (self.repo / 'tests').mkdir()
        (self.repo / 'tests' / 'test_ok.py').write_text('import unittest\n')
        cmd('git', 'add', 'tests', cwd=self.repo)
        cmd('git', 'commit', '-qm', 'tests', cwd=self.repo)
        base = cmd('git', 'rev-parse', 'HEAD', cwd=self.repo).stdout.strip()
        p, data = self.invoke(INTEGRATE, '--repo', str(self.repo / 'tests'), '--original-branch', 'main', '--expected-head', base,
                              '--source', 'feat/app', '--expected-source-head', self.feature_head, '--check', 'python3 -m unittest discover -s tests')
        self.assertEqual((p.returncode, data['status']), (2, 'BLOCKED_POLICY'))
        self.assertEqual(cmd('git', 'rev-parse', 'HEAD', cwd=self.repo).stdout.strip(), base)
        self.assertFalse(cmd('git', 'status', '--porcelain', cwd=self.repo).stdout.strip())

    def test_dirty_original_is_preserved(self):
        local = self.repo / 'user-notes.txt'
        local.write_text('do not replace\n')
        p, data = self.invoke(INTEGRATE, '--repo', str(self.repo), '--original-branch', 'main', '--expected-head', self.base,
                              '--source', 'feat/app', '--expected-source-head', self.feature_head, '--check', 'python3 -m unittest discover -s tests -v')
        self.assertEqual((p.returncode, data['status']), (3, 'BLOCKED_LOCAL'))
        self.assertEqual(local.read_text(), 'do not replace\n')
        self.assertEqual(cmd('git', 'rev-parse', 'HEAD', cwd=self.repo).stdout.strip(), self.base)


class _Unauthorized(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm="harness-test"')
        self.end_headers()

    do_POST = do_GET

    def log_message(self, *args):
        pass


class PublishRemoteFailures(unittest.TestCase):
    """The publish helper must report remote trouble instead of waiting on a terminal or hanging."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name) / 'feature'
        cmd('git', 'init', '-q', '-b', 'feat/remote', str(self.repo))
        cmd('git', 'config', 'user.email', 'test@example.invalid', cwd=self.repo)
        cmd('git', 'config', 'user.name', 'Harness test', cwd=self.repo)
        cmd('git', 'commit', '-q', '--allow-empty', '-m', 'feature', cwd=self.repo)
        self.head = cmd('git', 'rev-parse', 'HEAD', cwd=self.repo).stdout.strip()

    def publish_args(self, *extra):
        return ['python3', str(PUBLISH), '--repo', str(self.repo), '--branch', 'feat/remote', '--original-branch', 'main', '--expected-head', self.head, *extra]

    def test_credential_prompt_fails_fast_even_with_a_terminal(self):
        server = HTTPServer(('127.0.0.1', 0), _Unauthorized)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.shutdown)
        cmd('git', 'remote', 'add', 'origin', f'http://127.0.0.1:{server.server_address[1]}/x.git', cwd=self.repo)
        pid, fd = pty.fork()
        if pid == 0:  # pragma: no cover - child
            try:
                os.execvpe('python3', self.publish_args(), isolated_env())
            finally:
                os._exit(127)
        self.addCleanup(os.close, fd)
        output = b''
        deadline = time.monotonic() + 30
        exited = False
        while time.monotonic() < deadline:
            ready, _, _ = select.select([fd], [], [], 0.2)
            if ready:
                try:
                    chunk = os.read(fd, 4096)
                except OSError:  # Linux raises EIO once the child closes the terminal
                    chunk = b''
                if chunk:
                    output += chunk
                    continue
                os.waitpid(pid, 0)  # terminal closed, so the child is exiting
                exited = True
                break
            if os.waitpid(pid, os.WNOHANG)[0] == pid:
                exited = True
                break
        if not exited:
            os.kill(pid, 9)
            os.waitpid(pid, 0)
            self.fail(f'publish helper waited for a terminal credential prompt: {output[-300:]!r}')
        text = output.decode(errors='replace')
        self.assertFalse(text.lstrip().startswith('Username for'), text)  # the interactive prompt never appeared
        data = json.loads(text.strip().splitlines()[-1])
        self.assertEqual(data['status'], 'BLOCKED_REMOTE')
        self.assertIn('terminal prompts disabled', data['detail'])

    def test_stalled_remote_hits_timeout(self):
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)  # accept nothing, so the push can never progress
        self.addCleanup(listener.close)
        cmd('git', 'remote', 'add', 'origin', f'http://127.0.0.1:{listener.getsockname()[1]}/x.git', cwd=self.repo)
        started = time.monotonic()
        p = subprocess.run(self.publish_args('--timeout', '2'), text=True, capture_output=True, env=isolated_env(), timeout=60)
        self.assertLess(time.monotonic() - started, 30)
        data = json.loads(p.stdout)
        self.assertEqual((p.returncode, data['status']), (4, 'BLOCKED_REMOTE'))
        self.assertIn('2 seconds', data['message'])


if __name__ == '__main__':
    unittest.main()
