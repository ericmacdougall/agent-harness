import errno
import importlib.util
import io
import json
import os
import pty
import select
import signal
import shlex
import sys
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch


PUBLISH = Path(__file__).resolve().parents[1] / 'harness/hooks/publish_feature.py'
INTEGRATE = Path(__file__).resolve().parents[1] / 'harness/hooks/integrate_local.py'


def isolated_env():
    # User-level Git configuration (gpgsign, hooksPath, credential helpers, askpass) must not leak in.
    env = {**os.environ, 'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_CONFIG_NOSYSTEM': '1'}
    for name in list(env):
        if name.startswith('GIT_') and name not in {'GIT_CONFIG_GLOBAL', 'GIT_CONFIG_NOSYSTEM'}:
            env.pop(name)
    env.pop('SSH_ASKPASS', None)
    env['LC_ALL'] = 'C'
    # Nested Python checks must use the same interpreter as the test suite.
    env['PATH'] = str(Path(sys.executable).parent) + os.pathsep + env.get('PATH', '')
    return env


def cmd(*args, cwd=None, check=True):
    p = subprocess.run(args, cwd=cwd, text=True, capture_output=True, env=isolated_env())
    if check and p.returncode:
        raise AssertionError(f'{args}: {p.stdout}\n{p.stderr}')
    return p


def collect_pty(pid, fd, timeout=15):
    """Reap the child AND drain its terminal; either can finish first."""
    output = b''
    status = None
    eof = False
    deadline = time.monotonic() + timeout
    try:
        while time.monotonic() < deadline:
            if status is None:
                reaped, child_status = os.waitpid(pid, os.WNOHANG)
                if reaped:
                    status = child_status
            if not eof:
                ready, _, _ = select.select([fd], [], [], 0.1)
                if ready:
                    try:
                        chunk = os.read(fd, 4096)
                    except OSError as error:
                        if error.errno != errno.EIO:
                            raise
                        chunk = b''
                    output += chunk
                    eof = not chunk
            if eof and status is not None:
                return output, os.waitstatus_to_exitcode(status)
            if eof:
                time.sleep(0.01)
        raise AssertionError(f'child/terminal did not finish: {output[-300:]!r}')
    finally:
        if status is None:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.waitpid(pid, 0)


class TerminalCollection(unittest.TestCase):
    def test_drains_output_that_arrives_after_exit_is_observed(self):
        with patch('os.waitpid', return_value=(123, 4 << 8)), \
             patch('select.select', side_effect=[([], [], []), ([7], [], []), ([7], [], [])]), \
             patch('os.read', side_effect=[b'{"status":"BLOCKED_REMOTE"}\n', b'']):
            output, code = collect_pty(123, 7)
        self.assertEqual(json.loads(output)['status'], 'BLOCKED_REMOTE')
        self.assertEqual(code, 4)


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
        p = cmd(sys.executable, str(helper), *args, check=False)
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

    def add_feature_test(self, body):
        tests = self.feature / 'tests'
        tests.mkdir()
        (tests / 'test_check.py').write_text(body)
        cmd('git', 'add', 'tests', cwd=self.feature)
        cmd('git', 'commit', '-qm', 'verification fixture', cwd=self.feature)
        self.feature_head = cmd('git', 'rev-parse', 'HEAD', cwd=self.feature).stdout.strip()

    def integrate_args(self, *extra):
        return [sys.executable, str(INTEGRATE), '--repo', str(self.repo), '--original-branch', 'main',
                '--expected-head', self.base, '--source', 'feat/app', '--expected-source-head',
                self.feature_head, '--check', 'python3 -m unittest discover -s tests', *extra]

    def assert_restored(self):
        self.assertEqual(cmd('git', 'rev-parse', 'HEAD', cwd=self.repo).stdout.strip(), self.base)
        self.assertFalse(cmd('git', 'status', '--porcelain', cwd=self.repo).stdout.strip())
        self.assertNotEqual(cmd('git', 'rev-parse', '--verify', 'MERGE_HEAD', cwd=self.repo, check=False).returncode, 0)

    def test_check_timeout_kills_descendants_and_aborts_merge(self):
        marker = self.root / 'late-write'
        started = self.root / 'started'
        self.add_feature_test('import subprocess, sys, time\n'
                              'subprocess.Popen([sys.executable, "-c", '
                              + repr(f"import time; from pathlib import Path; Path({str(started)!r}).touch(); time.sleep(4); Path({str(marker)!r}).write_text('survived')")
                              + '])\ntime.sleep(8)\n')
        p = subprocess.run(self.integrate_args('--timeout', '2'), text=True, capture_output=True,
                           env=isolated_env(), timeout=15)
        self.assertEqual(p.returncode, 3, p.stderr)
        self.assertEqual(json.loads(p.stdout)['status'], 'BLOCKED_LOCAL')
        self.assert_restored()
        self.assertTrue(started.exists(), 'the fixture child must actually start')
        time.sleep(5)
        self.assertFalse(marker.exists(), 'verification descendant survived the timeout')

    def test_missing_preparation_executable_aborts_merge(self):
        # Simulate an unavailable package manager without depending on the host PATH.
        spec = importlib.util.spec_from_file_location('integration', INTEGRATE)
        module = importlib.util.module_from_spec(spec)
        with patch.object(sys, 'path', [str(INTEGRATE.parent), *sys.path]):
            spec.loader.exec_module(module)
        real_run = module.run
        def missing_prepare(repo, command, **kwargs):
            if command[0] == 'npm':
                raise FileNotFoundError('fixture: npm is unavailable')
            return real_run(repo, command, **kwargs)
        with patch.object(sys, 'argv', self.integrate_args('--prepare', 'npm ci --prefer-offline')[1:]), patch.object(module, 'run', side_effect=missing_prepare), patch('sys.stdout', new_callable=io.StringIO), patch.dict(os.environ, isolated_env(), clear=True):
            self.assertEqual(module.main(), 3)
        self.assert_restored()

    def test_successful_check_commits_the_merge(self):
        self.add_feature_test('import unittest\nclass Check(unittest.TestCase):\n'
                              '    def test_ok(self):\n        self.assertEqual(2 + 2, 4)\n')
        result = subprocess.run(self.integrate_args('--timeout', '10'), text=True, capture_output=True,
                                env=isolated_env(), timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['status'], 'INTEGRATED')
        self.assertFalse(cmd('git', 'status', '--porcelain', cwd=self.repo).stdout.strip())
        parents = cmd('git', 'rev-list', '--parents', '-n', '1', 'HEAD', cwd=self.repo).stdout.split()
        self.assertEqual(parents[1:], [self.base, self.feature_head])

    def test_nonpositive_timeout_rejected_before_merge(self):
        for value in ('0', '-1'):
            result = subprocess.run(self.integrate_args('--timeout', value), text=True, capture_output=True,
                                    env=isolated_env(), timeout=10)
            self.assertEqual(result.returncode, 2)
            self.assertIn('positive', result.stderr)
            self.assert_restored()

    def test_preparation_timeout_aborts_merge(self):
        # Use the real deadline and process cleanup with a disposable package-manager stand-in.
        bin_dir = self.root / 'bin'
        bin_dir.mkdir()
        npm = bin_dir / 'npm'
        npm.write_text('#!/bin/sh\nexec sleep 8\n')
        npm.chmod(0o700)
        env = isolated_env()
        env['PATH'] = str(bin_dir) + os.pathsep + env['PATH']
        result = subprocess.run(self.integrate_args('--prepare', 'npm ci --prefer-offline', '--timeout', '2'),
                                text=True, capture_output=True, env=env, timeout=15)
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertIn('Prepare exceeded 2 seconds', json.loads(result.stdout)['message'])
        self.assert_restored()

    def test_failed_abort_is_reported_without_claiming_restoration(self):
        self.add_feature_test('from pathlib import Path\n'
                              'Path("app.txt").write_text("check modified tracked content\\n")\n'
                              'raise RuntimeError("intentional check failure")\n')
        p = subprocess.run(self.integrate_args(), text=True, capture_output=True, env=isolated_env(), timeout=15)
        self.assertEqual(p.returncode, 3, p.stderr)
        data = json.loads(p.stdout)
        self.assertIs(data.get('merge_aborted'), False, data)
        self.assertIn('abort failed', data['message'])
        self.assertEqual((self.repo / 'app.txt').read_text(), 'check modified tracked content\n')

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
        return [sys.executable, str(PUBLISH), '--repo', str(self.repo), '--branch', 'feat/remote', '--original-branch', 'main', '--expected-head', self.head, *extra]

    def test_credential_prompt_fails_fast_even_with_a_terminal(self):
        remote = Path(self.temp.name) / 'remote.git'
        cmd('git', 'init', '-q', '--bare', str(remote))
        cmd('git', 'remote', 'add', 'origin', str(remote), cwd=self.repo)
        # Real Git credential prompting without an HTTP listener or a thread at fork.
        hook = self.repo / '.git/hooks/pre-push'
        hook.write_text('#!/bin/sh\nprintf "protocol=https\\nhost=example.invalid\\n\\n" | git -c credential.helper= credential fill\nexit 1\n')
        hook.chmod(0o700)
        pid, fd = pty.fork()
        if pid == 0:  # pragma: no cover - child
            try:
                os.execve(sys.executable, self.publish_args('--timeout', '2'), isolated_env())
            finally:
                os._exit(127)
        self.addCleanup(os.close, fd)
        output, exit_code = collect_pty(pid, fd)
        self.assertEqual(exit_code, 4, output)
        text = output.decode(errors='replace')
        self.assertFalse(text.lstrip().startswith('Username for'), text)  # the interactive prompt never appeared
        data = json.loads(text.strip().splitlines()[-1])
        self.assertEqual(data['status'], 'BLOCKED_REMOTE')
        self.assertIn('terminal prompts disabled', data['detail'])

    def test_stalled_push_kills_child_before_reporting_timeout(self):
        remote = Path(self.temp.name) / 'remote.git'
        cmd('git', 'init', '-q', '--bare', str(remote))
        cmd('git', 'remote', 'add', 'origin', str(remote), cwd=self.repo)
        marker = Path(self.temp.name) / 'late-write'
        child_pid = Path(self.temp.name) / 'child.pid'
        hook = self.repo / '.git/hooks/pre-push'
        child = (f"import os, time; from pathlib import Path; Path({str(child_pid)!r}).write_text(str(os.getpid())); "
                 f"time.sleep(4); Path({str(marker)!r}).write_text('survived')")
        hook.write_text('#!/bin/sh\n' + shlex.join([sys.executable, '-c', child]) + '\n')
        hook.chmod(0o700)
        try:
            started = time.monotonic()
            p = subprocess.run(self.publish_args('--timeout', '2'), text=True, capture_output=True,
                               env=isolated_env(), timeout=15)
            self.assertLess(time.monotonic() - started, 10)
            data = json.loads(p.stdout)
            self.assertEqual((p.returncode, data['status']), (4, 'BLOCKED_REMOTE'))
            self.assertIn('2 seconds', data['message'])
            self.assertTrue(child_pid.exists(), 'the fixture child must actually start')
            time.sleep(5)
            self.assertFalse(marker.exists(), 'a push descendant kept running after BLOCKED_REMOTE')
        finally:
            if child_pid.exists():
                try:
                    os.kill(int(child_pid.read_text()), signal.SIGKILL)
                except ProcessLookupError:
                    pass


if __name__ == '__main__':
    unittest.main()
