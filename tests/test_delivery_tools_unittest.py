"""Focused tools unittest delivery, GoodQA #15668; all repositories are disposable."""

import contextlib
import io
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HOOKS = Path(__file__).resolve().parents[1] / 'harness' / 'hooks'
sys.path.insert(0, str(HOOKS))
import integrate_local as integration
import deliver as delivery

COMMAND = ['python3', '-m', 'unittest', 'discover', '-s', 'tools/course_recovery',
           '-p', 'test_project_private_ak04.py', '-v']
GOOD = 'import unittest\nclass T(unittest.TestCase):\n    def test_ok(self):\n        self.assertEqual(2+2,4)\n'
BAD = 'import unittest\nclass T(unittest.TestCase):\n    def test_no(self):\n        self.fail("owned fixture")\n'
SKIP = 'import unittest\n@unittest.skip("owned fixture")\nclass T(unittest.TestCase):\n    def test_no(self):\n        self.fail("skipped")\n'


class ToolsGrammar(unittest.TestCase):
    def test_requested_command_and_existing_tests_forms(self):
        for interpreter in ('python', 'python3'):
            for start in ('tests', 'tools/course_recovery'):
                for verbose in (False, True):
                    command = [interpreter, *COMMAND[1:]]
                    command[5] = start
                    if not verbose:
                        command.pop()
                    with self.subTest(command=command):
                        self.assertTrue(integration.approved_check(command))
        self.assertTrue(integration.approved_check(['python3', '-m', 'unittest', 'discover', '-s', 'tests']))

    def test_bounded_ascii_identifier_and_literal_basename(self):
        for component in ('a', '_a', 'A_09', 'a' * 64):
            command = COMMAND.copy()
            command[5] = 'tools/' + component
            self.assertTrue(integration.approved_check(command), component)

    def test_path_filename_and_interpreter_negatives(self):
        for start in ('tools', 'tools/', 'tools/.', 'tools/..', 'tools/../tests',
                      '/tools/course_recovery', './tools/course_recovery', 'tools/a/b',
                      'tools/.hidden', 'tools/9a', 'tools/a-b', 'tools/a b', 'tools/a*',
                      'tools/é', 'tools/' + 'a' * 65, r'tools\course_recovery',
                      'C:/tools/course_recovery', 'tools/$(echo a)'):
            command = COMMAND.copy()
            command[5] = start
            self.assertFalse(integration.approved_check(command), start)
        for pattern in ('test_*.py', 'test_?.py', 'test_[ab].py', 'a.py', 'test_.py',
                        '../test_a.py', 'tools/test_a.py', 'test_' + 'a' * 101 + '.py'):
            command = COMMAND.copy()
            command[7] = pattern
            self.assertFalse(integration.approved_check(command), pattern)
        for interpreter in ('python3.14', '/usr/bin/python3', 'env', 'sh'):
            self.assertFalse(integration.approved_check([interpreter, *COMMAND[1:]]))

    def test_extra_flags_shell_tokens_and_option_order_are_refused(self):
        for extra in (['-v'], ['-t', '.'], ['--failfast'], ['--'], ['other'],
                      [';', 'echo', 'x'], ['&&', 'echo', 'x'], ['|', 'sh'], ['>', 'x']):
            self.assertFalse(integration.approved_check(COMMAND + extra), extra)
        for command in (COMMAND[:1] + ['-I'] + COMMAND[1:],
                        COMMAND[:1] + ['-c', 'pass'],
                        COMMAND[:4] + ['-v'] + COMMAND[4:-1],
                        ['FOO=x'] + COMMAND,
                        COMMAND[:4] + ['-p', COMMAND[7], '-s', COMMAND[5]]):
            self.assertFalse(integration.approved_check(command), command)

    def test_normal_main_dispatch_preserves_exact_argv(self):
        args = ['integrate_local.py', '--repo', '.', '--original-branch', 'main',
                '--expected-head', 'a' * 40, '--source', 'feature',
                '--expected-source-head', 'b' * 40, '--check', shlex.join(COMMAND)]
        with mock.patch.object(sys, 'argv', args), \
                mock.patch.object(integration, 'require_check_interpreters') as preflight, \
                mock.patch.object(integration, 'integrate_scratch', return_value=0) as dispatch:
            self.assertEqual(integration.main(), 0)
            self.assertEqual(preflight.call_args.args[0], [COMMAND])
            self.assertEqual(dispatch.call_args.args[1:], ([], [COMMAND]))

    def test_normal_main_rejects_shell_and_unsupported_runtime_before_effects(self):
        base = ['integrate_local.py', '--repo', '.', '--original-branch', 'main',
                '--expected-head', 'a' * 40, '--source', 'feature', '--expected-source-head', 'b' * 40]
        for check in (shlex.join(COMMAND) + ' ; echo x', shlex.join(COMMAND) + " '"):
            with mock.patch.object(sys, 'argv', base + ['--check', check]), \
                    mock.patch.object(integration, 'integrate_scratch') as dispatch, \
                    mock.patch.object(integration, 'require_check_interpreters') as preflight, \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(integration.main(), 2)
                dispatch.assert_not_called()
                preflight.assert_not_called()
        with mock.patch.object(sys, 'argv', base + ['--check', shlex.join(COMMAND)]), \
                mock.patch.object(integration, 'integrate_scratch') as dispatch, \
                mock.patch.object(integration, 'require_check_interpreters',
                                  side_effect=integration.CheckInterpreterError('unsupported Python')), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(integration.main(), 2)
            dispatch.assert_not_called()


@unittest.skipIf(sys.version_info < (3, 10), 'Real delivery checks require Python >=3.10')
class ToolsExecution(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name)
        self.home = self.root / 'home'
        self.home.mkdir()
        bindir = self.root / 'bin'
        bindir.mkdir()
        (bindir / 'python3').symlink_to(sys.executable)
        self.env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
        self.env.update(HOME=str(self.home), TMPDIR=str(self.root), GIT_CONFIG_GLOBAL=os.devnull,
                        GIT_CONFIG_NOSYSTEM='1', PYTHONDONTWRITEBYTECODE='1',
                        PATH=str(bindir) + os.pathsep + os.environ.get('PATH', ''))

    def files(self, repo, body=GOOD):
        directory = repo / 'tools/course_recovery'
        directory.mkdir(parents=True)
        (directory / COMMAND[7]).write_text(body)
        (directory / 'test_other.py').write_text('raise RuntimeError("must not be selected")\n')

    def git(self, repo, *args, check=True):
        result = subprocess.run(['git', *args], cwd=repo, env=self.env, text=True,
                                capture_output=True, timeout=15)
        if check:
            self.assertEqual(result.returncode, 0, result.stderr)
        return result

    def test_actual_run_uses_nonempty_runner_and_exact_options(self):
        repo = self.root / 'repo'
        self.files(repo)
        with mock.patch.object(integration, 'run_process', wraps=integration.run_process) as runner:
            result = integration.run(repo, COMMAND, timeout=10, discard_output=True, env=self.env)
        self.assertEqual(result.returncode, 0)
        argv = runner.call_args.args[0]
        self.assertEqual(argv[1:3], ['-c', integration.NONEMPTY_UNITTEST])
        self.assertEqual(argv[3:], COMMAND[3:])

    def test_finish_run_checks_passes_selected_assertion(self):
        repo = self.root / 'repo'
        self.files(repo)
        with mock.patch.dict(os.environ, self.env, clear=True):
            delivery.run_checks(repo, [], [COMMAND], 10, self.root / 'checks')

    def test_finish_run_checks_rejects_missing_empty_skip_import_and_assertion_failure(self):
        for index, body in enumerate(('import unittest\n', SKIP, 'raise ImportError("owned fixture")\n', BAD, GOOD)):
            repo = self.root / ('case' + str(index))
            self.files(repo, body)
            command = COMMAND.copy()
            if index == 4:
                command[7] = 'test_missing.py'
            with self.subTest(index=index), mock.patch.dict(os.environ, self.env, clear=True), \
                    self.assertRaises(delivery.DeliveryError) as raised:
                delivery.run_checks(repo, [], [command], 10, self.root / ('checks' + str(index)))
            self.assertEqual(raised.exception.status, 'DELIVERED_CHECK_FAILED')

    def integration_case(self, label, body):
        repo = self.root / label / 'repo'
        repo.mkdir(parents=True)
        self.git(repo, 'init', '-q', '-b', 'main')
        self.git(repo, 'config', 'user.name', 'Harness fixture')
        self.git(repo, 'config', 'user.email', 'fixture@example.invalid')
        (repo / 'base.txt').write_text('base\n')
        self.git(repo, 'add', 'base.txt')
        self.git(repo, 'commit', '-qm', 'base')
        base = self.git(repo, 'rev-parse', 'HEAD').stdout.strip()
        feature = repo.parent / 'feature'
        self.git(repo, 'worktree', 'add', '-qb', 'feature', str(feature))
        self.files(feature, body)
        self.git(feature, 'add', 'tools')
        self.git(feature, 'commit', '-qm', 'tracked verification fixture')
        head = self.git(feature, 'rev-parse', 'HEAD').stdout.strip()
        result = subprocess.run([sys.executable, str(HOOKS / 'integrate_local.py'), '--repo', str(repo),
                                 '--original-branch', 'main', '--expected-head', base,
                                 '--source', 'feature', '--expected-source-head', head,
                                 '--check', shlex.join(COMMAND), '--timeout', '15', '--check-timeout', '10'],
                                env=self.env, capture_output=True, text=True, timeout=40)
        return repo, base, result, json.loads(result.stdout)

    def test_normal_cli_integrates_tracked_selected_tools_check(self):
        repo, base, result, report = self.integration_case('good', GOOD)
        self.assertEqual((result.returncode, report['status']), (0, 'INTEGRATED'), result.stdout + result.stderr)
        self.assertNotEqual(self.git(repo, 'rev-parse', 'HEAD').stdout.strip(), base)
        self.assertEqual(self.git(repo, 'status', '--porcelain').stdout, '')

    def test_normal_cli_failed_and_vacuous_checks_preserve_original(self):
        for label, body in (('bad', BAD), ('empty', 'import unittest\n'), ('skip', SKIP)):
            with self.subTest(label=label):
                repo, base, result, report = self.integration_case(label, body)
                self.assertEqual((result.returncode, report['status'], report.get('phase')),
                                 (3, 'BLOCKED_LOCAL', 'check'), result.stdout + result.stderr)
                self.assertEqual(self.git(repo, 'rev-parse', 'HEAD').stdout.strip(), base)
                self.assertEqual(self.git(repo, 'status', '--porcelain').stdout, '')
                self.assertNotEqual(self.git(repo, 'rev-parse', '--verify', 'MERGE_HEAD', check=False).returncode, 0)


if __name__ == '__main__':
    unittest.main()
