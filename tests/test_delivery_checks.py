"""Delivery checks keep diagnosable output, pin a supported interpreter, and get a suite-sized deadline."""

import importlib.util
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch


HOOKS = Path(__file__).resolve().parents[1] / 'harness/hooks'


def load(name, filename):
    sys.path.insert(0, str(HOOKS))
    try:
        spec = importlib.util.spec_from_file_location(name, HOOKS / filename)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.remove(str(HOOKS))


def fake_python(directory, version):
    """An executable named python3 that reports `version` and otherwise fails."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / 'python3'
    path.write_text(f'#!/bin/sh\necho {version}\n')
    path.chmod(0o700)
    return path


@unittest.skipUnless(os.name == 'posix', 'Delivery checks require POSIX process groups')
class DeliveryCheckEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.delivery = load('delivery_checks_test', 'deliver.py')
        cls.integrate = load('integrate_checks_test', 'integrate_local.py')
        cls.process = load('process_checks_test', 'process.py')

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.repo = self.root / 'repo'
        self.repo.mkdir()
        self.logs = self.root / 'generation' / 'checks'
        self.logs.parent.mkdir(mode=0o700)
        # Checks resolve python3 through PATH; point it at this supported interpreter.
        self.env = patch.dict(os.environ, {'PATH': str(Path(sys.executable).parent) + os.pathsep
                                           + os.environ.get('PATH', '')})
        self.env.start()
        self.addCleanup(self.env.stop)

    def run_failing(self, script, timeout=60):
        with self.assertRaises(self.delivery.DeliveryError) as raised:
            self.delivery.run_checks(self.repo, [], [['python3', '-c', script]], timeout, self.logs)
        return raised.exception

    def test_failed_check_keeps_log_and_redacted_tail(self):
        token = 'ghp_' + 'A' * 36
        error = self.run_failing('import sys\nprint("x" * 9000)\n'
                                 f'print("deploy token={token} url=https://user:pw@example.invalid/r")\n'
                                 'sys.stdout.flush()\nprint("FAIL: test_flaky_case", file=sys.stderr)\nsys.exit(3)\n')
        facts = error.facts
        self.assertEqual((error.status, facts['check_status']), ('DELIVERED_CHECK_FAILED', 'exit 3'))
        log = Path(facts['check_log'])
        self.assertEqual(log.parent, self.logs)
        self.assertEqual(stat.S_IMODE(log.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.logs.stat().st_mode), 0o700)
        content = log.read_text()
        # The private log is complete (including stderr); only the reported tail is redacted.
        self.assertIn('$ python3 -c', content)
        self.assertIn('FAIL: test_flaky_case', content)
        self.assertIn('x' * 9000, content)
        tail = facts['check_tail']
        self.assertIn('FAIL: test_flaky_case', tail)
        self.assertLessEqual(len(tail), self.integrate.CHECK_TAIL_CHARS)
        self.assertNotIn(token, tail)
        self.assertNotIn('user:pw', tail)
        self.assertFalse(facts['check_log_truncated'])

    def test_timeout_reports_status_and_partial_output(self):
        error = self.run_failing('import time\nprint("started slow suite", flush=True)\ntime.sleep(30)\n', timeout=2)
        self.assertEqual(error.facts['check_status'], 'timeout')
        self.assertIn('exceeded 2 seconds', error.message)
        self.assertIn('started slow suite', error.facts['check_tail'])
        self.assertIn('started slow suite', Path(error.facts['check_log']).read_text())

    def test_log_is_size_bounded_without_changing_outcome(self):
        with patch.object(self.integrate, 'CHECK_LOG_LIMIT', 1000), \
             patch.object(sys.modules['integrate_local'], 'CHECK_LOG_LIMIT', 1000):
            self.delivery.run_checks(self.repo, [], [['python3', '-c', 'print("y" * 50000)']], 60, self.logs)
            logs = list(self.logs.iterdir())
            self.assertEqual(len(logs), 1)
            self.assertLessEqual(logs[0].stat().st_size, 1000)
            error = self.run_failing('for _ in range(600):\n    print("z" * 100)\nraise SystemExit(1)\n')
        self.assertTrue(error.facts['check_log_truncated'])
        self.assertTrue(error.facts['check_tail'].endswith('z' * 100 + '\n'))

    def test_recovery_wrappers_carry_only_check_evidence(self):
        error = self.delivery.DeliveryError('DELIVERED_CHECK_FAILED', 'failed', check_log='/x', check_tail='t',
                                            check_log_truncated=False, check_status='exit 1', unrelated='drop')
        self.assertEqual(self.delivery.check_facts(error),
                         {'check_log': '/x', 'check_tail': 't', 'check_log_truncated': False, 'check_status': 'exit 1'})
        self.assertEqual(self.delivery.check_facts(OSError('io')), {})


@unittest.skipUnless(os.name == 'posix', 'Interpreter probing requires POSIX executables')
class CheckInterpreter(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.integrate = load('integrate_interpreter_test', 'integrate_local.py')
        cls.delivery = load('delivery_interpreter_test', 'deliver.py')

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def test_unsupported_python_on_path_is_refused_with_remedy(self):
        old = fake_python(self.root / 'old-bin', '3.9')
        with self.assertRaises(self.integrate.CheckInterpreterError) as raised:
            self.integrate.resolve_check_interpreter('python3', {'PATH': str(old.parent)})
        message = str(raised.exception)
        self.assertIn('Python 3.9', message)
        self.assertIn('3.10 or newer', message)
        self.assertIn('first on PATH', message)

    def test_supported_python_is_pinned_to_an_absolute_path(self):
        supported = fake_python(self.root / 'new-bin', '3.12')
        self.assertEqual(self.integrate.resolve_check_interpreter('python3', {'PATH': str(supported.parent)}),
                         str(supported))

    def test_missing_or_silent_interpreter_is_refused(self):
        with self.assertRaises(self.integrate.CheckInterpreterError):
            self.integrate.resolve_check_interpreter('python3', {'PATH': str(self.root / 'empty')})
        broken = self.root / 'broken-bin'
        broken.mkdir()
        (broken / 'python3').write_text('#!/bin/sh\nexit 0\n')
        (broken / 'python3').chmod(0o700)
        with self.assertRaises(self.integrate.CheckInterpreterError):
            self.integrate.resolve_check_interpreter('python3', {'PATH': str(broken)})

    def test_run_refuses_unsupported_python_even_without_preflight(self):
        # Without run()-time pinning the fake 3.9 "python3" would execute and exit 0.
        old = fake_python(self.root / 'old-bin', '3.9')
        with self.assertRaises(self.integrate.CheckInterpreterError):
            self.integrate.run(self.root, ['python3', '-m', 'unittest', 'discover', '-s', 'tests'],
                               timeout=60, discard_output=True, env={**os.environ, 'PATH': str(old.parent)})

    def test_run_executes_the_pinned_absolute_interpreter(self):
        seen = []
        real = self.integrate.run_process

        def record(command, **kwargs):
            seen.append(command)
            return real(command, **kwargs)
        env = {**os.environ, 'PATH': str(Path(sys.executable).parent) + os.pathsep + os.environ.get('PATH', '')}
        with patch.object(self.integrate, 'run_process', side_effect=record):
            result = self.integrate.run(self.root, ['python3', '-c', 'pass'], timeout=60, discard_output=True, env=env)
        self.assertEqual(result.returncode, 0)
        executed = [command for command in seen if command[1:3] != ['-I', '-c']]
        self.assertEqual(len(executed), 1)
        self.assertTrue(Path(executed[0][0]).is_absolute())
        self.assertEqual(executed[0][1:], ['-c', 'pass'])

    def test_finish_refuses_unsupported_interpreter_before_any_checkout_effect(self):
        old = fake_python(self.root / 'old-bin', '3.9')
        argv = ['deliver.py', 'finish', '--task', 'interpreter-preflight', '--original', str(self.root / 'absent'),
                '--original-branch', 'main', '--mode', 'remote', '--check', 'python3 -m unittest discover -s tests']
        with patch.object(sys, 'argv', argv), patch.dict(os.environ, {'PATH': str(old.parent)}):
            args = self.delivery.parse_args()
            with self.assertRaises(self.delivery.DeliveryError) as raised:
                self.delivery.finish(args)
        self.assertEqual((raised.exception.status, raised.exception.code), ('BLOCKED_POLICY', 2))
        self.assertIn('Python 3.9', raised.exception.message)
        self.assertFalse((self.root / 'absent').exists())


    def test_finish_approves_the_focused_form_and_still_refuses_broader_ones(self):
        # The focused form passes the approval step (the failure is the later interpreter pin, goodqa#14730);
        # a glob or path name is refused at approval, before the interpreter is even looked at.
        old = fake_python(self.root / 'old-bin2', '3.9')
        for check, approved in (('python3 -m unittest discover -s tests -p test_merge_gate.py', True),
                                ("python3 -m unittest discover -s tests -p 'test_*.py'", False),
                                ('python3 -m unittest discover -s tests -p tests/test_a.py', False)):
            with self.subTest(check=check):
                argv = ['deliver.py', 'finish', '--task', 'focused-preflight', '--original', str(self.root / 'absent'),
                        '--original-branch', 'main', '--mode', 'remote', '--check', check]
                with patch.object(sys, 'argv', argv), patch.dict(os.environ, {'PATH': str(old.parent)}):
                    args = self.delivery.parse_args()
                    with self.assertRaises(self.delivery.DeliveryError) as raised:
                        self.delivery.finish(args)
                self.assertEqual((raised.exception.status, raised.exception.code), ('BLOCKED_POLICY', 2))
                if approved:
                    self.assertIn('Python 3.9', raised.exception.message)
                else:
                    self.assertIn('not approved', raised.exception.message)
                self.assertFalse((self.root / 'absent').exists())


    def run_checks_in(self, tests, pattern):
        """deliver.run_checks (the finish path) with a focused check, on a supported python3 first on PATH."""
        repo = self.root / 'repo'
        (repo / 'tests').mkdir(parents=True, exist_ok=True)
        for name, body in tests.items():
            (repo / 'tests' / name).write_text(body)
        bindir = self.root / 'bin'
        bindir.mkdir(exist_ok=True)
        if not (bindir / 'python3').exists():
            os.symlink(sys.executable, bindir / 'python3')
        command = ['python3', '-m', 'unittest', 'discover', '-s', 'tests', '-p', pattern]
        self.assertTrue(self.integrate.approved_check(command))
        with patch.dict(os.environ, {'PATH': str(bindir) + os.pathsep + os.environ['PATH']}):
            if sys.version_info < (3, 10):
                self.skipTest('the suite interpreter is older than the supported check Python (3.10)')
            self.delivery.run_checks(repo, [], [command], 60, self.root / 'logs')

    GOOD = 'import unittest\nclass T(unittest.TestCase):\n    def test_ok(self):\n        self.assertTrue(True)\n'

    def test_finish_run_checks_passes_a_focused_check_that_runs_a_test(self):
        self.run_checks_in({'test_a.py': self.GOOD, 'test_b.py': 'import unittest\nraise SystemExit(3)\n'}, 'test_a.py')

    def test_finish_run_checks_fails_a_focused_check_matching_no_file(self):
        with self.assertRaises(self.delivery.DeliveryError) as raised:
            self.run_checks_in({'test_a.py': self.GOOD}, 'test_missing.py')
        self.assertEqual(raised.exception.status, 'DELIVERED_CHECK_FAILED')

    def test_finish_run_checks_fails_a_focused_check_that_fails(self):
        bad = 'import unittest\nclass T(unittest.TestCase):\n    def test_no(self):\n        self.fail("intentional")\n'
        with self.assertRaises(self.delivery.DeliveryError) as raised:
            self.run_checks_in({'test_a.py': bad}, 'test_a.py')
        self.assertEqual(raised.exception.status, 'DELIVERED_CHECK_FAILED')


class TailRedaction(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.integrate = load('integrate_redaction_test', 'integrate_local.py')

    def test_common_secret_forms_are_redacted_but_test_names_survive(self):
        secrets = {'GITHUB_TOKEN=gho1secretvalue': 'gho1secretvalue', 'DB_PASSWORD=hunter2': 'hunter2',
                   'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI': 'wJalrXUtnFEMI', '{"password": "hunter3"}': 'hunter3',
                   'Authorization: Basic dXNlcjpwYXNz': 'dXNlcjpwYXNz', 'key AKIAABCDEFGHIJKLMNOP': 'AKIAABCDEFGHIJKLMNOP',
                   'ssh://user:pw9@host/repo': 'pw9', '--password hunter4': 'hunter4',
                   'bearer abc.def.ghi': 'abc.def.ghi', 'ghp_' + 'B' * 36: 'B' * 36,
                   '{"password": "two words here"}': 'words', 'MYSQL_PWD=abc9': 'abc9',
                   'Cookie: sid=abc8; theme=x': 'abc8',
                   '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaA\n-----END OPENSSH PRIVATE KEY-----': 'b3BlbnNzaA'}
        for line, secret in secrets.items():
            with self.subTest(line=line):
                self.assertNotIn(secret, self.integrate.redact_output(line))
        for benign in ('FAIL: test_token_refresh (tests.test_auth.Auth)', 'token budget exceeded', 'Ran 12 tests in 1.0s'):
            self.assertEqual(self.integrate.redact_output(benign), benign)

    def test_tail_window_never_starts_after_a_secret_key(self):
        log = self.integrate.CheckLog.__new__(self.integrate.CheckLog)
        log.truncated, log.path = False, Path('/dev/null')
        size = self.integrate.CHECK_TAIL_BYTES
        secret = b'password=S3CRETVALUE1234\n'
        for cut in range(len(secret)):
            rest = (('\u2713' * 40 + '\n').encode() * size)[:size - (len(secret) - cut)]
            log.tail = bytearray(secret[cut:] + rest)
            self.assertEqual(len(log.tail), size)
            # A large character budget isolates the byte-window guard from the trim guard.
            with self.subTest(cut=cut), patch.object(self.integrate, 'CHECK_TAIL_CHARS', 10 ** 6):
                self.assertNotIn('VALUE1234', log.facts()['check_tail'])


    def test_long_lines_are_omitted_and_redaction_stays_fast(self):
        log = self.integrate.CheckLog.__new__(self.integrate.CheckLog)
        log.truncated, log.path = False, Path('/dev/null')
        log.tail = bytearray(b'start\n' + b'tokenx' * 1500 + b'\nFAIL: test_last\n')
        started = time.monotonic()
        tail = log.facts()['check_tail']
        self.assertLess(time.monotonic() - started, 1.0)
        self.assertIn('[long line omitted]', tail)
        self.assertIn('FAIL: test_last', tail)

    def test_single_oversized_line_is_omitted_not_leaked(self):
        log = self.integrate.CheckLog.__new__(self.integrate.CheckLog)
        log.truncated, log.path = False, Path('/dev/null')
        log.tail = bytearray(b'Y' * self.integrate.CHECK_TAIL_BYTES)
        self.assertIn('omitted', log.facts()['check_tail'])


class CheckTimeoutOption(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.delivery = load('delivery_timeout_test', 'deliver.py')

    def parse(self, *extra):
        argv = ['deliver.py', 'finish', '--task', 'timeout-option', '--original', '/tmp/x',
                '--original-branch', 'main', '--mode', 'remote', '--check', 'python3 -m unittest discover -s tests',
                *extra]
        with patch.object(sys, 'argv', argv):
            return self.delivery.parse_args()

    def test_check_deadline_defaults_to_suite_size_and_is_bounded(self):
        args = self.parse()
        self.assertEqual((args.timeout, args.check_timeout), (120, 1800))
        self.assertEqual(self.parse('--check-timeout', '3600').check_timeout, 3600)
        for invalid in ('0', '7201'):
            with self.assertRaises(SystemExit), patch('sys.stderr'):
                self.parse('--check-timeout', invalid)


class DiscardSink(unittest.TestCase):
    def test_sink_receives_every_byte_and_cannot_be_used_without_discard(self):
        process = load('process_sink_test', 'process.py')
        received = []
        result = process.run([sys.executable, '-c', 'import sys; sys.stdout.write("a" * 200000); '
                                                    'sys.stdout.flush(); sys.stderr.write("TZ-END")'],
                             discard_output=True, timeout=60, sink=received.append)
        data = b''.join(received)
        self.assertEqual((result.returncode, result.stdout), (0, None))
        self.assertEqual(data.count(b'a'), 200000)
        self.assertTrue(data.endswith(b'TZ-END'))
        with self.assertRaises(ValueError):
            process.run([sys.executable, '-c', 'pass'], sink=received.append)


if __name__ == '__main__':
    unittest.main()
