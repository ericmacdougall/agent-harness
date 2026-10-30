import os
import select
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path


WATCH = Path(__file__).resolve().parents[1] / 'harness/tools/watch-tests.py'


class WatchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def invoke(self, *args, timeout=12):
        return subprocess.run([sys.executable, str(WATCH), '--root', str(self.root), *args],
                              capture_output=True, text=True, timeout=timeout)

    def test_once_preserves_test_failure_and_success_exits(self):
        for code in (0, 7):
            with self.subTest(code=code):
                result = self.invoke('--once', '--', sys.executable, '-c', f'raise SystemExit({code})')
                self.assertEqual(result.returncode, code)
                self.assertIn(f'[watch] exit {code}', result.stdout)

    def test_missing_command_and_bad_timeout_are_configuration_errors(self):
        self.assertEqual(self.invoke('--once').returncode, 2)
        self.assertEqual(self.invoke('--timeout', '0', '--once', '--', sys.executable, '-c', 'pass').returncode, 2)

    def test_stalled_test_and_child_are_terminated(self):
        pid_file = self.root / 'child.pid'
        late = self.root / 'late.txt'
        child = (f'import os, time; from pathlib import Path; '
                 f'Path({str(pid_file)!r}).write_text(str(os.getpid())); '
                 f'time.sleep(10); Path({str(late)!r}).write_text("late")')
        parent = ('import subprocess, sys, time; '
                  f'subprocess.Popen([sys.executable, "-c", {child!r}]); time.sleep(10)')
        started = time.monotonic()
        result = self.invoke('--once', '--timeout', '1', '--', sys.executable, '-c', parent)
        self.assertEqual(result.returncode, 124, result.stdout + result.stderr)
        self.assertLess(time.monotonic() - started, 8)
        self.assertTrue(pid_file.exists(), 'the child must start before the deadline')
        with self.assertRaises(ProcessLookupError):
            os.kill(int(pid_file.read_text()), 0)
        self.assertFalse(late.exists())

    def test_watch_reruns_after_a_source_edit_and_ignores_vendor_edit(self):
        source = self.root / 'app.py'
        source.write_text('first\n')
        vendor = self.root / 'node_modules'
        vendor.mkdir()
        (vendor / 'module.py').write_text('first\n')
        marker = self.root / 'runs.txt'
        command = (f'from pathlib import Path; p=Path({str(marker)!r}); '
                   'p.write_text(p.read_text()+"x" if p.exists() else "x")')
        process = subprocess.Popen([sys.executable, str(WATCH), '--root', str(self.root),
                                    '--interval', '0.1', '--', sys.executable, '-c', command],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                   start_new_session=True)
        try:
            deadline = time.monotonic() + 5
            while not marker.exists() and time.monotonic() < deadline:
                time.sleep(0.05)
            self.assertTrue(marker.exists())
            (vendor / 'module.py').write_text('second\n')
            time.sleep(0.5)
            self.assertEqual(marker.read_text(), 'x')
            source.write_text('second\n')
            deadline = time.monotonic() + 5
            while marker.read_text() != 'xx' and time.monotonic() < deadline:
                time.sleep(0.05)
            self.assertEqual(marker.read_text(), 'xx')
        finally:
            os.killpg(process.pid, signal.SIGTERM)
            process.communicate(timeout=5)

    def test_ctrl_c_during_test_run_stops_child_without_traceback(self):
        child_pid = self.root / 'test.pid'
        code = (f'import os, time; from pathlib import Path; '
                f'Path({str(child_pid)!r}).write_text(str(os.getpid())); time.sleep(30)')
        process = subprocess.Popen([sys.executable, str(WATCH), '--root', str(self.root), '--once',
                                    '--', sys.executable, '-c', code],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                   start_new_session=True)
        try:
            deadline = time.monotonic() + 5
            while not child_pid.exists() and time.monotonic() < deadline:
                time.sleep(0.05)
            self.assertTrue(child_pid.exists())
            os.kill(process.pid, signal.SIGINT)
            output, errors = process.communicate(timeout=8)
            self.assertEqual(process.returncode, 130, output + errors)
            self.assertIn('[watch] stopped during test run', output)
            self.assertNotIn('Traceback', errors)
            with self.assertRaises(ProcessLookupError):
                os.kill(int(child_pid.read_text()), 0)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.communicate(timeout=5)


if __name__ == '__main__':
    unittest.main()
