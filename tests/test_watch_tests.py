import contextlib
import importlib.util
import io
import os
import select
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch


WATCH = Path(__file__).resolve().parents[1] / 'harness/tools/watch-tests.py'


def load_watcher():
    spec = importlib.util.spec_from_file_location('watch_tests_under_test', WATCH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class WatchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def invoke(self, *args, timeout=12):
        return subprocess.run([sys.executable, str(WATCH), '--root', str(self.root), *args],
                              capture_output=True, text=True, timeout=timeout)

    def wait_for_runs(self, process, count, timeout=6):
        output = b''
        deadline = time.monotonic() + timeout
        while output.count(b'[watch] exit ') < count:
            remaining = deadline - time.monotonic()
            self.assertGreater(remaining, 0, output.decode(errors='replace'))
            ready, _, _ = select.select([process.stdout], [], [], remaining)
            self.assertTrue(ready, output.decode(errors='replace'))
            chunk = os.read(process.stdout.fileno(), 4096)
            self.assertTrue(chunk, output.decode(errors='replace'))
            output += chunk
        return output

    def test_once_preserves_test_failure_and_success_exits(self):
        for code in (0, 7):
            with self.subTest(code=code):
                result = self.invoke('--once', '--', sys.executable, '-c', f'raise SystemExit({code})')
                self.assertEqual(result.returncode, code)
                self.assertIn(f'[watch] exit {code}', result.stdout)

    def test_missing_command_and_bad_timeout_are_configuration_errors(self):
        self.assertEqual(self.invoke('--once').returncode, 2)
        self.assertEqual(self.invoke('--timeout', '0', '--once', '--', sys.executable, '-c', 'pass').returncode, 2)

    def test_status_does_not_echo_command_arguments(self):
        sensitive = 'fixture-sensitive-argument'
        for exit_code in (0, 7):
            with self.subTest(exit_code=exit_code):
                result = self.invoke('--once', '--', sys.executable, '-c',
                                     f'raise SystemExit({exit_code})', sensitive)
                self.assertEqual(result.returncode, exit_code, result.stderr)
                self.assertNotIn(sensitive, result.stdout + result.stderr)
                self.assertNotIn(str(self.root), result.stdout + result.stderr)

    def test_missing_executable_does_not_echo_its_path(self):
        sensitive = 'fixture-sensitive-executable'
        result = self.invoke('--once', '--', str(self.root / sensitive))
        self.assertEqual(result.returncode, 127)
        self.assertNotIn(sensitive, result.stdout + result.stderr)

    def test_default_snapshot_covers_common_dependency_files(self):
        names = ('pyproject.toml', 'requirements.txt', 'poetry.lock', 'uv.lock',
                 'go.mod', 'go.sum', 'go.work', 'go.work.sum',
                 'pnpm-lock.yaml', 'yarn.lock')
        for name in names:
            (self.root / name).write_text('synthetic\n')
        watcher = load_watcher()
        observed = watcher.snapshot(self.root, {'.not-a-source-extension'})
        self.assertTrue(set(names).issubset(observed), set(names) - set(observed))

    def test_snapshot_does_not_follow_symlinked_source_outside_root(self):
        watcher = load_watcher()
        outside = self.root.parent / f'{self.root.name}-outside.py'
        outside.write_text('first\n')
        self.addCleanup(outside.unlink)
        link = self.root / 'linked.py'
        link.symlink_to(outside)
        outside_dir = self.root.parent / f'{self.root.name}-outside-dir'
        outside_dir.mkdir()
        self.addCleanup(outside_dir.rmdir)
        (outside_dir / 'nested.py').write_text('outside\n')
        self.addCleanup((outside_dir / 'nested.py').unlink)
        (self.root / 'linked-dir').symlink_to(outside_dir, target_is_directory=True)
        before = watcher.snapshot(self.root, watcher.DEFAULT_EXTENSIONS)
        outside.write_text('second and longer\n')
        after = watcher.snapshot(self.root, watcher.DEFAULT_EXTENSIONS)
        self.assertEqual(before, after)
        self.assertNotIn('linked.py', before)
        self.assertFalse(any(name.startswith('linked-dir/') for name in before))

    def test_atomic_replace_with_restored_mtime_changes_snapshot(self):
        watcher = load_watcher()
        source = (self.root / 'app.py').resolve()
        source.write_text('first\n')
        before = watcher.snapshot(self.root, watcher.DEFAULT_EXTENSIONS)
        original = source.stat()
        replacement = self.root / 'temporary'
        replacement.write_text('other\n')
        os.utime(replacement, ns=(original.st_atime_ns, original.st_mtime_ns))
        os.replace(replacement, source)
        self.assertNotEqual(source.stat().st_ino, original.st_ino)
        self.assertEqual(source.stat().st_mtime_ns, original.st_mtime_ns)
        self.assertEqual(source.stat().st_size, original.st_size)
        self.assertNotEqual(watcher.snapshot(self.root, watcher.DEFAULT_EXTENSIONS), before)

    def test_scan_errors_are_loud_and_path_free(self):
        watcher = load_watcher()
        private = 'fixture-private-source-path'

        def walk_error(*args, **kwargs):
            kwargs['onerror'](OSError(private))
            yield from ()

        with patch.object(watcher.os, 'walk', side_effect=walk_error):
            with self.assertRaises(OSError) as raised:
                watcher.snapshot(self.root, watcher.DEFAULT_EXTENSIONS)
        self.assertNotIn(private, str(raised.exception))
        for sequence in ((OSError(private),), ({}, OSError(private))):
            with self.subTest(sequence=sequence), \
                 patch.object(watcher, 'snapshot', side_effect=sequence), \
                 patch.object(watcher, 'run_process', return_value=subprocess.CompletedProcess([], 0)), \
                 patch.object(sys, 'argv', [str(WATCH), '--root', str(self.root), '--', 'fixture']), \
                 contextlib.redirect_stdout(io.StringIO()) as stdout, \
                 contextlib.redirect_stderr(io.StringIO()) as stderr:
                self.assertEqual(watcher.main(), 2)
                self.assertNotIn(private, stdout.getvalue() + stderr.getvalue())

    def test_file_metadata_errors_are_loud_and_path_free(self):
        watcher = load_watcher()
        source = (self.root / 'app.py').resolve()
        source.write_text('synthetic\n')
        private = 'fixture-private-metadata-path'
        original_stat = os.stat
        for fail_on, expected_runs in ((1, 0), (2, 1)):
            seen = 0

            def fail_stat(path, *args, **kwargs):
                nonlocal seen
                if Path(path) == source:
                    seen += 1
                    if seen == fail_on:
                        raise PermissionError(private)
                return original_stat(path, *args, **kwargs)

            with self.subTest(fail_on=fail_on), \
                 patch.object(watcher.os, 'stat', side_effect=fail_stat), \
                 patch.object(watcher, 'run_process',
                              return_value=subprocess.CompletedProcess([], 0)) as run, \
                 patch.object(sys, 'argv', [str(WATCH), '--root', str(self.root), '--', 'fixture']), \
                 contextlib.redirect_stdout(io.StringIO()) as stdout, \
                 contextlib.redirect_stderr(io.StringIO()) as stderr:
                self.assertEqual(watcher.main(), 2)
                self.assertEqual(run.call_count, expected_runs)
                self.assertNotIn(private, stdout.getvalue() + stderr.getvalue())

    def test_stalled_test_and_child_are_terminated(self):
        pid_file = self.root / 'child.pid'
        late = self.root / 'late.txt'
        child = (f'import os, time; from pathlib import Path; '
                 f'Path({str(pid_file)!r}).write_text(str(os.getpid())); '
                 f'time.sleep(20); Path({str(late)!r}).write_text("late")')
        parent = ('import subprocess, sys, time; '
                  f'subprocess.Popen([sys.executable, "-c", {child!r}]); time.sleep(20)')
        started = time.monotonic()
        sensitive = 'fixture-sensitive-timeout-argument'
        result = self.invoke('--once', '--timeout', '6', '--', sys.executable,
                             '-c', parent, sensitive, timeout=30)
        self.assertEqual(result.returncode, 124, result.stdout + result.stderr)
        self.assertNotIn(sensitive, result.stdout + result.stderr)
        self.assertLess(time.monotonic() - started, 25)
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
        (vendor / 'pnpm-lock.yaml').write_text('first\n')
        lockfile = self.root / 'pnpm-lock.yaml'
        lockfile.write_text('first\n')
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
            self.wait_for_runs(process, 1)
            (vendor / 'module.py').write_text('second\n')
            (vendor / 'pnpm-lock.yaml').write_text('second\n')
            time.sleep(0.5)
            self.assertEqual(marker.read_text(), 'x')
            original = source.stat()
            source.write_text('other\n')
            os.utime(source, ns=(original.st_atime_ns, original.st_mtime_ns))
            self.assertEqual(source.stat().st_size, original.st_size)
            self.assertEqual(source.stat().st_mtime_ns, original.st_mtime_ns)
            deadline = time.monotonic() + 1.5
            while source.stat().st_ctime_ns == original.st_ctime_ns and time.monotonic() < deadline:
                time.sleep(0.02)
                os.utime(source, ns=(original.st_atime_ns, original.st_mtime_ns))
            self.assertNotEqual(source.stat().st_ctime_ns, original.st_ctime_ns)
            deadline = time.monotonic() + 5
            while marker.read_text() != 'xx' and time.monotonic() < deadline:
                time.sleep(0.05)
            self.assertEqual(marker.read_text(), 'xx')
            self.wait_for_runs(process, 1)
            lockfile.write_text('other\n')
            deadline = time.monotonic() + 5
            while marker.read_text() != 'xxx' and time.monotonic() < deadline:
                time.sleep(0.05)
            self.assertEqual(marker.read_text(), 'xxx')
            self.wait_for_runs(process, 1)
        finally:
            os.killpg(process.pid, signal.SIGTERM)
            process.communicate(timeout=5)

    def test_edit_during_test_run_triggers_immediate_rerun(self):
        source = self.root / 'app.py'
        source.write_text('first\n')
        marker = self.root / 'runs.txt'
        before = source.stat()
        command = ('import os, time; from pathlib import Path; '
                   f's=Path({str(source)!r}); p=Path({str(marker)!r}); '
                   'first=not p.exists(); '
                   'before=s.stat() if first else None; '
                   'time.sleep(1.1) if first else None; '
                   's.write_text("other\\n") if first else None; '
                   'os.utime(s, ns=(before.st_atime_ns, before.st_mtime_ns)) if first else None; '
                   'p.write_text(p.read_text()+"x" if p.exists() else "x")')
        process = subprocess.Popen([sys.executable, str(WATCH), '--root', str(self.root),
                                    '--interval', '0.1', '--', sys.executable, '-c', command],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                   start_new_session=True)
        try:
            deadline = time.monotonic() + 5
            while (not marker.exists() or marker.read_text() != 'xx') and time.monotonic() < deadline:
                time.sleep(0.05)
            self.assertEqual(marker.read_text(), 'xx')
            self.wait_for_runs(process, 2)
            self.assertEqual(source.stat().st_mtime_ns, before.st_mtime_ns)
            self.assertEqual(source.stat().st_size, before.st_size)
            self.assertNotEqual(source.stat().st_ctime_ns, before.st_ctime_ns)
        finally:
            os.killpg(process.pid, signal.SIGTERM)
            process.communicate(timeout=5)

    def test_generated_json_reports_do_not_retrigger_watcher(self):
        output_names = ('coverage', 'test-results', 'playwright-report', '.next', 'vendor')
        for name in output_names:
            folder = self.root / name
            folder.mkdir()
            (folder / 'report.json').write_text('{"run":0}\n')
        (self.root / 'vendor' / 'dependency.go').write_text('package dependency\n')
        watcher = load_watcher()
        observed = watcher.snapshot(self.root, watcher.DEFAULT_EXTENSIONS)
        self.assertFalse(any(name.startswith(f'{folder}/')
                             for folder in output_names for name in observed), observed)

        marker = self.root / 'runs.txt'
        report = self.root / 'coverage' / 'report.json'
        command = ('from pathlib import Path; '
                   f'm=Path({str(marker)!r}); r=Path({str(report)!r}); '
                   'm.write_text(m.read_text()+"x" if m.exists() else "x"); '
                   'r.write_text("{\\"run\\":"+str(len(m.read_text()))+"}\\n")')
        process = subprocess.Popen([sys.executable, str(WATCH), '--root', str(self.root),
                                    '--interval', '0.1', '--', sys.executable, '-c', command],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                   start_new_session=True)
        try:
            self.wait_for_runs(process, 1)
            time.sleep(0.5)
            self.assertEqual(marker.read_text(), 'x')
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
