"""GoodQA #15565 (item 22): the `timeout` stand-in for hosts without coreutils, and its installer step."""

import errno
import importlib.machinery
import importlib.util
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SHIM = ROOT / "harness" / "bin" / "timeout"
sys.path.insert(0, str(ROOT))
import install  # noqa: E402


def run(*args, limit=20):
    started = time.monotonic()
    result = subprocess.run([sys.executable, str(SHIM), *args], capture_output=True, text=True, timeout=limit)
    return result, time.monotonic() - started


def load_shim():
    loader = importlib.machinery.SourceFileLoader("timeout_shim_under_test", str(SHIM))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


class Shim(unittest.TestCase):
    def test_runs_a_command_and_passes_its_status_through(self):
        self.assertEqual(run("5", sys.executable, "-c", "print('ok')")[0].stdout.strip(), "ok")
        self.assertEqual(run("5", sys.executable, "-c", "import sys; sys.exit(7)")[0].returncode, 7)

    def test_a_slow_command_is_stopped_with_124_and_its_children_with_it(self):
        code = ("import subprocess,sys,time; subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)']);"
                "time.sleep(30)")
        result, elapsed = run("0.4", sys.executable, "-c", code)
        self.assertEqual(result.returncode, 124)
        self.assertLess(elapsed, 5)

    def test_kill_after_stops_a_command_that_ignores_term(self):
        code = "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(30)"
        result, elapsed = run("-k", "0.3", "0.3", sys.executable, "-c", code)
        self.assertEqual(result.returncode, 124)
        self.assertLess(elapsed, 6)

    def test_preserve_status_and_duration_units(self):
        result, _ = run("--preserve-status", "0.3s", sys.executable, "-c", "import time; time.sleep(30)")
        self.assertEqual(result.returncode, 128 + 15)
        self.assertEqual(run("0.001m", sys.executable, "-c", "import time; time.sleep(30)")[0].returncode, 124)

    def test_zero_means_no_limit_and_bad_usage_is_125_or_127(self):
        self.assertEqual(run("0", sys.executable, "-c", "pass")[0].returncode, 0)
        self.assertEqual(run("abc", "true")[0].returncode, 125)
        self.assertEqual(run("5")[0].returncode, 125)
        self.assertEqual(run("5", "/nonexistent/command")[0].returncode, 127)

    def test_an_invalid_signal_is_125_and_the_command_never_starts(self):
        # Codex final-gate F1: `-s 999999` reached os.killpg after the command started and crashed the shim
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / "started"
            code = "import sys,time; open(sys.argv[1],'w').close(); time.sleep(30)"
            for value in ("999999", "0", "65", "_DFL", "SIG_DFL", "NOPE", "99999999999999999999"):
                for form in (["-s", value], ["-s" + value], ["--signal=" + value]):
                    with self.subTest(form=form):
                        result, elapsed = run(*form, "0.1", sys.executable, "-c", code, str(marker))
                        self.assertEqual(result.returncode, 125, result.stderr)
                        self.assertFalse(marker.exists(), "the command started despite an invalid signal")
                        self.assertLess(elapsed, 5)

    def test_valid_signal_names_and_numbers_still_work(self):
        sleeper = (sys.executable, "-c", "import time; time.sleep(30)")
        for form in (["-s", "KILL"], ["-s", "9"], ["-sINT"], ["--signal=SIGTERM"], ["-s", "term"]):
            with self.subTest(form=form):
                result, elapsed = run(*form, "0.2", *sleeper)
                self.assertEqual(result.returncode, 124, result.stderr)
                self.assertLess(elapsed, 5)

    def test_a_signal_delivery_failure_still_stops_and_reaps_the_command_with_125(self):
        # Codex final-gate F1: any delivery error (not only ProcessLookupError/PermissionError) must not orphan
        shim = load_shim()
        started = []
        real_popen = subprocess.Popen

        def spy(*args, **kwargs):
            started.append(real_popen(*args, **kwargs))
            return started[-1]

        def refuse(_pid, _number):
            raise OSError(errno.EINVAL, "Invalid argument")

        saved = {n: signal.getsignal(n) for n in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)}
        self.addCleanup(lambda: [signal.signal(n, h) for n, h in saved.items()])

        def cleanup():
            for child in started:
                if child.poll() is None:
                    child.kill()
                    child.wait()
        self.addCleanup(cleanup)
        began = time.monotonic()
        with mock.patch.object(shim.subprocess, "Popen", spy), mock.patch.object(shim.os, "killpg", refuse):
            try:
                code = shim.main(["0.2", sys.executable, "-c", "import time; time.sleep(30)"])
            except Exception as error:  # the defect: the error escaped main() and left the child running
                self.fail("delivery failure escaped main(): %r" % error)
        self.assertEqual(code, 125)
        self.assertLess(time.monotonic() - began, 10)
        self.assertEqual(len(started), 1)
        self.assertIsNotNone(started[0].returncode, "the command was not reaped")
        with self.assertRaises(ProcessLookupError):
            os.kill(started[0].pid, 0)  # reaped: no process, not even a zombie


class Installer(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        self.bin = self.home / ".local" / "bin"
        self.bin.mkdir(parents=True)

    def test_places_the_shim_only_when_none_exists_and_local_bin_is_on_path(self):
        path = [str(self.bin)]
        self.assertIn("would place", install.timeout_shim_status(self.home, False, path))
        self.assertFalse((self.bin / "timeout").exists())
        self.assertIn("placed", install.timeout_shim_status(self.home, True, path))
        self.assertTrue(os.access(self.bin / "timeout", os.X_OK))
        self.assertIn("current", install.timeout_shim_status(self.home, True, path))

    def test_never_replaces_an_existing_command_or_a_foreign_file(self):
        other = self.home / "other"
        other.mkdir()
        (other / "timeout").write_text("#!/bin/sh\n")
        (other / "timeout").chmod(0o755)
        self.assertIn("not needed", install.timeout_shim_status(self.home, True, [str(self.bin), str(other)]))
        (self.bin / "timeout").write_text("#!/bin/sh\necho mine\n")
        self.assertIn("not ours", install.timeout_shim_status(self.home, True, [str(self.bin)]))
        self.assertEqual((self.bin / "timeout").read_text(), "#!/bin/sh\necho mine\n")

    def test_a_planted_link_a_directory_or_a_lookalike_marker_is_never_written_through_or_replaced(self):
        # red-team ad4294 C2
        victim = self.home / "victim.txt"
        victim.write_text("keep me")
        os.symlink(victim, self.bin / f".timeout.tmp{os.getpid()}")  # planted at the temp name
        status = install.timeout_shim_status(self.home, True, [str(self.bin)])
        self.assertIn("not placed", status)
        self.assertEqual(victim.read_text(), "keep me")
        os.unlink(self.bin / f".timeout.tmp{os.getpid()}")
        (self.bin / "timeout").mkdir()  # a directory named timeout must not abort the install
        self.assertIn("not a regular file", install.timeout_shim_status(self.home, True, [str(self.bin)]))
        os.rmdir(self.bin / "timeout")
        (self.bin / "timeout").write_text("#!/bin/sh\necho mine\n# GoodQA #15565 is only a comment here\n")
        self.assertIn("not ours", install.timeout_shim_status(self.home, True, [str(self.bin)]))
        os.unlink(self.bin / "timeout")
        os.symlink(victim, self.bin / "timeout")
        self.assertIn("link", install.timeout_shim_status(self.home, True, [str(self.bin)]))
        self.assertEqual(victim.read_text(), "keep me")

    def publish_race(self, interfere):
        """Run the installer and call interfere() the moment the temp file is created, i.e. after the
        replaceability check and before publication (Codex final-gate F2)."""
        real_open = os.open
        fired = []

        def hooked(path, flags, *args, **kwargs):
            fd = real_open(path, flags, *args, **kwargs)
            if Path(path).name.startswith(".timeout.tmp") and flags & os.O_CREAT and not fired:
                fired.append(path)
                interfere()
            return fd

        with mock.patch.object(install.os, "open", hooked):
            status = install.timeout_shim_status(self.home, True, [str(self.bin)])
        self.assertTrue(fired, "the hook never ran; the race was not exercised")
        self.assertEqual([p.name for p in self.bin.iterdir() if p.name.startswith(".timeout.tmp")], [])
        return status

    def outdated_shim(self):
        target = self.bin / "timeout"
        target.write_bytes(SHIM.read_bytes() + b"# an older revision\n")
        target.chmod(0o755)
        return target

    def test_a_foreign_file_created_between_check_and_publish_survives(self):
        target = self.bin / "timeout"
        status = self.publish_race(lambda: target.write_text("#!/bin/sh\necho foreign\n"))
        self.assertNotIn("placed " + str(target), status)
        self.assertEqual(target.read_text(), "#!/bin/sh\necho foreign\n")

    def test_a_link_created_between_check_and_publish_survives(self):
        target, victim = self.bin / "timeout", self.home / "victim.txt"
        victim.write_text("keep me")
        status = self.publish_race(lambda: os.symlink(victim, target))
        self.assertNotIn("placed " + str(target), status)
        self.assertTrue(target.is_symlink())
        self.assertEqual(victim.read_text(), "keep me")

    def test_an_owned_shim_swapped_for_a_foreign_file_before_publish_survives(self):
        target = self.outdated_shim()

        def swap():
            os.unlink(target)
            target.write_text("#!/bin/sh\necho foreign\n")
        status = self.publish_race(swap)
        self.assertNotIn("placed " + str(target), status)
        self.assertEqual(target.read_text(), "#!/bin/sh\necho foreign\n")

    def test_an_owned_shim_rewritten_in_place_before_publish_survives(self):
        target = self.outdated_shim()
        status = self.publish_race(lambda: target.write_text("#!/bin/sh\necho rewritten\n"))
        self.assertNotIn("placed " + str(target), status)
        self.assertEqual(target.read_text(), "#!/bin/sh\necho rewritten\n")

    def test_an_outdated_owned_shim_is_updated_when_nothing_interferes(self):
        target = self.outdated_shim()
        self.assertIn("placed", self.publish_race(lambda: None))
        self.assertEqual(target.read_bytes(), SHIM.read_bytes())

    def test_skips_when_local_bin_is_not_on_path(self):
        self.assertIn("not on PATH", install.timeout_shim_status(self.home, True, ["/usr/bin"]))


if __name__ == "__main__":
    unittest.main()
