"""GoodQA #15565 (item 22): the `timeout` stand-in for hosts without coreutils, and its installer step."""

import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SHIM = ROOT / "harness" / "bin" / "timeout"
sys.path.insert(0, str(ROOT))
import install  # noqa: E402


def run(*args, limit=20):
    started = time.monotonic()
    result = subprocess.run([sys.executable, str(SHIM), *args], capture_output=True, text=True, timeout=limit)
    return result, time.monotonic() - started


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

    def test_skips_when_local_bin_is_not_on_path(self):
        self.assertIn("not on PATH", install.timeout_shim_status(self.home, True, ["/usr/bin"]))


if __name__ == "__main__":
    unittest.main()
