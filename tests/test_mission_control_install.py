"""Mission Control installer wiring (GoodQA #15585 AC-11, AC-12, NEG-11)."""

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import mission_control_install as mci
from install import hook_argv, install


class Recorder:
    def __init__(self, code=0):
        self.calls, self.code = [], code

    def __call__(self, argv):
        self.calls.append(argv)
        return SimpleNamespace(returncode=self.code, stdout="", stderr="boom" if self.code else "")


class MissionControlInstall(unittest.TestCase):
    def setUp(self):
        isolate = patch.dict(os.environ)
        isolate.start()
        self.addCleanup(isolate.stop)
        os.environ.pop("CLAUDE_CODE_TMPDIR", None)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name).resolve()
        (self.home / ".claude").mkdir()

    def test_mission_app_copy_is_staged_swapped_and_private(self):
        count = mci.install_app(self.home)
        app = mci.app_dir(self.home)
        self.assertGreater(count, 10)
        self.assertTrue((app / "server.py").is_file())
        self.assertTrue((app / "web" / "index.html").is_file())
        self.assertTrue((app / "web" / "vendor" / "three.module.min.js").is_file())
        self.assertFalse((app / "web" / "tests").exists(), "tests are not installed")
        self.assertFalse(list(app.rglob("__pycache__")))
        self.assertEqual(stat.S_IMODE((app / "server.py").stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(mci.mc_root(self.home).stat().st_mode), 0o700)
        (app / "marker").write_text("old")
        mci.install_app(self.home)
        self.assertTrue((mci.mc_root(self.home) / "app.prev" / "marker").is_file(), "the previous copy is kept")
        self.assertFalse((app / "marker").exists())
        self.assertEqual([p.name for p in mci.mc_root(self.home).iterdir() if p.name.startswith(".app-")], [])

    def test_mission_app_refuses_a_symlinked_app_dir(self):
        elsewhere = self.home / "elsewhere"
        elsewhere.mkdir()
        mci.real_dir(self.home / ".agent-harness")
        mci.real_dir(mci.mc_root(self.home))
        os.symlink(elsewhere, mci.app_dir(self.home))
        line = mci.status(self.home, True, True, run=Recorder(), system="linux")
        self.assertIn("skipped", line)
        self.assertEqual(list(elsewhere.iterdir()), [], "nothing is written through the link")

    def test_mission_service_is_only_registered_for_the_real_home_on_macos(self):
        run = Recorder()
        line = mci.status(self.home, True, None, run=run, system="darwin")
        self.assertIn("skipped (non-default --home", line)
        self.assertFalse(mci.app_dir(self.home).exists())
        line = mci.status(self.home, True, True, run=run, system="darwin")
        self.assertTrue((mci.app_dir(self.home) / "server.py").is_file(), line)
        self.assertEqual(run.calls, [], "a non-default home never touches launchd")
        with patch.object(mci, "real_home", return_value=self.home):
            line = mci.status(self.home, True, None, run=run, system="darwin")
            self.assertIn("LaunchAgent com.agent-harness.mission-control: ok", line)
            argv = run.calls[-1]
            self.assertEqual(argv[0], "/usr/bin/python3")
            self.assertEqual(argv[1], str(mci.app_dir(self.home) / "server.py"), "launchd runs the installed copy")
            self.assertEqual(argv[2:], ["install-launchd", "--apply", "--python", "/usr/bin/python3"])
            calls = len(run.calls)
            mci.status(self.home, True, None, run=run, system="linux")
            self.assertEqual(len(run.calls), calls, "no launchd off macOS")

    def test_mission_failed_launchctl_is_reported_not_raised(self):
        with patch.object(mci, "real_home", return_value=self.home):
            line = mci.status(self.home, True, None, run=Recorder(code=1), system="darwin")
        self.assertIn("install-launchd failed (exit 1): boom", line)

    def test_no_mission_control_stops_the_service_and_is_remembered(self):
        run = Recorder()
        with patch.object(mci, "real_home", return_value=self.home):
            mci.status(self.home, True, None, run=run, system="darwin")
            plist = self.home / "Library" / "LaunchAgents" / f"{mci.LABEL}.plist"
            plist.parent.mkdir(parents=True)
            plist.write_text("<plist/>")
            line = mci.status(self.home, True, False, run=run, system="darwin")
            self.assertIn("off; LaunchAgent stopped (ok)", line)
            self.assertEqual(run.calls[-1][2:4], ["uninstall-launchd", "--apply"])
            self.assertTrue((mci.app_dir(self.home) / "server.py").is_file(), "files stay")
            calls = len(run.calls)
            line = mci.status(self.home, True, None, run=run, system="darwin")
            self.assertTrue(line.startswith("mission control: off"), line)
            self.assertNotIn("install-launchd", [c[2] for c in run.calls[calls:]], "a remembered opt-out never re-registers")
            self.assertFalse(mci.choice(self.home, None))
            self.assertTrue(mci.choice(self.home, True))

    def test_mission_preview_writes_nothing(self):
        with patch.object(mci, "real_home", return_value=self.home):
            run = Recorder()
            line = mci.status(self.home, False, True, run=run, system="darwin")
        self.assertIn("would copy", line)
        self.assertFalse((self.home / ".agent-harness").exists())
        self.assertEqual(run.calls, [])


if __name__ == "__main__":
    unittest.main()
