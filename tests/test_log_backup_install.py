"""log_backup_install: idempotent install over hand-installed copies, with an injected scheduler runner."""
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import install  # noqa: E402
import log_backup_install as lbi  # noqa: E402

PLIST = "Library/LaunchAgents/com.ericmacdougall.log-backup.plist"
UNITS = (".config/systemd/user/log-backup.service", ".config/systemd/user/log-backup.timer")
SCRIPT = ".agent-harness/bin/log-backup.sh"


class Runner:
    def __init__(self, code=0):
        self.calls, self.code = [], code

    def __call__(self, argv):
        self.calls.append(argv)
        return self.code


class Case(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="logbackup-inst-")).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.home = self.tmp / "home"
        self.home.mkdir()

    def seed(self, rel, text="hand installed\n"):
        path = self.home / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    def holder(self, directory="holder"):
        """A live process that looks like a backup run: `sh <dir>/log-backup.sh` (the dir name may hold a space)."""
        script = self.tmp / directory / "log-backup.sh"
        script.parent.mkdir(parents=True, exist_ok=True)
        script.write_text("#!/bin/sh\nsleep 60\n")
        proc = subprocess.Popen(["/bin/sh", str(script)])
        self.addCleanup(lambda: (proc.terminate(), proc.wait()))
        time.sleep(0.3)
        return proc

    def lock_held_by(self, pid, age=0):
        lock = self.home / ".agent-harness/logs/log-backup.lock.d"
        lock.mkdir(parents=True)
        (lock / "pid").write_text(str(pid))
        if age:
            when = time.time() - age
            os.utime(lock, (when, when))
        return lock

    def apply(self, system, runner=None, **kw):
        runner = runner if runner is not None else Runner()
        message = lbi.status(self.home, True, system=system, run=runner, uid=501, activate=kw.pop("activate", True), **kw)
        return message, runner


class Darwin(Case):
    def test_replaces_hand_installed_files_backs_them_up_and_reloads_once(self):
        self.seed(SCRIPT, "old script\n")
        self.seed(PLIST, "old plist\n")
        message, runner = self.apply("Darwin")
        self.assertIn("installed", message)
        self.assertEqual((self.home / SCRIPT).read_bytes(), (ROOT / "harness/bin/log-backup.sh").read_bytes())
        self.assertEqual((self.home / ".agent-harness/bin/log-backup.excludes").read_bytes(),
                         (ROOT / "harness/bin/log-backup.excludes").read_bytes())
        self.assertTrue(os.access(self.home / SCRIPT, os.X_OK))
        baks = sorted(p.name for p in (self.home / ".agent-harness/bin").glob("log-backup.sh.bak-*"))
        self.assertEqual(len(baks), 1)
        self.assertEqual(next((self.home / ".agent-harness/bin").glob("log-backup.sh.bak-*")).read_text(), "old script\n")
        plist = (self.home / PLIST).read_text()
        self.assertIn("<key>Label</key><string>com.ericmacdougall.log-backup</string>", plist)
        self.assertIn(f"{self.home}/.agent-harness/bin/log-backup.sh", plist)
        self.assertNotIn("@HOME@", plist)
        self.assertEqual(runner.calls, [["launchctl", "bootout", "gui/501/com.ericmacdougall.log-backup"],
                                        ["launchctl", "bootstrap", "gui/501", str(self.home / PLIST)]])

    def test_second_apply_changes_nothing_and_reloads_nothing(self):
        self.apply("Darwin")
        snapshot = sorted((str(p), p.read_bytes()) for p in self.home.rglob("*") if p.is_file())
        message, runner = self.apply("Darwin")
        self.assertEqual(runner.calls, [])
        self.assertIn("up to date", message)
        self.assertEqual(sorted((str(p), p.read_bytes()) for p in self.home.rglob("*") if p.is_file()), snapshot)

    def test_script_only_change_does_not_reload(self):
        self.apply("Darwin")
        (self.home / SCRIPT).write_text("tampered\n")
        message, runner = self.apply("Darwin")
        self.assertEqual(runner.calls, [])
        self.assertIn("scheduler untouched", message)
        self.assertEqual((self.home / SCRIPT).read_bytes(), (ROOT / "harness/bin/log-backup.sh").read_bytes())

    def test_preview_writes_nothing(self):
        message = lbi.status(self.home, False, system="Darwin")
        self.assertIn("would install", message)
        self.assertEqual(list(self.home.rglob("*")), [])

    def test_home_with_xml_metacharacters_is_escaped(self):
        odd = self.tmp / "a&b<c"
        odd.mkdir()
        self.home = odd
        self.apply("Darwin")
        text = (odd / PLIST).read_text()
        self.assertIn("a&amp;b&lt;c", text)
        import plistlib
        self.assertEqual(plistlib.loads(text.encode())["Label"], "com.ericmacdougall.log-backup")

    def test_reload_deferred_while_a_backup_runs(self):
        self.lock_held_by(self.holder().pid)
        message, runner = self.apply("Darwin")
        self.assertIn("deferred", message)
        self.assertEqual(runner.calls, [])

    def test_a_live_pid_that_is_not_a_backup_run_does_not_defer_the_reload(self):
        # failing control for F3: the pid is alive (this test process) but is no log-backup run
        self.lock_held_by(os.getpid())
        message, runner = self.apply("Darwin")
        self.assertNotIn("deferred", message)
        self.assertEqual(len(runner.calls), 2)

    def test_a_spoofed_holder_command_line_does_not_defer_the_reload(self):
        other = subprocess.Popen(["/bin/sh", "-c", "sleep 60", "log-backup.sh"])  # script name only as a later argument
        self.addCleanup(lambda: (other.terminate(), other.wait()))
        time.sleep(0.3)
        self.lock_held_by(other.pid)
        message, runner = self.apply("Darwin")
        self.assertNotIn("deferred", message)

    def test_a_lock_over_a_day_old_does_not_defer_even_for_a_real_holder_pid(self):
        self.lock_held_by(self.holder().pid, age=90000)
        message, runner = self.apply("Darwin")
        self.assertNotIn("deferred", message)

    def test_a_backup_run_whose_path_contains_a_space_defers_the_reload(self):
        self.lock_held_by(self.holder("my dir").pid)
        message, runner = self.apply("Darwin")
        self.assertIn("deferred", message)
        self.assertEqual(runner.calls, [])

    def test_a_legacy_lock_without_a_pid_defers_the_reload_so_the_running_job_is_not_killed(self):
        lock = self.home / ".agent-harness/logs/log-backup.lock.d"
        lock.mkdir(parents=True)
        old = os.stat(lock).st_mtime - 6600
        os.utime(lock, (old, old))
        message, runner = self.apply("Darwin")
        self.assertIn("deferred", message)
        self.assertEqual(runner.calls, [])
        self.assertEqual((self.home / SCRIPT).read_bytes(), (ROOT / "harness/bin/log-backup.sh").read_bytes())

    def test_young_hand_installed_transcripts_or_bulk_lock_defers_the_reload(self):
        for name, age, deferred in (("log-backup.transcripts.lock.d", 600, True), ("log-backup.transcripts.lock.d", 7200, False),
                                    ("log-backup.bulk.lock.d", 3 * 3600, True), ("log-backup.bulk.lock.d", 7 * 3600, False),
                                    ("log-backup.bulk.lock.d", -1800, True), ("log-backup.bulk.lock.d", -40 * 3600, False)):
            shutil.rmtree(self.home, ignore_errors=True)
            self.home.mkdir()
            lock = self.home / ".agent-harness/logs" / name
            lock.mkdir(parents=True)
            when = time.time() - age
            os.utime(lock, (when, when))
            message, runner = self.apply("Darwin")
            self.assertEqual("deferred" in message, deferred, (name, age, message))
            self.assertEqual(runner.calls == [], deferred, (name, age))

    def test_deferred_reload_is_finished_by_the_next_install(self):
        lock = self.lock_held_by(self.holder().pid)
        self.apply("Darwin")
        (lock / "pid").unlink()
        lock.rmdir()
        message, runner = self.apply("Darwin")
        self.assertEqual(len(runner.calls), 2)
        self.assertIn("scheduler loaded", message)
        message, runner = self.apply("Darwin")
        self.assertEqual(runner.calls, [])

    def test_non_default_home_writes_files_but_leaves_the_scheduler_alone(self):
        message, runner = self.apply("Darwin", activate=False)
        self.assertEqual(runner.calls, [])
        self.assertIn("not loaded", message)
        self.assertTrue((self.home / PLIST).exists())


class Linux(Case):
    def test_units_installed_with_one_reload_sequence_then_idempotent(self):
        self.seed(UNITS[0], "[Unit]\nDescription=old\n")
        message, runner = self.apply("Linux")
        self.assertIn("enabled", message)
        for rel, name in zip(UNITS, ("log-backup.service", "log-backup.timer")):
            self.assertEqual((self.home / rel).read_bytes(), (ROOT / "harness/schedulers" / name).read_bytes())
        self.assertEqual([c[:3] for c in runner.calls], [["systemctl", "--user", "daemon-reload"],
                                                         ["systemctl", "--user", "enable"],
                                                         ["systemctl", "--user", "restart"]])
        self.assertEqual(len(list((self.home / ".config/systemd/user").glob("log-backup.service.bak-*"))), 1)
        message, runner = self.apply("Linux")
        self.assertEqual(runner.calls, [])

    def test_reload_failure_is_reported_not_raised(self):
        message, _ = self.apply("Linux", runner=Runner(code=1))
        self.assertIn("failed", message)


class Refusals(Case):
    def test_symlinked_destination_is_refused_and_nothing_is_written(self):
        target = self.tmp / "elsewhere"
        target.write_text("precious")
        path = self.home / SCRIPT
        path.parent.mkdir(parents=True)
        os.symlink(target, path)
        message, runner = self.apply("Linux")
        self.assertIn("skipped", message)
        self.assertEqual(target.read_text(), "precious")
        self.assertEqual(runner.calls, [])
        self.assertFalse((self.home / UNITS[0]).exists())

    def test_symlinked_parent_directory_is_refused(self):
        real = self.tmp / "dotfiles"
        real.mkdir()
        (self.home / ".config").mkdir()
        os.symlink(real, self.home / ".config" / "systemd")
        message, runner = self.apply("Linux")
        self.assertIn("symlink", message)
        self.assertEqual(list(real.rglob("*")), [])
        self.assertEqual(runner.calls, [])

    def test_unsupported_platform_is_skipped(self):
        self.assertIn("unsupported", lbi.status(self.home, True, system="Windows"))


class Wiring(Case):
    def test_install_registers_one_session_start_hook_and_is_idempotent(self):
        import json
        install.install(self.home, apply=True, durable_tmp=False)
        install.install(self.home, apply=True, durable_tmp=False)
        settings = json.loads((self.home / ".claude/settings.json").read_text())
        found = [h for g in settings["hooks"]["SessionStart"] for h in g["hooks"] if "log_backup.py" in " ".join(h.get("args", []))]
        self.assertEqual(len(found), 1)
        self.assertTrue((self.home / ".claude/hooks/log_backup.py").exists())

    def test_foreign_session_start_hook_survives(self):
        import json
        (self.home / ".claude").mkdir()
        foreign = {"hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "echo", "args": ["mine"]}]}]}}
        (self.home / ".claude/settings.json").write_text(json.dumps(foreign))
        install.install(self.home, apply=True, durable_tmp=False)
        settings = json.loads((self.home / ".claude/settings.json").read_text())
        commands = [h.get("args") for g in settings["hooks"]["SessionStart"] for h in g["hooks"]]
        self.assertIn(["mine"], commands)

    def test_main_prints_a_log_backup_line_and_never_touches_the_real_scheduler(self):
        done = subprocess.run([sys.executable, str(ROOT / "install.py"), "--home", str(self.home), "--apply",
                               "--no-netwatch", "--no-durable-tmp"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=120, env={**os.environ, "HOME": str(self.home)})
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn(b"log backup: files written; scheduler not loaded", done.stdout)
        self.assertTrue((self.home / SCRIPT).exists())


if __name__ == "__main__":
    unittest.main()
