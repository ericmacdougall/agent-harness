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
        message = lbi.status(self.home, True, system=system, run=runner, uid=501, activate=kw.pop("activate", True), enabled=kw.pop("enabled", True), **kw)
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
        self.assertEqual(runner.calls, [["launchctl", "enable", "gui/501/com.ericmacdougall.log-backup"],
                                        ["launchctl", "bootout", "gui/501/com.ericmacdougall.log-backup"],
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

    def test_f8_a_lane_enabled_by_hand_survives_a_reinstall(self):
        # goodqa#15147 F8: the shipped plist has the lane off; an apply must not silently reset a hand-enabled lane.
        self.apply("Darwin")
        path = self.home / PLIST
        off = "<key>LOG_BACKUP_BULK_LANE</key><string>0</string>"
        on = "<key>LOG_BACKUP_BULK_LANE</key><string>1</string>"
        self.assertIn(off, path.read_text())
        path.write_text(path.read_text().replace(off, on))
        (self.home / SCRIPT).write_text("older script\n")
        message, runner = self.apply("Darwin")
        self.assertIn(on, path.read_text(), "the hand-enabled lane is kept")
        self.assertEqual(runner.calls, [], "keeping the lane setting is not a unit change")
        self.assertIn("keeps the bulk lane on", message)

    def test_f8_a_plist_without_the_lane_on_gets_the_shipped_lane_off(self):
        self.seed(PLIST, "<plist><key>LOG_BACKUP_BULK_LANE</key><string>yes</string></plist>\n")
        self.apply("Darwin")
        self.assertIn("<key>LOG_BACKUP_BULK_LANE</key><string>0</string>", (self.home / PLIST).read_text())

    def test_preview_writes_nothing(self):
        message = lbi.status(self.home, False, system="Darwin", enabled=True)
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
        self.assertEqual(len(runner.calls), 3)  # enable, bootout, bootstrap

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
        self.assertEqual(len(runner.calls), 3)  # enable, bootout, bootstrap
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


class FakeLaunchd:
    """Just enough launchd to tell a persistent opt-out from a temporary one: bootout unloads, `disable` is persistent,
    bootstrap is refused while disabled, and a reboot loads every plist in LaunchAgents that is not disabled."""
    def __init__(self, plist_present):
        self.loaded, self.disabled, self.plist_present, self.calls = False, False, plist_present, []

    def __call__(self, argv):
        self.calls.append(argv)
        verb = argv[1]
        if verb == "disable":
            self.disabled = True
        elif verb == "enable":
            self.disabled = False
        elif verb == "bootout":
            was = self.loaded
            self.loaded = False
            return 0 if was else 3
        elif verb == "bootstrap":
            if self.disabled:
                return 5
            self.loaded = True
        return 0

    def reboot(self):
        self.loaded = self.plist_present and not self.disabled  # RunAtLoad: loaded again unless disabled


class MacPersistentOptOut(Case):
    def test_opt_out_survives_a_reboot_with_the_plist_still_present(self):
        launchd = FakeLaunchd(True)
        message, _ = self.apply("Darwin", runner=launchd)
        self.assertTrue(launchd.loaded, message)
        lbi.save_choice(self.home, False)
        message = lbi.status(self.home, True, system="Darwin", run=launchd, uid=501, activate=True)
        self.assertIn("disabled by choice", message)
        self.assertFalse(launchd.loaded)
        self.assertTrue((self.home / PLIST).exists())     # files stay, as documented
        launchd.reboot()
        self.assertFalse(launchd.loaded, "the job came back at the next login: the opt-out was not persistent")

    def test_log_backup_flag_re_enables_after_a_disable(self):
        launchd = FakeLaunchd(True)
        self.apply("Darwin", runner=launchd)
        lbi.save_choice(self.home, False)
        lbi.status(self.home, True, system="Darwin", run=launchd, uid=501, activate=True)
        self.assertTrue(launchd.disabled)
        lbi.save_choice(self.home, True)
        message, _ = self.apply("Darwin", runner=launchd)
        self.assertTrue(launchd.loaded, message)
        self.assertFalse(launchd.disabled)
        launchd.reboot()
        self.assertTrue(launchd.loaded)

    def test_a_failed_disable_is_reported_not_called_stopped(self):
        def refusing(argv):
            return 1 if argv[1] == "disable" else 0
        lbi.save_choice(self.home, True)
        self.apply("Darwin")
        lbi.save_choice(self.home, False)
        message = lbi.status(self.home, True, system="Darwin", run=refusing, uid=501, activate=True)
        self.assertIn("disable failed", message)

    def test_alert_hook_stays_registered_when_the_backup_is_switched_off_on_purpose(self):
        import json
        base = [sys.executable, str(ROOT / "install.py"), "--home", str(self.home), "--apply", "--no-netwatch", "--no-durable-tmp"]
        env = {**os.environ, "HOME": str(self.home)}

        def run(*extra):
            done = subprocess.run(base + list(extra), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120, env=env)
            self.assertEqual(done.returncode, 0, done.stderr)

        def alert_count():
            settings = json.loads((self.home / ".claude/settings.json").read_text())
            return sum(1 for g in settings["hooks"].get("SessionStart", []) for h in g["hooks"]
                       if "log_backup.py" in " ".join(h.get("args", [])))
        run("--no-log-backup")
        self.assertEqual(alert_count(), 0)          # never installed here: nothing to warn about
        run("--log-backup")
        run("--no-log-backup")
        self.assertEqual(alert_count(), 1)          # installed, then switched off: a stale backup must still be visible
        run()
        self.assertEqual(alert_count(), 1)


class FakeScheduler:
    """launchd or systemd --user, reduced to the facts that matter: is the job loaded, is it disabled (persistent), and
    what a reboot does. fail = set of verbs that return 1; boom = (verb, exception) raised for that verb."""
    def __init__(self, system, fail=(), boom=None):
        self.system, self.fail, self.boom = system, set(fail), boom
        self.loaded = self.disabled = False
        self.calls = []

    def __call__(self, argv):
        self.calls.append(argv)
        verb = argv[1] if argv[0] == "launchctl" else argv[2] if argv[1] == "--user" else argv[1]
        if self.boom and verb == self.boom[0]:
            raise self.boom[1]
        if verb in self.fail:
            return 1
        if self.system == "Darwin":
            if verb == "disable":
                self.disabled = True
            elif verb == "enable":
                self.disabled = False
            elif verb == "bootout":
                was, self.loaded = self.loaded, False
                return 0 if was else 3
            elif verb == "bootstrap":
                if self.disabled:
                    return 5
                self.loaded = True
        else:
            if verb == "enable":
                self.disabled, self.loaded = False, True
            elif verb == "disable":
                self.disabled, self.loaded = True, False
            elif verb == "restart":
                self.loaded = True  # systemctl restart starts a stopped unit, even a disabled one
        return 0

    def reboot(self):
        self.loaded = not self.disabled  # RunAtLoad / WantedBy=timers.target

    @property
    def enable_calls(self):
        return [c for c in self.calls if "enable" in c or "bootstrap" in c]


class SchedulerStateMachine(Case):
    """The whole enable/disable state machine, per platform. States: unknown, enabled, disabled (scheduler-state file),
    plus a retry marker (reload-pending). Transitions are driven by the remembered choice and by changed files; none of
    these cases rewrites the plist or unit to force a path."""
    SYSTEMS = ("Darwin", "Linux")

    def go(self, system, sched, enabled, apply=True):
        return lbi.status(self.home, apply, system=system, run=sched, uid=501, activate=True, enabled=enabled)

    def state(self):
        return lbi.read_scheduler_state(self.home)

    def pending(self):
        return (self.home / ".agent-harness/logs/log-backup.reload-pending").exists()

    def each(self):
        for system in self.SYSTEMS:
            shutil.rmtree(self.home, ignore_errors=True)
            self.home.mkdir()
            yield system, FakeScheduler(system)

    def test_opt_in_then_unchanged_files_is_idempotent(self):
        for system, sched in self.each():
            self.go(system, sched, True)
            self.assertTrue(sched.loaded, system)
            self.assertEqual(self.state(), "enabled")
            before = len(sched.calls)
            message = self.go(system, sched, True)
            self.assertEqual(len(sched.calls), before, system)  # nothing touched
            self.assertIn("up to date", message)

    def test_changed_files_reload(self):
        for system, sched in self.each():
            self.go(system, sched, True)
            target = self.home / (PLIST if system == "Darwin" else UNITS[1])
            target.write_text("tampered\n")
            before = len(sched.calls)
            self.go(system, sched, True)
            self.assertGreater(len(sched.calls), before, system)
            self.assertTrue(sched.loaded)

    def test_opt_out_is_persistent_and_idempotent(self):
        for system, sched in self.each():
            self.go(system, sched, True)
            self.go(system, sched, False)
            self.assertFalse(sched.loaded, system)
            self.assertTrue(sched.disabled)
            self.assertEqual(self.state(), "disabled")
            sched.reboot()
            self.assertFalse(sched.loaded, f"{system}: the job came back after a reboot")
            before = len(sched.calls)
            message = self.go(system, sched, False)
            self.assertEqual(len(sched.calls), before, system)
            self.assertIn("nothing changed", message)

    def test_opt_in_after_opt_out_with_unchanged_files_re_enables(self):
        for system, sched in self.each():
            self.go(system, sched, True)
            self.go(system, sched, False)
            message = self.go(system, sched, True)  # the plist and units were NOT touched
            self.assertTrue(sched.loaded, f"{system}: {message}")
            self.assertFalse(sched.disabled, system)
            self.assertNotIn("up to date", message)
            self.assertEqual(self.state(), "enabled")
            sched.reboot()
            self.assertTrue(sched.loaded, system)
            self.assertFalse(self.pending())

    def test_opt_in_on_a_host_whose_scheduler_state_is_unknown_reloads_once(self):
        for system, sched in self.each():
            self.go(system, sched, True)
            (self.home / ".agent-harness/logs/log-backup.scheduler").unlink()  # e.g. installed by an older version
            self.go(system, FakeScheduler(system), True)
            second = FakeScheduler(system)
            self.go(system, second, True)
            self.assertEqual(second.calls, [], system)

    def test_failed_disable_is_reported_and_retried(self):
        for system, _ in self.each():
            good = FakeScheduler(system)
            self.go(system, good, True)
            bad = FakeScheduler(system, fail={"disable"})
            bad.loaded = True
            message = self.go(system, bad, False)
            self.assertIn("failed", message, system)
            self.assertNotEqual(self.state(), "disabled")
            self.assertTrue(self.pending())
            retry = FakeScheduler(system)
            retry.loaded = True
            self.go(system, retry, False)
            self.assertFalse(retry.loaded, system)
            self.assertEqual(self.state(), "disabled")
            self.assertFalse(self.pending())

    def test_failed_enable_is_not_up_to_date_and_is_retried_with_unchanged_files(self):
        for system, _ in self.each():
            bad = FakeScheduler(system, fail={"bootstrap" if system == "Darwin" else "enable"})
            message = self.go(system, bad, True)
            if system == "Darwin":  # on Linux the follow-up `restart` starts the unit even though `enable` failed
                self.assertFalse(bad.loaded, system)
            self.assertNotEqual(self.state(), "enabled")  # but it is not enabled across a reboot, so it is not 'done' 
            self.assertTrue(self.pending())
            self.assertNotIn("up to date", message)
            good = FakeScheduler(system)
            self.go(system, good, True)  # files unchanged since the failed attempt
            self.assertTrue(good.loaded, system)
            self.assertEqual(self.state(), "enabled")
            self.assertFalse(self.pending())

    def test_a_raising_disable_or_enable_is_retried(self):
        for system, _ in self.each():
            verb = "bootstrap" if system == "Darwin" else "enable"
            self.go(system, FakeScheduler(system, boom=(verb, subprocess.TimeoutExpired(["x"], 60))), True)
            self.assertTrue(self.pending(), system)
            good = FakeScheduler(system)
            self.go(system, good, True)
            self.assertTrue(good.loaded, system)
            self.assertFalse(self.pending())

    def test_status_never_says_up_to_date_while_the_job_is_disabled(self):
        for system, sched in self.each():
            self.go(system, sched, True)
            self.go(system, sched, False)
            self.assertNotIn("up to date", self.go(system, sched, True), system)

    def preview(self, system, enabled):
        return lbi.status(self.home, False, system=system, run=FakeScheduler(system), uid=501, activate=True, enabled=enabled)

    def snapshot(self):
        return sorted((str(p), p.read_bytes()) for p in self.home.rglob("*") if p.is_file())

    def test_preview_never_says_up_to_date_when_apply_would_act_and_changes_nothing(self):
        marker = ".agent-harness/logs/log-backup.reload-pending"
        for system, sched in self.each():
            # 1. up to date: apply and preview agree that nothing happens
            self.go(system, sched, True)
            before = self.snapshot()
            msg = self.preview(system, True)
            self.assertIn("up to date", msg, system)
            self.assertNotIn("would (re)load", msg)
            self.assertEqual(self.snapshot(), before)
            # 2. disabled: opt-in preview must say it would re-enable, never "up to date"
            self.go(system, sched, False)
            before = self.snapshot()
            msg = self.preview(system, True)
            self.assertNotIn("up to date", msg, f"{system}: {msg}")
            self.assertIn("would (re)load and enable", msg)
            self.assertIn("recorded scheduler state is disabled", msg)
            self.assertEqual(self.snapshot(), before)
            # 3. opt-out preview when already disabled: nothing would change (agrees with apply)
            msg = self.preview(system, False)
            self.assertIn("nothing changed", msg, system)
            self.assertNotIn("would stop", msg)
            # 4. state unknown
            self.go(system, sched, True)
            (self.home / ".agent-harness/logs/log-backup.scheduler").unlink()
            msg = self.preview(system, True)
            self.assertNotIn("up to date", msg, system)
            self.assertIn("state is unknown", msg)
            # 5. retry marker present although the state says enabled
            self.go(system, sched, True)
            (self.home / marker).write_text("reload started\n")
            msg = self.preview(system, True)
            self.assertNotIn("up to date", msg, system)
            self.assertIn("a retry is pending", msg)
            # 6. opt-out preview with the job enabled: would stop; with a marker while disabled: would stop
            os.unlink(self.home / marker)
            self.assertIn("would stop the scheduler job", self.preview(system, False), system)

    def test_preview_and_apply_agree_on_every_state(self):
        """The same plan() drives both: whenever the preview says it would act, apply makes scheduler calls, and the reverse."""
        for system, sched in self.each():
            self.go(system, sched, True)
            states = []
            for mutate in (lambda: None, lambda: lbi.write_scheduler_state(self.home, "disabled"),
                           lambda: (self.home / ".agent-harness/logs/log-backup.scheduler").unlink(),
                           lambda: (self.home / ".agent-harness/logs/log-backup.reload-pending").write_text("x\n")):
                mutate()
                msg = self.preview(system, True)
                fresh = FakeScheduler(system)
                self.go(system, fresh, True)
                states.append(("up to date" in msg, bool(fresh.calls)))
            for says_up_to_date, called in states:
                self.assertEqual(says_up_to_date, not called, system)

    def test_the_retry_marker_is_never_written_through_a_symlink(self):
        for system in self.SYSTEMS:
            shutil.rmtree(self.home, ignore_errors=True)
            self.home.mkdir()
            victim = self.home / "victim.txt"
            victim.write_text("precious\n")
            logs = self.home / ".agent-harness/logs"
            logs.mkdir(parents=True)
            os.symlink(victim, logs / "log-backup.reload-pending")
            self.go(system, FakeScheduler(system, fail={"bootstrap" if system == "Darwin" else "enable"}), True)
            self.assertEqual(victim.read_text(), "precious\n", system)
            self.assertFalse((logs / "log-backup.reload-pending").is_symlink(), system)

    def test_linux_opt_out_with_a_deleted_timer_unit_succeeds_once_and_stays_quiet(self):
        sched = FakeScheduler("Linux")
        self.go("Linux", sched, True)
        os.unlink(self.home / UNITS[1])
        sched.fail = {"disable"}  # systemctl disable of a unit whose file is gone fails, as the real one does
        message = self.go("Linux", sched, False)
        self.assertNotIn("failed", message)
        self.assertEqual(self.state(), "disabled")
        self.assertFalse(self.pending())
        before = len(sched.calls)
        self.go("Linux", sched, False)
        self.assertEqual(len(sched.calls), before)  # not retried on every install


class Raising:
    """A scheduler runner that raises like a hung or missing launchctl or systemctl."""
    def __init__(self, error):
        self.error, self.calls = error, []

    def __call__(self, argv):
        self.calls.append(argv)
        raise self.error


class ReloadFailures(Case):
    def test_a_raising_runner_leaves_a_pending_marker_and_the_next_install_retries(self):
        for system in ("Darwin", "Linux"):
            for error in (subprocess.TimeoutExpired(["x"], 60), FileNotFoundError("no launchctl or systemctl")):
                shutil.rmtree(self.home, ignore_errors=True)
                self.home.mkdir()
                message, runner = self.apply(system, runner=Raising(error))
                self.assertNotIn("up to date", message, (system, error))
                self.assertTrue((self.home / ".agent-harness/logs/log-backup.reload-pending").exists(), (system, error))
                self.assertIn("failed", message)
                message, runner = self.apply(system)  # a working runner finishes the reload
                self.assertTrue(runner.calls, (system, error))
                self.assertFalse((self.home / ".agent-harness/logs/log-backup.reload-pending").exists())
                message, runner = self.apply(system)
                self.assertEqual(runner.calls, [])


class OptIn(Case):
    COMPONENT = ".agent-harness/bin/log-backup.excludes"

    def test_a_host_without_the_component_gets_nothing_by_default(self):
        self.seed(SCRIPT, "hand installed script, no excludes file\n")  # dev2 and the Mac today
        self.assertFalse(lbi.choice(self.home, None))
        message = lbi.status(self.home, True, system="Linux", run=Runner(), uid=501, activate=True)
        self.assertIn("not installed on this host", message)
        self.assertEqual((self.home / SCRIPT).read_text(), "hand installed script, no excludes file\n")
        self.assertFalse((self.home / ".config/systemd/user").exists())

    def test_default_install_leaves_a_running_hand_installed_scheduler_alone(self):
        self.seed(SCRIPT, "hand installed\n")
        self.seed(UNITS[1], "[Timer]\nOnBootSec=2min\n")
        runner = Runner()
        message = lbi.status(self.home, True, system="Linux", run=runner, uid=501, activate=True)
        self.assertEqual(runner.calls, [])  # no stop, no disable, no reload
        self.assertEqual((self.home / UNITS[1]).read_text(), "[Timer]\nOnBootSec=2min\n")
        self.assertIn("nothing changed", message)

    def test_explicit_flag_installs_and_is_remembered(self):
        self.assertTrue(lbi.choice(self.home, True))
        lbi.save_choice(self.home, True)
        self.assertTrue(lbi.choice(self.home, None))
        message, runner = self.apply("Linux")
        self.assertIn("enabled", message)
        self.assertTrue((self.home / self.COMPONENT).exists())
        self.assertTrue(lbi.choice(self.home, None))  # an installed host keeps updating

    def test_no_log_backup_is_remembered_and_stops_the_job_but_keeps_files(self):
        self.apply("Linux")
        lbi.save_choice(self.home, False)
        self.assertFalse(lbi.choice(self.home, None))
        runner = Runner()
        message = lbi.status(self.home, True, system="Linux", run=runner, uid=501, activate=True)
        self.assertEqual(runner.calls, [["systemctl", "--user", "disable", "--now", "log-backup.timer"]])
        self.assertIn("disabled by choice", message)
        self.assertTrue((self.home / SCRIPT).exists() and (self.home / UNITS[1]).exists())
        # a reinstall without a flag does not recreate or restart anything
        runner = Runner()
        os.unlink(self.home / UNITS[1])
        lbi.status(self.home, True, system="Linux", run=runner, uid=501, activate=True)
        self.assertFalse((self.home / UNITS[1]).exists())

    def test_darwin_disable_disables_then_boots_out_the_label(self):
        self.apply("Darwin")
        lbi.save_choice(self.home, False)
        runner = Runner()
        lbi.status(self.home, True, system="Darwin", run=runner, uid=501, activate=True)
        self.assertEqual(runner.calls, [["launchctl", "disable", "gui/501/com.ericmacdougall.log-backup"],
                                        ["launchctl", "bootout", "gui/501/com.ericmacdougall.log-backup"]])

    def test_opting_out_stops_a_bulk_lane_run(self):
        # PR #124 review F4: launchd abandons the lane with the job's process group, so bootout never reached it.
        self.apply("Darwin")
        proc = self.holder()
        lane = self.home / ".agent-harness/logs/log-backup.lane.lock.d"
        lane.mkdir(parents=True)
        (lane / "pid").write_text(str(proc.pid))
        lbi.save_choice(self.home, False)
        message = lbi.status(self.home, True, system="Darwin", run=Runner(), uid=501, activate=True)
        self.assertIn(f"bulk lane run {proc.pid} told to stop", message)
        self.assertIsNotNone(proc.wait(timeout=10), "the lane run got SIGTERM")

    def test_opting_out_never_signals_a_lane_pid_that_is_not_a_backup_run(self):
        self.apply("Darwin")
        other = subprocess.Popen(["/bin/sh", "-c", "sleep 60"])
        self.addCleanup(lambda: (other.terminate(), other.wait()))
        lane = self.home / ".agent-harness/logs/log-backup.lane.lock.d"
        lane.mkdir(parents=True)
        (lane / "pid").write_text(str(other.pid))
        lbi.save_choice(self.home, False)
        message = lbi.status(self.home, True, system="Darwin", run=Runner(), uid=501, activate=True)
        self.assertNotIn("told to stop", message)
        self.assertIsNone(other.poll())

    def test_disable_is_deferred_while_a_run_is_active(self):
        self.apply("Linux")
        self.lock_held_by(self.holder().pid)
        lbi.save_choice(self.home, False)
        runner = Runner()
        message = lbi.status(self.home, True, system="Linux", run=runner, uid=501, activate=True)
        self.assertIn("deferred", message)
        self.assertEqual(runner.calls, [])

    def test_cli_default_registers_no_alert_and_flag_registers_it_and_no_flag_removes_it(self):
        import json
        def alert_count():
            settings = json.loads((self.home / ".claude/settings.json").read_text())
            return sum(1 for g in settings["hooks"].get("SessionStart", []) for h in g["hooks"]
                       if "log_backup.py" in " ".join(h.get("args", [])))
        base = [sys.executable, str(ROOT / "install.py"), "--home", str(self.home), "--apply", "--no-netwatch", "--no-durable-tmp"]
        env = {**os.environ, "HOME": str(self.home)}
        def run(*extra):
            done = subprocess.run(base + list(extra), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120, env=env)
            self.assertEqual(done.returncode, 0, done.stderr)
            return done.stdout
        out = run()
        self.assertEqual(alert_count(), 0)
        self.assertIn(b"not installed on this host", out)
        self.assertFalse((self.home / SCRIPT).exists())
        run("--log-backup")
        self.assertEqual(alert_count(), 1)
        self.assertTrue((self.home / SCRIPT).exists())
        run()  # remembered
        self.assertEqual(alert_count(), 1)
        run("--no-log-backup")
        self.assertEqual(alert_count(), 1)  # switched off on purpose: the alert stays, a stale backup must be visible
        self.assertTrue((self.home / SCRIPT).exists())  # files stay
        run()
        self.assertEqual(alert_count(), 1)  # the opt-out survives a plain reinstall (and the alert with it)


class UnitContents(unittest.TestCase):
    def test_timer_and_service_are_exactly_as_intended(self):
        timer = (ROOT / "harness/schedulers/log-backup.timer").read_text().splitlines()
        self.assertEqual(timer, ["[Unit]", "Description=Agent log backup every 15 min", "[Timer]", "OnBootSec=2min",
                                 "OnUnitActiveSec=15min", "RandomizedDelaySec=120", "[Install]", "WantedBy=timers.target"])
        self.assertNotIn("Persistent=true", timer)  # a no-op for OnBootSec/OnUnitActiveSec timers
        service = (ROOT / "harness/schedulers/log-backup.service").read_text().splitlines()
        self.assertIn("Type=oneshot", service)
        self.assertIn("ExecStart=/bin/bash %h/.agent-harness/bin/log-backup.sh", service)

    def test_launchd_template_interval_label_and_program(self):
        import plistlib
        text = (ROOT / "harness/schedulers/com.ericmacdougall.log-backup.plist").read_text().replace("@HOME@", "/h")
        data = plistlib.loads(text.encode())
        self.assertEqual(data["Label"], "com.ericmacdougall.log-backup")
        self.assertEqual(data["StartInterval"], 900)
        self.assertEqual(data["ProgramArguments"], ["/bin/bash", "/h/.agent-harness/bin/log-backup.sh"])
        self.assertEqual(data["EnvironmentVariables"]["LOG_BACKUP_JITTER_SECONDS"], "120")  # stagger hosts on one account


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
        install.install(self.home, apply=True, durable_tmp=False, log_backup=True)
        install.install(self.home, apply=True, durable_tmp=False, log_backup=True)
        settings = json.loads((self.home / ".claude/settings.json").read_text())
        found = [h for g in settings["hooks"]["SessionStart"] for h in g["hooks"] if "log_backup.py" in " ".join(h.get("args", []))]
        self.assertEqual(len(found), 1)
        self.assertTrue((self.home / ".claude/hooks/log_backup.py").exists())

    def test_foreign_session_start_hook_survives(self):
        import json
        (self.home / ".claude").mkdir()
        foreign = {"hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "echo", "args": ["mine"]}]}]}}
        (self.home / ".claude/settings.json").write_text(json.dumps(foreign))
        install.install(self.home, apply=True, durable_tmp=False, log_backup=True)
        settings = json.loads((self.home / ".claude/settings.json").read_text())
        commands = [h.get("args") for g in settings["hooks"]["SessionStart"] for h in g["hooks"]]
        self.assertIn(["mine"], commands)

    def test_main_prints_a_log_backup_line_and_never_touches_the_real_scheduler(self):
        done = subprocess.run([sys.executable, str(ROOT / "install.py"), "--home", str(self.home), "--apply",
                               "--no-netwatch", "--no-durable-tmp", "--log-backup"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=120, env={**os.environ, "HOME": str(self.home)})
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn(b"log backup: files written; scheduler not loaded", done.stdout)
        self.assertTrue((self.home / SCRIPT).exists())


if __name__ == "__main__":
    unittest.main()
