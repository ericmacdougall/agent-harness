"""harness/hooks/backup_watch.py: standing freshness alert. Fixtures only; no real backup, no rclone."""
import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "harness" / "hooks"))
import backup_watch as bw  # noqa: E402
import log_backup as lb  # noqa: E402

NOW = 1_800_000_000.0


def stamp(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name)
        self.logs = self.home / ".agent-harness" / "logs"
        self.logs.mkdir(parents=True)

    def tearDown(self):
        self.tmp.cleanup()

    def mark(self, name, age):
        (self.logs / name).write_text(stamp(NOW - age) + "\n")

    def lines(self):
        p = self.logs / bw.ALERT_LOG
        return [json.loads(x) for x in p.read_text().splitlines()] if p.exists() else []


class Verdict(Base):
    def test_fresh_both_is_zero(self):
        self.mark(lb.LAST_OK, 60)
        self.mark(lb.BULK_OK, 60)
        self.assertEqual(bw.run(self.home, NOW), 0)
        self.assertEqual(self.lines()[0]["event"], "recovered")  # first observation recorded

    def test_stale_transcripts_alerts_with_limit_from_log_backup(self):
        # Control: the 4 h old marker must be stale by the component's own limit, not a limit copied here.
        self.mark(lb.LAST_OK, lb.MAX_AGE_SECONDS + 600)
        self.mark(lb.BULK_OK, 60)
        self.assertEqual(bw.run(self.home, NOW), 1)
        self.assertEqual(self.lines()[0]["event"], "alert")

    def test_missing_marker_is_two_not_fresh(self):
        self.assertEqual(bw.run(self.home, NOW), 2)

    def test_future_marker_invalid(self):
        self.mark(lb.LAST_OK, -7200)
        self.assertEqual(bw.run(self.home, NOW), 2)

    def test_bulk_stale_is_three(self):
        self.mark(lb.LAST_OK, 60)
        self.mark(lb.BULK_OK, lb.BULK_MAX_AGE_SECONDS + 600)
        self.assertEqual(bw.run(self.home, NOW), 3)

    def test_last_skip_never_counts(self):
        (self.logs / lb.LAST_SKIP).write_text(stamp(NOW) + "\n")
        self.assertEqual(bw.run(self.home, NOW), 2)

    def test_unavailable_component_is_four_not_zero(self):
        orig = bw._lb
        bw._lb = lambda: None
        try:
            self.assertEqual(bw.run(self.home, NOW), 4)
        finally:
            bw._lb = orig


class Dedupe(Base):
    def test_same_bad_verdict_logged_once_per_hour(self):
        self.mark(lb.LAST_OK, 99999)
        bw.run(self.home, NOW)
        bw.run(self.home, NOW + 600)
        self.assertEqual(len(self.lines()), 1)
        bw.run(self.home, NOW + bw.REPEAT_SECONDS + 1)
        self.assertEqual(len(self.lines()), 2)

    def test_recovery_is_logged(self):
        self.mark(lb.LAST_OK, 99999)
        bw.run(self.home, NOW)
        self.mark(lb.LAST_OK, 30)
        self.mark(lb.BULK_OK, 30)
        bw.run(self.home, NOW + 60)
        self.assertEqual([x["event"] for x in self.lines()], ["alert", "recovered"])


class StateFile(Base):
    def _bad(self, content):
        (self.logs / bw.STATE).write_text(content)
        self.mark(lb.LAST_OK, 99999)
        self.assertEqual(bw.run(self.home, NOW), 1)  # verdict still computed, never a crash
        self.assertEqual(self.lines()[-1]["event"], "alert")  # and the alert is still logged

    def test_non_dict_state(self):
        self._bad("[]")

    def test_non_numeric_at(self):
        self._bad('{"code": 1, "at": "x"}')

    def test_future_at_does_not_silence_alerts(self):
        self._bad('{"code": 1, "at": 9999999999999}')

    def test_bool_code_rejected(self):
        self._bad('{"code": true, "at": 1}')

    def test_symlinked_state_refused(self):
        (self.logs / "elsewhere").write_text("x")
        (self.logs / bw.STATE).symlink_to(self.logs / "elsewhere")
        self.mark(lb.LAST_OK, 99999)
        with self.assertRaises(OSError):
            bw.run(self.home, NOW)
        self.assertEqual((self.logs / "elsewhere").read_text(), "x")

    def test_stale_ok_with_fresh_skip_still_stale(self):
        self.mark(lb.LAST_OK, 99999)
        (self.logs / lb.LAST_SKIP).write_text(stamp(NOW) + "\n")
        self.assertEqual(bw.run(self.home, NOW), 1)

    def test_unknown_bulk_state_is_bad(self):
        self.mark(lb.LAST_OK, 60)
        orig = lb.bulk_classify
        lb.bulk_classify = lambda *a, **k: {"state": "weird", "age": None}
        try:
            self.assertEqual(bw.run(self.home, NOW), 3)
        finally:
            lb.bulk_classify = orig


class Runner:
    def __init__(self, loaded=False):
        self.calls, self.loaded = [], loaded

    def __call__(self, argv):
        self.calls.append(argv)
        if argv[:2] in (["systemctl", "--user"],) and "is-enabled" in argv:
            return 0 if self.loaded else 1
        if argv[0] == "launchctl" and argv[1] == "print":
            return 0 if self.loaded else 113
        if argv[0] == "systemctl" and "enable" in argv or argv[0] == "launchctl" and argv[1] == "bootstrap":
            self.loaded = True
        return 0


class InstallCoverage(Base):
    def test_files_without_active_job_are_not_reported_installed(self):
        r = Runner(loaded=False)
        bw.install(self.home, False, "Linux", r)
        self.assertIn("NOT INSTALLED", bw.status(self.home, "Linux", r))
        bw.install(self.home, True, "Linux", Runner(loaded=False))
        self.assertIn("NOT ACTIVE", bw.status(self.home, "Linux", Runner(loaded=False)))
        self.assertIn("installed and active", bw.status(self.home, "Linux", Runner(loaded=True)))

    def test_dry_run_writes_and_activates_nothing(self):
        r = Runner()
        out = bw.install(self.home, False, "Linux", r)
        self.assertTrue(all(o.startswith("would write") for o in out))
        self.assertEqual(r.calls, [])

    def test_apply_writes_then_activates_linux_and_darwin(self):
        r = Runner()
        bw.install(self.home, True, "Linux", r)
        self.assertTrue(any("enable" in c and "backup-watch.timer" in c for c in r.calls))
        r2 = Runner()
        bw.install(self.home, True, "Darwin", r2)
        self.assertTrue(any(c[:2] == ["launchctl", "bootstrap"] for c in r2.calls))
        self.assertIn("installed and active", bw.status(self.home, "Darwin", r2))

    def test_second_apply_is_idempotent_when_active(self):
        r = Runner()
        bw.install(self.home, True, "Linux", r)
        r.calls.clear()
        out = bw.install(self.home, True, "Linux", r)
        self.assertTrue(all(o.startswith("unchanged") for o in out))
        self.assertFalse(any("enable" in c for c in r.calls))

    def test_plist_parses_and_targets_installed_script_not_checkout(self):
        import plistlib
        (path, text), = bw.unit_files(self.home, "Darwin")
        d = plistlib.loads(text.encode())
        self.assertEqual(d["ProgramArguments"][1], str(self.home / ".claude" / "hooks" / "backup_watch.py"))
        self.assertEqual(d["ProgramArguments"][2], "run")
        self.assertIn("StandardErrorPath", d)
        self.assertNotIn(str(ROOT), text)

    def test_systemd_unit_targets_installed_script_quoted(self):
        text = "".join(t for _, t in bw.unit_files(self.home, "Linux"))
        self.assertIn(f'ExecStart=/usr/bin/python3 "{self.home}/.claude/hooks/backup_watch.py" run', text)
        self.assertNotIn(str(ROOT), text)

    def test_symlinked_destination_refused_and_nothing_activated(self):
        d = self.home / ".config" / "systemd"
        d.mkdir(parents=True)
        (d / "user").symlink_to(self.home)
        r = Runner()
        self.assertTrue(any("refused" in o for o in bw.install(self.home, True, "Linux", r)))
        self.assertEqual(r.calls, [])

    def test_preexisting_tmp_symlink_not_followed(self):
        d = self.home / ".config" / "systemd" / "user"
        d.mkdir(parents=True)
        victim = self.home / "victim"
        victim.write_text("keep")
        for name in ("backup-watch.service", "backup-watch.timer"):
            (d / f"{name}.tmp.{__import__('os').getpid()}").symlink_to(victim)
        with self.assertRaises(OSError):
            bw.install(self.home, True, "Linux", Runner())
        self.assertEqual(victim.read_text(), "keep")


class ShippedHooksAreInstalled(unittest.TestCase):
    """Install coverage: a hook file that install.HOOKS does not copy never reaches ~/.claude/hooks."""
    # Owned by feat/command-guard (#14471); that PR must install them and then delete these entries.
    PENDING_OWNER = {"command_guard.py", "command_guard_policy.json", "redact.py"}

    def test_every_tracked_hook_file_is_installed_or_explicitly_pending(self):
        sys.path.insert(0, str(ROOT))
        import install
        shipped = {p.name for p in (ROOT / "harness" / "hooks").iterdir() if p.is_file()}
        missing = shipped - set(install.HOOKS) - self.PENDING_OWNER
        self.assertEqual(missing, set(), "hook files not copied by install.HOOKS")
        stale = self.PENDING_OWNER & set(install.HOOKS)
        self.assertEqual(stale, set(), "owner PR installed these; drop them from PENDING_OWNER")


if __name__ == "__main__":
    unittest.main()
