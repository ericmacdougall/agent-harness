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


class InstallCoverage(Base):
    def test_status_flags_unwired_scheduler(self):
        self.assertIn("NOT INSTALLED", bw.status(self.home, "Linux"))
        self.assertIn("NOT INSTALLED", bw.status(self.home, "Darwin"))

    def test_install_dry_run_writes_nothing_then_apply_wires(self):
        out = bw.install(self.home, False, "Linux")
        self.assertTrue(all(o.startswith("would write") for o in out))
        self.assertIn("NOT INSTALLED", bw.status(self.home, "Linux"))
        bw.install(self.home, True, "Linux")
        self.assertIn("scheduler installed", bw.status(self.home, "Linux"))
        self.assertTrue(all(o.startswith("unchanged") for o in bw.install(self.home, True, "Linux")))

    def test_units_invoke_this_script_with_run(self):
        for system in ("Linux", "Darwin"):
            text = "".join(t for _, t in bw.unit_files(self.home, system))
            self.assertIn("backup_watch.py", text)
            self.assertIn("run", text)

    def test_symlinked_destination_refused(self):
        d = self.home / ".config" / "systemd"
        d.mkdir(parents=True)
        (d / "user").symlink_to(self.home)
        self.assertTrue(any("refused" in o for o in bw.install(self.home, True, "Linux")))


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
