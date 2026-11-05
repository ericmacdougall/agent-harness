"""S1d (GoodQA goodqa#14791): ahd must actually run. install.py --services registers it; ah doctor fails while it is not
running. Fails on main 8ac2ec5: no service_commands, no `ahd running` doctor check."""
import fcntl
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "harness" / "hooks"))
import install as installer  # noqa: E402
import ah  # noqa: E402


class ServiceRegistration(unittest.TestCase):
    def test_service_commands_name_the_ahd_unit_installer(self):
        claude = Path("/x/.claude")
        cmds = installer.service_commands(claude)
        self.assertEqual(len(cmds), 1)
        self.assertEqual(cmds[0][1:], ["/x/.claude/hooks/ahd.py", "install", "--apply"])

    def test_install_registers_services_only_when_asked(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            with mock.patch.dict(os.environ, {"HOME": tmp}), mock.patch.object(installer, "install_services",
                                                                            return_value=["ahd.py install --apply"]) as svc:
                installer.install(home, apply=True)
                svc.assert_not_called()  # a plain install never touches launchd or systemd
                changes = installer.install(home, apply=True, services=True)
                svc.assert_called_once()
                self.assertIn("service: ahd.py install --apply", changes)

    def test_install_services_runs_each_command_through_the_runner(self):
        calls = []
        done = installer.install_services(Path("/x/.claude"), runner=calls.append)
        self.assertEqual(len(calls), 1)
        self.assertTrue(calls[0][1].endswith("hooks/ahd.py"))
        self.assertEqual(done, [" ".join(calls[0][1:])])


class DoctorAhdRunning(unittest.TestCase):
    def test_doctor_fails_until_ahd_holds_its_lock_or_beats(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            check = ah.ahd_running_check(home, now=time.time())
            self.assertFalse(check["ok"])
            self.assertIn("ahd.py install --apply", check["fix"])
            run = home / ".agent-harness" / "run"
            run.mkdir(parents=True)
            fd = os.open(run / "ahd.lock", os.O_RDONLY | os.O_CREAT, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)  # a running ahd holds this
                self.assertTrue(ah.ahd_running_check(home, now=time.time())["ok"])
            finally:
                os.close(fd)
            self.assertFalse(ah.ahd_running_check(home, now=time.time())["ok"])  # lock released: not running
            beat = home / ".agent-harness" / "state" / "ahd" / "heartbeat.json"
            beat.parent.mkdir(parents=True)
            beat.write_text("{}")
            self.assertTrue(ah.ahd_running_check(home, now=time.time())["ok"])
            self.assertFalse(ah.ahd_running_check(home, now=time.time() + 3600)["ok"])  # a stale beat is not running

    def test_doctor_document_carries_the_check(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, {"AH_HOME": tmp, "HOME": tmp}):
            doc = ah.doctor()
            names = [c["check"] for c in doc["checks"]]
            self.assertIn("ahd running", names)
            self.assertFalse(doc["ok"])  # nothing runs in a fresh scratch home


if __name__ == "__main__":
    unittest.main()
