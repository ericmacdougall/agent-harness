"""The real Seatbelt probe: in a temporary HOME with a fake ~/.ssh/id_test, /usr/bin/sandbox-exec built from the role
lists proves the secrets, records and write-scope boundaries, and a profile with the denials removed fails, which
shows the probe can fail. Only sandbox-exec (and git and sh inside it) really runs; every other program is faked."""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import ah_doctor  # noqa: E402
import ah_sandbox  # noqa: E402

SANDBOX_EXEC = "/usr/bin/sandbox-exec"
HERE = sys.platform == "darwin" and os.access(SANDBOX_EXEC, os.X_OK)


def runner(argv, env=None, cwd=None, timeout=60):
    if argv[0] == SANDBOX_EXEC:
        return ah_doctor.default_runner(argv, env=env, cwd=cwd, timeout=timeout)
    return 127, "", "not run in this test"


@unittest.skipUnless(HERE, "macOS with /usr/bin/sandbox-exec only")
class SeatbeltProbe(unittest.TestCase):
    MECH = "sandbox-exec"
    SYSTEM = "darwin"

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        self.home = root / "home"
        (self.home / ".ssh").mkdir(parents=True, mode=0o700)
        (self.home / ".ssh" / "id_test").write_text("fake key material\n")
        (self.home / ".aws").mkdir()
        (self.home / ".aws" / "credentials").write_text("[default]\n")
        for name in ("logs", "work", "releases"):
            (self.home / ".agent-harness" / name).mkdir(parents=True)
        (self.home / ".agent-harness" / "roles.json").write_text("{}")
        (self.home / ".agent-harness" / "approvals.jsonl").write_text("")
        self.tmp_root = root / "tmp"
        self.tmp_root.mkdir()
        env = mock.patch.dict(os.environ, {"HOME": str(self.home)})
        env.start()
        self.addCleanup(env.stop)

    def which(self, name):
        return {"sandbox-exec": SANDBOX_EXEC, "bwrap": "/usr/bin/bwrap"}.get(name)

    def doctor(self, roles=ah_sandbox.ROLES):
        before = sorted(str(p) for p in self.home.rglob("*"))
        report = ah_doctor.run(home=self.home, roles=roles, runner=self.runner, system=self.SYSTEM,
                               which=self.which, disk_usage=lambda p: (100, 10, 90),
                               managed_dir=self.home / "no-managed", tmp_root=self.tmp_root)
        self.assertEqual(sorted(str(p) for p in self.home.rglob("*")), before, "doctor left files behind")
        self.assertEqual(list(self.tmp_root.iterdir()), [])
        return {r["id"]: r for r in report["results"]}

    runner = staticmethod(runner)

    def test_proven(self):
        found = self.doctor()
        self.assertEqual(found["mechanism"]["status"], "OK")
        for role in ah_sandbox.ROLES:
            for probe in ("secrets", "records", "write-scope"):
                r = found[f"probe.{role}.{probe}"]
                self.assertEqual(r["status"], "PROVEN", r)
        self.assertEqual(found["probe.reviewer.read-only"]["status"], "PROVEN", found["probe.reviewer.read-only"])
        self.assertEqual(found["probe.worker.approvals"]["status"], "PROVEN", found["probe.worker.approvals"])
        self.assertEqual(found["probe.supervisor.approvals"]["status"], "PROVEN", found["probe.supervisor.approvals"])
        self.assertEqual(len(found["probe.worker.secrets"]["detail"]["targets"]), 3)   # two secrets and the twin

    def test_probe_can_fail(self):
        """The same probes with the denials taken out of the profile report FAILED, never PROVEN."""
        original = ah_doctor.Mechanism.argv

        def open_argv(mech, spec, script, cwd):
            return original(mech, {"deny_read": [], "deny_write": [], "allow_write": ["/"]}, script, cwd)
        with mock.patch.object(ah_doctor.Mechanism, "argv", open_argv):
            found = self.doctor(("worker",))
        for probe in ("secrets", "records", "write-scope", "approvals"):
            r = found[f"probe.worker.{probe}"]
            self.assertEqual(r["status"], "FAILED", r)
            self.assertIn("leaked", r["summary"])

    def test_twin_refused_fails(self):
        """A profile that denies every write blocks the twin too: FAILED, because blocking everything proves nothing."""
        original = ah_doctor.Mechanism.argv

        def closed_argv(mech, spec, script, cwd):
            return original(mech, dict(spec, allow_write=[]), script, cwd)
        with mock.patch.object(ah_doctor.Mechanism, "argv", closed_argv):
            found = self.doctor(("worker",))
        r = found["probe.worker.write-scope"]
        self.assertEqual(r["status"], "FAILED", r)
        self.assertIn("twin", r["summary"])


if __name__ == "__main__":
    unittest.main()
