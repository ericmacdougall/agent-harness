"""The real bubblewrap probe on Linux: the same checks as test_sandbox_probe_macos, with bwrap built from the role
lists. Skipped unless bwrap is installed and can create a user namespace on this host."""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import ah_doctor  # noqa: E402
import ah_sandbox  # noqa: E402

BWRAP = shutil.which("bwrap")


def bwrap_works() -> bool:
    if not sys.platform.startswith("linux") or not BWRAP:
        return False
    try:
        return subprocess.run([BWRAP, "--ro-bind", "/", "/", "--unshare-user", "--", "/bin/true"],
                              capture_output=True, timeout=20).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def runner(argv, env=None, cwd=None, timeout=60):
    if argv[0] == BWRAP:
        return ah_doctor.default_runner(argv, env=env, cwd=cwd, timeout=timeout)
    return 127, "", "not run in this test"


@unittest.skipUnless(bwrap_works(), "Linux with a working bwrap only")
class BwrapProbe(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        self.home = root / "home"
        (self.home / ".ssh").mkdir(parents=True, mode=0o700)
        (self.home / ".ssh" / "id_test").write_text("fake key material\n")
        (self.home / ".netrc").write_text("machine example\n")
        for name in ("logs", "work", "releases"):
            (self.home / ".agent-harness" / name).mkdir(parents=True)
        (self.home / ".agent-harness" / "roles.json").write_text("{}")
        self.tmp_root = root / "tmp"
        self.tmp_root.mkdir()
        env = mock.patch.dict(os.environ, {"HOME": str(self.home)})
        env.start()
        self.addCleanup(env.stop)

    def doctor(self, roles=ah_sandbox.ROLES):
        before = sorted(str(p) for p in self.home.rglob("*"))
        report = ah_doctor.run(home=self.home, roles=roles, runner=runner, system="linux",
                               which=lambda n: BWRAP if n == "bwrap" else None,
                               disk_usage=lambda p: (100, 10, 90), managed_dir=self.home / "no-managed",
                               tmp_root=self.tmp_root)
        self.assertEqual(sorted(str(p) for p in self.home.rglob("*")), before, "doctor left files behind")
        return {r["id"]: r for r in report["results"]}

    def test_proven(self):
        found = self.doctor()
        for role in ah_sandbox.ROLES:
            for probe in ("secrets", "records", "write-scope"):
                self.assertEqual(found[f"probe.{role}.{probe}"]["status"], "PROVEN", found[f"probe.{role}.{probe}"])
        self.assertEqual(found["probe.reviewer.read-only"]["status"], "PROVEN")

    def test_probe_can_fail(self):
        original = ah_doctor.Mechanism.argv

        def open_argv(mech, spec, script, cwd):
            return original(mech, {"deny_read": [], "deny_write": [], "allow_write": ["/"]}, script, cwd)
        with mock.patch.object(ah_doctor.Mechanism, "argv", open_argv):
            found = self.doctor(("worker",))
        for probe in ("secrets", "write-scope"):
            self.assertEqual(found[f"probe.worker.{probe}"]["status"], "FAILED", found[f"probe.worker.{probe}"])


if __name__ == "__main__":
    unittest.main()
