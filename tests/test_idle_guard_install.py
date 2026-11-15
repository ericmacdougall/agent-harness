"""Receipt r3 F1: the default idle_guard ops-watch check on an install that ships only what install_codex.py ships."""
import json
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOOKS = ROOT / "harness" / "hooks"
sys.path.insert(0, str(ROOT))
import install_codex  # noqa: E402

PROBE = (
    "import json, sys\n"
    "from pathlib import Path\n"
    "import ops_watch\n"
    "home = Path(sys.argv[1])\n"
    "cfg = ops_watch.load_config(home)\n"
    "print(json.dumps(ops_watch.check_idle_guard(cfg, {}, None, __import__('time').time())))\n"
)


class IsolatedInstall(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.bin = self.root / "installed"
        self.bin.mkdir()
        self.home = self.root / "home"
        wal = self.home / ".claude" / "wals" / "sess-iso-0001"
        wal.mkdir(parents=True)
        (wal / "main.jsonl").write_text(json.dumps({"at": "2026-01-01T00:00:00+00:00", "event": "check", "note": "x"}) + "\n")

    def install(self, names):
        for name in names:
            shutil.copy(HOOKS / name, self.bin / name)
        (self.bin / "probe.py").write_text(PROBE)

    def run_probe(self):
        return subprocess.run([sys.executable, str(self.bin / "probe.py"), str(self.home)], cwd=self.bin,
                              capture_output=True, text=True, timeout=60, env={"PATH": "/usr/bin:/bin", "HOME": str(self.home)})

    def test_codex_install_ships_what_the_default_check_imports(self):
        shipped = {"ops_watch.py", *install_codex.DELIVERY_HELPERS}
        for name in ("idle_guard.py", "ah.py", "liveness.py"):
            self.assertIn(name, shipped)
        self.install(sorted(n for n in shipped if n.endswith(".py")))
        done = self.run_probe()
        self.assertEqual(done.returncode, 0, done.stderr[-600:])
        self.assertEqual(json.loads(done.stdout), [])

    def test_missing_module_is_a_warning_not_a_check_error(self):
        self.install(["ops_watch.py"])
        done = self.run_probe()
        self.assertEqual(done.returncode, 0, done.stderr[-600:])
        out = json.loads(done.stdout)
        self.assertEqual([a["key"] for a in out], ["idle-guard:unavailable"])
        self.assertEqual(out[0]["severity"], "warning")

    def test_host_without_session_wals_returns_nothing_and_imports_nothing(self):
        shutil.rmtree(self.home / ".claude")
        self.install(["ops_watch.py"])
        done = self.run_probe()
        self.assertEqual(done.returncode, 0, done.stderr[-600:])
        self.assertEqual(json.loads(done.stdout), [])


if __name__ == "__main__":
    unittest.main()
