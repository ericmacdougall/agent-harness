"""The installers ship every module the installed commands import (GoodQA goodqa#15754 hardening review).

Evidence (2026-11-12, main db41da6f): a Codex host gets only install_codex.DELIVERY_HELPERS, which lists ah.py but not
goals_view.py or mission_coverage.py; since PR 218, `ah status` and `ah goals` import goals_view, so on a Codex host both
exit 4 with ModuleNotFoundError (ah owners still works). And install.py's HOOKS omits gq_browser.py, so the gq-browser
MCP registration main approved (`python3 -I ~/.claude/hooks/gq_browser.py mcp`) would point at a file no install
writes. On db41da6f both tests below fail; ee9fc12d (PR 223) added the Codex modules, so the first now guards against a
regression and the second still fails there.
"""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import install  # noqa: E402

SESSION = "11111111-2222-4333-8444-555555555555"


def codex_helpers():
    """DELIVERY_HELPERS without importing install_codex (it needs tomllib, Python 3.11+)."""
    import ast  # noqa: PLC0415
    tree = ast.parse((ROOT / "install_codex.py").read_text())
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(getattr(t, "id", "") == "DELIVERY_HELPERS" for t in node.targets):
            return tuple(ast.literal_eval(node.value))
    raise AssertionError("DELIVERY_HELPERS not found")


class CodexHelpersRunAh(unittest.TestCase):
    def test_ah_status_and_goals_run_from_only_the_codex_helpers(self):
        with tempfile.TemporaryDirectory(prefix="codex-helpers-") as tmp:
            d = Path(tmp, "agent-harness")
            d.mkdir()
            for name in codex_helpers():
                src = ROOT / "harness" / "hooks" / name
                if src.exists():
                    shutil.copy(src, d / name)
            home = Path(tmp, "home")
            folder = home / ".claude" / "wals" / SESSION
            folder.mkdir(parents=True)
            (folder / "main.jsonl").touch()
            env = {"HOME": str(home), "AH_HOME": str(home), "PATH": "/usr/bin:/bin"}
            for argv in (["status", "--since", "1h", "--session", SESSION], ["goals"]):
                p = subprocess.run([sys.executable, "-I", str(d / "ah.py")] + argv, capture_output=True, text=True,
                                   env=env, timeout=60, cwd=tmp)
                self.assertNotIn("ModuleNotFoundError", p.stdout + p.stderr, argv)
                self.assertNotEqual(p.returncode, 4, (argv, p.stdout[-300:]))


class InstallShipsTheMcpServer(unittest.TestCase):
    def test_gq_browser_is_installed_with_the_hooks(self):
        self.assertIn("gq_browser.py", install.HOOKS)
        self.assertTrue((ROOT / "harness" / "hooks" / "gq_browser.py").exists())


if __name__ == "__main__":
    unittest.main()
