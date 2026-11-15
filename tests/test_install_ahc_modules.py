"""install.py ships every module the installed ahc entry points import (GoodQA goodqa#16049).

The ahc units and the `~/.local/bin/ahc` wrapper exec ~/.claude/hooks/ahc_runner.py (ahc_install.py writes them),
and ahc_install.py itself is installed. ahc_runner imports ahc_contracts and ahc_crash, which install.HOOKS did not
list, so any install would exit with ModuleNotFoundError at the first `ahc` command. The list is derived here from
the code, transitively and including imports inside functions, so a new ahc module cannot be missed again.
"""
import ast
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOOKS_DIR = ROOT / "harness" / "hooks"
sys.path.insert(0, str(ROOT))
import install  # noqa: E402

ENTRY_POINTS = ("ahc_runner.py", "ahc_install.py")


def local_imports(path):
    """Names of modules imported anywhere in `path` (top level or inside functions) that are files in hooks/."""
    found = set()
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names = [node.module]
        else:
            continue
        for name in names:
            top = name.split(".")[0]
            if (HOOKS_DIR / (top + ".py")).exists():
                found.add(top + ".py")
    return found


def closure(entries):
    seen, todo = set(), list(entries)
    while todo:
        name = todo.pop()
        if name in seen:
            continue
        seen.add(name)
        todo.extend(sorted(local_imports(HOOKS_DIR / name) - seen))
    return seen


class InstallShipsAhcModules(unittest.TestCase):
    def test_every_module_the_ahc_entry_points_import_is_installed(self):
        needed = closure(ENTRY_POINTS)
        self.assertIn("ahc_contracts.py", needed, "the import scan found nothing; it would pass vacuously")
        self.assertIn("ahc_crash.py", needed)
        missing = sorted(needed - set(install.HOOKS))
        self.assertEqual(missing, [], "imported by the installed ahc entry points but not in install.HOOKS")

    def test_the_entry_points_import_from_only_the_installed_files(self):
        """The runtime counterpart: a directory holding only what install.HOOKS ships can import both."""
        with tempfile.TemporaryDirectory(prefix="ahc-install-") as tmp:
            for name in install.HOOKS:
                src = HOOKS_DIR / name
                if src.is_file():
                    shutil.copy(str(src), os.path.join(tmp, name))
            code = "import sys; sys.path.insert(0, sys.argv[1]); import ahc_runner, ahc_install"
            p = subprocess.run([sys.executable, "-I", "-B", "-c", code, tmp], capture_output=True, text=True,
                               timeout=60, cwd=tmp, env={"PATH": "/usr/bin:/bin", "HOME": tmp})
            self.assertEqual(p.returncode, 0, p.stderr[-800:])


if __name__ == "__main__":
    unittest.main()
