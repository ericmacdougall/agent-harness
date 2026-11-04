"""Installed hooks run under the host's default python3, which is 3.9 on macOS.

CI only runs 3.10+, so a PEP 604 annotation (``str | None``) evaluated at
definition time would pass CI and still crash every hook import on the Mac.
"""

import ast
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"


def has_future_annotations(tree):
    return any(isinstance(node, ast.ImportFrom) and node.module == "__future__"
               and any(alias.name == "annotations" for alias in node.names)
               for node in tree.body)


def evaluated_annotations(tree):
    """Annotations Python evaluates at definition time without the future import."""
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            arguments = node.args
            for argument in (arguments.posonlyargs + arguments.args + arguments.kwonlyargs
                             + [arguments.vararg, arguments.kwarg]):
                if argument is not None and argument.annotation is not None:
                    yield argument.annotation
            if node.returns is not None:
                yield node.returns
    for scope in [tree] + [node for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]:
        for statement in scope.body:
            if isinstance(statement, ast.AnnAssign):
                yield statement.annotation


def union_lines(path):
    tree = ast.parse(path.read_text(), filename=str(path))
    if has_future_annotations(tree):
        return []
    return sorted({node.lineno for annotation in evaluated_annotations(tree)
                   for node in ast.walk(annotation)
                   if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr)})


class HookPythonCompatibilityTests(unittest.TestCase):
    def test_hooks_have_no_runtime_pep604_annotations(self):
        files = sorted(HOOKS.glob("*.py"))
        self.assertGreater(len(files), 5)
        offenders = {path.name: lines for path in files if (lines := union_lines(path))}
        self.assertEqual(offenders, {}, "PEP 604 annotations break hook import on Python 3.9; "
                         "add `from __future__ import annotations`")

    def test_detector_flags_an_unprotected_union(self):
        sample = "def f(x: str | None = None) -> int | None:\n    return None\n"
        tree = ast.parse(sample)
        self.assertFalse(has_future_annotations(tree))
        self.assertEqual(len(list(evaluated_annotations(tree))), 2)
        protected = ast.parse("from __future__ import annotations\n" + sample)
        self.assertTrue(has_future_annotations(protected))

    @unittest.skipUnless(shutil.which("python3.9") or Path("/usr/bin/python3").exists(),
                         "no system python3 to check")
    def test_hooks_import_under_system_python(self):
        python = shutil.which("python3.9") or "/usr/bin/python3"
        version = subprocess.run([python, "-c", "import sys; print(sys.version_info[:2] < (3, 10))"],
                                 capture_output=True, text=True, timeout=30).stdout.strip()
        if version != "True":
            self.skipTest(f"{python} is not older than 3.10")
        for name in ("peer_review", "deliver", "integrate_local", "commit_policy", "wal_note", "rescue"):
            with self.subTest(module=name):
                result = subprocess.run([python, "-c", f"import {name}"], cwd=HOOKS,
                                        capture_output=True, text=True, timeout=60)
                self.assertEqual(result.returncode, 0, result.stderr[-800:])


if __name__ == "__main__":
    unittest.main()
