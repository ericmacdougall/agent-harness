"""GoodQA work-tracker-automatic#35905: approved_check accepts scoped go vet/test package lists, safe patterns only."""

import os
import sys
import unittest
from pathlib import Path

HOOKS = Path(os.environ.get("APPROVED_CHECK_HOOKS_DIR") or Path(__file__).resolve().parent.parent / "harness" / "hooks")
sys.path.insert(0, str(HOOKS))
import integrate_local as il  # noqa: E402


class GoPackages(unittest.TestCase):
    def test_scoped_packages_are_approved(self):
        for argv in (["go", "vet", "./internal/auth"], ["go", "vet", "./cmd/...", "./internal/store/..."],
                     ["go", "test", "./internal/auth"], ["go", "test", "-race", "-count=1", "-v", "./pkg/a", "./pkg/b/..."],
                     ["go", "test", "-count=1", "./..."], ["go", "vet", "./..."]):
            with self.subTest(argv=argv):
                self.assertTrue(il.approved_check(argv))

    def test_unsafe_or_unscoped_forms_are_refused(self):
        for argv in (["go", "vet"], ["go", "test"], ["go", "vet", "-vettool=/tmp/x", "./..."],
                     ["go", "test", "-run", "X", "./pkg"], ["go", "test", "-exec", "sh", "./pkg"],
                     ["go", "test", "./pkg", "-race"], ["go", "test", "./pkg", "-exec=sh"],
                     ["go", "vet", "pkg"], ["go", "vet", "example.com/pkg"], ["go", "vet", "/abs/pkg"],
                     ["go", "vet", "../escape"], ["go", "vet", "./a/../b"], ["go", "vet", "./a/./b"],
                     ["go", "vet", "./a//b"], ["go", "vet", "./a/.../b"], ["go", "vet", "./a;ls"],
                     ["go", "vet", "./a b"], ["go", "vet", "./$(id)"], ["go", "vet", "./a|b"],
                     ["go", "vet", "./a\n"], ["go", "vet", "./-flag"], ["go", "vet", "./"], ["go", "vet", "./pkg/"],
                     ["go", "vet", "./" + "a" * 250], ["go", "build", "./..."], ["go", "run", "./cmd"],
                     ["go", "vet", "./é"]):
            with self.subTest(argv=argv):
                self.assertFalse(il.approved_check(argv))


if __name__ == '__main__':
    unittest.main()
