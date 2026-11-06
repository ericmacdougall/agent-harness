"""GoodQA #14729: integrate_local.approved_check accepts one focused form,
`python3|python -m unittest discover -s tests -p test_<name>.py`, and nothing broader."""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HOOKS = Path(os.environ.get("APPROVED_CHECK_HOOKS_DIR") or Path(__file__).resolve().parent.parent / "harness" / "hooks")
sys.path.insert(0, str(HOOKS))
import integrate_local as il  # noqa: E402

BASE = ["-m", "unittest", "discover", "-s", "tests", "-p"]


class FocusedForm(unittest.TestCase):
    def test_literal_test_file_is_approved(self):
        for py in ("python3", "python"):
            for name in ("test_merge_gate.py", "test_a.py", "test_X_1.py"):
                with self.subTest(py=py, name=name):
                    self.assertTrue(il.approved_check([py, *BASE, name]))

    def test_unsafe_or_broader_patterns_are_refused(self):
        bad = ["test_*.py", "*.py", "test_?.py", "test_[ab].py", "../test_a.py", "tests/test_a.py", "sub/test_a.py",
               "..", "test_a.py/", "test_a", "test_a.pyc", "a.py", "Test_a.py", "test_.py", "test_a.py ", " test_a.py",
               "test_a.py\n", "test_a.py;ls", "test_a b.py", "test_a$.py", "-v", "--help", "test_a.py\x00", "", "test_é.py",
               "test_" + "a" * 200 + ".py"]
        for name in bad:
            with self.subTest(name=repr(name)):
                self.assertFalse(il.approved_check(["python3", *BASE, name]))

    def test_extra_or_reordered_argv_is_refused(self):
        ok = ["python3", *BASE, "test_a.py"]
        self.assertTrue(il.approved_check(ok))
        for argv in (ok + ["-v"], ok + ["test_b.py"], ok + ["-k", "x"], ok + ["--"],
                     ["python3", "-m", "unittest", "discover", "-p", "test_a.py", "-s", "tests"],
                     ["python3", "-m", "unittest", "discover", "-s", "tests", "-p"],
                     ["python3", "-m", "unittest", "discover", "-s", "other", "-p", "test_a.py"],
                     ["python3", "-m", "unittest", "discover", "-s", "tests", "-p", "test_a.py", "-t", "."],
                     ["python3", "-m", "unittest", "discover", "-s", "tests", "-pattern", "test_a.py"],
                     ["python3", "-m", "unittest", "discover", "-s", "tests", "--pattern", "test_a.py"],
                     ["python3", "-m", "unittest", "-s", "tests", "-p", "test_a.py"],
                     ["python3.13", *BASE, "test_a.py"], ["/usr/bin/python3", *BASE, "test_a.py"],
                     ["python3", "-c", "print(1)", "-p", "test_a.py"], ["sh", *BASE, "test_a.py"]):
            with self.subTest(argv=argv):
                self.assertFalse(il.approved_check(argv))

    def test_existing_forms_are_unchanged(self):
        approved = [["go", "vet", "./..."], ["go", "test", "./..."], ["go", "test", "-race", "-count=1", "-v", "./..."],
                    ["npm", "test"], ["pnpm", "run", "lint"], ["yarn", "run", "check"],
                    ["python3", "-m", "unittest", "discover", "-s", "tests"],
                    ["python3", "-m", "unittest", "discover", "-s", "tests", "-v"],
                    ["python3", "-m", "unittest", "discover", "-s", "tests", "-t", "."],
                    ["python3", "-m", "unittest", "discover", "-s", "tests", "-t", ".", "-v"],
                    ["python3", "-m", "pytest"], ["python", "-m", "pytest", "-q"], ["pytest"], ["pytest", "-q"]]
        refused = [[], ["go", "test"], ["go", "test", "-run", "X", "./..."], ["npm", "run", "evil"],
                   ["python3", "-c", "print(1)"], ["python3", "-m", "pytest", "-k", "x"], ["pytest", "x"],
                   ["python3", "-m", "unittest", "discover"], ["python3", "-m", "unittest", "discover", "-s", "tests", "-p", "*.py"],
                   ["bash", "-c", "true"]]
        for argv in approved:
            with self.subTest(argv=argv):
                self.assertTrue(il.approved_check(argv))
        for argv in refused:
            with self.subTest(argv=argv):
                self.assertFalse(il.approved_check(argv))


class NonemptyWrapperWithPattern(unittest.TestCase):
    """The wrapper run() puts around every `-m unittest discover` check must fail a pattern that runs no tests,
    on the interpreter running this suite (Python 3.9 exits zero on empty discovery without it)."""

    def run_wrapper(self, files, pattern):
        with tempfile.TemporaryDirectory() as tmp:
            tests = Path(tmp) / "tests"
            tests.mkdir()
            for name, body in files.items():
                (tests / name).write_text(body)
            return subprocess.run([sys.executable, "-c", il.NONEMPTY_UNITTEST, "discover", "-s", "tests", "-p", pattern],
                                  cwd=tmp, capture_output=True, text=True, timeout=60,
                                  env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})

    GOOD = "import unittest\nclass T(unittest.TestCase):\n    def test_ok(self):\n        self.assertTrue(True)\n"
    BAD = "import unittest\nclass T(unittest.TestCase):\n    def test_no(self):\n        self.fail('intentional')\n"
    SKIPPED = "import unittest\nclass T(unittest.TestCase):\n    @unittest.skip('x')\n    def test_s(self):\n        pass\n"

    def test_matching_passing_file_passes(self):
        done = self.run_wrapper({"test_a.py": self.GOOD, "test_b.py": self.BAD}, "test_a.py")
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)

    def test_pattern_matching_no_file_fails(self):
        done = self.run_wrapper({"test_a.py": self.GOOD}, "test_missing.py")
        self.assertNotEqual(done.returncode, 0, done.stdout + done.stderr)

    def test_failing_file_fails(self):
        done = self.run_wrapper({"test_a.py": self.BAD}, "test_a.py")
        self.assertNotEqual(done.returncode, 0, done.stdout + done.stderr)

    def test_all_skipped_file_fails(self):
        done = self.run_wrapper({"test_a.py": self.SKIPPED}, "test_a.py")
        self.assertNotEqual(done.returncode, 0, done.stdout + done.stderr)

    def test_run_applies_the_wrapper_to_a_focused_command(self):
        # integrate_local.run() must rewrite the focused command to the wrapper, or the guards above do not apply.
        captured = {}

        def fake(executed, **kw):
            probe = "-I" in executed  # the interpreter version probe, not the check itself
            if not probe:
                captured["argv"] = executed

            class Done:
                returncode, stderr = 0, ""
                stdout = "3.13\n" if probe else ""
            return Done()
        original = il.run_process
        il.run_process = fake
        try:
            with tempfile.TemporaryDirectory() as bindir:
                os.symlink(sys.executable, os.path.join(bindir, "python3"))
                il.run(".", ["python3", *BASE, "test_a.py"], discard_output=True,
                       env={"PATH": bindir + os.pathsep + os.environ["PATH"]})
        finally:
            il.run_process = original
        self.assertEqual(captured["argv"][1:2], ["-c"])
        self.assertEqual(captured["argv"][-4:], ["-s", "tests", "-p", "test_a.py"])


if __name__ == "__main__":
    unittest.main()
