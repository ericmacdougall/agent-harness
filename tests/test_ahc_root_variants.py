"""The failing-first runner tests/variants/ahc_root_variants.py itself (GoodQA goodqa#16049, PR 258 v5 F2).

A variant whose tests time out, or that is not really tested (no tests ran, an import failed), is inconclusive: it
is reported as such, never counted as caught, and the run exits nonzero. Every anchor must still be unique in the
current sources, or the real run would stop at that variant. The runner is driven with a fake test command here;
one real subprocess checks that a timeout kills the whole process group.
"""
import importlib.util
import os
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stdout, redirect_stderr
from io import StringIO
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("ahc_root_variants", str(ROOT / "tests" / "variants" /
                                                                        "ahc_root_variants.py"))
variants = importlib.util.module_from_spec(spec)
spec.loader.exec_module(variants)     # module level only defines; nothing runs until main()

CAUGHT_ERR = "FAIL: test_x (tests.t.X)\n----\nRan 3 tests in 0.1s\n\nFAILED (failures=1)\n"
PASSED_ERR = "...\n----\nRan 3 tests in 0.1s\n\nOK\n"


class RunnerTests(unittest.TestCase):

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.src = self.root / "mod.py"
        self.body = "X = 1\nY = 2\n"
        self.src.write_text(self.body)
        self.out = self.root / "variants.out"
        self.seen = []

    def fake(self, *results):
        """A test runner returning (or raising) results in order, recording the source as each run saw it."""
        queue = list(results)

        def runner(cmd, cwd, timeout):
            self.seen.append(self.src.read_text())
            result = queue.pop(0)
            if isinstance(result, BaseException):
                raise result
            return result
        return runner

    def variant(self, name, old="X = 1\n", new="X = 9\n"):
        return (name, [(old, new)], "mod.py")

    def main(self, vs, runner):
        stdout, stderr = StringIO(), StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = variants.main([str(self.out)], variants=vs, tests=["t"], root=str(self.root), runner=runner,
                                 timeout=5)
        return code, stdout.getvalue(), stderr.getvalue()

    def assert_source_restored(self):
        self.assertEqual(self.src.read_text(), self.body)
        self.assertFalse(Path(str(self.src) + ".vs.bak").exists())

    def test_a_timed_out_variant_is_inconclusive_reported_and_fails_the_run(self):
        """Receipt harness-pr258-v5 F2: a TimeoutExpired was `continue`d past, counted neither caught nor survived,
        and the run exited 0 whatever happened."""
        code, printed, _ = self.main([self.variant("hangs"), self.variant("fails", "Y = 2\n", "Y = 3\n")],
                                     self.fake(subprocess.TimeoutExpired("unittest", 5), (1, CAUGHT_ERR)))
        self.assertEqual(code, 1)
        summary = printed.strip().splitlines()[-1]
        self.assertIn("1 caught", summary)
        self.assertIn("1 timed out (inconclusive) ['hangs']", summary)
        self.assertIn("== variant hangs rc=timeout", printed)
        self.assertEqual(self.out.read_text().strip().splitlines()[-1], summary)
        self.assertEqual(self.seen, ["X = 9\nY = 2\n", "X = 1\nY = 3\n"], "each variant ran on its own swap")
        self.assert_source_restored()

    def test_a_survivor_fails_the_run(self):
        code, printed, _ = self.main([self.variant("passes")], self.fake((0, PASSED_ERR)))
        self.assertEqual(code, 1)
        self.assertIn("1 survived ['passes']", printed)
        self.assert_source_restored()

    def test_only_a_run_where_every_variant_was_caught_exits_zero(self):
        code, printed, _ = self.main([self.variant("a"), self.variant("b", "Y = 2\n", "Y = 0\n")],
                                     self.fake((1, CAUGHT_ERR), (1, CAUGHT_ERR)))
        self.assertEqual(code, 0)
        self.assertIn("2 variants: 2 caught, 0 survived [], 0 timed out (inconclusive) [], 0 broken", printed)
        self.assert_source_restored()

    def test_a_variant_that_was_not_really_tested_is_broken_not_caught(self):
        no_tests = "\n----\nRan 0 tests in 0.0s\n\nOK\n"
        import_failed = "ERROR: mod (unittest.loader._FailedTest)\n----\nRan 1 test in 0.0s\n\nFAILED (errors=1)\n"
        crashed = "Traceback (most recent call last):\nSegmentation fault\n"
        for stderr, rc in ((no_tests, 5), (import_failed, 1), (crashed, -11), ("Ran 2 tests\nOK\n", 3)):
            with self.subTest(stderr=stderr[:30], rc=rc):
                code, printed, _ = self.main([self.variant("v")], self.fake((rc, stderr)))
                self.assertEqual(code, 1)
                self.assertIn("1 broken (inconclusive) ['v']", printed)
                self.assert_source_restored()

    def test_a_non_unique_anchor_stops_the_run_with_the_source_restored(self):
        self.src.write_text("X = 1\nX = 1\n")
        self.body = "X = 1\nX = 1\n"
        code, printed, err = self.main([self.variant("dup")], self.fake())
        self.assertEqual((code, printed), (2, ""))
        self.assertIn("anchor not unique for dup (2)", err)
        self.assertFalse(self.out.exists())
        self.assert_source_restored()

    def test_a_swap_that_does_not_compile_stops_the_run(self):
        code, _printed, err = self.main([self.variant("syntax", "X = 1\n", "X = (\n")], self.fake())
        self.assertEqual(code, 2)
        self.assertIn("does not compile", err)
        self.assert_source_restored()

    def test_a_backup_left_by_an_interrupted_run_is_never_overwritten(self):
        bak = Path(str(self.src) + ".vs.bak")
        bak.write_text("the only clean copy\n")
        self.src.write_text("X = 9\nY = 2\n")             # the mutated source the interrupted run left
        code, _printed, err = self.main([self.variant("v", "Y = 2\n", "Y = 5\n")], self.fake())
        self.assertEqual(code, 2)
        self.assertIn("an interrupted run", err)
        self.assertEqual(bak.read_text(), "the only clean copy\n")
        self.assertEqual(self.src.read_text(), "X = 9\nY = 2\n", "nothing is touched")

    def test_the_source_is_restored_when_the_run_is_interrupted(self):
        with self.assertRaises(KeyboardInterrupt):
            self.main([self.variant("v")], self.fake(KeyboardInterrupt()))
        self.assert_source_restored()


class RealTimeoutTests(unittest.TestCase):

    def test_a_timeout_kills_the_test_command_and_its_children(self):
        """The real run_tests, on a command that starts a child and both sleep past the timeout."""
        with tempfile.TemporaryDirectory() as tmp:
            pidfile = Path(tmp) / "child.pid"
            script = ("import subprocess, sys, time\n"
                      "p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)'])\n"
                      "open(%r, 'w').write(str(p.pid))\n"
                      "time.sleep(120)\n" % str(pidfile))
            started = time.monotonic()
            with self.assertRaises(subprocess.TimeoutExpired):
                variants.run_tests([sys.executable, "-c", script], tmp, timeout=3)
            self.assertLess(time.monotonic() - started, 60, "run_tests waited for the sleepers")
            child = int(pidfile.read_text())
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                try:
                    os.kill(child, 0)
                except ProcessLookupError:
                    break
                time.sleep(0.1)
            else:
                self.fail("the test command's child %d is still alive" % child)


class AnchorTests(unittest.TestCase):

    def test_every_variant_applies_exactly_once_and_compiles(self):
        sources = {}
        for entry in variants.V:
            path = ROOT / (entry[2] if len(entry) > 2 else variants.SRC)
            text = sources.setdefault(path, path.read_text())
            with self.subTest(variant=entry[0]):
                compile(variants.apply_swaps(text, entry[1], entry[0]), str(path), "exec")

    def test_variant_names_are_unique(self):
        names = [entry[0] for entry in variants.V]
        self.assertEqual(len(names), len(set(names)))

    def test_every_named_test_target_exists(self):
        import unittest as ut
        sys.path.insert(0, str(ROOT))
        try:
            for target in variants.T:
                with self.subTest(target=target):
                    self.assertGreater(ut.defaultTestLoader.loadTestsFromName(target).countTestCases(), 0)
        finally:
            sys.path.remove(str(ROOT))


if __name__ == "__main__":
    unittest.main()
