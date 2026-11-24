"""Run named test classes of tests.test_ops_watch_proxmox (from <worktree>) against another ops_watch.py, loaded
in memory as `ops_watch`. Used for failing-first evidence against an earlier head. No file is written.
Usage: python3 -B tests_on_module.py <worktree> <ops_watch.py> <TestClass> [...]"""
import importlib
import io
import sys
import types
import unittest
from pathlib import Path

wt, src = Path(sys.argv[1]), Path(sys.argv[2])
sys.path.insert(0, str(wt / "harness/hooks"))
sys.path.insert(0, str(wt))
mod = types.ModuleType("ops_watch")
mod.__file__ = str(src)
sys.modules["ops_watch"] = mod
exec(compile(src.read_text(), str(src), "exec"), mod.__dict__)
tests = importlib.import_module("tests.test_ops_watch_proxmox")
suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(getattr(tests, c)) for c in sys.argv[3:])
stream = io.StringIO()
res = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
print(stream.getvalue())
sys.exit(0 if res.wasSuccessful() else 1)
