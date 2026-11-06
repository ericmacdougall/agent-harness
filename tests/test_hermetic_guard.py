"""Fail loudly when the suite could touch the real HOME, usage store or state directory (GoodQA #14560)."""
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import hermetic  # noqa: E402

hermetic.install()  # at import: discovery imports every module before any test runs

HOOKS = Path(__file__).resolve().parents[1] / 'harness' / 'hooks'
sys.path.insert(0, str(HOOKS))


class HermeticSuite(unittest.TestCase):
    def test_process_resolves_no_real_home_paths(self):
        self.assertEqual(hermetic.violations(), [])

    def test_usage_store_default_is_not_under_the_real_home(self):
        import usage_guard
        store = usage_guard.UsageStore()  # resolved from the pinned environment; creates a temp dir only
        self.assertFalse(hermetic.hits_protected(store.root), store.root)

    def test_guard_detects_a_real_home_resolution(self):
        real = hermetic.real_home()
        with mock.patch.dict(os.environ, {'AGENT_HARNESS_USAGE_DIR': str(real / '.agent-harness' / 'usage')}):
            self.assertTrue(any('AGENT_HARNESS_USAGE_DIR' in item for item in hermetic.violations()))
        with mock.patch.dict(os.environ, {'HOME': str(real)}):
            self.assertTrue(any(item.startswith('HOME=') for item in hermetic.violations()))

    def test_install_repairs_a_real_usage_dir(self):
        real = str(hermetic.real_home() / '.agent-harness' / 'usage')
        with mock.patch.dict(os.environ, {'AGENT_HARNESS_USAGE_DIR': real}):
            hermetic.install()
            self.assertNotEqual(os.environ['AGENT_HARNESS_USAGE_DIR'], real)
            self.assertEqual(hermetic.violations(), [])

    def test_a_temp_root_under_the_real_home_is_not_a_violation(self):
        under_home = hermetic.real_home() / '.agent-harness' / 'scratch' / 'x'
        self.assertFalse(hermetic.hits_protected(under_home))
        with mock.patch.dict(os.environ, {'AGENT_HARNESS_USAGE_DIR': str(under_home / 'usage')}):
            self.assertEqual([item for item in hermetic.violations() if 'USAGE' in item], [])

    def test_frozen_real_state_path_in_a_module_is_reported(self):
        fake = type(sys)('fake_frozen')
        fake.LOG_PATH = hermetic.real_home() / '.agent-harness' / 'logs' / 'x.jsonl'
        fake.SAFE = '/tmp/harmless'
        found = hermetic.scan_frozen_paths({'fake_frozen': fake})
        self.assertEqual(len(found), 1)
        self.assertIn('fake_frozen.LOG_PATH', found[0])

    def test_no_loaded_module_froze_a_real_state_path(self):
        # run_capped, heavy_job_guard and commit_policy compute their paths at import; with HOME pinned first
        # (gate wrapper) none may point at the real state. Under a bare `discover` this check is skipped (see the
        # Scope limits in the spec): those globals are frozen before test_hermetic_guard is imported.
        if os.environ.get('HARNESS_SUITE_PINNED') != '1':
            self.skipTest('only meaningful when the gate wrapper pinned HOME before Python started')
        # escalation pins its roots to the passwd home on purpose (a caller's HOME must not relabel them, GoodQA
        # #14686) and only reads it to verify receipts; the audit hook records any write into that store, so it stays the backstop.
        by_design = {'escalation.DEFAULT_USAGE_ROOT'}
        self.assertEqual([item for item in hermetic.scan_frozen_paths() if item.split('=')[0] not in by_design], [])

    def test_home_inside_a_protected_dir_is_a_violation(self):
        with mock.patch.dict(os.environ, {'HOME': str(hermetic.real_home() / '.claude')}):
            self.assertTrue(any(item.startswith('HOME=') for item in hermetic.violations()))


class PerTestGuard(unittest.TestCase):
    """A test whose cleanup restores HOME to the passwd home (as tests/test_escalation.py once did) must fail loudly."""

    LEAKY = (
        "import os, sys, unittest\n"
        "sys.path.insert(0, %(tests)r)\n"
        "import hermetic\n"
        "hermetic.install()\n"
        "class T(unittest.TestCase):\n"
        "    def test_a_leaks_home(self):\n"
        "        os.environ['HOME'] = %(real)r\n"
        "        self.addCleanup(lambda: os.environ.__setitem__('HOME', %(real)r))\n"
        "    def test_b_runs_later(self):\n"
        "        self.assertNotEqual(os.path.realpath(os.environ['HOME']), %(real)r)\n"
        "if __name__ == '__main__':\n"
        "    unittest.main()\n")
    CLEAN = (
        "import os, sys, unittest\n"
        "sys.path.insert(0, %(tests)r)\n"
        "import hermetic\n"
        "hermetic.install()\n"
        "class T(unittest.TestCase):\n"
        "    def test_a_borrows_home(self):\n"
        "        old = os.environ['HOME']\n"
        "        os.environ['HOME'] = %(real)r\n"
        "        self.addCleanup(os.environ.__setitem__, 'HOME', old)\n"
        "    def test_b_runs_later(self):\n"
        "        self.assertNotEqual(os.path.realpath(os.environ['HOME']), %(real)r)\n"
        "if __name__ == '__main__':\n"
        "    unittest.main()\n")

    def run_child(self, source):
        import subprocess
        import tempfile
        with tempfile.TemporaryDirectory() as temp:
            script = Path(temp) / 'child_tests.py'
            script.write_text(source % {'tests': str(Path(__file__).resolve().parent), 'real': str(hermetic.real_home())})
            env = {key: value for key, value in os.environ.items() if key not in ('HOME', 'AGENT_HARNESS_USAGE_DIR')}
            env['HOME'] = temp
            return subprocess.run([sys.executable, str(script)], capture_output=True, text=True, env=env, timeout=60)

    def test_a_leaking_test_fails_and_later_tests_stay_protected(self):
        done = self.run_child(self.LEAKY)
        self.assertNotEqual(done.returncode, 0, done.stderr)
        self.assertIn('test_a_leaks_home', done.stderr)
        self.assertIn('real home', done.stderr)
        # the re-pin keeps the later test from running against the real home
        self.assertNotIn('FAIL: test_b_runs_later', done.stderr)

    def test_a_test_that_restores_the_prior_value_passes(self):
        done = self.run_child(self.CLEAN)
        self.assertEqual(done.returncode, 0, done.stderr)


if __name__ == '__main__':
    unittest.main()
