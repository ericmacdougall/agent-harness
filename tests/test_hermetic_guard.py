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
        # (gate wrapper) none may point at the real state. Under a bare `discover` they are reported, not hidden.
        if os.environ.get('HARNESS_SUITE_PINNED') != '1':
            self.skipTest('only meaningful when the gate wrapper pinned HOME before Python started')
        self.assertEqual(hermetic.scan_frozen_paths(), [])

    def test_home_inside_a_protected_dir_is_a_violation(self):
        with mock.patch.dict(os.environ, {'HOME': str(hermetic.real_home() / '.claude')}):
            self.assertTrue(any(item.startswith('HOME=') for item in hermetic.violations()))


if __name__ == '__main__':
    unittest.main()
