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
        self.assertNotIn(hermetic.real_home(), Path(os.path.realpath(store.root)).parents)

    def test_guard_detects_a_real_home_resolution(self):
        with mock.patch.dict(os.environ, {'AGENT_HARNESS_USAGE_DIR': str(hermetic.real_home() / '.agent-harness' / 'usage')}):
            self.assertTrue(any('AGENT_HARNESS_USAGE_DIR' in item for item in hermetic.violations()))
        with mock.patch.dict(os.environ, {'HOME': str(hermetic.real_home())}):
            self.assertTrue(any(item.startswith('HOME=') for item in hermetic.violations()))

    def test_install_repairs_a_real_usage_dir(self):
        real = str(hermetic.real_home() / '.agent-harness' / 'usage')
        with mock.patch.dict(os.environ, {'AGENT_HARNESS_USAGE_DIR': real}):
            hermetic.install()
            self.assertNotEqual(os.environ['AGENT_HARNESS_USAGE_DIR'], real)
            self.assertEqual(hermetic.violations(), [])


if __name__ == '__main__':
    unittest.main()
