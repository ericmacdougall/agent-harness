"""S1 (GoodQA goodqa#15946): the installer ships every lane module and template (AC-44 inventory, NEG-83).

Bounded: one temp home, no network, no subprocess.
"""
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import install  # noqa: E402

LANE = ROOT / "harness" / "hooks" / "lane"


def shipped_files():
    return sorted(str(p.relative_to(ROOT / "harness" / "hooks")) for p in LANE.rglob("*")
                  if p.is_file() and "__pycache__" not in p.parts and p.suffix != ".pyc")


class InventoryTests(unittest.TestCase):
    def test_every_lane_file_is_in_the_installer_inventory(self):
        missing = [f for f in shipped_files() if f not in install.HOOKS]
        self.assertEqual(missing, [], "lane files missing from install.HOOKS")

    def test_inventory_check_is_not_vacuous(self):
        self.assertIn("lane/identity.py", shipped_files())
        self.assertGreaterEqual(len(shipped_files()), 10)

    def test_install_writes_every_lane_file_into_a_temp_home(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            install.install(home, True, hooks_only=True)
            hooks = home / ".claude" / "hooks"
            for name in shipped_files():
                self.assertTrue((hooks / name).is_file(), name)
                self.assertEqual((hooks / name).read_bytes(), (ROOT / "harness" / "hooks" / name).read_bytes())


if __name__ == "__main__":
    unittest.main()
