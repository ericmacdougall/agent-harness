"""Exercise release-version normalization without resolving any dependencies."""

from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("normalize-lock.py").resolve()
NORMALIZE = runpy.run_path(str(SCRIPT))
NAMES = {"alpha", "beta"}
BASE = b'''version = 4

[[package]]
name = "alpha"
version = "0.0.0"
dependencies = ["beta", "registry-fixture 0.0.0"]

[[package]]
name = "beta"
version = "0.0.0"

[[package]]
name = "registry-fixture"
version = "0.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "unchanged-fixture-checksum"
'''
EXPECTED = b'''version = 4

[[package]]
name = "alpha"
version = "0.169.0"
dependencies = ["beta", "registry-fixture 0.0.0"]

[[package]]
name = "beta"
version = "0.169.0"

[[package]]
name = "registry-fixture"
version = "0.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "unchanged-fixture-checksum"
'''


class LockNormalizationTests(unittest.TestCase):
    def test_only_source_less_local_package_versions_change(self):
        self.assertEqual(NORMALIZE["normalize_workspace_versions"](BASE, NAMES), EXPECTED)

    def test_unrecognized_lock_is_refused_without_rewriting(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            lock = root / "Cargo.lock"
            lock.write_bytes(BASE)
            result = subprocess.run([sys.executable, str(SCRIPT), str(root)], capture_output=True, text=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("could not be verified", result.stderr)
            self.assertEqual(result.stdout, "")
            self.assertEqual(lock.read_bytes(), BASE)

    def test_refuses_unverified_local_names_versions_and_edges(self):
        external = b'\n[[package]]\nname = "alpha"\nversion = "1.2.3"\nsource = "reg+conflict"\n'
        cases = {
            "duplicate local package": BASE + b'\n[[package]]\nname = "alpha"\nversion = "0.0.0"\n',
            "unexpected local package": BASE + b'\n[[package]]\nname = "extra"\nversion = "0.0.0"\n',
            "foreign package identity": BASE + external,
            "unknown local version": BASE.replace(b'version = "0.0.0"', b'version = "0.0.1"', 1),
            "qualified local dependency": BASE.replace(b'"beta",', b'"beta 0.0.0",'),
            "ambiguous lock ordering": BASE.replace(b'name = "alpha"\nversion = "0.0.0"',
                                                     b'version = "0.0.0"\nname = "alpha"'),
        }
        for case, data in cases.items():
            with self.subTest(case=case), self.assertRaises(ValueError):
                NORMALIZE["normalize_workspace_versions"](data, NAMES)

    def test_requires_exact_workspace_release_and_unique_inherited_manifests(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            workspace = root / "Cargo.toml"
            workspace.write_text('[workspace.package]\nversion = "0.169.0"\n')
            for name in NAMES:
                package = root / name
                package.mkdir()
                (package / "Cargo.toml").write_text(f'[package]\nname = "{name}"\nversion.workspace = true\n')
            verified = NORMALIZE["verify_workspace_members"]
            self.assertEqual(verified(root, NAMES), NAMES)
            with self.assertRaisesRegex(ValueError, "Missing workspace"):
                verified(root, NAMES | {"extra"})
            beta = root / "beta/Cargo.toml"
            beta.write_text('[package]\nname = "beta"\nversion = "0.169.0"\n')
            with self.assertRaisesRegex(ValueError, "inherited workspace"):
                verified(root, NAMES)
            beta.write_text('[package]\nname = "alpha"\nversion.workspace = true\n')
            with self.assertRaisesRegex(ValueError, "inherited workspace"):
                verified(root, NAMES)
            workspace.write_text('[workspace.package]\nversion = "0.169.1"\n')
            with self.assertRaisesRegex(ValueError, "Unexpected workspace version"):
                verified(root, NAMES)


if __name__ == "__main__":
    unittest.main()
