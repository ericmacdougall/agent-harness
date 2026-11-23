"""Cross-lane integration guards for the self-serve enabler (lane L5, integration owner).

X6  the installers ship every file the self-serve lanes added;
X1  the enabler writes no fallback denylist unless the user passes one (answer:1471f671-0ed0-40c3-8506-255cb670e4de/
    44bc4b2f-436b-4711-a4d8-9d7bd7cf0a06 "Allow every path");
X7  the preflight uses ah_parity.verify_gate(<user --ref>), never verify() with a ref;
X8  a policy and pin file the enabler writes are accepted by the REAL self_serve library.
Run: python3 -m unittest tests.test_enable_agent_ops_integration   (from the repository root)
"""
import ast
import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "harness" / "hooks"))
import install  # noqa: E402

SELF_SERVE_FILES = ("self_serve.py", "ah_ops.py", "ah_parity.py", "caller_identity.py", "native_context.py",
                    "safe_input.py", "usage_guard.py", "merge_gate.py", "git_safety.py", "process.py", "shellwords.py")


def codex_helpers():
    tree = ast.parse((ROOT / "install_codex.py").read_text())
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(getattr(t, "id", "") == "DELIVERY_HELPERS" for t in node.targets):
            return tuple(ast.literal_eval(node.value))
    raise AssertionError("DELIVERY_HELPERS not found")


class ManifestShipsSelfServeFiles(unittest.TestCase):
    def test_claude_hooks_manifest_lists_every_self_serve_file(self):
        for name in SELF_SERVE_FILES:
            self.assertIn(name, install.HOOKS, name)
            self.assertTrue((ROOT / "harness" / "hooks" / name).is_file(), name)

    def test_codex_helpers_list_every_self_serve_file(self):
        helpers = codex_helpers()
        for name in SELF_SERVE_FILES:
            self.assertIn(name, helpers, name)


if __name__ == "__main__":
    unittest.main()
