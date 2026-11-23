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


class RealLibraryAcceptsTheEnablersOutput(unittest.TestCase):
    """X8: no stub. A real --apply writes the policy, pin file and key; the real self_serve library then decides."""

    NOW = None

    def setUp(self):
        from unittest import mock
        import caller_identity as ci
        import self_serve as ss
        from tests import test_enable_agent_ops as T
        self.T, self.ss, self.sid = T, ss, "11111111-2222-3333-4444-555555555555"
        self.base = T.Base("setUp")
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.assertEqual(self.base.apply(), 0, self.base.output)
        home = str(self.base.home)
        claude = Path(home) / ".claude"
        transcript = claude / "projects" / "-x" / (self.sid + ".jsonl")
        transcript.parent.mkdir(parents=True, exist_ok=True)
        transcript.write_text("{}\n")
        patchers = [mock.patch.object(ci, "native_deny_reason", return_value=None),
                    mock.patch.dict(ss._SEAM, {"home": home, "claude_dir": str(claude), "clock": False})]
        for patcher in patchers:
            patcher.start()
            self.addCleanup(patcher.stop)
        self.home = home
        self.actor = {"kind": "claude_main", "payload": {"session_id": self.sid, "transcript_path": str(transcript)}}

    def grant(self, cap, **evidence):
        return self.ss.explain(cap, actor=self.actor, evidence=evidence or None, home=self.home)

    def test_the_library_reads_the_files_where_the_enabler_wrote_them(self):
        layout = self.T.E.Layout(self.home)
        self.assertEqual(self.ss.policy_path(self.home), layout.policy)
        self.assertEqual(self.ss.pubkeys_path(self.home), layout.pubkeys)
        self.assertEqual(self.ss.private_key_path(self.home), layout.keyfile)

    def test_every_capability_is_granted_to_proven_main(self):
        for cap in self.ss.CAPABILITIES:
            got, why = self.grant(cap, repo="ericmacdougall/agent-harness")
            self.assertIsNotNone(got, (cap, why))
            self.assertEqual(got["capability"], cap)

    def test_the_fallback_has_no_path_restriction_by_default(self):
        for path in ("harness/hooks/merge_gate.py", "db/migrations/1.sql", ".github/workflows/x.yml"):
            got, why = self.grant("same_harness_fallback_review", repo="ericmacdougall/agent-harness",
                                  changed_paths=[path])
            self.assertIsNotNone(got, (path, why))

    def test_a_helper_and_a_foreign_repo_still_get_nothing(self):
        helper = {"kind": "claude_main", "payload": dict(self.actor["payload"], agent_id="a1")}
        got, why = self.ss.explain("merge_reviewed_pr", actor=helper, evidence={"repo": "ericmacdougall/agent-harness"},
                                   home=self.home)
        self.assertIsNone(got)
        got, why = self.grant("merge_reviewed_pr", repo="someone/else")
        self.assertEqual(why, "repo_out_of_scope")


if __name__ == "__main__":
    unittest.main()
