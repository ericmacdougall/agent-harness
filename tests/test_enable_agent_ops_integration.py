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


REPO_SLUG = "ericmacdougall/agent-harness"


class FallbackDenylistIsOptional(unittest.TestCase):
    """X1: the enabler writes no fallback denylist unless the user passes --fallback-denylist
    (Source: answer:1471f671-0ed0-40c3-8506-255cb670e4de/44bc4b2f-436b-4711-a4d8-9d7bd7cf0a06 "Allow every path")."""

    def setUp(self):  # no apply here: each test applies with the options it needs
        from unittest import mock
        import caller_identity as ci
        import self_serve as ss
        from tests import test_enable_agent_ops as T
        self.T, self.ss, self.sid = T, ss, "11111111-2222-3333-4444-555555555555"
        self.base = T.Base("setUp")
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.home = str(self.base.home)
        claude = Path(self.home) / ".claude"
        transcript = claude / "projects" / "-x" / (self.sid + ".jsonl")
        transcript.parent.mkdir(parents=True, exist_ok=True)
        transcript.write_text("{}\n")
        for patcher in (mock.patch.object(ci, "native_deny_reason", return_value=None),
                        mock.patch.dict(ss._SEAM, {"home": self.home, "claude_dir": str(claude), "clock": False})):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.actor = {"kind": "claude_main", "payload": {"session_id": self.sid, "transcript_path": str(transcript)}}

    def grant(self, cap, **evidence):
        return self.ss.explain(cap, actor=self.actor, evidence=evidence or None, home=self.home)

    def scope(self, cap="same_harness_fallback_review"):
        import json
        return json.loads(self.T.E.Layout(self.home).policy.read_text())["capabilities"][cap]["scope"]

    def test_default_apply_writes_no_denylist(self):
        self.assertEqual(self.base.apply(), 0, self.base.output)
        self.assertEqual(self.scope(), {"repos": [REPO_SLUG]})

    def test_a_denylist_the_user_passes_is_signed_and_enforced_by_the_real_library(self):
        self.assertEqual(self.base.run_main("--apply", "--ref", self.T.REF, "--fallback-denylist", "*migrations/*",
                                            "--fallback-denylist", ".github/*"), 0, self.base.output)
        self.assertEqual(self.scope()["denylist_paths"], ["*migrations/*", ".github/*"])
        for path, ok in (("db/migrations/1.sql", False), (".github/workflows/x.yml", False), ("harness/hooks/merge_gate.py", True)):
            got, why = self.grant("same_harness_fallback_review", repo=REPO_SLUG, changed_paths=[path])
            self.assertEqual(got is not None, ok, (path, why))
        got, why = self.grant("same_harness_fallback_review", repo=REPO_SLUG)
        self.assertEqual(why, "changed_paths_required")

    def test_disable_keeps_the_denylist_and_still_refuses_a_tampered_scope(self):
        import json
        E = self.T.E
        self.assertEqual(self.base.run_main("--apply", "--ref", self.T.REF, "--fallback-denylist", "*migrations/*"), 0)
        self.assertEqual(self.base.run_main("--disable", "pool_cleanup"), 0, self.base.output)
        self.assertEqual(self.scope()["denylist_paths"], ["*migrations/*"])
        layout = E.Layout(self.home)
        policy = json.loads(layout.policy.read_text())
        policy["capabilities"]["same_harness_fallback_review"]["scope"]["allow_paths"] = [".*"]
        key = E.Enabler(layout)._identity()[0]
        layout.policy.write_text(json.dumps(E.sign_policy(policy, key), indent=2, sort_keys=True))
        before = layout.policy.read_bytes()
        self.assertEqual(self.base.run_main("--disable", "harness_repair"), 3, self.base.output)
        self.assertEqual(layout.policy.read_bytes(), before)

    def test_a_default_policy_round_trips_through_disable_with_no_denylist(self):
        self.assertEqual(self.base.apply(), 0)
        self.assertEqual(self.base.run_main("--disable", "pool_cleanup"), 0, self.base.output)
        self.assertEqual(self.scope(), {"repos": [REPO_SLUG]})

    def test_unusable_globs_are_refused_before_anything_is_written(self):
        for bad in ("", "a\x00b", "x" * 300, "a\nb"):
            self.assertEqual(self.base.run_main("--apply", "--ref", self.T.REF, "--fallback-denylist", bad), 3, repr(bad))
            self.assertFalse((Path(self.home) / ".agent-harness" / "policy").exists(), repr(bad))


class PreflightUsesTheParityGate(unittest.TestCase):
    """X7: the preflight asks ah_parity.verify_gate(<the user's --ref>) and nothing else, and fails closed."""

    def setUp(self):
        from tests import test_enable_agent_ops as T
        self.T = T
        self.base = T.Base("setUp")
        self.base.setUp()
        self.addCleanup(self.base.tearDown)

    def test_apply_asks_the_gate_for_exactly_the_users_ref(self):
        parity = self.T.FakeParity()
        self.assertEqual(self.base.run_main("--apply", "--ref", self.T.REF, parity=parity), 0, self.base.output)
        self.assertTrue(parity.calls and set(parity.calls) == {self.T.REF}, parity.calls)

    def test_a_refusing_gate_stops_apply_before_anything_is_written(self):
        parity = self.T.FakeParity(ok=False, gate=["mac: Codex will skip 2 hook(s) (untrusted or changed)"])
        self.assertEqual(self.base.run_main("--apply", "--ref", self.T.REF, parity=parity), 3)
        self.assertIn("Codex will skip", self.base.output)
        self.assertFalse((self.base.home / ".agent-harness").exists())

    def test_a_gate_report_that_is_not_a_clean_ok_is_a_refusal(self):
        for report in (None, {}, {"ok": "yes"}, {"ok": 1}, []):
            class Odd:
                calls = []

                def __call__(self, layout, ref, report=report):
                    return report
            self.assertEqual(self.base.run_main("--apply", "--ref", self.T.REF, parity=Odd()), 3, repr(report))
            self.assertFalse((self.base.home / ".agent-harness").exists())

    def test_a_missing_gate_module_fails_closed(self):
        E = self.T.E
        with self.assertRaises(E.Refused):
            E.default_parity(E.Layout(self.base.home), self.T.REF)  # no ah_parity.py in this fixture home

    def test_a_group_writable_gate_module_is_not_loaded(self):
        import os
        E = self.T.E
        hooks = self.base.home / ".claude" / "hooks"
        target = hooks / "ah_parity.py"
        target.write_text("def verify_gate(*a, **k):\n    return {'ok': True, 'gate': []}\n")
        os.chmod(target, 0o664)
        with self.assertRaises(E.Refused):
            E.default_parity(E.Layout(self.base.home), self.T.REF)

    def test_a_plain_gate_module_is_called_with_the_ref_and_the_real_home_only(self):
        import os
        E = self.T.E
        hooks = self.base.home / ".claude" / "hooks"
        target = hooks / "ah_parity.py"
        target.write_text("def verify_gate(pinned_sha=None, home=None, **k):\n"
                          "    return {'ok': True, 'gate': [], 'seen': [pinned_sha, str(home), sorted(k)]}\n")
        os.chmod(target, 0o644)
        report = E.default_parity(E.Layout(self.base.home), self.T.REF)
        self.assertEqual(report["seen"], [self.T.REF, str(self.base.home), []])

    def test_the_enabler_never_calls_the_free_ref_verify(self):
        source = (ROOT / "scripts" / "enable-agent-ops.py").read_text()
        self.assertNotRegex(source, r"(?<![\w])(?:parity|module|ah_parity)\.verify\(")
        self.assertIn("verify_gate", source)


if __name__ == "__main__":
    unittest.main()
