"""Guard installs stay the user's (goodqa#16944 ruling on the self-serve enabler, PR #326).

Both agent install routes are refused when the ref would change a guard file, even under a valid self-serve grant. The
routes are `ah ops repair` (also used by the central-decisions recipe) and `ah install-files --manifest`. The refusal
names the one line the user runs. A registered PreToolUse or Stop hook missing from the list fails here.
"""
from __future__ import annotations

import json
import shutil
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
HOOKS = ROOT / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
sys.path.insert(0, str(ROOT / "tests"))

import ah_install as ai  # noqa: E402
import ah_ops as ops  # noqa: E402
import guard_files as gf  # noqa: E402
import test_ah_install as tai  # noqa: E402
import test_ah_ops as tao  # noqa: E402


class List(unittest.TestCase):
    def test_every_registered_guard_hook_is_listed(self):
        registered = gf.registered_guard_hooks(HOOKS / "hooks_manifest.json")
        self.assertTrue(registered)
        self.assertEqual([n for n in registered if not gf.is_guard_file(n)], [])

    def test_installer_pretooluse_and_stop_hooks_are_listed(self):
        """Every script install.py registers for PreToolUse or Stop (its own managed_hooks table) is a guard file."""
        sys.path.insert(0, str(ROOT))
        import install  # noqa: PLC0415
        managed = install.managed_hooks(Path("/H/.claude"))
        scripts = {Path(a).name for event in gf.GUARD_EVENTS for group in managed.get(event, [])
                   for hook in group.get("hooks", []) for a in hook.get("args", []) if str(a).endswith(".py")}
        self.assertIn("mission_gate.py", scripts)
        self.assertIn("command_guard_hook.py", scripts)
        self.assertEqual(sorted(n for n in scripts if not gf.is_guard_file(n)), [])

    def test_closure_counts_imported_modules(self):
        closure = gf.guard_closure(HOOKS)
        for name in ("shellwords.py", "safe_input.py", "caller_identity.py"):
            self.assertIn(name, closure)
        self.assertEqual(gf.guard_subset(["shellwords.py", "README.md"], HOOKS), ["shellwords.py"])
        self.assertEqual(gf.guard_subset(["shellwords.py", "README.md"]), [])

    def test_unreadable_manifest_counts_everything(self, ):
        self.assertIsNone(gf.guard_closure(ROOT / "docs"))
        self.assertEqual(gf.guard_subset(["README.md", "x.py"], ROOT / "docs"), ["README.md", "x.py"])

    def test_refusal_names_the_user_line(self):
        text = gf.refusal("t2-dev", "a" * 40, ["command_guard.py"])
        self.assertIn("ah.py install-files --host t2-dev --from-ref " + "a" * 40 + " --file command_guard.py", text)
        self.assertIn("run by the user in his own terminal", text)


class Repair(tao.Base):
    """`ah ops repair --apply` under a valid grant (the FakeSelfServe seam grants everything)."""

    def drift(self, name, where="ref"):
        if where == "ref":
            real = self.fetch

            def fetch(ctx, ref, names):
                sources, listed, main = real(ctx, ref, names)
                if name in sources:
                    sources[name] = (b"", ops.blob_id(b"changed-" + name.encode()), "100644")
                return sources, listed, main
            patcher = mock.patch.object(ops, "_fetch", fetch)
            patcher.start()
            self.addCleanup(patcher.stop)
        else:
            self.fake.blob[name] = ops.blob_id(b"other-" + name.encode())

    def repair_applied(self):
        return [w for w in self.fake.words() if "repair-harness" in w and w.endswith("--apply")]

    def test_guard_change_is_refused_before_the_install(self):
        self.drift("command_guard.py")
        report = self.refused("repair", "--ref", tao.REF, "--apply")
        self.assertEqual(getattr(report, "code", None) or report["code"], "guard_files")
        self.assertIn("install-files --host", str(getattr(report, "message", report)))
        self.assertEqual(self.repair_applied(), [])

    def test_guard_drift_on_the_host_is_refused(self):
        self.drift("self_serve.py", where="host")
        self.refused("repair", "--ref", tao.REF, "--apply", code="guard_files")
        self.assertEqual(self.repair_applied(), [])

    def test_no_guard_change_installs(self):
        report = self.run_ops("repair", "--ref", tao.REF, "--apply")
        self.assertTrue(report["ok"], report)
        self.assertEqual(len(self.repair_applied()), 1)

    def test_preview_is_not_refused(self):
        self.drift("command_guard.py")
        report = self.run_ops("repair", "--ref", tao.REF)
        self.assertTrue(report["ok"], report)


class Manifest(tai.Base):
    """`ah install-files --manifest` under a valid grant (require_manifest_grant is the gate; it is satisfied here)."""

    def setUp(self):
        super().setUp()
        patcher = mock.patch.object(ai, "require_manifest_grant", lambda *a, **k: None)
        patcher.start()
        self.addCleanup(patcher.stop)
        mac_hooks = self.mac / ".claude" / "hooks"
        mac_hooks.mkdir(parents=True)
        shutil.copy2(HOOKS / "hooks_manifest.json", mac_hooks / "hooks_manifest.json")

    def manifest_install(self, ref):
        return ai.install_files("t2-dev", ref, [], tai.TICKET, False, self.mac, "sess", "agent-x", self.runner,
                                lambda t, text: None, manifest=True)

    def test_guard_change_is_refused_with_nothing_written(self):
        before = {n: self.live(n) for n in tai.NAMES}
        with self.assertRaises(ai.InstallError) as caught:
            self.manifest_install(self.c1)  # c1 changes every listed file, command_guard.py among them
        self.assertEqual(caught.exception.code, "guard_files")
        self.assertIn("command_guard.py", str(caught.exception))
        self.assertIn("install-files --host t2-dev --from-ref " + self.c1, str(caught.exception))
        self.assertEqual({n: self.live(n) for n in tai.NAMES}, before)
        self.assertEqual(self.rows("start"), [])

    def test_non_guard_change_installs(self):
        self.write_commit({"ah.py": self.base_bytes("ah.py") + b"\n# c2\n", "extra.py": self.base_bytes("extra.py") + b"\n# c2\n",
                           "command_guard.py": self.base_bytes("command_guard.py"), "doctor.py": self.base_bytes("doctor.py")}, "c2")
        c2 = tai.git(self.work, "rev-parse", "HEAD")
        tai.git(self.work, "push", "-q", str(self.origin), "main")
        out = self.manifest_install(c2)
        self.assertTrue(out["ok"], out)
        self.assertEqual(out["result"], "installed")

    def test_missing_manifest_on_the_mac_fails_closed(self):
        (self.mac / ".claude" / "hooks" / "hooks_manifest.json").unlink()
        self.write_commit({"extra.py": self.base_bytes("extra.py") + b"\n# c3\n", "ah.py": self.base_bytes("ah.py"),
                           "command_guard.py": self.base_bytes("command_guard.py"), "doctor.py": self.base_bytes("doctor.py")}, "c3")
        c3 = tai.git(self.work, "rev-parse", "HEAD")
        tai.git(self.work, "push", "-q", str(self.origin), "main")
        with self.assertRaises(ai.InstallError) as caught:
            self.manifest_install(c3)
        self.assertEqual(caught.exception.code, "guard_files")

    def test_explicit_file_install_is_unchanged(self):
        """The per-file route is the user's line (and main's sanctioned form); this ruling does not change it."""
        out = self.install(files=("ah.py", "extra.py"))
        self.assertTrue(out["ok"], out)


class EnablerGrants(unittest.TestCase):
    def test_enabler_text_says_guard_installs_stay_user_run(self):
        text = (ROOT / "templates" / "self-serve-block.md").read_text() + (ROOT / "scripts" / "enable-agent-ops.py").read_text()
        self.assertIn("guard", text.lower())
        self.assertIn("never install a guard file", text)


if __name__ == "__main__":
    unittest.main()
