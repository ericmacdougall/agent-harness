"""harness/hooks/doctor.py: wiring check and rules registry. Fixtures only; canaries run under a scratch HOME."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "harness" / "hooks"))
sys.path.insert(0, str(ROOT))
import doctor  # noqa: E402
import install  # noqa: E402
import install_codex  # noqa: E402

MANIFEST = doctor.load_json(doctor.MANIFEST)
RULES = doctor.load_json(doctor.RULES)
VALID_BATCH = {"B1", "B2", "B3", "B4", "B5", "backlog", "owner:pr-e"}


def tuples_from_hooks(hooks: dict):
    out = set()
    for event, groups in hooks.items():
        for g in groups:
            for h in g["hooks"]:
                toks = doctor.flatten(h)
                script = next((Path(t).name for t in toks if t.endswith(".py")), None)
                arg = toks[-1] if script and toks[-1] != toks[[Path(t).name for t in toks].index(script)] else None
                out.add((event, script, arg))
    return out


class ManifestCoversInstallers(unittest.TestCase):
    """If install.py writes a hook the manifest does not list, doctor could never notice it going missing."""

    def test_every_claude_hook_install_writes_is_in_manifest(self):
        written = tuples_from_hooks(install.managed_hooks(Path("/h/.claude"), True))
        listed = {(r["event"], r["script"], r["arg"]) for r in MANIFEST["hooks"] if "claude" in r["flavors"]}
        self.assertTrue(written, "vacuous: installer wrote nothing")
        self.assertEqual(written - listed, set())

    def test_every_codex_hook_install_writes_is_in_manifest(self):
        merged = install_codex.merge_hooks({}, Path("/h/.codex"))["hooks"]
        written = tuples_from_hooks(merged)
        listed = {(r["event"], r["script"], r["arg"]) for r in MANIFEST["hooks"] if "codex" in r["flavors"]}
        self.assertTrue(written)
        self.assertEqual(written - listed, set())

    def test_installed_rows_exist_in_installer_output_with_matching_matcher(self):
        hooks = install.managed_hooks(Path("/h/.claude"), True)
        for r in (x for x in MANIFEST["hooks"] if x["status"] == "installed" and "claude" in x["flavors"]):
            found = doctor.find_hook(hooks, r["event"], r["script"], r["arg"], r["tools"], Path("/h/.claude/hooks"))
            self.assertIsNotNone(found, f"manifest row {r['id']} is not what install.py writes")

    def test_pending_rows_do_not_hide_shipped_scripts(self):
        shipped = {p.name for p in (ROOT / "harness" / "hooks").iterdir()}
        hidden = [r["id"] for r in MANIFEST["hooks"] if r["status"] == "pending" and r["script"] in shipped and not r.get("known_gap")]
        self.assertEqual(hidden, [], "script ships in harness/hooks: promote the row to installed and wire it")

    def test_every_installed_row_script_is_shipped_by_the_installer(self):
        for r in MANIFEST["hooks"]:
            if r["status"] == "installed":
                self.assertIn(r["script"], install.HOOKS, r["id"])


class Check(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.claude = self.dir / ".claude"
        (self.claude / "hooks").mkdir(parents=True)
        for name in install.HOOKS:
            src = ROOT / "harness" / "hooks" / name
            if name.endswith(".py"):
                (self.claude / "hooks" / name).write_text(src.read_text() if src.exists() else "")
        self.live = {"hooks": install.managed_hooks(self.claude, True)}

    def tearDown(self):
        self.tmp.cleanup()

    def run_check(self, live=None, **kw):
        return doctor.check_hooks(MANIFEST, "claude", live or self.live, self.claude / "hooks", canary=False, **kw)

    def test_fully_wired_installer_output_passes(self):
        f = self.run_check()
        self.assertEqual(doctor.verdict(f), 0)
        self.assertTrue(any(x["state"] == doctor.WIRED for x in f))

    def test_removing_a_required_hook_is_detected(self):
        # The command guard incident: written, never wired.
        live = json.loads(json.dumps(self.live))
        live["hooks"]["PreToolUse"] = [g for g in live["hooks"]["PreToolUse"] if g.get("matcher") != "Bash"]
        f = {x["id"]: x["state"] for x in self.run_check(live)}
        self.assertEqual(f["commit_policy:hook"], doctor.MISSING)
        self.assertEqual(doctor.verdict(self.run_check(live)), 1)

    def test_wired_but_script_missing_is_not_wired(self):
        (self.claude / "hooks" / "commit_policy.py").unlink()
        f = {x["id"]: x["state"] for x in self.run_check()}
        self.assertEqual(f["commit_policy:hook"], doctor.SCRIPT_MISSING)

    def test_matcher_that_does_not_cover_the_tool_is_missing(self):
        live = json.loads(json.dumps(self.live))
        for g in live["hooks"]["PreToolUse"]:
            if g.get("matcher") == "Bash":
                g["matcher"] = "Write"
        f = {x["id"]: x["state"] for x in self.run_check(live)}
        self.assertEqual(f["commit_policy:hook"], doctor.MISSING)

    def test_pending_rows_report_but_do_not_fail(self):
        f = self.run_check()
        pending = [x for x in f if x["state"] == doctor.PENDING]
        self.assertTrue(pending)
        self.assertEqual(doctor.verdict(f), 0)

    def test_codex_command_string_form_is_understood(self):
        live = {"hooks": {"PreToolUse": [{"hooks": [{"type": "command",
                "command": "python3 /h/.codex/agent-harness/commit_policy.py hook"}]}]}}
        hooks = live["hooks"]
        hd = Path("/h/.codex/agent-harness")
        self.assertIsNotNone(doctor.find_hook(hooks, "PreToolUse", "commit_policy.py", "hook", ["Bash"], hd))
        self.assertIsNone(doctor.find_hook(hooks, "PreToolUse", "commit_policy.py", "other", ["Bash"], hd))


class WiringIsReal(Check):
    """Review B2 findings 1-3: a hook only counts when it really runs the installed script."""

    def _state(self, live, rid="commit_policy:hook"):
        return {x["id"]: x["state"] for x in self.run_check(live)}[rid]

    def _mut(self, fn):
        live = json.loads(json.dumps(self.live))
        for g in live["hooks"]["PreToolUse"]:
            if g.get("matcher") == "Bash":
                fn(g["hooks"][0])
        return live

    def test_wrong_path_is_not_wired(self):
        live = self._mut(lambda h: h.update(args=["/nonexistent/commit_policy.py", "hook"]))
        self.assertEqual(self._state(live), doctor.MISSING)

    def test_echo_is_not_wired(self):
        live = self._mut(lambda h: h.update(command="echo", args=["commit_policy.py", "hook"]))
        self.assertEqual(self._state(live), doctor.MISSING)

    def test_non_command_type_is_not_wired(self):
        live = self._mut(lambda h: h.update(type="prompt"))
        self.assertEqual(self._state(live), doctor.MISSING)

    def test_disable_all_hooks_means_nothing_is_wired(self):
        live = dict(self.live, disableAllHooks=True)
        f = self.run_check(live)
        self.assertTrue(all(x["state"] != doctor.WIRED for x in f))
        self.assertEqual(doctor.verdict(f), 1)

    def test_matcher_semantics(self):
        self.assertFalse(doctor.matcher_covers("Ba", ["Bash"]))
        self.assertTrue(doctor.matcher_covers("*", ["Bash"]))
        self.assertTrue(doctor.matcher_covers("", ["Bash"]))
        self.assertTrue(doctor.matcher_covers("Edit|Bash", ["Bash"]))
        self.assertFalse(doctor.matcher_covers("Edit|Write", ["Bash"]))

    def test_ssh_host_cannot_be_an_option(self):
        for bad in ("-oProxyCommand=x", "a b", "", "x;y"):
            with self.assertRaises(OSError):
                doctor.check_host(bad)
        self.assertEqual(doctor.check_host("dev2"), "dev2")


class Canary(unittest.TestCase):
    def script(self, body):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        p = Path(d.name) / "g.py"
        p.write_text(body)
        return p

    def test_guard_that_allows_a_denied_payload_fails_canary(self):
        row = {"canaries": [{"payload": {"tool_input": {"command": "x"}}, "expect": "deny"}]}
        allow = self.script("import sys; sys.stdin.read()\n")
        deny = self.script("import sys; sys.stdin.read(); print('{\"permissionDecision\": \"deny\"}')\n")
        self.assertFalse(doctor.run_canary(row, allow)[0])
        self.assertTrue(doctor.run_canary(row, deny)[0])

    def test_crashing_hook_fails_an_allow_canary(self):
        row = {"canaries": [{"payload": {}, "expect": "allow"}]}
        self.assertFalse(doctor.run_canary(row, self.script("raise SystemExit(7)\n"))[0])

    def test_exit_two_crash_does_not_satisfy_a_deny_canary(self):
        row = {"canaries": [{"payload": {}, "expect": "deny"}]}
        crash = self.script("import sys; sys.stderr.write('usage: g.py [-h]'); sys.exit(2)\n")
        self.assertFalse(doctor.run_canary(row, crash)[0])
        clean_deny = self.script("import sys; sys.stdin.read(); sys.stderr.write('blocked by policy'); sys.exit(2)\n")
        self.assertTrue(doctor.run_canary(row, clean_deny)[0])

    def test_empty_script_passes_allow_but_manifest_also_has_a_deny_canary(self):
        row = next(r for r in MANIFEST["hooks"] if r["id"] == "commit_policy:hook")
        self.assertEqual([c["expect"] for c in row["canaries"]], ["allow", "deny"])


class RulesRegistry(unittest.TestCase):
    def test_partial_rule_never_reports_enforced(self):
        rule = {"id": "R", "mechanisms": ["a"], "partial_reason": "only part"}
        self.assertEqual(doctor.rules_report([rule], [{"id": "a", "state": doctor.WIRED}], ROOT)[0]["state"], "PARTIAL")

    def test_known_overclaims_are_flagged_partial(self):
        by_id = {r["id"]: r for r in RULES}
        for rid in ("W05", "S21", "S23", "S04", "S05", "S24"):
            self.assertTrue(by_id[rid].get("partial_reason"), rid)
        self.assertEqual(by_id["S21"]["mode"], {"file": "commit_policy.json", "key": "enforcement"})

    def test_no_unmapped_rules_and_batches_valid(self):
        rows = doctor.rules_report(RULES, [], ROOT / "harness" / "hooks")
        self.assertTrue(rows)
        self.assertNotIn("UNMAPPED", {r["state"] for r in rows})
        for r in RULES:
            if r.get("planned_batch"):
                self.assertIn(r["planned_batch"], VALID_BATCH, r["id"])

    def test_unmapped_rule_is_flagged(self):
        rows = doctor.rules_report([{"id": "X1", "priority": "P0"}], [], ROOT)
        self.assertEqual(rows[0]["state"], "UNMAPPED")

    def test_mechanism_ids_exist_in_manifest(self):
        ids = {r["id"] for r in MANIFEST["hooks"]}
        for r in RULES:
            for m in r.get("mechanisms", []):
                self.assertIn(m, ids, r["id"])

    def test_states_follow_wiring_and_policy_mode(self):
        with tempfile.TemporaryDirectory() as d:
            hd = Path(d)
            (hd / "spec_policy.json").write_text('{"mode": "warn"}')
            rule = {"id": "R", "mechanisms": ["a"], "mode": {"file": "spec_policy.json", "key": "mode"}}
            wired = [{"id": "a", "state": doctor.WIRED}]
            self.assertEqual(doctor.rules_report([rule], wired, hd)[0]["state"], "ALERT-ONLY")
            (hd / "spec_policy.json").write_text('{"mode": "enforce"}')
            self.assertEqual(doctor.rules_report([rule], wired, hd)[0]["state"], "ENFORCED")
            self.assertEqual(doctor.rules_report([rule], [{"id": "a", "state": doctor.MISSING}], hd)[0]["state"],
                             "NOT-ENFORCED")
            (hd / "spec_policy.json").write_text("not json")
            self.assertEqual(doctor.rules_report([rule], wired, hd)[0]["state"], "ALERT-ONLY")  # unknown is never ENFORCED


if __name__ == "__main__":
    unittest.main()
