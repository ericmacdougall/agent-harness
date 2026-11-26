"""ah_sandbox: the per-role sandbox and permission settings (docs/sandbox.md). Every test uses a temporary HOME and
passes it explicitly; nothing here reads or writes the real ~/.claude, ~/.codex or ~/.agent-harness."""
from __future__ import annotations

import contextlib
import io
import json
import os
import stat
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest import mock

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import ah_sandbox  # noqa: E402

BASE = json.loads((HOOKS / "sandbox_base.json").read_text())


class Home(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.home = Path(tmp.name) / "home"
        (self.home / ".agent-harness").mkdir(parents=True)
        env = mock.patch.dict(os.environ, {"HOME": str(self.home)})
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop("AH_LOCAL_CONFIG", None)

    def local(self, data):
        (self.home / ".agent-harness" / "local.json").write_text(
            data if isinstance(data, str) else json.dumps(data))

    def settings(self, role, **kw):
        return ah_sandbox.claude_settings(role, home=self.home, **kw)

    def run_main(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = ah_sandbox.main(argv)
        return code, out.getvalue(), err.getvalue()


class ClaudeSettings(Home):
    def test_roles(self):
        self.assertEqual(ah_sandbox.ROLES, ("worker", "reviewer", "supervisor"))

    def test_sandbox_fails_closed_for_every_role(self):
        for role in ah_sandbox.ROLES:
            box = self.settings(role)["sandbox"]
            self.assertIs(box["enabled"], True, role)
            self.assertIs(box["failIfUnavailable"], True, role)
            self.assertIs(box["allowUnsandboxedCommands"], False, role)
            self.assertIs(box["network"]["strictAllowlist"], True, role)
            self.assertEqual(self.settings(role)["permissions"]["disableBypassPermissionsMode"], "disable")

    def test_secrets_denied_to_shell_and_read_tool(self):
        for role in ah_sandbox.ROLES:
            data = self.settings(role)
            deny_read, deny = data["sandbox"]["filesystem"]["denyRead"], data["permissions"]["deny"]
            for path in BASE["secret_paths"]:
                self.assertIn(path, deny_read, role)
                self.assertIn(f"Read({path})", deny, role)
                self.assertIn(f"Read({path}/**)", deny, role)

    def test_records_unwritable(self):
        for role in ah_sandbox.ROLES:
            data = self.settings(role)
            deny_write, deny = data["sandbox"]["filesystem"]["denyWrite"], data["permissions"]["deny"]
            for path in BASE["record_paths"]:
                if role == "supervisor" and path == "~/.agent-harness/approvals.jsonl":
                    continue
                self.assertIn(path, deny_write, (role, path))
                self.assertIn(f"Edit({path})", deny, (role, path))
                self.assertIn(f"Edit({path}/**)", deny, (role, path))

    def test_only_supervisor_writes_approvals(self):
        approvals = "~/.agent-harness/approvals.jsonl"
        sup = self.settings("supervisor")
        self.assertIn(approvals, sup["sandbox"]["filesystem"]["allowWrite"])
        self.assertNotIn(approvals, sup["sandbox"]["filesystem"]["denyWrite"])
        self.assertNotIn(f"Edit({approvals})", sup["permissions"]["deny"])
        for role in ("worker", "reviewer"):
            data = self.settings(role)
            self.assertNotIn(approvals, data["sandbox"]["filesystem"].get("allowWrite", []))
            self.assertIn(approvals, data["sandbox"]["filesystem"]["denyWrite"])

    def test_records_stay_readable(self):
        """Workers run `ah approvals check` and `ah user-msg`: the approvals log and transcripts are never read-denied."""
        for role in ah_sandbox.ROLES:
            data = self.settings(role)
            text = json.dumps(data["sandbox"]["filesystem"]["denyRead"]) + json.dumps(
                [r for r in data["permissions"]["deny"] if r.startswith("Read(")])
            for path in ("approvals.jsonl", ".claude/projects", ".codex/sessions", "roles.json"):
                self.assertNotIn(path, text, (role, path))

    def test_reviewer_is_read_only(self):
        data = self.settings("reviewer", project="/x/checkout")
        self.assertIn("/x/checkout", data["sandbox"]["filesystem"]["denyWrite"])
        for tool in ("Edit", "Write", "NotebookEdit"):
            self.assertIn(tool, data["permissions"]["deny"])
        self.assertEqual(data["sandbox"]["filesystem"].get("allowWrite", []), [])
        self.assertEqual(data["sandbox"].get("excludedCommands", []), [])
        for role in ("worker", "supervisor"):
            deny = self.settings(role)["permissions"]["deny"]
            self.assertNotIn("Edit", deny)
            self.assertNotIn(".", self.settings(role)["sandbox"]["filesystem"]["denyWrite"])

    def test_reviewer_project_path(self):
        """Claude Code 2.1.332 resolves `.` and `./` in a --settings file somewhere other than the working directory
        (the e2e run wrote into the project), so the reviewer's checkout is named by absolute path, never by `.`."""
        generic = self.settings("reviewer")["sandbox"]["filesystem"]["denyWrite"]
        self.assertNotIn(".", generic)
        self.assertNotIn("./", generic)
        with self.assertRaises(ValueError):
            self.settings("reviewer", project="relative/dir")
        code, out, _ = self.run_main(["show", "--role", "reviewer", "--project", "/x/c", "--home", str(self.home)])
        self.assertEqual(code, 0)
        self.assertIn("/x/c", json.loads(out)["sandbox"]["filesystem"]["denyWrite"])
        code, _, err = self.run_main(["show", "--role", "worker", "--project", "/x/c", "--home", str(self.home)])
        self.assertEqual(code, 2)
        self.assertIn("reviewer", err)

    def test_worker_write_scope_and_exclusions(self):
        worker = self.settings("worker")
        self.assertEqual(worker["sandbox"]["filesystem"]["allowWrite"], BASE["worker_write"])
        self.assertIn("ssh", worker["sandbox"]["excludedCommands"])
        self.assertIn("docker *", worker["sandbox"]["excludedCommands"])
        self.assertNotIn("harness *", worker["sandbox"]["excludedCommands"])
        self.assertIn("harness *", self.settings("supervisor")["sandbox"]["excludedCommands"])
        self.assertIs(worker["sandbox"]["autoAllowBashIfSandboxed"], True)

    def test_env_names_the_role(self):
        for role in ah_sandbox.ROLES:
            env = self.settings(role)["env"]
            self.assertEqual(env["AH_ROLE"], role)
            self.assertEqual(env["AH_ROLE_SOURCE"], f"ah-sandbox:{role}")

    def test_unknown_role_refused(self):
        with self.assertRaises(ValueError):
            self.settings("owner")
        with self.assertRaises(ValueError):
            self.settings("admin")

    def test_network_allow_list(self):
        worker = self.settings("worker")["sandbox"]["network"]["allowedDomains"]
        self.assertEqual(worker, BASE["network_allow"])
        reviewer = self.settings("reviewer")["sandbox"]["network"]["allowedDomains"]
        self.assertEqual(reviewer, BASE["reviewer_network_allow"])

    def test_local_hosts_and_domains_reach_the_allow_list(self):
        self.local({"hosts": {"worker-1": {"role": "worker"}, "bad host!": {}}, "remote_worktree_hosts": ["wt-2"],
                    "trusted_git_hosts": ["git.example.org", 7], "sandbox_allowed_domains": ["*.corp.example"],
                    "sandbox_extra_deny_read": ["~/.vault"], "sandbox_extra_write": ["~/build-out"]})
        data = self.settings("worker")
        domains = data["sandbox"]["network"]["allowedDomains"]
        for name in ("worker-1", "wt-2", "git.example.org", "*.corp.example"):
            self.assertIn(name, domains)
        self.assertNotIn("bad host!", domains)
        self.assertEqual(domains[:len(BASE["network_allow"])], BASE["network_allow"])
        self.assertIn("~/.vault", data["sandbox"]["filesystem"]["denyRead"])
        self.assertIn("Read(~/.vault/**)", data["permissions"]["deny"])
        self.assertIn("~/build-out", data["sandbox"]["filesystem"]["allowWrite"])
        self.assertNotIn("~/build-out", self.settings("reviewer")["sandbox"]["filesystem"].get("allowWrite", []))

    def test_local_dict_argument_wins_over_file(self):
        self.local({"sandbox_allowed_domains": ["file.example"]})
        data = ah_sandbox.claude_settings("worker", home=self.home, local={"sandbox_allowed_domains": ["arg.example"]})
        domains = data["sandbox"]["network"]["allowedDomains"]
        self.assertIn("arg.example", domains)
        self.assertNotIn("file.example", domains)

    def test_wrong_typed_keys_fall_back(self):
        self.local({"hosts": ["not", "a", "dict"], "sandbox_allowed_domains": "evil.example",
                    "sandbox_extra_deny_read": {"x": 1}, "sandbox_extra_write": 5, "sandbox_role": 3,
                    "remote_worktree_hosts": "wt"})
        self.assertEqual(self.settings("worker"), ah_sandbox.claude_settings("worker", home=self.home, local={}))
        self.assertEqual(ah_sandbox.sandbox_role(home=self.home), "worker")

    def test_broken_local_file_is_empty(self):
        self.local("{not json")
        self.assertEqual(self.settings("worker"), ah_sandbox.claude_settings("worker", home=self.home, local={}))

    def test_sandbox_role(self):
        self.local({"sandbox_role": "supervisor"})
        self.assertEqual(ah_sandbox.sandbox_role(home=self.home), "supervisor")
        self.local({"sandbox_role": "owner"})
        self.assertEqual(ah_sandbox.sandbox_role(home=self.home), "worker")

    def test_byte_identical(self):
        self.local({"hosts": {"b": {}, "a": {}}})
        one = ah_sandbox.render_claude(self.settings("worker"))
        two = ah_sandbox.render_claude(self.settings("worker"))
        self.assertEqual(one, two)
        self.assertTrue(one.endswith("}\n"))
        self.assertEqual(one, json.dumps(json.loads(one), indent=2, sort_keys=True) + "\n")
        code, out1, _ = self.run_main(["show", "--role", "worker", "--home", str(self.home)])
        code2, out2, _ = self.run_main(["show", "--role", "worker", "--home", str(self.home)])
        self.assertEqual((code, code2), (0, 0))
        self.assertEqual(out1, out2)
        self.assertEqual(out1, one)

    def test_installed_path(self):
        self.assertEqual(ah_sandbox.installed_path(self.home, "reviewer"),
                         self.home / ".agent-harness" / "sandbox" / "reviewer.claude.json")


class Managed(Home):
    def test_managed_adds_locks_and_no_only_keys(self):
        data = ah_sandbox.managed_settings("worker", home=self.home)
        self.assertIs(data["sandbox"]["enableWeakerNestedSandbox"], False)
        self.assertIs(data["sandbox"]["enableWeakerNetworkIsolation"], False)
        text = json.dumps(data)
        self.assertNotIn("allowManagedHooksOnly", text)
        self.assertNotIn("allowManagedPermissionRulesOnly", text)
        base = self.settings("worker")
        for key in ("enableWeakerNestedSandbox", "enableWeakerNetworkIsolation"):
            data["sandbox"].pop(key)
        self.assertEqual(data, base)

    def test_write_managed_needs_dir(self):
        code, out, err = self.run_main(["write", "--flavor", "managed", "--home", str(self.home)])
        self.assertEqual(code, 2)
        self.assertIn("--managed-dir", err)
        self.assertEqual(list(Path(self.home).rglob("*.json")), [])

    def test_write_managed_into_temp_dir(self):
        self.local({"sandbox_role": "reviewer"})
        target = self.home / "mdir"
        code, out, err = self.run_main(["write", "--flavor", "managed", "--managed-dir", str(target),
                                        "--home", str(self.home)])
        self.assertEqual(code, 0, err)
        path = target / "managed-settings.d" / "50-agent-harness.json"
        self.assertEqual(json.loads(path.read_text()), ah_sandbox.managed_settings("reviewer", home=self.home))
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertIn("sudo install", out)
        self.assertIn(ah_sandbox.MANAGED_NAME, out)


class Write(Home):
    def test_write_atomic_0600(self):
        out = self.home / "out" / "worker.json"
        code, _, err = self.run_main(["write", "--role", "worker", "--out", str(out), "--home", str(self.home)])
        self.assertEqual(code, 0, err)
        self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o600)
        self.assertEqual(out.read_text(), ah_sandbox.render_claude(self.settings("worker")))
        self.assertEqual([p.name for p in out.parent.iterdir()], ["worker.json"])  # no temp file left

    def test_write_refuses_symlink(self):
        real = self.home / "real.json"
        real.write_text("keep")
        link = self.home / "link.json"
        link.symlink_to(real)
        code, _, err = self.run_main(["write", "--role", "worker", "--out", str(link), "--home", str(self.home)])
        self.assertNotEqual(code, 0)
        self.assertIn("symlink", err)
        self.assertEqual(real.read_text(), "keep")
        self.assertTrue(link.is_symlink())

    def test_write_codex_flavor(self):
        out = self.home / "profiles.toml"
        code, _, err = self.run_main(["write", "--flavor", "codex", "--out", str(out), "--home", str(self.home)])
        self.assertEqual(code, 0, err)
        tomllib.loads(out.read_text())


class Codex(Home):
    def parsed(self):
        return tomllib.loads(ah_sandbox.codex_profiles(home=self.home))

    def test_three_tables(self):
        perms = self.parsed()["permissions"]
        self.assertEqual(sorted(perms), ["ah-reviewer", "ah-supervisor", "ah-worker"])
        self.assertNotIn("agent-harness:", ah_sandbox.codex_profiles(home=self.home))  # no markers

    def test_worker_profile(self):
        worker = self.parsed()["permissions"]["ah-worker"]
        self.assertEqual(worker["extends"], ":workspace")
        fs = worker["filesystem"]
        self.assertEqual(fs["~/.agent-harness/work"], "write")
        self.assertEqual(fs["~/.agent-harness/codex-wals"], "write")
        for path in BASE["secret_paths"]:
            self.assertEqual(fs[path], "deny")
        self.assertEqual(fs["~/.agent-harness/approvals.jsonl"], "read")
        self.assertEqual(fs[":workspace_roots"][".git"], "write")
        self.assertIs(worker["network"]["enabled"], True)
        self.assertEqual(worker["network"]["domains"]["github.com"], "allow")

    def test_reviewer_and_supervisor(self):
        perms = self.parsed()["permissions"]
        reviewer = perms["ah-reviewer"]
        self.assertEqual(reviewer["extends"], ":read-only")
        self.assertNotIn(":workspace_roots", reviewer["filesystem"])
        self.assertEqual(sorted(reviewer["network"]["domains"]), sorted(BASE["reviewer_network_allow"]))
        self.assertNotIn("write", [v for k, v in reviewer["filesystem"].items() if isinstance(v, str)])
        self.assertEqual(perms["ah-supervisor"]["filesystem"]["~/.agent-harness/approvals.jsonl"], "write")
        self.assertEqual(perms["ah-worker"]["filesystem"]["~/.ssh"], "deny")

    def test_local_additions(self):
        self.local({"sandbox_extra_deny_read": ["~/.vault"], "sandbox_extra_write": ["~/out"],
                    "hosts": {"w1": {}}})
        perms = self.parsed()["permissions"]
        self.assertEqual(perms["ah-worker"]["filesystem"]["~/.vault"], "deny")
        self.assertEqual(perms["ah-worker"]["filesystem"]["~/out"], "write")
        self.assertEqual(perms["ah-worker"]["network"]["domains"]["w1"], "allow")
        self.assertNotIn("~/out", perms["ah-reviewer"]["filesystem"])

    def test_quoting_survives_odd_paths(self):
        perms = tomllib.loads(ah_sandbox.codex_profiles(home=self.home, local={
            "sandbox_extra_write": ['~/a "quoted" dir', "~/back\\slash"]}))["permissions"]
        self.assertEqual(perms["ah-worker"]["filesystem"]['~/a "quoted" dir'], "write")
        self.assertEqual(perms["ah-worker"]["filesystem"]["~/back\\slash"], "write")

    def test_launch_args(self):
        self.assertEqual(ah_sandbox.codex_launch_args("reviewer"),
                         ["-c", 'default_permissions="ah-reviewer"', "-c",
                          'shell_environment_policy.set.AH_ROLE="reviewer"'])
        with self.assertRaises(ValueError):
            ah_sandbox.codex_launch_args("owner")

    def test_requirements(self):
        self.local({"sandbox_role": "supervisor"})
        req = tomllib.loads(ah_sandbox.codex_requirements(home=self.home))
        self.assertEqual(req["allowed_permission_profiles"],
                         {"ah-reviewer": True, "ah-supervisor": True, "ah-worker": True})
        self.assertEqual(req["default_permissions"], "ah-supervisor")
        self.assertEqual(req["permissions"]["filesystem"]["deny_read"], BASE["secret_paths"])

    def test_show_flavors(self):
        code, out, _ = self.run_main(["show", "--flavor", "codex", "--home", str(self.home)])
        self.assertEqual(code, 0)
        self.assertEqual(out, ah_sandbox.codex_profiles(home=self.home))
        code, out, _ = self.run_main(["show", "--role", "worker", "--flavor", "codex-launch", "--json"])
        self.assertEqual(json.loads(out), ah_sandbox.codex_launch_args("worker"))
        code, out, _ = self.run_main(["show", "--flavor", "codex-requirements", "--home", str(self.home)])
        self.assertEqual(code, 0)
        tomllib.loads(out)
        code, out, _ = self.run_main(["show", "--role", "worker", "--flavor", "managed", "--home", str(self.home)])
        self.assertEqual(json.loads(out), ah_sandbox.managed_settings("worker", home=self.home))

    def test_roles_command(self):
        code, out, _ = self.run_main(["roles"])
        self.assertEqual(code, 0)
        self.assertEqual([line.split()[0] for line in out.splitlines()], list(ah_sandbox.ROLES))

    def test_show_needs_role_for_claude(self):
        code, _, err = self.run_main(["show", "--home", str(self.home)])
        self.assertEqual(code, 2)


class RoleLists(Home):
    def test_expanded_lists_for_doctor(self):
        lists = ah_sandbox.role_lists("supervisor", home=self.home)
        h = str(self.home)
        self.assertIn(h + "/.ssh", lists["deny_read"])
        self.assertIn(h + "/.agent-harness/approvals.jsonl", lists["allow_write"])
        self.assertNotIn(h + "/.agent-harness/approvals.jsonl", lists["deny_write"])
        self.assertIn(h + "/.agent-harness/roles.json", lists["deny_write"])
        self.assertFalse(lists["project_read_only"])
        self.assertTrue(ah_sandbox.role_lists("reviewer", home=self.home)["project_read_only"])


if __name__ == "__main__":
    unittest.main()
