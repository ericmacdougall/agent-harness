"""The one approvals store (ah_approvals.py, docs/approvals.md): who may grant, what a scope covers, and that the
reader and the guards never fail on a bad store."""

import io
import json
import os
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import ah_approvals as ap  # noqa: E402
import ah_roles  # noqa: E402

try:  # resource_budget is not part of the approvals store; it may be removed with `ah limits` (release 1001)
    import resource_budget as rb  # noqa: E402
except ImportError:  # pragma: no cover - depends on the integrated tree
    rb = None

SUP = "11111111-2222-3333-4444-555555555555"
AGENT_ENV = {"CLAUDECODE": "1", "CLAUDE_CODE_SESSION_ID": SUP}
PLAIN_AGENT_ENV = {"CLAUDECODE": "1", "CLAUDE_CODE_SESSION_ID": "99999999-2222-3333-4444-555555555555"}


class Store(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="approvals-")
        self.addCleanup(tmp.cleanup)
        self.home = Path(tmp.name)
        self.proj = self.home / "proj"
        (self.proj / "src").mkdir(parents=True)
        (self.proj / ".git").mkdir()
        (self.proj / ".git" / "config").write_text('[remote "origin"]\n\turl = git@github.com:acme/widget.git\n')
        self.other = self.home / "other"
        self.other.mkdir()
        ah_roles.set_supervisor(SUP, [str(self.proj)], home=self.home)

    def cli(self, argv, env):
        out = io.StringIO()
        with redirect_stdout(out):
            code = ap.main(argv, env=env, home=self.home)
        return code, out.getvalue()

    # ---- who may grant

    def test_user_grant_in_a_terminal(self):
        code, out = self.cli(["approve", "merge", "--project", str(self.proj), "--pr", "7", "--reason", "ship it",
                              "--json"], env={})
        self.assertEqual(code, 0, out)
        record = json.loads(out)["approval"]
        self.assertEqual((record["granted_by"], record["scope"]["pr"]), ("user", 7))
        self.assertEqual(oct(os.stat(ap.store_path(self.home)).st_mode & 0o777), "0o600")

    def test_supervisor_grants_inside_its_projects_only(self):
        code, out = self.cli(["approve", "merge", "--project", str(self.proj), "--json"], env=AGENT_ENV)
        self.assertEqual(code, 0, out)
        self.assertEqual(json.loads(out)["approval"]["granted_by"], "supervisor:" + SUP)
        code, out = self.cli(["approve", "merge", "--project", "acme/widget", "--json"], env=AGENT_ENV)
        self.assertEqual(code, 0, out)  # the repo slug of a supervised checkout
        code, out = self.cli(["approve", "merge", "--project", str(self.other)], env=AGENT_ENV)
        self.assertEqual(code, 3)
        self.assertIn("projects it supervises", out)
        code, out = self.cli(["approve", "merge"], env=AGENT_ENV)  # no project: a supervisor cannot grant globally
        self.assertEqual(code, 3)
        for kind in ("secret", "spend", "harness"):
            code, out = self.cli(["approve", kind, "--project", str(self.proj)], env=AGENT_ENV)
            self.assertEqual(code, 3, kind)
        code, out = self.cli(["approve", "top-rung", "--task", "t1", "--project", str(self.proj), "--json"],
                             env=AGENT_ENV)
        self.assertEqual(code, 0, out)

    def test_plain_agent_is_refused_with_the_path(self):
        code, out = self.cli(["approve", "merge", "--project", str(self.proj)], env=PLAIN_AGENT_ENV)
        self.assertEqual(code, 3)
        message = json.loads(out)["message"]
        self.assertIn("--as-user --user-msg", message)
        self.assertEqual(ap.list_approvals(home=self.home), [])  # nothing written

    def test_as_user_needs_a_real_human_turn(self):
        def verify(session, msg):
            if msg != "uuid:good":
                raise ap.Refused("not a human turn")
            return "yes merge PR 7 please"
        who, source = ap.caller(True, "uuid:good", env=PLAIN_AGENT_ENV, home=self.home, verify=verify)
        self.assertEqual(who, "user")
        self.assertIn("yes merge PR 7", source)
        with self.assertRaises(ap.Refused):
            ap.caller(True, "uuid:bad", env=PLAIN_AGENT_ENV, home=self.home, verify=verify)
        with self.assertRaises(ap.Refused):
            ap.caller(True, None, env=PLAIN_AGENT_ENV, home=self.home, verify=verify)

    def test_as_user_never_records_an_owner_only_kind_and_names_who_recorded_it(self):
        """The release 1001 red team: --as-user returned "user" for any kind, citing any owner turn."""
        verify = lambda session, msg: "sure"  # noqa: E731 - any human turn
        for kind in ap.OWNER_ONLY_KINDS:
            with self.subTest(kind=kind), self.assertRaises(ap.Refused):
                ap.caller(True, "uuid:good", env=PLAIN_AGENT_ENV, home=self.home, verify=verify, kind=kind)
            code, out = self.cli(["approve", kind, "--as-user", "--user-msg", "uuid:good"], env=PLAIN_AGENT_ENV)
            self.assertEqual(code, 3, (kind, out))
        self.assertEqual(ap.list_approvals(home=self.home), [])
        who, source = ap.caller(True, "uuid:good", env=PLAIN_AGENT_ENV, home=self.home, verify=verify, kind="merge")
        self.assertEqual(who, "user")
        self.assertIn("recorded by worker session " + PLAIN_AGENT_ENV["CLAUDE_CODE_SESSION_ID"], source)

    def test_only_the_owner_names_supervisors(self):
        code, out = self.cli(["supervisor", "set", "--session", SUP, "--project", str(self.other)], env=AGENT_ENV)
        self.assertEqual(code, 3)
        code, out = self.cli(["supervisor", "set", "--session", SUP, "--project", str(self.other), "--harness"], env={})
        self.assertEqual(code, 0, out)
        entry = ah_roles.load_roles(self.home)["supervisors"][SUP]
        self.assertTrue(entry["harness"])
        code, out = self.cli(["supervisor", "list"], env={})
        view = json.loads(out)[SUP]
        self.assertEqual((view["harness"], view["model"]), (True, "unknown"))
        code, out = self.cli(["supervisor", "clear", "--session", SUP], env={})
        self.assertNotIn(SUP, ah_roles.load_roles(self.home)["supervisors"])

    # ---- what a scope covers

    def test_pr_approval_survives_a_head_change_and_exact_head_is_opt_in(self):
        ap.grant("merge", {"project": "acme/widget", "pr": 7}, "user", "ok", home=self.home)
        for head in ("a" * 40, "b" * 40):
            self.assertIsNotNone(ap.allowed("merge", repo="acme/widget", pr=7, head=head, home=self.home))
        self.assertIsNone(ap.allowed("merge", repo="acme/widget", pr=8, home=self.home))
        self.assertIsNotNone(ap.allowed("merge", project=str(self.proj), pr=7, home=self.home))  # checkout dir
        pinned = ap.grant("merge", {"project": "acme/other", "pr": 3}, "user", "ok", exact_head="c" * 40,
                          home=self.home)
        self.assertEqual(ap.allowed("merge", repo="acme/other", pr=3, head="c" * 40, home=self.home)["id"], pinned["id"])
        self.assertIsNone(ap.allowed("merge", repo="acme/other", pr=3, head="d" * 40, home=self.home))
        self.assertIsNone(ap.allowed("merge", repo="acme/other", pr=3, home=self.home))

    def test_project_wide_record_and_path_globs(self):
        ap.grant("delete", {"project": str(self.proj)}, "user", "cleanup", home=self.home)
        self.assertIsNotNone(ap.allowed("delete", path=str(self.proj / "src" / "x.py"), home=self.home))
        self.assertIsNone(ap.allowed("delete", path=str(self.other / "x.py"), home=self.home))
        ap.grant("kill", {"project": str(self.proj), "path": "build/*"}, "user", "", home=self.home)
        self.assertIsNotNone(ap.allowed("kill", project=str(self.proj), path=str(self.proj / "build" / "a"),
                                        home=self.home))
        self.assertIsNone(ap.allowed("kill", project=str(self.proj), path=str(self.proj / "src" / "a"),
                                     home=self.home))
        ap.grant("kill", {"pids": [10, 11]}, "user", "", home=self.home)
        self.assertIsNotNone(ap.allowed("kill", pids=[10], home=self.home))
        self.assertIsNone(ap.allowed("kill", pids=[10, 12], home=self.home))

    def test_expiry_and_revoke(self):
        record = ap.grant("release", {"project": "acme/widget"}, "user", "", expires="1h", home=self.home)
        self.assertIsNotNone(ap.allowed("release", repo="acme/widget", home=self.home))
        self.assertIsNone(ap.allowed("release", repo="acme/widget", now=time.time() + 7200, home=self.home))
        ap.revoke(record["id"], "user", home=self.home)
        self.assertIsNone(ap.allowed("release", repo="acme/widget", home=self.home))
        self.assertEqual(ap.list_approvals(home=self.home), [])
        self.assertEqual(len(ap.list_approvals(live=False, home=self.home)), 1)
        other = ap.grant("other", {"what": "x"}, "user", "", home=self.home)
        with self.assertRaises(ap.Refused):
            ap.revoke(other["id"], "supervisor:" + SUP, home=self.home)  # outside its projects

    def test_tolerant_reader_skips_a_corrupt_line(self):
        ap.grant("merge", {"project": "acme/widget"}, "user", "", home=self.home)
        with open(ap.store_path(self.home), "a") as handle:
            handle.write('{"op": "grant", "id": \n\x00garbage\n[1,2]\n')
        ap.grant("delete", {"project": str(self.proj)}, "user", "", home=self.home)
        self.assertIsNotNone(ap.allowed("merge", repo="acme/widget", home=self.home))
        self.assertIsNotNone(ap.allowed("delete", path=str(self.proj / "a"), home=self.home))
        self.assertIsNone(ap.allowed("merge", repo=object(), home=self.home))  # never raises

    def test_harness_kind_matches_what(self):
        ap.grant("harness", {"what": "heavy_job_guard copy rule"}, "user", "", home=self.home)
        self.assertIsNotNone(ap.allowed("harness", what="Heavy_Job_Guard copy rule", home=self.home))
        self.assertIsNone(ap.allowed("harness", what="command_guard", home=self.home))
        code, out = self.cli(["approvals", "check", "harness", "--what", "heavy_job_guard copy rule"], env=AGENT_ENV)
        self.assertEqual(code, 0, out)

    def test_check_and_list_cli(self):
        code, out = self.cli(["approvals", "check", "merge", "--repo", "acme/widget", "--pr", "7"], env=PLAIN_AGENT_ENV)
        self.assertEqual(code, 1)
        self.assertIn("not approved", out)
        ap.grant("merge", {"project": "acme/widget", "pr": 7}, "user", "the owner said ship", home=self.home)
        code, out = self.cli(["approvals", "check", "merge", "--repo", "acme/widget", "--pr", "7"], env=PLAIN_AGENT_ENV)
        self.assertEqual(code, 0)
        code, out = self.cli(["approvals"], env=PLAIN_AGENT_ENV)
        self.assertIn("the owner said ship", out)
        self.assertIn("standing", out)


class LaunchRoles(unittest.TestCase):
    """The role comes from the launch (AH_ROLE, ah_roles.launch_role), and the OS backs it: a sandbox that keeps
    approvals.jsonl read-only turns a grant into a clean refusal that names the path (docs/roles.md)."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="approvals-launch-")
        self.addCleanup(tmp.cleanup)
        self.home = Path(tmp.name).resolve()
        self.proj = self.home / "proj"
        self.proj.mkdir()
        self.other = self.home / "other"
        self.other.mkdir()

    def cli(self, argv, env):
        out = io.StringIO()
        with redirect_stdout(out):
            code = ap.main(argv, env=env, home=self.home)
        return code, out.getvalue()

    def supervisor_env(self, session=SUP):
        return {"AH_ROLE": "supervisor", "AH_ROLE_SOURCE": "ah-sandbox:supervisor", "CLAUDECODE": "1",
                "CLAUDE_CODE_SESSION_ID": session}

    def test_supervisor_by_launch_role_grants_inside_its_projects(self):
        ah_roles.set_role_default([str(self.proj)], home=self.home)  # no per-session entry: the role default
        env = self.supervisor_env("77777777-2222-3333-4444-555555555555")
        code, out = self.cli(["approve", "merge", "--project", str(self.proj), "--pr", "3", "--json"], env=env)
        self.assertEqual(code, 0, out)
        self.assertEqual(json.loads(out)["approval"]["granted_by"], "supervisor:77777777-2222-3333-4444-555555555555")
        code, out = self.cli(["approve", "merge", "--project", str(self.other)], env=env)
        self.assertEqual(code, 3)
        self.assertIn("projects it supervises", out)
        for kind in ap.OWNER_ONLY_KINDS:
            code, out = self.cli(["approve", kind, "--project", str(self.proj)], env=env)
            self.assertEqual(code, 3, kind)
            self.assertIn("owner", json.loads(out)["message"])

    def test_supervisor_by_launch_role_without_any_entry_supervises_nothing(self):
        code, out = self.cli(["approve", "merge", "--project", str(self.proj)], env=self.supervisor_env())
        self.assertEqual(code, 3)
        self.assertIn("(none)", out)

    def test_worker_is_refused_with_the_hint_even_when_roles_json_names_it(self):
        ah_roles.set_supervisor(SUP, [str(self.proj)], home=self.home)
        env = {"AH_ROLE": "worker", "CLAUDECODE": "1", "CLAUDE_CODE_SESSION_ID": SUP}
        code, out = self.cli(["approve", "merge", "--project", str(self.proj), "--pr", "4"], env=env)
        self.assertEqual(code, 3)
        message = json.loads(out)["message"]
        self.assertIn("worker", message)
        self.assertIn("ah approve merge --project " + str(self.proj) + " --pr 4", message)
        self.assertIn("ask the owner or a supervisor session", message)
        self.assertEqual(ap.list_approvals(home=self.home), [])
        reviewer = dict(env, AH_ROLE="reviewer")
        self.assertEqual(self.cli(["approve", "merge", "--project", str(self.proj)], env=reviewer)[0], 3)

    def test_ah_role_without_an_agent_marker_is_still_an_agent(self):
        code, _ = self.cli(["approve", "merge", "--project", str(self.proj)], env={"AH_ROLE": "worker"})
        self.assertEqual(code, 3)
        self.assertTrue(ap.in_agent({"AH_ROLE": "worker"}))
        self.assertFalse(ap.in_agent({}))

    def test_a_read_only_store_gives_exit_3_with_the_path_not_a_traceback(self):
        ah_roles.set_role_default([str(self.proj)], home=self.home)
        store = ap.store_path(self.home)
        store.parent.mkdir(parents=True, exist_ok=True)
        store.write_text("")
        os.chmod(store, 0o400)  # what the worker sandbox does to approvals.jsonl (W1 record_paths)
        self.addCleanup(os.chmod, store, 0o600)
        for env in (self.supervisor_env(), {}):
            with self.subTest(env=env):
                code, out = self.cli(["approve", "merge", "--project", str(self.proj), "--pr", "9"], env=env)
                self.assertEqual(code, 3, out)
                result = json.loads(out)
                self.assertEqual(result["code"], "refused")
                self.assertIn(str(store), result["message"])
                self.assertIn("ah approve merge --project " + str(self.proj) + " --pr 9", result["message"])
                self.assertIn("ask the owner or a supervisor session", result["message"])
        with mock.patch.object(ap, "_append", side_effect=PermissionError(1, "Operation not permitted")):
            code, out = self.cli(["approve", "merge", "--project", str(self.proj)], env=self.supervisor_env())
        self.assertEqual(code, 3)
        self.assertIn("Operation not permitted", json.loads(out)["message"])

    def test_a_read_only_store_on_revoke_is_a_clean_refusal(self):
        record = ap.grant("merge", {"project": str(self.proj)}, "user", "", home=self.home)
        with mock.patch.object(ap, "_append", side_effect=PermissionError(1, "Operation not permitted")):
            code, out = self.cli(["approvals", "revoke", record["id"]], env={})
        self.assertEqual(code, 3)
        self.assertIn(str(ap.store_path(self.home)), json.loads(out)["message"])

    def test_role_default_is_set_by_the_owner_only(self):
        code, out = self.cli(["supervisor", "set", "--role-default", "--project", str(self.proj)],
                             env=self.supervisor_env())
        self.assertEqual(code, 3)
        code, out = self.cli(["supervisor", "set", "--role-default", "--project", str(self.proj), "--harness"], env={})
        self.assertEqual(code, 0, out)
        self.assertEqual(ah_roles.load_roles(self.home)["supervisor"]["projects"], [str(self.proj)])
        self.assertTrue(ah_roles.load_roles(self.home)["supervisor"]["harness"])
        code, out = self.cli(["supervisor", "list"], env={})
        self.assertEqual(json.loads(out)[ap.ROLE_DEFAULT_KEY]["projects"], [str(self.proj)])
        code, out = self.cli(["supervisor", "clear", "--role-default"], env={})
        self.assertEqual(code, 0, out)
        self.assertNotIn("supervisor", ah_roles.load_roles(self.home))
        code, out = self.cli(["supervisor", "set", "--project", str(self.proj)], env={})
        self.assertEqual(code, 2)  # neither --session nor --role-default

    def test_a_read_only_roles_file_is_a_clean_refusal(self):
        with mock.patch.object(ah_roles, "save_roles", side_effect=PermissionError(13, "Permission denied")):
            code, out = self.cli(["supervisor", "set", "--session", SUP, "--project", str(self.proj)], env={})
        self.assertEqual(code, 3)
        self.assertIn("roles.json", json.loads(out)["message"])

    def test_owner_only_kinds_stay_owner_only_for_every_agent_role(self):
        ah_roles.set_supervisor(SUP, [str(self.proj)], home=self.home)
        for env in (self.supervisor_env(), {"CLAUDECODE": "1", "CLAUDE_CODE_SESSION_ID": SUP}):
            for kind in ap.OWNER_ONLY_KINDS:
                with self.subTest(env=env, kind=kind):
                    self.assertEqual(self.cli(["approve", kind, "--project", str(self.proj)], env=env)[0], 3)
        for kind in ap.OWNER_ONLY_KINDS:
            with self.subTest(owner=kind):
                self.assertEqual(self.cli(["approve", kind, "--project", str(self.proj)], env={})[0], 0)


@unittest.skipIf(rb is None, "resource_budget is not in this tree")
class Limits(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="limits-")
        self.addCleanup(tmp.cleanup)
        self.env = mock.patch.dict(os.environ, {"AH_HOME": tmp.name})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.home = Path(tmp.name)

    def write(self, key, value, set_by):
        path = self.home / ".agent-harness" / "limits.local.json"
        path.parent.mkdir(exist_ok=True)
        data = json.loads(path.read_text()) if path.exists() else {"values": {}}
        data["values"][key] = {"value": value, "set_by": set_by, "reason": "r"}
        path.write_text(json.dumps(data))

    def test_tightened_by_an_agent_is_ignored_with_one_log_line(self):
        self.write("max_live_owners", 2, "agent:abc")
        self.assertEqual(rb.limit("max_live_owners"), 16)
        self.assertEqual(rb.limit("max_live_owners"), 16)
        log = (self.home / ".agent-harness" / "logs" / "limits.log").read_text().splitlines()
        self.assertEqual(len(log), 1)
        self.assertIn("ignored", log[0])
        self.write("min_free_gb", 80, "")  # a higher floor is tighter
        self.assertEqual(rb.limit("min_free_gb"), 25.0)

    def test_loosening_is_always_honoured_and_owner_or_supervisor_may_tighten(self):
        self.write("max_live_owners", 40, "agent:abc")
        self.assertEqual(rb.limit("max_live_owners"), 40)
        self.write("max_live_owners", 4, "supervisor:" + SUP)
        self.assertEqual(rb.limit("max_live_owners"), 4)
        self.write("enforce", True, "user")
        self.assertEqual(rb.owner_cap(), {"max": 4, "enforce": True})

    def test_set_limit_refuses_an_agents_tightening(self):
        with self.assertRaises(PermissionError):
            rb.set_limit("max_heavy_mac", 1, "agent:abc", "less")
        rb.set_limit("max_heavy_mac", 4, "agent:abc", "more room")
        self.assertEqual(rb.limit("max_heavy_mac"), 4)
        rb.set_limit("max_heavy_mac", 1, "user", "the owner")
        self.assertEqual(rb.limit("max_heavy_mac"), 1)
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(rb.limits_cli(["show"]), 0)
        self.assertIn("max_heavy_mac", out.getvalue())


if __name__ == "__main__":
    unittest.main()
