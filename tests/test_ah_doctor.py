"""ah_doctor: the host self-test (docs/doctor.md). Every test uses a temporary HOME and an injected runner, so no
launchctl, systemctl, gh, sandbox or network call reaches the real machine. A "no sandbox" runner executes the probe
script with plain /bin/sh inside the temporary HOME, which is how the tests prove a leak is reported as FAILED."""
from __future__ import annotations

import contextlib
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import ah_doctor  # noqa: E402
import ah_sandbox  # noqa: E402

LABEL = re.compile(r'echo "([A-Za-z0-9_]+)=\$\?"')


class Fake:
    """A runner: sandbox calls answer from `outcome` (proven | leak | twin_refused | nosandbox), the rest canned."""

    def __init__(self, outcome="proven", loaded=(), gh_auth=0, visibility="PRIVATE", python="3.13.1", repos=None,
                 rulesets=None):
        self.outcome, self.loaded, self.gh_auth = outcome, set(loaded), gh_auth
        self.visibility, self.python, self.calls = visibility, python, []
        self.repos, self.rulesets = repos, rulesets or {}

    def __call__(self, argv, env=None, cwd=None, timeout=None):
        self.calls.append(list(argv))
        name = os.path.basename(argv[0])
        if name in ("sandbox-exec", "bwrap"):
            script = argv[-1]
            if self.outcome == "nosandbox":
                done = subprocess.run(["/bin/sh", "-c", script], env=env, cwd=cwd, capture_output=True, text=True,
                                      timeout=60)
                return done.returncode, done.stdout, done.stderr
            lines = []
            for label in LABEL.findall(script):
                denial = label.startswith("d")
                rc = 1 if denial else 0
                if self.outcome == "leak" and denial:
                    rc = 0
                if self.outcome == "twin_refused" and not denial:
                    rc = 1
                lines.append(f"{label}={rc}")
            return 0, "\n".join(lines) + "\n", ""
        if name == "launchctl":
            return (0 if argv[-1].rsplit("/", 1)[-1] in self.loaded else 113), "", ""
        if name == "systemctl":
            return (0 if argv[-1] in self.loaded else 3), "", ""
        if name == "gh" and argv[1:3] == ["auth", "status"]:
            return self.gh_auth, "", ""
        if name == "gh" and argv[1:3] == ["repo", "view"]:
            return 0, self.visibility + "\n", ""
        if name == "gh" and argv[1:3] == ["repo", "list"]:
            return (0, json.dumps(self.repos), "") if self.repos is not None else (1, "", "HTTP 401")
        if name == "gh" and argv[1] == "api" and argv[2].endswith("/rulesets"):
            slug = argv[2][len("repos/"):-len("/rulesets")]
            return 0, json.dumps([{"name": n} for n in self.rulesets.get(slug, [])]), ""
        if name.startswith("python"):
            if "version_info" in argv[-1]:
                return 0, self.python + "\n", ""
            return 0, "{}\n", ""
        return 127, "", "not faked"


class Base(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.home = self.root / "home"
        (self.home / ".agent-harness" / "work").mkdir(parents=True)
        (self.home / ".agent-harness" / "logs").mkdir()
        self.tmpdir = self.root / "tmp"
        self.tmpdir.mkdir()
        env = mock.patch.dict(os.environ, {"HOME": str(self.home), "TMPDIR": str(self.tmpdir)})
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop("AH_LOCAL_CONFIG", None)
        self.managed = self.root / "managed"

    def secret(self):
        (self.home / ".ssh").mkdir(mode=0o700)
        (self.home / ".ssh" / "id_test").write_text("not a real key\n")

    def which(self, name):
        return {"sandbox-exec": "/usr/bin/sandbox-exec", "gh": "/fake/gh", "python3": "/fake/python3",
                "launchctl": "/bin/launchctl"}.get(name)

    def run_doctor(self, runner=None, **kw):
        kw.setdefault("roles", ("worker",))
        return ah_doctor.run(home=self.home, runner=runner or Fake(), system="darwin", which=self.which,
                             disk_usage=lambda path: (100, 50, 50), managed_dir=self.managed, tmp_root=self.tmpdir,
                             **kw)

    def result(self, report, rid):
        found = [r for r in report["results"] if r["id"] == rid]
        self.assertEqual(len(found), 1, [r["id"] for r in report["results"]])
        return found[0]

    def cli(self, argv, runner=None):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = ah_doctor.main(argv + ["--home", str(self.home), "--managed-dir", str(self.managed)],
                                  runner=runner or Fake(), system="darwin", which=self.which,
                                  disk_usage=lambda path: (100, 50, 50), tmp_root=self.tmpdir)
        return code, out.getvalue(), err.getvalue()


class Probes(Base):
    def test_secrets_proven(self):
        self.secret()
        r = self.result(self.run_doctor(), "probe.worker.secrets")
        self.assertEqual(r["status"], "PROVEN", r)

    def test_secrets_denial_leaked(self):
        self.secret()
        r = self.result(self.run_doctor(Fake("leak")), "probe.worker.secrets")
        self.assertEqual(r["status"], "FAILED")
        self.assertIn("leak", r["summary"])

    def test_secrets_twin_refused(self):
        self.secret()
        r = self.result(self.run_doctor(Fake("twin_refused")), "probe.worker.secrets")
        self.assertEqual(r["status"], "FAILED")
        self.assertIn("twin", r["summary"])

    def test_secrets_target_missing(self):
        r = self.result(self.run_doctor(), "probe.worker.secrets")
        self.assertEqual(r["status"], "UNPROVEN")

    def test_no_mechanism_is_unproven(self):
        self.secret()
        report = ah_doctor.run(home=self.home, runner=Fake(), system="darwin", which=lambda n: None,
                               disk_usage=lambda p: (100, 50, 50), managed_dir=self.managed, tmp_root=self.tmpdir,
                               roles=("worker",))
        self.assertEqual(self.result(report, "probe.worker.secrets")["status"], "UNPROVEN")

    def test_unsandboxed_run_fails_and_cleans_up(self):
        """Without a sandbox every denial goes through: each probe says FAILED and no probe file is left behind."""
        self.secret()
        (self.home / ".agent-harness" / "roles.json").write_text("{}")
        before = sorted(str(p) for p in self.home.rglob("*"))
        report = self.run_doctor(Fake("nosandbox"), roles=ah_sandbox.ROLES)
        for rid in ("probe.worker.secrets", "probe.worker.records", "probe.worker.write-scope",
                    "probe.worker.approvals", "probe.reviewer.read-only", "probe.supervisor.approvals"):
            self.assertEqual(self.result(report, rid)["status"], "FAILED", rid)
        self.assertEqual(sorted(str(p) for p in self.home.rglob("*")), before)
        self.assertEqual(list(self.tmpdir.iterdir()), [])
        self.assertEqual((self.home / ".agent-harness" / "roles.json").read_text(), "{}")

    def test_no_content_printed(self):
        self.secret()
        code, out, err = self.cli(["--json", "--role", "all"], runner=Fake("nosandbox"))
        self.assertNotIn("not a real key", out + err)

    def test_probe_profile_names_role_lists(self):
        self.secret()
        fake = Fake()
        self.run_doctor(fake)
        profiles = [c[2] for c in fake.calls if os.path.basename(c[0]) == "sandbox-exec"]
        self.assertTrue(profiles)
        real_ssh = os.path.realpath(self.home / ".ssh")
        self.assertTrue(any(f'(deny file-read* (subpath "{real_ssh}"))' in p for p in profiles))
        self.assertTrue(all("(deny file-write*)" in p for p in profiles))

    def test_records_file_entry_never_created(self):
        """A record that is a file and absent (OFF) is skipped, never created by the probe."""
        self.run_doctor(Fake("nosandbox"))
        self.assertFalse((self.home / ".agent-harness" / "OFF").exists())

    def test_role_all_probes_three_roles(self):
        report = self.run_doctor(roles=ah_sandbox.ROLES)
        roles = {r["id"].split(".")[1] for r in report["results"] if r["id"].startswith("probe.")}
        self.assertEqual(roles, set(ah_sandbox.ROLES))
        ids = {r["id"] for r in report["results"]}
        self.assertIn("probe.reviewer.read-only", ids)
        self.assertNotIn("probe.worker.read-only", ids)


class Checks(Base):
    def write_settings(self, hooks):
        claude = self.home / ".claude"
        (claude / "hooks").mkdir(parents=True, exist_ok=True)
        for name in ("ah_hook.py", "wal.py"):
            (claude / "hooks" / name).write_text("")
        (claude / "settings.json").write_text(json.dumps({"hooks": hooks}))
        return claude

    def handler(self, script, *args):
        hooks = self.home / ".claude" / "hooks"
        return {"type": "command", "command": " ".join(["python3", str(hooks / "ah_hook.py"), script, *args])}

    def test_bash_pretooluse_handler_fails(self):
        self.write_settings({"PreToolUse": [{"matcher": "Bash|Edit", "hooks": [self.handler("wal.py", "pretool")]}]})
        r = self.result(self.run_doctor(), "wiring.claude")
        self.assertEqual(r["status"], "FAILED")
        self.assertIn("Bash", r["summary"])

    def test_regex_and_catch_all_matchers_count(self):
        for matcher in (".*", "", "Ba.h", "*"):
            self.write_settings({"PostToolUse": [{"matcher": matcher, "hooks": [self.handler("wal.py")]}]})
            self.assertEqual(self.result(self.run_doctor(), "wiring.claude")["status"], "FAILED", matcher)

    def test_clean_wiring_ok(self):
        self.write_settings({"SessionStart": [{"hooks": [self.handler("wal.py", "session")]}],
                             "PreToolUse": [{"matcher": "mcp__db__query", "hooks": [self.handler("wal.py")]}]})
        self.assertEqual(self.result(self.run_doctor(), "wiring.claude")["status"], "OK")

    def test_missing_script_and_direct_wiring_fail(self):
        hooks = self.home / ".claude" / "hooks"
        self.write_settings({"Stop": [{"hooks": [self.handler("gone.py")]}]})
        r = self.result(self.run_doctor(), "wiring.claude")
        self.assertEqual(r["status"], "FAILED")
        self.assertIn("gone.py", r["summary"])
        self.write_settings({"Stop": [{"hooks": [{"type": "command", "command": f"python3 {hooks / 'wal.py'}"}]}]})
        self.assertIn("launcher", self.result(self.run_doctor(), "wiring.claude")["summary"])

    def test_a_real_install_reads_as_ten_handlers_and_a_changed_one_differs(self):
        # The installer's own output, compared with the release snapshot it recorded (ah_switch.managed_wiring).
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        import install  # noqa: PLC0415
        with mock.patch.object(install, "scratch_status", lambda *a, **k: "durable scratch: skipped (test)"):
            install.install(self.home, True)
        r = self.result(self.run_doctor(), "wiring.claude")
        self.assertEqual((r["status"], r["detail"]["handlers"]), ("OK", 10), r)
        settings = self.home / ".claude" / "settings.json"
        doc = json.loads(settings.read_text())
        doc["hooks"]["Stop"][0]["hooks"][0]["timeout"] = 1
        settings.write_text(json.dumps(doc))
        r = self.result(self.run_doctor(), "wiring.claude")
        self.assertEqual(r["status"], "FAILED")
        self.assertIn("differs from release", r["summary"])

    def test_user_hook_on_bash_is_not_ours(self):
        self.write_settings({"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "mytool"}]}]})
        self.assertEqual(self.result(self.run_doctor(), "wiring.claude")["status"], "OK")

    def test_off_with_loaded_job_fails(self):
        (self.home / ".agent-harness" / "OFF").write_text(json.dumps({"at": "2026-11-25T08:00:12Z", "by": "o"}))
        label = "com.agent-harness.log-backup"
        r = self.result(self.run_doctor(Fake(loaded=[label])), "switch")
        self.assertEqual(r["status"], "FAILED")
        self.assertIn(label, r["summary"])
        r = self.result(self.run_doctor(Fake()), "switch")
        self.assertEqual(r["status"], "OK")
        self.assertIn("OFF since 2026-11-25T08:00:12Z", r["summary"])

    def test_on_with_jobs_ok(self):
        self.assertEqual(self.result(self.run_doctor(Fake(loaded=["com.agent-harness.ops-watch"])), "switch")["status"],
                         "OK")

    def test_public_rescue_remote_fails(self):
        (self.home / ".agent-harness" / "local.json").write_text(
            json.dumps({"rescue_remote": "https://github.com/someone/rescue.git"}))
        fake = Fake(visibility="PUBLIC")
        r = self.result(self.run_doctor(fake), "rescue-remote")
        self.assertEqual(r["status"], "FAILED")
        self.assertIn(["/fake/gh", "repo", "view", "someone/rescue", "--json", "visibility", "--jq", ".visibility"],
                      fake.calls)
        self.assertEqual(self.result(self.run_doctor(Fake()), "rescue-remote")["status"], "OK")

    def test_no_rescue_remote_says_bundles(self):
        r = self.result(self.run_doctor(), "rescue-remote")
        self.assertEqual(r["status"], "OK")
        self.assertIn("bundle", r["summary"])

    def test_disk(self):
        report = ah_doctor.run(home=self.home, runner=Fake(), system="darwin", which=self.which,
                               disk_usage=lambda p: (100, 93, 7), managed_dir=self.managed, tmp_root=self.tmpdir,
                               roles=())
        self.assertEqual(self.result(report, "disk")["status"], "FAILED")

    def test_python_and_gh(self):
        self.assertEqual(self.result(self.run_doctor(Fake(python="3.8.10")), "python")["status"], "FAILED")
        with mock.patch.object(ah_doctor, "account_home", return_value=os.path.realpath(self.home)):
            self.assertEqual(self.result(self.run_doctor(Fake(gh_auth=1)), "gh")["status"], "FAILED")
        self.assertEqual(self.result(self.run_doctor(), "gh")["status"], "OK")

    def test_gh_in_a_temporary_home_on_macos_is_unproven_not_failed(self):
        """The keychain search follows $HOME, so gh cannot log in from a temporary home (plan 6.2 step 4)."""
        with mock.patch.object(ah_doctor, "account_home", return_value="/Users/someone-else"):
            r = self.result(self.run_doctor(Fake(gh_auth=1)), "gh")
        self.assertEqual(r["status"], "UNPROVEN")
        self.assertIn("keychain", r["summary"])

    def test_each_launchd_label_is_checked_once(self):
        labels = ah_doctor._labels(ah_doctor.Ctx(self.home, Fake(), "darwin", self.which, None, None, None, 0, {}))
        self.assertEqual(len(labels), len(set(labels)), labels)
        fake = Fake()
        self.run_doctor(fake, roles=())
        prints = [c[-1] for c in fake.calls if os.path.basename(c[0]) == "launchctl"]
        self.assertEqual(len(prints), len(set(prints)), prints)

    def test_credential_shaped_files_outside_the_deny_list_are_listed(self):
        (self.home / ".config" / "acme").mkdir(parents=True)
        (self.home / ".config" / "acme" / "api-token").write_text("x")
        (self.home / ".config" / "billing.env").write_text("x")
        (self.home / ".config" / "goodqa").mkdir()
        (self.home / ".config" / "goodqa" / "user-token").write_text("x")   # denied: not listed
        (self.home / ".config" / "app.json").write_text("{}")             # not credential-shaped
        (self.home / ".vault-token").write_text("x")
        r = self.result(self.run_doctor(roles=()), "secrets-readable")
        self.assertEqual(r["status"], "FAILED")
        for name in ("~/.config/acme/api-token", "~/.config/billing.env", "~/.vault-token"):
            self.assertIn(name, r["detail"]["paths"])
        self.assertFalse([p for p in r["detail"]["paths"] if "goodqa" in p or "app.json" in p], r["detail"]["paths"])
        (self.home / ".agent-harness" / "local.json").write_text(json.dumps(
            {"sandbox_extra_deny_read": ["~/.config/acme", "~/.config/billing.env", "~/.vault-token"]}))
        self.assertEqual(self.result(self.run_doctor(roles=()), "secrets-readable")["status"], "OK")

    def test_active_repositories_without_the_merge_rule_fail(self):
        now = ah_doctor.parse_iso("2026-11-26T00:00:00Z")
        repos = [{"nameWithOwner": "o/active", "pushedAt": "2026-11-20T00:00:00Z", "viewerPermission": "ADMIN"},
                 {"nameWithOwner": "o/guarded", "pushedAt": "2026-11-25T00:00:00Z", "viewerPermission": "ADMIN"},
                 {"nameWithOwner": "o/old", "pushedAt": "2025-01-01T00:00:00Z", "viewerPermission": "ADMIN"},
                 {"nameWithOwner": "x/theirs", "pushedAt": "2026-11-25T00:00:00Z", "viewerPermission": "WRITE"}]
        fake = Fake(repos=repos, rulesets={"o/guarded": ["harness-merge-rule"], "o/active": ["other"]})
        r = self.result(self.run_doctor(fake, roles=(), now=now), "rulesets")
        self.assertEqual(r["status"], "FAILED")
        self.assertEqual(r["detail"]["missing"], ["o/active"])
        self.assertIn("ah repo protect o/active", r["summary"])
        fake = Fake(repos=repos, rulesets={"o/guarded": ["harness-merge-rule"], "o/active": ["harness-merge-rule"]})
        self.assertEqual(self.result(self.run_doctor(fake, roles=(), now=now), "rulesets")["status"], "OK")
        self.assertEqual(self.result(self.run_doctor(Fake(), roles=(), now=now), "rulesets")["status"], "UNPROVEN")

    def test_backup(self):
        r = self.result(self.run_doctor(), "backup")
        self.assertEqual(r["status"], "UNPROVEN")
        (self.home / ".agent-harness" / "logs" / "log-backup.last-ok").write_text("2026-11-20T00:00:00Z\n")
        r = self.result(self.run_doctor(now=ah_doctor.parse_iso("2026-11-25T00:00:00Z")), "backup")
        self.assertEqual(r["status"], "FAILED")
        r = self.result(self.run_doctor(now=ah_doctor.parse_iso("2026-11-20T03:00:00Z")), "backup")
        self.assertEqual(r["status"], "OK")

    def test_shim(self):
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        shim = bin_dir / "harness"
        shim.write_text("#!/bin/sh\n# agent-harness switch shim\n")
        which = lambda n: str(shim) if n == "harness" else self.which(n)  # noqa: E731
        report = ah_doctor.run(home=self.home, runner=Fake(), system="darwin", which=which,
                               disk_usage=lambda p: (100, 5, 95), managed_dir=self.managed, tmp_root=self.tmpdir,
                               roles=())
        self.assertEqual(self.result(report, "shim")["status"], "OK")
        shim.write_text("#!/bin/sh\nexec go-harness \"$@\"\n")
        report = ah_doctor.run(home=self.home, runner=Fake(), system="darwin", which=which,
                               disk_usage=lambda p: (100, 5, 95), managed_dir=self.managed, tmp_root=self.tmpdir,
                               roles=())
        self.assertEqual(self.result(report, "shim")["status"], "FAILED")

    def test_managed_dropin(self):
        self.assertEqual(self.result(self.run_doctor(), "managed")["status"], "OK")
        target = self.managed / "managed-settings.d" / "50-agent-harness.json"
        target.parent.mkdir(parents=True)
        target.write_text(ah_sandbox.render_claude(ah_sandbox.managed_settings("worker", home=self.home)))
        self.assertEqual(self.result(self.run_doctor(), "managed")["status"], "OK")
        target.write_text(ah_sandbox.render_claude(ah_sandbox.managed_settings("reviewer", home=self.home)))
        self.assertEqual(self.result(self.run_doctor(), "managed")["status"], "FAILED")

    def test_sandbox_files(self):
        path = ah_sandbox.installed_path(self.home, "worker")
        path.parent.mkdir(parents=True)
        path.write_text(ah_sandbox.render_claude(ah_sandbox.claude_settings("worker", home=self.home)))
        self.assertEqual(self.result(self.run_doctor(), "sandbox-files")["status"], "OK")
        path.write_text("{}\n")
        self.assertEqual(self.result(self.run_doctor(), "sandbox-files")["status"], "FAILED")

    def test_codex_trust(self):
        codex = self.home / ".codex"
        (codex / "agent-harness").mkdir(parents=True)
        (codex / "agent-harness" / "ah_hook.py").write_text("")
        (codex / "agent-harness" / "wal.py").write_text("")
        handler = {"type": "command", "timeout": 10,
                   "command": f"python3 {codex / 'agent-harness' / 'ah_hook.py'} wal.py hook"}
        hooks_json = codex / "hooks.json"
        hooks_json.write_text(json.dumps({"hooks": {"SessionStart": [{"hooks": [handler]}]}}))
        r = self.result(self.run_doctor(), "codex-trust")
        self.assertEqual(r["status"], "UNPROVEN")
        self.assertIn("/hooks", r["summary"])
        digest = ah_doctor.codex_trust_hash("SessionStart", handler)
        (codex / "config.toml").write_text(f'[hooks.state."{hooks_json}:session_start:0:0"]\n'
                                           f'trusted_hash = "{digest}"\n')
        self.assertEqual(self.result(self.run_doctor(), "codex-trust")["status"], "OK")

    def test_codex_trust_hash_formula(self):
        """The p2 2.3 formula: sha256 of compact, key-sorted {event_name, hooks: [{type, command, timeout, async}]}."""
        handler = {"type": "command", "command": "python3 /x/wal.py hook", "timeout": 10}
        body = '{"event_name":"user_prompt_submit","hooks":[{"async":false,"command":"python3 /x/wal.py hook",' \
               '"timeout":10,"type":"command"}]}'
        import hashlib
        self.assertEqual(ah_doctor.codex_trust_hash("UserPromptSubmit", handler),
                         "sha256:" + hashlib.sha256(body.encode()).hexdigest())

    def test_never_runs_a_hook_script(self):
        self.write_settings({"Stop": [{"hooks": [self.handler("wal.py")]}]})
        fake = Fake()
        self.run_doctor(fake, roles=ah_sandbox.ROLES)
        for call in fake.calls:
            self.assertFalse(any(str(a).endswith(("ah_hook.py", "wal.py")) for a in call), call)


class Cli(Base):
    def test_json_schema(self):
        self.secret()
        code, out, _ = self.cli(["--json"])
        data = json.loads(out)
        self.assertEqual(data["schema"], "ah-doctor/1")
        self.assertEqual(data["exit"], code)
        self.assertEqual(set(data["counts"]) - set(ah_doctor.STATUSES), set())
        for r in data["results"]:
            self.assertEqual(set(r), {"id", "status", "summary", "detail"})
            self.assertIn(r["status"], ah_doctor.STATUSES)

    def test_exit_0_and_strict(self):
        self.secret()
        code, out, _ = self.cli([])
        self.assertEqual(code, 0, out)
        self.assertIn("PROVEN", out)
        code, _, _ = self.cli(["--strict"])
        self.assertEqual(code, 1)   # UNPROVEN rows (backup not installed, shim not on PATH) count under --strict

    def test_exit_1_on_failed(self):
        self.secret()
        code, out, _ = self.cli([], runner=Fake("leak"))
        self.assertEqual(code, 1)
        self.assertIn("FAILED", out)

    def test_exit_2_on_unreadable_config(self):
        (self.home / ".agent-harness" / "local.json").write_text("{broken")
        code, out, _ = self.cli([])
        self.assertEqual(code, 2)
        (self.home / ".agent-harness" / "local.json").write_text("{}")
        (self.home / ".claude").mkdir()
        (self.home / ".claude" / "settings.json").write_text("[1,")
        code, _, _ = self.cli(["--json"])
        self.assertEqual(code, 2)

    def test_bad_role(self):
        code, _, err = self.cli(["--role", "owner"])
        self.assertEqual(code, 2)

    def test_no_probes_runs_the_checks_and_creates_nothing(self):
        """For a real host: no probe file in ~/.agent-harness/work or $HOME, and no sandbox run at all."""
        self.secret()
        before = sorted(str(p) for p in self.home.rglob("*"))
        for argv in (["--no-probes", "--json"], ["--role", "none", "--json"]):
            fake = Fake()
            code, out, _ = self.cli(argv, runner=fake)
            ids = [r["id"] for r in json.loads(out)["results"]]
            self.assertIn("switch", ids)
            self.assertFalse([i for i in ids if i.startswith(("probe.", "codex."))], ids)
            self.assertFalse([c for c in fake.calls if os.path.basename(c[0]) in ("sandbox-exec", "bwrap")])
        self.assertEqual(sorted(str(p) for p in self.home.rglob("*")), before)
        self.assertEqual(self.cli(["--no-probes", "--codex"])[0], 2)


if __name__ == "__main__":
    unittest.main()
