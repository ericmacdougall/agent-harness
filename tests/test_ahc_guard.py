"""AC-13 launch guard (goodqa#16049 slice 1 (b), spec r9): NoModelInDaemonTests.

Every allowed executable resolves, through the test constructor only, to a stub that appends its argv to a sentinel
file when it runs, so a refused launch is visible as "LaunchRefused and no sentinel" and an allowed one as "the
sentinel appears". Runs on the Mac and t2-dev without systemd. Each refusal helper turns any other exception into a
test failure, so a variant that breaks a rule fails with an assertion, never an error.
"""
import ast
import hashlib
import os
import socket
import subprocess
import sys
import tempfile
import textwrap
import threading
import unittest
from pathlib import Path
from unittest import mock

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import ahc_clone  # noqa: E402
import ahc_core  # noqa: E402
import ahc_guard as guard  # noqa: E402

A, B = "a" * 40, "b" * 40
RANGE = "%s..%s" % (B, A)


class _GuardFixture(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(os.path.realpath(self.tmp.name))
        self.root, self.stubs, self.marks = base / "root", base / "bin", base / "marks"
        for d in (self.root / "clones" / "o__r", self.stubs, self.marks):
            d.mkdir(parents=True)
        os.chmod(str(base), 0o700)
        paths = {}
        for name in guard.EXECUTABLES + ("curl",):
            p = self.stubs / name
            p.write_text("#!/bin/sh\necho \"$@\" >> %s\n" % (self.marks / name))
            os.chmod(str(p), 0o755)
            paths[name] = str(p)
        self.curl = paths["curl"]     # an unlisted executable: stubbed, trusted, but not in EXECUTABLES
        self.helper = base / "helpers" / "ah.py"
        self.helper.parent.mkdir()
        self.helper.write_text("import sys\nopen(%r, 'a').write(' '.join(sys.argv[1:]) + '\\n')\n"
                               % str(self.marks / "helper"))
        os.chmod(str(self.helper), 0o644)
        self.policy = guard.Policy.for_test(self.root, paths, repos=["o/r"], trusted_dirs=(str(self.stubs),),
                                            helpers={"ah": str(self.helper)})
        guard.install(self.policy)
        self.addCleanup(guard.deactivate)

    # ------------------------------------------------------------------ helpers

    def mark(self, name):
        return (self.marks / name).exists()

    def clear(self):
        for p in self.marks.iterdir():
            p.unlink()

    def launch(self, argv, env="form", cwd=None, name="git"):
        env = self.policy.env(name) if env == "form" else env
        return ahc_core.run_argv(argv, 20, cwd=str(self.root if cwd is None else cwd), env=env)

    def allowed(self, name, argv, **kw):
        self.clear()
        try:
            rc, _out, err = self.launch(argv, name=name, **kw)
        except guard.LaunchRefused as error:
            self.fail("allowed form refused: %s" % error)
        self.assertEqual(rc, 0, err)
        self.assertTrue(self.mark(name), "the allowed form's stub did not run")

    def refused(self, name, fn):
        self.clear()
        try:
            fn()
        except guard.LaunchRefused:
            pass
        except Exception as error:  # noqa: BLE001 -- a variant must fail with an assertion, not an error
            self.fail("expected LaunchRefused, got %s: %s" % (type(error).__name__, error))
        else:
            self.fail("launch was not refused")
        self.assertFalse(self.mark(name), "a refused launch left a sentinel")

    def refuse_argv(self, mark, argv, **kw):
        kw.setdefault("name", mark if mark in self.policy.exe else "git")
        self.refused(mark, lambda: self.launch(argv, **kw))

    def git(self, *args):
        return [self.policy.exe["git"]] + self.policy.git_prefix() + list(args)

    def gh(self, *args):
        return [self.policy.exe["gh"]] + list(args)

    def ctl(self, *args):
        return [self.policy.exe["systemctl"], "--user"] + list(args)


class NoModelInDaemonTests(_GuardFixture):

    # ------------------------------------------------------------------ positive controls

    def test_positive_control_per_executable(self):
        clone = str(self.root / "clones" / "o__r")
        self.allowed("git", self.git("-C", clone, "log", "--format=%H%x09%s", RANGE))
        rc, _o, _e = guard.run(self.policy, "git", self.policy.git_prefix() + ["-C", clone, "rev-parse", "HEAD"], 20)
        self.assertEqual(rc, 0)
        self.allowed("gh", self.gh("pr", "view", "5", "-R", "o/r", "--json", "number,state,headRefOid"))
        self.allowed("gh", self.gh("api", "--method", "GET", "-H", guard.GH_HEADERS[0], "repos/o/r/pulls/5"))
        self.allowed("gh", self.gh("api", "--paginate", "repos/o/r/commits/%s/check-runs?per_page=100" % A))
        self.allowed("systemctl", self.ctl("show", "-p", "ActiveState,SubState", "ahc-core.service"))
        self.allowed("systemctl", self.ctl("list-units", "--plain", "--no-legend", "--all", "ahc-review-*"))
        self.policy.migrating = True
        self.allowed("lsof", [self.policy.exe["lsof"], "-w", "-F", "p", "--", str(self.root / "ledger.sqlite3")])
        self.allowed("fuser", [self.policy.exe["fuser"], str(self.root / "ledger.sqlite3-wal")])
        if sys.platform == "darwin":
            self.allowed("sysctl", [self.policy.exe["sysctl"], "-n", "kern.bootsessionuuid"])
        else:
            self.refuse_argv("sysctl", [self.policy.exe["sysctl"], "-n", "kern.bootsessionuuid"], name="sysctl")
        self.clear()
        rc, _o, err = guard.run_helper(self.policy, "ah", ["ticket", "comment", "1", "--body", "x"], 20)
        self.assertEqual(rc, 0, err)
        self.assertTrue(self.mark("helper"))

    # ------------------------------------------------------------------ NEG-44 git

    def test_neg44_git_forms_outside_the_table_are_refused(self):
        clone = str(self.root / "clones" / "o__r")
        stub = self.curl
        cases = {
            "alias -c": self.git("-c", "alias.x=!%s" % stub, "x"),
            "planted alias": self.git("-C", clone, "myalias"),
            "core.pager": self.git("-c", "core.pager=%s" % stub, "log", RANGE),
            "sshCommand": self.git("-c", "core.sshCommand=%s" % stub, "fetch", "--quiet", "origin", A),
            "exec-path": self.git("--exec-path=%s" % self.stubs, "log", RANGE),
            "ext url": self.git("clone", "--quiet", "--no-checkout", "--template=", "--", "ext::%s" % stub,
                                str(self.root / "clones" / "x__y")),
            "upload-pack": self.git("fetch", "--upload-pack=%s" % stub, "origin", A),
            "config after clone": self.git("clone", "--config", "alias.x=!%s" % stub, "https://github.com/o/r.git",
                                           str(self.root / "clones" / "x__y")),
            "no SAFE prefix": [self.policy.exe["git"], "log", RANGE],
            "other repo url": self.git("clone", "--quiet", "--no-checkout", "--template=", "--",
                                       "https://github.com/evil/r.git", str(self.root / "clones" / "e__r")),
            "push": self.git("-C", clone, "push", "origin", A),
            "-C outside clones": self.git("-C", str(self.root), "log", RANGE),
        }
        for label, argv in cases.items():
            with self.subTest(label):
                self.refuse_argv("git", argv)

    def test_neg44_git_with_added_env_keys_is_refused(self):
        argv = self.git("log", "--format=%H%x09%s", RANGE)
        for extra in ({"GIT_SSH_COMMAND": "x"}, {"GIT_EXEC_PATH": str(self.stubs)},
                      {"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "core.pager", "GIT_CONFIG_VALUE_0": "x"}):
            with self.subTest(sorted(extra)):
                self.refuse_argv("git", argv, env={**self.policy.env("git"), **extra})

    # ------------------------------------------------------------------ NEG-45 gh

    def test_neg45_gh_forms_outside_the_table_are_refused(self):
        cases = {
            "extension name": self.gh("my-ext"),
            "extension exec": self.gh("extension", "exec", "my-ext"),
            "alias set": self.gh("alias", "set", "x", "api"),
            "graphql": self.gh("api", "graphql", "-f", "query=x"),
            "implied POST": self.gh("api", "repos/o/r/issues/1/comments", "-f", "body=x"),
            "method POST": self.gh("api", "--method", "POST", "repos/o/r/pulls/5"),
            "input": self.gh("api", "--input", str(self.helper), "repos/o/r/pulls/5"),
            "hostname": self.gh("api", "--hostname", "example.invalid", "repos/o/r/pulls/5"),
            "unlisted endpoint": self.gh("api", "repos/o/r/issues"),
            "unlisted repo": self.gh("api", "repos/evil/r/pulls/5"),
            "jq": self.gh("api", "--jq", ".x", "repos/o/r/pulls/5"),
            "paginate a single read": self.gh("api", "--paginate", "repos/o/r/pulls/5"),
            "pr view other field": self.gh("pr", "view", "5", "-R", "o/r", "--json", "number,comments"),
        }
        for label, argv in cases.items():
            with self.subTest(label):
                self.refuse_argv("gh", argv, name="gh")

    def test_neg45_w21_put_needs_the_flag_and_the_armed_expectation(self):
        put = self.gh("api", "--method", "PUT", "repos/o/r/pulls/5/update-branch", "-f", "expected_head_sha=" + A)
        import ahc_w21  # noqa: PLC0415
        self.assertEqual(put, self.gh(*ahc_w21.put_args("o/r", 5, A)), "the sender's PUT is the guard's one form")
        with mock.patch.dict(os.environ, {"AHC_W21_SEND": "0"}):
            self.policy.arm_w21(put)
            self.refuse_argv("gh", put, name="gh")
        with mock.patch.dict(os.environ, {"AHC_W21_SEND": "1"}):
            self.refuse_argv("gh", put, name="gh")                       # nothing armed
            self.policy.arm_w21(put[:-1] + ["expected_head_sha=" + B])
            self.refuse_argv("gh", put, name="gh")                       # a different sha
            self.policy.arm_w21(put)
            self.allowed("gh", put)                                      # positive control, consumed
            self.refuse_argv("gh", put, name="gh")

    # ------------------------------------------------------------------ NEG-46 units

    def unit_argv(self, *extra):
        return [self.policy.exe["systemd-run"], "--user", "--unit=ahc-review-r1-i1.service",
                "--slice=" + guard.REVIEW_SLICE, "-p", "RuntimeMaxSec=900", *extra, "--", "/usr/bin/true"]

    def test_neg46_systemd_run_only_the_armed_committed_command_line(self):
        a = self.unit_argv()
        self.refuse_argv("systemd-run", a, name="systemd-run")                     # nothing armed
        for label, other in {"payload": a[:-1] + [self.curl],
                             "ExecStartPre": self.unit_argv("-p", "ExecStartPre=" + self.curl),
                             "setenv": self.unit_argv("--setenv=X=1")}.items():
            with self.subTest(label):
                self.policy.arm_unit(a, guard.argv_digest(a))
                self.refuse_argv("systemd-run", other, name="systemd-run")
        self.policy.arm_unit(a, guard.argv_digest(a))
        self.allowed("systemd-run", a)
        self.refuse_argv("systemd-run", a, name="systemd-run")                     # consumed
        with self.assertRaises(guard.LaunchRefused):
            self.policy.arm_unit(a, guard.argv_digest(self.unit_argv("--setenv=X=1")))

    def test_neg46_systemctl_verbs_outside_the_table_are_refused(self):
        self.policy.intent_units.add("ahc-review-r1-i1.service")
        cases = {"start": self.ctl("start", "ahc-review-r1-i1.service"),
                 "stop role unit": self.ctl("stop", "ahc-core.service"),
                 "set-environment": self.ctl("set-environment", "X=1"),
                 "edit": self.ctl("edit", "ahc-review-r1-i1.service"),
                 "host": [self.policy.exe["systemctl"], "--user", "-H", "h", "show", "-p", "ActiveState",
                          "ahc-core.service"],
                 "no scope": [self.policy.exe["systemctl"], "show", "-p", "ActiveState", "ahc-core.service"],
                 "late recovery stop": self.ctl("stop", "ahc-review-r9-orphan.service")}
        for label, argv in cases.items():
            with self.subTest(label):
                self.refuse_argv("systemctl", argv, name="systemctl")
        self.allowed("systemctl", self.ctl("stop", "ahc-review-r1-i1.service"))

    def test_recovery_stop_needs_reconciliation_and_the_review_slice(self):
        orphan = "ahc-review-r9-orphan.service"
        self.policy.reconciling = True
        self.allowed("systemctl", self.ctl("show", "-p", "Slice,ActiveState,SubState", orphan))
        self.refuse_argv("systemctl", self.ctl("stop", orphan), name="systemctl")   # Slice not confirmed
        self.policy.slice_ok.add(orphan)
        self.allowed("systemctl", self.ctl("stop", orphan))
        self.refuse_argv("systemctl", self.ctl("stop", "ahc-review.service"), name="systemctl")
        self.policy.reconciling = False
        self.refuse_argv("systemctl", self.ctl("stop", orphan), name="systemctl")

    # ------------------------------------------------------------------ NEG-47 resolution

    def test_neg47_resolution_env_and_shell_are_refused(self):
        log = ["log", "--format=%H%x09%s", RANGE]
        self.refuse_argv("git", ["git"] + self.policy.git_prefix() + log)            # bare name, stub on PATH
        self.refuse_argv("git", [self.curl] + self.policy.git_prefix() + log)
        self.refuse_argv("git", self.git(*log), env=None)                            # inherited
        self.refuse_argv("git", self.git(*log), cwd="/")                             # cwd outside the root
        self.refused("curl", lambda: subprocess.run("%s x" % self.curl, shell=True,
                                                    env=self.policy.env("git"), cwd=str(self.root)))
        self.refused("curl", lambda: os.system(self.curl))

    def test_neg47_unlisted_executable_is_refused(self):
        base = {"PATH": self.policy.path_env, "HOME": self.policy.home, "LC_ALL": "C"}   # a plain form's env
        self.refuse_argv("curl", [self.curl, "https://example.invalid"], env=base)

    def test_neg47_group_writable_after_start_is_refused(self):
        os.chmod(self.policy.exe["git"], 0o775)
        self.refuse_argv("git", self.git("log", "--format=%H%x09%s", RANGE))

    def test_neg47_python_only_as_a_bound_unchanged_helper(self):
        py, env = self.policy.python, dict(self.policy.helper_env)
        other = self.helper.parent / "other.py"
        other.write_text(self.helper.read_text())
        self.refuse_argv("helper", [py, "-c", "open(%r,'a')" % str(self.marks / "helper")], env=env)
        self.refuse_argv("helper", [py, str(other), "ticket", "comment"], env=env)   # a config path, not installed
        self.refuse_argv("helper", [py, str(self.helper), "pr", "x"], env=env)       # outside its pattern
        self.refuse_argv("helper", [py, str(self.helper), "ticket", "comment"],
                         env={**env, "ANTHROPIC_API_KEY": "x"})
        self.helper.write_text(self.helper.read_text() + "# changed\n")
        self.refuse_argv("helper", [py, str(self.helper), "ticket", "comment"], env=env)

    # ------------------------------------------------------------------ NEG-48 sockets

    def test_neg48_sockets_only_unix_paths_under_the_root(self):
        guard.deactivate()
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        server.settimeout(0.5)
        self.addCleanup(server.close)
        upath = str(self.root / "r.sock")
        userver = socket.socket(socket.AF_UNIX)
        userver.bind(upath)
        userver.listen(1)
        self.addCleanup(userver.close)
        outside = tempfile.mkdtemp(dir=str(self.root.parent))
        opath = os.path.join(outside, "o.sock")
        oserver = socket.socket(socket.AF_UNIX)
        oserver.bind(opath)
        oserver.listen(1)
        self.addCleanup(oserver.close)
        guard.install(self.policy)
        port = server.getsockname()[1]
        for label, fn in {"tcp connect": lambda: socket.socket().connect(("127.0.0.1", port)),
                          "create_connection": lambda: socket.create_connection(("localhost", port), 1),
                          "getaddrinfo": lambda: socket.getaddrinfo("example.invalid", 443),
                          "unix outside the root": lambda: socket.socket(socket.AF_UNIX).connect(opath)}.items():
            with self.subTest(label):
                self.refused("none", fn)
        try:
            conn, _ = server.accept()
            conn.close()
            self.fail("the TCP server recorded a connection")
        except socket.timeout:
            pass
        client = socket.socket(socket.AF_UNIX)
        self.addCleanup(client.close)
        client.connect(upath)                                     # positive control: the review socket

    # ------------------------------------------------------------------ NEG-30 imports, static

    def test_neg30_runtime_provider_import_is_refused_in_a_child(self):
        pkg = self.root.parent / "fakesdk"
        (pkg / "anthropic").mkdir(parents=True)
        (pkg / "anthropic" / "__init__.py").write_text("def call():\n    return 'called'\n")
        script = self.root.parent / "child.py"
        script.write_text(textwrap.dedent("""
            import importlib, sys
            sys.path[:0] = [sys.argv[1], sys.argv[2]]
            import ahc_guard
            ahc_guard.install(ahc_guard.Policy(sys.argv[3], repos=[]))
            try:
                print(importlib.import_module("anthropic").call())
            except ahc_guard.LaunchRefused as error:
                print("REFUSED", error)
        """))
        guard.deactivate()
        out = subprocess.run([sys.executable, "-I", str(script), str(HOOKS), str(pkg), str(self.root)],
                             capture_output=True, text=True, timeout=60)
        self.assertIn("REFUSED", out.stdout, out.stderr)
        self.assertNotIn("called", out.stdout)

    def test_static_daemon_modules_import_no_provider_or_http_client(self):
        sys.path.insert(0, str(HOOKS.parents[1]))
        import install  # noqa: PLC0415
        banned = guard.PROVIDER_MODULES + guard.HTTP_MODULES
        hosts = ("api.anthropic.com", "api.openai.com", "generativelanguage.googleapis.com", "api.mistral.ai",
                 "api.cohere.")
        names = sorted(n for n in install.HOOKS if n.startswith("ahc_") and n.endswith(".py"))
        self.assertIn("ahc_guard.py", names)
        for name in names:
            text = (HOOKS / name).read_text(encoding="utf-8")
            for node in ast.walk(ast.parse(text)):
                mods = []
                if isinstance(node, ast.Import):
                    mods = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module:
                    mods = [node.module] + ["%s.%s" % (node.module, a.name) for a in node.names]
                for mod in mods:
                    self.assertFalse(any(mod == b or mod.startswith(b + ".") for b in banned), (name, mod))
            for host in hosts:
                self.assertNotIn(host, text, name)


class LegacyProductionPathTests(_GuardFixture):
    """NEG-44 and NEG-47 through the production dependency path (LiveDeps), under the enforcing policy."""

    def deps(self, **config):
        import ahc_runner  # noqa: PLC0415
        from types import SimpleNamespace  # noqa: PLC0415
        paths = SimpleNamespace(root=self.root, home=Path(self.policy.home))
        return ahc_runner.LiveDeps(paths, {"repos": ["o/r"], **config}, policy=self.policy)

    def test_legacy_commits_runs_in_the_git_form(self):
        self.clear()
        clone = str(self.root / "clones" / "o__r")
        rc, _o, err = 0, "", ""
        try:
            self.deps().commits(clone, B, A)
        except RuntimeError as error:            # the stub prints nothing; an empty log is fine, a refusal is not
            self.assertNotIsInstance(error, guard.LaunchRefused)
            err = str(error)
        self.assertTrue(self.mark("git"), err)
        line = (self.marks / "git").read_text()
        self.assertTrue(line.startswith(" ".join(ahc_clone.SAFE)), line)
        self.assertIn("-C %s log --format=%%H%%x09%%s %s" % (clone, RANGE), line)

    def test_legacy_helper_from_config_must_be_the_installed_one(self):
        other = self.helper.parent / "other.py"
        other.write_text(self.helper.read_text())
        self.clear()
        rc, _o, err = self.deps(ah=str(other)).ah(["ah", "ticket", "comment", "1", "--body", "x"], 20)
        self.assertEqual(rc, 126, err)
        self.assertIn("LaunchRefused", err)
        self.assertFalse(self.mark("helper"))
        rc, _o, err = self.deps(ah=str(self.helper)).ah(["ah", "ticket", "comment", "1", "--body", "x"], 20)
        self.assertEqual(rc, 0, err)
        self.assertTrue(self.mark("helper"))

    def test_legacy_gh_readback_runs_in_the_gh_form(self):
        self.clear()
        rc, _o, err = self.deps().gh(["gh", "pr", "view", "5", "-R", "o/r", "--json", "state"], 20)
        self.assertEqual(rc, 0, err)
        self.assertTrue(self.mark("gh"))
        rc, _o, err = self.deps().gh(["gh", "api", "--method", "POST", "repos/o/r/pulls/5"], 20)
        self.assertEqual(rc, 126, err)


class GuardPolicyUnitTests(unittest.TestCase):
    def test_read_templates_fill_only_whole_endpoints(self):
        self.assertEqual(guard.template_of("repos/o/r/pulls/5")[0], "pull")
        self.assertEqual(guard.template_of("repos/o/r/commits/%s/statuses" % A)[0], "statuses")
        for bad in ("repos/o/r/pulls/5/merge", "repos/o/r/pulls/5?x=1", "graphql", "repos/o/r/commits/abc"):
            self.assertEqual(guard.template_of(bad), (None, None), bad)

    def test_argv_digest_is_the_canonical_encoding(self):
        self.assertEqual(guard.argv_digest(["a", "b"]),
                         hashlib.sha256(b'["a","b"]').hexdigest())

    def test_safe_prefix_is_ahc_clone_s(self):
        p = guard.Policy.for_test("/nonexistent-root", {})
        self.assertEqual(p.git_prefix(), ahc_clone.SAFE)


if __name__ == "__main__":
    unittest.main()
