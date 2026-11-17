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
import sqlite3
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
import ahc_contracts as C  # noqa: E402
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

    def test_helper_sha_binds_to_the_release_list_not_the_file_at_start(self):
        """Owner ruling (e): the helper's expected sha256 is the release list's. A helper whose file differs from its
        release entry is refused even when it has not changed since the daemon started; a helper with no entry, or
        an unreadable list, binds nothing."""
        import hashlib  # noqa: PLC0415
        py, env = self.policy.python, dict(self.policy.helper_env)
        good = hashlib.sha256(self.helper.read_bytes()).hexdigest()
        stubs = {n: p for n, p in self.policy.exe.items()}
        for name, release in (("other sha", {"ah": "0" * 64}), ("no entry", {}), ("malformed", {"ah": "x"})):
            with self.subTest(name):
                p = guard.Policy.for_test(self.root, stubs, repos=["o/r"], trusted_dirs=(str(self.stubs),),
                                          helpers={"ah": str(self.helper)}, release=release)
                with self.assertRaises(guard.LaunchRefused):
                    p.check_launch(py, [py, str(self.helper), "ticket", "comment"], str(self.root), env)
        p = guard.Policy.for_test(self.root, stubs, repos=["o/r"], trusted_dirs=(str(self.stubs),),
                                  helpers={"ah": str(self.helper)}, release={"ah": good})
        self.assertEqual(p.check_launch(py, [py, str(self.helper), "ticket", "comment"], str(self.root), env), "ah")
        missing = Path(self.root) / "no-release.json"
        self.assertEqual(guard.release_helpers(missing), {})

    def test_the_shipped_release_list_binds_each_helper_to_its_repo_file(self):
        import hashlib  # noqa: PLC0415
        bound = guard.release_helpers()
        self.assertEqual(set(bound), set(guard.HELPER_SCRIPTS))
        for name, script in guard.HELPER_SCRIPTS.items():
            self.assertEqual(bound[name], hashlib.sha256((HOOKS / script).read_bytes()).hexdigest(), name)
        import importlib.util  # noqa: PLC0415
        spec = importlib.util.spec_from_file_location("ahc_release_hashes",
                                                      str(HOOKS.parents[1] / "scripts" / "ahc_release_hashes.py"))
        script = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(script)
        self.assertEqual(script.helpers(), bound, "the generator writes the same helpers section")
        self.assertEqual(script.main([]), 0, "the shipped list is current")

    def test_r247_f4_helper_drift_fails_the_check_and_ci_runs_it_before_the_tests(self):
        """PR 247 receipt F4: a helper changed without regenerating the list fails `--check` with the fix named, and
        CI runs that check as its own step, so the drift is caught at merge time, not by a refused launch."""
        import contextlib  # noqa: PLC0415
        import importlib.util  # noqa: PLC0415
        import io  # noqa: PLC0415
        import json as _json  # noqa: PLC0415
        spec = importlib.util.spec_from_file_location("ahc_release_hashes_f4",
                                                      str(HOOKS.parents[1] / "scripts" / "ahc_release_hashes.py"))
        script = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(script)
        stale = Path(self.root) / "ahc_release.json"
        data = _json.loads(script.LIST.read_text())
        data["helpers"]["ah"] = "0" * 64                        # ah.py changed on main; the list was not rewritten
        stale.write_text(_json.dumps(data))
        script.LIST = stale
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = script.main(["--check"])
        self.assertEqual(rc, 1, out.getvalue())
        self.assertIn("stale (helpers): ['ah']", out.getvalue())
        self.assertIn("ahc_release_hashes.py --write", out.getvalue())
        ci = (HOOKS.parents[1] / ".github" / "workflows" / "ci.yml").read_text()
        step = "run: python3 -I scripts/ahc_release_hashes.py --check"
        self.assertIn(step, ci, "CI runs the release-list check")
        self.assertLess(ci.index(step), ci.index("python3 -m unittest discover"), "before the long test step")

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



class MigrateProbeTests(_GuardFixture):
    """AC-11 steps 2 and 4 under the installed guard: the open-file probe launches through the policy's lsof form
    with its cwd at the root, and only while ahc-core is migrating; Ledger opens that gate for the migration only."""

    def test_ac11_the_probe_runs_through_the_policy_form_at_the_root_only_while_migrating(self):
        import ahc_migrate  # noqa: PLC0415
        import ahc_runner  # noqa: PLC0415
        ledger = str(self.root / "ledger.sqlite3")
        tools = {"lsof": self.policy.exe["lsof"]}
        with self.assertRaises(ahc_migrate.ProbeError):
            ahc_migrate.open_file_holders([ledger], ahc_runner.Ledger.PROBE_RUN, tools=tools)
        self.assertFalse(self.mark("lsof"), "refused before launch when not migrating")
        self.policy.migrating = True
        try:
            held = ahc_migrate.open_file_holders([ledger], ahc_runner.Ledger.PROBE_RUN, tools=tools)
        except ahc_migrate.ProbeError as error:
            self.fail("the probe was refused while migrating: %s" % error)
        self.assertEqual(held, set())
        self.assertTrue(self.mark("lsof"), "lsof ran through the policy's form")

    def test_ac11_the_ledger_opens_the_migrating_gate_for_the_migration_only(self):
        import ahc_runner  # noqa: PLC0415
        seen = []
        led = ahc_runner.Ledger.__new__(ahc_runner.Ledger)
        led._migrate_to_v5 = lambda n: seen.append((n, self.policy.migrating))
        self.assertFalse(self.policy.migrating)
        led._migrate_guarded(4)
        self.assertEqual(seen, [(4, True)])
        self.assertFalse(self.policy.migrating, "closed again after the migration")
        led._migrate_to_v5 = lambda n: 1 / 0
        with self.assertRaises(ZeroDivisionError):
            led._migrate_guarded(4)
        self.assertFalse(self.policy.migrating, "closed again when the migration fails")


class OrphanRecoveryTests(_GuardFixture):
    """NEG-49 (AC-13, part of NEG-36's startup reconciliation), through the production launch guard: the R3 runner's
    systemctl calls run AC-13's forms against a stub that keeps per-unit state and writes a stop sentinel."""

    STUB = r'''#!%(python)s
import os, sys
state, marks = %(state)r, %(marks)r
args = sys.argv[1:]
if args[:1] == ["--user"]:
    args = args[1:]
def path(unit):
    return os.path.join(state, unit + ".show")
if args[:1] == ["list-units"]:
    sys.stdout.write(open(os.path.join(state, "list")).read())
elif args[:1] == ["show"]:
    sys.stdout.write(open(path(args[3])).read())
elif args[:1] == ["stop"]:
    open(os.path.join(marks, "stop-" + args[1]), "w").close()
    if not os.path.exists(os.path.join(state, args[1] + ".sticky")):
        lines = [l for l in open(path(args[1])).read().splitlines() if not l.startswith("ActiveState=")]
        open(path(args[1]), "w").write("\n".join(lines + ["ActiveState=inactive"]) + "\n")
'''

    def setUp(self):
        super().setUp()
        import ahc_review  # noqa: PLC0415
        from tests import test_ahc_contracts as TC  # noqa: PLC0415
        self.R, self.TC = ahc_review, TC
        self.state = Path(self.tmp.name) / "unitstate"
        self.state.mkdir()
        stub = self.stubs / "systemctl"
        stub.write_text(self.STUB % {"python": sys.executable, "state": str(self.state), "marks": str(self.marks)})
        os.chmod(str(stub), 0o755)
        self.db = sqlite3.connect(":memory:", isolation_level=None)
        C.apply_schema(self.db)
        self.clock = TC.Clock()
        self.c = C.Contracts(self.db, C.AuthorityLog(Path(self.tmp.name) / "authority.jsonl"), now=self.clock,
                             mono=self.clock, boot_id=TC.BOOT)
        self.rows = {}
        for name, pr in (("A", 1), ("B", 2), ("C", 3)):
            r = self.c.require_review("adversarial", "o/r", pr, TC.H1, TC.PKT, TC.POLICY, item="wi-%s" % name,
                                      event_id="req-" + name, snapshot_base=TC.BASE)
            self.rows[name] = self.c.review(r["id"], "queued", expected_version=r["version"], event_id="q-" + name)
        row = self.rows["A"]
        self.intent, self.argv = self.c.launch_intent(row["id"], row["version"], lambda unit: self.R.r3_command(
            self.policy, unit, row, helper_script=str(self.helper),
            attempt=self.R.attempt_paths(Path(self.tmp.name), unit, row, "/clone")))
        self.units = {"A": self.intent["unit"], "B": "ahc-review-%s-%s.service" % (self.rows["B"]["id"], "b" * 16),
                      "C": "ahc-review-%s-%s.service" % (self.rows["C"]["id"], "c" * 16)}
        slices = {"A": "ahc-review.slice", "B": "ahc-review.slice", "C": "user.slice"}
        for name, unit in self.units.items():
            (self.state / (unit + ".show")).write_text("Slice=%s\nActiveState=active\nSubState=running\n"
                                                       % slices[name])
        (self.state / "list").write_text("".join("%s loaded active running x\n" % u for u in
                                                 list(self.units.values()) + ["ahc-review.service"]))

    def reconcile(self):
        def advance(seconds):
            self.clock.t += seconds
        self.clear()
        return self.R.Reconciler(self.c, self.policy, self.R.SystemdRunner(self.policy), sleep=advance).run()

    def stopped(self, name):
        return self.mark("stop-" + self.units[name]) if name in self.units else self.mark("stop-" + name)

    def test_neg49_orphan_recovery_through_the_production_launch_guard(self):
        self.assertIn("--slice=ahc-review.slice", self.argv, "a real R3 intent carries the review slice")
        self.assertEqual(self.intent["cmd_sha256"], guard.argv_digest(self.argv))
        out = self.reconcile()
        self.assertTrue(self.stopped("A") and self.stopped("B"), "A and B are shown, then stopped")
        self.assertFalse(self.stopped("C"), "C's stop is refused before it runs: no sentinel")
        self.assertFalse(self.stopped("ahc-review.service"), "the role unit is never stopped")
        self.assertEqual(self.c._row("launch_intents", "id", self.intent["id"])["state"], "orphaned")
        self.assertTrue(any(self.units["B"] in i for i in out["incidents"]), "B raises an incident")
        self.assertTrue(any(self.units["C"] in i and "refused" in i for i in out["incidents"]), "C: refused, incident")
        self.assertEqual(out["blocked"], [self.rows["C"]["id"]], "only C's row is blocked")
        with self.assertRaisesRegex(C.ContractError, "blocked"):
            self.c.launch_intent(self.rows["C"]["id"], self.rows["C"]["version"], lambda u: [u])
        a = self.rows["A"]
        self.c.launch_intent(a["id"], a["version"], lambda u: [u])        # A confirmed inactive: A's row may launch
        self.clear()
        with self.assertRaises(guard.LaunchRefused):                      # after reconciliation: no recovery stop
            self.R.SystemdRunner(self.policy).stop(self.units["B"])
        self.assertFalse(self.stopped("B"), "the late stop left no sentinel")

    def test_neg49_a_unit_never_confirmed_inactive_blocks_its_row_after_60_s_and_nothing_else(self):
        (self.state / (self.units["B"] + ".sticky")).write_text("")
        start = self.clock.t
        out = self.reconcile()
        self.assertGreaterEqual(self.clock.t - start, self.R.STOP_BOUND, "the bound ran on the injected clock")
        self.assertEqual(sorted(out["blocked"]), sorted([self.rows["B"]["id"], self.rows["C"]["id"]]))
        self.assertEqual(self.c._row("launch_intents", "id", self.intent["id"])["state"], "orphaned")
        (self.state / (self.units["B"] + ".sticky")).unlink()
        (self.state / (self.units["B"] + ".show")).write_text("Slice=ahc-review.slice\nActiveState=inactive\n")
        lifted = self.reconcile()["lifted"]
        self.assertIn(self.rows["B"]["id"], lifted, "a later reconciliation lifts the block once B is inactive")



class Ac12KitTests(unittest.TestCase):
    """AC-12 run kit (scripts/ahc_ac12_live_gate.py), off-host parts: the probe unit carries the R3 template's
    RuntimeMaxSec and ReadWritePaths, its socket sits under the daemon root's sock/ as in production, a path a
    DynamicUser cannot traverse is reported as a kit/path finding before any unit starts, and a unit that never
    connects is reported as "kit: no connection within Ns", not as a peer-uid failure."""

    @classmethod
    def setUpClass(cls):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "ahc_ac12_live_gate", Path(__file__).resolve().parents[1] / "scripts" / "ahc_ac12_live_gate.py")
        cls.kit = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.kit)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(os.path.realpath(self.tmp.name))

    def test_ac12_plan_carries_runtime_bound_and_the_one_writable_path(self):
        cmd = self.kit.plan("system", "u.service", "/r/sock/k.sock", "/w/probe.cred", "/w/out", "/usr/bin/python3")
        self.assertIn("--property=DynamicUser=yes", cmd)
        self.assertIn("--property=ReadWritePaths=/w/out", cmd)
        self.assertTrue(any(c.startswith("--property=RuntimeMaxSec=") for c in cmd))
        doc = self.kit.__doc__
        for prop in ("RuntimeMaxSec", "ReadWritePaths", "DynamicUser", "RemainAfterExit"):
            self.assertIn(prop, doc)

    def test_ac12_socket_is_under_the_daemon_roots_sock_dir(self):
        root = self.base / "ahc"
        self.assertEqual(Path(self.kit.socket_path(root, "abc")).parent, root / "sock")

    def test_ac12_a_dir_others_cannot_traverse_is_a_kit_path_finding(self):
        root = self.base / "home" / ".agent-harness" / "ahc"
        (root / "sock").mkdir(parents=True)
        for d in (self.base, self.base / "home", self.base / "home" / ".agent-harness", root, root / "sock"):
            os.chmod(d, 0o711)
        self.assertEqual(self.kit.untraversable(root / "sock" / "k.sock", below=self.base.parent), [])
        os.chmod(root, 0o700)
        blocked = self.kit.untraversable(root / "sock" / "k.sock", below=self.base.parent)
        self.assertEqual(blocked, [str(root)])

    def test_ac12_no_connection_is_reported_as_a_kit_timeout(self):
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(srv.close)
        srv.bind(str(self.base / "k.sock"))
        srv.listen(1)
        with self.assertRaises(self.kit.KitTimeout) as cm:
            self.kit.accept_within(srv, 0.05)
        self.assertIn("kit: no connection within", str(cm.exception))

if __name__ == "__main__":
    unittest.main()
