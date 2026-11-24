"""scripts/update_installed.py: the user-run updater (goodqa#16947, PR 336 review F1-F7). Hermetic: a local bare
repository stands in for the canonical URL, a temp home for ~, and a fake runner for `ah install-files` and doctor.
install.py itself runs for real (a small fixture installer) where the isolation of that step is under test."""
import io
import json
import os
import py_compile
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "harness" / "hooks"))
import update_installed as U  # noqa: E402

GIT = ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "init.defaultBranch=main",
       "-c", "commit.gpgsign=false"]
CLEAN_ENV = {k: v for k, v in os.environ.items() if k not in U.AGENT_MARKERS}

INSTALL_PY = ("import json, os, sys\n"
              "AGENTS = ('x.md',)\nHOOKS = %r\nTOOLS = ()\nSKILLS = ()\n"
              "if __name__ == '__main__':\n"
              "    home = sys.argv[sys.argv.index('--home') + 1]\n"
              "    for folder in ('hooks', 'agents'):\n"
              "        src = os.path.join('harness', folder)\n"
              "        for f in os.listdir(src):\n"
              "            with open(os.path.join(src, f), 'rb') as a, open(os.path.join(home, '.claude', folder, f), 'wb') as b:\n"
              "                b.write(a.read())\n")


def sh(cwd, *args):
    return subprocess.run(GIT + list(args), cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


class Fixture(unittest.TestCase):
    HOOKS = ("a.py", "b.py", "c.py")

    def setUp(self):
        self.t = tempfile.mkdtemp(prefix="update-installed-")
        self.addCleanup(shutil.rmtree, self.t, True)
        self.origin = os.path.join(self.t, "origin.git")
        self.seed = seed = os.path.join(self.t, "seed")
        sh(self.t, "init", "-q", "--bare", self.origin)
        sh(self.t, "init", "-q", seed)
        Path(seed, "install.py").write_text(INSTALL_PY % (self.HOOKS,))
        for d in ("hooks", "agents"):
            os.makedirs(os.path.join(seed, "harness", d))
        for n in self.HOOKS:
            Path(seed, "harness", "hooks", n).write_text("print(%r)\n" % n)
        Path(seed, "harness", "agents", "x.md").write_text("agent\n")
        self.main_sha = self.commit_main("seed")
        sh(seed, "checkout", "-qb", "side")
        Path(seed, "harness", "hooks", "a.py").write_text("print('side')\n")
        sh(seed, "commit", "-qam", "side")
        sh(seed, "push", "-q", self.origin, "HEAD:refs/heads/side")
        self.side_sha = sh(seed, "rev-parse", "HEAD")
        sh(seed, "checkout", "-q", "main")
        self.home = os.path.join(self.t, "home")
        hooks = Path(self.home, ".claude", "hooks")
        agents = Path(self.home, ".claude", "agents")
        hooks.mkdir(parents=True)
        agents.mkdir(parents=True)
        (hooks / "a.py").write_text("print('a.py')\n")       # current
        (hooks / "b.py").write_text("print('old')\n")        # differs; c.py is missing
        (agents / "x.md").write_text("agent\n")              # current
        mock.patch.object(U, "CANONICAL_URL", self.origin).start()
        mock.patch.object(U, "ALLOW_FILE", True).start()
        self.addCleanup(mock.patch.stopall)
        self.calls = []
        self.remote = {"a.py": "already_current", "b.py": "replaced", "c.py": "new"}
        self.unregistered = []
        self.doctor = None                                  # [findings] the fake doctor answers, or None: no doctor
        self.typed = []

    def commit_main(self, msg, files=None):
        for rel, text in (files or {}).items():
            Path(self.seed, rel).parent.mkdir(parents=True, exist_ok=True)
            Path(self.seed, rel).write_text(text)
        sh(self.seed, "add", "-A")
        sh(self.seed, "commit", "-qm", msg)
        sh(self.seed, "push", "-q", self.origin, "HEAD:refs/heads/main")
        return sh(self.seed, "rev-parse", "HEAD")

    def runner(self, argv, **kw):
        self.calls.append((argv, kw))
        if "install-files" in argv:
            names = [argv[i + 1] for i, x in enumerate(argv) if x == "--file"]
            dry = "--dry-run" in argv
            if not dry:
                for n in names:
                    self.remote[n] = "already_current"
            out = {"result": "dry_run" if dry else "installed", "run": "ins-%012d" % len(self.calls),
                   "files": {n: {"action": self.remote.get(n, "already_current")} for n in names}}
            if not dry and self.unregistered:
                out["unregistered"] = self.unregistered
            return subprocess.CompletedProcess(argv, 0, json.dumps(out), "")
        if any(str(x).endswith("doctor.py") for x in argv):
            return subprocess.CompletedProcess(argv, 0, json.dumps(self.doctor or []), "")
        if any(str(x).endswith("install.py") for x in argv):
            return subprocess.run(argv, **kw)              # the fixture installer, for real
        raise AssertionError("unexpected command %r" % (argv,))

    def reader(self, prompt):
        self.typed.append(prompt)
        return self.answer

    answer = None

    def run_main(self, *args, runner=None, environ=None, answer="first12"):
        self.answer = self.main_sha[:12] if answer == "first12" else answer
        err, out = io.StringIO(), io.StringIO()
        with redirect_stderr(err), redirect_stdout(out):
            rc = U.main(["--home", self.home, *args], runner=runner or self.runner, reader=self.reader,
                        environ=CLEAN_ENV if environ is None else environ)
        return rc, out.getvalue(), err.getvalue()

    def snapshot(self):
        """Every file of the home except the updater's own cache (checked separately with cache_runs)."""
        rows = {}
        for dp, dn, fn in os.walk(self.home):
            if dp == self.home:
                dn[:] = [d for d in dn if d != ".agent-harness"]
            for f in dn + fn:
                st = os.lstat(os.path.join(dp, f))
                rows[os.path.join(dp, f)] = (st.st_size, st.st_mtime_ns)
        return rows

    def cache_runs(self):
        root = Path(self.home, ".agent-harness", "update-cache")
        return sorted(p.name for p in root.iterdir()) if root.exists() else []


class Refusals(Fixture):
    def test_commit_not_on_main_is_refused(self):
        for extra in (["--preview"], ["--ticket", "GoodQA goodqa#1"]):
            rc, _, err = self.run_main("--commit", self.side_sha, *extra)
            self.assertEqual(rc, U.EXIT_STOP)
            self.assertIn("is not", err)
        self.assertEqual(self.calls, [])
        self.assertEqual(Path(self.home, ".claude", "hooks", "b.py").read_text(), "print('old')\n")
        self.assertEqual(self.cache_runs(), [], "the run folder is removed after a stop")

    def test_malformed_inputs_stop_before_anything_runs(self):
        for args, why in ((["--commit", self.main_sha[:12], "--preview"], "40-hex"),
                          (["--commit", self.main_sha.upper(), "--preview"], "40-hex"),
                          (["--ticket", "goodqa 1", "--preview"], "--ticket must"),
                          ([], "--ticket 'GoodQA")):
            rc, _, err = self.run_main(*args)
            self.assertEqual(rc, U.EXIT_STOP, args)
            self.assertIn(why, err)
        self.assertEqual(self.calls, [])
        self.assertFalse(Path(self.home, ".agent-harness").exists(), "nothing is fetched for a refused input")

    def test_a_non_literal_installer_list_stops(self):
        self.commit_main("computed", {"install.py": "HOOKS = tuple(['a.py'])\n"})
        rc, _, err = self.run_main("--preview")
        self.assertEqual(rc, U.EXIT_STOP)
        self.assertIn("not a literal tuple", err)
        self.commit_main("path", {"install.py": "HOOKS = ('../x.py',)\n"})
        rc, _, err = self.run_main("--preview")
        self.assertIn("bare file names", err)


class AgentsAndConfirmation(Fixture):
    """F1 (mitigation; the guard rule that closes it is goodqa#17036)."""

    def test_an_agent_environment_is_refused_for_a_preview_and_a_real_run(self):
        for marker in U.AGENT_MARKERS:
            for args in (["--preview"], ["--ticket", "GoodQA goodqa#1"]):
                rc, _, err = self.run_main(*args, environ=dict(CLEAN_ENV, **{marker: "1"}))
                self.assertEqual(rc, U.EXIT_STOP)
                self.assertIn("user-run", err)
        self.assertEqual(self.calls, [])
        self.assertFalse(Path(self.home, ".agent-harness").exists())

    def test_the_markers_are_the_commit_policy_agent_markers(self):
        import commit_policy
        self.assertEqual(U.AGENT_MARKERS, commit_policy.AGENT_MARKERS)

    def test_a_real_run_needs_the_commit_typed_at_the_terminal(self):
        before = self.snapshot()
        for answer in ("", "yes", self.main_sha[:11], None):
            rc, out, err = self.run_main("--ticket", "GoodQA goodqa#1", answer=answer)
            self.assertEqual(rc, U.EXIT_STOP)
            self.assertIn("not confirmed", err)
        self.assertEqual(self.snapshot(), before)
        self.assertFalse([a for a, _ in self.calls if "install-files" in a and "--dry-run" not in a])
        self.assertTrue(self.typed and all(self.main_sha in p for p in self.typed), "the prompt names the commit")

    def test_no_terminal_stops_a_real_run(self):
        with mock.patch("builtins.open", side_effect=OSError("no tty")):
            with self.assertRaises(U.Stop):
                U.read_tty("x")

    def test_without_isolation_the_script_stops_before_its_imports(self):
        d = tempfile.mkdtemp(prefix="update-installed-self-")
        self.addCleanup(shutil.rmtree, d, True)
        shutil.copy(ROOT / "scripts" / "update_installed.py", d)
        marker = os.path.join(d, "json-ran")
        Path(d, "json.py").write_text("open(%r, 'w').write('x')\nfrom _json import *\n" % marker)
        env = {k: v for k, v in CLEAN_ENV.items() if not k.startswith("PYTHON")}
        r = subprocess.run([sys.executable, os.path.join(d, "update_installed.py"), "--help"], capture_output=True,
                           text=True, env=env)
        self.assertEqual(r.returncode, U.EXIT_USAGE)
        self.assertIn("python3 -I", r.stderr)
        self.assertFalse(os.path.exists(marker))
        r = subprocess.run([sys.executable, "-I", os.path.join(d, "update_installed.py"), "--help"],
                           capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(os.path.exists(marker), "with -I the folder of the script is not on sys.path")


class FreshSource(Fixture):
    """F3: no persistent clone. Git runs hardened in a fresh repository, and the caller's git settings never reach it."""

    def test_the_callers_git_settings_never_reach_git(self):
        marker = os.path.join(self.t, "fsmonitor-ran")
        hook = os.path.join(self.t, "fsm.sh")
        Path(hook).write_text("#!/bin/sh\ntouch %s\nexit 1\n" % marker)
        os.chmod(hook, 0o755)
        Path(self.home, ".gitconfig").write_text("[core]\n\tfsmonitor = %s\n\thooksPath = %s\n" % (hook, self.t))
        tmpl = os.path.join(self.t, "tmpl", "hooks")
        os.makedirs(tmpl)
        shutil.copy(hook, os.path.join(tmpl, "post-checkout"))
        hostile = {"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "core.fsmonitor", "GIT_CONFIG_VALUE_0": hook,
                   "GIT_DIR": os.path.join(self.t, "elsewhere"), "GIT_TEMPLATE_DIR": os.path.dirname(tmpl),
                   "HOME": self.home, "GIT_CONFIG_GLOBAL": os.path.join(self.home, ".gitconfig")}
        with mock.patch.dict(os.environ, hostile):
            rc, _, err = self.run_main("--ticket", "GoodQA goodqa#1")
        self.assertEqual(rc, U.EXIT_OK, err)
        self.assertFalse(os.path.exists(marker))

    def test_git_env_and_flags_match_ah_install(self):
        import ah_install
        with mock.patch.dict(os.environ, {"GIT_DIR": "/x", "GIT_CONFIG_COUNT": "1", "PYTHONPATH": "/y"}):
            self.assertEqual(U.git_env(self.home), ah_install.git_env(self.home))
        for allow in (False, True):
            seen = []
            with mock.patch.object(ah_install.subprocess, "run", side_effect=lambda argv, **kw: seen.append(argv) or
                                   subprocess.CompletedProcess(argv, 0, b"", b"")), \
                    mock.patch.object(ah_install, "ALLOW_FILE", allow), mock.patch.object(U, "ALLOW_FILE", allow):
                ah_install.git(self.t, ["status"], self.home)
                self.assertEqual(U.git_argv(self.t, ["status"]), seen[0])

    def test_the_contract_with_ah_install_inputs(self):
        import ah_install
        self.assertEqual(U.BATCH, ah_install.MAX_FILES)
        self.assertEqual(U.TICKET_RE.pattern, ah_install.TICKET_RE.pattern)
        self.assertEqual(U.ordered(["command_guard.py", "a.py", "b.py"]),
                         ah_install.order(["command_guard.py", "a.py", "b.py"]))
        names = ["h%02d.py" % i for i in range(25)] + ["command_guard.py"]
        for dry in (True, False):
            for group in U.batches(names):
                argv = U.ah_argv(self.home, "t2-dev", self.main_sha, group, "GoodQA goodqa#1", dry)
                files = [argv[i + 1] for i, x in enumerate(argv) if x == "--file"]
                ah_install.check_inputs("t2-dev", argv[argv.index("--from-ref") + 1], files,
                                        None if dry else argv[argv.index("--ticket") + 1], dry, None, None, ())
                self.assertEqual(argv[:4], [sys.executable, "-I", str(Path(self.home, ".claude", "hooks", "ah.py")),
                                            "install-files"])

    def test_a_cache_folder_that_is_a_symlink_or_open_to_others_stops(self):
        cache = Path(self.home, ".agent-harness", "update-cache")
        cache.parent.mkdir(parents=True)
        os.symlink(self.t, cache)
        rc, _, err = self.run_main("--preview")
        self.assertEqual(rc, U.EXIT_STOP)
        os.remove(cache)
        cache.mkdir(mode=0o777)
        os.chmod(cache, 0o777)
        rc, _, err = self.run_main("--preview")
        self.assertEqual(rc, U.EXIT_STOP)
        self.assertIn("open to others", err)

    def test_a_run_folder_that_already_exists_stops_and_is_kept(self):
        cache = Path(self.home, ".agent-harness", "update-cache")
        cache.mkdir(parents=True, mode=0o700)
        (cache / "run-000000000000").mkdir()
        (cache / "run-000000000000" / "keep").write_text("x")
        with mock.patch.object(U.uuid, "uuid4", return_value=mock.Mock(hex="0" * 32)):
            rc, _, err = self.run_main("--preview")
        self.assertEqual(rc, U.EXIT_STOP)
        self.assertIn("already exists", err)
        self.assertTrue((cache / "run-000000000000" / "keep").exists())

    def test_install_py_runs_isolated_from_a_fresh_export(self):
        marker = os.path.join(self.t, "pythonpath-json-ran")
        planted = os.path.join(self.t, "planted")
        os.makedirs(planted)
        Path(planted, "json.py").write_text("open(%r, 'w').write('x')\nfrom _json import *\n" % marker)
        with mock.patch.dict(os.environ, {"PYTHONPATH": planted}):
            rc, _, err = self.run_main("--no-remote")
        self.assertEqual(rc, U.EXIT_OK, err)
        self.assertFalse(os.path.exists(marker), "-E: PYTHONPATH does not reach install.py")
        inst = [(a, kw) for a, kw in self.calls if str(a[-1]).endswith(self.home) and "--apply" in a]
        self.assertEqual(len(inst), 1)
        argv, kw = inst[0]
        self.assertEqual(argv[1:4], ["-B", "-E", "-s"])
        self.assertTrue(kw["cwd"].startswith(os.path.join(self.home, ".agent-harness", "update-cache", "run-")))
        self.assertEqual(argv[4], os.path.join(kw["cwd"], "install.py"))
        self.assertEqual(self.cache_runs(), [], "the run folder is removed")

    def test_an_object_that_does_not_hash_to_its_id_stops(self):
        with self.assertRaises(U.Stop):
            U.verified("blob", "0" * 40, b"x")


class Preview(Fixture):
    def test_preview_writes_nothing(self):
        before = self.snapshot()
        rc, out, err = self.run_main("--preview")
        self.assertEqual(rc, U.EXIT_OK, err)
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.cache_runs(), [])
        self.assertTrue(self.calls)
        self.assertTrue(all("--dry-run" in argv for argv, _ in self.calls))
        self.assertEqual(self.typed, [], "a preview asks nothing")
        self.assertIn("Preview only", out)
        self.assertIn("(1 dry run(s))", out)


class FileList(Fixture):
    def export(self, commit):
        d = os.path.join(self.t, "exp-" + commit[:7])
        repo, _ = U.fetch_main(Path(self.t), self.home)
        U.export_commit(repo, self.home, commit, Path(d))
        return repo, d

    def test_file_list_is_derived_from_the_installed_files(self):
        repo, d = self.export(self.main_sha)
        lists = U.installer_lists(d)
        self.assertEqual(lists["hooks"], list(self.HOOKS))
        self.assertEqual(U.local_changes(d, self.home, lists), ["hooks/b.py", "hooks/c.py"])
        self.assertEqual(U.remote_changes(self.home, "t2-dev", self.main_sha, lists["hooks"], self.runner),
                         ["b.py", "c.py"])
        Path(self.home, ".claude", "agents", "x.md").write_text("edited\n")
        os.remove(os.path.join(self.home, ".claude", "hooks", "a.py"))
        os.symlink(os.path.join(d, "harness", "hooks", "a.py"), os.path.join(self.home, ".claude", "hooks", "a.py"))
        self.assertEqual(U.local_changes(d, self.home, lists),
                         ["agents/x.md", "hooks/a.py", "hooks/b.py", "hooks/c.py"])   # a symlink is never "current"

    def test_the_lists_and_bytes_are_the_commits_not_mains(self):
        first = self.main_sha
        self.commit_main("add d", {"install.py": INSTALL_PY % (self.HOOKS + ("d.py",),), "harness/hooks/d.py": "d\n"})
        Path(self.home, ".claude", "hooks", "b.py").write_text("print('b.py')\n")
        rc, out, err = self.run_main("--commit", first, "--preview")
        self.assertEqual(rc, U.EXIT_OK, err)
        self.assertIn("Mac: 1 file(s) differ: hooks/c.py", out)
        self.assertNotIn("d.py", out)
        self.assertIn("Commit %s (seed)" % first, out)

    def test_an_older_commit_that_would_downgrade_a_mac_file_stops(self):
        first = self.main_sha
        self.commit_main("b v2", {"harness/hooks/b.py": "print('b v2')\n"})
        Path(self.home, ".claude", "hooks", "b.py").write_text("print('b v2')\n")
        rc, _, err = self.run_main("--commit", first, "--no-remote")
        self.assertEqual(rc, U.EXIT_STOP)
        self.assertIn("older versions", err)
        self.assertIn("hooks/b.py", err)
        self.assertEqual(Path(self.home, ".claude", "hooks", "b.py").read_text(), "print('b v2')\n")

    def test_remote_batches_hold_at_most_twenty_files_with_the_guard_last(self):
        names = ["command_guard.py"] + ["h%02d.py" % i for i in range(44)]
        U.remote_changes(self.home, "t2-dev", self.main_sha, names, self.runner)
        sent = [[a[i + 1] for i, x in enumerate(a) if x == "--file"] for a, _ in self.calls]
        self.assertEqual([len(s) for s in sent], [20, 20, 5])
        self.assertEqual(sent[-1][-1], "command_guard.py")
        self.assertNotIn("command_guard.py", sent[0] + sent[1])

    def test_a_dry_run_that_fails_omits_a_file_or_answers_oddly_stops(self):
        cases = [lambda argv, **kw: subprocess.CompletedProcess(argv, 2, "", "refused"),
                 lambda argv, **kw: subprocess.CompletedProcess(argv, 0, json.dumps({"files": {}}), ""),
                 lambda argv, **kw: subprocess.CompletedProcess(argv, 0, json.dumps({"files": {"a.py": "new"}}), ""),
                 lambda argv, **kw: subprocess.CompletedProcess(argv, 0, "not json", "")]
        for bad in cases:
            with self.assertRaises(U.Stop):
                U.remote_changes(self.home, "t2-dev", self.main_sha, ["a.py"], bad)


class RealRun(Fixture):
    def test_installs_the_mac_then_only_the_changed_remote_files_and_verifies(self):
        rc, out, err = self.run_main("--ticket", "GoodQA goodqa#1")
        self.assertEqual(rc, U.EXIT_OK, err)
        self.assertEqual(Path(self.home, ".claude", "hooks", "c.py").read_text(), "print('c.py')\n")
        real = [a for a, _ in self.calls if "install-files" in a and "--dry-run" not in a]
        self.assertEqual(len(real), 1)
        self.assertEqual([real[0][i + 1] for i, x in enumerate(real[0]) if x == "--file"], ["b.py", "c.py"])
        self.assertIn("GoodQA goodqa#1", real[0])
        self.assertIn(self.main_sha, real[0])
        self.assertIn("batch 1 of 1 installed (run ins-", out)
        self.assertIn("Done. Installed commit", out)
        self.assertEqual(len(self.typed), 1)
        self.assertEqual(self.cache_runs(), [])

    def test_a_mac_file_still_different_after_install_py_stops(self):
        def lazy(argv, **kw):
            if any(str(x).endswith("install.py") for x in argv):
                self.calls.append((argv, kw))
                return subprocess.CompletedProcess(argv, 0, "", "")      # exit 0, installs nothing
            return self.runner(argv, **kw)
        rc, _, err = self.run_main("--ticket", "GoodQA goodqa#1", runner=lazy)
        self.assertEqual(rc, U.EXIT_STOP)
        self.assertIn("still differ from the commit", err)
        self.assertFalse([a for a, _ in self.calls if "install-files" in a and "--dry-run" not in a])

    def test_a_remote_file_still_different_after_the_install_stops(self):
        def stuck(argv, **kw):
            r = self.runner(argv, **kw)
            self.remote["c.py"] = "new"                    # the host never takes c.py
            return r
        rc, _, err = self.run_main("--ticket", "GoodQA goodqa#1", runner=stuck)
        self.assertEqual(rc, U.EXIT_STOP)
        self.assertIn("still differ", err)

    def test_a_failed_batch_reports_what_was_installed_and_how_to_finish(self):
        self.remote.update({"h%02d.py" % i: "new" for i in range(25)})
        names = ["h%02d.py" % i for i in range(25)]
        audit = Path(self.home, ".agent-harness", "install-audit.jsonl")
        audit.parent.mkdir(parents=True, exist_ok=True)
        since = "2000-01-01T00:00:00Z"
        n = {"real": 0}

        def second_fails(argv, **kw):
            if "install-files" in argv and "--dry-run" not in argv:
                n["real"] += 1
                if n["real"] == 2:
                    with open(audit, "a") as fh:
                        fh.write(json.dumps({"event": "start", "run": "ins-0123456789ab", "host": "t2-dev",
                                             "kind": "install", "at": "2030-01-01T00:00:00Z"}) + "\n")
                    raise subprocess.TimeoutExpired(argv, 1)
            return self.runner(argv, **kw)
        out = io.StringIO()
        with redirect_stdout(out):
            with self.assertRaises(U.Stop) as cm:
                U.remote_install(self.home, "t2-dev", self.main_sha, names, "GoodQA goodqa#1", second_fails, since)
        msg = str(cm.exception)
        self.assertIn("timed out", msg)
        self.assertIn("Batches already installed on t2-dev: run ins-", msg)
        self.assertIn("--resume ins-0123456789ab", msg)
        self.assertIn("--rollback ins-0123456789ab", msg)
        self.assertIn("batch 1 of 2 installed", out.getvalue())

    def test_timeouts_and_odd_answers_stop_cleanly(self):
        def hang(argv, **kw):
            raise subprocess.TimeoutExpired(argv, 1)
        rc, _, err = self.run_main("--preview", runner=hang)
        self.assertEqual(rc, U.EXIT_STOP)
        self.assertIn("timed out", err)
        with mock.patch.object(U.subprocess, "run", side_effect=subprocess.TimeoutExpired(["git"], 1)):
            with self.assertRaises(U.Stop):
                U.git(self.t, ["status"], self.home)

        def odd(argv, **kw):
            if "install-files" in argv:
                return subprocess.CompletedProcess(argv, 0, json.dumps({"files": {"a.py": None}}), "")
            return self.runner(argv, **kw)
        rc, _, err = self.run_main("--preview", runner=odd)
        self.assertEqual(rc, U.EXIT_STOP)
        self.assertNotIn("Traceback", err)

        def install_hangs(argv, **kw):
            if any(str(x).endswith("install.py") for x in argv):
                raise subprocess.TimeoutExpired(argv, 1)
            return self.runner(argv, **kw)
        rc, _, err = self.run_main("--no-remote", runner=install_hangs)
        self.assertEqual(rc, U.EXIT_STOP)
        self.assertIn("install.py timed out", err)


class Registration(Fixture):
    """F7: a hook the commit declares but settings.json does not register is reported, and the exit says so."""

    def test_new_unregistered_hooks_give_exit_3_and_old_gaps_are_kept_apart(self):
        Path(self.home, ".claude", "hooks", "doctor.py").write_text("# fake: the runner answers for it\n")
        answers = [[{"id": "a", "state": "WIRED"}, {"id": "old", "state": "MISSING"}],
                   [{"id": "a", "state": "WIRED"}, {"id": "old", "state": "MISSING"}, {"id": "new", "state": "MISSING"}]]

        def with_doctor(argv, **kw):
            if any(str(x).endswith("doctor.py") for x in argv):
                self.doctor = answers.pop(0)
            return self.runner(argv, **kw)
        self.unregistered = ["remote-new"]
        rc, out, err = self.run_main("--ticket", "GoodQA goodqa#1", runner=with_doctor)
        self.assertEqual(rc, U.EXIT_REGISTER, err)
        self.assertIn("Mac: declared but not registered in settings.json, so not running yet: new", out)
        self.assertIn("t2-dev: declared but not registered in settings.json, so not running yet: remote-new", out)
        self.assertIn("already unregistered before this run: old", out)
        self.assertIn("NOT fully active", out)
        self.assertNotIn("Done.", out)

    def test_a_hook_wired_before_and_not_after_stops(self):
        Path(self.home, ".claude", "hooks", "doctor.py").write_text("# fake\n")
        answers = [[{"id": "a", "state": "WIRED"}], [{"id": "a", "state": "MISSING"}]]

        def with_doctor(argv, **kw):
            if any(str(x).endswith("doctor.py") for x in argv):
                self.doctor = answers.pop(0)
            return self.runner(argv, **kw)
        rc, _, err = self.run_main("--ticket", "GoodQA goodqa#1", runner=with_doctor)
        self.assertEqual(rc, U.EXIT_STOP)
        self.assertIn("not wired now: a", err)
        self.assertFalse([a for a, _ in self.calls if "install-files" in a and "--dry-run" not in a])


if __name__ == "__main__":
    unittest.main()
