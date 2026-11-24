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
import types
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "harness" / "hooks"))
import update_installed as U  # noqa: E402
sys.path.insert(0, str(ROOT / "tests"))
import test_ah_install as TAI  # noqa: E402  (its Base runs the real remote installer against a temporary host)

GIT = ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "init.defaultBranch=main",
       "-c", "commit.gpgsign=false"]
CLEAN_ENV = {k: v for k, v in os.environ.items() if k not in U.AGENT_MARKERS}

INSTALL_PY = ("import json, os, sys\n"
              "AGENTS = ('x.md',)\nHOOKS = %r\nTOOLS = ()\nSKILLS = %r\n"
              "if __name__ == '__main__':\n"
              "    home = sys.argv[sys.argv.index('--home') + 1]\n"
              "    for folder, names in (('hooks', HOOKS), ('agents', AGENTS), ('skills', SKILLS)):\n"
              "        for f in names:\n"
              "            dest = os.path.join(home, '.claude', folder, f)\n"
              "            os.makedirs(os.path.dirname(dest), exist_ok=True)\n"
              "            with open(os.path.join('harness', folder, f), 'rb') as a, open(dest, 'wb') as b:\n"
              "                b.write(a.read())\n")


def sh(cwd, *args):
    return subprocess.run(GIT + list(args), cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


class Fixture(unittest.TestCase):
    HOOKS = ("a.py", "b.py", "c.py")
    SKILLS = ()

    def setUp(self):
        self.t = tempfile.mkdtemp(prefix="update-installed-")
        self.addCleanup(shutil.rmtree, self.t, True)
        self.origin = os.path.join(self.t, "origin.git")
        self.seed = seed = os.path.join(self.t, "seed")
        sh(self.t, "init", "-q", "--bare", self.origin)
        sh(self.t, "init", "-q", seed)
        Path(seed, "install.py").write_text(INSTALL_PY % (self.HOOKS, self.SKILLS))
        for d in ("hooks", "agents", "scripts"):
            os.makedirs(os.path.join(seed, "harness", d) if d != "scripts" else os.path.join(seed, d))
        Path(seed, U.SELF_REL).write_bytes(U.SELF_BYTES)     # main's copy of the updater is the running one (F4)
        for n in self.HOOKS:
            Path(seed, "harness", "hooks", n).write_text("print(%r)\n" % n)
        for n in self.SKILLS:
            Path(seed, "harness", "skills", n).parent.mkdir(parents=True, exist_ok=True)
            Path(seed, "harness", "skills", n).write_text("skill %s\n" % n)
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
        (hooks / "doctor.py").write_text("# fake: the runner answers for it\n")
        mock.patch.object(U, "CANONICAL_URL", self.origin).start()
        mock.patch.object(U, "ALLOW_FILE", True).start()
        self.addCleanup(mock.patch.stopall)
        self.calls = []
        self.remote = {"a.py": "already_current", "b.py": "replaced", "c.py": "new"}
        self.unregistered = []
        self.doctor = []                                    # [findings] the fake doctor answers; None: it does not answer
        self.host_doctor = []                               # the same for `doctor.py check --ssh <host>`
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
            answer = self.host_doctor if "--ssh" in argv else self.doctor
            if answer is None:
                return subprocess.CompletedProcess(argv, 2, "Traceback: doctor crashed", "")
            rows = [dict(r, required=r.get("required", r["state"] != "PENDING")) for r in answer]
            rc = 1 if any(r["required"] and r["state"] != "WIRED" for r in rows) else 0   # = doctor.verdict
            return subprocess.CompletedProcess(argv, rc, json.dumps(rows), "")
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
            try:
                rc = U.main(list(args), runner=runner or self.runner, reader=self.reader,
                            environ=CLEAN_ENV if environ is None else environ, home=self.home)
            except SystemExit as e:            # argparse: a bad option or value
                rc = e.code
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
        """R5 F7: a bad value is usage (exit 2, as documented); a missing ticket for a real run is a stop (exit 1)."""
        for args, why, code in ((["--commit", self.main_sha[:12], "--preview"], "40-hex", U.EXIT_USAGE),
                                (["--commit", self.main_sha.upper(), "--preview"], "40-hex", U.EXIT_USAGE),
                                (["--ticket", "goodqa 1", "--preview"], "--ticket must", U.EXIT_USAGE),
                                (["--home", self.t, "--preview"], "unrecognized arguments", U.EXIT_USAGE),
                                ([], "--ticket 'GoodQA", U.EXIT_STOP)):
            rc, _, err = self.run_main(*args)
            self.assertEqual(rc, code, args)
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
        r = subprocess.run([sys.executable, "-S", os.path.join(d, "update_installed.py"), "--help"],
                           capture_output=True, text=True, env=env)  # -S alone: only the -I check can stop it
        self.assertEqual(r.returncode, U.EXIT_USAGE)
        self.assertIn("python3 -I -S", r.stderr)
        self.assertFalse(os.path.exists(marker))
        r = subprocess.run([sys.executable, "-I", "-S", os.path.join(d, "update_installed.py"), "--help"],
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
        self.assertEqual(argv[1:5], ["-B", "-E", "-s", "-S"])
        self.assertTrue(kw["cwd"].startswith(os.path.join(self.home, ".agent-harness", "update-cache", "run-")))
        self.assertEqual(argv[5], os.path.join(kw["cwd"], "install.py"))
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
        _, digests = U.export_commit(repo, self.home, commit, Path(d))
        return repo, d, digests

    def test_file_list_is_derived_from_the_installed_files(self):
        repo, d, digests = self.export(self.main_sha)
        lists = U.installer_lists(d)
        self.assertEqual(lists["hooks"], list(self.HOOKS))
        self.assertEqual(U.local_changes(digests, self.home, lists), ["hooks/b.py", "hooks/c.py"])
        self.assertEqual(U.remote_changes(self.home, "t2-dev", self.main_sha, lists["hooks"], self.runner),
                         ["b.py", "c.py"])
        Path(self.home, ".claude", "agents", "x.md").write_text("edited\n")
        os.remove(os.path.join(self.home, ".claude", "hooks", "a.py"))
        os.symlink(os.path.join(d, "harness", "hooks", "a.py"), os.path.join(self.home, ".claude", "hooks", "a.py"))
        self.assertEqual(U.local_changes(digests, self.home, lists),
                         ["agents/x.md", "hooks/a.py", "hooks/b.py", "hooks/c.py"])   # a symlink is never "current"

    def test_the_lists_are_parsed_only_from_the_verified_install_py(self):
        repo, d, digests = self.export(self.main_sha)
        Path(d, "install.py").write_text(INSTALL_PY % (self.HOOKS + ("planted.py",), ()))
        with self.assertRaises(U.Stop) as cm:
            U.installer_lists(d, digests)
        self.assertIn("install.py changed after it was verified", str(cm.exception))

    def test_the_digests_are_kept_in_memory_not_reread_from_the_export(self):
        repo, d, digests = self.export(self.main_sha)
        lists = U.installer_lists(d)
        Path(self.home, ".claude", "hooks", "b.py").write_text("print('b.py')\n")
        Path(d, "harness", "hooks", "b.py").write_text("tampered\n")   # the export changes after it was verified
        self.assertEqual(U.local_changes(digests, self.home, lists), ["hooks/c.py"])

    def test_the_lists_and_bytes_are_the_commits_not_mains(self):
        first = self.main_sha
        self.commit_main("add d", {"install.py": INSTALL_PY % (self.HOOKS + ("d.py",), ()), "harness/hooks/d.py": "d\n"})
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

    def test_an_older_commit_stops_a_remote_run_when_main_changed_any_hook_after_it(self):
        """F7: ah_install refuses an older commit for a hook main changed later, even one the host already has."""
        first = self.main_sha
        self.commit_main("a v2", {"harness/hooks/a.py": "print('a v2')\n"})
        rc, _, err = self.run_main("--commit", first, "--preview")
        self.assertEqual(rc, U.EXIT_STOP)
        self.assertIn("remote installer refuses an older commit", err)
        self.assertIn("hooks/a.py", err)
        self.assertEqual(self.calls, [], "no dry run is sent")
        rc, _, err = self.run_main("--commit", first, "--preview", "--no-remote")
        self.assertEqual(rc, U.EXIT_OK, err)

    def test_skills_in_folders_are_listed_like_install_py_lists_them(self):
        """F1: install.py's SKILLS are <folder>/<file>; HOOKS, AGENTS and TOOLS stay bare names."""
        for folder, name, ok in (("skills", "sk/SKILL.md", True), ("skills", "sk/scan.py", True),
                                 ("skills", "SKILL.md", True), ("skills", "sk/../x", False),
                                 ("skills", "../x", False), ("skills", "a/b/c", False), ("skills", "/abs", False),
                                 ("skills", ".hidden/x", False), ("hooks", "sk/x.py", False),
                                 ("hooks", "x.py", True), ("agents", "a/b.md", False), ("tools", "", False)):
            self.assertEqual(bool(U.valid_name(folder, name)), ok, (folder, name))

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

    def test_every_ah_call_is_told_the_updaters_home(self):
        """ah keeps its audit under AH_HOME; the open-run check reads the audit under the updater's home. With another
        AH_HOME in the caller's shell they would read two different files, and an open run would go unseen."""
        with mock.patch.dict(os.environ, {"AH_HOME": os.path.join(self.t, "elsewhere")}):
            rc, _, err = self.run_main("--ticket", "GoodQA goodqa#1")
        self.assertEqual(rc, U.EXIT_OK, err)
        ah_calls = [kw for a, kw in self.calls if "install-files" in a]
        self.assertTrue(ah_calls and any("--dry-run" not in a for a, _ in self.calls if "install-files" in a))
        self.assertEqual({kw["env"]["AH_HOME"] for kw in ah_calls}, {self.home})

    def test_a_mac_file_still_different_after_install_py_stops(self):
        def lazy(argv, **kw):
            if any(str(x).endswith("install.py") for x in argv):
                self.calls.append((argv, kw))
                return subprocess.CompletedProcess(argv, 0, "", "")      # exit 0, installs nothing
            return self.runner(argv, **kw)
        rc, _, err = self.run_main("--ticket", "GoodQA goodqa#1", runner=lazy)
        self.assertEqual(rc, U.EXIT_STOP)
        self.assertIn("these Mac files are live but are NOT the commit's bytes: hooks/b.py hooks/c.py", err)
        self.assertIn("The files they replaced are under %s" % U.BACKUPS, err)
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
                U.remote_install(self.home, "t2-dev", self.main_sha, names, "GoodQA goodqa#1", second_fails)
        msg = str(cm.exception)
        self.assertIn("timed out", msg)
        self.assertIn("Batches already installed on t2-dev: run ins-", msg)
        self.assertIn("--resume ins-0123456789ab", msg)
        self.assertIn("--rollback ins-0123456789ab", msg)
        self.assertIn("batch 1 of 2 installed", out.getvalue())

    def test_a_run_that_ended_unknown_gets_resume_and_rollback_guidance(self):
        """F3: a batch that exits 5 leaves `result: unknown`, which keeps the run open; the guidance must say so. The
        answer has the real shape (ah prints the result JSON, then its error line: RealRemoteAnswers produces the real
        one), and the run ids match the remote installer's RUN_RE."""
        audit = Path(self.home, ".agent-harness", "install-audit.jsonl")
        audit.parent.mkdir(parents=True, exist_ok=True)
        rows = [{"event": "start", "run": "ins-00000000000a", "host": "t2-dev", "kind": "install"},
                {"event": "result", "run": "ins-00000000000a", "host": "t2-dev", "kind": "install", "result": "unknown"},
                {"event": "start", "run": "ins-00000000000d", "host": "t2-dev", "kind": "install"},
                {"event": "result", "run": "ins-00000000000d", "host": "t2-dev", "kind": "install", "result": "installed"}]
        audit.write_text("".join(json.dumps(r) + "\n" for r in rows))

        def fails(argv, **kw):
            if "install-files" in argv and "--dry-run" not in argv:
                out = json.dumps({"ok": False, "run": "ins-00000000000a", "host": "t2-dev", "result": "unknown",
                                  "exit_code": 5}, indent=2) + "\n" + json.dumps(
                    {"ok": False, "code": "unknown", "message": "unknown on t2-dev (run ins-00000000000a)"}) + "\n"
                return subprocess.CompletedProcess(argv, 5, out, "")
            return self.runner(argv, **kw)
        with self.assertRaises(U.Stop) as cm:
            U.remote_install(self.home, "t2-dev", self.main_sha, ["b.py"], "GoodQA goodqa#1", fails)
        msg = str(cm.exception)
        self.assertIn("--host t2-dev --resume ins-00000000000a", msg)
        self.assertIn("--host t2-dev --rollback ins-00000000000a", msg)
        self.assertNotIn("ins-00000000000d", msg, "a run with a definite result is finished")

    def test_timeouts_and_odd_answers_stop_cleanly(self):
        def hang(argv, **kw):
            raise subprocess.TimeoutExpired(argv, 1)
        rc, _, err = self.run_main("--preview", runner=hang)
        self.assertEqual(rc, U.EXIT_STOP)
        self.assertIn("timed out", err)
        with mock.patch.object(U.subprocess, "run", side_effect=subprocess.TimeoutExpired(["git"], 1)):
            with self.assertRaises(U.Stop):
                U.git(self.t, ["status"], self.home)

        def odd(argv, **kw):                               # every name answered, one entry not a dict
            if "install-files" in argv:
                names = [argv[i + 1] for i, x in enumerate(argv) if x == "--file"]
                files = {n: {"action": "replaced"} for n in names}
                files[names[0]] = None
                return subprocess.CompletedProcess(argv, 0, json.dumps({"files": files}), "")
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
            if any(str(x).endswith("doctor.py") for x in argv) and "--ssh" not in argv:   # the Mac's two answers
                self.doctor = answers.pop(0)
            return self.runner(argv, **kw)
        self.unregistered = ["remote-new"]       # the host's install reports it; the host's doctor (fake) does not
        rc, out, err = self.run_main("--ticket", "GoodQA goodqa#1", runner=with_doctor)
        self.assertEqual(rc, U.EXIT_REGISTER, err)
        self.assertEqual(answers, [], "the Mac's doctor ran before and after the install")
        self.assertIn("Mac: declared but not registered in settings.json, so not running yet: new", out)
        self.assertIn("t2-dev: declared but not registered in settings.json, so not running yet: remote-new", out)
        self.assertIn("Mac (already before this run): declared but not registered in settings.json, so not running "
                      "yet: old", out)
        self.assertIn("NOT fully active", out)
        self.assertNotIn("Done.", out)

    def test_a_doctor_that_does_not_answer_after_the_install_stops(self):
        """F2a: no answer after the install means registration is not proven: never "Done" with exit 0."""
        answers = [[{"id": "a", "state": "WIRED"}], None]

        def with_doctor(argv, **kw):
            if any(str(x).endswith("doctor.py") for x in argv):
                self.doctor = answers.pop(0)
            return self.runner(argv, **kw)
        rc, out, err = self.run_main("--no-remote", runner=with_doctor)
        self.assertEqual(rc, U.EXIT_STOP)
        self.assertIn("registration is not proven", err)
        self.assertNotIn("Done.", out)

    def test_hooks_already_unregistered_before_the_run_still_give_exit_3(self):
        """F2b: exit 0 means every declared hook is registered, whether or not it was missing before this run."""
        self.doctor = [{"id": "a", "state": "WIRED"}, {"id": "old", "state": "MISSING"}]
        rc, out, err = self.run_main("--no-remote")
        self.assertEqual(rc, U.EXIT_REGISTER, err)
        self.assertIn("already before this run", out)
        self.assertNotIn("Done.", out)

    def test_nothing_to_install_still_runs_the_doctor(self):
        """F2c: a plain rerun after an exit 3 must not print Done while a hook is still unregistered."""
        for n in ("b.py", "c.py"):
            Path(self.home, ".claude", "hooks", n).write_text("print(%r)\n" % n)
        self.remote = {n: "already_current" for n in self.HOOKS}
        self.doctor = [{"id": "new", "state": "MISSING"}]
        rc, out, err = self.run_main("--ticket", "GoodQA goodqa#1")
        self.assertEqual(rc, U.EXIT_REGISTER, err)
        self.assertEqual(self.typed, [], "nothing to install asks nothing")
        self.assertTrue([a for a, _ in self.calls if str(a[2]).endswith("doctor.py")], "the doctor ran")
        self.doctor = [{"id": "new", "state": "WIRED"}]
        rc, out, err = self.run_main("--ticket", "GoodQA goodqa#1")
        self.assertEqual(rc, U.EXIT_OK, err)
        self.assertIn("Nothing to install", out)
        self.assertNotIn("Done. Installed", out)
        self.doctor = None
        rc, out, err = self.run_main("--ticket", "GoodQA goodqa#1")
        self.assertEqual(rc, U.EXIT_STOP, "no answer stops even when nothing was installed")

    def test_a_host_where_nothing_was_installed_is_still_checked(self):
        """R5 F4: after an exit 3 for t2-dev, a plain rerun installs nothing there; it must not exit 0 while the host
        still has an unregistered hook, and a host doctor that does not answer stops."""
        for n in ("b.py", "c.py"):
            Path(self.home, ".claude", "hooks", n).write_text("print(%r)\n" % n)
        self.remote = {n: "already_current" for n in self.HOOKS}
        self.host_doctor = [{"id": "remote-new", "state": "MISSING"}, {"id": "a", "state": "WIRED"}]
        rc, out, err = self.run_main("--ticket", "GoodQA goodqa#1")
        self.assertEqual(rc, U.EXIT_REGISTER, err)
        self.assertIn("t2-dev: declared but not registered in settings.json, so not running yet: remote-new", out)
        ssh = [a for a, _ in self.calls if str(a[2]).endswith("doctor.py") and "--ssh" in a]
        self.assertEqual(ssh[0][-2:], ["--ssh", "t2-dev"])
        self.host_doctor = None
        rc, out, err = self.run_main("--ticket", "GoodQA goodqa#1")
        self.assertEqual(rc, U.EXIT_STOP)
        self.assertIn("the doctor did not answer for t2-dev", err)
        self.host_doctor = [{"id": "a", "state": "WIRED"}]
        rc, out, err = self.run_main("--ticket", "GoodQA goodqa#1")
        self.assertEqual(rc, U.EXIT_OK, err)
        self.assertIn("the doctor reports every required hook wired on the Mac and on t2-dev", out)

    def test_a_required_hook_that_is_broken_stops_and_a_pending_one_is_not_a_gap(self):
        """R5 F5: SCRIPT_MISSING or CANARY_FAIL on a required hook is not a registration step; PENDING is not required."""
        for state in ("SCRIPT_MISSING", "CANARY_FAIL"):
            self.doctor = [{"id": "a", "state": "WIRED"}, {"id": "gone", "state": state}]
            rc, out, err = self.run_main("--no-remote")
            self.assertEqual(rc, U.EXIT_STOP, state)
            self.assertIn("not working (%s)" % state, err)
            self.assertNotIn("Done.", out)
        self.doctor = [{"id": "a", "state": "WIRED"}, {"id": "later", "state": "PENDING"}]
        rc, out, err = self.run_main("--no-remote")
        self.assertEqual(rc, U.EXIT_OK, err)

    def test_a_doctor_whose_exit_code_disagrees_with_its_rows_is_not_an_answer(self):
        def lying(argv, **kw):
            if any(str(x).endswith("doctor.py") for x in argv):
                return subprocess.CompletedProcess(argv, 1, json.dumps([{"id": "a", "state": "WIRED",
                                                                         "required": True}]), "")
            return self.runner(argv, **kw)
        rc, _, err = self.run_main("--no-remote", runner=lying)
        self.assertEqual(rc, U.EXIT_STOP)
        self.assertIn("registration is not proven", err)

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


class Contracts(unittest.TestCase):
    """The class behind PR 336 review R4: every test ran on a fixture the author built. These run the updater's
    parsers and rules against the repository's own files and the remote installer's own functions on the same inputs,
    so the two cannot drift."""

    def test_installer_lists_equal_install_pys_own_lists(self):
        sys.path.insert(0, str(ROOT))
        try:
            import install
        finally:
            sys.path.remove(str(ROOT))
        want = {folder: list(getattr(install, var)) for folder, var in U.FOLDERS}
        self.assertEqual(U.installer_lists(ROOT), want)
        for folder, names in want.items():
            for name in names:
                self.assertTrue((ROOT / "harness" / folder / name).is_file(), "%s/%s" % (folder, name))
        self.assertTrue(want["skills"], "the repository ships skills, so the skills layout is exercised")

    def test_unfinished_runs_equal_the_remote_installers_rule_on_the_same_audit(self):
        import ah_install
        self.assertEqual(U.CLEARING, ah_install.CLEARING)
        self.assertEqual(U.UNREGISTERED, ah_install.UNREGISTERED)
        self.assertEqual(U.NOT_REGISTERED_BEFORE, ah_install.NOT_REGISTERED_BEFORE)
        h = "t2-dev"
        cases = {
            "open start": [{"event": "start", "run": "r1", "host": h, "kind": "install"}],
            "unknown": [{"event": "start", "run": "r1", "host": h, "kind": "install"},
                        {"event": "result", "run": "r1", "host": h, "kind": "install", "result": "unknown"}],
            "installed": [{"event": "start", "run": "r1", "host": h, "kind": "install"},
                          {"event": "result", "run": "r1", "host": h, "kind": "install", "result": "installed"}],
            "failed resume": [{"event": "start", "run": "r1", "host": h, "kind": "install"},
                              {"event": "result", "run": "r1", "host": h, "kind": "install", "result": "unknown"},
                              {"event": "start", "run": "r1", "host": h, "kind": "resume"},
                              {"event": "result", "run": "r1", "host": h, "kind": "resume", "result": "attempt_refused"}],
            "rolled back": [{"event": "start", "run": "r1", "host": h, "kind": "install"},
                            {"event": "result", "run": "r1", "host": h, "kind": "install", "result": "unknown"},
                            {"event": "start", "run": "r1", "host": h, "kind": "rollback"},
                            {"event": "result", "run": "r1", "host": h, "kind": "rollback", "result": "rolled_back"}],
            "restored": [{"event": "start", "run": "r1", "host": h, "kind": "rollback"},
                         {"event": "result", "run": "r1", "host": h, "kind": "rollback", "result": "restored"}],
            "other host": [{"event": "start", "run": "r1", "host": "dev2", "kind": "install"}],
            "refused": [{"event": "start", "run": "r1", "host": h, "kind": "install"},
                        {"event": "result", "run": "r1", "host": h, "kind": "install", "result": "refused"}],
            "garbage": ["not json", {"event": "start", "host": h, "kind": "install"}, []],
        }
        for name, rows in cases.items():
            home = tempfile.mkdtemp(prefix="update-installed-audit-")
            self.addCleanup(shutil.rmtree, home, True)
            Path(home, ".agent-harness").mkdir()
            Path(home, ".agent-harness", "install-audit.jsonl").write_text(
                "".join((r if isinstance(r, str) else json.dumps(r)) + "\n" for r in rows))
            self.assertEqual(U.unfinished_runs(home, h), ah_install.unfinished_runs(home, h), name)
        self.assertEqual(U.unfinished_runs(tempfile.gettempdir() + "/no-such-home", h), [])

    def test_exit_codes_match_the_docs_and_the_docstring(self):
        codes = {U.EXIT_OK, U.EXIT_STOP, U.EXIT_USAGE, U.EXIT_REGISTER}
        self.assertEqual(codes, {0, 1, 2, 3})
        docs = (ROOT / "docs" / "operations.md").read_text()
        section = docs.split("## Updating the installed harness (user-run)", 1)[1].split("\n## ", 1)[0]
        line = section.split("Exit codes:", 1)[1].split("\n\n", 1)[0]
        import re
        self.assertEqual({int(c) for c in re.findall(r"(?:^|; )\s*(\d) ", line.replace("\n", " "))}, codes, line)
        doc = U.__doc__.split("Exit:", 1)[1]
        self.assertEqual({int(c) for c in re.findall(r"(?:^|; |\n)\s*(\d) ", doc)}, codes, doc)
        self.assertIn("-I -S", section)


class SelfCheck(Fixture):
    """F4: the updater that enforces the checks must be main's own copy."""

    def test_a_copy_that_is_not_mains_stops_before_the_commit_is_read(self):
        self.commit_main("edit updater", {U.SELF_REL: "# a different updater\n"})
        rc, _, err = self.run_main("--preview")
        self.assertEqual(rc, U.EXIT_STOP)
        self.assertIn("is not main's scripts/update_installed.py", err)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.cache_runs(), [])

    def test_main_without_the_updater_stops(self):
        os.remove(os.path.join(self.seed, U.SELF_REL))
        self.commit_main("drop updater")
        rc, _, err = self.run_main("--preview")
        self.assertEqual(rc, U.EXIT_STOP)
        self.assertIn("main has no scripts/update_installed.py", err)

    def test_blob_id_is_gits(self):
        p = os.path.join(self.seed, U.SELF_REL)
        self.assertEqual(U.blob_id(Path(p).read_bytes()), sh(self.seed, "hash-object", p))

    def test_without_no_site_the_script_stops(self):
        d = tempfile.mkdtemp(prefix="update-installed-nosite-")
        self.addCleanup(shutil.rmtree, d, True)
        shutil.copy(ROOT / "scripts" / "update_installed.py", d)
        env = {k: v for k, v in CLEAN_ENV.items() if not k.startswith("PYTHON")}
        r = subprocess.run([sys.executable, "-I", os.path.join(d, "update_installed.py"), "--help"],
                           capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, U.EXIT_USAGE)
        self.assertIn("-I -S", r.stderr)


class Export(Fixture):
    """F6: the export accepts only regular files and folders, and every object is re-hashed on the real call path."""

    def fetch(self):
        d = Path(tempfile.mkdtemp(prefix="fetch-", dir=self.t))
        repo, _ = U.fetch_main(d, self.home)
        return repo

    def test_a_symlink_or_gitlink_in_the_tree_stops_the_export(self):
        os.symlink("a.py", os.path.join(self.seed, "harness", "hooks", "link.py"))
        sym = self.commit_main("symlink")
        repo = self.fetch()
        with self.assertRaises(U.Stop) as cm:
            U.export_commit(repo, self.home, sym, Path(self.t, "exp-sym"))
        self.assertIn("not a regular file or folder", str(cm.exception))
        os.remove(os.path.join(self.seed, "harness", "hooks", "link.py"))
        sh(self.seed, "add", "-A")
        sh(self.seed, "update-index", "--add", "--cacheinfo", "160000,%s,sub" % self.main_sha)
        sh(self.seed, "commit", "-qm", "gitlink")
        sh(self.seed, "push", "-q", self.origin, "HEAD:refs/heads/main")
        gl = sh(self.seed, "rev-parse", "HEAD")
        repo = self.fetch()
        with self.assertRaises(U.Stop) as cm:
            U.export_commit(repo, self.home, gl, Path(self.t, "exp-gl"))
        self.assertIn("mode 160000", str(cm.exception))

    def test_an_unsafe_name_in_a_tree_stops_the_export(self):
        repo = self.fetch()
        blob = U.git(repo, ["hash-object", "-w", "--stdin"], self.home, data=b"x\n").stdout.decode().strip()
        bad = b"100644 ..\0" + bytes.fromhex(blob)
        tree = U.git(repo, ["hash-object", "-t", "tree", "-w", "--literally", "--stdin"], self.home,
                     data=bad).stdout.decode().strip()
        commit_body = ("tree %s\nauthor t <t@x> 0 +0000\ncommitter t <t@x> 0 +0000\n\nbad\n" % tree).encode()
        commit = U.git(repo, ["hash-object", "-t", "commit", "-w", "--stdin"], self.home,
                       data=commit_body).stdout.decode().strip()
        with self.assertRaises(U.Stop) as cm:
            U.export_commit(repo, self.home, commit, Path(self.t, "exp-bad"))
        self.assertIn("unsafe path entry", str(cm.exception))

    def literal_commit(self, repo, tree_body):
        tree = U.git(repo, ["hash-object", "-t", "tree", "-w", "--literally", "--stdin"], self.home,
                     data=tree_body).stdout.decode().strip()
        body = ("tree %s\nauthor t <t@x> 0 +0000\ncommitter t <t@x> 0 +0000\n\nx\n" % tree).encode()
        return U.git(repo, ["hash-object", "-t", "commit", "-w", "--stdin"], self.home, data=body).stdout.decode().strip()

    def test_two_entries_that_land_on_one_path_stop_the_export_without_a_traceback(self):
        """R5 F7: on case-insensitive APFS `A.py` and `a.py` are one path; the second write fails. Two entries with the
        same name produce that failure on every file system, for a file and for a folder."""
        repo = self.fetch()
        blob = U.git(repo, ["hash-object", "-w", "--stdin"], self.home, data=b"x\n").stdout.decode().strip()
        entry = b"100644 a.py\0" + bytes.fromhex(blob)
        sub = U.git(repo, ["hash-object", "-t", "tree", "-w", "--stdin"], self.home, data=entry).stdout.decode().strip()
        folder = b"40000 d\0" + bytes.fromhex(sub)
        for name, body in (("file", entry + entry), ("folder", folder + folder)):
            with self.subTest(name):
                with self.assertRaises(U.Stop) as cm:
                    U.export_commit(repo, self.home, self.literal_commit(repo, body), Path(self.t, "exp-dup-" + name))
                self.assertIn("could not export", str(cm.exception))
                self.assertIn("nothing was installed", str(cm.exception))

    def test_a_corrupt_object_on_the_real_read_path_stops_the_export(self):
        repo = self.fetch()
        real = U.git

        def corrupt(repo_, args, home, **kw):
            done = real(repo_, args, home, **kw)
            if args[:2] == ["cat-file", "--batch"]:
                done = subprocess.CompletedProcess(done.args, 0, done.stdout.replace(b"print(", b"PRINT("), b"")
            return done
        with mock.patch.object(U, "git", corrupt):
            with self.assertRaises(U.Stop) as cm:
                U.export_commit(repo, self.home, self.main_sha, Path(self.t, "exp-blob"))
        self.assertIn("does not hash to its own id", str(cm.exception))

        def corrupt_tree(repo_, args, home, **kw):
            done = real(repo_, args, home, **kw)
            if args[:2] == ["cat-file", "tree"]:
                done = subprocess.CompletedProcess(done.args, 0, done.stdout.replace(b"install.py", b"instalx.py"), b"")
            return done
        with mock.patch.object(U, "git", corrupt_tree):
            with self.assertRaises(U.Stop) as cm:
                U.export_commit(repo, self.home, self.main_sha, Path(self.t, "exp-tree"))
        self.assertIn("does not hash to its own id", str(cm.exception))


class SkillsInFolders(Fixture):
    """F1: a nested skill goes through the whole flow, preview and real run."""
    SKILLS = ("sk/SKILL.md", "sk/scan.py")

    def test_a_nested_skill_is_previewed_installed_and_verified(self):
        rc, out, err = self.run_main("--preview", "--no-remote")
        self.assertEqual(rc, U.EXIT_OK, err)
        self.assertIn("skills/sk/SKILL.md", out)
        self.assertIn("skills/sk/scan.py", out)
        rc, out, err = self.run_main("--no-remote")
        self.assertEqual(rc, U.EXIT_OK, err)
        self.assertEqual(Path(self.home, ".claude", "skills", "sk", "SKILL.md").read_text(), "skill sk/SKILL.md\n")


class TamperedExport(Fixture):
    """F5: bytes verified at export are not trusted again after the wait at the prompt."""

    def export_dir(self):
        runs = list(Path(self.home, ".agent-harness", "update-cache").glob("run-*"))
        self.assertEqual(len(runs), 1)
        return runs[0] / "export"

    def tamper_during_prompt(self, change):
        """Run a real Mac update; `change(export)` runs while the person is at the prompt. Returns (rc, err)."""
        def reader(prompt):
            change(self.export_dir())
            return self.main_sha[:12]
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()) as err:
            rc = U.main(["--no-remote"], runner=self.runner, reader=reader, environ=CLEAN_ENV, home=self.home)
        return rc, err.getvalue()

    def assertNothingRan(self, rc, err):
        self.assertEqual(rc, U.EXIT_STOP)
        self.assertIn("the export changed after it was verified", err)
        self.assertFalse([a for a, _ in self.calls if any(str(x).endswith("install.py") for x in a)],
                         "install.py never started")
        self.assertFalse(Path(self.home, ".claude", "hooks", "c.py").exists(), "nothing was installed")

    def test_install_py_changed_during_the_prompt_is_never_run(self):
        marker = os.path.join(self.t, "tampered-ran")
        rc, err = self.tamper_during_prompt(
            lambda e: Path(e, "install.py").write_text("open(%r, 'w').write('x')\n" % marker))
        self.assertNothingRan(rc, err)
        self.assertFalse(os.path.exists(marker))

    def test_a_harness_file_changed_during_the_prompt_stops_before_install_py_starts(self):
        """R5 F1: at 8bc05736 this installed the tampered c.py and only noticed afterwards."""
        rc, err = self.tamper_during_prompt(lambda e: Path(e, "harness", "hooks", "c.py").write_text("tampered\n"))
        self.assertNothingRan(rc, err)
        self.assertIn("harness/hooks/c.py", err)

    def test_a_module_planted_next_to_install_py_never_runs(self):
        """R5 F1: the export folder is first on install.py's import path; a planted json.py would replace the stdlib."""
        marker = os.path.join(self.t, "planted-ran")
        for planted in ("json.py", "__pycache__/json.cpython-39.pyc", "harness/hooks/extra.py"):
            with self.subTest(planted=planted):
                self.calls.clear()
                rc, err = self.tamper_during_prompt(lambda e: (Path(e, planted).parent.mkdir(exist_ok=True),
                                                               Path(e, planted).write_text(
                                                                   "open(%r, 'w').write('x')\n" % marker)))
                self.assertNothingRan(rc, err)
                self.assertFalse(os.path.exists(marker))

    def test_a_symlink_hard_link_extra_folder_or_missing_file_in_the_export_stops(self):
        """A symlink or a hard link to a file OUTSIDE the export with the very same bytes passes a digest check, but its
        target can be changed after the walk; only a plain file with one link is the export's own."""
        outside = Path(self.t, "same-bytes-c.py")

        def swap(link):
            def change(e):
                c = Path(e, "harness", "hooks", "c.py")
                outside.write_bytes(c.read_bytes())
                os.remove(c)
                link(outside, c)
            return change
        for name, change in (("symlink to identical bytes", swap(os.symlink)),
                             ("hard link to identical bytes", swap(os.link)),
                             ("extra folder", lambda e: os.mkdir(Path(e, "harness", "extra"))),
                             ("missing file", lambda e: os.remove(Path(e, "harness", "hooks", "c.py")))):
            with self.subTest(name):
                self.calls.clear()
                rc, err = self.tamper_during_prompt(change)
                self.assertNothingRan(rc, err)
                self.assertIn("harness/", err)

    def test_verify_export_accepts_the_untouched_export(self):
        repo, _ = U.fetch_main(Path(self.t), self.home)
        d = Path(self.t, "exp-ok")
        _, digests = U.export_commit(repo, self.home, self.main_sha, d)
        U.verify_export(d, digests)              # positive control: no Stop
        with self.assertRaises(U.Stop):
            U.verify_export(d, dict(digests, **{"harness/hooks/zz.py": "0" * 64}))   # a commit file is missing


class OpenRuns(Fixture):
    """R5 F3: an unfinished run on a host stops the whole update before anything is installed anywhere."""
    OPEN = [{"event": "start", "run": "ins-0123456789ab", "host": "t2-dev", "kind": "install"},
            {"event": "result", "run": "ins-0123456789ab", "host": "t2-dev", "kind": "install", "result": "unknown"}]

    def write_audit(self, rows):
        audit = Path(self.home, ".agent-harness", "install-audit.jsonl")
        audit.parent.mkdir(parents=True, exist_ok=True)
        audit.write_text("".join(json.dumps(r) + "\n" for r in rows))

    def test_an_open_run_stops_a_preview_and_a_real_run_before_any_dry_run_or_install(self):
        self.write_audit(self.OPEN)
        before = self.snapshot()
        for args in (["--preview"], ["--ticket", "GoodQA goodqa#1"]):
            self.calls.clear()
            rc, out, err = self.run_main(*args)
            self.assertEqual(rc, U.EXIT_STOP, args)
            self.assertIn("unfinished install run; nothing was installed on this Mac or any host", err)
            self.assertIn("--host t2-dev --resume ins-0123456789ab", err)
            self.assertIn("--host t2-dev --rollback ins-0123456789ab", err)
            self.assertEqual(self.calls, [], "no dry run, no doctor, no install.py")
        self.assertEqual(self.snapshot(), before, "the Mac is untouched")
        rc, _, err = self.run_main("--no-remote")
        self.assertEqual(rc, U.EXIT_OK, "a Mac-only update does not depend on a host's open run: " + err)

    def test_a_run_opened_while_waiting_at_the_prompt_stops_before_the_mac_install(self):
        def reader(prompt):
            self.write_audit(self.OPEN)
            return self.main_sha[:12]
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()) as err:
            rc = U.main(["--ticket", "GoodQA goodqa#1"], runner=self.runner, reader=reader, environ=CLEAN_ENV,
                        home=self.home)
        self.assertEqual(rc, U.EXIT_STOP)
        self.assertIn("unfinished install run", err.getvalue())
        self.assertFalse(Path(self.home, ".claude", "hooks", "c.py").exists())

    def test_an_unreadable_audit_stops(self):
        audit = Path(self.home, ".agent-harness", "install-audit.jsonl")
        audit.parent.mkdir(parents=True)
        audit.mkdir()                                   # reading a folder fails
        rc, _, err = self.run_main("--preview")
        self.assertEqual(rc, U.EXIT_STOP)
        self.assertIn("cannot be read", err)


class RealRemoteAnswers(TAI.Base):
    """R5 F2: the host path fed by the REAL answers, not by answers the author wrote. `ah install-files` runs in-process
    through ah.main with the argv the updater builds (so ah's own parser reads it), ah_install runs its real
    REMOTE_SCRIPT through a fake ssh against a temporary host home (test_ah_install.Base), and the real audit file is
    what the updater's open-run rule reads. The doctor runs for real with `--ssh`, its ssh transport pointed at the
    same temporary host home. Ticket comments are captured, never posted."""

    def setUp(self):
        super().setUp()
        import ah_install
        import ah
        self.ai, self.ah = ah_install, ah
        self.posted = []
        real_remote = ah_install.Remote
        for target, attr, value in (
                (ah_install, "post_comment", lambda ticket, text, poster: self.posted.append((ticket, text)) or True),
                (ah_install, "Remote", lambda host, runner: real_remote(host, self.runner))):
            p = mock.patch.object(target, attr, value)
            p.start()
            self.addCleanup(p.stop)
        self.home = str(self.mac)
        Path(self.home, ".claude", "hooks").mkdir(parents=True)
        shutil.copy(TAI.HOOKS / "doctor.py", Path(self.home, ".claude", "hooks", "doctor.py"))
        self.answers, self.doctor_answers = [], []     # every real answer, in order

    def ah_runner(self, argv, **kw):
        """The updater's `ah install-files` call, run by the real ah.main in this process. ah's home is the AH_HOME of
        the environment the caller passed (the updater always passes one); a command a person types gets theirs."""
        self.assertEqual(argv[:4], [sys.executable, "-I", str(Path(self.home, ".claude", "hooks", "ah.py")),
                                    "install-files"])
        ah_home = (kw.get("env") or {}).get("AH_HOME", self.home)
        out = io.StringIO()
        with mock.patch.dict(os.environ, {"AH_HOME": ah_home}), redirect_stdout(out):
            rc = self.ah.main(argv[3:])
        done = subprocess.CompletedProcess(argv, rc, out.getvalue(), "")
        self.answers.append(done)
        return done

    def fixture_answer(self, argv, remote, unregistered=()):
        """What the Fixture's hand-built stand-in for `ah install-files` answers to the same argv."""
        fake = types.SimpleNamespace(calls=[], remote=dict(remote), unregistered=list(unregistered), doctor=[],
                                     host_doctor=[])
        return Fixture.runner(fake, argv)

    def assertFixtureHasTheRealShape(self, real, fake):
        """Fixture audit, items 1 and 3: every field the updater reads from an answer (files.<name>.action, run,
        unregistered, the exit code) has the same type in the stand-in as in the real answer, the stand-in's actions are
        the real installer's actions, and its run ids are ids the real ah accepts."""
        r, f = json.loads(real.stdout), json.loads(fake.stdout)
        self.assertEqual((real.returncode, fake.returncode), (0, 0))
        self.assertEqual(sorted(r["files"]), sorted(f["files"]))
        actions = {"already_current", "new", "replaced"}           # = ah_install._plan_for
        for name in r["files"]:
            self.assertIn(r["files"][name]["action"], actions)
            self.assertIn(f["files"][name]["action"], actions)
        self.assertTrue(self.ai.RUN_RE.fullmatch(r["run"]) and self.ai.RUN_RE.fullmatch(f["run"]), (r["run"], f["run"]))
        self.assertEqual("unregistered" in r, "unregistered" in f)
        if "unregistered" in r:
            self.assertTrue(all(isinstance(x, str) for x in r["unregistered"] + f["unregistered"]))
        self.assertEqual(U.ah_call(lambda *a, **k: fake, fake.args, "fake", self.home)["files"].keys(),
                         U.ah_call(lambda *a, **k: real, real.args, "real", self.home)["files"].keys())

    def test_a_real_dry_run_and_install_parse_and_finish_current(self):
        names = list(TAI.NAMES)
        self.assertEqual(U.remote_changes(self.home, "t2-dev", self.c1, names, self.ah_runner),
                         ["doctor.py", "ah.py", "extra.py", "command_guard.py"])
        dry = self.answers[-1]
        self.assertEqual(U.remote_install(self.home, "t2-dev", self.c1, ["ah.py", "extra.py"], TAI.TICKET,
                                          self.ah_runner), [])
        installed = self.answers[-1]
        self.assertEqual(U.remote_changes(self.home, "t2-dev", self.c1, ["ah.py", "extra.py"], self.ah_runner), [])
        self.assertEqual(self.live("ah.py"), TAI.sha(TAI.Path(self.work, "harness", "hooks", "ah.py").read_bytes()))
        self.assertTrue(self.posted, "the real install wrote its ticket comment (captured)")
        self.assertEqual(U.unfinished_runs(self.home, "t2-dev"), self.ai.unfinished_runs(self.home, "t2-dev"))
        self.assertFixtureHasTheRealShape(dry, self.fixture_answer(dry.args, {n: "replaced" for n in names}))
        self.assertFixtureHasTheRealShape(installed, self.fixture_answer(installed.args, {}))

    def test_a_real_install_that_reports_unregistered_hooks(self):
        ref = TAI.SelfTest.manifest_commit(self, [TAI.SelfTest.ROW])
        got = U.remote_install(self.home, "t2-dev", ref, ["hooks_manifest.json", "extra.py"], TAI.TICKET,
                               self.ah_runner)
        self.assertEqual(got, ["newhook:stop"])
        real = self.answers[-1]
        self.assertFixtureHasTheRealShape(real, self.fixture_answer(real.args, {}, ["newhook:stop"]))

    def test_downgrades_for_a_host_equal_the_remote_installers_older_ref_refusal(self):
        """Fixture audit item 6: main changes ah.py after c1. The updater's host downgrade rule must name exactly the
        files for which the real ah_install.fetch_source refuses c1 with older_ref (the refusal a dry run would get)."""
        side = Path(self.tmp, "side-newer")
        TAI.git(self.tmp, "clone", "-q", str(self.origin), str(side))
        (side / "harness" / "hooks" / "ah.py").write_bytes(b"# newest\n")
        TAI.git(side, "add", "-A")
        TAI.git(side, "commit", "-q", "-m", "newer ah.py")
        TAI.git(side, "push", "-q", "origin", "main")
        with mock.patch.object(U, "CANONICAL_URL", "file://" + str(self.origin)), mock.patch.object(U, "ALLOW_FILE", True):
            run = U.new_run_dir(self.home)
            try:
                repo, main_sha = U.fetch_main(run, self.home)
                mine = U.downgrades(repo, self.home, self.c1, main_sha, ["hooks/" + n for n in TAI.NAMES])
            finally:
                shutil.rmtree(run, ignore_errors=True)
        refused = []
        for n in TAI.NAMES:
            try:
                self.ai.fetch_source(self.c1, [n], self.home)
            except self.ai.InstallError as e:
                self.assertEqual(e.code, "older_ref", str(e))
                refused.append("hooks/" + n)
        self.assertEqual(mine, refused)
        self.assertEqual(mine, ["hooks/ah.py"], "the control: one file is newer on main")

    def unknown_run(self):
        """A real `unknown`: the host ran the commit step and the answer was lost (ah exits 5 and prints two JSON
        documents)."""
        self.inject = ("commit", 1, "after")
        with self.assertRaises(U.Stop) as cm:
            U.remote_install(self.home, "t2-dev", self.c1, ["ah.py", "extra.py"], TAI.TICKET, self.ah_runner)
        self.inject = None
        open_runs = self.ai.unfinished_runs(self.home, "t2-dev")
        self.assertEqual(len(open_runs), 1)
        return open_runs[0], str(cm.exception)

    def test_a_real_run_ending_unknown_gives_guidance_that_real_ah_accepts_and_that_clears_the_host(self):
        run, msg = self.unknown_run()
        self.assertIn("failed with exit 5", msg)
        self.assertEqual(U.unfinished_runs(self.home, "t2-dev"), [run], "the mirror reads the real audit the same way")
        resume = [ln.strip() for ln in msg.splitlines() if "--resume" in ln]
        self.assertEqual(len(resume), 1, msg)
        argv = shlex_split(resume[0])
        self.assertEqual(argv[:4], ["python3", "-I", "~/.claude/hooks/ah.py", "install-files"])
        self.ah.build_parser().parse_args(argv[3:])          # ah's own parser takes the printed line
        rc = self.ah_runner([sys.executable, "-I", str(Path(self.home, ".claude", "hooks", "ah.py"))] + argv[3:]).returncode
        self.assertEqual(rc, 0)
        self.assertEqual(self.ai.unfinished_runs(self.home, "t2-dev"), [])
        self.assertEqual(U.unfinished_runs(self.home, "t2-dev"), [])
        U.check_no_open_runs(self.home, ["t2-dev"], TAI.TICKET)    # passes once the host is clear

    def test_the_real_refusal_for_an_unfinished_run_and_the_planning_check_agree(self):
        run, _ = self.unknown_run()
        with self.assertRaises(U.Stop) as planning:
            U.check_no_open_runs(self.home, ["t2-dev"], TAI.TICKET)
        self.assertIn("--host t2-dev --rollback %s" % run, str(planning.exception))
        with self.assertRaises(U.Stop) as cm:               # what the remote installer itself answers
            U.remote_install(self.home, "t2-dev", self.c1, ["extra.py"], TAI.TICKET, self.ah_runner)
        self.assertIn("unfinished run", str(cm.exception))
        rollback = [ln.strip() for ln in str(planning.exception).splitlines() if "--rollback" in ln][0]
        argv = shlex_split(rollback)
        rc = self.ah_runner([sys.executable, "-I", str(Path(self.home, ".claude", "hooks", "ah.py"))] + argv[3:]).returncode
        self.assertEqual(rc, 0)
        self.assertEqual(self.ai.unfinished_runs(self.home, "t2-dev"), [])

    def fake_ssh(self, argv, **kw):
        """doctor's ssh transport, pointed at the temporary host home (the remote half runs for real in sh)."""
        self.assertEqual(argv[0], "ssh")
        rest = argv[argv.index("--") + 2:]
        return subprocess.run(["sh", "-c", " ".join(rest)], env=self.env(), capture_output=True,
                              text=kw.get("text", False), timeout=60)

    def doctor_runner(self, argv, **kw):
        import doctor
        self.assertEqual(argv[-2:], ["--ssh", "t2-dev"])
        out = io.StringIO()
        fake = mock.Mock(run=self.fake_ssh, TimeoutExpired=subprocess.TimeoutExpired)
        with mock.patch.object(doctor, "subprocess", fake), redirect_stdout(out), redirect_stderr(io.StringIO()):
            rc = doctor.main(argv[3:])
        done = subprocess.CompletedProcess(argv, rc, out.getvalue(), "")
        self.doctor_answers.append(done)
        return done

    def assertFixtureDoctorAgrees(self, real):
        """Fixture audit item 7: the Fixture's stand-in doctor, given the real rows, answers the real exit code."""
        rows = [{"id": i["id"], "state": i["state"], "required": i["required"]} for i in json.loads(real.stdout)]
        fake = types.SimpleNamespace(calls=[], doctor=rows, host_doctor=rows)
        self.assertEqual(Fixture.runner(fake, real.args).returncode, real.returncode)

    def test_the_real_doctor_over_ssh_reports_a_host_with_nothing_registered(self):
        import doctor
        self.assertEqual((U.WIRED, U.UNREGISTERED), (doctor.WIRED, doctor.MISSING))
        self.assertIn(doctor.PENDING, U.NOT_REGISTERED_BEFORE)
        rows = U.doctor_check(self.doctor_runner, self.home, "t2-dev")
        self.assertIsNotNone(rows, "the real doctor's answer is accepted (exit code agrees with its rows)")
        self.assertEqual(self.doctor_answers[-1].returncode, 1)
        required = sorted(i for i, (state, req) in rows.items() if req)
        self.assertTrue(required)
        self.assertEqual({rows[i][0] for i in required}, {doctor.MISSING}, "settings.json {} registers nothing")
        lost, new, old = U.registration(None, rows, "t2-dev")
        self.assertEqual((lost, new, old), ([], required, []))
        self.assertFixtureDoctorAgrees(self.doctor_answers[-1])

    def test_the_real_doctor_over_ssh_answers_wired_and_a_broken_hook_stops(self):
        """Fixture audit item 7: the real doctor answering WIRED with exit 0 (the host's settings.json is what a full
        install.py writes, from install.merged_settings), then a real SCRIPT_MISSING after one script is removed."""
        import doctor
        sys.path.insert(0, str(ROOT))
        try:
            import install
        finally:
            sys.path.remove(str(ROOT))
        claude = self.host_home / ".claude"
        (claude / "settings.json").write_text(json.dumps(install.merged_settings({}, claude)))
        rows = U.doctor_check(self.doctor_runner, self.home, "t2-dev")
        self.assertIsNotNone(rows)
        self.assertEqual(self.doctor_answers[-1].returncode, 0)
        required = sorted(i for i, (state, req) in rows.items() if req)
        self.assertTrue(required)
        self.assertEqual({rows[i][0] for i in required}, {doctor.WIRED})
        self.assertEqual(U.registration(None, rows, "t2-dev"), ([], [], []))
        self.assertFixtureDoctorAgrees(self.doctor_answers[-1])
        manifest = json.loads((TAI.HOOKS / "hooks_manifest.json").read_text())
        victim = next(r for r in manifest["hooks"] if r["id"] == required[0])["script"]
        os.remove(self.hooks / victim)
        rows = U.doctor_check(self.doctor_runner, self.home, "t2-dev")
        self.assertIsNotNone(rows)
        self.assertEqual(rows[required[0]][0], doctor.SCRIPT_MISSING)
        self.assertEqual(self.doctor_answers[-1].returncode, 1)
        with self.assertRaises(U.Stop) as cm:
            U.registration(None, rows, "t2-dev")
        self.assertIn("not working (SCRIPT_MISSING)", str(cm.exception))
        self.assertFixtureDoctorAgrees(self.doctor_answers[-1])


def shlex_split(line):
    import shlex
    return shlex.split(line)


def full_checkout(root=ROOT):
    """R5 F6: a shallow clone (CI's default checkout, a review snapshot) cannot be pushed into an empty repository."""
    if not (Path(root) / ".git").exists():
        return False
    r = subprocess.run(["git", "-C", str(root), "rev-parse", "--is-shallow-repository"], capture_output=True, text=True)
    return r.returncode == 0 and r.stdout.strip() == "false"


class RealTreeSkip(Fixture):
    def test_a_shallow_clone_skips_the_real_tree_run_and_a_full_clone_does_not(self):
        """R5 F6: at 8bc05736 RealTree ran in a shallow clone and failed in setUp (git refuses to push from it)."""
        self.commit_main("second", {"harness/hooks/a.py": "print('a2')\n"})
        shallow, full = os.path.join(self.t, "shallow"), os.path.join(self.t, "full")
        sh(self.t, "clone", "-q", "--depth", "1", "file://" + self.origin, shallow)
        sh(self.t, "clone", "-q", self.origin, full)
        self.assertEqual(sh(shallow, "rev-parse", "--is-shallow-repository"), "true", "the control is really shallow")
        self.assertFalse(full_checkout(Path(shallow)))
        self.assertTrue(full_checkout(Path(full)))
        self.assertFalse(full_checkout(Path(self.t)), "no .git at all")


@unittest.skipUnless(full_checkout(), "needs a full (not shallow) git checkout of the repository")
class RealTree(unittest.TestCase):
    """End to end against the repository's own tree: its HEAD stands in for main (a local bare repository), a
    temporary home stands in for ~, and the repository's own install.py and doctor.py run for real. No remote host and
    no real home is touched. The packet carries this test's printed output."""

    def setUp(self):
        # realpath: install.py writes resolved paths into settings.json and the doctor compares them with --hooks-dir
        # (macOS temp folders live under the /var -> /private/var symlink)
        self.t = os.path.realpath(tempfile.mkdtemp(prefix="update-installed-real-"))
        self.addCleanup(shutil.rmtree, self.t, True)
        head = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True, text=True,
                              check=True).stdout.strip()
        dirty = subprocess.run(["git", "-C", str(ROOT), "status", "--porcelain", "--untracked-files=no", "--",
                                "scripts", "harness", "install.py"], capture_output=True, text=True, check=True).stdout
        self.assertEqual(dirty, "", "the end-to-end test runs the checkout's HEAD; commit first")
        self.origin = os.path.join(self.t, "main.git")
        subprocess.run(["git", "init", "-q", "--bare", self.origin], check=True)
        subprocess.run(["git", "-C", str(ROOT), "push", "-q", self.origin, "%s:refs/heads/main" % head], check=True,
                       capture_output=True)
        self.head = head
        self.home = os.path.join(self.t, "home")
        os.makedirs(self.home)
        mock.patch.object(U, "CANONICAL_URL", self.origin).start()
        mock.patch.object(U, "ALLOW_FILE", True).start()
        self.addCleanup(mock.patch.stopall)

    def test_a_tampered_log_backup_install_in_the_export_never_runs(self):
        """R5 F1: install.py imports the export's own log_backup_install.py on the --hooks-only path; a copy changed
        during the prompt must never run (the review: it ran unverified at 8bc05736)."""
        marker = os.path.join(self.t, "log-backup-install-ran")

        def reader(prompt):
            exp = list(Path(self.home, ".agent-harness", "update-cache").glob("run-*/export"))[0]
            Path(exp, "log_backup_install.py").write_text("open(%r, 'w').write('x')\n" % marker)
            return self.head[:12]
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = U.main(["--no-remote"], reader=reader, environ=CLEAN_ENV, home=self.home)
        self.assertEqual(rc, U.EXIT_STOP, err.getvalue())
        self.assertIn("the export changed after it was verified (log_backup_install.py)", err.getvalue())
        self.assertFalse(os.path.exists(marker))
        self.assertFalse(Path(self.home, ".claude", "hooks").exists(), "nothing was installed")

    def test_preview_then_real_run_into_a_temporary_home(self):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = U.main(["--preview", "--no-remote"], environ=CLEAN_ENV, home=self.home)
        print("\n--- real-tree preview (temp home) ---\n" + out.getvalue() + err.getvalue())
        self.assertEqual(rc, U.EXIT_OK, err.getvalue())
        self.assertIn("Commit %s" % self.head, out.getvalue())
        self.assertIn("skills/check-dropped-workstreams/SKILL.md", out.getvalue())
        self.assertFalse(Path(self.home, ".claude").exists(), "a preview writes nothing under ~/.claude")
        Path(self.home, ".claude", "hooks").mkdir(parents=True)
        Path(self.home, ".claude", "hooks", "ah.py").write_bytes(b"# an older ah.py\n")   # install.py must back it up
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = U.main(["--no-remote"], reader=lambda p: self.head[:12], environ=CLEAN_ENV, home=self.home)
        print("--- real-tree run (temp home, no settings.json) ---\n" + out.getvalue()[-800:] + err.getvalue()[-800:])
        # The real doctor exits 2 when it cannot read settings.json, so registration is not proven: STOP, not Done.
        self.assertEqual(rc, U.EXIT_STOP, err.getvalue())
        self.assertIn("registration is not proven", err.getvalue())
        self.assertNotIn("Done.", out.getvalue())
        for rel in ("hooks/doctor.py", "hooks/command_guard.py", "skills/check-dropped-workstreams/SKILL.md"):
            self.assertTrue(Path(self.home, ".claude", rel).is_file(), rel)
        # The folder every STOP message names (U.BACKUPS) is where the real install.py put the file it replaced.
        self.assertIn(U.BACKUPS, err.getvalue())
        saved = list(Path(self.home, U.BACKUPS[2:]).glob("*/hooks/ah.py"))
        self.assertEqual([p.read_bytes() for p in saved], [b"# an older ah.py\n"])
        Path(self.home, ".claude", "settings.json").write_text("{}\n")
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = U.main(["--no-remote"], reader=lambda p: self.fail("nothing to install asks"),
                        environ=CLEAN_ENV, home=self.home)
        print("--- real-tree rerun (settings.json with no hooks) ---\n" + out.getvalue()[-800:] + err.getvalue()[-800:])
        self.assertEqual(rc, U.EXIT_REGISTER, err.getvalue())
        self.assertIn("Mac: 0 file(s) differ", out.getvalue())
        self.assertIn("Mac (already before this run): declared but not registered", out.getvalue())
        self.assertIn("NOT fully active", out.getvalue())
        # The settings a full install.py writes (its own merged_settings): the real doctor answers WIRED, exit 0.
        sys.path.insert(0, str(ROOT))
        try:
            import install
        finally:
            sys.path.remove(str(ROOT))
        claude = Path(self.home, ".claude")
        claude.joinpath("settings.json").write_text(json.dumps(install.merged_settings({}, claude), indent=2) + "\n")
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = U.main(["--no-remote"], reader=lambda p: self.fail("nothing to install asks"),
                        environ=CLEAN_ENV, home=self.home)
        print("--- real-tree rerun (settings.json as install.py writes it) ---\n" + out.getvalue()[-800:]
              + err.getvalue()[-800:])
        self.assertEqual(rc, U.EXIT_OK, err.getvalue())
        self.assertIn("Nothing to install: everything listed already matches %s; the doctor reports every required "
                      "hook wired on the Mac." % self.head, out.getvalue())


if __name__ == "__main__":
    unittest.main()
