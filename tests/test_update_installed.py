"""scripts/update_installed.py: the user-run updater (goodqa#16947). Hermetic: a local bare repository stands in for
the canonical URL, a temp home for ~, and a fake runner for install.py and `ah install-files`."""
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import update_installed as U  # noqa: E402

GIT = ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "init.defaultBranch=main",
       "-c", "commit.gpgsign=false"]


def sh(cwd, *args):
    return subprocess.run(GIT + list(args), cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


class Fixture(unittest.TestCase):
    HOOKS = ("a.py", "b.py", "c.py")

    def setUp(self):
        self.t = tempfile.mkdtemp(prefix="update-installed-")
        self.origin = os.path.join(self.t, "origin.git")
        seed = os.path.join(self.t, "seed")
        sh(self.t, "init", "-q", "--bare", self.origin)
        sh(self.t, "init", "-q", seed)
        Path(seed, "install.py").write_text("AGENTS = ('x.md',)\nHOOKS = %r\nTOOLS = ()\nSKILLS = ()\n" % (self.HOOKS,))
        for d in ("hooks", "agents"):
            os.makedirs(os.path.join(seed, "harness", d))
        for n in self.HOOKS:
            Path(seed, "harness", "hooks", n).write_text("print(%r)\n" % n)
        Path(seed, "harness", "agents", "x.md").write_text("agent\n")
        sh(seed, "add", "-A")
        sh(seed, "commit", "-qm", "seed")
        sh(seed, "push", "-q", self.origin, "HEAD:refs/heads/main")
        self.main_sha = sh(seed, "rev-parse", "HEAD")
        sh(seed, "checkout", "-qb", "side")
        Path(seed, "harness", "hooks", "a.py").write_text("print('side')\n")
        sh(seed, "commit", "-qam", "side")
        sh(seed, "push", "-q", self.origin, "HEAD:refs/heads/side")
        self.side_sha = sh(seed, "rev-parse", "HEAD")
        self.clone = os.path.join(self.t, "clone")
        sh(self.t, "clone", "-q", self.origin, self.clone)
        sh(self.clone, "fetch", "-q", "origin", "side")
        self.home = os.path.join(self.t, "home")
        hooks = Path(self.home, ".claude", "hooks")
        agents = Path(self.home, ".claude", "agents")
        hooks.mkdir(parents=True)
        agents.mkdir(parents=True)
        (hooks / "a.py").write_text("print('a.py')\n")       # current
        (hooks / "b.py").write_text("print('old')\n")        # differs; c.py is missing
        (agents / "x.md").write_text("agent\n")              # current
        mock.patch.object(U, "CANONICAL_URL", self.origin).start()
        self.addCleanup(mock.patch.stopall)
        self.calls = []
        self.remote = {"a.py": "already_current", "b.py": "replaced", "c.py": "new"}

    def runner(self, argv, **kw):
        self.calls.append((argv, kw))
        if "install-files" in argv:
            names = [argv[i + 1] for i, x in enumerate(argv) if x == "--file"]
            if "--dry-run" not in argv:
                for n in names:
                    self.remote[n] = "already_current"
            out = {"result": "dry_run" if "--dry-run" in argv else "installed",
                   "files": {n: {"action": self.remote.get(n, "already_current")} for n in names}}
            return subprocess.CompletedProcess(argv, 0, json.dumps(out), "")
        if "install.py" in argv:                          # what install.py --apply --hooks-only does to the home
            for folder in ("hooks", "agents"):
                src = Path(kw["cwd"], "harness", folder)
                for f in src.iterdir():
                    Path(self.home, ".claude", folder, f.name).write_bytes(f.read_bytes())
            return subprocess.CompletedProcess(argv, 0, "installed", "")
        raise AssertionError("unexpected command %r" % (argv,))

    def run_main(self, *args):
        err, out = io.StringIO(), io.StringIO()
        with redirect_stderr(err), redirect_stdout(out):
            rc = U.main(["--clone", self.clone, "--home", self.home, *args], runner=self.runner)
        return rc, out.getvalue(), err.getvalue()

    def snapshot(self):
        """Every file of the home, and the clone's working tree (git's own folder is git's business)."""
        rows = {}
        for root in (self.home, self.clone):
            for dp, dn, fn in os.walk(root):
                dn[:] = [d for d in dn if d != ".git"]
                for f in dn + fn:
                    st = os.lstat(os.path.join(dp, f))
                    rows[os.path.join(dp, f)] = (st.st_size, st.st_mtime_ns)
        return rows


class Refusals(Fixture):
    def test_commit_not_on_main_is_refused(self):
        for extra in (["--preview"], ["--ticket", "GoodQA goodqa#1"]):
            rc, _, err = self.run_main("--commit", self.side_sha, *extra)
            self.assertEqual(rc, 1)
            self.assertIn("is not on origin/main", err)
        self.assertEqual(self.calls, [])
        self.assertEqual(Path(self.home, ".claude", "hooks", "b.py").read_text(), "print('old')\n")

    def test_dirty_clone_is_refused(self):
        Path(self.clone, "stray.txt").write_text("x")
        rc, _, err = self.run_main("--ticket", "GoodQA goodqa#1")
        self.assertEqual(rc, 1)
        self.assertIn("local changes or untracked files", err)
        os.remove(os.path.join(self.clone, "stray.txt"))
        Path(self.clone, "install.py").write_text("HOOKS = ()\n")
        rc, _, err = self.run_main("--preview")
        self.assertEqual(rc, 1)
        self.assertEqual(self.calls, [])

    def test_a_clone_of_another_repository_is_refused(self):
        sh(self.clone, "remote", "set-url", "origin", "https://example.invalid/other.git")
        rc, _, err = self.run_main("--preview")
        self.assertEqual(rc, 1)
        self.assertIn("not %s" % self.origin, err)

    def test_a_real_run_needs_a_ticket_and_a_preview_never_clones(self):
        rc, _, err = self.run_main()
        self.assertEqual(rc, 1)
        self.assertIn("--ticket", err)
        missing = os.path.join(self.t, "nowhere")
        err_io = io.StringIO()
        with redirect_stderr(err_io), redirect_stdout(io.StringIO()):
            rc = U.main(["--clone", missing, "--home", self.home, "--preview"], runner=self.runner)
        self.assertEqual(rc, 1)
        self.assertFalse(os.path.exists(missing))


class Preview(Fixture):
    def test_preview_writes_nothing(self):
        head = sh(self.clone, "rev-parse", "HEAD")
        before = self.snapshot()
        rc, out, err = self.run_main("--preview")
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(sh(self.clone, "rev-parse", "HEAD"), head)
        self.assertTrue(self.calls)
        self.assertTrue(all("--dry-run" in argv and "install.py" not in argv for argv, _ in self.calls))
        self.assertIn("Preview only", out)


class FileList(Fixture):
    def test_file_list_is_derived_from_the_installed_files(self):
        lists = U.installer_lists(self.clone, self.main_sha)
        self.assertEqual(lists["hooks"], list(self.HOOKS))
        self.assertEqual(U.local_changes(self.clone, self.main_sha, self.home, lists), ["hooks/b.py", "hooks/c.py"])
        self.assertEqual(U.remote_changes(self.home, "t2-dev", self.main_sha, lists["hooks"], self.runner),
                         ["b.py", "c.py"])
        Path(self.home, ".claude", "agents", "x.md").write_text("edited\n")
        os.remove(os.path.join(self.home, ".claude", "hooks", "a.py"))
        os.symlink(os.path.join(self.clone, "harness", "hooks", "a.py"), os.path.join(self.home, ".claude", "hooks", "a.py"))
        self.assertEqual(U.local_changes(self.clone, self.main_sha, self.home, lists),
                         ["agents/x.md", "hooks/a.py", "hooks/b.py", "hooks/c.py"])   # a symlink is never "current"

    def test_remote_batches_hold_at_most_twenty_files(self):
        names = ["h%02d.py" % i for i in range(45)]
        U.remote_changes(self.home, "t2-dev", self.main_sha, names, self.runner)
        sizes = [argv.count("--file") for argv, _ in self.calls]
        self.assertEqual(sizes, [20, 20, 5])

    def test_a_dry_run_that_fails_or_omits_a_file_stops(self):
        bad = lambda argv, **kw: subprocess.CompletedProcess(argv, 2, "", "refused")  # noqa: E731
        with self.assertRaises(U.Stop):
            U.remote_changes(self.home, "t2-dev", self.main_sha, ["a.py"], bad)
        short = lambda argv, **kw: subprocess.CompletedProcess(argv, 0, json.dumps({"files": {}}), "")  # noqa: E731
        with self.assertRaises(U.Stop):
            U.remote_changes(self.home, "t2-dev", self.main_sha, ["a.py"], short)


class RealRun(Fixture):
    def test_installs_the_mac_then_only_the_changed_remote_files_and_verifies(self):
        rc, out, err = self.run_main("--ticket", "GoodQA goodqa#1")
        self.assertEqual(rc, 0, err)
        self.assertEqual(sh(self.clone, "rev-parse", "HEAD"), self.main_sha)
        self.assertEqual(Path(self.home, ".claude", "hooks", "c.py").read_text(), "print('c.py')\n")
        install = [(a, kw) for a, kw in self.calls if "install.py" in a]
        self.assertEqual(len(install), 1)
        self.assertIn("--hooks-only", install[0][0])
        self.assertIn("--apply", install[0][0])
        self.assertEqual(install[0][1]["cwd"], self.clone)
        real = [a for a, _ in self.calls if "install-files" in a and "--dry-run" not in a]
        self.assertEqual(len(real), 1)
        self.assertEqual([real[0][i + 1] for i, x in enumerate(real[0]) if x == "--file"], ["b.py", "c.py"])
        self.assertIn("GoodQA goodqa#1", real[0])
        self.assertIn(self.main_sha, real[0])
        self.assertIn("Done. Installed commit", out)

    def test_a_remote_file_still_different_after_the_install_stops(self):
        real_runner = self.runner

        def stuck(argv, **kw):
            r = real_runner(argv, **kw)
            self.remote["c.py"] = "new"            # the host never takes c.py
            return r
        err = io.StringIO()
        with redirect_stderr(err), redirect_stdout(io.StringIO()):
            rc = U.main(["--clone", self.clone, "--home", self.home, "--ticket", "GoodQA goodqa#1"], runner=stuck)
        self.assertEqual(rc, 1)
        self.assertIn("still differ", err.getvalue())


if __name__ == "__main__":
    unittest.main()
