"""Tests for scripts/checkout_inventory.py (goodqa#16947): a read-only inventory of checkouts and work dirs.

Every test builds real git repositories in a temporary folder. The tool runs as a subprocess, the way main or the
user runs it. The safety tests carry a positive control: the same repository makes plain git do the unsafe thing, so
a pass is not vacuous.
"""
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "scripts" / "checkout_inventory.py"
sys.path.insert(0, str(ROOT / "scripts"))
import checkout_inventory as CI  # noqa: E402

COLS = ["repo", "kind", "path", "branch", "head", "exists", "locked", "prunable", "dirty", "unpushed", "merged_main",
        "upstream", "last_touched_utc", "size_mb", "note"]
ENV = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
ENV.update(GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.com", GIT_COMMITTER_NAME="t",
           GIT_COMMITTER_EMAIL="t@example.com", GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")


def sh(cwd, *args, env=None):
    return subprocess.run(["git", "-C", str(cwd), *args], capture_output=True, text=True, check=True,
                          env=env or ENV).stdout.strip()


class Base(unittest.TestCase):
    def setUp(self):
        self.t = Path(tempfile.mkdtemp(prefix="checkout-inventory-"))
        self.addCleanup(shutil.rmtree, self.t, True)
        self.origin = self.t / "origin.git"
        subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(self.origin)], check=True, env=ENV)
        self.repo = self.t / "repo"
        subprocess.run(["git", "init", "-q", "-b", "main", str(self.repo)], check=True, env=ENV)
        (self.repo / "a.txt").write_text("a\n")
        sh(self.repo, "add", "a.txt")
        sh(self.repo, "commit", "-qm", "one")
        sh(self.repo, "remote", "add", "origin", str(self.origin))
        sh(self.repo, "push", "-q", "origin", "main")
        sh(self.repo, "fetch", "-q", "origin")

    def run_tool(self, *args, env=None):
        r = subprocess.run([sys.executable, "-I", str(TOOL), *args], capture_output=True, text=True,
                           env=env or ENV, timeout=300)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout

    def rows(self, *paths, env=None):
        out = self.run_tool("repos", *map(str, paths), env=env)
        return [dict(zip(COLS, line.split("\t"))) for line in out.splitlines()]


class Rows(Base):
    def test_main_and_linked_worktree_rows(self):
        wt = self.t / "wt"
        sh(self.repo, "worktree", "add", "-q", "-b", "feature", str(wt))
        (wt / "b.txt").write_text("b\n")
        sh(wt, "add", "b.txt")
        sh(wt, "commit", "-qm", "two")
        (wt / "dirty.txt").write_text("x\n")
        rows = self.rows(self.repo, wt)
        self.assertEqual(len(rows), 2, "the linked worktree is listed once, under its main checkout")
        main, linked = rows
        self.assertEqual((main["kind"], main["branch"], main["dirty"], main["unpushed"], main["merged_main"]),
                         ("main", "main", "0", "0", "yes"))
        self.assertEqual((linked["kind"], linked["branch"], linked["dirty"], linked["unpushed"],
                          linked["merged_main"]), ("linked", "feature", "1", "1", "no"))
        self.assertEqual(Path(linked["path"]).resolve(), wt.resolve())
        self.assertIn("origin=" + str(self.origin), main["note"])
        self.assertRegex(main["note"], r"fetched=\d{4}-\d\d-\d\dT")

    def test_a_missing_worktree_folder_is_reported_not_skipped(self):
        wt = self.t / "gone"
        sh(self.repo, "worktree", "add", "-q", "-b", "gone", str(wt))
        shutil.rmtree(wt)
        linked = [r for r in self.rows(self.repo) if r["kind"] == "linked"][0]
        self.assertEqual((linked["exists"], linked["prunable"], linked["size_mb"]), ("no", "yes", "0"))

    def test_unpushed_commits_on_other_local_branches_are_counted_on_the_main_row(self):
        # Removing a whole clone deletes every local branch and tag, not only the one checked out.
        self.assertIn("local_unpushed=0", self.rows(self.repo)[0]["note"], "positive control: all pushed")
        sh(self.repo, "checkout", "-q", "-b", "side")
        (self.repo / "s.txt").write_text("s\n")
        sh(self.repo, "add", "s.txt")
        sh(self.repo, "commit", "-qm", "side only")
        sh(self.repo, "checkout", "-q", "main")
        sh(self.repo, "tag", "-a", "-m", "t", "local-tag", "side")
        main = self.rows(self.repo)[0]
        self.assertEqual(main["unpushed"], "0", "HEAD itself is pushed")
        self.assertIn("local_unpushed=1", main["note"])

    def test_stashes_are_counted_on_the_main_row(self):
        (self.repo / "a.txt").write_text("changed\n")
        sh(self.repo, "stash", "-q")
        self.assertIn("stashes=1", self.rows(self.repo)[0]["note"])


class Safety(Base):
    def arm(self):
        """Repo config that starts a program from plain git status: an fsmonitor hook and a hooks path."""
        marker = self.t / "program-ran"
        prog = self.t / "prog.sh"
        prog.write_text("#!/bin/sh\necho ran >> %s\nexit 1\n" % marker)
        prog.chmod(prog.stat().st_mode | stat.S_IXUSR)
        hooks = self.t / "hooks"
        hooks.mkdir()
        shutil.copy(prog, hooks / "post-index-change")
        sh(self.repo, "config", "core.fsmonitor", str(prog))
        sh(self.repo, "config", "core.hooksPath", str(hooks))
        return marker

    def test_repo_config_never_starts_a_program(self):
        marker = self.arm()
        subprocess.run(["git", "-C", str(self.repo), "status", "--porcelain"], capture_output=True, env=ENV)
        self.assertTrue(marker.exists(), "positive control: plain git status runs the repo's fsmonitor")
        marker.unlink()
        self.rows(self.repo)
        self.assertFalse(marker.exists(), "the inventory must not run a program named by the checkout's config")

    def test_status_does_not_rewrite_the_index(self):
        index = self.repo / ".git" / "index"
        f = self.repo / "a.txt"

        def make_stale():
            os.utime(f, (f.stat().st_atime + 100, f.stat().st_mtime + 100))
            return index.read_bytes(), index.stat().st_mtime_ns
        before = make_stale()
        subprocess.run(["git", "-C", str(self.repo), "status", "--porcelain"], capture_output=True, env=ENV)
        if (index.read_bytes(), index.stat().st_mtime_ns) == before:
            self.skipTest("this git did not refresh the index on a stale stat, so the control proves nothing")
        before = make_stale()
        self.rows(self.repo)
        self.assertEqual((index.read_bytes(), index.stat().st_mtime_ns), before, "the inventory wrote the index")

    def test_a_redirecting_environment_does_not_change_which_repo_is_read(self):
        other = self.t / "other"
        subprocess.run(["git", "init", "-q", "-b", "trunk", str(other)], check=True, env=ENV)
        env = dict(ENV, GIT_DIR=str(other / ".git"), GIT_WORK_TREE=str(other))
        main = self.rows(self.repo, env=env)[0]
        self.assertEqual((main["branch"], main["merged_main"]), ("main", "yes"))

    def test_credentials_in_the_origin_url_are_never_printed(self):
        sh(self.repo, "remote", "set-url", "origin", "https://someone:tok3n@example.com/o/r.git")
        out = self.run_tool("repos", str(self.repo))
        self.assertNotIn("tok3n", out)
        self.assertIn("origin=https://example.com/o/r.git", out)

    def test_redact_url_table(self):
        for url, want in (("https://u:p@h/o/r.git", "https://h/o/r.git"), ("https://tok@h/r", "https://h/r"),
                          ("ssh://git@h:22/r", "ssh://h:22/r"), ("git@github.com:o/r.git", "git@github.com:o/r.git"),
                          ("/abs/path.git", "/abs/path.git"), ("https://h/a@b", "https://h/a@b")):
            self.assertEqual(CI.redact_url(url), want, url)


class Workdirs(unittest.TestCase):
    def test_counts_heavy_folders_without_descending_them(self):
        t = Path(tempfile.mkdtemp(prefix="checkout-inventory-wd-"))
        self.addCleanup(shutil.rmtree, t, True)
        s = t / "session-a"
        for d in ("task/node_modules/pkg/node_modules", "task/.venv", "task/clone/.git", "task/build"):
            (s / d).mkdir(parents=True)
        (s / "task" / "run.log").write_text("x\n")
        (t / "not-a-dir.txt").write_text("x\n")
        r = subprocess.run([sys.executable, "-I", str(TOOL), "workdirs", str(t)], capture_output=True, text=True,
                           env=ENV, timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr)
        lines = r.stdout.splitlines()
        self.assertEqual(len(lines), 1)
        name, _size, _when, git_dirs, node_modules, venvs, builds, logs = lines[0].split("\t")
        self.assertEqual((name, git_dirs, node_modules, venvs, builds, logs), ("session-a", "1", "1", "1", "1", "1"),
                         "the nested node_modules is not counted: a counted heavy folder is not descended")


class Usage(unittest.TestCase):
    def test_bad_usage_exits_2(self):
        r = subprocess.run([sys.executable, "-I", str(TOOL), "remove", "x"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)


if __name__ == "__main__":
    unittest.main()
