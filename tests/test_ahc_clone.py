"""ahc_clone: daemon-owned full clones, fetched to the exact head, never shallow, with hooks and fsmonitor disabled
(GoodQA goodqa#16034 AC-3, NEG-3). Local bare-repo fixtures only; no network."""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import ahc_clone  # noqa: E402

ENV = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
       "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
       "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"}


def git(*args, cwd=None):
    return subprocess.run(["git", *args], cwd=cwd, env=ENV, check=True, capture_output=True, text=True).stdout.strip()


class CloneTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.marker = root / "PWNED"
        work = root / "src"
        git("init", "-q", "-b", "main", str(work))
        (work / "a.txt").write_text("one\n")
        git("add", "a.txt", cwd=work)
        git("commit", "-qm", "one", cwd=work)
        self.base = git("rev-parse", "HEAD", cwd=work)
        git("checkout", "-qb", "feature", cwd=work)
        (work / "a.txt").write_text("two\n")
        git("commit", "-qam", "two", cwd=work)
        self.head = git("rev-parse", "HEAD", cwd=work)
        self.remote = root / "remote.git"
        git("clone", "-q", "--bare", str(work), str(self.remote))
        # Hostile remote-side config cannot travel through a clone, but a hostile *local* config could if the daemon
        # ever reused an owner checkout. Plant both kinds of trap: a hook in the bare repo and, after cloning, an
        # fsmonitor and hooksPath pointing at a marker-writing script inside the daemon clone's own config.
        trap = root / "trap.sh"
        trap.write_text(f"#!/bin/sh\ntouch {self.marker}\n")
        trap.chmod(0o755)
        for name in ("post-checkout", "post-merge", "reference-transaction"):
            hook = self.remote / "hooks" / name
            hook.write_text(trap.read_text())
            hook.chmod(0o755)
        self.trap = trap
        self.clones = root / "clones"

    def tearDown(self):
        self.tmp.cleanup()

    def test_full_clone_at_exact_head_runs_no_hook(self):
        path = ahc_clone.prepare(self.clones, "o/n", str(self.remote), self.head, self.base, env=ENV)
        self.assertEqual(git("rev-parse", "HEAD", cwd=path), self.head)
        self.assertEqual(git("rev-parse", "--is-shallow-repository", cwd=path), "false")
        self.assertEqual(git("status", "--porcelain", cwd=path), "")
        self.assertFalse(self.marker.exists())

    def test_planted_local_fsmonitor_and_hookspath_never_run(self):
        path = ahc_clone.prepare(self.clones, "o/n", str(self.remote), self.base, self.base, env=ENV)
        git("config", "core.fsmonitor", str(self.trap), cwd=path)
        git("config", "core.hooksPath", str(self.trap.parent), cwd=path)
        (Path(self.trap.parent) / "post-checkout").write_text(self.trap.read_text())
        (Path(self.trap.parent) / "post-checkout").chmod(0o755)
        ahc_clone.prepare(self.clones, "o/n", str(self.remote), self.head, self.base, env=ENV)
        self.assertFalse(self.marker.exists(), "a planted fsmonitor or hooksPath ran under daemon authority")
        self.assertEqual(git("rev-parse", "HEAD", cwd=path), self.head)

    def test_unknown_head_is_refused(self):
        with self.assertRaises(ahc_clone.CloneError):
            ahc_clone.prepare(self.clones, "o/n", str(self.remote), "f" * 40, self.base, env=ENV)

    def test_dirty_clone_is_reset_to_head(self):
        path = ahc_clone.prepare(self.clones, "o/n", str(self.remote), self.head, self.base, env=ENV)
        (Path(path) / "a.txt").write_text("tampered\n")
        (Path(path) / "junk.txt").write_text("x\n")
        ahc_clone.prepare(self.clones, "o/n", str(self.remote), self.head, self.base, env=ENV)
        self.assertEqual(git("status", "--porcelain", cwd=path), "")

    def test_repo_slug_cannot_escape_clone_root(self):
        with self.assertRaises(ahc_clone.CloneError):
            ahc_clone.prepare(self.clones, "../evil", str(self.remote), self.head, self.base, env=ENV)


if __name__ == "__main__":
    unittest.main()
