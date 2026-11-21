"""Test copies (t2-dev disk full 2026-11-21): one copy per PR/lane, disk-low guard, report-only reaper.

Every test runs against a temporary HARNESS_TEST_COPY_HOME with real git repositories; nothing outside the temp dir is
read or written.
"""
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
HOOKS = ROOT / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import test_copies as tc  # noqa: E402

GB = 1024 ** 3


def sh(*args, cwd=None):
    subprocess.run(args, cwd=cwd, check=True, capture_output=True,
                   env=dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@e", GIT_COMMITTER_NAME="t",
                            GIT_COMMITTER_EMAIL="t@e", GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_NOSYSTEM="1"))


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name)
        self.env = mock.patch.dict(os.environ, {"HARNESS_TEST_COPY_HOME": str(self.home),
                                                "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1"})
        self.env.start()
        os.environ.pop("HARNESS_TEST_COPY_MIN_FREE_GB", None)
        # origin (bare) + a checkout of it
        self.origin = self.home / "origin.git"
        sh("git", "init", "-q", "--bare", "-b", "main", str(self.origin))
        self.repo = self.home / "repos" / "proj"
        sh("git", "clone", "-q", str(self.origin), str(self.repo))
        (self.repo / "a.txt").write_text("a\n")
        sh("git", "add", "a.txt", cwd=self.repo)
        sh("git", "commit", "-q", "-m", "init", cwd=self.repo)
        sh("git", "push", "-q", "origin", "HEAD:main", cwd=self.repo)

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def cfg(self, **kw):
        c = tc.load_config()
        c.update(kw)
        return c

    def write_config(self, **kw):
        d = self.home / ".agent-harness" / "state"
        d.mkdir(parents=True, exist_ok=True)
        (d / "test-copies.json").write_text(json.dumps(kw))


class Acquire(Base):
    def test_same_pr_reuses_one_copy(self):
        first = tc.acquire(str(self.repo), "pr-1408", cfg=self.cfg(min_free_gb=0))
        self.assertTrue(first["ok"], first)
        self.assertFalse(first["reused"])
        (self.repo / "b.txt").write_text("b\n")
        sh("git", "add", "b.txt", cwd=self.repo)
        sh("git", "commit", "-q", "-m", "round 2", cwd=self.repo)
        second = tc.acquire(str(self.repo), "pr-1408", ref="HEAD", cfg=self.cfg(min_free_gb=0))
        self.assertTrue(second["ok"], second)
        self.assertTrue(second["reused"])
        self.assertEqual(first["path"], second["path"])
        self.assertTrue((Path(second["path"]) / "b.txt").exists())   # moved to the new round's commit
        copies = list((self.home / ".agent-harness" / "test-copies" / "proj").iterdir())
        self.assertEqual(len(copies), 1)

    def test_dirty_copy_is_reused_but_never_discarded(self):
        p = Path(tc.acquire(str(self.repo), "lane-a", cfg=self.cfg(min_free_gb=0))["path"])
        (p / "a.txt").write_text("local edit\n")
        res = tc.acquire(str(self.repo), "lane-a", cfg=self.cfg(min_free_gb=0))
        self.assertTrue(res["reused"])
        self.assertFalse(res["moved"])
        self.assertEqual((p / "a.txt").read_text(), "local edit\n")

    def test_refuses_new_copy_below_floor_with_alert(self):
        with mock.patch.object(tc, "free_bytes", return_value=2 * GB):
            res = tc.acquire(str(self.repo), "pr-9", cfg=self.cfg(min_free_gb=25))
        self.assertFalse(res["ok"])
        self.assertEqual(res["refused"], "disk-low")
        self.assertIn("DISK LOW", res["error"])
        self.assertFalse((self.home / ".agent-harness" / "test-copies" / "proj" / "pr-9").exists())
        alerts = (self.home / ".agent-harness" / "state" / "test-copies-alerts.jsonl").read_text()
        self.assertIn("disk-low-refused-acquire", alerts)

    def test_existing_copy_is_still_reused_when_disk_is_low(self):
        p = tc.acquire(str(self.repo), "pr-7", cfg=self.cfg(min_free_gb=0))["path"]
        with mock.patch.object(tc, "free_bytes", return_value=1 * GB):
            res = tc.acquire(str(self.repo), "pr-7", cfg=self.cfg(min_free_gb=25))
        self.assertTrue(res["ok"])
        self.assertEqual(res["path"], p)


class Guard(Base):
    def ev(self, command):
        return {"tool_name": "Bash", "tool_input": {"command": command}, "cwd": str(self.home)}

    def test_denies_copy_commands_below_floor(self):
        with mock.patch.object(tc, "free_bytes", return_value=1 * GB):
            for cmd in ("git worktree add ../tester-1408-r5 HEAD", "git clone https://x/y.git tester-2",
                        "cp -R repo tester-3", "rsync -a repo/ tester-4/", "git -C /r worktree add /w HEAD"):
                code, err = tc.pretool(self.ev(cmd), self.cfg(min_free_gb=25))
                self.assertEqual(code, 2, cmd)
                self.assertIn("DISK LOW", err)

    def test_allows_everything_above_floor_and_non_copy_commands_always(self):
        with mock.patch.object(tc, "free_bytes", return_value=100 * GB):
            self.assertEqual(tc.pretool(self.ev("git clone https://x/y.git z"), self.cfg(min_free_gb=25)), (0, ""))
        with mock.patch.object(tc, "free_bytes", return_value=1 * GB):
            self.assertEqual(tc.pretool(self.ev("ls -la && git status"), self.cfg(min_free_gb=25)), (0, ""))
            self.assertEqual(tc.pretool({"tool_name": "Edit", "tool_input": {}}, self.cfg(min_free_gb=25)), (0, ""))

    def test_fails_open_on_internal_error(self):
        with mock.patch.object(tc, "free_bytes", side_effect=OSError("boom")):
            self.assertEqual(tc.pretool(self.ev("git clone a b"), self.cfg()), (0, ""))

    def test_cli_pretool_exit_codes(self):
        env = dict(os.environ, HARNESS_TEST_COPY_MIN_FREE_GB="999999")
        p = subprocess.run([sys.executable, str(HOOKS / "test_copies.py"), "pretool"], env=env, text=True,
                           input=json.dumps(self.ev("git clone a b")), capture_output=True)
        self.assertEqual(p.returncode, 2)
        self.assertIn("DISK LOW", p.stderr)
        p = subprocess.run([sys.executable, str(HOOKS / "test_copies.py"), "pretool"], env=env, text=True,
                           input="not json", capture_output=True)
        self.assertEqual(p.returncode, 0)


class Shm(Base):
    def ev(self, command):
        return {"tool_name": "Bash", "tool_input": {"command": command}, "cwd": str(self.home)}

    def test_writes_into_dev_shm_are_denied_regardless_of_disk(self):
        with mock.patch.object(tc, "free_bytes", return_value=500 * GB):
            for cmd in ("mkdir -p /dev/shm/run1", "cp -R build /dev/shm/x", "python3 gen.py > /dev/shm/out.bin",
                        "TMPDIR=/dev/shm npm test", "git clone a /dev/shm/repo", "cd x && tar -xf a.tar -C /dev/shm/t"):
                code, err = tc.pretool(self.ev(cmd), self.cfg())
                self.assertEqual(code, 2, cmd)
                self.assertIn("/dev/shm is memory", err)

    def test_reads_and_cleanup_of_dev_shm_are_allowed(self):
        with mock.patch.object(tc, "free_bytes", return_value=500 * GB):
            for cmd in ("df -h /dev/shm", "ls -la /dev/shm", "du -sh /dev/shm/*", "rm -rf /dev/shm/run1",
                        "cat /dev/shm/out.bin | head"):
                self.assertEqual(tc.pretool(self.ev(cmd), self.cfg()), (0, ""), cmd)


class Reap(Base):
    def make_old_copies(self):
        work = self.home / ".agent-harness" / "work" / "sess1"
        work.mkdir(parents=True)
        old = work / "tester-1408-r3"
        sh("git", "clone", "-q", str(self.origin), str(old))
        dirty = work / "tester-1408-r4"
        sh("git", "clone", "-q", str(self.origin), str(dirty))
        (dirty / "a.txt").write_text("unsaved\n")
        keep = work / "notes"
        keep.mkdir()
        past = time.time() - 72 * 3600
        for p in (old, dirty):
            for root, dirs, files in os.walk(p):
                for n in dirs + files:
                    os.utime(os.path.join(root, n), (past, past), follow_symlinks=False)
            os.utime(p, (past, past))
        return old, dirty, keep

    def test_default_is_report_only_even_with_apply(self):
        old, dirty, keep = self.make_old_copies()
        res = tc.reap(apply=True, cfg=self.cfg(max_age_hours=24))
        self.assertEqual(res["mode"], "report-only")
        self.assertIn("--apply ignored", res["note"])
        paths = {r["path"]: r for r in res["copies"]}
        self.assertTrue(paths[str(old)]["reap"])
        self.assertEqual(paths[str(old)]["action"], "would-remove (report-only)")
        self.assertNotIn(str(keep), paths)          # only copy-shaped names are candidates
        self.assertTrue(old.exists() and dirty.exists())

    def test_config_flag_without_apply_deletes_nothing(self):
        old, dirty, _ = self.make_old_copies()
        self.write_config(reaper_delete_enabled=True)
        res = tc.reap(apply=False)
        self.assertEqual(res["mode"], "report-only")
        self.assertTrue(old.exists())

    def test_non_literal_true_does_not_enable(self):
        self.write_config(reaper_delete_enabled="yes")
        self.assertFalse(tc.load_config()["reaper_delete_enabled"])

    def test_enabled_and_apply_removes_only_clean_pushed_idle_copies(self):
        old, dirty, keep = self.make_old_copies()
        self.write_config(reaper_delete_enabled=True, max_age_hours=24)
        with mock.patch.object(tc, "in_use", return_value=False):
            res = tc.reap(apply=True)
        acts = {r["path"]: r["action"] for r in res["copies"]}
        self.assertEqual(acts[str(old)], "removed")
        self.assertEqual(acts[str(dirty)], "kept: uncommitted changes")
        self.assertFalse(old.exists())
        self.assertTrue(dirty.exists() and keep.exists())

    def test_in_use_copy_is_kept(self):
        old, _, _ = self.make_old_copies()
        self.write_config(reaper_delete_enabled=True)
        with mock.patch.object(tc, "in_use", return_value=True):
            res = tc.reap(apply=True)
        self.assertTrue(old.exists())
        self.assertIn("a process is working in it", {r["path"]: r["action"] for r in res["copies"]}[str(old)])

    def test_unpushed_head_is_kept(self):
        old, _, _ = self.make_old_copies()
        (old / "c.txt").write_text("c\n")
        sh("git", "add", "c.txt", cwd=old)
        sh("git", "commit", "-q", "-m", "local only", cwd=old)
        past = time.time() - 72 * 3600
        for root, dirs, files in os.walk(old):
            for n in dirs + files:
                os.utime(os.path.join(root, n), (past, past), follow_symlinks=False)
        os.utime(old, (past, past))
        self.write_config(reaper_delete_enabled=True)
        with mock.patch.object(tc, "in_use", return_value=False):
            res = tc.reap(apply=True)
        self.assertTrue(old.exists())
        self.assertEqual({r["path"]: r["action"] for r in res["copies"]}[str(old)], "kept: HEAD is on no remote ref")

    def test_linked_worktree_copy_removed_with_plain_worktree_remove(self):
        p = Path(tc.acquire(str(self.repo), "pr-1", cfg=self.cfg(min_free_gb=0))["path"])
        self.write_config(reaper_delete_enabled=True, max_age_hours=0)
        with mock.patch.object(tc, "in_use", return_value=False):
            res = tc.reap(apply=True, now=time.time() + 3600)
        self.assertEqual({r["path"]: r["action"] for r in res["copies"]}[str(p)], "removed")
        out = subprocess.run(["git", "-C", str(self.repo), "worktree", "list"], capture_output=True, text=True).stdout
        self.assertNotIn(str(p), out)

    def test_size_cap_marks_oldest_first(self):
        work = self.home / ".agent-harness" / "work" / "s"
        work.mkdir(parents=True)
        for i, age in enumerate((10, 5, 2)):
            d = work / f"tester-{i}"
            d.mkdir()
            t = time.time() - age * 3600
            os.utime(d, (t, t))
        sizes = {str(work / "tester-0"): 30 * GB, str(work / "tester-1"): 30 * GB, str(work / "tester-2"): 30 * GB}
        with mock.patch.object(tc, "dir_size", side_effect=lambda p: sizes[p]):
            res = tc.reap(cfg=self.cfg(max_age_hours=48, max_total_gb=60))
        marks = {Path(r["path"]).name: r["reap"] for r in res["copies"]}
        self.assertEqual(marks, {"tester-0": True, "tester-1": False, "tester-2": False})


class Install(unittest.TestCase):
    def test_installer_ships_and_wires_the_guard(self):
        sys.path.insert(0, str(ROOT))
        import install  # noqa: E402
        self.assertIn("test_copies.py", install.HOOKS)
        src = (ROOT / "install.py").read_text()
        self.assertIn('"test_copies.py"), "pretool"]', src)
        manifest = json.loads((HOOKS / "hooks_manifest.json").read_text())
        row = [h for h in manifest["hooks"] if h["id"] == "test_copies:pretool"]
        self.assertEqual(len(row), 1)
        self.assertEqual(row[0]["status"], "installed")

    def test_install_never_enables_deletion(self):
        src = (ROOT / "install.py").read_text() + (HOOKS / "test_copies.py").read_text()
        self.assertNotIn('"reaper_delete_enabled": True', src)
        self.assertFalse(tc.DEFAULTS["reaper_delete_enabled"])

    def test_hygiene_entry_point_delegates(self):
        with tempfile.TemporaryDirectory() as h:
            env = dict(os.environ, HARNESS_TEST_COPY_HOME=h)
            p = subprocess.run([sys.executable, str(HOOKS / "worktree_hygiene.py"), "copies", "reap", "--json"],
                               env=env, capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(json.loads(p.stdout)["mode"], "report-only")


if __name__ == "__main__":
    unittest.main()
