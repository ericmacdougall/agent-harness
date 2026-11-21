"""Copy hygiene (t2-dev disk full 2026-11-21): one copy per PR/lane, disk-low guard, report-only reaper.

Every test runs against a temporary HARNESS_COPY_HYGIENE_HOME with real git repositories; nothing outside the temp dir is
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
import copy_hygiene as tc  # noqa: E402

GB = 1024 ** 3


def sh(*args, cwd=None):
    subprocess.run(args, cwd=cwd, check=True, capture_output=True,
                   env=dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@e", GIT_COMMITTER_NAME="t",
                            GIT_COMMITTER_EMAIL="t@e", GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_NOSYSTEM="1"))


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name)
        self.env = mock.patch.dict(os.environ, {"HARNESS_COPY_HYGIENE_HOME": str(self.home),
                                                "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1"})
        self.env.start()
        os.environ.pop("HARNESS_COPY_HYGIENE_MIN_FREE_GB", None)
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
        kw.setdefault("min_free_pct", 0)
        return tc.normalize(kw)

    def copies_dir(self):
        d = self.home / ".agent-harness" / "test-copies"
        return [x for x in d.iterdir() if x.is_dir()]

    def write_config(self, **kw):
        d = self.home / ".agent-harness" / "state"
        d.mkdir(parents=True, exist_ok=True)
        (d / "copy-hygiene.json").write_text(json.dumps(kw))


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
        self.assertEqual(len(self.copies_dir()), 1)
        self.assertEqual([x.name for x in self.copies_dir()[0].iterdir() if x.is_dir()], ["pr-1408"])

    def advance(self, name="b.txt"):
        (self.repo / name).write_text(name)
        sh("git", "add", name, cwd=self.repo)
        sh("git", "commit", "-q", "-m", name, cwd=self.repo)

    def test_dirty_copy_behind_the_ref_fails_loudly_and_keeps_the_edit(self):
        p = Path(tc.acquire(str(self.repo), "lane-a", cfg=self.cfg(min_free_gb=0))["path"])
        (p / "a.txt").write_text("local edit\n")
        self.advance()
        res = tc.acquire(str(self.repo), "lane-a", cfg=self.cfg(min_free_gb=0))
        self.assertFalse(res["ok"])
        self.assertTrue(res["stale"])
        self.assertNotEqual(res["commit"], res["wanted"])
        self.assertEqual((p / "a.txt").read_text(), "local edit\n")
        self.assertFalse((p / "b.txt").exists())

    def test_untracked_files_do_not_stop_the_move(self):
        p = Path(tc.acquire(str(self.repo), "pr-2", cfg=self.cfg(min_free_gb=0))["path"])
        (p / "screenshot.png").write_text("x")
        self.advance()
        res = tc.acquire(str(self.repo), "pr-2", cfg=self.cfg(min_free_gb=0))
        self.assertTrue(res["ok"], res)
        self.assertTrue((p / "b.txt").exists())
        self.assertTrue((p / "screenshot.png").exists())

    def test_cli_exit_code_for_stale_copy(self):
        p = Path(tc.acquire(str(self.repo), "pr-3", cfg=self.cfg(min_free_gb=0))["path"])
        (p / "a.txt").write_text("edit\n")
        self.advance()
        r = subprocess.run([sys.executable, str(HOOKS / "copy_hygiene.py"), "acquire", "--repo", str(self.repo),
                            "--key", "pr-3"], capture_output=True, text=True, env=dict(os.environ, HARNESS_COPY_HYGIENE_MIN_FREE_GB="0"))
        self.assertEqual(r.returncode, 4, r.stdout + r.stderr)

    def test_two_worktrees_of_one_repo_share_the_copy_and_bad_keys_are_refused(self):
        wt = self.home / "repos" / "proj-wt"
        sh("git", "-C", str(self.repo), "worktree", "add", "-q", "--detach", str(wt), "HEAD")
        a = tc.acquire(str(self.repo), "pr-5", cfg=self.cfg(min_free_gb=0))
        b = tc.acquire(str(wt), "pr-5", cfg=self.cfg(min_free_gb=0))
        self.assertEqual(a["path"], b["path"])
        self.assertFalse(tc.acquire(str(self.repo), "..", cfg=self.cfg(min_free_gb=0))["ok"])

    def test_refuses_new_copy_below_floor_with_alert(self):
        with mock.patch.object(tc, "free_bytes", return_value=2 * GB):
            res = tc.acquire(str(self.repo), "pr-9", cfg=self.cfg(min_free_gb=25))
        self.assertFalse(res["ok"])
        self.assertEqual(res["refused"], "disk-low")
        self.assertIn("DISK LOW", res["error"])
        self.assertFalse(any((d / "pr-9").exists() for d in self.copies_dir()))
        alerts = (self.home / ".agent-harness" / "state" / "copy-hygiene-alerts.jsonl").read_text()
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
                        "cp -R repo tester-3", "rsync -a repo/ tester-4/", "git -C /r worktree add /w HEAD",
                        "cp -r repo t5", "cp -rf repo t6", "cp -pr repo t7", "cp --recursive repo t8",
                        "cp --archive repo t9", "rsync -r src/ dst/", "rsync --archive src/ dst/",
                        "rsync -e ssh -a src/ dst/", "cd x && sudo cp -a repo t10", "ditto a b"):
                code, err = tc.pretool(self.ev(cmd), self.cfg(min_free_gb=25))
                self.assertEqual(code, 2, cmd)
                self.assertIn("DISK LOW", err)

    def test_allows_everything_above_floor_and_non_copy_commands_always(self):
        with mock.patch.object(tc, "free_bytes", return_value=100 * GB):
            self.assertEqual(tc.pretool(self.ev("git clone https://x/y.git z"), self.cfg(min_free_gb=25)), (0, ""))
        with mock.patch.object(tc, "free_bytes", return_value=1 * GB):
            for cmd in ("ls -la && git status", "cp a.txt b.txt", "git commit -m 'git clone later'",
                        "rsync -a src/ otherhost:/backup/"):
                self.assertEqual(tc.pretool(self.ev(cmd), self.cfg(min_free_gb=25)), (0, ""), cmd)
            self.assertEqual(tc.pretool({"tool_name": "Edit", "tool_input": {}}, self.cfg(min_free_gb=25)), (0, ""))

    def test_fails_open_on_internal_error(self):
        with mock.patch.object(tc, "free_bytes", side_effect=OSError("boom")):
            self.assertEqual(tc.pretool(self.ev("git clone a b"), self.cfg()), (0, ""))

    def test_cli_pretool_exit_codes(self):
        self.write_config(min_free_pct=0)
        env = dict(os.environ, HARNESS_COPY_HYGIENE_MIN_FREE_GB="999999")
        p = subprocess.run([sys.executable, str(HOOKS / "copy_hygiene.py"), "pretool"], env=env, text=True,
                           input=json.dumps(self.ev("git clone a b")), capture_output=True)
        self.assertEqual(p.returncode, 2)
        self.assertIn("DISK LOW", p.stderr)
        p = subprocess.run([sys.executable, str(HOOKS / "copy_hygiene.py"), "pretool"], env=env, text=True,
                           input="not json", capture_output=True)
        self.assertEqual(p.returncode, 0)


class Shm(Base):
    def ev(self, command):
        return {"tool_name": "Bash", "tool_input": {"command": command}, "cwd": str(self.home)}

    def test_writes_into_dev_shm_are_denied_regardless_of_disk(self):
        with mock.patch.object(tc, "free_bytes", return_value=500 * GB):
            for cmd in ("mkdir -p /dev/shm/run1", "cp -R build /dev/shm/x", "python3 gen.py > /dev/shm/out.bin",
                        "TMPDIR=/dev/shm npm test", "git clone a /dev/shm/repo", "cd x && tar -xf a.tar -C /dev/shm/t",
                        "mv out.bin /dev/shm/", "dd if=/dev/zero of=/dev/shm/big bs=1M count=10",
                        "cp -t /dev/shm/ a b", "echo hi >> /dev/shm/log"):
                code, err = tc.pretool(self.ev(cmd), self.cfg())
                self.assertEqual(code, 2, cmd)
                self.assertIn("/dev/shm is memory", err)

    def test_reads_and_cleanup_of_dev_shm_are_allowed(self):
        with mock.patch.object(tc, "free_bytes", return_value=500 * GB):
            for cmd in ("df -h /dev/shm", "ls -la /dev/shm", "du -sh /dev/shm/*", "rm -rf /dev/shm/run1",
                        "cat /dev/shm/out.bin | head", "mv /dev/shm/run1 ~/scratch/", "cp /dev/shm/out.bin .",
                        "tar -czf ~/save.tgz -C /dev/shm run1", "dd if=/dev/shm/x of=/tmp/disk.bin",
                        "grep install /dev/shm/log", "git commit -m 'do not touch /dev/shm'",
                        "rsync -a /dev/shm/run1/ ~/scratch/run1/"):
                self.assertEqual(tc.pretool(self.ev(cmd), self.cfg()), (0, ""), cmd)

    def test_relative_writes_from_a_dev_shm_cwd_are_denied(self):
        ev = {"tool_name": "Bash", "tool_input": {"command": "mkdir build && touch build/x"}, "cwd": "/dev/shm/run1"}
        self.assertEqual(tc.pretool(ev, self.cfg())[0], 2)


class Reap(Base):
    def make_old_copies(self):
        return self.make_old_copies_named("sess1")

    def make_old_copies_named(self, sess):
        work = self.home / ".agent-harness" / "work" / sess
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
        with mock.patch.object(tc, "last_activity", side_effect=lambda p, idx: time.time() - 72 * 3600):
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
        acts = self.enabled_reap()
        self.assertEqual(acts[str(old)], "removed")
        self.assertEqual(acts[str(dirty)], "kept: uncommitted or untracked changes")
        self.assertFalse(old.exists())
        self.assertTrue(dirty.exists() and keep.exists())

    def test_in_use_copy_is_kept(self):
        old, _, _ = self.make_old_copies()
        self.write_config(reaper_delete_enabled=True)
        with mock.patch.object(tc, "in_use", return_value=True), \
                mock.patch.object(tc, "last_activity", side_effect=lambda p, idx: time.time() - 72 * 3600):
            res = tc.reap(apply=True)
        self.assertTrue(old.exists())
        self.assertIn("a process is working in it", {r["path"]: r["action"] for r in res["copies"]}[str(old)])

    def test_unpushed_head_is_kept(self):
        old, _, _ = self.make_old_copies()
        (old / "c.txt").write_text("c\n")
        sh("git", "add", "c.txt", cwd=old)
        sh("git", "commit", "-q", "-m", "local only", cwd=old)
        acts = self.enabled_reap()
        self.assertTrue(old.exists())
        self.assertEqual(acts[str(old)], "kept: HEAD is on no remote ref")

    def test_linked_worktree_copy_removed_with_plain_worktree_remove(self):
        p = Path(tc.acquire(str(self.repo), "pr-1", cfg=self.cfg(min_free_gb=0))["path"])
        self.write_config(reaper_delete_enabled=True, max_age_hours=0)
        with mock.patch.object(tc, "in_use", return_value=False):
            res = tc.reap(apply=True, now=time.time() + 3600)
        self.assertEqual({r["path"]: r["action"] for r in res["copies"]}[str(p)], "removed")
        self.assertFalse(p.exists())
        out = subprocess.run(["git", "-C", str(self.repo), "worktree", "list", "--porcelain"], capture_output=True,
                             text=True).stdout
        self.assertNotIn(os.path.realpath(p), out)

    def age(self, p, hours=72):
        past = time.time() - hours * 3600
        for root, dirs, files in os.walk(p):
            for n in dirs + files:
                os.utime(os.path.join(root, n), (past, past), follow_symlinks=False)
        os.utime(p, (past, past))

    def enabled_reap(self):
        self.write_config(reaper_delete_enabled=True, max_age_hours=24)
        with mock.patch.object(tc, "in_use", return_value=False), \
                mock.patch.object(tc, "last_activity", side_effect=lambda p, idx: time.time() - 72 * 3600):
            return {r["path"]: r["action"] for r in tc.reap(apply=True)["copies"]}

    def test_unpushed_local_branch_is_kept(self):
        old, _, _ = self.make_old_copies()
        sh("git", "checkout", "-q", "-b", "side", cwd=old)
        (old / "s.txt").write_text("s")
        sh("git", "add", "s.txt", cwd=old)
        sh("git", "commit", "-q", "-m", "side", cwd=old)
        sh("git", "checkout", "-q", "-", cwd=old)
        acts = self.enabled_reap()
        self.assertTrue(old.exists())
        self.assertEqual(acts[str(old)], "kept: a local branch has commits on no remote")

    def test_stash_is_kept(self):
        old, _, _ = self.make_old_copies()
        (old / "a.txt").write_text("stash me\n")
        sh("git", "stash", "-q", cwd=old)
        acts = self.enabled_reap()
        self.assertTrue(old.exists())
        self.assertEqual(acts[str(old)], "kept: has a stash")

    def test_ignored_evidence_is_kept_but_build_output_is_not(self):
        old, _, _ = self.make_old_copies()
        (old / ".git" / "info" / "exclude").write_text("evidence/\nnode_modules/\n")
        (old / "node_modules").mkdir()
        (old / "node_modules" / "x.js").write_text("x")
        acts = self.enabled_reap()
        self.assertEqual(acts[str(old)], "removed")
        old2, _, _ = self.make_old_copies_named("s2")
        (old2 / ".git" / "info" / "exclude").write_text("evidence/\n")
        (old2 / "evidence").mkdir()
        (old2 / "evidence" / "shot.png").write_text("x")
        acts = self.enabled_reap()
        self.assertTrue(old2.exists())
        self.assertTrue(acts[str(old2)].startswith("kept: ignored files that may be evidence"))

    def test_fresh_copy_with_preserved_mtimes_is_not_idle(self):
        work = self.home / ".agent-harness" / "work" / "s3"
        work.mkdir(parents=True)
        p = work / "tester-1500-r1"
        sh("git", "clone", "-q", str(self.origin), str(p))
        self.age(p)                       # what cp -a / rsync -a / tar -x leave behind; ctime stays now
        res = tc.reap(cfg=self.cfg(max_age_hours=24))
        row = {r["path"]: r for r in res["copies"]}[str(p)]
        self.assertFalse(row["reap"], row)

    def test_round_named_dirs_outside_the_patterns_are_not_candidates(self):
        work = self.home / ".agent-harness" / "work" / "s4"
        (work / "r2-repair").mkdir(parents=True)
        res = tc.reap(cfg=self.cfg(max_age_hours=0))
        self.assertNotIn(str(work / "r2-repair"), {r["path"] for r in res["copies"]})

    def test_config_values_are_sanitised(self):
        self.write_config(min_free_gb="lots", max_total_gb=None, roots="~/elsewhere", name_patterns="*")
        c = tc.load_config()
        self.assertEqual(c["min_free_gb"], 25.0)
        self.assertEqual(c["max_total_gb"], 60.0)
        self.assertEqual(c["roots"], [os.path.expanduser("~/elsewhere")])
        self.assertEqual(c["name_patterns"], list(tc.DEFAULTS["name_patterns"]))

    def test_size_cap_marks_oldest_first(self):
        work = self.home / ".agent-harness" / "work" / "s"
        work.mkdir(parents=True)
        for i, age in enumerate((10, 5, 2)):
            d = work / f"tester-{i}"
            d.mkdir()
            t = time.time() - age * 3600
            os.utime(d, (t, t))
        sizes = {str(work / "tester-0"): 30 * GB, str(work / "tester-1"): 30 * GB, str(work / "tester-2"): 30 * GB}
        ages = {str(work / "tester-0"): 10, str(work / "tester-1"): 5, str(work / "tester-2"): 2}
        with mock.patch.object(tc, "dir_size", side_effect=lambda p: sizes[p]), \
                mock.patch.object(tc, "last_activity", side_effect=lambda p, idx: time.time() - ages[p] * 3600):
            res = tc.reap(cfg=self.cfg(max_age_hours=48, max_total_gb=60))
        marks = {Path(r["path"]).name: r["reap"] for r in res["copies"]}
        self.assertEqual(marks, {"tester-0": True, "tester-1": False, "tester-2": False})


class Install(unittest.TestCase):
    def test_installer_ships_and_wires_the_guard(self):
        sys.path.insert(0, str(ROOT))
        import install  # noqa: E402
        self.assertIn("copy_hygiene.py", install.HOOKS)
        src = (ROOT / "install.py").read_text()
        self.assertIn('"copy_hygiene.py"), "pretool"]', src)
        self.assertIn('"copy_hygiene.py"), "session-start"]', src)
        manifest = json.loads((HOOKS / "hooks_manifest.json").read_text())
        ids = {h["id"]: h for h in manifest["hooks"]}
        self.assertEqual(ids["copy_hygiene:pretool"]["status"], "installed")
        self.assertEqual(ids["copy_hygiene:session-start"]["status"], "installed")
        for c in ids["copy_hygiene:pretool"]["canaries"]:
            p = subprocess.run([sys.executable, str(HOOKS / "copy_hygiene.py"), "pretool"], input=json.dumps(c["payload"]),
                               capture_output=True, text=True)
            self.assertEqual(p.returncode, 2 if c["expect"] == "deny" else 0, c)

    def test_click_tester_brief_uses_acquire(self):
        brief = (ROOT / "harness" / "agents" / "click-tester.md").read_text()
        self.assertIn("copy_hygiene.py acquire", brief)

    def test_session_start_reports_idle_copies_and_never_deletes(self):
        with tempfile.TemporaryDirectory() as h:
            st = Path(h) / ".agent-harness" / "state"
            st.mkdir(parents=True)
            (st / "copy-hygiene-report.json").write_text(json.dumps(
                {"ts": time.time(), "total_gb": 117, "cap_gb": 60,
                 "copies": [{"path": "/x/tester-1", "bytes": 80 * GB, "reap": True}]}))
            env = dict(os.environ, HARNESS_COPY_HYGIENE_HOME=h)
            p = subprocess.run([sys.executable, str(HOOKS / "copy_hygiene.py"), "session-start"], input="{}",
                               env=env, capture_output=True, text=True)
            self.assertEqual(p.returncode, 0)
            self.assertIn("1 idle copies hold 80.0 GB", json.loads(p.stdout)["systemMessage"])

    def test_install_never_enables_deletion(self):
        self.assertFalse(tc.DEFAULTS["reaper_delete_enabled"])
        with tempfile.TemporaryDirectory() as h, mock.patch.dict(os.environ, {"HARNESS_COPY_HYGIENE_HOME": h}):
            self.assertFalse(tc.load_config()["reaper_delete_enabled"])       # first run: no config file at all
        self.assertNotIn("reaper_delete_enabled", (ROOT / "install.py").read_text())

    def test_hygiene_entry_point_delegates(self):
        with tempfile.TemporaryDirectory() as h:
            env = dict(os.environ, HARNESS_COPY_HYGIENE_HOME=h)
            p = subprocess.run([sys.executable, str(HOOKS / "worktree_hygiene.py"), "copies", "reap", "--json"],
                               env=env, capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(json.loads(p.stdout)["mode"], "report-only")


if __name__ == "__main__":
    unittest.main()
