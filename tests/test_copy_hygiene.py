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
        self.units = self.home / "units"
        self.units.mkdir()
        os.environ["HARNESS_COPY_HYGIENE_UNIT_DIRS"] = str(self.units)   # never read the host's real units
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
                        "cp -t /dev/shm/ a b", "echo hi >> /dev/shm/log", "make &> /dev/shm/build.log"):
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


class OldCopies:
    """Helpers for reaper tests (mixed into Base subclasses)."""

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

    def enabled_reap(self):
        self.write_config(reaper_delete_enabled=True, max_age_hours=24)
        with mock.patch.object(tc, "in_use", return_value=False), \
                mock.patch.object(tc, "last_activity", side_effect=lambda p, idx: time.time() - 72 * 3600):
            return {r["path"]: r["action"] for r in tc.reap(apply=True)["copies"]}


class Reap(OldCopies, Base):
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


class Protected(OldCopies, Base):
    """2026-11-21: cleanups deleted claude-rc's WorkingDirectory and the pp gate's runner and caches on t2-dev."""

    def unit(self, name, body, sub=""):
        d = self.units / sub if sub else self.units
        d.mkdir(parents=True, exist_ok=True)
        (d / name).write_text(body)

    def ev(self, command, cwd=None):
        return {"tool_name": "Bash", "tool_input": {"command": command}, "cwd": str(cwd or self.home)}

    def setup_services(self):
        self.rc = self.home / "coordinator-v2" / "rc" / "agent-harness"
        self.runner = self.home / "pp-ci" / "runner"
        self.nm = self.home / "pp-ci" / "nm"
        for d in (self.rc, self.runner, self.nm):
            d.mkdir(parents=True)
        self.unit("claude-rc.service", "[Service]\nWorkingDirectory=%s\nExecStart=/usr/bin/claude rc\n" % self.rc)
        self.unit("pp-gate.service", "[Service]\nExecStart=-/bin/bash \\\n  %h/pp-ci/runner/gate.sh --x\n"
                                     "Environment=NODE_PATH=%h/pp-ci/nm\n")

    def test_units_name_working_directory_exec_and_env_paths(self):
        self.setup_services()
        self.unit("10-extra.conf", "[Service]\nExecStartPre=+%h/pre/hook.sh\n", sub="pp-gate.service.d")
        prot = tc.protected_paths(self.cfg(protected_paths=["~/keepme"]))
        for p in (self.rc, self.runner / "gate.sh", self.nm, self.home / "pre" / "hook.sh",
                  Path(os.path.expanduser("~/keepme"))):
            self.assertIn(os.path.normpath(str(p)), prot, p)
        self.assertNotIn(str(self.home / "pp-ci"), prot)     # the parent is not itself named

    def test_launchd_plist_paths_are_protected(self):
        import plistlib
        job = self.home / "svc"
        job.mkdir()
        with open(self.units / "com.eric.svc.plist", "wb") as f:
            plistlib.dump({"Label": "x", "WorkingDirectory": str(job), "ProgramArguments": ["/bin/sh", str(job / "run")]}, f)
        prot = tc.protected_paths(self.cfg())
        self.assertIn(str(job), prot)
        self.assertIsNotNone(tc.protecting(str(self.home), prot))

    def test_pretool_denies_deleting_service_paths_and_their_parents(self):
        self.setup_services()
        for cmd, cwd in (("rm -rf ~/coordinator-v2/rc/agent-harness".replace("~", str(self.home)), None),
                         ("rm -rf %s" % (self.home / "pp-ci"), None),
                         ("rm -rf runner", self.home / "pp-ci"),
                         ("sudo rm -r %s/*" % (self.home / "pp-ci"), None),
                         ("find %s -mindepth 1 -delete" % self.nm, None),
                         ("find %s -name x -exec rm -rf {} +" % (self.home / "pp-ci"), None),
                         ("cd /tmp && rmdir %s" % self.nm, None),
                         ("git worktree remove %s" % self.rc, None)):
            code, err = tc.pretool(self.ev(cmd, cwd), self.cfg())
            self.assertEqual(code, 2, cmd)
            self.assertIn("PROTECTED PATH", err)
        alerts = (self.home / ".agent-harness" / "state").rglob("*")
        self.assertTrue(any("protected-delete-denied" in p.read_text(errors="ignore") for p in alerts if p.is_file()))

    def test_pretool_allows_unrelated_deletes_and_reads(self):
        self.setup_services()
        other = self.home / "pp-ci" / "old-logs"
        other.mkdir()
        for cmd in ("rm -rf %s" % other, "ls %s" % self.runner, "cat %s/gate.sh" % self.runner,
                    "rm -rf %s/node_modules/.cache" % self.home, "find %s -name '*.log'" % self.home):
            self.assertEqual(tc.pretool(self.ev(cmd), self.cfg())[0], 0, cmd)

    def test_reaper_keeps_a_copy_a_service_runs_from_even_when_enabled(self):
        old, _, _ = self.make_old_copies()
        self.unit("tester.service", "[Service]\nWorkingDirectory=%s\nExecStart=/usr/bin/true\n" % old)
        acts = self.enabled_reap()
        self.assertIn("kept: protected", acts[str(old)])
        self.assertTrue(old.exists())

    def test_reaper_deletes_nothing_when_units_cannot_be_read(self):
        old, _, _ = self.make_old_copies()
        with mock.patch.object(tc, "protected_scan", side_effect=RuntimeError("boom")):
            acts = self.enabled_reap()
        self.assertEqual(acts[str(old)], "kept: could not read service units")
        self.assertTrue(old.exists())

    def deny(self, cmd, cwd=None):
        code, err = tc.pretool(self.ev(cmd, cwd), self.cfg())
        self.assertEqual(code, 2, cmd)
        self.assertIn("PROTECTED PATH", err)

    def allow(self, cmd, cwd=None):
        self.assertEqual(tc.pretool(self.ev(cmd, cwd), self.cfg())[0], 0, cmd)

    def test_cd_variables_braces_wildcards_and_wrappers_cannot_slip_past(self):
        self.setup_services()
        h = str(self.home)
        with mock.patch.dict(os.environ, {"HOME": h}):
            for cmd in ("cd %s/pp-ci && rm -rf runner nm" % h,             # relative target after cd
                        "cd $SOMEWHERE && rm -rf pp-ci/runner",              # unknown base: matched by tail
                        "rm -rf $HOME/pp-ci/runner", 'rm -rf "${HOME}/pp-ci"', "rm -rf ~/pp-ci/{runner,nm}",
                        "rm -rf $UNSET_VAR/pp-ci/nm",
                        "rm -rf %s/*" % self.rc, "rm -rf ~/pp-ci/nm/*",        # emptying a protected directory
                        "find -L %s -delete" % self.nm, "find %s -exec sudo rm -rf {} +" % self.nm,
                        "find %s -type d | xargs rm -rf" % self.nm, "find %s -exec mv {} /tmp \\;" % self.nm,
                        "git -C %s worktree remove agent-harness" % self.rc.parent,
                        "mv %s /tmp/old-runner" % self.runner, "mv -t /tmp %s" % self.nm,
                        "bash -lc 'cd %s/pp-ci && rm -rf runner'" % h, "timeout 5 rm -rf %s" % self.nm,
                        "sudo -u eric rm -rf %s" % self.nm, "env -u X nohup rm -r %s" % self.nm):
                self.deny(cmd)

    def test_unresolved_variables_assignments_loops_and_brace_moves_are_denied(self):
        self.setup_services()
        h = str(self.home)
        with mock.patch.dict(os.environ, {"HOME": h}):
            for cmd in ("rm -rf ~/pp-ci/$d", 'D=~/pp-ci/runner; rm -rf "$D"',
                        'for d in ~/pp-ci/runner ~/pp-ci/nm; do rm -rf "$d"; done', "mv ~/pp-ci/runner{,.bak}",
                        "cd $X && rm -rf pp-ci/runner/*", "rm -rf $X/pp-ci/nm/*",
                        "if [ -d %s ]; then rm -rf %s; fi" % (self.nm, self.nm), "{ rm -rf %s; }" % self.nm,
                        "! rm -rf %s" % self.nm, "time rm -rf %s" % self.nm,
                        "find %s -print0 | xargs -0 -I {} rm -rf {}" % self.nm, "find %s | xargs -n 1 rm" % self.nm,
                        "find %s | grep -v keep | xargs rm -rf" % self.nm,
                        "find %s -name '*' -delete" % self.nm, "find %s -mtime +1 -delete" % self.nm,
                        "find %s -exec sh -c 'rm -rf \"$1\"' _ {} \\;" % self.nm, "rm -rf %s/**" % self.nm,
                        "rm -rf %s/[!.]*" % self.nm):
                self.deny(cmd)

    def test_cd_scope_does_not_leak_or_hide_the_real_directory(self):
        self.setup_services()
        pp = self.home / "pp-ci"
        for cmd in ("(cd /tmp && true); rm -rf runner", "bash -c 'cd /tmp'; rm -rf runner",
                    "pushd /tmp; popd; rm -rf runner", "cd /tmp && cd - && rm -rf runner",
                    "cd missing-dir; rm -rf runner"):
            self.deny(cmd, cwd=pp)

    def test_emptying_through_a_symlink_is_denied(self):
        self.setup_services()
        link = self.home / "nm-link"
        link.symlink_to(self.nm)
        (self.nm / "pkg").mkdir()
        self.deny("rm -rf %s/*" % link)
        self.deny("find -L %s -delete" % link)

    def test_unknown_cd_does_not_block_system_named_dirs(self):
        self.unit("sys.service", "[Service]\nExecStart=/usr/lib/thing/bin/run\n")
        self.allow("cd $X && rm -rf bin")

    def test_everyday_variable_and_substitution_commands_stay_allowed(self):
        self.setup_services()
        for cwd in ("/tmp", self.home, self.home / "pp-ci"):
            for cmd in ("rm -f out_$n.log", "mv x.tmp.$$ x", "rm -rf build-$V", 'D=""; rm -rf "$D"',
                        'D=$(mktemp -d); rm -rf "$D"', "rm -rf `mktemp -d`", "rm %s/log-$d" % self.runner):
                self.allow(cmd, cwd=cwd)

    def test_substitutions_and_scopes_cannot_hide_a_delete(self):
        self.setup_services()
        h = str(self.home)
        with mock.patch.dict(os.environ, {"HOME": h}):
            for cmd, cwd in (("rm -rf $(pwd)/runner", self.home / "pp-ci"),
                             ("find ~/pp-ci/nm -mtime +$(echo 1) -delete", None),
                             ("cd ~/pp-ci && (cd /tmp && true) && rm -rf runner", "/tmp"),
                             ("cd ~/pp-ci && x=$(cd /tmp && pwd) && rm -rf runner", "/tmp"),
                             ("cd ~/pp-ci && x=`cd /tmp && pwd` && rm -rf runner", "/tmp"),
                             ("cd ~/pp-ci && bash -c 'cd /tmp' && rm -rf runner", "/tmp"),
                             ("cd ~/pp-ci && pushd /tmp && popd && rm -rf runner", "/tmp"),
                             ("cd /nonexistent && cd /tmp; rm -rf runner", self.home / "pp-ci"),
                             ("rm -rf %s/" % (self.home / "nm-link"), None),
                             ("find ~/pp-ci/nm \\( -name a -o -name b \\) -mtime +1 -delete", None),
                             ('export D=~/pp-ci/runner; rm -rf "$D"', None), ('local D=~/pp-ci/runner; rm -rf "$D"', None),
                             ('declare D=~/pp-ci/runner; rm -rf "$D"', None), ("A=1 D=~/pp-ci/nm; rm -rf $D", None),
                             ("rm -rf ~/pp-ci/*/*", None), ("find ~/pp-ci/nm ! -name keep -delete", None)):
                if "nm-link" in cmd and not (self.home / "nm-link").exists():
                    (self.home / "nm-link").symlink_to(self.nm)
                if "\\(" in cmd:
                    # name selectors: the root itself may stay, but nm is protected exactly and the find is selective,
                    # so this is allowed; the case only checks that escaped parentheses are not split as subshells.
                    self.assertEqual(tc.delete_targets_line(cmd, "/tmp")[0][2], "below", cmd)
                    continue
                self.deny(cmd, cwd)

    def test_scope_handling_is_what_catches_and_joined_forms(self):
        # Failing-first guard: with the PUSH/POP scoping removed these would resolve `runner` against /tmp.
        self.setup_services()
        with mock.patch.dict(os.environ, {"HOME": str(self.home)}):
            targets = tc.delete_targets_line("cd ~/pp-ci && (cd /tmp && true) && rm -rf runner", "/tmp")
        self.assertIn(str(self.runner), [p for p, _k, _m in targets])
        self.assertNotIn("/tmp/runner", [p for p, _k, _m in targets])

    def test_variable_components_parameter_forms_and_quoted_parens(self):
        self.setup_services()
        h = str(self.home)
        with mock.patch.dict(os.environ, {"HOME": h}):
            for cmd in ("rm -rf ~/pp-ci/nm/$d", "rm -rf ~/pp-ci/runner/$(cat f)", "find ~/pp-ci/nm/$d -delete",
                        "rm -rf ~/pp-ci/$d/*", "rm -rf ~/pp-ci/$d/", "rm -rf ~/pp-ci/$d/.*",
                        "x=$(echo \"$l\" | cut -d'(' -f1); rm -rf ~/pp-ci/nm",
                        'n=$(grep -c ")" f); rm -rf ~/pp-ci/nm',
                        "rm -rf ~/pp-ci/${T:-nm}", 'D=~/pp-ci; rm -rf "${D:?}/nm"', 'D=~/pp-ci/nm; rm -rf "${D%/}"',
                        "find ~/pp-ci/nm -type f | xargs -P $(nproc) rm -rf", "find ~/pp-ci/nm | xargs -n$(nproc) rm",
                        "find ~/pp-ci/nm ! \\( -name a -o -name b \\) -delete"):
                self.deny(cmd)
            for cmd, cwd in (("cd /tmp/build && rm -rf runner", self.home / "pp-ci"),
                             ("rm -rf ~/pp-ci/runner/log-$d", None), ("echo $((1+2)); rm -f /tmp/x", None)):
                self.allow(cmd, cwd)

    def test_variables_inside_components_and_defaults(self):
        self.setup_services()
        h = str(self.home)
        with mock.patch.dict(os.environ, {"HOME": h}):
            for cmd in ("rm -rf ~/pp-ci/nm/${f##*/}", "rm -rf ~/pp-ci/nm/${d%/}", "rm -rf ~/pp-ci/nm/$prefix*",
                        "rm -rf ~/pp-ci/nm/${d}*", "rm -rf ~/pp-ci/nm/$a$b", "find ~/pp-ci/nm/$d* -delete",
                        "D=$HOME/pp-ci; rm -rf $D/nm", 'rm -rf "${X:-$HOME/pp-ci}/nm"',
                        'D=~/pp-ci/nm/cache; rm -rf "${D%/*}"', "rm -rf $ROOT/pp-ci/$d",
                        "rm -f ~/pp-ci/runner/$f"):             # non-recursive, but $f may be the named gate.sh
                self.deny(cmd)
            for cmd in ("rm -rf ~/pp-ci/runner/log-$d*", "rm -f ~/coordinator-v2/rc/agent-harness/$f",
                        "find ~/coordinator-v2/rc/agent-harness -name '*.pyc' -not -path '*/node_modules/*' -delete",
                        'TMPDIR=$(mktemp -d); rm -rf "$TMPDIR"'):
                self.allow(cmd)

    def test_nested_defaults_recursive_detection_and_find_alternatives(self):
        self.setup_services()
        h = str(self.home)
        with mock.patch.dict(os.environ, {"HOME": h}):
            for cmd in ('rm -rf "${X:-${HOME}/pp-ci/nm}"', 'rm -rf "${X:-${HOME}/pp-ci}/nm"',
                        "D=${X:-${HOME}/pp-ci}; rm -rf $D/nm", "rm -rf ${X:-~/pp-ci}/nm",
                        "rm -f ~/pp-ci/runner/$d/gate.sh", "rm -f ~/pp-ci/$sub/runner/gate.sh",
                        "rm ~/pp-ci/nm/$d -rf", "OPTS=-rf; rm $OPTS ~/pp-ci/nm/$d", "rm $OPTS ~/pp-ci/nm/$d",
                        "rm -${R}f ~/pp-ci/nm/$d", "find ~/pp-ci/nm -name .git -prune -o -type f -delete",
                        "find ~/pp-ci/nm -name '*.keep' -o -delete", "rm -rf ~/pp-ci/nm # cleanup",
                        'D=~/pp-ci/nm/a/b; rm -rf "${D%%/b*}"'):
                self.deny(cmd)
            for cmd in ('rm -rf "$dir/$name"', 'rm -f "$tmp/$f"', 'rm -rf "$BUILD/$target/"',
                        "rm -rf ~/pp-ci/nm/x$", "rm -rf ~/coordinator-v2/rc/agent-harness/build/x$"):
                self.allow(cmd)

    def test_prune_cleanups_allowed_and_alternatives_and_positional_forms_denied(self):
        self.setup_services()
        h = str(self.home)
        # From the service checkout itself. From an ancestor that contains protected paths a selective find is
        # refused by design (the name filter could match inside them).
        for cmd in ("find . -name __pycache__ -prune -exec rm -rf {} +",
                    "find . -type d -name node_modules -prune -exec rm -rf {} +"):
            self.allow(cmd, self.rc)
        with mock.patch.dict(os.environ, {"HOME": h}):
            for cmd in ("find ~/pp-ci/nm \\( -name '*.keep' -o -delete \\)",
                        "find ~/pp-ci/nm -name .git -prune -o \\( -type f -delete \\)",
                        "find ~/pp-ci/nm -newer x -o -delete", 'D=${D:-$HOME/pp-ci}; rm -rf "$D/nm"',
                        "rm -rf ~/pp-ci/nm/$1", "rm -rf ~/pp-ci/nm/$@", "rm -rf ~/pp-ci/nm/${a[0]}",
                        "rm -rf ~/pp-ci/nm/$(cat f)", 'args=(-rf); rm "${args[@]}" ~/pp-ci/nm/$d'):
                self.deny(cmd)
            self.allow('D=%s/x/build/; rm -rf "${D%%/}"' % h)

    def test_find_grammar_per_action_selectivity(self):
        self.setup_services()
        h = str(self.home)
        with mock.patch.dict(os.environ, {"HOME": h}):
            for cmd in ("find ~/pp-ci/nm -exec chmod u+w {} + \\( -name '*.keep' -o -delete \\)",
                        "find ~/pp-ci/nm -exec echo {} \\; \\( -name '*.keep' -o -delete \\)",
                        "find ~/pp-ci/nm -name .git -prune -o -print0 | xargs -0 rm -rf",
                        "find ~/pp-ci/nm -name '*.keep' -o -print | xargs rm -rf",
                        "rm -rf $(find ~/pp-ci/nm -name .git -prune -o -print)",
                        "find ~/pp-ci/nm -prune -exec rm -rf {} +",
                        "find ~/pp-ci/nm -exec grep -o x {} \\; -o -delete",
                        "find ~/pp-ci/nm -exec sh -c 'echo )' \\; -delete"):
                self.deny(cmd)
        for cmd in ("find . -name .git -prune -o -name '*.pyc' -delete",
                    "find . -path ./node_modules -prune -o -name '*.orig' -exec rm {} +",
                    "find . -name '*.pyc' -delete -o -name __pycache__ -exec rm -rf {} +",
                    "find . \\( -name a -o -name b \\) \\( -type f -delete \\)",
                    "find . -name '*.log' -print | xargs rm -f", "rm -f $(find . -name '*.tmp')",
                    "find . -empty -name '*.lock' -delete"):
            self.allow(cmd, self.rc)

    def test_single_children_and_unrelated_paths_stay_allowed(self):
        self.setup_services()
        (self.rc / "build").mkdir()
        h = str(self.home)
        with mock.patch.dict(os.environ, {"HOME": h}):
            for cmd in ("rm -rf %s/build" % self.rc, "rm %s/gate.log" % self.runner, "mv %s/a %s/b" % (self.nm, self.nm),
                        "cd %s && rm -rf build" % self.rc, "find %s -name '*.log' -delete" % self.rc,
                        "rm -rf $HOME/other", "mv a.txt b.txt", "find %s -name x" % self.nm):
                self.allow(cmd)

    def test_find_from_an_ancestor_with_delete_is_denied_by_design(self):
        # `find . -delete` from ~ could reach a service directory; the deny is deliberate (message explains).
        self.setup_services()
        self.deny("find . -name __pycache__ -delete", cwd=self.home)

    def test_removing_a_symlink_to_a_service_dir_is_allowed(self):
        self.setup_services()
        link = self.home / "rc-link"
        link.symlink_to(self.rc)
        self.allow("rm %s" % link)

    def test_paths_inside_shell_strings_specifiers_and_attached_options(self):
        self.unit("gate.service", "[Service]\nExecStart=/bin/bash -lc 'cd %h/pp-ci/runner && exec ./gate.sh'\n"
                                  "WorkingDirectory=%h/runners/%i\nExecStartPost=/usr/bin/tool -C/opt/tooldir\n"
                                  "StandardOutput=append:/var/log/gate/out.log\n"
                                  "Environment=PATH=%h/pp-ci/nm/.bin:/usr/bin\n")
        prot = tc.protected_paths(self.cfg())
        for p in (self.home / "pp-ci" / "runner", self.home / "runners", Path("/opt/tooldir"),
                  Path("/var/log/gate/out.log"), self.home / "pp-ci" / "nm" / ".bin"):
            self.assertIn(str(p), prot, p)

    def test_quoted_and_tilde_working_directory_and_dropin_override(self):
        self.unit("a.service", '[Service]\nWorkingDirectory="%s"\n' % (self.home / "wd a"))
        self.unit("b.service", "[Service]\nWorkingDirectory=~\n")
        self.unit("10-x.conf", "[Service]\nExecStart=%h/b2/run\n", sub="b.service.d")
        (self.units / "b.service.d" / "20-more.conf").write_text("[Service]\nExecStart=\nExecStart=%h/b3/run\n")
        prot = tc.protected_paths(self.cfg())
        for p in (self.home / "wd a", self.home, self.home / "b2" / "run", self.home / "b3" / "run"):
            self.assertIn(str(p), prot, p)

    def test_system_units_use_root_and_user_homes(self):
        sysd = self.home / "sys"
        sysd.mkdir()
        (sysd / "svc.service").write_text("[Service]\nUser=nosuchuser-xyz\nWorkingDirectory=%h/svcdir\n")
        (sysd / "svc.service.d").mkdir()
        (sysd / "svc.service.d" / "x.conf").write_text("[Service]\nExecStart=~/svc2/run\n")
        with mock.patch.object(tc, "_unit_dirs", return_value=[(str(sysd), "system")]), \
                mock.patch.object(tc, "_user_home", side_effect=lambda u: "/home/svcuser" if u == "nosuchuser-xyz" else ""):
            prot = tc.protected_paths(self.cfg())
        for p in ("/root/svcdir", "/home/svcuser/svcdir", "/home/svcuser/svc2/run"):
            self.assertIn(p, prot, p)

    def test_linked_unit_source_is_protected(self):
        src = self.home / "checkout" / "units"
        src.mkdir(parents=True)
        (src / "x.service").write_text("[Service]\nExecStart=/usr/bin/true\n")
        (self.units / "x.service").symlink_to(src / "x.service")
        self.assertIn(str((src / "x.service").resolve()), tc.protected_paths(self.cfg()))

    @unittest.skipIf(os.geteuid() == 0, "root reads mode-000 files")
    def test_unreadable_unit_makes_the_reaper_keep_everything(self):
        old, _, _ = self.make_old_copies()
        bad = self.units / "secret.service"
        bad.write_text("[Service]\nWorkingDirectory=/x\n")
        bad.chmod(0)
        try:
            self.assertGreater(tc.protected_scan(self.cfg())[1], 0)
            acts = self.enabled_reap()
        finally:
            bad.chmod(0o644)
        self.assertEqual(acts[str(old)], "kept: could not read service units")
        self.assertTrue(old.exists())
        self.assertEqual(tc.main(["protected", "--check", str(self.home / "anything")]), 1)

    def test_pretool_fails_open_with_an_alert_when_the_check_breaks(self):
        with mock.patch.object(tc, "protected_delete", side_effect=RuntimeError("boom")):
            self.assertEqual(tc.pretool(self.ev("rm -rf /tmp/x"), self.cfg())[0], 0)
        log = self.home / ".agent-harness" / "state" / "copy-hygiene-alerts.jsonl"
        self.assertIn("protected-check-error", log.read_text())

    def test_check_cli(self):
        self.setup_services()
        self.assertEqual(tc.main(["protected", "--check", str(self.home / "pp-ci")]), 1)
        self.assertEqual(tc.main(["protected", "--check", str(self.home / "elsewhere")]), 0)

    def test_cache_notices_new_units(self):
        self.setup_services()
        self.assertNotIn(str(self.home / "new"), tc.protected_paths(self.cfg()))
        time.sleep(0.01)
        self.unit("new.service", "[Service]\nWorkingDirectory=%h/new\n")
        self.assertIn(str(self.home / "new"), tc.protected_paths(self.cfg()))

    def test_remove_copy_refuses_protected_path(self):
        self.setup_services()
        ok, why = tc.remove_copy(str(self.home / "pp-ci"))
        self.assertFalse(ok)
        self.assertIn("protected", why)
        self.assertTrue(self.runner.exists())


class Scratch(Base):
    def test_scratch_is_disk_backed_and_shm_message_points_to_it(self):
        with mock.patch.object(tc, "free_bytes", return_value=100 * GB):
            d = tc.scratch("pr-12")
            esc = tc.scratch("../../etc")
        self.assertTrue(os.path.isdir(d))
        self.assertEqual(os.stat(d).st_mode & 0o777, 0o700)
        self.assertTrue(esc.startswith(str(self.home / ".agent-harness" / "scratch") + "/"))
        with mock.patch.object(tc, "free_bytes", return_value=1 * GB):
            self.assertIsNone(tc.scratch("pr-13"))
        self.assertTrue(d.startswith(str(self.home / ".agent-harness" / "scratch")))
        code, err = tc.pretool({"tool_name": "Bash", "tool_input": {"command": "TMPDIR=/dev/shm/x make"}, "cwd": "/"},
                               self.cfg())
        self.assertEqual(code, 2)
        self.assertIn("copy_hygiene.py scratch", err)


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
        with tempfile.TemporaryDirectory() as h:
            for c in ids["copy_hygiene:pretool"]["canaries"]:
                p = subprocess.run([sys.executable, str(HOOKS / "copy_hygiene.py"), "pretool"],
                                   input=json.dumps(c["payload"]), capture_output=True, text=True,
                                   env=dict(os.environ, HARNESS_COPY_HYGIENE_HOME=h))
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
