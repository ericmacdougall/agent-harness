"""Workspace janitor: session release, TTL sweep, shm sweep, container caps, on the shared rules of hygiene_safety.

Every test runs under a temporary HARNESS_JANITOR_HOME with real git repositories. Nothing touches the real home folder.
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

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import copy_hygiene as C  # noqa: E402
import hygiene_safety as S  # noqa: E402
import workspace_janitor as wj  # noqa: E402

OLD = time.time() - 3 * 86400
ENV = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t", GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@t",
           GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_NOSYSTEM="1")


def sh(*a, cwd=None):
    subprocess.run(a, cwd=cwd, check=True, capture_output=True, env=ENV)


def age(p):
    for dp, dn, fn in os.walk(p):
        for f in dn + fn:
            os.utime(os.path.join(dp, f), (OLD, OLD), follow_symlinks=False)


class Base(unittest.TestCase):
    delete = True

    def setUp(self):
        self.t = tempfile.mkdtemp()
        self.home = os.path.join(self.t, "home")
        os.makedirs(self.home)
        self.patch_env = mock.patch.dict(os.environ, {"HARNESS_JANITOR_HOME": self.home, "GIT_CONFIG_GLOBAL": "/dev/null",
                                                      "GIT_CONFIG_NOSYSTEM": "1"})
        self.patch_env.start()
        os.environ.pop("HARNESS_COPY_HYGIENE_HOME", None)
        os.environ.pop("HARNESS_JANITOR", None)
        self.origin = os.path.join(self.t, "origin.git")
        sh("git", "init", "-q", "-b", "main", "--bare", self.origin)
        seed = os.path.join(self.t, "seed")
        sh("git", "init", "-q", "-b", "main", seed)
        Path(seed, "a").write_text("a")
        sh("git", "add", ".", cwd=seed)
        sh("git", "commit", "-qm", "a", cwd=seed)
        sh("git", "push", "-q", self.origin, "main", cwd=seed)
        self.work = os.path.join(self.home, ".agent-harness", "work")
        if self.delete:
            self.write_config(reaper_delete_enabled=True)

    def tearDown(self):
        mock.patch.stopall()

    def write_config(self, **kw):
        d = os.path.join(self.home, ".agent-harness", "state")
        os.makedirs(d, exist_ok=True)
        Path(d, "copy-hygiene.json").write_text(json.dumps(kw))

    def write_config_at(self, home, **kw):
        d = os.path.join(home, ".agent-harness", "state")
        os.makedirs(d, exist_ok=True)
        Path(d, "copy-hygiene.json").write_text(json.dumps(kw))

    def clone(self, rel):
        p = os.path.join(self.work, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        sh("git", "clone", "-q", self.origin, p)
        return p

    def exclude(self, repo, *lines):
        with open(os.path.join(repo, ".git", "info", "exclude"), "a") as f:
            f.write("\n".join(lines) + "\n")


class Release(Base):
    def setUp(self):
        super().setUp()
        mock.patch.object(S, "in_use_paths", return_value=set()).start()
        mock.patch.object(S, "service_refs", return_value=set()).start()

    def test_release_removes_clean_pushed_and_keeps_dirty(self):
        clean = self.clone("s1/clean")
        dirty = self.clone("s1/dirty")
        os.makedirs(os.path.join(clean, "node_modules", "x"))
        Path(dirty, "new.txt").write_text("work")
        r = wj.release(os.path.join(self.work, "s1"), apply=True)
        self.assertFalse(os.path.exists(clean))
        self.assertTrue(os.path.exists(dirty))
        self.assertEqual(r["kept"][0]["why"], "uncommitted or untracked changes")
        self.assertTrue(os.path.exists(os.path.join(self.work, "s1")))

    def test_release_keeps_unpushed_and_removes_empty_session(self):
        ahead = self.clone("s2/ahead")
        sh("git", "commit", "-q", "--allow-empty", "-m", "local", cwd=ahead)
        r = wj.release(os.path.join(self.work, "s2"), apply=True)
        self.assertTrue(os.path.exists(ahead))
        self.assertEqual(r["kept"][0]["why"], "HEAD is on no remote ref")
        sh("git", "push", "-q", "origin", "HEAD:refs/heads/f", cwd=ahead)
        wj.release(os.path.join(self.work, "s2"), apply=True)
        self.assertFalse(os.path.exists(os.path.join(self.work, "s2")))

    def test_service_reference_and_open_files_protect(self):
        c = self.clone("s3/svc")
        with mock.patch.object(S, "service_refs", return_value={c + "/run.sh"}):
            r = wj.release(os.path.join(self.work, "s3"), apply=True)
        self.assertTrue(os.path.exists(c))
        self.assertIn("systemd", r["kept"][0]["why"])
        with mock.patch.object(S, "in_use_paths", return_value={c + "/a"}):
            wj.release(os.path.join(self.work, "s3"), apply=True)
        self.assertTrue(os.path.exists(c))

    def test_linked_worktree_removed_with_plain_remove_and_base_kept(self):
        base = self.clone("s4/base")
        wt = os.path.join(self.work, "s5", "wt")
        os.makedirs(os.path.dirname(wt))
        sh("git", "worktree", "add", "-q", "--detach", wt, cwd=base)
        r = wj.release(os.path.join(self.work, "s4"), apply=True)          # base has a live worktree elsewhere
        self.assertTrue(os.path.exists(base))
        self.assertIn("other linked worktrees", r["kept"][0]["why"])
        wj.release(os.path.join(self.work, "s5"), apply=True)
        self.assertFalse(os.path.exists(wt))
        self.assertEqual(subprocess.run(["git", "-C", base, "worktree", "list"], capture_output=True, text=True).stdout.count("\n"), 1)

    def test_protected_name(self):
        c = self.clone("yates-x/c")
        wj.release(os.path.join(self.work, "yates-x"), apply=True)
        self.assertTrue(os.path.exists(c))

    def test_stale_remote_tracking_ref_is_not_trusted(self):
        c = self.clone("s9/stale")
        sh("git", "checkout", "-qb", "feat", cwd=c)
        sh("git", "commit", "-q", "--allow-empty", "-m", "work", cwd=c)
        sh("git", "push", "-q", "origin", "feat", cwd=c)
        sh("git", "--git-dir", self.origin, "branch", "-D", "feat")  # deleted on the remote; refs/remotes/origin/feat stays
        r = wj.release(os.path.join(self.work, "s9"), apply=True)
        self.assertTrue(os.path.exists(c), r)
        self.assertEqual(r["kept"][0]["why"], "HEAD is on no remote ref")

    def test_failed_probe_keeps_everything(self):
        c = self.clone("s10/clean")
        with mock.patch.object(S, "service_refs", side_effect=S.ProbeError("docker ps failed")):
            r = wj.release(os.path.join(self.work, "s10"), apply=True)
        self.assertTrue(os.path.exists(c))
        self.assertIn("liveness probe failed", r["kept"][0]["why"])

    def test_skip_worktree_edit_is_kept(self):
        c = self.clone("s11/hidden")
        sh("git", "update-index", "--skip-worktree", "a", cwd=c)
        Path(c, "a").write_text("local only")
        r = wj.release(os.path.join(self.work, "s11"), apply=True)
        self.assertTrue(os.path.exists(c))
        self.assertIn("skip-worktree", r["kept"][0]["why"])

    # ---- review blocker B1: ignored files
    def test_ignored_env_file_is_kept(self):
        c = self.clone("b1/proj")
        self.exclude(c, ".env", "evidence/")
        Path(c, ".env").write_text("SECRET=1")
        r = wj.release(os.path.join(self.work, "b1"), apply=True)
        self.assertTrue(os.path.exists(os.path.join(c, ".env")), r)
        self.assertIn("ignored files that may be evidence", r["kept"][0]["why"])

    def test_ignored_nested_repo_is_kept_with_its_parent(self):
        c = self.clone("b1n/proj")
        self.exclude(c, "vendor/")
        inner = os.path.join(c, "vendor", "lib")
        os.makedirs(inner)
        sh("git", "init", "-q", inner)
        Path(inner, "wip.txt").write_text("unsaved work")
        self.assertFalse(S.recoverable(c)[0])        # the parent alone must already fail: it holds an ignored nested repo
        r = wj.release(os.path.join(self.work, "b1n"), apply=True)
        self.assertTrue(os.path.exists(os.path.join(inner, "wip.txt")), r)
        self.assertTrue(os.path.exists(c))
        whys = {k["path"]: k["why"] for k in r["kept"]}
        self.assertIn(inner, whys)
        self.assertIn(c, whys)

    def test_regenerable_folder_holding_a_repo_is_kept_unless_it_is_a_dependency_folder(self):
        c = self.clone("b1r/proj")
        self.exclude(c, "build/")
        sh("git", "init", "-q", os.path.join(c, "build", "keep"))
        r = wj.release(os.path.join(self.work, "b1r"), apply=True)
        self.assertTrue(os.path.exists(c))
        self.assertIn("nested repository", r["kept"][0]["why"])
        d = self.clone("b1r2/proj")
        self.exclude(d, "node_modules/")
        sh("git", "init", "-q", os.path.join(d, "node_modules", "dep"))
        wj.release(os.path.join(self.work, "b1r2"), apply=True)
        self.assertFalse(os.path.exists(d))

    # ---- one deletion switch, shared with copy_hygiene
    def test_deletion_is_off_by_default_and_with_the_kill_switch(self):
        c = self.clone("sw/c")
        os.remove(os.path.join(self.home, ".agent-harness", "state", "copy-hygiene.json"))
        r = wj.release(os.path.join(self.work, "sw"), apply=True)
        self.assertTrue(os.path.exists(c))
        self.assertEqual(r["removed"][0], c)                       # reported only
        self.write_config(reaper_delete_enabled=True)
        with mock.patch.dict(os.environ, {"HARNESS_JANITOR": "off"}):
            wj.release(os.path.join(self.work, "sw"), apply=True)
        self.assertTrue(os.path.exists(c))
        self.write_config(reaper_delete_enabled="yes")             # only a literal true enables it
        wj.release(os.path.join(self.work, "sw"), apply=True)
        self.assertTrue(os.path.exists(c))
        self.write_config(reaper_delete_enabled=True)
        wj.release(os.path.join(self.work, "sw"), apply=True)
        self.assertFalse(os.path.exists(c))

    def test_dry_run_reports_the_session_folder_it_would_remove(self):
        self.clone("dry/c")
        r = wj.release(os.path.join(self.work, "dry"), apply=False)
        self.assertIn(os.path.join(self.work, "dry"), r["removed"])
        self.assertTrue(os.path.exists(os.path.join(self.work, "dry", "c")))

    def test_session_folder_with_loose_files_is_never_removed(self):
        self.clone("loose/c")
        notes = Path(self.work, "loose", "build", "notes.txt")
        notes.parent.mkdir()
        notes.write_text("keep me")                                 # a loose file in a regenerable-looking folder
        wj.release(os.path.join(self.work, "loose"), apply=True)
        self.assertTrue(notes.exists())

    def test_a_running_acquire_lock_keeps_the_copy(self):
        res = C.acquire("", "pr-7", url=self.origin, cfg=C.normalize({"min_free_gb": 0, "min_free_pct": 0}))
        self.assertTrue(res["ok"], res)
        lk = S.lock_nonblocking(res["path"] + ".lock")
        try:
            r = wj.release(os.path.dirname(res["path"]), apply=True)
        finally:
            lk.close()
        self.assertTrue(os.path.exists(res["path"]))
        self.assertEqual(r["kept"][0]["why"], "locked by a running acquire")
        wj.release(os.path.dirname(res["path"]), apply=True)
        self.assertFalse(os.path.exists(res["path"]))

    def test_release_realpath_session_path_takes_the_lock_under_a_symlinked_home(self):
        real_home = os.path.join(self.t, "real-home")
        os.makedirs(real_home)
        link = os.path.join(self.t, "home-link")
        os.symlink(real_home, link)
        with mock.patch.dict(os.environ, {"HARNESS_JANITOR_HOME": link}):
            res = C.acquire("", "pr-8", url=self.origin, cfg=C.normalize({"min_free_gb": 0, "min_free_pct": 0}))
            self.assertTrue(res["ok"], res)
            real_dir = os.path.realpath(os.path.dirname(res["path"]))      # what the CLI passes (--path is realpath'd)
            self.write_config_at(link, reaper_delete_enabled=True)
            lk = S.lock_nonblocking(res["path"] + ".lock")
            try:
                r = wj.release(real_dir, apply=True)
            finally:
                lk.close()
        self.assertTrue(os.path.exists(res["path"]), r)
        self.assertEqual(r["kept"][0]["why"], "locked by a running acquire")

    def test_acquire_between_snapshot_and_removal_prevents_release_deletion(self):
        res = C.acquire("", "pr-12", url=self.origin, cfg=C.normalize({"min_free_gb": 0, "min_free_pct": 0}))
        self.assertTrue(res["ok"], res)
        p = res["path"]
        real_lock = S.lock_nonblocking

        def lock_after_acquire(path):
            C.touch_index(p)
            return real_lock(path)
        with mock.patch.object(S, "lock_nonblocking", side_effect=lock_after_acquire):
            r = wj.release(os.path.dirname(p), apply=True, min_idle_s=3600, now=time.time() - 1)
        self.assertTrue(os.path.exists(p), r)
        self.assertEqual(r["kept"][0]["why"], "used since the sweep started")

    def test_release_probes_again_right_before_removal(self):
        c = self.clone("s14/c")
        seen = []
        states = iter([{c}])             # the caller's snapshot is empty; the fresh probe sees a process in c

        def fresh():
            seen.append(1)
            return next(states)
        with mock.patch.object(S, "in_use_paths", side_effect=fresh):
            r = wj.release(os.path.join(self.work, "s14"), apply=True, used=set(), refs=set())
        self.assertTrue(os.path.exists(c), r)
        self.assertEqual(len(seen), 1)

    # ---- restricted roots
    def test_release_path_is_restricted_to_the_agent_harness_trees(self):
        proj = os.path.join(self.home, "projects", "real")
        os.makedirs(proj)
        for bad in (self.home, proj, os.path.join(self.home, ".agent-harness"), self.work):
            with self.assertRaises(SystemExit) as cm, mock.patch("sys.stderr"):
                wj.main(["release", "--path", bad, "--apply"])
            self.assertEqual(cm.exception.code, 2, bad)
        self.assertTrue(os.path.isdir(proj))
        r = wj.release(proj, apply=True)
        self.assertIn("outside", r["kept"][0]["why"])

    def test_work_roots_outside_the_trees_are_ignored_by_the_sweep(self):
        outside = os.path.join(self.home, "projects")
        c = os.path.join(outside, "s", "c")
        os.makedirs(os.path.dirname(c))
        sh("git", "clone", "-q", self.origin, c)
        self.write_config(reaper_delete_enabled=True, roots=[outside], max_age_hours=0)
        with mock.patch.object(wj, "uncapped_containers", return_value=[]), mock.patch.object(wj, "shm_sweep", return_value=[]):
            wj.sweep(apply=True, now=time.time() + 86400)
        self.assertTrue(os.path.exists(c))


class Sweep(Base):
    def setUp(self):
        super().setUp()
        mock.patch.object(S, "in_use_paths", return_value=set()).start()
        mock.patch.object(S, "service_refs", return_value=set()).start()
        mock.patch.object(wj, "uncapped_containers", return_value=[]).start()
        mock.patch.object(wj, "shm_sweep", return_value=[]).start()

    def test_sweep_respects_ttl(self):
        fresh = self.clone("s7/fresh")
        old = self.clone("s8/old")
        real = S.newest_activity
        with mock.patch.object(S, "newest_activity", side_effect=lambda p: (OLD if "/s8" in p else real(p))):
            r = wj.sweep(apply=True)
        self.assertTrue(os.path.exists(fresh))
        self.assertFalse(os.path.exists(old))
        self.assertEqual(r["mode"], "apply")

    def test_ctime_keeps_a_fresh_copy_that_cp_a_aged(self):
        c = self.clone("s12/c")
        age(os.path.join(self.work, "s12"))            # mtime old, ctime now: what cp -a / rsync -a leave behind
        wj.sweep(apply=True)
        self.assertTrue(os.path.exists(c))

    def test_sweep_is_report_only_until_the_owner_enables_deletion(self):
        os.remove(os.path.join(self.home, ".agent-harness", "state", "copy-hygiene.json"))
        old = self.clone("s13/old")
        with mock.patch.object(S, "newest_activity", return_value=OLD):
            r = wj.sweep(apply=True)
        self.assertTrue(os.path.exists(old))
        self.assertEqual(r["mode"], "report-only")
        self.assertIn("deletion is OFF", r["note"])

    def test_session_with_a_live_claude_process_is_skipped(self):
        sid = "5cbde717-82cc-47bc-8dc9-2f15ea122398"
        c = self.clone(sid + "/c")
        with mock.patch.object(S, "newest_activity", return_value=OLD), \
                mock.patch.object(wj, "live_sessions", return_value={sid}):
            r = wj.sweep(apply=True)
        self.assertTrue(os.path.exists(c))
        self.assertEqual(r["released"][0]["kept"][0]["why"], "session is alive or recent")

    def test_live_sessions_reads_command_lines_and_the_wal(self):
        sid = "11111111-2222-4333-8444-555555555555"
        p = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)", "--session-id", sid])
        try:
            time.sleep(0.3)
            self.assertEqual(wj.live_sessions([sid, "99999999-aaaa"], 3600, time.time()), {sid})
        finally:
            p.kill()
            p.wait()
        wal = os.path.join(self.home, ".claude", "wals", "22222222-3333-4444-8555-666666666666")
        os.makedirs(wal)
        Path(wal, "main.jsonl").write_text("{}")
        self.assertEqual(wj.live_sessions(["22222222-3333-4444-8555-666666666666"], 3600, time.time()),
                         {"22222222-3333-4444-8555-666666666666"})

    def test_probe_failure_keeps_everything_and_exits_zero(self):
        c = self.clone("s14/c")
        with mock.patch.object(S, "newest_activity", return_value=OLD), \
                mock.patch.object(S, "service_refs", side_effect=S.ProbeError("systemctl show timed out")):
            r = wj.sweep(apply=True)
            self.assertIn("systemctl show", r["probe_error"])
            with mock.patch("sys.stdout"):
                self.assertEqual(wj.main(["sweep", "--apply"]), 0)
        self.assertTrue(os.path.exists(c))


class MirrorSweep(Base):
    def setUp(self):
        super().setUp()
        mock.patch.object(S, "in_use_paths", return_value=set()).start()
        mock.patch.object(S, "service_refs", return_value=set()).start()
        mock.patch.object(wj, "uncapped_containers", return_value=[]).start()
        mock.patch.object(wj, "shm_sweep", return_value=[]).start()
        self.cfg_ = C.normalize({"reaper_delete_enabled": True, "mirror_ttl_days": 14})
        res = C.acquire("", "pr-1", url=self.origin, cfg=C.normalize({"min_free_gb": 0, "min_free_pct": 0}))
        self.assertTrue(res["ok"], res)
        self.copy = res["path"]
        self.mirror = C.mirror_path(self.origin)
        self.later = time.time() + 30 * 86400

    def drop_copy_folder(self):
        import shutil
        shutil.rmtree(self.copy)                # folder gone; git still lists the worktree as prunable

    def test_sweep_reports_count_and_size_and_keeps_a_young_mirror(self):
        r = wj.sweep(apply=True, cfg=self.cfg_)
        self.assertEqual(r["mirrors"]["count"], 1)
        self.assertGreater(r["mirrors"]["bytes"], 0)
        self.assertEqual(r["mirrors"]["rows"][0]["action"], "keep")
        self.assertTrue(os.path.isdir(self.mirror))

    def test_mirror_with_a_registered_worktree_is_kept_even_when_old(self):
        r = wj.mirror_sweep(True, self.cfg_, self.later)
        self.assertIn("registered worktree", r["rows"][0]["action"])
        self.assertTrue(os.path.isdir(self.mirror))

    def test_old_mirror_without_worktrees_is_removed_only_when_deletion_is_on(self):
        self.drop_copy_folder()
        off = C.normalize({"mirror_ttl_days": 14})
        self.assertEqual(wj.mirror_sweep(True, off, self.later)["rows"][0]["action"], "would remove (report-only)")
        self.assertEqual(wj.mirror_sweep(False, self.cfg_, self.later)["rows"][0]["action"], "would remove (report-only)")
        self.assertTrue(os.path.isdir(self.mirror))
        self.assertEqual(wj.mirror_sweep(True, self.cfg_, self.later)["rows"][0]["action"], "removed")
        self.assertFalse(os.path.exists(self.mirror))

    def test_in_use_service_referenced_probe_failed_and_locked_mirrors_are_kept(self):
        self.drop_copy_folder()
        with mock.patch.object(S, "in_use_paths", return_value={self.mirror}):
            self.assertIn("process", wj.mirror_sweep(True, self.cfg_, self.later)["rows"][0]["action"])
        with mock.patch.object(S, "service_refs", return_value={self.mirror + "/HEAD"}):
            self.assertIn("referenced", wj.mirror_sweep(True, self.cfg_, self.later)["rows"][0]["action"])
        with mock.patch.object(S, "service_refs", side_effect=S.ProbeError("x")):
            self.assertIn("probe failed", wj.mirror_sweep(True, self.cfg_, self.later)["rows"][0]["action"])
        lk = S.lock_nonblocking(self.mirror + ".lock")
        try:
            self.assertIn("locked", wj.mirror_sweep(True, self.cfg_, self.later)["rows"][0]["action"])
        finally:
            lk.close()
        self.assertTrue(os.path.isdir(self.mirror))

    def test_mirror_ttl_days_is_configurable_and_sanitised(self):
        self.assertEqual(C.normalize({})["mirror_ttl_days"], 14.0)
        self.assertEqual(C.normalize({"mirror_ttl_days": "bad"})["mirror_ttl_days"], 14.0)
        self.assertEqual(C.normalize({"mirror_ttl_days": 3})["mirror_ttl_days"], 3.0)


class ShmSweep(Base):
    delete = True

    def setUp(self):
        super().setUp()
        self.shm = os.path.join(self.t, "shm")
        os.makedirs(self.shm)
        mock.patch.object(wj, "SHM_DIR", self.shm).start()
        self.cfg = C.load_config()

    def make(self, name, data=b"x" * 4096, isdir=False):
        p = os.path.join(self.shm, name)
        if isdir:
            os.makedirs(p)
            Path(p, "f").write_bytes(data)
        else:
            Path(p).write_bytes(data)
        os.utime(p, (OLD, OLD))
        if isdir:
            os.utime(os.path.join(p, "f"), (OLD, OLD))
        return p

    def sweep_with_ctime_old(self, apply=True, used=None):
        later = time.time() + 3 * 86400            # ctime cannot be backdated, so move "now" forward instead
        return wj.shm_sweep(apply, S.in_use_paths() if used is None else used, self.cfg, later)

    def test_idle_entries_are_removed_and_semaphores_postgres_segments_are_not(self):
        f = self.make("scratch.bin")
        d = self.make("session-dir", isdir=True)
        sem = self.make("sem.mylock")
        pg = self.make("PostgreSQL.1234")
        rows = self.sweep_with_ctime_old()
        self.assertFalse(os.path.exists(f))
        self.assertFalse(os.path.exists(d))
        self.assertTrue(os.path.exists(sem) and os.path.exists(pg))
        self.assertEqual(sorted(r["action"] for r in rows), ["removed", "removed"])

    def test_a_file_a_process_mapped_and_closed_is_kept(self):
        f = self.make("dsm.segment", data=b"\0" * 8192)
        # libc mmap, then close the descriptor: Python's own mmap module keeps a dup'd descriptor open
        code = ("import ctypes,os,sys,time\nfd=os.open(sys.argv[1],os.O_RDWR)\nl=ctypes.CDLL(None)\n"
                "l.mmap.restype=ctypes.c_void_p\nl.mmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_long]\n"
                "a=l.mmap(None,8192,3,1,fd,0)\nassert a not in (None,2**64-1)\nos.close(fd)\n"
                "print('ready',flush=True)\ntime.sleep(60)\n")
        p = subprocess.Popen([sys.executable, "-c", code, f], stdout=subprocess.PIPE, text=True)
        try:
            self.assertEqual(p.stdout.readline().strip(), "ready")
            self.assertFalse(any(os.readlink("/proc/%d/fd/%s" % (p.pid, x)) == f for x in os.listdir("/proc/%d/fd" % p.pid)))
            rows = self.sweep_with_ctime_old()
            self.assertTrue(os.path.exists(f), rows)
            self.assertEqual(rows[0]["action"], "kept: open or mapped")
        finally:
            p.kill()
            p.wait()
        self.sweep_with_ctime_old()
        self.assertFalse(os.path.exists(f))

    def test_a_race_on_removal_does_not_crash_the_sweep(self):
        a = self.make("a.bin")
        b = self.make("b.bin")
        real = os.unlink

        def flaky(p, *x, **k):
            if p == a:
                raise FileNotFoundError(p)
            return real(p, *x, **k)
        with mock.patch("os.unlink", side_effect=flaky):
            rows = self.sweep_with_ctime_old()
        self.assertFalse(os.path.exists(b))
        self.assertTrue(any(r["action"].startswith("kept: remove failed") for r in rows))

    def test_report_only_removes_nothing(self):
        f = self.make("x.bin")
        rows = self.sweep_with_ctime_old(apply=False)
        self.assertTrue(os.path.exists(f))
        self.assertEqual(rows[0]["action"], "would remove")


class Pretool(unittest.TestCase):
    def setUp(self):
        self.cfg = C.normalize({})

    def ev(self, c, cwd="/"):
        return wj.pretool({"tool_name": "Bash", "tool_input": {"command": c}, "cwd": cwd}, self.cfg)[0]

    def test_container_caps(self):
        self.assertEqual(self.ev("docker run -d redis"), 2)
        self.assertEqual(self.ev("docker run -d --memory 2g redis"), 0)
        self.assertEqual(self.ev("docker run -m=2g redis"), 0)
        self.assertEqual(self.ev("docker run -m2g redis"), 0)
        self.assertEqual(self.ev("cd x && sudo docker run --memory=4g elasticsearch:8"), 2)
        self.assertEqual(self.ev("docker run --memory=4g -e ES_JAVA_OPTS='-Xmx1g' elasticsearch:8"), 0)
        self.assertEqual(self.ev("docker ps; echo 'docker run x'"), 0)
        self.assertEqual(wj.pretool({"tool_name": "Read"}, self.cfg)[0], 0)
        self.assertEqual(self.ev("docker run 'unterminated"), 2)       # unparseable: judged on its words, never skipped
        self.assertEqual(self.ev("docker run --memory 0 redis"), 2)

    def test_flags_after_the_image_name_are_not_the_containers_cap(self):
        self.assertEqual(self.ev("docker run python:3 python -m http.server"), 2)
        self.assertEqual(self.ev("docker run --memory 1g python:3 python -m http.server"), 0)
        self.assertEqual(self.ev("docker run -e A=1 -v /a:/b -p 80:80 python:3 python -m http.server"), 2)

    def test_prefixes_subshells_and_subcommands(self):
        for c in ("timeout 60 docker run redis", "env FOO=1 docker run redis", "env -i FOO=1 docker run redis",
                  "nice -n 5 docker run redis", "command docker run redis", "x=$(docker run redis)",
                  "echo hi | docker run -i redis", "docker container run redis", "docker --context c run redis",
                  "sudo -u bob docker create redis", "podman run redis", "bash -c 'docker run redis'",
                  "timeout -s KILL 30 docker run redis"):
            self.assertEqual(self.ev(c), 2, c)
        self.assertEqual(self.ev("timeout 60 docker run -m 1g redis"), 0)
        self.assertEqual(self.ev("docker container run --memory 1g redis"), 0)

    def test_compose_files_are_checked(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, "docker-compose.yml").write_text("services:\n  db:\n    image: postgres\n")
            self.assertEqual(self.ev("docker compose up -d", cwd=d), 2)
            self.assertEqual(self.ev("docker-compose up", cwd=d), 2)
            self.assertEqual(self.ev("docker compose down", cwd=d), 0)
            Path(d, "docker-compose.yml").write_text("services:\n  db:\n    image: postgres\n    mem_limit: 1g\n")
            self.assertEqual(self.ev("docker compose up -d", cwd=d), 0)
            Path(d, "other.yml").write_text("services:\n  x:\n    image: y\n")
            self.assertEqual(self.ev("docker compose -f other.yml up", cwd=d), 2)
        self.assertEqual(self.ev("docker compose up", cwd="/nonexistent"), 0)

    def test_elasticsearch_heap_may_come_from_an_env_file(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, "es.env").write_text("ES_JAVA_OPTS=-Xmx1g\n")
            self.assertEqual(self.ev("docker run -m 4g --env-file es.env elasticsearch:8", cwd=d), 0)
            self.assertEqual(self.ev("docker run -m 4g elasticsearch:8", cwd=d), 2)

    def test_fails_open(self):
        with mock.patch.object(wj, "command_problem", side_effect=RuntimeError("boom")):
            self.assertEqual(self.ev("docker run redis"), 0)


class SessionEnd(Base):
    def run_hook(self, payload):
        with mock.patch("sys.stdin", __import__("io").StringIO(payload)), mock.patch.object(wj.subprocess, "Popen") as po:
            code = wj.main(["session-end"])
        return code, po

    def test_deletion_off_starts_nothing(self):
        os.remove(os.path.join(self.home, ".agent-harness", "state", "copy-hygiene.json"))
        os.makedirs(os.path.join(self.work, "abc12345"))
        code, po = self.run_hook(json.dumps({"session_id": "abc12345"}))
        self.assertEqual(code, 0)
        po.assert_not_called()

    def test_enabled_starts_a_detached_budgeted_release(self):
        os.makedirs(os.path.join(self.work, "abc12345"))
        code, po = self.run_hook(json.dumps({"session_id": "abc12345"}))
        self.assertEqual(code, 0)
        args, kw = po.call_args
        self.assertIn("release", args[0])
        self.assertIn("--budget", args[0])
        self.assertTrue(kw["start_new_session"])

    def test_empty_or_bad_session_id_and_bad_json_exit_zero(self):
        for payload in ('{"session_id": ""}', "{}", "not json", '{"session_id": "../../etc"}'):
            code, po = self.run_hook(payload)
            self.assertEqual(code, 0, payload)
            po.assert_not_called()


class InstallTimer(unittest.TestCase):
    """install.py --janitor-timer: opt-in, unit files carry the limits, linger is advised, failures never raise."""

    def setUp(self):
        sys.path.insert(0, str(HOOKS.parents[1]))
        import install
        self.install = install
        self.home = Path(tempfile.mkdtemp())

    def fake(self, linger="no", fail=None):
        calls = []

        def run(argv):
            calls.append(argv)
            rc = 1 if fail and fail in " ".join(argv) else 0
            return subprocess.CompletedProcess(argv, rc, stdout=linger + "\n", stderr="denied" if rc else "")
        return run, calls

    def test_not_installed_unless_asked_and_preview_writes_nothing(self):
        self.assertIn("not installed", self.install.janitor_timer_status(self.home, True, False))
        self.assertIn("would install", self.install.janitor_timer_status(self.home, False, True))
        self.assertFalse((self.home / ".config").exists())

    def test_apply_writes_units_enables_the_timer_and_advises_linger(self):
        run, calls = self.fake()
        msg = self.install.janitor_timer_status(self.home, True, True, run=run)
        d = self.home / ".config" / "systemd" / "user"
        service = (d / "agent-harness-janitor.service").read_text()
        self.assertIn("TimeoutStartSec=", service)
        self.assertIn("MemoryMax=", service)
        self.assertIn("workspace_janitor.py sweep --apply", service)
        self.assertTrue((d / "agent-harness-janitor.timer").exists())
        self.assertIn(["systemctl", "--user", "enable", "--now", "agent-harness-janitor.timer"], calls)
        self.assertIn("enable-linger", msg)
        self.assertIn("report-only", msg)

    def test_linger_already_on_needs_no_advice_and_a_failing_systemctl_is_reported_not_raised(self):
        run, _ = self.fake(linger="yes")
        self.assertNotIn("enable-linger", self.install.janitor_timer_status(self.home, True, True, run=run))
        run, _ = self.fake(fail="enable")
        self.assertIn("failed", self.install.janitor_timer_status(self.home, True, True, run=run))

    def test_symlinked_unit_directory_is_refused(self):
        real = self.home / "elsewhere"
        real.mkdir()
        (self.home / ".config").mkdir()
        (self.home / ".config" / "systemd").symlink_to(real)
        run, calls = self.fake()
        self.assertIn("symlinked", self.install.janitor_timer_status(self.home, True, True, run=run))
        self.assertEqual(calls, [])

    def test_installer_ships_the_shared_module_with_the_hooks(self):
        self.assertIn("hygiene_safety.py", self.install.HOOKS)
        self.assertIn("workspace_janitor.py", self.install.HOOKS)


if __name__ == "__main__":
    unittest.main()
