"""Workspace janitor: session release, TTL sweep, shm sweep, container caps, on the shared rules of hygiene_safety.

Every test runs under a temporary HARNESS_JANITOR_HOME with real git repositories. Nothing touches the real home folder.
"""
import json
import os
import shutil
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

REAL_IN_USE = S.in_use_paths        # Base stubs the probe; the /proc test below needs the real one
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
    """Hermetic janitor fixture: a temp home, a bare origin and a seed repo. setUp stubs S.in_use_paths for the whole suite
    (the real probe is slow); only the /proc test uses the real one."""
    delete = True

    def setUp(self):
        self.t = os.path.realpath(tempfile.mkdtemp())            # macOS: /var -> /private/var
        self.home = os.path.join(self.t, "home")
        os.makedirs(self.home)
        units = os.path.join(self.t, "units")                   # hermetic: never read the real systemd/launchd folders
        os.makedirs(units)
        self.patch_env = mock.patch.dict(os.environ, {"HARNESS_JANITOR_HOME": self.home, "GIT_CONFIG_GLOBAL": "/dev/null",
                                                      "GIT_CONFIG_NOSYSTEM": "1", "HARNESS_COPY_HYGIENE_UNIT_DIRS": units})
        self.patch_env.start()
        mock.patch.object(S, "in_use_paths", return_value=set()).start()      # the real probe is slow (lsof on macOS); tests that need it patch it again
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
        self.assertEqual(r["would_remove"][0], c)                  # reported only
        self.assertEqual((r["removed"], r["freed_bytes"], r["mode"]), ([], 0, "report-only"))
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
        self.assertIn(os.path.join(self.work, "dry"), r["would_remove"])
        self.assertEqual(r["removed"], [])
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


    # ---- Fable review: S1 protect_names per repo and by remote URL
    def test_protected_name_inside_a_session_folder_keeps_the_clone_and_the_folder(self):
        c = self.clone("sess-1/yates")
        r = wj.release(os.path.join(self.work, "sess-1"), apply=True)
        self.assertTrue(os.path.exists(c), r)
        self.assertTrue(os.path.exists(os.path.join(self.work, "sess-1")))
        self.assertIn("protected name", r["kept"][0]["why"])

    def test_protect_names_also_matches_the_remote_url(self):
        self.write_config(reaper_delete_enabled=True, protect_names=["origin.git"])      # the clone's URL, not its name
        c = self.clone("sess-2/innocent")
        r = wj.release(os.path.join(self.work, "sess-2"), apply=True)
        self.assertTrue(os.path.exists(c), r)
        self.assertIn("remote URL", r["kept"][0]["why"])

    def test_reap_never_removes_a_protected_name_or_url(self):
        cp = os.path.join(self.home, ".agent-harness", "test-copies")
        named = os.path.join(cp, "yates-x", "k")
        os.makedirs(os.path.dirname(named))
        sh("git", "clone", "-q", self.origin, named)
        cfg = C.normalize({"reaper_delete_enabled": True, "max_age_hours": 0})
        self.assertIn("protected name", C._reap_one({"path": named, "min_idle_hours": 0}, time.time() + 9, cfg))
        self.assertTrue(os.path.exists(named))
        rows = C.reap(apply=True, cfg=cfg, now=time.time() + 9)["copies"]
        self.assertTrue(os.path.exists(named), rows)
        self.assertTrue(all("protected" in r["action"] for r in rows if r["path"] == named), rows)
        byurl = os.path.join(cp, "plain", "k")
        os.makedirs(os.path.dirname(byurl))
        sh("git", "clone", "-q", self.origin, byurl)
        cfg = C.normalize({"reaper_delete_enabled": True, "max_age_hours": 0, "protect_names": ["origin.git"]})
        self.assertIn("remote URL", C._reap_one({"path": byurl, "min_idle_hours": 0}, time.time() + 9, cfg))
        self.assertTrue(os.path.exists(byurl))

    # ---- S2 report-only wording
    def test_report_only_release_says_would_remove_never_removed(self):
        self.clone("ro/c")
        os.remove(os.path.join(self.home, ".agent-harness", "state", "copy-hygiene.json"))
        r = wj.release(os.path.join(self.work, "ro"), apply=True)
        self.assertEqual(r["mode"], "report-only")
        self.assertEqual((r["removed"], r["freed_bytes"]), ([], 0))
        self.assertTrue(r["would_remove"] and r["would_free_bytes"] > 0)
        self.write_config(reaper_delete_enabled=True)
        r = wj.release(os.path.join(self.work, "ro"), apply=True)
        self.assertEqual(r["mode"], "apply")
        self.assertTrue(r["removed"] and r["freed_bytes"] > 0 and r["would_remove"] == [])

    # ---- S3 one fresh, fail-closed removal function
    def test_every_removal_re_reads_the_service_units_without_the_cache(self):
        self.clone("fr/c")
        with mock.patch.object(C, "protected_scan", wraps=C.protected_scan) as ps:
            wj.release(os.path.join(self.work, "fr"), apply=True)
        self.assertFalse(os.path.exists(os.path.join(self.work, "fr")))
        calls = [c for c in ps.call_args_list]
        self.assertGreaterEqual(len(calls), 2)                               # the checkout and the session folder
        self.assertTrue(all(c.kwargs.get("fresh") is True for c in calls), calls)

    def test_removal_fails_closed_when_the_unit_scan_fails_and_honours_a_unit_that_names_it(self):
        c = self.clone("fc/c")
        with mock.patch.object(C, "protected_scan", side_effect=OSError("boom")):
            r = wj.release(os.path.join(self.work, "fc"), apply=True)
        self.assertTrue(os.path.exists(c), r)
        self.assertIn("protection check failed", r["kept"][0]["why"])
        units = os.environ["HARNESS_COPY_HYGIENE_UNIT_DIRS"]
        Path(units, "svc.service").write_text("[Service]\nWorkingDirectory=%s\nExecStart=/bin/true\n" % c)
        r = wj.release(os.path.join(self.work, "fc"), apply=True)           # S.service_refs is mocked empty here
        self.assertTrue(os.path.exists(c), r)
        self.assertIn("protected", r["kept"][0]["why"])

    # ---- S4 session folder: no rmtree of a stale check
    def test_a_file_written_before_the_session_folder_removal_survives(self):
        self.clone("late/c")
        sess = os.path.join(self.work, "late")
        real = S.du

        def du(path):
            n = real(path)
            if path == sess:
                Path(sess, "job-state.json").write_text("{}")             # written after the last scan
            return n
        with mock.patch.object(S, "du", side_effect=du):
            wj.release(sess, apply=True)
        self.assertTrue(os.path.exists(os.path.join(sess, "job-state.json")))

    def test_safe_remove_empty_tree_stops_at_the_first_file_and_never_uses_rmtree(self):
        d = os.path.join(self.work, "et")
        os.makedirs(os.path.join(d, "a", "b"))
        os.makedirs(os.path.join(d, "z"))
        Path(d, "a", "keep.txt").write_text("x")
        with mock.patch("shutil.rmtree", side_effect=AssertionError("rmtree")):
            ok, why = C.safe_remove(d, "empty-tree")
        self.assertFalse(ok)
        self.assertTrue(os.path.exists(os.path.join(d, "a", "keep.txt")))
        os.remove(os.path.join(d, "a", "keep.txt"))
        ok, why = C.safe_remove(d, "empty-tree")
        self.assertTrue(ok, why)
        self.assertFalse(os.path.exists(d))

    # ---- S5 evidence folders, nested repos
    def test_test_results_and_playwright_report_are_kept_as_evidence(self):
        for name in ("test-results", "playwright-report"):
            c = self.clone("ev-%s/c" % name)
            self.exclude(c, name + "/")
            os.makedirs(os.path.join(c, name))
            Path(c, name, "shot.png").write_text("evidence")
            r = wj.release(os.path.join(self.work, "ev-" + name), apply=True)
            self.assertTrue(os.path.exists(os.path.join(c, name, "shot.png")), r)
            self.assertIn("may be evidence", r["kept"][0]["why"])

    def test_a_clone_under_an_ignored_dot_cache_is_checked_not_deleted_blind(self):
        c = self.clone("dc/proj")
        self.exclude(c, ".cache/")
        sh("git", "init", "-q", os.path.join(c, ".cache", "keep"))
        r = wj.release(os.path.join(self.work, "dc"), apply=True)
        self.assertTrue(os.path.exists(c), r)
        self.assertIn("nested repository", r["kept"][0]["why"])

    # ---- nits
    def test_a_root_outside_the_trees_leaves_an_alert_row(self):
        outside = os.path.join(self.home, "projects2")
        os.makedirs(outside)
        self.write_config(reaper_delete_enabled=True, roots=[outside])
        with mock.patch.object(wj, "uncapped_containers", return_value=[]), mock.patch.object(wj, "shm_sweep", return_value=[]):
            wj.sweep(apply=False, now=time.time())
            C.candidates(C.load_config())
        self.assertEqual(Path(self.home, ".agent-harness", "state", "copy-hygiene-alerts.jsonl").read_text().count("root-ignored"), 1)     # once a day, not per call and per module
        with mock.patch.object(wj, "uncapped_containers", return_value=[]), mock.patch.object(wj, "shm_sweep", return_value=[]):
            wj.sweep(apply=False, now=time.time())
        self.assertEqual(Path(self.home, ".agent-harness", "state", "copy-hygiene-alerts.jsonl").read_text().count("root-ignored"), 1)
        other = os.path.join(self.home, "projects3")
        os.makedirs(other)
        self.write_config(reaper_delete_enabled=True, roots=[other])  # a different root is a different condition
        C.candidates(C.load_config())
        self.assertEqual(Path(self.home, ".agent-harness", "state", "copy-hygiene-alerts.jsonl").read_text().count("root-ignored"), 2)

    def test_unwrap_takes_the_value_of_stdbuf_and_doas_options(self):
        self.assertEqual(C._unwrap(["stdbuf", "-o", "L", "rm", "-rf", "x"]), ["rm", "-rf", "x"])
        self.assertEqual(C._unwrap(["doas", "-u", "bob", "rm", "x"]), ["rm", "x"])

    def test_acquire_by_branch_warns_when_the_source_branch_is_ahead_of_the_remote(self):
        src = self.clone("srcwarn/src")
        sh("git", "commit", "-q", "--allow-empty", "-m", "ahead", cwd=src)
        remote_sha = subprocess.run(["git", "-C", src, "rev-parse", "origin/main"], capture_output=True, text=True).stdout.strip()
        note = C.resolved_note("main", src, remote_sha)
        self.assertEqual(note["resolved_from"], "remote")
        self.assertIn("ahead: push it", note["warning"])
        self.assertIn("behind: pull it", note["warning"])
        self.assertIn("main", note["warning"])
        self.assertEqual(C.resolved_note("main", src, subprocess.run(["git", "-C", src, "rev-parse", "main"], capture_output=True,
                                                                     text=True).stdout.strip()), {})


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
                mock.patch.object(wj, "session_verdicts", return_value={sid: ["session_live"]}):
            r = wj.sweep(apply=True)
        self.assertTrue(os.path.exists(c))
        row = r["released"][0]
        self.assertEqual(row["kept"][0]["why"], "session is alive or recent (session_live)")
        self.assertEqual((row["mode"], row["would_remove"], row["would_free_bytes"]), ("apply", [], 0))

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


    def test_report_only_sweep_says_would_free_and_never_freed(self):
        os.remove(os.path.join(self.home, ".agent-harness", "state", "copy-hygiene.json"))
        self.clone("wd/c")
        with mock.patch.object(S, "newest_activity", return_value=OLD):
            r = wj.sweep(apply=True)
            self.assertEqual(r["freed_gb"], 0)
            self.assertEqual(r["released"][0]["removed"], [])
            self.assertTrue(r["released"][0]["would_remove"])
            self.assertIn("would_free_gb", r)
            with mock.patch("sys.stdout") as out:
                wj.main(["sweep", "--apply"])
        text = "".join(c.args[0] for c in out.write.call_args_list)
        self.assertIn("would free", text)
        self.assertNotIn("freed", text.replace("would free", ""))

    def test_live_sessions_without_proc_uses_ps_and_without_any_process_list_everything_is_alive(self):
        sid = "33333333-4444-4555-8666-777777777777"
        other = "44444444-5555-4666-8777-888888888888"
        with mock.patch.object(wj, "PROC", os.path.join(self.t, "no-proc")):
            with mock.patch.object(S, "probe", return_value=(0, "/usr/bin/claude --session-id %s\n/bin/zsh\n" % sid, "")) as pr:
                self.assertEqual(wj.live_sessions([sid, other], 3600, time.time()), {sid})
            self.assertEqual(pr.call_args.args[0][:2], ["ps", "-axo"])
            with mock.patch.object(S, "probe", return_value=(127, "", "not installed")):
                self.assertEqual(wj.live_sessions([sid, other], 3600, time.time()), {sid, other})
            with mock.patch.object(S, "probe", return_value=(0, "  \n", "")):
                self.assertEqual(wj.live_sessions([sid, other], 3600, time.time()), {sid, other})


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
        """The copy is removed the way release does it: `git worktree remove` (its admin entry goes too)."""
        sh("git", "worktree", "remove", "--force", self.copy, cwd=self.mirror)

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


    # ---- Fable review B1: a mirror may hold the only copy of a branch
    def test_b1_a_branch_that_exists_only_in_the_mirror_keeps_it(self):
        sh("git", "checkout", "-q", "-b", "fix", cwd=self.copy)
        sh("git", "commit", "-q", "--allow-empty", "-m", "unpushed work", cwd=self.copy)
        sh("git", "checkout", "-q", "--detach", "origin/main", cwd=self.copy)
        self.assertEqual(S.recoverable(self.copy), (True, ""))            # a linked worktree skips the branch check
        r = wj.release(self.copy, apply=True)
        self.assertFalse(os.path.exists(self.copy), r)                    # the copy goes; the commit lives in the mirror
        self.assertEqual(subprocess.run(["git", "-C", self.mirror, "rev-parse", "--verify", "refs/heads/fix"],
                                        capture_output=True).returncode, 0)
        row = wj.mirror_sweep(True, self.cfg_, self.later)["rows"][0]
        self.assertTrue(row["action"].startswith("kept"), row)
        self.assertIn("no remote ref", row["action"])
        self.assertTrue(os.path.isdir(self.mirror))
        sh("git", "branch", "-q", "-D", "fix", cwd=self.mirror)           # control: nothing unpushed -> removable
        self.assertEqual(wj.mirror_sweep(True, self.cfg_, self.later)["rows"][0]["action"], "removed")

    def origin_commit(self, branch="main"):
        seed = os.path.join(self.t, "seed")
        sh("git", "commit", "-q", "--allow-empty", "-m", "upstream " + branch, cwd=seed)
        sh("git", "push", "-q", self.origin, "HEAD:refs/heads/" + branch, cwd=seed)
        return subprocess.run(["git", "-C", seed, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()

    def has_object(self, sha):
        env = dict(os.environ, GIT_ALLOW_PROTOCOL="none-allowed", GIT_NO_LAZY_FETCH="1")
        return subprocess.run(["git", "-C", self.mirror, "cat-file", "-e", sha], capture_output=True, env=env).returncode == 0

    def test_n2_a_branch_gone_from_the_remote_does_not_pin_an_idle_mirror(self):
        self.origin_commit("pr")
        sh("git", "fetch", "-q", "origin", "+refs/heads/*:refs/remotes/origin/*", cwd=self.mirror)
        sh("git", "rev-parse", "--verify", "refs/remotes/origin/pr", cwd=self.mirror)
        sh("git", "push", "-q", self.origin, ":refs/heads/pr", cwd=os.path.join(self.t, "seed"))   # squash-merge-and-delete
        self.drop_copy_folder()
        self.assertEqual(wj.mirror_sweep(True, self.cfg_, self.later)["rows"][0]["action"], "removed")

    def test_n3_the_unpushed_check_does_not_download_new_upstream_commits(self):
        self.drop_copy_folder()
        new = self.origin_commit("main")
        self.assertFalse(self.has_object(new))
        self.assertEqual(wj._mirror_unpushed(self.mirror), "")
        self.assertFalse(self.has_object(new), "the check downloaded an upstream commit into the mirror")

    def test_n3_recoverable_does_not_download_new_upstream_commits_either(self):
        new = self.origin_commit("other")      # main keeps advertising what the copy holds
        self.assertEqual(S.recoverable(self.copy), (True, ""))
        self.assertFalse(self.has_object(new))

    def test_b1_recoverable_fetches_once_when_the_copys_branch_advanced_upstream(self):
        new = self.origin_commit("main")                  # the copy's own branch moved on the remote
        self.assertFalse(self.has_object(new))
        self.assertEqual(S.recoverable(self.copy), (True, ""))
        self.assertTrue(self.has_object(new))             # the one explicit commit-only fetch

    def test_b1_recoverable_keeps_the_copy_when_that_fetch_fails_and_never_fetches_when_not_needed(self):
        self.origin_commit("main")
        calls = []
        real = S.git

        def no_fetch(cwd, *a, **kw):
            if "fetch" in a:
                calls.append(a)
                return 1, "", "boom"
            return real(cwd, *a, **kw)
        with mock.patch.object(S, "git", side_effect=no_fetch):
            ok, why = S.recoverable(self.copy)
        self.assertFalse(ok)
        self.assertIn("fetch", why)
        self.assertEqual(len(calls), 1)
        calls.clear()
        self.drop_copy_folder()
        with mock.patch.object(S, "git", side_effect=no_fetch):
            self.assertEqual(wj._mirror_unpushed(self.mirror), "")      # the mirror check stays offline
        self.assertEqual(calls, [])

    def test_b1_the_offline_view_reports_missing_ids_without_spawning_a_fetch(self):
        new = self.origin_commit("main")
        trace = os.path.join(self.t, "trace.txt")
        with mock.patch.object(S, "GENV", dict(S.GENV, GIT_TRACE=trace)), S.offline_view(self.mirror) as v:
            self.assertEqual(v.types([new]), {new: "missing"})
            self.assertEqual(v.commits([new]), set())
            self.assertNotIn("fetch", Path(trace).read_text())
            cfg = subprocess.run(["git", "-C", v.path, "config", "--list"], capture_output=True, text=True, env=ENV).stdout
            self.assertNotIn("promisor", cfg)
            vp = v.path
        self.assertFalse(os.path.exists(vp), "the throwaway view must be removed")

    def test_b1_a_failing_object_check_keeps_the_mirror_explicitly(self):
        self.drop_copy_folder()
        real = S.git

        def fail(cwd, *a, **kw):
            return (-1, "", "timeout") if "cat-file" in a else real(cwd, *a, **kw)
        with mock.patch.object(S, "git", side_effect=fail):
            self.assertIn("timed out", wj._mirror_unpushed(self.mirror))

    def test_a_lightweight_tag_deleted_upstream_does_not_pin_the_mirror(self):
        self.drop_copy_folder()
        seed = os.path.join(self.t, "seed")
        sh("git", "commit", "-q", "--allow-empty", "-m", "tagged", cwd=seed)
        sh("git", "tag", "v-gone", cwd=seed)
        sh("git", "push", "-q", self.origin, "HEAD:refs/heads/main", "refs/tags/v-gone", cwd=seed)
        sh("git", "fetch", "-q", "--tags", "origin", cwd=self.mirror)
        sh("git", "push", "-q", self.origin, ":refs/tags/v-gone", cwd=seed)
        self.assertEqual(wj._mirror_unpushed(self.mirror), "")      # its commit is still on an advertised branch
        sh("git", "push", "-q", "-f", self.origin, "HEAD~1:refs/heads/main", cwd=seed)   # ...and now on none: the safe side keeps it
        self.assertIn("no remote ref", wj._mirror_unpushed(self.mirror))

    def test_n1_a_commit_parked_under_any_non_remote_ref_keeps_the_mirror(self):
        self.drop_copy_folder()
        for kind in ("backup", "tag", "note"):
            with self.subTest(kind):
                sha = subprocess.run(["git", "-C", self.mirror, "-c", "user.name=t", "-c", "user.email=t@t", "commit-tree",
                                      "-m", "wip-" + kind, "refs/remotes/origin/main^{tree}"], capture_output=True,
                                     text=True, env=ENV).stdout.strip()
                ref = {"backup": "refs/backup/x", "tag": "refs/tags/wip-save", "note": "refs/notes/commits"}[kind]
                sh("git", "update-ref", ref, sha, cwd=self.mirror)
                row = wj.mirror_sweep(True, self.cfg_, self.later)["rows"][0]
                self.assertTrue(row["action"].startswith("kept"), (kind, row))
                self.assertIn("no remote ref", row["action"])
                self.assertTrue(os.path.isdir(self.mirror))
                sh("git", "update-ref", "-d", ref, cwd=self.mirror)      # control: without it the mirror is removable
                self.assertEqual(wj._mirror_unpushed(self.mirror), "")

    def test_s2_the_fetch_wants_only_branch_heads_not_pull_refs(self):
        new = self.origin_commit("main")
        seed = os.path.join(self.t, "seed")
        for n in range(30):
            sh("git", "commit", "-q", "--allow-empty", "-m", "pr%d" % n, cwd=seed)
            sh("git", "push", "-q", self.origin, "HEAD:refs/pull/%d/head" % n, cwd=seed)
        calls = []
        real = S.git

        def spy(cwd, *a, **kw):
            if "fetch" in a:
                calls.append(a)
            return real(cwd, *a, **kw)
        with mock.patch.object(S, "git", side_effect=spy):
            self.assertEqual(S.recoverable(self.copy), (True, ""))
        self.assertEqual(len(calls), 1)
        ids = [x for x in calls[0] if len(x) == 40]
        self.assertEqual(ids, [new])
        self.assertNotIn("--filter=tree:0", calls[0])

    def test_b1_a_copy_on_a_pr_head_is_recoverable_after_the_pr_head_moves(self):
        seed = os.path.join(self.t, "seed")
        sh("git", "commit", "-q", "--allow-empty", "-m", "pr work", cwd=seed)
        x = subprocess.run(["git", "-C", seed, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
        sh("git", "push", "-q", self.origin, "HEAD:refs/pull/7/head", cwd=seed)  # X lives only on the PR head
        res = C.acquire(seed, "pr-7", ref=x, url=self.origin, cfg=C.normalize({"min_free_gb": 0, "min_free_pct": 0}))
        self.assertTrue(res["ok"], res)
        self.assertEqual(S.recoverable(res["path"]), (True, ""))
        sh("git", "commit", "-q", "--allow-empty", "-m", "pr pushed again", cwd=seed)
        y = subprocess.run(["git", "-C", seed, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
        sh("git", "push", "-q", self.origin, "HEAD:refs/pull/7/head", cwd=seed)  # the PR head moves to Y (X is below it)
        sh("git", "push", "-q", self.origin, "HEAD:refs/pull/7/merge", cwd=seed)
        self.assertFalse(self.has_object(y))
        calls = []
        real = S.git

        def spy(cwd, *a, **kw):
            if "fetch" in a:
                calls.append(a)
            return real(cwd, *a, **kw)
        with mock.patch.object(S, "git", side_effect=spy):
            self.assertEqual(S.recoverable(res["path"]), (True, ""))
        self.assertEqual([[i for i in c if len(i) == 40] for c in calls], [[y]])       # the head id once, in stage 2

    def test_s1_a_blob_or_tree_under_a_non_remote_ref_keeps_the_mirror(self):
        self.drop_copy_folder()
        blob = subprocess.run(["git", "-C", self.mirror, "hash-object", "-w", "--stdin"], input="parked", text=True,
                              capture_output=True, env=ENV).stdout.strip()
        tree = subprocess.run(["git", "-C", self.mirror, "mktree"], input="100644 blob %s\tf\n" % blob, text=True,
                              capture_output=True, env=ENV).stdout.strip()
        for ref, obj in (("refs/backup/blob", blob), ("refs/backup/tree", tree)):
            with self.subTest(ref):
                sh("git", "update-ref", ref, obj, cwd=self.mirror)
                self.assertIn("non-commit", wj._mirror_unpushed(self.mirror))
                sh("git", "update-ref", "-d", ref, cwd=self.mirror)           # control: removable once the ref is gone
                self.assertEqual(wj._mirror_unpushed(self.mirror), "")

    def test_nit_the_offline_view_uses_the_repos_object_format_and_old_views_are_cleaned(self):
        old = os.path.join(tempfile.gettempdir(), "%sleftover-%d-%d" % (S.VIEW_PREFIX, os.getpid(), time.time_ns()))
        os.makedirs(old)
        os.utime(old, (1, 1))
        self.addCleanup(shutil.rmtree, old, True)
        with mock.patch.object(S, "_SWEPT", False):
            with S.offline_view(self.mirror) as v:
                fmt = subprocess.run(["git", "-C", v.path, "rev-parse", "--show-object-format"], capture_output=True,
                                     text=True, env=ENV).stdout.strip()
                self.assertEqual(fmt, "sha1")
            self.assertFalse(os.path.exists(old))
            os.makedirs(old)
            os.utime(old, (1, 1))
            with S.offline_view(self.mirror):
                pass
            self.assertTrue(os.path.exists(old), "the sweep runs once per process")

    def test_nit_a_sha256_repository_gets_a_sha256_view(self):
        r = subprocess.run(["git", "init", "-q", "--object-format=sha256", os.path.join(self.t, "s256")],
                           capture_output=True, text=True, env=ENV)
        if r.returncode != 0:
            self.skipTest("this git has no sha256 support")
        repo = os.path.join(self.t, "s256")
        sh("git", "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "--allow-empty", "-m", "x", cwd=repo)
        with S.offline_view(repo) as v:
            fmt = subprocess.run(["git", "-C", v.path, "rev-parse", "--show-object-format"], capture_output=True,
                                 text=True, env=ENV).stdout.strip()
            self.assertEqual(fmt, "sha256")

    def test_a_local_only_annotated_tag_on_a_pushed_commit_keeps_the_mirror(self):
        self.drop_copy_folder()
        sh("git", "-c", "user.name=t", "-c", "user.email=t@t", "tag", "-a", "-m", "mine", "local-note", "refs/remotes/origin/main", cwd=self.mirror)
        row = wj.mirror_sweep(True, self.cfg_, self.later)["rows"][0]
        self.assertTrue(row["action"].startswith("kept"), row)
        self.assertIn("annotated tag", row["action"])
        sh("git", "tag", "-d", "local-note", cwd=self.mirror)
        self.assertEqual(wj.mirror_sweep(True, self.cfg_, self.later)["rows"][0]["action"], "removed")

    def test_b1_an_unreachable_origin_keeps_the_mirror(self):
        self.drop_copy_folder()
        moved = self.origin + ".moved"
        os.rename(self.origin, moved)
        try:
            row = wj.mirror_sweep(True, self.cfg_, self.later)["rows"][0]
            self.assertIn("ls-remote failed", row["action"])
            self.assertTrue(os.path.isdir(self.mirror))
        finally:
            os.rename(moved, self.origin)
        self.assertEqual(wj.mirror_sweep(True, self.cfg_, self.later)["rows"][0]["action"], "removed")

    def test_b1_a_worktree_admin_entry_keeps_the_mirror_even_when_its_folder_is_gone(self):
        import shutil
        shutil.rmtree(self.copy)                       # unmounted or moved: git still has the entry, os.path.exists says no
        self.assertTrue(os.listdir(os.path.join(self.mirror, "worktrees")))
        row = wj.mirror_sweep(True, self.cfg_, self.later)["rows"][0]
        self.assertIn("registered worktree", row["action"])
        self.assertTrue(os.path.isdir(self.mirror))

    def test_protect_names_covers_a_mirror_by_name_and_by_url(self):
        self.drop_copy_folder()
        for names in (["origin-"], ["origin.git"]):
            cfg = C.normalize({"reaper_delete_enabled": True, "mirror_ttl_days": 14, "protect_names": names})
            row = wj.mirror_sweep(True, cfg, self.later)["rows"][0]
            self.assertIn("protected name", row["action"], names)
            self.assertTrue(os.path.isdir(self.mirror))

    def test_mirror_removal_goes_through_the_fresh_removal_function(self):
        self.drop_copy_folder()
        with mock.patch.object(C, "protected_scan", wraps=C.protected_scan) as ps:
            self.assertEqual(wj.mirror_sweep(True, self.cfg_, self.later)["rows"][0]["action"], "removed")
        self.assertTrue(ps.call_args_list and all(c.kwargs.get("fresh") is True for c in ps.call_args_list))


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

    def sweep_with_ctime_old(self, apply=True):
        later = time.time() + 3 * 86400            # ctime cannot be backdated, so move "now" forward instead
        return wj.shm_sweep(apply, self.cfg, later)

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

    @unittest.skipUnless(sys.platform.startswith("linux"), "reads /proc")
    def test_a_file_a_process_mapped_and_closed_is_kept(self):
        f = self.make("dsm.segment", data=b"\0" * 8192)
        # libc mmap, then close the descriptor: Python's own mmap module keeps a dup'd descriptor open
        code = ("import ctypes,os,sys,time\nfd=os.open(sys.argv[1],os.O_RDWR)\nl=ctypes.CDLL(None)\n"
                "l.mmap.restype=ctypes.c_void_p\nl.mmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_long]\n"
                "a=l.mmap(None,8192,3,1,fd,0)\nassert a not in (None,2**64-1)\nos.close(fd)\n"
                "print('ready',flush=True)\ntime.sleep(60)\n")
        mock.patch.object(S, "in_use_paths", REAL_IN_USE).start()
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


    def test_s6_podman_lock_semaphores_and_postgres_segments_are_never_removed(self):
        keep = [self.make(n) for n in ("libpod_rootless_lock_1000", "sem.mp-abc", "PostgreSQL.123")]
        gone = self.make("scratch2.bin")
        self.sweep_with_ctime_old()
        self.assertTrue(all(os.path.exists(k) for k in keep))
        self.assertFalse(os.path.exists(gone))

    def test_idle_unmapped_browser_scratch_is_reclaimed_but_a_mapped_one_is_kept(self):
        crashed = self.make(".org.chromium.Chromium.abc")
        live = self.make("playwright_live")
        with mock.patch.object(S, "in_use_paths", return_value={live}):
            self.sweep_with_ctime_old()
        self.assertFalse(os.path.exists(crashed))
        self.assertTrue(os.path.exists(live))

    def test_s6_the_process_scan_is_taken_inside_the_shm_sweep_and_a_failed_scan_keeps_everything(self):
        f = self.make("held.bin")
        g = self.make("other.bin")
        with mock.patch.object(S, "in_use_paths", return_value={f}) as scan:
            rows = self.sweep_with_ctime_old()
        self.assertEqual(scan.call_count, 1)
        self.assertTrue(os.path.exists(f))
        self.assertFalse(os.path.exists(g))
        h = self.make("third.bin")
        with mock.patch.object(S, "in_use_paths", side_effect=S.ProbeError("scan failed")):
            rows = self.sweep_with_ctime_old()
        self.assertTrue(os.path.exists(h), rows)
        self.assertIn("probe failed", rows[0]["action"])


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


SID = "aaaaaaaa-1111-4222-8333-444444444444"
OLD_ISO = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(OLD))


class Ownership(Base):
    """Stream D (goodqa#16947): a session folder is released only when its session is retired: Claude and Codex WALs
    (file time and last row stamp), transcripts and rollouts, open asks, open ah tasks, live bg jobs. Each test here
    keeps a session that the previous liveness check (Claude WAL mtime or a command line only) released."""

    def setUp(self):
        super().setUp()
        mock.patch.object(S, "in_use_paths", return_value=set()).start()
        mock.patch.object(S, "service_refs", return_value=set()).start()
        mock.patch.object(wj, "uncapped_containers", return_value=[]).start()
        mock.patch.object(wj, "shm_sweep", return_value=[]).start()
        mock.patch.object(wj, "_process_blob", return_value="/bin/zsh\n").start()
        wj._TASKS = None
        self.addCleanup(setattr, wj, "_TASKS", None)

    def wal(self, flavor="claude", rows=None, when=OLD):
        d = (os.path.join(self.home, ".claude", "wals", SID) if flavor == "claude"
             else os.path.join(self.home, ".agent-harness", "codex-wals", SID))
        os.makedirs(d, exist_ok=True)
        p = Path(d, "main.jsonl")
        p.write_text("".join(json.dumps(r) + "\n" for r in (rows or [{"at": OLD_ISO, "event": "intent"}])))
        os.utime(p, (when, when))
        return d

    def session(self):
        c = self.clone(SID + "/c")
        age(os.path.join(self.work, SID))
        return c

    def sweep(self):
        real = S.newest_activity
        with mock.patch.object(S, "newest_activity", side_effect=lambda p: OLD if SID in p else real(p)):
            return wj.sweep(apply=True)

    def test_retired_session_is_released(self):
        c = self.session()
        self.wal()
        self.sweep()
        self.assertFalse(os.path.exists(c))

    def test_codex_session_with_a_fresh_codex_wal_is_kept(self):
        c = self.session()
        self.wal("codex", rows=[{"at": OLD_ISO}], when=time.time())
        r = self.sweep()
        self.assertTrue(os.path.exists(c))
        self.assertIn("recent_activity", r["released"][0]["session_reasons"])

    def test_fresh_transcript_keeps_a_session_whose_wal_is_old(self):
        c = self.session()
        self.wal()
        d = os.path.join(self.home, ".claude", "projects", "-Users-x")
        os.makedirs(d)
        Path(d, SID + ".jsonl").write_text(json.dumps({"timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}) + "\n")
        self.sweep()
        self.assertTrue(os.path.exists(c))

    def test_backdated_wal_with_a_fresh_row_stamp_is_kept(self):
        c = self.session()
        self.wal(rows=[{"at": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime()), "event": "intent"}], when=OLD)
        self.sweep()
        self.assertTrue(os.path.exists(c))

    def test_open_ask_keeps_and_a_resolved_ask_does_not(self):
        c = self.session()
        self.wal(rows=[{"at": OLD_ISO, "event": "ask", "id": "w1"}])
        r = self.sweep()
        self.assertTrue(os.path.exists(c))
        self.assertIn("open_work", r["released"][0]["session_reasons"])
        self.wal(rows=[{"at": OLD_ISO, "event": "ask", "id": "w1"}, {"at": OLD_ISO, "event": "ask_resolved", "ref": "w1"}])
        self.sweep()
        self.assertFalse(os.path.exists(c))

    def test_open_task_keeps_and_an_unreadable_task_ledger_keeps_everything(self):
        c = self.session()
        self.wal()
        with mock.patch.object(wj, "_open_task_sessions", return_value={SID}):
            self.sweep()
        self.assertTrue(os.path.exists(c))
        with mock.patch.object(wj, "_open_task_sessions", return_value=None):
            r = self.sweep()
        self.assertTrue(os.path.exists(c))
        self.assertIn("tasks_unreadable", r["released"][0]["session_reasons"])

    def test_session_in_both_wal_flavors_is_ambiguous_and_kept(self):
        c = self.session()
        self.wal("claude")
        self.wal("codex")
        r = self.sweep()
        self.assertTrue(os.path.exists(c))
        self.assertIn("ambiguous_session", r["released"][0]["session_reasons"])

    def test_live_bg_job_keeps(self):
        c = self.session()
        self.wal()
        jobs = os.path.join(self.work, SID, "bg-jobs")
        os.makedirs(jobs)
        Path(jobs, "j.json").write_text(json.dumps({"pid": 1, "nonce": "nonce-xyz"}))
        with mock.patch.object(wj, "_process_blob", return_value="python3 bg_job.py nonce-xyz\n"):
            self.sweep()
        self.assertTrue(os.path.exists(c))

    def test_release_cli_refuses_a_session_that_is_not_retired_and_session_end_may_release_its_own(self):
        c = self.session()
        self.wal(when=time.time())
        with mock.patch("sys.stdout") as out:
            self.assertEqual(wj.main(["release", "--session", SID, "--apply"]), 0)
        self.assertTrue(os.path.exists(c))
        self.assertIn("is not retired", "".join(x.args[0] for x in out.write.call_args_list))
        with mock.patch.dict(os.environ, {wj.SESSION_END_ENV: SID}), mock.patch("sys.stdout"):
            wj.main(["release", "--session", SID, "--apply"])
        self.assertFalse(os.path.exists(c))

    def test_no_process_list_keeps_every_session(self):
        c = self.session()
        self.wal()
        with mock.patch.object(wj, "_process_blob", return_value=None):
            self.sweep()
        self.assertTrue(os.path.exists(c))


class Regenerable(Base):
    """Stream D: in a retired session folder, node_modules beside a package.json and a venv with pyvenv.cfg are removed
    even though the folder also holds logs; nothing else outside a checkout is treated as regenerable."""

    def setUp(self):
        super().setUp()
        mock.patch.object(S, "in_use_paths", return_value=set()).start()
        mock.patch.object(S, "service_refs", return_value=set()).start()
        self.s = os.path.join(self.work, SID)
        os.makedirs(self.s)
        Path(self.s, "notes.jsonl").write_text("{}\n")
        Path(self.s, "run.log").write_text("log\n")

    def tree(self, *parts, files=("x.js",)):
        d = os.path.join(self.s, *parts)
        os.makedirs(d, exist_ok=True)
        for f in files:
            Path(d, f).write_text("x")
        return d

    def test_node_modules_and_venv_go_logs_and_the_folder_stay(self):
        self.tree("app", files=("package.json",))
        nm = self.tree("app", "node_modules", "left-pad")
        venv = self.tree("py", ".venv", files=("pyvenv.cfg",))
        r = wj.release(self.s, apply=True, regenerable=True)
        self.assertFalse(os.path.exists(os.path.dirname(nm)))
        self.assertFalse(os.path.exists(venv))
        self.assertTrue(os.path.exists(os.path.join(self.s, "notes.jsonl")))
        self.assertTrue(os.path.exists(os.path.join(self.s, "run.log")))
        self.assertTrue(os.path.exists(os.path.join(self.s, "app", "package.json")))
        self.assertEqual(len(r["regenerable"]), 2)

    def test_build_output_outside_a_checkout_is_kept(self):
        # the 4e8fba1c case: built firmware images in a build/ folder of a non-git work dir are not regenerable
        b = self.tree("gfx", "build", files=("final14.bin", "final14.json"))
        for name in ("dist", "out", "target", ".cache", "__pycache__"):
            self.tree("gfx", name, files=("a.bin",))
        wj.release(self.s, apply=True, regenerable=True)
        self.assertTrue(os.path.exists(os.path.join(b, "final14.bin")))
        for name in ("dist", "out", "target", ".cache", "__pycache__"):
            self.assertTrue(os.path.exists(os.path.join(self.s, "gfx", name, "a.bin")), name)

    def test_node_modules_without_a_package_json_and_venv_without_pyvenv_cfg_are_kept(self):
        nm = self.tree("lone", "node_modules", "pkg")
        venv = self.tree("lone", "venv", files=("bin",))
        wj.release(self.s, apply=True, regenerable=True)
        self.assertTrue(os.path.exists(nm))
        self.assertTrue(os.path.exists(venv))

    def test_symlinked_node_modules_is_not_followed(self):
        target = os.path.join(self.t, "shared-nm")
        os.makedirs(os.path.join(target, "pkg"))
        self.tree("app", files=("package.json",))
        os.symlink(target, os.path.join(self.s, "app", "node_modules"))
        wj.release(self.s, apply=True, regenerable=True)
        self.assertTrue(os.path.islink(os.path.join(self.s, "app", "node_modules")))
        self.assertTrue(os.path.exists(os.path.join(target, "pkg")))

    def test_node_modules_holding_a_repository_is_kept(self):
        self.tree("app", files=("package.json",))
        nested = os.path.join(self.s, "app", "node_modules", "linked")
        os.makedirs(nested)
        sh("git", "init", "-q", nested)
        wj.release(self.s, apply=True, regenerable=True)
        self.assertTrue(os.path.exists(os.path.join(nested, ".git")))

    def test_in_use_node_modules_is_kept(self):
        self.tree("app", files=("package.json",))
        nm = self.tree("app", "node_modules", "pkg")
        with mock.patch.object(S, "in_use_paths", return_value={nm}):
            r = wj.release(self.s, apply=True, regenerable=True)
        self.assertTrue(os.path.exists(nm))
        self.assertTrue(any("in use" in k["why"] or "used" in k["why"] for k in r["kept"]), r["kept"])

    def test_report_only_lists_and_removes_nothing(self):
        os.remove(os.path.join(self.home, ".agent-harness", "state", "copy-hygiene.json"))
        self.tree("app", files=("package.json",))
        nm = self.tree("app", "node_modules", "pkg")
        r = wj.release(self.s, apply=True, regenerable=True)
        self.assertTrue(os.path.exists(nm))
        self.assertIn(os.path.join(self.s, "app", "node_modules"), r["would_remove"])
        self.assertEqual(r["removed"], [])

    def test_without_the_regenerable_flag_nothing_outside_checkouts_is_touched(self):
        self.tree("app", files=("package.json",))
        nm = self.tree("app", "node_modules", "pkg")
        wj.release(self.s, apply=True)
        self.assertTrue(os.path.exists(nm))

    def test_node_modules_inside_a_checkout_is_left_to_the_checkout_rules(self):
        c = self.clone(SID + "/repo")
        Path(c, "package.json").write_text("{}")
        Path(c, "x").write_text("dirty")              # a dirty checkout is kept, and so is its node_modules
        os.makedirs(os.path.join(c, "node_modules", "p"))
        wj.release(self.s, apply=True, regenerable=True)
        self.assertTrue(os.path.exists(os.path.join(c, "node_modules", "p")))


class Report(Base):
    def setUp(self):
        super().setUp()
        mock.patch.object(wj, "_process_blob", return_value="/bin/zsh\n").start()
        wj._TASKS = None
        self.addCleanup(setattr, wj, "_TASKS", None)

    def test_report_lists_sessions_by_size_with_verdict_and_regenerable_bytes(self):
        s = os.path.join(self.work, SID)
        os.makedirs(os.path.join(s, "app", "node_modules", "p"))
        Path(s, "app", "package.json").write_text("{}")
        Path(s, "app", "node_modules", "p", "big").write_bytes(b"x" * 200000)
        live = "bbbbbbbb-1111-4222-8333-444444444444"
        os.makedirs(os.path.join(self.work, live))
        wal = os.path.join(self.home, ".claude", "wals", live)
        os.makedirs(wal)
        Path(wal, "main.jsonl").write_text("{}\n")
        self.write_config(reaper_delete_enabled=True, session_budget_gb=0.0001)
        r = wj.report()
        rows = {x["session"]: x for x in r["sessions"]}
        self.assertEqual(rows[SID]["state"], "retired")
        self.assertGreater(rows[SID]["regenerable_bytes"], 100000)
        self.assertTrue(rows[SID]["over_budget"])
        self.assertEqual(rows[live]["state"], "kept")
        self.assertIn("recent_activity", rows[live]["reasons"])
        self.assertEqual(r["sessions"][0]["session"], SID)
        self.assertTrue(os.path.exists(os.path.join(s, "app", "node_modules", "p", "big")))   # read only


class InstallTimer(unittest.TestCase):
    """install.py --janitor-timer: opt-in, unit files carry the limits, linger is advised, failures never raise."""

    def setUp(self):
        sys.path.insert(0, str(HOOKS.parents[1]))
        import install
        self.install = install
        self.home = Path(os.path.realpath(tempfile.mkdtemp()))
        # janitor_timer_status looks for systemctl even when `run` is injected: pretend it is there (macOS has none)
        mock.patch("shutil.which", side_effect=lambda n, *a, **k: "/usr/bin/" + n if n == "systemctl" else None).start()
        self.addCleanup(mock.patch.stopall)

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
