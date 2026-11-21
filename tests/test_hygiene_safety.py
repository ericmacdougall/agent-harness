"""hygiene_safety (shared by copy_hygiene and workspace_janitor) and the mirror-backed acquire().

service_refs() is exercised through fake systemctl/crontab/docker/podman programs on PATH, in_use_paths() through real
child processes, and each review blocker has a case that fails on the code it replaced. Temporary homes only.
"""
import json
import os
import stat
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

GENV = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t", GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@t",
            GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_NOSYSTEM="1")


def sh(*a, cwd=None):
    return subprocess.run(a, cwd=cwd, check=True, capture_output=True, text=True, env=GENV).stdout


class FakeTools(unittest.TestCase):
    """A bin/ directory of fake programs first on PATH; each logs its arguments to $FAKE_LOG."""

    def setUp(self):
        self.t = tempfile.mkdtemp()
        self.home = os.path.join(self.t, "home")
        os.makedirs(os.path.join(self.home, ".agent-harness", "work", "svc"))
        os.makedirs(os.path.join(self.home, ".config", "systemd", "user"))
        self.bin = os.path.join(self.t, "bin")
        os.makedirs(self.bin)
        self.log = os.path.join(self.t, "calls.log")
        Path(self.log).touch()
        self.env = mock.patch.dict(os.environ, {"HARNESS_JANITOR_HOME": self.home, "PATH": self.bin + ":/usr/bin:/bin",
                                                "FAKE_LOG": self.log})
        self.env.start()
        os.environ.pop("HARNESS_COPY_HYGIENE_HOME", None)
        for k in ("FAKE_SHOW_FAIL", "FAKE_SHOW_HANG", "FAKE_LIST_FAIL", "FAKE_CRON_FAIL", "FAKE_DOCKER_FAIL"):
            os.environ.pop(k, None)
        self.tool("crontab", 'if [ -n "$FAKE_CRON_FAIL" ]; then echo "bad" >&2; exit 1; fi\n'
                  'printf "* * * * * %s/.agent-harness/work/cronjob/run.sh\\n" "$HOME_FOR_FAKE"\n')
        self.tool("systemctl", self.systemctl_script())
        self.tool("docker", 'echo "docker $*" >> "$FAKE_LOG"\n'
                  'if [ -n "$FAKE_DOCKER_FAIL" ]; then exit 2; fi\n'
                  'case "$1" in ps) echo abc123;; inspect) printf "%s/.agent-harness/work/dockermount /compose/dir\\n" "$HOME_FOR_FAKE";; esac\n')
        self.tool("podman", 'echo "podman $*" >> "$FAKE_LOG"\n'
                  'case "$1" in ps) echo def456;; inspect) printf "%s/.agent-harness/work/podmanmount\\n" "$HOME_FOR_FAKE";; esac\n')
        os.environ["HOME_FOR_FAKE"] = self.home

    def tearDown(self):
        self.env.stop()

    def tool(self, name, body):
        p = os.path.join(self.bin, name)
        Path(p).write_text("#!/bin/sh\n" + body)
        os.chmod(p, 0o755)

    def systemctl_script(self):
        return r'''echo "systemctl $*" >> "$FAKE_LOG"
case "$*" in
  *list-unit-files*)
    if [ -n "$FAKE_LIST_FAIL" ]; then exit 1; fi
    printf 'a.service enabled enabled\n-.mount generated -\ntmpl@.service enabled enabled\ninst@x.service enabled enabled\n';;
  *list-units*) printf '  run-u42.service loaded active running transient\n';;
  *" show "*)
    if [ -n "$FAKE_SHOW_FAIL" ]; then echo "Failed to connect to bus" >&2; exit 1; fi
    if [ -n "$FAKE_SHOW_HANG" ]; then sleep 30; fi
    printf 'WorkingDirectory=%%h/.agent-harness/work/svc\nExecStart={ path=$HOME/.agent-harness/work/dollar/bin/app ; argv[]=${HOME}/.agent-harness/work/brace/x --flag ; }\n'
    printf 'Environment=CFG=~/.agent-harness/work/tilde/cfg A=1\nWhere=%%h/.agent-harness/work/mnt\n';;
esac
'''

    def calls(self):
        return Path(self.log).read_text().splitlines()


class ServiceRefs(FakeTools):
    def test_every_source_is_read_and_home_spellings_expand(self):
        refs = S.service_refs()
        w = os.path.join(self.home, ".agent-harness", "work")
        for sub in ("svc", "dollar/bin", "brace", "tilde", "mnt", "cronjob", "dockermount", "podmanmount"):
            self.assertTrue(any(r == os.path.join(w, sub) or r.startswith(os.path.join(w, sub) + "/") for r in refs), (sub, sorted(refs)[:12]))
        self.assertIn("/compose/dir", refs)

    def test_templates_are_skipped_and_dash_units_come_after_double_dash(self):
        S.service_refs()
        shows = [c for c in self.calls() if " show " in c]
        self.assertTrue(shows)
        for c in shows:
            self.assertNotIn("tmpl@.service", c)
            self.assertIn("inst@x.service", c)
            self.assertIn(" -- ", c)
            self.assertLess(c.index(" -- "), c.index("-.mount"))
            self.assertIn("run-u42.service", c)             # list-units --all finds transient (systemd-run) units

    def test_list_units_all_is_queried_for_both_scopes(self):
        S.service_refs()
        c = "\n".join(self.calls())
        self.assertIn("systemctl list-units --all", c)
        self.assertIn("systemctl --user list-units --all", c)

    def test_systemctl_show_failure_is_a_probe_error(self):
        os.environ["FAKE_SHOW_FAIL"] = "1"
        with self.assertRaises(S.ProbeError):
            S.service_refs()

    def test_systemctl_show_timeout_is_a_probe_error(self):
        os.environ["FAKE_SHOW_HANG"] = "1"
        real = S.probe
        with mock.patch.object(S, "probe", side_effect=lambda cmd, t=60: real(cmd, 1)):
            with self.assertRaises(S.ProbeError):
                S.service_refs()

    def test_systemctl_list_failure_is_a_probe_error(self):
        os.environ["FAKE_LIST_FAIL"] = "1"
        with self.assertRaises(S.ProbeError):
            S.service_refs()

    def test_crontab_and_docker_failures_are_probe_errors(self):
        os.environ["FAKE_CRON_FAIL"] = "1"
        with self.assertRaises(S.ProbeError):
            S.service_refs()
        del os.environ["FAKE_CRON_FAIL"]
        os.environ["FAKE_DOCKER_FAIL"] = "1"
        with self.assertRaises(S.ProbeError):
            S.service_refs()

    def test_no_crontab_for_user_is_not_an_error(self):
        self.tool("crontab", 'echo "no crontab for eric" >&2; exit 1\n')
        S.service_refs()

    def test_missing_tools_are_not_errors(self):
        for n in ("docker", "podman", "systemctl", "crontab"):
            os.remove(os.path.join(self.bin, n))
        with mock.patch.dict(os.environ, {"PATH": self.bin}):
            S.service_refs()

    def test_reference_through_a_symlink_matches_the_real_folder(self):
        real = os.path.join(self.home, ".agent-harness", "work", "linked")
        os.makedirs(real)
        link = os.path.join(self.t, "srv-app")
        os.symlink(real, link)
        Path(self.home, ".config", "systemd", "user", "x.service").write_text("[Service]\nExecStart=%s/run.sh\n" % link)
        refs = S.service_refs()
        self.assertTrue(S.referenced(real, refs))                       # the service names /srv-app/run.sh
        self.assertTrue(S.busy(real, set(), refs))

    def test_candidate_reached_through_a_symlinked_path_is_matched_by_realpath(self):
        real = os.path.join(self.home, ".agent-harness", "work", "linked2")
        os.makedirs(real)
        link = os.path.join(self.t, "alias")
        os.symlink(real, link)
        self.assertTrue(S.referenced(link, {real + "/run.sh"}))
        self.assertTrue(S.is_used(link, {real + "/x"}))

    def test_tool_symlinked_from_a_work_folder_in_local_bin(self):
        tool = os.path.join(self.home, ".agent-harness", "work", "tools", "cli")
        os.makedirs(os.path.dirname(tool))
        Path(tool).write_text("#!/bin/sh\n")
        os.makedirs(os.path.join(self.home, ".local", "bin"))
        os.symlink(tool, os.path.join(self.home, ".local", "bin", "cli"))
        self.assertTrue(S.referenced(os.path.dirname(tool), S.service_refs()))

    def test_home_itself_and_root_are_never_references(self):
        Path(self.home, ".config", "systemd", "user", "y.service").write_text("[Service]\nWorkingDirectory=%h\nExecStart=/\n")
        refs = S.service_refs()
        self.assertNotIn(self.home, refs)
        self.assertNotIn("/", refs)


class InUse(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.mkdtemp()
        self.procs = []

    def tearDown(self):
        for p in self.procs:
            p.kill()
            p.wait()

    def spawn(self, argv, **kw):
        p = subprocess.Popen(argv, stdout=subprocess.PIPE, text=True, **kw)
        self.procs.append(p)
        self.assertEqual(p.stdout.readline().strip(), "ready")
        return p

    def test_working_folder_open_file_exe_and_mapped_file_are_all_seen(self):
        cwd = os.path.join(self.t, "cwd")
        opened = os.path.join(self.t, "open")
        exe_dir = os.path.join(self.t, "exe")
        mapped = os.path.join(self.t, "mapped")
        for d in (cwd, opened, exe_dir, mapped):
            os.makedirs(d)
        Path(opened, "f").write_text("x")
        Path(mapped, "seg").write_bytes(b"\0" * 8192)
        ready = "import time;print('ready',flush=True);time.sleep(60)"
        self.spawn([sys.executable, "-c", ready], cwd=cwd)
        self.spawn([sys.executable, "-c", "import time;f=open(%r);print('ready',flush=True);time.sleep(60)" % os.path.join(opened, "f")])
        py = os.path.join(exe_dir, "mypython")
        os.symlink(os.path.realpath(sys.executable), py)
        # a copy so /proc/<pid>/exe resolves into exe_dir (a symlink would resolve to the interpreter)
        import shutil
        os.remove(py)
        shutil.copy2(os.path.realpath(sys.executable), py)
        self.spawn([py, "-c", ready], env=dict(os.environ, PYTHONHOME=sys.prefix))
        code = ("import ctypes,os,sys,time\nfd=os.open(sys.argv[1],os.O_RDWR)\nl=ctypes.CDLL(None)\n"
                "l.mmap.restype=ctypes.c_void_p\n"
                "l.mmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_long]\n"
                "a=l.mmap(None,8192,3,1,fd,0)\nos.close(fd)\nprint('ready',flush=True)\ntime.sleep(60)\n")
        self.spawn([sys.executable, "-c", code, os.path.join(mapped, "seg")])
        used = S.in_use_paths()
        for d, what in ((cwd, "cwd"), (opened, "open file"), (exe_dir, "exe"), (mapped, "memory map")):
            self.assertTrue(S.is_used(d, used), what)
        self.assertFalse(S.is_used(os.path.join(self.t, "idle"), used))

    def test_deleted_marker_is_stripped(self):
        self.assertEqual(S._norm("/x/y (deleted)"), "/x/y")

    def test_empty_scan_is_a_probe_error(self):
        with mock.patch.object(S.glob, "glob", return_value=[]):
            with self.assertRaises(S.ProbeError):
                S.in_use_paths()


class Removal(unittest.TestCase):
    def test_remove_tree_refuses_a_mount_inside(self):
        with tempfile.TemporaryDirectory() as t:
            d = os.path.join(t, "d", "sub")
            os.makedirs(d)
            Path(d, "f").write_text("x")
            with mock.patch.object(S, "mounts_under", return_value=[d]):
                ok, why = S.remove_tree(os.path.join(t, "d"))
            self.assertFalse(ok)
            self.assertIn("mount", why)
            self.assertTrue(os.path.exists(os.path.join(d, "f")))
            ok, _ = S.remove_tree(os.path.join(t, "d"))
            self.assertTrue(ok)

    def test_remove_tree_refuses_another_filesystem_inside(self):
        with tempfile.TemporaryDirectory() as t:
            d = os.path.join(t, "d", "sub")
            os.makedirs(d)
            real = os.lstat

            def other_dev(p, *a, **k):
                st = real(p, *a, **k)
                if str(p) == d:
                    return os.stat_result((st.st_mode, st.st_ino, st.st_dev + 1, st.st_nlink, st.st_uid, st.st_gid, st.st_size,
                                           int(st.st_atime), int(st.st_mtime), int(st.st_ctime)))
                return st
            with mock.patch("os.lstat", side_effect=other_dev):
                ok, why = S.remove_tree(os.path.join(t, "d"))
            self.assertFalse(ok)
            self.assertTrue(os.path.exists(d))

    def test_remove_tree_unlinks_a_symlink_without_following_it(self):
        with tempfile.TemporaryDirectory() as t:
            target = os.path.join(t, "target")
            os.makedirs(target)
            Path(target, "keep").write_text("x")
            os.symlink(target, os.path.join(t, "link"))
            self.assertTrue(S.remove_tree(os.path.join(t, "link"))[0])
            self.assertTrue(os.path.exists(os.path.join(target, "keep")))


class RepoFixture(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.mkdtemp()
        self.home = os.path.join(self.t, "home")
        os.makedirs(self.home)
        self.env = mock.patch.dict(os.environ, {"HARNESS_JANITOR_HOME": self.home, "GIT_CONFIG_GLOBAL": "/dev/null",
                                                "GIT_CONFIG_NOSYSTEM": "1"})
        self.env.start()
        os.environ.pop("HARNESS_COPY_HYGIENE_HOME", None)
        self.origin = os.path.join(self.t, "origin.git")
        self.branch = "main"
        self.cfg = C.normalize({"min_free_gb": 0, "min_free_pct": 0})

    def tearDown(self):
        self.env.stop()

    def make_origin(self, branch="main"):
        self.branch = branch
        sh("git", "init", "-q", "--bare", "-b", branch, self.origin)
        self.seed = os.path.join(self.t, "seed")
        sh("git", "init", "-q", "-b", branch, self.seed)
        self.push("a.txt")

    def push(self, name, ref=None):
        Path(self.seed, name).write_text(name)
        sh("git", "add", name, cwd=self.seed)
        sh("git", "commit", "-qm", name, cwd=self.seed)
        sh("git", "push", "-q", self.origin, "HEAD:refs/heads/" + (ref or self.branch), cwd=self.seed)
        return sh("git", "rev-parse", "HEAD", cwd=self.seed).strip()

    def acquire(self, key="pr-1", ref="HEAD", **kw):
        return C.acquire("", key, ref, cfg=self.cfg, url=self.origin, **kw)


class MirrorAcquire(RepoFixture):
    def test_one_mirror_and_one_copy_per_key_reused(self):
        self.make_origin()
        a = self.acquire()
        self.assertTrue(a["ok"], a)
        b = self.acquire()
        self.assertEqual(a["path"], b["path"])
        self.assertTrue(b["reused"])
        mirrors = [p for p in Path(self.home, ".agent-harness", "mirrors").rglob("*.git") if p.is_dir()]
        self.assertEqual(len(mirrors), 1)
        self.assertEqual(S.git(mirrors[0].as_posix(), "for-each-ref", "refs/heads")[1], "")      # no stale branch copies

    # review B3: refs/heads copies from `git clone --bare` made --ref main resolve to the clone day's commit forever
    def test_branch_ref_follows_the_remote_after_the_mirror_was_made(self):
        self.make_origin()
        first = self.acquire(ref="main")
        c2 = self.push("b.txt")
        second = self.acquire(ref="main")
        self.assertTrue(second["ok"], second)
        self.assertEqual(second["commit"], c2)
        self.assertNotEqual(first["commit"], c2)
        self.assertTrue(os.path.exists(os.path.join(second["path"], "b.txt")))

    def test_default_branch_other_than_main_resolves_through_origin_head(self):
        self.make_origin("master")
        r = self.acquire(ref="HEAD")
        self.assertTrue(r["ok"], r)
        c2 = self.push("m.txt")
        r2 = self.acquire(ref="HEAD")
        self.assertEqual(r2["commit"], c2)

    def test_tags_and_full_shas_resolve(self):
        self.make_origin()
        sha = sh("git", "rev-parse", "HEAD", cwd=self.seed).strip()
        sh("git", "tag", "v1", cwd=self.seed)
        sh("git", "push", "-q", self.origin, "v1", cwd=self.seed)
        self.assertEqual(self.acquire("t1", "v1")["commit"], sha)
        self.assertEqual(self.acquire("t2", sha)["commit"], sha)
        bad = self.acquire("t3", "no-such-branch")
        self.assertFalse(bad["ok"])

    # review B3: commits made on a detached HEAD became unreachable when the copy moved
    def test_a_commit_made_in_the_copy_blocks_the_move(self):
        self.make_origin()
        p = self.acquire()["path"]
        Path(p, "mine.txt").write_text("mine")
        sh("git", "add", "mine.txt", cwd=p)
        sh("git", "commit", "-qm", "local work", cwd=p)
        local = sh("git", "rev-parse", "HEAD", cwd=p).strip()
        self.push("b.txt")
        res = self.acquire()
        self.assertFalse(res["ok"])
        self.assertTrue(res["stale"])
        self.assertEqual(sh("git", "rev-parse", "HEAD", cwd=p).strip(), local)
        self.assertTrue(os.path.exists(os.path.join(p, "mine.txt")))
        r = subprocess.run([sys.executable, str(HOOKS / "copy_hygiene.py"), "acquire", "--url", self.origin, "--key", "pr-1"],
                           capture_output=True, text=True, env=dict(os.environ, HARNESS_COPY_HYGIENE_MIN_FREE_GB="0"))
        self.assertEqual(r.returncode, 4, r.stdout + r.stderr)
        self.assertIn("refused", r.stderr)

    def test_a_failed_checkout_is_an_error_not_a_silent_old_commit(self):
        self.make_origin()
        p = self.acquire()["path"]
        old = sh("git", "rev-parse", "HEAD", cwd=p).strip()
        self.push("clash.txt")
        Path(p, "clash.txt").write_text("untracked, would be overwritten")
        res = self.acquire()
        self.assertFalse(res["ok"])
        self.assertTrue(res["stale"])
        self.assertEqual(sh("git", "rev-parse", "HEAD", cwd=p).strip(), old)

    def test_a_dirty_tracked_copy_refuses_and_keeps_the_edit(self):
        self.make_origin()
        p = self.acquire()["path"]
        Path(p, "a.txt").write_text("edit")
        self.push("b.txt")
        res = self.acquire()
        self.assertFalse(res["ok"])
        self.assertEqual(Path(p, "a.txt").read_text(), "edit")

    def test_an_unreachable_remote_fails_instead_of_using_a_stale_mirror(self):
        self.make_origin()
        self.acquire()
        os.rename(self.origin, self.origin + ".gone")
        res = self.acquire(ref="main")
        self.assertFalse(res["ok"])
        self.assertIn("fetch failed", res["error"])

    def test_a_failed_first_clone_leaves_no_mirror_and_no_temp_folder(self):
        res = self.acquire()                                  # origin does not exist
        self.assertFalse(res["ok"])
        base = Path(self.home, ".agent-harness", "mirrors")
        self.assertEqual([p for p in base.rglob("*") if p.is_dir()], [p for p in base.rglob("*") if p.is_dir() and p.parent == base])

    def test_disk_floor_blocks_the_first_mirror_clone(self):
        self.make_origin()
        with mock.patch.object(C, "free_bytes", return_value=1 * S.GB):
            res = C.acquire("", "pr-9", url=self.origin, cfg=C.normalize({"min_free_gb": 25, "min_free_pct": 0}))
        self.assertEqual(res["refused"], "disk-low")
        self.assertFalse(any(Path(self.home, ".agent-harness", "mirrors").rglob("*.git")))

    def test_two_runners_share_one_mirror_without_corruption(self):
        self.make_origin()
        code = ("import sys; sys.path.insert(0, %r); import copy_hygiene as C, json\n"
                "r = C.acquire('', sys.argv[1], 'HEAD', cfg=C.normalize({'min_free_gb':0,'min_free_pct':0}), url=%r)\n"
                "print(json.dumps(r))" % (str(HOOKS), self.origin))
        env = dict(os.environ)
        procs = [subprocess.Popen([sys.executable, "-c", code, "k%d" % i], stdout=subprocess.PIPE, text=True, env=env) for i in range(4)]
        outs = [json.loads(p.communicate()[0]) for p in procs]
        self.assertTrue(all(o["ok"] for o in outs), outs)
        mirrors = [p for p in Path(self.home, ".agent-harness", "mirrors").rglob("*.git") if p.is_dir()]
        self.assertEqual(len(mirrors), 1)
        self.assertEqual(S.git(mirrors[0].as_posix(), "fsck", "--connectivity-only")[0], 0)

    def test_same_repo_over_two_url_spellings_and_distinct_repos_get_distinct_ids(self):
        a = C.mirror_id("https://github.com/Owner/Repo.git")[0]
        self.assertEqual(a, C.mirror_id("git@github.com:Owner/Repo.git")[0])
        self.assertEqual(a, C.mirror_id("ssh://git@github.com:22/Owner/Repo")[0])
        self.assertNotEqual(a, C.mirror_id("https://gitlab.com/Owner/Repo.git")[0])
        self.assertNotEqual(C.mirror_id("https://github.com/a__b/c")[0], C.mirror_id("https://github.com/a/b__c")[0])
        self.assertEqual(C.parse_url("ssh://git@host.example:2222/o/r.git"), ("host.example", "o/r"))

    def test_source_checkout_unpushed_commit_is_fetched_and_the_move_is_allowed_while_the_source_keeps_it(self):
        self.make_origin()
        src = os.path.join(self.t, "src")
        sh("git", "clone", "-q", self.origin, src)
        first = C.acquire(src, "lane", cfg=self.cfg)
        Path(src, "x.txt").write_text("x")
        sh("git", "add", "x.txt", cwd=src)
        sh("git", "commit", "-qm", "unpushed", cwd=src)
        second = C.acquire(src, "lane", cfg=self.cfg)
        self.assertTrue(second["ok"], second)
        self.assertTrue(os.path.exists(os.path.join(second["path"], "x.txt")))
        Path(src, "y.txt").write_text("y")
        sh("git", "add", "y.txt", cwd=src)
        sh("git", "commit", "-qm", "unpushed 2", cwd=src)
        self.assertTrue(C.acquire(src, "lane", cfg=self.cfg)["ok"])           # earlier round's commit is still in the source
        self.assertNotEqual(first["commit"], second["commit"])


class Recoverable(RepoFixture):
    def setUp(self):
        super().setUp()
        self.make_origin()
        self.c = os.path.join(self.t, "clone")
        sh("git", "clone", "-q", self.origin, self.c)

    def test_clean_pushed_clone_is_recoverable(self):
        self.assertEqual(S.recoverable(self.c), (True, ""))

    def test_a_reflog_free_detached_commit_is_not(self):
        sh("git", "checkout", "-q", "--detach", cwd=self.c)
        sh("git", "commit", "-q", "--allow-empty", "-m", "detached", cwd=self.c)
        self.assertEqual(S.recoverable(self.c), (False, "HEAD is on no remote ref"))

    def test_lfs_submodule_and_rebase_states_are_kept(self):
        os.makedirs(os.path.join(self.c, ".git", "lfs"))
        self.assertIn("LFS", S.recoverable(self.c)[1])
        os.rmdir(os.path.join(self.c, ".git", "lfs"))
        os.makedirs(os.path.join(self.c, ".git", "rebase-merge"))
        self.assertIn("rebase", S.recoverable(self.c)[1])

    def test_remote_that_cannot_be_asked_keeps_the_clone(self):
        sh("git", "remote", "set-url", "origin", os.path.join(self.t, "nowhere.git"), cwd=self.c)
        self.assertIn("ls-remote failed", S.recoverable(self.c)[1])

    def test_a_clone_without_a_remote_is_kept(self):
        sh("git", "remote", "remove", "origin", cwd=self.c)
        self.assertEqual(S.recoverable(self.c), (False, "no remote"))

    def test_time_budget_stops_before_any_probe(self):
        self.assertEqual(S.recoverable(self.c, deadline=time.time() - 1), (False, "time budget exhausted"))

    def test_regenerable_dependency_folder_is_allowed_but_evidence_is_not(self):
        with open(os.path.join(self.c, ".git", "info", "exclude"), "a") as f:
            f.write("node_modules/\nevidence/\n")
        os.makedirs(os.path.join(self.c, "node_modules", "x"))
        Path(self.c, "node_modules", "x", "i.js").write_text("x")
        self.assertTrue(S.recoverable(self.c)[0])
        os.makedirs(os.path.join(self.c, "evidence"))
        Path(self.c, "evidence", "shot.png").write_text("x")
        self.assertIn("evidence", S.recoverable(self.c)[1])

    def test_ignored_file_inside_a_tracked_folder_is_judged_by_its_own_name(self):
        os.makedirs(os.path.join(self.c, "docs"))
        Path(self.c, "docs", "t.md").write_text("t")
        sh("git", "add", "docs", cwd=self.c)
        sh("git", "commit", "-qm", "docs", cwd=self.c)
        sh("git", "push", "-q", "origin", "HEAD:main", cwd=self.c)
        with open(os.path.join(self.c, ".git", "info", "exclude"), "a") as f:
            f.write("docs/secret.key\n")
        Path(self.c, "docs", "secret.key").write_text("k")
        self.assertIn("secret.key", S.recoverable(self.c)[1])


class CommandSplitter(unittest.TestCase):
    def test_prefix_options_and_values_are_skipped(self):
        for line, want in (("timeout 30 git clone x", ["git", "clone", "x"]), ("env -i A=1 B=2 git clone x", ["git", "clone", "x"]),
                           ("nice -n 5 ionice -c 2 -n 7 git clone x", ["git", "clone", "x"]),
                           ("sudo -u bob git clone x", ["git", "clone", "x"]), ("time -p git clone x", ["git", "clone", "x"]),
                           ("FOO=1 command git clone x", ["git", "clone", "x"])):
            self.assertIn(want, S.simple_commands(line), line)
        self.assertIn(["git", "clone", "x"], S.simple_commands("bash -c 'cd d && git clone x'"))
        self.assertIn(["docker", "run", "x"], S.simple_commands("echo $(docker run x)"))


if __name__ == "__main__":
    unittest.main()
