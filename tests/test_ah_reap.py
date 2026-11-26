"""ah_reap: `ah reap scan`, `ah reap run` and `ah co`.

Real git repositories in a temporary directory with a temporary HOME; nothing here can reach the real
~/.agent-harness, ~/.claude or a real host. A bare repository named as `rescue_remote` through AH_LOCAL_CONFIG stands
in for the remote, the global git config rewrites https://fixture.invalid/ and https://github.com/acme/ to local bare
repositories, and `docker` is a script that answers from files and records what it was asked.
The deletion path follows section F of the t2-dev report: each rule there has a test below.
"""
import contextlib
import hashlib
import io
import json
import os
import re
import signal
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
import ah_local  # noqa: E402
import ah_reap  # noqa: E402
import git_save  # noqa: E402
import workdir  # noqa: E402

SESSION = "0f8fad5b-d9cb-469f-a165-70867728950e"
OTHER = "7c9e6679-7425-40de-944b-e07fc1f90ae7"
THIRD = "3d6f0a1c-5b7e-4c2d-8f9a-1b2c3d4e5f60"
DOCKER = '''#!/bin/sh
echo "$@" >> "{log}"
case "$1 $2" in
  "ps -aq") cat "{data}/ps" ;;
  "inspect "*) cat "{data}/inspect" ;;
  "volume ls") cat "{data}/volumes" ;;
  "volume inspect") cat "{data}/volume-inspect" ;;
  "stop "*|"rm "*|"volume rm") [ ! -f "{data}/refuse" ] ;;
  *) exit 1 ;;
esac
'''


class Case(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.addCleanup(self.make_writable)
        self.root = Path(os.path.realpath(temp.name))
        self.home, self.remotes, self.bin = self.root / "home", self.root / "remotes", self.root / "bin"
        for folder in (self.home, self.remotes, self.bin, self.root / "tmp", self.root / "docker"):
            folder.mkdir()
        (self.home / ".gitconfig").write_text(
            "[user]\n\tname = Test\n\temail = test@fixture.invalid\n[init]\n\tdefaultBranch = main\n"
            "[http]\n\tproxy = http://127.0.0.1:9\n[core]\n\tsshCommand = false\n"
            '[url "%s/"]\n\tinsteadOf = https://fixture.invalid/\n\tinsteadOf = https://github.com/acme/\n'
            % self.remotes)
        self.config_path = self.home / "local.json"
        env = {"HOME": str(self.home), "AH_LOCAL_CONFIG": str(self.config_path), "GIT_CONFIG_NOSYSTEM": "1",
               "GIT_CONFIG_GLOBAL": str(self.home / ".gitconfig"), "TMPDIR": str(self.root / "tmp"),
               "GIT_CEILING_DIRECTORIES": str(self.root),
               "PATH": "%s%s%s" % (self.bin, os.pathsep, os.environ.get("PATH", ""))}
        patcher = mock.patch.dict(os.environ, env)
        patcher.start()
        self.addCleanup(patcher.stop)
        for name in ([key for key in os.environ if key.startswith("GIT_") and key not in env]
                     + ["XDG_CONFIG_HOME", *ah_reap.SESSION_ENV]):
            os.environ.pop(name, None)
        tempfile.tempdir = None
        self.addCleanup(setattr, tempfile, "tempdir", None)
        ah_local.reset()
        self.addCleanup(ah_local.reset)
        git_save._HOOKS_OFF.clear()
        self.docker_log = self.root / "docker.log"
        self.docker()   # no test ever reaches a real docker: by default the script fails, as a missing one would
        self.rescue = self.bare("rescue")
        self.configure(rescue_remote=str(self.rescue))
        self.work = self.home / ".agent-harness" / "work"
        self.log = self.home / ".agent-harness" / "logs" / "reap.jsonl"
        self.real_processes = ah_reap._processes
        quiet = mock.patch.object(ah_reap, "_processes", return_value={os.getpid(): (os.getppid(), [])})
        self.processes = quiet.start()   # the real process table is used only by the tests that are about it
        self.addCleanup(quiet.stop)

    def assert_temporary_home(self):
        """No test may ever act on the real home folder."""
        if not str(Path.home()).startswith(str(self.root) + os.sep):
            raise AssertionError("HOME is not the temporary one: %s" % Path.home())

    def make_writable(self):
        for folder, _dirs, _files in os.walk(self.root):
            os.chmod(folder, 0o700)

    def configure(self, **keys):
        self.config_path.write_text(json.dumps(keys))
        ah_local.reset()

    def docker(self, containers=None, volumes=None):
        """Install the docker script. With no arguments it fails every call."""
        data = self.root / "docker"
        if containers is not None:
            (data / "ps").write_text("".join(c["Id"] + "\n" for c in containers))
            (data / "inspect").write_text(json.dumps(containers))
            (data / "volumes").write_text("".join(v["Name"] + "\n" for v in volumes or []))
            (data / "volume-inspect").write_text(json.dumps(volumes or []))
        script = self.bin / "docker"
        script.write_text(DOCKER.format(log=self.docker_log, data=data))
        script.chmod(0o755)

    def docker_calls(self):
        return self.docker_log.read_text().splitlines() if self.docker_log.exists() else []

    def git(self, repo, *args, check=True):
        done = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True)
        if check and done.returncode != 0:
            self.fail("git %s failed: %s" % (" ".join(args), done.stderr))
        return done.stdout.strip()

    def bare(self, name):
        path = self.remotes / (name + ".git")
        subprocess.run(["git", "init", "-q", "--bare", str(path)], check=True)
        return path

    def commit(self, repo, name="file.txt", text="one\n", message="change"):
        (Path(repo) / name).parent.mkdir(parents=True, exist_ok=True)
        (Path(repo) / name).write_text(text)
        self.git(repo, "add", "-f", "--", name)
        self.git(repo, "commit", "-q", "-m", message)
        return self.git(repo, "rev-parse", "HEAD")

    def repo(self, path, origin=None):
        """A checkout with one commit; with `origin`, a clone that starts in step with it."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        if origin:
            subprocess.run(["git", "clone", "-q", str(origin), str(path)], check=True, capture_output=True)
        else:
            subprocess.run(["git", "init", "-q", str(path)], check=True)
            self.commit(path, "README.md", "hello\n", "first")
        return path

    def seeded_remote(self, name="proj"):
        """A bare repository with one commit on main, reachable as https://fixture.invalid/<name>.git."""
        seed = self.repo(self.root / ("seed-" + name))
        bare = self.bare(name)
        self.git(seed, "push", "-q", str(bare), "main")
        return bare

    def folder(self, session=SESSION):
        self.assert_temporary_home()
        return Path(os.path.realpath(workdir.ensure_session_dir(session)))

    def age(self, path, hours):
        """Make everything in a tree look last changed `hours` ago."""
        then = time.time() - hours * 3600
        for folder, dirs, files in os.walk(path):
            for name in dirs + files:
                os.utime(os.path.join(folder, name), (then, then), follow_symlinks=False)
        os.utime(path, (then, then))

    def reap(self, *args):
        self.assert_temporary_home()
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = ah_reap.main([str(arg) for arg in args])
        return code, out.getvalue() + err.getvalue()

    def apply(self, *args):
        return self.reap("run", "--apply", "--idle-hours", "0", *args)

    def rows(self, action=None, kind=None):
        if not self.log.exists():
            return []
        rows = [json.loads(line) for line in self.log.read_text().splitlines()]
        return [row for row in rows if action in (None, row["action"]) and kind in (None, row["kind"])]

    def removed(self, kind="checkout"):
        return [row["path"] for row in self.rows("removed", kind)]

    def refs(self, bare=None):
        out = self.git(bare or self.rescue, "for-each-ref", "--format=%(refname) %(objectname)")
        return dict(line.split(" ") for line in out.splitlines())

    def rescued(self, ending):
        found = [commit for ref, commit in self.refs().items() if ref.endswith(ending)]
        self.assertEqual(len(found), 1, (ending, self.refs()))
        return found[0]

    def listing(self, path):
        return sorted((os.path.join(folder, name), os.lstat(os.path.join(folder, name)).st_mtime_ns)
                      for folder, dirs, files in os.walk(path) for name in dirs + files)


class Eligibility(Case):
    def test_a_dry_run_changes_nothing(self):
        folder = self.folder()
        (folder / "node_modules" / "pkg").mkdir(parents=True)
        (folder / "node_modules" / "pkg" / "index.js").write_text("x\n")
        repo = self.repo(folder / "app")
        (repo / "wip.txt").write_text("wip\n")
        before, objects = self.listing(folder), self.git(repo, "count-objects", "-v")
        code, out = self.reap("run", "--idle-hours", "0")
        self.assertEqual(code, 0, out)
        self.assertIn("would remove  rebuildable", out)
        self.assertRegex(out, r"would remove  checkout  .*%s  once its work is proven saved \(now unsaved: "
                              r"1 untracked files, no remote off this host\)" % re.escape(str(repo)))
        self.assertIn("dry run", out)
        self.assertEqual(self.listing(folder), before)
        self.assertEqual(self.git(repo, "count-objects", "-v"), objects)
        self.assertEqual(self.refs(), {})
        self.assertEqual(sorted(p.name for p in (self.home / ".agent-harness").iterdir()), ["work"])

    def test_the_default_is_48_idle_hours_and_local_json_can_change_it(self):
        folder = self.folder()
        (folder / "node_modules").mkdir()
        code, out = self.reap("run", "--apply")
        self.assertEqual(code, 0, out)
        self.assertRegex(out, r"left  folder  \S+  used 0\.0 hours ago, needs 48 idle hours")
        self.age(folder, 47)
        self.reap("run", "--apply")
        self.assertTrue((folder / "node_modules").is_dir())
        self.configure(rescue_remote=str(self.rescue), reap_idle_hours=100)
        self.age(folder, 60)
        self.assertIn("needs 100 idle hours", self.reap("run", "--apply")[1])
        self.assertTrue((folder / "node_modules").is_dir())
        self.configure(rescue_remote=str(self.rescue))
        code, out = self.reap("run", "--apply")
        self.assertEqual(code, 0, out)
        self.assertFalse((folder / "node_modules").exists())
        self.assertEqual(self.rows("removed")[0]["reason"], "idle 60.0 hours")
        (folder / ".venv").mkdir()
        self.age(folder, 1)
        for value, gone in (("soon", False), (True, False), (-1, False), (0.5, True)):   # only a real number counts
            self.configure(rescue_remote=str(self.rescue), reap_idle_hours=value)
            self.reap("run", "--apply")
            self.assertEqual((folder / ".venv").exists(), not gone, value)

    def test_a_folder_marked_done_needs_one_idle_hour(self):
        folder = self.folder()
        (folder / "node_modules").mkdir()
        (folder / ".done").write_text("")
        self.age(folder, 0.5)
        self.assertIn("needs 1 idle hours", self.reap("run", "--apply")[1])
        self.assertTrue((folder / "node_modules").is_dir())
        self.age(folder, 2)
        self.reap("run", "--apply")
        self.assertFalse((folder / "node_modules").exists())
        self.assertEqual(self.rows("removed")[0]["reason"], "marked done, idle 2.0 hours")

    def test_a_live_session_is_left_alone(self):
        folder = self.folder()
        (folder / "node_modules").mkdir()
        self.age(folder, 100)
        transcript = self.home / ".claude" / "projects" / "some-project" / (SESSION + ".jsonl")
        transcript.parent.mkdir(parents=True)
        transcript.write_text("{}\n")   # the session wrote its transcript just now
        code, out = self.reap("run", "--apply")
        self.assertEqual(code, 0, out)
        self.assertIn("used 0.0 hours ago", out)
        self.assertTrue((folder / "node_modules").is_dir())
        self.age(transcript.parent, 100)
        wal = self.home / ".claude" / "wals" / SESSION / "main.jsonl"
        wal.parent.mkdir(parents=True)
        wal.write_text("{}\n")          # or its write-ahead log
        self.assertIn("used 0.0 hours ago", self.reap("run", "--apply")[1])
        self.assertTrue((folder / "node_modules").is_dir())
        self.assertEqual(self.rows(), [])

    def test_a_keep_file_protects_the_whole_folder(self):
        folder = self.folder()
        (folder / "node_modules").mkdir()
        repo = self.repo(folder / "app")
        (folder / ".keep").write_text("")
        code, out = self.apply()
        self.assertEqual(code, 0, out)
        self.assertIn("has a .keep file", out)
        self.assertTrue((folder / "node_modules").is_dir() and (repo / ".git").is_dir())
        self.assertEqual(self.refs(), {})
        plan = self.reap("run", "--idle-hours", "0")[1]   # and the plan says so as well
        self.assertIn("left  folder  %s  has a .keep file" % folder, plan)
        self.assertNotIn("would remove", plan)

    def test_a_keep_directory_is_never_entered_and_the_folder_is_reduced_around_it(self):
        folder = self.folder()
        (folder / "keep" / "node_modules").mkdir(parents=True)
        paid = self.repo(folder / "keep" / "results")
        holder = self.repo(folder / "holder")
        (holder / "keep").mkdir()
        (holder / "keep" / "costly.json").write_text("{}\n")
        (holder / "node_modules").mkdir()
        plain = self.repo(folder / "plain")
        code, out = self.apply()
        self.assertEqual(code, 0, out)
        self.assertTrue((folder / "keep" / "node_modules").is_dir() and (paid / ".git").is_dir())
        self.assertTrue((holder / "keep" / "costly.json").is_file() and (holder / ".git").is_dir())
        self.assertFalse((holder / "node_modules").exists())   # rebuildable output goes even from what is kept
        self.assertFalse(plain.exists())
        kept = self.rows("kept")
        self.assertEqual([(row["path"], row["reason"]) for row in kept],
                         [(str(holder), "holds %s, which is never removed" % (holder / "keep"))])

    def test_the_calling_session_is_never_touched_unless_it_is_named(self):
        for variable in ah_reap.SESSION_ENV:
            with self.subTest(variable):
                folder = self.folder()
                (folder / "node_modules").mkdir()
                with mock.patch.dict(os.environ, {variable: SESSION}):
                    code, out = self.apply()
                    self.assertEqual(code, 0, out)
                    self.assertIn("the calling session's own folder", out)
                    self.assertTrue((folder / "node_modules").is_dir())
                    self.apply("--session", SESSION)
                self.assertFalse((folder / "node_modules").exists())

    def test_session_limits_the_run_to_the_named_folders(self):
        first, second = self.folder(), self.folder(OTHER)
        (first / "node_modules").mkdir()
        (second / "node_modules").mkdir()
        code, out = self.apply("--session", OTHER)
        self.assertEqual(code, 0, out)
        self.assertTrue((first / "node_modules").is_dir())
        self.assertFalse((second / "node_modules").exists())
        code, out = self.apply("--session", THIRD)
        self.assertEqual(code, 3, out)
        self.assertIn("no folder", out)

    def test_a_folder_that_is_a_symlink_is_never_followed(self):
        elsewhere = self.root / "elsewhere"
        (elsewhere / "node_modules").mkdir(parents=True)
        self.work.mkdir(parents=True)
        (self.work / OTHER).symlink_to(elsewhere)
        code, out = self.apply()
        self.assertEqual(code, 0, out)
        self.assertIn("a symlink, which is never followed", out)
        self.assertTrue((elsewhere / "node_modules").is_dir())

    def test_a_folder_too_large_to_look_through_is_kept(self):
        folder = self.folder()
        for name in ("node_modules", "a", "b", "c"):
            (folder / name).mkdir()
        with mock.patch.object(ah_reap, "WALK_MAX", 3):
            code, out = self.apply()
        self.assertEqual(code, 0, out)
        self.assertRegex(out, r"left  folder  \S+  (more than 3 entries to look through|too large or unreadable)")
        self.assertTrue((folder / "node_modules").is_dir())

    @unittest.skipIf(os.geteuid() == 0, "root ignores directory permissions")
    def test_an_unreadable_directory_keeps_the_folder(self):
        folder = self.folder()
        (folder / "node_modules").mkdir()
        (folder / "locked").mkdir()
        os.chmod(folder / "locked", 0)
        self.addCleanup(os.chmod, folder / "locked", 0o700)
        code, out = self.apply()
        self.assertEqual(code, 0, out)
        self.assertIn("unreadable", out)
        self.assertTrue((folder / "node_modules").is_dir())

    def test_bad_arguments_are_refused_with_exit_code_3(self):
        self.folder()
        for args in ([], ["run", "--bogus"], ["run", "--idle-hours", "soon"], ["run", "--if-above", "3"],
                     ["sweep"], ["scan", "--loose"]):
            with self.subTest(args):
                self.assertEqual(self.reap(*args)[0], 3)
        self.assertEqual(self.reap("run", "--help")[0], 0)
        with mock.patch.object(ah_reap.shutil.rmtree, "avoids_symlink_attacks", False):
            code, out = self.apply()
        self.assertEqual(code, 3, out)
        self.assertIn("without following symlinks", out)


class InUse(Case):
    def stranger(self, cwd, opens=None):
        """A live process that is not a child of this one (its parent has exited). Returns its pid."""
        code = ("import subprocess, sys\n"
                "body = 'import sys, time\\nhandle = open(sys.argv[1], \"w\") if len(sys.argv) > 1 else None\\n"
                "print(1, flush=True)\\ntime.sleep(300)'\n"
                "child = subprocess.Popen([sys.executable, '-c', body] + sys.argv[2:], cwd=sys.argv[1],\n"
                "                         stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,\n"
                "                         stderr=subprocess.DEVNULL, start_new_session=True)\n"
                "child.stdout.readline()\nprint(child.pid)\n")
        done = subprocess.run([sys.executable, "-c", code, str(cwd)] + ([str(opens)] if opens else []),
                              stdout=subprocess.PIPE, text=True, check=True, timeout=30)
        pid = int(done.stdout.strip())
        self.addCleanup(self.stop, pid)
        return pid

    def stop(self, pid):
        with contextlib.suppress(OSError):
            os.kill(pid, signal.SIGKILL)

    def test_this_process_its_parents_and_its_children_never_count(self):
        root = "/work/s1"   # every one of these is inside the folder; 100 is the reaper itself
        table = {1: (0, ["/"]), 50: (1, [root]), 60: (50, [root + "/a"]), 100: (60, [root]),
                 200: (100, [root + "/its-lsof"]), 201: (200, [root + "/a-grandchild"]),
                 300: (1, ["/", root + "/open.log"]), 301: (1, ["/work/s10/file", "/work/s"]), 302: (50, [root])}
        with mock.patch.object(ah_reap.os, "getpid", return_value=100):
            self.assertEqual(ah_reap._users(table, [root]), [300, 302])   # a stranger, and another shell of the agent
            self.assertEqual(ah_reap._users(table, ["/work/s10"]), [301])
            self.assertEqual(ah_reap._users(table, ["/nowhere", root + "/open.log"]), [300])
            self.assertIsNone(ah_reap._users(None, [root]))
            self.assertEqual(ah_reap._users({100: (100, [root])}, [root]), [])   # a table that loops still ends
            self.assertEqual(ah_reap._users({7: (1, [root])}, [root]), [7])

    def test_the_real_process_table_sees_a_stranger_but_not_itself(self):
        self.processes.side_effect = self.real_processes
        folder = self.folder()
        (folder / "node_modules").mkdir()
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(300)"], cwd=folder)
        self.addCleanup(child.wait)
        self.addCleanup(child.kill)
        here = os.getcwd()
        os.chdir(folder)   # this process is inside the folder too, and so is the listing it starts
        self.addCleanup(os.chdir, here)
        table = self.real_processes()
        self.assertIn(os.getpid(), table)
        self.assertIn(child.pid, table)
        self.assertEqual(ah_reap._users(table, [str(folder)]), [])
        other = self.folder(OTHER)
        (other / "node_modules").mkdir()
        (other / "logs").mkdir()
        cwd_user = self.stranger(folder)
        file_user = self.stranger(self.root, other / "logs" / "run.log")
        table = self.real_processes()
        self.assertEqual(ah_reap._users(table, [str(folder)]), [cwd_user])
        self.assertEqual(ah_reap._users(table, [str(other)]), [file_user])
        code, out = self.apply()
        self.assertEqual(code, 0, out)
        self.assertIn("in use by process %d" % cwd_user, out)
        self.assertIn("in use by process %d" % file_user, out)
        self.assertTrue((folder / "node_modules").is_dir() and (other / "node_modules").is_dir())
        self.stop(cwd_user)
        self.stop(file_user)
        deadline = time.time() + 10
        while time.time() < deadline and ah_reap._users(self.real_processes(), [str(folder), str(other)]):
            time.sleep(0.1)
        code, out = self.apply()
        self.assertEqual(code, 0, out)
        self.assertFalse((folder / "node_modules").exists() or (other / "node_modules").exists())

    def test_an_unknown_process_table_keeps_everything(self):
        folder = self.folder()
        (folder / "node_modules").mkdir()
        self.processes.return_value = None
        code, out = self.apply()
        self.assertEqual(code, 0, out)
        self.assertIn("cannot tell whether a process is using it", out)
        self.assertTrue((folder / "node_modules").is_dir())
        with mock.patch.dict(os.environ, {"PATH": str(self.root / "tmp")}):
            self.assertIsNone(self.real_processes(proc=str(self.root / "no-proc")))   # no /proc and no lsof

    def test_an_lsof_listing_is_read_and_one_without_this_process_is_not_trusted(self):
        me, nowhere = os.getpid(), str(self.root / "no-proc")
        lsof = self.bin / "lsof"
        listing = "p%d\\nR1\\nfcwd\\nn/some where\\nf3\\nn/x/run.log\\np4242\\nR%d\\nfcwd\\nn/\\n" % (me, me)
        lsof.write_text("#!/bin/sh\nprintf '%s'\nexit 1\n" % listing)   # lsof exits 1 when it also prints a warning
        lsof.chmod(0o755)
        self.assertEqual(self.real_processes(proc=nowhere), {me: (1, ["/some where", "/x/run.log"]), 4242: (me, ["/"])})
        lsof.write_text("#!/bin/sh\nprintf 'p1\\nR0\\nfcwd\\nn/\\n'\n")
        self.assertIsNone(self.real_processes(proc=nowhere))
        lsof.write_text("#!/bin/sh\nexit 1\n")
        self.assertIsNone(self.real_processes(proc=nowhere))

    def test_the_proc_filesystem_is_read_where_there_is_one(self):
        folder = self.folder()
        proc = self.root / "proc"
        for pid, parent, name, cwd, files in ((1, 0, "init", "/", []), (40, 1, "bash", str(self.root), []),
                                             (77, 40, "odd ) name\xff", str(folder / "app"), ["/dev/null"]),
                                             (78, 1, "tail", "/", [str(folder / "run.log"), "pipe:[1234]"])):
            (proc / str(pid) / "fd").mkdir(parents=True)
            (proc / str(pid) / "stat").write_bytes(("%d (%s) S %d 1 1 0" % (pid, name, parent)).encode("latin-1"))
            (proc / str(pid) / "cwd").symlink_to(cwd)
            for number, target in enumerate(files):
                (proc / str(pid) / "fd" / str(number)).symlink_to(target)
        (proc / "self" / "fd").mkdir(parents=True)
        (proc / "meminfo").write_text("MemTotal: 1 kB\n")
        (proc / "90").mkdir()    # it exited while it was being read
        (proc / "91" / "fd").mkdir(parents=True)
        (proc / "91" / "stat").write_text("garbage")
        table = self.real_processes(proc=str(proc))
        self.assertEqual({pid: parent for pid, (parent, _paths) in table.items()}, {1: 0, 40: 1, 77: 40, 78: 1})
        self.assertEqual(table[77][1], [str(folder / "app"), "/dev/null"])
        with mock.patch.object(ah_reap.os, "getpid", return_value=40):
            self.assertEqual(ah_reap._users(table, [str(folder)]), [78])       # 77 is a child of this process
        with mock.patch.object(ah_reap.os, "getpid", return_value=500):
            self.assertEqual(ah_reap._users(table, [str(folder)]), [77, 78])

    def test_use_is_checked_again_right_before_a_checkout_is_deleted(self):
        folder = self.folder()
        repo = self.repo(folder / "app")
        (repo / "wip.txt").write_text("wip\n")
        quiet = {os.getpid(): (os.getppid(), [])}
        busy = {**quiet, 70000001: (1, [str(repo / "wip.txt")])}
        self.processes.side_effect = [quiet, quiet, busy]   # the plan, the start of the folder, then after the save
        code, out = self.apply()
        self.assertEqual(code, 0, out)
        self.assertIn("kept  folder  %s  in use by process 70000001" % folder, out)
        self.assertTrue((repo / "wip.txt").is_file())
        self.assertTrue(self.rescued("/snapshot"))    # its work was saved all the same
        self.assertEqual(self.removed(), [])
        self.assertEqual(self.rows("kept", "folder")[0]["reason"], "in use by process 70000001")

    def test_a_folder_used_while_it_was_being_saved_is_kept(self):
        folder = self.folder()
        repo = self.repo(folder / "app")
        self.age(folder, 5)
        real = git_save.save
        transcript = self.home / ".claude" / "projects" / "some-project" / (SESSION + ".jsonl")
        transcript.parent.mkdir(parents=True)
        for new, reason in ((repo / "new-work.txt", "used again while it was being cleaned"),
                            (transcript, "used again while it was being cleaned"),   # the session came back
                            (folder / ".keep", "has a .keep file")):
            with self.subTest(new.name):
                self.age(folder, 5)
                self.age(self.home / ".claude", 5)

                def save_then_someone_writes(*args, **kw):
                    result = real(*args, **kw)
                    new.write_text("typed while the save ran\n")
                    return result

                with mock.patch.object(git_save, "save", side_effect=save_then_someone_writes):
                    code, out = self.reap("run", "--apply", "--idle-hours", "1")
                self.assertEqual(code, 0, out)
                self.assertIn("kept  folder  %s  %s" % (folder, reason), out)
                self.assertEqual((repo / "new-work.txt").read_text(), "typed while the save ran\n")
                self.assertEqual(self.removed(), [])

    def test_what_the_run_itself_changes_does_not_count_as_use(self):
        folder = self.folder()
        repo = self.repo(folder / "app")
        (repo / "node_modules").mkdir()
        (repo / ".gitignore").write_text("node_modules/\n")
        (repo / "wip.txt").write_text("wip\n")
        self.age(folder, 5)   # removing node_modules and writing the snapshot's objects happen now
        code, out = self.reap("run", "--apply", "--idle-hours", "1")
        self.assertEqual(code, 0, out)
        self.assertFalse(repo.exists())
        self.assertEqual(self.git(self.rescue, "show", self.rescued("/snapshot") + ":wip.txt"), "wip")


class Rebuildable(Case):
    def test_only_rebuildable_directories_go_and_git_decides_inside_a_checkout(self):
        folder = self.folder()
        gone = [folder / "node_modules", folder / "scratch" / ".venv", folder / "scratch" / "deep" / "__pycache__",
                folder / "rust" / "target", folder / "app" / "node_modules", folder / "app" / "dist",
                folder / "app" / "web" / ".next"]
        stays = [folder / "target", folder / "dist", folder / "build", folder / "app" / "build",
                 folder / "app" / "vendor" / "node_modules", folder / "app" / "src", folder / "notes"]
        repo = self.repo(folder / "app")
        (repo / ".gitignore").write_text("dist/\nnode_modules/\n.next/\n")
        (folder / "rust").mkdir()
        (folder / "rust" / "Cargo.toml").write_text("[package]\n")
        for path in gone + stays:
            path.mkdir(parents=True, exist_ok=True)
            (path / "file.bin").write_text("x" * 100)
        self.commit(repo, "vendor/node_modules/file.bin", "tracked\n")   # git tracks this one: not ours to judge
        with mock.patch.object(git_save, "save", return_value={"ok": False, "reason": "no"}):   # the checkout stays
            code, out = self.apply()
        self.assertEqual(code, 0, out)
        self.assertEqual([path for path in gone if path.exists()], [])
        self.assertEqual([path for path in stays if not (path / "file.bin").is_file()], [])
        self.assertEqual(sorted(self.removed("rebuildable")), sorted(str(path) for path in gone))
        self.assertEqual({row["bytes"] for row in self.rows("removed", "rebuildable")}, {100})
        self.assertEqual(self.git(repo, "status", "--porcelain", "--", "vendor"), "")

    @unittest.skipIf(os.geteuid() == 0, "root ignores directory permissions")
    def test_a_read_only_tree_is_removed_whole_and_files_are_never_changed(self):
        folder = self.folder()
        store = self.root / "store"
        store.mkdir()
        (store / "shared.bin").write_text("shared\n")
        os.chmod(store / "shared.bin", 0o444)
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "precious.txt").write_text("precious\n")
        cache = folder / "node_modules" / "pkg" / "mod" / "v1"
        cache.mkdir(parents=True)
        os.link(store / "shared.bin", cache / "shared.bin")   # a hard link into a shared store
        (cache / "own.go").write_text("package x\n")
        os.chmod(cache / "own.go", 0o444)
        (folder / "node_modules" / "link").symlink_to(outside)
        repo = self.repo(folder / "app")
        (repo / ".gitignore").write_text("gopath/\n")
        self.git(repo, "add", ".gitignore")
        self.git(repo, "commit", "-q", "-m", "ignore")
        module = repo / "gopath" / "pkg" / "mod" / "example.com" / "lib@v1"
        module.mkdir(parents=True)
        (module / "lib.go").write_text("package lib\n")
        os.chmod(module / "lib.go", 0o444)
        for path in (cache, cache.parent, cache.parent.parent, module, module.parent, module.parent.parent):
            os.chmod(path, 0o555)   # as `go mod download` leaves them
        code, out = self.apply()
        self.assertEqual(code, 0, out)
        self.assertFalse((folder / "node_modules").exists() or repo.exists())
        info = os.stat(store / "shared.bin")
        self.assertEqual((stat.S_IMODE(info.st_mode), info.st_nlink), (0o444, 1))
        self.assertEqual((store / "shared.bin").read_text(), "shared\n")
        self.assertEqual((outside / "precious.txt").read_text(), "precious\n")   # the symlink was not followed

    def test_a_name_that_is_not_text_is_printed_and_logged_all_the_same(self):
        self.assert_temporary_home()
        odd = os.fsdecode(b"/work/caf\xe9/node_modules")   # how Python hands over a name that is not UTF-8
        out = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
        with contextlib.redirect_stdout(out):
            done = ah_reap._Run(True).note("kept", "checkout", odd, {"owner": None, "loose": True, "name": "x"}, "why")
            out.flush()
        self.assertTrue(done)
        self.assertEqual(out.buffer.getvalue(), b"kept  checkout  /work/caf\\udce9/node_modules  why\n")
        self.assertEqual(self.rows()[-1]["path"], odd)

    def test_the_session_temp_directory_is_emptied_and_kept_for_a_session_that_may_still_be_alive(self):
        folder = self.folder()
        temp = self.home / ".agent-harness" / "tmp" / SESSION[:8]
        (temp / "fixture-repo").mkdir(parents=True)
        (temp / "fixture-repo" / "file").write_text("x\n")
        (temp / "loose.txt").write_text("x\n")
        outside = self.root / "outside.txt"
        outside.write_text("precious\n")
        os.symlink(outside, temp / "link")
        os.chmod(temp / "fixture-repo", 0o500)
        os.chmod(temp, 0o755)
        code, out = self.apply()
        self.assertEqual(code, 0, out)
        self.assertEqual(list(temp.iterdir()), [])   # the contents go; the directory stays, so TMPDIR still works
        self.assertEqual(stat.S_IMODE(temp.stat().st_mode), 0o700)
        self.assertEqual(outside.read_text(), "precious\n")
        self.assertEqual(self.removed("tmp"), [str(temp)])
        self.assertTrue(folder.is_dir())   # the folder and its small files are left to `workdir.py prune`
        (temp / "again").write_text("x\n")
        self.age(temp, 100)
        twin = self.work / (SESSION[:8] + "-0000-4000-8000-000000000000")   # two folders claim it: nobody's
        twin.mkdir()
        self.apply()
        self.assertTrue((temp / "again").exists())

    def test_a_folder_name_that_is_not_a_uuid_gets_a_hashed_temp_directory_of_its_own(self):
        import session_env  # noqa: PLC0415
        folder = self.folder("codex-run-7")
        key = hashlib.sha256(folder.name.encode()).hexdigest()[:8]
        self.assertEqual(session_env.tmp_key(folder.name), key)
        self.assertEqual(session_env.tmp_key(SESSION), SESSION[:8])
        self.assertEqual(session_env.tmp_key(SESSION.upper()), hashlib.sha256(SESSION.upper().encode()).hexdigest()[:8])
        temp = self.home / ".agent-harness" / "tmp" / key
        (temp / "fixture").mkdir(parents=True)
        code, out = self.apply()
        self.assertEqual(code, 0, out)
        self.assertEqual((self.removed("tmp"), list(temp.iterdir())), ([str(temp)], []))

    def test_temp_directories_of_no_folder_go_once_idle_and_unused(self):
        self.folder()   # its own temp directory is not an orphan, however idle it looks
        tmp = self.home / ".agent-harness" / "tmp"
        made = {}
        for name in ("deadbeef", "cafef00d", "0badc0de", SESSION[:8], "guard-selftest-x1", "abcdef12.txt"):
            made[name] = tmp / name
            if name.endswith(".txt"):
                made[name].write_text("x\n")
            else:
                (made[name] / "fixture").mkdir(parents=True)
                (made[name] / "fixture" / "file").write_text("x\n")
        for name in made:
            if name != "cafef00d":   # used just now
                self.age(made[name], 50)
        self.processes.return_value = {os.getpid(): (1, []), 70000002: (1, [str(made["0badc0de"] / "sock")])}
        code, out = self.reap("run")
        self.assertEqual(code, 0, out)
        self.assertIn("would remove  tmp  ", out)
        self.assertIn(str(made["deadbeef"]), out)
        self.assertTrue(made["deadbeef"].is_dir())
        self.assertEqual(self.reap("run", "--apply", "--session", SESSION)[0], 0)   # a run limited to sessions
        self.assertTrue(made["deadbeef"].is_dir())
        code, out = self.reap("run", "--apply")
        self.assertEqual(code, 0, out)
        self.assertFalse(made["deadbeef"].exists())
        self.assertEqual(self.removed("tmp"), [str(made["deadbeef"])])
        self.assertIn("in use by process 70000002", out)
        for name in ("cafef00d", "0badc0de", SESSION[:8], "guard-selftest-x1", "abcdef12.txt"):
            self.assertTrue(made[name].exists(), name)

    def test_a_process_inside_the_temp_directory_keeps_the_session(self):
        folder = self.folder()
        (folder / "node_modules").mkdir()
        temp = self.home / ".agent-harness" / "tmp" / SESSION[:8]
        temp.mkdir(parents=True)
        self.processes.return_value = {os.getpid(): (1, []), 70000001: (1, [str(temp / "sock")])}
        self.assertIn("in use by process 70000001", self.apply()[1])
        self.assertTrue(temp.is_dir() and (folder / "node_modules").is_dir())


class Checkouts(Case):
    def test_every_kind_of_unsaved_work_is_on_the_remote_before_the_checkout_goes(self):
        folder = self.folder()
        repo = self.repo(folder / "co" / "app")
        self.git(repo, "checkout", "-q", "-b", "topic")
        topic = self.commit(repo, "topic.txt")
        self.git(repo, "tag", "v1")
        (repo / "README.md").write_text("stashed edit\n")
        self.git(repo, "stash")
        stash = self.git(repo, "rev-parse", "refs/stash")
        self.git(repo, "checkout", "-q", "--detach")
        detached = self.commit(repo, "detached.txt")
        (repo / "README.md").write_text("dirty\n")
        (repo / "untracked.txt").write_text("new\n")
        code, out = self.apply()
        self.assertEqual(code, 0, out)
        self.assertFalse(repo.exists())
        self.assertEqual(self.rescued("/heads/topic"), topic)
        self.assertEqual(self.rescued("/tags/v1"), topic)
        self.assertEqual(self.rescued("/stash/0"), stash)        # a stash counts as work
        self.assertEqual(self.rescued("/detached"), detached)    # and so does a detached HEAD
        snapshot = self.rescued("/snapshot")
        self.assertEqual(self.git(self.rescue, "show", snapshot + ":README.md"), "dirty")
        self.assertEqual(self.git(self.rescue, "show", snapshot + ":untracked.txt"), "new")
        row, = self.rows("removed", "checkout")
        self.assertEqual((row["path"], row["session"], row["saved"]["where"]), (str(repo), SESSION, "remote"))
        self.assertEqual(row["saved"]["refs"], {ref: commit for ref, commit in self.refs().items()})
        self.assertTrue(all("/%s/co-app-" % SESSION in ref for ref in row["saved"]["refs"]), row["saved"])

    def test_the_save_hook_and_the_reaper_use_the_same_names(self):
        """autosave.py saves after every turn and the reaper saves again before deleting: the same rescue refs, not
        a second set, also when the session folder is itself a checkout. Both mean the same temp directory."""
        import autosave  # noqa: PLC0415
        import session_env  # noqa: PLC0415
        folder = self.folder()
        subprocess.run(["git", "init", "-q", str(folder)], check=True)
        self.commit(folder, "top.txt")
        self.commit(self.repo(folder / "co" / "app"), "more.txt")
        self.assertEqual(autosave.run(SESSION), "")
        hook = self.refs()
        self.assertEqual(len(hook), 3, hook)   # two heads/main, and a snapshot of the folder's untracked marker
        self.assertTrue(any("/%s/top-" % SESSION in ref for ref in hook), hook)
        temp = session_env.make_tmp(folder.name)
        (temp / "fixture").write_text("x\n")
        code, out = self.apply()
        self.assertEqual(code, 0, out)
        self.assertFalse(folder.exists())
        self.assertEqual(self.refs(), hook)
        self.assertEqual(self.removed("tmp"), [str(temp)])
        self.assertEqual(list(Path(temp).iterdir()), [])   # emptied, and still there for a session that comes back

    def test_an_edit_git_can_only_see_by_reading_the_file_is_saved_too(self):
        """Same size, same timestamp as the index entry and as the index itself: only the content differs. git reads
        the file in that case because the index is as new as the entry; a copy of the index must not look newer."""
        folder = self.folder()
        repo = self.repo(folder / "app")
        self.git(repo, "config", "core.trustctime", "false")
        then = time.time() - 5000
        (repo / "README.md").write_text("first\n")
        os.utime(repo / "README.md", (then, then))
        self.git(repo, "commit", "-q", "-a", "-m", "same second")
        os.utime(repo / ".git" / "index", (then, then))
        (repo / "README.md").write_text("EDIT!\n")
        os.utime(repo / "README.md", (then, then))
        self.assertTrue(git_save.facts(repo)["dirty"])   # asked without letting git rewrite the index
        code, out = self.apply()
        self.assertEqual(code, 0, out)
        self.assertFalse(repo.exists())
        self.assertEqual(self.git(self.rescue, "show", self.rescued("/snapshot") + ":README.md"), "EDIT!")

    def test_secret_shaped_and_ignored_files_are_held_and_never_pushed(self):
        folder = self.folder()
        repo = self.repo(folder / "app")
        (repo / ".gitignore").write_text("*.sqlite\n")
        (repo / ".env").write_text("TOKEN=not-a-real-one\n")
        (repo / "local.sqlite").write_text("rows\n")
        (repo / "notes.txt").write_text("notes\n")
        code, out = self.apply()
        self.assertEqual(code, 0, out)
        self.assertFalse(repo.exists())
        pushed = set()
        for commit in self.refs().values():
            pushed.update(self.git(self.rescue, "ls-tree", "-r", "--name-only", commit).splitlines())
        self.assertEqual(pushed, {"README.md", ".gitignore", "notes.txt"})
        row, = self.rows("removed", "checkout")
        held = Path(row["saved"]["held_dir"])
        self.assertEqual(row["saved"]["held"], 2)
        self.assertEqual((held / ".env").read_text(), "TOKEN=not-a-real-one\n")
        self.assertEqual((held / "local.sqlite").read_text(), "rows\n")
        self.assertEqual(stat.S_IMODE(os.stat(held / ".env").st_mode), 0o600)
        self.assertFalse(str(held).startswith(str(folder)))

    def test_a_checkout_with_nothing_to_save_is_removed_after_the_remote_confirms(self):
        self.seeded_remote("proj")
        folder = self.folder()
        repo = self.repo(folder / "proj", origin="https://fixture.invalid/proj.git")
        with mock.patch.object(git_save, "save", wraps=git_save.save) as save:
            code, out = self.apply()
        self.assertEqual(code, 0, out)
        self.assertEqual(save.call_args.kwargs, {"fresh": True})   # proven now, never answered from memory
        self.assertEqual(save.call_args.args, (str(repo), SESSION, "proj"))
        self.assertFalse(repo.exists())
        self.assertEqual(self.refs(), {})
        self.assertEqual(self.rows("removed", "checkout")[0]["saved"]["where"], "nothing")

    def test_a_clone_of_a_clone_is_measured_against_the_real_remote(self):
        self.seeded_remote("proj")
        folder = self.folder()
        first = self.repo(self.root / "first", origin="https://fixture.invalid/proj.git")
        second = self.repo(folder / "second", origin=first)
        work = self.commit(second, "work.txt")
        code, out = self.apply()
        self.assertEqual(code, 0, out)
        self.assertFalse(second.exists())
        self.assertEqual(self.rescued("/heads/main"), work)

    def test_a_push_that_reports_success_but_leaves_no_ref_deletes_nothing(self):
        hook = self.rescue / "hooks" / "post-receive"   # the remote accepts the push, then drops the ref
        hook.write_text('#!/bin/sh\nwhile read old new ref; do git update-ref -d "$ref"; done\n')
        hook.chmod(0o755)
        (self.home / ".agent-harness").mkdir()
        (self.home / ".agent-harness" / "rescue").write_text("no bundle can be written here")
        folder = self.folder()
        repo = self.repo(folder / "app")
        (repo / "wip.txt").write_text("wip\n")
        code, out = self.apply()
        self.assertEqual(code, 0, out)
        self.assertEqual(self.refs(), {})
        self.assertEqual((repo / "wip.txt").read_text(), "wip\n")
        row, = self.rows("kept", "checkout")
        self.assertEqual(row["path"], str(repo))
        self.assertRegex(row["reason"], r"^not saved: \S")
        self.assertEqual(self.removed(), [])
        os.unlink(self.home / ".agent-harness" / "rescue")   # with a place for a bundle the work is proven there
        code, out = self.apply()
        self.assertEqual(code, 0, out)
        self.assertFalse(repo.exists())
        saved = self.rows("removed", "checkout")[0]["saved"]
        self.assertEqual((saved["where"], self.refs()), ("bundle", {}))
        self.assertFalse(saved["bundle"].startswith(str(folder)))
        empty = self.root / "empty"
        subprocess.run(["git", "init", "-q", str(empty)], check=True)
        self.git(empty, "bundle", "verify", "-q", saved["bundle"])
        self.git(empty, "fetch", "-q", saved["bundle"], "refs/heads/rescue/snapshot")
        self.assertEqual(self.git(empty, "show", "FETCH_HEAD:wip.txt"), "wip")

    def test_only_a_proven_save_allows_a_deletion(self):
        folder = self.folder()
        repo = self.repo(folder / "app")
        answers = [{"ok": False, "reason": "held files too large"}, {"ok": False}, {},
                   {"ok": True, "where": "bundle", "bundle": str(folder / "saved.bundle")},
                   {"ok": True, "where": "remote", "held_dir": str(repo / "held")}]
        inside = "its saved copy would be inside the folder being removed"
        reasons = ["not saved: held files too large", "not saved: no reason given", "not saved: no reason given",
                   inside, inside]
        for answer, reason in zip(answers, reasons):
            with self.subTest(answer), mock.patch.object(git_save, "save", return_value=answer):
                code, out = self.apply()
                self.assertEqual(code, 0, out)
                self.assertTrue((repo / ".git").is_dir())
                self.assertEqual(self.rows("kept")[-1]["reason"], reason)
        self.assertEqual(self.rows("removed"), [])

    def test_a_checkout_git_cannot_read_is_kept(self):
        folder = self.folder()
        broken = self.repo(folder / "broken")
        (broken / ".git" / "HEAD").write_text("garbage\n")
        stray = folder / "stray"
        (stray / ".git").mkdir(parents=True)   # not a repository at all
        (stray / "data.txt").write_text("data\n")
        outer = self.repo(folder / "outer")
        (outer / "sub" / ".git").mkdir(parents=True)   # git answers for the checkout around it: not this one's proof
        (outer / "sub" / "data.txt").write_text("data\n")
        code, out = self.apply()
        self.assertEqual(code, 0, out)
        kept = {row["path"]: row["reason"] for row in self.rows("kept")}
        self.assertRegex(kept[str(broken)], "^git cannot read it: ")
        self.assertRegex(kept[str(stray)], "^git cannot read it: ")
        self.assertEqual(kept[str(outer / "sub")], "git does not see a checkout of its own here")
        self.assertIn(str(outer / "sub") + " is kept", kept[str(outer)])
        self.assertTrue((broken / "README.md").is_file() and (stray / "data.txt").is_file())
        self.assertTrue((outer / "sub" / "data.txt").is_file())
        self.assertEqual(self.removed(), [])

    def test_a_linked_worktree_goes_before_its_parent_whatever_their_names(self):
        for parent_name, linked_name, session in (("a-parent", "z-linked", SESSION), ("z-parent", "a-linked", OTHER)):
            with self.subTest(parent=parent_name):
                folder = self.folder(session)
                parent = self.repo(folder / parent_name)
                linked = folder / linked_name
                self.git(parent, "worktree", "add", "-q", "-b", "side", str(linked))
                side = self.commit(linked, "side.txt")
                (linked / "wip.txt").write_text("worktree wip\n")
                (parent / "README.md").write_text("parent wip\n")
                code, out = self.apply("--session", session)
                self.assertEqual(code, 0, out)
                self.assertEqual(self.removed()[-2:], [str(linked), str(parent)])
                self.assertFalse(linked.exists() or parent.exists())
                refs = self.refs()
                name = "%s-" % linked_name
                self.assertEqual([c for r, c in refs.items() if name in r and r.endswith("/heads/side")], [side])
                wip, = [c for r, c in refs.items() if name in r and r.endswith("/snapshot")]
                self.assertEqual(self.git(self.rescue, "show", wip + ":wip.txt"), "worktree wip")
                mine, = [c for r, c in refs.items() if parent_name + "-" in r and r.endswith("/snapshot")]
                self.assertEqual(self.git(self.rescue, "show", mine + ":README.md"), "parent wip")

    def test_worktrees_inside_their_own_parent_and_a_session_folder_that_is_itself_a_checkout(self):
        folder = self.folder()
        subprocess.run(["git", "init", "-q", str(folder)], check=True)   # the session folder is the checkout
        self.commit(folder, "README.md", "hello\n", "first")
        linked = folder / ".claude" / "worktrees" / "agent-1"           # where Claude Code puts an agent's worktree
        self.git(folder, "worktree", "add", "-q", "-b", "agent-1", str(linked))
        self.git(folder, "worktree", "lock", "--reason", "claude agent agent-1 (pid 1)", str(linked))
        work = self.commit(linked, "work.txt")
        (linked / "node_modules").mkdir()
        code, out = self.apply()
        self.assertEqual(code, 0, out)
        self.assertEqual(self.removed(), [str(linked), str(folder)])
        self.assertFalse(folder.exists())
        refs = self.refs()
        self.assertEqual([c for r, c in refs.items() if "agent-1-" in r and r.endswith("/heads/agent-1")], [work])
        marker, = [c for r, c in self.refs().items() if "/%s/top-" % SESSION in r and r.endswith("/snapshot")]
        self.assertIn(workdir.MARKER, self.git(self.rescue, "ls-tree", "--name-only", marker).splitlines())

    def test_checkouts_that_depend_on_each_other_in_a_circle_are_kept(self):
        folder = self.folder()
        first, second = self.repo(folder / "first"), self.repo(folder / "second")
        for repo, other in ((first, second), (second, first)):
            (repo / ".git" / "objects" / "info" / "alternates").write_text("%s\n" % (other / ".git" / "objects"))
        code, out = self.apply()
        self.assertEqual(code, 0, out)
        self.assertEqual({row["path"]: row["reason"] for row in self.rows("kept")},
                         dict.fromkeys((str(first), str(second)),
                                       "it and another checkout depend on each other in a circle"))
        self.assertTrue((first / ".git").is_dir() and (second / ".git").is_dir())
        self.assertEqual(self.removed(), [])

    def test_a_parent_with_a_linked_worktree_outside_the_folder_is_kept(self):
        folder = self.folder()
        parent = self.repo(folder / "parent")
        outside = self.root / "outside-worktree"
        self.git(parent, "worktree", "add", "-q", "-b", "side", str(outside))
        (outside / "wip.txt").write_text("uncommitted\n")
        code, out = self.apply()
        self.assertEqual(code, 0, out)
        row, = self.rows("kept", "checkout")
        self.assertEqual((row["path"], row["reason"]), (str(parent), "%s is a linked worktree of it" % outside))
        self.assertEqual(self.removed(), [])
        self.assertEqual(self.git(outside, "status", "--porcelain"), "?? wip.txt")   # the worktree still works
        self.assertEqual(self.git(outside, "log", "--format=%s"), "first")

    def test_a_linked_worktree_whose_parent_is_outside_goes_and_the_parent_forgets_it(self):
        parent = self.repo(self.root / "parent")
        folder = self.folder()
        linked, locked = folder / "linked", folder / "locked"
        self.git(parent, "worktree", "add", "-q", "-b", "side", str(linked))
        self.git(parent, "worktree", "add", "-q", "-b", "held", str(locked))
        self.git(parent, "worktree", "lock", str(locked))
        side = self.commit(linked, "side.txt")
        code, out = self.apply()
        self.assertEqual(code, 0, out)
        self.assertFalse(linked.exists() or locked.exists())
        self.assertEqual(self.git(parent, "rev-parse", "side"), side)
        listed = self.git(parent, "worktree", "list", "--porcelain")   # a lock left by a dead agent holds nothing
        self.assertEqual([line for line in listed.splitlines() if line.startswith("worktree ")],
                         ["worktree %s" % parent])
        self.git(parent, "checkout", "-q", "side")   # the branch is free again in the parent
        self.assertEqual(self.git(parent, "fsck", "--connectivity-only"), "")

    def test_a_repository_another_folder_borrows_objects_from_is_kept(self):
        folder, other = self.folder(), self.folder(OTHER)
        lender = self.repo(folder / "lender")
        borrower = other / "borrower"
        subprocess.run(["git", "clone", "-q", "--shared", str(lender), str(borrower)], check=True)
        self.commit(borrower, "own.txt")
        for args in (["--session", SESSION], []):   # the borrower's folder is read even when it is not in the run
            with self.subTest(args):
                self.age(other, 0)
                (other / ".keep").write_text("")
                code, out = self.apply(*args)
                self.assertEqual(code, 0, out)
                self.assertEqual(self.rows("kept", "checkout")[-1]["reason"], "%s borrows its objects" % borrower)
                self.assertTrue((lender / ".git").is_dir())
                self.assertEqual(self.git(borrower, "log", "--format=%s"), "change\nfirst")
        os.unlink(other / ".keep")   # once the borrower may go, it goes, and then nothing depends on the lender
        code, out = self.apply("--session", OTHER)
        self.assertEqual(code, 0, out)
        self.assertFalse(borrower.exists())
        self.apply("--session", SESSION)
        self.assertFalse(lender.exists())

    def test_borrowers_are_also_looked_for_in_the_home_folder_and_beside_a_named_path(self):
        folder = self.folder()
        inside = self.repo(folder / "lib")                    # a session's checkout, lent to a loose one
        loose = self.repo(self.root / "elsewhere" / "pp795n")  # a loose checkout, lent to its neighbour
        users = {inside: self.home / "uses-lib", loose: self.root / "elsewhere" / "pp-scratch" / "chk28"}
        for lender, borrower in users.items():
            borrower.parent.mkdir(exist_ok=True)
            subprocess.run(["git", "clone", "-q", "--shared", str(lender), str(borrower)], check=True)
        code, out = self.apply("--session", SESSION, "--path", loose)
        self.assertEqual(code, 0, out)
        self.assertEqual({row["path"]: row["reason"] for row in self.rows("kept")},
                         {str(lender): "%s borrows its objects" % borrower for lender, borrower in users.items()})
        self.assertEqual(self.removed(), [])
        for borrower in users.values():
            self.assertEqual(self.git(borrower, "log", "--format=%s"), "first")

    def test_a_borrower_in_the_same_folder_goes_before_its_lender(self):
        folder = self.folder()
        lender = self.repo(folder / "a-lender")
        borrower = folder / "z-borrower"
        subprocess.run(["git", "clone", "-q", "--shared", str(lender), str(borrower)], check=True)
        own = self.commit(borrower, "own.txt")
        code, out = self.apply()
        self.assertEqual(code, 0, out)
        self.assertEqual(self.removed(), [str(borrower), str(lender)])
        self.assertEqual(self.git(self.rescue, "rev-list", "--count", own), "2")   # borrowed history went along

    def test_a_nested_checkout_goes_first_and_a_kept_one_keeps_what_holds_it(self):
        folder = self.folder()
        outer = self.repo(folder / "outer")
        inner = self.repo(outer / "vendor" / "inner")
        deepest = self.commit(inner, "deep.txt")
        real = git_save.save
        with mock.patch.object(git_save, "save", side_effect=lambda repo, *a, **kw: (
                {"ok": False, "reason": "the remote is down"} if repo == str(inner) else real(repo, *a, **kw))):
            code, out = self.apply()
        self.assertEqual(code, 0, out)
        kept = {row["path"]: row["reason"] for row in self.rows("kept")}
        self.assertEqual(kept[str(inner)], "not saved: the remote is down")
        self.assertEqual(kept[str(outer)], "%s is kept, and it is inside this checkout or depends on it" % inner)
        self.assertTrue((inner / "deep.txt").is_file())
        code, out = self.apply()
        self.assertEqual(code, 0, out)
        self.assertEqual(self.removed(), [str(inner), str(outer)])
        self.assertFalse(outer.exists())
        self.assertIn(deepest, self.refs().values())

    def test_every_deletion_is_logged_before_it_happens_and_kept_items_are_logged_too(self):
        folder = self.folder()
        (folder / "node_modules").mkdir()
        (folder / "node_modules" / "big.js").write_text("x" * 5000)
        gone = self.repo(folder / "gone")
        stays = self.repo(folder / "stays")
        (stays / "keep").mkdir()
        seen = []
        real = ah_reap._remove

        def remove(path):
            seen.append((path, [row["path"] for row in self.rows("removed")]))
            real(path)

        with mock.patch.object(ah_reap, "_remove", side_effect=remove):
            code, out = self.apply()
        self.assertEqual(code, 0, out)
        for path, logged in seen:
            self.assertIn(path, logged)   # the row was on disk before the deletion began
        state = self.rows("removed", "state")   # the save's record of the deleted checkout goes with it
        self.assertEqual([(row["session"], row["reason"]) for row in state],
                         [(SESSION, "the state of %s, which was removed" % gone)])   # at once, in every mode
        rows = [row for row in self.rows() if row["kind"] != "state"]
        self.assertEqual([(row["action"], row["kind"], row["path"]) for row in rows],
                         [("removed", "rebuildable", str(folder / "node_modules")),
                          ("kept", "checkout", str(stays)), ("removed", "checkout", str(gone))])
        for row in rows:
            self.assertEqual(sorted(row), ["action", "bytes", "host", "kind", "path", "reason", "saved", "session",
                                           "time"])
            self.assertEqual((row["session"], bool(row["host"]), bool(row["reason"])), (SESSION, True, True))
            self.assertRegex(row["time"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        self.assertEqual(rows[0]["bytes"], 5000)
        self.assertGreater(rows[2]["bytes"], 0)
        self.assertEqual(stat.S_IMODE(os.stat(self.log).st_mode), 0o600)
        self.assertIn("freed ", out)

    def test_without_its_log_row_nothing_is_deleted(self):
        folder = self.folder()
        (folder / "node_modules").mkdir()
        repo = self.repo(folder / "app")
        (self.home / ".agent-harness" / "logs").write_text("not a directory")
        code, out = self.apply()
        self.assertEqual(code, 1, out)
        self.assertIn("cannot write the log", out)
        self.assertTrue((folder / "node_modules").is_dir() and (repo / ".git").is_dir())

    def test_a_deletion_that_fails_is_reported_and_logged(self):
        folder = self.folder()
        (folder / "node_modules").mkdir()
        with mock.patch.object(ah_reap.shutil, "rmtree", side_effect=PermissionError(1, "no", "x")):
            code, out = self.apply()
        self.assertEqual(code, 1, out)
        self.assertEqual([(row["action"], row["reason"]) for row in self.rows()][-1],
                         ("failed", "partly removed: PermissionError"))


class Pressure(Case):
    def folders(self):
        made = {}
        for session, hours in ((SESSION, 50), (OTHER, 30), (THIRD, 10)):
            made[session] = self.folder(session)
            (made[session] / "node_modules").mkdir()
            self.age(made[session], hours)
        return made

    def test_below_the_threshold_nothing_is_done(self):
        made = self.folders()
        with mock.patch.object(ah_reap, "_disk_used", return_value=69.9):
            code, out = self.reap("run", "--apply", "--if-above", "70")
        self.assertEqual(code, 0, out)
        self.assertIn("69.9% full, under 70%: nothing to do", out)
        self.assertTrue(all((folder / "node_modules").is_dir() for folder in made.values()))
        with mock.patch.object(ah_reap, "_disk_used", return_value=None):   # an unreadable disk: do nothing
            self.assertEqual(self.reap("run", "--apply", "--if-above", "70")[0], 0)
        self.assertTrue(all((folder / "node_modules").is_dir() for folder in made.values()))

    def test_above_it_folders_idle_a_day_go_oldest_first_until_five_points_under(self):
        made = self.folders()
        with mock.patch.object(ah_reap, "_disk_used", return_value=90):
            code, out = self.reap("run", "--apply", "--if-above", "70")
        self.assertEqual(code, 0, out)
        self.assertEqual(self.removed("rebuildable"), [str(made[SESSION] / "node_modules"),
                                                      str(made[OTHER] / "node_modules")])
        self.assertTrue((made[THIRD] / "node_modules").is_dir())   # idle for ten hours only
        self.assertIn("needs 24 idle hours", out)

    def test_f5_under_if_above_a_folder_idle_less_than_a_day_is_never_taken(self):
        made = self.folders()   # a live session waiting for its owner for ten hours keeps its checkout
        repo = self.repo(made[THIRD] / "co" / "app")
        (repo / "wip.txt").write_text("half done\n")
        self.age(made[THIRD], 10)
        with mock.patch.object(ah_reap, "_disk_used", return_value=99):
            code, out = self.reap("run", "--apply", "--if-above", "85", "--idle-hours", "2")
        self.assertEqual(code, 0, out)
        self.assertTrue((repo / "wip.txt").exists(), out)
        self.assertTrue((made[THIRD] / "node_modules").is_dir())
        self.assertIn("needs 24 idle hours", out)
        self.assertFalse((made[SESSION] / "node_modules").exists())

    def test_it_stops_as_soon_as_the_disk_is_five_points_under(self):
        made = self.folders()
        with mock.patch.object(ah_reap, "_disk_used", side_effect=[70, 70, 65, 65]):
            code, out = self.reap("run", "--apply", "--if-above", "70")
        self.assertEqual(code, 0, out)
        self.assertEqual(self.removed("rebuildable"), [str(made[SESSION] / "node_modules")])
        self.assertTrue((made[OTHER] / "node_modules").is_dir())
        self.assertIn("stopping", out)


class Cheap(Case):
    def test_with_nothing_eligible_no_tree_is_walked_for_size_and_no_git_or_docker_is_asked(self):
        own, kept, busy = self.folder(SESSION), self.folder(OTHER), self.folder(THIRD)
        for folder in (own, kept, busy):
            self.repo(folder / "app")
            (folder / "node_modules").mkdir()
        (kept / ".keep").write_text("")
        self.age(own, 100)
        self.age(kept, 100)
        self.age(busy, 100)
        (busy / "app" / "deep").mkdir()
        (busy / "app" / "deep" / "new.txt").write_text("written just now\n")
        os.environ["AH_SESSION"] = SESSION
        costly = AssertionError("costly work for a folder that is not eligible")
        self.processes.side_effect = costly
        with mock.patch.object(ah_reap, "_survey", side_effect=costly), \
                mock.patch.object(ah_reap, "_size", side_effect=costly), \
                mock.patch.object(ah_reap, "_docker_list", side_effect=costly), \
                mock.patch.object(git_save, "facts", side_effect=costly), \
                mock.patch.object(git_save, "_git", side_effect=costly):
            code, out = self.reap("run", "--apply")
        self.assertEqual(code, 0, out)
        self.assertIn("the calling session's own folder", out)
        self.assertIn("has a .keep file", out)
        self.assertIn("used 0.0 hours ago, needs 48 idle hours", out)
        with mock.patch.object(ah_reap, "_disk_used", return_value=40.0), \
                mock.patch.object(ah_reap, "_look", side_effect=costly):
            code, out = self.reap("run", "--apply", "--if-above", "70")
        self.assertEqual(code, 0, out)
        self.assertIn("nothing to do", out)
        self.processes.side_effect = None
        del os.environ["AH_SESSION"]
        self.assertEqual(self.apply()[0], 0)   # eligible now: the full work is done for those folders only
        self.assertEqual([(f / "node_modules").exists() for f in (own, kept, busy)], [False, True, False])


class Housekeeping(Case):
    def test_the_run_removes_its_own_leftovers_and_never_a_saved_copy(self):
        folder = self.folder()
        repo = self.repo(folder / "app")
        state = self.home / ".agent-harness" / "state" / "git-save"
        state.mkdir(parents=True)
        files = {"gone": state / ("a" * 64 + ".json"), "here": state / ("b" * 64 + ".json"),
                 "odd": state / ("c" * 64 + ".json"), "mine": state / ("session-%s.json" % SESSION),
                 "mine-lock": state / ("session-%s.json.lock" % SESSION),
                 "ended": state / ("session-%s.json" % OTHER), "ended-lock": state / ("session-%s.json.lock" % OTHER),
                 "private": state / ("private-%s.json" % ("d" * 16))}
        for key, path in files.items():
            path.write_text(json.dumps({"repo": str(self.root / "no-such-checkout"), "at": 1}) if key == "gone"
                            else json.dumps({"repo": str(repo)}) if key == "here" else "not json" if key == "odd"
                            else "{}")
        mirrors = self.home / ".agent-harness" / "cache" / "git" / "acme"
        for name in ("old", "new", "busy", "lent"):
            self.git(self.root, "init", "-q", "--bare", str(mirrors / (name + ".git")))
        borrower = self.repo(self.home / "elsewhere" / "borrower")
        alternates = borrower / ".git" / "objects" / "info" / "alternates"
        alternates.write_text(str(mirrors / "lent.git" / "objects") + "\n")
        for name in ("old", "busy", "lent"):
            self.age(mirrors / (name + ".git"), 31 * 24)
        self.age(mirrors / "new.git", 29 * 24)
        self.processes.return_value = {os.getpid(): (1, []), 70000003: (1, [str(mirrors / "busy.git" / "objects")])}
        rescue = self.home / ".agent-harness" / "rescue"
        (rescue / "host" / SESSION).mkdir(parents=True)
        (rescue / "host" / SESSION / "app-12345678.bundle").write_bytes(b"b" * 3000)
        (rescue / "host" / SESSION / "app-12345678.json").write_text("{}")
        (rescue / "held" / "host" / SESSION / "app-12345678").mkdir(parents=True)
        (rescue / "held" / "host" / SESSION / "app-12345678" / ".env").write_bytes(b"e" * 1000)
        self.age(rescue, 1000)
        before = self.listing(self.home / ".agent-harness")
        code, out = self.reap("run")
        self.assertEqual(code, 0, out)
        self.assertIn("would remove  state  ", out)
        self.assertIn("would remove  mirror  ", out)
        self.assertEqual(self.listing(self.home / ".agent-harness"), before)
        code, out = self.reap("run", "--apply")
        self.assertEqual(code, 0, out)
        self.assertEqual({key for key, path in files.items() if not path.exists()}, {"gone", "ended", "ended-lock"})
        self.assertEqual(sorted(p.name for p in mirrors.iterdir()), ["busy.git", "lent.git", "new.git"])
        self.assertEqual(sorted(self.removed("state")), sorted(str(files[k]) for k in ("gone", "ended", "ended-lock")))
        self.assertEqual(self.removed("mirror"), [str(mirrors / "old.git")])
        self.assertIn("borrows its objects", out)
        self.assertEqual(sorted(str(p) for p in rescue.rglob("*") if p.is_file()), sorted(
            str(p) for p in [rescue / "host" / SESSION / "app-12345678.bundle", rescue / "host" / SESSION /
                             "app-12345678.json", rescue / "held" / "host" / SESSION / "app-12345678" / ".env"]))
        code, out = self.reap("scan")
        self.assertEqual(code, 0, out)
        self.assertIn("1 bundles (2.9 KB), 1 held files (1000 B)", out)
        report = json.loads(self.reap("scan", "--json")[1])
        self.assertEqual(report["rescue"], {"bundles": 1, "bundle_bytes": 3000, "held_files": 1, "held_bytes": 1000})


class PathOption(Case):
    def test_one_named_folder_outside_the_work_root_is_treated_as_ownerless(self):
        idle = self.folder()
        (idle / "node_modules").mkdir()
        loose = self.repo(self.home / "timbar-pr41")
        work = self.commit(loose, "work.txt")
        (loose / "node_modules").mkdir()
        beside = self.repo(self.home / "timbar-pr42")
        code, out = self.reap("run", "--idle-hours", "0", "--path", loose)
        self.assertEqual(code, 0, out)
        self.assertTrue((loose / "work.txt").is_file())    # a dry run
        code, out = self.apply("--path", loose)
        self.assertEqual(code, 0, out)
        self.assertFalse(loose.exists())
        self.assertTrue((beside / ".git").is_dir())        # only what was named
        self.assertTrue((idle / "node_modules").is_dir())  # and not the work root
        ref, = [ref for ref in self.refs() if ref.endswith("/heads/main")]
        self.assertRegex(ref, r"^refs/rescue/[^/]+/loose/timbar-pr41-[0-9a-f]{8}/[0-9]{8}T[0-9]{6}Z-[0-9a-f]{4}/heads/main$")
        self.assertEqual(self.refs()[ref], work)
        self.assertEqual({row["session"] for row in self.rows()}, {None})

    def test_a_loose_folder_must_be_idle_too(self):
        loose = self.repo(self.home / "busy")
        code, out = self.reap("run", "--apply", "--path", loose)
        self.assertEqual(code, 0, out)
        self.assertIn("needs 48 idle hours", out)
        self.assertTrue((loose / ".git").is_dir())

    def test_paths_that_could_take_too_much_are_refused(self):
        folder = self.folder()
        (self.home / ".claude" / "projects").mkdir(parents=True)
        (self.home / "real").mkdir()
        (self.home / "link").symlink_to(self.home / "real")
        (self.home / "file.txt").write_text("x\n")
        for path in (self.home, self.root, "/", folder, self.work, self.home / ".agent-harness",
                     self.home / ".claude" / "projects", self.home / "link", self.home / "file.txt",
                     self.home / "missing", "~"):
            with self.subTest(path):
                code, out = self.apply("--path", path)
                self.assertEqual(code, 3, out)
                self.assertIn("--path", out)
        self.assertEqual(self.rows(), [])


class Docker(Case):
    def things(self, folder, state="exited"):
        containers = [
            {"Id": "c0ffee01", "Name": "/pp795-pg", "Config": {"Labels": {"ah.session": SESSION}},
             "State": {"Status": state}, "Mounts": []},
            {"Id": "c0ffee02", "Name": "/bound", "Config": {"Labels": {}}, "State": {"Status": "exited"},
             "Mounts": [{"Type": "bind", "Source": str(folder / "data")}, {"Type": "volume", "Name": "anon"}]},
            {"Id": "c0ffee03", "Name": "/guard-pin", "Config": {"Labels": None}, "State": {"Status": "exited"},
             "Mounts": [{"Type": "bind", "Source": "/srv/elsewhere"}]},
            {"Id": "c0ffee04", "Name": "/other-session", "Config": {"Labels": {"ah.session": OTHER}},
             "State": {"Status": "running"}, "Mounts": []},
            {"Id": "--force", "Name": "/odd", "Config": {"Labels": {"ah.session": SESSION}},
             "State": {"Status": "exited"}, "Mounts": []}]
        volumes = [{"Name": "pgdata-s1", "Labels": {"ah.session": SESSION}}, {"Name": "unowned", "Labels": None},
                   {"Name": "other-vol", "Labels": {"ah.session": OTHER}}]
        self.docker(containers, volumes)

    def test_only_the_idle_sessions_stopped_containers_and_its_volumes_are_removed(self):
        folder, live = self.folder(), self.folder(OTHER)
        self.age(folder, 60)
        self.things(folder)
        code, out = self.reap("run")
        self.assertEqual(code, 0, out)
        self.assertIn("would remove  container  pp795-pg", out)
        self.assertEqual([call for call in self.docker_calls() if call.split()[0] in ("stop", "rm")], [])
        code, out = self.reap("run", "--apply")
        self.assertEqual(code, 0, out)
        changes = [call for call in self.docker_calls() if not call.startswith(("ps", "inspect", "volume ls",
                                                                                 "volume inspect"))]
        self.assertEqual(changes, ["rm -v c0ffee01", "rm -v c0ffee02", "volume rm pgdata-s1"])   # nothing is stopped
        for word in ("prune", "rmi", "image", "system", "guard", "c0ffee03", "c0ffee04", "unowned", "other-vol",
                     "--force"):   # never an image, a prune, an unlabelled thing or a live session's
            self.assertFalse([call for call in changes if word in call], word)
        self.assertEqual([(row["kind"], row["path"]) for row in self.rows("removed")],
                         [("container", "pp795-pg"), ("container", "bound"), ("volume", "pgdata-s1")])
        self.assertTrue(live.is_dir())

    def test_a_running_container_keeps_the_folder_its_checkouts_and_its_volume(self):
        folder = self.folder()
        repo = self.repo(folder / "co" / "app")
        (repo / "wip.txt").write_text("wip\n")
        self.age(folder, 72)
        for state in ("running", "paused", "restarting", None):
            with self.subTest(state):
                self.things(folder, state)
                code, out = self.reap("run", "--apply")
                self.assertEqual(code, 0, out)
                self.assertIn("kept  folder  %s  container pp795-pg is %s" % (
                    folder, state or "in an unknown state"), out)
                self.assertEqual([call for call in self.docker_calls() if call.split()[0] in ("stop", "rm", "volume")
                                  and not call.startswith(("volume ls", "volume inspect"))], [])
                self.assertTrue((repo / "wip.txt").exists())
                self.assertEqual(self.rows("removed"), [])

    def test_a_removal_docker_refuses_is_a_failure(self):
        folder = self.folder()
        self.things(folder)
        (self.root / "docker" / "refuse").write_text("")
        code, out = self.apply("--session", SESSION)
        self.assertEqual(code, 1, out)
        self.assertEqual([row["reason"] for row in self.rows("failed")], ["docker did not remove it"] * 3)

    def test_scan_reports_unlabelled_things_and_ties_the_rest_to_their_folder(self):
        folder = self.folder()
        self.things(folder)
        code, out = self.reap("scan", "--json")
        self.assertEqual(code, 0, out)
        report = json.loads(out)
        self.assertEqual(sorted(thing["name"] for thing in report["docker_unlabelled"]),
                         ["guard-pin", "other-session", "other-vol", "unowned"])
        mine, = [look for look in report["folders"] if look["name"] == SESSION]
        self.assertEqual(sorted(thing["name"] for thing in mine["docker"]), ["bound", "odd", "pgdata-s1", "pp795-pg"])
        self.assertEqual([call for call in self.docker_calls() if call.split()[0] in ("stop", "rm")], [])
        self.assertIn("unlabelled container guard-pin  exited (report only)", self.reap("scan")[1])

    def test_without_docker_everything_else_still_works(self):
        folder = self.folder()
        (folder / "node_modules").mkdir()
        self.assertIsNone(ah_reap._docker_list([]))   # the script fails every call
        with mock.patch.dict(os.environ, {"PATH": str(self.root / "tmp")}):
            self.assertIsNone(ah_reap._docker("ps"))  # and here there is no docker at all
        code, out = self.reap("scan", "--json")
        self.assertEqual(code, 0, out)
        self.assertIsNone(json.loads(out)["docker_unlabelled"])
        self.assertIn("docker did not answer", self.reap("scan")[1])
        code, out = self.apply()
        self.assertEqual(code, 0, out)
        self.assertFalse((folder / "node_modules").exists())


class Scan(Case):
    def test_the_report_names_owner_use_size_and_what_is_unsaved_and_changes_nothing(self):
        self.seeded_remote("proj")
        folder = self.folder()
        saved = self.repo(folder / "saved", origin="https://fixture.invalid/proj.git")
        ahead = self.repo(folder / "ahead", origin="https://fixture.invalid/proj.git")
        self.commit(ahead, "more.txt")
        dirty = self.repo(folder / "dirty", origin="https://fixture.invalid/proj.git")
        (dirty / "README.md").write_text("edited\n")
        (dirty / "new.txt").write_text("new\n")
        self.git(dirty, "stash", "-u")
        (dirty / "new.txt").write_text("new again\n")
        second = self.repo(folder / "second", origin=saved)
        alone = self.repo(folder / "alone")
        (folder / "node_modules").mkdir()
        (folder / "node_modules" / "lib.js").write_text("x" * 300)
        (folder / "keep").mkdir()
        with open(folder / "dump.sql", "wb") as handle:
            handle.truncate(ah_reap.BIG_FILE + 1)
        with open(saved / "big.bin", "wb") as handle:
            handle.truncate(ah_reap.BIG_FILE + 1)
        named = self.work / "lc-engine-pilot"
        named.mkdir()
        (named / ".keep").write_text("")
        self.age(named, 100)
        (self.work / "link").symlink_to(self.root / "tmp")
        before = self.listing(self.work)
        with mock.patch.dict(os.environ, {"AH_SESSION": "someone-else"}):
            code, out = self.reap("scan", "--json")
        self.assertEqual(code, 0, out)
        report = json.loads(out)
        self.assertEqual(report["work_root"], str(self.work))
        self.assertTrue(0 <= report["disk_used_percent"] <= 100)
        looks = {look["name"]: look for look in report["folders"]}
        mine = looks[SESSION]
        self.assertEqual((mine["owner"], mine["live"], mine["in_use"], mine["keep_file"]), (SESSION, True, [], False))
        self.assertEqual(mine["keep"], [str(folder / "keep")])
        self.assertEqual(mine["rebuildable_bytes"], 300)
        self.assertEqual(mine["big"], [{"path": str(folder / "dump.sql"), "bytes": ah_reap.BIG_FILE + 1}])
        self.assertGreater(mine["bytes"], ah_reap.BIG_FILE)
        states = {os.path.basename(item["path"]): (item["state"], item["why"]) for item in mine["checkouts"]}
        self.assertEqual(states["saved"], ("unsaved", ["1 untracked files"]))   # big.bin is not on any remote
        self.assertEqual(states["ahead"], ("unsaved", ["commits not on its remote-tracking refs"]))
        self.assertEqual(states["dirty"], ("unsaved", ["1 untracked files", "1 stashes",
                                                       "commits not on its remote-tracking refs"]))
        self.assertEqual(states["second"], ("unknown", ["its origin is a local path (--check-remote asks the real "
                                                        "remote)"]))
        self.assertEqual(states["alone"], ("unsaved", ["no remote off this host"]))
        other = looks["lc-engine-pilot"]
        self.assertEqual((other["owner"], other["live"], other["keep_file"], other["idle_hours"]),
                         (None, False, True, 100.0))
        self.assertEqual(looks["link"]["skip"], "a symlink, which is never followed")
        self.assertEqual(self.listing(self.work), before)
        self.assertEqual(sorted(p.name for p in (self.home / ".agent-harness").iterdir()), ["work"])
        os.unlink(saved / "big.bin")
        code, out = self.reap("scan", "--json", "--check-remote")
        states = {os.path.basename(item["path"]): item["state"]
                  for item in {look["name"]: look for look in json.loads(out)["folders"]}[SESSION]["checkouts"]}
        self.assertEqual(states, {"saved": "saved", "ahead": "unsaved", "dirty": "unsaved", "second": "saved",
                                  "alone": "unsaved"})
        code, text = self.reap("scan")
        self.assertEqual(code, 0, text)
        self.assertIn("%s  owner %s  live" % (SESSION, SESSION), text)
        self.assertIn("lc-engine-pilot  owner unknown  not live, idle 100.0 h", text)
        self.assertIn("    checkout %s  unsaved: no remote off this host" % alone, text)
        self.assertIn("    checkout %s  saved\n" % saved, text)
        self.assertIn("    large file %s  100.0 MB (never deleted here)" % (folder / "dump.sql"), text)
        self.assertIn("[keep/]", text)

    def test_loose_lists_checkouts_at_most_two_levels_down_and_never_under_the_work_root(self):
        folder = self.folder()
        self.repo(folder / "inside")
        top = self.repo(self.home / "pp795n")
        deeper = self.repo(self.home / "pp-scratch" / "chk28")
        self.repo(self.home / "pp-scratch" / "group" / "too-deep")
        self.repo(top / "nested")
        code, out = self.reap("scan", "--json", "--loose", self.home)
        self.assertEqual(code, 0, out)
        loose = {item["path"]: item["state"] for item in json.loads(out)["loose"]}
        self.assertEqual(loose, {str(top): "unsaved", str(deeper): "unsaved"})
        self.assertIn("loose checkout %s  unsaved: " % top, self.reap("scan", "--loose", self.home)[1])
        self.assertTrue((top / ".git").is_dir() and (deeper / ".git").is_dir())

    def test_the_module_runs_on_its_own(self):
        self.folder()
        done = subprocess.run([sys.executable, str(HOOKS / "ah_reap.py"), "scan", "--json"], capture_output=True,
                              text=True)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(json.loads(done.stdout)["work_root"], str(self.work))


class Checkout(Case):
    def co(self, *args, session=SESSION):
        self.assert_temporary_home()
        out, err = io.StringIO(), io.StringIO()
        env = {"AH_SESSION": session} if session else {}
        with mock.patch.dict(os.environ, env), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = ah_reap.co_main([str(arg) for arg in args])
        return code, out.getvalue().strip(), err.getvalue()

    def test_a_checkout_in_the_session_folder_with_the_real_origin_and_no_dependence(self):
        remote = self.seeded_remote("proj")
        seed = self.root / "seed-proj"
        self.git(seed, "checkout", "-q", "-b", "feature")
        feature = self.commit(seed, "feature.txt")
        self.git(seed, "push", "-q", str(remote), "feature", "feature:refs/pull/7/head")
        code, path, err = self.co("acme/proj")
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(path, str(self.folder() / "co" / "proj"))
        self.assertEqual(self.git(path, "config", "remote.origin.url"), "https://github.com/acme/proj.git")
        self.assertFalse(os.path.exists(os.path.join(path, ".git", "objects", "info", "alternates")))
        mirror = self.home / ".agent-harness" / "cache" / "git" / "acme" / "proj.git"
        self.assertEqual(self.git(mirror, "rev-parse", "--is-bare-repository"), "true")
        self.assertNotIn("refs/pull/", self.git(mirror, "for-each-ref"))   # branches and tags only
        facts = git_save.facts(path)
        self.assertEqual((facts["real_remote"], facts["alternates"], facts["branch"], facts["errors"]),
                         ("https://github.com/acme/proj.git", [], "main", []))
        os.rename(mirror, self.root / "mirror-moved")   # the checkout does not need the mirror afterwards
        self.assertEqual(self.git(path, "fsck", "--connectivity-only"), "")
        os.rename(self.root / "mirror-moved", mirror)
        later = self.commit(seed, "later.txt")
        self.git(seed, "push", "-q", str(remote), "feature")
        code, second, err = self.co("https://fixture.invalid/proj.git", "--ref", "feature", "--name", "second")
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(second, str(self.folder() / "co" / "second"))
        self.assertEqual((self.git(second, "rev-parse", "HEAD"), self.git(second, "symbolic-ref", "--short", "HEAD")),
                         (later, "feature"))
        code, third, err = self.co("acme/proj", "--ref", "refs/pull/7/head", "--name", "pr7")
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(self.git(third, "rev-parse", "HEAD"), feature)
        code, fourth, err = self.co("acme/proj", "--ref", feature, "--name", "by-id")
        self.assertEqual((code, self.git(fourth, "rev-parse", "HEAD")), (0, feature))
        code, _path, err = self.co("acme/proj", "--ref", "no-such-ref", "--name", "fifth")
        self.assertEqual(code, 1)
        self.assertIn("is on its default branch", err)

    def test_what_it_refuses(self):
        self.seeded_remote("proj")
        local = self.repo(self.root / "local")
        self.assertEqual(self.co("acme/proj", session=None)[0], 3)       # no session, so no owner for the checkout
        for args in ([str(local)], ["file://%s" % local], ["acme/proj", "--name", "../up"],
                     ["acme/proj", "--name", "."], ["acme/proj", "--ref=--upload-pack=x"], ["--upload-pack=x"], []):
            with self.subTest(args):
                self.assertEqual(self.co(*args)[0], 3)
        self.assertEqual(self.co("acme/proj")[0], 0)
        code, _path, err = self.co("acme/proj")
        self.assertEqual(code, 3)
        self.assertIn("already exists", err)
        code, _path, err = self.co("acme/missing")
        self.assertEqual(code, 1)
        self.assertTrue(err)
        self.assertEqual(sorted(p.name for p in (self.folder() / "co").iterdir()), ["proj"])


class ReviewFixes(Case):
    """Each test here failed before the fix it is named for (reviews rt2-data-loss and rt2-friction-security)."""

    def temp(self, session=SESSION):
        import session_env  # noqa: PLC0415
        return Path(os.path.realpath(session_env.make_tmp(self.folder(session).name)))

    def everything(self):
        """Every object the rescue remote holds, as one blob of bytes."""
        return subprocess.run(["git", "-C", str(self.rescue), "cat-file", "--batch-all-objects", "--batch"],
                              capture_output=True, check=True).stdout

    def test_checkouts_and_keep_in_the_session_temp_directory_are_saved_or_kept_first(self):
        folder, temp = self.folder(), self.temp()
        main = self.repo(folder / "co" / "app")
        self.git(main, "worktree", "add", "-q", "-b", "fix-tmp", str(temp / "wt"))
        (temp / "wt" / "README.md").write_text("UNCOMMITTED WORKTREE EDIT\n")
        self.git(main, "worktree", "add", "-q", "--detach", str(temp / "detached"))
        detached = self.commit(temp / "detached", "d.txt", "DETACHED COMMIT\n")
        clone = self.repo(temp / "clone", origin=main)
        unpushed = self.commit(clone, "c.txt", "UNPUSHED IN TMP CLONE\n")
        (temp / "keep").mkdir()
        (temp / "keep" / "results.json").write_text("{}\n")
        (temp / "scratch.txt").write_text("disposable\n")
        code, out = self.apply()
        self.assertEqual(code, 0, out)
        objects = self.everything()
        for text in (b"UNCOMMITTED WORKTREE EDIT", b"DETACHED COMMIT", b"UNPUSHED IN TMP CLONE"):
            self.assertIn(text, objects)
        commits = set(self.refs().values())
        self.assertTrue({detached, unpushed} <= commits, out)
        self.assertEqual((temp / "keep" / "results.json").read_text(), "{}\n")
        self.assertFalse((temp / "scratch.txt").exists())
        removed = self.removed()
        self.assertLess(removed.index(str(temp / "wt")), removed.index(str(main)))   # a worktree before its repository
        self.assertIn(str(temp / "clone"), removed)

    def test_a_kept_checkout_in_the_temp_directory_keeps_its_main_repository_and_itself(self):
        folder, temp = self.folder(), self.temp()
        main = self.repo(folder / "co" / "app")
        self.git(main, "worktree", "add", "-q", "-b", "side", str(temp / "wt"))
        (temp / "wt" / "keep").mkdir()   # a checkout that holds a keep/ is kept whole
        (temp / "wt" / "keep" / "paid.json").write_text("{}\n")
        code, out = self.apply()
        self.assertEqual(code, 0, out)
        self.assertTrue((temp / "wt" / "keep" / "paid.json").exists())
        self.assertTrue(main.is_dir(), out)

    def test_a_temp_directory_of_no_folder_that_holds_a_checkout_is_left(self):
        orphan = self.home / ".agent-harness" / "tmp" / "deadbeef"
        repo = self.repo(orphan / "clone")
        self.commit(repo, "x.txt", "only here\n")
        self.age(orphan, 100)
        code, out = self.apply()
        self.assertEqual(code, 0, out)
        self.assertIn("holds the git checkout %s" % repo, out)
        self.assertTrue((repo / "x.txt").exists())

    def test_a_deletion_that_stops_part_way_never_lets_a_later_save_replace_the_proof(self):
        folder = self.folder()
        repo = self.repo(folder / "co" / "app")
        (repo / "README.md").write_text("UNCOMMITTED EDIT THAT EXISTS NOWHERE ELSE\n")
        real = ah_reap._remove

        def stops_part_way(path):
            if path == str(repo):
                os.unlink(os.path.join(path, "README.md"))
                raise PermissionError(1, "Operation not permitted", path)
            return real(path)

        with mock.patch.object(ah_reap, "_remove", side_effect=stops_part_way):
            code, out = self.apply()
        self.assertEqual(code, 1, out)
        before = self.refs()
        self.assertTrue((repo / ".git" / git_save.REAPING).exists())
        self.age(folder, 100)
        code, out = self.apply()   # another idle period, a real deletion this time
        self.assertIn("stopped part way", out)
        self.assertTrue(repo.is_dir())
        self.assertEqual(self.refs(), before)
        self.assertIn(b"UNCOMMITTED EDIT THAT EXISTS NOWHERE ELSE", self.everything())
        import autosave  # noqa: PLC0415  and the save at a turn end does not save over it either
        self.assertIn("stopped part way", autosave.run(SESSION))
        self.assertEqual(self.refs(), before)

    def test_the_autosave_lock_is_held_while_a_folder_is_reduced(self):
        import fcntl  # noqa: PLC0415
        import session_env  # noqa: PLC0415
        folder = self.folder()
        repo = self.repo(folder / "co" / "app")
        lock_path = str(session_env.state_file(folder.name)) + ".lock"
        os.makedirs(os.path.dirname(lock_path), exist_ok=True)
        with open(lock_path, "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)   # autosave is saving right now
            code, out = self.apply()
        self.assertEqual(code, 0, out)
        self.assertIn("autosave is saving it right now", out)
        self.assertTrue(repo.is_dir())
        seen = []
        real = git_save.save

        def save_and_probe(*args, **kw):
            with open(lock_path, "a") as probe:   # while the reaper saves, autosave cannot get in
                try:
                    fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    seen.append("free")
                except OSError:
                    seen.append("held")
            return real(*args, **kw)

        with mock.patch.object(git_save, "save", side_effect=save_and_probe):
            code, out = self.apply()
        self.assertEqual((code, seen), (0, ["held"]), out)
        self.assertFalse(repo.exists())

    def test_one_run_at_a_time(self):
        import fcntl  # noqa: PLC0415
        lock_path = self.home / ".agent-harness" / "state" / "reap.lock"
        lock_path.parent.mkdir(parents=True)
        with open(lock_path, "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            code, out = self.apply()
        self.assertEqual(code, 3, out)
        self.assertIn("another `ah reap run --apply` is running", out)
        self.assertEqual(self.reap("run")[0], 0)   # a dry run takes no lock

    def test_a_file_moved_in_after_the_save_keeps_the_checkout(self):
        folder = self.folder()
        repo = self.repo(folder / "co" / "app")
        real = git_save.save

        def save_then_move_in(*args, **kw):
            result = real(*args, **kw)
            moved = self.root / "made-elsewhere.txt"
            moved.write_text("MOVED IN AFTER THE SAVE\n")
            old = time.time() - 5 * 86400
            os.utime(moved, (old, old))
            os.rename(moved, repo / "moved.txt")   # keeps its five-day-old mtime
            return result

        with mock.patch.object(git_save, "save", side_effect=save_then_move_in):
            code, out = self.apply()
        self.assertEqual(code, 0, out)
        self.assertIn("it changed after its save", out)
        self.assertTrue((repo / "moved.txt").exists())
        self.assertFalse((repo / ".git" / git_save.REAPING).exists())

    def test_a_mount_point_keeps_the_folder_and_is_never_crossed(self):
        folder, temp = self.folder(), self.temp()
        share = temp / "tmp.M0unt" / "share"
        share.mkdir(parents=True)
        (share / "remote-file.txt").write_text("on another machine\n")
        (folder / "node_modules").mkdir()
        real = ah_reap._dev
        with mock.patch.object(ah_reap, "_dev", side_effect=lambda path: real(path) + (
                1 if str(path).startswith(str(share)) else 0)):
            code, out = self.apply()
            self.assertIn("a mount point inside: %s" % share, out)
            self.assertTrue((share / "remote-file.txt").exists())
            self.assertTrue((folder / "node_modules").is_dir())
            with self.assertRaisesRegex(OSError, "another file system"):
                ah_reap._remove(str(temp / "tmp.M0unt"))
        self.assertTrue((share / "remote-file.txt").exists())

    def test_a_checkout_inside_or_named_like_a_rebuildable_directory_is_saved_before_it_goes(self):
        folder = self.folder()
        app = self.repo(folder / "co" / "app")
        lib = self.repo(app / ".venv" / "src" / "lib")   # where `pip install -e git+URL` clones
        patched = self.commit(lib, "f.txt", "PATCHED DEPENDENCY\n")
        venv = self.repo(folder / "co" / "venv")         # a checkout that happens to be called venv
        only = self.commit(venv, "v.txt", "ONLY COMMIT\n")
        (app / ".gitignore").write_text("build/\n.venv/\n")
        fmt = self.repo(app / "build" / "_deps" / "fmt-src")
        later = self.commit(fmt, "p.txt", "PATCH 2\n")
        (app / "node_modules" / "x").mkdir(parents=True)  # plain rebuildable output still goes
        code, out = self.apply()
        self.assertEqual(code, 0, out)
        commits = set(self.refs().values())
        self.assertTrue({patched, only, later} <= commits, out)
        self.assertFalse((folder / "co").exists() and any((folder / "co").iterdir()), out)
        self.assertIn(str(app / "node_modules"), self.removed("rebuildable"))
        self.assertNotIn(str(app / ".venv"), self.removed("rebuildable"))


class LifeVerifyFixes(Case):
    """Each test here failed before the fix it is named for (verifier run lifeverify-328a, problems F1 to F4)."""

    def temp(self, session=SESSION):
        import session_env  # noqa: PLC0415
        return Path(os.path.realpath(session_env.make_tmp(self.folder(session).name)))

    def state_file(self, repo):
        return self.home / ".agent-harness" / "state" / "git-save" / (
            hashlib.sha256(os.fsencode(str(repo))).hexdigest() + ".json")

    def held(self):
        base = self.home / ".agent-harness" / "rescue" / "held"
        return sorted(path.read_text() for path in base.rglob(".env")) if base.is_dir() else []

    def bare_with(self, path, text, branch="only-here"):
        """A bare repository at `path` that holds the only copy of one commit."""
        path.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "init", "-q", "--bare", str(path)], check=True)
        work = self.repo(self.root / ("w-" + path.name))
        only = self.commit(work, "only.txt", text)
        self.git(work, "push", "-q", str(path), "HEAD:refs/heads/" + branch)
        return only

    def test_f1_a_deleted_checkout_takes_its_state_file_with_it_in_every_mode(self):
        import autosave  # noqa: PLC0415
        self.seeded_remote("app")
        for mode in ("--session", "--path"):
            with self.subTest(mode):
                if mode == "--session":
                    base = self.folder()
                else:
                    base = self.root / "loose-folder"
                    base.mkdir()
                repo = self.repo(base / "co" / "app", origin="https://fixture.invalid/app.git")
                (repo / ".env").write_text("DAY1_LOCAL=only-copy\n")
                if mode == "--session":
                    self.assertEqual(autosave.run(SESSION), "")   # an ordinary turn end first
                    self.assertTrue(self.state_file(repo).is_file())
                code, out = self.apply(mode, SESSION if mode == "--session" else base)
                self.assertEqual(code, 0, out)
                self.assertFalse(repo.exists(), out)
                self.assertFalse(self.state_file(repo).exists(), out)
                self.assertIn(str(self.state_file(repo)), self.removed("state"))
        self.repo(self.folder() / "co" / "app", origin="https://fixture.invalid/app.git")   # made again
        (self.folder() / "co" / "app" / ".env").write_text("DAY2_LOCAL=x\n")
        self.assertEqual(autosave.run(SESSION), "")
        self.assertIn("DAY1_LOCAL=only-copy\n", self.held())

    def test_f2_removing_the_mark_after_a_stopped_deletion_keeps_the_proven_copy(self):
        import autosave  # noqa: PLC0415
        for takes_the_mark in (False, True):
            with self.subTest(takes_the_mark=takes_the_mark):
                folder = self.folder()
                repo = self.repo(folder / "co" / ("app%d" % takes_the_mark))
                (repo / "README.md").write_text("UNCOMMITTED EDIT THAT EXISTS NOWHERE ELSE\n")
                real = ah_reap._remove

                def stops_part_way(path, repo=repo):
                    if path == str(repo):
                        os.unlink(os.path.join(path, "README.md"))
                        if takes_the_mark:   # the deletion got as far as the mark itself
                            os.unlink(os.path.join(path, ".git", git_save.REAPING))
                        raise PermissionError(1, "Operation not permitted", path)
                    return real(path)

                with mock.patch.object(ah_reap, "_remove", side_effect=stops_part_way):
                    code, out = self.apply()
                self.assertEqual(code, 1, out)
                proven = self.refs()
                mark = repo / ".git" / git_save.REAPING
                if not takes_the_mark:
                    message = autosave.run(SESSION)
                    self.assertIn("stays untouched", message)
                    mark.unlink()   # what the message allows
                self.assertEqual(autosave.run(SESSION), "")
                now = self.refs()
                for ref, commit in proven.items():
                    self.assertEqual(now.get(ref), commit, ref)
                self.assertGreater(len(now), len(proven))   # a fresh copy beside the proven one
                self.assertEqual(self.apply()[0], 0)
                for ref, commit in proven.items():
                    self.assertEqual(self.refs().get(ref), commit, ref)

    def test_f3_bare_repositories_are_saved_fresh_before_they_go_and_kept_when_that_fails(self):
        folder, temp = self.folder(), self.temp()
        in_tmp = temp / "tmp.Bb77Rr" / "scratch-remote.git"
        in_folder = folder / "remote.git"
        only_tmp = self.bare_with(in_tmp, "ONLY IN THE BARE REPO IN TMPDIR\n")
        only_folder = self.bare_with(in_folder, "ONLY IN THE BARE REPO IN THE FOLDER\n")
        unsaved = temp / "tmp.Cc88Ss" / "lfs-remote.git"
        self.bare_with(unsaved, "IN A BARE REPO THAT USES LFS\n")
        (unsaved / "lfs" / "objects").mkdir(parents=True)   # its save is never ok
        code, out = self.apply()
        self.assertEqual(code, 0, out)
        commits = set(self.refs().values())
        self.assertTrue({only_tmp, only_folder} <= commits, out)
        self.assertIn(str(in_tmp), self.removed())
        self.assertFalse(in_tmp.exists())
        self.assertFalse(in_folder.exists())
        self.assertTrue((unsaved / "HEAD").is_file(), out)
        self.assertIn("git-lfs", out)

    def test_f3_a_temp_directory_of_no_folder_that_holds_a_bare_repository_is_left(self):
        orphan = self.home / ".agent-harness" / "tmp" / "abcdef01"
        bare = orphan / "remote.git"
        self.bare_with(bare, "ONLY IN THE ORPHAN TMP BARE REPO\n")
        self.age(orphan, 100)
        code, out = self.apply()
        self.assertEqual(code, 0, out)
        self.assertIn("holds the git checkout %s" % bare, out)
        self.assertTrue((bare / "HEAD").is_file())

    def test_f4_scan_and_run_never_run_a_submodule_own_filter_program(self):
        marker = self.root / "filter-ran"
        lib = self.repo(self.root / "lib-src")
        self.commit(lib, ".gitattributes", "* filter=x\n")
        top = self.repo(self.folder() / "dl" / "super")
        self.git(top, "-c", "protocol.file.allow=always", "submodule", "add", "-q", str(lib), "lib")
        self.git(top, "commit", "-q", "-m", "add lib")
        subgit = top / ".git" / "modules" / "lib"
        for key, value in (("filter.x.clean", "touch '%s'; cat" % marker), ("filter.x.smudge", "cat")):
            subprocess.run(["git", "--git-dir", str(subgit), "config", key, value], check=True)
        (top / "lib" / "README.md").write_text("edited inside the submodule\n")
        os.utime(top / "lib" / "README.md", (1, 1))
        code, out = self.reap("scan")
        self.assertEqual(code, 0, out)
        self.assertFalse(marker.exists(), out)
        code, out = self.reap("run")
        self.assertFalse(marker.exists(), out)


if __name__ == "__main__":
    unittest.main()
