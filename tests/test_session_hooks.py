"""session_env.py (SessionStart) and autosave.py (Stop, SubagentStop, SessionEnd), and how they are wired.

Every test runs under a temporary HOME with real git repositories in a temporary directory; a bare repository named
as `rescue_remote` through AH_LOCAL_CONFIG stands in for the remote. The hook processes get an environment without
any CLAUDE*, CODEX_*, AH_* or GIT_* variable of the session that runs the tests, so they can never write to a real
env file or a real ~/.agent-harness. No test reaches a real host: http goes to a closed local port, ssh is `false`.
"""
import fcntl
import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
HOOKS = ROOT / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
sys.path.insert(0, str(ROOT))
import ah_local  # noqa: E402
import autosave  # noqa: E402
import git_save  # noqa: E402
import session_env  # noqa: E402

SESSION = "0f8fad5b-d9cb-469f-a165-70867728950e"
OTHER = "99999999-8888-7777-6666-555555555555"
GB = 1024 ** 3


class Case(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.addCleanup(self.make_writable)
        self.root = Path(os.path.realpath(temp.name))
        self.home, self.remotes, fake_bin = self.root / "home", self.root / "remotes", self.root / "bin"
        for folder in (self.home, self.remotes, fake_bin, self.root / "tmp"):
            folder.mkdir()
        (fake_bin / "gh").write_text("#!/bin/sh\nexit 1\n")   # never a real gh call
        (fake_bin / "gh").chmod(0o755)
        (self.home / ".gitconfig").write_text(
            "[user]\n\tname = Test\n\temail = test@fixture.invalid\n[init]\n\tdefaultBranch = main\n"
            "[http]\n\tproxy = http://127.0.0.1:9\n[core]\n\tsshCommand = false\n")
        self.config_path = self.home / "local.json"
        self.work = self.home / ".agent-harness" / "work" / SESSION
        self.env_file = self.root / "claude-env.sh"
        kept = {k: v for k, v in os.environ.items() if not k.startswith(("CLAUDE", "CODEX_", "AH_", "GIT_", "XDG_"))}
        self.env = dict(kept, HOME=str(self.home), AH_LOCAL_CONFIG=str(self.config_path), GIT_CONFIG_NOSYSTEM="1",
                        GIT_CONFIG_GLOBAL=str(self.home / ".gitconfig"), TMPDIR=str(self.root / "tmp"),
                        GIT_CEILING_DIRECTORIES=str(self.root),
                        PATH="%s%s%s" % (fake_bin, os.pathsep, os.environ.get("PATH", "")))
        patcher = mock.patch.dict(os.environ, self.env, clear=True)   # in-process calls see the same environment
        patcher.start()
        self.addCleanup(patcher.stop)
        tempfile.tempdir = None
        self.addCleanup(setattr, tempfile, "tempdir", None)
        self.addCleanup(ah_local.reset)
        git_save._HOOKS_OFF.clear()
        self.rescue = self.remotes / "rescue.git"
        subprocess.run(["git", "init", "-q", "--bare", str(self.rescue)], check=True)
        self.configure(rescue_remote=str(self.rescue))

    def make_writable(self):
        for folder, _dirs, _files in os.walk(self.root):
            os.chmod(folder, 0o700)

    def configure(self, **keys):
        self.config_path.write_text(json.dumps(keys))
        ah_local.reset()

    def hook(self, script, payload, **env):
        """Run one hook as Claude Code does: JSON on stdin. Returns the finished process."""
        data = payload if isinstance(payload, (str, bytes)) else json.dumps(payload)
        return subprocess.run([sys.executable, str(HOOKS / script)], input=data, capture_output=True, timeout=120,
                              text=not isinstance(data, bytes), env=dict(self.env, **env))

    def start(self, session=SESSION, env_file=True, **env):
        if env_file:
            env.setdefault("CLAUDE_ENV_FILE", str(self.env_file))
        return self.hook("session_env.py", {"hook_event_name": "SessionStart", "session_id": session,
                                            "source": "startup"}, **env)

    def stop(self, event="Stop", session=SESSION, **env):
        return self.hook("autosave.py", {"hook_event_name": event, "session_id": session}, **env)

    @staticmethod
    def context(done):
        return json.loads(done.stdout)["hookSpecificOutput"]["additionalContext"] if done.stdout.strip() else ""

    def git(self, repo, *args):
        done = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, "git %s: %s" % (" ".join(args), done.stderr))
        return done.stdout.strip()

    def checkout(self, rel="co/app"):
        """A checkout with one commit and no remote, inside the session folder."""
        path = self.work / rel
        path.mkdir(parents=True)
        self.git(path, "init", "-q")
        (path / "README.md").write_text("hello\n")
        self.git(path, "add", "README.md")
        self.git(path, "commit", "-q", "-m", "first")
        return path

    def rescued(self):
        """{ref name: commit id} of everything in the stand-in rescue remote."""
        out = self.git(self.rescue, "for-each-ref", "--format=%(refname) %(objectname)", "refs/")
        return dict(line.split(" ") for line in out.splitlines())

    def state(self):
        return json.loads(session_env.state_file(SESSION).read_text())


class SessionStart(Case):
    def test_makes_the_folder_and_adds_the_env_file_lines(self):
        done = self.start()
        self.assertEqual((done.returncode, done.stderr), (0, ""))
        self.assertEqual(stat.S_IMODE(self.work.stat().st_mode), 0o700)
        self.assertTrue((self.work / ".agent-harness-session.json").is_file())
        tmp = self.home / ".agent-harness" / "tmp" / SESSION[:8]
        self.assertEqual(self.env_file.read_text().splitlines(),
                         ["export AH_SESSION=%s" % SESSION, "export AH_WORK=%s" % self.work, "export TMPDIR=%s" % tmp])
        self.assertEqual(stat.S_IMODE(tmp.stat().st_mode), 0o700)
        self.assertLess(len(str(session_env.tmp_dir(SESSION)).replace(str(self.home), "/Users/somebody")), 60,
                        "the temp path must stay short: a unix socket path holds about 104 characters")

    def test_a_shell_that_reads_the_env_file_gets_the_exact_values(self):
        odd = "a b'c;$(touch %s)" % (self.root / "ran")
        self.assertEqual(self.start(session=odd).returncode, 0)
        shown = subprocess.run(["sh", "-c", '. "$1"; printf "%s\\n%s" "$AH_SESSION" "$AH_WORK"', "sh", str(self.env_file)],
                               capture_output=True, text=True, env=self.env).stdout.split("\n")
        self.assertEqual(shown[0], odd)
        self.assertTrue(Path(shown[1]).is_dir())
        self.assertEqual(Path(shown[1]).parent, self.work.parent)
        self.assertFalse((self.root / "ran").exists(), "a session id is data, never run")

    def test_a_second_start_adds_no_line_twice_and_keeps_what_was_there(self):
        self.env_file.write_text("export KEEP=1")   # no newline at the end
        self.start()
        self.start()
        lines = self.env_file.read_text().splitlines()
        self.assertEqual(lines[0], "export KEEP=1")
        self.assertEqual(len(lines), 4)

    def test_session_tmpdir_false_leaves_tmpdir_alone(self):
        self.configure(session_tmpdir=False)
        self.start()
        self.assertEqual([line.split("=")[0] for line in self.env_file.read_text().splitlines()],
                         ["export AH_SESSION", "export AH_WORK"])
        self.assertFalse((self.home / ".agent-harness" / "tmp").exists())

    def test_a_session_id_that_is_not_a_uuid_gets_a_temp_directory_of_its_own(self):
        done = self.start(session="codex-run-7")
        self.assertEqual(done.returncode, 0, done.stderr)
        tmp = self.home / ".agent-harness" / "tmp" / hashlib.sha256(b"codex-run-7").hexdigest()[:8]
        self.assertIn("export TMPDIR=%s" % tmp, self.env_file.read_text().splitlines())
        self.assertEqual(stat.S_IMODE(tmp.stat().st_mode), 0o700)

    def test_a_temp_path_that_is_a_symlink_is_never_exported(self):
        (self.home / ".agent-harness" / "tmp").mkdir(parents=True)
        (self.home / ".agent-harness" / "tmp" / SESSION[:8]).symlink_to(self.root / "tmp")
        done = self.start()
        self.assertEqual(done.returncode, 0)
        self.assertEqual(len(self.env_file.read_text().splitlines()), 2)
        self.assertIn("($AH_WORK)", self.context(done))

    def test_one_line_of_context_under_400_characters(self):
        text = self.context(self.start())
        self.assertNotIn("\n", text)
        self.assertLess(len(text), 400)
        for part in ("Session folder: ", SESSION, "($AH_WORK)", "not in the home folder or /tmp", "may be removed by ah reap",
                     "unpushed work is saved first", "keep/", " co <owner/repo>."):
            self.assertIn(part, text)

    def test_the_line_gives_full_paths_when_they_fit_and_home_relative_ones_when_not(self):
        short = session_env.context("/Users/sam/.agent-harness/work/" + SESSION, "/Users/sam/.claude/hooks/ah.py",
                                    "/Users/sam", True)
        self.assertIn("Session folder: /Users/sam/.agent-harness/work/%s ($AH_WORK)." % SESSION, short)
        self.assertIn("python3 /Users/sam/.claude/hooks/ah.py co <owner/repo>.", short)
        self.assertLess(len(short), 400)
        home = "/Volumes/" + "x" * 150
        long = session_env.context(home + "/.agent-harness/work/" + SESSION, home + "/.claude/hooks/ah.py", home)
        self.assertIn("Session folder: ~/.agent-harness/work/%s." % SESSION, long)
        self.assertIn("python3 ~/.claude/hooks/ah.py co", long)
        self.assertLess(len(long), 400)
        odd = session_env.context(home + "/.agent-harness/work/" + SESSION, "/opt/" + "z" * 200 + "/ah.py", home)
        self.assertIn("For a checkout: ah co <owner/repo>.", odd)   # an install outside the home folder: plain `ah`
        self.assertLess(len(odd), 400)
        self.assertLess(len(session_env.context("/" + "y" * 900, "/z/ah.py", "/home/sam")), 400)

    def test_without_an_env_file_there_is_a_folder_and_a_line_and_nothing_else(self):
        done = self.start(env_file=False)   # Codex has no CLAUDE_ENV_FILE
        self.assertEqual((done.returncode, done.stderr), (0, ""))
        self.assertTrue(self.work.is_dir())
        self.assertFalse(self.env_file.exists())
        self.assertFalse((self.home / ".agent-harness" / "tmp").exists())
        self.assertNotIn("$AH_WORK", self.context(done))
        self.assertIn(" co <owner/repo>.", self.context(done))
        # `ah co` needs the session, and this shell was given no AH_SESSION: the command carries it
        self.assertRegex(self.context(done), r"For a checkout: AH_SESSION=%s (python3 \S+/)?ah(\.py)? co <" % SESSION)
        self.assertLess(len(self.context(done)), 400)
        self.assertNotIn("AH_SESSION", self.context(self.start()))   # exported through the env file instead

    def write_size(self, size, complete=True):
        path = session_env.state_file(SESSION)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"bytes": size, "complete": complete, "top": [
            ["co", 6 * GB], ["data", 4 * GB], ["temp files (/t/0f8fad5b)", 2 * GB], ["small", 1]]}))

    def test_over_the_quota_adds_one_line_naming_the_three_largest_directories(self):
        self.write_size(12 * GB)
        lines = self.context(self.start()).split("\n")
        self.assertEqual(len(lines), 2)
        self.assertLess(len(lines[0]), 400)
        self.assertIn("holds 12.0 GB, over the limit of 10 GB", lines[1])
        self.assertIn("Largest: co 6.0 GB, data 4.0 GB, temp files (/t/0f8fad5b) 2.0 GB.", lines[1])
        self.assertNotIn("small", lines[1])
        self.write_size(12 * GB, complete=False)
        self.assertIn("holds at least 12.0 GB", self.context(self.start()))

    def test_the_quota_is_a_local_json_key_and_under_it_nothing_is_added(self):
        self.write_size(12 * GB)
        self.configure(session_quota_gb=20)
        self.assertNotIn("\n", self.context(self.start()))
        self.configure(session_quota_gb=1.5)
        self.assertIn("over the limit of 1.5 GB", self.context(self.start()))
        self.configure(session_quota_gb="lots")   # a wrong type is the default, 10
        self.write_size(9 * GB)
        self.assertNotIn("\n", self.context(self.start()))
        for junk in ("{not json", json.dumps([1]), json.dumps({"bytes": "big"}), json.dumps({"bytes": True})):
            session_env.state_file(SESSION).write_text(junk)
            done = self.start()
            self.assertEqual((done.returncode, self.context(done).count("\n")), (0, 0), junk)

    def test_every_failure_is_exit_0(self):
        for payload in ("", "{not json", "[]", json.dumps({"session_id": 7}), json.dumps({"session_id": " "}),
                        json.dumps({"hook_event_name": "SessionStart"}), b"\xff\xfe" + b"x" * 300000):
            done = self.hook("session_env.py", payload, CLAUDE_ENV_FILE=str(self.env_file))
            self.assertEqual((done.returncode, done.stdout), (0, b"" if isinstance(payload, bytes) else ""), payload[:20])
        self.assertFalse(self.env_file.exists())
        blocked = self.root / "not-a-home"
        blocked.write_text("a file where the home folder should be\n")
        done = self.start(HOME=str(blocked))
        self.assertEqual((done.returncode, done.stdout), (0, ""))
        self.assertIn("session_env: skipped", done.stderr)
        done = self.start(CLAUDE_ENV_FILE=str(self.root / "missing" / "dir" / "env"))
        self.assertEqual(done.returncode, 0)
        self.assertIn("Session folder: ", self.context(done))
        self.assertNotIn("$AH_WORK", self.context(done))


class Save(Case):
    def test_unpushed_commits_and_changes_are_saved_and_nothing_is_printed(self):
        repo = self.checkout()
        (repo / "notes.txt").write_text("not committed\n")
        (repo / ".env").write_text("TOKEN=not-a-real-one\n")
        for event in ("Stop", "SubagentStop", "SessionEnd"):
            done = self.stop(event)
            self.assertEqual((done.returncode, done.stdout, done.stderr), (0, "", ""), event)
        refs = self.rescued()
        head = self.git(repo, "rev-parse", "HEAD")
        branch = [ref for ref in refs if ref.endswith("/heads/main")]
        snapshot = [ref for ref in refs if ref.endswith("/snapshot")]
        self.assertEqual((len(branch), len(snapshot)), (1, 1), refs)
        self.assertIn("/%s/co-app-" % SESSION, branch[0])
        self.assertEqual(refs[branch[0]], head)
        files = self.git(self.rescue, "ls-tree", "-r", "--name-only", refs[snapshot[0]]).splitlines()
        self.assertEqual(files, ["README.md", "notes.txt"], "the secret-shaped file never leaves the machine")
        self.assertEqual(self.git(repo, "status", "--porcelain"), "?? .env\n?? notes.txt", "the checkout is as it was")
        self.assertEqual(self.state()["unsaved"], [])

    def test_a_missing_session_temp_directory_is_made_again_at_the_end_of_a_turn(self):
        self.start()
        tmp = self.home / ".agent-harness" / "tmp" / SESSION[:8]
        tmp.rmdir()   # as if something removed it while the session was still alive
        done = self.stop()
        self.assertEqual((done.returncode, done.stdout, done.stderr), (0, "", ""))
        self.assertEqual(stat.S_IMODE(tmp.stat().st_mode), 0o700)
        self.configure(rescue_remote=str(self.rescue), session_tmpdir=False)   # session_env would not make it
        tmp.rmdir()
        self.assertEqual(self.stop().returncode, 0)
        self.assertFalse(tmp.exists())

    def test_an_unchanged_checkout_costs_no_network_call(self):
        self.checkout()
        self.assertEqual(self.stop().stderr, "")
        self.rescue.rename(self.remotes / "gone.git")   # any push or ls-remote would now fail and fall back to a bundle
        done = self.stop()
        self.assertEqual((done.returncode, done.stdout, done.stderr), (0, "", ""))
        self.assertEqual(list((self.home / ".agent-harness").rglob("*.bundle")), [])

    def test_a_failed_save_is_one_line_on_stderr_and_exit_0(self):
        good = self.checkout("co/good")
        (self.work / "co" / "broken" / ".git").mkdir(parents=True)   # looks like a checkout, is not one
        done = self.stop()
        self.assertEqual((done.returncode, done.stdout), (0, ""))
        self.assertEqual(len(done.stderr.splitlines()), 1)
        self.assertIn("1 of 2 checkouts not saved (co/broken: ", done.stderr)
        self.assertIn("Nothing was deleted.", done.stderr)
        self.assertTrue((self.work / "co" / "broken" / ".git").is_dir())
        self.assertIn(self.git(good, "rev-parse", "HEAD"), self.rescued().values())
        self.assertEqual([row["path"] for row in self.state()["unsaved"]], ["co/broken"])

    def test_git_missing_or_state_unwritable_still_exits_0(self):
        self.checkout()
        done = self.stop(PATH=str(self.root / "bin"))   # no git on PATH
        self.assertEqual((done.returncode, done.stdout), (0, ""))
        self.assertIn("1 of 1 checkouts not saved", done.stderr)
        state = self.home / ".agent-harness" / "state" / "git-save"
        os.chmod(state, 0o500)
        done = self.stop()
        self.assertEqual((done.returncode, done.stdout), (0, ""))
        self.assertEqual(len(done.stderr.splitlines()), 1)
        self.assertIn("autosave: skipped", done.stderr)

    def test_bad_input_no_folder_or_a_symlinked_folder_is_silence(self):
        for payload in ("", "{not json", "[]", json.dumps({"session_id": None}), b"\xff" * 300000):
            done = self.hook("autosave.py", payload)
            self.assertEqual(done.returncode, 0, payload[:20])
            self.assertFalse(done.stdout)
        done = self.stop()   # the session never made a folder
        self.assertEqual((done.returncode, done.stdout, done.stderr), (0, "", ""))
        self.assertFalse(self.work.exists())
        repo = self.checkout()   # in SESSION's folder; OTHER's folder is a symlink to it
        (self.work.parent / OTHER).symlink_to(self.work)
        done = self.stop(session=OTHER)
        self.assertEqual((done.returncode, done.stdout, done.stderr), (0, "", ""))
        self.assertEqual(self.rescued(), {}, "a symlinked session folder is not followed: %s" % repo)

    def test_a_run_in_progress_makes_the_next_one_step_aside(self):
        self.checkout()
        lock = Path(str(session_env.state_file(SESSION)) + ".lock")
        lock.parent.mkdir(parents=True)
        with open(lock, "a") as handle:
            fcntl.flock(handle, fcntl.LOCK_EX)
            done = self.stop()
        self.assertEqual((done.returncode, done.stdout, done.stderr), (0, "", ""))
        self.assertEqual(self.rescued(), {})

    def test_finds_nested_checkouts_worktrees_and_bare_repositories_children_first(self):
        app = self.checkout("co/app")
        inner = self.checkout("co/app/vendor/lib")
        self.git(app, "worktree", "add", "-q", str(self.work / "wt"), "-b", "side")
        subprocess.run(["git", "init", "-q", "--bare", str(self.work / "mirror.git")], check=True)
        self.checkout("co/app/node_modules/dep")          # rebuildable output is not searched
        outside = self.root / "outside"
        outside.mkdir()
        self.git(outside, "init", "-q")
        (self.work / "link").symlink_to(outside)          # a symlink is not followed
        found, more = autosave.checkouts(self.work)
        self.assertFalse(more)
        self.assertEqual(found[0], str(inner))
        self.assertEqual(sorted(found), sorted(str(p) for p in (app, inner, self.work / "wt", self.work / "mirror.git")))
        self.assertLess(found.index(str(inner)), found.index(str(app)))

    def test_at_most_20_checkouts_in_one_run_and_it_says_so(self):
        for n in range(22):
            (self.work / ("r%02d" % n) / ".git").mkdir(parents=True)
        found, more = autosave.checkouts(self.work)
        self.assertEqual((len(found), more), (20, True))
        with mock.patch.object(autosave, "MAX_CHECKOUTS", 1):
            self.checkout("a")
            line = autosave.run(SESSION)
        self.assertIn("the search stopped at its limit, so other checkouts may not be saved", line)
        self.assertNotIn("\n", line)

    def test_when_the_budget_runs_out_the_rest_is_reported_not_guessed(self):
        self.checkout("a")
        self.checkout("b")
        with mock.patch.object(autosave, "BUDGET_S", 0):
            line = autosave.run(SESSION)
        self.assertIn("2 of 2 checkouts not saved (a: the 0 second budget ran out; b: ", line)
        self.assertEqual(self.rescued(), {})

    def test_the_size_is_recorded_and_the_next_session_start_reads_it(self):
        repo = self.checkout()
        (repo / "blob.bin").write_bytes(os.urandom(300 * 1024))
        (self.work / "data").mkdir()
        (self.work / "data" / "rows.csv").write_bytes(b"x" * 100 * 1024)
        (self.work / "loose.txt").write_text("a file directly in the folder\n")
        self.start()                                        # makes the session temp directory
        fixture = self.home / ".agent-harness" / "tmp" / SESSION[:8] / "fixture"
        fixture.mkdir()
        (fixture / "db.sqlite").write_bytes(b"y" * 200 * 1024)
        self.assertEqual(self.stop().stderr, "")
        state = self.state()
        self.assertTrue(state["complete"])
        self.assertGreater(state["bytes"], 500 * 1024)
        names = [name for name, _size in state["top"]]
        self.assertEqual(names[0], "co")
        self.assertEqual(sorted(names), sorted(["co", "data", "temp files (%s)" % fixture.parent]))
        self.assertGreaterEqual(state["bytes"], sum(size for _name, size in state["top"]))
        self.assertNotIn("\n", self.context(self.start()))   # far under the default 10 GB
        self.configure(rescue_remote=str(self.rescue), session_quota_gb=0.0001)
        second = self.context(self.start()).split("\n")[1]
        self.assertIn("over the limit of 0.0001 GB", second)
        self.assertIn("Largest: co ", second)
        self.assertIn("temp files (", second)

    def test_the_size_walk_runs_at_most_every_ten_minutes_and_keeps_to_its_time(self):
        self.checkout()
        self.stop()
        first = self.state()["sized_at"]
        self.stop()
        self.assertEqual(self.state()["sized_at"], first)
        with mock.patch.object(autosave, "SIZE_SECONDS", -1):   # no time at all: a lower bound, marked as one
            for n in range(600):
                (self.work / ("f%03d" % n)).write_text("x")
            got = autosave.measure(self.work, session_env.tmp_dir(SESSION))
        self.assertFalse(got["complete"])


class Wiring(Case):
    def scripts(self, groups):
        import install
        return [(Path(install.hook_argv(h)[0]).name, h) for g in groups for h in g["hooks"]]

    def test_claude_registers_the_start_hook_once_and_the_save_hook_on_three_events(self):
        import install
        claude = self.home / ".claude"
        managed = install.managed_hooks(claude)
        start = [h for name, h in self.scripts(managed["SessionStart"]) if name == "session_env.py"]
        self.assertEqual([h["timeout"] for h in start], [10])
        for event in ("Stop", "SubagentStop", "SessionEnd"):
            saves = [h for name, h in self.scripts(managed[event]) if name == "autosave.py"]
            self.assertEqual(len(saves), 1, event)
            # a turn never waits for the save: Stop and SubagentStop run it in the background ("async", Claude Code
            # 2.1.332 and later); SessionEnd stays synchronous. 30 seconds either way: the hook's own budget is 20
            expected = {"type": "command", "command": "python3", "timeout": 30}
            expected.update({} if event == "SessionEnd" else {"async": True})
            self.assertEqual({k: v for k, v in saves[0].items() if k != "args"}, expected, event)
            self.assertEqual(saves[0]["args"][:2], [str(claude / "hooks" / "ah_hook.py"), "autosave.py"])
            self.assertLess(autosave.BUDGET_S + autosave.SIZE_SECONDS, saves[0]["timeout"])
        once = install.merged_settings({}, claude)
        twice = install.merged_settings(once, claude)
        self.assertEqual(once, twice)
        self.assertEqual(sum(name == "autosave.py" for name, _h in self.scripts(twice["hooks"]["SessionEnd"])), 1)
        for name in ("git_save.py", "ah_reap.py", "session_env.py", "autosave.py"):
            self.assertIn(name, install.HOOKS)

    def test_codex_registers_both_last_and_a_second_install_changes_nothing(self):
        try:
            import install_codex
        except (ImportError, SyntaxError, TypeError) as error:   # needs Python 3.11 (tomllib)
            self.skipTest("install_codex not importable here: %s" % error)
        codex = self.home / ".codex"
        foreign = {"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "python3 /other/stop.py"}]}]}}
        once = install_codex.merge_hooks(foreign, codex)
        self.assertEqual(install_codex.command_argv(once["hooks"]["SessionStart"][-1]["hooks"][0]["command"]),
                         [str(codex / "agent-harness" / "session_env.py")])
        self.assertEqual(install_codex.command_argv(once["hooks"]["Stop"][-1]["hooks"][0]["command"]),
                         [str(codex / "agent-harness" / "autosave.py")])
        self.assertEqual(once["hooks"]["Stop"][-1]["hooks"][0]["timeout"], 30)
        self.assertEqual(once["hooks"]["Stop"][0], foreign["hooks"]["Stop"][0])
        self.assertEqual(install_codex.merge_hooks(once, codex), once)
        for event in ("PreToolUse", "UserPromptSubmit", "SubagentStart", "Interrupt"):
            self.assertFalse([g for g in once["hooks"].get(event, []) if "autosave.py" in json.dumps(g)
                              or "session_env.py" in json.dumps(g)], event)
        for name in ("git_save.py", "ah_reap.py", "session_env.py", "autosave.py", "workdir.py", "safe_input.py"):
            self.assertIn(name, install_codex.DELIVERY_HELPERS)

    def test_ah_reap_and_ah_co_go_to_the_reaper_module(self):
        import ah
        calls = []
        fake = types.ModuleType("ah_reap")
        fake.main = lambda argv: calls.append(("main", argv)) or 3
        fake.co_main = lambda argv: calls.append(("co_main", argv)) or 0
        with mock.patch.dict(sys.modules, {"ah_reap": fake}):
            self.assertEqual(ah.main(["reap", "run", "--if-above", "70"]), 3)
            self.assertEqual(ah.main(["co", "owner/repo", "--name", "x"]), 0)
        self.assertEqual(calls, [("main", ["run", "--if-above", "70"]), ("co_main", ["owner/repo", "--name", "x"])])

    def test_the_role_check_names_the_temp_directory_session_env_makes(self):
        import ah_roles
        import workdir
        tmp = self.home / ".agent-harness" / "tmp"
        for session in (SESSION, "ABCDEF12-0000-4000-8000-000000000000", "0f8fad5bcafe"):
            roots = ah_roles.own_roots({"session_id": session}, home=str(self.home))
            key = session_env.tmp_key(workdir.safe_name(session))
            self.assertIn(tmp / key, roots, session)
            if key != session[:8]:   # never another session's: 0f8fad5bcafe is not SESSION
                self.assertNotIn(tmp / session[:8], roots, session)

class ReviewFixes(Case):
    """Each test here failed before the fix it is named for (reviews rt2-data-loss and rt2-friction-security)."""

    def test_the_next_start_says_what_ah_reap_removed_and_what_could_not_be_saved(self):
        self.start()
        self.stop()   # a turn end: the state file records when
        log = self.home / ".agent-harness" / "logs" / "reap.jsonl"
        log.parent.mkdir(parents=True, exist_ok=True)
        later = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 5))
        rows = [{"time": later, "session": SESSION, "kind": "checkout", "action": "removed",
                 "path": os.path.realpath(str(self.work / "co" / "app")), "saved": {"where": "bundle"}},
                {"time": later, "session": OTHER, "kind": "checkout", "action": "removed", "path": "/x/other"},
                {"time": "2000-01-01T00:00:00Z", "session": SESSION, "kind": "checkout", "action": "removed",
                 "path": "/x/long-ago"}]
        log.write_text("".join(json.dumps(row) + "\n" for row in rows) + "not json\n")
        state = self.state()
        state["unsaved"] = [{"path": "co/cov", "reason": "more than 5000 ignored files to hold"}]
        session_env.state_file(SESSION).write_text(json.dumps(state))
        lines = self.context(self.start()).split("\n")
        self.assertEqual(len(lines), 2, lines)
        self.assertIn("ah reap removed 1 checkout(s) after saving them (co/app)", lines[1])
        self.assertIn("reap.jsonl", lines[1])
        self.assertIn("could not save 1 checkout(s) (co/cov: more than 5000 ignored files to hold)", lines[1])
        self.assertNotIn("other", lines[1])
        self.assertNotIn("long-ago", lines[1])

    def test_checkouts_in_the_session_temp_directory_are_saved_at_a_turn_end(self):
        self.start()
        tmp = self.home / ".agent-harness" / "tmp" / SESSION[:8]
        clone = tmp / "clone"
        clone.mkdir()
        self.git(clone, "init", "-q")
        (clone / "fix.txt").write_text("only in the temp directory\n")
        self.git(clone, "add", "fix.txt")
        self.git(clone, "commit", "-q", "-m", "fix")
        done = self.stop()
        self.assertEqual((done.returncode, done.stderr), (0, ""))
        head = self.git(clone, "rev-parse", "HEAD")
        self.assertIn(head, self.rescued().values())
        self.assertTrue([ref for ref in self.rescued() if "/tmp-clone-" in ref])


if __name__ == "__main__":
    unittest.main()
