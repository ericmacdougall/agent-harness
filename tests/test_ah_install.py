"""`ah install-files` (goodqa#15742): a local bare repository stands in for the canonical URL, a fake ssh runs the REAL constant
remote command string through `sh -c` against a temporary host HOME that holds the real command_guard.py and doctor.py.
Nothing here touches a real host or the real hooks directory."""
import hashlib
import io
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
HOOKS = ROOT / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import ah  # noqa: E402
import ah_install as ai  # noqa: E402

GIT_ENV = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
GIT_ENV.update(GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_NOSYSTEM="1", GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.invalid",
               GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.invalid")
NAMES = ("command_guard.py", "doctor.py", "ah.py", "extra.py")
TICKET = "GoodQA goodqa#15742"
# what the registered hook entry answers after a good install (goodqa#15913 AC-10)
HOOK_OK = {"hook_deny_wal": {"exit": 2, "rule": "log_delete/log-delete"}, "hook_subagent_local": {"exit": 2, "rule": "log_delete/install-files"}}


def git(cwd, *args, check=True):
    done = subprocess.run(["git", "-c", "protocol.file.allow=always", *args], cwd=str(cwd), env=GIT_ENV, capture_output=True, text=True)
    if check and done.returncode:
        raise AssertionError("git %s: %s" % (" ".join(args), done.stderr))
    return done.stdout.strip()


def sha(data):
    return hashlib.sha256(data).hexdigest()


class Base(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ah-inst-")
        self.addCleanup(self.temp.cleanup)
        self.tmp = os.path.realpath(self.temp.name)
        self.mac = Path(self.tmp, "mac")
        self.host_home = Path(self.tmp, "host")
        self.mac.mkdir()
        self.hooks = self.host_home / ".claude" / "hooks"
        shutil.copytree(HOOKS, self.hooks, ignore=shutil.ignore_patterns("__pycache__"))
        (self.host_home / ".claude" / "settings.json").write_text("{}")
        pybin = Path(self.tmp, "pybin")
        pybin.mkdir()
        os.symlink(sys.executable, pybin / "python3")
        self.pybin = str(pybin)
        self.calls = []
        self.inject = None  # (op, nth) -> raise a lost connection
        self.counts = {}
        # the source repository: c0 is what the host has, c1 changes every listed file, side branch commits are NOT merged
        self.work = Path(self.tmp, "work")
        git(self.tmp, "init", "-q", "-b", "main", str(self.work))
        self.write_commit({n: self.base_bytes(n) for n in NAMES}, "c0")
        self.c0 = git(self.work, "rev-parse", "HEAD")
        self.write_commit({n: self.base_bytes(n) + b"\n# c1\n" for n in NAMES}, "c1")
        self.c1 = git(self.work, "rev-parse", "HEAD")
        self.origin = Path(self.tmp, "origin.git")
        git(self.tmp, "clone", "-q", "--bare", str(self.work), str(self.origin))
        for n in NAMES:  # the host holds the c0 bytes
            (self.hooks / n).write_bytes(self.base_bytes(n))
        self.patches = [mock.patch.object(ai, "CANONICAL_URL", "file://" + str(self.origin)), mock.patch.object(ai, "ALLOW_FILE", True)]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)

    def base_bytes(self, name):
        if name in ("command_guard.py", "doctor.py"):
            return (HOOKS / name).read_bytes()
        return ("# %s\n" % name).encode()

    def write_commit(self, files, message, branch=None):
        (self.work / "install.py").write_text("HOOKS = %r\n" % (NAMES,))
        (self.work / "harness" / "hooks").mkdir(parents=True, exist_ok=True)
        for name, data in files.items():
            (self.work / "harness" / "hooks" / name).write_bytes(data)
        git(self.work, "add", "-A")
        git(self.work, "commit", "-q", "-m", message)

    def runner(self, argv, input=None, capture_output=True, timeout=None, **kw):
        self.calls.append(list(argv))
        self.assertEqual(argv[0], "ssh")
        self.assertIn("BatchMode=yes", argv)
        self.assertEqual(argv[argv.index("--") - 0], "--")
        cmd = argv[-1]
        op = cmd.split("' ")[-2].split()[-1] if "' " in cmd else ""
        key = None
        for candidate in ("probe", "lock", "unlock", "stage", "commit", "restore", "selftest", "audit", "prune", "cleanup", "read_backup"):
            if (" %s '{" % candidate) in cmd[-400:] or cmd[-400:].split("' '")[0].endswith(" " + candidate) or (" " + candidate + " ") in cmd[-300:]:
                key = candidate
        self.counts[key] = self.counts.get(key, 0) + 1
        if self.inject and self.inject[0] == key and self.counts[key] == self.inject[1]:
            if len(self.inject) > 2 and self.inject[2] == "after":
                subprocess.run(["sh", "-c", cmd], input=input, env=self.env(), capture_output=True, timeout=300)
            raise subprocess.TimeoutExpired(argv, 1)
        return subprocess.run(["sh", "-c", cmd], input=input, env=self.env(), capture_output=True, timeout=300)

    def env(self):
        return {"HOME": str(self.host_home), "PATH": self.pybin + ":/usr/bin:/bin", "LC_ALL": "C"}

    def install(self, ref=None, files=("ah.py", "extra.py"), dry_run=False, ticket=TICKET, **kw):
        posted = kw.setdefault("posted", [])
        return ai.install_files("t2-dev", ref or self.c1, list(files), ticket, dry_run, self.mac, "sess", "agent-x", self.runner,
                                lambda t, text: posted.append((t, text))) if "posted" not in kw or True else None

    def live(self, name):
        return sha((self.hooks / name).read_bytes())

    def rows(self, event=None):
        return [r for r in ai.audit_rows(self.mac) if event is None or r.get("event") == event]

    def refused(self, **kw):
        with self.assertRaises(ai.InstallError) as caught:
            self.install(**kw)
        return caught.exception


class Inputs(Base):
    def test_every_bad_input_refuses_before_any_ssh_call(self):  # AC-1, NEG-1
        good = dict(host="t2-dev", ref=self.c1, files=["ah.py"], ticket=TICKET, dry_run=False, resume=None, rollback=None, force_files=())
        ai.check_inputs(**good)
        cases = {
            "host outside": dict(host="dev2"), "host metachar": dict(host="t2-dev;ls"), "host dash": dict(host="-oProxyCommand=x"),
            "branch ref": dict(ref="main"), "short ref": dict(ref=self.c1[:12]), "upper ref": dict(ref=self.c1.upper()),
            "slash name": dict(files=["../x.py"]), "dot name": dict(files=[".hidden"]), "dotdot": dict(files=["a..b"]), "path": dict(files=["harness/hooks/ah.py"]),
            "duplicate": dict(files=["ah.py", "ah.py"]), "too many": dict(files=["f%d.py" % i for i in range(21)]), "empty": dict(files=[]),
            "no ticket": dict(ticket=None), "bad ticket": dict(ticket="project#1"), "bad run id": dict(resume="ins-xyz", files=None, ref=None),
            "resume with files": dict(resume="ins-0123456789ab"), "force without rollback": dict(force_files=("ah.py",)),
            "resume and rollback": dict(resume="ins-0123456789ab", rollback="ins-0123456789ab", files=None, ref=None),
        }
        for label, change in cases.items():
            with self.subTest(label):
                with self.assertRaises(ai.InstallError) as caught:
                    ai.check_inputs(**dict(good, **change))
                self.assertEqual(caught.exception.exit_code, 2)
        ai.check_inputs(**dict(good, ticket=None, dry_run=True))  # a dry run needs no ticket
        self.assertEqual(self.calls, [])

    def test_a_name_outside_the_installer_list_at_that_commit_refuses_before_ssh(self):  # NEG-1
        self.refused(files=("notlisted.py",))
        self.assertEqual(self.calls, [])


class Listed(Base):
    def test_a_blob_that_exists_but_is_not_in_the_installer_list_refuses(self):  # AC-1, NEG-1
        side = Path(self.tmp, "side-unlisted")
        git(self.tmp, "clone", "-q", str(self.origin), str(side))
        (side / "harness" / "hooks" / "unlisted.py").write_text("# not listed\n")
        git(side, "add", "-A")
        git(side, "commit", "-q", "-m", "adds an unlisted blob")
        git(side, "push", "-q", "origin", "main")
        error = self.refused(ref=git(side, "rev-parse", "HEAD"), files=("unlisted.py",))
        self.assertIn("HOOKS list", str(error))
        self.assertEqual(self.calls, [])


class Receipt1c(Base):
    """Receipt r1c: a failed attempt must not unblock a host in an unknown state, a hanging guard must be rolled back, and a rollback
    reports the real state of a file it was asked to remove."""

    def unknown_install(self):
        self.inject = ("commit", 1, "after")  # the commit ran on the host and the answer was lost
        with self.assertRaises(ai.InstallError) as caught:
            self.install()
        self.inject = None
        return caught.exception.data["run"]

    def assertHostRefuses(self):
        error = self.refused()
        self.assertEqual(error.code, "unfinished_run")

    def test_a_rollback_lost_at_the_lock_does_not_clear_the_unfinished_run(self):  # F1
        run = self.unknown_install()
        self.assertHostRefuses()
        self.inject = ("lock", self.counts.get("lock", 0) + 1)
        with self.assertRaises(ai.InstallError) as caught:
            ai.rollback(run, TICKET, (), self.mac, "s", "a", self.runner, lambda t, x: None)
        self.assertEqual(caught.exception.data["result"], "attempt_refused")
        self.inject = None
        self.assertHostRefuses()
        self.assertEqual(ai.unfinished_runs(self.mac, "t2-dev"), [run])

    def test_a_resume_refused_by_another_runs_lock_does_not_clear_the_unfinished_run(self):  # F1
        run = self.unknown_install()
        lock = self.hooks / ".ah-install" / "lock"
        lock.mkdir(parents=True, exist_ok=True)
        (lock / "run").write_text("ins-eeeeeeeeeeee")
        with self.assertRaises(ai.InstallError) as caught:
            ai.resume(run, TICKET, self.mac, "s", "a", self.runner, lambda t, x: None)
        self.assertEqual(caught.exception.data["result"], "attempt_refused")
        shutil.rmtree(lock)
        self.assertHostRefuses()

    def test_a_resume_that_fails_at_stage_is_unknown_and_the_host_keeps_refusing(self):  # F1
        run = self.unknown_install()
        (self.hooks / "extra.py").write_bytes(self.base_bytes("extra.py"))  # one file is back at its old bytes: the resume must stage it
        self.inject = ("stage", self.counts.get("stage", 0) + 1)
        with self.assertRaises(ai.InstallError) as caught:
            ai.resume(run, TICKET, self.mac, "s", "a", self.runner, lambda t, x: None)
        self.assertEqual(caught.exception.data["result"], "unknown")
        self.inject = None
        self.assertHostRefuses()

    def test_only_a_definite_result_clears_an_unfinished_run(self):  # F1
        for result, cleared in (("installed", True), ("rolled_back", True), ("restored", True), ("already_current", True), ("refused", True),
                                ("unknown", False), ("attempt_refused", False)):
            with self.subTest(result):
                home = Path(self.tmp, "audit-" + result)
                ai.audit(home, {"event": "start", "kind": "install", "run": "ins-000000000001", "host": "t2-dev"})
                ai.audit(home, {"event": "result", "kind": "install", "run": "ins-000000000001", "host": "t2-dev", "result": result})
                self.assertEqual(ai.unfinished_runs(home, "t2-dev") == [], cleared)

    def test_a_guard_that_hangs_forever_after_the_install_is_rolled_back_not_left_live(self):  # F2
        side = Path(self.tmp, "hang")
        git(self.tmp, "clone", "-q", str(self.origin), str(side))
        (side / "harness" / "hooks" / "command_guard.py").write_bytes(b"import time\ntime.sleep(1000)\n")
        git(side, "add", "-A")
        git(side, "commit", "-q", "-m", "hanging guard")
        git(side, "push", "-q", "origin", "main")
        ref = git(side, "rev-parse", "HEAD")
        before = {n: self.live(n) for n in NAMES}
        quick = ai.REMOTE_SCRIPT.replace("60, 120, 200", "1, 1, 3")
        self.assertNotEqual(quick, ai.REMOTE_SCRIPT)
        started = __import__("time").time()
        with mock.patch.object(ai, "REMOTE_SCRIPT", quick):
            with self.assertRaises(ai.InstallError) as caught:
                self.install(ref=ref, files=("ah.py", "command_guard.py"))
        self.assertLess(__import__("time").time() - started, 120)
        self.assertEqual(caught.exception.data["result"], "rolled_back")
        self.assertEqual({n: self.live(n) for n in NAMES}, before)

    def test_an_after_test_that_does_not_answer_in_time_attempts_a_rollback_guard_first(self):  # F2
        self.inject = ("selftest", 2)  # the baseline answers, the after-install test never does
        before = {n: self.live(n) for n in NAMES}
        with self.assertRaises(ai.InstallError) as caught:
            self.install(files=("ah.py", "command_guard.py"))
        self.assertEqual(caught.exception.data["result"], "rolled_back")
        self.assertEqual({n: self.live(n) for n in NAMES}, before)

    def test_a_rollback_that_could_not_remove_a_file_does_not_report_restored(self):  # F3
        (self.hooks / "extra.py").unlink()
        run = self.install(files=("extra.py",))["run"]
        (self.hooks / "extra.py").write_bytes(b"# changed by someone else\n")
        with self.assertRaises(ai.InstallError) as caught:
            ai.rollback(run, TICKET, ("extra.py",), self.mac, "s", "a", self.runner, lambda t, x: None)
        self.assertEqual(caught.exception.data["result"], "unknown")
        self.assertIn("read-back differs", str(caught.exception.data["reason"]))
        self.assertTrue((self.hooks / "extra.py").exists())


class Hardening(Base):
    """Findings of the code review (M2 to M6, L3 to L6)."""

    def test_a_host_guard_that_already_fails_open_refuses_before_any_write(self):  # M2
        (self.hooks / "command_guard.py").write_bytes(b"import sys\nprint('{\"verdict\": \"allow\", \"message\": \"\"}')\n")
        before = {n: self.live(n) for n in NAMES}
        error = self.refused(files=("ah.py", "command_guard.py"))
        self.assertIn("self-test cannot run", str(error))
        self.assertEqual({n: self.live(n) for n in NAMES}, before)
        self.assertFalse(ai.selftest_ok_to_start({"guard": {"allow": {"exit": 0, "verdict": "allow"}, "deny_wal": {"exit": 0, "verdict": "allow"}}}))

    def test_an_older_ref_that_would_downgrade_a_file_refuses_unless_allow_older_is_given_and_audited(self):  # M3
        side = Path(self.tmp, "side-newer")
        git(self.tmp, "clone", "-q", str(self.origin), str(side))
        (side / "harness" / "hooks" / "ah.py").write_bytes(b"# newest\n")
        git(side, "add", "-A")
        git(side, "commit", "-q", "-m", "newer ah.py")
        git(side, "push", "-q", "origin", "main")
        error = self.refused(ref=self.c1, files=("ah.py",))
        self.assertEqual(error.code, "older_ref")
        self.assertIn("DOWNGRADE", str(error))
        self.assertEqual(self.calls, [])
        out = ai.install_files("t2-dev", self.c1, ["ah.py"], TICKET, False, self.mac, "s", "a", self.runner, lambda t, x: None, allow_older=True)
        self.assertEqual(out["result"], "installed")
        self.assertTrue(self.rows("start")[0]["allow_older"])
        # a file with no newer merged version is unaffected
        self.assertEqual(ai.install_files("t2-dev", self.c1, ["extra.py"], TICKET, False, self.mac, "s", "a", self.runner, lambda t, x: None)["result"], "installed")

    def test_a_hooks_directory_that_is_a_symlink_or_owned_by_another_user_refuses(self):  # M4
        real = self.host_home / ".claude" / "hooks-real"
        self.hooks.rename(real)
        os.symlink(real, self.hooks)
        error = self.refused(files=("ah.py",))
        self.assertIn("symlink", str(error))
        self.assertEqual(sha((real / "ah.py").read_bytes()), sha(self.base_bytes("ah.py")))

    def test_an_unexpected_error_after_the_first_live_write_is_unknown_with_json_not_a_traceback(self):  # M6
        real = ai.Remote.call

        def boom(self_, op, args=None, data=None, **kw):
            out = real(self_, op, args, data, **kw)
            if op == "commit":
                return {"unexpected": "shape"}  # a KeyError for done["live"]
            return out
        with mock.patch.object(ai.Remote, "call", boom):
            with self.assertRaises(ai.InstallError) as caught:
                self.install()
        self.assertEqual(caught.exception.exit_code, 5)
        self.assertEqual(caught.exception.data["result"], "unknown")
        self.assertIn("check t2-dev", str(caught.exception.data["reason"]))

    def test_a_non_literal_hooks_tuple_is_a_refusal_not_a_traceback(self):  # L5
        side = Path(self.tmp, "side-nonliteral")
        git(self.tmp, "clone", "-q", str(self.origin), str(side))
        (side / "install.py").write_text("HOOKS = ('a.py',) + tuple(x for x in ('b.py',))\n")
        git(side, "add", "-A")
        git(side, "commit", "-q", "-m", "non literal")
        git(side, "push", "-q", "origin", "main")
        error = self.refused(ref=git(side, "rev-parse", "HEAD"), files=("ah.py",))
        self.assertIn("plain literal", str(error))

    def test_a_lost_answer_taking_the_lock_says_a_lock_may_remain(self):  # L6
        self.inject = ("lock", 1, "after")
        error = self.refused()
        self.assertEqual(error.exit_code, 2)
        self.assertIn("lock may remain", str(error.data["reason"]))

    def test_prune_keeps_ten_run_directories_and_ignores_other_entries(self):  # L4
        backups = self.hooks / ".ah-install" / "backups"
        backups.mkdir(parents=True)
        for i in range(12):
            d = backups / ("ins-%012x" % i)
            d.mkdir()
            os.utime(d, (1000 + i, 1000 + i))
        (backups / "not-a-run").mkdir()
        argv = ai.ssh_argv("t2-dev", "prune", {})
        self.assertEqual(subprocess.run(["sh", "-c", argv[-1]], capture_output=True, env=self.env()).returncode, 0)
        names = sorted(p.name for p in backups.iterdir())
        self.assertEqual(len([n for n in names if n.startswith("ins-")]), 10)
        self.assertIn("not-a-run", names)


class Source(Base):
    def test_an_unmerged_commit_refuses_before_any_remote_call(self):  # AC-2, NEG-2
        side = Path(self.tmp, "side")
        git(self.tmp, "clone", "-q", str(self.origin), str(side))
        git(side, "checkout", "-q", "-b", "feature")
        (side / "harness" / "hooks" / "ah.py").write_bytes(b"# evil\n")
        git(side, "add", "-A")
        git(side, "commit", "-q", "-m", "unmerged")
        unmerged = git(side, "rev-parse", "HEAD")
        git(side, "push", "-q", "origin", "feature")  # on the remote, but not on main
        error = self.refused(ref=unmerged)
        self.assertTrue("not a commit of the canonical main" in str(error) or "not an ancestor" in str(error), str(error))
        self.assertEqual(self.calls, [])

    def test_a_ref_that_adds_a_name_to_hooks_but_is_not_merged_refuses(self):  # NEG-2
        side = Path(self.tmp, "side2")
        git(self.tmp, "clone", "-q", str(self.origin), str(side))
        (side / "install.py").write_text("HOOKS = %r\n" % (NAMES + ("newhook.py",),))
        (side / "harness" / "hooks" / "newhook.py").write_text("# new\n")
        git(side, "add", "-A")
        git(side, "commit", "-q", "-m", "adds a name")
        ref = git(side, "rev-parse", "HEAD")
        self.refused(ref=ref, files=("newhook.py",))
        self.assertEqual(self.calls, [])

    def test_a_planted_object_in_the_install_cache_has_no_effect_and_a_forged_object_after_the_fetch_is_caught(self):  # NEG-2
        cache = self.mac / ".agent-harness" / "install-cache"
        cache.mkdir(parents=True)
        (cache / "planted-pack").write_text("forged")
        self.assertEqual(self.install()["result"], "installed")
        # now forge the blob after the fetch: a loose object with other content under the real id
        blob = git(self.work, "rev-parse", "%s:harness/hooks/ah.py" % self.c1)

        def forge(event, repo=None, **kw):
            if event == "after_fetch":
                path = Path(repo) / "objects" / blob[:2] / blob[2:]
                if path.exists():
                    os.chmod(path, 0o644)
                    path.unlink()
                import zlib
                body = b"# forged\n"
                path.parent.mkdir(exist_ok=True)
                path.write_bytes(zlib.compress(b"blob %d\0" % len(body) + body))
        for n in NAMES:
            (self.hooks / n).write_bytes(self.base_bytes(n))
        with mock.patch.object(ai, "HOOK", forge):
            with self.assertRaises(ai.InstallError) as caught:
                self.install()
        self.assertIn("does not hash", str(caught.exception))
        self.assertEqual(self.live("ah.py"), sha(self.base_bytes("ah.py")))

    def test_a_replace_ref_in_the_fetched_repository_refuses(self):  # NEG-2
        def add_replace(event, repo=None, **kw):
            if event == "after_fetch":
                git(repo, "update-ref", "refs/replace/%s" % self.c0, self.c1)
        with mock.patch.object(ai, "HOOK", add_replace):
            error = self.refused()
        self.assertIn("replace", str(error))

    def test_a_symlink_blob_refuses(self):  # NEG-2
        side = Path(self.tmp, "side3")
        git(self.tmp, "clone", "-q", str(self.origin), str(side))
        os.unlink(side / "harness" / "hooks" / "extra.py")
        os.symlink("/etc/passwd", side / "harness" / "hooks" / "extra.py")
        git(side, "add", "-A")
        git(side, "commit", "-q", "-m", "symlink")
        git(side, "push", "-q", "origin", "main")
        ref = git(side, "rev-parse", "HEAD")
        error = self.refused(ref=ref, files=("extra.py",))
        self.assertIn("not a regular file", str(error))

    def test_a_fork_or_unreachable_canonical_url_refuses(self):  # NEG-2
        with mock.patch.object(ai, "CANONICAL_URL", "file://" + str(Path(self.tmp, "nowhere.git"))):
            error = self.refused()
        self.assertEqual(error.code, "fetch_failed")
        self.assertEqual(self.calls, [])

    def test_the_bytes_never_come_from_a_caller_path(self):  # NEG-10
        (self.work / "harness" / "hooks" / "ah.py").write_bytes(b"# edited in a worktree\n")
        self.assertEqual(self.install()["result"], "installed")
        self.assertEqual(sha((self.hooks / "ah.py").read_bytes()), sha(self.base_bytes("ah.py") + b"\n# c1\n"))


class Install(Base):
    def test_a_good_install_backs_up_stages_renames_and_reports_every_sha(self):  # AC-3
        old = {n: self.live(n) for n in NAMES}
        out = self.install(files=("ah.py", "extra.py", "doctor.py", "command_guard.py"))
        self.assertEqual(out["result"], "installed")
        self.assertEqual(out["exit_code"], 0)
        for n in NAMES:
            plan = out["files"][n]
            self.assertEqual(plan["old_sha"], old[n])
            self.assertEqual(self.live(n), plan["new_sha"])
            self.assertNotEqual(plan["new_sha"], old[n])
            self.assertEqual(sha((self.hooks / ".ah-install" / "backups" / out["run"] / n).read_bytes()), old[n])
            self.assertEqual(sha((self.mac / ".agent-harness" / "install-backups" / out["run"] / n).read_bytes()), old[n])
            self.assertFalse((self.hooks / ("." + n + ".ah-install-tmp")).exists())
        self.assertEqual(oct((self.hooks / ".ah-install" / "backups").stat().st_mode & 0o777), "0o700")
        self.assertFalse((self.hooks / ".ah-install" / "lock").exists())
        host_rows = [json.loads(l) for l in (self.host_home / ".agent-harness" / "install-audit.jsonl").read_text().splitlines()]
        self.assertEqual(host_rows[0]["script_sha256"], ai.SCRIPT_SHA256)
        self.assertEqual(oct((self.host_home / ".agent-harness" / "install-audit.jsonl").stat().st_mode & 0o777), "0o600")

    def test_the_guard_is_renamed_last_and_the_order_is_fixed(self):  # AC-3
        order = []
        real = ai.Remote.call

        def spy(self_, op, args=None, **kw):
            if op == "commit":
                order.extend(args["names"])
            return real(self_, op, args, **kw)
        with mock.patch.object(ai.Remote, "call", spy):
            self.install(files=("command_guard.py", "ah.py", "extra.py"))
        self.assertEqual(order, ["ah.py", "extra.py", "command_guard.py"])

    def test_a_bad_file_two_changes_nothing_live_even_when_file_one_is_the_guard(self):  # AC-3, NEG-3
        os.symlink("/etc/hosts", self.hooks / "extra.py.tmp-link")
        (self.hooks / "extra.py").unlink()
        os.symlink(str(self.hooks / "ah.py"), self.hooks / "extra.py")  # the target of file two is a symlink
        before = {n: self.live(n) for n in ("command_guard.py", "ah.py")}
        error = self.refused(files=("command_guard.py", "extra.py"))
        self.assertIn("symlink", str(error))
        for n, value in before.items():
            self.assertEqual(self.live(n), value)

    def test_a_wrong_upload_leaves_every_live_file_and_removes_the_temporary_files(self):  # AC-3, NEG-3
        real = ai.Remote.call

        def corrupt(self_, op, args=None, data=None, **kw):
            if op == "stage" and args["name"] == "extra.py":
                data = data + b"x"
            return real(self_, op, args, data, **kw)
        before = {n: self.live(n) for n in NAMES}
        with mock.patch.object(ai.Remote, "call", corrupt):
            error = self.refused(files=("ah.py", "extra.py"))
        self.assertEqual(error.exit_code, 2)
        self.assertEqual({n: self.live(n) for n in NAMES}, before)
        self.assertEqual([p.name for p in self.hooks.glob(".*.ah-install-tmp")], [])
        self.assertFalse((self.hooks / ".ah-install" / "lock").exists())

    def test_a_directory_at_the_temporary_name_refuses(self):  # NEG-3
        (self.hooks / ".ah.py.ah-install-tmp").mkdir()
        error = self.refused(files=("ah.py",))
        self.assertIn("temporary name", str(error))

    def test_a_rerun_is_a_no_op_per_file(self):  # AC-6
        self.assertEqual(self.install()["result"], "installed")
        again = self.install()
        self.assertEqual(again["result"], "already_current")
        self.assertEqual(self.counts.get("stage"), 2)  # only the first run staged
        self.assertEqual(len(list((self.hooks / ".ah-install" / "backups").iterdir())), 1)

    def test_dry_run_changes_nothing_and_takes_no_lock(self):  # AC-7, NEG-8
        before = sorted((p.name, p.stat().st_size, p.stat().st_mtime_ns, p.stat().st_ino) for p in self.hooks.iterdir())
        out = self.install(dry_run=True, ticket=None)
        self.assertEqual(out["result"], "dry_run")
        self.assertEqual({n: v["action"] for n, v in out["files"].items()}, {"ah.py": "replaced", "extra.py": "replaced"})
        after = sorted((p.name, p.stat().st_size, p.stat().st_mtime_ns, p.stat().st_ino) for p in self.hooks.iterdir())
        self.assertEqual(before, after)
        self.assertFalse((self.hooks / ".ah-install").exists())
        self.assertEqual(self.counts.get("stage"), None)
        self.assertEqual([r["kind"] for r in self.rows("result")], ["dry_run"])

    def test_the_remote_command_string_reaches_python_unchanged_through_a_shell(self):  # AC-6
        argv = ai.ssh_argv("t2-dev", "probe", {"names": ["a b'c\"d.py"]})
        self.assertEqual(argv[argv.index("--") + 1], "t2-dev")
        self.assertIn("ClearAllForwardings=yes", argv)
        done = subprocess.run(["sh", "-c", "printf '%s' " + "\"$0\"", argv[-1]], capture_output=True, text=True)
        self.assertEqual(done.stdout, argv[-1])
        probe = subprocess.run(["sh", "-c", argv[-1].replace("python3 -I -c", sys.executable + " -I -c", 1)], capture_output=True, text=True,
                               env={"HOME": str(self.host_home), "PATH": "/usr/bin:/bin"})
        self.assertNotEqual(probe.returncode, 0)  # the bad name is refused by the remote script, not mangled by the shell
        self.assertIn("bad name", probe.stderr)

    def test_the_remote_script_compiles_with_python_3_9_syntax_only(self):  # AC-6
        tree = __import__("ast").parse(ai.REMOTE_SCRIPT, feature_version=(3, 9))
        self.assertTrue(tree.body)
        self.assertNotIn("match ", ai.REMOTE_SCRIPT)


class SelfTest(Base):
    def broken_commit(self, guard_bytes):
        side = Path(self.tmp, "broken")
        git(self.tmp, "clone", "-q", str(self.origin), str(side))
        (side / "harness" / "hooks" / "command_guard.py").write_bytes(guard_bytes)
        git(side, "add", "-A")
        git(side, "commit", "-q", "-m", "broken guard")
        git(side, "push", "-q", "origin", "main")
        return git(side, "rev-parse", "HEAD")

    def test_an_allow_all_guard_rolls_every_file_back_with_the_guard_restored_first(self):  # AC-4, NEG-4, NEG-5
        ref = self.broken_commit(b"import sys\nprint('{\"verdict\": \"allow\", \"message\": \"\"}')\n")
        before = {n: self.live(n) for n in NAMES}
        with self.assertRaises(ai.InstallError) as caught:
            self.install(ref=ref, files=("ah.py", "command_guard.py"))
        self.assertEqual(caught.exception.exit_code, 4)
        self.assertEqual(caught.exception.data["result"], "rolled_back")
        self.assertEqual({n: self.live(n) for n in NAMES}, before)
        self.assertFalse((self.hooks / ".ah-install" / "lock").exists())

    def test_a_read_back_sha_that_differs_after_the_rename_rolls_back_with_the_guard_first(self):  # AC-3, NEG-3
        real = ai.Remote.call
        restores = []

        def lie(self_, op, args=None, data=None, **kw):
            out = real(self_, op, args, data, **kw)
            if op == "commit":
                out = {"live": dict(out["live"], **{args["names"][0]: "0" * 64})}
            if op == "restore":
                restores.append([i["name"] for i in args["items"]])
            return out
        before = {n: self.live(n) for n in NAMES}
        with mock.patch.object(ai.Remote, "call", lie):
            with self.assertRaises(ai.InstallError) as caught:
                self.install(files=("ah.py", "command_guard.py"))
        self.assertEqual(caught.exception.data["result"], "rolled_back")
        self.assertEqual({n: self.live(n) for n in NAMES}, before)
        self.assertEqual(restores[0][0], "command_guard.py")  # the guard is restored FIRST

    def test_a_crashing_guard_rolls_back(self):  # AC-4, NEG-4
        ref = self.broken_commit(b"raise SystemExit(3)\n")
        before = {n: self.live(n) for n in NAMES}
        with self.assertRaises(ai.InstallError) as caught:
            self.install(ref=ref, files=("command_guard.py",))
        self.assertEqual(caught.exception.data["result"], "rolled_back")
        self.assertEqual({n: self.live(n) for n in NAMES}, before)

    def test_a_guard_that_stops_denying_the_hooks_copy_probe_is_worse(self):  # AC-4, NEG-4
        before = {"guard": {"deny_hooks_copy": {"exit": 0, "verdict": "block", "rule": "log_delete/log-delete"}}, "hook": HOOK_OK, "doctor": {"flags": True, "failing": []}}
        after = {"guard": {"deny_hooks_copy": {"exit": 0, "verdict": "allow", "rule": ""}}, "hook": HOOK_OK, "doctor": {"flags": True, "failing": []}}
        self.assertIn("changed", ai.selftest_worse(before, after))
        self.assertIsNone(ai.selftest_worse(before, before))

    def test_only_new_doctor_failures_count_and_a_baseline_with_failures_passes(self):  # AC-4, NEG-4
        guard = {"allow": {"exit": 0, "verdict": "allow", "rule": ""}}
        before = {"guard": guard, "doctor": {"flags": True, "failing": ["a", "b"]}}
        self.assertIsNone(ai.selftest_worse(before, {"guard": guard, "hook": HOOK_OK, "doctor": {"flags": True, "failing": ["a"]}}))
        self.assertIn("new failing", ai.selftest_worse(before, {"guard": guard, "hook": HOOK_OK, "doctor": {"flags": True, "failing": ["a", "b", "c"]}}))
        self.assertIn("could not run", ai.selftest_worse(before, {"guard": guard, "hook": HOOK_OK, "doctor": {"flags": True, "failing": None}}))

    def manifest_commit(self, extra_rows, first=False):
        """A merged commit whose installer also lists hooks_manifest.json, with `extra_rows` added to the manifest."""
        side = Path(self.tmp, "manifest-side")
        git(self.tmp, "clone", "-q", str(self.origin), str(side))
        (side / "install.py").write_text("HOOKS = %r\n" % (NAMES + ("hooks_manifest.json",),))
        manifest = json.loads((self.hooks / "hooks_manifest.json").read_text())
        manifest["hooks"] = list(extra_rows) + manifest["hooks"] if first else manifest["hooks"] + list(extra_rows)
        (side / "harness" / "hooks" / "hooks_manifest.json").write_text(json.dumps(manifest, indent=1) + "\n")
        git(side, "add", "-A")
        git(side, "commit", "-q", "-m", "manifest adds rows")
        git(side, "push", "-q", "origin", "main")
        return git(side, "rev-parse", "HEAD")

    ROW = {"id": "newhook:stop", "script": "extra.py", "arg": "stop", "event": "Stop", "tools": [], "flavors": ["claude"],
           "status": "installed", "rules": []}

    def test_a_manifest_that_only_adds_an_unregistered_hook_installs_and_says_so(self):  # goodqa#15754 AC-10
        """t2-dev 2026-11-12, run ins-d882276cc2a3: the new manifest declared three status-truth rows, settings.json does
        not register them (install-files never edits settings), doctor called them MISSING and the run rolled back.
        On main 6e318911 this test fails with "new failing doctor checks: newhook:stop"."""
        ref = self.manifest_commit([self.ROW])
        posted = []
        out = self.install(ref=ref, files=("hooks_manifest.json", "extra.py"), posted=posted)
        self.assertEqual(out["result"], "installed")
        self.assertEqual(out["unregistered"], ["newhook:stop"])
        self.assertIs(out["registration_needed"], True)
        self.assertIn("not registered in settings.json", out["note"])
        self.assertIn("newhook:stop", posted[-1][1])  # the ticket comment says it too

    def test_newly_declared_but_broken_rows_and_lost_wiring_still_roll_back(self):  # goodqa#15754 AC-10 NEG
        guard = {"allow": {"exit": 0, "verdict": "allow", "rule": ""}}

        def doc(states):
            failing = sorted(i for i, st in states.items() if st not in ("WIRED", "PENDING"))
            return {"guard": guard, "hook": HOOK_OK, "doctor": {"flags": True, "failing": failing, "states": states}}
        before = doc({"a:stop": "WIRED", "b:stop": "MISSING"})
        # a new row that is only unregistered is reported, not a regression
        self.assertIsNone(ai.selftest_worse(before, doc({"a:stop": "WIRED", "b:stop": "MISSING", "new:stop": "MISSING"})))
        self.assertEqual(ai.newly_declared_unregistered(before, doc({"a:stop": "WIRED", "b:stop": "MISSING",
                                                                     "new:stop": "MISSING"})), ["new:stop"])
        # a pending row promoted to installed and still unregistered is the same case (review a36299f2 finding 2)
        pend = doc({"a:stop": "WIRED", "p:stop": "PENDING"})
        self.assertIsNone(ai.selftest_worse(pend, doc({"a:stop": "WIRED", "p:stop": "MISSING"})))
        self.assertEqual(ai.newly_declared_unregistered(pend, doc({"a:stop": "WIRED", "p:stop": "MISSING"})), ["p:stop"])
        # a new row that is registered but whose script is missing is a regression (CANARY_FAIL is covered for a
        # doctor run with canaries; the install self-test runs --no-canary)
        for state in ("SCRIPT_MISSING", "CANARY_FAIL"):
            self.assertIn("new:stop", ai.selftest_worse(before, doc({"a:stop": "WIRED", "b:stop": "MISSING",
                                                                       "new:stop": state})) or "")
        # a row wired before that is unregistered after, or renamed away, is a regression
        self.assertIn("a:stop", ai.selftest_worse(before, doc({"a:stop": "MISSING", "b:stop": "MISSING"})) or "")
        self.assertIn("a:stop", ai.selftest_worse(before, doc({"a2:stop": "MISSING", "b:stop": "MISSING"})) or "")
        # a baseline without states (an older journal row) keeps the strict rule
        old = {"guard": guard, "doctor": {"flags": True, "failing": ["b:stop"]}}
        self.assertIn("new:stop", ai.selftest_worse(old, doc({"a:stop": "WIRED", "b:stop": "MISSING",
                                                               "new:stop": "MISSING"})) or "")
        self.assertEqual(ai.newly_declared_unregistered(old, doc({"new:stop": "MISSING"})), [])

    def test_a_doctor_past_the_state_bound_records_no_states_and_stays_strict(self):  # review a36299f2 finding 1
        rows = [dict(self.ROW, id="bulk%03d:stop" % n) for n in range(400)]
        # placed FIRST, so a map cut at 400 rows would hold exactly the new rows and pass them all (on 949fb22d this
        # installs); with no map past the bound the strict rule rolls back
        ref = self.manifest_commit(rows, first=True)
        with self.assertRaises(ai.InstallError) as caught:
            self.install(ref=ref, files=("hooks_manifest.json", "extra.py"))
        self.assertEqual(caught.exception.data["result"], "rolled_back")
        self.assertIn("new failing doctor checks", str(caught.exception))

    def test_the_host_self_test_records_each_doctor_state(self):  # goodqa#15754 AC-10
        ref = self.manifest_commit([self.ROW])
        out = self.install(ref=ref, files=("hooks_manifest.json", "extra.py"))
        states = out["selftest_after"]["doctor"]["states"]
        self.assertEqual(states["newhook:stop"], "MISSING")
        self.assertTrue(all(isinstance(k, str) and isinstance(v, str) for k, v in states.items()))

    def test_a_self_test_that_cannot_run_before_any_write_refuses(self):  # AC-4, NEG-4
        (self.hooks / "command_guard.py").write_bytes(b"raise SystemExit(7)\n")
        before = {n: self.live(n) for n in NAMES}
        error = self.refused(files=("ah.py",))
        self.assertIn("self-test cannot run", str(error))
        self.assertEqual({n: self.live(n) for n in NAMES}, before)

    def test_a_new_file_removed_on_rollback_only_by_its_live_name_and_only_when_it_is_the_new_one(self):  # AC-4
        (self.hooks / "extra.py").unlink()
        ref = self.broken_commit(b"import sys\nprint('{\"verdict\": \"allow\", \"message\": \"\"}')\n")
        with self.assertRaises(ai.InstallError):
            self.install(ref=ref, files=("extra.py", "command_guard.py"))
        self.assertFalse((self.hooks / "extra.py").exists())
        self.assertEqual(self.live("command_guard.py"), sha(self.base_bytes("command_guard.py")))


class Audit(Base):
    def test_start_row_before_the_first_remote_write_and_a_result_row_after(self):  # AC-5
        seen = []
        real = ai.Remote.call

        def spy(self_, op, args=None, **kw):
            if op in ("lock", "stage", "commit"):
                seen.append((op, [r["event"] for r in self.rows()]))
            return real(self_, op, args, **kw)
        with mock.patch.object(ai.Remote, "call", spy):
            out = self.install()
        self.assertTrue(all(events == ["start"] for _op, events in seen), seen)
        start = self.rows("start")[0]
        for key in ("run", "host", "url", "main", "ref", "files", "baseline", "script_sha256", "session", "agent", "ticket"):
            self.assertIn(key, start)
        self.assertEqual(start["agent"], "agent-x")
        self.assertEqual(self.rows("result")[0]["result"], "installed")
        self.assertEqual(oct(ai.audit_path(self.mac).stat().st_mode & 0o777), "0o600")
        self.assertEqual(out["ticket_comment"], True)

    def test_a_failed_mac_audit_write_stops_before_any_remote_write_with_exit_3(self):  # AC-5, NEG-6
        with mock.patch.object(ai, "audit", side_effect=OSError("disk full")):
            with self.assertRaises(ai.InstallError) as caught:
                self.install()
        self.assertEqual(caught.exception.exit_code, 3)
        for key in ("lock", "stage", "commit"):
            self.assertNotIn(key, self.counts)

    def test_a_lost_answer_after_the_first_rename_is_unknown_and_blocks_a_plain_rerun(self):  # AC-5, NEG-6
        self.inject = ("commit", 1, "after")  # the commit ran on the host, the answer is lost
        with self.assertRaises(ai.InstallError) as caught:
            self.install()
        self.assertEqual(caught.exception.exit_code, 5)
        self.assertEqual(caught.exception.data["result"], "unknown")
        self.assertIn("t2-dev", str(caught.exception))
        self.inject = None
        error = self.refused()
        self.assertEqual(error.code, "unfinished_run")

    def test_resume_finishes_with_the_original_baseline(self):  # AC-5, NEG-6
        self.inject = ("commit", 1, "after")
        with self.assertRaises(ai.InstallError) as caught:
            self.install()
        run = caught.exception.data["run"]
        self.inject = None
        baseline = self.rows("start")[0]["baseline"]
        seen = {}
        real = ai.Remote.call

        def spy(self_, op, args=None, **kw):
            if op == "selftest":
                seen["called"] = seen.get("called", 0) + 1
            return real(self_, op, args, **kw)
        with mock.patch.object(ai.Remote, "call", spy):
            out = ai.resume(run, TICKET, self.mac, "s", "agent-x", self.runner, lambda t, x: None)
        self.assertIn(out["result"], ("installed", "already_current"))
        self.assertEqual(seen.get("called"), 1)  # only the after-test: the baseline came from the start row
        self.assertEqual(self.rows("start")[-1]["baseline"], baseline)
        self.assertEqual(ai.unfinished_runs(self.mac, "t2-dev"), [])

    def test_an_automatic_rollback_that_loses_its_connection_is_unknown_rollback_incomplete(self):  # AC-5, NEG-6
        ref = SelfTest.broken_commit(self, b"import sys\nprint('{\"verdict\": \"allow\", \"message\": \"\"}')\n")
        self.inject = ("restore", 1)
        with self.assertRaises(ai.InstallError) as caught:
            self.install(ref=ref, files=("command_guard.py",))
        self.assertEqual(caught.exception.exit_code, 5)
        self.assertIn("rollback incomplete", str(caught.exception))

    def test_a_lost_answer_before_any_live_write_is_refused_not_unknown(self):  # AC-5, NEG-6
        self.inject = ("stage", 1)
        error = self.refused()
        self.assertEqual(error.exit_code, 2)
        self.assertEqual(self.rows("result")[-1]["result"], "refused")

    def test_a_failed_host_audit_write_is_reported_and_not_fatal(self):  # AC-5
        real = ai.Remote.call

        def deny(self_, op, args=None, **kw):
            if op == "audit":
                raise ai.InstallError("remote_failed", "no space", 2)
            return real(self_, op, args, **kw)
        with mock.patch.object(ai.Remote, "call", deny):
            self.assertEqual(self.install()["result"], "installed")

    def test_the_ticket_comment_names_the_ref_and_the_shas(self):  # AC-5
        posted = []
        self.install(posted=posted)
        self.assertEqual(len(posted), 1)
        self.assertEqual(posted[0][0], TICKET)
        self.assertIn(self.c1, posted[0][1])

    def test_a_failed_ticket_comment_on_a_fleet_run_is_reported_and_keeps_its_exit(self):  # goodqa#15913 AC-11
        out = ai.install_files("t2-dev", self.c1, ["ah.py"], TICKET, False, self.mac, "s", "a", self.runner, lambda t, x: False)
        self.assertEqual((out["result"], out["exit_code"], out["ok"]), ("installed", 0, True))  # the host keeps its own audit copy
        self.assertIs(out["comment_failed"], True)


class Lock(Base):
    def test_a_fresh_lock_refuses_and_a_stale_one_is_taken_over_atomically(self):  # AC-6, NEG-7
        lock = self.hooks / ".ah-install" / "lock"
        lock.mkdir(parents=True)
        (lock / "run").write_text("ins-aaaaaaaaaaaa")
        error = self.refused()
        self.assertEqual(error.exit_code, 2)
        self.assertTrue(lock.exists())
        old = __import__("time").time() - 4000
        os.utime(lock, (old, old))
        out = self.install()
        self.assertEqual(out["result"], "installed")
        self.assertFalse([p for p in (self.hooks / ".ah-install").iterdir() if p.name.startswith("lock.stale-")])  # pruned after the run
        self.assertFalse(lock.exists())

    def test_a_run_takes_its_own_leftover_lock_back_and_a_slow_run_does_not_look_stale(self):  # review M5
        out = self.install()
        run = out["run"]
        lock = self.hooks / ".ah-install" / "lock"
        lock.mkdir()
        (lock / "run").write_text(run)
        old = __import__("time").time() - 100
        os.utime(lock, (old, old))
        argv = ai.ssh_argv("t2-dev", "lock", {"run": run})
        done = subprocess.run(["sh", "-c", argv[-1]], capture_output=True, text=True, env=self.env())
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertGreater(lock.stat().st_mtime, old + 50)  # touched, and taken back although fresh
        other = ai.ssh_argv("t2-dev", "lock", {"run": "ins-dddddddddddd"})
        self.assertNotEqual(subprocess.run(["sh", "-c", other[-1]], capture_output=True, text=True, env=self.env()).returncode, 0)

    def test_the_lock_is_released_only_by_its_own_run_id(self):  # NEG-7
        lock = self.hooks / ".ah-install" / "lock"
        lock.mkdir(parents=True)
        (lock / "run").write_text("ins-bbbbbbbbbbbb")
        argv = ai.ssh_argv("t2-dev", "unlock", {"run": "ins-cccccccccccc"})
        done = subprocess.run(["sh", "-c", argv[-1]], capture_output=True, text=True, env=self.env())
        self.assertEqual(json.loads(done.stdout)["released"], False)
        self.assertTrue(lock.exists())


class Rollback(Base):
    def installed(self, ref=None, files=("ah.py", "extra.py")):
        return self.install(ref=ref, files=files)

    def test_a_rollback_restores_the_old_bytes_and_runs_the_self_test(self):  # AC-8
        old = {n: self.live(n) for n in NAMES}
        out = self.installed()
        done = ai.rollback(out["run"], TICKET, (), self.mac, "s", "agent-x", self.runner, lambda t, x: None)
        self.assertEqual(done["result"], "restored")
        for n in ("ah.py", "extra.py"):
            self.assertEqual(self.live(n), old[n])
        self.assertEqual(self.rows("result")[-1]["result"], "restored")
        with self.assertRaises(ai.InstallError):
            ai.rollback(out["run"], TICKET, (), self.mac, "s", "agent-x", self.runner, lambda t, x: None)  # already rolled back

    def test_a_rollback_of_run_one_after_run_two_refuses_that_file_and_force_file_restores_it(self):  # AC-8, NEG-9
        run1 = self.installed()["run"]
        side = Path(self.tmp, "side4")
        git(self.tmp, "clone", "-q", str(self.origin), str(side))
        (side / "harness" / "hooks" / "ah.py").write_bytes(b"# run two\n")
        git(side, "add", "-A")
        git(side, "commit", "-q", "-m", "run two")
        git(side, "push", "-q", "origin", "main")
        ref2 = git(side, "rev-parse", "HEAD")
        run2 = self.install(ref=ref2, files=("ah.py",))["run"]
        with self.assertRaises(ai.InstallError) as caught:
            ai.rollback(run1, TICKET, (), self.mac, "s", "a", self.runner, lambda t, x: None)
        self.assertEqual(caught.exception.code, "live_changed")
        self.assertIn(run2, str(caught.exception))
        self.assertEqual(sha((self.hooks / "ah.py").read_bytes()), sha(b"# run two\n"))
        ai.rollback(run1, TICKET, ("ah.py",), self.mac, "s", "a", self.runner, lambda t, x: None)
        self.assertEqual(self.live("ah.py"), sha(self.base_bytes("ah.py")))
        self.assertEqual(self.rows("start")[-1]["forced"], ["ah.py"])

    def test_a_tampered_host_backup_falls_back_to_the_local_copy_and_both_tampered_refuse(self):  # AC-8, NEG-9
        run = self.installed()["run"]
        backup = self.hooks / ".ah-install" / "backups" / run / "ah.py"
        backup.write_bytes(b"tampered")
        ai.rollback(run, TICKET, (), self.mac, "s", "a", self.runner, lambda t, x: None)
        self.assertEqual(self.live("ah.py"), sha(self.base_bytes("ah.py")))
        run2 = self.installed()["run"]
        (self.hooks / ".ah-install" / "backups" / run2 / "ah.py").write_bytes(b"tampered")
        (self.mac / ".agent-harness" / "install-backups" / run2 / "ah.py").write_bytes(b"tampered too")
        with self.assertRaises(ai.InstallError):
            ai.rollback(run2, TICKET, (), self.mac, "s", "a", self.runner, lambda t, x: None)
        self.assertEqual(self.live("ah.py"), sha(self.base_bytes("ah.py") + b"\n# c1\n"))
        self.assertEqual(ai.unfinished_runs(self.mac, "t2-dev"), [])  # r1c H1: a refusal before any write must not wedge the host

    def test_unknown_run_other_hosts_run_and_another_unfinished_run_refuse(self):  # AC-8, NEG-9
        with self.assertRaises(ai.InstallError):
            ai.rollback("ins-000000000000", TICKET, (), self.mac, "s", "a", self.runner, lambda t, x: None)
        self.inject = ("commit", 1, "after")
        with self.assertRaises(ai.InstallError):
            self.install()
        other = ai.new_run_id()
        ai.audit(self.mac, {"event": "start", "kind": "install", "run": other, "host": "t2-dev", "files": {}, "ref": self.c1})
        ai.audit(self.mac, {"event": "result", "run": other, "host": "t2-dev", "result": "installed"})
        self.inject = None
        with self.assertRaises(ai.InstallError) as caught:
            ai.rollback(other, TICKET, (), self.mac, "s", "a", self.runner, lambda t, x: None)
        self.assertEqual(caught.exception.code, "unfinished_run")

    def test_a_rollback_is_never_blocked_by_a_failing_self_test(self):  # AC-8
        run = self.installed()["run"]
        before = self.rows("start")[0]["baseline"]
        self.assertTrue(before)
        (self.hooks / "doctor.py").write_bytes(b"import sys\nprint('not json')\nsys.exit(0)\n")
        done = ai.rollback(run, TICKET, (), self.mac, "s", "a", self.runner, lambda t, x: None)
        self.assertEqual(done["result"], "restored")


def ssh_localhost_works():
    try:
        return subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", "localhost", "true"], capture_output=True, timeout=15).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


@unittest.skipUnless(ssh_localhost_works(), "this machine does not accept ssh to localhost with a key (BatchMode)")
class RealSsh(Base):
    """AC-3/AC-6: the real ssh transport and the remote login shell, on a disposable HOME (a `HOME=` prefix, test only)."""

    def test_a_real_ssh_install_and_a_bad_file_two_that_changes_nothing(self):
        prefix = "HOME=%s " % __import__("shlex").quote(str(self.host_home))
        with mock.patch.object(ai, "HOSTS", ("localhost",)), mock.patch.object(ai, "REMOTE_PREFIX", prefix):
            out = ai.install_files("localhost", self.c1, ["ah.py", "extra.py"], TICKET, False, self.mac, "s", "a", subprocess.run, lambda t, x: None)
        self.assertEqual(out["result"], "installed")
        self.assertEqual(self.live("ah.py"), out["files"]["ah.py"]["new_sha"])


class Wiring(Base):
    def cli(self, *argv):
        out = io.StringIO()
        with mock.patch.dict(os.environ, {"AH_HOME": str(self.mac), "CLAUDE_CODE_SESSION_ID": "s1"}), redirect_stdout(out):
            code = ah.main(["install-files", *argv])
        return code, out.getvalue()

    def test_the_command_is_wired_and_installed(self):
        text = (ROOT / "install.py").read_text() + (ROOT / "install_codex.py").read_text()
        self.assertIn("ah_install.py", text)
        with mock.patch.object(ai, "install_files", return_value={"ok": True, "result": "dry_run"}) as run:
            code, text = self.cli("--host", "t2-dev", "--from-ref", self.c1, "--file", "ah.py", "--dry-run")
        self.assertEqual(code, 0)
        self.assertTrue(run.call_args[0][4])

    def test_bad_input_exits_2_and_a_non_success_result_keeps_its_exit_code(self):  # AC-5
        code, text = self.cli("--host", "dev2", "--from-ref", self.c1, "--file", "ah.py", "--ticket", TICKET)
        self.assertEqual(code, 2)
        err = ai.InstallError("unknown", "unknown on t2-dev", 5, {"ok": False, "result": "unknown"})
        with mock.patch.object(ai, "install_files", side_effect=err):
            code, text = self.cli("--host", "t2-dev", "--from-ref", self.c1, "--file", "ah.py", "--ticket", TICKET)
        self.assertEqual(code, 5)
        self.assertIn('"result": "unknown"', text)

    def test_the_local_targets_are_wired_and_an_unknown_name_exits_2(self):  # goodqa#15913 AC-1, NEG-2
        for host in ("local", "local-codex"):
            with self.subTest(host), mock.patch.object(ai, "install_files", return_value={"ok": True, "result": "dry_run"}) as run:
                code, _text = self.cli("--host", host, "--from-ref", self.c1, "--file", "ah.py", "--dry-run")
                self.assertEqual(code, 0)
                self.assertEqual(run.call_args[0][0], host)
        code, _text = self.cli("--host", "mac", "--from-ref", self.c1, "--file", "ah.py", "--ticket", TICKET)
        self.assertEqual(code, 2)

    def test_local_real_runs_resumes_and_rollbacks_run_whole_in_their_own_session_and_nothing_else(self):  # AC-8, NEG-21
        for run, host in (("ins-00000000000a", "local"), ("ins-00000000000b", "t2-dev"), ("ins-00000000000c", "local-codex")):
            ai.audit(self.mac, {"event": "start", "kind": "install", "run": run, "host": host, "ref": self.c1, "files": {}})
        real = ["--host", "local", "--from-ref", self.c1, "--file", "ah.py", "--ticket", TICKET]
        own_cases = (real, ["--host", "local-codex", "--from-ref", self.c1, "--file", "ah.py", "--ticket", TICKET],
                     # a resume or rollback goes by the run's own start row, as resume() and rollback() do, not by --host
                     ["--host", "t2-dev", "--resume", "ins-00000000000a", "--ticket", TICKET],
                     ["--host", "t2-dev", "--rollback", "ins-00000000000c", "--ticket", TICKET])
        inline_cases = (["--host", "local", "--from-ref", self.c1, "--file", "ah.py", "--dry-run"],
                        ["--host", "t2-dev", "--from-ref", self.c1, "--file", "ah.py", "--ticket", TICKET],
                        ["--host", "local", "--resume", "ins-00000000000b", "--ticket", TICKET],
                        ["--host", "local", "--rollback", "ins-0000000000ff", "--ticket", TICKET])  # unknown here: refused inline
        done = {"ok": True, "result": "dry_run"}
        with mock.patch.object(ai, "run_in_own_session", return_value=4) as own, \
                mock.patch.object(ai, "install_files", return_value=done), mock.patch.object(ai, "resume", return_value=done), \
                mock.patch.object(ai, "rollback", return_value=done):
            for argv in own_cases:
                with self.subTest(argv):
                    own.reset_mock()
                    self.assertEqual(self.cli(*argv)[0], 4)  # the session's exit status is the command's
                    self.assertEqual(own.call_args[0][0], ["install-files", *argv])  # the same command line, unchanged
            for argv in inline_cases:
                with self.subTest(argv):
                    own.reset_mock()
                    self.cli(*argv)
                    own.assert_not_called()
            own.reset_mock()
            with mock.patch.dict(os.environ, {ai.IN_SESSION_ENV: "1"}):
                self.assertEqual(self.cli(*real)[0], 0)  # the copy in its own session runs the install itself
            own.assert_not_called()


CODEX_NAMES = ("command_guard.py", "ah.py", "extra.py")  # doctor.py is a Claude-only hook here, as in the real lists
HOOK_ENTRY = "command_guard_hook.py"  # listed by both installers here (as in the real lists); a commit adds it when a test needs it
ALLOW_ALL = b"import sys\nprint('{\"verdict\": \"allow\", \"message\": \"\"}')\n"
FAIL_OPEN_HOOK = b"import sys\nsys.stdin.buffer.read()\nsys.exit(0)\n"  # a hook entry that allows everything, as a crashing hook does on Codex


class LocalBase(Base):
    """goodqa#15913: the local targets run the SAME constant program as a local subprocess, never ssh. On one machine the
    caller's home and the target's home are one directory, so the audit file, the local backup copies and the hooks share it."""

    def setUp(self):
        super().setUp()
        self.mac = self.host_home
        self.codex = self.host_home / ".codex" / "agent-harness"
        self.envs = []

    def write_commit(self, files, message, branch=None):
        (self.work / "install_codex.py").write_text("DELIVERY_HELPERS = (\n    # a comment, as in the real file\n    %s)\n"
                                                    % "".join("%r, " % n for n in CODEX_NAMES + (HOOK_ENTRY,)))
        super().write_commit(files, message, branch)
        (self.work / "install.py").write_text("HOOKS = %r\n" % (NAMES + (HOOK_ENTRY,),))
        git(self.work, "add", "-A")
        git(self.work, "commit", "-q", "--amend", "--no-edit")

    def make_codex(self):
        shutil.copytree(HOOKS, self.codex, ignore=shutil.ignore_patterns("__pycache__", "doctor.py"))
        for n in CODEX_NAMES:
            (self.codex / n).write_bytes(self.base_bytes(n))

    def push(self, files, label):
        side = Path(self.tmp, "side-" + label)
        git(self.tmp, "clone", "-q", str(self.origin), str(side))
        for name, data in files.items():
            (side / "harness" / "hooks" / name).write_bytes(data)
        git(side, "add", "-A")
        git(side, "commit", "-q", "-m", label)
        git(side, "push", "-q", "origin", "main")
        return git(side, "rev-parse", "HEAD")

    def runner(self, argv, input=None, capture_output=True, timeout=None, env=None, **kw):
        self.calls.append(list(argv))
        self.assertEqual(argv[:3], [sys.executable, "-I", "-c"])
        self.assertNotIn("ssh", " ".join(argv[:1] + argv[4:]))
        key = argv[4]
        self.envs.append(dict(env or {}))
        self.counts[key] = self.counts.get(key, 0) + 1
        if self.inject and self.inject[0] == key and self.counts[key] == self.inject[1]:
            if len(self.inject) > 2 and self.inject[2] == "after":
                subprocess.run(argv, input=input, env=env, capture_output=True, timeout=300)
            raise subprocess.TimeoutExpired(argv, 1)
        return subprocess.run(argv, input=input, env=env, capture_output=True, timeout=300)

    def install(self, ref=None, files=("ah.py", "extra.py"), dry_run=False, ticket=TICKET, host="local", poster=None, **kw):
        posted = kw.setdefault("posted", [])
        return ai.install_files(host, ref or self.c1, list(files), ticket, dry_run, self.mac, "sess", "agent-x", self.runner,
                                poster or (lambda t, text: posted.append((t, text))))

    def codex_sha(self, name):
        return sha((self.codex / name).read_bytes())

    def no_temp_files(self, folder):
        return not [p.name for p in folder.iterdir() if p.name.endswith(".ah-install-tmp")]


class LocalTarget(LocalBase):
    def test_a_local_install_runs_the_same_program_without_ssh_and_reports_every_sha(self):  # AC-1, NEG-8
        old = {n: self.live(n) for n in NAMES}
        posted = []
        with mock.patch.dict(os.environ, {"AH_AGENT_ID": "agent-sub", "PYTHONPATH": "/tmp/evil", "AH_GUARD_OFF": "1",
                                          "PATH": ".:relbin:" + os.environ.get("PATH", "/usr/bin:/bin")}):
            out = self.install(files=("ah.py", "extra.py", "command_guard.py"), posted=posted)
        self.assertEqual(out["result"], "installed")
        self.assertEqual(out["host"], "local")
        for n in ("ah.py", "extra.py", "command_guard.py"):
            self.assertEqual(out["files"][n]["old_sha"], old[n])
            self.assertEqual(self.live(n), out["files"][n]["new_sha"])
            self.assertEqual(sha((self.hooks / ".ah-install" / "backups" / out["run"] / n).read_bytes()), old[n])
            self.assertEqual(sha((self.mac / ".agent-harness" / "install-backups" / out["run"] / n).read_bytes()), old[n])
            self.assertFalse((self.hooks / ("." + n + ".ah-install-tmp")).exists())
        self.assertEqual(self.live("doctor.py"), old["doctor.py"])
        self.assertTrue(self.calls)
        self.assertTrue(all(c[-1] == "claude" for c in self.calls))
        for env in self.envs:
            self.assertEqual(env.get("HOME"), str(self.mac))
            self.assertLessEqual(set(env), {"HOME", "PATH", "LANG", "LC_ALL", "TMPDIR", "USER", "LOGNAME", "SHELL"})
            self.assertTrue(all(p.startswith("/") for p in env["PATH"].split(os.pathsep)), env["PATH"])  # no relative entry
        rows = self.rows()
        self.assertEqual([(r["event"], r.get("host")) for r in rows], [("start", "local"), ("result", "local")])  # no second host row
        self.assertEqual(rows[1]["result"], "installed")
        self.assertEqual(len(posted), 1)
        self.assertIn("on local: installed (run %s)" % out["run"], posted[0][1])
        self.assertFalse((self.hooks / ".ah-install" / "lock").exists())
        self.assertEqual(out["selftest_after"]["hook"], HOOK_OK)  # the registered entry ran on both payloads (AC-10)

    def test_an_allow_all_guard_after_a_local_install_is_rolled_back_guard_first(self):  # AC-1, NEG-3
        ref = self.push({"command_guard.py": b"import sys\nprint('{\"verdict\": \"allow\", \"message\": \"\"}')\n"}, "allow-all")
        before = {n: self.live(n) for n in NAMES}
        restores = []
        real = ai.Remote.call

        def spy(self_, op, args=None, data=None, **kw):
            if op == "restore":
                restores.append([i["name"] for i in args["items"]])
            return real(self_, op, args, data, **kw)
        with mock.patch.object(ai.Remote, "call", spy), self.assertRaises(ai.InstallError) as caught:
            self.install(ref=ref, files=("ah.py", "command_guard.py"))
        self.assertEqual(caught.exception.exit_code, 4)
        self.assertEqual(caught.exception.data["result"], "rolled_back")
        self.assertEqual(restores[0][0], "command_guard.py")
        self.assertEqual({n: self.live(n) for n in NAMES}, before)
        self.assertEqual(self.rows("result")[-1]["host"], "local")

    def test_a_local_rollback_and_a_local_resume_by_run_id(self):  # AC-4
        old = {n: self.live(n) for n in NAMES}
        run = self.install()["run"]
        done = ai.rollback(run, TICKET, (), self.mac, "s", "a", self.runner, lambda t, x: None)
        self.assertEqual(done["result"], "restored")
        self.assertEqual({n: self.live(n) for n in NAMES}, old)
        self.inject = ("commit", self.counts.get("commit", 0) + 1, "after")  # the commit ran and its answer was lost: unknown
        with self.assertRaises(ai.InstallError) as caught:
            self.install()
        self.inject = None
        self.assertEqual(caught.exception.data["result"], "unknown")
        again = ai.resume(caught.exception.data["run"], TICKET, self.mac, "s", "a", self.runner, lambda t, x: None)
        self.assertEqual(again["result"], "installed")
        self.assertEqual(self.live("ah.py"), again["files"]["ah.py"]["new_sha"])

    def test_a_local_dry_run_changes_nothing_and_takes_no_lock(self):  # AC-1, NEG-11
        before = sorted((p.name, p.stat().st_size, p.stat().st_mtime_ns, p.stat().st_ino) for p in self.hooks.iterdir())
        out = self.install(dry_run=True, ticket=None, files=("ah.py", "command_guard.py"))
        self.assertEqual(out["result"], "dry_run")
        self.assertEqual({n: v["action"] for n, v in out["files"].items()}, {"ah.py": "replaced", "command_guard.py": "replaced"})
        self.assertEqual(sorted((p.name, p.stat().st_size, p.stat().st_mtime_ns, p.stat().st_ino) for p in self.hooks.iterdir()), before)
        self.assertFalse((self.hooks / ".ah-install").exists())
        self.assertEqual(self.counts.get("stage"), None)

    def test_a_local_rollback_is_never_blocked_by_a_failing_self_test(self):  # AC-4, NEG-12
        old = self.live("ah.py")
        run = self.install()["run"]
        (self.hooks / "doctor.py").write_bytes(b"import sys\nprint('not json')\nsys.exit(0)\n")
        done = ai.rollback(run, TICKET, (), self.mac, "s", "a", self.runner, lambda t, x: None)
        self.assertEqual(done["result"], "restored")
        self.assertIn("selftest_note", done)
        self.assertEqual(self.live("ah.py"), old)

    def test_an_unfinished_local_run_blocks_only_its_own_target(self):  # AC-4, NEG-7
        self.inject = ("commit", 1, "after")
        with self.assertRaises(ai.InstallError):
            self.install()
        self.inject = None
        self.assertEqual(len(ai.unfinished_runs(self.mac, "local")), 1)
        self.assertEqual(ai.unfinished_runs(self.mac, "local-codex"), [])
        self.assertEqual(ai.unfinished_runs(self.mac, "t2-dev"), [])
        error = self.refused()
        self.assertEqual(error.code, "unfinished_run")
        ai.audit(self.mac, {"event": "start", "kind": "install", "run": "ins-00000000000a", "host": "t2-dev", "files": {}})
        self.assertEqual(len(ai.unfinished_runs(self.mac, "local")), 1)  # a remote run never counts for the local target

    def test_names_that_only_look_local_refuse_before_any_call(self):  # NEG-2
        good = dict(host="local", ref=self.c1, files=["ah.py"], ticket=TICKET, dry_run=False, resume=None, rollback=None, force_files=())
        ai.check_inputs(**good)
        ai.check_inputs(**dict(good, host="local-codex"))
        for host in ("mac", "localhost", "local;ls", "LOCAL", "local ", "local-claude", "./local", "local-codex2"):
            with self.subTest(host), self.assertRaises(ai.InstallError) as caught:
                ai.check_inputs(**dict(good, host=host))
            self.assertEqual(caught.exception.exit_code, 2)
        self.assertEqual(self.calls, [])

    def test_the_script_refuses_an_unknown_root_and_the_remote_argv_has_none(self):  # NEG-9, AC-6
        env = {"HOME": str(self.mac), "PATH": "/usr/bin:/bin"}
        done = subprocess.run([sys.executable, "-I", "-c", ai.REMOTE_SCRIPT, "probe", json.dumps({"names": ["ah.py"]}), "other"],
                              capture_output=True, text=True, env=env)
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("bad root", done.stderr)
        done = subprocess.run(ai.local_argv("codex", "probe", {"names": ["ah.py"]}), capture_output=True, text=True, env=env)
        self.assertNotEqual(done.returncode, 0)  # the program itself refuses a missing directory, with a reason, not a traceback
        self.assertEqual(done.stderr.strip().splitlines()[-1], "the hooks directory does not exist")
        argv = ai.ssh_argv("t2-dev", "probe", {"names": ["ah.py"]})
        self.assertTrue(argv[-1].endswith(__import__("shlex").quote(json.dumps({"names": ["ah.py"]}))))

    def test_local_reports_the_codex_copies_that_differ_from_what_it_installed(self):  # AC-3
        self.make_codex()
        out = self.install(files=("ah.py", "doctor.py"))
        self.assertEqual(out["result"], "installed")
        self.assertEqual(out["codex_differs"], ["ah.py"])  # doctor.py has no Codex copy
        self.assertIn("--host local-codex", out["note"])
        self.assertEqual(self.codex_sha("ah.py"), sha(self.base_bytes("ah.py")))  # reported, never written
        self.install(host="local-codex", files=("ah.py",))
        again = self.install(files=("ah.py", "doctor.py"))
        self.assertEqual(again["result"], "already_current")
        self.assertEqual(again.get("codex_differs", []), [])

    def test_a_rerun_at_the_same_commit_is_already_current_with_no_backup_stage_or_lock(self):  # AC-9
        first = self.install(files=("ah.py", "command_guard.py"))
        self.assertEqual(first["result"], "installed")
        self.counts.clear()
        posted = []
        out = self.install(files=("ah.py", "command_guard.py"), posted=posted)
        self.assertEqual((out["result"], out["exit_code"]), ("already_current", 0))
        self.assertEqual({n: v["action"] for n, v in out["files"].items()}, {"ah.py": "already_current", "command_guard.py": "already_current"})
        self.assertFalse((self.hooks / ".ah-install" / "backups" / out["run"]).exists())
        self.assertFalse((self.mac / ".agent-harness" / "install-backups" / out["run"]).exists())
        self.assertEqual({k for k in self.counts if k in ("lock", "stage", "commit", "restore", "read_backup")}, set())
        rows = [r for r in self.rows() if r.get("run") == out["run"]]
        self.assertEqual([(r["event"], r.get("host"), r.get("result")) for r in rows],
                         [("start", "local", None), ("result", "local", "already_current")])
        self.assertEqual(len(posted), 1)
        self.assertIn("on local: already_current (run %s)" % out["run"], posted[0][1])

    def test_a_local_run_whose_ticket_comment_fails_exits_6_and_keeps_the_real_result_row(self):  # AC-11, NEG-18
        def down(_ticket, _text):
            raise RuntimeError("ticket service down")
        with self.assertRaises(ai.InstallError) as caught:
            self.install(files=("ah.py",), poster=down)
        error = caught.exception
        self.assertEqual((error.code, error.exit_code), ("comment_failed", 6))
        self.assertEqual((error.data["result"], error.data["ok"], error.data["comment_failed"]), ("installed", False, True))
        self.assertIn("post it by hand", error.data["reason"])
        self.assertEqual(self.rows("result")[-1]["result"], "installed")  # the files are installed: the row says so
        self.assertEqual(self.live("ah.py"), error.data["files"]["ah.py"]["new_sha"])
        with self.assertRaises(ai.InstallError) as caught:  # a poster that reports failure counts too, on a rerun as well
            self.install(files=("ah.py",), poster=lambda t, x: False)
        self.assertEqual((caught.exception.exit_code, caught.exception.data["result"]), (6, "already_current"))
        # `ah ticket comment` failing is seen through its exit status, not only through an exception
        with mock.patch.object(ai.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, b"", b"")):
            self.assertIs(ai.post_comment(TICKET, "x", None), False)
        with mock.patch.object(ai.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, b"", b"")) as run:
            self.assertIs(ai.post_comment(TICKET, "x", None), True)
        self.assertEqual(run.call_args[0][0][:5], [sys.executable, "-I", ai.AH_PY, "ticket", "comment"])  # isolated, no PATH lookup

    def test_the_hook_probe_runs_the_entry_exactly_as_both_installers_register_it(self):  # AC-10
        self.assertIn('"command": "python3", "args": [str(claude / "hooks" / "command_guard_hook.py"), "hook"]', (ROOT / "install.py").read_text())
        self.assertIn("return 'python3 ' + shlex.quote(str(codex_home / 'agent-harness' / 'command_guard_hook.py')) + verb",
                      (ROOT / "install_codex.py").read_text())
        (self.hooks / HOOK_ENTRY).write_bytes(b"import os, sys\nsys.stdin.read()\nwith open(os.path.expanduser('~/probe-record.txt'), 'a') as f:\n"
                                              b"    f.write('%d %s\\n' % (sys.flags.isolated, ' '.join(sys.argv[1:])))\n")
        ai.Remote("local", self.runner, self.mac).call("selftest", timeout=ai.SELFTEST_TIMEOUT)
        self.assertEqual((self.mac / "probe-record.txt").read_text().splitlines(), ["0 hook", "0 hook"])  # python3 ENTRY hook, no -I

    def test_codex_home_elsewhere_refuses_local_codex_and_is_noted_by_local(self):  # AC-3, NEG-19
        self.make_codex()
        other = Path(self.tmp, "other-codex")
        with mock.patch.dict(os.environ, {"CODEX_HOME": str(other)}):
            with mock.patch.object(ai, "fetch_source", side_effect=AssertionError("fetched before checking CODEX_HOME")):
                error = self.refused(host="local-codex", files=("ah.py",))
            self.assertIn("CODEX_HOME", str(error))
            self.assertEqual(self.rows("start"), [])
            out = self.install(files=("ah.py",))
            self.assertEqual(out["codex_home"], str(other))
            self.assertIn("CODEX_HOME is set to %s" % other, out["note"])
        self.assertEqual(self.codex_sha("ah.py"), sha(self.base_bytes("ah.py")))
        for same in (str(self.host_home / ".codex"), ""):  # the default directory spelled out, or empty: accepted
            with self.subTest(same), mock.patch.dict(os.environ, {"CODEX_HOME": same}):
                self.assertIsNone(ai.codex_home_elsewhere(self.mac))
        with mock.patch.dict(os.environ, {"CODEX_HOME": str(self.host_home / ".codex")}):
            self.assertEqual(self.install(host="local-codex", files=("ah.py",))["result"], "installed")

    def test_a_symlinked_claude_or_codex_parent_refuses_before_any_write(self):  # NEG-20
        self.make_codex()
        for host, parent, folder in (("local", ".claude", "hooks"), ("local-codex", ".codex", "agent-harness")):
            with self.subTest(host):
                real = self.host_home / ("real" + parent)
                (self.host_home / parent).rename(real)
                os.symlink(real, self.host_home / parent)
                before = sorted((p.name, p.stat().st_mtime_ns) for p in (real / folder).iterdir())
                error = self.refused(host=host, files=("ah.py",))
                self.assertIn("parent (~/%s) is a symlink" % parent, str(error))
                self.assertEqual(sorted((p.name, p.stat().st_mtime_ns) for p in (real / folder).iterdir()), before)
                self.assertEqual(self.rows("start"), [])

    def test_the_hook_probes_are_absolute_after_the_install_and_never_compared_with_the_baseline(self):  # AC-10, NEG-16
        guard = {"allow": {"exit": 0, "verdict": "allow", "rule": ""}}
        doctor = {"flags": True, "failing": []}
        old_host = {"guard": guard, "doctor": doctor, "hook": {"hook_deny_wal": HOOK_OK["hook_deny_wal"],
                                                                "hook_subagent_local": {"exit": 0, "rule": ""}}}
        self.assertIsNone(ai.selftest_worse(old_host, {"guard": guard, "doctor": doctor, "hook": HOOK_OK}))  # the mini today
        self.assertIn("hook_subagent_local", ai.selftest_worse(old_host, old_host))  # an old guard left in place
        for bad in ({"exit": 0, "rule": ""}, {"exit": 2, "rule": ""}, {"exit": None, "rule": "", "error": "TimeoutExpired"},
                    {"exit": 2, "rule": "guard_failure"}):  # allow, a missing entry (python exits 2), a hang, the fallback
            with self.subTest(bad):
                after = {"guard": guard, "doctor": doctor, "hook": dict(HOOK_OK, hook_deny_wal=bad)}
                self.assertIn("hook_deny_wal", ai.selftest_worse({"guard": guard, "doctor": doctor, "hook": HOOK_OK}, after))
        self.assertIn("hook_deny_wal", ai.selftest_worse({"guard": guard, "doctor": doctor}, {"guard": guard, "doctor": doctor}))

    def test_a_fail_open_hook_entry_is_rolled_back_on_both_local_targets(self):  # AC-10, NEG-16
        self.make_codex()
        ref = self.push({HOOK_ENTRY: FAIL_OPEN_HOOK}, "fail-open-hook")
        for host, folder in (("local", self.hooks), ("local-codex", self.codex)):
            with self.subTest(host):
                before = sha((folder / HOOK_ENTRY).read_bytes())
                with self.assertRaises(ai.InstallError) as caught:
                    self.install(host=host, ref=ref, files=(HOOK_ENTRY,))
                self.assertEqual((caught.exception.exit_code, caught.exception.data["result"]), (4, "rolled_back"))
                self.assertIn("hook entry probe hook_deny_wal", caught.exception.data["reason"])
                self.assertEqual(sha((folder / HOOK_ENTRY).read_bytes()), before)
                self.assertTrue(self.no_temp_files(folder))


DRIVER = r'''
import json, sys
cfg = json.loads(open(sys.argv[1]).read())
sys.path.insert(0, cfg["hooks"])
import ah_install as ai
ai.CANONICAL_URL, ai.ALLOW_FILE, ai.REMOTE_SCRIPT = cfg["url"], True, cfg["script"]
try:
    ai.install_files(cfg["host"], cfg["ref"], cfg["files"], cfg["ticket"], home=cfg["home"], session="s", agent="a",
                     poster=lambda t, x: None)
except ai.InstallError:
    pass
'''
FOREGROUND = r'''
import sys
sys.path.insert(0, sys.argv[1])
import ah_install as ai
sys.exit(ai.run_in_own_session(["install-files"], sys.argv[2], launcher=sys.argv[3:]))
'''
PROGRESS_FN = '''
def progress(what, name):
    with open(PROGRESS_PATH, "a") as f:
        f.write("%s %s %d %d\\n" % (what, name, os.getpid(), os.getsid(0)))
        f.flush()
        os.fsync(f.fileno())
    time.sleep(PROGRESS_DELAY)
'''


class LocalKill(LocalBase):
    """AC-8: the caller (ah.py inside a tool call) is SIGKILLed with its whole process group, as a tool-call timeout does,
    while the program is between two renames. A driver process stands in for the caller: it runs install_files with the
    DEFAULT runner and a copy of the program that records each rename and then sleeps."""

    FILES = ["ah.py", "extra.py", "command_guard.py"]

    def instrumented(self, progress, delay=1.0):
        script = ai.REMOTE_SCRIPT
        for old, new in (("STALE = 1800\n", "STALE = 1800\nPROGRESS_PATH = %r\nPROGRESS_DELAY = %r\n%s" % (str(progress), delay, PROGRESS_FN)),
                         ("        os.replace(t, p)\n", "        os.replace(t, p)\n        progress('commit', name)\n"),
                         ("        os.replace(t, live(name))\n", "        os.replace(t, live(name))\n        progress('restore', name)\n")):
            self.assertEqual(script.count(old), 1, old)
            script = script.replace(old, new)
        return script

    def drive(self, ref, progress, foreground=False):
        """The caller. foreground=False: install_files itself (each program step detached, the verdict in the caller).
        foreground=True: ah.main's foreground, which runs that same whole install in its own session and waits."""
        cfg = Path(self.tmp, "driver.json")
        cfg.write_text(json.dumps({"hooks": str(HOOKS), "url": "file://" + str(self.origin), "script": self.instrumented(progress),
                                   "host": "local", "ref": ref, "files": self.FILES, "ticket": TICKET, "home": str(self.mac)}))
        driver = Path(self.tmp, "driver.py")
        driver.write_text(DRIVER)
        argv = [sys.executable, "-I", str(driver), str(cfg)]
        if foreground:
            fg = Path(self.tmp, "foreground.py")
            fg.write_text(FOREGROUND)
            argv = [sys.executable, "-I", str(fg), str(HOOKS), str(self.mac)] + argv
        env = {"HOME": str(self.mac), "PATH": self.pybin + ":/usr/bin:/bin", "LC_ALL": "C", "TMPDIR": os.environ.get("TMPDIR", "/tmp")}
        self.caller_err = Path(self.tmp, "caller.err")
        with open(self.caller_err, "wb") as err:
            proc = subprocess.Popen(argv, env=env, start_new_session=True, stdout=subprocess.DEVNULL, stderr=err)
        self.addCleanup(self.reap, proc)
        return proc

    def wait_rows(self, event, seconds):
        deadline = time.time() + seconds
        while time.time() < deadline:
            if self.rows(event):
                return self.rows(event)
            time.sleep(0.05)
        self.fail("no %s row within %d s: the run stopped with its caller" % (event, seconds))

    @staticmethod
    def reap(proc):
        if proc.poll() is None:
            os.killpg(proc.pid, signal.SIGKILL)
        proc.wait()

    @staticmethod
    def lines(progress, what):
        return [line.split() for line in (progress.read_text().splitlines() if progress.exists() else []) if line.startswith(what + " ")]

    def wait_for(self, progress, what, count, seconds, proc=None):
        deadline = time.time() + seconds
        while time.time() < deadline:
            if len(self.lines(progress, what)) >= count:
                return self.lines(progress, what)
            if proc is not None and proc.poll() is not None:
                self.fail("the driver ended before %d %s rename(s)" % (count, what))
            time.sleep(0.02)
        self.fail("only %d of %d %s rename(s) happened: the program stopped with its caller" % (len(self.lines(progress, what)), count, what))

    def wait_gone(self, pid, seconds=60):
        deadline = time.time() + seconds
        while time.time() < deadline:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return
            time.sleep(0.05)
        self.fail("the program %d did not end" % pid)

    def kill_after(self, proc, progress, what):
        self.wait_for(progress, what, 1, 240, proc)
        os.killpg(proc.pid, signal.SIGKILL)  # the caller and its whole process group, mid-run
        proc.wait()
        done = self.wait_for(progress, what, len(self.FILES), 20)
        self.assertNotEqual(int(done[0][3]), proc.pid, "the program ran in the caller's session")
        self.wait_gone(int(done[0][2]))
        return [line[1] for line in done]

    def test_a_caller_killed_after_one_of_three_renames_does_not_stop_the_program(self):  # AC-8, NEG-13
        old = {n: self.live(n) for n in NAMES}
        new = {n: sha(self.base_bytes(n) + b"\n# c1\n") for n in self.FILES}
        progress = Path(self.tmp, "progress-commit.txt")
        order = self.kill_after(self.drive(self.c1, progress), progress, "commit")
        self.assertEqual(order, ["ah.py", "extra.py", "command_guard.py"])  # every other file first, the guard last
        self.assertEqual({n: self.live(n) for n in self.FILES}, new)
        self.assertTrue(self.no_temp_files(self.hooks))
        run = self.rows("start")[0]["run"]
        self.assertEqual(self.rows("result"), [])  # the caller died before its result row
        self.assertEqual(ai.unfinished_runs(self.mac, "local"), [run])
        done = ai.rollback(run, TICKET, (), self.mac, "s", "a", None, lambda t, x: None)  # the default (detached) runner
        self.assertEqual(done["result"], "restored")
        self.assertEqual({n: self.live(n) for n in NAMES}, old)
        self.assertEqual(ai.unfinished_runs(self.mac, "local"), [])

    def test_a_caller_killed_during_the_automatic_rollback_does_not_stop_the_restore(self):  # AC-8, NEG-14
        ref = self.push({"command_guard.py": ALLOW_ALL}, "allow-all-kill")
        old = {n: self.live(n) for n in NAMES}
        progress = Path(self.tmp, "progress-restore.txt")
        order = self.kill_after(self.drive(ref, progress), progress, "restore")
        self.assertEqual(order[0], "command_guard.py")  # the guard first on restore
        self.assertEqual({n: self.live(n) for n in NAMES}, old)
        self.assertTrue(self.no_temp_files(self.hooks))
        run = self.rows("start")[0]["run"]
        self.assertEqual(ai.unfinished_runs(self.mac, "local"), [run])
        done = ai.rollback(run, TICKET, (), self.mac, "s", "a", None, lambda t, x: None)
        self.assertEqual(done["result"], "restored")
        self.assertEqual(set(done["notes"]), set(self.FILES))  # every file was already back at its old sha
        self.assertEqual(ai.unfinished_runs(self.mac, "local"), [])

    def test_a_caller_side_timeout_leaves_the_local_program_running_in_its_own_session(self):  # AC-8, NEG-15
        marker = Path(self.tmp, "marker")
        code = ("import os, sys, time; time.sleep(1.5); open(sys.argv[1] + '.t', 'w').write(str(os.getsid(0))); "
                "os.replace(sys.argv[1] + '.t', sys.argv[1])")
        started = time.time()
        with self.assertRaises(subprocess.TimeoutExpired):
            ai.detached_run([sys.executable, "-I", "-c", code, str(marker)], timeout=0.3, env={"PATH": "/usr/bin:/bin"})
        self.assertLess(time.time() - started, 1.3)  # the caller is not held until the program ends
        deadline = time.time() + 20
        while not marker.exists() and time.time() < deadline:
            time.sleep(0.05)
        self.assertTrue(marker.exists(), "the program was killed at the caller's timeout")
        self.assertNotEqual(int(marker.read_text()), os.getsid(0))
        for host in ("local", "local-codex"):
            self.assertIs(ai.Remote(host, None, self.mac).runner, ai.detached_run)
        self.assertIs(ai.Remote("t2-dev", None).runner, subprocess.run)  # the fleet transport is unchanged

    def test_a_caller_killed_after_the_commit_still_gets_the_verdict_and_the_automatic_rollback(self):  # AC-8, NEG-21
        ref = self.push({"command_guard.py": ALLOW_ALL}, "allow-all-session")
        old = {n: self.live(n) for n in NAMES}
        progress = Path(self.tmp, "progress-session.txt")
        proc = self.drive(ref, progress, foreground=True)
        self.wait_for(progress, "commit", 1, 240, proc)
        os.killpg(proc.pid, signal.SIGKILL)  # ah.main's foreground and its whole process group, after the first live write
        proc.wait()
        notice = re.search(r"own session \(pid (\d+)\).*its output: (\S+)", self.caller_err.read_text())
        self.assertIsNotNone(notice, self.caller_err.read_text())
        restores = self.wait_for(progress, "restore", len(self.FILES), 240)
        self.assertEqual(restores[0][1], "command_guard.py")  # the verdict ran, and the rollback put the guard back first
        self.assertEqual([r["result"] for r in self.wait_rows("result", 120)], ["rolled_back"])
        self.wait_gone(int(notice.group(1)), 120)
        self.assertEqual({n: self.live(n) for n in NAMES}, old)
        self.assertEqual(ai.unfinished_runs(self.mac, "local"), [])
        self.assertTrue(self.no_temp_files(self.hooks))
        self.assertTrue(Path(notice.group(2)).exists())  # the caller died before relaying: the run's output is kept

    def test_a_run_killed_after_the_commit_is_finished_by_resume_with_the_verdict_and_the_rollback(self):  # AC-4, AC-8, NEG-22
        ref = self.push({"command_guard.py": ALLOW_ALL}, "allow-all-resume")
        old = {n: self.live(n) for n in NAMES}
        progress = Path(self.tmp, "progress-resume.txt")
        proc = self.drive(ref, progress)  # stands in for a kill that also ends the run's own session after the commit
        done = self.wait_for(progress, "commit", len(self.FILES), 240, proc)
        os.killpg(proc.pid, signal.SIGKILL)
        proc.wait()
        self.wait_gone(int(done[0][2]))
        self.assertEqual(self.live("command_guard.py"), sha(ALLOW_ALL))  # the allow-all guard is live, with no verdict yet
        run = self.rows("start")[0]["run"]
        self.assertEqual(self.rows("result"), [])
        self.assertEqual(ai.unfinished_runs(self.mac, "local"), [run])
        restore = Path(self.tmp, "progress-resume-restore.txt")
        with mock.patch.object(ai, "REMOTE_SCRIPT", self.instrumented(restore, 0.0)):
            with self.assertRaises(ai.InstallError) as caught:
                ai.resume(run, TICKET, self.mac, "s", "a", None, lambda t, x: None)  # the default (detached) runner
        self.assertEqual((caught.exception.exit_code, caught.exception.data["result"]), (4, "rolled_back"))
        self.assertEqual([line[1] for line in self.lines(restore, "restore")][0], "command_guard.py")
        self.assertEqual({n: self.live(n) for n in NAMES}, old)
        self.assertEqual(ai.unfinished_runs(self.mac, "local"), [])
        self.assertTrue(self.no_temp_files(self.hooks))

    def test_a_run_in_its_own_session_relays_its_output_and_exit_status_and_a_signal_is_unknown(self):  # AC-8
        code = ("import json, os, sys; print(json.dumps({'sid': os.getsid(0), 'marker': os.environ.get(%r)})); "
                "sys.stderr.write('note\\n'); sys.exit(4)" % ai.IN_SESSION_ENV)
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            self.assertEqual(ai.run_in_own_session(["install-files"], self.mac, launcher=[sys.executable, "-I", "-c", code]), 4)
        data = json.loads(out.getvalue())
        self.assertNotEqual(data["sid"], os.getsid(0))
        self.assertEqual(data["marker"], "1")  # the copy in its own session never starts another
        self.assertTrue(err.getvalue().endswith("note\n"))
        folder = self.mac.joinpath(*ai.SESSION_DIR)
        self.assertEqual((list(folder.iterdir()), stat.S_IMODE(folder.stat().st_mode)), ([], 0o700))  # relayed, then removed
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            killed = ai.run_in_own_session([], self.mac, launcher=[sys.executable, "-I", "-c", "import os, signal; os.kill(os.getpid(), signal.SIGKILL)"])
        self.assertEqual(killed, 5)


class LocalCodex(LocalBase):
    def test_local_codex_installs_into_the_codex_harness_directory_only(self):  # AC-2
        self.make_codex()
        claude_before = {n: self.live(n) for n in NAMES}
        out = self.install(host="local-codex", files=("ah.py", "command_guard.py"))
        self.assertEqual(out["result"], "installed")
        self.assertEqual(out["host"], "local-codex")
        for n in ("ah.py", "command_guard.py"):
            self.assertEqual(self.codex_sha(n), out["files"][n]["new_sha"])
            self.assertEqual(sha((self.codex / ".ah-install" / "backups" / out["run"] / n).read_bytes()), sha(self.base_bytes(n)))
        self.assertEqual({n: self.live(n) for n in NAMES}, claude_before)
        self.assertFalse((self.hooks / ".ah-install").exists())
        self.assertTrue(all(c[-1] == "codex" for c in self.calls))
        self.assertEqual({r.get("host") for r in self.rows()}, {"local-codex"})

    def test_a_name_outside_the_codex_list_refuses_before_any_call(self):  # NEG-5
        self.make_codex()
        error = self.refused(host="local-codex", files=("doctor.py",))
        self.assertIn("DELIVERY_HELPERS", str(error))
        self.assertEqual(self.calls, [])
        self.assertEqual(self.rows(), [])

    def test_no_codex_harness_directory_refuses_and_creates_nothing(self):  # NEG-4
        with mock.patch.object(ai, "fetch_source", side_effect=AssertionError("fetched before checking the directory")):
            error = self.refused(host="local-codex", files=("ah.py",))
        self.assertEqual(error.exit_code, 2)
        self.assertIn("does not exist", str(error))
        self.assertFalse((self.host_home / ".codex").exists())
        self.assertEqual(self.rows("start"), [])

    def test_a_symlinked_codex_directory_refuses(self):  # NEG-10: a planted link must not redirect the write
        self.make_codex()
        real = self.host_home / ".codex" / "elsewhere"
        self.codex.rename(real)
        os.symlink(real, self.codex)
        error = self.refused(host="local-codex", files=("ah.py",))
        self.assertIn("symlink", str(error))
        self.assertEqual(sha((real / "ah.py").read_bytes()), sha(self.base_bytes("ah.py")))

    def test_an_allow_all_guard_in_the_codex_directory_is_rolled_back(self):  # AC-2, NEG-3
        self.make_codex()
        ref = self.push({"command_guard.py": b"import sys\nprint('{\"verdict\": \"allow\", \"message\": \"\"}')\n"}, "codex-allow-all")
        before = {n: self.codex_sha(n) for n in CODEX_NAMES}
        with self.assertRaises(ai.InstallError) as caught:
            self.install(host="local-codex", ref=ref, files=("ah.py", "command_guard.py"))
        self.assertEqual(caught.exception.data["result"], "rolled_back")
        self.assertEqual({n: self.codex_sha(n) for n in CODEX_NAMES}, before)


if __name__ == "__main__":
    unittest.main()
