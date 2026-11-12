"""`ah install-files` (goodqa#15742): a local bare repository stands in for the canonical URL, a fake ssh runs the REAL constant
remote command string through `sh -c` against a temporary host HOME that holds the real command_guard.py and doctor.py.
Nothing here touches a real host or the real hooks directory."""
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
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
        before = {"guard": {"deny_hooks_copy": {"exit": 0, "verdict": "block", "rule": "log_delete/log-delete"}}, "doctor": {"flags": True, "failing": []}}
        after = {"guard": {"deny_hooks_copy": {"exit": 0, "verdict": "allow", "rule": ""}}, "doctor": {"flags": True, "failing": []}}
        self.assertIn("changed", ai.selftest_worse(before, after))
        self.assertIsNone(ai.selftest_worse(before, before))

    def test_only_new_doctor_failures_count_and_a_baseline_with_failures_passes(self):  # AC-4, NEG-4
        guard = {"allow": {"exit": 0, "verdict": "allow", "rule": ""}}
        before = {"guard": guard, "doctor": {"flags": True, "failing": ["a", "b"]}}
        self.assertIsNone(ai.selftest_worse(before, {"guard": guard, "doctor": {"flags": True, "failing": ["a"]}}))
        self.assertIn("new failing", ai.selftest_worse(before, {"guard": guard, "doctor": {"flags": True, "failing": ["a", "b", "c"]}}))
        self.assertIn("could not run", ai.selftest_worse(before, {"guard": guard, "doctor": {"flags": True, "failing": None}}))

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


if __name__ == "__main__":
    unittest.main()
