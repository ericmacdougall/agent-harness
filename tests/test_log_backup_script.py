"""harness/bin/log-backup.sh against a recording fake rclone and, where it matters, real rclone to a local remote.

Every run gets a scratch HOME and an explicit minimal environment (the equivalent of env -i). A canary file sits
beside the sources and must survive. Corpora are Python constants here, never shell text.
"""
import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "harness" / "bin" / "log-backup.sh"
REAL_RCLONE = shutil.which("rclone")

FAKE = """#!%(python)s
import json, os, sys, time
argv = sys.argv[1:]
with open(os.environ["FAKE_LOG"], "a") as h:
    h.write(json.dumps({"argv": argv, "rclone_env": sorted(k for k in os.environ if k.startswith("RCLONE_"))}) + "\\n")
if argv and argv[0] == "listremotes":
    print(os.environ.get("FAKE_REMOTES", "lessons-dropbox: dropbox"))
    sys.exit(0)
if argv and argv[0] == "copy":
    time.sleep(float(os.environ.get("FAKE_COPY_SLEEP", "0")))
    first = int(os.environ.get("FAKE_FAIL_FIRST", "0"))
    if first:
        counter = os.environ["FAKE_LOG"] + ".count"
        seen = int(open(counter).read()) if os.path.exists(counter) else 0
        open(counter, "w").write(str(seen + 1))
        if seen < first:
            sys.exit(1)
    match = os.environ.get("FAKE_FAIL_MATCH")
    if match and any(match in a for a in argv):
        sys.exit(1)
    real = os.environ.get("FAKE_DELEGATE")
    if real:
        os.execv(real, [real] + argv)
sys.exit(0)
"""

# Credential-named files planted in every source; none may reach the remote.
SECRET_NAMES = ["auth.json", "rclone.conf", "member.key", "x.key", "cert.pem", "a.p12", "a.token", "id_rsa", ".netrc",
                ".npmrc", "kit.json", ".env", ".env.local", "x.secret", ".credentials.json"]
SOURCES = [".claude/projects", ".claude/wals", ".codex/sessions", ".codex/archived_sessions", ".agent-harness/work"]
ORDINARY = {
    ".claude/projects/p1/a.jsonl": b"claude transcript A\n",
    ".claude/projects/p1/sub/b.jsonl": b"claude transcript B\n",
    ".claude/wals/s1/main.jsonl": b"wal line\n",
    ".codex/sessions/2026/x.jsonl": b"codex session\n",
    ".codex/archived_sessions/y.jsonl": b"archived\n",
    ".claude/history.jsonl": b"history\n",
    ".agent-harness/work/t1/notes.md": b"notes\n",
}


class Case(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="logbackup-test-")).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.home = self.tmp / "home"
        self.remote = self.tmp / "remote"
        self.remote.mkdir()
        self.fake = self.tmp / "bin" / "fakerclone"
        self.fake.parent.mkdir()
        self.fake.write_text(FAKE % {"python": sys.executable})
        self.fake.chmod(0o755)
        self.calls = self.tmp / "calls.jsonl"
        self.canary = self.tmp / "canary"
        self.canary.write_text("alive")
        for rel, data in ORDINARY.items():
            self.put(rel, data)
        self.logs = self.home / ".agent-harness" / "logs"

    def put(self, rel, data):
        path = self.home / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    def env(self, **extra):
        env = {"HOME": str(self.home), "PATH": "/usr/bin:/bin", "LOG_BACKUP_RCLONE": str(self.fake),
               "LOG_BACKUP_HOST": "testhost", "FAKE_LOG": str(self.calls)}
        env.update(extra)
        return env

    def run_script(self, script=SCRIPT, **extra):
        extra.setdefault("LOG_BACKUP_RETRY_SLEEP", "0")
        done = subprocess.run(["/bin/bash", str(script)], env=self.env(**extra), cwd=str(self.tmp),
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
        self.assertEqual(self.canary.read_text(), "alive")
        return done

    def local_run(self, **extra):
        """Real rclone, local directory as the remote."""
        if not REAL_RCLONE:
            self.skipTest("rclone not installed")
        return self.run_script(FAKE_DELEGATE=REAL_RCLONE, LOG_BACKUP_REMOTE=str(self.remote),
                               LOG_BACKUP_ALLOW_LOCAL="1", **extra)

    def recorded(self):
        if not self.calls.exists():
            return []
        return [json.loads(line) for line in self.calls.read_text().splitlines()]

    def copies(self):
        return [c["argv"] for c in self.recorded() if c["argv"][0] == "copy"]

    def remote_files(self):
        base = self.remote / "testhost"
        return {str(p.relative_to(base)) for p in base.rglob("*") if p.is_file()
                and not str(p.relative_to(base)).startswith("versions/")}

    def last_ok(self):
        return self.logs / "log-backup.last-ok"


ALLOWED_FLAGS = {"--tpslimit", "--transfers", "--contimeout", "--timeout", "--log-file", "--log-level", "--exclude-from", "--backup-dir"}


def assert_copy_only(test, calls):
    """Every rclone call is `copy` or `listremotes`; flags come from an allowlist; `--` precedes positionals;
    --backup-dir sits under the same remote's versions/ tree; nothing that deletes, syncs or moves."""
    for call in calls:
        argv = call["argv"]
        test.assertIn(argv[0], ("copy", "listremotes"), argv)
        if argv[0] == "listremotes":
            continue
        test.assertIn("--", argv, argv)
        flags = [a for a in argv[: argv.index("--")] if a.startswith("--")]
        for flag in flags:
            test.assertIn(flag, ALLOWED_FLAGS, argv)
            test.assertFalse(flag.startswith("--delete"), argv)
        src, dst = argv[argv.index("--") + 1:]
        if "--backup-dir" in argv:
            backup = argv[argv.index("--backup-dir") + 1]
            test.assertTrue(backup.startswith(dst.split("/.", 1)[0].rsplit("/", 1)[0] + "/versions/")
                            or "/versions/" in backup, argv)
            test.assertFalse(backup.startswith(dst + "/") or backup == dst, argv)


class Exclusion(Case):
    def plant_secrets(self):
        for source in SOURCES:
            for name in SECRET_NAMES:
                self.put(f"{source}/{name}", b"SECRET-MARKER\n")
        self.put(".claude/projects/goodqa-hive/ordinary-in-hive.txt", b"hive\n")
        self.put(".claude/projects/p1/node_modules/dep/index.js", b"dep\n")
        outside = self.tmp / "outside-secret"
        outside.write_text("SECRET-MARKER")
        os.symlink(outside, self.home / ".claude/projects/p1/linked")

    def test_credentials_never_reach_remote_and_ordinary_files_do(self):
        self.plant_secrets()
        done = self.local_run()
        self.assertEqual(done.returncode, 0, done.stderr)
        files = self.remote_files()
        expected = {rel if not rel.startswith(".claude/history") else rel for rel in ORDINARY}
        self.assertEqual(files, expected)  # exact, non-empty set
        self.assertGreaterEqual(len(files), 7)
        for path in (self.remote / "testhost").rglob("*"):
            if path.is_file():
                self.assertNotIn(b"SECRET-MARKER", path.read_bytes(), path)
        assert_copy_only(self, self.recorded())

    def test_control_without_a_filter_the_same_fixture_leaks(self):
        """Proves the fixture can fail: real rclone with no excludes copies the secrets the script withholds."""
        if not REAL_RCLONE:
            self.skipTest("rclone not installed")
        self.plant_secrets()
        empty = self.tmp / "empty.excludes"
        empty.write_text("# nothing\n")
        out = self.tmp / "unfiltered"
        done = subprocess.run([REAL_RCLONE, "copy", "--exclude-from", str(empty), "--", str(self.home / ".claude/projects"),
                               str(out)], env={"HOME": str(self.tmp), "PATH": "/usr/bin:/bin"}, capture_output=True)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertTrue((out / "auth.json").exists())
        self.assertTrue((out / "member.key").exists())

    def test_vm_dumps_never_appear_in_the_remote(self):
        for name in ("dump.vma", "dump.vma.zst"):
            self.put(f".agent-harness/work/t1/{name}", b"VMA")
            self.put(f".claude/projects/p1/{name}", b"VMA")
        done = self.local_run()
        self.assertEqual(done.returncode, 0, done.stderr)
        files = self.remote_files()
        self.assertEqual(files, set(ORDINARY))
        self.assertFalse([f for f in files if ".vma" in f])
        text = (ROOT / "harness" / "bin" / "log-backup.excludes").read_text().split()
        self.assertIn("*.vma", text)
        self.assertIn("*.vma.zst", text)

    def test_no_glob_expansion_and_no_symlink_following_flags(self):
        for name in ("a.secret", "b.secret"):
            (self.tmp / name).write_text("x")  # the cwd of the run holds files an unquoted glob would expand to
        self.run_script()
        for argv in self.copies():
            self.assertNotIn("--exclude", argv)
            self.assertIn("--exclude-from", argv)
            for flag in ("-L", "--copy-links", "--links", "-l"):
                self.assertNotIn(flag, argv)

    def test_excludes_file_names_the_required_credentials(self):
        text = (ROOT / "harness" / "bin" / "log-backup.excludes").read_text().split()
        for needed in ("auth.json", "rclone.conf", "member.key", "*.key", "*.pem", ".env", "*.secret", "goodqa-hive/**"):
            self.assertIn(needed, text)


class CopyOnly(Case):
    def test_only_copy_calls_with_allowlisted_flags(self):
        self.run_script()
        self.assertTrue(self.copies())
        assert_copy_only(self, self.recorded())

    def test_control_variant_with_a_delete_flag_or_moveto_fails_the_checker(self):
        text = SCRIPT.read_text()
        for needle, repl in (("args=(copy ", "args=(moveto "), ("--tpslimit 4", "--delete-after --tpslimit 4")):
            variant = self.tmp / "variant.sh"
            variant.write_text(text.replace(needle, repl))
            (self.tmp / "log-backup.excludes").write_text("*.secret\n")
            if self.calls.exists():
                self.calls.unlink()
            self.run_script(script=variant, LOG_BACKUP_EXCLUDES=str(ROOT / "harness/bin/log-backup.excludes"))
            with self.assertRaises(AssertionError):
                assert_copy_only(self, self.recorded())

    def test_local_deletion_does_not_delete_remote_copies(self):
        self.assertEqual(self.local_run().returncode, 0)
        before = self.remote_files()
        os.unlink(self.home / ".claude/projects/p1/a.jsonl")
        shutil.rmtree(self.home / ".codex/archived_sessions")
        shutil.rmtree(self.home / ".claude/wals")
        self.assertEqual(self.local_run().returncode, 0)
        self.assertEqual(self.remote_files(), before)
        self.assertEqual((self.remote / "testhost/.claude/projects/p1/a.jsonl").read_bytes(), ORDINARY[".claude/projects/p1/a.jsonl"])


class Versions(Case):
    def test_changed_and_truncated_files_keep_previous_bytes(self):
        self.assertEqual(self.local_run().returncode, 0)
        self.put(".claude/projects/p1/a.jsonl", b"changed\n")
        self.put(".claude/wals/s1/main.jsonl", b"")  # truncated, e.g. crash or full disk
        time.sleep(1.1)  # a new STAMP
        self.assertEqual(self.local_run().returncode, 0)
        kept = {p.read_bytes() for p in (self.remote / "testhost/versions").rglob("*") if p.is_file()}
        self.assertIn(ORDINARY[".claude/projects/p1/a.jsonl"], kept)
        self.assertIn(ORDINARY[".claude/wals/s1/main.jsonl"], kept)
        self.assertEqual((self.remote / "testhost/.claude/projects/p1/a.jsonl").read_bytes(), b"changed\n")
        for argv in self.copies():
            backup = argv[argv.index("--backup-dir") + 1]
            self.assertIn("/versions/", backup)
            self.assertFalse(backup.startswith(argv[-1] + "/"))

    def test_only_exact_zero_disables_versions(self):
        for value, expect in (("0", False), ("00", True), ("", True), ("false", True)):
            if self.calls.exists():
                self.calls.unlink()
            self.run_script(LOG_BACKUP_VERSIONS=value, LOG_BACKUP_REMOTE=str(self.remote), LOG_BACKUP_ALLOW_LOCAL="1")
            copies = self.copies()
            self.assertTrue(copies)
            self.assertEqual(all("--backup-dir" in c for c in copies), expect, value)
        self.assertIn("WARNING: versions disabled", (self.logs / "log-backup.log").read_text())


class Locking(Case):
    def holder(self, name="holder/log-backup.sh"):
        script = self.tmp / name
        script.parent.mkdir(exist_ok=True)
        script.write_text("#!/bin/sh\nsleep 60\n")
        proc = subprocess.Popen(["/bin/sh", str(script)])
        self.addCleanup(lambda: (proc.terminate(), proc.wait()))
        return proc

    def lock(self, pid):
        lock = self.logs / "log-backup.lock.d"
        lock.mkdir(parents=True)
        (lock / "pid").write_text(str(pid))
        return lock

    def test_live_holder_means_skip_not_success(self):
        proc = self.holder()
        time.sleep(0.3)
        self.lock(proc.pid)
        done = self.run_script()
        self.assertEqual(done.returncode, 0)
        self.assertEqual(self.recorded(), [])  # zero rclone calls
        self.assertTrue((self.logs / "log-backup.last-skip").exists())
        self.assertFalse(self.last_ok().exists())

    def test_skip_leaves_an_existing_last_ok_untouched(self):
        self.logs.mkdir(parents=True)
        self.last_ok().write_text("2020-01-01T00:00:00Z sources=1\n")
        os.utime(self.last_ok(), (1000, 1000))
        proc = self.holder()
        time.sleep(0.3)
        self.lock(proc.pid)
        self.run_script()
        self.assertEqual(self.last_ok().read_text(), "2020-01-01T00:00:00Z sources=1\n")
        self.assertEqual(int(self.last_ok().stat().st_mtime), 1000)

    def test_dead_pid_is_taken_over(self):
        dead = subprocess.Popen(["/usr/bin/true"])
        dead.wait()
        self.lock(dead.pid)
        self.assertEqual(self.run_script().returncode, 0)
        self.assertTrue(self.last_ok().exists())
        self.assertFalse((self.logs / "log-backup.lock.d").exists())

    def test_recycled_pid_of_another_program_is_taken_over(self):
        other = subprocess.Popen(["/bin/sleep", "60"])
        self.addCleanup(lambda: (other.terminate(), other.wait()))
        self.lock(other.pid)
        self.assertEqual(self.run_script().returncode, 0)
        self.assertTrue(self.last_ok().exists())

    def test_lock_older_than_a_day_is_taken_over_even_if_pid_looks_live(self):
        proc = self.holder()
        time.sleep(0.3)
        lock = self.lock(proc.pid)
        old = time.time() - 90000
        os.utime(lock, (old, old))
        self.assertEqual(self.run_script().returncode, 0)
        self.assertTrue(self.last_ok().exists())

    def test_lookalike_process_is_not_a_live_holder(self):
        # a command line containing "log-backup" but not the script (tail of the log) must not wedge the backup
        other = subprocess.Popen(["/bin/sh", "-c", "sleep 60", "log-backup.log"])
        self.addCleanup(lambda: (other.terminate(), other.wait()))
        time.sleep(0.3)
        self.lock(other.pid)
        self.assertEqual(self.run_script().returncode, 0)
        self.assertTrue(self.last_ok().exists())

    def test_two_simultaneous_takeovers_have_one_winner(self):
        dead = subprocess.Popen(["/usr/bin/true"])
        dead.wait()
        self.lock(dead.pid)
        procs = [subprocess.Popen(["/bin/bash", str(SCRIPT)], env=self.env(FAKE_COPY_SLEEP="1.5"), cwd=str(self.tmp),
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE) for _ in range(2)]
        for proc in procs:
            proc.communicate(timeout=120)
            self.assertEqual(proc.returncode, 0)
        primaries = [c for c in self.copies() if c[-2].endswith(".claude/projects")]
        self.assertEqual(len(primaries), 1)


class Failure(Case):
    def test_failed_source_fails_the_run_and_keeps_last_ok(self):
        self.logs.mkdir(parents=True)
        self.last_ok().write_text("2020-01-01T00:00:00Z sources=1\n")
        done = self.run_script(FAKE_FAIL_MATCH=".claude/wals")
        self.assertNotEqual(done.returncode, 0)
        self.assertEqual(self.last_ok().read_text(), "2020-01-01T00:00:00Z sources=1\n")
        self.assertTrue(any(c[-2].endswith(".agent-harness/work") for c in self.copies()))  # later sources still ran

    def test_file_changing_mid_copy_is_retried_and_the_run_can_still_succeed(self):
        done = self.run_script(FAKE_FAIL_FIRST="2")  # the first two copy attempts fail, e.g. hash changed mid-upload
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertTrue(self.last_ok().exists())
        self.assertIn("retry 1", (self.logs / "log-backup.log").read_text())

    def test_persistent_failure_exhausts_retries_and_is_not_fresh(self):
        done = self.run_script(FAKE_FAIL_FIRST="1000", LOG_BACKUP_RETRIES="1")
        self.assertNotEqual(done.returncode, 0)
        self.assertFalse(self.last_ok().exists())
        self.assertEqual(len(self.copies()), 2 * 6)  # six sources, one retry each

    def test_no_sources_or_no_primary_source_fails(self):
        shutil.rmtree(self.home)
        done = self.run_script()
        self.assertNotEqual(done.returncode, 0)
        self.assertFalse(self.last_ok().exists())
        self.put(".claude/wals/s1/main.jsonl", b"x")  # a non-primary source alone is not a backup
        done = self.run_script()
        self.assertNotEqual(done.returncode, 0)
        self.assertFalse(self.last_ok().exists())

    def test_success_writes_last_ok_with_start_time_atomically(self):
        done = self.run_script()
        self.assertEqual(done.returncode, 0, done.stderr)
        text = self.last_ok().read_text()
        self.assertRegex(text, r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ sources=\d+ remote=lessons-dropbox\n$")
        self.assertEqual([p.name for p in self.logs.glob("log-backup.last-ok.tmp*")], [])

    def test_rclone_missing_and_no_remote_give_one_line_errors(self):
        done = self.run_script(LOG_BACKUP_RCLONE="/nonexistent/rclone")
        self.assertEqual(done.returncode, 127)
        done = self.run_script(FAKE_REMOTES="")
        self.assertEqual(done.returncode, 3)
        self.assertEqual(len(done.stderr.decode().strip().splitlines()), 1)
        self.assertEqual(self.copies(), [])

    def test_remote_must_be_dropbox_or_crypt(self):
        done = self.run_script(FAKE_REMOTES="lessons-dropbox: sftp\ndropbox: s3")
        self.assertEqual(done.returncode, 3)
        self.assertEqual(self.copies(), [])

    def test_hostile_remote_overrides_are_refused_before_any_copy(self):
        bad = ["-x:y", ":webdav,url=http://evil.example:", "lessons-dropbox:../x", "a:b:c", "lessons-dropbox:$(id)",
               "lessons-dropbox:a b", "lessons-dropbox:a;b", "unconfigured:path", "/absolute/local", "nocolon",
               "--config=x:y"]
        for value in bad:
            if self.calls.exists():
                self.calls.unlink()
            done = self.run_script(LOG_BACKUP_REMOTE=value)
            self.assertEqual(done.returncode, 3, value)
            self.assertEqual(self.copies(), [], value)

    def test_remote_pin_detects_a_changed_remote(self):
        self.assertEqual(self.run_script().returncode, 0)
        done = self.run_script(FAKE_REMOTES="dropbox: dropbox")
        self.assertEqual(done.returncode, 4)
        self.assertIn(b"remote changed", done.stderr)

    def test_inherited_rclone_options_are_dropped_but_config_passes(self):
        self.run_script(RCLONE_DELETE_AFTER="true", RCLONE_CONFIG="/nonexistent/rclone.conf")
        seen = {k for c in self.recorded() for k in c["rclone_env"]}
        self.assertEqual(seen, {"RCLONE_CONFIG"})

    def test_explicit_override_must_also_be_dropbox_or_crypt(self):
        done = self.run_script(LOG_BACKUP_REMOTE="evil:Backups", FAKE_REMOTES="evil: sftp")
        self.assertEqual(done.returncode, 3)
        self.assertEqual(self.copies(), [])

    def test_gutted_excludes_file_is_refused(self):
        for text in ("", "# only a comment\n", "auth.json\n"):
            gutted = self.tmp / "gutted.excludes"
            gutted.write_text(text)
            done = self.run_script(LOG_BACKUP_EXCLUDES=str(gutted))
            self.assertEqual(done.returncode, 2, text)
        self.assertEqual(self.copies(), [])

    def test_invalid_host_label_is_refused(self):
        for host in ("a b", "-x", "../x", "a/b"):
            done = self.run_script(LOG_BACKUP_HOST=host)
            self.assertEqual(done.returncode, 2, host)


if __name__ == "__main__":
    unittest.main()
