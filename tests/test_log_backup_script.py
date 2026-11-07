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
            sys.stderr.write(os.environ.get("FAKE_ERR", ""))
            sys.exit(1)
    forced = os.environ.get("FAKE_EXIT")
    if forced and os.environ.get("FAKE_EXIT_MATCH") and os.environ["FAKE_EXIT_MATCH"] not in argv:
        forced = None
    if forced:
        sys.exit(int(forced))
    match = os.environ.get("FAKE_FAIL_MATCH")
    if match and any(match in a for a in argv):
        sys.exit(1)
    note = os.environ.get("FAKE_RCLONE_LOG_TEXT")  # what real rclone writes to its --log-file (e.g. a rate limit)
    if note and "--log-file" in argv:
        with open(argv[argv.index("--log-file") + 1], "a") as h:
            h.write(note + "\\n")
    drain = float(os.environ.get("FAKE_TERM_DRAIN", "0"))  # rclone's exit handlers commit a batch on SIGTERM
    if drain:
        import signal
        signal.signal(signal.SIGTERM, lambda *_: (time.sleep(drain), sys.exit(143)))
    hang = float(os.environ.get("FAKE_HANG", "0"))  # a pacer wait that ignores --max-duration
    hang_match = os.environ.get("FAKE_HANG_MATCH")
    if hang and (not hang_match or any(hang_match in a for a in argv)):
        time.sleep(hang)
    if os.environ.get("FAKE_EXIT_AFTER_NOTE") and note:
        sys.exit(int(os.environ["FAKE_EXIT_AFTER_NOTE"]))
    real = os.environ.get("FAKE_DELEGATE")
    if real:
        os.execv(real, [real] + argv)
sys.exit(0)
"""

# Credential-named files planted in every source; none may reach the remote.
SECRET_NAMES = ["auth.json", "rclone.conf", "member.key", "x.key", "cert.pem", "a.p12", "a.token", "id_rsa", ".netrc",
                ".npmrc", "kit.json", ".env", ".env.local", "x.secret", ".credentials.json",
                "key", "token", "pem", "p12", "netrc", "_netrc", "Auth.json", "AUTH.JSON", ".ENV", "Member.Key",
                ".pgpass", ".pypirc", "a.jks", "a.gpg", "a.tfvars", "secrets.json", "service-account-1.json", "id_dsa",
                ".git/config", ".docker/config.json", "cookies.sqlite"]
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
        old = time.time() - 3600  # static sources skip files younger than 2 minutes (--min-age)
        os.utime(path, (old, old))

    def env(self, **extra):
        env = {"HOME": str(self.home), "PATH": "/usr/bin:/bin", "LOG_BACKUP_RCLONE": str(self.fake),
               "LOG_BACKUP_HOST": "testhost", "FAKE_LOG": str(self.calls)}
        env.update(extra)
        return env

    def run_script(self, script=SCRIPT, **extra):
        extra.setdefault("LOG_BACKUP_RETRY_SLEEP", "0")
        extra.setdefault("LOG_BACKUP_BULK_EVERY_SECONDS", "0")  # tests run the bulk tier every time unless they test the gap
        done = subprocess.run(["/bin/bash", str(script)], env=self.env(**extra), cwd=str(self.tmp),
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
        self.assertEqual(self.canary.read_text(), "alive")
        return done

    def local_run(self, **extra):
        """Real rclone, local directory as the remote."""
        if not REAL_RCLONE:
            if os.environ.get("LOG_BACKUP_REQUIRE_RCLONE") == "1":  # the gate sets this: fail, never skip
                self.fail("rclone is required on this host (LOG_BACKUP_REQUIRE_RCLONE=1) but was not found")
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

    def bulk_ok(self):
        return self.logs / "log-backup.bulk-last-ok"


ALLOWED_FLAGS = {"--tpslimit", "--transfers", "--contimeout", "--timeout", "--log-file", "--log-level", "--exclude-from", "--backup-dir", "--ignore-case",
                 "--dropbox-batch-mode", "--dropbox-batch-size", "--checkers", "--retries", "--retries-sleep",
                 "--low-level-retries", "--min-age", "--checksum", "--max-duration", "--max-size", "--max-transfer"}


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

    def test_case_variants_of_credential_names_never_enter_the_stage_or_the_remote(self):
        # F2: rsync cannot ignore case, so the snapshot patterns are case-folded; no credential copy stays on disk
        names = ["Auth.JSON", "AUTH.json", ".ENV", ".Env.Local", "Member.KEY", "X.Secret", "Kit.JSON", "RCLONE.CONF",
                 "Id_Rsa", ".NETRC", "SECRETS.JSON", "Cookies.SQLite"]
        for source in (".claude/projects", ".codex/sessions"):
            for name in names:
                self.put(f"{source}/{name}", b"SECRET-MARKER")
            self.put(f"{source}/sibling-Auth.JSON.txt", b"harmless")  # a different name: stays
        self.put(".claude/projects/Goodqa-Hive/inner.txt", b"hive")
        done = self.local_run()
        self.assertEqual(done.returncode, 0, done.stderr)
        stage = self.home / ".agent-harness/backup-stage"
        staged = {p.name.lower() for p in stage.rglob("*") if p.is_file()}
        self.assertFalse(staged & {n.lower() for n in names}, staged)
        self.assertNotIn("inner.txt", staged)
        self.assertIn("sibling-auth.json.txt", staged)
        for path in (self.remote / "testhost").rglob("*"):
            if path.is_file():
                self.assertNotIn(b"SECRET-MARKER", path.read_bytes(), path)

    def test_a_plain_directory_named_like_a_credential_is_staged_but_the_credential_file_is_not(self):
        # F3: rsync patterns match directories too; an ordinary file under a directory named token must still be staged
        for name in ("token", "key", "pem", "credentials-dir"):
            self.put(f".claude/projects/p1/{name}/ordinary.jsonl", b"ordinary")
        self.put(".claude/projects/p1/sub/token", b"SECRET-MARKER")  # the credential-named FILE
        done = self.local_run()
        self.assertEqual(done.returncode, 0, done.stderr)
        stage = self.home / ".agent-harness/backup-stage/.claude/projects/p1"
        for name in ("token", "key", "pem", "credentials-dir"):
            self.assertTrue((stage / name / "ordinary.jsonl").exists(), name)
        self.assertFalse((stage / "sub" / "token").exists())
        remote = self.remote / "testhost/.claude/projects/p1"
        self.assertTrue((remote / "token/ordinary.jsonl").exists())
        self.assertFalse((remote / "sub/token").exists())

    def test_log_over_ten_megabytes_is_rotated_once_per_run(self):
        self.logs.mkdir(parents=True)
        (self.logs / "log-backup.log").write_bytes(b"x" * (10 * 1024 * 1024 + 10))
        self.assertEqual(self.run_script().returncode, 0)
        self.assertEqual((self.logs / "log-backup.log.1").stat().st_size, 10 * 1024 * 1024 + 10)
        self.assertLess((self.logs / "log-backup.log").stat().st_size, 100000)

    def test_write_rate_settings_are_validated_and_reach_rclone(self):
        self.run_script(LOG_BACKUP_TPSLIMIT="3", LOG_BACKUP_TRANSFERS="5")
        argv = self.copies()[0]
        self.assertEqual((argv[argv.index("--tpslimit") + 1], argv[argv.index("--transfers") + 1]), ("3", "5"))
        for name in ("LOG_BACKUP_TPSLIMIT", "LOG_BACKUP_TRANSFERS"):
            for value in ("0", "00", "100", "1.5", "-1", "abc", "$(id)", " 2"):
                if self.calls.exists():
                    self.calls.unlink()
                done = self.run_script(**{name: value})
                self.assertEqual(done.returncode, 2, (name, value))
                self.assertEqual(self.copies(), [], (name, value))

    def test_bulk_tier_runs_at_most_once_per_gap_while_transcripts_run_every_time(self):
        first = self.run_script(LOG_BACKUP_BULK_EVERY_SECONDS="3600")
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertTrue(self.bulk_ok().exists())
        os.unlink(self.last_ok())
        os.unlink(self.bulk_ok())
        self.calls.unlink()
        second = self.run_script(LOG_BACKUP_BULK_EVERY_SECONDS="3600")
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertTrue(self.last_ok().exists())            # transcripts ran again
        self.assertFalse(self.bulk_ok().exists())           # the bulk tier was skipped, no marker claimed
        self.assertFalse([c for c in self.copies() if "--min-age" in c])
        self.assertIn("bulk tier skipped", (self.logs / "log-backup.log").read_text())
        old = time.time() - 7200
        os.utime(self.logs / "log-backup.bulk-last-try", (old, old))
        self.run_script(LOG_BACKUP_BULK_EVERY_SECONDS="3600")  # the gap has passed: bulk runs again
        self.assertTrue(self.bulk_ok().exists())

    def test_jitter_is_validated_and_a_run_still_completes_with_it(self):
        self.assertEqual(self.run_script(LOG_BACKUP_JITTER_SECONDS="1").returncode, 0)
        for value in ("abc", "1.5", "-3", "007", "123456"):
            self.assertEqual(self.run_script(LOG_BACKUP_JITTER_SECONDS=value).returncode, 2, value)

    def test_goodqa_trash_never_appears_in_the_remote(self):
        """Quarantined deletions (the goodqa trash folder) are not logs; it held 8 GB on dev2 (B7)."""
        for rel in (".agent-harness/work/t1/.goodqa-trash/old/f.md", ".claude/projects/p1/.goodqa-trash/g.jsonl"):
            self.put(rel, b"trashed")
        done = self.local_run()
        self.assertEqual(done.returncode, 0, done.stderr)
        files = self.remote_files()
        self.assertEqual(files, set(ORDINARY))  # exact, non-empty set
        self.assertFalse([f for f in files if ".goodqa-trash" in f])
        # rsync anchors patterns that contain a slash, so the snapshot stage must be checked too (nested trash)
        staged = [str(p) for p in (self.home / ".agent-harness/backup-stage").rglob("*")]
        self.assertTrue([s for s in staged if "p1" in s], "stage empty: the check would be vacuous")
        self.assertFalse([s for s in staged if ".goodqa-trash" in s], staged)
        self.assertIn(".goodqa-trash/**", (ROOT / "harness" / "bin" / "log-backup.excludes").read_text().split())

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
        for needle, repl in (("args=(copy ", "args=(moveto "), ('--tpslimit "$TPSLIMIT"', '--delete-after --tpslimit "$TPSLIMIT"')):
            variant = self.tmp / "variant.sh"
            variant.write_text(text.replace(needle, repl))
            (self.tmp / "log-backup.excludes").write_text("*.secret\n")
            if self.calls.exists():
                self.calls.unlink()
            self.run_script(script=variant, LOG_BACKUP_EXCLUDES=str(ROOT / "harness/bin/log-backup.excludes"),
                            LOG_BACKUP_WORK_EXCLUDES=str(ROOT / "harness/bin/log-backup.work-excludes"))
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

    def test_spoofed_command_line_with_script_name_as_later_argument_is_not_a_holder(self):
        other = subprocess.Popen(["/bin/sh", "-c", "sleep 60", "log-backup.sh"])  # script name only as argv[2]
        self.addCleanup(lambda: (other.terminate(), other.wait()))
        time.sleep(0.3)
        self.lock(other.pid)
        self.assertEqual(self.run_script().returncode, 0)
        self.assertTrue(self.last_ok().exists())

    def test_legacy_lock_without_a_pid_is_never_taken_over_while_young(self):
        # the hand-installed script keeps the same lock.d directory without a pid file
        lock = self.logs / "log-backup.lock.d"
        lock.mkdir(parents=True)
        old = time.time() - 6600  # 110 minutes: an old-script bulk pass that is still running
        os.utime(lock, (old, old))
        done = self.run_script()
        self.assertEqual(done.returncode, 0)
        self.assertEqual(self.recorded(), [])
        self.assertTrue((self.logs / "log-backup.last-skip").exists())
        self.assertFalse(self.last_ok().exists())
        self.assertTrue(lock.is_dir())
        old = time.time() - 90000  # over a day: abandoned
        os.utime(lock, (old, old))
        self.assertEqual(self.run_script().returncode, 0)
        self.assertTrue(self.last_ok().exists())

    def test_a_live_holder_whose_path_contains_a_space_is_still_a_live_holder(self):
        # F2: a HOME with a space split the path and made a running backup look like a stranger's pid
        proc = self.holder("my dir/log-backup.sh")
        time.sleep(0.3)
        self.lock(proc.pid)
        done = self.run_script()
        self.assertEqual(done.returncode, 0)
        self.assertEqual(self.recorded(), [])
        self.assertFalse(self.last_ok().exists())

    def make_lock(self, name, age):
        lock = self.logs / name
        lock.mkdir(parents=True)
        when = time.time() - age
        os.utime(lock, (when, when))
        return lock

    def test_young_hand_installed_locks_mean_skip_and_stale_ones_mean_proceed(self):
        cases = [("log-backup.transcripts.lock.d", 600, True), ("log-backup.transcripts.lock.d", 7200, False),
                 ("log-backup.bulk.lock.d", 3 * 3600, True), ("log-backup.bulk.lock.d", 7 * 3600, False),
                 ("log-backup.transcripts.lock.d", -1800, True),      # future, within the limit: assume live
                 ("log-backup.transcripts.lock.d", -36000, False),    # future beyond the limit: cannot be a real run
                 ("log-backup.bulk.lock.d", -36000, False)]
        for name, age, skips in cases:
            shutil.rmtree(self.logs, ignore_errors=True)
            if self.calls.exists():
                self.calls.unlink()
            self.make_lock(name, age)
            done = self.run_script()
            self.assertEqual(done.returncode, 0, (name, age))
            if skips:
                self.assertEqual(self.recorded(), [], (name, age))
                self.assertTrue((self.logs / "log-backup.last-skip").exists(), (name, age))
                self.assertFalse(self.last_ok().exists(), (name, age))
            else:
                self.assertTrue(self.copies(), (name, age))
                self.assertTrue(self.last_ok().exists(), (name, age))

    def test_a_hand_installed_lock_with_an_unreadable_mtime_means_skip(self):
        self.make_lock("log-backup.bulk.lock.d", 7 * 3600)  # would be stale, but its time cannot be read
        fakebin = self.tmp / "statbin"
        fakebin.mkdir()
        stat = fakebin / "stat"
        stat.write_text('#!/bin/sh\ncase "$*" in *bulk.lock.d*) exit 1 ;; esac\nexec /usr/bin/stat "$@"\n')
        stat.chmod(0o755)
        done = self.run_script(PATH=f"{fakebin}:/usr/bin:/bin")
        self.assertEqual(done.returncode, 0)
        self.assertEqual(self.recorded(), [])
        self.assertFalse(self.last_ok().exists())

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

    def test_a_failing_copy_with_rate_limit_text_keeps_run_non_fresh_then_succeeds_on_retry(self):
        err = "ERROR : upload failed: batch upload failed: too_many_write_operations\n"
        done = self.run_script(FAKE_FAIL_FIRST="1", FAKE_ERR=err, LOG_BACKUP_RETRIES="0")
        self.assertNotEqual(done.returncode, 0)  # no retry budget: a rate-limited source fails the run
        self.assertFalse(self.last_ok().exists())
        if self.calls.exists():
            self.calls.unlink()
        (self.tmp / "calls.jsonl.count").unlink()
        done = self.run_script(FAKE_FAIL_FIRST="1", FAKE_ERR=err)  # default retries absorb it
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertTrue(self.last_ok().exists())

    def test_rate_limit_settings_match_the_reviewed_live_script(self):
        self.run_script()
        argv = self.copies()[0]
        want = {"--transfers": "2", "--tpslimit": "1", "--checkers": "4", "--dropbox-batch-mode": "sync",
                "--dropbox-batch-size": "100", "--retries": "3", "--retries-sleep": "30s", "--low-level-retries": "20"}
        for flag, value in want.items():
            self.assertEqual(argv[argv.index(flag) + 1], value, flag)

    def test_build_outputs_and_images_never_appear_in_the_remote(self):
        for d in ("node_modules/x", ".next/x", "dist/x", "build/x", "target/x", ".venv/x", "venv/x", ".gradle/x", ".cache/x"):
            self.put(f".agent-harness/work/t1/{d}/f.js", b"junk")
        for name in ("a.vma", "a.vma.zst", "a.qcow2", "a.iso", "work-ledger.key"):
            self.put(f".agent-harness/work/t1/{name}", b"junk")
        done = self.local_run()
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(self.remote_files(), set(ORDINARY))

    def test_live_sources_upload_from_a_stable_snapshot_and_static_ones_skip_young_files(self):
        young = self.home / ".agent-harness/work/t1/young.md"
        young.write_text("just written")  # mtime now: inside the 2 minute window
        done = self.local_run()
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertNotIn(".agent-harness/work/t1/young.md", self.remote_files())
        stage = self.home / ".agent-harness/backup-stage"
        self.assertEqual((stage / ".claude/projects/p1/a.jsonl").read_bytes(), ORDINARY[".claude/projects/p1/a.jsonl"])
        for argv in self.copies():
            live = argv[-2].startswith(str(stage))
            self.assertEqual("--min-age" in argv, not live, argv)

    def test_snapshot_temp_files_live_outside_every_uploaded_tree(self):
        stage = self.home / ".agent-harness/backup-stage"
        self.assertEqual(self.run_script().returncode, 0)
        self.assertTrue((stage / ".rsync-tmp").is_dir())
        for argv in self.copies():
            self.assertFalse(argv[-2].startswith(str(stage / ".rsync-tmp")), argv)
        # a stub rsync records its arguments: --temp-dir must be present and outside every staged tree
        fakebin = self.tmp / "fakebin"
        fakebin.mkdir()
        record = self.tmp / "rsync-args"
        stub = fakebin / "rsync"
        stub.write_text(f'#!/bin/sh\nprintf "%s\\n" "$@" >> {record}\nexit 0\n')
        stub.chmod(0o755)
        self.run_script(PATH=f"{fakebin}:/usr/bin:/bin")
        args = record.read_text().splitlines()
        self.assertIn(f"--temp-dir={stage}/.rsync-tmp", args)
        folded = self.home / ".agent-harness/logs/log-backup.rsync-excludes"
        self.assertIn(f"--exclude-from={folded}", args)  # the case-folded copy, not the case-sensitive original
        text = folded.read_text()
        self.assertIn("[aA][uU][tT][hH].[jJ][sS][oO][nN]", text.splitlines())
        self.assertNotIn("#", text)

    def test_failed_snapshot_skips_upload_and_keeps_run_non_fresh(self):
        fakebin = self.tmp / "fakebin"
        fakebin.mkdir()
        rsync = fakebin / "rsync"
        rsync.write_text("#!/bin/sh\nexit 11\n")
        rsync.chmod(0o755)
        done = self.run_script(PATH=f"{fakebin}:/usr/bin:/bin")
        self.assertNotEqual(done.returncode, 0)
        self.assertFalse(self.last_ok().exists())
        staged_dirs = (".claude/projects", ".claude/wals", ".codex/sessions")  # rsync-staged; files use cp
        self.assertFalse([c for c in self.copies() if ".agent-harness/backup-stage" in c[-2] and c[-2].endswith(staged_dirs)])

    def test_partial_snapshot_uploads_what_was_staged_but_withholds_last_ok(self):
        fakebin = self.tmp / "fakebin"
        fakebin.mkdir()
        real = shutil.which("rsync")
        wrapper = fakebin / "rsync"
        wrapper.write_text(f'#!/bin/sh\n{real} "$@"\nexit 23\n')
        wrapper.chmod(0o755)
        done = self.run_script(PATH=f"{fakebin}:/usr/bin:/bin")
        self.assertNotEqual(done.returncode, 0)
        self.assertFalse(self.last_ok().exists())
        self.assertTrue([c for c in self.copies() if c[-2].endswith(".claude/projects")])

    def test_rsync_vanished_files_exit_24_is_tolerated_but_other_codes_are_not(self):
        fakebin = self.tmp / "fakebin"
        fakebin.mkdir()
        real = shutil.which("rsync")
        wrapper = fakebin / "rsync"
        wrapper.write_text(f"#!/bin/sh\n{real} \"$@\"\nexit 24\n")
        wrapper.chmod(0o755)
        done = self.run_script(PATH=f"{fakebin}:/usr/bin:/bin")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertTrue(self.last_ok().exists())

    def test_symlink_inside_a_live_source_is_never_uploaded_or_followed(self):
        outside = self.tmp / "outside"
        outside.mkdir()
        (outside / "secret.txt").write_text("SECRET-MARKER")
        os.symlink(outside, self.home / ".claude/projects/p1/dirlink")
        os.symlink(outside / "secret.txt", self.home / ".claude/projects/p1/filelink")
        done = self.local_run()
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(self.remote_files(), set(ORDINARY))
        for path in (self.remote / "testhost").rglob("*"):
            if path.is_file():
                self.assertNotIn(b"SECRET-MARKER", path.read_bytes())

    def test_deleted_live_tree_with_a_stale_stage_is_not_a_backup(self):
        self.assertEqual(self.local_run().returncode, 0)
        shutil.rmtree(self.home / ".claude/projects")
        shutil.rmtree(self.home / ".codex/sessions")
        (self.home / ".claude/projects").mkdir()
        (self.home / ".codex/sessions").mkdir()
        os.unlink(self.last_ok())
        done = self.local_run()
        self.assertNotEqual(done.returncode, 0)  # the stage still holds old files, the live primary trees are empty
        self.assertFalse(self.last_ok().exists())

    def test_credential_files_are_not_even_copied_into_the_stage(self):
        for source in (".claude/projects", ".codex/sessions"):
            for name in ("auth.json", "member.key", "x.secret", "kit.json"):
                self.put(f"{source}/{name}", b"SECRET-MARKER")
        self.assertEqual(self.run_script().returncode, 0)
        stage = self.home / ".agent-harness/backup-stage"
        staged = {p.name for p in stage.rglob("*") if p.is_file()}
        self.assertFalse(staged & {"auth.json", "member.key", "x.secret", "kit.json"}, staged)
        self.assertIn("a.jsonl", staged)

    def test_leftover_rsync_temp_files_are_cleared_at_start(self):
        tmpdir = self.home / ".agent-harness/backup-stage/.rsync-tmp"
        tmpdir.mkdir(parents=True)
        (tmpdir / ".a.jsonl.partial").write_text("partial")
        self.assertEqual(self.run_script().returncode, 0)
        self.assertFalse((tmpdir / ".a.jsonl.partial").exists())

    def test_hostile_or_unsafe_stage_locations_are_refused(self):
        link_target = self.tmp / "decoy"
        link_target.mkdir()
        link = self.tmp / "stagelink"
        os.symlink(link_target, link)
        bad = ["relative/stage", "-x", "/", "//", "/tmp/elsewhere", str(self.home), str(self.home / ".claude/projects/stg"),
               str(self.home / ".claude"), str(self.home / ".agent-harness/work/stg"),
               str(self.home / ".agent-harness"), str(self.tmp / "a" / ".." / "b"), str(link)]
        mode_before = link_target.stat().st_mode
        home_mode = self.home.stat().st_mode
        for value in bad:
            if self.calls.exists():
                self.calls.unlink()
            done = self.run_script(LOG_BACKUP_STAGE=value)
            self.assertEqual(done.returncode, 2, value)
            self.assertEqual(self.copies(), [], value)
        self.assertEqual(link_target.stat().st_mode, mode_before)
        self.assertEqual(self.home.stat().st_mode, home_mode)

    def test_work_tree_backs_up_only_small_durable_state(self):
        base = ".agent-harness/work/t1"
        self.put(f"{base}/wt1/.git", b"gitdir: /elsewhere")          # a git worktree: .git is a file
        self.put(f"{base}/wt1/src/code.py", b"code")
        self.put(f"{base}/co/.git/HEAD", b"ref")                      # a checkout: .git is a directory
        self.put(f"{base}/co/src/main.py", b"code")
        self.put(f"{base}/shots/a.png", b"png")
        self.put(f"{base}/shots/b.webm", b"video")
        self.put(f"{base}/big.json", b"x" * 5000)
        self.put(f"{base}/odd[1]/.git", b"gitdir: /elsewhere")        # glob characters cannot be excluded safely
        self.put(f"{base}/state.json", b"{}")
        done = self.local_run(LOG_BACKUP_WORK_MAX_SIZE="1K")
        self.assertEqual(done.returncode, 0, done.stderr)
        files = {f for f in self.remote_files() if f.startswith(".agent-harness/work/")}
        self.assertEqual(files, {".agent-harness/work/t1/notes.md", f"{base}/state.json", f"{base}/odd[1]/.git"})
        for argv in self.copies():
            if argv[-2].endswith(".agent-harness/work"):
                self.assertIn("--max-size", argv)
                self.assertIn("--max-transfer", argv)

    def test_budget_exit_codes_leave_a_partial_run_non_fresh_without_retry(self):
        for code in (8, 10):
            if self.calls.exists():
                self.calls.unlink()
            done = self.run_script(FAKE_EXIT=str(code))
            self.assertNotEqual(done.returncode, 0, code)
            self.assertFalse(self.last_ok().exists())
            n_sources = len(self.copies())
            self.assertGreater(n_sources, 0)
            self.assertEqual(len({tuple(c[-2:]) for c in self.copies()}), n_sources)  # one attempt per source, no retry

    def test_bulk_only_budget_exit_withholds_only_the_bulk_marker(self):
        done = self.run_script(FAKE_EXIT="10", FAKE_EXIT_MATCH="--min-age")
        self.assertNotEqual(done.returncode, 0)
        self.assertTrue(self.last_ok().exists())     # transcripts completed
        self.assertFalse(self.bulk_ok().exists())    # the bulk gap is not hidden

    def test_non_numeric_budget_or_retry_settings_are_refused_before_any_copy(self):
        for name in ("LOG_BACKUP_BUDGET_SECONDS", "LOG_BACKUP_RETRIES", "LOG_BACKUP_RETRY_SLEEP"):
            for value in ("1.5", "abc", "-1", "999999", "x[$(id)]", " 5", "08", "09", "007", "00"):
                if self.calls.exists():
                    self.calls.unlink()
                done = self.run_script(**{name: value})
                self.assertEqual(done.returncode, 2, (name, value))
                self.assertEqual(self.copies(), [], (name, value))
                self.assertFalse(self.last_ok().exists() or self.bulk_ok().exists())

    def test_work_size_settings_must_be_plain_non_zero_sizes(self):
        # F1: a zero transfer cap would stop every run at once; free text would reach rclone
        for name in ("LOG_BACKUP_WORK_MAX_SIZE", "LOG_BACKUP_WORK_MAX_TRANSFER"):
            for value in ("0", "0M", "-1", "1.5G", "abc", "12T", "1234567", "5 M", "--delete-after", "$(id)", "1m"):
                if self.calls.exists():
                    self.calls.unlink()
                done = self.run_script(**{name: value})
                self.assertEqual(done.returncode, 2, (name, value))
                self.assertEqual(self.copies(), [], (name, value))
            for value in ("1", "25M", "5G", "100K", "999999G"):
                if self.calls.exists():
                    self.calls.unlink()
                self.assertEqual(self.run_script(**{name: value}).returncode, 0, (name, value))

    def test_hostile_work_directory_names_never_cause_a_wrong_exclusion(self):
        base = ".agent-harness/work/t1"
        names = ["a\\b", "br{ace}", "star*", "new\nline", "foo"]
        for n in names[:4]:
            self.put(f"{base}/{n}/.git", b"gitdir: x")
            self.put(f"{base}/{n}/src.txt", b"code")
        self.put(f"{base}/x\nfoo/.git", b"gitdir: x")                  # would excise every dir named foo if mis-split
        self.put(f"{base}/keep/foo/state.json", b"{}")
        self.put(f"{base}/deep/1/2/3/4/5/6/7/wt/.git", b"gitdir: x")  # deeper than the old depth limit
        self.put(f"{base}/deep/1/2/3/4/5/6/7/wt/code.py", b"code")
        self.put(".agent-harness/work/.git/HEAD", b"ref")                  # the work root is itself a checkout
        done = self.local_run()
        self.assertEqual(done.returncode, 0, done.stderr)
        files = self.remote_files()
        self.assertIn(f"{base}/keep/foo/state.json", files)               # a plain dir named foo survives
        self.assertNotIn(f"{base}/deep/1/2/3/4/5/6/7/wt/code.py", files)
        self.assertFalse([f for f in files if f.startswith(".agent-harness/work/.git/")])

    def test_used_up_time_budget_skips_the_remaining_sources_and_stays_non_fresh(self):
        done = self.run_script(LOG_BACKUP_BUDGET_SECONDS="0")
        self.assertNotEqual(done.returncode, 0)
        self.assertEqual(self.copies(), [])
        self.assertFalse(self.last_ok().exists())
        self.assertIn("budget", (self.logs / "log-backup.log").read_text())

    def test_every_copy_carries_a_max_duration_inside_the_budget(self):
        self.run_script(LOG_BACKUP_BUDGET_SECONDS="300")
        for argv in self.copies():
            seconds = int(argv[argv.index("--max-duration") + 1].rstrip("s"))
            self.assertTrue(20 <= seconds <= 300, argv)

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

    def test_two_tiers_have_separate_markers(self):
        done = self.run_script()
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertTrue(self.last_ok().exists() and self.bulk_ok().exists())
        self.assertRegex(self.bulk_ok().read_text(), r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ\n$")
        for p in (self.last_ok(), self.bulk_ok()):
            os.unlink(p)
        done = self.run_script(FAKE_FAIL_MATCH="--min-age", LOG_BACKUP_RETRIES="0")  # only bulk sources carry --min-age
        self.assertNotEqual(done.returncode, 0)
        self.assertTrue(self.last_ok().exists())            # transcripts are safe and say so
        self.assertFalse(self.bulk_ok().exists())           # the gap in the bulk tier is not hidden
        for p in (self.last_ok(), self.bulk_ok()):
            if p.exists():
                os.unlink(p)
        done = self.run_script(FAKE_FAIL_MATCH=".claude/wals", LOG_BACKUP_RETRIES="0")  # transcripts tier fails
        self.assertNotEqual(done.returncode, 0)
        self.assertFalse(self.last_ok().exists())
        self.assertTrue(self.bulk_ok().exists())
        self.assertTrue((self.logs / "log-backup.first-run").exists())

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

    def test_symlinked_source_root_and_empty_primary_do_not_make_a_fresh_backup(self):
        outside = self.tmp / "outside"
        outside.mkdir()
        (outside / "stolen.txt").write_text("x")
        shutil.rmtree(self.home / ".claude/projects")
        os.symlink(outside, self.home / ".claude/projects")
        shutil.rmtree(self.home / ".codex/sessions")
        (self.home / ".codex/sessions").mkdir()  # an empty primary tree
        done = self.local_run()
        self.assertNotEqual(done.returncode, 0)
        self.assertFalse(self.last_ok().exists())
        self.assertNotIn("stolen.txt", {Path(f).name for f in self.remote_files()})

    def test_invalid_host_label_is_refused(self):
        for host in ("a b", "-x", "../x", "a/b", "..", ".", ".hidden"):
            done = self.run_script(LOG_BACKUP_HOST=host)
            self.assertEqual(done.returncode, 2, host)


class Contention(Case):
    """Mac 2026-11-07: other uploads to the same Dropbox account used its write budget. Each too_many_write_operations
    cost a 300 s pacer wait that --max-duration did not cut short, runs overran the 780 s budget and slipped past the
    900 s schedule, and the log said only "sources=0"."""

    def test_a_copy_that_ignores_max_duration_is_stopped_near_the_budget(self):
        start = time.time()
        done = self.run_script(LOG_BACKUP_BUDGET_SECONDS="40", LOG_BACKUP_DEADLINE_GRACE_SECONDS="3",
                               LOG_BACKUP_KILL_GRACE_SECONDS="2", FAKE_HANG="90", FAKE_RCLONE_LOG_TEXT="x")
        elapsed = time.time() - start
        self.assertLess(elapsed, 60, "the run must end near its budget, not after the hung copy")
        self.assertNotEqual(done.returncode, 0)
        self.assertFalse(self.last_ok().exists())
        self.assertIn("stopped at the run deadline", (self.logs / "log-backup.log").read_text())

    def test_jitter_does_not_spend_the_copy_budget(self):
        # The first copy's share must not depend on the start delay. A run without delay sets the baseline; with a
        # delay of 0-3 s the old code keeps the baseline only when the delay is under 2 s, so eight runs pass on the
        # old code about 1 time in 256.
        settings = dict(LOG_BACKUP_BUDGET_SECONDS="300", LOG_BACKUP_SLICE_RESERVE_SECONDS="0",
                        LOG_BACKUP_DEADLINE_GRACE_SECONDS="0", LOG_BACKUP_KILL_GRACE_SECONDS="0")

        def first_share(jitter):
            open(self.calls, "w").close()
            done = self.run_script(LOG_BACKUP_JITTER_SECONDS=jitter, **settings)
            self.assertEqual(done.returncode, 0, done.stderr)
            first = self.copies()[0]
            return int(first[first.index("--max-duration") + 1].rstrip("s"))

        baseline = first_share("0")
        for attempt in range(8):
            self.assertGreaterEqual(first_share("3"), baseline - 1, "attempt %d: the start delay spent the budget" % attempt)

    def test_a_hung_projects_copy_leaves_time_for_the_later_tier1_sources(self):
        start = time.time()
        done = self.run_script(LOG_BACKUP_BUDGET_SECONDS="60", LOG_BACKUP_SLICE_RESERVE_SECONDS="10",
                               LOG_BACKUP_DEADLINE_GRACE_SECONDS="2", LOG_BACKUP_KILL_GRACE_SECONDS="1",
                               FAKE_HANG="300", FAKE_HANG_MATCH=".claude/projects")
        self.assertLess(time.time() - start, 100)
        log = (self.logs / "log-backup.log").read_text()
        self.assertIn("copy of .claude/projects stopped at the run deadline", log)
        later = [a for a in self.copies() if any(".claude/wals" in x for x in a)]
        self.assertTrue(later, "the WALs still get their own slice after a hung projects copy")
        self.assertNotIn("used up before .claude/wals", log)
        self.assertIn("sources=", log)
        self.assertNotEqual(done.returncode, 0)  # projects is partial, so the run is still not fresh

    def test_a_rate_limited_copy_names_the_cause(self):
        # Two other uploads to this account and one to a remote whose name merely ends the same way: only the two count.
        # A remote name of its own keeps real uploads running on this host out of the count.
        others = [subprocess.Popen(["/bin/bash", "-c", 'exec -a "rclone copy /x %s" sleep 60' % spec])
                  for spec in ("lbtest-box:a", "lbtest-box:b", "old-lbtest-box:c")]
        for proc in others:
            self.addCleanup(proc.wait)
            self.addCleanup(proc.kill)
        done = self.run_script(FAKE_RCLONE_LOG_TEXT="ERROR : upload failed: too_many_write_operations",
                               FAKE_EXIT_AFTER_NOTE="1", LOG_BACKUP_RETRIES="0",
                               LOG_BACKUP_REMOTE="lbtest-box:Backups/agent-logs", FAKE_REMOTES="lbtest-box: dropbox")
        self.assertNotEqual(done.returncode, 0)
        log = (self.logs / "log-backup.log").read_text()
        self.assertIn("Dropbox write rate limit", log)
        self.assertIn("other rclone uploads running now: 2 ", log)

    def test_a_copy_that_drains_after_the_stop_signal_is_killed(self):
        # rclone commits its pending Dropbox batch on SIGTERM with no time limit; under rate limiting that is minutes.
        start = time.time()
        done = self.run_script(LOG_BACKUP_BUDGET_SECONDS="40", LOG_BACKUP_DEADLINE_GRACE_SECONDS="2",
                               LOG_BACKUP_KILL_GRACE_SECONDS="3", FAKE_HANG="300", FAKE_TERM_DRAIN="200",
                               FAKE_HANG_MATCH=".claude/projects")
        self.assertLess(time.time() - start, 75, "a copy that ignores SIGTERM must be killed, not waited for")
        self.assertNotEqual(done.returncode, 0)
        self.assertFalse(self.last_ok().exists())
        self.assertIn("copy of .claude/projects stopped at the run deadline", (self.logs / "log-backup.log").read_text())

    def test_every_tier1_source_gets_a_slice_and_the_run_ends_in_its_budget(self):
        # All 11 tier-1 sources present and every copy hung: each still gets its own slice, and the whole run (stop and
        # kill grace included) ends inside the budget, so the next scheduled run is never pushed back.
        for rel in (".claude/history.jsonl", ".codex/history.jsonl", ".agent-harness/work-assignments.json",
                    ".agent-harness/work-ledger.json", ".agent-harness/work-ledger.events.jsonl",
                    ".agent-harness/work-ledger.archive.jsonl", ".agent-harness/work-ledger.failures.jsonl",
                    ".agent-harness/work-ledger.spool.jsonl"):
            self.put(rel, b"x\n")
        start = time.time()
        done = self.run_script(LOG_BACKUP_BUDGET_SECONDS="100", LOG_BACKUP_SLICE_RESERVE_SECONDS="2",
                               LOG_BACKUP_DEADLINE_GRACE_SECONDS="1", LOG_BACKUP_KILL_GRACE_SECONDS="1",
                               FAKE_HANG="300", FAKE_TERM_DRAIN="300", LOG_BACKUP_BULK_EVERY_SECONDS="99999")
        elapsed = time.time() - start
        log = (self.logs / "log-backup.log").read_text()
        self.assertNotIn("used up before .agent-harness/work-ledger", log)
        self.assertIn("copy of .agent-harness/work-ledger.spool.jsonl stopped at the run deadline", log)
        self.assertLess(elapsed, 100 + 10, "the run overran its budget")
        self.assertNotEqual(done.returncode, 0)

    def test_the_run_ends_inside_the_schedule_period_whatever_the_start_delay(self):
        # A long start delay must shrink the copying time rather than push the run past the next scheduled start.
        start = time.time()
        self.run_script(LOG_BACKUP_JITTER_SECONDS="0", LOG_BACKUP_BUDGET_SECONDS="300", LOG_BACKUP_PERIOD_SECONDS="70",
                        LOG_BACKUP_DEADLINE_GRACE_SECONDS="1", LOG_BACKUP_KILL_GRACE_SECONDS="1",
                        LOG_BACKUP_SLICE_RESERVE_SECONDS="2", FAKE_HANG="300", FAKE_TERM_DRAIN="300")
        self.assertLess(time.time() - start, 70, "the run outlived its schedule period")

    def test_a_stale_deadline_marker_does_not_mark_a_clean_copy_as_stopped(self):
        # A watchdog that outlived a killed run leaves its marker; a later copy with that pid must not read it.
        self.logs.mkdir(parents=True, exist_ok=True)
        (self.logs / ".log-backup.deadline.stale").write_text("")
        done = self.run_script()
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertFalse((self.logs / ".log-backup.deadline.stale").exists(), "leftover deadline markers are cleared")


class BulkTier(Case):
    """Mac 2026-11-07 (goodqa#15062): tier 1 used the whole budget, so the hourly bulk attempts at 03:24, 04:47 and
    06:00 copied nothing, failed the run and still spent the hour; bulk-last-ok never appeared and check stayed 3."""

    def bulk_try(self):
        return self.logs / "log-backup.bulk-last-try"

    def bulk_copies(self):
        return [c for c in self.copies() if "--min-age" in c]

    def test_bulk_tier_with_no_time_left_is_deferred_not_spent(self):
        done = self.run_script(LOG_BACKUP_BULK_EVERY_SECONDS="3600", LOG_BACKUP_BUDGET_SECONDS="30",
                               LOG_BACKUP_SLICE_RESERVE_SECONDS="3", LOG_BACKUP_DEADLINE_GRACE_SECONDS="1",
                               LOG_BACKUP_KILL_GRACE_SECONDS="1", FAKE_HANG="300")
        self.assertNotEqual(done.returncode, 0)  # tier 1 is partial
        log = (self.logs / "log-backup.log").read_text()
        self.assertIn("bulk tier deferred", log)
        self.assertNotIn("bulk exit=1", log)
        self.assertNotIn("git trees excluded", log, "the work-tree scan must not start with no time left")
        self.assertFalse(self.bulk_try().exists(), "a deferred bulk tier must not spend the hourly slot")
        self.assertIn("bulk=0", (self.logs / "log-backup.last-run").read_text())
        open(self.calls, "w").close()
        again = self.run_script(LOG_BACKUP_BULK_EVERY_SECONDS="3600")  # the next run has time: bulk runs now
        self.assertEqual(again.returncode, 0, again.stderr)
        self.assertTrue(self.bulk_copies(), "the next run with time left attempts the bulk tier")
        self.assertTrue(self.bulk_ok().exists())

    def test_bulk_pass_cut_short_by_the_budget_continues_next_run(self):
        done = self.run_script(LOG_BACKUP_BULK_EVERY_SECONDS="3600", FAKE_EXIT="10", FAKE_EXIT_MATCH="--min-age")
        self.assertNotEqual(done.returncode, 0)
        self.assertFalse(self.bulk_ok().exists())
        self.assertFalse(self.bulk_try().exists(), "a pass stopped on the budget is unfinished, not an hourly attempt")
        self.assertIn("bulk tier stopped on the run budget", (self.logs / "log-backup.log").read_text())
        open(self.calls, "w").close()
        again = self.run_script(LOG_BACKUP_BULK_EVERY_SECONDS="3600")
        self.assertEqual(again.returncode, 0, again.stderr)
        self.assertTrue(self.bulk_copies())
        self.assertTrue(self.bulk_ok().exists())

    def test_a_failed_bulk_pass_still_waits_for_the_gap(self):
        # NEG: only a budget stop skips the gate; an ordinary failure keeps the hourly limit on write load.
        done = self.run_script(LOG_BACKUP_BULK_EVERY_SECONDS="3600", FAKE_FAIL_MATCH="archived_sessions",
                               LOG_BACKUP_RETRIES="0")
        self.assertNotEqual(done.returncode, 0)
        self.assertTrue(self.bulk_try().exists())
        open(self.calls, "w").close()
        again = self.run_script(LOG_BACKUP_BULK_EVERY_SECONDS="3600")
        self.assertEqual(again.returncode, 0, again.stderr)
        self.assertEqual(self.bulk_copies(), [])
        self.assertIn("bulk tier skipped", (self.logs / "log-backup.log").read_text())


if __name__ == "__main__":
    unittest.main()
