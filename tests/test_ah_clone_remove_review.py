"""Tests added after the Opus code review of clone_remove.py (M1 rollback gap, M2 identity sources, M3 first-run ctime,
L1 relative alternates, L2 token userinfo, L3 result rows). They reuse the fixtures of test_ah_clone_remove."""
import io
import json
import os
import sys
import time
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_ah_clone_remove as T  # noqa: E402
SESSION, ah, cr, git, cg = T.SESSION, T.ah, T.cr, T.git, T.cg


class Identity(T.Base):
    def cli(self, env, trusted, *extra):
        out = io.StringIO()
        with mock.patch.dict(os.environ, env), redirect_stdout(out), \
                mock.patch.object(cr, "trusted_home", lambda: trusted or self.home):
            code = ah.main(["clone-remove", "--reason", "why", "--verify-only", *extra])
        return code, out.getvalue()

    def make_session_dirs(self, session):
        os.makedirs(os.path.join(self.home, ".claude", "wals", session), exist_ok=True)
        os.makedirs(os.path.join(self.home, ".agent-harness", "work", session), exist_ok=True)

    def test_the_command_gets_past_the_session_gate_for_a_real_session(self):  # option A, POSITIVE end to end through ah.main
        path = self.clone()
        self.make_session_dirs(SESSION)
        code, text = self.cli({"AH_HOME": self.home, "CLAUDE_CODE_SESSION_ID": SESSION}, None, "--path", path)
        self.assertEqual(code, 0, text)
        self.assertTrue(json.loads(text)["removable"])
        self.assertTrue(os.path.isdir(path))

    def test_a_session_without_its_wal_or_work_directory_is_refused(self):  # option A
        path = self.clone()
        env = {"AH_HOME": self.home, "CLAUDE_CODE_SESSION_ID": SESSION}
        code, text = self.cli(env, None, "--path", path)  # the work directory exists, the WAL directory does not
        self.assertNotEqual(code, 0, text)
        self.assertIn("WAL directory", text)
        os.makedirs(os.path.join(self.home, ".claude", "wals", SESSION))
        shutil_rmtree = __import__("shutil").rmtree
        shutil_rmtree(os.path.join(self.home, ".agent-harness", "work", SESSION))
        code, text = self.cli(env, None, "--path", path)
        self.assertNotEqual(code, 0, text)
        self.assertIn("work directory", text)

    def test_a_missing_malformed_or_fallback_session_is_refused(self):  # option A
        path = self.clone()
        self.make_session_dirs(SESSION)
        for env in ({"AH_HOME": self.home}, {"AH_HOME": self.home, "CLAUDE_CODE_SESSION_ID": "../x"},
                    {"AH_HOME": self.home, "CLAUDE_SESSION_ID": SESSION}):
            with self.subTest(env):
                clean = {k: v for k, v in os.environ.items() if k not in ("CLAUDE_CODE_SESSION_ID", "CLAUDE_SESSION_ID")}
                with mock.patch.dict(os.environ, clean, clear=True):
                    code, text = self.cli(env, None, "--path", path)
                self.assertNotEqual(code, 0, text)

    def test_an_untrusted_home_is_refused_and_the_forged_session_limit_is_real(self):  # option A, STATED LIMIT
        path = self.clone()
        self.make_session_dirs(SESSION)
        env = {"AH_HOME": self.home, "CLAUDE_CODE_SESSION_ID": SESSION}
        code, text = self.cli(env, "/somewhere/else", "--path", path)
        self.assertNotEqual(code, 0, text)
        # The limit, pinned so nobody mistakes it for a control: a caller who names ANOTHER existing session reaches that
        # session's clean, fully pushed receipts clone (identity is caller-settable; see the spec).
        self.make_session_dirs("other-session")
        other = os.path.join(self.home, ".agent-harness", "work", "other-session", "receipts")
        os.makedirs(other, exist_ok=True)
        stolen = os.path.join(other, "wt-a")
        T.git(self.tmp, "clone", "-q", "file://" + self.origin, stolen)
        T.git(stolen, "remote", "set-url", "origin", T.URL)
        code, text = self.cli(dict(env, CLAUDE_CODE_SESSION_ID="other-session"), None, "--path", stolen)
        self.assertEqual(code, 0, text)


class ParentEnvironment(T.Base):
    """The parser that decides the calling session runs UNMOCKED against real child processes (receipt r2, F1)."""

    def child(self, argv_tail, env):
        proc = __import__("subprocess").Popen([sys.executable, "-c", "import time; time.sleep(60)", *argv_tail], env=env)
        self.addCleanup(proc.wait)
        self.addCleanup(proc.terminate)
        time.sleep(0.4)
        return proc

    def clean_env(self, **extra):
        env = {k: v for k, v in os.environ.items() if k != cr.SESSION_VAR}
        env.update(extra)
        return env

    def test_the_command_line_is_never_read_only_the_environment(self):
        proc = self.child([cr.SESSION_VAR + "=OTHER"], self.clean_env(**{cr.SESSION_VAR: "REAL"}))
        self.assertEqual(cr.parent_session_env(proc.pid), "REAL")

    def test_a_command_line_override_with_no_variable_in_the_environment_reads_as_none(self):
        proc = self.child([cr.SESSION_VAR + "=OTHER"], self.clean_env())
        self.assertIsNone(cr.parent_session_env(proc.pid))

    def test_a_missing_process_and_a_duplicate_variable_read_as_none(self):
        self.assertIsNone(cr.parent_session_env(2 ** 22 + 12345))
        with mock.patch.object(cr, "process_environment", lambda pid: [cr.SESSION_VAR + "=A", cr.SESSION_VAR + "=B"]):
            self.assertIsNone(cr.parent_session_env(1))
        with mock.patch.object(cr, "process_environment", lambda pid: [cr.SESSION_VAR + "="]):
            self.assertIsNone(cr.parent_session_env(1))

    def test_the_buffer_parser_separates_arguments_from_the_environment(self):
        buf = (2).to_bytes(4, "little") + b"/usr/bin/zsh\x00\x00\x00zsh\x00" + (cr.SESSION_VAR + "=ARGV").encode() + b"\x00" \
            + (cr.SESSION_VAR + "=ENV").encode() + b"\x00PATH=/bin\x00\x00junk"
        self.assertEqual(cr.parse_procargs2(buf), [cr.SESSION_VAR + "=ENV", "PATH=/bin"])
        with self.assertRaises(ValueError):
            cr.parse_procargs2(b"\x01\x00")

    def test_an_empty_argv0_shifts_the_parse_and_fails_safe(self):  # r3 F3, a pinned limit
        buf = (2).to_bytes(4, "little") + b"/usr/bin/x\x00\x00\x00" + b"\x00" + b"arg1\x00" \
            + (cr.SESSION_VAR + "=REAL").encode() + b"\x00PATH=/bin\x00\x00"
        env = cr.parse_procargs2(buf)
        self.assertNotIn(cr.SESSION_VAR + "=REAL", env)  # the first environment entry is skipped: a lookup misses and refuses
        self.assertNotIn("arg1", env)  # an argument is never read as an environment entry

    def run_real_ah(self, env):
        import subprocess
        clean = {k: v for k, v in os.environ.items() if k not in ("CLAUDE_CODE_SESSION_ID", "CLAUDE_SESSION_ID", "AH_HOME")}
        clean.update(env)
        done = subprocess.run([sys.executable, str(T.HOOKS / "ah.py"), "clone-remove", "--path", "/x/y", "--reason", "r",
                               "--verify-only"], env=clean, capture_output=True, text=True, timeout=120)
        return done.returncode, done.stdout + done.stderr

    def test_the_real_ah_refuses_a_missing_or_unknown_session_in_a_real_process(self):  # option A, unmocked
        code, text = self.run_real_ah({})
        self.assertNotEqual(code, 0, text)
        self.assertIn("session", text)
        code, text = self.run_real_ah({"CLAUDE_CODE_SESSION_ID": "no-such-session-" + "x" * 8})
        self.assertNotEqual(code, 0, text)
        self.assertIn("session", text)


class IntentFields(T.Base):
    def interrupted(self):
        path = self.clone()
        real = os.unlink
        count = []

        def failing(name, *a, **kw):
            count.append(name)
            if len(count) > 3:
                raise OSError(5, "io")
            return real(name, *a, **kw)
        with mock.patch.object(os, "unlink", failing):
            return self.remove(path)

    def test_an_intent_row_without_a_directory_set_refuses_with_a_clone_error(self):  # r2 F2
        result = self.interrupted()
        real = cr.audit_rows

        def stripped(home, audit_id):
            return [{k: v for k, v in r.items() if k not in ("dirs_sha256", "dirs_count")} if r.get("kind") == "clone-intent" else r
                    for r in real(home, audit_id)]
        with mock.patch.object(cr, "audit_rows", stripped):
            with self.assertRaises(cr.CloneError) as caught:
                cr.resume_clone(result["audit_id"], SESSION, self.home)
        self.assertIn("no verified directory set", str(caught.exception))

    def test_the_directory_set_file_is_deleted_once_the_removal_is_recorded_and_kept_until_then(self):  # r2 F3
        result = self.interrupted()
        sidecar = cr.dirs_path(self.home, result["audit_id"])
        self.assertTrue(os.path.exists(sidecar))
        done = cr.resume_clone(result["audit_id"], SESSION, self.home)
        self.assertIs(done["removed"], True)
        self.assertFalse(os.path.exists(sidecar))
        path = self.clone("wt-second")
        whole = self.remove(path)
        self.assertFalse(os.path.exists(cr.dirs_path(self.home, whole["audit_id"])))


class VerifiedTree(T.Walk):
    def test_a_directory_outside_the_verified_set_is_kept_whole_on_any_walk(self):  # AC-6, F1
        root = self.tree()
        allowed = cr.dir_inodes(root)
        os.makedirs(os.path.join(root, "moved-in"))
        Path(root, "moved-in", "precious").write_text("x")
        stats = self.run_walk(root, allowed_dirs=allowed)
        self.assertEqual(Path(root, "moved-in", "precious").read_text(), "x")
        self.assertEqual([entry.split(" ")[0] for entry in stats["left"]], ["moved-in"])
        self.assertEqual(sorted(os.listdir(root)), ["moved-in"])

    def test_a_touched_but_verified_directory_is_still_emptied_and_a_new_file_in_it_is_kept(self):  # AC-8
        root = self.tree()
        cutoff = os.lstat(os.path.join(root, "sub", "deep", "c")).st_ctime_ns
        allowed = cr.dir_inodes(root)
        time.sleep(0.05)
        Path(root, "sub", "later").write_text("x")
        Path(root, "late").write_text("x")
        stats = self.run_walk(root, cutoff, allowed_dirs=allowed)
        self.assertFalse(os.path.exists(os.path.join(root, "sub", "b")), "an old file in a verified directory is deleted")
        self.assertTrue(os.path.exists(os.path.join(root, "sub", "later")))
        self.assertTrue(os.path.exists(os.path.join(root, "late")))
        self.assertEqual(sorted(entry.split(" ")[0] for entry in stats["left"]), ["late", "sub/later"])


class Rollback(T.Base):
    def quarantines(self):
        return [n for n in os.listdir(self.receipts) if n.startswith(cr.QUARANTINE_PREFIX)]

    def test_resume_never_deletes_what_the_first_run_kept(self):  # F1 (receipt r1b)
        path = self.clone()
        old = os.path.join(self.tmp, "olddir")
        os.makedirs(old)
        Path(old, "precious").write_text("x")

        def move_in(event, **kw):
            if event == "after_verify":
                os.rename(old, os.path.join(path, "moved-in"))
        with mock.patch.object(cr, "HOOK", move_in):
            result = self.remove(path)
        self.assertIsNone(result["removed"])
        again = cr.resume_clone(result["audit_id"], SESSION, self.home)
        self.assertIsNone(again["removed"])
        self.assertEqual(Path(result["quarantine"], "moved-in", "precious").read_text(), "x")

    def test_a_directory_moved_in_while_verification_runs_is_kept(self):  # Opus spec review, window between status and the end
        path = self.clone()
        old = os.path.join(self.tmp, "olddir")
        os.makedirs(old)
        Path(old, "precious").write_text("x")

        def move_in(event, **kw):
            if event == "after_status":
                os.rename(old, os.path.join(path, "moved-in"))
        with mock.patch.object(cr, "HOOK", move_in):
            result = self.remove(path)
        self.assertIsNone(result["removed"])
        self.assertEqual(Path(result["quarantine"], "moved-in", "precious").read_text(), "x")

    def test_the_walk_cannot_be_called_without_a_verified_directory_set(self):
        fd = os.open(self.tmp, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, fd)
        with self.assertRaises(TypeError):
            cr.walk_delete(fd, 2 ** 62)

    def test_any_promisor_value_git_reads_as_true_refuses_in_the_hook_form(self):  # Sonnet review M-a
        path = self.clone(partial=True)
        git(path, "config", "--unset", "remote.origin.partialclonefilter")
        git(path, "config", "remote.origin.promisor", "2")
        with mock.patch.object(cg, "REMOTE_LS", side_effect=AssertionError("the network must not be reached")):
            self.assertIn("partial clone", cg.reproducible_clone_refusal(path))

    def test_a_linked_worktree_of_a_partial_clone_is_refused_by_the_reclaim_route(self):  # D4 behaviour change, accepted by main
        primary = self.clone(partial=True)
        linked = os.path.join(self.tmp, "linked-wt")
        git(primary, "worktree", "add", "-q", "--detach", linked)
        with mock.patch.object(cg, "REMOTE_LS", side_effect=AssertionError("the network must not be reached")):
            reason = cg.linked_worktree_remove_refusal(linked, self.tmp, remote_ls=lambda *a, **k: {})
        self.assertIsNotNone(reason)
        self.assertIn("partial clone", reason)

    def test_a_file_moved_into_the_clone_after_verification_is_kept(self):  # real filesystem, no patched stat
        path = self.clone()
        stray = os.path.join(self.tmp, "stray.txt")
        Path(stray).write_text("x")
        os.utime(stray, (1_000_000_000, 1_000_000_000))

        def move_in(event, **kw):
            if event == "after_verify":
                os.rename(stray, os.path.join(path, "stray.txt"))
        with mock.patch.object(cr, "HOOK", move_in):
            result = self.remove(path)
        self.assertEqual(Path(result["quarantine"], "stray.txt").read_text(), "x")

    def test_a_missing_or_altered_directory_set_refuses_resume(self):  # F1
        path = self.clone()
        real = os.unlink
        count = []

        def failing(name, *a, **kw):
            count.append(name)
            if len(count) > 3:
                raise OSError(5, "io")
            return real(name, *a, **kw)
        with mock.patch.object(os, "unlink", failing):
            result = self.remove(path)
        sidecar = cr.dirs_path(self.home, result["audit_id"])
        saved = Path(sidecar).read_text()
        Path(sidecar).write_text(saved + "1 2\n")
        with self.assertRaises(cr.CloneError):
            cr.resume_clone(result["audit_id"], SESSION, self.home)
        os.unlink(sidecar)
        with self.assertRaises(cr.CloneError):
            cr.resume_clone(result["audit_id"], SESSION, self.home)
        self.assertTrue(os.path.isdir(result["quarantine"]))

    def test_the_hook_form_exemption_refuses_a_partial_clone_by_its_keys_without_the_network(self):  # D4, review of spec v4
        path = self.clone(partial=True)
        with mock.patch.object(cg, "REMOTE_LS", side_effect=AssertionError("the network must not be reached")):
            reason = cg.reproducible_clone_refusal(path)
        self.assertIn("partial clone", reason)

    def test_a_directory_moved_into_the_clone_after_verification_is_kept(self):  # M3
        path = self.clone()
        old = os.path.join(self.tmp, "olddir")
        os.makedirs(old)
        Path(old, "precious").write_text("x")

        def move_in(event, **kw):
            if event == "after_verify":
                os.rename(old, os.path.join(path, "moved-in"))
        with mock.patch.object(cr, "HOOK", move_in):
            result = self.remove(path)
        self.assertIsNone(result["removed"])
        self.assertEqual(Path(result["quarantine"], "moved-in", "precious").read_text(), "x")

    def test_an_unwritable_marker_puts_the_clone_back_and_records_it(self):  # M1
        path = self.clone()

        def lock_root(event, **kw):
            if event == "after_verify":
                os.chmod(path, 0o555)
        try:
            with mock.patch.object(cr, "HOOK", lock_root):
                with self.assertRaises(cr.CloneError):
                    self.remove(path)
        finally:
            os.chmod(path, 0o755)
        self.assertTrue(os.path.isdir(os.path.join(path, ".git")))
        self.assertEqual(self.quarantines(), [])
        self.assertIs(self.rows("clone-result")[-1]["removed"], False)

    def test_resume_restores_a_clone_whose_run_stopped_before_the_marker_row(self):  # M1
        path = self.clone()

        def killed(*a, **kw):
            raise KeyboardInterrupt  # the process dies between the rename and the marker
        with mock.patch.object(cr, "_write_marker", killed):
            with self.assertRaises(KeyboardInterrupt):
                self.remove(path)
        self.assertFalse(os.path.exists(path))
        restored = cr.resume_clone(self.rows("clone-intent")[0]["audit_id"], SESSION, self.home)
        self.assertTrue(restored["restored"])
        self.assertTrue(os.path.isdir(os.path.join(path, ".git")))
        self.assertEqual(self.quarantines(), [])

    def test_a_refusal_after_the_intent_row_writes_a_result_row(self):  # L3
        path = self.clone()
        os.makedirs(os.path.join(self.receipts, cr.QUARANTINE_PREFIX + "20260101T000000-aaaaaaaa"))
        with mock.patch.object(cr, "_now_id", lambda: "20260101T000000-aaaaaaaa"):
            with self.assertRaises(cr.CloneError):
                self.remove(path)
        self.assertEqual([r["kind"] for r in self.rows()], ["clone-intent", "clone-result"])
        self.assertIs(self.rows("clone-result")[0]["removed"], False)

    def test_a_relative_alternates_entry_is_resolved_against_objects(self):  # L1
        path = self.clone()
        borrower = os.path.join(self.receipts, "wt-rel")
        git(self.tmp, "clone", "-q", self.origin, borrower)
        Path(borrower, ".git", "objects", "info").mkdir(exist_ok=True)
        Path(borrower, ".git", "objects", "info", "alternates").write_text("../../../wt-a/.git/objects\n")
        self.assertRefused(path, "borrows")

    def test_a_token_as_the_only_userinfo_refuses(self):  # L2
        path = self.clone()
        git(path, "remote", "set-url", "origin", "https://ghp_tokenvalue@github.com/a/b.git")
        verdict = self.assertRefused(path, "credential")
        self.assertNotIn("ghp_tokenvalue", json.dumps(verdict))


if __name__ == "__main__":
    unittest.main()
