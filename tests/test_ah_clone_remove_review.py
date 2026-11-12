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
    def cli(self, env, parent_session, trusted, *extra):
        out = io.StringIO()
        with mock.patch.dict(os.environ, env), redirect_stdout(out), \
                mock.patch.object(ah, "_session_env_of", lambda pid: parent_session), \
                mock.patch.object(cr, "trusted_home", lambda: trusted or self.home):
            code = ah.main(["clone-remove", "--reason", "why", "--verify-only", *extra])
        return code, out.getvalue()

    def test_the_cli_takes_the_session_from_the_harness_identity_only(self):  # NEG-15, M2
        path = self.clone()
        os.makedirs(os.path.join(self.home, ".agent-harness", "work", "other", "receipts"))
        base = {"AH_HOME": self.home, "AH_SESSION": SESSION, "SESSION": SESSION}
        code, text = self.cli(dict(base, CLAUDE_CODE_SESSION_ID="other"), SESSION, None, "--path", path)
        self.assertNotEqual(code, 0, text)  # a variable that differs from the calling shell's session
        code, text = self.cli(dict(base, CLAUDE_CODE_SESSION_ID=SESSION), SESSION, None, "--path", path)
        self.assertEqual(code, 0, text)
        self.assertTrue(json.loads(text)["removable"])
        code, text = self.cli(dict(base, CLAUDE_CODE_SESSION_ID=SESSION), None, None, "--path", path)
        self.assertNotEqual(code, 0, text)  # the calling shell's session cannot be read: refuse
        code, text = self.cli({"AH_HOME": self.home, "CLAUDE_SESSION_ID": SESSION}, SESSION, None, "--path", path)
        self.assertNotEqual(code, 0, text)  # the CLAUDE_SESSION_ID fallback is not accepted
        code, text = self.cli(dict(base, CLAUDE_CODE_SESSION_ID=SESSION), SESSION, "/somewhere/else", "--path", path)
        self.assertNotEqual(code, 0, text)  # an AH_HOME that is not the account's real home
        self.assertTrue(os.path.isdir(path))


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
