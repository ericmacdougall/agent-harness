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
SESSION, ah, cr, git = T.SESSION, T.ah, T.cr, T.git


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
        code, text = self.cli(dict(base, CLAUDE_CODE_SESSION_ID=SESSION), SESSION, "/somewhere/else", "--path", path)
        self.assertNotEqual(code, 0, text)  # an AH_HOME that is not the account's real home
        self.assertTrue(os.path.isdir(path))


class FirstRunAndResume(T.Walk):
    def newer(self, resumed):
        root = self.tree()
        cutoff = os.lstat(os.path.join(root, "sub", "deep", "c")).st_ctime_ns
        time.sleep(0.05)
        Path(root, "late").write_text("x")
        Path(root, "sub", "later").write_text("x")
        os.makedirs(os.path.join(root, "newdir"))
        Path(root, "newdir", "inner").write_text("x")
        return root, self.run_walk(root, cutoff, resumed=resumed)

    def test_first_run_judges_every_entry_by_ctime_so_a_touched_directory_is_kept_whole(self):  # AC-6, H2, M3
        root, stats = self.newer(False)
        self.assertTrue(os.path.exists(os.path.join(root, "late")))
        self.assertTrue(os.path.exists(os.path.join(root, "newdir", "inner")))
        self.assertTrue(os.path.exists(os.path.join(root, "sub", "b")), "sub was touched after the cutoff: kept whole")
        self.assertEqual(sorted(entry.split(" ")[0] for entry in stats["left"]), ["late", "newdir", "sub"])
        self.assertFalse(os.path.exists(os.path.join(root, "a")))

    def test_a_resumed_walk_judges_directories_by_birth_so_a_partly_emptied_one_is_finished(self):  # AC-8
        root, stats = self.newer(True)
        self.assertTrue(os.path.exists(os.path.join(root, "late")))
        self.assertTrue(os.path.exists(os.path.join(root, "newdir", "inner")), "born after the cutoff: kept whole")
        self.assertTrue(os.path.exists(os.path.join(root, "sub", "later")))
        self.assertFalse(os.path.exists(os.path.join(root, "sub", "b")), "an old file in an old directory is deleted on resume")
        self.assertEqual(sorted(entry.split(" ")[0] for entry in stats["left"]), ["late", "newdir", "sub/later"])


class Rollback(T.Base):
    def quarantines(self):
        return [n for n in os.listdir(self.receipts) if n.startswith(cr.QUARANTINE_PREFIX)]

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
