"""goodqa#15787: bulk staging (git add -A, ., :/, -u; git commit -a) in a shared original checkout that has uncommitted changes
sweeps other sessions' work into one commit. The guard gives a bulk_staging finding (a warn by default, a block under enforce
mode) for the original checkout (a `.git` DIRECTORY) with changes, and leaves a linked worktree, a clean checkout, explicit
paths and every other directory alone. Real temporary repositories; no network."""
import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import command_guard as cg  # noqa: E402

ENV = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.com", GIT_COMMITTER_NAME="t",
           GIT_COMMITTER_EMAIL="t@example.com", GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_SYSTEM="/dev/null")


def git(cwd, *args):
    return subprocess.run(["git", *args], cwd=str(cwd), env=ENV, capture_output=True, text=True, check=True).stdout.strip()


def decide(command, mode=None, cwd=None):
    policy = cg.load_policy()
    if mode:
        policy["modes"]["bulk_staging"] = mode
    compiled = cg.Compiled(policy)
    return cg.decide(command, compiled, cwd=cwd, marker=cg.Approvals(compiled=compiled))


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name).resolve()
        self.orig = root / "orig"
        self.orig.mkdir()
        git(self.orig, "init", "-q", "-b", "main")
        (self.orig / "a.txt").write_text("a\n")
        (self.orig / "sub").mkdir()
        (self.orig / "sub" / "b.txt").write_text("b\n")
        git(self.orig, "add", "-A")
        git(self.orig, "commit", "-q", "-m", "init")
        (self.orig / "a.txt").write_text("changed by another session\n")  # uncommitted: the dirt that must not be swept
        self.wt = root / "wt"
        git(self.orig, "worktree", "add", "-q", "--detach", str(self.wt))
        (self.wt / "a.txt").write_text("mine\n")
        self.clean = root / "clean"
        self.clean.mkdir()
        git(self.clean, "init", "-q", "-b", "main")
        (self.clean / "x").write_text("x\n")
        git(self.clean, "add", "-A")
        git(self.clean, "commit", "-q", "-m", "init")
        self.plain = root / "plain"
        self.plain.mkdir()

    def verdict(self, command, cwd, mode=None):
        result = decide("cd %s && %s" % (cwd, command), mode)
        return result[0], result[1] if len(result) > 1 else ""

    def finding(self, command, cwd, mode=None):
        verdict, message = self.verdict(command, cwd, mode)
        return verdict != "allow" and "bulk_staging" in message


BULK = ["git add -A", "git add --all", "git add .", "git add ./", "git add -- .", "git add :/", "git add ':(top)'", "git add -u",
        "git add --update", "git stage -A", "git add -Au", "git add -fA", "git add sub/..", "git add ../orig",
        "git commit -a -m x", "git commit -am x", "git commit --all -m x", "git commit -sa -m x", "git commit -m x -a",
        "git add --a", "git add --upd", "git add -A -- .", "git add *", "git add ':/'"]
EXPLICIT = ["git add a.txt", "git add sub/", "git add sub/.", "git add ./sub/b.txt", "git add -p", "git add -p .", "git add -i", "git add -N a.txt",
            "git commit -m x", "git commit -m '-a'", "git commit -ma", "git commit -m x a.txt", "git commit --amend --no-edit",
            "git commit -m 'add -A'", "git status", "git diff", "git add --dry-run a.txt", "git commit -F msg.txt"]


class BulkStaging(Base):
    # AC-1
    def test_bulk_forms_in_a_dirty_original_checkout_give_a_finding(self):
        for command in BULK:
            with self.subTest(command):
                self.assertTrue(self.finding(command, self.orig), command)

    def test_the_same_forms_behind_dash_c_work_tree_and_environment_give_a_finding(self):
        for command in ("git -C %s add -A" % self.orig, "git --work-tree=%s --git-dir=%s/.git add -A" % (self.orig, self.orig),
                        "GIT_WORK_TREE=%s GIT_DIR=%s/.git git add ." % (self.orig, self.orig), "git -C %s commit -am x" % self.orig):
            with self.subTest(command):
                self.assertTrue(self.finding(command, self.plain), command)

    def test_a_bulk_form_run_from_inside_a_subdirectory_of_the_original_checkout_gives_a_finding(self):
        self.assertTrue(self.finding("git add .", self.orig / "sub"))

    # AC-2
    def test_explicit_paths_interactive_forms_and_message_text_are_left_alone(self):
        for command in EXPLICIT:
            with self.subTest(command):
                self.assertFalse(self.finding(command, self.orig), command)

    def test_a_linked_worktree_a_clean_checkout_and_a_plain_directory_are_left_alone(self):
        for where in (self.wt, self.clean, self.plain):
            for command in ("git add -A", "git commit -am x", "git add ."):
                with self.subTest("%s %s" % (where.name, command)):
                    self.assertFalse(self.finding(command, where), command)

    def test_dash_c_into_a_linked_worktree_from_the_original_checkout_is_left_alone_and_the_reverse_is_not(self):
        self.assertFalse(self.finding("git -C %s add -A" % self.wt, self.orig))
        self.assertTrue(self.finding("git -C %s add -A" % self.orig, self.wt))

    # AC-3
    def test_an_alias_expansion_is_judged(self):
        self.assertTrue(self.finding("git -c alias.a='add -A' a", self.orig))
        self.assertTrue(self.finding("git -c alias.ca='commit -a -m x' ca", self.orig))
        self.assertTrue(self.finding("git -c alias.b='!git add -A' b", self.orig))
        self.assertFalse(self.finding("git -c alias.l='log -1' l", self.orig))
        self.assertFalse(self.finding("git -c alias.a='add -A' a", self.wt))

    # AC-4
    def test_the_mode_decides_warn_or_block_and_the_message_names_the_sanctioned_form(self):
        verdict, message = self.verdict("git add -A", self.orig)
        self.assertEqual(verdict, "warn", message)
        self.assertIn("bulk_staging", message)
        self.assertIn("explicit", message.lower())
        verdict, message = self.verdict("git add -A", self.orig, mode="enforce")
        self.assertEqual(verdict, "block", message)
        self.assertEqual(self.verdict("git add a.txt", self.orig, mode="enforce")[0], "allow")
        self.assertEqual(self.verdict("git add -A", self.wt, mode="enforce")[0], "allow")

    def test_the_other_categories_keep_their_modes(self):
        policy = cg.load_policy()
        self.assertEqual(policy["modes"]["secret_dump"], "enforce")
        self.assertEqual(policy["modes"]["log_delete"], "enforce")
        self.assertEqual(policy["modes"]["broad_kill"], "warn")
        self.assertEqual(policy["modes"]["bulk_staging"], "warn")

    # NEG-7
    def test_an_unreadable_status_reports_nothing_and_never_raises(self):
        broken = Path(self.tmp.name) / "broken"
        (broken / ".git").mkdir(parents=True)  # a .git directory that is not a repository
        self.assertFalse(self.finding("git add -A", broken))
        self.assertFalse(self.finding("git add -A", Path(self.tmp.name) / "no-such-directory"))


if __name__ == "__main__":
    unittest.main()
