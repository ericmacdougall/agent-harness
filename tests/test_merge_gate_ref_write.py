"""merge_gate.py: a tag written through the GitHub refs API must point at an ancestor of main (goodqa#14909).

Real-tool control: every case runs against a real throwaway git repository (no network); the fake gh runner raises if
the gate ever calls gh, because this path must be decided from local git alone. Deterministic: no randomness."""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
HOOKS = Path(os.environ.get("MERGE_GATE_HOOKS_DIR") or ROOT / "harness" / "hooks")  # override: failing-first run on old code
sys.path.insert(0, str(HOOKS))
import merge_gate as mg  # noqa: E402


def git(cwd, *args):
    env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@e", GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@e",
               GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_SYSTEM="/dev/null")
    return subprocess.run(["git", *args], cwd=cwd, env=env, capture_output=True, text=True, check=True).stdout.strip()


def no_gh(args, timeout, cwd=None):
    raise AssertionError("the ref-write path must not call gh: " + " ".join(args))


class RefWriteTag(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.repo = os.path.join(cls.tmp.name, "r")
        os.mkdir(cls.repo)
        git(cls.repo, "init", "-q", "-b", "main")
        git(cls.repo, "remote", "add", "origin", "https://github.com/o/r.git")
        for name in ("a", "b"):
            Path(cls.repo, name).write_text(name)
            git(cls.repo, "add", name)
            git(cls.repo, "commit", "-q", "-m", name)
        cls.on_main = git(cls.repo, "rev-parse", "HEAD")
        git(cls.repo, "update-ref", "refs/remotes/origin/main", cls.on_main)
        git(cls.repo, "checkout", "-q", "--orphan", "old")  # unrelated history, like the pre-rewrite line
        Path(cls.repo, "o").write_text("old")
        git(cls.repo, "add", "o")
        git(cls.repo, "commit", "-q", "-m", "old")
        cls.off_main = git(cls.repo, "rev-parse", "HEAD")
        git(cls.repo, "checkout", "-q", "main")
        cls.plain = os.path.join(cls.tmp.name, "plain")
        os.mkdir(cls.plain)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def run_cmd(self, command, cwd=None):
        payload = {"tool_name": "Bash", "tool_input": {"command": command}, "cwd": cwd or self.repo}
        with tempfile.TemporaryDirectory() as state:
            return mg.decide(payload, no_gh, state)

    def api(self, method, endpoint, *fields):
        return "gh api -X %s %s %s" % (method, endpoint, " ".join("-f %s" % f for f in fields))

    def test_tag_on_main_allowed(self):
        code, _ = self.run_cmd(self.api("POST", "repos/o/r/git/refs", "ref=refs/tags/v1", "sha=" + self.on_main))
        self.assertEqual(code, 0)

    def test_tag_off_main_blocked(self):  # the incident: backup-pin pinned an old, non-main line
        code, text = self.run_cmd(self.api("POST", "repos/o/r/git/refs", "ref=refs/tags/backup-pin/x", "sha=" + self.off_main))
        self.assertEqual(code, 2, text)
        self.assertIn("not an ancestor of main", text)

    def test_tag_move_via_patch_blocked(self):
        code, text = self.run_cmd(self.api("PATCH", "repos/o/r/git/refs/tags/v1", "sha=" + self.off_main, "force=true"))
        self.assertEqual(code, 2, text)

    def test_annotated_tag_object_blocked(self):
        code, text = self.run_cmd(self.api("POST", "repos/o/r/git/tags", "tag=v2", "message=m", "object=" + self.off_main, "type=commit"))
        self.assertEqual(code, 2, text)

    def test_branch_create_out_of_scope(self):
        code, _ = self.run_cmd(self.api("POST", "repos/o/r/git/refs", "ref=refs/heads/feat", "sha=" + self.off_main))
        self.assertEqual(code, 0)

    def test_delete_never_blocked(self):
        code, _ = self.run_cmd("gh api -X DELETE repos/o/r/git/refs/tags/backup-pin/x")
        self.assertEqual(code, 0)

    def test_read_never_blocked(self):
        code, _ = self.run_cmd("gh api repos/o/r/git/refs/tags")
        self.assertEqual(code, 0)

    def test_runtime_sha_blocked(self):
        code, text = self.run_cmd('gh api -X POST repos/o/r/git/refs -f ref=refs/tags/v1 -f sha=$SHA')
        self.assertEqual(code, 2, text)

    def test_hidden_body_blocked(self):
        code, text = self.run_cmd("gh api -X POST repos/o/r/git/refs --input body.json")
        self.assertEqual(code, 2, text)

    def test_short_sha_blocked(self):
        code, text = self.run_cmd(self.api("POST", "repos/o/r/git/refs", "ref=refs/tags/v1", "sha=" + self.on_main[:10]))
        self.assertEqual(code, 2, text)

    def test_unknown_commit_blocked(self):
        code, text = self.run_cmd(self.api("POST", "repos/o/r/git/refs", "ref=refs/tags/v1", "sha=" + "c" * 40))
        self.assertEqual(code, 2, text)

    def test_not_a_checkout_blocked(self):
        code, text = self.run_cmd(self.api("POST", "repos/o/r/git/refs", "ref=refs/tags/v1", "sha=" + self.on_main), cwd=self.plain)
        self.assertEqual(code, 2, text)

    def test_other_repo_checkout_blocked(self):
        code, text = self.run_cmd(self.api("POST", "repos/x/y/git/refs", "ref=refs/tags/v1", "sha=" + self.on_main))
        self.assertEqual(code, 2, text)

    def test_wrapped_in_bash_c_blocked(self):
        inner = self.api("POST", "repos/o/r/git/refs", "ref=refs/tags/v1", "sha=" + self.off_main)
        code, text = self.run_cmd("bash -c '%s'" % inner)
        self.assertEqual(code, 2, text)

    def test_cd_elsewhere_blocked(self):
        inner = self.api("POST", "repos/o/r/git/refs", "ref=refs/tags/v1", "sha=" + self.on_main)
        code, text = self.run_cmd("cd /somewhere/else && " + inner)
        self.assertEqual(code, 2, text)

    def test_cases_not_vacuous(self):
        self.assertNotEqual(self.on_main, self.off_main)
        self.assertEqual(len(self.on_main), 40)


if __name__ == "__main__":
    unittest.main()
