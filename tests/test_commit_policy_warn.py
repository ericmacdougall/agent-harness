"""Commit policy warn mode (2026-11-24): form problems warn and exit 0; an empty message or a secret is refused;
strict mode (flag or local profile) still blocks. COMMIT_POLICY_HOOKS_DIR points the suite at another copy of the
hooks (the failing-first run on the old code)."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOOKS = Path(os.environ.get("COMMIT_POLICY_HOOKS_DIR") or ROOT / "harness" / "hooks")
DATA = ROOT / "tests" / "data"
GOOD = """fix(deliver): refuse non-compliant commit ranges before publication

Why: an agent reverted two production auth fixes with no recorded reason.
What: prepare runs the commit policy over the owner range and blocks.
Testing: `python3 -m unittest tests.test_commit_policy` -> 42 passed
Refs: GoodQA #14151
"""
LONG_SUBJECT = "fix(deliver): " + "refuse non-compliant commit ranges before publication and say why " * 2
LONG_SUBJECT = LONG_SUBJECT[:120]
FAKE_TOKEN = "gh" + "p_" + "Ab3" * 12  # secret-shaped at run time only, not a credential


class WarnMode(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(dir=ROOT / "tests")
        self.addCleanup(temp.cleanup)
        self.tmp = Path(temp.name)
        self.home = self.tmp / "home"
        self.home.mkdir()
        self.gitconfig = self.tmp / "gitconfig"
        self.gitconfig.write_text("[user]\n\tname = T\n\temail = t@example.invalid\n[init]\n\tdefaultBranch = main\n")
        self.env = {k: v for k, v in os.environ.items()
                    if not k.startswith(("GIT_", "CLAUDE", "CODEX", "AI_AGENT", "AGENT_HARNESS_POLICY_LOCAL"))}
        self.env.update(HOME=str(self.home), GIT_CONFIG_GLOBAL=str(self.gitconfig), GIT_CONFIG_NOSYSTEM="1",
                        PYTHONDONTWRITEBYTECODE="1")
        self.repo = self.tmp / "repo"
        self.git("init", "-q", str(self.repo), cwd=self.tmp)
        self.git("remote", "add", "origin", "https://github.com/example-org/demo.git")

    def git(self, *args, cwd=None, env=None):
        return subprocess.run(["git", *args], cwd=cwd or self.repo, env=env or self.env, capture_output=True,
                              text=True, timeout=60)

    def cli(self, *args, stdin=None, env=None, hooks=HOOKS):
        return subprocess.run([sys.executable, str(hooks / "commit_policy.py"), *args], input=stdin,
                              capture_output=True, text=True, env=env or self.env, timeout=60, cwd=self.tmp)

    def check(self, message, *flags, env=None):
        path = self.tmp / "msg.txt"
        path.write_text(message)
        return self.cli("check-message", *flags, "--file", str(path), env=env)

    def test_a_120_character_subject_warns_and_exits_0(self):
        self.assertEqual(len(LONG_SUBJECT), 120)
        result = self.check(GOOD.replace(GOOD.splitlines()[0], LONG_SUBJECT))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["status"], "WARN")
        self.assertTrue(any("120 chars" in item for item in report["warnings"]), report)

    def test_many_form_problems_print_at_most_three_warnings(self):
        result = self.check("wip\nno blank line, no sections, no refs\n")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertLessEqual(len(json.loads(result.stdout)["warnings"]), 3)

    def test_strict_flag_still_blocks(self):
        result = self.check(GOOD.replace(GOOD.splitlines()[0], LONG_SUBJECT), "--strict")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout)["status"], "BLOCKED")

    def test_strict_mode_in_the_local_profile_still_blocks(self):
        env = dict(self.env, AGENT_HARNESS_POLICY_LOCAL=str(DATA / "policy_profile_strict_fixture.json"))
        result = self.check("wip\n", env=env)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)

    def test_empty_message_is_refused(self):
        self.assertEqual(self.check("\n").returncode, 2)

    def test_a_secret_value_is_refused_without_printing_it(self):
        result = self.check(GOOD.replace("42 passed", "42 passed with token " + FAKE_TOKEN))
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertIn("looks like a secret", result.stdout)
        self.assertNotIn(FAKE_TOKEN, result.stdout + result.stderr)

    def test_pretooluse_hook_warns_and_allows_a_sloppy_commit(self):
        payload = {"session_id": "s", "cwd": str(self.repo), "tool_name": "Bash",
                   "tool_input": {"command": "git commit -m 'wip'"}}
        result = self.cli("hook", stdin=json.dumps(payload))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertLessEqual(len(result.stderr.strip().splitlines()), 4, result.stderr)
        self.assertIn("not blocking", result.stderr)

    def test_pretooluse_hook_refuses_a_secret(self):
        message = GOOD.replace("42 passed", FAKE_TOKEN)
        payload = {"session_id": "s", "cwd": str(self.repo), "tool_name": "Bash",
                   "tool_input": {"command": "git commit -F - <<'EOF'\n" + message + "EOF"}}
        result = self.cli("hook", stdin=json.dumps(payload))
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertNotIn(FAKE_TOKEN, result.stderr)

    def test_git_commit_msg_backstop_warns_and_allows(self):
        hooks = self.tmp / "hooks"
        shutil.copytree(HOOKS, hooks, ignore=shutil.ignore_patterns("__pycache__"))
        shutil.copy(DATA / "policy_profile_fixture.json", hooks / "commit_policy.local.json")  # backstop on, no mode
        command = 'f=%s; [ -f "$f" ] || exit 0; exec python3 "$f" git-hook' % (hooks / "commit_policy.py")
        self.git("config", "--global", "hook.agent-harness-commit-policy.event", "commit-msg")
        self.git("config", "--global", "hook.agent-harness-commit-policy.command", command)
        agent = dict(self.env, CLAUDECODE="1")
        done = self.git("commit", "-q", "--allow-empty", "-m", "wip", env=agent)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("not blocking", done.stderr)
        empty = self.git("commit", "-q", "--allow-empty", "--allow-empty-message", "-m", "", env=agent)
        self.assertNotEqual(empty.returncode, 0, "an empty message is still refused")

    def test_waive_accepts_any_non_empty_subject_and_reason(self):
        result = self.cli("waive", "--subject", "deadbeef", "--reason", "ok; fine")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["status"], "WAIVED")


if __name__ == "__main__":
    unittest.main()
