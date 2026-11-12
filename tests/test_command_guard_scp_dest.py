"""goodqa#15759: scp and rsync TO a remote harness path are refused like a local or ssh-wrapped cp (the 2026-11-11 t2-dev install of
command_guard.py was blocked as cp and then done with scp). Downloads and ordinary remote destinations stay allowed."""
import contextlib
import io
import json
import sys
import unittest
from pathlib import Path

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import command_guard as cg  # noqa: E402


def check(command):
    compiled = cg.Compiled(cg.load_policy())
    return cg.decide(command, compiled, marker=cg.Approvals(compiled=compiled))


def hook(command):
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": command}}).encode()
    err = io.StringIO()
    with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
        code = cg.hook_main("exit2", stdin_bytes=payload, marker=False)
    return code, err.getvalue()


BLOCKED = [
    "scp x t2-dev:~/.claude/hooks/command_guard.py",
    "scp -P 22 x user@t2-dev:/home/eric/.claude/hooks/command_guard.py",
    "scp -r d t2-dev:.claude/hooks/command_guard.py",
    "scp x scp://t2-dev/home/eric/.claude/hooks/command_guard.py",
    "scp command_guard.py t2-dev:~/.claude/hooks/",
    "scp /tmp/work/command_guard.py t2-dev:.claude/hooks",
    "rsync -a x t2-dev:~/.claude/hooks/command_guard.py",
    "rsync -av -e 'ssh -p 22' ah.py command_guard.py t2-dev:~/.claude/hooks/",
    "rsync -a x user@t2-dev:/home/eric/.claude/hooks/command_guard.py",
    "scp x t2-dev:~/.claude/wals/s/main.jsonl",
    "scp -i key -o BatchMode=yes x t2-dev:~/.claude/hooks/command_guard.py",
]
ALLOWED = [
    "scp t2-dev:~/.claude/hooks/command_guard.py /tmp/x",
    "scp -r t2-dev:~/.claude/hooks /tmp/hooks-copy",
    "rsync -av t2-dev:~/.claude/hooks/ /tmp/hooks-copy/",
    "scp x t2-dev:/tmp/x",
    "scp x t2-dev:",
    "scp x.py t2-dev:~/project/x.py",
    "rsync -av x t2-dev:~/project/",
    "rsync -av src/ user@host:/srv/app/",
    "scp -P 2222 report.txt user@host:reports/",
    "scp a.txt b.txt t2-dev:/tmp/",
]


class RemoteDestinations(unittest.TestCase):
    def test_a_copy_to_a_remote_harness_path_is_blocked_with_the_cp_rule_id(self):  # AC-1, AC-2
        for command in BLOCKED:
            with self.subTest(command):
                verdict, message = check(command)
                self.assertEqual(verdict, "block", command)
                self.assertIn("log_delete/log-delete", message)
                self.assertIn("ah install-files", message)

    def test_downloads_and_ordinary_remote_destinations_stay_allowed(self):  # AC-3, NEG-1
        for command in ALLOWED:
            with self.subTest(command):
                self.assertEqual(check(command)[0], "allow", command)

    def test_the_hook_entry_blocks_the_scp_and_lets_the_download_pass(self):  # AC-4
        code, message = hook("scp x t2-dev:~/.claude/hooks/command_guard.py")
        self.assertEqual(code, 2)
        self.assertIn("ah install-files", message)
        self.assertEqual(hook("scp t2-dev:~/.claude/hooks/command_guard.py /tmp/x")[0], 0)

    def test_the_existing_cp_rules_are_unchanged(self):  # AC-5
        for command in ("cp x ~/.claude/hooks/command_guard.py", 'ssh t2-dev "cp x ~/.claude/hooks/command_guard.py"',
                        'ssh t2-dev "mv x ~/.claude/hooks/command_guard.py"'):
            with self.subTest(command):
                self.assertEqual(check(command)[0], "block")
        self.assertEqual(check("cp x ~/.claude/hooks/")[0], "allow")  # a directory destination without a protected file stays as before

    def test_the_sanctioned_command_itself_is_not_blocked_by_this_rule(self):  # AC-5
        command = 'python3 -I ~/.claude/hooks/ah.py install-files --host t2-dev --from-ref %s --file ah.py --ticket "GoodQA goodqa#15742"' % ("a" * 40)
        self.assertEqual(check(command)[0], "allow")


if __name__ == "__main__":
    unittest.main()
