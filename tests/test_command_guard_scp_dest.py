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
    # option values AFTER the destination do not hide it (review M1)
    "rsync x t2-dev:~/.claude/hooks/command_guard.py -e ssh",
    "rsync x t2-dev:~/.claude/hooks/command_guard.py --chmod 644",
    "scp x t2-dev:~/.claude/hooks/command_guard.py -P 22",
    # IPv6 hosts (review M2)
    "scp x [::1]:~/.claude/hooks/command_guard.py",
    "scp x 'eric@[fe80::1]:~/.claude/hooks/command_guard.py'",
    # url forms, home-relative, with a user, a port, an escape (review M3)
    "scp x scp://t2-dev/.claude/hooks/command_guard.py",
    "scp x scp://eric@t2-dev/~/.claude/hooks/command_guard.py",
    "scp x scp://t2-dev:22/.claude/hooks/command_guard.py",
    "scp x scp://t2-dev/%2Eclaude/hooks/command_guard.py",
    # rsync daemon forms (review L1)
    "rsync x rsync://t2-dev/mod/.claude/hooks/command_guard.py",
    "rsync x t2-dev::mod/.claude/hooks/command_guard.py",
    # a sync or a recursive copy into a directory that CONTAINS protected files, and the delete flags (review H1, M4)
    "rsync -a --del src/ t2-dev:~/.claude/hooks/",
    "rsync -a --delete-after src/ t2-dev:~/.claude/hooks/",
    "rsync -a --delete src/ t2-dev:~/.claude/wals/",
    "rsync -av ./hooks/ t2-dev:~/.claude/hooks/",
    "scp -r hooks t2-dev:~/.claude/",
    "scp -r hooks/ t2-dev:~/.claude/hooks",
    # a short cluster ending in a value flag after the destination, and an unknown option with a value (review M5)
    "rsync x t2-dev:~/.claude/hooks/command_guard.py -avze ssh",
    "rsync -a x t2-dev:~/.claude/hooks/command_guard.py -e ssh",
    "scp x t2-dev:~/.claude/hooks/command_guard.py -rP 22",
    "rsync -a x t2-dev:~/.claude/hooks/command_guard.py --max-alloc 1G",
    "rsync -a x t2-dev:~/.claude/hooks/command_guard.py --some-future-opt 1G",
    # an empty remote path is the remote home (review M6)
    "rsync -a ./.claude t2-dev:",
    "scp -r .claude t2-dev:",
    "scp -r .claude user@t2-dev:",
    # contents copied to the home or a delete into it still reach the protected files (review M7, kept)
    "rsync -a ./ t2-dev:~/",
    "rsync -a --delete proj/ t2-dev:~/",
    "rsync -a --delete proj t2-dev:~/",
    # rsync -R / --relative / --files-from rebuild the source path under the destination (receipt r1 F1)
    "rsync -R .claude/hooks/command_guard.py t2-dev:",
    "rsync -aR .claude/hooks/command_guard.py t2-dev:~/",
    "rsync -aR ./.claude/hooks t2-dev:~/",
    "rsync -R /home/eric/.claude/hooks/command_guard.py t2-dev:/",
    "rsync --relative .claude/hooks/command_guard.py t2-dev:",
    "rsync -R /home/eric/./.claude/hooks/command_guard.py t2-dev:~/",
    "rsync --files-from=list.txt . t2-dev:~/",
    "rsync -a --files-from list.txt ./ t2-dev:~/",
    # sshpass is looked through (receipt r1 F2)
    "sshpass -p x scp x t2-dev:~/.claude/hooks/command_guard.py",
    "sshpass -f pw rsync -a x t2-dev:~/.claude/hooks/command_guard.py",
    "sshpass -e scp x t2-dev:~/.claude/hooks/command_guard.py",
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
    "scp t2-dev:~/.claude/hooks/command_guard.py /tmp/x -P 22",
    "rsync -a --del src/ t2-dev:~/project/",
    "rsync -av -e 'ssh -p 22' t2-dev:~/.claude/hooks/ /tmp/h/",
    "scp -r src t2-dev:~/project/",
    "scp x scp://t2-dev/tmp/x",
    # a project copied INTO the home is not a copy over the harness directories (review M7)
    "scp -r proj t2-dev:~/",
    "rsync -a proj t2-dev:~/",
    "rsync -avze ssh proj t2-dev:~/proj2/",
    "rsync -a proj t2-dev:~/p --max-alloc 1G",
    "rsync --rsh ssh t2-dev:~/.claude/hooks/command_guard.py /tmp/x",
    "rsync --zc zstd t2-dev:~/.claude/hooks/command_guard.py ./",
    "rsync --copy-as eric t2-dev:~/.claude/hooks/command_guard.py ./",
    "rsync -R src/app.py t2-dev:~/proj/",
    "rsync -aR ./proj/x.py t2-dev:~/",
    "sshpass -p x scp x t2-dev:/tmp/x",
    "rsync --exclude '*.pyc' t2-dev:~/.claude/hooks/ /tmp/h/",
    "scp -P22 x t2-dev:~/x",
    "scp -rP 22 x t2-dev:/tmp/x",
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
