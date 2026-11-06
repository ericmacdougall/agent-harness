"""kill_guard: the word "kill" inside data given to harness CLIs, or inside a string literal of inline Python, is not
signalling (GoodQA goodqa#14864). Real signalling must still be blocked."""
import sys
import tempfile
import unittest
from pathlib import Path

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import kill_guard as kg  # noqa: E402

CLI = "python3 ~/.claude/hooks/"
WAL = "/Users/eric/.claude/wals/s1/main.jsonl"
HOME = str(Path.home())

ALLOW = [
    CLI + "ah.py user-msg --text 'find the ah kill discussion'",
    CLI + 'ah.py user-msg --recent 5 --text "kill and pkill talk"',
    CLI + "wal_note.py --wal %s --event status --note 'kill-guard follow-up: ah kill scope'" % WAL,
    CLI + "wal_note.py --wal %s --event decision --note 'kill 4242 was refused' --source inferred:x" % WAL,
    CLI + "provenance.py find-user --session s1 --text 'please kill it'",
    "python3 -I " + HOME + "/.claude/hooks/wal_note.py --wal %s --event check --note 'os.kill is blocked'" % WAL,
    "python3 -c \"title = 'ah kill: audited process stop command'; print(title)\"",
    "python3 -c 'import json; print(json.dumps({\"title\": \"kill-guard false positives\"}))'",
    "python3 -c \"print('the word kill appears here as data')\"",
    "python3 -c \"import json; t = 'ah kill scope'; print(json.dumps({'title': t, 'n': len([1, 2])}))\"",
    "python3 -c \"import datetime; print(f'kill-ticket {datetime.date.today()}')\"",
]
BLOCK = [
    CLI + "ah.py kill --pid 1 --reason x",
    CLI + "ah.py kill --pid 4242",
    CLI + "ah.py kill --pid $(pgrep -f x) --reason x",
    CLI + "ah.py kill --pid 4242 --reason x --wal /etc/passwd",
    "python3 ./ah.py user-msg --text 'kill 1'",
    "python3 /tmp/ah.py user-msg --text 'kill 1'",
    "python3 /tmp/x.py --note 'kill 1'",
    "PYTHONPATH=/tmp/x " + CLI + "ah.py user-msg --text 'kill'",
    "python3 -c 'import os; os.kill(4242, 9)'",
    "python3 -c \"x = 'ok'; import os; os.kill(1, 9)\"",
    "python3 -c 'import os, signal; os.killpg(1, signal.SIGKILL)'",
    "python3 -c 'import os, signal; os.pthread_kill(1, signal.SIGTERM)'",
    "python3 -c 'import signal; signal.raise_signal(signal.SIGTERM)'",
    "python3 -c 'import subprocess; subprocess.run([\"kill\", \"-9\", \"4242\"])'",
    "python3 -c 'import subprocess; subprocess.run(\"kill -9 4242\", shell=True)'",
    "python3 -c \"import os; os.system('echo hi; pkill -f x')\"",
    "python3 -c \"import os; os.system('xargs kill')\"",
    "python3 -c \"import subprocess; subprocess.run(['/bin/kill', '4242'])\"",
    "python3 -c 'import os; os.kill(int(open(\"p\").read()), 9)'",
    "python3 -c \"import subprocess; subprocess.Popen(['bash','-c','kill 4242'])\"",
    "kill 4242", "pkill -f vite", "bash -c 'kill 4242'",
    "node -e \"process.kill(4242)\"", "ruby -e 'Process.kill(9, 4242)'",
    "node -e \"console.log('kill is data')\"",  # only pure-data Python is narrowed
    # red-team of 58ee560: code hidden in literals, comment desync, odd shell strings, argparse tricks, other homes
    "python3 -c 'import os; f\"{os.kill(4242, 9)}\"'",
    "python3 -c 'exec(\"import os; os.kill(4242, 9)\")'",
    "python3 -c 'eval(\"__import__(\\\"os\\\").kill(4242,9)\")'",
    "python3 -c 'exec(compile(\"import os\\nos.kill(1,9)\",\"x\",\"exec\"))'",
    "python3 -c 'import os; getattr(os, \"pthread_kill\")(1, 9)'",
    "python3 -c 'import os # \"\"\"\nos.kill(4242, 9) # \"\"\"'",
    "python3 -c 'import os; os.system(\"command kill 1\")'",
    "python3 -c 'import os; os.system(\"{ kill 1; }\")'",
    "python3 -c 'import os; os.system(\"x=1 kill 1\")'",
    "python3 -c 'import os; os.system(\"tmux kill-server\")'",
    "python3 -c 'import os; print(\"kill\")'",
    "python3 -c 'import subprocess; print(\"kill\")'",
    # review of 679c18b: reaching the OS through sys.modules / exec* / spawn* from a "pure data" program
    "python3 -c \"import sys; sys.modules['os'].execv('/bin/kill', ['kill','-9','4242'])\"",
    "python3 -c \"import sys; sys.modules['os'].posix_spawn('/bin/kill', ['kill','-9','4242'], {})\"",
    "python3 -c \"import json, sys; sys.modules['os'].execvp('pkill', ['pkill','x'])\"",
    "python3 -c \"import re; print(re.__builtins__['__import__']('os').kill(1, 9))\"",
    "python3 -c \"import operator; operator.methodcaller('kill', 4242, 9)(__import__('os'))\"",
    "python3 -c \"print(open('/etc/hosts').read(), 'kill')\"",
    # review of 2e668cf: module members outside the allowlist reach sys/os through an allowed import
    "python3 -c \"import re; re.enum.sys.modules['os'].system('pkill -f node')\"",
    "python3 -c \"import json; json.decoder.re.enum.sys.modules['os'].system('pkill -f node')\"",
    "python3 -c \"import textwrap; textwrap.re.enum.sys.modules['os'].system('pkill -f node')\"",
    "python3 -c \"from re import enum; enum.sys.modules['os'].system('pkill -f node')\"",
    "python3 -c \"import re as r; r.enum.sys.modules['os'].system('pkill -f node')\"",
    "python3 -c \"import re; re = 1; print('kill')\"",
    CLI + "ah.py --text kill --pid 4242 --reason x --foreign",
    CLI + "ah.py -- kill --pid 4242",
    CLI + "ah.py --te kill --pid 4242 --reason x",
    "python3 /Users/bob/.claude/hooks/ah.py user-msg --text 'kill 1'",
    "python3 /home/bob/.claude/hooks/wal_note.py --note 'kill 1'",
]


class DataArgs(unittest.TestCase):
    def verdict(self, cmd):
        with tempfile.TemporaryDirectory() as tmp:
            return kg.decide(cmd, cwd=tmp, policy=kg.load_policy(), home=tmp)[0]

    def test_data_mentions_of_kill_pass(self):
        for cmd in ALLOW:
            with self.subTest(cmd=cmd):
                self.assertEqual(self.verdict(cmd), "allow")

    def test_real_signalling_stays_blocked(self):
        for cmd in BLOCK:
            with self.subTest(cmd=cmd):
                self.assertEqual(self.verdict(cmd), "block")


class WranglerSql(unittest.TestCase):
    """npx wrangler d1 execute --command "SELECT count(*) ..." was blocked: the SQL was re-read as a shell line and its
    (*) became a command-position glob that can match pkill (goodqa#14506)."""

    def decide(self, cmd):
        with tempfile.TemporaryDirectory() as tmp:
            return kg.decide(cmd, cwd=tmp, policy=kg.load_policy(), home=tmp)

    def test_sql_in_command_option_passes(self):
        for cmd in (
            'npx wrangler d1 execute DB --remote --command "SELECT count(*) FROM users WHERE lower(email)=\'a@b.com\'"',
            'npx wrangler d1 execute DB --command "SELECT count(*) FROM users" --json',
            'pnpm exec wrangler d1 execute DB --command "SELECT count(*) FROM users"',
            'env CF=1 npx wrangler d1 execute DB --command "SELECT max(id), count(*) FROM t"',
        ):
            with self.subTest(cmd=cmd):
                self.assertEqual(self.decide(cmd)[0], "allow")

    def test_real_commands_in_command_option_still_block(self):
        for cmd in (
            "su -c 'pkill -f x' bob", "su --command 'pkill -f x' bob", "runuser --command 'kill 1' bob",
            'npx runner --command "pkill -f vite"', 'npx runner --command "echo a; kill 4242"',
            'env X=1 sh -c "SELECT count(*) FROM t"',  # a shell really would run the glob
            "env x 'SELECT count(*) FROM users'",
        ):
            with self.subTest(cmd=cmd):
                self.assertEqual(self.decide(cmd)[0], "block")

    def test_block_message_names_every_finding(self):
        verdict, _rule, message, _pids = self.decide("pkill -f a; killall node; skill -9 b")
        self.assertEqual(verdict, "block")
        self.assertNotRegex(message, r"\(\d+ more\)")
        for word in ("pkill", "killall", "skill"):
            self.assertIn(word, message)
        self.assertIn("Also found", message)


if __name__ == "__main__":
    unittest.main()
