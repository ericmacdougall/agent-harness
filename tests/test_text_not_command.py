"""Guards judge commands, not text (goodqa#17149, goodqa#17094 and the bare-word class).

Every command string here is data for a guard. None of them is ever run by a shell. TNC_HOOKS_DIR points the suite at
another hooks directory (for example the base commit's) to show the allow rows failing first.
"""
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
HOOKS = Path(os.environ.get("TNC_HOOKS_DIR") or ROOT / "harness" / "hooks")
sys.path.insert(0, str(HOOKS))
sys.path.insert(0, str(ROOT))
import command_guard_hook as launcher  # noqa: E402
import shell_words  # noqa: E402

TOOLS = ("wal_note.py", "ah.py", "usage_guard.py")
NOTE = "python3 ~/.claude/hooks/wal_note.py --wal ~/.claude/wals/s1/agent-a.jsonl --event status --note "
COMMENT = "python3 ~/.claude/hooks/ah.py ticket comment goodqa#17149 --body "
RECONCILE = "python3 ~/.claude/hooks/usage_guard.py reconcile --run r-1 --actor main --reason "

RECORDS = [
    NOTE + "'one'",
    NOTE + '"pkill -f was refused; the note only says so"',
    "\n".join(NOTE + "'note %d: rm, mv and kill are words here'" % n for n in range(3)),
    NOTE + "'a' && " + NOTE + "'b'; " + COMMENT + "'c'",
    NOTE + "'a'\n\n" + NOTE + "'b'\n",
    NOTE + "'ah.py install-files was named, not run' --ticket goodqa#17149",
    NOTE + "'two lines\nkill 1\n'",
    "python3 -I -B ~/.claude/hooks/wal_note.py --event check --note plain --result PASS --live "
    "--wal ~/.claude/wals/s1/main.jsonl",
    COMMENT + '"the script runs kill and git merge"',
    "python3 ~/.claude/hooks/ah.py ticket get goodqa#17149 && python3 ~/.claude/hooks/ah.py ticket comments goodqa#17149",
    RECONCILE + "'the run was stopped, pid 4242 is gone' --evidence 'ps shows no such process; kill -0 said no'",
]

# Each is one step away from a recording call. Not one of them may take the fast path.
NEAR_MISSES = [
    # something else in the command
    NOTE + "'a'; rm -rf ~/.claude/wals/s1", NOTE + "'a' && kill 4242", "rm -f x; " + NOTE + "'a'", NOTE + "'a'\nkill 4242",
    "echo hi; " + NOTE + "'a'", "cd /tmp && " + NOTE + "'a'", NOTE + "'a' & kill 4242", NOTE + "'a' &", NOTE + "'a' || kill 1",
    NOTE + "'a' | sh", NOTE + "'a' |& bash", "echo x | " + NOTE + "'a'", "( " + NOTE + "'a' )", "{ " + NOTE + "'a'; }",
    "! " + NOTE + "'a'", "if true; then " + NOTE + "'a'; fi", "time " + NOTE + "'a'", "sudo " + NOTE + "'a'",
    "env " + NOTE + "'a'", "exec " + NOTE + "'a'", "eval " + NOTE + "'a'", "ssh host " + NOTE + "'a'",
    NOTE + "'a' &&\n" + NOTE + "'b'", NOTE + "'a'; ; " + NOTE + "'b'", NOTE + "'a' &&", "&& " + NOTE + "'a'", "", " \n ", ";",
    # aliases, functions and shell state defined earlier in the same command
    "alias python3='rm -rf'; " + NOTE + "'a'", "python3() { rm -rf ~; }; " + NOTE + "'a'",
    "function python3 { kill 1; }\n" + NOTE + "'a'", "hash -p /tmp/evil python3; " + NOTE + "'a'",
    "source /tmp/x; " + NOTE + "'a'", ". /tmp/x; " + NOTE + "'a'", "set -x; " + NOTE + "'a'",
    "trap 'kill 1' EXIT; " + NOTE + "'a'",
    # environment prefixes and moves
    "HOME=/tmp/x " + NOTE + "'a'", "HOME=/tmp/x; " + NOTE + "'a'", "PATH=/tmp/x " + NOTE + "'a'",
    "PYTHONPATH=/tmp/x " + NOTE + "'a'", "export PATH=/tmp/x; " + NOTE + "'a'", "X=1 " + NOTE + "'a'",
    "BASH_ENV=/tmp/x " + NOTE + "'a'",
    # redirects, heredocs, substitutions and expansions
    NOTE + "'a' > ~/.claude/hooks/wal.py", NOTE + "'a' >> /tmp/x", NOTE + "'a' 2>&1", NOTE + "'a' < /etc/hosts",
    NOTE + "'a' <<< x", NOTE + "'a' <<'E'\nkill 1\nE", NOTE + "'a' &> /tmp/x", NOTE + "'a'>/tmp/x",
    NOTE + '"$(kill 4242)"', NOTE + "\"`kill 4242`\"", NOTE + "$(kill 4242)", NOTE + "<(kill 4242)", NOTE + ">(sh)",
    NOTE + "$NOTE", NOTE + '"$NOTE"', NOTE + '"${NOTE}"', NOTE + "{a,b}", NOTE + "a*", NOTE + "?", NOTE + "[a]",
    NOTE + "~root", NOTE + "=kill", NOTE + "a~b", NOTE + "a^b", NOTE + "(a)", NOTE + "#c", NOTE + '"a!b"', NOTE + "!!",
    # quoting tricks
    NOTE + "$'a\\x27; kill 1'", NOTE + '$"a"', NOTE + "'a'b", NOTE + "a'b'", NOTE + "'a''b'", NOTE + "\"a\"'b'",
    NOTE + "a\\ b", NOTE + '"a\\"b"', NOTE + "'a", NOTE + '"a', NOTE + "'a' \\\n--live", NOTE + "'a'\\\n; kill 1",
    "python\\3" + NOTE[7:] + "'a'", "'python3'" + NOTE[7:] + "'a'", "pyth''on3" + NOTE[7:] + "'a'",
    # control characters
    NOTE + "'a'\r\nkill 4242", NOTE + "'a\r'", NOTE + "'a'\x00", NOTE + "'a\x00b'", NOTE + "'a\x1b[2K'", NOTE + "'a\x0b'",
    NOTE + "'a'\x0ckill", NOTE + "'a\x7f'", NOTE + "‘a’", NOTE + "'a' kill", NOTE + "'a' kill 1",
    # another interpreter, another program, another path
    "python " + NOTE[8:] + "'a'", "python3.9 " + NOTE[8:] + "'a'", "/usr/bin/python3 " + NOTE[8:] + "'a'",
    "python3 -c 'import os' " + NOTE[8:] + "'a'", "python3 -m wal_note --note 'a'", "python3 -X utf8 " + NOTE[8:] + "'a'",
    "python3 -i " + NOTE[8:] + "'a'", "python3 -IB " + NOTE[8:] + "'a'", "bash " + NOTE[8:] + "'a'",
    "python3 ./wal_note.py --wal ~/.claude/wals/s1/m.jsonl --event status --note a",
    "python3 /tmp/wal_note.py --wal ~/.claude/wals/s1/m.jsonl --event status --note a",
    "python3 '~/.claude/hooks/wal_note.py' --wal ~/.claude/wals/s1/m.jsonl --event status --note a",
    "python3 ~/.claude/hooks/../hooks/wal_note.py --wal ~/.claude/wals/s1/m.jsonl --event status --note a",
    "python3 ~/.claude/hooks//wal_note.py --wal ~/.claude/wals/s1/m.jsonl --event status --note a",
    "python3 ~/.claude/hooks/./wal_note.py --wal ~/.claude/wals/s1/m.jsonl --event status --note a",
    "python3 ~other/.claude/hooks/wal_note.py --wal ~/.claude/wals/s1/m.jsonl --event status --note a",
    "python3 /Users/other/.claude/hooks/wal_note.py --wal ~/.claude/wals/s1/m.jsonl --event status --note a",
    "python3 $HOME/.claude/hooks/wal_note.py --wal ~/.claude/wals/s1/m.jsonl --event status --note a",
    "python3 ~/.claude/hooks/wal_note.py/x --wal ~/.claude/wals/s1/m.jsonl --event status --note a",
    "python3 ~/.claude/hooks/kill_guard.py spawn -- kill 4242",
    "python3 ~/.claude/hooks/peer_review.py pr --pr 5",
    "python3 ~/.claude/hooks/run_capped.py -- kill 4242",
    "python3 -I ~/.claude/hooks/command_guard.py approve-delete --path /x --remote y --wal z",
    # a recording tool asked to do something else
    "python3 -I ~/.claude/hooks/ah.py kill --pid 4242 --reason x",
    "python3 ~/.claude/hooks/ah.py install-files --host t2-dev --from-ref abc --file x",
    "python3 ~/.claude/hooks/ah.py task dispose --agent a --kind closed",
    "python3 ~/.claude/hooks/ah.py ticket create --title x --body y",
    "python3 ~/.claude/hooks/ah.py --text ticket get goodqa#1",
    "python3 ~/.claude/hooks/ah.py ticket get goodqa#1 --then kill",
    "python3 ~/.claude/hooks/ah.py ticket get -- goodqa#1",
    "python3 ~/.claude/hooks/ah.py ticket comment goodqa#1",
    "python3 ~/.claude/hooks/ah.py ticket comment goodqa#1 --body-file ~/.ssh/id_rsa",
    "python3 ~/.claude/hooks/ah.py ticket comment goodqa#1 --bod x",
    "python3 ~/.claude/hooks/usage_guard.py check --owner a -- kill 4242",
    "python3 ~/.claude/hooks/usage_guard.py --state-dir /tmp/x reconcile --run r --actor a --reason b --evidence c",
    "python3 ~/.claude/hooks/usage_guard.py reconcile --run r --auto",
    "python3 ~/.claude/hooks/usage_guard.py reconcile --run r --actor a --reason b",
    "python3 ~/.claude/hooks/usage_guard.py reconcile --run ../r --actor a --reason b --evidence c",
    # options the parser would read another way, and paths the tool opens
    NOTE + "'a' --note 'b'", NOTE + "'a' --no b", NOTE + "'a' --decision approved", NOTE + "'a' --by escalation",
    NOTE + "'a' --recites w1", NOTE + "'a' extra", NOTE + "'a' -- kill 4242", NOTE + "--live", NOTE + "'-x'",
    NOTE + "'a' --source 'file:/etc/passwd#1'", NOTE + "'a' --source 'inferred: FILE:/etc/passwd'",
    NOTE[:-len("--note ")] + "--note='a'",
    NOTE.replace("--event status", "--event ask_resolved") + "'a'", NOTE.replace("--event status", "--event ask") + "'a'",
    NOTE.replace("~/.claude/wals/s1/agent-a.jsonl", "~/.claude/hooks/wal.py") + "'a'",
    NOTE.replace("~/.claude/wals/s1/agent-a.jsonl", "~/.claude/wals/../hooks/x.jsonl") + "'a'",
    NOTE.replace("~/.claude/wals/s1/agent-a.jsonl", "~/.claude/wals/./x.jsonl") + "'a'",
    NOTE.replace("~/.claude/wals/s1/agent-a.jsonl", "/tmp/.claude/wals/s1/x.jsonl") + "'a'",
    NOTE.replace("~/.claude/wals/s1/agent-a.jsonl", "/etc/passwd") + "'a'",
    "python3 ~/.claude/hooks/wal_note.py --help", "python3 ~/.claude/hooks/wal_note.py", "python3", "python3 -I",
]


TOOL = "~/.claude/hooks/wal_note.py"
REST = " --wal ~/.claude/wals/s1/agent-a.jsonl --event status --note "

# A literal assignment is literal. kill_guard, merge_gate and dropped_gate accept these; the launcher's fast path does not.
ASSIGNED = [
    "W=" + TOOL + "; python3 \"$W\"" + REST + "'dispose of it: the gate is fail-closed'",
    "W=" + TOOL + "\npython3 $W" + REST + "'os.kill and pkill are words here'",
    "PY=python3 && $PY " + TOOL + REST + "'gh pr merge 5 is main only; pkill too'",
    "T='said: dispose, closed'; " + NOTE + "'a'",
    "N='two words; kill 4242'; " + NOTE + '"$N"',
    "note=\"git merge, gh pr merge 5\"; " + NOTE + '"${note}" --ticket goodqa#1',
    "W=" + TOOL + "; N=plain; python3 ${W}" + REST + "$N; python3 $W" + REST + "'b'",
]

ASSIGNED_MISSES = [
    # the value is computed, or is not the installed tool
    "W=$(which wal_note.py); python3 $W" + REST + "'a'", "W=`which x`; python3 $W" + REST + "'a'",
    "W=/tmp/wal_note.py; python3 $W" + REST + "'a'", "W=./wal_note.py; python3 $W" + REST + "'a'",
    "W=\"~/.claude/hooks/wal_note.py\"; python3 $W" + REST + "'a'", "W=$HOME/.claude/hooks/wal_note.py; python3 $W" + REST + "'a'",
    "W=" + TOOL + "x; python3 $W" + REST + "'a'", "W=~/.claude/hooks/kill_guard.py; python3 $W spawn -- kill 1",
    "PY=bash; $PY " + TOOL + REST + "'a'", "PY='python3 -i'; $PY " + TOOL + REST + "'a'",
    "W=/tmp/x:" + TOOL + "; python3 $W" + REST + "'a'",
    # a name that can change what runs, or an assignment of another kind
    "HOME=/tmp/x; " + NOTE + "'a'", "PATH=/tmp/x; " + NOTE + "'a'", "path=/tmp/x; " + NOTE + "'a'", "IFS=x; " + NOTE + "'a'",
    "PYTHONPATH=/tmp/x; " + NOTE + "'a'", "fpath=/tmp/x; " + NOTE + "'a'", "BASH_ENV=/tmp/x; " + NOTE + "'a'",
    "home=/tmp/x; " + NOTE + "'a'", "cdpath=/tmp; " + NOTE + "'a'", "ENV=/tmp/x; " + NOTE + "'a'",
    "W=" + TOOL + " python3 $W" + REST + "'a'", "export W=" + TOOL + "; python3 $W" + REST + "'a'",
    "declare W=" + TOOL + "; python3 $W" + REST + "'a'", "W+=" + TOOL + "; python3 $W" + REST + "'a'",
    "W=(a b); " + NOTE + "'a'", "W[1]=a; " + NOTE + "'a'", "read W; python3 $W" + REST + "'a'",
    # set somewhere else, later, in a subshell, or conditionally
    "python3 $W" + REST + "'a'", "python3 $W" + REST + "'a'; W=" + TOOL + "; " + NOTE + "'a'",
    "W=" + TOOL + " & python3 $W" + REST + "'a'", "W=" + TOOL + " | python3 $W" + REST + "'a'",
    "W=" + TOOL + " || python3 $W" + REST + "'a'", "(W=" + TOOL + "); python3 $W" + REST + "'a'", "W=" + TOOL, "W=a;", "W=a; N=b\n",
    # an expansion that is more than the whole value
    "N='a b'; " + NOTE + "$N", "N='*'; " + NOTE + "$N", "N='$(kill 1)'; " + NOTE + "$N", "N='~/x'; " + NOTE + "$N",
    "N=a; " + NOTE + "$N$N", "N=a; " + NOTE + '"$N"b', "N=a; " + NOTE + '"b$N"', "N=a; " + NOTE + "b$N", "N=a; " + NOTE + "$Nb",
    "N=a; " + NOTE + "${N:-kill}", "N=a; " + NOTE + "${N%a}", "N=a; " + NOTE + "$N[1]", "N=a; " + NOTE + "$N:h",
    "N=a; " + NOTE + "${N", "N=a; " + NOTE + '"$N', "N=a; " + NOTE + "$N\"", "N=a; " + NOTE + "${#N}", "N=a; " + NOTE + "${!N}",
    "N=a; " + NOTE + "$(kill 1)", "N=a; " + NOTE + '"$(kill 1)"', "N=a; " + NOTE + "$1", "N=a; " + NOTE + "$@", "N=a; " + NOTE + "$$",
    "N=a; " + NOTE + "$'$N'",
    # a value that is not one literal word, and something else next to it
    "N=\"$(kill 1)\"; " + NOTE + "'a'", "N=$'a'; " + NOTE + "'a'", "N=a\\ b; " + NOTE + "'a'", "N='a'b; " + NOTE + "'a'", "N=a b; " + NOTE + "'a'",
    "N=a;kill 1; " + NOTE + "'a'", "N=a>x; " + NOTE + "'a'", "N=a <x; " + NOTE + "'a'", "N=a {b,c}; " + NOTE + "'a'", "N=; " + NOTE + '"$N"',
    "N='--decision'; " + NOTE + "'a' $N approved", "N='-x'; " + NOTE + "$N", "N=kill; $N 4242; " + NOTE + "'a'",
]


class Home(unittest.TestCase):
    """A private HOME with the recording tools in place (empty files: nothing here runs them)."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="tnc-")
        self.addCleanup(tmp.cleanup)
        self.home = Path(os.path.realpath(tmp.name)) / "home"
        self.hooks = self.home / ".claude" / "hooks"
        self.hooks.mkdir(parents=True)
        for path in (self.home, self.home / ".claude", self.hooks):
            path.chmod(0o700)
        for name in TOOLS:
            (self.hooks / name).write_text("# a stand-in, never run\n")
            (self.hooks / name).chmod(0o600)
        env = mock.patch.dict(os.environ, {"HOME": str(self.home)})
        env.start()
        self.addCleanup(env.stop)

    def bash(self, command, **extra):
        return dict({"tool_name": "Bash", "tool_input": {"command": command}, "cwd": str(self.home)}, **extra)


class FastPath(Home):
    def test_recording_calls_qualify(self):
        failures = [c for c in RECORDS if not launcher.records_only(c)]
        self.assertEqual(failures, [])

    def test_near_misses_do_not(self):
        self.assertGreater(len(NEAR_MISSES), 140)
        self.assertEqual([c for c in NEAR_MISSES if launcher.records_only(c)], [])

    def test_literal_assignments_count_only_where_asked(self):
        self.assertEqual([c for c in RECORDS + ASSIGNED if not launcher.records_only(c, True)], [])
        self.assertEqual([c for c in ASSIGNED if launcher.records_only(c) or launcher.payload_records_only(self.bash(c))], [])
        self.assertGreater(len(ASSIGNED_MISSES), 70)
        self.assertEqual([c for c in NEAR_MISSES + ASSIGNED_MISSES if launcher.records_only(c, True)], [])

    def test_the_shared_shell_reader_reads_the_same_words(self):
        """bash and zsh agree with the fast path about every command it accepts (shell_words is checked against both)."""
        for command in RECORDS:
            scan = shell_words.scan(command)
            self.assertTrue(scan.verified, (command, scan.message))
            self.assertTrue(all(s.op in ("", ";", "&&", "\n") and not s.redirects and not s.depth for s in scan.segments))
            mine = [[value for value, _bare in words] for words in launcher._record_statements(command)]
            theirs = [[str(self.home) + v[1:] if w.lead == "unquoted" and v.startswith("~/") else v
                       for w in s.words for v in [w.value]] for s in scan.segments]
            self.assertEqual(mine, theirs, command)

    def test_the_tool_must_be_the_callers_own_installed_file(self):
        command = NOTE + "'a'"
        tool = self.hooks / "wal_note.py"
        self.assertTrue(launcher.records_only(command))
        for mode in (0o620, 0o602):
            tool.chmod(mode)
            self.assertFalse(launcher.records_only(command), oct(mode))
        tool.chmod(0o600)
        self.hooks.chmod(0o777)
        self.assertFalse(launcher.records_only(command), "another user could replace the tool")
        self.hooks.chmod(0o700)
        tool.rename(self.home / "elsewhere.py")
        self.assertFalse(launcher.records_only(command), "missing")
        tool.symlink_to(self.home / "elsewhere.py")
        self.assertFalse(launcher.records_only(command), "a symlink")
        tool.unlink()
        tool.mkdir()
        self.assertFalse(launcher.records_only(command), "a directory")
        tool.rmdir()
        (self.home / "elsewhere.py").rename(tool)
        self.hooks.rename(self.home / "planted")
        self.hooks.symlink_to(self.home / "planted")
        self.assertFalse(launcher.records_only(command), "a symlinked hooks directory")

    def test_a_home_the_shell_would_split_or_expand_never_qualifies(self):
        for home in ("/tmp/a b", "/tmp/$x", "relative", "/tmp/../tmp", "/tmp/a*", "/"):
            with mock.patch.dict(os.environ, {"HOME": home}):
                self.assertFalse(launcher.records_only(NOTE + "'a'"), home)

    def test_only_one_plain_bash_command_field(self):
        command = NOTE + "'a'"
        self.assertTrue(launcher.payload_records_only(self.bash(command)))
        for payload in ({"tool_name": "write_stdin", "tool_input": {"chars": command}},
                        {"tool_name": "PowerShell", "tool_input": {"command": command}},
                        {"tool_name": "Bash", "tool_input": {"command": command, "cmd": "kill 1"}},
                        {"tool_name": "Bash", "tool_input": {"command": command, "input": "kill 1"}},
                        {"tool_name": "Bash", "tool_input": {"command": [command]}},
                        {"tool_name": "Bash", "tool_input": command}, {"tool_input": {"command": command}},
                        {"tool_name": "Bash"}, [], None, "x"):
            self.assertFalse(launcher.payload_records_only(payload), payload)


class Launcher(Home):
    """command_guard_hook.py end to end, with an analyser that never answers."""

    def run_launcher(self, payload, analyser=None, child_timeout=None):
        with tempfile.TemporaryDirectory(prefix="tnc-launcher-") as tmp:
            source = (HOOKS / "command_guard_hook.py").read_text()
            if child_timeout is not None:
                line = next(x for x in source.splitlines() if x.startswith("CHILD_TIMEOUT = "))
                source = source.replace(line, "CHILD_TIMEOUT = %r" % child_timeout)
            (Path(tmp) / "command_guard_hook.py").write_text(source)
            for name in () if analyser else ("command_guard.py", "redact.py", "safe_input.py"):
                (Path(tmp) / name).write_text((HOOKS / name).read_text())
            if analyser:
                (Path(tmp) / "command_guard.py").write_text(analyser)
            done = subprocess.run([sys.executable, str(Path(tmp) / "command_guard_hook.py")],
                                  input=json.dumps(payload).encode(), capture_output=True, timeout=120, check=False,
                                  env={"PATH": "/usr/bin:/bin", "HOME": str(self.home)})
            return done.returncode, done.stderr.decode()

    HANGS = "import time\ntime.sleep(60)\n"

    def test_recording_calls_never_wait_for_the_analyser(self):
        for command in RECORDS:
            with self.subTest(command=command):
                started = time.monotonic()
                code, err = self.run_launcher(self.bash(command), analyser=self.HANGS, child_timeout=3.0)
                self.assertEqual((code, err), (0, ""))
                self.assertLess(time.monotonic() - started, 3.0)

    def test_a_timed_out_analyser_still_refuses_what_names_a_protected_place(self):
        for command in (NOTE + "'a'; rm -rf ~/.claude/wals/s1", "rm -rf ~/.claude/projects", NOTE + "'a' | sh",
                        NOTE + "'a' > ~/.claude/wals/s1/main.jsonl", "HOME=/tmp/x " + NOTE + "'a'",
                        "truncate -s 0 ~/.claude/wals/s1/main.jsonl", "echo x | sh; rm -f y"):
            code, err = self.run_launcher(self.bash(command), analyser=self.HANGS, child_timeout=0.5)
            self.assertEqual(code, 2, command)
            self.assertIn("[guard_failure]: the analyser timed out", err)

    def test_a_note_that_names_a_guarded_subcommand_is_recorded(self):
        for note in ("'step one\nah install-files was named, not run'", "'python3 does not import ah_install here'"):
            with self.subTest(note=note):
                self.assertEqual(self.run_launcher(self.bash(NOTE + note)), (0, ""))
        for command in ("python3 ~/.claude/hooks/ah.py install-files --host x",
                        NOTE + "'a'; python3 /tmp/ah.py install-files --host t2-dev --from-ref x --file y"):
            code, err = self.run_launcher(self.bash(command))
            self.assertEqual(code, 2, command)
            self.assertIn("install-files", err)

    def test_the_child_has_five_seconds_less_than_the_hook_entry(self):
        import install
        import install_codex
        claude = install.command_guard_group(Path("/x"))["hooks"][0]["timeout"]
        groups = install_codex.merge_hooks({}, Path("/x"))["hooks"]["PreToolUse"]
        codex = [h["timeout"] for g in groups for h in g["hooks"] if "command_guard_hook.py" in h["command"]]
        self.assertEqual((claude, codex), (30, [30]))
        self.assertEqual(launcher.CHILD_TIMEOUT, 25.0)


class OtherGuards(Home):
    """kill_guard, merge_gate and dropped_gate use the same helper. A sub-agent's payload, so nothing is main's."""

    def kill(self, command):
        done = subprocess.run([sys.executable, str(HOOKS / "kill_guard.py"), "hook"], timeout=120, check=False,
                              input=json.dumps(self.bash(command, agent_id="a1")).encode(), capture_output=True,
                              env={"PATH": "/usr/bin:/bin", "HOME": str(self.home)})
        return done.returncode, done.stderr.decode()

    def merge(self, command):
        import merge_gate

        def no_gh(*_args, **_kwargs):
            raise merge_gate.GateError("no gh in this test")

        with tempfile.TemporaryDirectory() as state:
            return merge_gate.decide(self.bash(command, agent_id="a1"), no_gh, state)

    def dropped(self, command):
        import dropped_gate
        return dropped_gate.cmd_pretool(self.bash(command, agent_id="a1", session_id="s1"))

    def test_kill_guard_allows_recording_calls(self):
        rows = [RECONCILE + "'the run was killed' --evidence 'kill -0 said no'", ASSIGNED[1],
                NOTE + "'HOME is set; os.kill was refused'"]
        for command in rows + [ASSIGNED[4], RECORDS[8]]:  # the last two were allowed before and stay so
            with self.subTest(command=command):
                self.assertEqual(self.kill(command), (0, ""))

    def test_kill_guard_still_refuses(self):
        for command in (NOTE + "'a'; kill 4242", "W=/tmp/x.py; python3 $W" + REST + "'os.kill'", "pkill -f x; " + NOTE + "'a'",
                        "python3 ~/.claude/hooks/usage_guard.py check --owner a -- pkill -f x",
                        "python3 ./usage_guard.py reconcile --run r --actor a --reason 'kill 1' --evidence e",
                        "python3 ~/.claude/hooks/usage_guard.py reconcile --reason x -- kill 4242",
                        "HOME=/tmp/x python3 ~/.claude/hooks/usage_guard.py reconcile --reason 'kill 4242'",
                        NOTE + '"$(pkill -f x)"', NOTE + "'kill 4242' | sh", "N=kill; $N 4242; " + NOTE + "'a'"):
            with self.subTest(command=command):
                code, err = self.kill(command)
                self.assertEqual(code, 2)
                self.assertIn("kill_guard BLOCKED", err)

    def test_kill_guard_mixed_reconcile_is_judged_by_its_own_words(self):
        mixed = "cd /tmp && " + RECONCILE + "'the run was killed' --evidence 'kill -0 said no'"
        self.assertEqual(self.kill(mixed), (0, ""))
        self.assertEqual(self.kill(mixed + " && pkill -f x")[0], 2)

    def test_merge_gate_allows_recording_calls(self):
        for command in (NOTE + "'gh pr merge 5 waits for main'", ASSIGNED[2], ASSIGNED[5],
                        COMMENT + "'gh pr merge 5 waits for main'",
                        RECONCILE + "'merge_gate.py waive was refused' --evidence 'none'",
                        "W=" + TOOL + "; python3 $W" + REST + "'the merge_gate waive was refused'"):
            with self.subTest(command=command):
                self.assertEqual(self.merge(command), (0, ""))

    def test_merge_gate_still_refuses(self):
        waive = "python3 ~/.claude/hooks/merge_gate.py waive --repo o/r --pr 5 --head " + "a" * 40 + " --ticket 'GoodQA #1' --reason x"
        for command in (waive, NOTE + "'a'; " + waive, "W=~/.claude/hooks/merge_gate.py; python3 $W waive --pr 5",
                        "W='python3 ~/.claude/hooks/merge_gate.py waive --pr 5'; $W", "PY=python3; $PY ~/.claude/hooks/merge_gate.py waive --pr 5",
                        NOTE + "'gh pr merge 5' | sh", NOTE + '"$(' + waive + ')"',
                        NOTE + "'x' >> ~/.claude/merge-gate-waivers.jsonl", "G=gh; $G pr merge 5; " + NOTE + "'a'"):
            with self.subTest(command=command):
                self.assertEqual(self.merge(command)[0], 2)

    def test_dropped_gate_allows_recording_calls(self):
        for command in (ASSIGNED[0], "PY=python3; $PY " + TOOL + REST + "'dispose; kind closed'"):
            with self.subTest(command=command):
                self.assertEqual(self.dropped(command), {})

    def test_dropped_gate_still_refuses_a_computed_acknowledgement(self):
        ah = "python3 ~/.claude/hooks/ah.py task dispose --agent a --kind "
        for command in (ah + "closed", "K=closed; " + ah + '"$K"', "A=~/.claude/hooks/ah.py; python3 $A task dispose --kind closed",
                        NOTE + "'a'; " + ah + "closed", "W=$(which ah); python3 $W task dispose --kind closed",
                        "AH='" + ah + "closed'; $AH", NOTE + '"$(' + ah + 'closed)"'):
            with self.subTest(command=command):
                self.assertIn("deny", json.dumps(self.dropped(command)))


if __name__ == "__main__":
    unittest.main()
