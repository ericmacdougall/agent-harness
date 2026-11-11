"""Native WAL note contract, GoodQA #15646. Every command is inert parser data."""

import shlex
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

HOOKS = Path(__file__).resolve().parents[1] / 'harness' / 'hooks'
sys.path.insert(0, str(HOOKS))
import command_guard as cg
import kill_guard as kg

HOME = str(Path.home())
SCRIPT = HOME + '/.codex/agent-harness/wal.py'
WAL = HOME + '/.agent-harness/codex-wals/session-1/agent-owner.jsonl'
PROSE = 'Actual diagnostic used os.killpg on timeout. No process signal occurred.'


class NativeWalNote(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.compiled = cg.Compiled(cg.load_policy(), home=self.scratch.name, cwd=self.scratch.name)
        self.policy = kg.load_policy()

    def command(self, rest=None, head='python3', script=SCRIPT):
        if rest is None:
            rest = '--wal %s --event blocker --note %s' % (WAL, shlex.quote(PROSE))
        return '%s %s note %s' % (head, script, rest)

    def scan(self, command):
        # Pure Analyzer traversal: no audit, runner, ledger, target script or process probe.
        owner = SimpleNamespace(home=self.scratch.name,
                                check=lambda *a, **kw: (False, 'synthetic', 'no owned target'))
        analyzer = kg.make_analyzer_class(cg)(self.compiled, self.scratch.name, False,
                                            owner, self.policy, command)
        with mock.patch.object(analyzer, 'check_interpreter', wraps=analyzer.check_interpreter) as scan:
            findings = analyzer.run_kill_scan(command)
        return findings, scan.call_count

    def assert_data(self, command):
        findings, scans = self.scan(command)
        self.assertEqual(findings, [], command)
        self.assertEqual(scans, 0, command)

    def assert_scanned(self, command):
        findings, scans = self.scan(command)
        self.assertGreater(scans, 0, command)
        self.assertIn('script-kill', [f[0] for f in findings], command)

    def test_actual_refusal_shape_is_note_data(self):
        self.assert_data(self.command())
        self.assert_data(self.command('--wal %s --event status --note %s' %
                                      (WAL, shlex.quote('no cleanup/kill; os.killpg is only prose'))))

    def test_supported_interpreter_flags_and_raw_install_paths(self):
        for head in ('python', 'python3', 'python3.11', 'python3 -I', 'python3 -I -B -u'):
            for script in (SCRIPT, '~/.codex/agent-harness/wal.py'):
                with self.subTest(head=head, script=script):
                    self.assert_data(self.command(head=head, script=script))

    def test_exact_events_order_equals_and_literal_note_bounds(self):
        for event in ('intent', 'scope', 'decision', 'risk', 'check', 'commit', 'blocker', 'status', 'handoff', 'result'):
            rest = '--note=%s --event=%s --wal=%s' % (shlex.quote(PROSE), event, WAL)
            with self.subTest(event=event):
                self.assert_data(self.command(rest))
        for text in ('os.killpg', 'x' * 3991 + 'os.killpg', '--flag os.killpg'):
            self.assert_data(self.command('--wal=%s --event=check --note=%s' % (WAL, shlex.quote(text))))

    def test_main_agent_and_session_grammar(self):
        for session, leaf in (('s_1.a-b', 'main.jsonl'), ('a' * 120, 'agent-a.jsonl')):
            path = HOME + '/.agent-harness/codex-wals/' + session + '/' + leaf
            self.assert_data(self.command('--wal %s --event status --note %s' % (path, shlex.quote(PROSE))))

    def test_unknown_duplicate_missing_and_option_like_values_keep_scan(self):
        valid = '--wal %s --event status --note %s' % (WAL, shlex.quote(PROSE))
        for rest in (valid + ' --extra x', valid + ' extra', valid + ' --event check',
                     valid + ' --note other', valid + ' --wal ' + WAL,
                     '--event status --note ' + shlex.quote(PROSE),
                     '--wal %s --note %s' % (WAL, shlex.quote(PROSE)),
                     valid + ' --', valid.replace('--event status', '--event --note'),
                     valid.replace('--note ', '--no '), valid.replace('--event status', '--event bogus'),
                     valid.replace('--note ', '--note --event ')):
            with self.subTest(rest=rest):
                self.assert_scanned(self.command(rest))

    def test_option_like_note_separate_value_is_not_argparse_data(self):
        # argparse rejects this separate option-looking value; attached --note= is supported above.
        self.assert_scanned(self.command('--wal %s --event status --note %s' %
                                         (WAL, shlex.quote('--bad os.killpg'))))

    def test_overlong_or_empty_note_retains_original_scan(self):
        self.assert_scanned(self.command('--wal %s --event status --note %s' %
                                         (WAL, shlex.quote('os.killpg' + 'x' * 4000))))
        findings, scans = self.scan(self.command('--wal %s --event status --note %s' % (WAL, "''")))
        self.assertEqual(findings, [])  # no kill text; conservative scan is the contract here
        self.assertEqual(scans, 1)

    def test_invalid_wal_paths_keep_scan(self):
        for path in ('relative/session/main.jsonl', '/tmp/session/main.jsonl',
                     HOME + '/.agent-harness/codex-wals/main.jsonl',
                     HOME + '/.agent-harness/codex-wals/./main.jsonl',
                     HOME + '/.agent-harness/codex-wals/../main.jsonl',
                     HOME + '/.agent-harness/codex-wals/' + 'x' * 121 + '/main.jsonl',
                     HOME + '/.agent-harness/codex-wals/s/nested/main.jsonl',
                     HOME + '/.agent-harness/codex-wals/s/main.txt'):
            with self.subTest(path=path):
                self.assert_scanned(self.command('--wal %s --event status --note %s' %
                                                 (path, shlex.quote(PROSE))))

    def test_helper_and_interpreter_spoofs_remain_scanned(self):
        for script in ('./wal.py', '/tmp/wal.py', '/home/other/.codex/agent-harness/wal.py',
                       HOME + '/.claude/hooks/wal.py', "'~/.codex/agent-harness/wal.py'",
                       r'\~/.codex/agent-harness/wal.py', HOME + '/.codex/agent-harness/../wal.py'):
            with self.subTest(script=script):
                self.assert_scanned(self.command(script=script))
        for head in ("'python3'", '/usr/bin/python3', 'python3 -s', 'FOO=1 python3', 'python3 -m fake'):
            with self.subTest(head=head):
                self.assert_scanned(self.command(head=head))
        self.assert_scanned('HOME=/tmp/other; ' + self.command())

    def test_other_subcommands_and_redirections_are_not_exempt(self):
        for subcommand in ('hook', 'start-manual', 'continuation', '--help'):
            self.assert_scanned(self.command().replace(' note ', ' ' + subcommand + ' ', 1))
        self.assert_scanned(self.command() + " <<'PY'\nimport os; os.killpg(1,9)\nPY")
        self.assert_scanned(self.command() + " <<< 'os.killpg(1,9)'")
        self.assert_scanned(self.command() + ' > /dev/null')
        self.assert_scanned(self.command() + ' &')

    def test_variables_and_substitutions_never_become_literal_notes(self):
        for value in ('"$NOTE os.killpg"', '"$(pkill -f synthetic) os.killpg"',
                      '"`pkill -f synthetic` os.killpg"'):
            with self.subTest(value=value):
                findings, scans = self.scan(self.command('--wal %s --event status --note %s' % (WAL, value)))
                self.assertGreater(scans, 0)
                self.assertTrue(findings)
        self.assert_scanned('NOTE=x; ' + self.command('--wal %s --event status --note "$NOTE os.killpg"' % WAL))

    def test_compound_code_wrappers_and_signal_controls_remain_enforced(self):
        for command in (self.command() + "; python3 -c 'import os; os.killpg(1,9)'",
                        "python3 -c 'import os; os.killpg(1,9)' " + SCRIPT,
                        "bash -c " + shlex.quote(self.command()),
                        self.command() + '; pkill -f synthetic',
                        self.command() + ' | sh',
                        "python3 -I ~/.codex/agent-harness/ah.py kill --pid 4242 --reason synthetic"):
            with self.subTest(command=command):
                findings, _ = self.scan(command)
                self.assertTrue(findings, command)


if __name__ == '__main__':
    unittest.main()
