"""kill_guard must not judge file text written by an edit tool as a command (GoodQA #15565).

A Codex apply_patch call carries the patch body in tool_input.command. Before the fix, guarded_text saw the
`command` key, treated the patch as a shell command and blocked any patch that mentioned signals or kill verbs
(a unittest file, a review packet). Writing a file runs nothing; the shell tool that later runs it is still judged.

Every kill string here is DATA piped to the hook; nothing in this file sends a signal.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOOKS = Path(os.environ.get('KG_HOOKS_DIR') or ROOT / 'harness/hooks')
sys.path.insert(0, str(HOOKS))

import kill_guard as kg  # noqa: E402

KILL_TEXT = ('import os, signal, subprocess\n'
             'os.kill(pid, signal.SIGTERM)\n'
             'subprocess.run(["pkill", "-f", "x"])\n'
             '# pkill -f x\n'
             '# killall node\n')
SHELL_KILL = 'pkill -f x; killall node'
PATCH = ('*** Begin Patch\n*** Add File: tests/test_reaper.py\n' +
         ''.join('+' + line + '\n' for line in KILL_TEXT.splitlines()) + '*** End Patch\n')


def edit_payloads(name_case=lambda n: n):
    """Payloads in the shapes Claude Code and Codex send for their file-edit tools."""
    return [
        {'tool_name': name_case('apply_patch'), 'tool_input': {'command': PATCH}},
        {'tool_name': name_case('apply_patch'), 'tool_input': {'input': PATCH}},
        {'tool_name': name_case('apply_patch'), 'tool_input': PATCH},
        {'tool_name': name_case('Write'), 'tool_input': {'file_path': '/w/t.py', 'content': KILL_TEXT}},
        {'tool_name': name_case('Write'), 'tool_input': {'file_path': '/w/run.sh', 'command': SHELL_KILL,
                                                          'content': SHELL_KILL}},
        {'tool_name': name_case('Edit'), 'tool_input': {'file_path': '/w/t.py', 'old_string': SHELL_KILL,
                                                         'new_string': KILL_TEXT}},
        {'tool_name': name_case('MultiEdit'), 'tool_input': {'file_path': '/w/t.py', 'edits': [
            {'old_string': 'pass', 'new_string': KILL_TEXT}], 'script': SHELL_KILL}},
        {'tool_name': name_case('NotebookEdit'), 'tool_input': {'notebook_path': '/w/n.ipynb',
                                                                 'new_source': KILL_TEXT, 'cmd': SHELL_KILL}},
    ]


class HookCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = self.tmp.name

    def run_hook(self, payload, entry='hook'):
        payload = dict(payload, cwd=self.home, session_id='kg-edit-tools-test')
        return subprocess.run([sys.executable, str(HOOKS / 'kill_guard.py'), entry], input=json.dumps(payload),
                              text=True, capture_output=True, timeout=30, env=dict(os.environ, HOME=self.home))

    def assert_allowed(self, payload):
        for entry in ('hook', 'analyze'):  # the launcher and the child both decide
            done = self.run_hook(payload, entry)
            self.assertEqual((done.returncode, done.stdout.strip(), done.stderr.strip()), (0, '', ''),
                             '%s %s' % (entry, payload['tool_name'] if 'tool_name' in payload else '<none>'))

    def assert_blocked(self, payload):
        done = self.run_hook(payload)
        self.assertEqual(done.returncode, 2, payload)
        self.assertIn('BLOCKED', done.stderr, payload)


class EditToolsAllowed(HookCase):
    def test_apply_patch_with_kill_text_is_allowed(self):
        # The defect: this blocked as [broad-kill]/[script-kill] on main before the fix.
        self.assert_allowed({'tool_name': 'apply_patch', 'tool_input': {'command': PATCH}})

    def test_every_edit_tool_shape_is_allowed(self):
        for payload in edit_payloads():
            with self.subTest(tool=payload['tool_name'], keys=sorted(payload['tool_input'])
                              if isinstance(payload['tool_input'], dict) else 'str'):
                self.assert_allowed(payload)

    def test_edit_tool_names_match_case_insensitively(self):
        for case in (str.upper, str.title, lambda n: 'Apply_Patch' if n == 'apply_patch' else n.upper()):
            for payload in edit_payloads(case):
                with self.subTest(tool=payload['tool_name']):
                    self.assert_allowed(payload)

    def test_patch_markers_alone_are_not_a_command(self):
        # `***` read as a shell glob was refused too before the fix.
        self.assert_allowed({'tool_name': 'apply_patch', 'tool_input': {'command': '*** Begin Patch\n*** End Patch'}})

    def test_guarded_text_reports_edit_tools_unguarded(self):
        for payload in edit_payloads():
            self.assertEqual(kg.guarded_text(json.dumps(payload)), (False, ''), payload['tool_name'])


class StillJudged(HookCase):
    """Negative controls: the early allow must not open a hole for anything that runs a command."""

    def test_same_text_on_shell_tools_is_blocked(self):
        for tool, key in (('Bash', 'command'), ('shell', 'command'), ('exec_command', 'cmd'),
                          ('local_shell', 'command'), ('unified_exec', 'cmd'), ('container.exec', 'command')):
            with self.subTest(tool=tool):
                self.assert_blocked({'tool_name': tool, 'tool_input': {key: SHELL_KILL}})

    def test_write_stdin_is_not_an_edit_tool(self):
        # 'write' is a substring of write_stdin; the edit-tool match must be exact.
        for tool in ('write_stdin', 'Write_Stdin', 'WRITE_STDIN'):
            with self.subTest(tool=tool):
                self.assert_blocked({'tool_name': tool, 'tool_input': {'session_id': 1, 'chars': SHELL_KILL + '\n'}})
                self.assertTrue(kg.guarded_text(json.dumps({'tool_name': tool,
                                                            'tool_input': {'chars': SHELL_KILL}}))[0])

    def test_names_that_only_contain_an_edit_word_are_judged(self):
        for tool in ('write_and_run', 'edit_exec', 'apply_patch_and_run', ' apply_patch'):
            with self.subTest(tool=tool):
                self.assert_blocked({'tool_name': tool, 'tool_input': {'command': SHELL_KILL}})

    def test_unknown_tool_with_a_command_key_fails_closed(self):
        self.assert_blocked({'tool_name': 'mystery_tool', 'tool_input': {'command': SHELL_KILL}})

    def test_missing_tool_name_is_judged(self):
        self.assert_blocked({'tool_input': {'command': SHELL_KILL}})


if __name__ == '__main__':
    unittest.main()
