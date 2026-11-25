"""Native edit/data contracts never confer permission to change protected state."""
import io
import json
import os
import shlex
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'harness' / 'hooks'))
import merge_gate as mg


class NativeEditFixtures(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name).resolve()
        self.cwd = self.home / 'project'
        self.cwd.mkdir()
        self.state = self.home / '.agent-harness' / 'state'
        self.protected = self.state / 'main-stamps'
        self.protected.mkdir(parents=True)
        self.secret_target = self.protected / 'record.json'
        self.secret_target.write_text('fixture unchanged')
        patch = mock.patch.object(mg.Path, 'home', return_value=self.home)
        patch.start(); self.addCleanup(patch.stop)
        for name in ('_stamp_waive', '_stamp_review', '_audit'):
            patch = mock.patch.object(mg, name, side_effect=AssertionError('data reached ' + name))
            patch.start(); self.addCleanup(patch.stop)

    def decide(self, tool, value, **extra):
        payload = dict(tool_name=tool, tool_input=value, cwd=str(self.cwd), agent_id='fixture-child')
        payload.update(extra)
        def runner(*args, **kwargs):
            raise AssertionError('unexpected external call')
        return mg.decide(payload, runner, self.state)[0]

    @staticmethod
    def patch(path, move=None):
        return ('*** Begin Patch\n*** Update File: ' + str(path) + '\n'
                + ('*** Move to: ' + str(move) + '\n' if move is not None else '')
                + '@@\n-old\n+new\n*** End Patch')


class NativeEditBoundary(NativeEditFixtures):
    def test_complete_patch_envelopes_preserve_content_as_data(self):
        patch = self.patch('notes.txt').replace('+new', '+merge_gate.py waive; peer_review.py --pr 5')
        for value in (patch, *({key: patch} for key in ('input', 'patch', 'command', 'cmd'))):
            with self.subTest(shape=type(value).__name__):
                self.assertEqual(self.decide('apply_patch', value), 0)

    def test_every_patch_envelope_checks_protected_targets(self):
        patch = self.patch(self.secret_target)
        for value in (patch, *({key: patch} for key in ('input', 'patch', 'command', 'cmd'))):
            with self.subTest(shape=str(value)[:30]):
                self.assertEqual(self.decide('apply_patch', value), 2)
        self.assertEqual(self.secret_target.read_text(), 'fixture unchanged')

    def test_move_and_nested_edits_check_all_targets(self):
        self.assertEqual(self.decide('apply_patch', {'command': self.patch('notes.txt', self.secret_target)}), 2)
        self.assertEqual(self.decide('MultiEdit', {'edits': [
            {'file_path': 'notes.txt', 'old_string': 'a', 'new_string': 'b'},
            {'file_path': str(self.secret_target), 'old_string': 'a', 'new_string': 'b'}]}), 2)

    def test_relative_and_symlink_protected_destinations_are_refused(self):
        alias = self.cwd / 'alias.json'; alias.symlink_to(self.secret_target)
        parent = self.cwd / 'alias-parent'; parent.symlink_to(self.protected, target_is_directory=True)
        for target, cwd in (('record.json', self.protected), ('alias.json', self.cwd),
                            ('alias-parent/new.json', self.cwd)):
            with self.subTest(target=target):
                self.assertEqual(self.decide('Write', {'file_path': target, 'content': 'x'}, cwd=str(cwd)), 2)
                self.assertEqual(self.decide('apply_patch', self.patch(target), cwd=str(cwd)), 2)
        ordinary = self.cwd / 'ordinary'; ordinary.write_text('fixture')
        reverse_alias = self.protected / 'alias.json'; reverse_alias.symlink_to(ordinary)
        self.assertEqual(self.decide('Edit', {'file_path': str(reverse_alias)}), 2)

    def test_safe_absolute_relative_and_legacy_edits(self):
        for tool in ('Write', 'Edit', 'MultiEdit', 'NotebookEdit', 'WRITE'):
            for target in ('notes.txt', str(self.cwd / 'notes.txt')):
                with self.subTest(tool=tool, target=target):
                    self.assertEqual(self.decide(tool, {'file_path': target, 'content': 'merge_gate.py waive'}), 0)

    def test_alias_identity_requires_absent_valid_canonical_name(self):
        value = {'file_path': str(self.cwd / 'notes.txt'), 'command': 'merge_gate.py waive'}
        payload = dict(tool_input=value, toolName='Edit', cwd=str(self.cwd), agent_id='fixture-child')
        self.assertEqual(mg.decide(payload, None, self.state)[0], 0)
        for canonical in ('Bash', '', None, [], 'namespace.Edit', 'EditExtra', 'noteboo\u212aedit'):
            with self.subTest(canonical=canonical):
                self.assertEqual(self.decide(canonical, value, toolName='Edit'), 2)
        for canonical in ('', None, []):
            self.assertEqual(self.decide(canonical, {'file_path': str(self.cwd / 'notes.txt')}, toolName='Edit'), 2)

    def test_ambiguous_edit_envelopes_fail_closed(self):
        patch = self.patch('notes.txt')
        cases = [('apply_patch', {'command': patch, 'cmd': self.patch('other.txt')}),
                 ('apply_patch', '*** Begin Patch\n*** Move to: notes.txt\n*** End Patch'),
                 ('apply_patch', '*** Begin Patch\n*** Update File: notes.txt'),
                 ('Write', {'content': 'x'}), ('Write', {'file_path': 42}),
                 ('Edit', {'file_path': 'a', 'path': 'b'}),
                 ('MultiEdit', {'edits': [{'new_string': 'x'}]}),
                 ('MultiEdit', {'edits': 'unknown'}), ('NotebookEdit', None)]
        for tool, value in cases:
            with self.subTest(tool=tool, value=value): self.assertEqual(self.decide(tool, value), 2)

    def test_ambiguous_effective_targets_fail_closed(self):
        for cwd in (None, 'relative', 42):
            with self.subTest(cwd=cwd): self.assertEqual(self.decide('Write', {'file_path': 'notes.txt'}, cwd=cwd), 2)
        ordinary = self.cwd / 'ordinary'; ordinary.write_text('fixture')
        hard = self.cwd / 'hard'; os.link(ordinary, hard)
        loop = self.cwd / 'loop'; loop.symlink_to('loop')
        for target in (hard, loop, ordinary / 'child', '~/ambiguous.txt'):
            with self.subTest(target=target): self.assertEqual(self.decide('Write', {'file_path': str(target)}), 2)

    def test_resolution_failure_and_target_budgets_refuse(self):
        with mock.patch.object(mg.Path, 'resolve', side_effect=PermissionError('fixture unreadable')):
            self.assertEqual(self.decide('Write', {'file_path': 'notes.txt'}), 2)
        self.assertEqual(self.decide('Write', {'file_path': 'x' * 4097}), 2)
        self.assertEqual(self.decide('MultiEdit', {'edits': [{'path': 'x'}] * 129}), 2)

    def test_missing_dotdot_cannot_hide_effective_hardlink_target(self):
        alias = self.cwd / 'alias.json'; os.link(self.secret_target, alias)
        target = 'missing/../alias.json'
        self.assertEqual((self.cwd / target).resolve().stat().st_nlink, 2)
        self.assertEqual(self.decide('Write', {'file_path': target, 'content': 'x'}), 2)
        self.assertEqual(self.secret_target.read_text(), 'fixture unchanged')

    def test_known_edit_resolution_fault_never_falls_through_hook_warning(self):
        payload = {'tool_name': 'Write', 'tool_input': {'file_path': 'record.json'},
                   'cwd': str(self.protected), 'agent_id': 'fixture-child'}
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(mg.Path, 'is_dir', side_effect=PermissionError('fixture unreadable cwd')):
            code = mg.main(['hook', '--state-dir', str(self.state)], runner=None,
                           stdin=io.BytesIO(json.dumps(payload).encode()), stdout=out, stderr=err)
        self.assertEqual(code, 2, err.getvalue())
        self.assertNotIn('warning', err.getvalue().lower())
        self.assertEqual(self.secret_target.read_text(), 'fixture unchanged')

    def test_add_delete_and_top_level_multiedit_contracts(self):
        for operation, body in (('Add', '+fixture\n'), ('Delete', '')):
            patch = '*** Begin Patch\n*** ' + operation + ' File: notes.txt\n' + body + '*** End Patch'
            self.assertEqual(self.decide('apply_patch', patch), 0)
        self.assertEqual(self.decide('MultiEdit', {'file_path': 'notes.txt', 'edits': [
            {'old_string': 'old', 'new_string': 'merge_gate.py waive'}]}), 0)
        self.assertEqual(self.decide('MultiEdit', {'file_path': 'notes.txt', 'edits': [
            {'file_path': 'other.txt', 'old_string': 'old', 'new_string': 'new'}]}), 2)

    def test_unknown_and_shell_execution_remain_gated(self):
        command = 'python3 /h/merge_gate.py waive --repo o/r'
        for tool in ('Bash', 'shell', 'unknown', 'namespace.apply_patch'):
            for value in ({'command': command}, {'cmd': command}, command,
                          {'command': ['python3', '/h/merge_gate.py', 'waive', '--repo', 'o/r']}):
                with self.subTest(tool=tool, shape=type(value).__name__): self.assertEqual(self.decide(tool, value), 2)


class NativeNoteBoundary(NativeEditFixtures):
    def setUp(self):
        super().setUp()
        self.helper = self.home / '.codex' / 'agent-harness' / 'wal.py'
        self.helper.parent.mkdir(parents=True)
        self.helper.write_text('# inert trusted-path fixture; never executed\n')
        self.wal = self.home / '.agent-harness' / 'codex-wals' / 'fixture-session' / 'agent-fixture.jsonl'
        self.wal.parent.mkdir(parents=True)

    def note(self, text='merge_gate.py waive; peer_review.py --pr 5; main-stamps', wal=None, program='python3'):
        return shlex.join([program, str(self.helper), 'note', '--wal', str(wal or self.wal), '--event', 'intent', '--note', text])

    def test_exact_native_note_is_data_without_stamping(self):
        for program in ('python3', 'python'):
            self.assertEqual(self.decide('Bash', {'command': self.note(program=program)}), 0)
        self.assertEqual(self.decide('Bash', self.note(), agent_id=None), 0)
        self.assertEqual(self.decide('Bash', self.note("operator's merge_gate.py waive note")), 0)
        words = ['python3', str(self.helper), 'note', '--note',
                 'merge_gate.py waive --repo o/r --pr 5 --head ' + 'a' * 40 + ' --ticket fixture',
                 '--event', 'check', '--wal', str(self.wal)]
        self.assertEqual(self.decide('Bash', shlex.join(words), agent_id=None), 0)
        words[-1] = '~/' + str(self.wal.relative_to(self.home))
        self.assertEqual(self.decide('Bash', shlex.join(words)), 0)
        self.assertFalse(self.wal.exists())
        self.assertEqual(self.secret_target.read_text(), 'fixture unchanged')

    def test_native_note_targets_and_helper_aliases_are_refused(self):
        alias = self.wal.parent / 'alias.jsonl'; alias.symlink_to(self.secret_target)
        for target in (self.secret_target, alias, self.wal.parent / 'other.txt', self.home / 'outside.jsonl'):
            with self.subTest(target=target): self.assertEqual(self.decide('Bash', self.note(wal=target)), 2)
        alternate = self.cwd / 'wal.py'; alternate.symlink_to(self.helper)
        self.assertEqual(self.decide('Bash', self.note().replace(str(self.helper), str(alternate))), 2)

    def test_single_note_does_not_exempt_compounds_or_interpreters(self):
        base = self.note('merge_gate.py waive')
        commands = [base + '; python3 /h/merge_gate.py waive', 'env ' + base,
                    'HOME=/other ' + base, base + ' > output',
                    base.replace(' note ', ' continuation '), base + ' --unknown value',
                    base + ' --event result', base.replace('python3 ', 'python3 -I ', 1),
                    'printf x > ' + str(self.helper) + '; ' + base,
                    self.note(program='/other/python3'), "python3 - <<'EOF'\nprint('merge_gate.py waive')\nEOF"]
        for command in commands:
            with self.subTest(command=command): self.assertEqual(self.decide('Bash', command), 2)

    def test_shell_expansion_is_not_literal_note_data(self):
        for value in ('"$(python3 /h/merge_gate.py waive)"', '`python3 /h/merge_gate.py waive`'):
            command = self.note().rsplit(' --note ', 1)[0] + ' --note ' + value
            self.assertEqual(self.decide('Bash', command), 2)

    def test_unquoted_newline_is_a_shell_separator(self):
        # A literal newline inside a single quoted note is data; between words it is code.
        self.assertEqual(self.decide('Bash', self.note('merge_gate.py waive\nordinary note')), 0)
        for command in (self.note().replace(' note ', '\nnote ', 1), self.note() + '\ntrue'):
            self.assertEqual(self.decide('Bash', command), 2)

    def test_note_event_and_size_contracts(self):
        for text in ('', 'x' * 4001):
            self.assertEqual(self.decide('Bash', self.note(text) + ' # merge_gate.py waive'), 2)
        self.assertEqual(self.decide('Bash', self.note().replace('--event intent', '--event bogus')), 2)


if __name__ == '__main__': unittest.main()
