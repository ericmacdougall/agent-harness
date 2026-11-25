"""16640: all signalling-looking commands are analyzer data, never executed."""
import hashlib
import os
from pathlib import Path
import shlex
import sys
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'harness/hooks'))
import commit_policy as cp
import kill_guard as kg


class DataOperations(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name).resolve()
        self.env = mock.patch.dict(os.environ, HOME=str(self.home))
        self.env.start()
        self.addCleanup(self.env.stop)
        self.script = self.home / '.codex/agent-harness/wal.py'
        self.script.parent.mkdir(parents=True, mode=0o700)
        self.script.write_bytes((ROOT / 'codex/hooks/wal.py').read_bytes())
        self.script.chmod(0o600)
        self.wal = self.home / '.agent-harness/codex-wals/session/main.jsonl'
        self.wal.parent.mkdir(parents=True, mode=0o700)
        for p in (self.wal.parent.parent, self.wal.parent.parent.parent):
            p.chmod(0o700)
        self.wal.write_text('')
        self.wal.chmod(0o600)

    def decide(self, command):
        """kill_guard judges effect (redesign 2026-11-24): pid 12345 is another owner's process in this fixed table."""
        table = {12345: kg.Proc(12345, 1, 12345, os.getuid(), 'node /other/owner/server.js')}
        ctx = kg.Context(cwd=str(self.home), table=table, ancestors=[], cwds={12345: '/other/owner'},
                         roles={'top': False, 'maintainer': False, 'supervised': [], 'own': []},
                         own_roots=([str(self.home)], []), ledger=set(), start=lambda pid: None)
        with mock.patch.object(kg, 'audit'):
            return kg.decide(command, context=ctx, home=str(self.home))[0]

    def note(self, text='will kill nothing'):
        return (f'{Path(sys.executable).resolve()} -I -S {self.script} note --wal {self.wal} '
                f'--event intent --note {shlex.quote(text)}')

    def test_edit_payloads_are_data_before_both_entry_points(self):
        patch = "*** Begin Patch\n*** Add File: one.md\n+git commit parent's guide\n*** Add File: two.md\n+gh pr create\n*** End Patch"
        for name in ('apply_patch', 'APPLY_PATCH', 'write', 'Edit', 'MultiEdit', 'NotebookEdit'):
            for data in (patch, {'input': patch}, {'command': patch}, {'cmd': patch}):
                with self.subTest(name=name, data=type(data).__name__):
                    payload = {'tool_name': name, 'tool_input': data}
                    self.assertFalse(cp.may_commit(payload))
                    self.assertEqual(cp.run_hook(payload, {'enforcement': 'on'})[0], 0)

    def test_executable_and_unknown_operations_keep_checks(self):
        for name in ('Bash', 'exec_command', 'write_stdin', 'functions.exec', 'apply_patch_shell', '', None):
            payload = {'tool_name': name, 'tool_input': {'command': "git commit parent's guide"}}
            self.assertTrue(cp.may_commit(payload), name)
            self.assertEqual(cp.run_hook(payload, {'enforcement': 'on'})[0], 2, name)

    def test_notes_are_data_whatever_they_say(self):
        # The old guard allowed a note only through a hashed, trusted interpreter path; prose never signals anything.
        for text in ('will kill nothing', 'literal $(kill 12345) and `kill 12345`', 'multi\nline kill prose',
                     'kill ' + 'x' * 4000):
            self.assertEqual(self.decide(self.note(text)), 'allow', text)
        self.assertEqual(self.decide('env ' + self.note()), 'allow')
        self.assertEqual(self.decide('PYTHONPATH=/tmp ' + self.note()), 'allow')

    def test_a_real_stop_of_another_owners_pid_is_refused_behind_any_wrapper(self):
        wrappers = ('', '/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C ', '/usr/bin/sudo -n ',
                    '/usr/bin/timeout --signal=TERM --kill-after=2s 20s ', 'nohup ', 'timeout -s TERM -k 2s 20s ')
        for prefix in wrappers:
            for inner in ("python3 -c 'import os; os.kill(12345, 9)'", 'kill 12345', "sh -c 'kill 12345'",
                          'python3 observer.py "$(kill 12345)"', self.note() + ' ; kill 12345'):
                with self.subTest(prefix=prefix, inner=inner):
                    self.assertEqual(self.decide(prefix + inner), 'block')

    def test_wrapped_programs_that_signal_nothing_are_allowed(self):
        for command in ('/usr/bin/timeout --kill-after=2s 20s python3 observer.py --count 2',
                        '/usr/bin/env -i PATH=/usr/bin:/bin BASH_ENV=kill python3 observer.py kill',
                        '/usr/bin/timeout --signal=TERM --kill-after=2s 20s /usr/bin/python3.12 -I -S -B '
                        '/usr/local/lib/agent-harness/process-visibility.py --target /x --pid 12345:67890',
                        # code read from stdin is a file's contents: not judged
                        "printf 'import os; os.kill(12345,9)' | /usr/bin/timeout --kill-after=2s 20s python3 -"):
            with self.subTest(command=command):
                self.assertEqual(self.decide(command), 'allow')

if __name__ == '__main__':
    unittest.main()
