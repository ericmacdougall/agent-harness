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
        with mock.patch.object(kg, 'audit'):
            return kg.decide(command, cwd=str(self.home), home=str(self.home))[0]

    def note(self, text='will kill nothing'):
        return (f'{sys.executable} -I -S {self.script} note --wal {self.wal} '
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

    def test_literal_native_note(self):
        for text in ('will kill nothing', 'literal $(kill 12345) and `kill 12345`', 'multi\nline kill prose'):
            self.assertEqual(self.decide(self.note(text)), 'allow', text)
        self.assertEqual(self.decide(self.note().replace('-I -S ', '-I -S -B -u ')), 'allow')

    def test_native_note_rejects_executable_or_unbound_forms(self):
        base = self.note()
        bad = [base.replace(' -I -S ', ' '), base.replace(' -I -S ', ' -I '),
               base.replace('--event intent', '--event madeup'), base + ' --event risk',
               base + ' --other kill', base.replace("'will kill nothing'", '"$(kill 12345)"'),
               base + ' > out', base + ' ; kill 12345', base.replace(sys.executable, '/tmp/python3'),
               base.replace('--note', '--note=kill --note'), base.replace('note --wal', 'hook --wal'),
               self.note('kill ' + 'x' * 4000), base.replace('--note', '--notefake'),
               base.replace(str(self.wal), str(self.wal.parent / '../session/main.jsonl')),
               base.replace("'will kill nothing'", '"`kill 12345`"'),
               'PYTHONPATH=/tmp ' + base, 'env ' + base,
               base + " <<'EOF'\nkill 12345\nEOF"]
        for command in bad:
            with self.subTest(command=command):
                self.assertEqual(self.decide(command), 'block')
        self.script.write_text(self.script.read_text() + '\n# drift\n')
        self.assertEqual(self.decide(base), 'block')

    def test_native_note_rejects_linked_install_and_wal(self):
        saved = self.script.with_name('saved.py')
        self.script.rename(saved)
        self.script.symlink_to(saved)
        self.assertEqual(self.decide(self.note()), 'block')
        self.script.unlink()
        self.script.write_bytes(saved.read_bytes())
        self.script.chmod(0o600)
        os.link(self.script, self.script.with_name('alias.py'))
        self.assertEqual(self.decide(self.note()), 'block')
        self.script.with_name('alias.py').unlink()
        os.link(self.wal, self.wal.with_name('alias.jsonl'))
        self.assertEqual(self.decide(self.note()), 'block')

    def test_native_note_requires_private_regular_wal(self):
        self.wal.chmod(0o644)
        self.assertEqual(self.decide(self.note()), 'block')
        self.wal.chmod(0o600)
        other = self.wal.with_name('other')
        self.wal.rename(other)
        self.wal.symlink_to(other)
        self.assertEqual(self.decide(self.note()), 'block')

    def test_note_digest_tracks_reviewed_source(self):
        self.assertEqual(kg.CODEX_WAL_NOTE_SHA256, hashlib.sha256(self.script.read_bytes()).hexdigest())

    def test_cellar_exception_is_exact_and_rejects_acl_uncertainty(self):
        info = SimpleNamespace(st_mode=stat.S_IFDIR | 0o775, st_uid=os.getuid(), st_gid=80)
        result = SimpleNamespace(returncode=0, stdout='drwxrwxr-x 10 owner admin 320 date /opt/homebrew/Cellar')
        with mock.patch.object(kg.sys, 'platform', 'darwin'), mock.patch('grp.getgrgid', return_value=SimpleNamespace(gr_name='admin')), mock.patch.object(kg.subprocess, 'run', return_value=result):
            self.assertTrue(kg._trusted_cellar_directory(Path('/opt/homebrew/Cellar'), info))
            self.assertFalse(kg._trusted_cellar_directory(Path('/opt/homebrew/Cellar/other'), info))
            info.st_gid = 20
            self.assertFalse(kg._trusted_cellar_directory(Path('/opt/homebrew/Cellar'), info))
            info.st_gid = 80
            info.st_mode |= 0o002
            self.assertFalse(kg._trusted_cellar_directory(Path('/opt/homebrew/Cellar'), info))
            info.st_mode &= ~0o002
            result.stdout = 'drwxrwxr-x+ 10 owner admin 320 date /opt/homebrew/Cellar'
            self.assertFalse(kg._trusted_cellar_directory(Path('/opt/homebrew/Cellar'), info))
            result.stdout = ''
            self.assertFalse(kg._trusted_cellar_directory(Path('/opt/homebrew/Cellar'), info))

    def test_trusted_python_rejects_writable_binary_and_other_ancestor(self):
        original = Path.lstat
        binary = Path(sys.executable).resolve()
        for target in (binary, binary.parent):
            def changed(path):
                result = original(path)
                if path == target:
                    data = list(result)
                    data[0] |= 0o022
                    return os.stat_result(data)
                return result
            with mock.patch.object(Path, 'lstat', changed):
                self.assertEqual(self.decide(self.note()), 'block')

    def test_supervised_observer_argv(self):
        command = ('/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C /usr/bin/sudo -n '
                   '/usr/bin/timeout --signal=TERM --kill-after=2s 20s /usr/bin/python3.12 '
                   '-I -S -B /usr/local/lib/agent-harness/process-visibility.py '
                   '--target /home/example/observer-canary --pid 12345:67890')
        self.assertEqual(self.decide(command), 'allow')

    def test_wrappers_preserve_inner_danger_and_uncertain_grammar(self):
        wrappers = ('/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C ', '/usr/bin/sudo -n ',
                    '/usr/bin/timeout --signal=TERM --kill-after=2s 20s ',
                    '/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C /usr/bin/sudo -n '
                    '/usr/bin/timeout --signal=TERM --kill-after=2s 20s ')
        for prefix in wrappers:
            for inner in ("python3 -c 'import os; os.kill(12345, 9)'", 'kill 12345',
                          "sh -c 'kill 12345'", "python3 - <<'EOF'\nimport os; os.kill(12345, 9)\nEOF"):
                with self.subTest(prefix=prefix, inner=inner):
                    self.assertEqual(self.decide(prefix + inner), 'block')
        for prefix in ('timeout --kill-after=2s nope ', 'timeout --kill-after=2s 0s ',
                       'timeout --unknown=kill 2s ', 'env -i BASH_ENV=kill ', 'sudo -s '):
            self.assertEqual(self.decide(prefix + 'python3 observer.py kill'), 'block')

    def test_wrapper_boundary_and_injection_controls(self):
        for prefix in ('/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C ', '/usr/bin/sudo -n ',
                       '/usr/bin/timeout -s TERM -k 2s 20s '):
            self.assertEqual(self.decide(prefix + 'python3 observer.py --count 2'), 'allow')
            self.assertEqual(self.decide(prefix + 'python3 observer.py "$(kill 12345)"'), 'block')
            self.assertEqual(self.decide(prefix + "python3 - <<< 'import os; os.kill(12345,9)'"), 'block')
        for prefix in ('/usr/bin/env -i PATH=/tmp LC_ALL=C ', '/usr/bin/env -i PATH=/usr/bin:/bin BASH_ENV=kill ',
                       '/usr/bin/timeout --kill-after=2s -1 ', '/usr/bin/timeout --kill-after=2s 999999999d ',
                       '/usr/bin/timeout --kill-after=2s --signal=ANY 2s ',
                       '/usr/bin/timeout --kill-after=2s --kill-after=1s 2s '):
            self.assertEqual(self.decide(prefix + 'python3 observer.py kill'), 'block')
        self.assertEqual(self.decide("printf 'import os; os.kill(12345,9)' | /usr/bin/timeout --kill-after=2s 20s python3 -"), 'block')


if __name__ == '__main__':
    unittest.main()
