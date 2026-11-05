"""The guard reads a shell's and Python's options the way they do (GoodQA goodqa#14518).

Every command string here is DATA handed to command_guard.decide(); nothing in this file runs one. Files are synthetic and
live in a temporary HOME. CG_HOOKS_DIR points the tests at an older guard to show them failing first.
"""

import os
import shlex
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
HOOKS = Path(os.environ.get('CG_HOOKS_DIR') or ROOT / 'harness/hooks')
sys.path.insert(0, str(HOOKS))

import command_guard as cg  # noqa: E402

DELETE = 'rm -rf ~/.claude/projects'
DUMP = 'rclone config show'
# Each takes the payload as bash does: the first word that is not an option or an option's value.
PAYLOAD_FORMS = ('-c', '-ce', '-ec', '-ceo pipefail', '-ceuo pipefail', '-co pipefail', '-oc pipefail', '-c -e', '-c -x',
                 '-c -o pipefail', '-c --', '-e -c', '-o pipefail -c', '-euo pipefail -c', '-O extglob -c', '+o pipefail -c')
SCRIPT_FORMS = ('', '-e', '-eu', '-euo pipefail', '-eo pipefail', '-eou pipefail', '-oe pipefail', '-eoux pipefail',
                '-o pipefail', '+o pipefail', '-O extglob', '-eO extglob', '+O extglob', '--', '-', '--norc', '-norc',
                '--noprofile', '-noprofile', '-noediting', '-login', '--rcfile /dev/null', '-rcfile /dev/null')
PYTHON_FORMS = ('', '-I', '-Iu', '-W ignore', '-Wignore', '-X utf8', '-Xutf8', '-IW ignore', '--check-hash-based-pycs always',
                '-B -I', '--')
SHELLS = ('bash', 'sh', '/bin/bash', 'zsh')


class WalkerUnits(unittest.TestCase):
    def test_shell_options(self):
        for words, stop, on in ((['-c', 'x'], 0 + 1, {'c'}), (['-ceo', 'pipefail', 'x'], 2, {'c', 'e'}),
                                (['-oc', 'pipefail', 'x'], 2, {'c'}), (['-c', '--', 'x'], 2, {'c'}),
                                (['-', 'x'], 1, set()), (['--', '-c', 'x'], 1, set()), (['-norc', 'x'], 1, set()),
                                (['--rcfile', 'f', 'x'], 2, set()), (['-n', '+n', 'x'], 2, set()), (['-oo', 'a', 'b', 'x'], 3, set()),
                                (['-o'], 1, set()), ([], 0, set()), (['x', '-c', 'y'], 0, set()), (['--command', 'x'], 1, {'c'})):
            with self.subTest(words=words):
                self.assertEqual(cg.shell_options(words), (stop, on))

    def test_python_options(self):
        for words, expected in ((['f.py'], ('script', 0)), (['-I', 'f.py'], ('script', 1)), (['-W', 'ignore', 'f.py'], ('script', 2)),
                                (['-Wignore', 'f.py'], ('script', 1)), (['-IX', 'utf8', 'f.py'], ('script', 2)),
                                (['--check-hash-based-pycs', 'always', 'f.py'], ('script', 2)), (['--', '-f.py'], ('script', 1)),
                                (['-c', 'x'], ('code', 1)), (['-Ic', 'x'], ('code', 1)), (['-m', 'x'], ('module', 1)),
                                (['-Im', 'x'], ('module', 1)), (['-'], ('stdin', 0)), (['f.py', '-m', 'x'], ('script', 0)),
                                ([], (None, 0)), (['-I'], (None, 1)), (['--'], (None, 0))):
            with self.subTest(words=words):
                self.assertEqual(cg.python_options(words), expected)


class Rows(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.home = Path(tmp.name).resolve()
        env = mock.patch.dict(os.environ, {'HOME': str(self.home)})
        env.start()
        self.addCleanup(env.stop)
        self.clean = self.write('x/clean.sh', ('#!/bin/bash\n%s\n' % DELETE).encode())
        self.named = self.write('x/named.sh', b'#!/bin/bash\nwc -c ~/.config/rclone/rclone.conf\n')
        self.named_py = self.write('x/named.py', b'open("/any/.config/rclone/rclone.conf")\n')
        self.plain = self.write('x/plain.sh', b'#!/bin/bash\necho hello\n')
        self.plain_py = self.write('x/plain.py', b'print("hello")\n')

    def write(self, rel, data):
        path = self.home / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def verdict(self, command):
        return cg.decide(command)[0]

    def test_a_payload_is_judged_whatever_options_surround_it(self):
        self.assertGreater(len(PAYLOAD_FORMS), 10)
        for shell in SHELLS:
            for form in PAYLOAD_FORMS:
                for payload in (DELETE, DUMP):
                    command = '%s %s %s' % (shell, form, shlex.quote(payload))
                    with self.subTest(command=command):
                        self.assertEqual(self.verdict(command), 'block')

    def test_a_harmless_payload_stays_allowed(self):
        for form in PAYLOAD_FORMS:
            command = 'bash %s %s' % (form, shlex.quote('echo hello'))
            with self.subTest(command=command):
                self.assertEqual(self.verdict(command), 'allow')

    def test_a_script_is_judged_whatever_options_come_first(self):
        for form in SCRIPT_FORMS:
            for script in (self.clean, self.named):
                command = 'bash %s %s' % (form, script)
                with self.subTest(command=command):
                    self.assertEqual(self.verdict(command), 'block')

    def test_a_plain_script_stays_allowed(self):
        for form in SCRIPT_FORMS:
            command = 'bash %s %s' % (form, self.plain)
            with self.subTest(command=command):
                self.assertEqual(self.verdict(command), 'allow')

    def test_a_script_is_judged_when_its_own_arguments_look_like_options(self):
        for args in ('-c prod', '--command x', '-ic x', '-n', '-e'):
            for script in (self.clean, self.named):
                command = 'bash %s %s' % (script, args)
                with self.subTest(command=command):
                    self.assertEqual(self.verdict(command), 'block')

    def test_a_c_after_the_script_keeps_its_text_judged(self):
        # bash hands these to the script, but the first word may be a variable or `busybox sh`, so this stays as strict
        for command in ('bash %s -c %s' % (self.plain, shlex.quote(DELETE)), 'bash $OPTS -c %s' % shlex.quote(DELETE),
                        'busybox sh -c %s' % shlex.quote(DELETE)):
            with self.subTest(command=command):
                self.assertEqual(self.verdict(command), 'block')

    def test_only_a_real_n_stops_the_script_from_running(self):
        for form, verdict in (('-n', 'allow'), ('-en', 'allow'), ('-ne', 'allow'), ('-n -e', 'allow'),
                              ('-noprofile', 'block'), ('-noediting', 'block'), ('-norc', 'block'), ('-n +n', 'block')):
            command = 'bash %s %s' % (form, self.named)
            with self.subTest(command=command):
                self.assertEqual(self.verdict(command), verdict)

    def test_python_options_before_the_script(self):
        for form in PYTHON_FORMS:
            command = 'python3 %s %s' % (form, self.named_py)
            with self.subTest(command=command):
                self.assertEqual(self.verdict(command), 'block')
            command = 'python3 %s %s' % (form, self.plain_py)
            with self.subTest(command=command):
                self.assertEqual(self.verdict(command), 'allow')

    def test_python_arguments_after_the_script_do_not_hide_it(self):
        for args in ('-m prod', '-m', '-c config.json', '-c', '-W x'):
            command = 'python3 %s %s' % (self.named_py, args)
            with self.subTest(command=command):
                self.assertEqual(self.verdict(command), 'block')

    def test_python_modules_and_code_are_not_read_as_a_script(self):
        for command in ('python3 -m %s' % self.named_py, 'python3 -Im %s' % self.named_py, 'python3 -m unittest %s' % self.named_py):
            with self.subTest(command=command):
                self.assertEqual(self.verdict(command), 'allow')
        self.assertEqual(self.verdict('python3 -c %s' % shlex.quote('print(1)')), 'allow')

    def test_python_arguments_after_the_script_keep_their_text_judged(self):
        command = 'python3 %s -c %s' % (self.plain_py, shlex.quote("import os; os.system('%s')" % DELETE))
        self.assertEqual(self.verdict(command), 'block')

    def test_a_script_written_in_this_command_is_found_past_an_option_value(self):
        target = self.home / 'x/w3.py'
        command = "printf %%s %s > %s; python3 -W ignore %s" % (shlex.quote("import os; os.system('%s')" % DELETE), target, target)
        self.assertEqual(self.verdict(command), 'block')


if __name__ == '__main__':
    unittest.main()
