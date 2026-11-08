"""goodqa#15365: a path glob in argument position of an ssh remote command line is not a command name.

Every command string is DATA handed to kill_guard (decide() or the hook launcher); nothing here executes one.
Cause: the remote line arrives as one word, norm_name() keeps only the text after its last '/', so
`ls tools/x/*` became the name `*`, which command_guard.names_for() fnmatches against every known command (pkill included).
KG_HOOKS_DIR points the suite at another hooks directory, as in test_kill_guard.py.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOOKS = Path(os.environ.get('KG_HOOKS_DIR') or ROOT / 'harness/hooks')
sys.path.insert(0, str(HOOKS))

import kill_guard as kg  # noqa: E402

CWD = '/Users/eric'

ALLOW = [
    "ssh t2-dev 'wc -c tools/x/*'",
    "ssh t2-dev 'ls tools/x/*'",
    "ssh t2-dev 'ls /var/log/*.log'",
    "ssh t2-dev 'grep -r needle src/*/y'",
    "ssh t2-dev 'wc -c tools/x/a'",
    "ssh t2-dev 'cat *.txt'",
    "ssh t2-dev wc -c 'tools/*'",
    "wc -c tools/x/*",
    "bash -c 'ls tools/*'",
]
BLOCK = [
    "ssh h 'pkill -f x'",
    "ssh h 'p*ll -f x'",
    "ssh h '/usr/bin/pk* x'",
    "ssh h 'ls; killall x'",
    "ssh h '/usr/bin/*'",  # glob in command position
    "ssh h '/usr/bin/p*ll x'",
    "ssh h 'ls tools/x/*; pkill x'",  # a glob argument does not hide a later kill
    "ssh h /usr/bin/pk* x",
    # red-team F1: only a SPACE head is re-parsed word by word; tab/newline heads must keep the glob expansion
    "parallel ::: $'echo\\tnode\\t|\\txargs\\t/usr/bin/killal?'",
    "parallel ::: $'echo\\t-f\\tnode\\t|\\txargs\\t/usr/bin/pki?l'",
    "parallel ::: $'ls\\t|\\txargs\\t/bin/k*l'",
    "parallel -j1 ::: $'true\\t;\\t/usr/bin/pk*'",
    "parallel --shell ::: $'ls\\t|\\txargs\\t/bin/k*l'",
]


def decide(cmd):
    with tempfile.TemporaryDirectory() as home:
        return kg.decide(cmd, cwd=CWD, home=home)[0]


def hook_rc(cmd, hooks):
    payload = json.dumps({'tool_name': 'Bash', 'cwd': CWD, 'tool_input': {'command': cmd}})
    with tempfile.TemporaryDirectory() as home:
        done = subprocess.run([sys.executable, '-I', str(Path(hooks) / 'kill_guard.py'), 'hook'], input=payload.encode(),
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60, check=False,
                              env={'HOME': home, 'PATH': '/usr/bin:/bin'})
    return 'block' if done.returncode == 2 else ('allow' if done.returncode == 0 else 'rc%d' % done.returncode)


class SshGlob(unittest.TestCase):
    def test_ac1_glob_in_argument_position_is_allowed(self):
        for cmd in ALLOW:
            self.assertEqual(decide(cmd), 'allow', cmd)

    def test_ac2_real_kills_and_glob_commands_still_block(self):
        for cmd in BLOCK:
            self.assertEqual(decide(cmd), 'block', cmd)

    def test_hook_exit_codes(self):
        self.assertEqual(hook_rc("ssh t2-dev 'ls tools/x/*'", HOOKS), 'allow')
        self.assertEqual(hook_rc("ssh h 'pkill -f x'", HOOKS), 'block')

    def test_mutant_that_rebreaks_ac1_is_caught(self):
        """Copy the hooks, remove the fix, and show AC-1 fails on the copy (so the test is not vacuous)."""
        src = (HOOKS / 'kill_guard.py').read_text(encoding='utf-8')
        marker = 'SSH_GLOB_LINE_FIX = True'
        self.assertIn(marker, src, 'fix marker missing')
        with tempfile.TemporaryDirectory() as tmp:
            for pattern in ('*.py', '*.json'):
                for f in HOOKS.glob(pattern):
                    shutil.copy(f, tmp)
            (Path(tmp) / 'kill_guard.py').write_text(src.replace(marker, 'SSH_GLOB_LINE_FIX = False'), encoding='utf-8')
            self.assertEqual(hook_rc("ssh t2-dev 'ls tools/x/*'", tmp), 'block')  # re-broken
            self.assertEqual(hook_rc("ssh h 'pkill -f x'", tmp), 'block')
            self.assertEqual(hook_rc("ssh t2-dev 'ls tools/x/*'", HOOKS), 'allow')  # real tree fixed


    def test_mutant_that_widens_to_any_whitespace_is_caught(self):
        """The first version of the fix used any whitespace; the tab/newline block rows must catch that."""
        src = (HOOKS / 'kill_guard.py').read_text(encoding='utf-8')
        marker = "SSH_GLOB_LINE_FIX and ' ' in text"
        self.assertIn(marker, src, 'fix marker missing')
        with tempfile.TemporaryDirectory() as tmp:
            for pattern in ('*.py', '*.json'):
                for f in HOOKS.glob(pattern):
                    shutil.copy(f, tmp)
            (Path(tmp) / 'kill_guard.py').write_text(src.replace(marker, "SSH_GLOB_LINE_FIX and re.search(r'\\s', text)"),
                                                     encoding='utf-8')
            self.assertEqual(hook_rc("ssh t2-dev 'ls tools/x/*'", tmp), 'allow')  # AC-1 still fine in the mutant
            self.assertEqual(hook_rc(BLOCK[-3], tmp), 'allow')  # the real-kill row slips through: the mutant is detectable
            self.assertEqual(hook_rc(BLOCK[-3], HOOKS), 'block')


if __name__ == '__main__':
    unittest.main()
