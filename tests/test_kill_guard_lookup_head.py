"""goodqa#15377 (H-a): a command line whose last path segment is `which`, `type` or `hash` is not a lookup command.

Every string is DATA handed to kill_guard.decide() or the hook launcher; nothing here executes one.
Cause: apply() returned at its lookup-command check before the space-head re-parse. norm_name() keeps the last path segment,
so `echo 1 | xargs /bin/k*l; ls /x/which` was read as the name `which`, a lookup that runs nothing.
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
BLOCK = [
    "parallel ::: 'echo 1234 | xargs /bin/k*l; ls /x/which'",
    "parallel ::: 'echo 1234 | xargs /bin/k*l; ls /x/type'",
    "parallel ::: 'echo 1234 | xargs /bin/k*l; ls /x/hash'",
    "parallel ::: 'pkill -f node; ls /x/which'",
    "parallel ::: 'killall node; ls /x/hash'",
    "ssh h 'pkill -f node; ls /x/which'",
    "ssh h 'ls; killall x; ls /x/type'",
    "ssh h 'echo 1234 | xargs /bin/k*l; ls /x/hash'",
]
ALLOW = [
    "which pkill",
    "type pkill",
    "hash pkill",
    "command -v pkill",
    "ssh h 'ls /x/which'",
    "ssh h 'ls tools/x/*'",
    "parallel ::: 'ls /x/which'",
    "parallel ::: 'echo hi; ls /x/type'",
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


class LookupHead(unittest.TestCase):
    def test_command_lines_ending_in_a_lookup_name_are_still_judged(self):
        for cmd in BLOCK:
            self.assertEqual(decide(cmd), 'block', cmd)

    def test_real_lookups_and_harmless_lines_stay_allowed(self):
        for cmd in ALLOW:
            self.assertEqual(decide(cmd), 'allow', cmd)

    def test_mutant_without_the_fix_is_caught(self):
        src = (HOOKS / 'kill_guard.py').read_text(encoding='utf-8')
        marker = 'LOOKUP_HEAD_FIX = True'
        self.assertIn(marker, src, 'fix marker missing')
        with tempfile.TemporaryDirectory() as tmp:
            for pattern in ('*.py', '*.json'):
                for f in HOOKS.glob(pattern):
                    shutil.copy(f, tmp)
            (Path(tmp) / 'kill_guard.py').write_text(src.replace(marker, 'LOOKUP_HEAD_FIX = False'), encoding='utf-8')
            self.assertEqual(hook_rc(BLOCK[0], tmp), 'allow')  # re-broken
            self.assertEqual(hook_rc(BLOCK[0], HOOKS), 'block')
            self.assertEqual(hook_rc(BLOCK[5], HOOKS), 'block')


if __name__ == '__main__':
    unittest.main()
