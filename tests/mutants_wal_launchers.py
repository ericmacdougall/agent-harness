"""goodqa#17008 failing-first evidence for the launcher rule of the WAL guard: tests.test_wal_write_guard must fail
against command_guard.py before the rule (the stand-alone replay of the WAL guard, which skipped every launcher) and
against each controlled broken variant of the rule.

Run: python3 -B tests/mutants_wal_launchers.py   (copies the hooks and the tests into a temporary tree; changes nothing
here). The base is a fixed commit, not origin/main, so the check stays meaningful after the fix merges."""
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEST = 'tests.test_wal_write_guard'
GUARD = 'command_guard.py'
BASE = 'c00ffa9334099c07cfcc76b6c4d0607d62523e05'  # the WAL guard on main before the launcher rule
TESTS = ('test_wal_write_guard.py',)

# each mutant is a list of (old, new) replacements in command_guard.py
MUTANTS = {
    'every launcher is quiet': [('        launcher = WAL_LAUNCHER_CLASS.get(name)',
                                 '        launcher = WAL_QUIET if name in WAL_LAUNCHER_CLASS else None')],
    'every launcher may write': [('        launcher = WAL_LAUNCHER_CLASS.get(name)',
                                  '        launcher = WAL_MAY_WRITE if name in WAL_LAUNCHER_CLASS else None')],
    'a recorder is classified quiet': [("'strace', 'ltrace', 'dtruss', 'script', 'flock',", "'strace', 'ltrace', 'dtruss', 'flock',"),
                                       ("'runuser', 'gosu', 'sshpass',", "'runuser', 'gosu', 'sshpass', 'script',")],
    'a launcher is left unclassified': [("'strace', 'ltrace', 'dtruss', 'script', 'flock',", "'strace', 'ltrace', 'dtruss', 'flock',")],
    'the working directory is ignored': [('            if here or any(self._wal_hit(a) or', '            if any(self._wal_hit(a) or')],
    "an option's text is ignored": [('any(self._wal_hit(a) or self._names_wal_tree(a.raw or a.text) for a in args):',
                                     'any(self._wal_hit(a) for a in args):')],
    'nohup in the tree is allowed': [("            if name == 'nohup' and here:", '            if False:')],
    "an unknown program's text is ignored": [
        ('        if not hits and not any(self._names_wal_tree(a.raw or a.text) for a in args):', '        if not hits:')],
    'the refusal keeps the generic route': [("route + '; to write a row, ' + note if route else note", 'note')],
}


def run(tmp, label):
    done = subprocess.run([sys.executable, '-B', '-m', 'unittest', TEST], cwd=str(tmp), capture_output=True, text=True)
    killed = done.returncode != 0
    print('%-48s %s' % (label, 'FAILS (good)' if killed else 'PASSES (test is vacuous)'))
    return killed


def tree():
    tmp = Path(tempfile.mkdtemp(prefix='mutant-'))
    shutil.copytree(ROOT / 'harness' / 'hooks', tmp / 'harness' / 'hooks', ignore=shutil.ignore_patterns('__pycache__'))
    (tmp / 'tests').mkdir()
    for name in TESTS:
        shutil.copy(ROOT / 'tests' / name, tmp / 'tests')
    return tmp


def main():
    bad = 0
    tmp = tree()
    try:
        base = subprocess.run(['git', '-C', str(ROOT), 'show', BASE + ':harness/hooks/' + GUARD], capture_output=True,
                              check=True).stdout
        (tmp / 'harness' / 'hooks' / GUARD).write_bytes(base)
        bad += 0 if run(tmp, 'base %s (no launcher rule)' % BASE[:8]) else 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    for name, edits in MUTANTS.items():
        tmp = tree()
        try:
            path = tmp / 'harness' / 'hooks' / GUARD
            text = path.read_text()
            missing = [old for old, _ in edits if old not in text]
            if missing:
                print('MUTANT NOT APPLIED:', name)
                bad += 1
                continue
            for old, new in edits:
                text = text.replace(old, new, 1)
            path.write_text(text)
            bad += 0 if run(tmp, name) else 1
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
