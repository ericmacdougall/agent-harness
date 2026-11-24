"""goodqa#17008 failing-first evidence for the launcher rule of the WAL guard: tests.test_wal_write_guard must fail
against each controlled broken variant of the rule.

Run: python3 -B tests/mutants_wal_launchers.py   (temporary trees only; see tests/mutant_runner.py for the control
rule). There is no base run: before the rule the WAL guard was not on main, and the replay commit it was built on is
not a base a reviewer can check out on its own; tests/test_wal_write_guard.py's failing-first rows cover it."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import mutant_runner  # noqa: E402

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
        ('                if value is not None and self._names_wal_tree(value):', '                if False:')],
    'the refusal keeps the generic route': [("route + '; to write a row, ' + note if route else note", 'note')],
}


if __name__ == '__main__':
    sys.exit(mutant_runner.run('tests.test_wal_write_guard', 'command_guard.py', MUTANTS))
