"""goodqa#17044 failing-first evidence: tests.test_guard_double_bracket must fail against command_guard.py without the
`[[ ]]` fold (the base commit) and against each controlled broken variant of every branch of the fold.

Run: python3 -B tests/mutants_double_bracket.py   (copies the hooks and the tests into a temporary tree; changes nothing
here). The base is a fixed commit, not origin/main, so the check stays meaningful after the fix merges."""
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEST = 'tests.test_guard_double_bracket'
GUARD = 'command_guard.py'
BASE = 'd56a8cb0c1e40f4f99ba73c8a90016a48a7ccd6a'  # main before the fold
TESTS = ('test_guard_double_bracket.py', 'test_command_guard.py', 'test_kill_guard.py', 'command_guard_corpus.py',
         'kill_guard_corpus.json')

MUTANTS = {
    'the fold is not called': ('        tokens = _fold_conditionals(tokens)', '        pass'),
    'PowerShell text is folded': ('    if not ps:  # PowerShell', '    if True:  # PowerShell'),
    'a bracket anywhere is folded': ("if kind == 'w' and at_start and _plain(val, '[[')", "if kind == 'w' and _plain(val, '[[')"),
    'any reserved word leads, in any position': (
        'at_start = at_start and kind == \'w\' and not val.quoted and val.text in _LEAD_WORDS',
        'at_start = kind == \'w\' and not val.quoted and val.text in RESERVED'),
    'a closing parenthesis leads': ("at_start = val != ')' or (", "at_start = True or ("),
    'a function body does not lead': ("at_start = val != ')' or (len(out) >= 3", "at_start = val != ')' or (False"),
    'a redirection keeps the position': (
        "                at_start = at_start and kind == 'w' and not val.quoted and val.text in _LEAD_WORDS",
        "                at_start = at_start and (kind == 'redir' or (not val.quoted and val.text in _LEAD_WORDS))"),
    'a quoted bracket is folded': ('    return not word.quoted and word.raw == text', '    return word.text == text'),
    'an unterminated bracket is folded': ('    return len(tokens), False',
                                          '    return (len(tokens) - 1, True) if len(tokens) > i else (len(tokens), False)'),
    'a separator inside is accepted': ("        elif val not in ('(', ')', '\\n') and not (val == '|' and pattern):",
                                       "        elif val in ('|&',):"),
    'a pipe is accepted outside a pattern': ("and not (val == '|' and pattern):", "and not (val == '|'):"),
    'a pipe is refused inside a pattern': ("and not (val == '|' and pattern):", "and not False:"),
    'a pattern never ends': ("        elif val in ('&&', '||'):\n            pattern = False",
                             "        elif val in ('&&', '||'):\n            pass"),
    'any redirection is accepted': ("            if val.op not in ('<', '>') or val.fd is not None or val.target is None:",
                                    "            if val.target is None:"),
    'an fd redirection is accepted': ("val.op not in ('<', '>') or val.fd is not None or", "val.op not in ('<', '>') or"),
    'a line break stays a separator': ("            elif inner != '\\n':\n                out.append(('w', _operator_word(inner)))",
                                       "            else:\n                out.append(('op', inner))"),
    'operators inside are dropped': ("            elif inner != '\\n':\n                out.append(('w', _operator_word(inner)))",
                                     "            elif False:\n                pass"),
    'the first closing word is skipped': ("            if _plain(val, ']]'):\n                return j, True",
                                          "            if _plain(val, ']]') and j > i + 2:\n                return j, True"),
    'a failed scan is repeated': ("and _plain(val, '[[') and i >= dead_until:", "and _plain(val, '[['):"),
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
        bad += 0 if run(tmp, 'base %s (no fold)' % BASE[:8]) else 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    for name, (old, new) in MUTANTS.items():
        tmp = tree()
        try:
            path = tmp / 'harness' / 'hooks' / GUARD
            text = path.read_text()
            if old not in text:
                print('MUTANT NOT APPLIED:', name)
                bad += 1
                continue
            path.write_text(text.replace(old, new, 1))
            bad += 0 if run(tmp, name) else 1
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
