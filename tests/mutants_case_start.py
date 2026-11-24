"""goodqa#17059 failing-first evidence for the case-keyword rule: tests.test_guard_case_start must fail against
command_guard.py before the rule and against a controlled broken variant of each of its conditions.

Run: python3 -B tests/mutants_case_start.py   (copies the hooks and the tests into a temporary tree; changes nothing
here). The base is a fixed commit, not origin/main, so the check stays meaningful after the fix merges.

Not a mutant: dropping `not word.quoted` from _keyword_word alone. A quoted word's source text keeps its quotes, so
`raw == name` already rejects it; the mutant 'the expanded text is read' removes both checks together."""
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEST = 'tests.test_guard_case_start'
GUARD = 'command_guard.py'
BASE = 'd56a8cb0'  # main before the rule

# each mutant is a list of (old, new) replacements in command_guard.py
MUTANTS = {
    'the expanded text is read, not the source': [
        ("    return not word.quoted and word.raw == name and not word.odd_edge",
         "    return word.text == name and not word.odd_edge")],
    'a word glued at \\r, \\f or \\v is a keyword': [
        ("    return not word.quoted and word.raw == name and not word.odd_edge",
         "    return not word.quoted and word.raw == name")],
    'the lexer never marks a glued word': [
        ("            w.odd_edge = s[j:j + 1] in ODD_WS or (i > 0 and s[i - 1] in ODD_WS)",
         "            w.odd_edge = False")],
    'any word leads to a command start': [
        ("        if kind != 'w' or not start or not any(_keyword_word(val, w) for w in LEAD_WORDS):",
         "        if kind != 'w':")],
    'a lead word leads in any position': [
        ("        if kind != 'w' or not start or not any(_keyword_word(val, w) for w in LEAD_WORDS):",
         "        if kind != 'w' or not any(_keyword_word(val, w) for w in LEAD_WORDS):")],
    'a closing parenthesis starts a command': [
        ("START_OPS = frozenset(('\\n', ';', '&', '&&', '||', '|', '|&', '('))",
         "START_OPS = frozenset(('\\n', ';', '&', '&&', '||', '|', '|&', '(', ')'))")],
    'time or ! after a pipe leads': [
        ("        if val.raw in ('time', '!'):", "        if False:")],
    'a redirection keeps the command start': [
        ("        if kind == 'op':\n            return val in START_OPS\n",
         "        if kind == 'op':\n            return val in START_OPS\n        if kind == 'redir':\n            return start\n")],
    'an assignment keeps the command start': [
        ("        if kind == 'op':\n            return val in START_OPS\n",
         "        if kind == 'op':\n            return val in START_OPS\n"
         "        if kind == 'w' and '=' in (val.raw or ''):\n            return start\n")],
    'an alias is ignored': [
        ("    if _aliases_a_keyword(tokens):\n        return list(tokens)", "    if False:\n        return list(tokens)")],
    'a subscripted alias is read from the expanded text only': [
        ("    return any(w.text == 'alias' or w.text.startswith('aliases[') or (w.raw or '').startswith('aliases[')",
         "    return any(w.text == 'alias' or w.text.startswith('aliases[')")],
    'a quoted in is accepted': [
        ("and _keyword_word(tokens[i + 2][1], 'in'):", "and tokens[i + 2][1].text == 'in':")],
}


def unittest_run(tmp):
    done = subprocess.run([sys.executable, '-B', '-m', 'unittest', TEST], cwd=str(tmp), capture_output=True, text=True)
    ran = re.search(r'^Ran (\d+) test', done.stderr, re.M)
    failed = [ln for ln in done.stderr.splitlines() if ln.startswith(('FAIL:', 'ERROR:'))]
    return done.returncode, int(ran.group(1)) if ran else 0, failed


def run(tmp, label, expect_ran):
    """A mutant counts as killed only when the whole module loaded (the same number of tests ran as in the control)
    and a test failed: an import error or a missing fixture is not a kill."""
    rc, ran, failed = unittest_run(tmp)
    killed = rc != 0 and ran == expect_ran and failed
    verdict = 'FAILS (good)' if killed else 'PASSES (test is vacuous)' if rc == 0 else 'BROKEN TREE (ran %d)' % ran
    print('%-56s %s' % (label, verdict))
    for line in failed:
        print('    ' + line)
    return bool(killed)


def tree():
    tmp = Path(tempfile.mkdtemp(prefix='mutant-'))
    shutil.copytree(ROOT / 'harness' / 'hooks', tmp / 'harness' / 'hooks', ignore=shutil.ignore_patterns('__pycache__'))
    shutil.copytree(ROOT / 'tests', tmp / 'tests', ignore=shutil.ignore_patterns('__pycache__'))
    return tmp


def main():
    tmp = tree()
    try:  # control: the unmutated tree must pass, so a kill below means the mutant, not the copy
        rc, expect_ran, failed = unittest_run(tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print('%-56s %s' % ('control: unmutated copy', 'PASSES, %d tests' % expect_ran if rc == 0 else 'FAILS'))
    if rc != 0 or expect_ran == 0:
        for line in failed:
            print('    ' + line)
        return 1
    bad = 0
    tmp = tree()
    try:
        base = subprocess.run(['git', '-C', str(ROOT), 'show', BASE + ':harness/hooks/' + GUARD], capture_output=True,
                              check=True).stdout
        (tmp / 'harness' / 'hooks' / GUARD).write_bytes(base)
        bad += 0 if run(tmp, 'base %s (pattern mode after any reserved word)' % BASE, expect_ran) else 1
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
            bad += 0 if run(tmp, name, expect_ran) else 1
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    print('mutants not killed or not applied:', bad)
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
