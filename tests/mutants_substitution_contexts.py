"""goodqa#17060 failing-first evidence: tests.test_guard_substitution_contexts must fail against command_guard.py before
the fix and against a controlled broken variant of each part of it.

Run: python3 -B tests/mutants_substitution_contexts.py   (temporary trees only; see tests/mutant_runner.py for the
control rule). The base is a fixed commit, not origin/main, so the check stays meaningful after the fix merges."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import mutant_runner  # noqa: E402

BASE = '8539e978'  # main before the fix

MUTANTS = {
    'a ${...} body is not scanned': [
        ('            self._record_inner_subs(body, w)\n', '')],
    'an arithmetic body is not scanned': [
        ('                self._record_inner_subs(s[i + 3:end - 2], w)\n', '')],
    'every $(( is arithmetic': [
        ("        return j + 1 if s[j] == ')' else None", '        return j + 1')],
    'a backtick in a body is not recorded': [
        ("            if c == '`' and not self.ps:\n                j = scan_backtick(text, i + 1)\n"
         "                w.subs.append((text[i + 1:j - 1]",
         "            if False:\n                j = scan_backtick(text, i + 1)\n"
         "                w.subs.append((text[i + 1:j - 1]")],
    'arithmetic inside a body is skipped whole': [
        ('                    i += 3\n                    continue\n                j = scan_balanced(text, i + 2)  # `$((cmd)',
         '                    i = min(end, n)\n                    continue\n'
         '                j = scan_balanced(text, i + 2)  # `$((cmd)')],
    'the scan ends a substitution at a closer inside a nested one': [
        ("        if c == '$' and s[i + 1:i + 2] in ('(', '{'):\n            i = scan_balanced(",
         "        if False:\n            i = scan_balanced(")],
    'the scan ignores substitutions inside double quotes': [
        ("                if s[i] == '$' and s[i + 1:i + 2] in ('(', '{'):", '                if False:')],
    "a case pattern's ) ends the substitution": [
        ("        elif start and w == 'case':\n            cases.append('subject')",
         "        elif False:\n            cases.append('subject')")],
    'a dropped case pattern loses its substitutions': [
        ('    if not dropped:\n        return stripped', '    if True:\n        return stripped')],
    'a fall-through does not return to patterns': [
        ("            if state == 'body' and c == ';' and s[i + 1:i + 2] in (';', '&'):",
         "            if state == 'body' and c == ';' and s[i + 1:i + 2] == ';':")],
}

if __name__ == '__main__':
    sys.exit(mutant_runner.run('tests.test_guard_substitution_contexts', 'command_guard.py', MUTANTS, BASE))
