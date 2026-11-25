"""Failing-first evidence for the lexer model (goodqa#17059, goodqa#17060, goodqa#17073): tests.test_guard_oracle_pins
must fail against command_guard.py at main before the repair and against a controlled break of each rule.

Run: python3 -B tests/mutants_lexer_model.py   (temporary trees only; tests/mutant_runner.py holds the control rule).
The base is a fixed commit, not origin/main, so the check stays meaningful after the repair merges."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import mutant_runner  # noqa: E402

BASE = '8539e978'  # main before the repair

MUTANTS = {
    '\\r, \\f and \\v are blanks again': [("WS = ' \\t'\n", "WS = ' \\t\\r\\f\\v'\n")],
    'a backslash before \\r\\n joins lines': [("LINE_JOIN = re.compile(r'\\\\\\n')", "LINE_JOIN = re.compile(r'\\\\\\r?\\n')")],
    'only the word alias changes a keyword': [
        ("        if 'alias' in text.lower() or text in KEYWORD_CHANGERS:", "        if text == 'alias':")],
    'zsh `}` does not end a case': [
        ("(_closes_case(val) or (not val.quoted and val.text == '}'))", '_closes_case(val)')],
    '`function NAME` is a function header': [
        ('        # not `function NAME` without parentheses',
         "        if len(fed) >= 2 and fed[-1][0][0] == 'w' and fed[-2][0][0] == 'w' and fed[-2][1] \\\n"
         "                and _keyword_word(fed[-2][0][1], 'function'):\n            return True\n"
         '        # not `function NAME` without parentheses')],
    'the scan opens a case at any word': [("        elif start and w == 'case':", "        elif w == 'case':")],
    'the scan ends a substitution at a closer inside a nested one': [
        ("        if c == '$' and s[i + 1:i + 2] in ('(', '{'):\n            i = scan_balanced(",
         "        if False:\n            i = scan_balanced(")],
    "a case pattern's ) ends the substitution": [
        ("            if state in ('pattern', 'pattern_word') and c in '()|':", '            if False:')],
    "only bash's reading of ' in a double-quoted ${..}": [
        ("            if in_dq and not self.ps and \"'\" in body:", '            if False:')],
    "zsh's reading of a $((..)) that is not arithmetic is skipped": [
        ('                if _maybe_not_arithmetic(s[i + 3:end - 2]):', '                if False:')],
    'text glued after an array assignment starts a command': [
        ("                    and ARRAY_ASSIGN.fullmatch(tokens[-1][1].raw or ''):",
         '                    and False:')],
    'a dropped case pattern loses its substitutions': [
        ('    if not dropped:\n        return stripped', '    if True:\n        return stripped')],
}

if __name__ == '__main__':
    sys.exit(mutant_runner.run('tests.test_guard_oracle_pins', 'command_guard.py', MUTANTS, BASE))
