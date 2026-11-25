"""goodqa#17059: a case statement's pattern lists are dropped only where `case` is provably the keyword.

Both guards share `_strip_case_patterns`, which drops the pattern words of `case X in a|b) ...` so that `a|b` is not
read as a pipeline. It used to start pattern mode after any reserved word in any position. So in a command such as
`echo done case x in; <command>`, the `;` and the command after it were dropped as "patterns", and neither guard saw
the command, which the shell runs.

The rule is now inverted. Pattern mode starts only at an unquoted `case`, written as such in the source, at a
provable command start (`CommandStart`), followed by a source `in`. Anywhere else, `case` is an ordinary word.

Every command string here is DATA handed to decide(); nothing in this file executes a row. ShellOracle runs only fixed
forms whose commands call a local `marker` function, to pin the shell behaviour the parser models. GUARD_HOOKS_DIR
points the suite at another hooks directory to show it failing first.
"""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
HOOKS = Path(os.environ.get('GUARD_HOOKS_DIR') or ROOT / 'harness/hooks')
os.environ.setdefault('KG_HOOKS_DIR', str(HOOKS))
os.environ.setdefault('CG_HOOKS_DIR', str(HOOKS))
sys.path.insert(0, str(HOOKS))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import command_guard as cg  # noqa: E402
import command_guard_corpus as corpus  # noqa: E402
import test_command_guard as tcg  # noqa: E402
import test_kill_guard as tkg  # noqa: E402

DELETE = 'rm -rf ~/.claude/projects'  # command_guard refuses it wherever it runs
KILL = 'kill -9 -1'  # kill_guard refuses it only as a real command: no indirect-kill text, no verb in an operand

# each row breaks exactly one condition of "case is the keyword here"; {X} is a command the shell really runs
NOT_THE_KEYWORD = {
    # not at a command start
    'after an argument': 'echo x case y in; {X}',
    **{'after the reserved word %r used as an argument' % w: 'echo %s case y in; {X}' % w
       for w in ('if', 'then', 'else', 'elif', 'fi', 'do', 'done', 'while', 'until', 'esac', 'in', '{', '}', '!',
                 'time', 'case')},
    'after an argument, next line': 'echo done case y in\n{X}',
    'after an argument, and-list': 'echo done case y in && {X}',
    'after a closing parenthesis': '(true) case y in; {X}',
    'after a redirection': '>/dev/null case y in; {X}',
    'after an assignment': 'A=1 case y in; {X}',
    'after an empty array assignment': 'a=() case y in; {X}',
    'after time following a pipe': 'true | time case y in; {X}',
    'after ! following a pipe': 'true | ! case y in; {X}',
    'after time following a pipe and a line break': 'true |\ntime case y in; {X}',
    'after time (not a keyword in sh or dash)': 'time case y in; {X}',
    'after ! following a pipe and a line break': 'true |\n! case y in; {X}',
    'no word between case and in': 'case ; in; {X}',
    'after a lead word that is itself an argument': 'echo if then case y in; {X}',
    # not the keyword's spelling
    'double-quoted': '"case" y in; {X}',
    'single-quoted': "'case' y in; {X}",
    'backslash in it': 'c\\ase y in; {X}',
    'brace expansion': '{case,} y in; {X}',
    'carriage return after it': 'case\r y in; {X}',
    'form feed before it': '\fcase y in; {X}',
    'vertical tab after in': 'case y in\v; {X}',
    'quoted in': 'case y "in"; {X}',
    'aliased': "alias case='echo'; case y in; {X}",
    'aliased in zsh': "aliases[case]=echo; case y in; {X}",
    'lead word aliased': "alias then='echo'; if true; then case y in; {X}",
    # the name only in the source: the command word is made by a substitution
    'aliased by a substituted command word': "$(echo alias) case='echo'\ncase y in; {X}",
    # a pattern that assigns when it is tried; a later case is no longer provably the keyword
    'a pattern assigns the name': 'case x in ${a:=alias}) true ;; esac\n$a case=echo\ncase y in; {X}',
    # a changer after one case statement still counts for the next one
    'aliased between two cases': "case x in x) true ;; esac\nalias case='echo'\ncase y in; {X}",
}

# a real case statement whose closing word is not the keyword `esac` (the shell reports a syntax error); the pass ends
# pattern mode at any unquoted word whose text is esac, which is stricter, so {X} stays visible
NOT_THE_CLOSER = {
    'brace-expanded esac': 'case a in a) true ;; {esac,}; {X}',
}
# Not a row: 'case a in a) true ;; esac\r; {X}'. `esac\r` is one word to bash, dash and zsh, so the case never
# closes and no shell runs {X} (checked under each); with \r a word character the guards agree.

# PowerShell has no case statement: the word is a command name there, and the command after `;` runs
POWERSHELL = {
    'case statement shape': 'case y in; {X}',
    'case statement shape across lines': 'case y in\n{X}',
}
PS_DELETE = 'Remove-Item -Recurse -Force ~/.claude/projects'

# real case statements: both guards allow them before and after (the pattern words are not commands)
REAL_CASES = {
    'one line': 'case "$1" in a|b) echo ab ;; *) echo other ;; esac',
    'several lines': 'case "$1" in\n  start|stop)\n    echo "$1"\n    ;;\n  *)\n    exit 64\n    ;;\nesac',
    'inside if': 'if true; then case "$1" in -h|--help) echo usage ;; esac; fi',
    'inside a loop': 'for a in "$@"; do case "$a" in -v) v=1 ;; *) break ;; esac; done',
    'after a pipe': 'printf x | case "$1" in a) cat ;; *) cat ;; esac',
    'fall-through terminators': 'case "$1" in a) echo a ;& b) echo b ;;& *) echo c ;; esac',
    'parenthesised patterns': 'case "$1" in (a|b) echo ab ;; (*) echo other ;; esac',
}


def _base_strip_case_patterns(tokens, ps=False):
    """The pass as it was at d56a8cb0, kept verbatim as the reference for the verdict-diff property."""
    out, stack, i, n = [], [], 0, len(tokens)
    while i < n:
        kind, val = tokens[i]
        at_start = not out or out[-1][0] == 'op' or (out[-1][0] == 'w' and not out[-1][1].quoted
                                                       and out[-1][1].text in cg.RESERVED)
        if kind == 'w' and not val.quoted and val.text == 'case' and at_start and i + 2 < n \
                and tokens[i + 2][0] == 'w' and tokens[i + 2][1].text == 'in':
            out.append(tokens[i])
            out.append(tokens[i + 1])
            stack.append('patterns')
            i += 3
            continue
        if stack and stack[-1] == 'patterns':
            if kind == 'w' and not val.quoted and val.text == 'esac':
                stack.pop()
                out.append(tokens[i])
            elif kind == 'op' and val == ')':
                stack[-1] = 'body'
                out.append(('op', ';'))
            elif kind == 'op' and val == '\n':
                out.append(tokens[i])
            i += 1
            continue
        if stack and kind == 'op' and val == ';' and i + 1 < n and tokens[i + 1] == ('op', ';'):
            stack[-1] = 'patterns'
            out.append(('op', ';'))
            i += 2
            continue
        if stack and kind == 'op' and val == ';' and i + 1 < n and tokens[i + 1] in (('op', '&'), ('op', ';;&')):
            stack[-1] = 'patterns'
            out.append(('op', ';'))
            i += 2
            continue
        if stack and kind == 'w' and not val.quoted and val.text == 'esac' and at_start:
            stack.pop()
        out.append(tokens[i])
        i += 1
    return out


class Guards(tkg.WorldCase):
    def setUp(self):
        super().setUp()
        home = tcg.make_fixture(tempfile.mkdtemp(prefix='case-cg-'))
        self.addCleanup(shutil.rmtree, str(home), True)
        self.home = home
        self.compiled = cg.Compiled(cg.load_policy(path=str(home / 'none.json')), home=str(home),
                                    cwd=str(home / 'repo'))
        patch = mock.patch.dict(os.environ, {'HOME': str(home)})
        patch.start()
        self.addCleanup(patch.stop)

    def cg_verdict(self, cmd, ps=False):
        return cg.decide(cmd, self.compiled, cwd=str(self.home / 'repo'), ps=ps)[0]

    def kg_verdict(self, cmd):
        return self.decide(cmd)[0]


class Refused(Guards):
    def test_every_row_that_breaks_one_condition_is_refused_by_both_guards(self):
        wrong = []
        for label, form in list(NOT_THE_KEYWORD.items()) + list(NOT_THE_CLOSER.items()):
            if self.cg_verdict(form.replace('{X}', DELETE)) != 'block':
                wrong.append(('command_guard', label))
            if self.kg_verdict(form.replace('{X}', KILL)) != 'block':
                wrong.append(('kill_guard', label))
        self.assertEqual(wrong, [])

    def test_powershell_text_is_never_read_as_a_case_statement(self):
        wrong = [label for label, form in POWERSHELL.items()
                 if self.cg_verdict(form.replace('{X}', PS_DELETE), ps=True) != 'block']
        self.assertEqual(wrong, [])

    def test_the_twin_command_alone_is_refused_so_the_rows_are_not_vacuous(self):
        self.assertEqual(self.cg_verdict('true; ' + DELETE), 'block')
        self.assertEqual(self.kg_verdict('true; ' + KILL), 'block')
        self.assertEqual(self.kg_verdict('echo ' + KILL), 'allow')  # the kill twin needs a real command
        self.assertEqual(self.cg_verdict('true; ' + PS_DELETE, ps=True), 'block')

    def test_a_command_after_a_real_case_statement_is_still_judged(self):
        for form in ('case y in a) true ;; esac; {X}', 'case y in a) {X} ;; esac', 'case y in a|{X}) true ;; esac\n{X}'):
            self.assertEqual(self.cg_verdict(form.replace('{X}', DELETE)), 'block', form)
            self.assertEqual(self.kg_verdict(form.replace('{X}', KILL)), 'block', form)


class Allowed(Guards):
    def test_real_case_statements_are_allowed_by_both_guards(self):
        wrong = [(label, self.cg_verdict(cmd), self.kg_verdict(cmd)) for label, cmd in REAL_CASES.items()
                 if self.cg_verdict(cmd) != 'allow' or self.kg_verdict(cmd) != 'allow']
        self.assertEqual(wrong, [])

    def test_pattern_words_are_dropped_only_for_the_keyword(self):
        ctx = cg.Ctx(cg.Compiled(cg.load_policy(), cwd='/tmp'), cwd='/tmp')
        heads = lambda text: [c.words[0].text for p in cg.parse(cg.Lexer(ctx).lex(text)) for c in p.cmds  # noqa: E731
                              if c.words]
        self.assertEqual(heads('case x in a|b) echo y ;; esac'), ['case', 'echo', 'esac'])
        self.assertEqual(heads('echo done case x in; b'), ['echo', 'b'])


class Property(Guards):
    """Nothing allowed before is refused except a command whose verdict changes only because a `case` that is not
    the keyword no longer hides the words after it; nothing refused before is allowed."""

    def _both(self, judge, rows):
        new = [judge(r) for r in rows]
        with mock.patch.object(cg, '_strip_case_patterns', _base_strip_case_patterns):
            old = [judge(r) for r in rows]
        return [(r, b, a) for r, b, a in zip(rows, old, new) if a != b]

    def test_no_corpus_row_changes_verdict_in_either_guard(self):
        self.assertEqual(self._both(lambda r: self.decide(r['cmd'], cwd=tkg.CWD)[0], tkg.ROWS), [])
        rows = []
        for name in dir(corpus):
            value = getattr(corpus, name)
            if name.isupper() and isinstance(value, list):
                for row in value:
                    cmd = row if isinstance(row, str) else row.get('cmd') if isinstance(row, dict) else None
                    if isinstance(cmd, str):
                        rows.append((tcg.fill(cmd, self.home), name.endswith('_PS')))
        self.assertGreater(len(rows), 700)  # the whole command_guard corpus, not a sample
        self.assertEqual(self._both(lambda r: self.cg_verdict(r[0], ps=r[1]), rows), [])

    def test_only_rows_that_break_a_condition_change_and_only_toward_refusal(self):
        forms = list(NOT_THE_KEYWORD.values()) + list(NOT_THE_CLOSER.values())
        rows = [f.replace('{X}', DELETE) for f in forms] + list(REAL_CASES.values())
        changed = self._both(self.cg_verdict, rows)
        rows_k = [f.replace('{X}', KILL) for f in forms] + list(REAL_CASES.values())
        changed += self._both(self.kg_verdict, rows_k)
        changed += self._both(lambda r: self.cg_verdict(r, ps=True), [f.replace('{X}', PS_DELETE)
                                                                       for f in POWERSHELL.values()])
        self.assertTrue(all(before == 'allow' and after == 'block' for _r, before, after in changed), changed)
        self.assertTrue(all('case' in r and r not in REAL_CASES.values() for r, _b, _a in changed), changed)
        self.assertGreater(len(changed), 0)  # the old pass hid them: not vacuous


CASE_GLOB = 'case "$1" in a|b) echo ab ;; *) echo other ;; esac'
CASE_SIGNALS = 'case "$s" in TERM|KILL) echo sig ;; *) true ;; esac'
# Item 1 of the lexer repair (goodqa#17059): a real case statement next to a word that only holds a changer's
# spelling. At 2c8b1b34 both guards refused every one of these, because any such word anywhere put the whole text
# under the strict reading, and the strict reading of a real case statement is refused.
CHANGER_AFTER = {
    'enable after the case': '%s; echo enable',
    'the name in a path after the case': '%s; cat ~/.bash_aliases',
    'eval after the case, on the next line': '%s\nmake eval',
}
CHANGER_PATTERNS = {
    'changer words as patterns': 'case "$1" in enable|disable|eval) echo x ;; *) echo y ;; esac',
    'the name as a pattern': 'case "$1" in alias|unalias) echo x ;; *) echo y ;; esac',
}
# The cost that stays: a changer's spelling before the case keeps the strict reading, wherever the word stands,
# because whether an argument can reach an alias (through read, a pipe into a builtin, a file later sourced, a
# variable later run as a command) is not modelled.
CHANGER_BEFORE = {
    'enable before the case, an argument': 'echo enable; %s',
    'enable before the case, a systemctl argument': 'systemctl --user enable x.service; %s',
    'eval before the case, a make target': 'make eval; %s',
    'the name inside a file name, before': 'cat notes/test_aliases.txt; %s',
    'the name in a quoted note, before': "echo 'the alias rule'; %s",
}


class ChangerReach(Guards):
    """A word that may change keywords counts only for the text after it (goodqa#17059, lexer repair item 1)."""

    def rows(self, forms):
        return [('%s [%s]' % (label, name), form % case) for label, form in forms.items()
                for name, case in (('glob', CASE_GLOB), ('signals', CASE_SIGNALS))]

    def verdicts(self, rows):
        return [(label, self.cg_verdict(cmd), self.kg_verdict(cmd)) for label, cmd in rows]

    def test_the_bare_case_statements_are_allowed_so_the_rows_are_not_vacuous(self):
        self.assertEqual(self.verdicts([('glob', CASE_GLOB), ('signals', CASE_SIGNALS)]),
                         [('glob', 'allow', 'allow'), ('signals', 'allow', 'allow')])

    def test_a_changer_after_the_case_or_as_a_plain_pattern_leaves_it_the_keyword(self):
        rows = self.rows(CHANGER_AFTER) + list(CHANGER_PATTERNS.items())
        self.assertEqual([r for r in self.verdicts(rows) if r[1:] != ('allow', 'allow')], [])

    def test_a_changer_before_the_case_keeps_the_strict_reading(self):
        self.assertEqual([r for r in self.verdicts(self.rows(CHANGER_BEFORE)) if r[1:] != ('block', 'block')], [])


@unittest.skipUnless(shutil.which('bash'), 'needs bash')
class ShellOracle(unittest.TestCase):
    """What bash and dash do with these shapes, on forms whose only command is a local `marker`."""

    def run_shell(self, shell, body):
        tmp = tempfile.mkdtemp(prefix='case-oracle-')
        self.addCleanup(shutil.rmtree, tmp, True)
        done = subprocess.run([shell, '-c', 'marker() { echo RAN; }\n' + body], cwd=tmp, capture_output=True,
                              text=True, timeout=10)
        return done.stdout

    def shells(self):
        return [s for s in dict.fromkeys(filter(None, (shutil.which('bash'), shutil.which('dash'))))]

    def test_the_command_after_a_case_that_is_not_the_keyword_runs(self):
        forms = ['echo done case y in; marker', 'echo then case y in\nmarker', 'echo if case y in && marker',
                 'echo esac case y in; marker', '"case" y in; marker', '{case,} y in; marker',
                 'A=1 case y in; marker', '>/dev/null case y in; marker']
        for shell in self.shells():
            for form in forms:
                if shell.endswith('dash') and '{' in form:
                    continue  # dash has no brace expansion: the word is the literal `{case,}`, also not a keyword
                self.assertIn('RAN', self.run_shell(shell, form), (shell, form))

    def test_time_after_a_pipe_is_a_command_in_bash(self):
        self.assertIn('RAN', self.run_shell(shutil.which('bash'), 'true | time case y in; marker'))

    @unittest.skipUnless(shutil.which('dash'), 'needs dash')
    def test_time_is_not_a_keyword_in_dash(self):
        self.assertIn('RAN', self.run_shell(shutil.which('dash'), 'time case y in; marker'))

    def test_a_real_case_statement_runs_its_body_not_its_patterns(self):
        for shell in self.shells():
            self.assertEqual(self.run_shell(shell, 'case a in marker|a) echo body ;; esac').strip(), 'body')
            self.assertIn('RAN', self.run_shell(shell, 'case a in a) true ;; esac; marker'))


if __name__ == '__main__':
    unittest.main()
