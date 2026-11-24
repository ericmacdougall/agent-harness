"""goodqa#17044: `[[ ... ]]` is one conditional expression, not a command list.

bash and zsh read everything from `[[` to the closing `]]` as one test whose words are operands: `||`, `&&`, `(`, `)`,
`!`, `<`, `>` and line breaks inside it never end a command, and nothing inside runs except a `$( )` substitution. The
parser used to split `[[ a || b ]]` at the `||`, so `b ]]` became a command; with a variable as `b` that is a command
name built at run time, and kill_guard refused a script that kills nothing.

Every command string here is DATA handed to decide(); nothing in this file executes a row. ShellOracle runs only fixed
forms whose operands call a local `marker` function, in a temporary directory, to pin the shell behaviour the parser
models. GUARD_HOOKS_DIR points the suite at another hooks directory to show it failing first.
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
import kill_guard as kg  # noqa: E402
import command_guard_corpus as corpus  # noqa: E402
import test_command_guard as tcg  # noqa: E402
import test_kill_guard as tkg  # noqa: E402

# a script prelude like the one that was refused: a token made with base64 (indirection text in a variable's value)
# and a value computed from it, both referenced inside the tests below
PRE = ('tok="$(head -c 16 /dev/urandom | base64)"; '
       'v="$(printf %s "$tok" | shasum -a 256 | cut -d" " -f1)"; ')

# must be allowed by both guards: every operator below is inside a closed `[[ ]]`
ALLOW = {
    'or with negated regexes (the refused script)':
        PRE + 'if [[ ! "$tok" =~ ^[A-Za-z0-9+/=]{24}$ || ! "$v" =~ ^[0-9a-f]{64}$ ]]; then echo bad >&2; exit 64; fi',
    'and': PRE + 'if [[ -n "$tok" && "$v" == x ]]; then echo ok; fi',
    'spanning lines': PRE + 'if [[ -n "$tok" &&\n      "$v" == x ]]; then\n  echo ok\nfi',
    'line breaks after the opening and before the closing bracket': PRE + 'if [[\n  -n "$v"\n]]; then echo ok; fi',
    'nested groups and negation': PRE + 'if [[ ( -n "$tok" || -n "$v" ) && ! ( "$v" == x ) ]]; then echo ok; fi',
    'regex alternation in a group': PRE + '[[ "$v" =~ ^(ab|cd)$ ]] && echo ok',
    'bare regex alternation': PRE + '[[ "$v" =~ ab|cd ]] && echo ok',
    'regex alternation ending in a variable': PRE + '[[ "$tok" =~ ab|"$v" ]] && echo ok',
    'regex group alternation then a list operator inside': PRE + '[[ "$tok" =~ ^(a|b)$ || "$v" == x ]] && echo ok',
    'string comparisons with < and >': PRE + '[[ "$v" < b || "$v" > a ]] && echo ok',
    'negated test before a list operator': PRE + '! [[ -z "$v" || -z "$tok" ]] || echo empty',
    'after then, inside a function and a loop': PRE + 'f() { while [[ -n "$v" || -n "$tok" ]]; do break; done; }; f',
    'case arms around it': PRE + 'case "$1" in a) [[ -n "$v" || -n "$tok" ]] && shift ;; *) exit 64 ;; esac',
    'closed bracket then a real list operator': PRE + '[[ -n "$v" || -n "$tok" ]] || { echo missing; exit 64; }',
}

STOP = 'pkill -f pytest'  # a broad kill: kill_guard refuses it wherever it runs
DELETE = 'rm -rf ~/.claude/projects'  # a protected-path deletion: command_guard refuses it wherever it runs

# executed twins: the same words where a shell really runs them. Each must stay refused.
TWINS = {
    'after the closing bracket with ||': '[[ -n "$v" ]] || %s',
    'after the closing bracket with &&': '[[ -n "$v" ]] && %s',
    'after the closing bracket with ;': '[[ -n "$v" ]] ; %s',
    'on the next line': '[[ -n x &&\n -n y ]]\n%s',
    'inside a substitution in an operand': '[[ -n "$(%s)" ]]',
    'inside a substitution in a regex operand': '[[ "$v" =~ "$(%s)" ]]',
    'inside a substitution inside a group': '[[ ( -n x || -n "$(%s)" ) ]]',
    'in the second of two tests': '[[ -n x ]] && [[ -n y || -n "$(%s)" ]]',
    'unterminated bracket': '[[ -n x || %s',
    'unterminated bracket over lines': 'if [[ -n x ||\n%s\nfi',
    'a pipe outside a regex': '[[ x == y | %s ]]',
    'a background operator inside': '[[ x == y & %s ]]',
    'an & in a regex': '[[ x =~ a&%s ]]',
    'a semicolon inside': '[[ x == y ; %s ]]',
    'bracket as an argument, not a command': 'echo [[ a || %s ]]',
    'bracket after an assignment': 'X=1 [[ a || %s ]]',
    'quoted bracket is a command name': '"[[" a || %s ]]',
    'quoted closing bracket is an operand': '[[ "$v" == "]]" || -n x ]] && %s',
    'a here-document inside': '[[ x <<EOF\nbody\nEOF\n|| %s ]]',
    'an fd redirection inside': '[[ x 2> y || %s ]]',
    'nested substitution with its own bracket': '[[ -n "$( [[ a ]] || %s )" ]]',
}


class Allowed(tkg.WorldCase):
    def test_closed_conditionals_are_allowed_by_both_guards(self):
        home = Path(tempfile.mkdtemp(prefix='dbl-home-'))
        self.addCleanup(shutil.rmtree, home, True)
        compiled = cg.Compiled(cg.load_policy(path=str(home / 'none.json')), home=str(home), cwd=str(home))
        wrong = []
        for label, cmd in ALLOW.items():
            kv = self.decide(cmd)
            cv = cg.decide(cmd, compiled, cwd=str(home))
            if kv[0] != 'allow' or cv[0] != 'allow':
                wrong.append('%s: kill_guard %s %s, command_guard %s' % (label, kv[0], kv[1], cv[0]))
        self.assertEqual(wrong, [])

    def test_the_conditional_is_one_command_whose_operators_are_words(self):
        ctx = cg.Ctx(cg.Compiled(cg.load_policy(), cwd='/tmp'), cwd='/tmp')
        pipelines = cg.parse(cg.Lexer(ctx).lex('[[ ( a || b ) && ! c < d ]] || e'))
        heads = [[w.text for w in c.words] for p in pipelines for c in p.cmds]
        self.assertEqual(heads, [['[[', '(', 'a', '||', 'b', ')', '&&', '!', 'c', '<', 'd', ']]'], ['e']])


class Refused(tkg.WorldCase):
    def test_every_executed_twin_is_refused_by_kill_guard(self):
        wrong = [label for label, form in TWINS.items() if self.decide(PRE + form % STOP)[0] != 'block']
        self.assertEqual(wrong, [])

    def test_every_executed_twin_is_refused_by_command_guard(self):
        home = tcg.make_fixture(tempfile.mkdtemp(prefix='dbl-cg-'))
        self.addCleanup(shutil.rmtree, str(home), True)
        compiled = cg.Compiled(cg.load_policy(path=str(home / 'none.json')), home=str(home), cwd=str(home / 'repo'))
        with mock.patch.dict(os.environ, {'HOME': str(home)}):
            wrong = [label for label, form in TWINS.items()
                     if cg.decide(PRE + form % DELETE, compiled, cwd=str(home / 'repo'))[0] != 'block']
        self.assertEqual(wrong, [])


class OnlyInsideAClosedConditional(tkg.WorldCase):
    """The property the review checks first: nothing refused before is now allowed unless every word that changed
    verdict sits inside a closed `[[ ]]`. With the fold switched off the parser is the old one, so a command whose
    verdict differs between the two readings must contain `[[`, and must be one of the ALLOW rows."""

    def _both(self, judge, rows):
        on = [judge(r) for r in rows]
        with mock.patch.object(cg, '_fold_conditionals', lambda tokens: tokens):
            off = [judge(r) for r in rows]
        return [(r, a, b) for r, a, b in zip(rows, on, off) if a != b]

    def test_no_corpus_row_changes_verdict(self):
        changed = self._both(lambda r: self.decide(r['cmd'], cwd=tkg.CWD)[0], tkg.ROWS)
        self.assertEqual(changed, [])
        home = tcg.make_fixture(tempfile.mkdtemp(prefix='dbl-cg-'))
        self.addCleanup(shutil.rmtree, str(home), True)
        compiled = cg.Compiled(cg.load_policy(path=str(home / 'none.json')), home=str(home), cwd=str(home / 'repo'))
        rows = []
        for name in dir(corpus):
            value = getattr(corpus, name)
            if name.isupper() and isinstance(value, list):
                for row in value:
                    cmd = row if isinstance(row, str) else row.get('cmd') if isinstance(row, dict) else None
                    if isinstance(cmd, str):
                        rows.append((tcg.fill(cmd, home), name.endswith('_PS')))
        self.assertGreater(len(rows), 700)  # 761 at the time of writing: the whole command_guard corpus, not a sample
        with mock.patch.dict(os.environ, {'HOME': str(home)}):
            changed = self._both(lambda r: cg.decide(r[0], compiled, cwd=str(home / 'repo'), ps=r[1])[0], rows)
        self.assertEqual(changed, [])

    def test_only_the_allowed_rows_change_and_no_twin_does(self):
        rows = list(ALLOW.values()) + [PRE + form % STOP for form in TWINS.values()]
        changed = self._both(lambda c: self.decide(c)[0], rows)
        self.assertTrue(all('[[' in c and c in ALLOW.values() for c, _a, _b in changed), changed)
        self.assertTrue(all(a == 'allow' and b == 'block' for _c, a, b in changed), changed)
        self.assertGreater(len(changed), 0)  # the fold is what allows them: not vacuous


@unittest.skipUnless(shutil.which('bash'), 'needs bash')
class ShellOracle(unittest.TestCase):
    """The shell behaviour the parser models, observed in real shells on forms whose operands are harmless."""

    def run_shell(self, shell, body):
        tmp = tempfile.mkdtemp(prefix='dbl-oracle-')
        self.addCleanup(shutil.rmtree, tmp, True)
        done = subprocess.run([shell, '-c', 'marker() { echo RAN; }; x=ab; ' + body], cwd=tmp, capture_output=True,
                              text=True, timeout=10)
        return done.stdout, os.listdir(tmp)

    def shells(self):
        return [s for s in dict.fromkeys(filter(None, (shutil.which('bash'), shutil.which('zsh'))))]

    def test_operands_never_run_and_comparisons_never_redirect(self):
        forms = ['[[ $x == zz && marker ]] || echo F', '[[ $x == ab || marker ]] && echo T',
                 '[[ ( $x == zz ) || ! ( marker ) ]] && echo T', '[[ $x > made && $x < read ]] || echo F',
                 '[[ $x == ab &&\n marker ]] && echo T']
        for shell in self.shells():
            for form in forms:
                out, files = self.run_shell(shell, form)
                self.assertNotIn('RAN', out, (shell, form))
                self.assertEqual(files, [], (shell, form))

    def test_substitutions_inside_run_and_list_operators_outside_run(self):
        for shell in self.shells():
            self.assertIn('RAN', self.run_shell(shell, '[[ -n "$(marker)" ]] && echo "$(marker)"')[0])
            self.assertIn('RAN', self.run_shell(shell, '[[ $x == zz ]] || marker')[0])


if __name__ == '__main__':
    unittest.main()
