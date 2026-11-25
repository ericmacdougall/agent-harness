"""goodqa#17060: a command substitution is recorded wherever the shell can run one.

The lexer records the inner script of `$(..)`, backticks and `<(..)` in `Word.subs`, and both guards judge each one as
a command. It skipped the body of a `${...}` expansion and of an arithmetic expansion `$((...))` without looking
inside, so a substitution there was never judged, although bash, zsh and dash run it. Three more shapes of the same
class are pinned here: a `$((cmd) )` read as arithmetic, a substitution ended early at a `}` or a case pattern's `)`
that belongs to something nested inside it (EARLY_END), and a substitution in a case pattern, which the case pass
dropped (CASE_PATTERN).

The rows are generated from a table: every substitution form, in every expansion context, inside every quoting
wrapper, judged by both guards with a command each guard refuses on its own. Recording is deliberately
over-approximate: a substitution the shell would not run (single quotes inside an unquoted `${x:-'..'}`) is still
recorded, which can only make a guard stricter.

Every command string here is DATA handed to decide(); nothing in this file executes a row. ShellOracle runs only fixed
forms whose substitution calls a local `marker` function, to pin which contexts the shells really run.
GUARD_HOOKS_DIR points the suite at another hooks directory to show it failing first.
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
KILL = 'kill -9 -1'  # kill_guard refuses it as a real command

# how the substitution is written; {X} is the command
FORMS = {
    'dollar-paren': '$({X})',
    'backtick': '`{X}`',
    'nested': '$(echo $({X}))',
}

# where the substitution sits; {S} is the substitution. shells: the shells whose oracle row must run it.
POSIX, BASH = ('bash', 'dash'), ('bash',)
CONTEXTS = {
    'default': ('${x:-{S}}', POSIX),
    'default if unset': ('${x-{S}}', POSIX),
    'assign default': ('${x:={S}}', POSIX),
    'alternative': ('${y:+{S}}', POSIX),
    'alternative if set': ('${y+{S}}', POSIX),
    'strip shortest prefix': ('${y#{S}}', POSIX),
    'strip longest prefix': ('${y##{S}}', POSIX),
    'strip shortest suffix': ('${y%{S}}', POSIX),
    'strip longest suffix': ('${y%%{S}}', POSIX),
    'replace with': ('${y/a/{S}}', BASH),
    'replace all with': ('${y//a/{S}}', BASH),
    'replace pattern': ('${y/{S}/b}', BASH),
    'substring offset': ('${y:{S}:1}', BASH),
    'substring length': ('${y:0:{S}}', BASH),
    'array subscript': ('${a[{S}]}', BASH),
    'length of a subscript': ('${#a[{S}]}', BASH),
    'nested expansion': ('${x:-${z:-{S}}}', POSIX),
    'arithmetic': ('$(( {S} ))', POSIX),
    'arithmetic operand': ('$(( 1 + {S} ))', POSIX),
    'arithmetic subscript': ('$(( a[{S}] ))', BASH),
    'old arithmetic': ('$[ {S} ]', BASH),
    'arithmetic in a default': ('${x:-$(( {S} ))}', POSIX),
    'default in arithmetic': ('$(( ${x:-{S}} ))', POSIX),
}

# how the expansion is used: {E} is the expansion. shells: where the wrapper exists at all
WRAPPERS = {
    'unquoted argument': ('echo {E}', POSIX),
    'double-quoted argument': ('echo "{E}"', POSIX),
    'inner double quotes': None,  # built from the context, see rows()
    'assignment': ('v={E}', POSIX),
    'here-string': ('cat <<< {E}', BASH),
    'here-document': ('cat <<EOF\n{E}\nEOF', POSIX),
}


def _inner_quoted(context):
    """The same context with the substitution in double quotes inside the expansion: `"${x:-"$(..)"}"`."""
    return '"%s"' % context.replace('{S}', '"{S}"')


def rows(command):
    """(label, text) for every form x context x wrapper, with {X} = command."""
    out = []
    for fname, form in FORMS.items():
        sub = form.replace('{X}', command)
        for cname, (context, _shells) in CONTEXTS.items():
            for wname, wrap in WRAPPERS.items():
                if wrap is None:
                    if not context.startswith('${'):
                        continue
                    text = 'echo ' + _inner_quoted(context).replace('{S}', sub)
                else:
                    text = wrap[0].replace('{E}', context.replace('{S}', sub))
                out.append(('%s / %s / %s' % (fname, cname, wname), text))
    return out


# substitution forms the shell does not run; recorded anyway (over-approximation), so both guards refuse them
NOT_RUN_BUT_REFUSED = {
    'single quotes inside an unquoted default': "echo ${x:-'$({X})'}",
}

# a substitution that the old scan ended too early, at a closer that belongs to something inside it; {X} then sat in
# text the lexer read as a quoted or literal word, while the shell runs it inside the substitution
EARLY_END = {
    'brace inside a substitution in a quoted default': 'echo "${x:-$(true }; {X})}"',
    'brace inside a substitution in a default': 'echo ${x:-$(true }; {X})}',
    'case pattern inside a quoted substitution': 'echo "$(case a in a) {X};; esac)"',
    'case pattern inside a substitution': 'echo $(case a in a) {X};; esac)',
    'case pattern after a fall-through inside a substitution': 'echo "$(case a in b) true;& a) {X};; esac)"',
    'case pattern inside a process substitution': 'cat <(case a in a) {X};; esac)',
    'parenthesis inside a default inside a substitution': 'echo "$(echo ${x:-)}; {X})"',
    'substitution inside a quoted word inside a substitution': 'echo "$(echo "$(echo ")")"; {X})"',
}

# a case pattern is expanded when the shell tries it, so its substitutions run; the case pass used to drop them
CASE_PATTERN = {
    'substitution as a pattern': 'case y in $({X})) true ;; esac',
    'backtick in a pattern list': 'case y in a|`{X}`) true ;; esac',
    'quoted substitution as a pattern': 'case y in "$({X})") true ;; esac',
    'substitution in a later pattern': 'case y in a) true ;; $({X})) true ;; esac',
}

# a `$((` that is not arithmetic: bash reads `$((cmd) )` as a command substitution holding a subshell
ARITH_THAT_IS_A_SUBSHELL = {
    'subshell in a substitution': 'echo $(({X}) )',
    'subshell in a quoted substitution': 'echo "$(({X}) )"',
}


class Guards(tkg.WorldCase):
    def setUp(self):
        super().setUp()
        home = tcg.make_fixture(tempfile.mkdtemp(prefix='subctx-cg-'))
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

    def both(self, forms):
        """[(guard, label)] for every row either guard does not refuse."""
        wrong = []
        for label, form in forms:
            if self.cg_verdict(form.replace('{X}', DELETE)) != 'block':
                wrong.append(('command_guard', label))
            if self.kg_verdict(form.replace('{X}', KILL)) != 'block':
                wrong.append(('kill_guard', label))
        return wrong


class Refused(Guards):
    def test_every_substitution_in_every_context_is_refused_by_both_guards(self):
        generated = rows('{X}')
        self.assertEqual(len(generated), 399)  # the whole table: 3 forms x (23 contexts x 5 wrappers + 18 inner-quoted)
        self.assertEqual(self.both(generated), [])

    def test_a_substitution_is_not_ended_by_a_closer_inside_it(self):
        self.assertEqual(self.both(EARLY_END.items()), [])

    def test_a_substitution_in_a_case_pattern_is_refused(self):
        self.assertEqual(self.both(CASE_PATTERN.items()), [])

    def test_an_arithmetic_opening_that_is_a_subshell_is_refused(self):
        self.assertEqual(self.both(ARITH_THAT_IS_A_SUBSHELL.items()), [])

    def test_a_substitution_the_shell_would_not_run_is_still_refused(self):
        self.assertEqual(self.both(NOT_RUN_BUT_REFUSED.items()), [])

    def test_the_twins_alone_are_refused_so_the_rows_are_not_vacuous(self):
        self.assertEqual(self.cg_verdict('echo $(%s)' % DELETE), 'block')
        self.assertEqual(self.kg_verdict('echo $(%s)' % KILL), 'block')
        self.assertEqual(self.kg_verdict('echo ' + KILL), 'allow')  # the kill twin needs a real command


class Allowed(Guards):
    """Harmless substitutions in the same contexts stay allowed: recording them must not refuse ordinary text."""

    def test_harmless_substitutions_in_every_context_are_allowed(self):
        wrong = []
        for label, text in rows('date'):
            if self.cg_verdict(text) != 'allow':
                wrong.append(('command_guard', label))
            if self.kg_verdict(text) != 'allow':
                wrong.append(('kill_guard', label))
        self.assertEqual(wrong, [])

    def test_plain_arithmetic_and_expansions_are_allowed(self):
        for text in ('echo $(( 1 + 2 ))', 'echo ${x:-default}', 'echo "${y/a/b}"', 'echo $(( (1 + 2) * 3 ))',
                     'echo ${#x}', 'echo $((x))'):
            self.assertEqual(self.cg_verdict(text), 'allow', text)
            self.assertEqual(self.kg_verdict(text), 'allow', text)


class Recorded(unittest.TestCase):
    """The lexer itself: the inner script reaches Word.subs."""

    def subs(self, text):
        ctx = cg.Ctx(cg.Compiled(cg.load_policy(), cwd='/tmp'), cwd='/tmp')
        return [s for k, v in cg.Lexer(ctx).lex(text) if k == 'w' for s in v.subs]

    def test_inner_scripts_are_recorded(self):
        self.assertEqual(self.subs('echo ${x:-$(date)}'), ['date'])
        self.assertEqual(self.subs('echo $(( $(date) ))'), ['date'])
        self.assertEqual(self.subs('echo "${y/a/`date`}"'), ['date'])
        self.assertEqual(self.subs('echo $((date) )'), ['(date) '])
        self.assertEqual(self.subs('echo $(( 1 + 2 ))'), [])

    def test_the_scan_ends_a_substitution_where_the_shell_does(self):
        """scan_balanced from just after `$(` or `${`: each text below is one whole substitution, so the scan must
        end at its last character (bash 5 and dash agree; see ShellOracle)."""
        for text, (open_ch, close_ch) in (
                ('$(echo "$(echo ")")"; b)', '()'),
                ('$(case a in a) b;; esac)', '()'),
                ('$(case a in (a) b;; esac)', '()'),
                ('$(case a in b) c;& a) d;; esac)', '()'),
                ('$(echo ${x:-)}; b)', '()'),
                ('${x:-$(a }; b)}', '{}'),
                ('${x:-"$(a }; b)"}', '{}'),
                ('$(( (1 + 2) * 3 ))', '()')):
            self.assertEqual(cg.scan_balanced(text, 2, open_ch, close_ch), len(text), text)


@unittest.skipUnless(shutil.which('bash'), 'needs bash')
class ShellOracle(unittest.TestCase):
    """What the shells do with each context, on forms whose substitution calls a local `marker` that writes to
    stderr."""

    def run_shell(self, shell, body):
        tmp = tempfile.mkdtemp(prefix='subctx-oracle-')
        self.addCleanup(shutil.rmtree, tmp, True)
        prelude = 'marker() { echo RAN >&2; }\ny=ab\na=1\n'
        done = subprocess.run([shell, '-c', prelude + body], cwd=tmp, capture_output=True, text=True, timeout=10)
        return done.stderr

    def test_each_context_runs_its_substitution(self):
        missed = []
        for cname, (context, shells) in CONTEXTS.items():
            for shell in shells:
                path = shutil.which(shell)
                if not path:
                    continue
                for wname, wrap in WRAPPERS.items():
                    if wrap is None or shell not in wrap[1]:
                        continue
                    text = wrap[0].replace('{E}', context.replace('{S}', '$(marker)'))
                    if 'RAN' not in self.run_shell(path, text):
                        missed.append((shell, cname, wname))
        self.assertEqual(missed, [])

    def test_the_command_after_an_inner_closer_runs(self):
        """At least one current shell runs {X} in each row. bash before 4 misreads a case statement inside `$(..)`
        (a known parser bug), so bash counts only from version 4; dash has no `;&` and no process substitution."""
        major = self.run_shell(shutil.which('bash'), 'echo "${BASH_VERSINFO[0]}" >&2').strip()
        bash4 = major.isdigit() and int(major) >= 4
        shells = [s for s in (shutil.which('bash') if bash4 else None, shutil.which('dash')) if s]
        missed = []
        for label, form in EARLY_END.items():
            text = form.replace('{X}', 'marker')
            usable = [s for s in shells if not (s.endswith('dash') and ('fall-through' in label or 'process' in label))]
            if not usable:
                continue  # no shell here can read this row; the dev host's bash 5 covers it
            if not any('RAN' in self.run_shell(s, text) for s in usable):
                missed.append(label)
        self.assertEqual(missed, [])

    def test_a_case_pattern_runs_its_substitution(self):
        missed = []
        for label, form in CASE_PATTERN.items():
            text = form.replace('{X}', 'marker')
            for shell in filter(None, (shutil.which('bash'), shutil.which('dash'))):
                if 'RAN' not in self.run_shell(shell, text):
                    missed.append((shell, label))
        self.assertEqual(missed, [])

    def test_an_arithmetic_opening_that_is_a_subshell_runs_it(self):
        self.assertIn('RAN', self.run_shell(shutil.which('bash'), 'echo $((marker) )'))

    def test_single_quotes_inside_an_unquoted_default_do_not_run_it(self):
        self.assertNotIn('RAN', self.run_shell(shutil.which('bash'), "echo ${x:-'$(marker)'}"))


def _base_scan_balanced(s, i, open_ch='(', close_ch=')'):
    """`scan_balanced` as it was at d56a8cb0, kept verbatim as the reference for the verdict-diff property."""
    depth, n = 1, len(s)
    while i < n:
        c = s[i]
        if c == '\\':
            i += 2
            continue
        if c == "'":
            j = s.find("'", i + 1)
            i = n if j < 0 else j + 1
            continue
        if c == '"':
            i += 1
            while i < n and s[i] != '"':
                i += 2 if s[i] == '\\' else 1
            i += 1
            continue
        if c == '`':
            j = i + 1
            while j < n and s[j] != '`':
                j += 2 if s[j] == '\\' else 1
            i = j + 1
            continue
        if c == open_ch:
            depth += 1
        elif c == close_ch:
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return n + 1


def _base_arith_end(s, i):
    """`_arith_end` as it was at d56a8cb0: every `$((` was arithmetic."""
    return _base_scan_balanced(s, i + 3) + 1


class Property(Guards):
    """Nothing refused before is allowed, and nothing allowed before is refused except text holding a substitution in
    a `${...}` or arithmetic body (or a `$((cmd) )`). The old lexer is the new one with both changes undone: no inner
    substitutions recorded, and every `$((` read as arithmetic."""

    def _both(self, judge, rows):
        new = [judge(r) for r in rows]
        with mock.patch.object(cg.Lexer, '_record_inner_subs', lambda self, text, w: None), \
                mock.patch.object(cg.Lexer, '_arith_end', staticmethod(_base_arith_end)), \
                mock.patch.object(cg, 'scan_balanced', _base_scan_balanced), \
                mock.patch.object(cg, '_keep_dropped_substitutions', lambda tokens, stripped: stripped):
            old = [judge(r) for r in rows]
        return [(r, b, a) for r, b, a in zip(rows, old, new) if a != b]

    def test_no_corpus_row_changes_verdict_in_either_guard(self):
        self.assertEqual(self._both(lambda r: self.decide(r['cmd'], cwd=tkg.CWD)[0], tkg.ROWS), [])
        rows_cg = []
        for name in dir(corpus):
            value = getattr(corpus, name)
            if name.isupper() and isinstance(value, list):
                for row in value:
                    cmd = row if isinstance(row, str) else row.get('cmd') if isinstance(row, dict) else None
                    if isinstance(cmd, str):
                        rows_cg.append((tcg.fill(cmd, self.home), name.endswith('_PS')))
        self.assertGreater(len(rows_cg), 700)  # the whole command_guard corpus, not a sample
        self.assertEqual(self._both(lambda r: self.cg_verdict(r[0], ps=r[1]), rows_cg), [])

    def test_only_rows_with_a_hidden_substitution_change_and_only_toward_refusal(self):
        extra = list(ARITH_THAT_IS_A_SUBSHELL.items()) + list(NOT_RUN_BUT_REFUSED.items()) + list(EARLY_END.items()) \
            + list(CASE_PATTERN.items())
        table = rows('{X}') + extra
        changed = self._both(self.cg_verdict, [t.replace('{X}', DELETE) for _l, t in table])
        changed += self._both(self.kg_verdict, [t.replace('{X}', KILL) for _l, t in table])
        harmless = [t for _l, t in rows('date')]
        changed += self._both(self.cg_verdict, harmless) + self._both(self.kg_verdict, harmless)
        # a here-document naming the deletion was a warning before (its text, not a command); now a refusal
        self.assertTrue(all(before in ('allow', 'warn') and after == 'block' for _r, before, after in changed),
                        [c for c in changed if c[1] not in ('allow', 'warn') or c[2] != 'block'])
        self.assertTrue(all('date' not in r for r, _b, _a in changed), changed)  # harmless rows never change
        self.assertGreater(len(changed), 0)  # the old lexer hid them: not vacuous


if __name__ == '__main__':
    unittest.main()
