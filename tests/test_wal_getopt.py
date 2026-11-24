"""goodqa#17008: wal_specs.wal_getopt, the one option model of the session-WAL guard.

Three kinds of test. Generated forms: every option of every spec, written separately, attached, clustered, as
--opt=value, as `--opt value` and as a unique prefix, puts its value where the spec says and leaves a launcher's command
start on the true command. Fail closed: an unknown, ambiguous or valueless option makes the parse unresolved, and an
operand or value without a stated role is a write. Rows: the design's risk-table cases and the find primaries.
Paths are text here; nothing touches the disk."""

import itertools
from pathlib import Path
import string
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'harness/hooks'))
import wal_specs as ws  # noqa: E402

W = '/h/.claude/wals/s/main.jsonl'
# words a launcher needs after its options before the command starts (its positional words)
PRE = {'timeout': ['10s'], 'taskset': ['0x3'], 'gosu': ['bob'], 'chrt': ['5'], 'flock': ['/tmp/l']}
# launchers whose operands are not a command: their command is text, or a shell's arguments
NO_COMMAND = {'watch', 'sg', 'su', 'runuser'}


def every_spec():
    for name, specs in sorted(ws.SPECS.items()):
        for s in specs:
            yield s


def runs_command(s):
    return s.name not in NO_COMMAND and s.layout(frozenset(), PRE.get(s.name, []) + ['cat', W])[-1:] == [ws.COMMAND]


def harmless_flag(s):
    """A short flag of `s` with no mode, to cluster in front of another option."""
    return next((n for n, o in sorted(s.opts.items()) if len(n) == 2 and o.takes == ws.NO and not o.mode), None)


def unique_prefix(s, name):
    """The shortest prefix of long option `name` that selects only it, if shorter than the name."""
    for k in range(3, len(name)):
        p = name[:k]
        if p in s.opts:
            continue
        if [n for n in s.opts if n.startswith(p) and n.startswith('--')] == [name]:
            return p
    return None


def forms(s, name, opt):
    """(label, words, value or None) for every way of writing option `name` with the value V."""
    out = []
    long_ = name.startswith('--') or s.long_only
    if opt.takes == ws.NO:
        out.append(('flag', [name], None))
        if long_ and not s.long_only and unique_prefix(s, name):
            out.append(('prefix', [unique_prefix(s, name)], None))
        return out
    if long_:
        if opt.takes == ws.REQ:
            out.append(('separate', [name, 'V'], 'V'))
        if not s.long_only:
            out.append(('equals', [name + '=V'], 'V'))
            p = unique_prefix(s, name)
            if p:
                out.append(('prefix', [p + '=V'], 'V'))
        return out
    out.append(('attached', [name + 'V'], 'V'))
    f = harmless_flag(s)
    if f and f != name:
        out.append(('cluster', [f + name[1:] + 'V'], 'V'))
    if opt.takes == ws.REQ:
        out.append(('separate', [name, 'V'], 'V'))
        if f and f != name:
            out.append(('cluster-separate', [f + name[1:], 'V'], 'V'))
    return out


class GeneratedForms(unittest.TestCase):
    def test_every_option_in_every_form(self):
        checked = 0
        for s in every_spec():
            for name, opt in sorted(s.opts.items()):
                for label, words, value in forms(s, name, opt):
                    tail = PRE.get(s.name, []) + ['cat', W]
                    p = ws.wal_getopt(s, words + tail)
                    where = '%s %s: %s %s' % (s.name, s.reading, label, ' '.join(words))
                    if opt.role == ws.OPAQUE and value is not None:
                        self.assertIsNotNone(p.unresolved, where)
                        continue
                    self.assertIsNone(p.unresolved, where)
                    if value is not None:
                        got = [i for i in p.items if i.option == name]
                        self.assertEqual(len(got), 1, where)
                        item = got[0]
                        self.assertEqual(item.role, opt.role, where)
                        self.assertEqual(item.text, value, where)
                        self.assertEqual((words + tail)[item.index][item.offset:], value, where)
                    if runs_command(s) and not opt.mode:
                        self.assertEqual(p.command_at, len(words) + len(PRE.get(s.name, [])), where)
                    checked += 1
        self.assertGreater(checked, 300)

    def test_an_optional_value_is_attached_only(self):
        for s in every_spec():
            for name, opt in s.opts.items():
                if opt.takes != ws.OPT:
                    continue
                p = ws.wal_getopt(s, [name] + PRE.get(s.name, []) + ['cat', W])
                where = '%s %s %s' % (s.name, s.reading, name)
                self.assertIsNone(p.unresolved, where)
                self.assertEqual(p.values.get(name), '', where)
                self.assertNotIn('cat', [i.text for i in p.items if i.option == name], where)

    def test_double_dash_ends_the_options(self):
        for s in every_spec():
            if not runs_command(s) or s.long_only:
                continue
            p = ws.wal_getopt(s, ['--'] + PRE.get(s.name, []) + ['-cat', W])
            self.assertIsNone(p.unresolved, s.name)
            self.assertEqual(p.command_at, 1 + len(PRE.get(s.name, [])), s.name)


class FailsClosed(unittest.TestCase):
    def test_an_unknown_short_option(self):
        for s in every_spec():
            if s.long_only:
                continue
            short = {n[1] for n in s.opts if len(n) == 2 and n[0] == '-'}
            c = next(ch for ch in 'QZqzjJkKyY' + string.ascii_letters if ch not in short)
            p = ws.wal_getopt(s, ['-' + c, 'cat', W])
            self.assertIsNotNone(p.unresolved, '%s %s -%s' % (s.name, s.reading, c))
            self.assertIsNone(p.command_at, s.name)

    def test_an_unknown_long_option(self):
        for s in every_spec():
            p = ws.wal_getopt(s, ['--frobnicate-wals', 'cat', W])
            self.assertIsNotNone(p.unresolved, '%s %s' % (s.name, s.reading))
            self.assertIsNotNone(ws.wal_getopt(s, ['--frobnicate-wals=1', 'cat', W]).unresolved, s.name)

    def test_a_value_option_at_the_end(self):
        for s in every_spec():
            for name, opt in s.opts.items():
                if opt.takes == ws.REQ:
                    p = ws.wal_getopt(s, [name])
                    self.assertIsNotNone(p.unresolved, '%s %s %s' % (s.name, s.reading, name))

    def test_a_flag_given_a_value(self):
        for s in every_spec():
            for name, opt in s.opts.items():
                if opt.takes == ws.NO and name.startswith('--'):
                    p = ws.wal_getopt(s, [name + '=x', 'cat', W])
                    self.assertIsNotNone(p.unresolved, '%s %s %s' % (s.name, s.reading, name))

    def test_an_ambiguous_prefix(self):
        p = ws.wal_getopt(ws.readings('env')[0], ['--ignore', 'cat', W])
        self.assertIn('ambiguous', p.unresolved)

    def test_a_prefix_of_options_alike_takes_their_role(self):
        # chrt --sched-runtime, --sched-period and --sched-deadline: getopt may refuse `--sched`, but whichever it
        # takes, the value is an ARG and the command starts after it
        p = ws.wal_getopt(ws.readings('chrt')[0], ['--sched=5', '9', 'tee', W])
        self.assertIsNone(p.unresolved)
        self.assertEqual([(i.role, i.text) for i in p.items], [(ws.ARG, '5'), (ws.ARG, '9')])
        self.assertEqual(p.command_at, 2)

    def test_roles_default_to_write(self):
        self.assertEqual(ws.Opt('-o', ws.REQ).role, ws.WRITE)
        self.assertEqual(ws.Layout().rest, ws.WRITE)
        s = ws.spec('demo', ws.ANY, ws.opts(write='-o', flags='-v'), ws.Layout())
        p = ws.wal_getopt(s, ['-v', 'a', '-o', 'b'], permute=True)
        self.assertEqual([(i.text, i.role) for i in p.items], [('-v', ws.ARG), ('a', ws.WRITE), ('b', ws.WRITE)])

    def test_the_table_rejects_a_bad_entry(self):
        with self.assertRaises(ValueError):
            ws.opts(reed='-x')
        with self.assertRaises(ValueError):
            ws.opts(flags='-x', arg='-x')
        with self.assertRaises(ValueError):
            ws.opts(flags='-x', modes={'-y': 'm'})

    def test_an_opaque_option_is_unresolved(self):
        for name in ('su', 'runuser'):
            for p in ws.parse_all(name, ['-s', '/bin/x', 'root']):
                if p.spec.reading == ws.GNU:
                    self.assertIn('not modelled', p.unresolved)


class Refusal(unittest.TestCase):
    def test_which_roles_refuse_at_which_relation(self):
        rels = ['in', 'possibly-in', 'above', 'possibly-above', None]
        table = {role: [r for r in rels if ws.refuses(role, r)] for role in sorted(ws.ROLES)}
        lands, all4 = ['in', 'possibly-in'], ['in', 'possibly-in', 'above', 'possibly-above']
        self.assertEqual(table, {
            ws.ARG: [], ws.READ: [], ws.TEXT: [], ws.COMMAND: [], ws.SHELL_ARGS: [], ws.CHDIR: [], ws.ENV: [],
            ws.OPAQUE: [], ws.WRITE: lands, ws.WRITE_DIR: lands, ws.ALIAS: lands,
            ws.POPULATE: all4, ws.ALIAS_TREE: all4, ws.ROOT: all4})

    def test_every_role_in_the_table_is_known(self):
        for s in every_spec():
            for o in s.opts.values():
                self.assertIn(o.role, ws.ROLES, s.name)
            for modes in itertools.chain([frozenset()], ({o.mode} for o in s.opts.values() if o.mode)):
                for r in s.layout(frozenset(modes), ['-', 'A=1', '5', 'x', 'y', 'z']):
                    self.assertIn(r, ws.ROLES, s.name)


def parse_rows(row):
    words = row.split()
    return ws.parse_all(words[0], words[1:])


class Rows(unittest.TestCase):
    """The option-model rows of the design's risk table, and the launcher forms of the review findings."""

    def starts(self, row):
        words = row.split()
        return {p.spec.reading: (words[1 + p.command_at] if p.command_at is not None else p.unresolved)
                for p in ws.parse_all(words[0], words[1:])}

    def test_launcher_starts(self):
        self.assertEqual(self.starts('exec -a cat tee -a W'), {ws.ANY: 'tee'})
        self.assertEqual(self.starts('env -vu cat tee -a W'), {ws.GNU: 'tee', ws.BSD: 'tee'})
        self.assertEqual(self.starts('env --ch D tee -a main.jsonl'),
                         {ws.GNU: 'tee', ws.BSD: 'unknown option --ch'})
        self.assertEqual(self.starts('xargs -J cat cp cat W'), {ws.GNU: 'unknown option -J', ws.BSD: 'cp'})
        self.assertEqual(self.starts('env -a cat tee -a W'),
                         {ws.GNU: 'unknown option -a', ws.BSD: 'unknown option -a'})
        self.assertEqual(self.starts('nice -n5 cat W'), {ws.GNU: 'cat', ws.BSD: 'cat'})
        self.assertEqual(self.starts('nice -10 tee -a W'), {ws.GNU: 'tee', ws.BSD: 'tee'})
        self.assertEqual(self.starts('nice --10 tee -a W')[ws.GNU], 'tee')
        self.assertEqual(self.starts('timeout -k 5 10s tee -a W'), {ws.GNU: 'tee'})
        self.assertEqual(self.starts('chrt 5 tee W'), {ws.GNU: 'tee'})
        self.assertEqual(self.starts('chrt -o tee W'), {ws.GNU: 'tee'})
        self.assertEqual(self.starts('taskset -c 0-3 tee W'), {ws.GNU: 'tee'})
        self.assertEqual(self.starts('stdbuf -oL tee W'), {ws.GNU: 'tee', ws.BSD: 'tee'})
        self.assertEqual(self.starts('runuser -u bob -- tee W'), {ws.GNU: 'tee'})
        self.assertEqual(self.starts('xargs -n 1 -P4 tee -a'), {ws.GNU: 'tee', ws.BSD: 'tee'})
        self.assertEqual(self.starts('xargs -I{} cp {} W'), {ws.GNU: 'cp', ws.BSD: 'cp'})
        self.assertEqual(self.starts('arch -arm64 -e A=1 tee W'), {ws.BSD: 'tee'})
        self.assertEqual(self.starts('env - FOO=1 BAR=2 tee W'), {ws.GNU: 'tee', ws.BSD: 'tee'})
        self.assertEqual(self.starts('watch -x tee W'), {ws.GNU: 'tee'})

    def roles(self, row, reading):
        p = next(p for p in parse_rows(row) if p.spec.reading == reading and not p.permuted) \
            if reading == ws.GNU and row.startswith('su') else \
            next(p for p in parse_rows(row) if p.spec.reading == reading)
        return [(i.role, i.text) for i in p.items]

    def test_text_shell_and_path_roles(self):
        self.assertIn((ws.CHDIR, 'D'), self.roles('env -C D tee x', ws.GNU))
        self.assertIn((ws.CHDIR, 'D'), self.roles('env --chdir=D tee x', ws.GNU))
        self.assertEqual(self.roles('env -S tee W', ws.GNU), [(ws.TEXT, 'tee'), (ws.TEXT, 'W')])
        self.assertIn((ws.ENV, 'PAGER=tee'), self.roles('env PAGER=tee git log', ws.BSD))
        self.assertEqual(self.roles('watch -n1 tee W', ws.GNU), [(ws.ARG, '1'), (ws.TEXT, 'tee'), (ws.TEXT, 'W')])
        self.assertEqual(self.roles('sg staff -c tee', ws.GNU), [(ws.ARG, 'staff'), (ws.ARG, '-c'), (ws.TEXT, 'tee')])
        self.assertEqual(self.roles('flock W true', ws.GNU), [(ws.WRITE, 'W')])
        self.assertEqual(self.roles('flock 9', ws.GNU), [(ws.ARG, '9')])
        self.assertEqual(self.roles('flock L -c tee', ws.GNU), [(ws.WRITE, 'L'), (ws.ARG, '-c'), (ws.TEXT, 'tee')])
        self.assertEqual(self.roles('time -o W cat', ws.GNU), [(ws.WRITE, 'W')])
        self.assertEqual(self.roles('time -ao W cat', ws.BSD), [(ws.ARG, '-ao'), (ws.WRITE, 'W')])
        self.assertEqual(self.roles('su - root -c tee', ws.GNU),
                         [(ws.ARG, '-'), (ws.ARG, 'root'), (ws.SHELL_ARGS, '-c'), (ws.SHELL_ARGS, 'tee')])
        self.assertIn((ws.WRITE, 'nohup.out'), self.roles('nohup cat W', ws.BSD))
        self.assertIn((ws.READ, '/tmp/p'), self.roles('sshpass -f /tmp/p ssh h', ws.ANY))
        self.assertIn((ws.READ, 'F'), self.roles('xargs -a F tee', ws.GNU))

    def test_su_is_read_both_ways(self):
        both = [p for p in parse_rows('su root -c tee') if p.spec.reading == ws.GNU]
        self.assertEqual(sorted(p.permuted for p in both), [False, True])
        self.assertIn((ws.TEXT, 'tee'), [(i.role, i.text) for i in both[0].items if both[0].permuted]
                      or [(i.role, i.text) for i in both[1].items])

    def test_xargs_tokens(self):
        token = {r: ws.xargs_token(p) for r, p in ((p.spec.reading, p) for p in parse_rows('xargs -I@ cp @ D'))}
        self.assertEqual(token, {ws.GNU: '@', ws.BSD: '@'})
        gnu = lambda row: next(ws.xargs_token(p) for p in parse_rows(row) if p.spec.reading == ws.GNU)  # noqa: E731
        self.assertEqual(gnu('xargs -i cp {} D'), '{}')
        self.assertEqual(gnu('xargs --replace=% cp % D'), '%')
        self.assertEqual(gnu('xargs --rep cp {} D'), '{}')
        self.assertIsNone(gnu('xargs -n1 cp D'))
        bsd = next(ws.xargs_token(p) for p in parse_rows('xargs -J % cp % D') if p.spec.reading == ws.BSD)
        self.assertEqual(bsd, '%')

    def test_unknown_programs_have_no_reading(self):
        self.assertEqual(ws.parse_all('mytool', ['x']), [])


class Find(unittest.TestCase):
    def parse(self, row, reading):
        return ws.find_parse(row.split()[1:], reading)

    def test_starts_count_at_every_position(self):
        for r in (ws.GNU, ws.BSD):
            self.assertEqual([i.text for i in self.parse('find -name x W -exec cat {} ;', r).starts()], ['W'])
            self.assertEqual([i.text for i in self.parse('find . -type f W2 -print', r).starts()], ['.', 'W2'])
        self.assertEqual([i.text for i in self.parse('find -f W -print', ws.BSD).starts()], ['W'])
        self.assertIsNotNone(self.parse('find -f W -print', ws.GNU).unresolved)

    def test_bodies_end_at_a_semicolon_or_a_braced_plus(self):
        p = self.parse('find W -name x -exec tee -a {} +', ws.GNU)
        self.assertEqual(p.bodies, ((4, 7, '-exec'),))
        p = self.parse('find W -execdir sh -c x+y ; -ok cat {} ;', ws.BSD)
        self.assertEqual(p.bodies, ((2, 5, '-execdir'), (7, 9, '-ok')))
        self.assertIsNotNone(self.parse('find W -exec tee +', ws.GNU).unresolved)   # `+` only after {}
        self.assertIsNotNone(self.parse('find W -exec', ws.BSD).unresolved)

    def test_write_actions_and_delete(self):
        p = self.parse('find . -fprint W -fprintf W2 %p -fls W3 -fprint0 W4', ws.GNU)
        self.assertEqual([(i.role, i.text) for i in p.items if i.option],
                         [(ws.WRITE, 'W'), (ws.WRITE, 'W2'), (ws.ARG, '%p'), (ws.WRITE, 'W3'), (ws.WRITE, 'W4')])
        self.assertIsNotNone(self.parse('find . -fprint W', ws.BSD).unresolved)
        p = self.parse('find W -name x -delete', ws.BSD)
        self.assertTrue(p.deletes)
        self.assertEqual([(i.role, i.text) for i in p.starts()], [(ws.WRITE, 'W')])

    def test_value_roles_and_arity(self):
        p = self.parse('find -L . -newermt 2026-01-01 -newer F -newerma G -samefile H -name x', ws.GNU)
        self.assertEqual([(i.option, i.role, i.text) for i in p.items], [
            ('-L', ws.ARG, '-L'), ('', ws.READ, '.'), ('-newermt', ws.ARG, '2026-01-01'), ('-newer', ws.READ, 'F'),
            ('-newerma', ws.READ, 'G'), ('-samefile', ws.READ, 'H'), ('-name', ws.ARG, 'x')])
        p = self.parse('find . -depth 2 -print', ws.BSD)
        self.assertEqual([i.text for i in p.starts()], ['.'])
        self.assertEqual([i.text for i in self.parse('find -O3 -D exec . -name y', ws.GNU).starts()], ['.'])

    def test_unknown_primaries_and_missing_values(self):
        for r in (ws.GNU, ws.BSD):
            self.assertIn('unknown primary', self.parse('find . -frob', r).unresolved)
            self.assertIn('needs a value', self.parse('find . -name', r).unresolved)


if __name__ == '__main__':
    unittest.main()
