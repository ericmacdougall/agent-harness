"""goodqa#17008: every wal_specs option agrees with the program's own documentation.

The fixtures in tests/fixtures/wal_help are the programs' own words: `--help` on t2-dev (GNU coreutils 9.4, findutils
4.9.0, util-linux 2.39.3, procps 4.0.4, bash 5.2.21) and the SYNOPSIS and option lines of the man pages on macOS 26.
A spec option must be documented with the same arity (no value, a required value, an optional attached value), and
every documented option must be in the spec. A wrong arity is the one way the option model fails open (the command
start moves, or a value is read as an operand), so this is its contract. Options a program takes without documenting
them in that text are listed below with the reason. WAL_HELP_LIVE=1 also compares each fixture with the `--help` of
the program on this host, when it is the same implementation."""

import os
from pathlib import Path
import re
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'harness/hooks'))
import wal_specs as ws  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / 'fixtures' / 'wal_help'
NO, REQ, OPT = ws.NO, ws.REQ, ws.OPT

# (program, reading): {option: reason} for options a spec takes that its fixture does not document
UNDOCUMENTED = {
    ('arch', ws.BSD): {o: 'an instance of the -arch_name placeholder' for o in
                       ('-i386', '-x86_64', '-x86_64h', '-arm64', '-arm64e')},
    ('xargs', ws.BSD): {'--null': 'man lists it beside -0', '--max-args': 'man lists it beside -n',
                        '--max-procs': 'man lists it beside -P', '--interactive': 'man lists it beside -p',
                        '--no-run-if-empty': 'man lists it beside -r', '--max-chars': 'man lists it beside -s',
                        '--verbose': 'man lists it beside -t', '--exit': 'man lists it beside -x'},
}
# documented words that are not options of the spec's table: a lone `-` is a spec's `dash` or an operand; `-NUM` is
# a spec's numeric= or digits=
NOT_OPTIONS = {'-', '--', '-arch_name', '-NUM', '--GTYPE-group-format', '--LTYPE-line-format'}
_DIFF_FORMATS = {o: (REQ, "the help's GTYPE/LTYPE placeholder") for o in (
    '--old-group-format', '--new-group-format', '--changed-group-format', '--unchanged-group-format',
    '--old-line-format', '--new-line-format', '--unchanged-line-format')}
# (program, reading): {option: (arity, reason)} where this module's reading of the document is wrong
ARITY_EXCEPTIONS = {
    ('sort', ws.GNU): {'-C': (NO, '`-C, --check=quiet, --check=silent` spells values of --check'),
                       '--check': (OPT, '`--check, --check=diagnose-first`: the value is optional')},
    ('tr', ws.BSD): {'-d': (NO, 'the synopsis word after -d is the operand string1'),
                     '-s': (NO, 'the synopsis word after -s is the operand string1')},
    ('shasum', ws.ANY): {'-a': (REQ, 'the help gives the values (1, 224, ...) in the description'),
                         '--algorithm': (REQ, 'the help gives the values in the description')},
    ('file', ws.ANY): {'-P': (REQ, 'file(1): -P name=value; the help omits the argument'),
                       '--parameter': (REQ, 'file(1): --parameter name=value')},
    ('jq', ws.ANY): {'--slurpfile': (REQ, 'its help line runs `name file` into the description')},
    ('xargs', ws.GNU): {'-e': (OPT, "findutils' getopt string has e:: (as --eof[=END])"),
                        '-i': (OPT, "findutils' getopt string has i:: (as --replace[=R])")},
    ('diff', ws.GNU): _DIFF_FORMATS,
    ('strings', ws.GNU): {'-a': (NO, '`-a - --all`: the lone dash is a third spelling'),
                          '-t': (REQ, '`-t --radix={o,d,x}`: the value list is in lower case'),
                          '-e': (REQ, 'its line runs the value list into the description'),
                          '--encoding': (REQ, 'its line runs the value list into the description'),
                          '-w': (NO, 'its line runs the description into the option'),
                          '--include-all-whitespace': (NO, 'its line runs the description into the option')},
    ('diff', ws.BSD): {'--unified': (OPT, 'diff(1) gives it as the synonym of -u and of -U number'),
                       '--context': (OPT, 'diff(1) gives it as the synonym of -c and of -C number')},
}
# programs with a spec and no fixture, and why
NO_FIXTURE = {
    ('time', ws.GNU): 'GNU time is not installed on t2-dev; the spec follows time(1) of GNU time 1.9',
    ('noglob', ws.ANY): 'a zsh precommand modifier with no options',
    ('unbuffer', ws.ANY): 'expect is not installed on t2-dev or the Mac; unbuffer(1) documents only -p',
    ('gosu', ws.ANY): 'not installed on t2-dev; gosu takes no options before USER',
    ('sshpass', ws.ANY): 'not installed on t2-dev; sshpass(1) 1.09 options -f -d -p -P -e[VAR] -v -h -V',
}

_STRENGTH = {NO: 0, OPT: 1, REQ: 2}


def _merge(table, name, takes):
    table[name] = max(table.get(name, NO), takes, key=_STRENGTH.get)


def _marker(rest):
    """The arity a token's own text gives its option: None (no marker), OPT, REQ, or 'prose' (not an option)."""
    if rest == '':
        return None
    if re.fullmatch(r'\[=[^\]]*\]|\[[^\]=\s]+\]|\s+\[[^\]\s]+\]', rest):
        return OPT    # --follow[=HOW], -l[MAX-LINES], --all-repeated [septype]
    if re.fullmatch(r'=\S+|\s+(<[^>]+>|\S+)(\.\.\.)?|\s+[a-z]+\s+[a-z]+', rest):
        return REQ    # --lines=NUM, -E END, --class <class>, --pid <pid>..., jq's --arg name value
    return 'prose'


def option_lines(text, long_only=False, placeholder=r'[A-Z<]'):
    """{option: arity} from GNU `--help` lines and man-page option lines: the option part of a line is everything
    before two spaces or a tab, as `-n, --lines=NUM`, `-c, --class <class>`, `-l[MAX-LINES]`, `-E END`. Each token's
    own marker wins. A one-letter option without one takes the marker of the token right after it when that is a
    required value (coreutils: mandatory arguments to long options are mandatory for short ones too) or an optional
    one in the util-linux `<x>` style; otherwise it takes none, so BSD sort's `-g, ..., --sort=general-numeric` gives
    -g nothing. A name given both bare and with `=VALUE` (sort's `--check, --check=diagnose-first`) takes an optional
    value. ARITY_EXCEPTIONS corrects the few documents this reads wrongly."""
    table = {}
    for line in text.splitlines():
        line = re.sub(r'^(\s*-\w)\s{2,}(--)', r'\1, \2', line)   # GNU stat: `-c  --format=FORMAT`
        line = re.sub(r'^(\s*-.*?<[^>]+>(?:\.\.\.)?) (?=\S)', r'\1  ', line)   # chrt: `--sched-deadline <ns> deadline`
        m = re.match(r'^[ ]{1,7}(-\S.*?),?(?:[ ]{2,}|\t|$)', line)   # deeper lines are descriptions (rg: 8)
        if not m:
            continue
        group = []
        if re.search(r'\b(and|or|the|options?)\b|(?<!\.)\.$', m.group(1)):
            continue   # prose that starts with a dash (BSD wc: `-c, -l and -w options.`)
        part = re.sub(r'(?<=[^,\s]) (?=--?[A-Za-z])', ', ', m.group(1))   # BSD diff: `-a --text`
        for t in (t.strip() for t in re.split(r',\s+', part)):
            tm = re.match(r'^(--?[A-Za-z0-9][A-Za-z0-9_-]*|-\.|-)(.*)$', t)   # rg: `-., --hidden`
            kind = _marker(tm.group(2)) if tm else 'prose'
            if kind == 'prose':
                group = []   # prose that starts with a dash: not an option line
                break
            group.append((tm.group(1), kind, tm.group(2)))
        own = {}
        for name, kind, rest in group:
            if name in own and {own[name][0], kind} == {None, REQ}:
                own[name] = (OPT, '')   # given bare and with =VALUE
            elif name not in own:
                own[name] = (kind, rest)
        names = list(own)
        for k, name in enumerate(names):
            kind = own[name][0]
            if kind is None:
                nxt_name = names[k + 1] if k + 1 < len(names) else ''
                nxt = own.get(nxt_name, (None, ''))
                inherits = len(name) == 2 and nxt_name.startswith('--') and re.search(placeholder, nxt[1])
                kind = nxt[0] if inherits and (nxt[0] == REQ or (nxt[0] == OPT and '<' in nxt[1])) else NO
            _merge(table, name, kind)
    return table


def synopsis(text, long_only=False):
    """{option: arity} from a synopsis or usage line: `[-0iv]`, `[-u name]`, `[-C[num]]`, `[--color=when]`."""
    table = {}
    lines = [ln for ln in text.splitlines() if re.match(r'^\s*(usage:|Usage:|[a-z]+: [a-z]+ |\s{4,}[a-z]+ \[|\s+\[)', ln)
             or ln.startswith('     ') and '[' in ln and not re.match(r'^\s+-', ln)]
    syn = ' '.join(lines)
    for name, _ in re.findall(r'(?<![\w-])(-\w)\[(\w+)\]', syn):
        _merge(table, name, OPT)
    syn = re.sub(r'(?<![\w-])(-\w)\[(\w+)\]', ' ', syn)
    for name in re.findall(r'(--[\w-]+)\[=\w+\]', syn):
        _merge(table, name, OPT)
    for name in re.findall(r'(--[\w-]+)=\w+', syn):
        _merge(table, name, REQ)
    syn = re.sub(r'--[\w-]+(\[=\w+\]|=\w+)', ' ', syn)
    tokens = re.findall(r'\[|\]|\||\.\.\.|[^\s\[\]|]+', syn)
    depth = 0
    for k, t in enumerate(tokens):
        depth += 1 if t == '[' else -1 if t == ']' else 0
        if not t.startswith('-') or t in ('-', '--'):
            continue
        nxt = tokens[k + 1] if k + 1 < len(tokens) else ']'
        # a value only inside the option's brackets: `[-u name]`, not `rg [OPTIONS] --help` then the next line
        value = depth > 0 and nxt not in ('[', ']', '|', '...') and not nxt.startswith('-')
        if t.startswith('--'):
            _merge(table, t, REQ if value else NO)
        elif long_only or len(t) == 2:
            _merge(table, t, REQ if value else NO)
        else:
            for c in t[1:]:
                _merge(table, '-' + c, NO)
    return table


def documented(text, reading, long_only=False):
    # GNU texts write placeholders in capitals (--lines=NUM) and examples in lower case (-p, --indicator-style=slash)
    table = option_lines(text, long_only, r'[A-Z<]' if reading != ws.BSD else r'\S')
    if reading != ws.GNU:   # GNU --help lists every option on its own line; its usage line only says [OPTION]
        for name, takes in synopsis(text, long_only).items():
            _merge(table, name, takes)
    # a negation the prose names (rg: `This flag can be disabled with --no-heading`, `the --no-pre flag`): a flag, when
    # the option it negates is documented
    for name in set(re.findall(r'(?<![\w-])(--no-[a-z0-9][a-z0-9-]*[a-z0-9])', text)):
        if name not in table and '--' + name[5:] in table:
            _merge(table, name, NO)
    return {n: t for n, t in table.items() if n not in NOT_OPTIONS}


def documented_for(name, reading, long_only=False):
    """The documented arity table of one program's fixture, with ARITY_EXCEPTIONS applied."""
    path = FIXTURES / reading / (name + '.txt')
    doc = documented(path.read_text(encoding='utf-8'), reading, long_only)
    for opt, (takes, _) in ARITY_EXCEPTIONS.get((name, reading), {}).items():
        doc[opt] = takes
    return doc


def spec_table(s):
    return {n: o.takes for n, o in s.opts.items()}


# find: primaries the fixture does not document, or documents with the wrong number of words, and why
FIND_UNDOCUMENTED = {
    ws.GNU: {'-d': 'find(1): a synonym of -depth', '-ipath': 'find(1): deprecated spelling of -iwholename',
             '-samefile': 'find(1)', '-help': 'find(1): same as --help', '-version': 'find(1)',
             '-regextype': 'its --help line omits the TYPE argument'},
    ws.BSD: {'-follow': 'find(1) names it a deprecated primary (the -L option)',
             '-xdev': 'find(1) names it a deprecated primary (the -x option)'},
}
FIND_SKIP = {'-newerXY': 'a placeholder for FIND_NEWER_XY', '-not': 'an operator', '-a': 'an operator',
             '-o': 'an operator', '-and': 'an operator', '-or': 'an operator'}


def find_documented(text, reading):
    """{primary or leading option: number of words it takes} from find's --help (GNU, primaries in paragraphs after
    'Positional options') or man page (BSD, one per line). The -exec family is left out: FIND_RUN models it."""
    table = {}
    if reading == ws.GNU:
        body = text.split('Positional options', 1)[1].split('Other common options', 1)[0]
        for tokens in (ln.split() for ln in body.splitlines() if ln.startswith(' ')):
            _find_line(tokens, table)
        usage = text.split('\n', 1)[0]
        assert '[-Olevel]' in usage   # find_parse reads -O with FIND_GNU_O
        for name, takes in synopsis(usage.replace('[-Olevel]', '')).items():
            table[name] = 1 if takes != NO else 0
    else:
        for name, takes in option_lines(text).items():
            table[name] = 1 if takes != NO else 0
    for run in ws.FIND_RUN:
        table.pop(run, None)
    return {n: a for n, a in table.items() if n not in FIND_SKIP and n not in NOT_OPTIONS}


def _find_line(tokens, table):
    """Primaries on one line of GNU find's --help, each followed by its argument names (FILE, N, [-/]MODE)."""
    primary = re.compile(r'-[a-z][a-z0-9_-]*')
    for k, t in enumerate(tokens):
        if not primary.fullmatch(t):
            continue
        n = 0
        while k + 1 + n < len(tokens) and re.match(r'[A-Z\[]', tokens[k + 1 + n]):
            n += 1
        table[t] = max(table.get(t, 0), n)


def find_table(reading):
    table = dict(ws.FIND_PRIMARIES[reading])
    for name, o in ws.FIND_LEAD[reading].items():
        table[name] = 0 if o.takes == NO else 1
    if reading == ws.BSD:
        table['-depth'] = 1   # `-depth` and `-depth n`: find_parse takes a following number
    return table


class HelpContract(unittest.TestCase):
    def test_every_spec_has_a_fixture_or_a_reason(self):
        for name, specs in ws.SPECS.items():
            for s in specs:
                path = FIXTURES / s.reading / (name + '.txt')
                self.assertTrue(path.exists() or (name, s.reading) in NO_FIXTURE, '%s %s' % (name, s.reading))
                self.assertFalse(path.exists() and (name, s.reading) in NO_FIXTURE, '%s %s' % (name, s.reading))

    def test_every_fixture_has_a_spec(self):
        for path in FIXTURES.glob('*/*.txt'):
            name, reading = path.stem, path.parent.name
            self.assertTrue(name == 'find' or any(s.reading == reading for s in ws.readings(name)), str(path))

    def test_find_primaries_match_the_documentation(self):
        for reading in (ws.GNU, ws.BSD):
            doc = find_documented((FIXTURES / reading / 'find.txt').read_text(encoding='utf-8'), reading)
            have = find_table(reading)
            extra = FIND_UNDOCUMENTED[reading]
            self.assertEqual(sorted(set(doc) - set(have)), [], reading + ': documented primaries find_parse lacks')
            wrong = sorted((n, have[n], doc[n]) for n in doc if have[n] != doc[n] and n not in extra)
            self.assertEqual(wrong, [], reading + ': (primary, words find_parse takes, documented)')
            self.assertEqual(sorted(set(have) - set(doc) - set(extra)), [],
                             reading + ': primaries the documentation does not list')
            self.assertGreater(len(doc), 50, reading)

    def test_spec_options_match_the_documentation(self):
        compared = 0
        for name, specs in sorted(ws.SPECS.items()):
            for s in specs:
                path = FIXTURES / s.reading / (name + '.txt')
                if not path.exists():
                    continue
                doc = documented_for(name, s.reading, s.long_only)
                have = spec_table(s)
                extra = UNDOCUMENTED.get((name, s.reading), {})
                where = '%s (%s)' % (name, s.reading)
                missing = sorted(set(doc) - set(have))
                self.assertEqual(missing, [], where + ': documented options the spec lacks')
                wrong = sorted((n, have[n], doc[n]) for n in doc if have[n] != doc[n])
                self.assertEqual(wrong, [], where + ': (option, spec arity, documented arity)')
                invented = sorted(set(have) - set(doc) - set(extra))
                self.assertEqual(invented, [], where + ': spec options the documentation does not list')
                self.assertEqual(sorted(set(extra) - set(have)), [], where + ': stale UNDOCUMENTED entries')
                compared += len(doc)
        self.assertGreater(compared, 200)

    def test_the_synopsis_parser_reads_each_form(self):
        self.assertEqual(synopsis('usage: grep [-abc] [-A num] [-C[num]] [--color=when] [--context[=num]] [--null]'),
                         {'-a': NO, '-b': NO, '-c': NO, '-A': REQ, '-C': OPT, '--color': REQ, '--context': OPT,
                          '--null': NO})
        self.assertEqual(synopsis('     time [-al] [-h | -p] [-o file] utility [argument ...]'),
                         {'-a': NO, '-l': NO, '-h': NO, '-p': NO, '-o': REQ})

    def test_the_line_parser_reads_value_forms(self):
        got = option_lines('  -n, --lines=[+]NUM   output\n      --block-signal[=SIG]  block\n'
                           ' -c, --class <class>    name\n  -E END   set\n -, -l, --login   make\n'
                           '     -C altwd\n     -s size, --max-chars=size\n     -0      End each\n'
                           '  -i, --ignore-environment  start with an empty environment\n'
                           ' -m, -p, --preserve-environment      do not reset\n')
        self.assertEqual(got, {'-n': REQ, '--lines': REQ, '--block-signal': OPT, '-c': REQ, '--class': REQ,
                               '-E': REQ, '-': NO, '-l': NO, '--login': NO, '-C': REQ, '-s': REQ, '--max-chars': REQ,
                               '-0': NO, '-i': NO, '--ignore-environment': NO, '-m': NO, '-p': NO,
                               '--preserve-environment': NO})
        self.assertEqual(option_lines('  -l[MAX-LINES]   similar\n  -d, --differences[=<permanent>]\n'),
                         {'-l': OPT, '-d': OPT, '--differences': OPT})

    @unittest.skipUnless(os.environ.get('WAL_HELP_LIVE') == '1', 'set WAL_HELP_LIVE=1 to compare with this host')
    def test_fixtures_match_this_host(self):
        reading = ws.GNU if sys.platform.startswith('linux') else ws.BSD
        for path in sorted((FIXTURES / reading).glob('*.txt')):
            name = path.stem
            if reading == ws.GNU:
                done = subprocess.run([name, '--help'], capture_output=True, text=True, env={'LC_ALL': 'C',
                                      'PATH': '/usr/bin:/bin:/usr/sbin:/sbin'})
                live = documented(done.stdout + done.stderr, reading)
            else:
                done = subprocess.run(['man', name], capture_output=True, text=True,
                                      env={'LC_ALL': 'C', 'MANPAGER': 'cat', 'PAGER': 'cat',
                                           'PATH': '/usr/bin:/bin:/usr/sbin:/sbin'})
                live = documented(re.sub(r'.\x08', '', done.stdout), reading)
            self.assertEqual(live, documented(path.read_text(encoding='utf-8'), reading), name)


if __name__ == '__main__':
    unittest.main()
