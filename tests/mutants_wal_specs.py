"""goodqa#17008 controls for the WAL rule's option model: each controlled break of harness/hooks/wal_specs.py must make
tests.test_wal_getopt (the parser, the roles and the design rows) or tests.test_wal_help_contract (the arity contract)
fail.

Run: python3 -B tests/mutants_wal_specs.py   (temporary trees only; see tests/mutant_runner.py for the control rule).
There is no base run: wal_specs.py is new in this branch. The role-flip mutants over every non-grant role, killed by
hand-written WRITES rows of tests/test_wal_choke_point.py, come with the command_guard wiring (C5)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import mutant_runner  # noqa: E402

# (old, new) replacements in wal_specs.py, killed by tests.test_wal_getopt
PARSER = {
    'a value option is read as a flag (xargs -n)': [
        ("'-x --exit --show-limits ' + _HELP,", "'-x --exit --show-limits -n --max-args ' + _HELP,"),
        ('-L --max-lines -n --max-args -P --max-procs', '-L --max-lines -P --max-procs')],
    'long options take no prefixes': [('    long_prefix: bool = True ', '    long_prefix: bool = False ')],
    'an attached value is ignored': [('            if j + 1 < len(t):\n                take(opt, k, j + 1, t[j + 1:])',
                                      '            if False:\n                take(opt, k, j + 1, t[j + 1:])')],
    'nice -NUM is an operand': [("opts(arg='-n --adjustment', flags=_HELP), _RUN, numeric=ARG",
                                 "opts(arg='-n --adjustment', flags=_HELP), _RUN, numeric=None")],
    '-- does not end the options': [("        if t == '--' and not spec.long_only:", '        if False:')],
    'an unknown short option is skipped': [("                unresolved = 'unknown option -%s' % c\n                break",
                                            '                j += 1\n                continue')],
    'an ambiguous prefix is taken': [('    if len(kinds) > 1:', '    if False:')],
    'a missing value is not noticed': [("                    unresolved = 'option %s needs a value' % opt.name\n",
                                        '')],
    'a long flag accepts a value': [("                if eq:\n                    unresolved = 'option %s takes no value'",
                                     "                if False:\n                    unresolved = 'option %s takes no value'")],
    'operands default to read': [('    rest: str = WRITE', '    rest: str = READ')],
    'a populate write is judged only inside the tree': [('    POPULATE: _LANDS | _REACHES,', '    POPULATE: _LANDS,')],
    'env -C is not a directory change': [("arg='-u --unset', chdir='-C --chdir'", "arg='-u --unset -C --chdir'")],
    'watch -x still runs text': [("modes={'-x': 'exec', '--exec': 'exec'}),", 'modes={}),')],
    'an opaque option is modelled': [('        if any(i.role == OPAQUE for i in items):', '        if False:')],
    'BSD xargs has no -J': [("arg='-E -I -J -L -n", "arg='-E -I -L -n"),
                            ("modes={'-I': 'replace', '-J': 'replace-j'}),", "modes={'-I': 'replace'}),")],
    'su is read one way': [("fixed(_SU_SHELL), dash=ARG, permute=True,", "fixed(_SU_SHELL), dash=ARG, permute=False,")],
    'the POSIXLY_CORRECT reading is dropped': [('        if s.permute:\n            out.append(',
                                                '        if False:\n            out.append(')],
    'nohup.out is not written': [("    spec('nohup', BSD, opts(), _RUN, implicit=(('nohup.out', WRITE),)),",
                                  "    spec('nohup', BSD, opts(), _RUN),")],
    'the lock file is not a write': [('    roles = [WRITE]   # the lock file', '    roles = [ARG]   # the lock file')],
    'xargs -i has no default token': [("return parse.values[name] or '{}'", 'return parse.values[name] or None')],
    'a start after the first primary is not a start': [
        ("            items.append(Item(k, 0, READ, '', t))   # a start, at any position",
         "            items.append(Item(k, 0, READ, '' if not items else '-x', t))")],
    'BSD find -f is not a start': [("option='' if i.option == '-f' else i.option", 'option=i.option')],
    'a plus without braces ends a body': [("(texts[j] == '+' and texts[j - 1] == '{}')", "texts[j] == '+'")],
    '-fprint is not a write': [("FIND_WRITES = {'-fprint': WRITE,", "FIND_WRITES = {'-fprint': ARG,")],
    '-delete leaves the starts read': [
        ("        items = [i._replace(role=WRITE) if i.option == '' else i for i in items]", '        pass')],
}

# (old, new) replacements in wal_specs.py, killed by tests.test_wal_help_contract
ARITY = {
    'GNU xargs -P is a flag': [("'-x --exit --show-limits ' + _HELP,", "'-x --exit --show-limits -P --max-procs ' + _HELP,"),
                               ('-n --max-args -P --max-procs -s', '-n --max-args -s')],
    'GNU env gains an invented option': [("spec('env', GNU, opts(flags='-i ", "spec('env', GNU, opts(flags='-Z -i ")],
    'GNU timeout loses -k': [("arg='-k --kill-after -s --signal'),", "arg='-s --signal'),")],
    'watch -d requires its value': [("arg='-q --equexit -n --interval', opt_arg='-d --differences',",
                                     "arg='-q --equexit -n --interval -d --differences',")],
    'BSD stdbuf -o is a flag': [("spec('stdbuf', BSD, opts(arg='-i -o -e'), _RUN),",
                                 "spec('stdbuf', BSD, opts(arg='-i -e', flags='-o'), _RUN),")],
    'find -fprintf takes one word': [("**{'-fprintf': 2,", "**{'-fprintf': 1,")],
    'find -maxdepth takes no word': [("_FIND_COMMON0 = ('-delete -depth", "_FIND_COMMON0 = ('-maxdepth -delete -depth"),
                                     ('-lname -maxdepth -mindepth', '-lname -mindepth')],
}


if __name__ == '__main__':
    a = mutant_runner.run('tests.test_wal_getopt', 'wal_specs.py', PARSER)
    b = mutant_runner.run('tests.test_wal_help_contract', 'wal_specs.py', ARITY)
    sys.exit(1 if a or b else 0)
