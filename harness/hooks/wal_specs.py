"""goodqa#17008: the option model of the session-WAL guard, as one table of program specs and one parser.

command_guard's WAL rule asks this module what each word of a dispatched program does to the path it names, and
judges every answer with wal_paths.relation. The module is pure and stdlib-only; it never touches the disk.

Roles. ARG and READ are the only grants. A value option or an operand whose spec gives it no role is a WRITE, and an
option a spec does not list makes the parse unresolved, so a missing entry fails closed. Only a wrong entry fails open
(a value option recorded as a flag, or a write, alias, text or command role recorded as a grant); the --help contract
test and the role-flip mutants (tests/mutants_wal_specs.py) exist for those.

Readings. A program may have a GNU and a BSD reading, and a reading that permutes its options also gets a second
reading that stops at the first operand (POSIXLY_CORRECT). command_guard takes the union of the writes of every
reading, and treats the program as unresolved when any reading is.
"""
import re
from typing import Callable, Dict, FrozenSet, List, NamedTuple, Optional, Tuple

# ---- roles ----------------------------------------------------------------------------------------------------------
ARG = 'arg'                # a value that names no file: a number, name, pattern, format, signal
READ = 'read'              # a file the program only reads
WRITE = 'write'            # a file it creates, appends to, replaces or removes
WRITE_DIR = 'write-dir'    # a directory it writes new entries into (cp -t DIR, sort -T DIR)
POPULATE = 'populate'      # a directory it fills recursively (cp -r SRC DEST, tar -x -C DIR)
ALIAS = 'alias'            # a file it gives a second name (ln SRC, cp -l SRC)
ALIAS_TREE = 'alias-tree'  # a directory whose files it gives second names (cp -al SRC, rsync --link-dest=SRC)
TEXT = 'text'              # run as shell text (sh -c, watch, env -S, su -c); the text items of a parse join in order
COMMAND = 'command'        # the first word of the command a launcher runs; the words after it are that command's
SHELL_ARGS = 'shell-args'  # the arguments of a shell the program starts (su USER ARGS)
CHDIR = 'chdir'            # the working directory of the command the program runs (env -C DIR)
ROOT = 'root'              # the root directory of the command it runs (chroot DIR)
ENV = 'env'                # a NAME=VALUE assignment for the command it runs; command_guard's environment rule judges it
OPAQUE = 'opaque'          # an option the guard does not model past its name (su -s SHELL): the parse is unresolved

GRANTS: FrozenSet[str] = frozenset({ARG, READ})
PATH_ROLES = frozenset({WRITE, WRITE_DIR, POPULATE, ALIAS, ALIAS_TREE, ROOT})
RUN_ROLES = frozenset({TEXT, COMMAND, SHELL_ARGS})
ROLES = GRANTS | PATH_ROLES | RUN_ROLES | {CHDIR, ENV, OPAQUE}

# the relations (wal_paths.relation) at which a path role refuses; CHDIR, ENV and the run roles are not refused by a
# relation: command_guard applies the directory, judges the assignment and dispatches the command or text
_LANDS = frozenset({'in', 'possibly-in'})
_REACHES = frozenset({'above', 'possibly-above'})
REFUSE_AT: Dict[str, FrozenSet[str]] = {
    WRITE: _LANDS, WRITE_DIR: _LANDS, ALIAS: _LANDS,
    POPULATE: _LANDS | _REACHES, ALIAS_TREE: _LANDS | _REACHES, ROOT: _LANDS | _REACHES,
}


def refuses(role: str, relation: Optional[str]) -> bool:
    """True when a word of `role` whose path has `relation` to a protected root may write there."""
    return relation in REFUSE_AT.get(role, frozenset())


# ---- specs ----------------------------------------------------------------------------------------------------------
GNU, BSD, ANY = 'gnu', 'bsd', 'any'
NO, REQ, OPT = 'no', 'req', 'opt'   # an option takes no value, a required one, or an optional attached one


class Opt(NamedTuple):
    name: str           # '-n', '--lines', or '-arch' in a long_only spec
    takes: str = NO
    role: str = WRITE   # the role of its value (a flag's is ARG)
    mode: str = ''      # a mode it switches on, which the spec's layout reads (cp -r: 'recursive')


class Layout(NamedTuple):
    """How a spec's operands get their roles. `pre` are positional words before the rest (timeout DURATION); a
    (role, pattern) entry is optional and taken only when the word fully matches the pattern (chrt's priority).
    `rest` is the role of each remaining operand; COMMAND makes the first remaining word the launched command, and the
    words after it are not parsed here. `last` is the role of the last operand when there are at least `last_min`.
    Operands default to WRITE: a reader states READ."""
    pre: Tuple = ()
    rest: str = WRITE
    last: Optional[str] = None
    last_min: int = 2


class Spec(NamedTuple):
    name: str
    reading: str
    opts: Dict[str, Opt]
    layout: Callable            # (modes, operand texts) -> list of roles, see Layout and roles_for
    permute: bool = False       # GNU getopt: options may follow operands
    long_prefix: bool = True    # getopt_long: a unique prefix of a long option selects it
    long_only: bool = False     # options are whole words, matched exactly (arch -arch NAME, -x86_64)
    numeric: Optional[str] = None   # a `-NUM` word is an option with this role (tail -5, nice -10)
    numeric_re: str = r'-\d+'
    digits: bool = False        # digits are flags inside a cluster (grep -n3)
    dash: Optional[str] = None  # the role of a lone `-` word, when it is not an operand
    implicit: Tuple = ()        # (path text, role) writes the program makes without naming them (nohup.out)
    note: str = ''


def opts(**groups) -> Dict[str, Opt]:
    """Build an option table. Keywords: flags= (no value); a role name (arg=, read=, write=, ...) for options that
    require a value with that role; opt_<role>= for an optional attached value. modes= maps an option to a mode.
    Each keyword's value is a whitespace-separated list of option names."""
    modes = groups.pop('modes', {})
    table: Dict[str, Opt] = {}
    for key, names in groups.items():
        if key == 'flags':
            takes, role = NO, ARG
        elif key.startswith('opt_'):
            takes, role = OPT, key[4:].replace('_', '-')
        else:
            takes, role = REQ, key.replace('_', '-')
        if role not in ROLES:
            raise ValueError('unknown role %r' % role)
        for name in names.split():
            if name in table:
                raise ValueError('option %s listed twice' % name)
            table[name] = Opt(name, takes, role, modes.get(name, ''))
    for name in modes:
        if name not in table:
            raise ValueError('mode for unlisted option %s' % name)
    return table


def roles_for(layout: Layout, operands: List[str]) -> List[str]:
    """The role of each operand under `layout`."""
    roles: List[str] = []
    k = 0
    for entry in layout.pre:
        if k >= len(operands):
            break
        role, pattern = entry if isinstance(entry, tuple) else (entry, None)
        if pattern is not None and not re.fullmatch(pattern, operands[k]):
            continue  # an optional positional that is absent
        roles.append(role)
        k += 1
    rest = operands[k:]
    if layout.rest == COMMAND:
        return roles + ([COMMAND] if rest else [])
    roles += [layout.rest] * len(rest)
    if layout.last and len(rest) >= layout.last_min:
        roles[-1] = layout.last
    return roles


def fixed(layout: Layout) -> Callable:
    return lambda modes, operands: roles_for(layout, operands)


def by_mode(default: Layout, **when: Layout) -> Callable:
    """The first layout whose mode is on (in keyword order), else `default`."""
    def pick(modes, operands):
        for mode, layout in when.items():
            if mode.replace('_', '-') in modes:
                return roles_for(layout, operands)
        return roles_for(default, operands)
    return pick


def spec(name, reading, table, layout, **kw) -> Spec:
    return Spec(name, reading, table, layout if callable(layout) else fixed(layout), **kw)


# ---- the parser -----------------------------------------------------------------------------------------------------
class Item(NamedTuple):
    index: int        # the word's position in the argument list (-1: a write the program makes without naming it)
    offset: int       # where the value starts inside that word (0: the whole word)
    role: str
    option: str       # the option it belongs to ('' for an operand)
    text: str         # the value's text (the word from `offset`)


class Parse(NamedTuple):
    spec: Spec
    items: Tuple[Item, ...]
    modes: FrozenSet[str]
    command_at: Optional[int]     # where the launched command starts, for a launcher that runs one
    unresolved: Optional[str]     # why the guard cannot model this invocation (None: modelled)
    values: Dict[str, str]        # each option's last value (the replacement token of xargs -I)
    permuted: bool

    def roles(self, *wanted):
        return [i for i in self.items if i.role in wanted]

    def non_grants(self):
        return [i for i in self.items if i.role not in GRANTS]


def _long_match(spec: Spec, name: str):
    """The option a long name selects: an exact name, else a unique prefix (when the spec allows them). Returns
    (opt, None) or (None, reason)."""
    if name in spec.opts:
        return spec.opts[name], None
    if not spec.long_prefix or spec.long_only:
        return None, 'unknown option %s' % name
    hits = [o for n, o in spec.opts.items() if n.startswith('--') and n.startswith(name)]
    kinds = {(o.takes, o.role, o.mode) for o in hits}
    if not hits:
        return None, 'unknown option %s' % name
    if len(kinds) > 1:
        return None, 'ambiguous option %s (%s)' % (name, ', '.join(sorted(o.name for o in hits))[:80])
    return hits[0], None


def wal_getopt(spec: Spec, texts: List[str], permute: Optional[bool] = None) -> Parse:
    """Parse `texts` (a program's argument words, without its name) the way `spec`'s program does."""
    permute = spec.permute if permute is None else permute
    items: List[Item] = []
    modes, values = set(), {}
    operands: List[Tuple[int, str]] = []
    unresolved = None
    k, n = 0, len(texts)

    def take(opt, value_index, offset, text):
        if opt.takes == NO:
            items.append(Item(value_index, 0, ARG, opt.name, texts[value_index]))
        else:
            items.append(Item(value_index, offset, opt.role, opt.name, text))
            values[opt.name] = text
        if opt.mode:
            modes.add(opt.mode)

    while k < n:
        t = texts[k]
        if t == '--' and not spec.long_only:
            operands += [(j, texts[j]) for j in range(k + 1, n)]
            break
        if t == '-' and spec.dash:
            items.append(Item(k, 0, spec.dash, '-', t))
            k += 1
            continue
        if not t.startswith('-') or t == '-':
            operands.append((k, t))
            k += 1
            if not permute:
                operands += [(j, texts[j]) for j in range(k, n)]
                break
            continue
        if spec.numeric and re.fullmatch(spec.numeric_re, t):
            items.append(Item(k, 0, spec.numeric, t, t))
            k += 1
            continue
        if spec.long_only or t.startswith('--'):
            name, eq, value = t.partition('=')
            opt, why = _long_match(spec, name)
            if opt is None:
                unresolved = why
                break
            if opt.takes == NO:
                if eq:
                    unresolved = 'option %s takes no value' % opt.name
                    break
                take(opt, k, 0, t)
            elif eq:
                take(opt, k, len(name) + 1, value)
            elif opt.takes == REQ:
                if k + 1 >= n:
                    unresolved = 'option %s needs a value' % opt.name
                    break
                k += 1
                take(opt, k, 0, texts[k])
            else:
                take(opt, k, len(t), '')   # an optional value is attached only
            k += 1
            continue
        # a cluster of short options
        j = 1
        while j < len(t):
            c = t[j]
            if spec.digits and c.isdigit():
                items.append(Item(k, j, ARG, '-' + c, c))
                j += 1
                continue
            opt = spec.opts.get('-' + c)
            if opt is None:
                unresolved = 'unknown option -%s' % c
                break
            if opt.takes == NO:
                take(opt, k, j, t)
                j += 1
                continue
            if j + 1 < len(t):
                take(opt, k, j + 1, t[j + 1:])
            elif opt.takes == REQ:
                if k + 1 >= n:
                    unresolved = 'option -%s needs a value' % c
                    break
                k += 1
                take(opt, k, 0, texts[k])
            else:
                take(opt, k, len(t), '')
            break
        if unresolved:
            break
        k += 1
    command_at = None
    if unresolved is None:
        roles = spec.layout(frozenset(modes), [t for _, t in operands])
        for (index, text), role in zip(operands, roles):
            if role == COMMAND:
                command_at = index
                break
            items.append(Item(index, 0, role, '', text))
        if any(i.role == OPAQUE for i in items):
            unresolved = 'option %s is not modelled' % next(i.option for i in items if i.role == OPAQUE)
    for path, role in spec.implicit:
        items.append(Item(-1, 0, role, '', path))
    return Parse(spec, tuple(sorted(items, key=lambda i: (i.index, i.offset))), frozenset(modes), command_at,
                 unresolved, values, permute)


# ---- find -----------------------------------------------------------------------------------------------------------
# GNU findutils 4.9 and macOS find: the leading options, the primaries and how many words each takes, the actions that
# write, and the actions that run a command. Starts count at every position (a word that is not a primary, its value
# or an operator), so a start after the expression, which find itself rejects, is judged too.
FIND_LEAD = {
    GNU: opts(flags='-H -L -P', arg='-D', modes={}),
    BSD: opts(flags='-H -L -P -E -X -d -s -x', read='-f'),
}
FIND_GNU_O = re.compile(r'-O\d*')
FIND_OPERATORS = frozenset({'(', ')', '!', ',', '-not', '-a', '-and', '-o', '-or'})
_FIND_COMMON0 = ('-delete -depth -empty -false -true -follow -ignore_readdir_race -noignore_readdir_race -ls -mount '
                 '-xdev -nogroup -nouser -noleaf -print -print0 -prune -quit')
_FIND_COMMON1 = ('-amin -anewer -atime -cmin -cnewer -ctime -fstype -gid -group -ilname -iname -inum -ipath -iregex '
                 '-iwholename -links -lname -maxdepth -mindepth -mmin -mtime -name -newer -path -perm -regex '
                 '-samefile -size -type -uid -user -wholename')
FIND_PRIMARIES = {
    GNU: dict({p: 0 for p in (_FIND_COMMON0 + ' -d -daystart -nowarn -warn -readable -writable -executable -help '
                              '-version').split()},
              **{p: 1 for p in (_FIND_COMMON1 + ' -context -printf -regextype -used -xtype -files0-from').split()},
              **{'-fprintf': 2, '-fprint': 1, '-fprint0': 1, '-fls': 1}),
    BSD: dict({p: 0 for p in (_FIND_COMMON0 + ' -acl -d -sparse -xattr').split()},
              **{p: 1 for p in (_FIND_COMMON1 + ' -Bmin -Bnewer -Btime -flags -mnewer -xattrname').split()}),
}
FIND_NEWER_XY = {GNU: re.compile(r'-newer[aBcmt][aBcmt]'), BSD: re.compile(r'-newer[aBcmt][aBcmt]')}
FIND_WRITES = {'-fprint': WRITE, '-fprint0': WRITE, '-fls': WRITE, '-fprintf': WRITE}
FIND_READS = {'-anewer': READ, '-cnewer': READ, '-newer': READ, '-samefile': READ, '-files0-from': READ,
              '-Bnewer': READ, '-mnewer': READ}
FIND_RUN = frozenset({'-exec', '-execdir', '-ok', '-okdir'})


def _find_value_role(primary, j, reading):
    if j == 1 and primary in FIND_WRITES:
        return FIND_WRITES[primary]
    if primary in FIND_READS:
        return FIND_READS[primary]
    if FIND_NEWER_XY[reading].fullmatch(primary):
        return ARG if primary.endswith('t') else READ   # -newerXt takes a time, the others a file
    return ARG


class FindParse(NamedTuple):
    reading: str
    items: Tuple[Item, ...]       # starts (READ, or WRITE under -delete), primary values with their roles
    bodies: Tuple[Tuple[int, int, str], ...]   # (first word, end, primary) of each -exec/-ok body; end is ; or +
    deletes: bool
    unresolved: Optional[str]

    def starts(self):
        return [i for i in self.items if i.option == '']


def find_parse(texts: List[str], reading: str) -> FindParse:
    """Parse a find command's words (without `find`) under one reading."""
    lead, primaries = FIND_LEAD[reading], FIND_PRIMARIES[reading]
    items: List[Item] = []
    bodies = []
    k, n = 0, len(texts)
    while k < n:   # leading options
        t = texts[k]
        if t == '--':
            k += 1
            break
        if reading == GNU and FIND_GNU_O.fullmatch(t):
            items.append(Item(k, 0, ARG, '-O', t))
            k += 1
            continue
        if not t.startswith('-') or t in primaries or t == '-' or FIND_NEWER_XY[reading].fullmatch(t) \
                or t in FIND_RUN or t in FIND_OPERATORS:
            break
        p = wal_getopt(Spec('find', reading, lead, fixed(Layout())), [t] + texts[k + 1:k + 2], permute=False)
        if p.unresolved:
            return FindParse(reading, tuple(items), (), False, 'find: ' + p.unresolved)
        used = 2 if any(i.index == 1 and i.option for i in p.items) else 1
        for i in p.items:
            if i.index < used and i.option:
                # BSD -f PATH names a start
                items.append(i._replace(index=i.index + k, option='' if i.option == '-f' else i.option))
        k += used
    deletes = False
    while k < n:
        t = texts[k]
        if t in FIND_OPERATORS:
            k += 1
            continue
        if t in FIND_RUN:
            end = next((j for j in range(k + 1, n) if texts[j] == ';' or (texts[j] == '+' and texts[j - 1] == '{}')),
                       None)
            if end is None or end == k + 1:
                return FindParse(reading, tuple(items), tuple(bodies), deletes, 'find: %s has no command' % t)
            bodies.append((k + 1, end, t))
            k = end + 1
            continue
        if t == '-depth' and reading == BSD and k + 1 < n and re.fullmatch(r'[-+]?\d+', texts[k + 1]):
            items.append(Item(k + 1, 0, ARG, t, texts[k + 1]))
            k += 2
            continue
        arity = primaries.get(t, 1 if FIND_NEWER_XY[reading].fullmatch(t) else None)
        if arity is None:
            if t.startswith('-') and t != '-':
                return FindParse(reading, tuple(items), tuple(bodies), deletes, 'find: unknown primary %s' % t[:40])
            items.append(Item(k, 0, READ, '', t))   # a start, at any position
            k += 1
            continue
        if t == '-delete':
            deletes = True
        if k + arity >= n:
            return FindParse(reading, tuple(items), tuple(bodies), deletes, 'find: %s needs a value' % t)
        for j in range(1, arity + 1):
            items.append(Item(k + j, 0, _find_value_role(t, j, reading), t, texts[k + j]))
        k += arity + 1
    if deletes:
        items = [i._replace(role=WRITE) if i.option == '' else i for i in items]
    return FindParse(reading, tuple(items), tuple(bodies), deletes, None)


# ---- launchers ------------------------------------------------------------------------------------------------------
_HELP = '--help --version'
_UL_HELP = '-h --help -V --version'   # util-linux


def _env_layout(split_rest):
    def layout(modes, operands):
        roles, k = [], 0
        if operands and operands[0] == '-':
            roles.append(ARG)   # a lone `-` after the options is -i
            k = 1
        while k < len(operands) and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*=.*', operands[k], re.S):
            roles.append(ENV)
            k += 1
        if 'split' in modes:
            return roles + [TEXT] * (len(operands) - k)
        return roles + ([COMMAND] if k < len(operands) else [])
    return layout


def _sg_layout(modes, operands):
    roles = [ARG] if operands else []
    rest = operands[1:]
    if rest and rest[0] == '-c':
        roles.append(ARG)
        rest = rest[1:]
    return roles + [TEXT] * len(rest)


def _flock_layout(modes, operands):
    if not operands:
        return []
    if re.fullmatch(r'\d+', operands[0]) and len(operands) == 1:
        return [ARG]   # a file descriptor
    roles = [WRITE]   # the lock file, created when missing
    rest = operands[1:]
    if rest and rest[0] in ('-c', '--command'):
        return roles + [ARG] + [TEXT] * len(rest[1:])
    return roles + ([COMMAND] if rest else [])


_SU_SHELL = Layout(pre=(ARG,), rest=SHELL_ARGS)    # su [-] [USER [ARGS]]: the arguments go to the user's shell
_RUN = Layout(rest=COMMAND)
_PIDS = Layout(rest=ARG)

LAUNCHERS = [
    spec('env', GNU, opts(flags='-i --ignore-environment -0 --null -v --debug --list-signal-handling ' + _HELP,
                          arg='-u --unset', chdir='-C --chdir', text='-S --split-string',
                          opt_arg='--block-signal --default-signal --ignore-signal',
                          modes={'-S': 'split', '--split-string': 'split'}),
         _env_layout(True)),
    spec('env', BSD, opts(flags='-0 -i -v', arg='-u -P', chdir='-C', text='-S', modes={'-S': 'split'}),
         _env_layout(True), note='-P ALTPATH is where the utility is looked up, not a file written'),
    spec('nice', GNU, opts(arg='-n --adjustment', flags=_HELP), _RUN, numeric=ARG, numeric_re=r'-[-+]?\d+'),
    spec('nice', BSD, opts(arg='-n'), _RUN, numeric=ARG, numeric_re=r'-[-+]?\d+'),
    spec('ionice', GNU, opts(arg='-c --class -n --classdata -p --pid -P --pgid -u --uid', flags='-t --ignore ' + _UL_HELP,
                             modes={o: 'pids' for o in '-p --pid -P --pgid -u --uid'.split()}),
         by_mode(_RUN, pids=_PIDS)),
    spec('chrt', GNU, opts(flags='-b --batch -d --deadline -f --fifo -i --idle -o --other -r --rr -R --reset-on-fork '
                                 '-a --all-tasks -m --max -p --pid -v --verbose ' + _UL_HELP,
                           arg='-T --sched-runtime -P --sched-period -D --sched-deadline',
                           modes={'-p': 'pid', '--pid': 'pid', '-m': 'max', '--max': 'max'}),
         by_mode(Layout(pre=((ARG, r'[-+]?\d+'),), rest=COMMAND), pid=_PIDS, max=_PIDS)),
    spec('taskset', GNU, opts(flags='-a --all-tasks -p --pid -c --cpu-list ' + _UL_HELP,
                              modes={'-p': 'pid', '--pid': 'pid'}),
         by_mode(Layout(pre=(ARG,), rest=COMMAND), pid=_PIDS)),
    spec('setsid', GNU, opts(flags='-c --ctty -f --fork -w --wait ' + _UL_HELP), _RUN),
    spec('stdbuf', GNU, opts(arg='-i --input -o --output -e --error', flags=_HELP), _RUN),
    spec('stdbuf', BSD, opts(arg='-i -o -e'), _RUN),
    spec('timeout', GNU, opts(flags='--preserve-status --foreground -v --verbose ' + _HELP,
                              arg='-k --kill-after -s --signal'),
         Layout(pre=(ARG,), rest=COMMAND)),
    spec('nohup', GNU, opts(flags=_HELP), _RUN, implicit=(('nohup.out', WRITE),),
         note='nohup.out lands in the working directory (or $HOME) when stdout is a terminal'),
    spec('nohup', BSD, opts(), _RUN, implicit=(('nohup.out', WRITE),)),
    spec('watch', GNU, opts(flags='-b --beep -c --color -C --no-color -e --errexit -g --chgexit -p --precise '
                                  '-r --no-rerun -t --no-title -w --no-wrap -x --exec -h --help -v --version',
                            arg='-q --equexit -n --interval', opt_arg='-d --differences',
                            modes={'-x': 'exec', '--exec': 'exec'}),
         by_mode(Layout(rest=TEXT), exec=_RUN), note='without -x the words are joined and run by sh -c'),
    spec('xargs', GNU, opts(flags='-0 --null -o --open-tty -p --interactive -r --no-run-if-empty -t --verbose '
                                  '-x --exit --show-limits ' + _HELP,
                            read='-a --arg-file',
                            arg='-d --delimiter -E -I -L --max-lines -n --max-args -P --max-procs -s --max-chars '
                                '--process-slot-var',
                            opt_arg='-e --eof -i --replace -l',
                            modes={'-I': 'replace', '-i': 'replace', '--replace': 'replace'}),
         _RUN, note='no command runs echo'),
    spec('xargs', BSD, opts(flags='-0 --null -o -p --interactive -r --no-run-if-empty -t --verbose -x --exit',
                            arg='-E -I -J -L -n --max-args -P --max-procs -R -S -s --max-chars',
                            modes={'-I': 'replace', '-J': 'replace-j'}),
         _RUN),
    spec('su', GNU, opts(flags='-m -p --preserve-environment -l --login -f --fast -P --pty ' + _UL_HELP,
                         arg='-w --whitelist-environment -g --group -G --supp-group',
                         text='-c --command --session-command', opaque='-s --shell'),
         fixed(_SU_SHELL), dash=ARG, permute=True, note='read both ways: options after the user may be su\'s'),
    spec('su', BSD, opts(flags='-f -l -m'), fixed(_SU_SHELL), dash=ARG),
    spec('runuser', GNU, opts(flags='-m -p --preserve-environment -l --login -f --fast -P --pty ' + _UL_HELP,
                              arg='-u --user -w --whitelist-environment -g --group -G --supp-group',
                              text='-c --command --session-command', opaque='-s --shell',
                              modes={'-u': 'user', '--user': 'user'}),
         by_mode(_SU_SHELL, user=_RUN), dash=ARG, permute=True),
    spec('sg', GNU, opts(), _sg_layout, note='sg GROUP [[-c] COMMAND]: the command is run by sh -c'),
    spec('flock', GNU, opts(flags='-s --shared -x --exclusive -u --unlock -n --nonblock -o --close -F --no-fork '
                                  '--verbose ' + _UL_HELP,
                            arg='-w --timeout -E --conflict-exit-code', text='-c --command'),
         _flock_layout),
    spec('time', GNU, opts(flags='-a --append -p --portability -q --quiet -v --verbose -V --version --help',
                           arg='-f --format', write='-o --output'),
         _RUN, note='GNU time 1.9 (not installed on t2-dev); the shell keyword takes only -p'),
    spec('time', BSD, opts(flags='-a -h -l -p', write='-o'), _RUN),
    spec('command', ANY, opts(flags='-p -v -V'), _RUN),
    spec('builtin', ANY, opts(), _RUN),
    spec('exec', ANY, opts(flags='-c -l', arg='-a'), _RUN),
    spec('noglob', ANY, opts(), _RUN),
    spec('caffeinate', BSD, opts(flags='-d -i -m -s -u', arg='-t -w'), _RUN),
    spec('unbuffer', ANY, opts(flags='-p'), _RUN),
    spec('arch', BSD, opts(flags='-32 -64 -c -h -i386 -x86_64 -x86_64h -arm64 -arm64e', arg='-arch -d -e'), _RUN,
         long_only=True),
    spec('gosu', ANY, opts(), Layout(pre=(ARG,), rest=COMMAND)),
    spec('sshpass', ANY, opts(flags='-v -h -V', read='-f', arg='-d -p -P', opt_arg='-e'), _RUN),
]

# ---- the table ------------------------------------------------------------------------------------------------------
SPECS: Dict[str, Tuple[Spec, ...]] = {}


def _register(specs):
    for s in specs:
        SPECS.setdefault(s.name, ())
        if any(o.reading == s.reading for o in SPECS[s.name]):
            raise ValueError('two %s readings of %s' % (s.reading, s.name))
        SPECS[s.name] += (s,)


_register(LAUNCHERS)


def readings(name: str) -> Tuple[Spec, ...]:
    return SPECS.get(name, ())


def parse_all(name: str, texts: List[str]) -> List[Parse]:
    """Every reading of `name texts...`: each platform's, and for a permuting reading, the POSIXLY_CORRECT one that
    stops at the first operand. Empty when the program has no spec (it is unresolved)."""
    out = []
    for s in readings(name):
        out.append(wal_getopt(s, texts))
        if s.permute:
            out.append(wal_getopt(s, texts, permute=False))
    return out


def command_starts(parses: List[Parse]) -> List[int]:
    """The distinct positions where the readings say a launcher's command starts."""
    return sorted({p.command_at for p in parses if p.command_at is not None})


def xargs_token(parse: Parse) -> Optional[str]:
    """The replacement token of an xargs reading (-I R, -i[R], --replace[=R], BSD -J R), or None."""
    for name in ('-I', '-J', '--replace', '-i'):
        if name in parse.values:
            return parse.values[name] or '{}'   # -i and --replace without a value mean {}
    return None
