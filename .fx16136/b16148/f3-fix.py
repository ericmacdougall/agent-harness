"""goodqa#16148 code review F3: a short-flag cluster that pflag reads as containing -e is BAD. Run in infra/selfhost/app."""
p = 'cmdline-sampler.py'
s = open(p).read()
edits = [
    ("ALLOWED_SHORT = {'-d', '-e', '-i', '-t', '-u'}\nBAD = {'-e', '-e(attached)', '--env', '--env(attached)'}\n",
     "ALLOWED_SHORT = {'-d', '-e', '-i', '-t', '-u'}\n"
     "# docker run's boolean shorthands: pflag lets these cluster (-dit), and any other shorthand takes the rest as its value.\n"
     "BOOL_SHORT = set('ditP')\n"
     "BAD = {'-e', '-e(attached)', '-e(cluster)', '--env', '--env(attached)'}\n"),
    ("""        elif tok.startswith('-') and len(tok) >= 2:
            short = tok[:2]
            if len(tok) > 2:
                flags.append((short if short in ALLOWED_SHORT else '-(other)') + '(attached)')
            else:
                flags.append(short if short in ALLOWED_SHORT else '-(other)')
""",
     """        elif tok.startswith('-') and len(tok) >= 2:
            flags.append(short_flag(tok))
"""),
    ("def in_container(cgroup_text, container):\n",
     '''def short_flag(tok):
    """A single-dash token, read the way pflag reads a shorthand cluster (code review F3): booleans chain, `e` anywhere
    in the chain is an env flag (-de, -ieK=V), and the first value-taking shorthand ends the chain."""
    short = tok[:2]
    if len(tok) == 2:
        return short if short in ALLOWED_SHORT else '-(other)'
    for i, c in enumerate(tok[1:]):
        if c == 'e':
            return '-e(attached)' if i == 0 else '-e(cluster)'
        if c not in BOOL_SHORT:
            break
    return (short if short in ALLOWED_SHORT else '-(other)') + '(attached)'


def in_container(cgroup_text, container):
'''),
    ("  * a short flag with an attached value (`-eK=V`) is recorded as `-e(attached)`; others as `-x` if allow-listed;\n",
     "  * a short flag with an attached value (`-eK=V`) is recorded as `-e(attached)`; others as `-x` if allow-listed;\n"
     "    a cluster is read as pflag reads it, so `-de` and `-ieK=V` record `-e(cluster)`;\n"),
    ("FAIL: any observed run has\n-e, -e(attached), --env or --env(attached).",
     "FAIL: any observed run has\n-e, -e(attached), -e(cluster), --env or --env(attached)."),
]
for o, n in edits:
    assert s.count(o) == 1, o
    s = s.replace(o, n)
open(p, 'w').write(s)
print('source patched')
