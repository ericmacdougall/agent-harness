"""goodqa#16198 (D1): add q to BOOL_SHORT; state derive's single-instance rule. Run in infra/selfhost/app."""
p = 'cmdline-sampler.py'
s = open(p).read()
old = ("# docker run's boolean shorthands: pflag lets these cluster (-dit), and any other shorthand takes the rest as its value.\n"
       "BOOL_SHORT = set('ditP')\n")
new = ("# docker run's boolean shorthands (-d detach, -i interactive, -t tty, -P publish-all, -q quiet; goodqa#16198 added q):\n"
       "# pflag lets these cluster (-dit), and any other shorthand takes the rest as its value.\n"
       "BOOL_SHORT = set('ditPq')\n")
assert s.count(old) == 1
open(p, 'w').write(s.replace(old, new))

p = 'derive-job-secrets.py'
s = open(p).read()
anchor = '"""derive-job-secrets.py'
i = s.index(anchor)
end = s.index('"""', i + 3)
note = ("\nSINGLE INSTANCE (goodqa#16198): run this only through apply-job-secrets.sh or rw-ship, which hold the deploy lock,\n"
        "or by hand only while no such run holds it. Two concurrent runs can each see the other's rename as a changed file;\n"
        "the fail-closed unlink then removes the other run's fresh file. That still fails closed (the key reads as missing,\n"
        "no value is exposed), and the next single run repairs it.\n")
s = s[:end] + note + s[end:]
open(p, 'w').write(s)
print('source patched')
