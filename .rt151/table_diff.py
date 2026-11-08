"""Compare command_guard's GNU parallel option table with the real table in parallel's own source. Reads text only."""
import re
import sys

REPO, SRC = sys.argv[1], sys.argv[2]
sys.path.insert(0, REPO + '/harness/hooks')
import command_guard as cg  # noqa: E402

lines = open(SRC, encoding='latin-1').read().split('\n')
start = next(i for i, l in enumerate(lines) if l.startswith('sub options_completion_hash'))
end = next(i for i in range(start, len(lines)) if lines[i].startswith('}'))
real = {}
for l in lines[start:end]:
    for m in re.finditer(r'"([A-Za-z0-9_\-|]+)([=:!+][a-z]*)?(\[|")', l):
        names, kind = m.group(1), m.group(2) or ''
        for n in names.split('|'):
            real.setdefault(n, kind)
print('real options parsed:', len(real))
short = {n: k for n, k in real.items() if len(n) == 1}
long_ = {n: k for n, k in real.items() if len(n) > 1}


def guard_short(c):
    if c in cg.PAR_SHORT_VALUED:
        return 'v'
    if c in cg.PAR_SHORT_OPTIONAL:
        return 'o'
    if c in cg.PAR_SHORT_FLAGS:
        return 'f'
    return None


def real_kind(k):
    return 'v' if k.startswith('=') else 'o' if k.startswith(':') else 'f'


print('\n== long: guard says flag, real takes a value (template start is misread)')
for n in sorted(cg.PAR_LONG_FLAGS):
    if n in long_ and real_kind(long_[n]) == 'v':
        print('  --%s real %s' % (n, long_[n]))
print('\n== long: guard says value, real is a flag (the guard swallows the first template word)')
for n in sorted(cg.PAR_LONG_VALUED):
    if n in long_ and real_kind(long_[n]) == 'f':
        print('  --%s real flag' % n)
print('\n== long: guard says flag/optional, real optional')
for n in sorted(cg.PAR_LONG_FLAGS | cg.PAR_LONG_OPTIONAL):
    if n in long_ and real_kind(long_[n]) == 'o' and n not in cg.PAR_LONG_OPTIONAL:
        print('  --%s real %s' % (n, long_[n]))
print('\n== long in guard, absent from the real table')
print('  ', sorted(n for n in (cg.PAR_LONG_FLAGS | cg.PAR_LONG_VALUED | cg.PAR_LONG_OPTIONAL) if n not in long_))
print('\n== real long missing from guard (refused unless an abbreviation hits)')
print('  ', sorted(n for n in long_ if n not in (cg.PAR_LONG_FLAGS | cg.PAR_LONG_VALUED | cg.PAR_LONG_OPTIONAL)))
print('\n== short differences')
for c in sorted(short):
    g = guard_short(c)
    if g != real_kind(short[c]):
        print('  -%s guard=%s real=%s' % (c, g, short[c] or 'flag'))
for c in sorted(set(cg.PAR_SHORT_VALUED | cg.PAR_SHORT_OPTIONAL | cg.PAR_SHORT_FLAGS) - set(short)):
    print('  -%s in guard, not in real' % c)

print('\n== abbreviations resolving to a different kind than real parsing')
allreal = sorted(long_)
for n in sorted(long_):
    for ln in range(1, len(n)):
        pre = n[:ln]
        if pre in long_:
            continue
        hits = {x for x in allreal if x.startswith(pre)}
        kinds = {real_kind(long_[x]) for x in hits}
        full, kind = cg._par_long(pre)
        if full is None or len(kinds) != 1:
            continue
        if next(iter(kinds)) != kind:
            print('  --%s guard->%s(%s) real->%s(%s)' % (pre, full, kind, sorted(hits)[:3], kinds))
