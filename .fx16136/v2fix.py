import re, sys
p = sys.argv[1]; t = open(p).read()
lines = t.split('\n'); out = []; i = 0
in_ac = False
while i < len(lines):
    l = lines[i]
    if l.startswith('## '):
        in_ac = l.strip() in ('## Acceptance criteria', '## Negative cases')
    if in_ac and re.match(r'^- (AC|NEG)-\d+', l):
        buf = [l.rstrip()]; i += 1
        while i < len(lines) and not lines[i].startswith('- ') and not lines[i].startswith('## '):
            s = lines[i].strip()
            if s: buf.append(re.sub(r'^(\d+\.|-)\s*', '', s))
            i += 1
        out.append(' '.join(buf)); out.append('')
        continue
    out.append(l); i += 1
t = re.sub(r'\n\n\n+', '\n\n', '\n'.join(out))
t = t.replace('-- review C4\n', '-- review condition C4, a classic store cannot resolve repo@id\n')
t = t.replace('-- review C6\n', '-- review condition C6, the anchor must not diverge\n')
t = t.replace('-- review F2\n', '-- review finding F2, prune silently breaks job refs\n')
open(p, 'w').write(t)
