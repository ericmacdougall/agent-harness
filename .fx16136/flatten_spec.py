"""Flatten nested AC/NEG bullets into one line each (spec_flow lint reads one line per criterion)."""
import os, re, sys
p = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), 'spec-16148-pem.md')
lines = open(p).read().split('\n'); out = []; cur = None
for l in lines:
    if re.match(r'^- (AC|NEG)-\d+', l):
        if cur is not None: out.append(cur)
        cur = l.rstrip(); continue
    if cur is not None and l.startswith('  ') and l.strip():
        s = l.strip(); s = re.sub(r'^(?:- |\d+\. )', '', s)
        sep = ' ' if cur.endswith(':') else ' '
        cur = cur + sep + s; continue
    if cur is not None: out.append(cur); cur = None
    out.append(l)
if cur is not None: out.append(cur)
open(p, 'w').write('\n'.join(out)); print('flattened')
