"""Apply only the selfhost-ctl.py part of f2-store-patch.py. usage: python3 f2-ctl-only.py <selfhost-ctl.py> <f2-store-patch.py>"""
import sys

p, patch = sys.argv[1:3]
src = open(patch).read()
ns = {}
start = src.index("edit('selfhost-ctl.py', [(")
seg = src[start + len("edit('selfhost-ctl.py', "):src.index("\nedit('test_rw_ship_selfhost.py'")].rstrip()
assert seg.endswith(')')
pairs = eval(seg[:-1])
t = open(p).read()
for old, new in pairs:
    assert t.count(old) == 1
    t = t.replace(old, new)
open(p, 'w').write(t)
print('ctl patched')
