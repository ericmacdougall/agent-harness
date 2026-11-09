p = '../spec-15561-v4.md'
s = open(p).read()
lines = s.split('\n')


def find(prefix):
    idx = [i for i, l in enumerate(lines) if l.startswith(prefix)]
    assert len(idx) == 1, (prefix, idx)
    return idx[0]


i = find('- AC-14')
assert 'covering NEG-31..NEG-35 and NEG-37' in lines[i]
lines[i] = lines[i].replace('covering NEG-31..NEG-35 and NEG-37', 'covering NEG-31..NEG-35, NEG-37 and NEG-38 (the embedded-timeline guard)')
i = find('- S1e')
lines[i] = lines[i].replace('let a bound session use it only with the grant, the switch and the org opt-in;', 'let a bound session use it only with the grant, the switch and the org opt-in; empty the timeline embedded in contact detail unless the same conditions hold (NEG-38);')
assert 'NEG-38' in lines[i]
i = find('- NEG-35')
assert 'both routes' in lines[i]
lines[i] = lines[i].replace('both routes', 'the detail route and the timeline route')
open(p, 'w').write('\n'.join(lines))
print('ok')
