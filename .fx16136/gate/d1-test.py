"""goodqa#16198 (D1): NEG-18 gains -qe and -qieK=V. Run in infra/selfhost/app."""
p = 'test_cmdline_sampler.py'
s = open(p).read()
old = """                     ['docker', 'run', '-dite', 'K=' + MARKER, 'img']):
"""
new = """                     ['docker', 'run', '-dite', 'K=' + MARKER, 'img'],
                     # goodqa#16198 (D1): -q (--quiet) is a boolean shorthand too.
                     ['docker', 'run', '-qe', 'K=' + MARKER, 'img'],
                     ['docker', 'run', '-qieK=' + MARKER, 'img']):
"""
assert s.count(old) == 1
open(p, 'w').write(s.replace(old, new))
print('tests patched')
