import os
R = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/agent-ab8a7d1bf54ed3c9a/fresh/t2c/'


def count(p):
    n = 0
    for dp, dn, fn in os.walk(R + p):
        n += len(fn)
    return n


print('dist entries:', sorted(os.listdir(R + 'dist')))
print('dist/client top:', sorted(os.listdir(R + 'dist/client'))[:25])
for p in ('public/audio', 'public/engineering-videos', 'public/data-audio', 'power-user/public/audio'):
    print(p, count(p))
for p in ('dist/client/audio', 'dist/client/engineering-videos', 'dist/client/data-audio', 'dist/client/power-user', 'dist/client/power-user/audio', 'dist/client/learn', 'dist/client/power'):
    if os.path.exists(R + p):
        print(p, count(p))
# where do power-user audio files land?
pu = R + 'power-user/public/audio'
first = None
for dp, dn, fn in os.walk(pu):
    if fn:
        first = os.path.relpath(os.path.join(dp, fn[0]), R + 'power-user/public'); break
print('sample power-user file rel to its public/:', first)
hits = []
for dp, dn, fn in os.walk(R + 'dist'):
    if first and os.path.basename(first) in fn:
        hits.append(os.path.relpath(dp, R))
        if len(hits) > 3: break
print('sample found under:', hits)
