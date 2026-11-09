import json, collections, re, sys
sys.path.insert(0, '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/harness-delivery/.claude/worktrees/agent-ab8a7d1bf54ed3c9a')
import patterns
B = json.load(open('/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/skip13_bodies.json'))
clear = 0
left = collections.Counter()
ex = {}
for i, bl in B.items():
    rem = [b for b in bl if patterns.classify(b) is None]
    if not rem:
        clear += 1
    for b in rem:
        k = re.sub(r'[0-9a-f]{7,}|\d+', 'N', b.strip()[:26])
        left[k] += 1
        ex.setdefault(k, b.strip()[:110].replace('\n', ' '))
print(len(B), 'tickets;', clear, 'now clear;', sum(left.values()), 'comments still unmatched in', len(left), 'shapes')
for k, v in left.most_common(14):
    print(v, '|', ex[k])
