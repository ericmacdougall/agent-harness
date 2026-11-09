import json, sys
T = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/'
d = json.load(open(T + 'combine_goodqa.json'))
n = 0
for i, v in d.items():
    for q in v['instructions']:
        n += 1
        if n <= 14:
            print(len(q), repr(q[:170]))
print('total quoted passages', n, 'in', sum(1 for v in d.values() if v['instructions']), 'tickets')
