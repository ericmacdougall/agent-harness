import json, collections
T = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/'
O = json.load(open(T + 'classes4.json'))
h = [o for o in O if o['human'] and not o['prot']]
print(len(h))
c = collections.Counter()
nolab = 0
for o in h:
    if not o['labels']:
        nolab += 1
    for l in o['labels']:
        c[l.split(':')[0] if ':' in l else l] += 1
print('no labels', nolab)
print(c.most_common(40))
print(collections.Counter(o['status'] for o in h))
print(collections.Counter(o['proj'] for o in h).most_common(8))
print([o['title'][:60] for o in h if not o['labels']][:25])
