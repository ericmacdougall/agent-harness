import sys, json, random
T = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/'
sys.path.insert(0, T)
import gq
O = json.load(open(T + 'classes4.json'))
h = [o for o in O if o['human'] and o['proj'] == 'framebright/goodqa' and not o['prot']]
print(len(h))
random.seed(7)
for o in random.sample(h, 6):
    d = gq.call('get_issue', {'issueId': o['id']})
    d = d.get('issue', d)
    print(o['n'], o['title'][:70], '|', {k: (str(d.get(k))[:50]) for k in ('source', 'createdVia', 'createdViaApiKeyId', 'labels', 'reporterId')}, '| desc:', (d.get('description') or '')[:160].replace('\n', ' '))
