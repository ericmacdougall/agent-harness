import json, collections, sys
T = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/'
proj = sys.argv[1] if len(sys.argv) > 1 else 'parent-proof'
ids = set()
for l in open(T + 'plan17-%s.jsonl' % proj):
    for c in json.loads(l)['children']:
        ids.add(c['id'])
latest = {}
for l in open(T + 'done13.jsonl'):
    j = json.loads(l)
    latest[j['id']] = j
c = collections.Counter()
for i in ids:
    j = latest.get(i)
    c[(j['result'], (j.get('why') or '')[:40]) if j else ('no record', '')] += 1
print(proj, len(ids), dict(c))
