import json, collections, glob
T = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/'
fl = []
for l in open(T + 'open_now10.jsonl'):
    j = json.loads(l)
    if j['_proj'] == 'goodqa' and j['title'].lower().startswith('fleet liveness') and 'cleanup-2026-11' in j['labels']:
        fl.append(j)
print(len(fl), collections.Counter(j['status'] for j in fl), collections.Counter(j['type'] for j in fl), collections.Counter((j.get('reporter') or {}).get('name') for j in fl))
j = fl[0]
print({k: j[k] for k in ('number', 'title', 'labels', 'updatedAt', 'commentCount')})
ids = {j['id'] for j in fl}
rec = collections.Counter()
for f in glob.glob(T + 'done*.jsonl'):
    for l in open(f):
        d = json.loads(l)
        if d['id'] in ids:
            rec[(f.split('/')[-1], d['result'], d.get('why') or d.get('to'))] += 1
print(dict(rec))
