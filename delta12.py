import json, collections
T = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/'
a = {json.loads(l)['id']: json.loads(l) for l in open(T + 'open_now11.jsonl')}
b = {json.loads(l)['id']: json.loads(l) for l in open(T + 'open_now12.jsonl')}
new = [b[i] for i in b if i not in a]
gone = [a[i] for i in a if i not in b]
print('open now', len(b), 'new since dump13', len(new), 'gone', len(gone))
c = collections.Counter()
for r in new:
    c[(r['_proj'], (r.get('reporter') or {}).get('name'), r['title'][:40])] += 1
for k, v in c.most_common(14):
    print(v, k)
print(collections.Counter(r['_proj'] for r in b.values()).most_common(8))
print('fleet liveness open', len([r for r in b.values() if r['title'].lower().startswith('fleet liveness')]))
print('goodqa types', collections.Counter(r['type'] for r in b.values() if r['_proj'] == 'goodqa'))
