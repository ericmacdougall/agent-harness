import json, collections
T = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/'
rows = [json.loads(l) for l in open(T + 'open_now4.jsonl')]
g = [r for r in rows if r['_proj'] == 'goodqa']
byid = {r['id']: r for r in g}
pc = collections.Counter(r['parentId'] for r in g if r['parentId'])
print(len(pc), 'distinct parents; open parents:', sum(1 for p in pc if p in byid))
for p, n in pc.most_common(15):
    print(n, p[:8], byid.get(p, {}).get('title', '(not open)')[:80])
orph = [r for r in g if r['parentId'] and r['parentId'] not in byid]
print('children with non-open parent', len(orph), collections.Counter(r['source'] for r in orph))
ch = [r for r in g if r['parentId'] in byid]
print('children of open parents', len(ch), collections.Counter(r['source'] for r in ch))
