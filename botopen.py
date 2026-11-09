import json, collections
T = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/'
b = [json.loads(l) for l in open(T + 'open_now15.jsonl')]
print('open', len(b))
for r in b:
    t = r['title'].lower()
    if t.startswith(('fleet liveness', 'live:')) or 'liveness' in t or 'alert' in t[:40]:
        print(r['_proj'], r['number'], r['status'], (r.get('reporter') or {}).get('name'), r['title'][:80])
print(collections.Counter((r['_proj'], r['type']) for r in b if r['_proj'] == 'goodqa'))
