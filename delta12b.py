import json, collections
T = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/'
plan = json.loads(open(T + 'plan21-goodqa.jsonl').readline())
ids = {c['id']: c['n'] for c in plan['children']}
b = {json.loads(l)['id']: json.loads(l) for l in open(T + 'open_now12.jsonl')}
still = [(ids[i], b[i]['status'], b[i]['updatedAt']) for i in ids if i in b]
print('of 76 combined alerts, open in dump14:', len(still))
for s in sorted(still)[:8]:
    print(s)
other = [r['number'] for r in b.values() if r['_proj'] == 'goodqa' and r['title'].lower().startswith('fleet liveness') and r['id'] not in ids]
print('other open fleet liveness (not in the 76):', other)
