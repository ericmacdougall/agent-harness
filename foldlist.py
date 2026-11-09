import json, collections
T = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/'
R = [json.loads(l) for l in open(T + 'open_now9.jsonl')]
OK = {'Eric MacDougall', 'Claude (agent)'}
c = collections.Counter()
for r in R:
    t = r['title'].lower()
    if r['type'] == 'epic' or t.startswith(('area:', 'umbrella', 'live work:', 'merged, awaiting', 'on dev, awaiting', 'lane mirrors ended')) or 'umbrella' in [l.lower() for l in r['labels']]:
        continue
    if (r.get('reporter') or {}).get('name') not in OK or r.get('externalReporterId'):
        continue
    if 'security' in [l.lower() for l in r['labels']] or r['_proj'] == 'security-project':
        continue
    if r['_org'] in ('p51-media', 'petafiliate', 'qa-bot-2026-10-29-s29-billing', 'pipeline-verify-sandbox') or 'yates' in r['_proj'] or r['_proj'] == 'optinrouter':
        continue
    c[r['_proj']] += 1
print(' '.join(p for p, n in c.most_common()), '|', dict(c))
