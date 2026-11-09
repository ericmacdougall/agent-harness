import json, collections
T = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/'
R = [json.loads(l) for l in open(T + 'open_now9.jsonl')]
OK = {'Eric MacDougall', 'Claude (agent)'}
tot = collections.Counter()
by = collections.defaultdict(collections.Counter)
for r in R:
    p = r['_proj']
    t = r['title'].lower()
    if r['type'] == 'epic' or t.startswith(('area:', 'umbrella', 'live work:', 'merged, awaiting', 'on dev, awaiting', 'lane mirrors ended')) or 'umbrella' in [l.lower() for l in r['labels']]:
        k = 'epic or umbrella (kept as the work surface)'
    elif p in ('yates-cloud', 'optinrouter') or 'yates' in p:
        k = 'excluded project'
    elif (r.get('reporter') or {}).get('name') not in OK or r.get('externalReporterId'):
        k = 'reporter is a customer or teammate'
    elif 'security' in [l.lower() for l in r['labels']] or p == 'security-project':
        k = 'security finding (excluded)'
    elif r['_org'] in ('p51-media', 'petafiliate', 'qa-bot-2026-10-29-s29-billing', 'pipeline-verify-sandbox'):
        k = 'other organisation'
    else:
        k = 'foldable under the ruling (not yet folded)'
    by[p][k] += 1
    tot[k] += 1
print('TOTAL', len(R))
for k, v in tot.most_common():
    print(v, k)
for p, c in sorted(by.items(), key=lambda x: -sum(x[1].values()))[:10]:
    print(p, sum(c.values()), dict(c))
