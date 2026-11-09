import json, collections
T = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/'
R = [json.loads(l) for l in open(T + 'open_now9.jsonl')]
C = {o['id']: o for o in json.load(open(T + 'classes9.json'))}


def is_epic(r):
    t = r['title'].lower()
    return r['type'] == 'epic' or t.startswith(('area:', 'umbrella', 'live work:', 'merged, awaiting', 'on dev, awaiting', 'lane mirrors ended')) or 'umbrella' in [l.lower() for l in r['labels']]


cnt = collections.Counter()
samp = collections.defaultdict(list)
for r in R:
    if not is_epic(r):
        continue
    p = r['_proj']
    pr = set(C[r['id']]['prot']) - {'epic'}
    k = ('protected:' + ','.join(sorted(pr))) if pr else 'eligible'
    cnt[(p, k)] += 1
    if len(samp[(p, k)]) < 2:
        samp[(p, k)].append(r['title'][:70])
for (p, k), v in sorted(cnt.items(), key=lambda x: -x[1])[:16]:
    print(v, p, k, samp[(p, k)])
print('epics/umbrellas total', sum(cnt.values()))
