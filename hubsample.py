import json, collections
T = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/'
R = [json.loads(l) for l in open(T + 'open_now10.jsonl')]
c = collections.Counter()
ex = {}
for r in R:
    if r['_proj'] != 'goodqa':
        continue
    t = r['title'].lower()
    labs = [l.lower() for l in r['labels']]
    if 'live-work-combined' in labs or t.startswith(('live work:', 'live security', 'live hub')):
        continue
    ours = t.startswith(('area:', 'umbrella (cleanup', 'merged, awaiting', 'on dev, awaiting', 'lane mirrors ended')) or any(l.startswith('cleanup-2026-11') for l in labs)
    if ours:
        k = t.split(':')[0][:30]
        c[(k, tuple(l for l in r['labels'] if 'cleanup' in l.lower())[:2])] += 1
        ex.setdefault(k, (r['number'], r['title'][:80], r['type'], r['source']))
for k, v in c.most_common(12):
    print(v, k, ex[k[0]])
