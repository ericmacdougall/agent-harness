"""Audit step 2 (read-only, local files only): what the fold snapshots and ledgers hold."""
import json, glob, collections
T = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/'
rows = {}
for f in glob.glob(T + 'done*.jsonl'):
    for l in open(f):
        d = json.loads(l)
        if d.get('result') == 'closed':
            rows.setdefault(d['id'], []).append((f.split('/')[-1], d.get('to'), d.get('from'), d.get('n')))
print('distinct ids closed by my ledgers:', len(rows))
c = collections.Counter(r[0][0] for r in rows.values())
print(sorted(c.items()))
keys = None
n = 0
for f in glob.glob(T + 'snapshots*/snap-*.jsonl'):
    for l in open(f):
        n += 1
        if keys is None:
            j = json.loads(l)
            keys = sorted(j.keys()) if isinstance(j, dict) else type(j)
            print('sample keys', keys, str(j)[:300])
print('snapshot rows', n)
