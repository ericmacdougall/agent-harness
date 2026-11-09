# One-command undo for consol13: python3 reopen13.py [--apply] [--umbrella N]   (default dry run; reopens each child to its snapshot state)
import sys, os, json, glob
os.chdir('/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup')
sys.path.insert(0, '.')
import gq
apply = '--apply' in sys.argv
umb = int(sys.argv[sys.argv.index('--umbrella') + 1]) if '--umbrella' in sys.argv else None
snap = {}
for f in glob.glob('snapshots13/snap-*.jsonl'):
    for l in open(f):
        j = json.loads(l)
        snap[j['issue']['id']] = j
closed = {}
for l in open('done13.jsonl'):
    j = json.loads(l)
    if j['result'] == 'closed':
        closed[j['id']] = j
rows = [(i, snap[i]) for i, c in closed.items() if i in snap and (umb is None or c['umb'] == umb)]
print(len(rows), 'tickets would be reopened')
if apply:
    for i, s in rows:
        gq.call('update_issue', {'issueId': i, 'patch': {'status': s['issue']['status']}})
    print('reopened', len(rows))
