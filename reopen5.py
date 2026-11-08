# Undo for consol.py: python3 reopen5.py [--apply] [--kind noise|parent|cluster]   (default dry run)
import sys, os, json, glob
os.chdir(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, '.')
import gq
apply = '--apply' in sys.argv
kind = sys.argv[sys.argv.index('--kind') + 1] if '--kind' in sys.argv else None
snap = {}
for f in glob.glob('snapshots5/snap-*.jsonl'):
    for l in open(f):
        j = json.loads(l)
        snap[j['issue']['id']] = j
closed = [json.loads(l) for l in open('done5.jsonl') if '"closed"' in l]
rows = [c for c in closed if (not kind or c['kind'] == kind) and c['id'] in snap]
print(len(rows), 'tickets to reopen')
if apply:
    for c in rows:
        gq.call('update_issue', {'issueId': c['id'], 'patch': {'status': snap[c['id']]['issue']['status']}})
