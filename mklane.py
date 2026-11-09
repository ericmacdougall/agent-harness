import json, uuid, sys, time
T = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/'
sys.path.insert(0, T)
import gq
s = open(T + 'consol10.py').read()
s = s.replace("OKSTAT = {'triage', 'backlog', 'todo'}", "OKSTAT = {'triage', 'backlog', 'todo', 'in_progress', 'in_review', 'on_dev'}")
s = s.replace("grp['kind'] == 'noise'", "grp['kind'] in ('noise', 'lane')")
s = s.replace("tail = 'merged into umbrella %s#%s (its ledger lists this ticket with latest comments).' % (U['slug'], U['number'])",
              "tail = ('lane ended (no live process, no WAL or ticket activity for 48h), superseded by umbrella %s#%s which lists this lane mirror with its last state; NOT done.' if grp['kind'] == 'lane' else 'merged into umbrella %s#%s (its ledger lists this ticket with latest comments).') % (U['slug'], U['number'])")
for a, b in [("done10.jsonl", "done11.jsonl"), ("closes10.tsv", "closes11.tsv"), ("snapshots10", "snapshots11"), ("bulk_errors10", "bulk_errors11"), ("ledger10|", "ledger11|")]:
    s = s.replace(a, b)
open(T + 'consol11.py', 'w').write(s)
ok = set(json.load(open(T + 'lane_ok.json')))
O = json.load(open(T + 'classes6.json'))
P = {p['slug']: p for p in json.load(open(T + 'projects.json'))}['work-tracker-automatic']
kids = [o for o in O if o['id'] in ok]
lines = ['%d [lane] mirrors whose lane has ended (no live process, no WAL mention and no ticket update for 48 hours, no human comment in 14 days). Closed wont_fix, NOT done; each keeps its last state here (goodqa#14977, %s).' % (len(kids), time.strftime('%Y-%m-%d', time.gmtime())), '']
for o in sorted(kids, key=lambda o: -o['n']):
    lines.append('- #%d [%s] %s' % (o['n'], o['status'], o['title'][:130]))
r = gq.call('create_issue', dict(orgId=P['orgId'], projectId=P['id'], title='Lane mirrors ended (work-tracker-automatic, 2026-11-09 sweep)', description='\n'.join(lines)[:49000], type='epic', labels=['umbrella', 'cleanup-2026-11e', 'keep-open'], operationId=str(uuid.uuid4())))
iss = r['issue']
grp = {'kind': 'lane', 'umbrella': {'id': iss['id'], 'number': iss['number'], 'slug': 'work-tracker-automatic'}, 'note': '',
       'children': [{'id': o['id'], 'n': o['n'], 'status': o['status'], 'rev': o['rev'], 'title': o['title'], 'proj': o['proj']} for o in kids]}
open(T + 'plan11-lane.jsonl', 'w').write(json.dumps(grp) + '\n')
print('umbrella', iss['number'], len(kids))
