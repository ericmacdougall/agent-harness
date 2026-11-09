"""Combine open security findings into ONE live security ticket per project (main ruling w3c9555ae9a9). Each finding becomes an OPEN checklist row quoting title, state, severity and the description VERBATIM.
Originals close as duplicates, never as fixed. usage: mkseccombine.py [--create]   -> plan19-<project>.jsonl for consol16"""
import sys, json, time, uuid, collections
T = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/'
sys.path.insert(0, T)
import gq
OK = {'Eric MacDougall', 'Claude (agent)'}
R = [json.loads(l) for l in open(T + 'open_now9.jsonl')]
sel = []
for r in R:
    t = r['title'].lower()
    if r['type'] == 'epic' or t.startswith(('area:', 'umbrella', 'live work:', 'merged, awaiting', 'on dev, awaiting', 'lane mirrors ended', 'live security')):
        continue
    if (r.get('reporter') or {}).get('name') not in OK or r.get('externalReporterId'):
        continue
    if r['_org'] in ('p51-media', 'petafiliate', 'qa-bot-2026-10-29-s29-billing', 'pipeline-verify-sandbox') or 'yates' in r['_proj'] or r['_proj'] == 'optinrouter':
        continue
    if 'security' in [l.lower() for l in r['labels']] or r['_proj'] == 'security-project':
        sel.append(r)
by = collections.defaultdict(list)
for r in sel:
    by[r['_proj']].append(r)
print('security findings selected:', len(sel), {p: len(v) for p, v in by.items()}, flush=True)
if '--create' not in sys.argv:
    sys.exit(0)
projects = {p['slug']: p for p in json.load(open(T + 'projects.json'))}
for p, lst in by.items():
    kids = []
    for r in sorted(lst, key=lambda x: -x['number']):
        d = gq.call('get_issue', {'issueId': r['id']})['issue']
        kids.append({'id': r['id'], 'n': r['number'], 'status': d['status'], 'rev': d['revision'], 'title': d['title'], 'proj': r['_org'] + '/' + p,
                     'owner': (d.get('assignee') or {}).get('name') or '-', 'pr': '-', 'upd': d.get('updatedAt', ''), 'active': False,
                     'finding': {'severity': d.get('severity'), 'priority': d.get('priority'), 'labels': d.get('labels'), 'description': (d.get('description') or '')[:3500]}})
    P = projects[p]
    desc = 'LIVE security ticket for %s (goodqa#14977, %s). It combines %d open security findings. Each finding is an OPEN checklist row in the comments below, quoting its title, state, severity and description verbatim. The originals were closed as duplicates of this ticket. They are NOT fixed and NOT wont_fix: every row stays open here until it is fixed and proven.' % (p, time.strftime('%Y-%m-%d', time.gmtime()), len(kids))
    r = gq.call('create_issue', dict(orgId=P['orgId'], projectId=P['id'], title='Live security findings [%s]' % p, description=desc, type='task', priority='high', labels=['security', 'live-work-combined', 'cleanup-2026-11j'], operationId=str(uuid.uuid5(uuid.NAMESPACE_URL, 'sec19|%s' % p))))
    iss = r.get('issue') if isinstance(r, dict) else None
    if not iss:
        print('FAIL', p, str(r)[:150]); continue
    with open(T + 'plan19-%s.jsonl' % p, 'w') as f:
        f.write(json.dumps({'kind': 'security', 'umbrella': {'id': iss['id'], 'number': iss['number'], 'slug': p}, 'area': 'Live security findings', 'note': '', 'children': kids}) + '\n')
    print('live security ticket', p, iss['number'], len(kids), flush=True)
