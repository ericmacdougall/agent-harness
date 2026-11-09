"""Step 3: merge my own area umbrellas into ONE hub per project. 'Live work:' and 'Live security findings' tickets stay (they hold the verbatim quotes).
My umbrellas = open tickets with a cleanup-2026-11* or umbrella label, or titles starting Area:/Umbrella (cleanup/Merged, awaiting/On dev, awaiting/Lane mirrors ended, that are NOT live-work-combined.
usage: mkhub.py [--create] -> plan20-<project>.jsonl for consol17 (originals close as duplicates of the hub)"""
import sys, json, time, uuid, collections
T = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/'
sys.path.insert(0, T)
import gq
R = [json.loads(l) for l in open(T + 'open_now10.jsonl')]
closed = set()
for f in ('done16.jsonl', 'done17.jsonl'):
    try:
        for l in open(T + f):
            j = json.loads(l)
            if j['result'] == 'closed':
                closed.add(j['id'])
    except FileNotFoundError:
        pass
mine = collections.defaultdict(list)
for r in R:
    if r['id'] in closed:
        continue
    t = r['title'].lower()
    labs = [l.lower() for l in r['labels']]
    if 'live-work-combined' in labs or t.startswith(('live work:', 'live security', 'live hub')):
        continue
    ours = t.startswith(('area:', 'umbrella (cleanup', 'merged, awaiting', 'on dev, awaiting', 'lane mirrors ended')) or (r['type'] == 'epic' and any(l.startswith('cleanup-2026-11') for l in labs))
    if ours and r['_org'] in ('framebright', 'eric'):
        mine[r['_proj']].append(r)
print({p: len(v) for p, v in mine.items()}, 'total', sum(len(v) for v in mine.values()), flush=True)
if '--create' not in sys.argv:
    sys.exit(0)
projects = {p['slug']: p for p in json.load(open(T + 'projects.json'))}
for p, lst in mine.items():
    if len(lst) < 2:
        continue
    kids = []
    for r in sorted(lst, key=lambda x: x['number']):
        d = gq.call('get_issue', {'issueId': r['id']})['issue']
        kids.append({'id': r['id'], 'n': r['number'], 'status': d['status'], 'rev': d['revision'], 'title': d['title'], 'proj': r['_org'] + '/' + p, 'owner': '-', 'pr': '-', 'upd': d.get('updatedAt', ''), 'active': False,
                     'comments': [{'at': d.get('updatedAt', '')[:10], 'body': 'umbrella description (verbatim): ' + (d.get('description') or '')[:600] + ' | the checklist rows of its members stay in the comments of #%d, which remains readable (closed as a duplicate of the hub).' % r['number']}]})
    P = projects[p]
    desc = 'LIVE hub for %s (goodqa#14977, %s). It replaces %d cleanup umbrellas and area tickets (state-keeping lists of tickets merged during the 2026-11 cleanup). Each umbrella is a row below with its link, state and description. Their member checklists stay in the comments of the closed umbrellas. The Live work and Live security tickets of this project remain separate and open.' % (p, time.strftime('%Y-%m-%d', time.gmtime()), len(kids))
    r = gq.call('create_issue', dict(orgId=P['orgId'], projectId=P['id'], title='Live hub: cleanup areas [%s]' % p, description=desc, type='task', priority='medium', labels=['live-work-combined', 'live-hub', 'cleanup-2026-11k'], operationId=str(uuid.uuid5(uuid.NAMESPACE_URL, 'hub20|%s' % p))))
    iss = r.get('issue') if isinstance(r, dict) else None
    if not iss:
        print('FAIL', p, str(r)[:150]); continue
    with open(T + 'plan20-%s.jsonl' % p, 'w') as f:
        f.write(json.dumps({'kind': 'hub', 'umbrella': {'id': iss['id'], 'number': iss['number'], 'slug': p}, 'area': 'cleanup areas', 'note': '', 'children': kids}) + '\n')
    print('hub', p, iss['number'], len(kids), flush=True)
