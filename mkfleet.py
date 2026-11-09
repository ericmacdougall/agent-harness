"""Combine the 68 open 'Fleet liveness:' bot tickets (closed on 11-08, reopened by the liveness bot on 11-09) into ONE live ticket. Rows quote the title and every recent comment the bot patterns do not classify, verbatim.
The bot re-opens tickets by idempotency key, so a duplicate close may be reopened again; that is recorded on the live ticket. usage: mkfleet.py [--create] -> plan21-goodqa.jsonl for consol15-style closer (consol18)"""
import sys, json, time, uuid, datetime as D
from concurrent.futures import ThreadPoolExecutor
T = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/'
H = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/harness-delivery/.claude/worktrees/agent-ab8a7d1bf54ed3c9a/'
sys.path.insert(0, T)
sys.path.insert(0, H)
import gq, patterns
c14 = (D.datetime.now(D.timezone.utc) - D.timedelta(days=14)).isoformat()
R = [json.loads(l) for l in open(T + 'open_now11.jsonl')]
fl = [r for r in R if r['_proj'] == 'goodqa' and r['title'].lower().startswith('fleet liveness') and r['type'] != 'epic']
print('fleet liveness tickets:', len(fl), flush=True)


def grab(r):
    c = gq.call('get_issue_comments', {'issueId': r['id']})
    out = [{'at': x.get('createdAt', ''), 'body': (x.get('body') or '')[:1500]} for x in c.get('comments', []) if x.get('kind', 'comment') != 'system' and x.get('createdAt', '') >= c14 and patterns.classify(x.get('body') or '') is None and 'cleanup-2026-11' not in (x.get('body') or '')]
    return out


with ThreadPoolExecutor(4) as ex:
    res = list(ex.map(grab, fl))
print('with unclassified recent comments:', sum(1 for x in res if x), flush=True)
if '--create' not in sys.argv:
    sys.exit(0)
P = {p['slug']: p for p in json.load(open(T + 'projects.json'))}['goodqa']
kids = [{'id': r['id'], 'n': r['number'], 'status': r['status'], 'rev': r['revision'], 'title': r['title'], 'proj': r['_org'] + '/goodqa', 'owner': '-', 'pr': '-', 'upd': r['updatedAt'], 'active': False, 'comments': cs} for r, cs in zip(sorted(fl, key=lambda x: -x['number']), [res[fl.index(r)] for r in sorted(fl, key=lambda x: -x['number'])])]
desc = 'LIVE ticket for the fleet liveness alerts (goodqa#14977, %s). It combines %d "Fleet liveness: ... failed" tickets that the liveness bot files per failing unit. They were closed on 2026-11-08 and the bot REOPENED them on 2026-11-09 (it matches by idempotency key). Each alert is a checklist row below with its title and any comment that was not bot output, verbatim. The originals are closed as duplicates of this ticket. If the bot reopens them again, the bot should append here instead of reopening: that is the regrowth defect to fix.' % (time.strftime('%Y-%m-%d', time.gmtime()), len(kids))
r = gq.call('create_issue', dict(orgId=P['orgId'], projectId=P['id'], title='Live: fleet liveness alerts (combined)', description=desc, type='task', priority='medium', labels=['live-work-combined', 'fleet-liveness', 'cleanup-2026-11l'], operationId=str(uuid.uuid5(uuid.NAMESPACE_URL, 'fleet21|goodqa'))))
iss = r.get('issue') if isinstance(r, dict) else None
if not iss:
    print('FAIL', str(r)[:200]); sys.exit(1)
with open(T + 'plan21-goodqa.jsonl', 'w') as f:
    f.write(json.dumps({'kind': 'combine', 'umbrella': {'id': iss['id'], 'number': iss['number'], 'slug': 'goodqa'}, 'area': 'Fleet liveness alerts', 'note': '', 'children': kids}) + '\n')
print('live ticket', iss['number'], len(kids))
