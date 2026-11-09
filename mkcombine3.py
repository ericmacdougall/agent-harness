"""Combine the tickets the fold's comment guard skipped into LIVE area tickets, quoting EVERY unmatched recent comment verbatim with its ticket number and date (main ruling).
usage: mkcombine2.py <project> [--create]   -> plan16-<project>.jsonl (for consol15). Originals close as duplicates of the live ticket.
Reuses the live ticket of the same area when plan14-<project>.jsonl has one; otherwise creates 'Live work: <area> [<project>]' (task, triage)."""
import sys, json, re, time, uuid, collections, datetime as D
from concurrent.futures import ThreadPoolExecutor
T = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/'
H = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/harness-delivery/.claude/worktrees/agent-ab8a7d1bf54ed3c9a/'
sys.path.insert(0, T)
sys.path.insert(0, H)
import gq, patterns
proj = sys.argv[1]
c14 = (D.datetime.now(D.timezone.utc) - D.timedelta(days=14)).isoformat()
R = {}
for l in open(T + 'open_now9.jsonl'):
    j = json.loads(l)
    R[j['id']] = j
closed = set()
for f in ('done13.jsonl', 'done14.jsonl', 'done15.jsonl'):
    try:
        for l in open(T + f):
            j = json.loads(l)
            if j['result'] == 'closed':
                closed.add(j['id'])
    except FileNotFoundError:
        pass
latest = {}
for l in open(T + 'done13.jsonl'):
    j = json.loads(l)
    latest[j['id']] = j
ids = [i for i, j in latest.items() if j['result'] == 'skipped' and (j.get('why') or '').startswith('recent-human') and i in R and R[i]['_proj'] == proj and i not in closed]
print(proj, len(ids), 'guard-skipped tickets to combine', flush=True)
OUT = T + 'combine3_%s.json' % proj


def grab(i):
    r = gq.call('get_issue_comments', {'issueId': i})
    out = []
    for x in r.get('comments', []):
        b = x.get('body') or ''
        if x.get('kind', 'comment') == 'system' or x.get('createdAt', '') < c14 or patterns.classify(b) is not None or 'cleanup-2026-11' in b:
            continue
        out.append({'at': x.get('createdAt', ''), 'body': b[:2500]})
    return out


with ThreadPoolExecutor(4) as ex:
    res = list(ex.map(grab, ids))
data = dict(zip(ids, res))
json.dump(data, open(OUT, 'w'))
print('with comments to quote:', sum(1 for v in res if v), 'comments:', sum(len(v) for v in res), flush=True)
J = json.load(open(T + 'join6.json'))
C = {o['id']: o for o in json.load(open(T + 'classes9.json'))}
src = open(H + 'mkfold.py').read()
ns = {}
exec('import re\nproj = %r\n' % proj + src[src.index('AREAS = {'):src.index('AR = [')], ns)
AR = [(n, re.compile(p, re.I)) for n, p in ns['AREAS']]
if proj == 'work-tracker-automatic':
    AR = [(n, re.compile(p, re.I)) for n, p in [('Lane mirrors and lane work', r'^\[lane\]|lane'), ('Console, takeover and hosts', r'\[console\]|takeover|console|host|dev2|t2-dev'), ('System design and other work-tracker items', r'.')]]


def area(r):
    t = (r['title'] + ' ' + ' '.join(r['labels'])).lower()
    for n, p in AR:
        if p.search(t):
            return n
    return 'Other'


groups = collections.defaultdict(list)
for i, cs in data.items():
    r = R[i]
    pr = sorted(set(J['merged'].get('%s#%d' % (proj, r['number']), [])))[:2]
    own = (r.get('assignee') or {}).get('name') or ('agent-key ' + r['assignedAgentApiKeyId'][:8] if r.get('assignedAgentApiKeyId') else '-')
    groups[area(r)].append({'id': i, 'n': r['number'], 'status': r['status'], 'rev': r['revision'], 'title': r['title'], 'proj': 'framebright/' + proj if proj in ('goodqa', 'parent-proof', 'work-tracker-automatic') else r['_org'] + '/' + proj,
                            'owner': own, 'pr': ', '.join(pr) or '-', 'upd': r['updatedAt'], 'active': bool({'wal-72h', 'active-agent'} & set(C.get(i, {}).get('prot', []))), 'comments': cs})
for a, v in sorted(groups.items(), key=lambda x: -len(x[1])):
    print('  ', len(v), a)
if '--create' not in sys.argv:
    sys.exit(0)
projects = {p['slug']: p for p in json.load(open(T + 'projects.json'))}
P = projects[proj]
existing = {}
try:
    for l in open(T + 'plan14-%s.jsonl' % proj):
        g0 = json.loads(l)
        existing[g0['area']] = g0['umbrella']
except FileNotFoundError:
    pass
out = []
for a, kids in groups.items():
    kids.sort(key=lambda x: -x['n'])
    if a in existing:
        U = existing[a]
    else:
        desc = 'LIVE work ticket "%s" for %s (goodqa#14977, %s). It combines %d tickets that carried a recent comment the automation patterns could not classify. Originals were closed as duplicates of this ticket (not done, not wont_fix). Every such comment is quoted VERBATIM in the checklist comments with its ticket number and date, together with the original title, state, owner, PR and last activity, so nothing a person said is lost.' % (a, proj, time.strftime('%Y-%m-%d', time.gmtime()), len(kids))
        r = gq.call('create_issue', dict(orgId=P['orgId'], projectId=P['id'], title='Live work: %s [%s]' % (a, proj), description=desc, type='task', priority='medium', labels=['live-work-combined', 'cleanup-2026-11i'], operationId=str(uuid.uuid5(uuid.NAMESPACE_URL, 'combine16|%s|%s' % (proj, a)))))
        iss = r.get('issue') if isinstance(r, dict) else None
        if not iss:
            print('FAIL', a, str(r)[:150]); continue
        U = {'id': iss['id'], 'number': iss['number'], 'slug': proj}
    out.append({'kind': 'combine', 'umbrella': U, 'area': a, 'note': '', 'children': kids})
with open(T + 'plan18-%s.jsonl' % proj, 'w') as f:
    for g in out:
        f.write(json.dumps(g) + '\n')
print('live tickets', [(g['umbrella']['number'], len(g['children'])) for g in out], flush=True)
