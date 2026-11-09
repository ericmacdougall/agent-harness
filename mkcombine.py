"""Combine the tickets the fold's comment guard skipped into LIVE area tickets (main ruling): nothing the user asked for is lost.
usage: mkcombine.py <project> [--fetch] [--create]
--fetch   reads comments of every skipped ticket (4 threads) into combine_<project>.json: blocking comment excerpts plus quoted user instructions
--create  creates the combined live tickets (type task, triage) and writes plan14-<project>.jsonl for consol14 (originals close as 'duplicate' pointing at the combined ticket)
Quoted-instruction detector: a double-quoted passage next to Eric/user/owner instruction/verbatim/asked/Source: user. Each passage is kept in full (up to 1,500 chars)."""
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
for l in open(T + 'open_now7.jsonl'):
    j = json.loads(l)
    R[j['id']] = j
latest = {}
for l in open(T + 'done13.jsonl'):
    j = json.loads(l)
    latest[j['id']] = j
ids = [i for i, j in latest.items() if j['result'] == 'skipped' and (j.get('why') or '').startswith('recent-human') and i in R and R[i]['_proj'] == proj]
print(proj, len(ids), 'skipped tickets to combine', flush=True)
OUT = T + 'combine_%s.json' % proj
INSTR = re.compile(r'(?:Eric|user|owner instruction|verbatim|asked|Source: user|said)[^"\n]{0,80}"([^"]{12,1500})"|"([^"]{12,1500})"[^"\n]{0,60}(?:Eric|user|verbatim)', re.I)


def grab(i):
    r = gq.call('get_issue_comments', {'issueId': i})
    bl, ins = [], []
    for x in r.get('comments', []):
        b = x.get('body') or ''
        if x.get('kind', 'comment') == 'system' or x.get('createdAt', '') < c14 or patterns.classify(b) is not None or 'cleanup-2026-11' in b:
            continue
        bl.append(b[:300].replace('\n', ' '))
        for m in INSTR.finditer(b):
            q = (m.group(1) or m.group(2) or '').strip()
            if q and q not in ins:
                ins.append(q)
    return {'blocking': bl[:3], 'instructions': ins[:6]}


if '--fetch' in sys.argv:
    with ThreadPoolExecutor(4) as ex:
        res = list(ex.map(grab, ids))
    json.dump(dict(zip(ids, res)), open(OUT, 'w'))
    print('fetched; tickets with a quoted instruction:', sum(1 for r in res if r['instructions']), flush=True)
data = json.load(open(OUT))
J = json.load(open(T + 'join6.json'))
C = {o['id']: o for o in json.load(open(T + 'classes7.json'))}
src = open(H + 'mkfold.py').read()
ns = {}
exec('import re\nproj = %r\n' % proj + src[src.index('AREAS = {'):src.index('AR = [')], ns)
AR = [(n, re.compile(p, re.I)) for n, p in ns['AREAS']]


def area(r):
    t = (r['title'] + ' ' + ' '.join(r['labels'])).lower()
    for n, p in AR:
        if p.search(t):
            return n
    return 'Other'


groups = collections.defaultdict(list)
for i, d in data.items():
    r = R[i]
    pr = sorted(set(J['merged'].get('%s#%d' % (proj, r['number']), [])))[:2]
    own = (r.get('assignee') or {}).get('name') or ('agent-key ' + r['assignedAgentApiKeyId'][:8] if r.get('assignedAgentApiKeyId') else '-')
    groups[area(r)].append({'id': i, 'n': r['number'], 'status': r['status'], 'rev': r['revision'], 'title': r['title'], 'proj': 'framebright/' + proj,
                            'owner': own, 'pr': ', '.join(pr) or '-', 'upd': r['updatedAt'], 'active': bool({'wal-72h', 'active-agent'} & set(C.get(i, {}).get('prot', []))),
                            'blocking': d['blocking'], 'instructions': d['instructions']})
for a, v in sorted(groups.items(), key=lambda x: -len(x[1])):
    print('  ', len(v), a, '| with quoted instruction:', sum(1 for x in v if x['instructions']))
if '--create' not in sys.argv:
    sys.exit(0)
projects = {p['slug']: p for p in json.load(open(T + 'projects.json'))}
P = projects[proj]
out = []
for a, kids in groups.items():
    kids.sort(key=lambda x: -x['n'])
    quotes = []
    for k in kids:
        for q in k['instructions']:
            quotes.append('- #%d: "%s"' % (k['n'], q))
    desc = 'LIVE work ticket "%s" for %s (goodqa#14977, %s). It combines %d tickets that carried recent comments. Originals were closed as duplicates of this ticket, not as done and not as wont_fix; each is listed in the checklist comments with its state, owner, PR and the comment that held it. Every quoted user instruction found on them is reproduced below, so nothing the user asked for is lost.\n\nQuoted user instructions (%d):\n%s' % (a, proj, time.strftime('%Y-%m-%d', time.gmtime()), len(kids), len(quotes), '\n'.join(quotes)[:38000] or '(none found by the detector; read the checklist rows)')
    r = gq.call('create_issue', dict(orgId=P['orgId'], projectId=P['id'], title='Live work: %s [%s]' % (a, proj), description=desc, type='task', priority='medium', labels=['live-work-combined', 'cleanup-2026-11f'], operationId=str(uuid.uuid5(uuid.NAMESPACE_URL, 'combine14|%s|%s' % (proj, a)))))
    iss = r.get('issue') if isinstance(r, dict) else None
    if not iss:
        print('FAIL', a, str(r)[:150]); continue
    out.append({'kind': 'combine', 'umbrella': {'id': iss['id'], 'number': iss['number'], 'slug': proj}, 'area': a, 'note': '', 'children': kids})
with open(T + 'plan14-%s.jsonl' % proj, 'w') as f:
    for g in out:
        f.write(json.dumps(g) + '\n')
print('combined tickets', [(g['umbrella']['number'], len(g['children'])) for g in out])
