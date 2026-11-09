"""Split a big area umbrella into sub-umbrellas by re-parenting checklist rows (no ticket is reopened). usage: mksplit.py <umbrella-number> [--create]
Reads plan13-goodqa.jsonl and done13.jsonl; classifies the CLOSED children of that umbrella into sub-areas, creates the sub-umbrellas (parent = the big umbrella),
posts the rows there (20 per comment), and posts a pointer comment on the big umbrella. Children keep their 'merged into umbrella #N' close note; the pointer explains where each row moved."""
import json, sys, re, time, uuid, hashlib, collections
T = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/'
sys.path.insert(0, T)
import gq
num = int(sys.argv[1])
CREATE = '--create' in sys.argv
plan = [json.loads(l) for l in open(T + 'plan13-goodqa.jsonl')]
grp = [g for g in plan if g['umbrella']['number'] == num][0]
closed = {}
for l in open(T + 'done13.jsonl'):
    j = json.loads(l)
    if j['result'] == 'closed' and j['umb'] == num:
        closed[j['id']] = j
kids = [c for c in grp['children'] if c['id'] in closed]
SUB = [
    ('Lane mirrors and lane liveness', r'\[lane\]|^lane |lane .*stuck|lane-|liveness|deadman|auto-decider|queue launcher|orphan'),
    ('Fleet hosts, failover and infrastructure', r'fleet|host|dev2|t2-dev|t2\b|proxmox|failover|hot-swap|disk|backup|vm\b|docker|daemon|ssh|netwatch|ops-watch|drain'),
    ('Runner briefs and round tickets', r'-r\d+-|-sol-|-opus-|-astra|runner|brief|round|successor|rescue|pairing|hive|gorunner'),
    ('Hooks, guards, gates and policy', r'hook|guard|gate|policy|merge|review|peer|commit|ban|block|refus|permission|rule|allowlist|denylist'),
    ('Tests, evidence, specs and quality', r'test|evidence|spec|acceptance|coverage|mutant|flak|baseline|assert|verify|proof|click'),
    ('Sessions, WAL, logs, tasks and ledger', r'wal|log|session|ledger|task|transcript|receipt|ticket|status|stale|digest|alert|monitor|queue|state'),
]
SUBS = [(n, re.compile(p, re.I)) for n, p in SUB] + [('Runner, harness policy and misc', re.compile('.'))]
buckets = collections.defaultdict(list)
for c in kids:
    t = c['title']
    for n, p in SUBS:
        if p.search(t):
            buckets[n].append(c); break
print('umbrella', num, grp['area'], 'closed children', len(kids))
for n, v in buckets.items():
    print('  ', len(v), n)
if not CREATE:
    sys.exit(0)
snap = {}
import glob
for f in glob.glob(T + 'snapshots13/snap-*.jsonl'):
    for l in open(f):
        j = json.loads(l)
        snap[j['issue']['id']] = j['issue']['status']
projects = {p['slug']: p for p in json.load(open(T + 'projects.json'))}
P = projects[grp['umbrella']['slug']]
lines_ptr = []
for n, v in buckets.items():
    desc = 'Sub-area "%s" split out of umbrella #%d (%s) on %s, goodqa#14977. %d checklist rows moved here from #%d; no ticket was reopened. Children keep their close note "merged into umbrella #%d". Reopen a child by setting its status back to the state in its row.' % (n, num, grp['area'], time.strftime('%Y-%m-%d', time.gmtime()), len(v), num, num)
    r = gq.call('create_issue', dict(orgId=P['orgId'], projectId=P['id'], title='Area: %s [%s, from #%d]' % (n, grp['umbrella']['slug'], num), description=desc, type='epic', parentId=grp['umbrella']['id'], labels=['umbrella', 'cleanup-2026-11f', 'keep-open'], operationId=str(uuid.uuid5(uuid.NAMESPACE_URL, 'split13|%d|%s' % (num, n)))))
    iss = r.get('issue') if isinstance(r, dict) else None
    if not iss:
        print('FAIL', n, str(r)[:150]); continue
    for k in range(0, len(v), 20):
        blk = v[k:k + 20]
        body = 'Checklist rows moved from #%d (state is the state at merge time):\n\n%s' % (num, '\n'.join('- #%s | %s | state: %s | owner: %s | PR: %s | last activity: %s%s' % (c['n'], c['title'][:140].replace('|', '/'), snap.get(c['id'], c['status']), c['owner'], c['pr'], c['upd'][:16], ' | ACTIVE' if c['active'] else '') for c in blk))
        gq.call('comment_on_issue', {'issueId': iss['id'], 'body': body[:15000], 'operationId': str(uuid.uuid5(uuid.NAMESPACE_URL, 'splitrows13|' + hashlib.sha1(','.join(c['id'] for c in blk).encode()).hexdigest()))})
    lines_ptr.append('- %d rows moved to #%d "%s"' % (len(v), iss['number'], n))
    print('created', iss['number'], n, len(v))
gq.call('comment_on_issue', {'issueId': grp['umbrella']['id'], 'body': 'Split (goodqa#14977, %s): this umbrella held %d checklist rows, too many to work from. The rows were re-parented to sub-umbrellas (each is a child of this ticket). The earlier ledger comments here remain as the record at merge time.\n\n%s' % (time.strftime('%Y-%m-%d', time.gmtime()), len(kids), '\n'.join(lines_ptr)), 'operationId': str(uuid.uuid4())})
print('DONE')
