"""Plan 'Merged, awaiting live proof: <area>' umbrellas. Candidates: open tickets with a merged PR (join6) and no live record,
status triage/backlog/todo/in_review/on_dev, no epic/named-keep/active-agent/human-owner protection, type not epic, no recent non-pattern comment.
usage: mkplan9.py [--create] [--project goodqa|parent-proof|work-tracker-automatic]"""
import json, sys, re, time, uuid, collections, datetime as D
T = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/'
sys.path.insert(0, T)
sys.path.insert(0, '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/harness-delivery/.claude/worktrees/agent-ab8a7d1bf54ed3c9a')
import gq
import patterns
CREATE = '--create' in sys.argv
proj = sys.argv[sys.argv.index('--project') + 1] if '--project' in sys.argv else 'goodqa'
J = json.load(open(T + 'join6.json'))
O = json.load(open(T + 'classes5.json'))
projects = {p['slug']: p for p in json.load(open(T + 'projects.json'))}
BLOCK = {'epic', 'named-keep', 'named-keep-pp', 'active-agent', 'human-owner', 'do-not-touch', 'hold'}
cut = (D.datetime.now(D.timezone.utc) - D.timedelta(days=14)).isoformat()
done = set()
for f in ('done5.jsonl', 'done7.jsonl', 'done8.jsonl', 'done9.jsonl'):
    try:
        for l in open(T + f):
            j = json.loads(l)
            if j['result'] == 'closed' and j.get('to') != 'done':
                done.add(j['id'])
    except FileNotFoundError:
        pass
cand = []
for o in O:
    if o['proj'].split('/')[1] != proj or o['id'] in done or o['type'] == 'epic':
        continue
    k = proj + '#' + str(o['n'])
    if k not in J['merged'] or set(o['prot']) & BLOCK or o['status'] not in ('triage', 'backlog', 'todo', 'in_review', 'on_dev'):
        continue
    cand.append((o, k))
print(proj, 'candidates (merged PR, unblocked):', len(cand))
ok, skipped = [], collections.Counter()
for o, k in cand:
    r = gq.call('get_issue_comments', {'issueId': o['id']})
    recent = [c for c in r.get('comments', []) if c.get('createdAt', '') >= cut and c.get('kind', 'comment') != 'system' and 'cleanup-2026-11' not in (c.get('body') or '')]
    if any(patterns.classify(c.get('body') or '') is None for c in recent):
        skipped['recent-non-pattern-comment'] += 1
        continue
    ok.append((o, k))
print('after comment guard:', len(ok), dict(skipped))
STOP = set('the and for with from that this when into does not are was has have its all any new via per user users page pages issue issues ticket tickets after before without while only but out can use used using test tests'.split())


def area(o):
    for l in o['labels']:
        if l in ('harness', 'ui', 'ux', 'desktop', 'bugtracker', 'optinrouter', 'datasuite', 'qac', 'hawkeye', 'fabric', 'android', 'ios', 'windows', 'macos', 'security'):
            return l
    t = re.sub(r'^(\[[^\]]*\]\s*)+', '', o['title'].lower())
    w = [x for x in re.findall(r'[a-z]{4,}', t) if x not in STOP]
    return ' '.join(w[:2]) if len(w) >= 2 else 'other'


groups = collections.defaultdict(list)
for o, k in ok:
    groups[area(o)].append((o, k))
big = {a: l for a, l in groups.items() if len(l) >= 4 and a != 'other'}
rest = [x for a, l in groups.items() if a not in big for x in l]
if rest:
    big['mixed (small areas)'] = rest
print('areas:', {a: len(l) for a, l in sorted(big.items(), key=lambda x: -len(x[1]))})
if not CREATE:
    sys.exit(0)
P = projects[proj]
out = []
for a, lst in big.items():
    lst.sort(key=lambda x: -x[0]['n'])
    for part in range(0, len(lst), 150):
        chunk = lst[part:part + 150]
        title = 'Merged, awaiting live proof: %s [%s] (batch 2)%s' % (a, proj, '' if len(lst) <= 150 else ' part %d' % (part // 150 + 1))
        lines = ['%d tickets whose fix has a merged PR but no deploy or live record yet (goodqa#14977 under-300 push, %s). They are NOT done. Each child keeps its state in this list and can be reopened from the cleanup snapshot.' % (len(chunk), time.strftime('%Y-%m-%d', time.gmtime())), '']
        for o, k in chunk:
            lines.append('- #%d [%s] %s | merged: %s | live proof: none recorded%s' % (o['n'], o['status'], o['title'][:110], ', '.join(sorted(set(J['merged'][k]))[:3]), ' | REALLY_TESTED: ' + str(sorted(set(J['rt'][k]))[0]) if k in J['rt'] else ''))
        r = gq.call('create_issue', dict(orgId=P['orgId'], projectId=P['id'], title=title, description='\n'.join(lines)[:49000], type='epic', labels=['umbrella', 'cleanup-2026-11d', 'keep-open', 'awaiting-live-proof'], operationId=str(uuid.uuid5(uuid.NAMESPACE_URL, 'umb9b|%s|%s|%d' % (proj, a, part)))))
        iss = r.get('issue') if isinstance(r, dict) else None
        if not iss:
            print('UMBRELLA FAIL', a, str(r)[:150]); continue
        out.append({'kind': 'awaiting-live', 'umbrella': {'id': iss['id'], 'number': iss['number'], 'slug': proj}, 'note': '',
                    'children': [{'id': o['id'], 'n': o['n'], 'status': o['status'], 'rev': o['rev'], 'title': o['title'], 'proj': o['proj']} for o, k in chunk]})
with open(T + 'plan9-%s.jsonl' % proj, 'w') as f:
    for g in out:
        f.write(json.dumps(g) + '\n')
print('umbrellas', len(out), 'children', sum(len(g['children']) for g in out))
