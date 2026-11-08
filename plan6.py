"""Cluster eligible parentless agent-filed tickets into new umbrellas. usage: plan6.py [--create]  (dry run default)"""
import json, re, sys, os, time, uuid, collections as C
T = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/'
sys.path.insert(0, T)
import gq
CREATE = '--create' in sys.argv
E = json.load(open(T + 'elig4.json'))
O = {o['id']: o for o in json.load(open(T + 'classes4.json'))}
projects = {p['slug']: p for p in json.load(open(T + 'projects.json'))}
done = set()
for l in open(T + 'done5.jsonl'):
    j = json.loads(l)
    if j['result'] == 'closed':
        done.add(j['id'])
STOP = set('the and for with from that this when into does not are was has have its all any new via per user users page pages issue issues ticket tickets after before without while only but out can use used using test tests'.split())


def words(t):
    t = re.sub(r'^(\[[^\]]*\]\s*)+', '', t.lower())
    return [w for w in re.findall(r'[a-z]{4,}', t) if w not in STOP]


def tag(t):
    m = re.match(r'^\[([^\]]{3,30})\]', t)
    return m.group(1).strip().lower() if m else None


elig = [o for o in E if o['id'] not in done and not o['noise'] and not o['proj'].endswith('qac-acceptance-disposable') and (not o['parent'] or o['parent'] not in O)]
byproj = C.defaultdict(list)
for o in elig:
    byproj[o['proj']].append(o)
clusters = C.defaultdict(list)
for proj, lst in byproj.items():
    tags = C.Counter(tag(o['title']) for o in lst if tag(o['title']))
    bg, ug = C.Counter(), C.Counter()
    for o in lst:
        w = words(o['title'])
        for x in set(w):
            ug[x] += 1
        for k in set(zip(w, w[1:])):
            bg[' '.join(k)] += 1
    for o in lst:
        t = tag(o['title'])
        if t and tags[t] >= 4 and t not in ('p0', 'p1', 'p2'):
            key = '[' + t + ']'
        else:
            w = words(o['title'])
            cands = [(bg[' '.join(k)], ' '.join(k)) for k in zip(w, w[1:]) if bg[' '.join(k)] >= 5]
            key = max(cands)[1] if cands else None
            if not key:
                uc = [(ug[x], x) for x in set(w) if ug[x] >= 10]
                key = max(uc)[1] if uc else None
        clusters[(proj, key or 'other')].append(o)
rows = [(proj, key, len(l)) for (proj, key), l in sorted(clusters.items(), key=lambda x: -len(x[1]))]
print('eligible', len(elig), 'clusters', len(clusters))
for r in rows[:30]:
    print(r)
if not CREATE:
    sys.exit(0)


def call(t, a):
    for k in range(25):
        d = gq.call(t, a)
        if isinstance(d, dict) and isinstance(d.get('error'), dict) and d['error'].get('code') == 'rate_limited':
            time.sleep(min(60, 4 * (k + 1)))
            continue
        return d
    return d


out = []
for (proj, key), lst in clusters.items():
    if key == 'other' or len(lst) < 5:
        continue
    org, slug = proj.split('/')
    P = projects[slug]
    lst.sort(key=lambda o: -o['n'])
    for part in range(0, len(lst), 150):
        chunk = lst[part:part + 150]
        title = 'Umbrella (cleanup 2026-11): %s [%s]%s' % (key, slug, '' if len(lst) <= 150 else ' part %d' % (part // 150 + 1))
        desc = 'Umbrella for %d related agent-filed tickets merged by the goodqa#14977 under-300 push on %s. Members and their latest comments are in the ledger comments below; each closed member can be reopened.' % (len(chunk), time.strftime('%Y-%m-%d', time.gmtime()))
        opid = str(uuid.uuid5(uuid.NAMESPACE_URL, 'umbrella6|%s|%s|%d' % (proj, key, part)))
        r = call('create_issue', dict(orgId=P['orgId'], projectId=P['id'], title=title, description=desc, type='epic', labels=['umbrella', 'cleanup-2026-11c', 'keep-open'], operationId=opid))
        iss = r.get('issue') if isinstance(r, dict) else None
        if not iss:
            print('UMBRELLA FAIL', proj, key, str(r)[:200])
            continue
        out.append({'kind': 'cluster', 'umbrella': {'id': iss['id'], 'number': iss['number'], 'slug': slug}, 'note': '',
                    'children': [{'id': o['id'], 'n': o['n'], 'status': o['status'], 'rev': o['rev'], 'title': o['title'], 'proj': o['proj']} for o in chunk]})
with open(T + 'plan6.jsonl', 'w') as f:
    for g in out:
        f.write(json.dumps(g) + '\n')
print('umbrellas', len(out), 'children', sum(len(g['children']) for g in out))
