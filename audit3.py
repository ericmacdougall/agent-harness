"""Audit step 3 (read-only, local files + gh search): which tickets closed by my ledgers today are mentioned in a WAL touched in the last 48 h
(other than my own), named in an open PR, or carry spec markers in the comments the closers stored. Writes audit3.json."""
import json, glob, re, os, time, subprocess, collections
T = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/'
OUT = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/harness-delivery/.claude/worktrees/agent-ab8a7d1bf54ed3c9a/audit3.json'
closed = {}
for f in glob.glob(T + 'done*.jsonl'):
    for l in open(f):
        d = json.loads(l)
        if d.get('result') == 'closed':
            closed[d['id']] = dict(n=d['n'], to=d.get('to'), ledger=f.split('/')[-1])
snap = {}
for f in glob.glob(T + 'snapshots*/snap-*.jsonl'):
    for l in open(f):
        j = json.loads(l)
        snap[j['issue']['id']] = j['proj']
key = {}
for i, c in closed.items():
    proj = snap.get(i, '?/?')
    key[(proj.split('/')[-1].lower(), c['n'])] = i
print('closed', len(closed), 'mapped to a project', sum(1 for i in closed if i in snap))
# 1. WAL mentions, last 48 h, excluding my own WAL
cut = time.time() - 48 * 3600
pat = re.compile(r'(?i)\b([a-z][a-z0-9-]*)\s?#(\d{1,6})\b')
mention = collections.defaultdict(set)
nwal = 0
for f in glob.glob('/Users/eric/.claude/wals/*/*.jsonl'):
    if 'agent-ab8a7d1bf54ed3c9a' in f or os.path.getmtime(f) < cut:
        continue
    nwal += 1
    who = f.split('/')[-2][:8] + '/' + f.split('/')[-1][:-6]
    is_agent = '/agent-' in f
    for line in open(f, errors='ignore'):
        ev = ''
        try:
            ev = (json.loads(line).get('event') or '')
        except Exception:
            pass
        work = is_agent and ev in ('intent', 'scope', 'decision', 'result', 'handoff', 'check', 'commit', 'requirement', 'risk', 'blocker')
        for m in pat.finditer(line):
            k = (m.group(1).lower(), int(m.group(2)))
            if k in key:
                mention[k].add(('W:' if work else 'o:') + who)
print('WALs scanned', nwal)
# 2. open PRs naming a ticket
prs = []
try:
    out = subprocess.run(['gh', 'search', 'prs', '--owner', 'ericmacdougall', '--state', 'open', '--limit', '200', '--json', 'repository,number,title,body,url'], capture_output=True, text=True, timeout=120).stdout
    prs = json.loads(out or '[]')
except Exception as e:
    print('gh search failed', e)
prm = collections.defaultdict(list)
for p in prs:
    for m in pat.finditer((p.get('title') or '') + ' ' + (p.get('body') or '')):
        k = (m.group(1).lower(), int(m.group(2)))
        if k in key:
            prm[k].append(p['url'])
print('open PRs scanned', len(prs))
# 3. spec markers in the comments the closers stored
spec = {}
for f in glob.glob(T + 'plan*.jsonl'):
    for l in open(f):
        try:
            g = json.loads(l)
        except Exception:
            continue
        for c in g.get('children', []):
            txt = ' '.join(x.get('body', '') for x in c.get('comments', []))
            if re.search(r'Verify by:|spec_flow|\bAC-\d|NEG-\d', txt):
                spec[c['id']] = f.split('/')[-1]
cand = {}
for k, i in key.items():
    why = []
    if k in mention:
        why.append(('WALwork:' if any(x.startswith('W:') for x in mention[k]) else 'WALother:') + ','.join(sorted(mention[k])[:3]))
    if k in prm:
        why.append('PR:' + prm[k][0])
    if i in spec:
        why.append('spec-marker:' + spec[i])
    if why:
        cand[i] = dict(slug=k[0], n=k[1], proj=snap.get(i), to=closed[i]['to'], ledger=closed[i]['ledger'], why=why)
json.dump(cand, open(OUT, 'w'), indent=1)
print('candidates', len(cand), collections.Counter(v['proj'] for v in cand.values()).most_common(6))
print('by reason', collections.Counter(w.split(':')[0] for v in cand.values() for w in v['why']))
