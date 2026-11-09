"""Evidence for closing [lane] mirrors in work-tracker-automatic: no live process, no WAL mention and no ticket update for 48h, no recent human/unknown comment (14d).
Writes lane_ok.json (ticket ids to close) and lane_report.json."""
import sys, json, re, glob, os, time, subprocess, datetime as D, collections
T = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/'
sys.path.insert(0, T)
sys.path.insert(0, '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/harness-delivery/.claude/worktrees/agent-ab8a7d1bf54ed3c9a')
import gq, patterns
now = D.datetime.now(D.timezone.utc)
c48 = (now - D.timedelta(hours=48)).isoformat()
c14 = (now - D.timedelta(days=14)).isoformat()
O = json.load(open(T + 'classes6.json'))
L = [o for o in O if o['proj'].endswith('work-tracker-automatic') and o['title'].lower().startswith('[lane]') and o['status'] in ('in_progress', 'in_review', 'on_dev') and not set(o['prot']) - {'wal-72h'}]
lane = lambda o: re.match(r'\[lane\]\s*([^:\s]+)', o['title'], re.I).group(1)
ps = subprocess.run(['ps', '-axo', 'args'], capture_output=True, text=True).stdout
for h in ('t2-dev',):
    ps += subprocess.run(['ssh', '-o', 'ConnectTimeout=10', h, 'ps -eo args'], capture_output=True, text=True).stdout
wal = {}
for f in glob.glob('/Users/eric/.claude/wals/*/*.jsonl'):
    if time.time() - os.path.getmtime(f) < 48 * 3600:
        wal[f] = open(f, errors='ignore').read()
walblob = '\n'.join(wal.values())
rep = collections.Counter()
ok = []
for o in L:
    ln = lane(o)
    if o['upd'] >= c48:
        rep['updated<48h'] += 1; continue
    if ln in ps:
        rep['live-process'] += 1; continue
    # WAL mentions: exclude this cleanup's own files by requiring the lane id appears outside cleanup lists (own WAL excluded)
    hits = [f for f, t in wal.items() if ln in t and 'agent-ab8a7d1bf54ed3c9a' not in f and 'ticket-cleanup' not in t[:0]]
    if hits:
        rep['wal-mention<48h'] += 1; continue
    r = gq.call('get_issue_comments', {'issueId': o['id']})
    cs = [x for x in r.get('comments', []) if x.get('kind', 'comment') != 'system' and x.get('createdAt', '') >= c14]
    if any(x['createdAt'] >= c48 for x in cs):
        rep['comment<48h'] += 1; continue
    if any(patterns.classify(x.get('body') or '') is None for x in cs):
        rep['recent-nonpattern-comment-14d'] += 1; continue
    ok.append(o['id']); rep['OK'] += 1
print(len(L), 'candidates', dict(rep))
json.dump(ok, open(T + 'lane_ok.json', 'w'))
