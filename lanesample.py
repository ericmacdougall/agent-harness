import sys, json, re, random, datetime as D, collections
T = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/'
sys.path.insert(0, T)
sys.path.insert(0, '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/harness-delivery/.claude/worktrees/agent-ab8a7d1bf54ed3c9a')
import gq, patterns
c14 = (D.datetime.now(D.timezone.utc) - D.timedelta(days=14)).isoformat()
O = json.load(open(T + 'classes6.json'))
L = [o for o in O if o['proj'].endswith('work-tracker-automatic') and o['title'].lower().startswith('[lane]') and o['status'] in ('in_progress', 'in_review', 'on_dev') and not set(o['prot']) - {'wal-72h'}]
lane_ok = set(json.load(open(T + 'lane_ok.json')))
cand = [o for o in L if o['upd'] < (D.datetime.now(D.timezone.utc) - D.timedelta(hours=48)).isoformat() and o['id'] not in lane_ok]
shapes = collections.Counter()
ex = {}
for o in cand:
    r = gq.call('get_issue_comments', {'issueId': o['id']})
    for x in r.get('comments', []):
        if x.get('kind', 'comment') != 'system' and x.get('createdAt', '') >= c14 and patterns.classify(x.get('body') or '') is None:
            k = re.sub(r'[0-9a-f]{7,}|\d+', 'N', (x.get('body') or '')[:40])
            shapes[k] += 1
            ex.setdefault(k, (x.get('authorId'), (x.get('body') or '')[:160].replace('\n', ' ')))
print(len(cand), 'candidates; distinct unmatched comment shapes:', len(shapes))
for k, v in shapes.most_common(25):
    print(v, ex[k])
