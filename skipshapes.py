import sys, json, re, collections, datetime as D
from concurrent.futures import ThreadPoolExecutor
T = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/'
sys.path.insert(0, T)
sys.path.insert(0, '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/harness-delivery/.claude/worktrees/agent-ab8a7d1bf54ed3c9a')
import gq, patterns
c14 = (D.datetime.now(D.timezone.utc) - D.timedelta(days=14)).isoformat()
ids = []
for f in ('done10.jsonl', 'done11.jsonl'):
    for l in open(T + f):
        j = json.loads(l)
        if j.get('why', '').startswith('recent-human'):
            ids.append(j['id'])
ids = list(dict.fromkeys(ids))


def shapes(i):
    r = gq.call('get_issue_comments', {'issueId': i})
    return [(x.get('body') or '') for x in r.get('comments', []) if x.get('kind', 'comment') != 'system' and x.get('createdAt', '') >= c14 and patterns.classify(x.get('body') or '') is None]


with ThreadPoolExecutor(5) as ex:
    res = list(ex.map(shapes, ids))
c = collections.Counter()
ex_ = {}
tick = collections.Counter()
for i, bl in zip(ids, res):
    for b in bl:
        k = re.sub(r'[0-9a-f]{7,}|\d+', 'N', b[:32])
        c[k] += 1
        ex_.setdefault(k, b[:150].replace('\n', ' '))
print(len(ids), 'skipped tickets; blocking-comment shapes:', len(c))
for k, v in c.most_common(30):
    print(v, '|', ex_[k])
