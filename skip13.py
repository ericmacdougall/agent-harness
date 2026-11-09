import sys, json, re, collections, datetime as D
from concurrent.futures import ThreadPoolExecutor
T = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/'
sys.path.insert(0, T)
sys.path.insert(0, '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/harness-delivery/.claude/worktrees/agent-ab8a7d1bf54ed3c9a')
import gq, patterns
c14 = (D.datetime.now(D.timezone.utc) - D.timedelta(days=14)).isoformat()
ids = []
for l in open(T + 'done13.jsonl'):
    j = json.loads(l)
    if (j.get('why') or '').startswith('recent-human'):
        ids.append(j['id'])
ids = list(dict.fromkeys(ids))
print(len(ids), 'skipped tickets', flush=True)


def blocking(i):
    r = gq.call('get_issue_comments', {'issueId': i})
    return [(x.get('body') or '') for x in r.get('comments', []) if x.get('kind', 'comment') != 'system' and x.get('createdAt', '') >= c14 and patterns.classify(x.get('body') or '') is None]


with ThreadPoolExecutor(4) as ex:
    res = list(ex.map(blocking, ids))
json.dump(dict(zip(ids, res)), open(T + 'skip13_bodies.json', 'w'))
shape = collections.Counter()
exs = {}
for bl in res:
    for b in bl:
        k = re.sub(r'[0-9a-f]{7,}|\d+', 'N', b.strip()[:26])
        shape[k] += 1
        exs.setdefault(k, b.strip()[:140].replace('\n', ' '))
print(len(shape), 'distinct blocking shapes over', sum(shape.values()), 'comments')
for k, v in shape.most_common(45):
    print(v, '|', exs[k])
