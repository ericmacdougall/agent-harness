import sys, json, re, collections, datetime as D
from concurrent.futures import ThreadPoolExecutor
T = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/'
sys.path.insert(0, T)
sys.path.insert(0, '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/harness-delivery/.claude/worktrees/agent-ab8a7d1bf54ed3c9a')
import gq, patterns
proj = sys.argv[1]
c14 = (D.datetime.now(D.timezone.utc) - D.timedelta(days=14)).isoformat()
ids = []
for l in open(T + 'plan15-%s.jsonl' % proj):
    for c in json.loads(l)['children']:
        ids.append(c['id'])


def grab(i):
    r = gq.call('get_issue_comments', {'issueId': i})
    return [(x.get('body') or '') for x in r.get('comments', []) if x.get('kind', 'comment') != 'system' and x.get('createdAt', '') >= c14 and patterns.classify(x.get('body') or '') is None and 'cleanup-2026-11' not in (x.get('body') or '')]


with ThreadPoolExecutor(3) as ex:
    res = list(ex.map(grab, ids))
json.dump(dict(zip(ids, res)), open(T + 'shapes_%s.json' % proj, 'w'))
shape = collections.Counter(); exs = {}
for bl in res:
    for b in bl:
        k = re.sub(r'[0-9a-f]{7,}|\d+', 'N', b.strip()[:24]); shape[k] += 1; exs.setdefault(k, b.strip()[:130].replace('\n', ' '))
print(len(ids), 'tickets,', sum(1 for r in res if r), 'with unmatched recent comments;', sum(shape.values()), 'comments in', len(shape), 'shapes')
for k, v in shape.most_common(25):
    print(v, '|', exs[k])
