import sys, json, collections, datetime as D, re
T = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/'
sys.path.insert(0, T)
import gq
cut = (D.datetime.now(D.timezone.utc) - D.timedelta(days=14)).isoformat()
sk = [json.loads(l) for l in open(T + 'done7.jsonl')]
sk = [j for j in sk if j.get('why') == 'recent-comment-14d']
out = {}
for j in sk:
    r = gq.call('get_issue_comments', {'issueId': j['id']})
    out[j['id']] = [{'at': x['createdAt'], 'author': x.get('authorId'), 'kind': x.get('kind'), 'body': x.get('body') or ''} for x in r.get('comments', []) if x.get('createdAt', '') >= cut and x.get('kind', 'comment') != 'system']
json.dump(out, open(T + 'recent_bodies7.json', 'w'))
c = collections.Counter()
for i, cs in out.items():
    for x in cs:
        c[re.sub(r'[0-9a-f]{7,}|\d+', 'N', x['body'][:50])] += 1
print(len(out), 'tickets', sum(len(v) for v in out.values()), 'comments')
for k, v in c.most_common(40):
    print(v, repr(k))
