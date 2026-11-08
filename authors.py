import sys, json, collections, datetime as D
T = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/'
sys.path.insert(0, T)
import gq
cut = (D.datetime.now(D.timezone.utc) - D.timedelta(days=14)).isoformat()
sk = [json.loads(l) for l in open(T + 'done7.jsonl')]
sk = [j for j in sk if j.get('why') == 'recent-comment-14d']
c = collections.Counter()
ex = {}
for j in sk:
    r = gq.call('get_issue_comments', {'issueId': j['id']})
    for x in r.get('comments', []):
        if x.get('createdAt', '') >= cut:
            k = (x.get('authorId'), x.get('kind'), json.dumps(x.get('metadata'))[:80])
            c[k] += 1
            ex[k] = (x.get('body') or '')[:100].replace('\n', ' ')
for k, v in c.most_common():
    print(v, k, '|', ex[k])
