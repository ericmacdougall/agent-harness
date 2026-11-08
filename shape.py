import sys, json
T = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/'
sys.path.insert(0, T)
import gq
E = json.load(open(T + 'elig4.json'))
o = [x for x in E if (x['cc'] or 0) > 1][0]
d = gq.call('get_issue', {'issueId': o['id']})
print(list(d.keys())[:20]); i = d.get('issue', d); print({k: str(v)[:40] for k, v in i.items()})
c = gq.call('get_issue_comments', {'issueId': o['id']})
print(list(c.keys())); print(json.dumps(c['comments'][0])[:500])
