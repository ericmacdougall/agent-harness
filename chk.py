import sys, json
T = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/'
sys.path.insert(0, T)
import gq
j = [json.loads(l) for l in open(T + 'done5.jsonl')]
c = [x for x in j if x['result'] == 'closed'][0]
d = gq.call('get_issue', {'issueId': c['id']})['issue']
print(d['number'], d['status'], d['title'][:60])
r = gq.call('get_issue_comments', {'issueId': c['id']})
print(r['comments'][-1]['body'][:400])
