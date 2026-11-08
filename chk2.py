import sys, json
T = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/'
sys.path.insert(0, T)
import gq
g = json.loads(open(T + 'plan5.jsonl').readlines()[1])
U = g['umbrella']
i = gq.call('get_issue', {'issueId': U['id']})['issue']
print(i['number'], 'commentCount', i['commentCount'], 'was', 'see dump')
r = gq.call('get_issue_comments', {'issueId': U['id'], 'cursor': None})
print(r.keys())
for c in r['comments'][-3:]:
    print(c['createdAt'][:19], (c['body'] or '')[:100].replace('\n', ' '))
nc = r.get('newerCursor') or r.get('nextCursor')
print('cursors', r.get('nextCursor') is not None, r.get('newerCursor') is not None, r.get('olderCursor') is not None)
