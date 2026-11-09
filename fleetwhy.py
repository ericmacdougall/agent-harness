"""Why did the closed Fleet liveness tickets reopen? Reads events + recent comments of 3 sampled tickets (read-only)."""
import sys, json, collections
T = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/'
sys.path.insert(0, T)
import gq
R = [json.loads(l) for l in open(T + 'open_now11.jsonl')]
fl = sorted([r for r in R if r['_proj'] == 'goodqa' and r['title'].lower().startswith('fleet liveness')], key=lambda x: x['number'])
print(len(fl), 'open')
for r in [fl[0], fl[len(fl) // 2], fl[-1]]:
    print('==', r['number'], r['title'][:80], r['labels'])
    ev = gq.call('get_issue_events', {'issueId': r['id']})
    evs = ev.get('events', ev) if isinstance(ev, dict) else ev
    for e in (evs or [])[-8:]:
        print('  EV', json.dumps(e)[:330])
    c = gq.call('get_issue_comments', {'issueId': r['id']})
    for x in c.get('comments', [])[-3:]:
        print('  CM', x.get('createdAt'), (x.get('author') or {}).get('name') if isinstance(x.get('author'), dict) else x.get('author'), (x.get('body') or '')[:300].replace('\n', ' / '))
