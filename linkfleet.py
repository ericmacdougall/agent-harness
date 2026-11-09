"""POST a `duplicates` link alert -> live ticket for alerts in plan21-goodqa.jsonl (usage: linkfleet.py [--only N ...]). 409 = exists. Idempotent.
The liveness bot follows `duplicates` links to the open canonical ticket instead of reopening a duplicate-closed alert."""
import sys, json, time
T = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/'
sys.path.insert(0, T)
import gq
plan = json.loads(open(T + 'plan21-goodqa.jsonl').readline())
live = plan['umbrella']['id']
only = {int(x) for x in sys.argv[sys.argv.index('--only') + 1:]} if '--only' in sys.argv else None
done = fail = 0
for c in plan['children']:
    if only and c['n'] not in only:
        continue
    w = 60
    for _ in range(7):
        r = gq.call('call_api', dict(method='POST', path='/issues/%s/links' % c['id'], body={'relatedIssueId': live, 'kind': 'duplicates'}))
        e = r.get('error') if isinstance(r, dict) else None
        if e and e.get('code') in ('rate_limited', 'user_token_rate_limited'):
            time.sleep(w); w *= 2; continue
        break
    msg = json.dumps(r)[:160]
    if e and '409' not in msg and e.get('code') not in ('conflict', 'already_exists'):
        fail += 1
        print('FAIL', c['n'], msg, flush=True)
    else:
        done += 1
print('linked', done, 'failed', fail)
