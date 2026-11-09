"""Live test of the deployed liveness fix: close ONE alert (goodqa#15544) as duplicate of #15558, then watch it. usage: livetest.py close | watch"""
import sys, json, time, uuid
T = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/'
sys.path.insert(0, T)
import gq
plan = json.loads(open(T + 'plan21-goodqa.jsonl').readline())
live = plan['umbrella']['id']
alert = [c for c in plan['children'] if c['n'] == 15544][0]['id']
if sys.argv[1] == 'close':
    r = gq.call('bulk_update_issues', {'items': [{'issueId': alert, 'status': 'duplicate', 'note': 'goodqa#14977 live test of the liveness duplicate-follow fix: closed as duplicate of goodqa#15558 (a duplicates link exists). NOT done, NOT wont_fix.'}]})
    print(json.dumps(r)[:300])
else:
    for tag, iid in (('alert 15544', alert), ('live 15558', live)):
        ev = gq.call('get_issue_events', {'issueId': iid})
        evs = ev.get('events', ev) if isinstance(ev, dict) else ev
        for e in (evs or [])[-6:]:
            print(tag, e.get('createdAt'), e.get('type'), json.dumps(e.get('data'))[:90])
        c = gq.call('get_issue_comments', {'issueId': iid})
        for x in c.get('comments', [])[-3:]:
            print(tag, 'COMMENT', x.get('createdAt'), (x.get('body') or '')[:200].replace('\n', ' / '))
    print('status alert:', gq.call('get_issue', {'issueId': alert})['issue']['status'])
