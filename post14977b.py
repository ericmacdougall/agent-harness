"""Correction comment on goodqa#14977: the honest measured count after the fold audit. Backoff on rate_limited."""
import sys, json, time, uuid
T = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/'
sys.path.insert(0, T)
import gq
P = {p['slug']: p for p in json.load(open(T + 'projects.json'))}['goodqa']
g = gq.call('get_issue_by_number', dict(orgId=P['orgId'], projectId=P['id'], number=14977))['issue']
body = """Correction to my 275 post: measured open tickets across all projects are now 306 (dump16, open_now14.jsonl, 2026-11-09). That is 6 over the 300 target.

Why it rose from 275: 25 tickets were reopened because a live owner works them or an open PR body cites them (the fold had closed them in error, e.g. goodqa#15545), 5 new tickets other owners or bots filed (15564, 15566, 15567, 14250 and others) plus the round umbrella goodqa#15565. The audit first reopened 40 on a rule that was too wide; 27 of those were put back as the fold left them (restore_audit.jsonl); 13 stay open.

Kept open on purpose (live owner or open PR citing them): 10701, 10935, 13241, 13431, 14155, 14216, 14310, 14351, 14394, 14710, 14753, 14791, 14798, 15158, 15346, 15355, 15371, 15372, 15373, 15382, 15398, 15434, 15476, 15488, 15510, plus 15545 reopened by main.
Dump command: cd /Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup && sed 's/open_now3/open_now15/' dump5.py > dump17.py && python3 dump17.py | grep TOTAL"""
w = 60
for _ in range(7):
    r = gq.call('comment_on_issue', dict(issueId=g['id'], body=body, operationId=str(uuid.uuid5(uuid.NAMESPACE_URL, 'final306|14977'))))
    e = r.get('error') if isinstance(r, dict) else None
    if e and e.get('code') == 'rate_limited':
        time.sleep(w); w *= 2; continue
    break
print(json.dumps(r)[:120])
