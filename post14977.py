"""Post the measured open-ticket count and the dump command on goodqa#14977 (backoff on rate_limited)."""
import sys, json, time, uuid
T = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/'
sys.path.insert(0, T)
import gq
P = {p['slug']: p for p in json.load(open(T + 'projects.json'))}['goodqa']
g = gq.call('get_issue_by_number', dict(orgId=P['orgId'], projectId=P['id'], number=14977))['issue']
body = """Measured open tickets across all projects: 275 (target: under 300). Taken 2026-11-09 after the last close finished; none of the 76 combined fleet alerts was reopened in that dump.

Dump command (reads every org and project and prints TOTAL; the per-project rows are in open_now13.jsonl):
  cd /Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup && sed 's/open_now3/open_now14/' dump5.py > dump16.py && python3 dump16.py | grep TOTAL

Path: 6,552 (11-08 morning) -> 990 -> 482 -> 343 (after security findings and hubs) -> 275 (after the 76 fleet alerts were closed as duplicates of goodqa#15558).
This count includes tickets other owners filed today; it can rise again as new work arrives. The fleet alerts no longer regrow: goodqa_liveness.py now follows a duplicate-closed alert to its open canonical ticket (PR 60, merged 9ad96c0eaa34, live test REALLY_TESTED wf5b9dee75d2). Left untouched by ruling: other-organisation tickets, customer and teammate tickets, and the PRIVATE lessons epics."""
w = 60
for _ in range(7):
    r = gq.call('comment_on_issue', dict(issueId=g['id'], body=body, operationId=str(uuid.uuid5(uuid.NAMESPACE_URL, 'final275|14977'))))
    e = r.get('error') if isinstance(r, dict) else None
    if e and e.get('code') == 'rate_limited':
        time.sleep(w); w *= 2; continue
    break
print(json.dumps(r)[:160])
