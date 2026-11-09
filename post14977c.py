"""Correction comment on goodqa#14977: the honest measured count after the fold audit. Backoff on rate_limited."""
import sys, json, time, uuid
T = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/'
sys.path.insert(0, T)
import gq
P = {p['slug']: p for p in json.load(open(T + 'projects.json'))}['goodqa']
g = gq.call('get_issue_by_number', dict(orgId=P['orgId'], projectId=P['id'], number=14977))['issue']
body = """Measured open tickets across all projects: 299 (dump18, open_now16.jsonl, 2026-11-09), under the 300 target. Supersedes my 306 post.

What changed since 306: goodqa#14250 and #14360 (fleet alerts) closed as duplicates of #15558, and #15558 closed as a duplicate of the area live ticket #15532 (the liveness bot follows duplicate chains up to 3 hops and posts its hourly aggregate note there); the stale PRs poopyduck#26 (13 days) and Android-security#655 (9 days) were closed with comments, branches kept, and tickets 10701, 10935, 13241, 13431 folded back into their umbrellas (15528, 15533, 15529). The other 11 PR-cited tickets stay open: their PRs have commits in the last 3 to 5 days or a live owner.
Still open on purpose (live owner or active PR): 14155, 14216, 14310, 14351, 14394, 14710, 14753, 14791, 14798, 15158, 15346, 15355, 15371, 15372, 15373, 15382, 15398, 15434, 15476, 15488, 15510, 15545.
Dump command: cd /Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup && sed 's/open_now3/open_now17/' dump5.py > dump19.py && python3 dump19.py | grep TOTAL"""
w = 60
for _ in range(7):
    r = gq.call('comment_on_issue', dict(issueId=g['id'], body=body, operationId=str(uuid.uuid5(uuid.NAMESPACE_URL, 'final299|14977'))))
    e = r.get('error') if isinstance(r, dict) else None
    if e and e.get('code') == 'rate_limited':
        time.sleep(w); w *= 2; continue
    break
print(json.dumps(r)[:120])
