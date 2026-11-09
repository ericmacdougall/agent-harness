"""Comment on goodqa#15558 naming the liveness fix commits (commit policy ticket freshness). Backoff on rate_limited."""
import sys, json, time, uuid
T = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/'
sys.path.insert(0, T)
import gq
body = ('Fix for the reopening alert bot: bugtracker-harness branch fix/liveness-duplicate-follow, commits 91eab2224fe5, 90d7aaba78c9, 4a03f94850dc, 8c125d54cec3, 0b2bbaf843e0 '
        '(head 0b2bbaf8). goodqa_liveness.py follows an alert closed as duplicate to its open canonical ticket (this one) instead of reopening it, and posts one aggregate note per hour '
        'listing the alerts still failing. Draft PR follows; deploy after the waiver by copying only bin/goodqa_liveness.py.')
w = 60
for _ in range(7):
    r = gq.call('comment_on_issue', dict(issueId='ee93e729-60e2-4983-a9f3-32db7c44bf98', body=body, operationId=str(uuid.uuid5(uuid.NAMESPACE_URL, 'fixnote|0b2bbaf8'))))
    e = r.get('error') if isinstance(r, dict) else None
    if e and e.get('code') == 'rate_limited':
        time.sleep(w); w *= 2; continue
    break
print(json.dumps(r)[:200])
