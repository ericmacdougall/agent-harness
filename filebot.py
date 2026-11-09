"""File the goodqa_liveness regrowth defect in goodqa (rate-limit backoff 60 s doubling) and link it from goodqa#15532 and goodqa#14977."""
import sys, json, time, uuid
T = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/'
sys.path.insert(0, T)
import gq
P = {p['slug']: p for p in json.load(open(T + 'projects.json'))}['goodqa']


def bo(name, args):
    w = 60
    for _ in range(7):
        r = gq.call(name, args)
        e = r.get('error') if isinstance(r, dict) else None
        if not e or e.get('code') != 'rate_limited':
            return r
        print('rate_limited, wait', w, flush=True)
        time.sleep(w)
        w *= 2
    return r


desc = """Defect: the fleet liveness bot reopens alert tickets that a person closed, including tickets closed as duplicate of a combined live ticket. That regrows the open-ticket count after every cleanup.

Source: harness repo bin/goodqa_liveness.py (on t2-dev ~/repos/harness/bin/goodqa_liveness.py, commit bc893538f at time of writing). Run by goodqa-liveness.timer on t2-dev, OnBootSec=4min, OnUnitActiveSec=2min.
Mechanism (lines ~2415-2433 and reopen_closed at ~2961): per alert class the bot stores a['ref'], the ORIGINAL ticket. If the finding still holds and the ticket status is in CLOSED_ALERT_STATUSES = (done, wont_fix, duplicate, cancelled, on_production), and more than 3600 s passed since a['reopened'], it PATCHes the ticket to triage and comments: "Reopened: the fleet liveness finding `<cls>` still holds; keep this alert open until it clears."
Evidence: goodqa#10756, #12975 and #15544 were closed wont_fix by the cleanup (2026-11-08 and 2026-11-09) and set back to triage by the bot within minutes to an hour (event actor is the Claude agent token, status_changed wont_fix -> triage, plus the Reopened comment). #10756 was reopened twice on 2026-11-08 alone (01:21Z, 20:26Z).
Observed volume: 68 closed alert tickets reopened between 2026-11-08 and 2026-11-09; 76 open "Fleet liveness" tickets on 2026-11-09.

Fix options (smallest first):
1. When the ref is closed as duplicate, follow it to the duplicate-of target. If the target is open, append the status block there and do not reopen the original. (moved_copy / undo_copy already exist for the move case.)
2. Treat a human close of an alert as an acknowledged snooze for N days unless the finding class changes, instead of reopening within an hour.
3. Keep one live ticket per project for all alerts and let alert rows be comments, not tickets (what the cleanup built by hand in the combined ticket).
Acceptance: close an alert ticket as duplicate of an open live ticket; after 3 timer ticks it stays closed, and the status text lands on the live ticket. Negative: a cleared finding that recurs after 7 days still opens a fresh alert.
Not changed by me: I did not edit the harness repo (protected path for this task)."""
r = bo('create_issue', dict(orgId=P['orgId'], projectId=P['id'], title='goodqa_liveness reopens closed and duplicate alert tickets; the open count regrows after every cleanup', description=desc, type='bug', priority='high', labels=['fleet-liveness', 'cleanup-2026-11l'], operationId=str(uuid.uuid5(uuid.NAMESPACE_URL, 'livebot|goodqa'))))
iss = r.get('issue')
print('filed', iss and iss['number'], str(r)[:200] if not iss else '')
if iss:
    for n in (15532, 14977):
        g = bo('get_issue_by_number', dict(orgId=P['orgId'], projectId=P['id'], number=n))['issue']
        bo('comment_on_issue', dict(issueId=g['id'], body='Fleet liveness reopen defect filed as goodqa#%d: goodqa_liveness.py reopens duplicate-closed alert tickets about hourly (2-minute timer on t2-dev); the 68 reopened alerts are combined in one live ticket but will regrow until it is fixed.' % iss['number'], operationId=str(uuid.uuid5(uuid.NAMESPACE_URL, 'livebotc|%d' % n))))
        print('commented', n)
