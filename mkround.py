"""Create the umbrella ticket for the harness fix round (11 items as checklist lines). Backoff on rate_limited."""
import sys, json, time, uuid
T = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/'
sys.path.insert(0, T)
import gq
P = {p['slug']: p for p in json.load(open(T + 'projects.json'))}['goodqa']
items = [
    'Item 1: liveness false alarm. ops-watch keeps a CRITICAL "silent" alert for agent-a0680533 although its disposition was recorded as reassigned to a1a19164 (wf5a5ff8879a); `ah owners` showed live=false for a1a19164 while active. A reassigned or waiting disposition must clear or downgrade the alert; liveness must count recent tool use.',
    'Item 2: ask reminders are duplicated per host (Mac-2 and Erics-MacBook-Air alert the same ask, ~37 high alerts). One alert per ask; reminder cadence that backs off (reminder 7 on one ask already).',
    'Item 3: ah-kill --foreign alerts: 40 HIGH alerts for kills that were user-approved or own-tree. Approved or own-session kills should be info, aggregated, and expire.',
    'Item 4: wal_note.py has no `deploy` event although CLAUDE.md requires a deploy record for LIVE status. Add `deploy` (and `live_test` if missing) and make `ah status` count them.',
    'Item 5: merge_gate PreToolUse hook parses the command text literally: `-R $R` was read as "$R" and blocked. Expand simple assignments in the same command or give a clear message to inline the value. Must keep the safety property.',
    'Item 6: approve-delete requires the AskUserQuestion answer to be exactly "Delete, no backup"; "Yes, delete it" is refused. Accept a documented affirmative set bound to the question text, or show the required option text in the refusal. Must keep the safety property.',
    'Item 7: remote ssh resets (exit 255 on Mac -> t2-dev -> dev2) are reported as task failures. Add a retry-once wrapper with a distinct INFRA exit and make bg_job wait report it as infrastructure.',
    'Item 8: bg_lint flags `until ...; done; cmd | tail` loops; ship `bg_job.py wait-remote --host --until-file-line` so the right pattern is the easy one.',
    'Item 9: disk budget: owner ab8a7d1b is 13 GiB over a 5 GiB budget on the Mac. fresh/t2c (12 GB, derivable, hand-written files verified on Dropbox) awaits the user answer with the exact option label; proof/assets (478 MB) is left alone as possible evidence.',
    'Item 10: t2-blog-drip on t2-dev: last run exit 6, last success 27 h ago. Find the cause and fix, or file it with the cause.',
    'Item 11: Codex reports 4 harness PreToolUse hooks untrusted/changed since trust, so Codex skips them. Find whether trust can be re-established without the user (config file or non-interactive command); otherwise register one sourced ask with the exact command.',
]
desc = ('Harness fix round, 2026-11-09 (goodqa#14977 stream). Source: /Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/harness-fix-round-20261109.md. '
        'Each item: reproducer first, failing-first test, small PR, one red-team plus one delta; main waives; batched PRs where sensible. No guard weakening (items 5 and 6 only reduce false refusals). '
        'Order: items 9, 1, 2, 3, 10, 4, then the rest. Checklist (state in the comments as items land):\n\n' + '\n'.join('- [ ] ' + x for x in items))
w = 60
for _ in range(7):
    r = gq.call('create_issue', dict(orgId=P['orgId'], projectId=P['id'], title='Harness fix round 2026-11-09: 11 items (liveness, ask and kill alerts, deploy events, guards, ssh, drip)', description=desc, type='task', priority='high', labels=['harness', 'cleanup-2026-11m'], operationId=str(uuid.uuid5(uuid.NAMESPACE_URL, 'round|20261109'))))
    e = r.get('error') if isinstance(r, dict) else None
    if e and e.get('code') == 'rate_limited':
        time.sleep(w); w *= 2; continue
    break
i = r.get('issue')
print('umbrella', i and i['number'], '' if i else str(r)[:200])
