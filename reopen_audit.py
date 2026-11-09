"""Reopen tickets the 2026-11 folds closed in error (active owner / spec / open PR / WAL work mention in 48 h; plus the named tickets). One rate-limited job.
For each: read the CURRENT status (never touch a ticket that is no longer closed), restore the status it had before the fold, with a comment naming the reason.
usage: reopen_audit.py [--dry]. Ledger: reopen_audit.jsonl (append-only)."""
import sys, json, glob, time, os
T = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/'
H = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/harness-delivery/.claude/worktrees/agent-ab8a7d1bf54ed3c9a/'
sys.path.insert(0, T)
import gq
plan = json.load(open(H + 'reopen_plan.json'))
tc = json.load(open(H + 'tierC.json'))
for i, v in tc.items():
    if v['slug'] == 'goodqa' and v['n'] in (15434, 15510):
        plan[i] = v
was = {}
for f in glob.glob(T + 'done*.jsonl'):
    for l in open(f):
        d = json.loads(l)
        if d.get('result') == 'closed':
            was[d['id']] = d.get('from') or 'triage'
LOG = H + 'reopen_audit.jsonl'
done = set()
if os.path.exists(LOG):
    done = {json.loads(l)['id'] for l in open(LOG)}
CLOSED = ('done', 'wont_fix', 'duplicate', 'cancelled')
items, meta = [], {}
for k, (i, v) in enumerate(sorted(plan.items(), key=lambda kv: (kv[1]['proj'], kv[1]['n']))):
    if i in done:
        continue
    iss = gq.call('get_issue', {'issueId': i}).get('issue')
    if not iss or iss.get('status') not in CLOSED:
        with open(LOG, 'a') as f:
            f.write(json.dumps({'id': i, 'n': v['n'], 'proj': v['proj'], 'result': 'skip-not-closed', 'status': iss and iss.get('status')}) + '\n')
        continue
    back = was.get(i, 'triage')
    if back in CLOSED or back == 'duplicate':
        back = 'triage'
    why = '; '.join(w.split(':')[0] + ' ' + w.split(':', 1)[1][:70] for w in v['why'])
    note = ('goodqa#14977 audit: REOPENED. The 2026-11 cleanup fold closed this ticket (as %s) in error: it has live work (%s). Restored to %s; it was NOT done and NOT wont_fix. '
            'Closed in error because the fold guard could not tell agent comments posted through the user token from the user\'s own.') % (iss['status'], why, back)
    items.append({'issueId': i, 'status': back, 'note': note[:1800]})
    meta[i] = (v['n'], v['proj'], iss['status'], back)
    if '--dry' not in sys.argv and len(items) == 20:
        pass
    if len(items) >= 20 or k == len(plan) - 1:
        if '--dry' in sys.argv:
            print('would reopen', [meta[x['issueId']][0] for x in items]); items = []; continue
        r = gq.call('bulk_update_issues', {'items': items})
        ok = {x.get('issueId') for x in r.get('results', []) if x.get('ok')}
        with open(LOG, 'a') as f:
            for x in items:
                n, proj, was_s, back2 = meta[x['issueId']]
                f.write(json.dumps({'id': x['issueId'], 'n': n, 'proj': proj, 'result': 'reopened' if x['issueId'] in ok else 'FAILED', 'from': was_s, 'to': back2, 'at': time.strftime('%FT%TZ', time.gmtime())}) + '\n')
        print('batch', len(items), 'ok', len(ok), flush=True)
        items = []
if items and '--dry' not in sys.argv:
    r = gq.call('bulk_update_issues', {'items': items})
    ok = {x.get('issueId') for x in r.get('results', []) if x.get('ok')}
    with open(LOG, 'a') as f:
        for x in items:
            n, proj, was_s, back2 = meta[x['issueId']]
            f.write(json.dumps({'id': x['issueId'], 'n': n, 'proj': proj, 'result': 'reopened' if x['issueId'] in ok else 'FAILED', 'from': was_s, 'to': back2, 'at': time.strftime('%FT%TZ', time.gmtime())}) + '\n')
    print('final batch', len(items), 'ok', len(ok))
print('done', sum(1 for l in open(LOG) if '"reopened"' in l) if os.path.exists(LOG) else 0, 'reopened')
