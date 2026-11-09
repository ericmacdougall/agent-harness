"""Put back what the audit reopened but the coordinator's rule says stays folded; reopen what the rule says must be open.
Rule (coordinator): separate and open only when a live owner works it now, or an open PR body cites it, plus the named list (keep.json).
1. For each reopened ticket NOT in keep: set the status the fold left (ledger `to`), only if its status is still the one the audit set.
   Also checks the 20 tickets after the 40 logged ones, in case the stopped job's third batch was applied but not logged.
2. For each keep ticket (goodqa, closed by my ledgers) that is still closed: reopen to its pre-fold status with a comment.
Ledger: restore_audit.jsonl. Goodqa numbers only for keep; optinrouter and yates are never touched."""
import sys, json, glob, time, os
T = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/'
H = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/harness-delivery/.claude/worktrees/agent-ab8a7d1bf54ed3c9a/'
sys.path.insert(0, T)
import gq
K = json.load(open(H + 'keep.json'))
keep = {int(k): v for k, v in K['keep'].items()}
fold = {}
for f in glob.glob(T + 'done*.jsonl'):
    for l in open(f):
        d = json.loads(l)
        if d.get('result') == 'closed':
            fold[d['id']] = dict(to=d.get('to'), frm=d.get('from') or 'triage', n=d['n'])
snap = {}
for f in glob.glob(T + 'snapshots*/snap-*.jsonl'):
    for l in open(f):
        j = json.loads(l)
        snap[j['issue']['id']] = j['proj']
audit = [json.loads(l) for l in open(H + 'reopen_audit.jsonl')]
reopened = {r['id']: r for r in audit if r['result'] == 'reopened'}
plan = json.load(open(H + 'reopen_plan.json'))
order = [i for i, v in sorted(plan.items(), key=lambda kv: (kv[1]['proj'], kv[1]['n']))]
unlogged = [i for i in order[40:60] if i not in reopened]
LOG = H + 'restore_audit.jsonl'
done = {json.loads(l)['id'] for l in open(LOG)} if os.path.exists(LOG) else set()
CLOSED = ('done', 'wont_fix', 'duplicate', 'cancelled')


def log(**k):
    with open(LOG, 'a') as f:
        f.write(json.dumps(dict(k, at=time.strftime('%FT%TZ', time.gmtime()))) + '\n')


def is_keep(i):
    return snap.get(i, '').endswith('/goodqa') and fold.get(i, {}).get('n') in keep


put = []
for i in list(reopened) + unlogged:
    if i in done or is_keep(i) or i not in fold:
        continue
    cur = gq.call('get_issue', {'issueId': i}).get('issue') or {}
    want = fold[i]['to']
    if cur.get('status') in CLOSED:
        log(id=i, n=fold[i]['n'], result='already-closed', status=cur.get('status'))
        continue
    put.append({'issueId': i, 'status': want})
    log(id=i, n=fold[i]['n'], result='queued-put-back', cur=cur.get('status'), to=want)
for s in range(0, len(put), 20):
    r = gq.call('bulk_update_issues', {'items': put[s:s + 20]})
    ok = {x.get('issueId') for x in r.get('results', []) if x.get('ok')}
    for it in put[s:s + 20]:
        log(id=it['issueId'], n=fold[it['issueId']]['n'], result='put-back' if it['issueId'] in ok else 'PUT-BACK-FAILED', to=it['status'])
    print('put back batch', len(ok), flush=True)
rop = []
for i, f in fold.items():
    if is_keep(i) and i not in done:
        cur = gq.call('get_issue', {'issueId': i}).get('issue') or {}
        if cur.get('status') in CLOSED:
            back = f['frm'] if f['frm'] not in CLOSED else 'triage'
            rop.append({'issueId': i, 'status': back, 'note': 'goodqa#14977 audit: REOPENED. A live owner works this ticket now or an open PR cites it (%s); the fold closed it in error. Restored to %s; NOT done, NOT wont_fix.' % ('; '.join(keep[f['n']])[:200], back)})
for s in range(0, len(rop), 20):
    r = gq.call('bulk_update_issues', {'items': rop[s:s + 20]})
    ok = {x.get('issueId') for x in r.get('results', []) if x.get('ok')}
    for it in rop[s:s + 20]:
        log(id=it['issueId'], n=fold[it['issueId']]['n'], result='keep-reopened' if it['issueId'] in ok else 'KEEP-REOPEN-FAILED', to=it['status'])
    print('keep reopen batch', len(ok), flush=True)
print('summary: put back', len(put), 'keep reopened', len(rop), 'unlogged checked', len(unlogged))
