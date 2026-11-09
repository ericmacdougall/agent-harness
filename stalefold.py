"""1. #14250 -> duplicate of #15558 (link first, then close). 2. Stale PRs (no commit in 7 days, no live owner): close the PR with a comment, keep the branch,
then put the cited tickets back as the fold left them (status from the ledger, checklist row intact in the umbrella). usage: stalefold.py [--dry]"""
import sys, json, glob, subprocess, time, uuid
T = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/'
H = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/harness-delivery/.claude/worktrees/agent-ab8a7d1bf54ed3c9a/'
sys.path.insert(0, T)
import gq
dry = '--dry' in sys.argv
P = {p['slug']: p for p in json.load(open(T + 'projects.json'))}['goodqa']
stale = json.load(open(H + 'prstale.json'))
fold = {}
for f in glob.glob(T + 'done*.jsonl'):
    for l in open(f):
        d = json.loads(l)
        if d.get('result') == 'closed':
            fold[d['n']] = d
snap = {}
for f in glob.glob(T + 'snapshots*/snap-*.jsonl'):
    for l in open(f):
        j = json.loads(l)
        snap[j['issue']['number'], j['proj']] = j['issue']['id']


def issue(n):
    return gq.call('get_issue_by_number', dict(orgId=P['orgId'], projectId=P['id'], number=n))['issue']


# 1. #14250
a = issue(14250)
live = issue(15558)
print('14250', a['status'], 'live', live['status'])
if not dry and a['status'] not in ('duplicate', 'done', 'wont_fix'):
    gq.call('call_api', dict(method='POST', path='/issues/%s/links' % a['id'], body={'relatedIssueId': live['id'], 'kind': 'duplicates'}))
    r = gq.call('bulk_update_issues', {'items': [{'issueId': a['id'], 'status': 'duplicate', 'note': 'goodqa#14977: closed as a duplicate of goodqa#15558 (combined fleet liveness alerts); goodqa_liveness.py follows it there instead of reopening. NOT done.'}]})
    print('14250 closed', r.get('succeeded'))
# 2. stale PRs
for k, v in stale.items():
    if v.get('error') or v['state'] != 'OPEN' or v['ageDays'] is None or v['ageDays'] < 7 or v['liveOwnerHolds']:
        continue
    repo = k.split('#')[0]
    num = int(k.split('#')[1])
    umbs = sorted({fold[n]['umb'] for n in v['tickets'] if n in fold and fold[n].get('umb')})
    hub = ('hub/umbrella goodqa#%s' % ', #'.join(str(u) for u in umbs)) if umbs else 'its umbrella'
    comment = ('Closing as stale: no commit for %d days (last %s), no live owner, no review. The work is tracked as a checklist row in %s (goodqa#14977 cleanup); the branch %s is KEPT and nothing was deleted. Reopen the PR from that branch if the work resumes.' % (v['ageDays'], v['lastCommit'], hub, v['branch']))
    print('PR', k, 'age', v['ageDays'], 'tickets', v['tickets'], 'umb', umbs)
    if dry:
        continue
    r = subprocess.run(['gh', 'pr', 'close', str(num), '--repo', 'ericmacdougall/' + repo, '--comment', comment], capture_output=True, text=True)
    print('  gh pr close rc', r.returncode, (r.stderr or r.stdout)[:120])
    if r.returncode:
        continue
    items = []
    for n in v['tickets']:
        iid = [i for (nn, pr), i in snap.items() if nn == n and pr.endswith('/goodqa')]
        if not iid:
            continue
        cur = gq.call('get_issue', {'issueId': iid[0]})['issue']
        if cur['status'] in ('done', 'wont_fix', 'duplicate', 'cancelled'):
            print('  already closed', n); continue
        items.append({'issueId': iid[0], 'status': fold[n]['to'], 'note': 'goodqa#14977: folded back into its umbrella (%s). The PR %s#%d was closed as stale (no commit in %d days, no live owner); the branch %s is kept. Checklist row intact. NOT done.' % (hub, repo, num, v['ageDays'], v['branch'])})
    if items:
        r = gq.call('bulk_update_issues', {'items': items})
        print('  folded back', r.get('succeeded'), 'of', len(items))
