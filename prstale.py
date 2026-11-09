"""Read-only: for each open PR that cites a reopened-for-PR ticket, last commit date, review state, draft flag, and whether a LIVE owner's WAL names the PR. Writes prstale.json."""
import json, subprocess, re, glob, os, time, datetime as D
H = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/harness-delivery/.claude/worktrees/agent-ab8a7d1bf54ed3c9a/'
prs = {
    ('poopyduck', 26): [10701, 10935], ('Android-security', 655): [13241, 13431], ('bugtracker-harness', 49): [14155],
    ('goodqa-land-scratch-20261104', 5): [14216], ('bugtracker-harness', 41): [14310], ('bugtracker-harness', 43): [14351], ('solver', 9): [14394],
    ('bugtracker-harness', 52): [14710], ('bugtracker-harness', 53): [14753], ('agent-harness', 151): [15346, 15355], ('agent-fabric', 23): [15373],
    ('Android-security', 764): [15476], ('private-lessons-authoring', 3): [15446],
}
own = json.loads(subprocess.run(['python3', '-I', '/Users/eric/.claude/hooks/ah.py', 'owners'], capture_output=True, text=True).stdout)
live = [o['agent_id'] for o in own['owners'] if o.get('state') in ('live', 'finishing')]
wal = {}
for a in live:
    for f in glob.glob('/Users/eric/.claude/wals/*/agent-%s*.jsonl' % a[:12]):
        wal[a[:9]] = open(f, errors='ignore').read()
now = D.datetime.now(D.timezone.utc)
out = {}
for (repo, n), tickets in prs.items():
    r = subprocess.run(['gh', 'pr', 'view', str(n), '--repo', 'ericmacdougall/' + repo, '--json', 'state,isDraft,reviewDecision,updatedAt,headRefName,headRefOid,title,commits,baseRefName'], capture_output=True, text=True)
    if r.returncode:
        out['%s#%d' % (repo, n)] = dict(error=r.stderr[:120], tickets=tickets)
        continue
    j = json.loads(r.stdout)
    last = max((c.get('committedDate') or c.get('authoredDate') or '') for c in j['commits']) if j['commits'] else ''
    age = (now - D.datetime.fromisoformat(last.replace('Z', '+00:00'))).days if last else None
    holders = [a for a, t in wal.items() if re.search(r'%s[/ #]+(pull/)?%d\b|%s#%d\b|PR[ #]*%d\b' % (repo, n, repo, n, n), t) and (repo in t)]
    out['%s#%d' % (repo, n)] = dict(tickets=tickets, state=j['state'], draft=j['isDraft'], review=j['reviewDecision'], lastCommit=last[:10], ageDays=age, updated=j['updatedAt'][:10],
                                   branch=j['headRefName'], base=j['baseRefName'], liveOwnerHolds=holders, title=j['title'][:60])
json.dump(out, open(H + 'prstale.json', 'w'), indent=1)
for k, v in out.items():
    print(k, {x: v.get(x) for x in ('tickets', 'state', 'draft', 'review', 'lastCommit', 'ageDays', 'liveOwnerHolds', 'error')})
print('live owners:', [a[:9] for a in live])
