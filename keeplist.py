"""Tickets that must be separate and open: a live owner in `ah owners` works them now, or an open PR body cites them, plus the coordinator's named list.
Prints the set and which of my 40 reopened tickets are NOT in it (to be put back as the fold left them). Writes keep.json."""
import json, subprocess, re, glob, collections
H = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/harness-delivery/.claude/worktrees/agent-ab8a7d1bf54ed3c9a/'
T = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/ticket-cleanup/'
named = {15545, 15434, 15510, 15372, 15382, 14798, 15560, 15561, 15564, 15565, 15563, 14791, 15397, 15398}
keep = {n: ['named by coordinator'] for n in named}
own = json.loads(subprocess.run(['python3', '-I', '/Users/eric/.claude/hooks/ah.py', 'owners'], capture_output=True, text=True).stdout)
for o in own['owners']:
    if o.get('state') in ('live', 'finishing'):
        m = re.search(r'(\d{3,6})', str(o.get('ticket') or ''))
        print('live owner', o['agent_id'][:9], o.get('state'), 'ticket', o.get('ticket'))
        if m:
            keep.setdefault(int(m.group(1)), []).append('live owner %s' % o['agent_id'][:9])
prs = json.loads(subprocess.run(['gh', 'search', 'prs', '--owner', 'ericmacdougall', '--state', 'open', '--limit', '200', '--json', 'repository,number,title,body,url'], capture_output=True, text=True).stdout or '[]')
pat = re.compile(r'(?i)\bgoodqa\s?#(\d{3,6})\b')
for p in prs:
    for m in pat.finditer((p.get('title') or '') + ' ' + (p.get('body') or '')):
        keep.setdefault(int(m.group(1)), []).append('open PR ' + p['url'].split('github.com/')[-1])
print('keep set (goodqa numbers):', len(keep))
rows = [json.loads(l) for l in open(H + 'reopen_audit.jsonl')]
reo = {r['n']: r for r in rows if r['result'] == 'reopened'}
snap = {}
for f in glob.glob(T + 'snapshots*/snap-*.jsonl'):
    for l in open(f):
        j = json.loads(l)
        snap[j['issue']['id']] = j['proj']
back = [r for r in reo.values() if not (snap.get(r['id'], '').endswith('/goodqa') and r['n'] in keep)]
stay = [r for r in reo.values() if r not in back]
print('reopened', len(reo), 'stay open', sorted(r['n'] for r in stay), 'put back', len(back))
json.dump(dict(keep={str(k): v for k, v in keep.items()}, back=[r['id'] for r in back], backn=[(r['n'], snap.get(r['id'])) for r in back]), open(H + 'keep.json', 'w'), indent=1)
for k in sorted(keep):
    print(k, keep[k][:2])
