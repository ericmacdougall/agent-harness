import subprocess, json, sys
W = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/agent-ab8a7d1bf54ed3c9a/'
out = []
for l in open(W + 'branchcounts.txt'):
    n, r = l.split()
    if int(n) < 10:
        continue
    d = json.loads(subprocess.run(['gh', 'api', f'repos/ericmacdougall/{r}'], capture_output=True, text=True).stdout)
    prs = json.loads(subprocess.run(['gh', 'pr', 'list', '-R', f'ericmacdougall/{r}', '--state', 'open', '--json', 'number,headRefName,updatedAt', '--limit', '200'], capture_output=True, text=True).stdout or '[]')
    print(r, n, d['default_branch'], 'fork' if d['fork'] else 'own', d['pushed_at'], d['size'], 'openPRs', len(prs), flush=True)
