import subprocess
W = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/agent-ab8a7d1bf54ed3c9a/'
H = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/harness-delivery/.claude/worktrees/agent-ab8a7d1bf54ed3c9a/'
for r in 'timbar t2-sites bugtracker poopyduck interview-prep bugtracker-harness transition2-squeeze'.split():
    d = subprocess.run(['ssh', 't2-dev', f'cat gq-branch-clean/r4/c-{r}.tsv'], capture_output=True, text=True).stdout
    open(W + f'c-{r}.tsv', 'w').write(d)
    o = subprocess.run(['python3', '-I', H + 'dec.py', r], capture_output=True, text=True)
    print(o.stdout.strip()[:2500], o.stderr[-200:])
