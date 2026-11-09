import subprocess
W = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/agent-ab8a7d1bf54ed3c9a/'
H = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/harness-delivery/.claude/worktrees/agent-ab8a7d1bf54ed3c9a/'
for r in ['timbar', 't2-sites', 'bugtracker', 'interview-prep', 'transition2-squeeze']:
    n = len(open(W + 'del-%s.txt' % r).read().split('\n')) - 1
    print(r, 'branches to delete', n)
    subprocess.run(['scp', '-q', W + 'del-%s.txt' % r, 't2-dev:gq-branch-clean/r4/del-%s.txt' % r], check=True)
subprocess.run(['scp', '-q', H + 'del7.sh', 't2-dev:gq-branch-clean/r4/del7.sh'], check=True)
subprocess.run(['ssh', 't2-dev', '(cd gq-branch-clean/r4 && nohup bash del7.sh > /dev/null 2>&1 &)'], check=True)
print('started')
