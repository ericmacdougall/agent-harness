import subprocess, sys
H = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/harness-delivery/.claude/worktrees/agent-ab8a7d1bf54ed3c9a/'
for r in sys.argv[1:]:
    o = subprocess.run(['python3', '-I', H + 'delrun.py', r], capture_output=True, text=True)
    print('=====', r, flush=True)
    print(o.stdout[-1500:], o.stderr[-300:], flush=True)
