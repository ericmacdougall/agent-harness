"""The real entry point: command_guard_hook.py with a hook payload on stdin. Text only, nothing in the command is run.
Worktree lives outside every protected root, the way ~/wt/x does on t2-dev."""
import json
import os
import subprocess
import sys
import tempfile
import time

REPO = sys.argv[1]
HOOK = os.path.join(REPO, 'harness/hooks/command_guard_hook.py')
home = os.path.realpath(tempfile.mkdtemp())
prim, out = os.path.join(home, 'wt', 'prim'), os.path.join(home, 'wt', 'out')
os.makedirs(prim)
env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
env.update(HOME=home, GIT_CONFIG_GLOBAL='/dev/null', GIT_CONFIG_NOSYSTEM='1', GIT_AUTHOR_NAME='t',
           GIT_AUTHOR_EMAIL='t@e.invalid', GIT_COMMITTER_NAME='t', GIT_COMMITTER_EMAIL='t@e.invalid')
for a in (['init', '-q', '-b', 'main'], ['commit', '-q', '--allow-empty', '-m', 'x'],
          ['worktree', 'add', '-q', '-b', 'out', out]):
    subprocess.run(['git'] + a, cwd=prim, env=env, check=True)
TAIL = ' ; git worktree remove --force ' + out
srcs = ' '.join('::: a b c d' for _ in range(6))
many = ' '.join('x%04d' % n for n in range(4095))
CASES = dict(
    control='git worktree remove --force ' + out,
    trim='parallel --trim lr git worktree remove --force ::: ' + out,
    empty_source='parallel git worktree remove --force ::: ::: ' + out,
    builtin_list="git -c alias.bisect--helper='worktree remove --force' bisect--helper " + out,
    dot_command="git -c alias.wr=status -c alias.wr.command='worktree remove --force' wr " + out,
    xargs_all='echo worktree remove --force %s | xargs git' % out,
    rm_product="parallel 'rm -f {1} {2} {3} {4} {5} {6}' " + srcs + TAIL,
    plan_40k='parallel echo ' + ' '.join(['{}'] * 5000) + ' ::: ' + many + TAIL,
)
for name, cmd in CASES.items():
    payload = json.dumps({'tool_name': 'Bash', 'tool_input': {'command': cmd}, 'cwd': prim})
    t0 = time.monotonic()
    d = subprocess.run([sys.executable, HOOK], input=payload, capture_output=True, text=True, env=env, timeout=40)
    print('%-13s bytes=%-6d rc=%s secs=%.1f stdout=%s stderr=%s' % (
        name, len(cmd), d.returncode, time.monotonic() - t0, d.stdout[:150].replace(home, '$H').replace('\n', ' '),
        d.stderr[:150].replace(home, '$H').replace('\n', ' ')))
