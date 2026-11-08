"""Budget and fail-open probes. Text only: decide()/hook_main() on strings, nothing executed.

usage: dos.py REPO CASE
Each case runs alone so run_probe can bound it. Uses a repo outside every protected root, like ~/wt/x on t2-dev.
"""
import io
import json
import os
import sys
import tempfile
import time
import contextlib
import subprocess

REPO, CASE = sys.argv[1], sys.argv[2]
sys.path.insert(0, REPO + '/harness/hooks')
import command_guard as cg  # noqa: E402

home = os.path.realpath(tempfile.mkdtemp())
os.environ['HOME'] = home
prim, out = os.path.join(home, 'wt', 'prim'), os.path.join(home, 'wt', 'out')
os.makedirs(prim)
env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
env.update(GIT_CONFIG_GLOBAL='/dev/null', GIT_CONFIG_NOSYSTEM='1', GIT_AUTHOR_NAME='t', GIT_AUTHOR_EMAIL='t@e.invalid',
           GIT_COMMITTER_NAME='t', GIT_COMMITTER_EMAIL='t@e.invalid')
for a in (['init', '-q', '-b', 'main'], ['commit', '-q', '--allow-empty', '-m', 'x'],
          ['worktree', 'add', '-q', '-b', 'out', out]):
    subprocess.run(['git'] + a, cwd=prim, env=env, check=True)

policy = cg.load_policy(path=os.path.join(home, 'missing.json'))
compiled = cg.Compiled(policy, home=home, cwd=prim)
TAIL = ' ; git worktree remove --force ' + out
many = ' '.join('x%04d' % n for n in range(4095))
two = ' '.join('::: a b' for _ in range(12))
placeholders = ' '.join(['{}'] * 30000)
big_values = ' '.join('v%019d' % n for n in range(4096))

CASES = {
    'control': 'git worktree remove --force ' + out,
    'control-echo': 'echo hi' + TAIL,
    'lines-4095-echo': 'parallel echo ::: ' + many + TAIL,
    'lines-4095-quoted': "parallel 'echo {}' ::: " + many + TAIL,
    'lines-4096-product': 'parallel echo ' + two + TAIL,
    'lines-kept-reading': "parallel -j4 sh -c 'echo {}' ::: " + many + TAIL,
    'lines-rm-f': "parallel 'rm -f {}' ::: " + many + TAIL,
    'lines-compound': "parallel 'echo {} && echo {} && echo {} && echo {}' ::: " + many + TAIL,
    'nested': "parallel 'parallel \"parallel echo ::: 1 2 3 4 5 6 7 8\" ::: 1 2 3 4 5 6 7 8' ::: 1 2 3 4 5 6 7 8" + TAIL,
    'nested-wide': "parallel 'parallel echo ::: %s' ::: %s" % (' '.join(map(str, range(64))), ' '.join(map(str, range(64)))) + TAIL,
    'plan-amplify': 'parallel echo ' + placeholders + ' ::: ' + big_values + TAIL,
    'plan-only-stats': None,
    'plan-40k': 'parallel echo ' + ' '.join(['{}'] * 5000) + ' ::: ' + many + TAIL,
    'rm-compound': "parallel 'rm -f {} && rm -f {} && rm -f {}' ::: " + many + TAIL,
    'rm-compound-small': "parallel 'rm -f {} {} {} {} {} {} {} {}' ::: " + ' '.join('x%d' % n for n in range(1500)) + TAIL,
    'rm-product': "parallel 'rm -f {1} {2} {3} {4} {5} {6}' " + ' '.join('::: a b c d' for _ in range(6)) + TAIL,
    'rm-product-noalias': "parallel 'rm -f {1} {2} {3} {4} {5} {6}' " + ' '.join('::: a b c d' for _ in range(6)) + ' ; rm -rf ' + out,
}

cmd = CASES[CASE]
if CASE == 'plan-only-stats':
    words = [cg._literal_word(x) for x in (['echo'] + ['{}'] * 30000 + [':::'] + big_values.split())]
    t0 = time.monotonic()
    lines, mode, err = cg.parallel_plan(words)
    print('plan secs %.1f lines %s bytes %s err %s' % (time.monotonic() - t0, len(lines or []), sum(map(len, lines or [])), err))
    sys.exit(0)
print('command bytes', len(cmd.encode()), 'limit', compiled.limits['max_command_bytes'])
if os.environ.get('RT_HOOK'):
    payload = json.dumps({'tool_name': 'Bash', 'tool_input': {'command': cmd}, 'cwd': prim}).encode()
    t0 = time.monotonic()
    buf, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(err):
        rc = cg.hook_main(stdin_bytes=payload, compiled=compiled, marker=False)
    print('hook_main rc=%s secs=%.2f stdout=%s stderr=%s' % (rc, time.monotonic() - t0, buf.getvalue()[:300].replace(home, '$H'),
                                                              err.getvalue()[:300].replace(home, '$H')))
else:
    t0 = time.monotonic()
    v = cg.decide(cmd, compiled, cwd=prim)
    print('decide %s secs=%.2f %s' % (v[0], time.monotonic() - t0, str(v[1])[:300].replace(home, '$H')))
