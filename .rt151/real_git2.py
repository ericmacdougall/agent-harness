"""Real git: GIT_CONFIG_* words after the subcommand are arguments, and an alias from a config file still runs.
Stand-ins only (echo), in a throwaway repo under the run_probe sandbox TMPDIR."""
import os
import subprocess
import tempfile

t = tempfile.mkdtemp()
env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
env.update(GIT_CONFIG_NOSYSTEM='1', GIT_AUTHOR_NAME='t', GIT_AUTHOR_EMAIL='t@e.invalid', GIT_COMMITTER_NAME='t',
           GIT_COMMITTER_EMAIL='t@e.invalid', GIT_CONFIG_GLOBAL=os.path.join(t, 'cfg'))
with open(os.path.join(t, 'cfg'), 'w') as f:
    f.write('[alias]\n\twr = !echo ALIAS-FROM-FILE-RAN first=$1 #\n')
for cmd in ('git init -q -b main .',
            'git wr /some/path GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=alias.wr GIT_CONFIG_VALUE_0=status',
            'git wr GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=alias.wr GIT_CONFIG_VALUE_0=status /some/path'):
    d = subprocess.run(['bash', '-c', cmd], cwd=t, env=env, capture_output=True, text=True, timeout=20)
    print('$', cmd, '\n  rc=%s %s' % (d.returncode, (d.stdout + d.stderr).strip()[:200]))
# chain longer than the guard's depth limit
chain = ' '.join('-c alias.a%d=a%d' % (n, n + 1) for n in range(1, 10))
d = subprocess.run(['bash', '-c', "git %s -c alias.a10='worktree list' a1" % chain], cwd=t, env=env, capture_output=True,
                   text=True, timeout=20)
print('$ git <9 links> -c alias.a10=worktree-list a1\n  rc=%s %s' % (d.returncode, (d.stdout + d.stderr).strip()[:200].replace(t, '$T')))
