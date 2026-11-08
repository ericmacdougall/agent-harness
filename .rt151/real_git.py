"""What real git does with the forms the guard allowed. Read-only stand-ins only: `worktree list`, `status`, echo.
Runs in a throwaway repo under $TMPDIR (run_probe sandbox). Nothing is removed."""
import os
import subprocess
import tempfile

t = tempfile.mkdtemp()
repo = os.path.join(t, 'r')
os.mkdir(repo)
env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
env.update(GIT_CONFIG_GLOBAL='/dev/null', GIT_CONFIG_NOSYSTEM='1', GIT_AUTHOR_NAME='t', GIT_AUTHOR_EMAIL='t@e.invalid',
           GIT_COMMITTER_NAME='t', GIT_COMMITTER_EMAIL='t@e.invalid')


def sh(cmd, extra=None):
    e = dict(env)
    e.update(extra or {})
    d = subprocess.run(['bash', '-c', cmd], cwd=repo, env=e, capture_output=True, text=True, timeout=20)
    out = (d.stdout + d.stderr).strip().replace(t, '$T')
    return d.returncode, out[:300]


sh('git init -q -b main . && git commit -q --allow-empty -m x')
bin_dir = os.path.join(t, 'bin')
os.mkdir(bin_dir)
with open(os.path.join(bin_dir, 'git-wr'), 'w') as f:
    f.write('#!/bin/sh\necho EXTERNAL-git-wr-ran "$@"\n')
os.chmod(os.path.join(bin_dir, 'git-wr'), 0o755)
with open(os.path.join(t, 'alias.cfg'), 'w') as f:
    f.write('[alias]\n\twr = worktree list\n')

CASES = [
    ('list-of-builtins entry bisect--helper is an alias', "git -c alias.bisect--helper='worktree list' bisect--helper"),
    ('rebase--interactive is an alias', "git -c alias.rebase--interactive='worktree list' rebase--interactive"),
    ('env--helper is an alias', "git -c alias.env--helper='worktree list' env--helper"),
    ('submodule (a script, not a built-in)', "git -c alias.submodule='worktree list' submodule status"),
    ('.command after plain: last wins', "git -c alias.wr=status -c alias.wr.command='worktree list' wr"),
    ('plain after .command: last wins', "git -c alias.wr.command='worktree list' -c alias.wr=status wr"),
    ('GIT_CONFIG_COUNT .command later', "GIT_CONFIG_COUNT=2 GIT_CONFIG_KEY_0=alias.wr GIT_CONFIG_VALUE_0=status "
     "GIT_CONFIG_KEY_1=alias.wr.command GIT_CONFIG_VALUE_1='worktree list' git wr"),
    ('-c beats GIT_CONFIG_COUNT', "GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=alias.wr GIT_CONFIG_VALUE_0='worktree list' "
     "git -c alias.wr=status wr"),
    ('built-in wins over alias', "git -c alias.status='worktree list' status --short"),
    ('--shallow-file eats the next word', 'git --shallow-file status worktree list'),
    ('external git-wr beats -c alias', 'PATH=%s:$PATH git -c alias.wr=status wr' % bin_dir),
    ('GIT_EXEC_PATH external beats -c alias', 'GIT_EXEC_PATH=%s git -c alias.wr=status wr' % bin_dir),
    ('key built at run time, last wins', "K=alias.wr; git -c alias.wr=status -c \"$K=worktree list\" wr"),
    ('--config-env later, last wins', "V='worktree list' git -c alias.wr=status --config-env=alias.wr=V wr"),
    ('-c include.path defines the alias', 'git -c include.path=%s/alias.cfg wr' % t),
    ('GIT_CONFIG_PARAMETERS defines it', "GIT_CONFIG_PARAMETERS=\"'alias.wr=worktree list'\" git wr"),
    ('unexported GIT_CONFIG_*, alias from global file wins', "GIT_CONFIG_COUNT=1; GIT_CONFIG_KEY_0=alias.wr; "
     "GIT_CONFIG_VALUE_0=status; GIT_CONFIG_GLOBAL=%s git wr" % os.path.join(t, 'alias.cfg')),
    ('legacy config, option between key and value', "git config --file %s/c1 alias.wr --comment=x 'worktree list'; "
     "git config --file %s/c1 --get alias.wr" % (t, t)),
    ('config set, option between key and value', "git config set --file %s/c2 alias.wr --comment=x 'worktree list'; "
     "git config --file %s/c2 --get alias.wr" % (t, t)),
    ('rename-section with an option in between', "git config --file %s/c3 foo.wr 'worktree list'; "
     "git config --rename-section --file %s/c3 foo alias; git config --file %s/c3 --get alias.wr" % (t, t, t)),
    ('rename-section subcommand spelling, option between',
     "git config --file %s/c4 foo.wr 'worktree list'; git config rename-section --file %s/c4 foo alias; "
     "git config --file %s/c4 --get alias.wr" % (t, t, t)),
    ('alias via rebase --exec: value has no word worktree', "git config --file %s/c5 alias.x \"rebase --exec 'echo RAN' HEAD\";"
     " GIT_CONFIG_GLOBAL=%s/c5 git x" % (t, t)),
    ('for-each-repo runs any subcommand', 'git -c r.repo=$PWD for-each-repo --config=r.repo worktree list'),
    ('subcommand and target on xargs input', "echo 'worktree list' | xargs git"),
    ('remove-verb on xargs input', "echo 'list' | xargs git worktree"),
    ('verb in the -I slot', "echo list | xargs -I{} git worktree {}"),
    ('ls-remote --upload-pack runs a command', "git ls-remote --upload-pack='echo UPLOADPACK-RAN >&2;:' ."),
    ('core.pager runs a command', "git -c core.pager='echo PAGER-RAN' -p log -1 --oneline"),
    ('core.fsmonitor runs a command', "git -c core.fsmonitor='echo FSMONITOR-RAN >&2;:' status --short"),
    ('alias with -c inside', "git -c alias.x='-c alias.y=worktree y list' x"),
    ('alias name is matched case-insensitively', "git -c alias.WR='worktree list' wr"),
    ('subsection alias is case-sensitive', "git -c alias.WR.command='worktree list' wr"),
]
print(sh('git --version')[1])
for label, cmd in CASES:
    rc, out = sh(cmd)
    print('[%s] rc=%s\n    $ %s\n    %s' % (label, rc, cmd.replace(t, '$T'), out.replace('\n', ' | ')))
