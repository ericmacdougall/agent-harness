"""Per-worktree check for l1-deploy/.claude/worktrees/*. usage: wtcheck.py [--remove]
Pass = no live process, clean (incl untracked), no stash, HEAD reachable from a remote ref, and its branch (if any) pushed with the same sha.
Removal uses 'git worktree remove --force' from the main checkout so no dangling admin entries are left."""
import os, subprocess, sys
BASE = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/l1-deploy/'
WT = BASE + '.claude/worktrees/'
RM = '--remove' in sys.argv
ps = subprocess.run(['ps', '-axo', 'args'], capture_output=True, text=True).stdout


def g(p, *a):
    r = subprocess.run(['git', '-C', p] + list(a), capture_output=True, text=True)
    return r.returncode, r.stdout.strip()


for d in sorted(os.listdir(WT)):
    p = WT + d
    why = []
    if any(p in l for l in ps.splitlines()):
        why.append('live-process')
    if g(p, 'status', '--porcelain')[1]:
        why.append('dirty')
    if g(p, 'stash', 'list')[1]:
        why.append('stash')
    head = g(p, 'rev-parse', 'HEAD')[1]
    if not g(p, 'branch', '-r', '--contains', head)[1]:
        why.append('head-not-on-remote')
    rc, br = g(p, 'symbolic-ref', '--short', '-q', 'HEAD')
    if rc == 0:
        up = g(p, 'for-each-ref', '--format=%(upstream:short)', 'refs/heads/' + br)[1]
        r2 = g(p, 'ls-remote', '--heads', 'origin', br)[1]
        if not r2 or r2.split()[0] != head:
            if not g(p, 'branch', '-r', '--contains', head)[1]:
                why.append('branch-not-pushed:' + br)
    size = subprocess.run(['du', '-sm', p], capture_output=True, text=True).stdout.split()[0]
    print(('KEEP ' if why else 'OK   '), size, 'MB', d, why)
    if RM and not why:
        r = subprocess.run(['git', '-C', BASE, 'worktree', 'remove', '--force', p], capture_output=True, text=True)
        print('   removed rc', r.returncode, r.stderr.strip()[:120])
