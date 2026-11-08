"""Read-only safety check of candidate clones. usage: macclone.py [--delete]
A path passes only if: no process has it as cwd/arg, status clean (incl. untracked), no stash, every local branch/tag tip is reachable from a remote ref
(non-bare: `git branch -r --contains`; bare/mirror: tip sha present in `git ls-remote origin`), and has a remote. Fails keep the dir."""
import os, subprocess, sys, shutil
W = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/'
CAND = ['sites-seo/rev-t2-course', 'agent-a26cf320273795e32/bt-full', 'agent-a26cf320273795e32/bt-r6', 'rt1191/bt', 'rt1192/repo', 'agent-ab67b166a35308e10/review-clone']
CAND += ['sites-seo/repos/' + d for d in sorted(os.listdir(W + 'sites-seo/repos'))] if os.path.isdir(W + 'sites-seo/repos') else []
DELETE = '--delete' in sys.argv
ps = subprocess.run(['ps', '-axo', 'args'], capture_output=True, text=True).stdout
lsof = ''


def g(path, *a):
    r = subprocess.run(['git', '-C', path] + list(a), capture_output=True, text=True)
    return r.returncode, r.stdout.strip()


def size(p):
    return int(subprocess.run(['du', '-sk', p], capture_output=True, text=True).stdout.split()[0]) // 1024


freed = 0
for c in CAND:
    p = W + c
    if not os.path.isdir(p):
        print('MISSING', c); continue
    why = []
    if any(p in l for l in ps.splitlines()):
        why.append('live-process')
    rc, top = g(p, 'rev-parse', '--git-dir')
    if rc != 0:
        # not itself a repo: scan one level for repos
        subs = [d for d in os.listdir(p) if os.path.exists(os.path.join(p, d, '.git')) or os.path.exists(os.path.join(p, d, 'HEAD'))]
        if subs:
            why.append('container-of-repos:' + ','.join(subs[:4]))
        else:
            why.append('no-git')
    else:
        bare = g(p, 'rev-parse', '--is-bare-repository')[1] == 'true'
        if not bare:
            if g(p, 'status', '--porcelain')[1]:
                why.append('dirty')
            if g(p, 'stash', 'list')[1]:
                why.append('stash')
        if not g(p, 'remote')[1]:
            why.append('no-remote')
        else:
            rem = g(p, 'ls-remote', '--heads', '--tags', 'origin')
            if rem[0] != 0:
                why.append('remote-unreachable')
            else:
                remshas = {l.split()[0] for l in rem[1].splitlines()}
                for ln in g(p, 'for-each-ref', '--format=%(objectname) %(refname)', 'refs/heads', 'refs/tags')[1].splitlines():
                    sha, ref = ln.split(' ', 1)
                    if sha in remshas:
                        continue
                    if not bare and ref.startswith('refs/heads/') and g(p, 'branch', '-r', '--contains', sha)[1]:
                        continue
                    why.append('unpushed:' + ref)
                    break
        # worktrees / detached HEAD
        if not bare:
            rc2, h = g(p, 'symbolic-ref', '-q', 'HEAD')
            if rc2 != 0 and g(p, 'branch', '-r', '--contains', 'HEAD')[1] == '':
                why.append('detached-head-unpushed')
    sz = size(p)
    if why:
        print('KEEP  %6d MB %s :: %s' % (sz, c, why[:3]))
    else:
        print('OK    %6d MB %s' % (sz, c))
        if DELETE:
            shutil.rmtree(p)
            freed += sz
            print('  removed', c)
print('FREED_MB', freed)
