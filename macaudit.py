import os, subprocess, time
W = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/'
ps = subprocess.run(['ps', '-axo', 'args'], capture_output=True, text=True).stdout
for d in ['l1-deploy', 'sites-seo', 'agent-a26cf320273795e32', 'sites', 'rt1191', 'rt1192', 'agent-ab67b166a35308e10', 'agent-ad693d1f419a19ff9', 'agent-afbfda63d7383957d', 'agent-a4d180f0adade1a14', 'borrow', 'repo-diet']:
    root = W + d
    newest = 0
    for dp, dn, fn in os.walk(root):
        dn[:] = [x for x in dn if x not in ('node_modules', '.git')]
        for f in fn:
            try:
                newest = max(newest, os.lstat(os.path.join(dp, f)).st_mtime)
            except OSError:
                pass
    sub = sorted(((sum(os.path.getsize(os.path.join(a, b)) for a, _, c in os.walk(os.path.join(root, s)) for b in c if os.path.isfile(os.path.join(a, b))) // 1048576, s) for s in os.listdir(root) if s not in ('.git',) and os.path.isdir(os.path.join(root, s))), reverse=True)[:2]
    live = sum(1 for l in ps.splitlines() if root in l)
    print(d, 'newest(non-node_modules/.git):', time.strftime('%m-%d %H:%M', time.localtime(newest)) if newest else '-', 'live-procs', live, 'top:', sub)
