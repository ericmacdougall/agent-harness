"""Age no longer matters (main, 2026-11-09; the 14-day age rule is an ASSUMPTION). Delete every branch that is NOT: the head of an open PR, a branch a live owner is using
(branch name mentioned in a WAL touched in the last 24h, or checked out in a worktree on t2-dev), or a release/* branch mentioned in a recent WAL. Writes del7-<repo>.txt (branch sha)."""
import json, subprocess, glob, os, time, sys
W = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/agent-ab8a7d1bf54ed3c9a/'
REPOS = sys.argv[1:] or ['timbar', 'poopyduck', 'interview-prep', 'bugtracker', 'bugtracker-harness']
wal = []
for f in glob.glob('/Users/eric/.claude/wals/*/*.jsonl'):
    if time.time() - os.path.getmtime(f) < 24 * 3600 and 'agent-ab8a7d1bf54ed3c9a' not in f:
        wal.append(open(f, errors='ignore').read())
wal = '\n'.join(wal)
print('recent WAL text:', len(wal) // 1000000, 'MB')
# worktrees on t2-dev (branch names checked out in any repo clone there)
wt = subprocess.run(['ssh', 't2-dev', 'for g in $(find /home/eric /srv -maxdepth 5 -name .git 2>/dev/null | head -300); do d=$(dirname $g); git -C $d worktree list --porcelain 2>/dev/null | grep "^branch " | sed "s#branch refs/heads/##"; done | sort -u'], capture_output=True, text=True).stdout.split()
print('t2-dev checked-out branches:', len(wt))
wtset = set(wt)
for r in REPOS:
    prs = json.loads(subprocess.run(['gh', 'pr', 'list', '-R', 'ericmacdougall/' + r, '--state', 'open', '--json', 'number,headRefName,updatedAt,title,isDraft', '--limit', '300'], capture_output=True, text=True).stdout or '[]')
    openheads = {p['headRefName']: p for p in prs}
    rows = [l.rstrip('\n').split('\t') for l in open(W + 'c-%s.tsv' % r)]
    dele, keep = [], []
    for b, sha, age, merged, uniq, behind, conf in rows:
        why = None
        if b in openheads:
            why = 'open-PR #%d' % openheads[b]['number']
        elif b in wtset:
            why = 'checked-out-in-a-t2-dev-worktree'
        elif len(b) > 8 and b in wal:
            why = 'named-in-a-WAL-touched-in-24h' + (' (release)' if b.startswith('release/') else '')
        elif b.startswith('claude/qac-q3-'):
            why = 'qac-q3 (never delete, in active use)'
        if why:
            keep.append((b, why))
        else:
            dele.append((b, sha))
    open(W + 'del7-%s.txt' % r, 'w').write(''.join('%s %s\n' % x for x in dele))
    print(r, 'total', len(rows) + 1, 'delete', len(dele), 'keep', len(keep) + 1)
    for b, w in keep:
        print('   KEEP', b, '|', w)
    if len(keep) + 1 >= 10:
        print('   STILL >=10: open PRs kept:')
        for b, w in keep:
            if w.startswith('open-PR'):
                p = openheads[b]
                print('     #%d %s last activity %s draft=%s | %s' % (p['number'], b, p['updatedAt'], p['isDraft'], p['title'][:70]))
