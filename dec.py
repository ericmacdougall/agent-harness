"""usage: dec.py <repo>  -> reads c-<repo>.tsv (fetched from t2-dev), writes del-<repo>.txt, and prints the keep list + reasons."""
import sys, json, subprocess, datetime as D, re
W = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/agent-ab8a7d1bf54ed3c9a/'
repo = sys.argv[1]
prs = json.loads(subprocess.run(['gh', 'pr', 'list', '-R', f'ericmacdougall/{repo}', '--state', 'all', '--limit', '500', '--json', 'number,headRefName,headRefOid,state,updatedAt'], capture_output=True, text=True).stdout or '[]')
cut = (D.datetime.now(D.timezone.utc) - D.timedelta(days=14)).isoformat()
byb = {}
for p in prs:
    byb.setdefault(p['headRefName'], []).append(p)
keep, dele, close = [], [], []
for l in open(W + f'c-{repo}.tsv'):
    b, sha, age, merged, uniq, behind, conf = l.rstrip('\n').split('\t')
    age, merged, uniq, behind = int(age), int(merged), int(uniq), int(behind)
    c = 999 if conf == 'ERR' else int(conf)
    ps = byb.get(b, [])
    openp = [p for p in ps if p['state'] == 'OPEN']
    mergedp = [p for p in ps if p['state'] == 'MERGED' and p['headRefOid'] == sha]
    if re.match(r'release/', b) or b.startswith('claude/qac-q3-'):
        keep.append((b, 'protected-name')); continue
    if openp and max(p['updatedAt'] for p in openp) >= cut:
        keep.append((b, 'open-PR-active')); continue
    why = []
    if age >= 14: why.append('stale')
    if merged or uniq == 0 or mergedp: why.append('superseded')
    if c > 10 or (behind > 300 and c > 0): why.append('conflict')
    if why:
        dele.append((b, sha, '+'.join(why)))
        for p in openp: close.append((p['number'], b))
    else:
        keep.append((b, f'young-unmerged age={age} uniq={uniq} conf={conf}'))
open(W + f'del-{repo}.txt', 'w').write(''.join(f'{b} {s}\n' for b, s, _ in dele))
open(W + f'prclose-{repo}.txt', 'w').write(''.join(f'{n} {b}\n' for n, b in close))
open(W + f'why-{repo}.txt', 'w').write(''.join(f'{b} {s} {w}\n' for b, s, w in dele))
print(repo, 'delete', len(dele), 'keep', len(keep), '+default; open PRs to close', len(close))
for b, w in keep:
    print('   KEEP', b, w)
