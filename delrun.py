"""usage: delrun.py <repo>. Needs BACKUP_OK in t2-dev bk-<repo>.log, del-<repo>.txt from dec.py. Closes listed open PRs with a restore note, deletes lease-guarded, verifies."""
import sys, subprocess, json
repo = sys.argv[1]
W = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/agent-ab8a7d1bf54ed3c9a/'
log = subprocess.run(['ssh', 't2-dev', f'cat gq-branch-clean/r4/bk-{repo}.log'], capture_output=True, text=True).stdout
ok = [l for l in log.splitlines() if l.startswith('BACKUP_OK')]
if not ok or 'complete history' not in log or 'differences found' not in log or ' 0 differences found' not in log:
    sys.exit('NO VERIFIED BACKUP for ' + repo)
parts = ok[-1].split()
dest, sha = parts[2], parts[3]
for l in open(W + f'prclose-{repo}.txt'):
    n, b = l.split(None, 1)
    note = (f'Closing as part of branch hygiene (stale, superseded or conflicting branch `{b.strip()}`). Nothing was lost: the full repository bundle '
            f'(sha256 {sha[:16]}...) is at Dropbox {dest}. Restore: `git fetch <bundle> refs/heads/{b.strip()}:refs/heads/{b.strip()}` and reopen this PR.')
    r = subprocess.run(['gh', 'pr', 'close', n, '-R', f'ericmacdougall/{repo}', '-c', note], capture_output=True, text=True)
    print('PR', n, r.returncode, (r.stderr or r.stdout).strip()[:100])
subprocess.run(['scp', '-q', W + f'del-{repo}.txt', 't2-dev:gq-branch-clean/r4/'], check=True)
r = subprocess.run(['ssh', 't2-dev', f'bash gq-branch-clean/r4/del.sh {repo}'], capture_output=True, text=True)
print(r.stdout, r.stderr[-200:])
n = subprocess.run(['gh', 'api', f'repos/ericmacdougall/{repo}/branches?per_page=100', '--paginate', '-q', '.[].name'], capture_output=True, text=True).stdout.split()
print(repo, 'branches now', len(n))
