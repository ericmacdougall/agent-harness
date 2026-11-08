"""Upload media parts from t2-dev to R2 via the Mac's logged-in wrangler; verify by download + sha256. Idempotent (state in r2up.state)."""
import json, subprocess, os, hashlib, sys
B = 'learnai-field-lab-media'
ENV = dict(os.environ, CLOUDFLARE_ACCOUNT_ID='13d81064a7db8648d9c595da226dffa2')
W = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/agent-ab8a7d1bf54ed3c9a/'
TMP = W + 'r2tmp/'
os.makedirs(TMP, exist_ok=True)
man = json.loads(subprocess.run(['ssh', 't2-dev', 'cat gq-branch-clean/tc/parts/media-manifest.json'], capture_output=True, text=True, check=True).stdout)
open(W + 'media-manifest.json', 'w').write(json.dumps(man, indent=1) + '\n')
state = set(open(W + 'r2up.state').read().split()) if os.path.exists(W + 'r2up.state') else set()


def sha(p):
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        for c in iter(lambda: f.read(1 << 20), b''):
            h.update(c)
    return h.hexdigest()


for part in man['parts']:
    k = part['key']
    if k in state:
        continue
    base = os.path.basename(k)
    src, chk = TMP + base, TMP + 'chk-' + base
    subprocess.run(['scp', '-q', 't2-dev:gq-branch-clean/tc/parts/' + base, src], check=True)
    assert sha(src) == part['sha256'], 'scp corrupted ' + base
    subprocess.run(['npx', '--yes', 'wrangler@4', 'r2', 'object', 'put', B + '/' + k, '--file', src, '--remote'], env=ENV, check=True, capture_output=True)
    subprocess.run(['npx', '--yes', 'wrangler@4', 'r2', 'object', 'get', B + '/' + k, '--file', chk, '--remote'], env=ENV, check=True, capture_output=True)
    ok = sha(chk) == part['sha256']
    print(k, 'uploaded+verified' if ok else 'VERIFY FAILED', flush=True)
    os.remove(src); os.remove(chk)
    if not ok:
        sys.exit(1)
    open(W + 'r2up.state', 'a').write(k + '\n')
print('ALL PARTS UPLOADED', len(man['parts']))
