"""Stream R2 media parts through the Mac (no Mac disk use) into t2-dev .media-cache. Idempotent."""
import json, subprocess, os, sys
env = dict(os.environ, CLOUDFLARE_ACCOUNT_ID='13d81064a7db8648d9c595da226dffa2')
man = json.load(open('/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/agent-ab8a7d1bf54ed3c9a/media-manifest.json'))
subprocess.run(['ssh', 't2-dev', 'mkdir -p gq-branch-clean/tc/work/.media-cache'], check=True)
for p in man['parts']:
    b = os.path.basename(p['key'])
    r = subprocess.run(['ssh', 't2-dev', f'stat -c %s gq-branch-clean/tc/work/.media-cache/{b} 2>/dev/null'], capture_output=True, text=True)
    if r.stdout.strip() == str(p['bytes']):
        continue
    g = subprocess.Popen(['npx', '--yes', 'wrangler@4', 'r2', 'object', 'get', 'learnai-field-lab-media/' + p['key'], '--remote', '--pipe'], env=env, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    s = subprocess.run(['ssh', 't2-dev', f'cat > gq-branch-clean/tc/work/.media-cache/{b}'], stdin=g.stdout)
    g.wait()
    print(b, 'rc', g.returncode, s.returncode, flush=True)
    if g.returncode or s.returncode:
        sys.exit(1)
print('STREAM DONE')
