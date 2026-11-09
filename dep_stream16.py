"""Stream R2 parts 1-6 through the Mac into the t2-dev deploy checkout's .media-cache (no credentials move: wrangler on the Mac reads R2 with its own login)."""
import json, subprocess, os, sys
env = dict(os.environ, CLOUDFLARE_ACCOUNT_ID='13d81064a7db8648d9c595da226dffa2')
man = json.load(open('/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/agent-ab8a7d1bf54ed3c9a/media-manifest.json'))
for p in man['parts'][:6]:
    b = os.path.basename(p['key'])
    g = subprocess.Popen(['npx', '--yes', 'wrangler@4', 'r2', 'object', 'get', 'learnai-field-lab-media/' + p['key'], '--remote', '--pipe'], env=env, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    s = subprocess.run(['ssh', 't2-dev', 'cat > /home/eric/gq-branch-clean/dep/t2c/.media-cache/' + b], stdin=g.stdout)
    g.wait()
    print(b, g.returncode, s.returncode, flush=True)
    if g.returncode or s.returncode:
        sys.exit(1)
print('STREAM16_DONE')
