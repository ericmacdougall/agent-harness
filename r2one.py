import json, subprocess, os, sys
env = dict(os.environ, CLOUDFLARE_ACCOUNT_ID='13d81064a7db8648d9c595da226dffa2')
man = json.load(open('/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/agent-ab8a7d1bf54ed3c9a/media-manifest.json'))
want = sys.argv[1]
p = [x for x in man['parts'] if os.path.basename(x['key']).startswith(want)][0]
b = os.path.basename(p['key'])
subprocess.run(['ssh', 't2-dev', 'mkdir -p gq-branch-clean/tc/work/.media-cache'], check=True)
g = subprocess.Popen(['npx', '--yes', 'wrangler@4', 'r2', 'object', 'get', 'learnai-field-lab-media/' + p['key'], '--remote', '--pipe'], env=env, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
s = subprocess.run(['ssh', 't2-dev', f'cat > gq-branch-clean/tc/work/.media-cache/{b}'], stdin=g.stdout)
g.wait()
print(b, g.returncode, s.returncode)
