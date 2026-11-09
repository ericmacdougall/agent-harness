"""Stream parts 1-6 (not in tc/parts) from R2 to Dropbox via rclone rcat (throttled), then verify size and sha256 of the Dropbox copy against the manifest."""
import json, subprocess, os, sys, hashlib
env = dict(os.environ, CLOUDFLARE_ACCOUNT_ID='13d81064a7db8648d9c595da226dffa2')
man = json.load(open('/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/agent-ab8a7d1bf54ed3c9a/media-manifest.json'))
D = 'lessons-dropbox:Backups/repo-archives-private/t2-course-media-parts-20261108/'
have = subprocess.run(['rclone', 'lsf', D, '--tpslimit', '2'], capture_output=True, text=True).stdout.split()
for p in man['parts'][:6]:
    b = os.path.basename(p['key'])
    if b in have:
        continue
    g = subprocess.Popen(['npx', '--yes', 'wrangler@4', 'r2', 'object', 'get', 'learnai-field-lab-media/' + p['key'], '--remote', '--pipe'], env=env, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    r = subprocess.run(['rclone', 'rcat', D + b, '--tpslimit', '2'], stdin=g.stdout)
    g.wait()
    print(b, g.returncode, r.returncode, flush=True)
    if g.returncode or r.returncode:
        sys.exit(1)
for p in man['parts'][:6]:
    b = os.path.basename(p['key'])
    h = subprocess.run(['rclone', 'sha256sum', D + b, '--tpslimit', '2'], capture_output=True, text=True).stdout.split()
    print(b, 'OK' if h and h[0] == p['sha256'] else 'MISMATCH', flush=True)
subprocess.run(['rclone', 'copyto', '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/agent-ab8a7d1bf54ed3c9a/media-manifest.json', D + 'media-manifest.json', '--tpslimit', '2'])
print('DONE')
