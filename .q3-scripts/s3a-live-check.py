# goodqa#14903 S3a post-deploy API check on goodqa.app, in QA org FrameBright, with the user token (never printed).
# Mint on Kimi residue thread 08a474cf must be refused. A 201 means the fix is not live: the link is revoked at once
# and the check fails. Stores nothing when it passes. Usage: s3a-live-check.py <sha prefix>
import json, os, sys, time, urllib.request, urllib.error
WANT = sys.argv[1]; ORG = 'a19d343e-f162-4a05-849d-4565e90e4b3f'; THREAD = '08a474cf-001e-43b8-b775-309cf3d866b8'
tok = open(os.path.expanduser('~/.config/goodqa/user-token')).read().strip()
def call(method, path, body=None, auth=True):
    h = {'Authorization': 'Bearer ' + tok} if auth else {}
    data = None
    if body is not None:
        data = json.dumps(body).encode(); h['Content-Type'] = 'application/json'
    for _ in range(6):
        try:
            with urllib.request.urlopen(urllib.request.Request('https://goodqa.app/v1' + path, headers=h, data=data, method=method), timeout=30) as r:
                raw = r.read(); return r.status, json.loads(raw or b'{}')
        except urllib.error.HTTPError as e:
            raw = e.read()
            try: parsed = json.loads(raw)
            except Exception: parsed = {}
            if e.code != 429: return e.code, parsed
            time.sleep(float(((parsed.get('error') or {}).get('details') or {}).get('retryAfterSeconds', 1)) + 0.5)
    return 429, {}
bad = 0
s, v = call('GET', '/version', auth=False); sha = v.get('sourceSha', '')
print('version', s, sha); bad += not sha.startswith(WANT)
s, o = call('GET', '/orgs'); names = {x.get('id'): x.get('name') for x in (o.get('orgs') or [])}
print('org', names.get(ORG)); bad += names.get(ORG) != 'FrameBright'
s, m = call('POST', f'/orgs/{ORG}/invite-links', {'orgRole': 'member', 'conversationId': THREAD})
err = (m.get('error') or {}) if isinstance(m, dict) else {}
print('mint on AI thread:', s, err.get('code'), err.get('message'))
if s == 201:
    link = (m.get('inviteLink') or {}).get('id')
    rs, _ = call('DELETE', f'/orgs/{ORG}/invite-links/{link}')
    print('FIX NOT LIVE: minted link', link, 'revoke status', rs); bad += 1
elif not (s == 400 and 'AI threads are shared from the thread itself' in str(err.get('message'))):
    print('unexpected mint outcome'); bad += 1
s, l = call('GET', f'/orgs/{ORG}/invite-links')
links = l.get('inviteLinks', l.get('links', l.get('items', []))) if isinstance(l, dict) else []
hit = [x.get('id') for x in links if x.get('conversationId') == THREAD]
print('list', s, 'links on this thread:', len(hit)); bad += s != 200 or bool(hit)
print('S3A-LIVE-CHECK:', 'PASS' if bad == 0 else f'FAIL ({bad})')
sys.exit(1 if bad else 0)
