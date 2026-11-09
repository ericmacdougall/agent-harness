#!/bin/bash
# on t2-dev: READ-ONLY Workers Builds probe for the learnai-field-lab worker, using the deploy-token pattern (token only in the process environment, never printed or written).
set -uo pipefail
. "$HOME/.agent-harness/lessons-private.env"
ACCT=13d81064a7db8648d9c595da226dffa2
CLOUDFLARE_API_TOKEN=$(gcloud secrets versions access latest --secret="$SECRET_DEPLOY_TOKEN" --project "$GCP_PROJECT") || { echo "token read failed"; exit 3; }
export CLOUDFLARE_API_TOKEN ACCT
python3 -I - <<'EOF'
import os, json, urllib.request, urllib.error
T = os.environ['CLOUDFLARE_API_TOKEN']; A = os.environ['ACCT']


def call(path):
    req = urllib.request.Request('https://api.cloudflare.com/client/v4' + path, headers={'Authorization': 'Bearer ' + T, 'Content-Type': 'application/json'})
    try:
        r = urllib.request.urlopen(req, timeout=30)
        return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read())
        except Exception:
            return e.code, {}


s, d = call('/accounts/%s/workers/services/learnai-field-lab' % A)
res = d.get('result') or {}
tag = (((res.get('default_environment') or {}).get('script') or {}).get('tag')) or res.get('id')
print('service lookup: http', s, 'success', d.get('success'), 'script tag found:', bool(tag), 'errors:', [e.get('message') for e in d.get('errors', [])][:2])
if tag:
    for name, path in (('triggers', '/accounts/%s/builds/workers/%s/triggers' % (A, tag)), ('builds', '/accounts/%s/builds/workers/%s/builds?limit=1' % (A, tag))):
        s, d = call(path)
        r = d.get('result')
        n = len(r) if isinstance(r, list) else (1 if r else 0)
        print('builds %s: http %s success %s results %s errors %s' % (name, s, d.get('success'), n, [e.get('message') for e in d.get('errors', [])][:2]))
EOF
unset CLOUDFLARE_API_TOKEN
