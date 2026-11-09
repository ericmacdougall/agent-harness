#!/bin/bash
# on t2-dev: VERIFYING deploy of t2-course main fc842900 (routes block removed, PR 52). Same token pattern as dep_run.sh (gcloud -> process env only, never printed, unset).
# Steps: fresh shallow clone, media parts from the verified Dropbox copy, npm ci, media:pull, build, gate, read-only domain check BEFORE, npm run deploy, domain check AFTER, workers.dev check.
# Aborts if free space falls under 11 GB (and refuses to start under 20 GB). Logs to dep2_run.log, token never appears in it.
set -uo pipefail
D=/home/eric/gq-branch-clean/dep2; LOG=/home/eric/gq-branch-clean/dep2_run.log; : > $LOG
CONF="$HOME/.agent-harness/lessons-private.env"; [ -r "$CONF" ] || { echo "missing $CONF" >> $LOG; exit 2; }
. "$CONF"
free() { df -BG / | awk 'NR==2{print $4}' | tr -d G; }
chk() { f=$(free); echo "[$1] free ${f}G" >> $LOG; [ "$f" -lt 11 ] && { echo "ABORT: free space ${f}G under the 11G guard" >> $LOG; exit 9; }; }
f=$(free); echo "[start] free ${f}G" >> $LOG; [ "$f" -lt 20 ] && { echo "NOT STARTED: need 20G free, have ${f}G" >> $LOG; exit 8; }
rm -rf $D; mkdir -p $D; cd $D
git clone -q --depth 1 git@github.com:ericmacdougall/t2-course.git t2c || { echo "clone failed" >> $LOG; exit 1; }
cd t2c
H=$(git rev-parse HEAD); echo "HEAD $H" >> $LOG
[ "$H" = "fc842900398bc3ba209090c81c81b682e7d415b3" ] || { echo "ABORT: main is not fc842900" >> $LOG; exit 2; }
export CLOUDFLARE_ACCOUNT_ID=$(sed -n 's/.*"account_id"[[:space:]]*:[[:space:]]*"\([0-9a-f]*\)".*/\1/p' wrangler.cloudflare.jsonc | head -1)
echo "--- media parts from Dropbox (verified copy)" >> $LOG
mkdir -p .media-cache
rclone copy dropbox:Backups/repo-archives-private/t2-course-media-parts-20261108 .media-cache --include "part-*.tar" --tpslimit 2 --transfers 2 >> $LOG 2>&1
echo "parts in cache: $(ls .media-cache | wc -l) (need 25)" >> $LOG; chk after-parts
[ "$(ls .media-cache | wc -l)" = "25" ] || { echo "ABORT: cache incomplete" >> $LOG; exit 3; }
echo "--- npm ci" >> $LOG; npm ci >> $LOG 2>&1; echo "rc=$?" >> $LOG; chk after-npm-ci
echo "--- media:pull" >> $LOG; npm run media:pull >> $LOG 2>&1; rc=$?; echo "rc=$rc" >> $LOG; chk after-pull; [ $rc = 0 ] || exit 4
echo "--- build" >> $LOG; npm run build >> $LOG 2>&1; rc=$?; echo "rc=$rc" >> $LOG; chk after-build; [ $rc = 0 ] || exit 5
echo "--- gate" >> $LOG; node scripts/media-sync.mjs gate >> $LOG 2>&1; rc=$?; echo "gate rc=$rc" >> $LOG; [ $rc = 0 ] || exit 6
grep -c '"routes"' wrangler.cloudflare.jsonc | sed 's/^/routes keys in config: /' >> $LOG
CLOUDFLARE_API_TOKEN=$(gcloud secrets versions access latest --secret="$SECRET_DEPLOY_TOKEN" --project "$GCP_PROJECT") || { echo "token read failed" >> $LOG; exit 7; }
export CLOUDFLARE_API_TOKEN
dom() {  # read-only: is the custom domain still attached to this worker service?
python3 -I - "$1" >> $LOG <<'EOF'
import os, sys, json, urllib.request, urllib.error
T = os.environ['CLOUDFLARE_API_TOKEN']; A = os.environ['CLOUDFLARE_ACCOUNT_ID']
def call(p):
    req = urllib.request.Request('https://api.cloudflare.com/client/v4' + p, headers={'Authorization': 'Bearer ' + T})
    try:
        r = urllib.request.urlopen(req, timeout=30); return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        try: return e.code, json.loads(e.read())
        except Exception: return e.code, {}
s, d = call('/accounts/%s/workers/domains?service=learnai-field-lab' % A)
res = d.get('result') or []
print('DOMAINS %s: http %s success %s attached=%s hostnames=%s errors=%s' % (sys.argv[1], s, d.get('success'), any(x.get('hostname') == 'learnai.ericmacdougall.com' for x in res), [x.get('hostname') for x in res][:5], [e.get('message') for e in d.get('errors', [])][:1]))
s, d = call('/accounts/%s/workers/subdomain' % A)
print('SUBDOMAIN %s: http %s name=%s' % (sys.argv[1], s, (d.get('result') or {}).get('subdomain')))
s, d = call('/accounts/%s/workers/scripts/learnai-field-lab/subdomain' % A)
print('WORKERS_DEV flags %s: http %s result=%s' % (sys.argv[1], s, {k: v for k, v in (d.get('result') or {}).items() if k in ('enabled', 'previews_enabled')}))
EOF
}
dom before
echo "-- versions before:" >> $LOG; npx --no-install wrangler deployments list --config wrangler.cloudflare.jsonc 2>&1 | grep -E "Created|Version\(s\)|\(100%\)" | tail -4 >> $LOG
echo "-- npm run deploy:" >> $LOG; npm run deploy > /tmp/.tcdeploy2.$$ 2>&1; rc=$?
sed -E 's/(Bearer |token[=: ]+)[A-Za-z0-9_-]{16,}/\1<redacted>/g' /tmp/.tcdeploy2.$$ | tail -25 >> $LOG
echo "deploy rc=$rc" >> $LOG
grep -c "No deploy targets for" /tmp/.tcdeploy2.$$ | sed 's/^/lines "No deploy targets for": /' >> $LOG
grep -c "workers.dev" /tmp/.tcdeploy2.$$ | sed 's/^/lines mentioning workers.dev: /' >> $LOG
rm -f /tmp/.tcdeploy2.$$
echo "-- versions after:" >> $LOG; npx --no-install wrangler deployments list --config wrangler.cloudflare.jsonc 2>&1 | grep -E "Created|Version\(s\)|\(100%\)" | tail -4 >> $LOG
dom after
unset CLOUDFLARE_API_TOKEN
chk end
echo "DEP2_DONE rc=$rc" >> $LOG
