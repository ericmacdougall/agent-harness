#!/bin/bash
# on t2-dev: deploy t2-course main through `npm run deploy`, using the lessons deploy-token pattern (apollo_deploy.sh): the Cloudflare token is read by
# gcloud from Secret Manager into this process's environment only, never printed, never written, never in an argument, then unset.
# Aborts if free space falls under 11 GB. Logs to dep_run.log (token never appears in it).
set -uo pipefail
D=/home/eric/gq-branch-clean/dep/t2c; cd $D || exit 1
LOG=/home/eric/gq-branch-clean/dep_run.log; : > $LOG
CONF="$HOME/.agent-harness/lessons-private.env"; [ -r "$CONF" ] || { echo "missing $CONF" >> $LOG; exit 2; }
. "$CONF"
free() { df -BG / | awk 'NR==2{print $4}' | tr -d G; }
chk() { f=$(free); echo "[$1] free ${f}G" >> $LOG; [ "$f" -lt 11 ] && { echo "ABORT: free space ${f}G under the 11G guard" >> $LOG; exit 9; }; }
export CLOUDFLARE_ACCOUNT_ID=$(sed -n 's/.*"account_id"[[:space:]]*:[[:space:]]*"\([0-9a-f]*\)".*/\1/p' wrangler.cloudflare.jsonc | head -1)
echo "account from wrangler.cloudflare.jsonc: $CLOUDFLARE_ACCOUNT_ID" >> $LOG
chk start
# parts present?
echo "parts in cache: $(ls .media-cache | wc -l) (need 25)" >> $LOG
[ "$(ls .media-cache | wc -l)" = "25" ] || { echo "ABORT: cache incomplete" >> $LOG; exit 3; }
echo "--- npm ci" >> $LOG; npm ci >> $LOG 2>&1; echo "rc=$?" >> $LOG; chk after-npm-ci
echo "--- media:pull" >> $LOG; npm run media:pull >> $LOG 2>&1; rc=$?; echo "rc=$rc" >> $LOG; chk after-pull; [ $rc = 0 ] || exit 4
echo "--- build" >> $LOG; npm run build >> $LOG 2>&1; rc=$?; echo "rc=$rc" >> $LOG; chk after-build; [ $rc = 0 ] || exit 5
echo "--- gate dry check (no token)" >> $LOG; node scripts/media-sync.mjs gate >> $LOG 2>&1; rc=$?; echo "gate rc=$rc" >> $LOG; [ $rc = 0 ] || exit 6
echo "--- read token and deploy" >> $LOG
CLOUDFLARE_API_TOKEN=$(gcloud secrets versions access latest --secret="$SECRET_DEPLOY_TOKEN" --project "$GCP_PROJECT") || { echo "token read failed" >> $LOG; exit 7; }
export CLOUDFLARE_API_TOKEN
echo "-- versions before:" >> $LOG; npx --no-install wrangler deployments list --config wrangler.cloudflare.jsonc 2>&1 | grep -E "Created|Version\(s\)|\(100%\)" | tail -4 >> $LOG
echo "-- npm run deploy:" >> $LOG; npm run deploy > /tmp/.tcdeploy.$$ 2>&1; rc=$?
sed -E 's/(Bearer |token[=: ]+)[A-Za-z0-9_-]{16,}/\1<redacted>/g' /tmp/.tcdeploy.$$ | tail -30 >> $LOG; rm -f /tmp/.tcdeploy.$$
echo "deploy rc=$rc" >> $LOG
echo "-- versions after:" >> $LOG; npx --no-install wrangler deployments list --config wrangler.cloudflare.jsonc 2>&1 | grep -E "Created|Version\(s\)|\(100%\)" | tail -4 >> $LOG
unset CLOUDFLARE_API_TOKEN
chk end
echo "DEP_DONE rc=$rc" >> $LOG
