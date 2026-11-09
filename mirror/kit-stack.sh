#!/usr/bin/env bash
# goodqa#15561 click-test kit, runs INSIDE a pgpool lease (see run.sh). LOCAL, disposable, never production.
# Starts the API (tsx, production entrypoint, console email, disk storage) and the web (next build + start) of the checkout in
# $TREE, seeds disposable data, prints a JSON summary (ids and file paths, never a secret value), then waits until stopped.
set -u
TREE="${TREE:?TREE}"; KIT="${KIT:-$HOME/g15561-click}"; API_PORT="${API_PORT:-43561}"; WEB_PORT="${WEB_PORT:-43562}"
mkdir -p "$KIT/run" "$KIT/secrets"; chmod 700 "$KIT/secrets"
: "${DATABASE_URL:?DATABASE_URL must come from the pool lease}"
export NODE_ENV=production DEPLOY_ENV=dev PORT="$API_PORT"
JWT_SECRET="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"; export JWT_SECRET
CRON_TOKEN="$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"; export CRON_TOKEN
export WEB_ORIGIN="http://127.0.0.1:$WEB_PORT" OAUTH_REDIRECT_BASE="http://127.0.0.1:$WEB_PORT" API_PUBLIC_URL="http://127.0.0.1:$API_PORT"
export STORAGE_DRIVER=disk UPLOAD_DIR="$KIT/run/uploads" EMAIL_DRIVER=console TASK_298_ATTACHMENT_FINAL_GATE_ENABLED=true
RELEASE_SOURCE_SHA="$(git -C "$TREE" rev-parse HEAD)"; export RELEASE_SOURCE_SHA RELEASE_DEPLOYMENT_ID=click-kit-15561
cleanup() {
  [ -n "${API_PID:-}" ] && kill -- "-$API_PID" 2>/dev/null
  [ -n "${WEB_PID:-}" ] && kill -- "-$WEB_PID" 2>/dev/null
  rm -f "$TREE/apps/api/.click-seed.ts"; rm -rf "$KIT/secrets"/*
  echo "kit stopped, secrets removed"
}
trap cleanup EXIT INT TERM
cd "$TREE" && node packages/db/scripts/migrate.mjs > "$KIT/run/migrate.log" 2>&1 || { echo "migrate failed, see $KIT/run/migrate.log"; exit 1; }
cd "$TREE/apps/api" && setsid ./node_modules/.bin/tsx --import ./src/instrument.ts src/server.ts > "$KIT/run/api.log" 2>&1 &
API_PID=$!
for i in $(seq 1 90); do curl -fsS "http://127.0.0.1:$API_PORT/v1/version" > "$KIT/run/version.json" 2>/dev/null && break; sleep 2; done
grep -q "$RELEASE_SOURCE_SHA" "$KIT/run/version.json" || { echo "API did not report the candidate sha"; exit 1; }
cd "$TREE/apps/web" && API_PROXY_TARGET="http://127.0.0.1:$API_PORT" NEXT_PUBLIC_API_URL='' NEXT_TELEMETRY_DISABLED=1 NODE_OPTIONS=--max-old-space-size=8192 pnpm exec next build > "$KIT/run/web-build.log" 2>&1 || { echo "web build failed, see $KIT/run/web-build.log"; exit 1; }
API_PROXY_TARGET="http://127.0.0.1:$API_PORT" NEXT_PUBLIC_API_URL='' setsid pnpm exec next start --port "$WEB_PORT" > "$KIT/run/web.log" 2>&1 &
WEB_PID=$!
for i in $(seq 1 60); do curl -fsS -o /dev/null "http://127.0.0.1:$WEB_PORT/login" 2>/dev/null && break; sleep 2; done
cp "$KIT/seed.ts" "$TREE/apps/api/.click-seed.ts"
cd "$TREE/apps/api" && API_URL="http://127.0.0.1:$API_PORT" SECRETS_DIR="$KIT/secrets" ./node_modules/.bin/tsx .click-seed.ts > "$KIT/run/summary.json" 2> "$KIT/run/seed.err" || { echo "seed failed, see $KIT/run/seed.err"; exit 1; }
echo "READY api=http://127.0.0.1:$API_PORT web=http://127.0.0.1:$WEB_PORT sha=$RELEASE_SOURCE_SHA summary=$KIT/run/summary.json"
while true; do sleep 30; done
