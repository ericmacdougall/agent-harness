#!/usr/bin/env bash
# Runs on t2-dev in ~/wt/q3-kimi. Red (sources at HEAD) then green (working tree) for the privacy fix:
# api test test/qac-ai-thread-invite-link.test.ts (pgpool) and web test channel-header-words.test.tsx.
set -u
cd "$HOME/wt/q3-kimi" || exit 2
L=$HOME/wt/aab3-priv
SRCS="apps/api/src/modules/orgs/routes.ts apps/api/src/modules/orgs/invite-links.ts apps/web/src/components/messaging/conversation-pane.tsx"
for f in $SRCS; do cp "$f" "$L.$(basename "$f").fixed"; git show "HEAD:$f" > "$f"; done
api() { timeout 1200 python3 ~/repos/harness/lanes/pgpool.py run --mode server --job "aab3-priv-$1" --lane qacq3 --ttl 1300 -- \
  pnpm --filter @bugtracker/api exec vitest run test/qac-ai-thread-invite-link.test.ts > "$L.api-$1.log" 2>&1
  echo "api-$1 rc=$? $(sed 's/\x1b\[[0-9;]*m//g' "$L.api-$1.log" | grep -E '^ +Tests ' | tr -s ' ')"; }
web() { timeout 900 pnpm --filter @bugtracker/web exec vitest run src/components/messaging/channel-header-words.test.tsx > "$L.web-$1.log" 2>&1
  echo "web-$1 rc=$? $(sed 's/\x1b\[[0-9;]*m//g' "$L.web-$1.log" | grep -E '^ +Tests ' | tr -s ' ')"
  sed 's/\x1b\[[0-9;]*m//g' "$L.web-$1.log" | grep -E '^ +× ' | head -4 | cut -c1-180; }
web red
for f in $SRCS; do cp "$L.$(basename "$f").fixed" "$f"; done
api green
web green
git status --short
echo PRIV_END
