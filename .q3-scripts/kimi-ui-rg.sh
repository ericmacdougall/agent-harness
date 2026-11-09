#!/usr/bin/env bash
# t2-dev. Red (tests on old code) then green (with the fix) for Kimi UI batch 1; then neighbour suites and typecheck.
set -u
T=$HOME/wt/q3-kimi-ui; O=$HOME/wt/aab3-kimi-ui1.out
cd "$T" || exit 2
[ -z "$(git status --porcelain)" ] || { echo DIRTY_START; exit 2; }
cp "$HOME/wt/aab3-upload-reason.test.tsx" apps/web/src/components/messaging/message-composer-upload-reason.test.tsx
python3 "$HOME/wt/aab3-fix-kimi-ui-1.py" test || exit 3
TESTS="src/components/messaging/message-composer-upload-reason.test.tsx src/components/messaging/new-ai-thread-dialog.test.tsx"
run(){ timeout 900 pnpm --filter @bugtracker/web exec vitest run $1 > "$2" 2>&1; echo "$3 rc=$? $(sed 's/\x1b\[[0-9;]*m//g' "$2" | grep -E '^ +Tests ' | tr -s ' ')"; sed 's/\x1b\[[0-9;]*m//g' "$2" | grep -E '^ +(×|✗) ' | head -6 | cut -c1-200; }
run "$TESTS" "$O.red.log" red
python3 "$HOME/wt/aab3-fix-kimi-ui-1.py" src || exit 4
run "$TESTS" "$O.green.log" green
run "src/components/messaging/message-composer-secure.test.tsx src/components/messaging/message-composer-paste.test.tsx src/components/messaging/message-composer-delivery.test.tsx src/lib/upload-session-recovery.test.ts src/components/messaging/thread-panel.test.tsx" "$O.neigh.log" neighbours
( cd apps/web && timeout 900 npx tsc --noEmit -p . > "$O.tsc.log" 2>&1; echo "web tsc rc=$? errors=$(grep -c 'error TS' "$O.tsc.log")" )
grep 'error TS' "$O.tsc.log" | head -5 | cut -c1-200
( cd apps/web && timeout 600 npx eslint src/lib/uploads.ts src/components/messaging/message-composer.tsx src/components/messaging/new-ai-thread-dialog.tsx src/components/messaging/message-composer-upload-reason.test.tsx > "$O.lint.log" 2>&1; echo "eslint rc=$?" ); tail -5 "$O.lint.log" | cut -c1-200
git status --short
echo RG_END
