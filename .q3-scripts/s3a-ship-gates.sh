#!/usr/bin/env bash
# Runs on t2-dev. S3a ship candidate gates on worktree ~/wt/q3-s3a-ship (branch claude/qac-q3-s3-ship):
# install from lockfile, tsc gate (only the known base error goodqa#15113 allowed), focused + regression vitest
# files, one process per file, through pgpool. Logs: ~/wt/aab3-ship.*.log
set -u
T=$HOME/wt/q3-s3a-ship; L=$HOME/wt/aab3-ship
cd "$T" || exit 2
echo "HEAD $(git rev-parse HEAD) TREE $(git rev-parse HEAD^{tree}) DIRTY=$(git status --porcelain | wc -l)"
[ -d node_modules ] || { timeout 1500 pnpm install --frozen-lockfile --prefer-offline > "$L.install.log" 2>&1; echo "install_rc=$?"; }
bash "$HOME/wt/aab3-tsc-gate.sh" "$T" "$L.tsc.log"
for f in test/qac-run-reports-s3a.test.ts test/qac-workflow-drafts-s1.test.ts test/qac-workflow-drafts-s2.test.ts \
         test/automations-waits-drafts.test.ts test/automation-schedule-trigger.test.ts test/automation-workflow-history.test.ts \
         test/commander-actions.test.ts test/automation-capabilities-parity.test.ts; do
  b=$(basename "$f" .test.ts)
  [ -f "apps/api/$f" ] || { echo "$b MISSING"; continue; }
  timeout 1500 python3 ~/repos/harness/lanes/pgpool.py run --mode server --job "aab3-ship-$b" --lane qacq3 --ttl 1600 -- \
    pnpm --filter @bugtracker/api exec vitest run "$f" > "$L.$b.log" 2>&1
  rc=$?; echo "$b rc=$rc $(sed 's/\x1b\[[0-9;]*m//g' "$L.$b.log" | grep -E '^ +Tests ' | tr -s ' ')"
  [ $rc = 0 ] || sed 's/\x1b\[[0-9;]*m//g' "$L.$b.log" | grep -E '^ FAIL ' | head -6 | cut -c1-220
done
echo "PORCELAIN $(git status --porcelain | wc -l)"
echo GATES_END
