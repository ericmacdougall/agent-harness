#!/usr/bin/env bash
# Red-team probe P1 runner (goodqa#15561 S1e-a review). Out-of-tree test, worktree read-only, pooled test DB.
set -u
P=/home/eric/review-scratch/s1e-probe
cd /home/eric/wt-15561/apps/api || exit 2
export PATH="$PATH"
export PGPOOL_STATE=/home/eric/.local/state/pgpool
python3 /home/eric/repos/harness/lanes/pgpool.py run --job g15561-rt-probe --lane g15561-rt-probe --mode server --ttl 400 -- \
  pnpm exec vitest run --fileParallelism=false --dir "$P" test/s1e-oracle.test.ts > "$P/probe.log" 2>&1
RC=$?
sed 's/\x1b\[[0-9;]*m//g' "$P/probe.log" > "$P/probe.txt"
grep -E 'PROBE|✓|×|Test Files|Tests |FAIL|Error' "$P/probe.txt" | cut -c1-600 | head -60
echo "rc=$RC"
exit $RC
