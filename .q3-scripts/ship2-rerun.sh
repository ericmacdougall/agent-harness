#!/usr/bin/env bash
# Runs on t2-dev. Exact-head rerun of the gates that ship2.sh ran before the N2/N3 pick reached its worktree at
# 20:59:30Z (tsc, s3a, ai-thread-invite-link, S1, S2, waits-drafts). Later suites in that run started on this head.
set -u
WANT=7a459f866d91ce0a41413e1491f2420c11c7be49
T=$HOME/wt/q3-ship2; L=$HOME/wt/aab3-rerun
until grep -q SHIP2_END "$HOME/wt/aab3-ship2.out"; do sleep 10; done
cd "$T" || exit 2
head_ok() { [ "$(git rev-parse HEAD)" = "$WANT" ] && [ -z "$(git status --porcelain)" ]; }
head_ok || { echo "HEAD_OR_TREE_MISMATCH $(git rev-parse HEAD) dirty=$(git status --porcelain | wc -l)"; echo RERUN_END; exit 3; }
echo "HEAD $WANT TREE $(git rev-parse HEAD^{tree}) start $(date -u +%H:%M:%S)"
bash "$HOME/wt/aab3-tsc-gate.sh" "$T" "$L.tsc.log"; grep "error TS" "$L.tsc.log"
for b in qac-run-reports-s3a qac-ai-thread-invite-link qac-workflow-drafts-s1 qac-workflow-drafts-s2 automations-waits-drafts; do
  timeout 1500 python3 ~/repos/harness/lanes/pgpool.py run --mode server --job "aab3-rerun-$b" --lane qacq3 --ttl 1600 -- \
    pnpm --filter @bugtracker/api exec vitest run "test/$b.test.ts" > "$L.$b.log" 2>&1
  rc=$?; echo "$b rc=$rc $(sed 's/\x1b\[[0-9;]*m//g' "$L.$b.log" | grep -E '^ +Tests ' | tr -s ' ')"
  [ $rc = 0 ] || sed 's/\x1b\[[0-9;]*m//g' "$L.$b.log" | grep -E '^ FAIL ' | head -6 | cut -c1-220
done
head_ok && echo "HEAD_STABLE $WANT" || echo "HEAD_MOVED $(git rev-parse HEAD)"
echo RERUN_END
