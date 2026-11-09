#!/usr/bin/env bash
# goodqa#14903 K2: run the K2 API test file in ~/wt/q3-kimi-create on a pgpool lease. Arg 1: label (red|green|...).
set -u
WT=$HOME/wt/q3-kimi-create; L=$HOME/wt/aab3-k2-api; LABEL=${1:-run}
cd "$WT" || exit 2
if [ ! -d node_modules ]; then
  pnpm install --frozen-lockfile --offline > "$L.install.log" 2>&1 || pnpm install --frozen-lockfile > "$L.install.log" 2>&1 || { echo INSTALL_FAILED; tail -5 "$L.install.log"; exit 3; }
fi
timeout 1500 python3 ~/repos/harness/lanes/pgpool.py run --mode server --job "aab3-k2-$LABEL" --lane qacq3 --ttl 1600 -- \
  pnpm --filter @bugtracker/api exec vitest run test/ai-thread-create-idempotency.test.ts ${EXTRA:-} > "$L.$LABEL.log" 2>&1
echo "$LABEL rc=$?"
grep -E "Tests |✓|×" "$L.$LABEL.log" | sed 's/\x1b\[[0-9;]*m//g' | head -30 | cut -c1-170
echo K2_API_END
