#!/usr/bin/env bash
# Runs on t2-dev. usage: run-s3a.sh <label> [mutant]   mutant=M31 swaps hourStart(now) for hourStart(run.finishedAt).
# Runs vitest files one per process through pgpool in ~/wt/q3-s3a-aab3; logs to ~/wt/aab3-<label>.*.log
set -u
WT=$HOME/wt/q3-s3a-aab3; L=$HOME/wt/aab3-$1; MUT=${2:-}
cd "$WT" || exit 2
echo "HEAD $(git rev-parse HEAD) TREE $(git add -A -n . >/dev/null; git stash create 2>/dev/null || echo clean)"
[ -d node_modules ] || { timeout 1500 pnpm install --frozen-lockfile --prefer-offline > "$L.install.log" 2>&1; echo "install_rc=$?"; }
RR=apps/api/src/modules/automations/run-reports.ts
if [ "$MUT" = M31 ]; then
  cp "$RR" "$L.rr.bak"
  python3 -I - "$RR" <<'PY'
import sys,pathlib
p=pathlib.Path(sys.argv[1]); s=p.read_text(); a="    const hour = hourStart(now);"
assert s.count(a)==1; p.write_text(s.replace(a,"    const hour = hourStart(run.finishedAt);")); print("MUTANT M31 applied")
PY
fi
shift 2 2>/dev/null || shift 1
FILES=${FILES:-apps/api/test/qac-run-reports-s3a.test.ts}
for f in $FILES; do
  b=$(basename "$f" .test.ts)
  timeout 1200 python3 ~/repos/harness/lanes/pgpool.py run --mode server --job "aab3-$b" --lane qacq3 --ttl 1300 -- \
    pnpm --filter @bugtracker/api exec vitest run "${f#apps/api/}" > "$L.$b.log" 2>&1
  rc=$?; echo "$b rc=$rc $(sed 's/\x1b\[[0-9;]*m//g' "$L.$b.log" | grep -E '^ +Tests ' | tr -s ' ')"
  [ $rc = 0 ] || sed 's/\x1b\[[0-9;]*m//g' "$L.$b.log" | grep -E '✗|×|FAIL |AssertionError' | head -6 | cut -c1-220
done
if [ "$MUT" = M31 ]; then cp "$L.rr.bak" "$RR"; echo "MUTANT reverted"; fi
git status --short
