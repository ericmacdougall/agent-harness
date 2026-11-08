#!/usr/bin/env bash
# Runs on t2-dev. usage: red-green.sh <worktree> <label> <src-file-to-revert> <test-file>
# Red: test file at working tree, src file at HEAD. Green: both at working tree. One pgpool vitest process each.
set -u
W=$1; L=$HOME/wt/aab3-$2; SRC=$3; TEST=$4
cd "$W" || exit 2
cp "$SRC" "$L.src.fixed"
git show "HEAD:$SRC" > "$SRC"
run() {
  timeout 1200 python3 ~/repos/harness/lanes/pgpool.py run --mode server --job "aab3-$2" --lane qacq3 --ttl 1300 -- \
    pnpm --filter @bugtracker/api exec vitest run "${TEST#apps/api/}" > "$L.$1.log" 2>&1
  echo "$1 rc=$? $(sed 's/\x1b\[[0-9;]*m//g' "$L.$1.log" | grep -E '^ +Tests ' | tr -s ' ')"
  sed 's/\x1b\[[0-9;]*m//g' "$L.$1.log" | grep -E '^ +× ' | head -8 | cut -c1-200
}
run red "$2-red"
cp "$L.src.fixed" "$SRC"
run green "$2-green"
git status --short
echo RG_END
