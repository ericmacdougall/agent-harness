#!/bin/bash
# goodqa#16136: build the three review packets (head, base, diff sha256, literal test output) on t2-dev.
set -uo pipefail
P=~/repos/fx-16136/packets; mkdir -p "$P"; F=~/repos/fx-16136
mk(){ name=$1 repo=$2 base=$3 head=$4; shift 4
  out=$P/$name.txt
  { echo "# packet $name (goodqa#16136) built $(date -u +%FT%TZ) on $(hostname)"
    echo "repo: $repo"; echo "base: $(git -C "$repo" rev-parse "$base")"; echo "head: $(git -C "$repo" rev-parse "$head")"
    echo "diff sha256: $(git -C "$repo" diff "$base" "$head" | sha256sum | cut -c1-64)"
    echo "diff stat:"; git -C "$repo" diff --stat "$base" "$head"
    echo; echo "commits:"; git -C "$repo" log --format='%h %s' "$base..$head"
    for f in "$@"; do echo; echo "== $(basename "$f") (sha256 $(sha256sum "$f" | cut -c1-16))"; cat "$f"; done
  } > "$out"
  echo "$name: $(wc -c < "$out") bytes, sha256 $(sha256sum "$out" | cut -c1-64)"
}
# literal test excerpts
grep -E "^(PASSED|FAILED|SKIPPED)|passed|failed" $F/final2-selfhost.txt | grep -vE "^(PASSED)" > $F/ex-rh-final.txt
grep -cE "^PASSED" $F/final2-selfhost.txt | sed 's/^/PASSED lines: /' >> $F/ex-rh-final.txt
grep -E "^PASSED.*(real_compose|job|hold|guard|state|restore|classic|third|fp_|vm_disk|id_mismatch)" $F/final2-selfhost.txt >> $F/ex-rh-final.txt
{ echo "failing-first (5a78109 scripts, v1+v2 tests):"; tail -1 $F/failing-first.txt; grep -E "^FAILED" $F/failing-first.txt | sed -E 's/ - .*//'
  echo "failing-first (v2.1 tests):"; tail -1 $F/failing-first-v21.txt
  echo "probe fix failing-first (ef4e011/a6eaed rw-ship.sh):"; tail -1 $F/probefix-failing-first.txt; grep -E "^FAILED" $F/probefix-failing-first.txt | sed -E 's/ - .*//'
  echo "baseline 5a78109 failed set (test_rw_ship_selfhost.py):"; cat $F/base-failed.txt
  echo "final failed set:"; cat $F/final2-failed.txt
  echo "test_selfhost_ctl.py at HEAD: $(tail -1 $F/final-ctl.txt); failed set identical to baseline: $(cmp -s $F/base-ctl-failed.txt $F/final-ctl-failed.txt && echo yes || echo NO)"
} > $F/ex-rh-first.txt
cp $F/probe-real.txt $F/ex-probe-real.txt
mk rh-release-harness $F/bt-rh b3604eaec1c6 HEAD $F/ex-rh-final.txt $F/ex-rh-first.txt $F/ex-probe-real.txt
{ grep -E "Test Files|Tests " $F/guard-green1.txt | sed 's/\x1b\[[0-9;]*m//g'; echo "unit suite:"; grep -E "Test Files|Tests " $F/guard-unit.txt | sed 's/\x1b\[[0-9;]*m//g'
  echo "failing-first:"; grep -E "FAIL|Error|Tests" $F/guard-failing-first.txt | sed 's/\x1b\[[0-9;]*m//g'; echo "broken variants:"; cat $F/guard-mutations.txt; } > $F/ex-guard.txt
mk guard-pr $F/bt-guard origin/main HEAD $F/ex-guard.txt $F/ex-probe-real.txt
cp $F/restage-out.txt $F/ex-restage.txt
mk harness-restage $F/harness origin/main HEAD $F/ex-restage.txt
