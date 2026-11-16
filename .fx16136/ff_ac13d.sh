#!/bin/bash
# goodqa#16136 AC-13 matcher, API-log pairing (option d): green and broken variants, in bt-rh. Run on t2-dev.
set -u
cd ~/repos/fx-16136/bt-rh || exit 2
R=infra/release-harness; F=~/repos/fx-16136; PY=$F/venv/bin/python
export SCRATCH="$PWD/.scratch/release-runtime-check" TMPDIR="$PWD/.scratch/release-runtime-check/tmp"
cp $F/ac13-count.py $R/ac13-count.py; chmod 755 $R/ac13-count.py; cp $F/test_ac13_count.py $R/test_ac13_count.py
t() { timeout 300 $PY -m pytest -q -p no:cacheprovider --basetemp=$SCRATCH/e4 $R/test_ac13_count.py 2>&1 | tail -1; }
echo "matcher tests: $(t)"
cp $R/ac13-count.py $F/ac13.good
m() { cp $F/ac13.good $R/ac13-count.py; sed -i "$1" $R/ac13-count.py; cmp -s $F/ac13.good $R/ac13-count.py && echo "mutant $2: NOT APPLIED" || echo "mutant $2: $(t)"; }
m 's/if st == 501 and k in a.held_empty:/if st == 501:/' 501-always-held
m 's/if tc422 != ref_n:/if False:/' no-pairing
m "s/if st == 422 and k == 'transcode' and a.guard_held_transcribe:/if st == 422:/" any-422-held
m "s/and HELD_TAG in line: n += 1/: n += 1/" any-launch-failure-is-held
m "s/if not m: bad += 1; continue/if not m: continue/" untimed-ignored
cp $F/ac13.good $R/ac13-count.py; cmp $F/ac13.good $R/ac13-count.py && echo restored
git status --short
