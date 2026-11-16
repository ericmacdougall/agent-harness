#!/bin/bash
# goodqa#16136 E4 + AC-13 matcher: failing first, then green, in bt-rh. Run on t2-dev.
set -u
cd ~/repos/fx-16136/bt-rh || exit 2
R=infra/release-harness; T=$R/test_rw_ship_selfhost.py; F=~/repos/fx-16136; PY=$F/venv/bin/python
git status --short | head -3
export SCRATCH="$PWD/.scratch/release-runtime-check" TMPDIR="$PWD/.scratch/release-runtime-check/tmp"
python3 $F/patch_tests_e4.py $T
cp $F/test_ac13_count.py $R/test_ac13_count.py
echo "E4 tests, old ctl: $(timeout 300 $PY -m pytest -q -p no:cacheprovider --basetemp=$SCRATCH/e4 $T -k 'empty_job_value or held_empty_lines or non_holdable' 2>&1 | tail -1)"
echo "matcher tests, no tool: $(timeout 300 $PY -m pytest -q -p no:cacheprovider --basetemp=$SCRATCH/e4 $R/test_ac13_count.py 2>&1 | tail -1)"
python3 $F/patch_e4.py $R
cp $F/ac13-count.py $R/ac13-count.py; chmod 755 $R/ac13-count.py
echo "E4 tests, new ctl: $(timeout 300 $PY -m pytest -q -p no:cacheprovider --basetemp=$SCRATCH/e4 $T -k 'empty_job_value or held_empty_lines or non_holdable' 2>&1 | tail -1)"
echo "matcher tests: $(timeout 300 $PY -m pytest -q -p no:cacheprovider --basetemp=$SCRATCH/e4 $R/test_ac13_count.py 2>&1 | tail -1)"
# broken variants of the matcher
cp $R/ac13-count.py $F/ac13.good
sed -i 's/if st == 501 and k in a.held_empty:/if st == 501:/' $R/ac13-count.py
echo "mutant 501-always-held: $(timeout 300 $PY -m pytest -q -p no:cacheprovider --basetemp=$SCRATCH/e4 $R/test_ac13_count.py 2>&1 | tail -1)"
cp $F/ac13.good $R/ac13-count.py
sed -i 's/if tc422 != ref_n:/if False:/' $R/ac13-count.py
echo "mutant no-pairing: $(timeout 300 $PY -m pytest -q -p no:cacheprovider --basetemp=$SCRATCH/e4 $R/test_ac13_count.py 2>&1 | tail -1)"
cp $F/ac13.good $R/ac13-count.py
sed -i "s/if st == 422 and k == 'transcode' and a.guard_held_transcribe:/if st == 422:/" $R/ac13-count.py
echo "mutant any-422-held: $(timeout 300 $PY -m pytest -q -p no:cacheprovider --basetemp=$SCRATCH/e4 $R/test_ac13_count.py 2>&1 | tail -1)"
cp $F/ac13.good $R/ac13-count.py; cmp $F/ac13.good $R/ac13-count.py && echo restored
git status --short
