#!/bin/bash
# goodqa#16136 G1-G3: failing first against rh5, then green, in bt-rh. Run on t2-dev.
set -u
cd ~/repos/fx-16136/bt-rh || exit 2
R=infra/release-harness; T=$R/test_rw_ship_selfhost.py; F=~/repos/fx-16136; PY=$F/venv/bin/python
git rev-parse --short HEAD; git status --short
export SCRATCH="$PWD/.scratch/release-runtime-check" TMPDIR="$PWD/.scratch/release-runtime-check/tmp"
p() { timeout 300 $PY -m pytest -q -p no:cacheprovider --basetemp=$SCRATCH/g "$@" 2>&1 | grep -E "^FAILED|passed|failed" | sed -E "s/.*:://;s/ - .*//" | tr "\n" " "; }
python3 $F/patch_tests_g3.py $T
cp $F/test_ac13_count.py $R/test_ac13_count.py
echo "G3 tests vs rh5 ctl: $(p $T -k 'value_must_be_a_pin or plain_or_quoted')"
echo "G1/G2 tests vs rh5 matcher: $(p $R/test_ac13_count.py)"
python3 $F/patch_g3.py $R || exit 3
cp $F/ac13-count.py $R/ac13-count.py
echo "G3 tests: $(p $T -k 'value_must_be_a_pin or plain_or_quoted or empty_job_value or held_empty_lines or non_holdable')"
echo "matcher tests: $(p $R/test_ac13_count.py)"
cp $R/ac13-count.py $F/ac13.good
m() { cp $F/ac13.good $R/ac13-count.py; sed -i "$1" $R/ac13-count.py; cmp -s $F/ac13.good $R/ac13-count.py && echo "mutant $2: NOT APPLIED" || echo "mutant $2: $(p $R/test_ac13_count.py)"; }
m 's/if not used\[i\] and abs(u - t) <= tol:/if not used[i]:/' no-time-tolerance
m 's/lo = None if a.since is None else a.since - tol; hi = None if a.until is None else a.until + tol/lo, hi = a.since, a.until/' no-window-widening
m 's/if m: replicas.add((n, m.group(1)))/if m: replicas.add((0, None))/' replicas-collapsed
m 's/if st == 501 and k in a.held_empty:/if st == 501:/' 501-always-held
m "s/and HELD_TAG in line else other/else other/" any-launch-failure-is-held
cp $F/ac13.good $R/ac13-count.py; cmp $F/ac13.good $R/ac13-count.py && echo restored
DS=""; for t in $(sed "s/^FAILED //" $F/base-failed.txt); do DS="$DS --deselect $t"; done
RW_REAL_COMPOSE=1 timeout 900 $PY -m pytest -q -rA -p no:cacheprovider --basetemp=$SCRATCH/fixtures $T $R/test_ac13_count.py $DS > $F/g-green.txt 2>&1; echo "full rh exit $?: $(tail -1 $F/g-green.txt)"
grep -E "^(FAILED|ERROR)" $F/g-green.txt | sed -E "s/.*:://;s/ - (.{0,160}).*/ -- \1/"
git status --short
