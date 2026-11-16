#!/bin/bash
# goodqa#16136: add G1-G3 to the 1371 mirror (bt-fwd; hold, D, E4 already applied, uncommitted). Run on t2-dev.
set -u
cd ~/repos/fx-16136/bt-fwd || exit 2
R=infra/release-harness; T=$R/test_rw_ship_selfhost.py; F=~/repos/fx-16136; PY=$F/venv/bin/python
export SCRATCH="$PWD/.scratch/release-runtime-check" TMPDIR="$PWD/.scratch/release-runtime-check/tmp"
python3 $F/patch_tests_g3.py $T
echo "G3 tests before G3 ctl: $(timeout 300 $PY -m pytest -q -p no:cacheprovider --basetemp=$SCRATCH/g $T -k 'value_must_be_a_pin or plain_or_quoted' 2>&1 | tail -1)"
python3 $F/patch_g3.py $R || exit 3
for f in ac13-count.py test_ac13_count.py; do git -C ~/repos/fx-16136/bt-rh show "$1:$R/$f" > $R/$f; done; chmod 755 $R/ac13-count.py
python3 -m py_compile $R/selfhost-ctl.py && echo syntax ok
diff <(git -C ~/repos/fx-16136/bt-rh show "$1:$R/selfhost-ctl.py" | grep -n "HOLDABLE_KEYS\|JOB_PIN_VALUE_RE\|HELD_VALUE" | cut -d: -f2-) <(grep -n "HOLDABLE_KEYS\|JOB_PIN_VALUE_RE\|HELD_VALUE" $R/selfhost-ctl.py | cut -d: -f2-) && echo "hold/E4/G3 ctl lines equal rh"
RW_REAL_COMPOSE=1 timeout 900 $PY -m pytest -q -rA -p no:cacheprovider --basetemp=$SCRATCH/fixtures $T $R/test_rw_image_jobs.py $R/test_ac13_count.py > $F/fwd-g.txt 2>&1; echo "selfhost+jobs+ac13 exit $?: $(tail -1 $F/fwd-g.txt)"
grep -E "^(FAILED|ERROR)" $F/fwd-g.txt | sed -E "s/.*:://;s/ - (.{0,160}).*/ -- \1/"
timeout 900 $PY -m pytest -q -p no:cacheprovider $R/test_selfhost_ctl.py > $F/fwd-ctl-g.txt 2>&1; echo "ctl exit $?: $(tail -1 $F/fwd-ctl-g.txt)"
git status --short
