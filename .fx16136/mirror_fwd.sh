#!/bin/bash
# goodqa#16136: mirror the hold launch block, D rename, E4 and the AC-13 matcher onto 1371 (bt-fwd). Run on t2-dev.
set -u
cd ~/repos/fx-16136/bt-fwd || exit 2
R=infra/release-harness; T=$R/test_rw_ship_selfhost.py; F=~/repos/fx-16136; PY=$F/venv/bin/python
git rev-parse --short HEAD; git status --short
export SCRATCH="$PWD/.scratch/release-runtime-check" TMPDIR="$PWD/.scratch/release-runtime-check/tmp"
sed -i "s/test_ctl_job_hold_keeps_line_and_skips_presence/test_ctl_job_hold_empties_line_and_skips_presence/" $T
python3 $F/patch_tests_e4.py $T
cp $F/test_ac13_count.py $R/test_ac13_count.py
echo "E4+hold tests on 59501565 scripts: $(timeout 600 $PY -m pytest -q -p no:cacheprovider --basetemp=$SCRATCH/m1 $T -k 'empty_job_value or held_empty_lines or non_holdable or empties_line' 2>&1 | tail -1)"
python3 $F/patch_hold.py $R || exit 3
python3 $F/patch_e4.py $R || exit 3
cp $F/ac13-count.py $R/ac13-count.py; chmod 755 $R/ac13-count.py
bash -n $R/rw-ship.sh && python3 -m py_compile $R/selfhost-ctl.py && echo syntax ok
for f in ac13-count.py test_ac13_count.py; do cmp $R/$f <(git -C ~/repos/fx-16136/bt-rh show 18fa30fb8f8a:$R/$f) && echo "$f equals rh5"; done
RW_REAL_COMPOSE=1 timeout 900 $PY -m pytest -q -rA -p no:cacheprovider --basetemp=$SCRATCH/fixtures $T $R/test_rw_image_jobs.py $R/test_ac13_count.py > $F/fwd-v4.txt 2>&1; echo "selfhost+jobs+ac13 exit $?: $(tail -1 $F/fwd-v4.txt)"
grep -E "^(FAILED|ERROR)" $F/fwd-v4.txt | sed -E "s/.*:://;s/ - (.{0,160}).*/ -- \1/"
timeout 900 $PY -m pytest -q -p no:cacheprovider $R/test_selfhost_ctl.py > $F/fwd-ctl-v4.txt 2>&1; echo "ctl exit $?: $(tail -1 $F/fwd-ctl-v4.txt)"
git status --short
