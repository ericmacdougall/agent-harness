#!/usr/bin/env bash
# F2 broken variants for PR 73's staged lane: each edits one committed runtime file (rw-ship.sh or selfhost-ctl.py),
# runs the tests that must catch it, and restores the file from git. Usage: bash f2_variants.sh <pr73 clone>  (t2-dev)
cd "$1/config/goodqa-release/bin" || exit 9
P=$HOME/repos/fx-16136/venv/bin/python
git diff --quiet -- rw-ship.sh selfhost-ctl.py || { echo "runtime files dirty; stop"; exit 9; }
var(){ # name, file, old, new, -k expression
  python3 - "$2" "$3" "$4" <<'PY' || { echo "$1: anchor missing"; return; }
import sys
p, o, n = sys.argv[1:4]; t = open(p).read()
assert t.count(o) == 1, t.count(o)
open(p, 'w').write(t.replace(o, n))
PY
  r=$(timeout 900 "$P" -B -m pytest -q -p no:cacheprovider test_rw_ship_selfhost.py -k "$5" 2>&1 | tail -1)
  echo "$1 [-k $5]: $r"
  git checkout -q -- "$2"
}
var V1-guard-probe-ignored rw-ship.sh \
  'if [ "$prc" != 0 ] && [ "$prc" != 124 ] && grep -q '"'"'GUARD_HELD_ENV must be'"'"' "$RD/guard-probe.txt"; then' \
  'if false; then' 'transcribe_hold'
var V2-guard-log-not-checked rw-ship.sh \
  '*) sh_fail_rollback "the running guard does not report the transcription hold";;' '*) ;;' 'guard_not_reporting'
var V3-no-default-hold rw-ship.sh \
  'JHOLD=$(shconf SELFHOST_JOB_HOLD intelligence-worker,transcribe)' 'JHOLD=$(shconf SELFHOST_JOB_HOLD none)' \
  'default_holds or held_kind_never_starts or held_value_never_reaches'
var V4-held-keys-out-of-parity selfhost-ctl.py \
  "        if got != want_env:" \
  "        if {k: v for k, v in got.items() if k not in marked} != {k: v for k, v in want_env.items() if k not in marked}:" \
  'resolved_compose_dropping or held_key_pin_passes'
var V5-labels-accepted selfhost-ctl.py \
  "            if not m or not in_svc or cur != JOB_BLOCK or sub != 'environment':" \
  "            if not m or not in_svc or cur != JOB_BLOCK:" 'job_key_under_labels'
var V6-timeout-counts-as-support rw-ship.sh \
  'if [ "$prc" != 0 ] && [ "$prc" != 124 ] && grep -q '"'"'GUARD_HELD_ENV must be'"'"' "$RD/guard-probe.txt"; then' \
  'if [ "$prc" != 0 ]; then' 'old_guard_that_just_listens'
git diff --quiet -- rw-ship.sh selfhost-ctl.py && echo "restored clean"
