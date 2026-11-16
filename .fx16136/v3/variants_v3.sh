#!/bin/bash
# 1377 v3 broken variants: break one committed fix, run its tests, restore the file from git. Needs a clean tree at the fix.
# Usage: variants_v3.sh > log
P=~/repos/fx-16136/venv/bin/python
R=~/repos/fx-16136/bt-16148-gate
cd "$R" || exit 2
[ -z "$(git status --short --untracked-files=no)" ] || { echo "tree not clean"; exit 2; }
export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@example.invalid GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@example.invalid
echo "== head $(git rev-parse HEAD)"
mut(){ # mut <file> <python old literal> <python new literal>
  python3 - "$1" "$2" "$3" <<'PY'
import sys
p, old, new = sys.argv[1:4]; t = open(p).read()
assert t.count(old) == 1, ('anchor', old[:80], t.count(old)); open(p, 'w').write(t.replace(old, new))
PY
}
py(){ (cd infra/release-harness && timeout 1200 $P -B -m pytest -q -p no:cacheprovider "$@" 2>&1 | tail -1); }
run(){ # run <name> <file> <old> <new> <runner...>
  local name=$1 f=$2 old=$3 new=$4; shift 4
  if mut "$f" "$old" "$new"; then echo "$name -> $("$@")"; else echo "$name -> ANCHOR MISSING"; fi
  git checkout -q -- "$f"
}
RH=infra/release-harness
run "V1a strict reader accepts quoted keys" $RH/selfhost-ctl.py "(?P<k>[A-Za-z0-9_-]+)" "[\"\\x27]?(?P<k>[A-Za-z0-9_-]+)[\"\\x27]?" \
  py test_rw_ship_selfhost.py -k "f1_quoted_root or f1_containerd_config_refusals"
run "V1b no case check on root/imports" $RH/selfhost-ctl.py "if k.lower() in ('root', 'imports') and k != k.lower():" "if False:" \
  py test_rw_ship_selfhost.py -k "f1_containerd_config_refusals"
run "V2a pre-gate-c failures not re-held" $RH/rw-ship.sh 'then js_hold_fail "$1"; fi' 'then :; fi' \
  py test_rw_ship_jobsecret_gate.py -k "pre_gate_c_failure"
run "V2b rollback after a failed re-hold not verified" $RH/rw-ship.sh 'elif [ -n "$iw" ] && [ "$iw" = "$INTEL_PRE" ]; then how=same-as-before; fi' 'else how=unverified; fi' \
  py test_rw_ship_jobsecret_gate.py -k "not_the_previous_value"
run "V3a boot status ignores the conflict" apps/job-dispatcher/src/job-env-file.ts 'if (envFileConflict(entry, config.jobBaseEnv[entry.kind])) {' 'if (false) {' \
  bash -c 'cd apps/job-dispatcher && timeout 600 npx vitest run test/job-env-file.test.ts test/boot-check.test.ts 2>&1 | grep -E "Tests " | tail -1'
run "V3b gate (c) word for the conflict dropped" $RH/selfhost-ctl.py "'both JOB_ENV_ and JOB_ENVFILE_ are set': 'conflict'" "'(dropped)': 'conflict'" \
  py test_selfhost_ctl_gate.py -k disp_status
run "V4 envfile-key counts only canonical lines" $RH/selfhost-ctl.py "out({'count': len(named)," "out({'count': sum(1 for l in named if l == JOBSECRET_KEY_LINE.encode())," \
  py test_selfhost_ctl_gate.py -k envfile_key
run "V5 float bound dropped" $RH/ac13-count.py "math.isfinite(v) and -MAX_TIME <= v <= MAX_TIME else None" "math.isfinite(v) else None" \
  py test_ac13_count.py -k "out_of_range or in_range_float"
echo "== tree after: $(git status --short --untracked-files=no | wc -l) changed"
