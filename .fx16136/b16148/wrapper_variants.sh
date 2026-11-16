#!/bin/bash
# goodqa#16148: broken variants of apply-job-secrets.sh must each fail its tests. Step-2 worktree root.
set -u
F=infra/selfhost/app/apply-job-secrets.sh
variant() {
  local name="$1" old="$2" new="$3"
  python3 -I - "$F" "$old" "$new" <<'EOF'
import sys
p, old, new = sys.argv[1:4]
s = open(p).read()
assert s.count(old) >= 1, old
open(p, 'w').write(s.replace(old, new))
EOF
  echo "$name: $(cd infra/selfhost/app && DERIVE_TEST_TMP=$PWD/../../../.scratch timeout 300 python3 -m unittest test_apply_job_secrets_wrapper 2>&1 | grep -E '^(OK|FAILED)')"
  git checkout -q -- "$F"
}
variant "W1 no lock" 'flock -n 8 ||' 'true ||'
variant "W2 no in-flight check" '[ -e "$INFL" ] &&' 'false &&'
variant "W3 derive result ignored" 'nothing else applied"; exit 2;;' 'nothing else applied";;'
variant "W4 no epoch bump" 'printf '"'"'%s\n'"'"' "$EPOCH" > "$EPOCHF.$$" && mv -f "$EPOCHF.$$" "$EPOCHF"' ':'
echo "restored: $(git status --short "$F" | wc -l) changed"
