#!/bin/bash
# goodqa#16148: each broken variant of derive-job-secrets.py must fail the derive tests (non-vacuous).
# Run from the repo root of the step-2 worktree; restores the committed file after each variant.
set -u
F=infra/selfhost/app/derive-job-secrets.py
variant() {
  local name="$1" old="$2" new="$3"
  python3 -I - "$F" "$old" "$new" <<'EOF'
import sys
p, old, new = sys.argv[1:4]
s = open(p).read()
assert s.count(old) >= 1, old
open(p, 'w').write(s.replace(old, new))
EOF
  local out
  out=$(bash infra/selfhost/app/run_derive_tests.sh 2>&1 | grep -E '^(OK|FAILED)'; DERIVE_ONLY_CONTAINER=1 true)
  echo "$name: $(echo $out | tr '\n' ' ')"
  git checkout -q -- "$F"
}
variant "V1 follows links (no O_NOFOLLOW)" "os.O_NOFOLLOW" "0"
variant "V2 strips quotes" "    value = found[0]
" "    value = found[0].strip(b'\"\\'')
"
variant "V3 skips NSS" "_getent('group', GROUP) + _getent('group', str(GID))" "''"
variant "V4 no inode check" "if not _is_reg(now.st_mode) or (now.st_dev, now.st_ino) != (own.st_dev, own.st_ino):" "if False:"
variant "V5 writes when unchanged" "            if read_existing(dfd) == value:
                return 'unchanged', 0
" ""
echo "restored: $(git status --short "$F" | wc -l) changed"
