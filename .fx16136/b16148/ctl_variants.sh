#!/bin/bash
# goodqa#16148: broken variants of selfhost-ctl.py must fail test_selfhost_ctl_job_secrets.py. Step-2 worktree root.
set -u
F=infra/release-harness/selfhost-ctl.py
PY=$HOME/repos/fx-16136/venv/bin/python
t(){ timeout 300 $PY -m pytest -q -p no:cacheprovider infra/release-harness/test_selfhost_ctl_job_secrets.py 2>&1 | tail -1; }
variant() {
  local name="$1" old="$2" new="$3"
  python3 -I - "$F" "$old" "$new" <<'EOF'
import sys
p, old, new = sys.argv[1:4]
s = open(p).read()
assert s.count(old) == 1, old
open(p, 'w').write(s.replace(old, new))
EOF
  echo "$name: $(t)"
  git checkout -q -- "$F"
}
echo "as is: $(t)"
variant "C1 pin rewrite drops the marked block" "            lines[idx[0]] = '    image: %s # %s' % (ref, note)
        return '\n'.join(lines)" "            lines[idx[0]] = '    image: %s # %s' % (ref, note)
        return '\n'.join(l for l in lines if '# goodqa#16148 AC-11' not in l)"
variant "C2 no restore fence" "    restore_fence(stk, a, files, baks)
" "    pass
"
echo "restored: $(git status --short "$F" | wc -l) changed"
