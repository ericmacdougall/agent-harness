#!/bin/bash
# goodqa#16148: broken variants of cmdline-sampler.py must each fail its tests. Step-2 worktree root.
set -u
F=infra/selfhost/app/cmdline-sampler.py
t(){ (cd infra/selfhost/app && DERIVE_TEST_TMP=$PWD/../../../.scratch timeout 300 python3 -m unittest test_cmdline_sampler 2>&1 | grep -E '^(OK|FAILED)'); }
variant() {
  local name="$1" old="$2" new="$3"
  python3 -I - "$F" "$old" "$new" <<'EOF'
import sys
p, old, new = sys.argv[1:4]
s = open(p).read()
assert s.count(old) >= 1, old
open(p, 'w').write(s.replace(old, new))
EOF
  echo "$name: $(t)"
  git checkout -q -- "$F"
}
echo "as committed: $(t)"
variant "S1 keeps raw argv" "    return {'argc': len(argv), 'flags': flags}" "    return {'argc': len(argv), 'flags': flags, 'raw': argv}"
variant "S2 no cgroup filter" "                if not in_container(f.read(), container):" "                if False:"
variant "S3 no positive control" "    if len(runs) < a.expect_runs:" "    if False:"
variant "S4 attached short flag kept whole" "                flags.append((short if short in ALLOWED_SHORT else '-(other)') + '(attached)')" "                flags.append(tok)"
echo "restored: $(git status --short "$F" | wc -l) changed"
