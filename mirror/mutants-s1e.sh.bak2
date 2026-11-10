#!/bin/sh
# Runs S1e-a mutants on t2-dev: each mutant is applied to a copy, the focused file run, then the original restored.
# Usage: mutants-s1e.sh   (needs the green source already pushed to ~/wt-15561)
set -u
cd "$(dirname "$0")"
run_mutant() {
  name="$1"; remote="$2"; local_file="$3"; old="$4"; new="$5"
  cp "$local_file" "mut-$name.ts"
  python3 - "$name" "$old" "$new" <<'PY'
import sys
name, old, new = sys.argv[1:4]
p = f'mut-{name}.ts'
s = open(p).read()
assert s.count(old) == 1, (name, s.count(old))
open(p, 'w').write(s.replace(old, new))
PY
  scp -q "mut-$name.ts" "t2-dev:wt-15561/$remote"
  ssh t2-dev "CAP=900 ~/review-scratch/run15561.sh s1e-mut-$name test/user-token-contact-timeline-default.test.ts >/dev/null 2>&1; grep -E 'Tests ' ~/review-scratch/g15561-s1e-mut-$name.txt; cp ~/review-scratch/g15561-s1e-mut-$name.txt ~/release-evidence/g15561-s1e-mut-$name.txt"
  scp -q "$local_file" "t2-dev:wt-15561/$remote"
}
run_mutant operator apps/api/src/modules/user-tokens/auth-gate.ts auth-gate.ts " && token.createdVia !== 'operator' && isSessionOnlyOpened" " && isSessionOnlyOpened"
run_mutant crmswitch apps/api/src/plugins/auth.ts auth.ts.plugin "(apiKeyRouteResources(r.method, route)?.includes('crm') || w4Route)" "(apiKeyRouteResources(r.method, route)?.includes('crm'))"
run_mutant optout apps/api/src/lib/desktop-token-session.ts desktop-token-session.ts "!== false;" "!== 'never';"
run_mutant ability apps/api/src/modules/user-tokens/auth-gate.ts auth-gate.ts "policy.abilities = [...new Set([...policy.abilities, 'crm', 'read'])].sort();" "policy.abilities = [];"
echo mutants-done
