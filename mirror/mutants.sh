#!/usr/bin/env bash
# goodqa#15561 S1b controlled broken variants: each mutant must turn the delegation test red on the named assertion.
# Restores every file after each run. usage: mutants.sh
set -u
cd "$HOME/wt-15561/apps/api" || exit 2
GATE=src/modules/user-tokens/auth-gate.ts
BOUND=src/modules/user-tokens/bound-session.ts
OUT="$HOME/review-scratch/g15561-mutants.txt"
: > "$OUT"
run() { # name file sed-expression
  local name="$1" file="$2" expr="$3"
  cp "$file" "/tmp/g15561-mut.bak"
  sed -i "$expr" "$file"
  if cmp -s "$file" /tmp/g15561-mut.bak; then echo "MUTANT $name: sed did not change the file" >> "$OUT"; return; fi
  CAP=700 "$HOME/review-scratch/run15561.sh" "mut-$name" test/user-token-desktop-session-delegation.test.ts > /dev/null 2>&1
  { echo "MUTANT $name:"; grep -E "^ FAIL |Tests " "$HOME/review-scratch/g15561-mut-$name.txt" | cut -c1-260 | head -12; } >> "$OUT"
  cp /tmp/g15561-mut.bak "$file"
}
run skip-ability-check-delegated "$GATE" "s/const missing = missingAbilities(held, required);/const missing = bound?.door === 'delegated' ? [] : missingAbilities(held, required);/"
run skip-kill-switch "$BOUND" "s/if (!(await userTokensPlatformAllows(db, token))) return/if (false \&\& !(await userTokensPlatformAllows(db, token))) return/"
run skip-approval-bound "$GATE" "s/if (mustAsk \&\& policy.approvalReason) {/if (!bound \&\& mustAsk \&\& policy.approvalReason) {/"
run host-waive-everything "$GATE" "s/if (bound.door === 'host') applyHostDoorWaivers(req.method, bound.routeKey, policy);/if (bound.door === 'host') { applyHostDoorWaivers(req.method, bound.routeKey, policy); policy.approvalReason = null; policy.abilities = []; }/"
git status --short >> "$OUT"
echo DONE >> "$OUT"
