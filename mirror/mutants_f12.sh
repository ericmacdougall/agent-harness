#!/usr/bin/env bash
# goodqa#15561 delta F1/F2: variants equal to b616866 behavior; the delegation test must fail on each. Restores files.
set -u
cd "$HOME/wt-15561/apps/api" || exit 2
OUT="$HOME/release-evidence/g15561-mutants-delta-f12.txt"
: > "$OUT"
run() {
  local name="$1" file="$2" expr="$3"
  cp "$file" /tmp/g15561-m.bak
  sed -i "$expr" "$file"
  if cmp -s "$file" /tmp/g15561-m.bak; then echo "MUTANT $name: sed did not change the file" >> "$OUT"; return; fi
  CAP=700 "$HOME/review-scratch/run15561.sh" "mutf-$name" test/user-token-desktop-session-delegation.test.ts > /dev/null 2>&1
  { echo "MUTANT $name:"; grep -E "^ FAIL |Tests " "$HOME/review-scratch/g15561-mutf-$name.txt" | cut -c1-230 | head -6; } >> "$OUT"
  cp /tmp/g15561-m.bak "$file"
}
run operator-waivers src/lib/desktop-token-session.ts "s/  if (createdVia === 'operator') return fired;/  if (false) return fired;/"
run poll-always-quiet src/modules/user-tokens/auth-gate.ts "s/  if (seen \&\& seen.ip === ip \&\& seen.ua === ua \&\& now - seen.at < DESKTOP_POLL_QUIET_WINDOW_MS) return true;/  return true;/"
git status --short >> "$OUT"
echo DONE >> "$OUT"
