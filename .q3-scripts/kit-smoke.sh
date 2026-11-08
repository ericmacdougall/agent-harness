#!/usr/bin/env bash
# t2-dev release kit. Usage: smoke.sh <full sha> <evidence dir name>. Install plus release smoke on a clean tree. Deploys nothing.
set -u
SHA=${1:?full sha}; R=$HOME/release-evidence/${2:?evidence dir name}; S12=${SHA:0:12}
W=$HOME/repos/bt-release-smoke-$S12
[[ "$SHA" =~ ^[0-9a-f]{40}$ ]] || { echo "NOT_A_FULL_SHA"; exit 2; }
mkdir -p "$R" "$HOME/sc" "$HOME/ipc"; chmod 700 "$HOME/ipc" "$HOME/sc"
cd "$HOME/repos/bugtracker" || exit 2
git fetch -q origin
[ -d "$W" ] || git worktree add -q --detach "$W" "$SHA" || exit 2
mkdir -p "$W/.scratch"; cd "$W" || exit 2
[ "$(git rev-parse HEAD)" = "$SHA" ] || { echo HEAD_MISMATCH; exit 3; }
timeout 1500 pnpm install --frozen-lockfile --prefer-offline > "$R/install.log" 2>&1; echo "install_rc=$?"
printf "%s\nporcelain=%s\n" "$(git rev-parse HEAD)" "$(git status --porcelain | wc -l)" > "$R/smoke-$S12.head"
SC=$(mktemp -d "$HOME/sc/gXXXX")
timeout 2400 node "$HOME/repos/harness/bin/release-smoke.mjs" --tree "$W" --out "$R/smoke-$S12.json" --scratch "$SC" --ipc-root "$HOME/ipc" > "$R/smoke-$S12.log" 2>&1
echo "SMOKE_EXIT=$?" | tee -a "$R/smoke-$S12.log"
cat "$R/smoke-$S12.head"
sha256sum "$R/smoke-$S12.json"
tail -3 "$R/smoke-$S12.log" | cut -c1-300
echo SMOKE_END
