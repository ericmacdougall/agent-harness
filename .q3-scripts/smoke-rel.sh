#!/usr/bin/env bash
# Runs on dev2. Merged-tree install and release smoke for the S3a release. Same recipe as goodqa-15314-e13e368/smoke.sh.
set -u
SHA=30c7e41b20bbed1f46a3d078aaaf35e74feba72d; S12=${SHA:0:12}
W=$HOME/repos/bt-q3s3-smoke; R=$HOME/release-evidence/goodqa-14903-30c7e41
mkdir -p "$R"
cd "$HOME/repos/bugtracker" || exit 2
git fetch -q origin
[ -d "$W" ] || git worktree add -q --detach "$W" "$SHA" || exit 2
mkdir -p "$W/.scratch"; cd "$W" || exit 2
[ "$(git rev-parse HEAD)" = "$SHA" ] || { echo HEAD_MISMATCH; exit 3; }
timeout 1500 pnpm install --frozen-lockfile --prefer-offline > "$R/install.log" 2>&1; echo "install_rc=$?"
P=$(git status --porcelain | wc -l)
printf "%s\nporcelain=%s\n" "$(git rev-parse HEAD)" "$P" > "$R/smoke-$S12.head"
S=$(mktemp -d /home/eric/sc/gXXXX)
timeout 2400 node ~/repos/harness/bin/release-smoke.mjs --tree "$W" --out "$R/smoke-$S12.json" --scratch "$S" --ipc-root /home/eric/ipc > "$R/smoke-$S12.log" 2>&1
echo "SMOKE_EXIT=$?" | tee -a "$R/smoke-$S12.log"
cat "$R/smoke-$S12.head"
sha256sum "$R/smoke-$S12.json"
tail -4 "$R/smoke-$S12.log" | cut -c1-300
echo SMOKE_END
