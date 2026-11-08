#!/usr/bin/env bash
# Runs on t2-dev. tsc on origin/main c6bb42381610 to show which tsc errors are base (not S3a). Reuses
# node_modules from the ship worktree: S3a changes no package.json or lockfile, so the install is identical.
set -u
B=$HOME/wt/q3-main-tsc; S=$HOME/wt/q3-s3a-ship
cd "$HOME/repos/bugtracker" || exit 2
[ -d "$B" ] || git worktree add -q --detach "$B" c6bb42381610
cd "$B" || exit 2
echo "BASE $(git rev-parse HEAD)"
git diff --quiet c6bb42381610 "$(cd "$S" && git rev-parse HEAD)" -- pnpm-lock.yaml package.json apps/api/package.json packages/db/package.json && echo LOCK_SAME || { echo LOCK_DIFFERS; exit 3; }
( cd "$S" && find . -name node_modules -type d -prune -not -path "*/node_modules/*" ) | while read -r d; do
  mkdir -p "$(dirname "$B/$d")"; [ -e "$B/$d" ] || cp -a "$S/$d" "$B/$d"
done
bash "$HOME/wt/aab3-tsc-gate.sh" "$B" "$HOME/wt/aab3-base.tsc.log"
grep "error TS" "$HOME/wt/aab3-base.tsc.log"
echo BASE_TSC_END
