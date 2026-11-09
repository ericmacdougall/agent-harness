#!/usr/bin/env bash
# goodqa#15561: the donor install (bt-release-smoke-c4054490cde8) was deleted under my symlinks. Re-create node_modules as a
# HARD-LINK copy of another install with the identical pnpm-lock.yaml (no data blocks copied, survives the donor's deletion).
set -e
DONOR="$HOME/repos/bt-release-smoke-b33ada8231d9"
MINE="$HOME/wt-15561"
cmp -s "$MINE/pnpm-lock.yaml" "$DONOR/pnpm-lock.yaml" || { echo "lockfile differs"; exit 1; }
cd "$DONOR"
for d in . apps/api apps/web packages/*; do
  [ -d "$DONOR/$d/node_modules" ] || continue
  if [ -L "$MINE/$d/node_modules" ]; then rm "$MINE/$d/node_modules"; fi
  [ -e "$MINE/$d/node_modules" ] && continue
  cp -al "$DONOR/$d/node_modules" "$MINE/$d/node_modules"
  echo "linked $d"
done
ls "$MINE/apps/api/node_modules/vitest/vitest.mjs"
