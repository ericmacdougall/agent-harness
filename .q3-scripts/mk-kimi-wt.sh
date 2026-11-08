#!/usr/bin/env bash
# Runs on t2-dev. Worktree ~/wt/q3-kimi on new branch claude/qac-kimi-fixes from origin/main, reusing the
# ship worktree's node_modules (same lockfile; checked).
set -euo pipefail
K=$HOME/wt/q3-kimi; S=$HOME/wt/q3-s3a-ship
cd "$HOME/repos/bugtracker"
git fetch -q origin
[ -d "$K" ] || git worktree add -q -b claude/qac-kimi-fixes "$K" origin/main
cd "$K"
git diff --quiet HEAD c6bb4238161bed2a83b74fb10382734ee224566b -- pnpm-lock.yaml && echo LOCK_SAME || { echo LOCK_DIFFERS; exit 3; }
( cd "$S" && find . -name node_modules -type d -prune -not -path "*/node_modules/*" ) | while read -r d; do
  mkdir -p "$(dirname "$K/$d")"; [ -e "$K/$d" ] || cp -a "$S/$d" "$K/$d"
done
echo "KIMI_WT $(git rev-parse HEAD)"
