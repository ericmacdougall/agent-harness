#!/usr/bin/env bash
# t2-dev. Kimi QAC UI fix worktree from origin/main (deployed 30c7e41b plus deploy record); node_modules reused from q3-ship2.
set -u
T=$HOME/wt/q3-kimi-ui; S=$HOME/wt/q3-ship2
cd "$HOME/repos/bugtracker" || exit 2
git fetch -q origin
[ -d "$T" ] || git worktree add -q -b claude/qac-kimi-ui "$T" origin/main || exit 2
cd "$T" || exit 2
git log -1 --format='%H %s' | cut -c1-110
git diff --quiet 0dd91b778e1f9245157afcf9d94b6a09b84b5ad2 HEAD -- pnpm-lock.yaml && echo LOCK_SAME || { echo LOCK_DIFFERS; exit 4; }
( cd "$S" && find . -name node_modules -type d -prune -not -path "*/node_modules/*" ) | while read -r d; do
  mkdir -p "$(dirname "$T/$d")"; [ -e "$T/$d" ] || cp -a "$S/$d" "$T/$d"
done
echo "PORCELAIN $(git status --porcelain | wc -l)"
echo MK_END
