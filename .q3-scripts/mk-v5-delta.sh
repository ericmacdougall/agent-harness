#!/usr/bin/env bash
# Runs on t2-dev. Writes the S3a v5 interdiff (files of 96a6f88+s3a10.patch that differ from
# 96a6f88+diff(96a6f88..bb3918c8bd), limited to paths the patch touches) into a worktree of
# claude/qac-q3-s3-reports at bb3918c8bd.
set -euo pipefail
R=$HOME/repos/bugtracker; P=$HOME/wt/aab3-s3a10.patch; WT=$HOME/wt/q3-s3a-aab3
HEAD_SHA=bb3918c8bdfa0ae9dc5b99c783cada8c9e3d2569
cd "$R"
IA=$(mktemp); IB=$(mktemp)
GIT_INDEX_FILE=$IA git read-tree 96a6f88ecbc
git diff --binary 96a6f88ecbc "$HEAD_SHA" | GIT_INDEX_FILE=$IA git apply --cached
TA=$(GIT_INDEX_FILE=$IA git write-tree)
GIT_INDEX_FILE=$IB git read-tree 96a6f88ecbc
GIT_INDEX_FILE=$IB git apply --cached "$P"
TB=$(GIT_INDEX_FILE=$IB git write-tree)
echo "TREE_A $TA"; echo "TREE_B $TB (expect 15cd04f99ecdc03ed3f902ae2953a4a39349fb76)"
TOUCHED=$(grep '^diff --git' "$P" | sed 's#^diff --git a/\(.*\) b/.*#\1#' | sort -u)
CHANGED=$(git diff --name-only "$TA" "$TB" | sort -u)
DELTA=$(comm -12 <(echo "$TOUCHED") <(echo "$CHANGED"))
echo "DELTA_FILES:"; echo "$DELTA"
[ -d "$WT" ] || git worktree add -q -b claude/qac-q3-s3-reports "$WT" "$HEAD_SHA"
cd "$WT"; [ "$(git rev-parse HEAD)" = "$HEAD_SHA" ] || { echo WT_HEAD_MISMATCH; exit 3; }
for f in $DELTA; do
  [ "$(git rev-parse "HEAD:$f" 2>/dev/null)" = "$(git rev-parse "$TA:$f" 2>/dev/null)" ] || { echo "DRIFT $f"; exit 4; }
  git show "$TB:$f" > "$f"
done
git status --short; git diff --stat; rm -f "$IA" "$IB"
