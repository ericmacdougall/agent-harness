#!/bin/bash
cd /home/eric/t2-audit/t2-course || exit 1
git status --porcelain
echo ---
git diff --stat | tail -5
for f in $(git status --porcelain | grep '^??' | cut -c4-); do echo "untracked: $f $(du -sk "$f" 2>/dev/null | cut -f1) KB newest $(find "$f" -type f -printf '%TY-%Tm-%Td\n' 2>/dev/null | sort | tail -1)"; done
