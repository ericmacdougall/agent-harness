#!/bin/bash
# on dev2: unpushed or dirty state of every t2-course clone (read-only)
for d in /home/eric/t2-audit/t2-course /home/eric/work/t2-course /home/eric/pr47-work; do
  echo "== $d"; cd "$d" || continue
  echo "  dirty(non-pycache)=$(git status --porcelain | grep -v __pycache__ | grep -v '^?? .claude/' | wc -l) stash=$(git stash list | wc -l)"
  git for-each-ref --format='%(refname:short) %(objectname:short)' refs/heads | while read b s; do
    echo "  $b $s onremote=$(git branch -r --contains "$s" 2>/dev/null | wc -l)"
  done
done
df -h / | tail -1
