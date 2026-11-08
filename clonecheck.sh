#!/bin/bash
# on t2-dev: report state of every t2-course clone
for d in /home/eric/sites-seo/t2-course-main /home/eric/gq-branch-clean/tc/wc /home/eric/gq-branch-clean/tc/work; do
  echo "== $d"; cd "$d" || continue
  echo "  branch=$(git branch --show-current) dirty=$(git status --porcelain | wc -l) stash=$(git stash list | wc -l) worktrees=$(ls .git/worktrees 2>/dev/null | wc -l)"
  git for-each-ref --format='%(refname:short) %(objectname:short)' refs/heads | while read b s; do
    echo "  $b $s remote-branches-containing=$(git branch -r --contains "$s" 2>/dev/null | wc -l)"
  done
done
