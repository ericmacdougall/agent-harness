#!/bin/bash
# on t2-dev: where are these bugtracker branches checked out, and when was that worktree last touched
for g in $(find /home/eric /srv -maxdepth 5 -name .git 2>/dev/null | head -300); do
  d=$(dirname "$g")
  git -C "$d" worktree list --porcelain 2>/dev/null | awk -v dir="$d" '/^worktree /{p=$2} /^branch refs\/heads\/(claude\/qac-kimi-create-web|claude\/qac-kimi-fixes|claude\/qac-q3-s3-reports|claude\/qac-q3-s3-ship|full-delegate-token|merge\/goodqa-15479-into-1309|rescue\/goodqa-15477-revocation)$/{print p, $2}' | while read p b; do
    echo "$b $p last-modified $(stat -c %y "$p" 2>/dev/null | cut -c1-16) procs: $(ps -eo args | grep -F "$p" | grep -v grep | wc -l)"
  done
done | sort -u
