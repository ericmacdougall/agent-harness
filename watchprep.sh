#!/bin/bash
# emits when t2-dev free space < 11 GB while the rewrite prep runs, and on every prep milestone
last=""
while true; do
  f=$(ssh -o ConnectTimeout=10 t2-dev "df -BG / | awk 'NR==2{print \$4}' | tr -d G" 2>/dev/null)
  [ -n "$f" ] && [ "$f" -lt 11 ] && echo "LOW DISK t2-dev ${f}G free"
  l=$(ssh -o ConnectTimeout=10 t2-dev "grep -E 'N1|MAIN_MOVED|CLONE_FAILED|OLD_MAIN|NEW_MAIN|SECRET_SCAN|PREP_DONE|size after|HIT|FILE@|media_files' gq-branch-clean/rewrite_prep.log | tail -30" 2>/dev/null)
  if [ "$l" != "$last" ]; then echo "$l" | tail -6; last="$l"; fi
  echo "$l" | grep -qE "PREP_DONE|N1_HITS_STOPPING|MAIN_MOVED|CLONE_FAILED" && break
  sleep 30
done
