#!/bin/bash
# on t2-dev: delete refs listed in hid-del.txt ("ref sha"), lease-guarded, chunks of 50
cd ~/gq-branch-clean/bt; : > hid-del.log
split -l 50 hid-del.txt hidchunk.
for f in hidchunk.*; do
  args=(); specs=()
  while read ref sha; do args+=("--force-with-lease=$ref:$sha"); specs+=(":$ref"); done < "$f"
  if git -C bugtracker.git push "${args[@]}" git@github.com:ericmacdougall/bugtracker.git "${specs[@]}" > push.out 2>&1; then echo "OK $f $(wc -l < $f)" >> hid-del.log; else echo "FAIL $f $(tail -3 push.out | tr '\n' ' ' | cut -c1-300)" >> hid-del.log; fi
done
cat hid-del.log | cut -c1-200 | sort | uniq -c | sort -rn | head
