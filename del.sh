#!/bin/bash
# usage: del.sh <repo> ; run ON t2-dev in ~/gq-branch-clean/r4 with del-<repo>.txt (branch sha). Lease-guarded: only deletes if tip == classified sha.
r="$1"; cd ~/gq-branch-clean/r4; : > "del-$r.log"
[ -d "$r.git" ] || git init --bare -q "$r.git"
while read b sha; do
  if git -C "$r.git" push --force-with-lease="refs/heads/$b:$sha" "git@github.com:ericmacdougall/$r.git" ":refs/heads/$b" >/dev/null 2>del.err; then echo "DELETED $b $sha" >> "del-$r.log"; else echo "FAIL $b $sha $(tr '\n' ' ' < del.err | cut -c1-160)" >> "del-$r.log"; fi
done < "del-$r.txt"
cut -d' ' -f1 "del-$r.log" | sort | uniq -c
