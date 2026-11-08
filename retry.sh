#!/bin/bash
# on t2-dev: retry FAILED deletes for repo $1. Objects must exist locally for an explicit lease, so fetch branch tips first.
r="$1"; cd ~/gq-branch-clean/r4
grep '^FAIL' "del-$r.log" | awk '{print $2" "$3}' > "retry-$r.txt"
git -C "$r.git" fetch -q "git@github.com:ericmacdougall/$r.git" '+refs/heads/*:refs/remotes/o/*' 2>&1 | tail -2
cp "del-$r.txt" "del-$r.full"; cp "retry-$r.txt" "del-$r.txt"
bash del.sh "$r"
cp "del-$r.full" "del-$r.txt"
