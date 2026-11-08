#!/bin/bash
# on t2-dev: save diff + non-node_modules untracked files of each review-scratch checkout, upload, verify, THEN delete the checkout
set -u
ts=$(date -u +%Y%m%dT%H%M%SZ); out=~/gq-branch-clean/rsave-$ts; mkdir -p $out
dest=dropbox:Backups/repo-archives-private/review-scratch-qaca-diffs-$ts
cd ~/review-scratch
for d in qaca-ffa1 qaca-ffn qaca-mut qaca-muta qaca-mutb qaca-mutc qaca-p2b-74b1448 qaca-p2b-8c26f27 qaca-p2b-c72fc22; do
  ( cd $d
    git diff HEAD --binary > $out/$d.diff
    git status --porcelain | grep '^??' | cut -c4- | grep -v 'node_modules' > $out/$d.untracked.txt
    git rev-parse HEAD > $out/$d.head.txt
    if [ -s $out/$d.untracked.txt ]; then tar -cf $out/$d.untracked.tar -T $out/$d.untracked.txt 2>/dev/null; fi
  )
done
ls -la $out
rclone copy $out $dest/ && rclone check $out $dest 2>&1 | tail -2 | tee $out/check.log
if grep -q " 0 differences found" $out/check.log; then
  for d in qaca-ffa1 qaca-ffn qaca-mut qaca-muta qaca-mutb qaca-mutc qaca-p2b-74b1448 qaca-p2b-8c26f27 qaca-p2b-c72fc22; do rm -rf ~/review-scratch/$d; echo "removed $d"; done
else echo "CHECK FAILED - nothing deleted"; fi
df -h / | tail -1
