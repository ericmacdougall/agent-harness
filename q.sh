#!/bin/bash
# on t2-dev: ONE Dropbox lane, queued. 1) wait for the old unthrottled moff.sh to end 2) copy media parts 3) re-run mac-offload copy+check (throttled) 4) restore-test a part 5) delete only after checks
log=/home/eric/gq-branch-clean/q.log; : > $log
D=dropbox:Backups/repo-archives-private
while pgrep -f "gq-branch-clean/moff.sh" > /dev/null; do sleep 20; done
echo "OLD_MOFF_ENDED $(tail -c 100 /home/eric/gq-branch-clean/moff.log | tr '\n' ' ')" >> $log
rclone copy /home/eric/gq-branch-clean/tc/parts $D/t2-course-media-parts-20261108 --tpslimit 2 --transfers 2 --exclude "*.json" >> $log 2>&1
cp /home/eric/gq-branch-clean/tc/work/media-manifest.json /tmp/media-manifest.json
rclone copy /tmp/media-manifest.json $D/t2-course-media-parts-20261108 --tpslimit 2 >> $log 2>&1
rclone check /home/eric/gq-branch-clean/tc/parts $D/t2-course-media-parts-20261108 --tpslimit 2 --exclude "*.json" >> $log 2>&1
echo "PARTS_CHECK_DONE" >> $log
# restore test: download one part from Dropbox and compare sha256 with the manifest
f=$(ls /home/eric/gq-branch-clean/tc/parts | grep '^part-0015' | head -1)
rclone copy $D/t2-course-media-parts-20261108/$f /tmp/restoretest --tpslimit 2 >> $log 2>&1
echo "RESTORE_SHA $(sha256sum /tmp/restoretest/$f | cut -d' ' -f1) $f" >> $log
grep "$f" /home/eric/gq-branch-clean/tc/work/media-manifest.json | head -1 >> $log
rm -rf /tmp/restoretest
echo "PARTS_STAGE_DONE" >> $log
rclone copy /home/eric/mac-offload $D/mac-offload-20261108 --tpslimit 2 --transfers 2 >> $log 2>&1
rclone check /home/eric/mac-offload $D/mac-offload-20261108 --one-way --tpslimit 2 > /home/eric/gq-branch-clean/q-check.log 2>&1
cat /home/eric/gq-branch-clean/q-check.log >> $log
if grep -q " 0 differences found" /home/eric/gq-branch-clean/q-check.log; then
  rm -rf /home/eric/mac-offload/branch-rescue-20261105 /home/eric/mac-offload/repos
  echo "MOFF_DELETED" >> $log
else echo "MOFF_CHECK_FAILED_NOTHING_DELETED" >> $log; fi
df -h / | tail -1 >> $log
echo Q_DONE >> $log
