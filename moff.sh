#!/bin/bash
# on t2-dev: stream ~/mac-offload to Dropbox, verify with rclone check, then delete only on 0 differences
dest=dropbox:Backups/repo-archives-private/mac-offload-20261108
src=/home/eric/mac-offload
log=/home/eric/gq-branch-clean/moff.log; : > $log
rclone copy $src $dest --transfers 2 --stats 60s --stats-one-line >> $log 2>&1
rclone check $src $dest --one-way >> $log 2>&1
if grep -q "0 differences found" $log; then
  rm -rf /home/eric/mac-offload/branch-rescue-20261105 /home/eric/mac-offload/repos
  echo "MOFF_DELETED" >> $log
else echo "MOFF_CHECK_FAILED_NOTHING_DELETED" >> $log; fi
df -h / | tail -1 >> $log
echo MOFF_DONE >> $log
