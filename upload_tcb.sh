#!/bin/bash
# on t2-dev: upload the t2-course bundle to Dropbox (one lane, throttled), verify with rclone check, delete the local bundle only on 0 differences
cd /home/eric/gq-branch-clean/tcb || exit 1
log=/home/eric/gq-branch-clean/upload_tcb.log; : > $log
b=$(ls t2-course-*.bundle | head -1); ts=${b#t2-course-}; ts=${ts%.bundle}
D=dropbox:Backups/repo-archives-private/t2-course-prerewrite-$ts
echo "BUNDLE $b" >> $log
rclone copy $b $D --tpslimit 2 --transfers 1 >> $log 2>&1
rclone copy $b.sha256 $D --tpslimit 2 >> $log 2>&1
rclone copy refs-$ts.txt $D --tpslimit 2 >> $log 2>&1
mkdir -p chk; ln -f $b chk/ 2>/dev/null || cp $b chk/; cp $b.sha256 refs-$ts.txt chk/
rclone check chk $D --tpslimit 2 > check.log 2>&1; cat check.log >> $log
if grep -q " 0 differences found" check.log; then
  rm -f $b chk/$b
  echo "UPLOAD_VERIFIED $D sha256 $(cut -d' ' -f1 $b.sha256) local bundle removed" >> $log
else echo "UPLOAD_CHECK_FAILED local bundle kept" >> $log; fi
df -h / | tail -1 >> $log
echo UPLOAD_DONE >> $log
