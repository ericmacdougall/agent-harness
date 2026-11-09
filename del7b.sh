#!/bin/bash
# on t2-dev: for each repo, bundle ONLY the branches about to be deleted (excluding what is already on the default branch), verify, upload throttled, rclone check, then lease-guarded delete (del.sh).
cd /home/eric/gq-branch-clean/r4 || exit 1
LOG=/home/eric/gq-branch-clean/del7b.log; : > $LOG
D=dropbox:Backups/repo-archives-private
for r in timbar poopyduck interview-prep bugtracker bugtracker-harness; do
  f=$(df -BG / | awk 'NR==2{print $4}' | tr -d G); [ "$f" -lt 11 ] && { echo "STOP free ${f}G under 11G" >> $LOG; break; }
  [ -s "del-$r.txt" ] || { echo "$r: no delete list" >> $LOG; continue; }
  ts=$(date -u +%Y%m%dT%H%M%SZ)
  def=$(git -C $r.git symbolic-ref --short HEAD)
  git -C $r.git remote update --prune >/dev/null 2>&1
  br=$(awk '{print "refs/heads/"$1}' del-$r.txt | tr '\n' ' ')
  b=$r-deltabranches-$ts.bundle
  if ! git -C $r.git bundle create /home/eric/gq-branch-clean/r4/$b ^$def $br >> $LOG 2>&1; then echo "$r: BUNDLE_FAILED" >> $LOG; continue; fi
  git -C $r.git bundle verify /home/eric/gq-branch-clean/r4/$b 2>&1 | tail -1 >> $LOG
  cp del-$r.txt $r-deltabranches-$ts.txt; sha256sum $b > $b.sha256
  rclone copy $b $D/$r-branchclean5-$ts/ --tpslimit 2 --transfers 1 >> $LOG 2>&1
  rclone copy $b.sha256 $D/$r-branchclean5-$ts/ --tpslimit 2 >> $LOG 2>&1
  rclone copy $r-deltabranches-$ts.txt $D/$r-branchclean5-$ts/ --tpslimit 2 >> $LOG 2>&1
  mkdir -p chk5-$r; rm -f chk5-$r/*; cp $b $b.sha256 $r-deltabranches-$ts.txt chk5-$r/
  rclone check chk5-$r $D/$r-branchclean5-$ts --tpslimit 2 > check5-$r.log 2>&1
  if grep -q " 0 differences found" check5-$r.log; then
    echo "$r: BACKUP_OK $D/$r-branchclean5-$ts" >> $LOG
    bash del.sh $r >> $LOG 2>&1
    echo "$r: deleted $(grep -c '^DELETED' del-$r.log) failed $(grep -c '^FAIL' del-$r.log)" >> $LOG
  else echo "$r: BACKUP_CHECK_FAILED nothing deleted" >> $LOG; fi
  rm -f $b chk5-$r/$b
done
echo DEL7_DONE >> $LOG
df -h / | tail -1 >> $LOG
