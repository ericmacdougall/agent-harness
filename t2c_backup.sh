#!/bin/bash
# mirror fresh/t2c (minus rebuildable content) to Dropbox (throttled), then rclone check. Deletion is a separate, guard-approved step.
SRC=/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/agent-ab8a7d1bf54ed3c9a/fresh/t2c
DST=lessons-dropbox:Backups/repo-archives-private/t2c-proof-tree-20261109
LOG=/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/agent-ab8a7d1bf54ed3c9a/t2c_backup.log
: > $LOG
EX=(--exclude "/node_modules/**" --exclude "/dist/**" --exclude "/public/audio/**" --exclude "/public/engineering-videos/**" --exclude "/public/data-audio/**" --exclude "/power-user/public/audio/**" --exclude "/.media-cache/**")
rclone copy "$SRC" "$DST" "${EX[@]}" --tpslimit 2 --transfers 2 >> $LOG 2>&1
rclone check "$SRC" "$DST" "${EX[@]}" --tpslimit 2 > $LOG.check 2>&1
cat $LOG.check >> $LOG
if grep -q " 0 differences found" $LOG.check; then echo "T2C_BACKUP_VERIFIED $(grep -c . $LOG.check) lines" >> $LOG; else echo "T2C_BACKUP_CHECK_FAILED" >> $LOG; fi
echo T2C_BACKUP_DONE >> $LOG
