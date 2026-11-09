#!/bin/bash
# emits deploy milestones from t2-dev's dep_run.log (no token ever appears there) and stops on DEP_DONE or ABORT
last=""
while true; do
  l=$(ssh -o ConnectTimeout=10 t2-dev "grep -E '^\[|^---|rc=|ABORT|DEP_DONE|deploy|Deployed|Current Version|Uploaded|Error|ERROR' /home/eric/gq-branch-clean/dep_run.log | tail -8" 2>/dev/null)
  if [ "$l" != "$last" ]; then echo "$l" | tail -4; last="$l"; fi
  echo "$l" | grep -qE "DEP_DONE|ABORT" && break
  sleep 45
done
