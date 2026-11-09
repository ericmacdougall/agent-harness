#!/bin/bash
# emits when Mac free space < 8 GB (abort threshold is 6) and when the fresh-clone proof ends
out=/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/agent-ab8a7d1bf54ed3c9a/freshproof.out
while true; do
  f=$(df -g /System/Volumes/Data | awk 'NR==2{print $4}')
  if [ "$f" -lt 8 ]; then echo "LOW DISK ${f}G free"; fi
  if grep -q FRESH_DONE "$out"; then echo "PROOF ENDED free ${f}G"; break; fi
  sleep 30
done
