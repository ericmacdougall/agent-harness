#!/bin/bash
# emits one line per terminal state of: R2 upload, mac-offload, ticket consolidation; exits when all three have ended
W=/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770
r2=0; mo=0; tk=0
while true; do
  r=$(tail -1 $W/agent-ab8a7d1bf54ed3c9a/r2up.out 2>/dev/null)
  if [ $r2 = 0 ] && echo "$r" | grep -qE "ALL PARTS|FAILED|Traceback"; then echo "R2 ENDED: $r"; r2=1; fi
  if [ $r2 = 0 ] && ! pgrep -f "r2up.py" > /dev/null; then echo "R2 PROCESS GONE: $r"; r2=1; fi
  m=$(ssh -o ConnectTimeout=10 t2-dev 'tail -3 gq-branch-clean/moff.log' 2>/dev/null | tr '\n' ' ')
  if [ $mo = 0 ] && echo "$m" | grep -qE "MOFF_DONE"; then echo "MAC-OFFLOAD ENDED: $m"; mo=1; fi
  if [ $tk = 0 ] && ! pgrep -f "consol.py plan5" > /dev/null; then echo "TICKETS ENDED: $(tail -1 $W/ticket-cleanup/consol5.log)"; tk=1; fi
  [ $r2 = 1 ] && [ $mo = 1 ] && [ $tk = 1 ] && break
  sleep 120
done
echo ALL-THREE-ENDED
