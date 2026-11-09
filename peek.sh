#!/bin/bash
# READ-ONLY peek at non-git big dirs on t2-dev
for d in /home/eric/repos/hawk-cmp-t2 /home/eric/sites-seo /home/eric/rt-15477 /home/eric/rt-15477d /home/eric/rt-15477e /home/eric/rt-15477f /home/eric/pp-josh-batch /home/eric/pp-hwq-prep-s654 /home/eric/lessons2-t2c /home/eric/rt561 /home/eric/gq-branch-clean /home/eric/branch-cleanup-20261108; do
  echo "== $d $(du -sh $d 2>/dev/null | cut -f1) newest=$(find $d -type f -printf '%TY-%Tm-%Td %TH:%TM\n' 2>/dev/null | sort | tail -1)"
  ls -1 $d | head -8 | tr '\n' ' '; echo
  du -sh $d/* 2>/dev/null | sort -rh | head -4 | tr '\n' ';'; echo
  lsof +D $d 2>/dev/null | head -3
done
df -BG --output=avail / | tail -1
