#!/bin/bash
# on t2-dev: refresh mirrors and re-classify the five repos still above the target (one at a time; free space checked)
cd /home/eric/gq-branch-clean/r4 || exit 1
for r in timbar poopyduck interview-prep bugtracker bugtracker-harness; do
  f=$(df -BG / | awk 'NR==2{print $4}' | tr -d G)
  [ "$f" -lt 11 ] && { echo "STOP free ${f}G under 11G" ; exit 9; }
  rm -rf "$r.git"
  bash cls.sh "$r"
done
echo RECLS5_DONE
