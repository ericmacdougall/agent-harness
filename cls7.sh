#!/bin/bash
# on t2-dev: read-only classification of the seven repos still at 10 or more branches
cd ~/gq-branch-clean/r4
for r in timbar t2-sites bugtracker poopyduck interview-prep bugtracker-harness transition2-squeeze; do bash cls.sh $r; done
echo CLS7_DONE
