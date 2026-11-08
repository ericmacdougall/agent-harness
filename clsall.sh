#!/bin/bash
cd ~/gq-branch-clean/r4
for r in timbar hawkeye agent-rules fb-signage Stoke harness-example petfiliate poopyduck vcs-agents reachscout interview-prep t2-course harness-eval-builds field-notes-site harness-v2 netwatch one-shot-lab solver our-stream metaplex bugtracker-harness agentbrowser private-lessons-host; do
  bash cls.sh $r
done
echo ALLDONE
