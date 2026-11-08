#!/bin/bash
cd ~/gq-branch-clean/r4
for r in agent-rules fb-signage Stoke harness-example petfiliate poopyduck vcs-agents reachscout interview-prep harness-eval-builds field-notes-site harness-v2 netwatch one-shot-lab solver our-stream metaplex bugtracker-harness agentbrowser private-lessons-host t2-course; do
  bash bk.sh $r > bk-$r.log 2>&1; echo "$r rc=$? $(tail -1 bk-$r.log)" >> bkall.log
done
echo BKALLDONE >> bkall.log
