#!/bin/bash
# on t2-dev: show the flagged line with every 12+ char token masked, so no secret value is printed
cd /home/eric/gq-branch-clean/tcr/mirror.git || exit 1
git show cede65472a2aafa0e8bdd242732d90052baf0652:narration/beginner-and-audio-workflow.md 2>/dev/null | grep -nE 'API_KEY|SECRET|PASSWORD|AKIA|ghp_|sk-|xox|AIza|eyJ|re_[A-Za-z0-9]{20}' | sed -E 's/[A-Za-z0-9_.\/+-]{12,}/<TOKEN>/g' | cut -c1-200 | head -5
echo "--- is that file in main tip?"; git cat-file -e main:narration/beginner-and-audio-workflow.md 2>&1 && echo yes || echo no
