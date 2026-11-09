#!/bin/bash
# round 2 of N2 on the existing scratchpad clone: commit the dist-aware gate and tests on fix/media-deploy-marker and push (no force)
set -eu
H=/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/harness-delivery/.claude/worktrees/agent-ab8a7d1bf54ed3c9a
cd /Users/eric/.agent-harness/scratch/claude-501/-Users-eric/baab765b-d85c-46b4-b7b9-588eb912c770/scratchpad/n2/t2c
git checkout -q fix/media-deploy-marker
cp $H/media-sync.mjs scripts/media-sync.mjs
cp $H/media-deploy-gate.test.mjs tests/media-deploy-gate.test.mjs
node --check scripts/media-sync.mjs
node --test tests/media-deploy-gate.test.mjs 2>&1 | grep -E "^ℹ (tests|pass|fail)"
git add -A; git status --short
git commit -q -m "test(media): gate refuses wrong sizes and names in dist" -m "Why: the delta review of PR 50 found the tests still passed when the gate only counted dist files, so nothing proved the path and size comparison." -m "What: a test where a dist file has the wrong size, and one where a dist file has the wrong name." -m "Testing: \`node --test tests/media-deploy-gate.test.mjs\` -> 10 pass; a count-only mutant of the gate fails exactly this test." -m "Refs: GoodQA #15484"
git push -q origin fix/media-deploy-marker 2>&1 | tail -1
echo "N2_HEAD $(git rev-parse HEAD)"
