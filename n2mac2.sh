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
git commit -q -m "fix(media): gate checks the shipped dist, not only the source" -m "Why: the review of PR 50 found an ok marker could sit on a dist with no media (a pull finishing between build and postbuild, or a stale marker after a rebuild that skipped postbuild)." -m "What: gate and mark compare the dist/client public media (paths and sizes) with the verified source tree; verify deletes any old marker first; a malformed marker fails with a clean message; tests simulate the build output." -m "Testing: \`node --test tests/media-deploy-gate.test.mjs\` -> 9 pass; 4 of the 9 fail against the previous script; the gate also passes on the real 38,218-file build output." -m "Refs: GoodQA #15484"
git push -q origin fix/media-deploy-marker 2>&1 | tail -1
echo "N2_HEAD $(git rev-parse HEAD)"
