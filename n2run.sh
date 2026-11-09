#!/bin/bash
# round-1 script (the one reviewed, BLOCK) vs round-2 script against the new tests, in a tiny sandbox
H=/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/harness-delivery/.claude/worktrees/agent-ab8a7d1bf54ed3c9a
S=/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/agent-ab8a7d1bf54ed3c9a/n2sandbox
mkdir -p $S/scripts $S/tests
cp $H/media-deploy-gate.test.mjs $S/tests/
echo "=== round-1 script (commit 9a71aa13d620, the reviewed one) against the new tests"
cp $H/media-sync.before-n2b.mjs $S/scripts/media-sync.mjs
(cd $S && node --test tests/media-deploy-gate.test.mjs 2>&1 | grep -E "^ℹ (tests|pass|fail)|^✖ [A-Za-z]|^✔" | head -14)
echo "=== round-2 script"
cp $H/media-sync.mjs $S/scripts/media-sync.mjs
(cd $S && node --test tests/media-deploy-gate.test.mjs 2>&1 | grep -E "^ℹ (tests|pass|fail)|^✖|^✔")
