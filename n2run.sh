#!/bin/bash
# failing-first and passing run of the N2 test, in a tiny sandbox (only a few KB of temp files)
H=/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/harness-delivery/.claude/worktrees/agent-ab8a7d1bf54ed3c9a
S=/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/agent-ab8a7d1bf54ed3c9a/n2sandbox
mkdir -p $S/scripts $S/tests
cp $H/media-deploy-gate.test.mjs $S/tests/
echo "=== BEFORE the fix (media-sync.mjs from head 7d08b79: no mark/gate)"
cp $H/media-sync.before-n2.mjs $S/scripts/media-sync.mjs
(cd $S && node --test tests/media-deploy-gate.test.mjs 2>&1 | grep -E "^# (tests|pass|fail)|^not ok|^ok")
echo "=== AFTER the fix"
cp $H/media-sync.mjs $S/scripts/media-sync.mjs
(cd $S && node --test tests/media-deploy-gate.test.mjs 2>&1 | grep -E "^# (tests|pass|fail)|^not ok|^ok")
