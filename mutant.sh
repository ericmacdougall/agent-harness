#!/bin/bash
# controlled broken variant: gate and mark compare only the dist file COUNT, not paths and sizes. The new size/name test must fail.
H=/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/harness-delivery/.claude/worktrees/agent-ab8a7d1bf54ed3c9a
S=/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/agent-ab8a7d1bf54ed3c9a/n2sandbox
cp $H/media-sync.mjs $S/scripts/media-sync.mjs
sed -i.bak 's/treeHashOf(dist) !== treeHashOf(src)/dist.length !== src.length/; s/treeHashOf(distPublicEntries()) === treeHashOf(sourcePublicEntries())/distPublicEntries().length === sourcePublicEntries().length/' $S/scripts/media-sync.mjs
grep -c "dist.length !== src.length" $S/scripts/media-sync.mjs
(cd $S && node --test tests/media-deploy-gate.test.mjs 2>&1 | grep -E "^ℹ (tests|pass|fail)|^✖ [a-z]" | head -6)
cp $H/media-sync.mjs $S/scripts/media-sync.mjs
