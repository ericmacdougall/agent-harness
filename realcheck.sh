#!/bin/bash
# run the round-2 gate against the REAL proof-tree build output (dist/client from the earlier real build), via a sandbox root with symlinks
H=/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/harness-delivery/.claude/worktrees/agent-ab8a7d1bf54ed3c9a
T=/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/agent-ab8a7d1bf54ed3c9a/fresh/t2c
S=/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/agent-ab8a7d1bf54ed3c9a/n2real
mkdir -p $S/scripts; cp $H/media-sync.mjs $S/scripts/media-sync.mjs; cp $T/media-manifest.json $S/
ln -sfn $T/public $S/public; ln -sfn $T/power-user $S/power-user; ln -sfn $T/dist $S/dist
cd $S
echo "--- verify (prebuild)"; node scripts/media-sync.mjs verify | tail -1
echo "--- mark (postbuild)";  node scripts/media-sync.mjs mark | tail -1
echo "--- gate";              node scripts/media-sync.mjs gate | tail -2; echo "gate rc=$?"
cat $T/dist/.media-marker.json
