#!/bin/sh
# Four concurrent copies of the changed test module, to see whether a time budget explains the one lost failure.
cd /Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/harness-delivery/.claude/worktrees/agent-ad33ebd391da329e6 || exit 1
for n in 1 2 3 4; do
  python3 -m unittest tests.test_command_guard_worktree_remove > "$TMPDIR/run$n.log" 2>&1 &
done
wait
for n in 1 2 3 4; do
  echo "--- run $n"
  grep -E '^(FAIL|ERROR|Ran|OK|FAILED)' "$TMPDIR/run$n.log" | cut -c1-200
done
