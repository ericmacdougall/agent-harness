On the first run against a fresh lock directory, infra/release-harness/rw-ship.sh prints a spurious error:

    rw-ship.sh: line 496: <lane>/locks/gq-promote.epoch: No such file or directory

Line 496 (bugtracker 6c187f88, staged byte-equal in bugtracker-harness PR 73 config/goodqa-release/bin/rw-ship.sh):

    E0=$(tr -dc 0-9 < "$EPOCHF" 2>/dev/null); EPOCH=$(( ${E0:-0} + 1 )); ...

Bash applies redirections left to right. The `< "$EPOCHF"` redirection fails before `2>/dev/null` takes effect, so the shell's own error reaches stderr.

Behaviour is still correct: E0 is empty, the epoch becomes 1, and the file is then written with temp-then-rename. So this is log noise only, not a lock or epoch fault. It does put a "No such file" line in a deploy log that an operator reads during a release.

Fix: put the stderr redirect first (`2>/dev/null < "$EPOCHF"`), or test for the file before reading it. Add a test asserting that a first run prints no "No such file" line.

Seen in the staged lane test runs on t2-dev (PR 73, goodqa#16136). Low priority; cosmetic.

Refs: goodqa#16136.
