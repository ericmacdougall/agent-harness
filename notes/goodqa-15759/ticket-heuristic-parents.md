Follow-up to goodqa#15759, receipt r1 findings on PR 219.

1. Operand-position heuristic (F3): the scp and rsync rule treats every remote operand that follows a local operand as an upload target, so an rsync option VALUE that is not in the value-flag list and precedes a remote SOURCE can make a download look like an upload (the known cases were added, e.g. --zc and --copy-as). Proposal: parse each tool's full option table, or promote a non-last remote operand only when the last operand is itself remote. Acceptance: a download with each rsync value flag stays allowed; hidden-destination forms stay refused.

2. Local `cp --parents` (and `install -D`, a local `rsync -R`) rebuild the source path under the destination, so `cp --parents .claude/hooks/command_guard.py ~/` writes a protected file. Same family as goodqa#15767 for the local side. Acceptance: tests for cp --parents into a directory whose source path names a protected file; a mutant that drops the handling.
