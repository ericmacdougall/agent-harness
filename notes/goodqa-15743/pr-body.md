Why: a clean, fully pushed partial clone under the session receipts directory could not be removed by verify-worktree, the hook rm exemption or any other route, so a receipts directory over its budget deadlocked a ParentProof PR (goodqa#15743).

What:
- New harness/hooks/clone_remove.py and `ah clone-remove --path P --reason R [--remote-auth] [--verify-only] [--resume AUDIT_ID]`, this machine only. It is not a general deleter: the target is exactly this session's receipts/wt-NAME, a real .git directory, no symlink, every path component equal to its directory entry.
- Verification uses its own git runner with the network denied (protocol.allow=never, no per-protocol key, no lazy fetch); only one ls-remote may talk to the network. Every ref, tracking ref and reflog commit must be reachable from a sha the live remote lists (heads, tags, pull heads). It refuses stashes, local state, LFS, alternates, hooks, odd .git entries, credentials in URLs, other extensions, and any process or open file inside the clone.
- Removal writes an fsynced intent row, renames the clone to a quarantine name beside it, re-reads the refs there, writes a marker, then deletes by a descriptor walk that never follows a symlink, never crosses a device and keeps anything changed after verification began. Any stop before deletion restores the clone. Resume finishes exactly that quarantine.
- Wired into ah and both installers. The hook-form rm exemption and the shared config check are not widened.

Testing:
- python3 -B -m unittest tests.test_ah_clone_remove tests.test_ah_clone_remove_review: 56 tests OK.
- python3 -B tests/mutants_clone_remove.py: 21 of 21 broken variants killed.
- Regression suites for worktree remove, reproducible clone, command guard worktree remove and hooks rule: 151 tests OK, 1 skipped.
- Spec reviews (Opus and Sonnet) ACCEPT; code review (Opus) BLOCK then fixed, delta ACCEPT. Not live tested: the real proof on receipts is for main.

Disclosed deviations: directories are judged by birth time on resume only; a partial clone is accepted without extensions.partialClone because git 2.54 does not write it; the live owner refusal is not implemented because ah owners has no worktree or cwd (needs a sourced spec amendment).

Refs: GoodQA goodqa#15743

Risk: a new deletion path, local only; revert the commit to remove it.

🤖 Generated with [Claude Code](https://claude.ai/code)
