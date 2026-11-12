# PR review packet: `ah clone-remove` (agent-harness PR 215, GoodQA goodqa#15743)

Base: 4f9f4a3971eb0c1c68ea131df60762aebb55aa6b (origin/main; use `--snapshot-base 4f9f4a3971eb0c1c68ea131df60762aebb55aa6b`). Head: the PR head commit, which is the code commit a2b4686858d167afef28a227d85f2255690688da plus one notes-only commit that adds this packet and the validation log under notes/goodqa-15743/ (no code differs). Claude-authored: `--author-harness claude`.
Changed code paths: harness/hooks/clone_remove.py (new), harness/hooks/ah.py (clone-remove command), install.py, install_codex.py (file lists), tests/test_ah_clone_remove.py, tests/test_ah_clone_remove_review.py, tests/mutants_clone_remove.py. Specs and review records: notes/goodqa-15743/ (spec.md, review-opus-delta.md, review-sonnet-delta.md).

## Outcome
A clean, fully pushed PRIMARY clone (full, or a `blob:none` partial clone) under the caller's own session `~/.agent-harness/work/SESSION/receipts/wt-NAME` can be removed through one audited command, so a receipts directory over its budget stops deadlocking (ParentProof PR 773 could not get a full clone while receipts/wt-pp768 could not be removed by `verify-worktree`, the hook-form rm, or anything else). It is not a general deleter.

## Design (read clone_remove.py)
- Scope: exactly receipts/wt-NAME of the caller session, a real .git directory, no symlink, each component equal to its directory entry byte for byte; the CLI takes the session only from CLAUDE_CODE_SESSION_ID, refuses it when it differs from the calling shell, and refuses any AH_HOME or HOME that is not the account home.
- Verification: its own git runner (`git_argv`, `git_env`): `-c protocol.allow=never`, no per-protocol key, no lazy fetch, no SSH agent; only `REMOTE_LS` (one ls-remote) may use the network. The shared `_config_refusal` is reused unchanged; partial-clone acceptance is a separate check. Every ref, tracking ref, reflog commit, ORIG_HEAD and FETCH_HEAD sha must be reachable from the live listing (heads, tags, refs/pull/N/head; not pull merge refs). Refusals: stash, dirty or untracked, ignored files that are not tracked-.gitignore build directories, linked worktrees, modules, commondir, LFS, info attributes, hooks, in-progress state files, unknown top-level .git entries, alternates (own or from another repository under the session directory), credentials in URLs, unknown host, another extension, process cwd, open files (lsof), mounts.
- Removal: intent audit row fsynced before anything moves; rename to `.clone-remove-AUDITID` through the parent descriptor with (device, inode) checks; refs re-read inside the quarantine and compared; marker written and its inode row fsynced; descriptor walk (`walk_delete`) that holds one descriptor at a time, never follows a symlink, never crosses a device, keeps anything whose ctime is newer than the cutoff (directories by birth time only on resume); marker deleted last. Any stop before deletion restores the clone; `--resume AUDIT_ID` finishes exactly that quarantine (or restores a quarantine with no marker row).

## Spec, reviews, decisions
Spec v3 (notes/goodqa-15743/spec.md) attached to goodqa#15743 after two spec reviews (Opus adversarial, Sonnet acceptance) ACCEPT. First spec review BLOCKed v1 with eight high findings; all folded in. Code review (Opus): BLOCK on a rollback gap (a clone could stay in quarantine with no marker and no way back), caller-settable session and home sources, first-run directory rule; all fixed in a2b4686; delta review ACCEPT.

Deviations from spec v3 (assumptions, disclosed):
1. Directories are judged by birth time on RESUME only (ctime on the first run): removing a child moves a directory ctime, so the spec ctime rule made every interrupted run unresumable.
2. A partial clone is accepted without `extensions.partialClone` (git 2.54 writes only remote.NAME.promisor and partialclonefilter): exactly one remote, format version 1, filter exactly blob:none, any extension must name the promisor remote, no other extension.
3. The live-owner refusal in AC-4 and NEG-15 is NOT implemented: `ah owners` rows expose no worktree or cwd (`_live_owner_hits` returns no hits and says so). The process cwd scan and the lsof open-file scan are the live-use controls. The spec needs a sourced amendment before AC-4 evidence is recorded.
Not done: the real proof (AC-7) on receipts clones; the owner may not run git outside its worktree. Main runs `ah clone-remove --verify-only` then the real removal on receipts/wt-pp768.

## Failing-first and risk table (highest-risk negative cases)
The module was written before its tests, so failing-first rests on controlled broken variants: `python3 -B tests/mutants_clone_remove.py` applies 21 mutants (network denial removed, lazy fetch left on, symlink followed, cutoff removed, device crossed, intent row optional, no refs re-read in quarantine, resume ignoring marker or inode, pull merge refs accepted, reflog ignored, alternates scan off, local exclude accepted, foreign session accepted, byte-for-byte check off, credential URL accepted, birth time on first run, ctime on resume, unwritable marker not restored, relative alternates, token userinfo) and each is caught by a named test (21 of 21). The canary test proves a plain git call contacts the remote (control) while the runner does not. Highest-risk cases and the tests that pin them: unique unpushed work (unpushed commit, commit only in logs/HEAD, orphan reflog, stale tracking ref, stash, ORIG_HEAD), another path or session (scope table, spoofed session), symlink or device traversal (Walk tests), TOCTOU (directory swapped after verification, moved-in directory, file written after verification then resume), resume abuse (forged row, wrong inode, extra refs, concurrent lock), rollback (intent write failure, marker failure, kill before marker row, refs differ in quarantine).

## Validation (exact head, run in the owner worktree at code commit a2b4686858d1)
$ python3 -B -m unittest tests.test_ah_clone_remove tests.test_ah_clone_remove_review tests.test_ah_worktree_remove tests.test_reproducible_clone tests.test_command_guard_worktree_remove tests.test_worktree_hooks_rule tests.test_worktree_config_extension
Ran 231 tests in 120.611s
OK (skipped=1)
exit 0

## Risk and rollback
A new deletion path, host local only, behind a verification that refuses on any doubt and a quarantine that restores on any stop before deletion. Revert the commit to remove it; nothing else depends on it. t2-dev is out of scope (git 2.43 ignores GIT_NO_LAZY_FETCH).
