# Spec: Verified-clean primary clone removal: ah clone-remove

Ticket: GoodQA goodqa#15743
Author: agent:af9e (Sonnet 5.5)
Click-test: required
Sign-off: main
Review-policy: standard

## Outcome

A clean, fully pushed PRIMARY clone under the harness work directory on this machine (a full clone or a partial clone made with `--filter=blob:none`) can be removed through one audited command, `ah clone-remove --path P --reason R [--remote-auth] [--verify-only]` (with `--resume AUDIT_ID` to finish an interrupted removal), so that a receipts directory over its budget no longer deadlocks (ParentProof PR 773 cannot get a full clone while `receipts/wt-pp768` cannot be removed by `verify-worktree`, `rm` or any other route). The tool exists to unblock that deadlock and stays small: it is not a general deleter.

## Scope

- In: `command_guard.py verify-clone` and `remove-clone` (JSON out, like `verify-worktree`), and `ah_worktree.py` plus `ah clone-remove`, host `local` only. Verification reuses `reproducible_clone_refusal` (clean tree, no stash, every ref reachable from a live remote ref, no linked worktrees, no submodules, no hooks, config whitelist) and adds the refusals listed in AC-3 to AC-5. Removal is a quarantine rename followed by an in-process descriptor-based walk (AC-6, AC-8).
- Out: `--host t2-dev` (the receipts deadlock is on the Mac; a remote run needs the git 2.44 lazy-fetch gate and a remote audit design and gets its own ticket); linked worktrees (`ah worktree-remove` stays their route); any path outside the work directory; the hook-form `rm` exemption (unchanged, still refuses a partial clone); network clones; the owner removes nothing under receipts while this is built, main uses the tool after merge and install.
- Decisions: (D1) host local only, because the red-team found git 2.43 on t2-dev ignores `GIT_NO_LAZY_FETCH`; source: ticket:GoodQA goodqa#15743 red-team H6. (D2) a target in another session's directory is allowed (main must remove a receipts clone) but the audit row records the caller session and the owning session directory; assumption, inferred.

## Acceptance criteria

- AC-1: A clean, fully pushed full clone under the work directory is judged removable; `remove-clone` deletes the whole directory (clone, `.git`, whole regenerable ignored build directories), reports `removed`, `directory_removed` and bytes freed (block count at verification, hard links counted once), and writes the audit rows. Verify by: `python3 -B -m unittest tests.test_ah_clone_remove` (real temporary repositories, fake network). Source: ticket:GoodQA goodqa#15743
- AC-2: A partial clone (`extensions.partialClone=origin`, `remote.origin.promisor=true`, `remote.origin.partialclonefilter=blob:none`, objects missing) that is otherwise clean and pushed is judged removable. Verification never fetches on any git version: every verification git call runs with `-c protocol.allow=never` and no per-protocol overrides, plus `GIT_NO_LAZY_FETCH=1`; only the single authenticated `ls-remote` call gets `https` and `ssh`. A verification that needs a missing object refuses. Verify by: the same suite with a real `--filter=blob:none` clone and a canary `remote.origin.uploadpack` wrapper that records every contact (zero contacts expected while a missing-object read is forced). Source: ticket:GoodQA goodqa#15743
- AC-3: Every unsafe state refuses with its own reason and removes nothing: - refs: every ref (heads, tags, `refs/remotes/*` except the symbolic HEAD, notes, bisect, rewritten, replace) and the shas in ORIG_HEAD, FETCH_HEAD, `logs/HEAD` and every file under `.git/logs` (read directly) must be reachable from a sha the live remote lists (authenticated when `--remote-auth`); a stale tracking ref whose commits exist nowhere else refuses (H5, M4); - working tree: stash, modified, staged or untracked file; an ignored file that is not a whole regenerable build directory, where each accepted ignored directory must be matched (by `git check-ignore -v`) by a tracked `.gitignore`, never by `.git/info/exclude` or a global ignore (M3); - structure: any entry under `.git/worktrees`, a submodule, `.git/commondir`, a `rev-parse --git-common-dir` other than `TARGET/.git`, `.git/lfs`, `.git/info/attributes`, replace refs or grafts, installed hooks, an `objects/info/alternates` or `http-alternates` naming a path that does not exist (H4, H8); - state files: MERGE_HEAD, CHERRY_PICK_HEAD, REVERT_HEAD, REBASE_HEAD, AUTO_MERGE, `rebase-merge/`, `rebase-apply/`, `sequencer/`, BISECT_LOG refuse (ORIG_HEAD and FETCH_HEAD shas join the pushed set instead, M1); - remote: a remote that is not on a known hosting service, a remote URL that carries a password (refused without echoing the URL, M9), a remote that does not answer. Shallow clones are allowed (L2). Verify by: the same suite, one subtest per state. Source: ticket:GoodQA goodqa#15743
- AC-4: Scope: a directory at least two levels below `~/.agent-harness/work`, a real `.git` directory (not a file), no symlink in the path or at the target, not the work directory, a session directory or a task directory, not the caller's current directory or an ancestor of it, not inside a registered delivery checkout (`harness-delivery`), and no same-user process working inside it, holding an open file or mapping inside it (lsof, fail closed when lsof is unavailable or times out), same rule and service skip list as `ah worktree-remove` for the working-directory part. Containment and ancestry are judged by (device, inode) along the ancestor chain, not by string comparison (M6). A literal absolute path only. Verify by: the same suite. Source: ticket:GoodQA goodqa#15743
- AC-5: Partial-clone acceptance is exact: `extensions.partialClone` equals the single remote the verifier reads (known host), `remote.NAME.promisor` is true, `remote.NAME.partialclonefilter` is a plain filter spec (`blob:none`, `blob:limit=N`, `tree:0`; `combine:` and `sparse:` refuse), `core.repositoryformatversion` is 1, no other `extensions.*` key is accepted (`worktreeConfig` is not accepted for a clone), and any other promisor remote or a missing promisor key refuses. The legacy `core.partialclonefilter` refuses. Verify by: the same suite, one subtest per variant. Source: ticket:GoodQA goodqa#15743
- AC-6: The walk is done by the tool with descriptors: open the quarantine root with `O_NOFOLLOW|O_DIRECTORY` and require `fstat` to equal the verified (device, inode); every descent uses `os.open(name, O_NOFOLLOW|O_DIRECTORY, dir_fd=fd)` and compares `fstat` with the earlier `lstat`; entries are removed with `os.unlink` and `os.rmdir` taking `dir_fd`; a symlink is unlinked as a link, never traversed; the walk never crosses a different `st_dev` and the tool refuses up front when the mount table (`mount` on macOS, `/proc/self/mountinfo` on Linux) lists a mount at or under the target; a read-only directory gets its owner write bit through `os.fchmod` on its own descriptor only; `uchg`, `schg` and ACLs are never cleared and what they leave is reported; an entry whose ctime is later than the start of verification is not deleted and is reported (M2). A partial deletion is reported as `removed: null` with `directory_removed` and what is left, never a definite false. Verify by: the same suite (swapped directory, symlink inside, bind-like second device simulated with a patched `st_dev`, failing unlink, a file that appears mid-walk). Source: ticket:GoodQA goodqa#15743
- AC-7: Real proof: on the Mac, `ah clone-remove --verify-only` then the real run, with `--remote-auth`, on a disposable full clone and a disposable blob:none clone created by the tester inside the work directory, remove both and free their bytes; real-environment negatives (a disposable clone with an unpushed commit, one with a stale tracking ref, one with a non-build ignored file) each refuse and nothing is deleted; verify-only output for `receipts/wt-pp768` is saved first; main then runs the real removal on it (confirming first that it is a primary clone with a real `.git` directory and a partial filter) and the result and bytes freed are recorded (REALLY_TESTED) with the installed commit. The owner removes nothing under receipts. Verify by: the saved outputs under the work directory. Source: ticket:GoodQA goodqa#15743
- AC-8: After the final verification and identity check, the tool atomically renames the clone to `PARENT/.clone-remove-AUDITID` on the same device, re-reads refs, reflogs, stash and `.git/worktrees` inside the quarantine and compares them with the verified snapshot, and only then deletes. `ah clone-remove --resume AUDIT_ID` deletes only a quarantine directory whose (device, inode) matches the audit row, without re-checking cleanliness; any other directory, or a mismatch, refuses. A failed walk therefore never leaves a half-deleted clone that nothing can remove. Verify by: the same suite (injected failure halfway, then `--resume`). Source: ticket:GoodQA goodqa#15743
- AC-9: `--verify-only` prints the verdict, every ref and the proof shas, the top-level entries and ignored directories that would be deleted and their size, and deletes nothing and changes no file in the clone (`GIT_OPTIONAL_LOCKS=0`; a listing of `.git` names, sizes, mtimes and inodes is identical before and after). The audit row for either mode holds every ref and sha, the live remote shas used as proof, the (device, inode), the size, git and verifier versions, and remote URLs with credentials removed (M5). The CLI always uses the policy from code: no policy file or argument widens the known hosts or the ignored-directory names (L5). Verify by: the same suite. Source: ticket:GoodQA goodqa#15743

## Negative cases

- NEG-1 (AC-4): the work directory itself, a session directory, a task directory one level below it, a path outside the work directory, a parent that is a symlink, a relative path, `..`, a trailing slash, a space or shell metacharacter, a directory without `.git`, a `.git` that is a file, a case-variant spelling of the work directory and a `/System/Volumes/Data/...` spelling must all refuse before any deletion. Source: ticket:GoodQA goodqa#15743
- NEG-2 (AC-3): a branch whose only commits are reachable from a remote ref the live remote no longer lists refuses (judged against live remote refs, not cached tracking refs); a commit reachable only from `logs/HEAD` after `reset --hard HEAD~1` refuses; an orphan reflog file under `logs/refs` refuses. Source: ticket:GoodQA goodqa#15743
- NEG-3 (AC-3): two remotes with one not on a known host refuses; a remote URL with embedded credentials refuses and appears in no stdout, stderr, audit row or exception text. Source: ticket:GoodQA goodqa#15743
- NEG-4 (AC-5): `extensions.partialClone` naming a missing remote, a promisor remote other than the verified one, or `extensions.objectFormat`, `worktreeConfig`, `refStorage` beside it refuses. Source: ticket:GoodQA goodqa#15743
- NEG-5 (AC-2): with the protocol denial and `GIT_NO_LAZY_FETCH` removed, the same canary test shows a remote contact (failing first); with them in place a forced missing-object read (stat-dirty file under `* text=auto eol=crlf`, a reflog entry for an absent commit) causes zero contacts and a refusal. Source: ticket:GoodQA goodqa#15743
- NEG-6 (AC-6): a symlink inside the clone to a path outside the work directory is removed as a link and its target survives; a directory deep in the tree swapped for a symlink mid-walk leaves the symlink target intact; a second device or mount inside the tree refuses before anything is deleted; the root renamed and replaced by another real directory after verification refuses. Source: ticket:GoodQA goodqa#15743
- NEG-7 (AC-6): the walk is killed halfway: the result is recorded as unknown with the quarantine path named, and a retry after an unknown outcome finds the audit row and reports "already removed (audit id)" or resumes, never a stat error. Source: ticket:GoodQA goodqa#15743
- NEG-8 (AC-4): a process whose cwd is inside the clone, or one holding an open file inside it, blocks the removal; a same-user service on the skip list does not block on cwd alone. Source: ticket:GoodQA goodqa#15743
- NEG-9 (AC-7): the owner removes nothing under receipts, and no typed rm, mv, scp or other route is used. Source: ticket:GoodQA goodqa#15743
- NEG-10 (AC-8): an injected failure halfway through the walk followed by `--resume` finishes the job; `--resume` with a different audit id, or on a directory with a different inode, refuses and deletes nothing. Source: ticket:GoodQA goodqa#15743
- NEG-11 (AC-3): a `--shared` clone of the target makes the scan of the work directory find an `objects/info/alternates` entry resolving inside the target and the removal refuses; a scan that cannot finish in its budget refuses. Source: ticket:GoodQA goodqa#15743
- NEG-12 (AC-3): a stale tracking ref with an expired reflog holding a commit that exists nowhere else refuses; a `.git/lfs` directory refuses; an ORIG_HEAD naming an unpushed commit refuses while an ORIG_HEAD naming a pushed commit passes. Source: ticket:GoodQA goodqa#15743
- NEG-13 (AC-3): an ignored `build/` created by hand and matched only by `.git/info/exclude` or a global ignore refuses. Source: ticket:GoodQA goodqa#15743
- NEG-14 (AC-9): a policy file or argument that adds a hosting service or ignored-directory name has no effect. Source: ticket:GoodQA goodqa#15743

Domain-gate: backup-before-delete waived (irreversible by design, so the control is verification instead of a backup: AC-3 requires every ref, reflog tip and stash to be reachable from a live remote ref, and the audit keeps every ref and sha so the pushed state can be re-fetched; the quarantine rename in AC-8 keeps the clone until the final delete)
Domain-gate: unpushed-work-detection waived (covered by real acceptance criteria, not waived in substance: AC-3, NEG-2, NEG-12 are the unpushed-work checks and AC-8 re-reads them inside the quarantine)
Domain-gate: dry-run-diff waived (covered: AC-9 `--verify-only` prints the full deletion plan and a test pins that it changes nothing)
Domain-gate: scope-pinning waived (covered: AC-4 and NEG-1 pin one literal path inside the work directory by device and inode, AC-6 pins identity at every descent)
Domain-gate: cross-host-approval-portability waived (no approval is involved: the verifier runs on the same host against its own files, host local only)
Domain-gate: idempotent-retry waived (covered: AC-8 `--resume` and NEG-7 and NEG-10 define retry after an interrupted or unknown removal)
Domain-gate: pre-account-hijack waived (no authentication or account flow is involved)
Domain-gate: lookalike-identifier waived (no identifiers or accounts are involved)
Domain-gate: request-device-binding waived (no login or approval link is involved)
Domain-gate: link-expiry-single-use waived (no emailed link or token is involved)
Domain-gate: session-fixation waived (no sessions are involved)
Domain-gate: rate-limit-enumeration waived (no account lookup is involved)
Domain-gate: store-billing-exposure waived (no billing or entitlement is involved)
Domain-gate: device-identity-binding waived (a path-based verifier on the host it runs on; no device enrollment is involved)
Domain-gate: unattended-recovery waived (a one-shot command with no resident agent)
Domain-gate: grant-durability waived (no grants or approvals are involved)
Domain-gate: remote-exec-audit waived (host local only in this work: no remote command is added; a t2-dev route needs its own ticket and spec)
Domain-gate: factory-reset-guard waived (no device wipe or unenroll is involved)
Domain-gate: idempotency-key waived (no money movement is involved)
Domain-gate: double-submit waived (no money movement or form is involved)
Domain-gate: currency-precision waived (no amounts are involved)
Domain-gate: refund-reversal-path waived (no money movement is involved)
Domain-gate: ledger-reconciliation waived (no ledger is involved)
Domain-gate: authorization-vs-capture waived (no payments are involved)
Domain-gate: derived-gate-floor-with-ratchet waived (no release gate or count floor is involved)
Domain-gate: artifact-inventory-mirrored waived (no signed artifact is built)
Domain-gate: self-update-e2e waived (no updater is involved; installing the hook files is a later, separate step)
Domain-gate: transport-proof waived (no remote transport in this work: the only network call is one authenticated ls-remote, exercised in AC-7 on the Mac)
Domain-gate: rollback-not-blocked waived (reverting this PR is a plain revert; nothing here gates a rollback)
Domain-gate: staging-exists waived (the rehearsal is AC-7: verify-only, disposable clones and real-environment negatives on the Mac before main runs the real removal)

## Resource budget

Host: mac
Fan-out: agents=2 jobs=1 processes=4 browser_pages=0 test_workers=1
Peak memory: 0.5 GB (method: unit tests with real temporary repositories)
CPU: 2 cores (method: the suite takes about a minute)
Disk: 0.2 GB (method: temporary repositories; the real run frees several GiB under receipts)
Network: 1 MB (method: one authenticated ls-remote per verification)
Wall time: 180 min
Cap and kill: foreground; each git call has a timeout; the deletion is bounded by REMOVE_SECONDS and a partial deletion is reported, never retried silently
Checkpoint: not required (under 10 min per step); every step is idempotent: verification changes nothing and a removal resumes through AC-8 --resume with the audit rows as the record

## Risks

- Deleting a clone with unique work is irreversible: mitigation, AC-3 (every ref, tracking ref, reflog tip and stash reachable from a live remote sha), AC-8 quarantine rename and re-verification, audit with every ref and sha.
- A failed partial deletion strands an unremovable directory (the original deadlock): mitigation, AC-8 quarantine and `--resume`.
- Walk races and symlink or mount traversal: mitigation, AC-6 descriptor walk with identity checks, no cross-device descent, up-front mount refusal.
- Another repository borrows this clone's objects: mitigation, AC-3 alternates scan and commondir refusal, NEG-11.
- A lazy fetch changes the clone or leaks a credential: mitigation, AC-2 protocol denial plus lazy-fetch off, canary test, no credential in output.
- The tool becomes a general rm: mitigation, scope strictly inside the work directory, a real .git directory, host local only, policy from code, literal path, audit on both ends, hook-form rm exemption unchanged.
- Known limits: dangling and cruft-pack objects that no ref or reflog reaches are not protected; notes and refs that `ls-remote --heads --tags` does not list always refuse (clear message).
