# Spec review (adversarial, delta) of goodqa#15743 spec v3

Reviewer: native agent a0c568dfa08e7eb86 (Opus), WAL ids we7be5fc8489 (first round, BLOCK on v2) and w65e145764a1 (delta round).
Reviewed: notes/goodqa-15743/spec.md at 222afa0; the follow-up commit d0c2b1c applied the reviewer's items 1 to 6 (marker exemption by inode, resume scope pinned to receipts/.clone-remove-ID, session identity from hooks plus spoof NEG-15, live-owner refusal, scope wording, allowlist additions) and the lows (transport-proof wording).

Round 1 (v2): BLOCK, three high findings: H1 resume as a general deleter on a forgeable audit row, H2 ctime rule undefined for directories and defeated by resume, H3 AC-2/NEG-5 test unbuildable (remote.uploadpack refused first, `_git_out` adds protocol overrides, shared config check would be widened).

Round 2 (v3 delta): all three high findings closed by AC-8 and NEG-10, AC-6 and NEG-7, AC-2 and NEG-5; M1 to M3 and M5 to M8 closed; M4 partly closed (now closed by the live-owner refusal and NEG-15). Two spec contradictions reported (marker vs ctime rule, resume scope vs the wt-* name rule) and fixed in d0c2b1c. Remaining lows (rename destination race documented as acceptable given the random audit id, lsof timeout fails closed) are accepted.

Not examined by the reviewer: implementation code (none yet), APFS ctime behaviour (probe refused by the isolation guard, not routed around), live state of receipts/wt-pp768.

Round 3 (final confirmation of the working tree): ACCEPT with one medium and two lows, all applied by the author in the final spec text: compare refs before writing the marker (a difference leaves no marker), fsync the marker-inode row before any deletion, exact-or-slash lsof prefix match, the Known-limits wording; NEG-16 added.

Rounds 4 to 6 (spec v4, reviewed at 231ed6e, c05b858 and 6a18019 against code 6c1f357, 32e303d and 3fabef1): ACCEPT each time. Round 4 found no new high; round 5 found two mediums (the verified directory set was read at the end of verification, so a directory moved in during the git status and scan window would be deleted; `ah worktree-remove` shares the tightened config check and the spec did not say so); round 6 confirmed both are closed (set taken right after the cutoff, behaviour change stated in D4 and Scope and pinned by a test), the Out list and D4 agree, AC-6 states the early set and its single gap. D6, D7 and D8 are honestly labelled owner assumptions; AC-4 is stated plainly as weakened.

Round 7 (spec v4 at 969e431 plus one stated-limit sentence in AC-4, code 8647cd2): ACCEPT. The environment read is sound (KERN_PROCARGS2 layout, argc handling, start-environment limit). Findings kept as follow-ups: sysctl called without argtypes (fragile on arm64), an empty string in the environment ends the parse early, and the parent check looks one level up so a deliberately wrapping shell with an inline override passes it (now a stated limit in AC-4).

Rounds 8 to 10 (spec v4 at 640d82d, 8ca46b1 and the final text, code 0a07513): ACCEPT each time. The environment-identity model was withdrawn (probe: no ancestor start environment carries the session variable) and replaced by option A with a STATED LIMIT that the session identity is caller-settable. Findings applied: the old sentence claiming the session is never caller-settable deleted, the loss list (a) to (e) added, D2 and Risks point to the limit and to goodqa#15751, the loss headline reworded to match the named exceptions. The user acceptance of the residual is a pending ask registered by main, not granted.

Round 11 (spec v4 at 5d40d30, code 56b8dd9): ACCEPT. The AC-2 clause for the github.com-scoped gh credential helper (only with --remote-auth, other helpers cleared, no token in argv, output or audit, fails closed without gh) matches the code. Lows filed as a follow-up ticket: quote the gh path in the helper string, pin gh to known install locations, run ls-remote from / with no -C repo, report gh not found.

Verdict: ACCEPT
