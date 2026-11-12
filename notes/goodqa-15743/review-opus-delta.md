# Spec review (adversarial, delta) of goodqa#15743 spec v3

Reviewer: native agent a0c568dfa08e7eb86 (Opus), WAL ids we7be5fc8489 (first round, BLOCK on v2) and w65e145764a1 (delta round).
Reviewed: notes/goodqa-15743/spec.md at 222afa0; the follow-up commit d0c2b1c applied the reviewer's items 1 to 6 (marker exemption by inode, resume scope pinned to receipts/.clone-remove-ID, session identity from hooks plus spoof NEG-15, live-owner refusal, scope wording, allowlist additions) and the lows (transport-proof wording).

Round 1 (v2): BLOCK, three high findings: H1 resume as a general deleter on a forgeable audit row, H2 ctime rule undefined for directories and defeated by resume, H3 AC-2/NEG-5 test unbuildable (remote.uploadpack refused first, `_git_out` adds protocol overrides, shared config check would be widened).

Round 2 (v3 delta): all three high findings closed by AC-8 and NEG-10, AC-6 and NEG-7, AC-2 and NEG-5; M1 to M3 and M5 to M8 closed; M4 partly closed (now closed by the live-owner refusal and NEG-15). Two spec contradictions reported (marker vs ctime rule, resume scope vs the wt-* name rule) and fixed in d0c2b1c. Remaining lows (rename destination race documented as acceptable given the random audit id, lsof timeout fails closed) are accepted.

Not examined by the reviewer: implementation code (none yet), APFS ctime behaviour (probe refused by the isolation guard, not routed around), live state of receipts/wt-pp768.

Round 3 (final confirmation of the working tree): ACCEPT with one medium and two lows, all applied by the author in the final spec text: compare refs before writing the marker (a difference leaves no marker), fsync the marker-inode row before any deletion, exact-or-slash lsof prefix match, the Known-limits wording; NEG-16 added.

Rounds 4 to 6 (spec v4, reviewed at 231ed6e, c05b858 and 6a18019 against code 6c1f357, 32e303d and 3fabef1): ACCEPT each time. Round 4 found no new high; round 5 found two mediums (the verified directory set was read at the end of verification, so a directory moved in during the git status and scan window would be deleted; `ah worktree-remove` shares the tightened config check and the spec did not say so); round 6 confirmed both are closed (set taken right after the cutoff, behaviour change stated in D4 and Scope and pinned by a test), the Out list and D4 agree, AC-6 states the early set and its single gap. D6, D7 and D8 are honestly labelled owner assumptions; AC-4 is stated plainly as weakened.

Verdict: ACCEPT
