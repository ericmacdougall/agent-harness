# Adversarial delta spec review: S1 lane factory (goodqa#15946), core 39cd576c

Reviewer: agent ad0db2290d8c0ce39 (red-team, Opus). This is the one delta round after BLOCK on 41037e46 (review-redteam-41037e46.md).
Spec: software-factory/s1/spec.md, core 39cd576c12d60e25dcad10f3a571d03ffacca7bc833b6b8e452b710e76922a95. Lint PASS with `--repo software-factory/s1/wt`.
Method: a full text diff of spec.md against spec-3fe91599.md (41037e46 plus the compatibility paragraph). Each fold-in below was checked against the spec text, not against the author's summary.

VERDICT: ACCEPT (no material finding).

## Fold-in verification
- **M1 (checkpoint identity):** fixed.
  - AC-9 Verify by now requires `checkpoint` to take the agent id only from the hook stamp, equal to the journal's current `holder_bound` agent or main.
  - NEG-87 adds three cases: an env or argument id is refused, an agent bound to lane M is refused on lane L, and a helper inheriting A's environment is refused.
  - NEG-87 keeps its mutation clause (trusting the environment must fail).
- **Rollback:** fixed.
  - The compatibility paragraph is now in the core.
  - The rollback target is pinned to the pre-S1 commit c82ad2af.
  - AC-44 rehearses the store being left in place and unread, the registered hooks no longer referring to the lane, an owner spawn still working and no lane module imported.
  - It then reinstalls the landed commit and requires `verify` to pass.
  - The author's challenge (no lane reader at the rollback target) holds and is now stated.
- **AC-52:** both crash cases were added:
  - a kill after the revision is linked and before `manifest.head` is replaced;
  - a kill after the swap followed by a retry that fails before manifest publication, where the prior kit must still be recoverable.
- **NEG-92 (traversal):** added. It covers a ticket ref or slug containing `../`, `/`, NUL or an overlong value, a lane id with a separator, and `LANE_KIT_VERSION=<ticket>=../../x`. All are refused before any path is built.
- **AC-2:** adds a barrier test with two concurrent `new` calls, which must give one lane, one index entry and one attachment.
- **AC-1:** the read-back matches on lane id, op id and sha256 together. A same-name attachment with a different sha256 is never adopted, with a positive control.
- **AC-8:** ticket calls are counted in a server-side log at the fixture server, so traffic from child processes is seen. It also adds `regenerate`, `start --release` and `start --reconcile` to the table.
- **NEG-88:** now has a check. The installed module is run with LANE_FAKE_NOW and every test flag set, and the test asserts the real clock is used and `push-late` is unchanged.
- **Click-test citation:** corrected to line 98 (section 1.2), with main's judgment that line 98 governs over the line-8 header default.

## New text examined for regressions
- **N1 (Low, introduced by the delta): AC-8 dropped the in-process socket spy for the networked commands.** The old Verify by asserted the exact connect set. The new one counts only ticket calls at the fixture server, plus exec spies. An in-process connect to any other endpoint would go unseen, for example a model HTTP call from `new` or `checkpoint`. The clause "no spy records a model call" no longer names a spy that could see one. Socket denial remains only for `status` and `verify`. Fix: keep the server log and also keep the in-process socket spy, asserting no connect except to the fixture ticket server (and `git ls-remote` for `refresh`, which runs through exec). This does not block: the code has no network client in the lane package today, and the exec spy still catches a model CLI.
- **N2 (Low): Topology now says the escalation-ledger rung is per host.** That is a disclosure of how the existing ledger works, and lane commands run only on main's host, so S1 is unaffected. But if a stream ever moves hosts, it restarts at the lowest rung. Flag this for SC and S3, which own any move of a lane between hosts.
- **NEG-89 (tightened):** the head must be exactly one behind, and the writer's temp file must hold exactly that revision's bytes. This is consistent with AC-52, where the retry consumes the residue. The same-user forgery limit stays stated. No gap.
- **No other changes:** the diff contains no other edits to the ACs or NEGs.

## Probes
None. This is a spec delta review.

## Not examined
- The code against the new criteria (the command layer is not built).
- The tests.
- Install on either host.
