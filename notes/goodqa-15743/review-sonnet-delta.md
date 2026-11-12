# Spec review (acceptance, delta passes) of goodqa#15743 spec v4

Reviewer: native agent a5d878417503c1093 (Sonnet), WAL ids w914718f0cf3 and waef258cccb5 (round 1, BLOCK on v1), w7089a82129b (v3 ACCEPT), w37dfcd8425f (v4 first pass, BLOCK), wae3b29eaf5b (v4 final pass, ACCEPT).
Reviewed: notes/goodqa-15743/spec.md (v4) at 6a18019 against code on PR 215 at 3fabef195ced7a0e120fb3ca5509ad8df978f2d8. The only later change is one Risks-list phrase the reviewer pointed out ("hook-form rm exemption unchanged" now reads "tightened, not widened (D4)").

History: the first v4 pass BLOCKed on one item, D7 versus D4: the hook-form exemption refused partial clones only because the shared config check rejected the extensions section, which git 2.54 no longer writes; the test meant to prove the refusal was vacuous (it reached a real ls-remote). Fixed in code (the shared check refuses promisor and partial-clone filter keys unless clone-remove opts in; a test that fails if the network is reached) and in D4.
Final pass: M-a (any promisor value not plainly false refuses), M-b (the ah worktree-remove behaviour change stated in D4 and Scope, accepted by main), L-a (the directory set taken right after the cutoff and before git status), L-b (walk_delete requires the set) are closed; Out list and AC-6 consistent; no new high. Still open and not blocking: Review-policy standard (two reviews recorded), files kept because macOS metadata changed their ctime are never cleared.

Verdict: ACCEPT
