# Spec review (acceptance) of goodqa#15742 spec (ah install-files)

Reviewer: native agent a5d878417503c1093 (Sonnet), WAL ids wa78e8779a0b (first pass, BLOCK: H1 the ticket's exact-literal guard form dropped, H2 merged code not enforced, H3 A2 takes a decision the ticket reserves, H4 rollback over a later run; dropped ticket requirements, medium gaps), wbf7462583ce (v2, ACCEPT with build items), w2e3e3318987 (v3, ACCEPT).
Final text reviewed: v3 at 1db08bfb plus the fresh-repository-per-run change, the AC-5 start-row wording and the A2 wording (applied by the guard rule, which is accident prevention) that the reviewer pointed out; the spec at the attached sha is the final text.

Closed: the guard literal form (AC-9, NEG-11, with its stated limit), the merged-code proof (AC-2, NEG-2), main-only by default (A2, main to confirm), rollback over a later run (AC-8, NEG-9), the dropped ticket requirements now covered or labelled (A5 HOOKS only, A1 hosts, A7 backup location, required ticket, one comment), exit codes and JSON (AC-5), the real command string through sh -c and python 3.9 (AC-6), real command_guard.py and doctor.py in the fake host (AC-4), the lock covering rollback, the first-install audit file creation, and the honest staging-exists waiver. Remaining, not blocking: Review-policy standard keeps two reviews, which is recorded.

Verdict: ACCEPT
