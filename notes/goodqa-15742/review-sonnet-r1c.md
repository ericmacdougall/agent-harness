# Sonnet acceptance review, receipt r1c spec text (agent a5d878417503c1093)

The new AC-4, AC-5, AC-8 and AC-9 text matches the code at 309ab43b, contradicts nothing else in the spec and adds no untestable claim (CLEARING results, attempt_refused, TOTAL_DEADLINE 200 under SELFTEST_TIMEOUT 330, real post-restore state, goodqa#15769 and goodqa#15759 references).
Gap raised: no sanctioned exit when neither resume nor rollback can succeed. Resolution: stated as an AC-5 limit with a follow-up ticket for a main-only --resolve.
Verdict: ACCEPT
