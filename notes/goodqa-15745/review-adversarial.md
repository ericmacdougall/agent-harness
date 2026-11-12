# Adversarial spec review, agent a4ffb12f1f937dad5 (red-team), goodqa#15745

Round 1: BLOCK with 9 material findings (key custody, replay, live-view exposure, injection scope, user-token automation, revocation bound, profile races, sentinel vacuity, resource limits) and 5 notes.
Round 2: BLOCK on one item (N1, live-view frame store retention, unspecified signed-in page images in Postgres) plus notes N2 (ticket enforcement, shared worker key) and N3 (helper gates).
Round 3 (final, after spec revision): N1, N2 and N3 resolved. Frame store is one UNLOGGED overwritten row per lease deleted within 15 s of view close, lease close, profile delete or stale view_until (NEG-18). Ticket id and shared worker key clarified in AC-9. Helper takes no flag, env or stdin for profile or domains (AC-8).
Non-blocking residuals folded into the spec afterwards: frames added to AC-10 search and AC-11 matrix, AC-9 sentence fixed, device-identity-binding waiver states the bearer-token residual risk.

VERDICT: ACCEPT

Round 4 (after fixes for the acceptance reviewer: in-process Keychain via purego, network policy stated, AC-20, capability gate): one BLOCK, AC-17 wrongly said "existing wildcard syntax" (schema accepts exact origins only). Fixed in spec (exact origins only, no wildcards, 16 max, NEG-13 covers wildcard). Reviewer found no other new BLOCK and stated it would accept after that text fix.

VERDICT: ACCEPT
