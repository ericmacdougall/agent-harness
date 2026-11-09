# K2 spec adversarial review (native red-team agent a4e5a7bee7a5c4fc1, Opus)

Round 1 (draft spec): BLOCK. H1 dialog unmount loses key and draft; H2 request hash undefined (raw vs redacted body,
title); M1 race with ordinary send endpoint (foreign replay or 23505 500); M2 history predicate is membership-based and
replay skipped the access check; M3 retry waits behind a hung original (no lock timeout, root cause unnamed); M4 409
leaves the dialog stuck; M5 AC-2..5 could pass on wrong implementations; L1 two 409 codes; L2 archived replay vs notice
copy; L3 randomUUID secure context; L4 replay rate limit; L5 MCP title compat NEG.
Ruled out: deadlock (lock order acyclic), cross-user leak (key space per author), quota bypass (with AC-4 fix).

Round 2 (delta, spec core sha 0d2adf1409bf4f95): ACCEPT. All round-1 findings fixed. New: D1 (M) lock_timeout must be
limited to the advisory-lock statement and only its 55P03 mapped; D2 (M) conditional move of post-commit work needs an
AC; D3 (L) NEG-5 source note; D4 (L) injectable timeout. D1-D4 folded into the spec after this verdict (AC-9, NEG-16).
Round 3 (confirmation, spec core sha c7498706971d1553): ACCEPT. D1-D4 hold; AC-7 and AC-8 observable with
broken-variant controls. Non-blocking notes folded into AC-7 afterwards (pool lock_timeout check; accepted per-user
lock side effect named for the click-tester). Later wording-only edits from the acceptance review (AC-8 loophole
closed, NEG-8 test link) do not change the design.
Read-only; no probes run. Reviewer WAL: /Users/eric/.claude/wals/baab765b-d85c-46b4-b7b9-588eb912c770/agent-a4e5a7bee7a5c4fc1.jsonl
