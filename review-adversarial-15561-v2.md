VERDICT: BLOCK

# Delta adversarial review: spec-15561 v2 (desktop token session delegation)

Reviewer: red-team agent ac5a43d2a99a04c6d. This is a read-only review of the revised spec against bugtracker c4054490cde8 on t2-dev, which was not modified. No probes were run.
Where this file is: the worktree guard blocked the work-dir path in round 1, so this file sits in my isolated worktree. The owner should copy it to `.../agent-ab3d0525e41a23326/review-adversarial-15561-v2.md`.

## Resolution of the v1 findings

| v1 | Status | Where |
|---|---|---|
| B1 kill switch | RESOLVED | D1 and D2 call `assertUserTokenUsable` on both doors; NEG-19; S1b's broken variant |
| B2 weaker host door | PARTLY: design fixed, waiver set wrong | D1 and D3 put both doors through one gate. W2 is too narrow, see N1 |
| M1 auth shape per door | RESOLVED for presence proofs and consent audit (NEG-22). Introduces N2 | D9 |
| M2 crm.api.enabled and session-only CRM | RESOLVED | F6, AC-1 iterates S0, AC-7 uses the segment DELETE, NEG-24, NEG-25, Q7 |
| M3 Messages live proof | RESOLVED | AC-12 Messages leg, Q8, NEG-23 |
| M4 notifications subtree | RESOLVED | D4 lists exact routes; NEG-23 |
| M5 Q2 alternative | RESOLVED | D6, Q2 |
| M6 preset copy | RESOLVED | D11a, AC-11, NEG-28 |
| m1 every isForbiddenError consumer | RESOLVED in D10 and AC-10. The Scope section still says "the four CRM pages", see N4 | |
| m2 edit existing token | RESOLVED | D10 copy, D11 |
| m3 ledger the route-class refusals | RESOLVED | D3 order, D9 |
| m4 AC-13 "unchanged" | RESOLVED | AC-13 names the exempted files |
| m5 projectIds and conversationScope | RESOLVED | D2 loads the full row; NEG-26 |
| m6 saved-view route | RESOLVED | AC-1 names the segments routes |
| m7 streams | RESOLVED | D4 rule |
| m8 shared rate bucket | RESOLVED | D9, D10 (429 copy) |
| m9 attribution | RESOLVED | D9 |

## New findings in the revision

**N1 (MAJOR). W2 is too narrow. The D1 and D3 design as written refuses most host-door routes, even for a token holding all five abilities. Confirmed from the route lists.**
- With every bound request going through the gate, a host route that no org API key can reach and that is not in `USER_TOKEN_BEYOND_API_KEY_ROUTES` gets `policy.signedInPersonOnly = true` (`user-token-policy.ts:655`). It is then refused `user_token_non_delegable` unless W2 waives it.
- W2 waives only `GET /v1/me/remote-control/catalog` and `ALLOWED_SUBTREES`. These host-list routes are session-only too (they appear in neither `API_KEY_ALLOWED_ROUTES` nor BEYOND):
  - `POST /v1/machines/:p/presence-challenge` (`plugins/auth.ts:3585`)
  - `POST /v1/machines/:p/browser-setup` (no API-key entry)
  - `GET /v1/orgs/:p/machines/remote-sessions` (`:3226`)
  - `.../remote-sessions/availability` (`:3227`)
  - `.../remote-sessions/:p` (`:3228`)
  - `.../:p/stop` (`:3230`)
  - `.../:p/renew` (`:3231`)
- The design therefore breaks presence, browser consent setup, and remote-session view, stop and renew. That contradicts D6 ("tokens that hold all five behave as today") and NEG-20. The builder would then be tempted to widen W2 ad hoc.
- Fix: replace the W2 list with a list built from the code: every ALLOWED route whose `isApiKeyReachableRoute` is false and that is not BEYOND. Today that is the 9 routes above, the catalog, and the subtrees. Each one must still require `machines`; all of them except the catalog already match `MACHINES_BEARER_ROUTE`. Pin with a test: W2 equals the set of signedInPersonOnly ALLOWED routes, so a drift fails.
- Check before relying on this: `isApiKeyReachableRoute` (`plugins/auth.ts:5877`) is `apiKeyRouteResources(...) !== undefined`. I classified the routes by their presence in the lists. S0 should confirm with the real function.

**N2 (MAJOR, material: credential lifetime). The host-door session shape lets a bound session mint machine credentials that are not tied to the token. W3 removes the last check. AC-6 parity passes anyway. Confirmed.**
- D9 keeps the host door at session shape: no `userTokenId`, `userTokenOrgIds` or `userTokenExpiresAt`. `modules/machines/enroll/routes.ts:56-63` (`enrollActor`) builds the machine-token and enrollment actor from exactly those fields. For a bound session they come out null.
- `requireRecentAuth` deliberately passes a bound session on `POST /v1/me/machine-enrollments` (`lib/platform-admin.ts:194-199`).
- So an enrollment made through a desktop session is:
  - not capped at the token chain's end
  - not limited to the token's `orgIds` (the allowed-orgs filter at `enroll/routes.ts:147` reads `actor.userTokenOrgIds`)
  - not linked to the token
- The resulting machine credential outlives a token revoke, and it ignores a later `orgIds` narrowing. That contradicts D7 and the "never longer-lived than the token" invariant (`desktop-token-session.ts` header rule 2).
- The same token used by bearer gets the cap, because `enrollActor` sees `userTokenId`. So the session path launders the mint-chain ceiling.
- W3 then waives approval on that route.
- AC-6 and AC-13 compare only allow/refuse codes, so they pass while this holds. This flaw existed before the revision, but v2 now writes the host shape and W3 into the design.
- Fix: carry the token facts into every host-door credential-minting site while keeping `sessionId = claims.sid`. For example, set `userTokenId`, `userTokenOrgIds` and `userTokenExpiresAt` on host `req.auth` for the enrollment and machine-token routes only, or have `enrollActor` read a separate `req.boundUserToken`.
- Add NEG: a machine token or enrollment created through a bound session carries the token id, expires no later than the token chain, is limited to the token's `orgIds`, and is revoked or refused after the token is revoked.
- Make Q6 (W3) conditional on that fix.

**N3 (MINOR). D2 allows `createdVia` values `session` and `user_token` only.**
- The schema also allows `operator` and `pairing` (`packages/db/src/schema/user-tokens.ts:82`).
- A desktop session minted today from a `pairing` or `operator` token would be revoked on the first request after deploy. That fails closed, but it may break the live desktop if its key file came from MCP pairing.
- Name all six values in the spec with a decision for each, and have S0 check the createdVia of the token the mini uses.

**N4 (MINOR). Stale text.**
- Scope still lists "the four CRM pages and the Messages page"; D10 says about 16 sites.
- Risks bullet 1 still puts the inventory in "S1 and S3"; it is S0 now.
- Risks bullet 4 says "S1" for the orgs filter; it is S1d now.

**N5 (MINOR). The D10 404 mapping can mislabel a real not-found.**
- "A 404 from a bound session on a CRM route reads as CRM switched off". The `crm.api.enabled` gate (`Errors.notFound('Not found')`), the token org list (`'Organization not found'`) and a deleted record all return 404 with the same `not_found` code.
- A pure client helper cannot tell them apart, so a deleted contact would read as "CRM is switched off".
- Fix: on the delegated door only, the server returns a distinct code for the dark gate, for example `crm_api_disabled`. The owner is the viewer, so nothing is hidden from anyone. Alternatively, make the copy say both possibilities.

## Product questions

Q1-Q8 each have a recommended answer, and that is acceptable. Q6 must become conditional on N2. The block is on N1 and N2. Both are design defects, not product choices, and both are fixable in the spec text plus tests.

## Not examined

- Runtime behavior.
- `apiKeyRouteResources` beyond its use in the list.
- The full chat route inventory.
- The machine-token lifetime and revocation code beyond `enrollActor`.
- Whether `crm.api.enabled` is on for the live org (S0 owns that).
- No probes were run.
