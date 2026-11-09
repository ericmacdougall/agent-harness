VERDICT: ACCEPT

# Delta adversarial review v3: spec-15561 (N1-N5 only)

Reviewer: red-team agent ac5a43d2a99a04c6d. I did a read-only check of the revised spec against my v2 findings. No probes were run.
Where this file is: the worktree guard blocks the work-dir path, so this file sits in my isolated worktree. The owner should copy it to `.../agent-ab3d0525e41a23326/review-adversarial-15561-v3.md`.

| v2 | Status | Evidence in the spec |
|---|---|---|
| N1 W2 too narrow (MAJOR) | RESOLVED | D3 W2 is now computed: (ALLOWED + subtrees) where `isApiKeyReachableRoute` is false and the route is not BEYOND. It names the routes I listed, and S0 confirms the set with the real function. D6 adds `machines` to every non-base host route, which covers the catalog, the one W2 route outside `MACHINES_BEARER_ROUTE`. NEG-30 pins the set against drift and checks that a token with all five abilities behaves as today. |
| N2 enrollment credential not tied to the token (MAJOR) | RESOLVED | D9: the host door keeps `sessionId=claims.sid` and passes `userTokenId`, `userTokenOrgIds` and `userTokenExpiresAt` to `enrollActor` through `req.boundUserToken` for the enrollment and machine-token routes. NEG-29 covers the token link, the cap at the chain's end, the org list, and revocation. Q6 (W3) is explicitly conditional on it. `enroll/routes.ts` is now in Scope. |
| N3 createdVia (MINOR) | RESOLVED | D2 names all six values: refuse `oauth` and `commander_turn`; refuse `operator` and `pairing` by default; S0 checks the live token; Q9 has a recommendation. |
| N4 stale text (MINOR) | RESOLVED | Scope now says every CRM and Messages consumer. Risks points at S0 and S1d. |
| N5 404 mislabel (MINOR) | RESOLVED | D10: a distinct `crm_api_disabled` code on the delegated door only. A plain `not_found` keeps the ordinary copy. |

## New BLOCKER or MAJOR

None.

## MINOR, not blocking

- No slice in the slice plan names NEG-29 or NEG-30. Add NEG-29 to S1b, where W3 and per-door `req.auth` land, and NEG-30 to S3 (route inventory). Otherwise both can be skipped without anyone noticing.
- `crm_api_disabled` should name its tests: a test that the delegated door returns it and the bearer path still returns plain 404 (bearer behavior unchanged, AC-13), plus a helper case in AC-10.

## Not examined

- Anything outside N1-N5.
- Runtime behavior.
- `apiKeyRouteResources` internals (S0 confirms the W2 set with the real function).
