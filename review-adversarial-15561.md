VERDICT: BLOCK

# Adversarial review: spec-15561 (desktop token session delegation, goodqa#15561 + #15382)

Reviewer: red-team agent ac5a43d2a99a04c6d (Opus). Mode: read-only spec review against bugtracker c4054490cde8 on t2-dev (`/home/eric/repos/bt-release-smoke-c4054490cde8`, detached, not modified). Spec: `.../agent-a6d28999ce9ba1787/spec-15561.md`.
Probes: none were run. Nothing was runnable (no product code exists) and no install or test run was allowed. Every finding below comes from reading the code. "Confirmed" means the code at c4054490cde8 shows it. "Hypothesis" means a check is still needed.

The direction is right: one gate, default-deny delegated table, fresh row per request, and handler RBAC kept. It blocks for these reasons. The extraction boundary leaves out the user-token kill switch (B1). The host door stays a second, weaker gate that D6 makes reachable with much weaker tokens (B2, M1). And AC-12 and the CRM outcome rest on two facts the Findings do not mention: `crm.api.enabled`, and session-only CRM routes (M2).

## BLOCKER

**B1. The delegated door skips the platform user-token kill switch (`userTokens.enabled`). Confirmed.**
- D1 extracts "the part of `authenticateUserTokenRequest` that starts after `authenticateUserTokenCredential`". The kill switch lives inside the credential step: `modules/user-tokens/auth-gate.ts:263` throws `401 User tokens are disabled`. The OAuth-disabled check (`:255`) and the oauth `orgIds` narrowing (`:256-262`) are also there.
- D2's per-request load lists only owner, id, fingerprint, chain and end. Today's bound-session check (`lib/desktop-token-session.ts` `desktopBindingState`, `plugins/auth.ts:6721-6729`) does not read `userTokens.enabled` either.
- Result: during an incident, a platform operator turns user tokens off. Every bearer token stops. Every desktop session bound to a token keeps CRM read/write and Messages send through the new delegated door.
- Reproducer: mint a session from a `read+write+crm+desktop_signin` token, set platform setting `userTokens.enabled=false`, then `GET /v1/orgs/:o/crm/contacts` with the session cookie. Under the spec as written this returns 200. A bearer call returns 401.
- Fix: D2 must also run the switch check, preferably by moving it into a shared `assertUserTokenUsable(token)` that both paths call. Add NEG: kill switch off gives 401 on the delegated door and on the host door. Also add NEG: a token with `createdVia` `oauth` or `commander_turn` can never be the bound token. The extracted function's commander-grant and continuation branches (`auth-gate.ts:276-298`) must assert this for `via='desktop_session'`.

**B2. The host door stays a second gate, and D6 opens it to weak tokens. The session gets more than the token on at least one route. Confirmed.**
- D6 drops `machines`, `write` and `tokens.create_other_keys` from mint and liveness. It then says "each host route requires the abilities `userTokenRoutePolicy` computes". That means abilities only. It does not apply `signedInPersonOnly`, `approvalReason`, the org list, org pause or the ledger.
- Concrete route: `GET /v1/me/remote-control/catalog` is on the host allow-list (`desktop-token-session.ts` ALLOWED). It is `SESSION_ONLY_ROUTES` (`plugins/auth.ts:3051`; `product-expert/route-requires.ts:143` `sessionOnly: true`). Its path does not match `MACHINES_BEARER_ROUTE` (`user-token-policy.ts:30-31`), so the policy computes only `read`.
- After D6, a `desktop_signin+read` token gets a session that reads a route the same bearer token is refused with `user_token_non_delegable`. Today the five-ability requirement hides this gap.
- Approval bypass on the host door (exists today, and the spec makes it permanent while claiming "never more than the token"): `POST /v1/me/machine-enrollments` has `approval: 'tokens.create_other_keys'` (`user-token-policy.ts:359-365`). A bearer token with Ask me first gets 409. The bound session enrolls a machine, which mints a machine credential, with no approval.
- D7 also needs the host door to call `setUserTokenScope`, which only the gate does today (`auth-gate.ts:478`). Without it, `GET /v1/orgs` (`orgs/routes.ts:401`), `/v1/me` (`access.ts:1105`) and notifications (`notifications/routes.ts:84,94`) are unscoped. So AC-5 and NEG-7 cannot pass without a third partial copy of the gate.
- Fix: run every bound request, host and delegated, through `applyUserTokenRoutePolicy` with an explicit, enumerated host-door waiver set (the `machines` rule, and `signedInPersonOnly` only for named host routes that also require `machines`). Approval, the org list, pause, scope and the ledger then apply to both doors. Alternatively, keep `machines` required for every host-door route except `GET /v1/me`, `GET /v1/orgs` and the notifications GETs.
- Pin it with a test: for each host route and a token without `machines`, the bound answer equals the bearer answer apart from the listed waivers. Add NEG: an Ask-me-first token's session gets 409 on machine enrollment, or the spec records a sourced decision that the host door does not ask.

## MAJOR

**M1. D9's `req.auth` shape conflicts with host-door handlers. The spec does not say which shape each door gets. Confirmed.**
- D9 changes `sessionId` to the `usertoken:` form for delegated requests. Host-door handlers bind to the real session id:
  - The presence proof in `modules/machines/agent-browser.ts:310` (`presenceProven(..., { sessionId: auth.sessionId })`).
  - `auditBoundConsent` (`desktop-token-session.ts`), which runs `select login_method from sessions where id = ${sid}::uuid`. A `usertoken:` id fails the cast, the `.catch` swallows the error, and the audit row is silently lost.
- If the B2 fix sends host requests through the gate, the gate's `req.auth` assignment (`auth-gate.ts:571-586`) would break presence proofs and consent audit. It would also flip `isAgentCredential` (`lib/credential-kind.ts:32`) on host routes, and `/v1/me` would switch to the `credential` response shape (`auth/routes.ts:416`).
- Fix: the spec must state per door: host keeps `sessionId=claims.sid` and gains only the scope and ledger; delegated uses the token shape. Add a test that a presence proof minted for session A does not validate for session B of the same token.
- Also state that the `x-goodqa-recovery-actor` check (`plugins/auth.ts:6733-6736`) still runs on the delegated path, which returns before it.

**M2. The CRM outcome and AC-12 rest on facts the Findings omit. Confirmed.**
- (a) Through any token, CRM is dark per org unless entitlement `crm.api.enabled` is on (default off). See `plugins/auth.ts:1034-1037` and the token switch at `:6235`, which returns 404. D1 now applies this switch to the session. If the org behind saved view 757da781 has it off, the desktop CRM returns 404. The page then renders "not found", which D10 does not handle.
- (b) Many CRM routes are `SESSION_ONLY_ROUTES`, so every token gets `user_token_non_delegable`. Examples: contact detail `GET /v1/orgs/:p/crm/contacts/:p` (`:4640`), timeline (`:4643`), meetings, export, import, AI briefing and suggestions, call and SMS (`:3383-3400`), and `DELETE /v1/orgs/:p/crm/contacts/:p` (`:3485`). Clicking any person in the desktop CRM will fail.
- (c) AC-7's example "a CRM DELETE needs `data.delete` + approval" is wrong for contacts: that DELETE is session-only, so a test against it gets 403 `user_token_non_delegable`, not 409. Use a token-reachable DELETE such as `DELETE /v1/orgs/:p/crm/segments/:p` (`:1127`).
- (d) The CRM page also calls non-CRM routes the v1 table refuses: `useOrgEntitlements` (`/v1/orgs/:p/entitlements`), `useOrgMembers` (`/v1/orgs/:p/members`), and `page-content.tsx:175,185,250`. A refused entitlements read happens to leave `useCrmGated` false (`crm-plan-gate.tsx:40-43`), but member filters break.
- Fix: add these facts to F3. State whether `crm.api.enabled` is on for the live org, with evidence. Make the route inventory a spec input now (not a post-S1 risk). Add a product question: is contact detail in or out of v1? Add NEG cases for the 404 dark state and the session-only detail state, each with honest UI copy.

**M3. The Messages surface has no live acceptance, and the v1 table does not cover what the Messages UI calls. Confirmed.**
- The ticket title says CRM *and* Messages. AC-12 proves only CRM.
- The Messages UI also calls routes outside D4:
  - `/v1/uploads/:id/content` (attachments)
  - `/v1/ai-threads/**`, `/v1/orgs/:p/agent-chat/**`, `/v1/orgs/:p/assistant`
  - `/v1/me/notes-to-self/**`, `/v1/orgs/:p/personas/:p/dm`
  - `/v1/vault/secrets`, `/v1/secret-requests/:p/fulfil` (secret composer)
- Several `/v1/chat/**` routes are session-only: mentionable-members (`:3866`), add-candidates, conversation PATCH, archive and unarchive (`:3668-3670`).
- A partly broken Messages page would pass every AC.
- Fix: add a live Messages AC that lists the routes in and out of v1. Record a deliberate decision on secrets and vault: keep them out, and add a NEG case.

**M4. D4 delegates "write methods under `/v1/notifications/**`". That is broader than Messages. Confirmed.**
- The subtree includes `PATCH /v1/notifications/dnd`, `/notifications/preferences` and `/notifications/unsubscribe` (`notifications/routes.ts:245,270,532`).
- A stolen desktop session could silence the owner's alerts, possibly including token-approval and security notices, to hide its own use.
- The session is still within the token's `write`, so the invariant holds. Least privilege does not.
- Fix: list exact routes (`POST /notifications/read`, `read-all`, `:id/archive`, `:id/unarchive`). Add NEG: preferences, dnd and unsubscribe stay `desktop_token_session_scope`.

**M5. Q2's alternative is not actually available, so D6 is load-bearing. Confirmed.**
- `UserTokensManager.tsx:225-227` hides the `machines` checkbox until its UI is approved. So "keep all five and have the preset tick them" adds an unapproved product control, or forces users onto `all`.
- Say this in Q2. If main says no to D6, the only user-mint path is "Everything", which is far more privileged than a CRM preset.

**M6. Preset naming understates the power of the credential. Confirmed.**
- Mint requires `orgIds === null` (`user-tokens/routes.ts:165`), so a "Desktop app: view and edit CRM" token holds `write` in every org. Through bearer it can also:
  - do every plain-write route (issues, projects, comments, chat)
  - read and write outreach (`crm` covers outreach, `user-token-policy.ts:291`)
- #15158 designed the token file to be handed to an agent. D11b's copy note is not enough for a preset named for CRM.
- Fix: preset labels and descriptions must say "also lets anything holding this token write across all your organizations" and keep Ask me first on. Add an AC that the preset keeps `requireHumanApproval=true`.

## MINOR

- **m1.** D10 and F2 cover "the four CRM pages". `isForbiddenError` is used by about 12 more CRM consumers (deals, deals/[dealId], companies, companies/[companyId], follow-ups, graph, `contact-attribute-rail.tsx`, `customers-affected-panel.tsx`). Put the code-specific copy in the shared helper so every consumer gets it. `human_approval_required` is a 409, not a 403, so the helper "next to `isForbiddenError`" must handle it too. AC-10 has no 409 case.
- **m2.** D10's copy says "Create a token with CRM ... then sign the desktop app in again". D2 makes a PATCH that adds `crm` effective on the next request. The copy should offer editing the existing token, or the spec should say why not (for example, the agent also holds it).
- **m3.** Audit gap: D3 refuses route class first. If it runs before the token load, `desktop_token_session_scope` probes from a stolen session leave no token-ledger trail. Today the liveness check runs before scope (`plugins/auth.ts:6722-6729`). Keep that order and ledger these refusals as `refused`, with `via`.
- **m4.** AC-13 says all `user-token*.test.ts` "pass unchanged". AC-9 and S2 change `user-token-desktop-session*.test.ts` and the line-349 pin. Name the exempted files.
- **m5.** `projectIds` and `conversationScope` narrowing are not mentioned. Mint checks only `orgIds`. Add NEG: a token narrowed by `conversationScope` or `projectIds` is limited the same way on both doors. This needs the D2 row to be the full `UserTokenRow`, not the five fields D2 lists.
- **m6.** AC-1 "a saved-view read" does not name a route. The web CRM uses segments (`/v1/orgs/:p/crm/segments/:p[/preview]`). Name it.
- **m7.** Long-lived streams: the gate runs once per request. If a stream route (SSE or hijack, for example `agent-chat/delivery-stream.ts`) is ever added to the table, a revoke would not end it. Add a table rule: no stream routes without a liveness re-check. This is a hypothesis; no v1 entry is a stream as far as I checked.
- **m8.** The rate bucket (600/min, per instance) is shared between the desktop UI and any agent using the same token through bearer. A busy agent will 429 the desktop CRM. Document the 429 copy.
- **m9.** Attribution: under D9, desktop CRM edits and chat posts are labelled as the token (`setRequestActor` with `userTokenId`; `isAgentCredential`). A human typing in the desktop app will appear as "via token X". State that this is intended.

## Findings F1-F5, checked against the code

- **F1: correct.** 24 exact routes plus 3 subtrees, and the 403 code and text match `plugins/auth.ts:6727-6729`.
- **F2: correct but incomplete.** The line refs check out (`page-content.tsx:235,559-563`, `records/page.tsx:206`, `[contactId]/page.tsx:213`, `[recordId]/page.tsx:71`), but there are about 12 more consumers (m1).
- **F3: correct on the policy pattern. It omits two material facts:** the `crm.api.enabled` dark gate and the session-only CRM routes (M2). "Both refused today" is true.
- **F4: correct.** `DEFAULT_SCOPES` and `OAUTH_ABILITIES` are at `mcp-oauth/policy.ts:20-21`; the dialog defaults to `['read']` with Ask me first on. It omits that `machines` is hidden by a product rule (M5).
- **F5: (a), (c) and (d) are correct.** (b) is right in effect but names the wrong mechanism. Mint does not get the five-ability requirement from the policy line. It gets it from `createSession` calling `desktopBindingState` with a non-null fingerprint (`auth/service.ts:210-212`). Refresh uses the same check (`:677-678`). D6 must change `desktopBindingState`, which every request, refresh and mint share, and the spec should say so.

## Acceptance criteria a wrong implementation could still pass

- **AC-5 and NEG-7** pass only if the host door sets the scope. The spec does not require that as a design step (B2).
- **AC-6**'s "reachable(bound) ⊆ reachable(owner session)" is trivially true. The risky subset is reachable(bound) ⊆ reachable(bearer same token) plus named waivers. Add it (B2).
- **AC-7**'s example route cannot produce 409 (M2c).
- **AC-12** covers CRM only; Messages has no live check (M3).
- **AC-13** parity "at least 30 routes across families" should include every host-door route and be explicit about the waivers.

## Not examined

- The desktop app's code: whether ctl sign-in handles a 409 on mint, and whether the webview uses cookies or bearer.
- CSRF posture for the desktop webview.
- Every route under `/v1/chat/**` and `/v1/orgs/:p/chat/**`: I checked samples, not the full inventory.
- Whether `crm.api.enabled` is on for the live org.
- The test-DB behavior of any claim.
- `assertUserTokenStillLive` internals.
- Session-actions interplay under the delegated prefixes beyond a read of the gate.
- No probes were run.
