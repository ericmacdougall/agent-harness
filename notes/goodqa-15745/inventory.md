# #15745 inventory, gap list and design proposal (plan checkpoint)
Branch feat/agent-browser-15745 off origin/main f1360b0944c, worktree t2-dev:/home/eric/wt-goodqa-15745-agent-browser.

## What exists (read from source, probed live with the user token; no secrets printed)
A. API "Agent Browsers" (apps/api/src/modules/agent-browsers, workers/agent-browsers.ts, Dockerfile.agent-browsers, infra/do/agent-browsers deploy):
   Playwright Chromium leased per session; REST /v1/orgs/:org/agent-browsers/sessions and MCP agent_browser_open/list/status/close plus one tool per action (navigate, click, type, screenshot, credential via credentialRef). Egress proxy, origin allowlist, grants, caps 4/org and 32/fleet, 8 queued jobs/session, audit.
   Live: GET .../agent-browsers/settings -> enabled:true. GET sessions -> []. GET grants -> []. POST sessions with the USER TOKEN -> 403 forbidden "Use a granted organization agent key" (service.ts browserProject refuses userTokenId; only a granted agent key may open). Grants can be created by a user token holding ability agent_browser_grants.
   runtime.ts:58 launches chromium with headless:true, one page per lease (extra pages closed).
B. Desktop Electron agent browser (apps/desktop/src/agent-browser, machines/agent-browser.ts, MCP browser_* tools; surfaces desktop_visible, desktop_hidden, chrome_extension): runs on a user's own machine, needs machine control lease, owner grant and per-session consent. Live: GET /orgs/:o/machines with the user token -> 403 user_token_non_delegable (also #15638). /me/machines works (7 machines; Mac-2 active in 5 orgs). This lane lives on the user's Mac, so it competes for the user's screen by design.
C. Prior Codex stream goodqa-15638-browser-lending (fix/goodqa-15638-browser-lending dfa39f4f21a "owner browser freshness and diagnostics") and native-browser branches: desktop-lane lending, not a fleet browser, no cookie import.
D. Cookie / Chrome profile import: NOT PRESENT in api, desktop or tools (git grep: no Chrome Safe Storage, no cookie import path).
E. Fleet: t2-dev has Xvfb, xvfb-run, google-chrome, playwright chromium-1228. 28 GB free.

## Six properties
1 headed: MISSING in A (headless:true). B is headed but on the user's Mac.
2 parallel: PARTIAL. A allows 4/org, 32/fleet, one page per lease, isolated context per lease. Needs measured N-parallel proof.
3 rapidly usable: PARTIAL. MCP/REST exists but needs admin grant + agent key + origin list; user token refused. No measured time-to-ready.
4 off user's screen: PARTIAL. A is containerised so off-screen; B is not. A with headed+Xvfb satisfies this by construction.
5 agent-controllable: PARTIAL. navigate/click/type/read/screenshot work in A; single page, no tab management; watch-on-demand is screenshots only.
6 cookie import: MISSING.

## Gap list
G1 headed Chrome on a virtual display in the A worker (Xvfb in image, headless:false).
G2 multi-tab per lease (list/new/switch/close), keep per-lease context isolation, measured parallel proof N>=3.
G3 cookie profiles: native Mac helper -> sealed upload -> encrypted-at-rest per-user profile -> injected at lease -> revoke/delete/audit.
G4 on-demand watch: read-only screenshot/screencast the user opens deliberately (no focus theft). May ship as screenshot polling first, labelled.
G5 time-to-ready: warm worker, measure p50/p95 open-to-first-navigate.
G6 auth ergonomics: user token cannot open a lease (P0 ticket filed). Workaround: user token creates a key grant.

## Design proposal (extends A, no new system)
- Runtime: AGENT_BROWSER_HEADED=1 -> chromium.launch({headless:false}) under Xvfb per worker; each lease its own browser process and tmpfs user-data-dir; same egress proxy and allowlist.
- Cookie import (new tables agent_browser_profiles, agent_browser_profile_imports; migration):
  * Helper tools/goodqa-cookie-export (Go, darwin): native dialog picks Chrome profile and domains, triggers the Keychain "Chrome Safe Storage" prompt (the one human approval), decrypts in-process only, filters to chosen domains, seals the bundle to the server public key (sealed box), uploads ciphertext with Idempotency-Key = sha256(userId|profile|sorted domains|bundle digest). Plaintext never touches disk, stdout or logs. The helper reads the user token itself; agents only launch it.
  * Server keeps ciphertext only (AES-256-GCM envelope); clear metadata is domains, count, createdAt, expiresAt, userId, orgId. Plaintext is reachable only by the worker through the existing broker lease path at lease start, filtered to the lease origins, via context.addCookies. No API ever returns values.
  * Owner-only: usable only when session.userId == profile.userId; admins cannot read or use. Revoke deletes ciphertext and audits. Stale/expired -> visible profile_stale error, never silent anonymous browsing.
- MCP/REST: agent_browser_profiles_list/delete; agent_browser_open gains optional profileId.
- Tests: failing-first vitest on t2-dev for ACL, idempotency, retry, stale, revoke, no plaintext in responses/logs, concurrency cap, crash recovery; helper unit tests with a synthetic Chrome-format DB (never the real DB).
- Real Mac proof: user runs one command and clicks Allow in the Keychain dialog (the only human step).

## Open choices for main (recommended first)
1. Extend A rather than build on the Mac desktop lane. Rec: yes (only A gives off-screen + parallel by construction).
2. Let the user token open its own leases (G6)? Rec: keep the grant step; consider an owner-own-lease route only after a sourced decision and security review (ticket filed).
3. Live worker location (infra/do/agent-browsers). Rec: deploy there on main's direction; I will not deploy.
