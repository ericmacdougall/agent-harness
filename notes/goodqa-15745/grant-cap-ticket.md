Security follow-up from goodqa#15745 (kept out of PR 1329).

POST /v1/orgs/:org/agent-browsers/grants accepts a grant lasting up to 30 days when called with a user token holding agent_browser_grants (apps/api/src/modules/agent-browsers/routes.ts: "Grant expiry must be within 30 days"). A holder of that token, for example a prompt-injected agent, can therefore mint a long grant directly and bypass the 24 hour default of scripts/agent-browser-lease.mjs. This behaviour predates PR 1329 (shipped 2026-11-06) and is not made worse by it.

Proposal: a server-side cap on grants created through a user token, default 24 hours and maximum 7 days, with a clear error; session-created grants keep their current rules. Needs the existing user-token-browser-grants tests updated (they create 29 day grants through a token) and a security review.

Source: ticket:GoodQA goodqa#15745 ; main decision in the build session to file this follow-up.
