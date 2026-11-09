p = 'user-token-desktop-surface-inventory.test.ts'
s = open(p).read()
old = """/** Filled from the first run (see the snapshot's `host` rows with `refused:signed_in_person`); a change is a deliberate edit. */
const W2_ROUTES: readonly string[] = [];"""
assert s.count(old) == 1
routes = [
    'GET /v1/machines/:machineId/agent-browser/consent/requests/:clientRequestId',
    'GET /v1/machines/:machineId/agent-browser/context',
    'GET /v1/me/remote-control/catalog',
    'GET /v1/orgs/:orgId/machines/remote-sessions',
    'GET /v1/orgs/:orgId/machines/remote-sessions/:sessionId',
    'GET /v1/orgs/:orgId/machines/remote-sessions/:sessionId/agent-browser/attachments/:commandId',
    'GET /v1/orgs/:orgId/machines/remote-sessions/:sessionId/browser-pairing',
    'GET /v1/orgs/:orgId/machines/remote-sessions/availability',
    'POST /v1/machines/:machineId/agent-browser/consent',
    'POST /v1/machines/:machineId/agent-browser/consent/cancel',
    'POST /v1/machines/:machineId/browser-setup',
    'POST /v1/machines/:machineId/presence-challenge',
    'POST /v1/orgs/:orgId/machines/remote-sessions/:sessionId/agent-browser/activity',
    'POST /v1/orgs/:orgId/machines/remote-sessions/:sessionId/agent-browser/next',
    'POST /v1/orgs/:orgId/machines/remote-sessions/:sessionId/agent-browser/results/:commandId',
    'POST /v1/orgs/:orgId/machines/remote-sessions/:sessionId/browser-pairing/challenge',
    'POST /v1/orgs/:orgId/machines/remote-sessions/:sessionId/browser-pairing/connected',
    'POST /v1/orgs/:orgId/machines/remote-sessions/:sessionId/browser-pairing/permit',
    'POST /v1/orgs/:orgId/machines/remote-sessions/:sessionId/renew',
    'POST /v1/orgs/:orgId/machines/remote-sessions/:sessionId/stop',
    'PUT /v1/orgs/:orgId/machines/remote-sessions/:sessionId/agent-browser/consent',
]
body = '\n'.join(f"  '{r}'," for r in routes)
new = f"""/**
 * W2 (goodqa#15561 D3): the host-door routes that are session-only for EVERY credential today (no org key reaches them), taken
 * from the router and the policy on 2026-11-09. Each is served to a bound session only with the `machines` ability. A route
 * added to the host list that is session-only fails the test above until it is classified here on purpose.
 */
const W2_ROUTES: readonly string[] = [
{body}
];"""
s = s.replace(old, new)
open(p, 'w').write(s)
print('ok')
