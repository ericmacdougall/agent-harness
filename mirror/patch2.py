import sys


def patch(path, edits):
    s = open(path).read()
    for old, new in edits:
        assert s.count(old) == 1, (path, s.count(old), old[:80])
        s = s.replace(old, new)
    open(path, 'w').write(s)


patch('auth-gate.ts', [
    ("import { applyHostDoorWaivers } from '../../lib/desktop-token-session';",
     "import { applyHostDoorWaivers, desktopExplainedSurface } from '../../lib/desktop-token-session';"),
    ("canonicalBodySha256, commanderOutboundAction, missingAbilities, userTokenRouteKey } from '../../lib/user-token-policy';",
     "canonicalBodySha256, commanderOutboundAction, missingAbilities, userTokenRouteKey, userTokenRoutePolicy } from '../../lib/user-token-policy';"),
    ("""/** The ledger detail that names a desktop-session carrier;""",
     """/**
 * goodqa#15561: a bound request whose route is on neither door. On a surface the app has pages for (CRM), a route that EVERY
 * credential is refused (session-only, non-delegable, governance sign-off) is answered with the token policy's own code
 * (`user_token_non_delegable`) so the app can say "not available in a desktop session started from a token"; any other route
 * is `desktop_token_session_scope`. Either way it is ledgered as `refused`.
 */
export function boundRouteClassRefusal(req: FastifyRequest, token: UserTokenRow, routePattern: string | undefined, routeKey: string, deps: UserTokenGateDeps): AppError {
  if (routePattern && desktopExplainedSurface(routeKey)) {
    const policy = userTokenRoutePolicy(req.method, routePattern, deps.isApiKeyReachableRoute(req.method, routePattern));
    if (policy.nonDelegable) return refusal(req, token, routePattern, new AppError(403, 'user_token_non_delegable', policy.nonDelegable.reason, { rule: policy.nonDelegable.code }));
    if (deps.isGovernanceSessionOnlyRoute(req.method, routePattern)) return refusal(req, token, routePattern, new AppError(403, 'user_token_non_delegable', 'This governance action needs a signed-in person; no token can do it.', { rule: 'governance_sign_off' }));
    if (policy.signedInPersonOnly) return refusal(req, token, routePattern, new AppError(403, 'user_token_non_delegable', USER_TOKEN_SIGNED_IN_PERSON_RULE.reason, { rule: USER_TOKEN_SIGNED_IN_PERSON_RULE.code }));
  }
  return refusal(req, token, routePattern, new AppError(403, 'desktop_token_session_scope', 'This desktop session was started from a user token and can only do what the desktop app needs.'));
}

/** The ledger detail that names a desktop-session carrier;"""),
])
patch('desktop-token-session.ts', [
    ("""export type DesktopDoor = 'host' | 'delegated';""",
     """export type DesktopDoor = 'host' | 'delegated';

/** Surfaces the app has pages for: their routes outside the table are explained by the token policy's own refusal where one exists (see boundRouteClassRefusal). */
const EXPLAINED_SURFACES: readonly RegExp[] = [/^\\/v1\\/orgs\\/:p\\/crm(\\/|$)/];
export function desktopExplainedSurface(routeKey: string): boolean { return EXPLAINED_SURFACES.some((re) => re.test(routeKey)); }"""),
])
