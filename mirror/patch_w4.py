def patch(path, edits):
    s = open(path).read()
    for old, new in edits:
        assert s.count(old) == 1, (path, s.count(old), old[:90])
        s = s.replace(old, new)
    open(path, 'w').write(s)


patch('desktop-token-session.ts', [
    ("""  crm('GET /v1/orgs/:p/entitlements', ['read']),""",
     """  // W4 (goodqa#15561 S1e-a, user answer "Yes, on by default"): contact detail and the contact timeline, for the bound session only.
  crm('GET /v1/orgs/:p/crm/contacts/:p', CRM_READ),
  crm('GET /v1/orgs/:p/crm/contacts/:p/timeline', CRM_READ),
  crm('GET /v1/orgs/:p/entitlements', ['read']),"""),
    ("""export type DesktopDoor = 'host' | 'delegated';""",
     """/**
 * W4: the two routes that are session-only for every credential (contact detail) or a session action behind the platform switch,
 * the org owner's opt-in and a `session:crm_timeline` grant (the contact timeline), and that a BOUND desktop session reads with
 * just `crm` + `read`, with no opt-in and no switch (the user's answer "Yes, on by default"). The bearer door is NOT touched: a
 * bearer call with the same token keeps today's answers. The one deliberate exception to "bound is a subset of bearer", pinned
 * by test (exact set) so a new route cannot join silently.
 */
export const DESKTOP_SESSION_ONLY_OPENED: ReadonlySet<string> = new Set([
  'GET /v1/orgs/:p/crm/contacts/:p',
  'GET /v1/orgs/:p/crm/contacts/:p/timeline',
]);
export function isSessionOnlyOpened(method: string, routeKey: string): boolean {
  return DESKTOP_SESSION_ONLY_OPENED.has(`${methodOf(method)} ${routeKey}`);
}

export type DesktopDoor = 'host' | 'delegated';"""),
])

patch('auth-gate.ts', [
    ("import { applyHostDoorWaivers, desktopExplainedSurface, isDesktopPollRoute } from '../../lib/desktop-token-session';",
     "import { applyHostDoorWaivers, desktopExplainedSurface, isDesktopPollRoute, isSessionOnlyOpened } from '../../lib/desktop-token-session';"),
    ("""  const { policy, sessionAction, disabled } = userTokenRequestRoutePolicy(req.method, routePattern, deps.isApiKeyReachableRoute(req.method, routePattern), sessionActionsOn, orgOptIn);
  if (bound) {
    // A desktop session never reaches a session action (its grant is an explicit human grant to a token, not to a screen).
    if (candidate) throw""", """  // W4 (goodqa#15561 S1e-a, user answer "Yes, on by default"): on the bound delegated door only, contact detail and the contact
  // timeline are ordinary `crm` + `read` routes: not session-only, not a session action, no org opt-in and no platform switch.
  const w4 = !!bound && bound.door === 'delegated' && isSessionOnlyOpened(req.method, bound.routeKey);
  const requestPolicy = userTokenRequestRoutePolicy(req.method, routePattern, deps.isApiKeyReachableRoute(req.method, routePattern), sessionActionsOn && !w4, w4 ? false : orgOptIn);
  const { policy } = requestPolicy;
  const sessionAction = w4 ? undefined : requestPolicy.sessionAction;
  const disabled = w4 ? false : requestPolicy.disabled;
  if (w4) {
    policy.signedInPersonOnly = false;
    policy.nonDelegable = null;
    policy.abilities = [...new Set([...policy.abilities, 'crm', 'read'])].sort();
  }
  if (bound) {
    // A desktop session never reaches a session action (its grant is an explicit human grant to a token, not to a screen).
    if (candidate && !w4) throw"""),
])
print('ok')
