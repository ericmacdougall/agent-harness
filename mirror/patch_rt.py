def patch(path, edits):
    s = open(path).read()
    for old, new in edits:
        assert s.count(old) == 1, (path, s.count(old), old[:90])
        s = s.replace(old, new)
    open(path, 'w').write(s)


# RT15561-1: the host-door waivers only for a token holding the legacy host set
patch('desktop-token-session.ts', [
    ("""interface HostPolicyShape {""", """/**
 * RT15561-1: the waivers below exist for the desktop app signed in with a token that holds the host set it always needed
 * (before D6 a session could not start without all three). A token holding only some of them, now able to start a session
 * (D6 needs just `desktop_signin` and `read`), gets the plain bearer policy on the host routes: no waiver, so the machines
 * non-delegable rule and the session-only rule refuse it exactly as they refuse the token by bearer.
 */
export const HOST_WAIVER_ABILITIES = ['machines', 'write', 'tokens.create_other_keys'] as const;

interface HostPolicyShape {"""),
    ("""export function applyHostDoorWaivers(method: string, routeKey: string, policy: HostPolicyShape): Array<'W1' | 'W2' | 'W3'> {
  const key = `${methodOf(method)} ${routeKey}`;
  const fired: Array<'W1' | 'W2' | 'W3'> = [];""", """export function applyHostDoorWaivers(method: string, routeKey: string, policy: HostPolicyShape, held: ReadonlySet<string>): Array<'W1' | 'W2' | 'W3'> {
  const key = `${methodOf(method)} ${routeKey}`;
  const fired: Array<'W1' | 'W2' | 'W3'> = [];
  if (!HOST_WAIVER_ABILITIES.every((a) => held.has(a))) return fired;"""),
])

patch('auth-gate.ts', [
    ("""    if (bound.door === 'host') applyHostDoorWaivers(req.method, bound.routeKey, policy);""",
     """    if (bound.door === 'host') applyHostDoorWaivers(req.method, bound.routeKey, policy, expandUserTokenAbilities(token.abilities));"""),
    ("door: 'host' | 'delegated' };\n    /**\n     * goodqa#15561 D9", "door: 'host' | 'delegated' | 'none' };\n    /**\n     * goodqa#15561 D9"),
    # RT15561-3: the shared rate check
    ("""  const rate = rateAllowed(token.id, now);
  if (!rate.ok) {
    reply.header('retry-after', String(rate.retryAfterSeconds));
    // Deliberately NOT written to the ledger: a token over its rate would otherwise turn every refused request into a
    // database write, which is the load the limit exists to shed. One log line (ids only) instead.
    req.log.warn({ userTokenId: token.id, route: routePattern }, 'user token rate limited');
    throw new AppError(429, 'user_token_rate_limited', 'This user token is sending too many requests. Slow down.', {
      retryAfterSeconds: rate.retryAfterSeconds,
    });
  }
""", """  enforceTokenRate(req, reply, token, routePattern, now);
"""),
    ("""/** The ledger detail that names a desktop-session carrier;""", """/**
 * The per-token request rate (429). Deliberately NOT written to the ledger: a token over its rate would otherwise turn every
 * refused request into a database write, which is the load the limit exists to shed. One log line (ids only) instead.
 */
function enforceTokenRate(req: FastifyRequest, reply: FastifyReply, token: UserTokenRow, routePattern: string | undefined, now: number): void {
  const rate = rateAllowed(token.id, now);
  if (rate.ok) return;
  reply.header('retry-after', String(rate.retryAfterSeconds));
  req.log.warn({ userTokenId: token.id, route: routePattern }, 'user token rate limited');
  throw new AppError(429, 'user_token_rate_limited', 'This user token is sending too many requests. Slow down.', {
    retryAfterSeconds: rate.retryAfterSeconds,
  });
}

/** The ledger detail that names a desktop-session carrier;"""),
    ("""export function boundRouteClassRefusal(req: FastifyRequest, token: UserTokenRow, routePattern: string | undefined, routeKey: string, deps: UserTokenGateDeps): AppError {
""", """export function boundRouteClassRefusal(req: FastifyRequest, reply: FastifyReply, token: UserTokenRow, routePattern: string | undefined, routeKey: string, deps: UserTokenGateDeps): AppError {
  // RT15561-3: the token's rate applies to a refused request too (the ledger write below is the load it sheds).
  enforceTokenRate(req, reply, token, routePattern, Date.now());
"""),
])

patch('patch3.py', []) if False else None
