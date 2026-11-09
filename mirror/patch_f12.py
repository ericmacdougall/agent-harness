import sys
mode = sys.argv[1]


def patch(path, edits):
    s = open(path).read()
    for old, new in edits:
        assert s.count(old) == 1, (path, s.count(old), old[:90])
        s = s.replace(old, new)
    open(path, 'w').write(s)


if mode == 'mirror':
    # F1: an operator-bound session gets no host waivers
    patch('desktop-token-session.ts', [
        ("export function applyHostDoorWaivers(method: string, routeKey: string, policy: HostPolicyShape, held: ReadonlySet<string>): Array<'W1' | 'W2' | 'W3'> {",
         "export function applyHostDoorWaivers(method: string, routeKey: string, policy: HostPolicyShape, held: ReadonlySet<string>, createdVia: string): Array<'W1' | 'W2' | 'W3'> {"),
        ("  if (!HOST_WAIVER_ABILITIES.every((a) => held.has(a))) return fired;",
         "  if (!HOST_WAIVER_ABILITIES.every((a) => held.has(a))) return fired;\n  // The operator token is the non-expiring, agent-held orchestrator token: admitted as a bound token for the base reads and the\n  // delegated CRM door, but never given the machine waivers (it is refused those by bearer; RT15561 delta F1).\n  if (createdVia === 'operator') return fired;"),
    ])
    patch('bound-session.ts', [
        ("(`operator`: the orchestrator token, every ability, no expiry; a session bound to\n * it can do nothing its owner-held token cannot do by bearer)",
         "(`operator`: the orchestrator token, every ability, no expiry; bound to it a session\n * gets the base reads and the delegated CRM door but NO host waivers, so it reaches no machine route the token is refused by bearer)"),
    ])
    patch('auth-gate.ts', [
        ("applyHostDoorWaivers(req.method, bound.routeKey, policy, expandUserTokenAbilities(token.abilities));",
         "applyHostDoorWaivers(req.method, bound.routeKey, policy, expandUserTokenAbilities(token.abilities), token.createdVia);"),
        ("      machineGrantIds?: string[];\n    };", "      machineGrantIds?: string[];\n      /** A desktop poll the gate decided to leave unwritten (a same session, IP and user agent already wrote within the window); the response hook still writes it when it is not 2xx. */\n      pollQuiet?: boolean;\n    };"),
        ("""/**
 * True when this request leaves no ledger row and no last-use write: the listed zero-write observation reads (any credential)
 * and, for a bound desktop session only, its polling reads (DESKTOP_POLL_ROUTES).
 */
export function ledgerQuiet(req: FastifyRequest, routePattern: string | undefined): boolean {
  return isZeroWriteRead(req.method, routePattern) || (!!req.userTokenDoor && isDesktopPollRoute(req.method, routePattern));
}
""", """/**
 * Desktop polling is THROTTLED, not suppressed (RT15561 delta F2): a poll on DESKTOP_POLL_ROUTES stays unwritten only while the
 * same session already wrote within the window from the same address and user agent, and only when it answers 2xx. A first
 * poll, a poll from a new address or user agent (a stolen session), or a poll that fails writes the row and the last-use update.
 */
export const DESKTOP_POLL_QUIET_WINDOW_MS = 5 * 60_000;
const pollSeen = new Map<string, { ip: string; ua: string; at: number }>();
function pollQuietNow(sessionId: string, client: { ip?: string | null; userAgent?: string | null }, now: number): boolean {
  const ip = client.ip ?? '';
  const ua = client.userAgent ?? '';
  const seen = pollSeen.get(sessionId);
  if (seen && seen.ip === ip && seen.ua === ua && now - seen.at < DESKTOP_POLL_QUIET_WINDOW_MS) return true;
  pollSeen.delete(sessionId);
  pollSeen.set(sessionId, { ip, ua, at: now });
  while (pollSeen.size > FAILURE_TABLE_MAX) {
    const oldest = pollSeen.keys().next().value;
    if (oldest === undefined) break;
    pollSeen.delete(oldest);
  }
  return false;
}
"""),
        ("""  if (!ledgerQuiet(req, routePattern)) {
    req.server.trackBackgroundWork(recordUserTokenUse(""", """  const pollQuiet = !!bound && isDesktopPollRoute(req.method, routePattern) && pollQuietNow(bound.sessionId, client, now);
  if (!isZeroWriteRead(req.method, routePattern) && !pollQuiet) {
    req.server.trackBackgroundWork(recordUserTokenUse("""),
        ("req.userTokenLedger = { tokenId: token.id, userId: user.id, approvalId: sessionAction ? null : approvalId };",
         "req.userTokenLedger = { tokenId: token.id, userId: user.id, approvalId: sessionAction ? null : approvalId, ...(pollQuiet ? { pollQuiet } : {}) };"),
    ])
elif mode == 'plugin':
    patch(sys.argv[2], [
        ("    if (!ledger || ledgerQuiet(req, req.routeOptions?.url)) return payload;",
         "    if (!ledger || isZeroWriteRead(req.method, req.routeOptions?.url) || (ledger.pollQuiet && reply.statusCode >= 200 && reply.statusCode < 300)) return payload;"),
        ("doorDetail, boundRouteClassRefusal, ledgerQuiet, ", "doorDetail, boundRouteClassRefusal, "),
    ])
else:
    f = 'user-token-desktop-session-delegation.test.ts'
    s = open(f).read()
    a = s.index("describe('ledger load (goodqa#15561)")
    s = s[:a] + """describe('ledger load (goodqa#15561): a desktop left open writes about one row per window, not one per poll', () => {
  it('30 polls from one session, address and user agent write at most one row; a new user agent, a failing poll and the same read by bearer each write; a refused poll is written', async () => {
    const { token, session } = await bound(['desktop_signin', 'read', 'crm']);
    const count = async () => (await ctx.db.select().from(userTokenEvents).where(eq(userTokenEvents.tokenId, token.id))).length;
    const settle = () => new Promise((r) => setTimeout(r, 400));
    await settle();
    const rows0 = await count();
    for (let i = 0; i < 6; i++) {
      for (const u of ['/v1/me', '/v1/orgs', '/v1/notifications/unread-count', '/v1/notifications', '/v1/desktop/update-status']) {
        expect((await inj('GET', u, session.headers)).statusCode, u).toBe(200);
      }
    }
    await settle();
    expect(await count()).toBeLessThanOrEqual(rows0 + 1);
    const rows1 = await count();
    // a stolen session: same polls from a new user agent are written (and the last-use trace names it)
    expect((await inj('GET', '/v1/me', { ...session.headers, 'user-agent': 'stolen-session/1.0' })).statusCode).toBe(200);
    await settle();
    expect(await count()).toBe(rows1 + 1);
    const [row] = await ctx.db.select().from(userTokens).where(eq(userTokens.id, token.id));
    expect(row!.lastUsedUserAgent).toBe('stolen-session/1.0');
    // not quiet: the same read by bearer, and real CRM work
    await inj('GET', '/v1/me', token.headers);
    await inj('GET', crmUrl('/contacts'), { ...session.headers, 'user-agent': 'stolen-session/1.0' });
    await settle();
    expect(await count()).toBe(rows1 + 3);
    // a REFUSED poll is the trail of a stolen session: it is written
    await ctx.db.update(userTokens).set({ abilities: ['desktop_signin', 'crm'] }).where(eq(userTokens.id, token.id));
    expect((await inj('GET', '/v1/me', { ...session.headers, 'user-agent': 'stolen-session/1.0' })).statusCode).toBe(403);
    await settle();
    expect(await count()).toBe(rows1 + 4);
  });

  it('a polling read that fails in its handler is written even inside the quiet window', async () => {
    const { token, session } = await bound(FIVE_PLUS_CRM);
    const count = async () => (await ctx.db.select().from(userTokenEvents).where(eq(userTokenEvents.tokenId, token.id))).length;
    expect((await inj('GET', '/v1/me', session.headers)).statusCode).toBe(200); // opens the quiet window
    await new Promise((r) => setTimeout(r, 400));
    const before = await count();
    const missing = await inj('GET', '/v1/orgs/00000000-0000-4000-8000-0000000000ee/machines/remote-sessions/availability', session.headers);
    expect(missing.statusCode, missing.body).toBeGreaterThanOrEqual(400);
    await new Promise((r) => setTimeout(r, 400));
    expect(await count()).toBeGreaterThan(before);
  });
});

describe('RT15561 delta F1: an operator-bound session gets no host waivers', () => {
  it('the operator token is admitted for CRM and the base reads but is refused by the session what it is refused by bearer on the machine routes', async () => {
    const { token, session } = await bound(['all']);
    await ctx.db.execute(sql`update user_tokens set created_via = 'operator' where id = ${token.id}::uuid`);
    expect((await inj('GET', crmUrl('/contacts'), session.headers)).statusCode).toBe(200);
    expect((await inj('GET', '/v1/me', session.headers)).statusCode).toBe(200);
    for (const u of ['/v1/me/remote-control/catalog', `/v1/orgs/${w.org.id}/machines/remote-sessions`, `/v1/orgs/${w.org.id}/machines`]) {
      const direct = await inj('GET', u, token.headers);
      const viaSession = await inj('GET', u, session.headers);
      expect(direct.statusCode, `bearer ${u}`).toBe(403);
      expect(viaSession.statusCode, `session ${u} ${viaSession.body}`).toBe(403);
    }
    const enroll = await inj('POST', '/v1/me/machine-enrollments', session.headers, { orgIds: [w.org.id], preset: 'resting' });
    expect(enroll.statusCode, enroll.body).toBe(403);
  });
});
"""
    open(f, 'w').write(s)
print('ok')
