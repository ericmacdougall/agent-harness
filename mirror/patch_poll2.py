import sys
mode = sys.argv[1]


def patch(path, edits):
    s = open(path).read()
    for old, new in edits:
        assert s.count(old) == 1, (path, s.count(old), old[:90])
        s = s.replace(old, new)
    open(path, 'w').write(s)


if mode == 'plugin':
    patch(sys.argv[2], [
        ("    if (!ledger || isZeroWriteRead(req.method, req.routeOptions?.url)) return payload;",
         "    if (!ledger || ledgerQuiet(req, req.routeOptions?.url)) return payload;"),
        ("doorDetail, boundRouteClassRefusal, ", "doorDetail, boundRouteClassRefusal, ledgerQuiet, "),
    ])
else:
    s = open('user-token-desktop-session-delegation.test.ts').read()
    s += """
describe('ledger load (goodqa#15561): a desktop left open does not write a row per poll', () => {
  it('polling reads of a bound session leave no ledger row and no last-use write; the same read by bearer, and real CRM work, still do', async () => {
    const { token, session } = await bound(['desktop_signin', 'read', 'crm']);
    const count = async () => (await ctx.db.select().from(userTokenEvents).where(eq(userTokenEvents.tokenId, token.id))).length;
    await new Promise((r) => setTimeout(r, 300));
    const rows0 = await count();
    const [use0] = await ctx.db.select().from(userTokens).where(eq(userTokens.id, token.id));
    for (let i = 0; i < 6; i++) {
      for (const u of ['/v1/me', '/v1/orgs', '/v1/notifications/unread-count', '/v1/notifications', '/v1/desktop/update-status']) {
        expect((await inj('GET', u, session.headers)).statusCode, u).toBe(200);
      }
    }
    await new Promise((r) => setTimeout(r, 400));
    expect(await count()).toBe(rows0);
    const [use1] = await ctx.db.select().from(userTokens).where(eq(userTokens.id, token.id));
    expect(use1!.useCount).toBe(use0!.useCount);
    // not quiet: a bearer call of the same read, and a CRM read through the session
    await inj('GET', '/v1/me', token.headers);
    await inj('GET', crmUrl('/contacts'), session.headers);
    await new Promise((r) => setTimeout(r, 400));
    expect(await count()).toBe(rows0 + 2);
  });
});
"""
    open('user-token-desktop-session-delegation.test.ts', 'w').write(s)
print('ok')
