p = 'user-token-desktop-session-delegation.test.ts'
s = open(p).read()
assert s.count("import { resetUserTokenLimitersForTests } from '../src/modules/user-tokens/auth-gate';") == 1
s = s.replace("import { resetUserTokenLimitersForTests } from '../src/modules/user-tokens/auth-gate';",
              "import { resetUserTokenLimitersForTests, setUserTokenRateLimitForTests } from '../src/modules/user-tokens/auth-gate';")
s += """
describe('red-team RT15561-1: the host-door waivers need the legacy host set, not just machines', () => {
  it('a token with machines but without write and tokens.create_other_keys is refused by the session what it is refused by bearer', async () => {
    for (const abilities of [['desktop_signin', 'read', 'machines'], ['desktop_signin', 'read', 'write', 'machines']]) {
      const { token, session } = await bound(abilities);
      for (const u of [`/v1/orgs/${w.org.id}/machines`, `/v1/orgs/${w.org.id}/machines/remote-sessions`, '/v1/me/remote-control/catalog']) {
        const direct = await inj('GET', u, token.headers);
        const viaSession = await inj('GET', u, session.headers);
        expect(direct.statusCode, `bearer ${u}`).toBe(403);
        expect(viaSession.statusCode, `session ${abilities.length} ${u} ${viaSession.body}`).toBe(403);
      }
    }
  });
});

describe('red-team RT15561-2: crm_api_disabled does not reveal other organizations', () => {
  it('a missing org, an org outside the token list and an org the owner is not in are plain not_found; only a reachable member org says the switch is off', async () => {
    const { token, session } = await bound(CRM_SESSION);
    await ctx.db.update(organizations).set({ entitlementOverrides: { 'crm.v2.records': true, 'crm.api.enabled': false } }).where(eq(organizations.id, w.org.id));
    const missing = await inj('GET', '/v1/orgs/00000000-0000-4000-8000-0000000000ee/crm/contacts', session.headers);
    expect(codeOf(missing)).toBe('not_found');
    const own = await inj('GET', crmUrl('/contacts'), session.headers);
    expect(codeOf(own)).toBe('crm_api_disabled');
    await ctx.db.update(userTokens).set({ orgIds: [w.other.id] }).where(eq(userTokens.id, token.id));
    const outside = await inj('GET', crmUrl('/contacts'), session.headers);
    expect(outside.statusCode).toBe(404);
    expect(codeOf(outside)).toBe('not_found');
    const stranger = await addMember(ctx, w.other.id, { role: 'member', name: 'Other' });
    await ctx.db.update(organizations).set({ entitlementOverrides: { 'crm.v2.records': true, 'crm.api.enabled': false } }).where(eq(organizations.id, w.other.id));
    await ctx.db.update(userTokens).set({ orgIds: null }).where(eq(userTokens.id, token.id));
    const { orgMembers } = await import('@bugtracker/db');
    await ctx.db.delete(orgMembers).where(and(eq(orgMembers.orgId, w.other.id), eq(orgMembers.userId, w.owner.user.id)));
    const notMember = await inj('GET', `/v1/orgs/${w.other.id}/crm/contacts`, session.headers);
    expect(codeOf(notMember), notMember.body).toBe('not_found');
    expect(stranger.user.id).toBeTruthy();
  });
});

describe('red-team RT15561-3: the token rate limit also covers refused requests', () => {
  it('requests outside both doors hit 429 after the per-token limit, not only a ledger row each', async () => {
    const { session } = await bound(CRM_SESSION);
    resetUserTokenLimitersForTests();
    setUserTokenRateLimitForTests(5);
    const codes: number[] = [];
    for (let i = 0; i < 8; i++) codes.push((await inj('GET', `/v1/orgs/${w.org.id}/crm/lifecycles`, session.headers)).statusCode);
    expect(codes.slice(0, 5).every((c) => c === 403)).toBe(true);
    expect(codes.slice(5).every((c) => c === 429), codes.join(',')).toBe(true);
    resetUserTokenLimitersForTests();
  });
});
"""
open(p, 'w').write(s)
print('ok')
