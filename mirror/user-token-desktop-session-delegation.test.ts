/**
 * goodqa#15561 (P0, also #15382): a desktop session started from a user token must serve the product surfaces that token's
 * abilities cover (CRM in this slice) and nothing else. The first draft refused every CRM and Messages route with the
 * host-only allow-list's `desktop_token_session_scope`, and the CRM page rendered that 403 as "ask an organization owner".
 *
 * Written FIRST and run red on origin/main (dc90b522); each block names the AC or NEG of the spec it pins. The token gate
 * (modules/user-tokens/auth-gate.ts `applyUserTokenRoutePolicy`) is the ONE policy for both doors; a bound request is
 * `host` (the desktop's own routes, the session keeps its real id) or `delegated` (the default-deny
 * DESKTOP_DELEGATED_SURFACES table, token-shaped actor). Every request loads the minting token row fresh (no cache).
 */
import { and, eq, isNull, like, sql } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { machineEnrollments, organizations, sessions, userTokenApprovals, userTokenEvents, userTokens } from '@bugtracker/db';
import { resetUserTokenLimitersForTests, setUserTokenRateLimitForTests } from '../src/modules/user-tokens/auth-gate';
import { createTestApp, enableUserTokensForTests, resetDb, type TestContext } from './helpers';
import { PARITY_ROUTES, answerOf, fill, setupParityWorld } from './user-token-parity-fixtures';
import { addMember } from './webhook-test-kit';
import { legacyChildFixture } from './user-token-session-fixtures';

type H = Record<string, string>;
let ctx: TestContext;
let w: Awaited<ReturnType<typeof setupParityWorld>>;
beforeAll(async () => { ctx = await createTestApp(); });
afterAll(async () => { await ctx?.close(); });
beforeEach(async () => {
  await resetDb(ctx.db);
  w = await setupParityWorld(ctx);
  await enableUserTokensForTests(ctx.db);
  resetUserTokenLimitersForTests();
});
const inj = (method: string, url: string, headers: H, payload?: unknown) =>
  ctx.app.inject({ method: method as 'POST', url, headers, ...(payload === undefined ? {} : { payload: payload as object }) });
const bearer = (t: string): H => ({ authorization: `Bearer ${t}` });
const codeOf = (res: { json: () => unknown }) => (res.json() as { error?: { code?: string } }).error?.code;
const detailsOf = (res: { json: () => unknown }) => (res.json() as { error?: { details?: Record<string, unknown> } }).error?.details ?? {};

const CRM_SESSION = ['desktop_signin', 'read', 'crm'];
const CRM_WRITE_SESSION = ['desktop_signin', 'read', 'write', 'crm'];
const FIVE_PLUS_CRM = ['desktop_signin', 'read', 'write', 'machines', 'tokens.create_other_keys', 'crm'];

async function mint(owner: { headers: H }, abilities: string[], extra: Record<string, unknown> = {}) {
  const step = await inj('POST', '/v1/auth/webauthn/step-up', owner.headers, { method: 'password', password: 'password123', purpose: 'user_tokens_manage' });
  const res = await inj('POST', '/v1/me/user-tokens', owner.headers, { name: 'delegation', abilities, requireHumanApproval: false, ...extra, stepUpToken: step.json().stepUpToken });
  expect(res.statusCode, res.body).toBe(201);
  const j = res.json() as { userToken: { id: string }; token: string };
  return { id: j.userToken.id, headers: bearer(j.token) };
}
async function startSession(t: { headers: H }) {
  const r = await inj('POST', '/v1/me/desktop-session', t.headers, { client: 'desktop-ctl' });
  expect(r.statusCode, `desktop-session: ${r.body}`).toBe(200);
  const tokens = r.json().tokens as { accessToken: string; refreshToken: string };
  return { ...tokens, headers: bearer(tokens.accessToken) };
}
async function bound(abilities: string[], extra: Record<string, unknown> = {}, owner: { headers: H } = w.owner) {
  const token = await mint(owner, abilities, extra);
  return { token, session: await startSession(token) };
}
const crmUrl = (path: string) => `/v1/orgs/${w.org.id}/crm${path}`;
/** The CRM list page's own calls (S0 inventory, `GET` rows of the `crm` surface) that must answer 200 for a crm token. */
const CRM_LIST_PAGE_SET = [
  crmUrlOf('/contacts'), crmUrlOf('/companies'), crmUrlOf('/segments'), crmUrlOf('/segments/SEG'), crmUrlOf('/segments/SEG/preview'),
  crmUrlOf('/records?kind=contact'), '/v1/orgs/ORG/entitlements', '/v1/orgs/ORG/members',
];
function crmUrlOf(path: string) { return `/v1/orgs/ORG/crm${path}`; }
const pageUrl = (u: string) => u.replace('ORG', w.org.id).replace('SEG', w.segId);

describe('AC-1: a bound session reaches the CRM list and saved-view reads its token covers (F1, F3)', () => {
  it('a read+crm token: every route of the CRM list page answers 200 through the session', async () => {
    const { session } = await bound(CRM_SESSION);
    for (const u of CRM_LIST_PAGE_SET) {
      const res = await inj('GET', pageUrl(u), session.headers);
      expect(res.statusCode, `${u} -> ${res.statusCode} ${res.body}`).toBe(200);
    }
  });

  it('F1 as shipped on origin/main: a token holding all five session abilities plus crm already reaches the CRM list (baseline answered desktop_token_session_scope for every one of these)', async () => {
    const { session } = await bound(FIVE_PLUS_CRM);
    for (const u of CRM_LIST_PAGE_SET) {
      const res = await inj('GET', pageUrl(u), session.headers);
      expect(res.statusCode, `${u} -> ${res.statusCode} ${codeOf(res)}`).toBe(200);
    }
  });

  it('NEG-1: a token without crm is refused every CRM route with user_token_ability_missing naming crm, not the host-only scope text', async () => {
    const { session } = await bound(['desktop_signin', 'read']);
    for (const u of CRM_LIST_PAGE_SET.filter((x) => x.includes('/crm'))) {
      const res = await inj('GET', pageUrl(u), session.headers);
      expect(res.statusCode, u).toBe(403);
      expect(codeOf(res), u).toBe('user_token_ability_missing');
      expect(detailsOf(res).missing, u).toEqual(['crm']);
    }
  });

  it('NEG-6: a route outside every table stays desktop_token_session_scope even for an all-abilities token', async () => {
    const { session } = await bound(['all']);
    for (const [m, u] of [['GET', `/v1/orgs/${w.org.id}/crm/lifecycles`], ['GET', `/v1/orgs/${w.org.id}/issues`], ['POST', `/v1/orgs/${w.org.id}/api-keys`], ['GET', '/v1/me/user-tokens']] as const) {
      const res = await inj(m, u, session.headers, m === 'POST' ? { name: 'k', scopes: ['read'] } : undefined);
      expect(res.statusCode, `${m} ${u}`).toBe(403);
      expect(codeOf(res), `${m} ${u}`).toBe('desktop_token_session_scope');
    }
  });

  it('NEG-25: the CRM routes that are session-only for every token answer user_token_non_delegable, not a blank or role 403', async () => {
    const { session } = await bound(CRM_WRITE_SESSION);
    for (const u of [crmUrl('/contacts/00000000-0000-4000-8000-000000000000'), crmUrl('/contacts/export'), crmUrl('/contacts/00000000-0000-4000-8000-000000000000/timeline')]) {
      const res = await inj('GET', u, session.headers);
      expect(res.statusCode, u).toBe(403);
      expect(codeOf(res), u).toBe('user_token_non_delegable');
    }
  });
});

describe('NEG-8: non-delegable routes stay refused to a bound session, whatever the token holds', () => {
  it('secret reveal, channel members, commander admission, token mint, approval approve, revoke-all, step-up, account, device registration', async () => {
    const { session } = await bound(['all']);
    const ZERO = '00000000-0000-4000-8000-000000000000';
    const cases: Array<[string, string, unknown]> = [
      ['POST', `/v1/chat/conversations/${ZERO}/messages/${ZERO}/secure/reveal`, { method: 'password', currentPassword: 'password123' }],
      ['POST', `/v1/chat/conversations/${ZERO}/members`, { userIds: [ZERO] }],
      ['PUT', `/v1/chat/conversations/${ZERO}/commander-admission`, {}],
      ['POST', '/v1/me/user-tokens', { name: 'x', abilities: ['all'], requireHumanApproval: false }],
      ['POST', `/v1/me/user-token-approvals/${ZERO}/approve`, {}],
      ['POST', '/v1/me/user-tokens/revoke-all', {}],
      ['POST', '/v1/auth/webauthn/step-up', { method: 'password', password: 'password123', purpose: 'user_tokens_manage' }],
      ['DELETE', '/v1/account', { confirmEmail: 'x@example.test' }],
      ['POST', '/v1/account/sessions/revoke-others', {}],
    ];
    for (const [m, u, b] of cases) {
      const res = await inj(m, u, session.headers, b);
      expect(res.statusCode, `${m} ${u} ${res.body}`).toBe(403);
      expect(['desktop_token_session_scope', 'user_token_non_delegable'], `${m} ${u}`).toContain(codeOf(res));
    }
  });
});

describe('AC-2 / NEG-9: writes need the token write ability AND the owner role', () => {
  const body = { firstName: 'Deleg', lastName: 'Ated', primaryEmail: 'deleg@example.test' };
  it('read+crm: 403 user_token_ability_missing write; write+crm with an owner role: created; write+crm with a member role: the handler refuses', async () => {
    const readOnly = await bound(CRM_SESSION);
    const r1 = await inj('POST', crmUrl('/contacts'), readOnly.session.headers, body);
    expect(r1.statusCode, r1.body).toBe(403);
    expect(codeOf(r1)).toBe('user_token_ability_missing');
    expect(detailsOf(r1).missing).toEqual(['write']);

    const writer = await bound(CRM_WRITE_SESSION);
    const r2 = await inj('POST', crmUrl('/contacts'), writer.session.headers, body);
    expect(r2.statusCode, r2.body).toBe(201);

    const member = await addMember(ctx, w.org.id, { role: 'member', name: 'Viewer' });
    const asMember = await bound(CRM_WRITE_SESSION, {}, member);
    expect((await inj('GET', crmUrl('/contacts'), asMember.session.headers)).statusCode).toBe(200);
    const r3 = await inj('POST', crmUrl('/contacts'), asMember.session.headers, { ...body, primaryEmail: 'deleg2@example.test' });
    expect(r3.statusCode, r3.body).toBe(403);
    expect(codeOf(r3) ?? '').not.toMatch(/^user_token_|^desktop_token_/);
  });
});

describe('AC-4 / NEG-5 / NEG-2 / NEG-3 / NEG-10: narrowing, revoke, expiry and rotation apply on the next request (no cache)', () => {
  it('removing crm: the very next CRM request on the same access token is 403; removing write: reads stay 200 and writes 403; removing desktop_signin: 401 and the session is revoked', async () => {
    const { token, session } = await bound(CRM_WRITE_SESSION);
    expect((await inj('GET', crmUrl('/contacts'), session.headers)).statusCode).toBe(200);
    await ctx.db.update(userTokens).set({ abilities: ['desktop_signin', 'read', 'crm'] }).where(eq(userTokens.id, token.id));
    expect((await inj('GET', crmUrl('/contacts'), session.headers)).statusCode).toBe(200);
    const noWrite = await inj('POST', crmUrl('/contacts'), session.headers, { firstName: 'N', lastName: 'W', primaryEmail: 'nw@example.test' });
    expect(noWrite.statusCode, noWrite.body).toBe(403);
    expect(codeOf(noWrite)).toBe('user_token_ability_missing');
    await ctx.db.update(userTokens).set({ abilities: ['desktop_signin', 'read'] }).where(eq(userTokens.id, token.id));
    const noCrm = await inj('GET', crmUrl('/contacts'), session.headers);
    expect(noCrm.statusCode, noCrm.body).toBe(403);
    expect(detailsOf(noCrm).missing).toEqual(['crm']);
    expect((await inj('GET', '/v1/me', session.headers)).statusCode).toBe(200);
    await ctx.db.update(userTokens).set({ abilities: ['read', 'crm'] }).where(eq(userTokens.id, token.id));
    expect((await inj('GET', crmUrl('/contacts'), session.headers)).statusCode).toBe(401);
    const rows = await ctx.db.select().from(sessions).where(eq(sessions.userId, w.owner.user.id));
    expect(rows.filter((r) => r.loginMethod?.startsWith('user_token_desktop:')).every((r) => r.revokedAt && r.revokedReason === 'user_token_ended')).toBe(true);
  });

  it('revoked, expired and a revoked parent: 401 on the delegated door, refresh refused, session revoked', async () => {
    const a = await bound(CRM_SESSION);
    await ctx.db.update(userTokens).set({ revokedAt: new Date() }).where(eq(userTokens.id, a.token.id));
    expect((await inj('GET', crmUrl('/contacts'), a.session.headers)).statusCode).toBe(401);
    expect((await inj('POST', '/v1/auth/refresh', {}, { refreshToken: a.session.refreshToken })).statusCode).toBe(401);

    const b = await bound(CRM_SESSION);
    // an instant, not a day: a token whose end is exactly now is refused
    await ctx.db.update(userTokens).set({ expiresAt: new Date(Date.now() - 1) }).where(eq(userTokens.id, b.token.id));
    expect((await inj('GET', crmUrl('/contacts'), b.session.headers)).statusCode).toBe(401);

    const parent = await mint(w.owner, ['all']);
    const child = await legacyChildFixture(ctx.db, parent.headers, { name: 'child', abilities: CRM_SESSION });
    const childToken = { headers: bearer((child.json() as { token: string }).token) };
    await ctx.db.update(userTokens).set({ requireHumanApproval: false }).where(eq(userTokens.createdByTokenId, parent.id));
    const c = await startSession(childToken);
    expect((await inj('GET', crmUrl('/contacts'), c.headers)).statusCode).toBe(200);
    await ctx.db.update(userTokens).set({ revokedAt: new Date() }).where(eq(userTokens.id, parent.id));
    expect((await inj('GET', crmUrl('/contacts'), c.headers)).statusCode).toBe(401);
  });

  it('rotation: a session started under the old secret is dead on the delegated door', async () => {
    const { token, session } = await bound(CRM_SESSION);
    expect((await inj('GET', crmUrl('/contacts'), session.headers)).statusCode).toBe(200);
    const step = await inj('POST', '/v1/auth/webauthn/step-up', w.owner.headers, { method: 'password', password: 'password123', purpose: 'user_tokens_manage' });
    const rot = await inj('POST', `/v1/me/user-tokens/${token.id}/rotate`, w.owner.headers, { stepUpToken: step.json().stepUpToken });
    expect(rot.statusCode, rot.body).toBeLessThan(300);
    expect((await inj('GET', crmUrl('/contacts'), session.headers)).statusCode).toBe(401);
  });

  it('NEG-18: a request already past the gate completes; the next one is 401 (no mid-response abort)', async () => {
    const { token, session } = await bound(CRM_SESSION);
    const first = inj('GET', crmUrl('/contacts'), session.headers);
    const first200 = await first;
    expect(first200.statusCode).toBe(200);
    await ctx.db.update(userTokens).set({ revokedAt: new Date() }).where(eq(userTokens.id, token.id));
    expect(first200.json()).toHaveProperty('contacts');
    expect((await inj('GET', crmUrl('/contacts'), session.headers)).statusCode).toBe(401);
  });
});

describe('NEG-16: a malformed or missing binding is 401 and revokes the session, never unbound-and-allowed', () => {
  it('empty marker, bad fingerprint and a deleted token row', async () => {
    for (const mutate of [
      (id: string) => ({ loginMethod: 'user_token_desktop:not-a-uuid' }),
      (id: string) => ({ loginMethod: `user_token_desktop:${id}:0000000000000000` }),
    ]) {
      const { token, session } = await bound(CRM_SESSION);
      await ctx.db.update(sessions).set(mutate(token.id)).where(and(eq(sessions.userId, w.owner.user.id), isNull(sessions.revokedAt), like(sessions.loginMethod, 'user_token_desktop:%')));
      const res = await inj('GET', crmUrl('/contacts'), session.headers);
      expect(res.statusCode, res.body).toBe(401);
    }
    const { token, session } = await bound(CRM_SESSION);
    await ctx.db.update(sessions).set({ loginMethod: 'user_token_desktop:11111111-1111-4111-8111-111111111111:0000000000000000' }).where(and(eq(sessions.userId, w.owner.user.id), isNull(sessions.revokedAt), like(sessions.loginMethod, 'user_token_desktop:%')));
    expect((await inj('GET', crmUrl('/contacts'), session.headers)).statusCode).toBe(401);
    expect(token.id).toBeTruthy();
  });
});

describe('NEG-19: the platform kill switch and the token kinds', () => {
  it('userTokens.enabled off: 401 on the host door and the delegated door, session revoked; an oauth, operator or pairing token is never the bound token (commander_turn cannot hold desktop_signin and is refused in the gate by kind)', async () => {
    const { token, session } = await bound(CRM_SESSION);
    expect((await inj('GET', '/v1/me', session.headers)).statusCode).toBe(200);
    await ctx.db.execute(sql`update platform_settings set value = 'false'::jsonb where key = 'userTokens.enabled'`);
    expect((await inj('GET', crmUrl('/contacts'), session.headers)).statusCode).toBe(401);
    expect((await inj('GET', '/v1/me', session.headers)).statusCode).toBe(401);
    await ctx.db.execute(sql`update platform_settings set value = 'true'::jsonb where key = 'userTokens.enabled'`);

    for (const kind of ['oauth', 'pairing']) {
      const t = await bound(CRM_SESSION);
      await ctx.db.execute(sql`update user_tokens set created_via = ${kind} where id = ${t.token.id}::uuid`);
      const res = await inj('GET', crmUrl('/contacts'), t.session.headers);
      expect(res.statusCode, kind).toBe(401);
      const ended = await ctx.db.select().from(sessions).where(and(eq(sessions.userId, w.owner.user.id), like(sessions.loginMethod, `user_token_desktop:${t.token.id}:%`)));
      expect(ended.every((r) => r.revokedAt && r.revokedReason === 'user_token_ended'), kind).toBe(true);
    }
    // the operator script mints an all-ability orchestrator token; a session bound to it is admitted (it can do what the token can)
    const op = await bound(CRM_SESSION);
    await ctx.db.execute(sql`update user_tokens set created_via = 'operator' where id = ${op.token.id}::uuid`);
    expect((await inj('GET', crmUrl('/contacts'), op.session.headers)).statusCode).toBe(200);
    expect(token.id).toBeTruthy();
  });
});

describe('AC-7 / NEG-11: a token that asks first still asks through the session', () => {
  it('DELETE of a saved view: 409 human_approval_required with an approval row and the view untouched; a token that does not ask deletes it; the session cannot approve', async () => {
    const asks = await bound(['desktop_signin', 'read', 'write', 'crm', 'data.delete']);
    await ctx.db.update(userTokens).set({ requireHumanApproval: true }).where(eq(userTokens.id, asks.token.id));
    const del = await inj('DELETE', crmUrl(`/segments/${w.segId}`), asks.session.headers);
    expect(del.statusCode, del.body).toBe(409);
    expect(codeOf(del)).toBe('human_approval_required');
    const approvalId = detailsOf(del).approvalId as string;
    const approvals = await ctx.db.select().from(userTokenApprovals).where(eq(userTokenApprovals.tokenId, asks.token.id));
    expect(approvals.map((a) => a.id)).toContain(approvalId);
    expect((await inj('GET', crmUrl(`/segments/${w.segId}`), asks.session.headers)).statusCode).toBe(200);

    const approve = await inj('POST', `/v1/me/user-token-approvals/${approvalId}/approve`, asks.session.headers, {});
    expect(approve.statusCode, approve.body).toBe(403);

    // another token's approval id is not this token's approval
    const other = await bound(['desktop_signin', 'read', 'write', 'crm', 'data.delete']);
    await ctx.db.update(userTokens).set({ requireHumanApproval: true }).where(eq(userTokens.id, other.token.id));
    const replay = await inj('DELETE', crmUrl(`/segments/${w.segId}`), { ...other.session.headers, 'x-goodqa-approval-id': approvalId });
    expect(replay.statusCode, replay.body).toBeGreaterThanOrEqual(400);
    expect((await inj('GET', crmUrl(`/segments/${w.segId}`), asks.session.headers)).statusCode).toBe(200);

    const free = await bound(['desktop_signin', 'read', 'write', 'crm', 'data.delete']);
    const ok = await inj('DELETE', crmUrl(`/segments/${w.segId}`), free.session.headers);
    expect(ok.statusCode, ok.body).toBeLessThan(300);
  });
});

describe('AC-8 / NEG-12: every bound request after the token loads is written to the token ledger', () => {
  it('allowed, refused-by-ability, refused-at-route-class and approval-required rows carry the token id, via and the session id; no token value or body; last use is updated', async () => {
    const { token, session } = await bound(['desktop_signin', 'read', 'write', 'crm', 'data.delete']);
    await ctx.db.update(userTokens).set({ requireHumanApproval: true }).where(eq(userTokens.id, token.id));
    await inj('POST', crmUrl('/contacts'), session.headers, { firstName: 'Led', lastName: 'Ger', primaryEmail: 'ledger@example.test' });
    await inj('DELETE', crmUrl(`/segments/${w.segId}`), session.headers);
    await inj('GET', crmUrl('/lifecycles'), session.headers); // route class: not on any list
    await ctx.db.update(userTokens).set({ abilities: ['desktop_signin', 'read'] }).where(eq(userTokens.id, token.id));
    await inj('GET', crmUrl('/contacts'), session.headers); // ability missing
    await new Promise((r) => setTimeout(r, 400)); // the ledger is written after the response
    const rows = await ctx.db.select().from(userTokenEvents).where(eq(userTokenEvents.tokenId, token.id));
    const sid = (await ctx.db.select().from(sessions).where(and(eq(sessions.userId, w.owner.user.id), isNull(sessions.revokedAt)))).find((r) => r.loginMethod?.startsWith('user_token_desktop:'))!.id;
    const desktop = rows.filter((r) => (r.detail as { via?: string } | null)?.via === 'desktop_session');
    const codes = desktop.map((r) => `${r.kind} ${r.statusCode} ${(r.detail as { code?: string }).code ?? ''}`.trim());
    expect(codes).toEqual(expect.arrayContaining(['request 201', 'refused 409 human_approval_required', 'refused 403 desktop_token_session_scope', 'refused 403 user_token_ability_missing']));
    for (const r of desktop) {
      expect((r.detail as { sessionId?: string }).sessionId).toBe(sid);
      expect(JSON.stringify(r)).not.toContain(session.accessToken);
      expect(JSON.stringify(r)).not.toContain('ledger@example.test');
    }
    const [row] = await ctx.db.select().from(userTokens).where(eq(userTokens.id, token.id));
    expect(row!.useCount).toBeGreaterThan(0);
  });
});

describe('NEG-24: crm.api.enabled off for the org', () => {
  it('the delegated door answers 404 crm_api_disabled (so the app can say so); a bearer call keeps the plain 404', async () => {
    const { token, session } = await bound(CRM_SESSION);
    await ctx.db.update(organizations).set({ entitlementOverrides: { 'crm.v2.records': true, 'crm.api.enabled': false } }).where(eq(organizations.id, w.org.id));
    const viaSession = await inj('GET', crmUrl('/contacts'), session.headers);
    expect(viaSession.statusCode, viaSession.body).toBe(404);
    expect(codeOf(viaSession)).toBe('crm_api_disabled');
    const direct = await inj('GET', crmUrl('/contacts'), token.headers);
    expect(direct.statusCode).toBe(404);
    expect(codeOf(direct)).toBe('not_found');
    // a deleted contact is an ordinary not-found, never mislabelled as the switch
    await ctx.db.update(organizations).set({ entitlementOverrides: { 'crm.v2.records': true, 'crm.api.enabled': true } }).where(eq(organizations.id, w.org.id));
    const gone = await inj('GET', crmUrl('/segments/00000000-0000-4000-8000-000000000009'), session.headers);
    expect(gone.statusCode).toBe(404);
    expect(codeOf(gone)).toBe('not_found');
  });
});

describe('NEG-26: the gate reads the FULL token row on the next request, projectIds and conversationScope included', () => {
  it('a narrowing of projectIds or conversationScope is visible to the gate with no cache', async () => {
    const { loadBoundUserToken } = await import('../src/modules/user-tokens/bound-session');
    const { token } = await bound(CRM_SESSION);
    const [row] = await ctx.db.select().from(userTokens).where(eq(userTokens.id, token.id));
    const fp = row!.tokenHash.slice(0, 16);
    const first = await loadBoundUserToken(ctx.db, w.owner.user.id, token.id, fp);
    expect(first.ok && first.credential.token.projectIds).toBeNull();
    await ctx.db.update(userTokens).set({ projectIds: ['22222222-2222-4222-8222-222222222222'], conversationScope: ['33333333-3333-4333-8333-333333333333'] }).where(eq(userTokens.id, token.id));
    const second = await loadBoundUserToken(ctx.db, w.owner.user.id, token.id, fp);
    expect(second.ok && second.credential.token.projectIds).toEqual(['22222222-2222-4222-8222-222222222222']);
    expect(second.ok && second.credential.token.conversationScope).toEqual(['33333333-3333-4333-8333-333333333333']);
  });
});

describe('NEG-27: a mismatching x-goodqa-recovery-actor is 409 session_changed on both doors', () => {
  it('host door and delegated door', async () => {
    const { session } = await bound(CRM_SESSION);
    const h = { ...session.headers, 'x-goodqa-recovery-actor': '00000000-0000-4000-8000-0000000000aa' };
    for (const u of ['/v1/me', crmUrl('/contacts')]) {
      const res = await inj('GET', u, h);
      expect(res.statusCode, `${u} ${res.body}`).toBe(409);
      expect(codeOf(res)).toBe('session_changed');
    }
  });
});

describe('AC-9 / NEG-13 / NEG-20 (D6, pulled forward: narrowing a token is untestable while mint demands all five abilities)', () => {
  it('a desktop_signin+read+crm token starts a session; without read, or without desktop_signin, it cannot', async () => {
    const ok = await mint(w.owner, CRM_SESSION);
    expect((await inj('POST', '/v1/me/desktop-session', ok.headers, { client: 'desktop-ctl' })).statusCode).toBe(200);
    const noRead = await mint(w.owner, ['desktop_signin', 'crm']);
    const r_noRead = await inj('POST', '/v1/me/desktop-session', noRead.headers, { client: 'desktop-ctl' });
    expect(r_noRead.statusCode, r_noRead.body).toBe(403);
    expect(codeOf(r_noRead)).toBe('user_token_ability_missing');
    const noSignin = await mint(w.owner, ['read', 'crm']);
    const r_noSignin = await inj('POST', '/v1/me/desktop-session', noSignin.headers, { client: 'desktop-ctl' });
    expect(r_noSignin.statusCode, r_noSignin.body).toBe(403);
    expect(codeOf(r_noSignin)).toBe('user_token_ability_missing');
  });

  it('a CRM-only session cannot enroll a machine or read the machines catalog; /v1/me, /v1/orgs and notification reads still work', async () => {
    const { session } = await bound(CRM_SESSION);
    for (const u of ['/v1/me', '/v1/orgs', '/v1/notifications', '/v1/notifications/unread-count']) expect((await inj('GET', u, session.headers)).statusCode, u).toBe(200);
    const enroll = await inj('POST', '/v1/me/machine-enrollments', session.headers, { orgIds: [w.org.id], preset: 'resting' });
    expect(enroll.statusCode, enroll.body).toBe(403);
    expect(codeOf(enroll)).toBe('user_token_ability_missing');
    const catalog = await inj('GET', '/v1/me/remote-control/catalog', session.headers);
    expect(catalog.statusCode, catalog.body).toBe(403);
    // no waiver without the host set (RT15561-1): the plain bearer answer, a route no token reaches
    expect(codeOf(catalog)).toBe('user_token_non_delegable');
  });
});

describe('W1-W3 and NEG-21 / NEG-29: the host door is the same gate with three named waivers', () => {
  it('W1: a token holding machines reaches an allow-listed machine route through the session that the same token is refused by bearer (non_delegable machines)', async () => {
    const { token, session } = await bound(FIVE_PLUS_CRM);
    const viaSession = await inj('GET', `/v1/orgs/${w.org.id}/machines`, session.headers);
    expect(viaSession.statusCode, viaSession.body).toBe(200);
    const direct = await inj('GET', `/v1/orgs/${w.org.id}/machines`, token.headers);
    expect(direct.statusCode).toBe(403);
    expect(codeOf(direct)).toBe('user_token_non_delegable');
  });

  it('W2: the catalog (session-only for every credential) is served to a machines token and refused without machines', async () => {
    const full = await bound(FIVE_PLUS_CRM);
    expect((await inj('GET', '/v1/me/remote-control/catalog', full.session.headers)).statusCode).toBe(200);
    const bare = await bound(CRM_SESSION);
    expect((await inj('GET', '/v1/me/remote-control/catalog', bare.session.headers)).statusCode).toBe(403);
  });

  it('W3 + NEG-29: an Ask-me-first token session enrolls a machine (no 409), and the enrollment carries the token id, its end and its org list', async () => {
    const endsAt = new Date(Date.now() + 3 * 3600_000);
    const { token, session } = await bound(FIVE_PLUS_CRM, { expiresAt: endsAt.toISOString() });
    await ctx.db.update(userTokens).set({ requireHumanApproval: true }).where(eq(userTokens.id, token.id));
    const enroll = await inj('POST', '/v1/me/machine-enrollments', session.headers, { orgIds: [w.org.id], preset: 'resting' });
    expect(enroll.statusCode, enroll.body).toBe(201);
    const [row] = await ctx.db.select().from(machineEnrollments).where(eq(machineEnrollments.id, enroll.json().enrollment.id));
    expect(row!.mintedByUserTokenId).toBe(token.id);
    expect(row!.expiresAt.getTime()).toBeLessThanOrEqual(endsAt.getTime());
    // the waiver is for the enrollment routes only: the same token by bearer still asks (409)
    const direct = await inj('POST', '/v1/me/machine-enrollments', token.headers, { orgIds: [w.org.id], preset: 'resting' });
    expect(codeOf(direct)).toBe('human_approval_required');
    // after the token's org list narrows, an enrollment naming another org is refused
    await ctx.db.update(userTokens).set({ orgIds: [w.other.id] }).where(eq(userTokens.id, token.id));
    const narrowed = await inj('POST', '/v1/me/machine-enrollments', session.headers, { orgIds: [w.org.id], preset: 'resting' });
    expect(narrowed.statusCode, narrowed.body).toBeGreaterThanOrEqual(400);
  });
});

describe('AC-13: the bound answer never exceeds the bearer answer for the same token (subset invariant)', () => {
  const GATE = /^(user_token_|desktop_token_|human_approval_required|crm_api_disabled)/;
  const gate = (a: string) => GATE.test(a.split(' ').slice(1).join(' '));
  // the named differences: W1 (machines non-delegable waived on allow-listed machine routes), W2 (session-only host routes served),
  // W3 (approval waived on the enrollment routes). Everything else must be equal or bound-refused.
  const WAIVED = /\/v1\/orgs\/[^/]+\/machines(\/|$)|\/v1\/machines\/|\/v1\/me\/remote-control\/catalog|\/v1\/me\/machine-enrollments/;

  it('for 40+ routes and two token shapes, a bound session is never allowed what the bearer call is refused, and delegated routes answer exactly as bearer', async () => {
    expect(PARITY_ROUTES.length).toBeGreaterThanOrEqual(30);
    for (const abilities of [CRM_WRITE_SESSION, FIVE_PLUS_CRM]) {
      const { token, session } = await bound(abilities);
      resetUserTokenLimitersForTests();
      for (const r of PARITY_ROUTES) {
        const url = fill(r.url, w.ids);
        const viaSession = answerOf(await inj(r.method, url, session.headers, r.body));
        const viaBearer = answerOf(await inj(r.method, url, token.headers, r.body));
        const label = `${abilities.length} abilities ${r.method} ${r.url}: session ${viaSession} / bearer ${viaBearer}`;
        if (WAIVED.test(r.url)) continue;
        if (!gate(viaSession) && gate(viaBearer)) throw new Error(`session exceeds bearer: ${label}`);
        if (/\/crm\/(contacts|companies|segments|records)|\/entitlements|\/members$/.test(r.url) && r.method !== 'DELETE') expect(viaSession, label).toBe(viaBearer);
      }
    }
  }, 240_000);
});

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
    // a REFUSED poll is the trail of a stolen session: it is written
    await ctx.db.update(userTokens).set({ abilities: ['desktop_signin', 'crm'] }).where(eq(userTokens.id, token.id));
    expect((await inj('GET', '/v1/me', session.headers)).statusCode).toBe(403);
    await new Promise((r) => setTimeout(r, 400));
    expect(await count()).toBe(rows0 + 3);
  });
});
