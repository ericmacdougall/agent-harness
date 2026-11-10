/**
 * goodqa#15561 slice S1e-a: contact detail and contact timeline for a desktop session started from a user token, on by
 * default (user answer "Yes, on by default"): no org-owner opt-in, no userTokens.sessionActions switch, no session:crm_timeline
 * grant. The BOUND door only (waiver W4); a bearer call with the same token keeps today's answers.
 * Written first and run red on origin/main (both routes answer user_token_non_delegable to a bound session).
 */
import { eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { organizations, userTokenEvents, userTokens } from '@bugtracker/db';
import { resetUserTokenLimitersForTests } from '../src/modules/user-tokens/auth-gate';
import { createOrg, createTestApp, enableUserTokensForTests, resetDb, signupUser, type TestContext } from './helpers';
import { setupParityWorld } from './user-token-parity-fixtures';
import { addMember } from './webhook-test-kit';

type H = Record<string, string>;
let ctx: TestContext;
let w: Awaited<ReturnType<typeof setupParityWorld>>;
let contactA: string;
let contactB: string;
beforeAll(async () => { ctx = await createTestApp(); });
afterAll(async () => { await ctx?.close(); });
const inj = (method: string, url: string, headers: H, payload?: unknown) =>
  ctx.app.inject({ method: method as 'POST', url, headers, ...(payload === undefined ? {} : { payload: payload as object }) });
const bearer = (t: string): H => ({ authorization: `Bearer ${t}` });
const codeOf = (res: { json: () => unknown }) => (res.json() as { error?: { code?: string } }).error?.code;
const detailsOf = (res: { json: () => unknown }) => (res.json() as { error?: { details?: Record<string, unknown> } }).error?.details ?? {};

async function makeContact(orgId: string, headers: H, first: string) {
  const r = await inj('POST', `/v1/orgs/${orgId}/crm/contacts`, headers, { firstName: first, lastName: 'Timeline', primaryEmail: `${first.toLowerCase()}@example.test` });
  expect(r.statusCode, r.body).toBe(201);
  return (r.json() as { contact: { id: string } }).contact.id;
}
async function logEntry(orgId: string, headers: H, contactId: string, title: string, extra: Record<string, unknown> = {}) {
  const r = await inj('POST', `/v1/orgs/${orgId}/crm/timeline`, headers, { kind: 'task', title, occursAt: '2026-08-11T14:05:00.000Z', links: [{ subjectKind: 'contact', subjectId: contactId }], ...extra });
  expect(r.statusCode, r.body).toBe(201);
  return (r.json() as { entry: { id: string } }).entry.id;
}
async function mint(owner: { headers: H }, abilities: string[], extra: Record<string, unknown> = {}) {
  const step = await inj('POST', '/v1/auth/webauthn/step-up', owner.headers, { method: 'password', password: 'password123', purpose: 'user_tokens_manage' });
  const res = await inj('POST', '/v1/me/user-tokens', owner.headers, { name: 's1e', abilities, requireHumanApproval: false, ...extra, stepUpToken: step.json().stepUpToken });
  expect(res.statusCode, res.body).toBe(201);
  const j = res.json() as { userToken: { id: string }; token: string };
  return { id: j.userToken.id, headers: bearer(j.token) };
}
async function bound(abilities: string[], owner: { headers: H } = w.owner, extra: Record<string, unknown> = {}) {
  const token = await mint(owner, abilities, extra);
  const r = await inj('POST', '/v1/me/desktop-session', token.headers, { client: 'desktop-ctl' });
  expect(r.statusCode, `desktop-session: ${r.body}`).toBe(200);
  const t = r.json().tokens as { accessToken: string };
  return { token, session: { headers: bearer(t.accessToken), accessToken: t.accessToken } };
}
const CRM = ['desktop_signin', 'read', 'crm'];
const detail = (org: string, id: string) => `/v1/orgs/${org}/crm/contacts/${id}`;
const timeline = (org: string, id: string) => `/v1/orgs/${org}/crm/contacts/${id}/timeline`;

beforeEach(async () => {
  await resetDb(ctx.db);
  w = await setupParityWorld(ctx);
  await enableUserTokensForTests(ctx.db);
  resetUserTokenLimitersForTests();
  contactA = await makeContact(w.org.id, w.owner.headers, 'Ada');
  contactB = await makeContact(w.other.id, w.owner.headers, 'Bea');
  await logEntry(w.org.id, w.owner.headers, contactA, 'Shared follow up');
});

describe('AC-1: a bound session reads contact detail and timeline with no opt-in, switch or grant', () => {
  it('crm + read: 200 on both routes while userTokens.sessionActions is off and the org has not opted in', async () => {
    const { session } = await bound(CRM);
    const d = await inj('GET', detail(w.org.id, contactA), session.headers);
    expect(d.statusCode, d.body).toBe(200);
    expect((d.json() as { contact: { id: string } }).contact.id).toBe(contactA);
    const t = await inj('GET', timeline(w.org.id, contactA), session.headers);
    expect(t.statusCode, t.body).toBe(200);
    expect(JSON.stringify(t.json())).toContain('Shared follow up');
  });
});

describe('NEG-1: the ability ceiling still applies', () => {
  it('a token without crm is refused both routes naming crm', async () => {
    const { session } = await bound(['desktop_signin', 'read']);
    for (const u of [detail(w.org.id, contactA), timeline(w.org.id, contactA)]) {
      const r = await inj('GET', u, session.headers);
      expect(r.statusCode, u).toBe(403);
      expect(codeOf(r), u).toBe('user_token_ability_missing');
      expect(detailsOf(r).missing, u).toEqual(['crm']);
    }
  });
});

describe('AC-2 / NEG-8 / NEG-9: exactly two routes, exactly the bound door', () => {
  it('a bearer call with the same token keeps today answers on both routes', async () => {
    const { token } = await bound(CRM);
    for (const u of [detail(w.org.id, contactA), timeline(w.org.id, contactA)]) {
      const r = await inj('GET', u, token.headers);
      expect(r.statusCode, u).toBe(403);
      expect(codeOf(r), u).toBe('user_token_non_delegable');
    }
  });

  it('the other session-only CRM routes stay refused to the bound session', async () => {
    const { session } = await bound(['desktop_signin', 'read', 'write', 'crm']);
    const ZERO = '00000000-0000-4000-8000-000000000000';
    const cases: Array<[string, string, unknown?]> = [
      ['GET', `/v1/orgs/${w.org.id}/crm/contacts/export`],
      ['GET', `/v1/orgs/${w.org.id}/crm/contacts/${contactA}/meetings`],
      ['GET', `/v1/orgs/${w.org.id}/crm/contacts/${contactA}/files`],
      ['GET', `/v1/orgs/${w.org.id}/crm/contacts/${contactA}/ai/suggestions`],
      ['POST', `/v1/orgs/${w.org.id}/crm/contacts/${contactA}/ai/briefing`, {}],
      ['POST', `/v1/orgs/${w.org.id}/crm/contacts/${contactA}/issue-links`, { issueId: ZERO }],
      ['POST', `/v1/orgs/${w.org.id}/crm/timeline`, { kind: 'task', title: 'x', occursAt: '2026-08-11T14:05:00.000Z', links: [] }],
      ['GET', `/v1/orgs/${w.org.id}/crm/timeline`],
      ['GET', `/v1/orgs/${w.org.id}/crm/deals/${ZERO}`],
      ['GET', `/v1/orgs/${w.org.id}/crm/pipelines`],
    ];
    for (const [m, u, b] of cases) {
      const r = await inj(m, u, session.headers, b);
      expect(r.statusCode, `${m} ${u} ${r.body}`).toBe(403);
      expect(['user_token_non_delegable', 'desktop_token_session_scope'], `${m} ${u}`).toContain(codeOf(r));
    }
  });

  it('the W4 waiver set is exactly the two routes', async () => {
    const { DESKTOP_SESSION_ONLY_OPENED } = await import('../src/lib/desktop-token-session');
    expect([...DESKTOP_SESSION_ONLY_OPENED].sort()).toEqual([
      'GET /v1/orgs/:p/crm/contacts/:p',
      'GET /v1/orgs/:p/crm/contacts/:p/timeline',
    ]);
  });
});

describe('AC-3 / NEG-2..5: the tenant boundary and revocation hold', () => {
  it('a contact of org B under org A is 404, also for a token that reaches both orgs', async () => {
    const { session } = await bound(CRM);
    expect((await inj('GET', detail(w.other.id, contactB), session.headers)).statusCode).toBe(200); // org B is the owner's own org
    await logEntry(w.other.id, w.owner.headers, contactB, 'Org B secret follow up');
    const d = await inj('GET', detail(w.org.id, contactB), session.headers);
    expect(d.statusCode, d.body).toBe(404);
    const t = await inj('GET', timeline(w.org.id, contactB), session.headers);
    expect(t.statusCode, t.body).toBe(200); // the existing handler does not check the contact; the page is empty and org-scoped
    expect((t.json() as { timeline: unknown[] }).timeline).toEqual([]);
    expect(t.body).not.toContain('Org B secret follow up');
  });

  it('narrowing the token org list after the session started is 404 on the next request', async () => {
    const { token, session } = await bound(CRM);
    expect((await inj('GET', detail(w.org.id, contactA), session.headers)).statusCode).toBe(200);
    await ctx.db.update(userTokens).set({ orgIds: [w.other.id] }).where(eq(userTokens.id, token.id));
    for (const u of [detail(w.org.id, contactA), timeline(w.org.id, contactA)]) expect((await inj('GET', u, session.headers)).statusCode, u).toBe(404);
  });

  it('a user who is not a member of the org cannot read either route through their own session', async () => {
    const outsider = await signupUser(ctx.app, { name: 'Outsider' });
    const { session } = await bound(CRM, outsider);
    for (const u of [detail(w.org.id, contactA), timeline(w.org.id, contactA)]) {
      const r = await inj('GET', u, session.headers);
      expect([403, 404], `${u} ${r.body}`).toContain(r.statusCode);
      expect(r.body).not.toContain('Ada');
      expect(r.body).not.toContain('Shared follow up');
    }
  });

  it('revoking the token or removing crm ends or refuses the next request on the same access token', async () => {
    const a = await bound(CRM);
    expect((await inj('GET', detail(w.org.id, contactA), a.session.headers)).statusCode).toBe(200);
    await ctx.db.update(userTokens).set({ abilities: ['desktop_signin', 'read'] }).where(eq(userTokens.id, a.token.id));
    const noCrm = await inj('GET', timeline(w.org.id, contactA), a.session.headers);
    expect(noCrm.statusCode).toBe(403);
    expect(codeOf(noCrm)).toBe('user_token_ability_missing');
    const b = await bound(CRM);
    await ctx.db.update(userTokens).set({ revokedAt: new Date() }).where(eq(userTokens.id, b.token.id));
    expect((await inj('GET', detail(w.org.id, contactA), b.session.headers)).statusCode).toBe(401);
    expect((await inj('GET', timeline(w.org.id, contactA), b.session.headers)).statusCode).toBe(401);
  });
});

describe('AC-4 / NEG-6 / NEG-7 / NEG-10: privacy inside the org and the audit trail', () => {
  it('a colleague personal entry is absent for another member session; the owner still sees it', async () => {
    const colleague = await addMember(ctx, w.org.id, { role: 'admin', extraPermissions: ['crm:create', 'crm:edit'], name: 'Colleague' });
    const mate = await addMember(ctx, w.org.id, { role: 'member', name: 'Mate' });
    await logEntry(w.org.id, colleague.headers, contactA, 'Colleague private note', { visibility: 'personal', ownerUserId: colleague.user.id });
    const mateSession = (await bound(CRM, mate)).session;
    const t = await inj('GET', timeline(w.org.id, contactA), mateSession.headers);
    expect(t.statusCode, t.body).toBe(200);
    expect(JSON.stringify(t.json())).toContain('Shared follow up');
    expect(JSON.stringify(t.json())).not.toContain('Colleague private note');
    const d = await inj('GET', detail(w.org.id, contactA), mateSession.headers);
    expect(JSON.stringify(d.json())).not.toContain('Colleague private note');
    // the colleague sees their own personal entry through a normal session
    const own = await inj('GET', timeline(w.org.id, contactA), colleague.headers);
    expect(JSON.stringify(own.json())).toContain('Colleague private note');
  });

  it('the bound door reads as an agent credential, so Gmail mailbox content stays withheld', async () => {
    const { gmailContentWithheldFrom } = await import('../src/lib/gmail-limited-use');
    expect(gmailContentWithheldFrom({ headers: {} }, { userTokenId: '00000000-0000-4000-8000-000000000001' })).toBe(true);
  });

  it('every request on the two routes is ledgered with via desktop_session, never quiet, and carries no payload', async () => {
    const { token, session } = await bound(CRM);
    await inj('GET', detail(w.org.id, contactA), session.headers);
    await inj('GET', timeline(w.org.id, contactA), session.headers);
    await inj('GET', detail(w.org.id, contactA), session.headers); // a repeat is still written (not a poll)
    await ctx.db.update(userTokens).set({ abilities: ['desktop_signin', 'read'] }).where(eq(userTokens.id, token.id));
    await inj('GET', timeline(w.org.id, contactA), session.headers); // refused
    await new Promise((r) => setTimeout(r, 500));
    const rows = (await ctx.db.select().from(userTokenEvents).where(eq(userTokenEvents.tokenId, token.id)))
      .filter((r) => (r.detail as { via?: string } | null)?.via === 'desktop_session' && /contacts\/:contactId/.test(r.route ?? ''));
    expect(rows.filter((r) => r.kind === 'request').length).toBe(3);
    expect(rows.filter((r) => r.kind === 'refused').length).toBe(1);
    for (const r of rows) {
      expect(JSON.stringify(r)).not.toContain('Shared follow up');
      expect(JSON.stringify(r)).not.toContain(session.accessToken);
    }
  });
});

async function setSetting(key: string, value: unknown) {
  await ctx.db.execute(sql`insert into platform_settings(key,value,value_type,updated_by,reason)
    select ${key}, ${JSON.stringify(value)}::jsonb, ${typeof value === 'boolean' ? 'boolean' : 'string'}, id, 'test' from users order by created_at limit 1
    on conflict(key) do update set value=excluded.value`);
}
async function setOverrides(orgId: string, overrides: Record<string, unknown>) {
  await ctx.db.update(organizations).set({ entitlementOverrides: { 'crm.v2.records': true, 'crm.api.enabled': true, ...overrides } }).where(eq(organizations.id, orgId));
}

describe('AC-1 matrix (F4): every switch state gives 200 through the bound session, never the session-action path', () => {
  it('platform on with no org opt-in, and platform on with opt-in, with and without the session:crm_timeline grant', async () => {
    await setSetting('userTokens.sessionActions', true);
    const plain = await bound(CRM);
    for (const u of [detail(w.org.id, contactA), timeline(w.org.id, contactA)]) expect((await inj('GET', u, plain.session.headers)).statusCode, `on/no opt-in ${u}`).toBe(200);
    await setOverrides(w.org.id, { 'userTokens.sessionActions': true });
    for (const u of [detail(w.org.id, contactA), timeline(w.org.id, contactA)]) expect((await inj('GET', u, plain.session.headers)).statusCode, `on/opt-in/no grant ${u}`).toBe(200);
    const granted = await bound([...CRM, 'session:crm_timeline']);
    for (const u of [detail(w.org.id, contactA), timeline(w.org.id, contactA)]) expect((await inj('GET', u, granted.session.headers)).statusCode, `on/opt-in/grant ${u}`).toBe(200);
    // never the session-action path: no session-action audit row for the bound requests
    const audits = await ctx.db.execute(sql`select count(*)::int as n from audit_events where action = 'user_token.session_action'`);
    expect(((audits as unknown as { rows?: Array<{ n: number }> }).rows ?? (audits as unknown as Array<{ n: number }>))[0]!.n).toBe(0);
  });

  it('the bearer answers are unchanged in each switch state (bearer never gets contact detail; the timeline keeps its session-action refusal)', async () => {
    const t = await mint(w.owner, [...CRM]);
    for (const state of ['off', 'on', 'on+optin']) {
      if (state !== 'off') await setSetting('userTokens.sessionActions', true);
      if (state === 'on+optin') await setOverrides(w.org.id, { 'userTokens.sessionActions': true });
      const d = await inj('GET', detail(w.org.id, contactA), t.headers);
      expect([d.statusCode, codeOf(d)], `detail ${state}`).toEqual([403, 'user_token_non_delegable']);
      const tl = await inj('GET', timeline(w.org.id, contactA), t.headers);
      expect(tl.statusCode, `timeline ${state} ${tl.body}`).toBe(403);
      expect(['user_token_non_delegable', 'session_actions_disabled', 'user_token_ability_missing', 'user_token_session_action_missing'], `timeline ${state} ${codeOf(tl)}`).toContain(codeOf(tl));
    }
  });
});

describe('F1 / F3: the org CRM switch and the org opt-out both apply to the two routes', () => {
  it('crm.api.enabled off: 404 crm_api_disabled on both routes (contact list already answers the same)', async () => {
    const { session } = await bound(CRM);
    await setOverrides(w.org.id, { 'crm.api.enabled': false });
    for (const u of [detail(w.org.id, contactA), timeline(w.org.id, contactA)]) {
      const r = await inj('GET', u, session.headers);
      expect([r.statusCode, codeOf(r)], u).toEqual([404, 'crm_api_disabled']);
    }
  });
  it('the org opt-out userTokens.contactTimelines=false: 404 contact_timelines_disabled on both routes; other CRM reads stay; unset or true is on', async () => {
    const { session } = await bound(CRM);
    await setOverrides(w.org.id, { 'userTokens.contactTimelines': false });
    for (const u of [detail(w.org.id, contactA), timeline(w.org.id, contactA)]) {
      const r = await inj('GET', u, session.headers);
      expect([r.statusCode, codeOf(r)], u).toEqual([404, 'contact_timelines_disabled']);
    }
    expect((await inj('GET', `/v1/orgs/${w.org.id}/crm/contacts`, session.headers)).statusCode).toBe(200);
    await setOverrides(w.org.id, { 'userTokens.contactTimelines': true });
    expect((await inj('GET', detail(w.org.id, contactA), session.headers)).statusCode).toBe(200);
  });
});

describe('F2 / F8 / F7: operator tokens, HEAD, exact keys, the delegated door', () => {
  it('an operator-kind token gets no W4 (an agent-held, non-expiring orchestrator)', async () => {
    const op = await bound(CRM);
    await ctx.db.execute(sql`update user_tokens set created_via = 'operator' where id = ${op.token.id}::uuid`);
    for (const u of [detail(w.org.id, contactA), timeline(w.org.id, contactA)]) {
      const r = await inj('GET', u, op.session.headers);
      expect([r.statusCode, codeOf(r)], u).toEqual([403, 'user_token_non_delegable']);
    }
  });
  it('HEAD is covered exactly like GET on the two routes (200 with crm, refused without), and no other method on those paths is opened', async () => {
    const { session } = await bound(['desktop_signin', 'read', 'write', 'crm']);
    for (const u of [detail(w.org.id, contactA), timeline(w.org.id, contactA)]) {
      const h = await inj('HEAD', u, session.headers);
      expect(h.statusCode, `HEAD ${u}`).toBe(200);
    }
    const noCrm = await bound(['desktop_signin', 'read']);
    for (const u of [detail(w.org.id, contactA), timeline(w.org.id, contactA)]) {
      const h = await inj('HEAD', u, noCrm.session.headers);
      expect(h.statusCode, `HEAD no crm ${u}`).toBe(403);
    }
    // PATCH on the detail path stays the ordinary CRM write door (allowed by crm+write, owner role), never a W4 path
    const patchR = await inj('PATCH', detail(w.org.id, contactA), session.headers, { firstName: 'Zed' });
    expect(patchR.statusCode, patchR.body).toBe(200);
    const del = await inj('DELETE', detail(w.org.id, contactA), session.headers);
    expect(del.statusCode).toBe(403);
    expect(['user_token_non_delegable', 'desktop_token_session_scope']).toContain(codeOf(del));
    // POST on the timeline path is the existing session-only timeline create, still refused to a bound session
    const post = await inj('POST', `/v1/orgs/${w.org.id}/crm/timeline`, session.headers, { kind: 'task', title: 'x', occursAt: '2026-08-11T14:05:00.000Z', links: [] });
    expect(post.statusCode).toBe(403);
  });
  it('both keys are on the delegated door, not the host door (the Gmail withholding and live token re-read depend on it)', async () => {
    const { desktopRouteDoor } = await import('../src/lib/desktop-token-session');
    for (const k of ['/v1/orgs/:p/crm/contacts/:p', '/v1/orgs/:p/crm/contacts/:p/timeline']) expect(desktopRouteDoor('GET', k)).toBe('delegated');
  });
});

describe('F6: busy_only entries arrive opaque to a colleague session on both routes', () => {
  it('a colleague busy_only meeting shows as Busy with no subjects and no join link, on the timeline and in the contact detail', async () => {
    const colleague = await addMember(ctx, w.org.id, { role: 'admin', extraPermissions: ['crm:create', 'crm:edit'], name: 'Colleague2' });
    const mate = await addMember(ctx, w.org.id, { role: 'member', name: 'Mate2' });
    await logEntry(w.org.id, colleague.headers, contactA, 'Renewal negotiation', {
      kind: 'meeting', visibility: 'busy_only', ownerUserId: colleague.user.id, conferencingUrl: 'https://zoom.us/j/987654321',
      links: [{ subjectKind: 'contact', subjectId: contactA }, { subjectKind: 'user', subjectId: colleague.user.id, role: 'organizer' }],
    });
    const { session } = await bound(CRM, mate);
    for (const u of [timeline(w.org.id, contactA), detail(w.org.id, contactA)]) {
      const r = await inj('GET', u, session.headers);
      expect(r.statusCode, `${u} ${r.body}`).toBe(200);
      expect(r.body, u).not.toContain('Renewal negotiation');
      expect(r.body, u).not.toContain('zoom.us/j/987654321');
    }
  });
});

describe('NEG-1 (rest): read and desktop_signin are needed to start and to keep a session', () => {
  it('a token without read cannot start a session; removing read or desktop_signin mid-session refuses or ends it', async () => {
    const noRead = await mint(w.owner, ['desktop_signin', 'crm']);
    const start = await inj('POST', '/v1/me/desktop-session', noRead.headers, { client: 'desktop-ctl' });
    expect(start.statusCode, start.body).toBeGreaterThanOrEqual(400);
    for (const drop of ['read', 'desktop_signin']) {
      const { token, session } = await bound(CRM);
      expect((await inj('GET', detail(w.org.id, contactA), session.headers)).statusCode).toBe(200);
      await ctx.db.update(userTokens).set({ abilities: CRM.filter((a) => a !== drop) }).where(eq(userTokens.id, token.id));
      const r = await inj('GET', detail(w.org.id, contactA), session.headers);
      expect([401, 403], `${drop} removed: ${r.body}`).toContain(r.statusCode);
      expect(r.body).not.toContain('Ada');
    }
  });
});

describe('NEG-13 (red-team N1): a bound session cannot probe withheld entries through q, pinned or the cursor', () => {
  it('q and pinned are refused on the timeline; a page showing no visible entry gives no cursor and no withheld id', async () => {
    const colleague = await addMember(ctx, w.org.id, { role: 'admin', extraPermissions: ['crm:create', 'crm:edit'], name: 'Colleague3' });
    const mate = await addMember(ctx, w.org.id, { role: 'member', name: 'Mate3' });
    const hiddenId = await logEntry(w.org.id, colleague.headers, contactA, 'Personal wombatsecret note', {
      visibility: 'personal', ownerUserId: colleague.user.id, occursAt: '2026-09-01T10:00:00.000Z',
    });
    const { session } = await bound(CRM, mate);
    for (const qs of ['?q=wombatsecret', '?q=platypusword', '?pinned=true']) {
      const r = await inj('GET', `${timeline(w.org.id, contactA)}${qs}`, session.headers);
      expect([r.statusCode, codeOf(r)], qs).toEqual([400, 'user_token_filter_unsupported']);
      expect(r.body).not.toContain(hiddenId);
    }
    // newest raw row is the colleague personal entry: limit=1 shows nothing visible, and must not hand back its id or time
    const page = await inj('GET', `${timeline(w.org.id, contactA)}?limit=1`, session.headers);
    expect(page.statusCode, page.body).toBe(200);
    expect(page.body).not.toContain(hiddenId);
    expect(page.body).not.toContain('2026-09-01');
    expect((page.json() as { nextCursor: string | null }).nextCursor).toBeNull();
    // the contact detail embeds the same first page and must not name it either
    const d = await inj('GET', detail(w.org.id, contactA), session.headers);
    expect(d.body).not.toContain(hiddenId);
    // control: the colleague signed in sees the entry and a person's own paging is unchanged
    const own = await inj('GET', `${timeline(w.org.id, contactA)}?q=wombatsecret`, colleague.headers);
    expect(own.statusCode, own.body).toBe(200);
    expect(own.body).toContain(hiddenId);
  });
});

describe('NEG-13 positive control (acceptance X1): paging still works for a bound session', () => {
  it('limit=1 over two visible entries returns the visible-entry cursor, and following it returns the other entry once', async () => {
    const newerId = await logEntry(w.org.id, w.owner.headers, contactA, 'Newer follow up', { occursAt: '2026-09-02T09:00:00.000Z' });
    const { session } = await bound(CRM);
    const page1 = await inj('GET', `${timeline(w.org.id, contactA)}?limit=1`, session.headers);
    expect(page1.statusCode, page1.body).toBe(200);
    const j1 = page1.json() as { timeline: Array<{ id: string; title: string }>; nextCursor: string | null };
    expect(j1.timeline.map((e) => e.id)).toEqual([newerId]);
    expect(j1.nextCursor).toBe(`2026-09-02T09:00:00.000Z|${newerId}`);
    const page2 = await inj('GET', `${timeline(w.org.id, contactA)}?limit=1&cursor=${encodeURIComponent(j1.nextCursor!)}`, session.headers);
    expect(page2.statusCode, page2.body).toBe(200);
    const j2 = page2.json() as { timeline: Array<{ id: string; title: string }>; nextCursor: string | null };
    expect(j2.timeline.map((e) => e.title)).toEqual(['Shared follow up']);
    expect(j2.timeline.map((e) => e.id)).not.toContain(newerId);
  });
});
