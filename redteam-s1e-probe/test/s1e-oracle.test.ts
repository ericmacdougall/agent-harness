/**
 * Red-team probe P1 (goodqa#15561 S1e-a review, NOT a repo file): does the contact timeline `q` search, reached through
 * a bound desktop session (W4), act as a content oracle over entries the session must not see?
 *  - Gmail mailbox-read entries (withheld from every agent credential)
 *  - a colleague's `personal` entry (absent)
 *  - a colleague's `busy_only` meeting (opaque Busy row)
 * Signal: `timeline` returned to the session, and `nextCursor` (computed from the raw page before filtering).
 */
import { eq } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { organizations, outreachConfig } from '@bugtracker/db';
import { createOrg, createTestApp, enableUserTokensForTests, resetDb, signupUser, type TestContext } from '/home/eric/wt-15561/apps/api/test/helpers';
import { addMember } from '/home/eric/wt-15561/apps/api/test/webhook-test-kit';
import { resetUserTokenLimitersForTests } from '/home/eric/wt-15561/apps/api/src/modules/user-tokens/auth-gate';
import { ingestInboxMessage } from '/home/eric/wt-15561/apps/api/src/modules/outreach/inbox-ingest';

type H = Record<string, string>;
let ctx: TestContext;
let owner: Awaited<ReturnType<typeof signupUser>>;
let orgId: string;
let contactId: string;
const inj = (method: string, url: string, headers: H, payload?: unknown) =>
  ctx.app.inject({ method: method as 'POST', url, headers, ...(payload === undefined ? {} : { payload: payload as object }) });

beforeAll(async () => { ctx = await createTestApp({ OUTREACH_PIPELINE_VIEW_ENABLED: 'true', INBOX_ENABLED: 'true' }); });
afterAll(async () => { await ctx?.close(); });

async function boundSession(user: { headers: H }) {
  const step = await inj('POST', '/v1/auth/webauthn/step-up', user.headers, { method: 'password', password: 'password123', purpose: 'user_tokens_manage' });
  const minted = await inj('POST', '/v1/me/user-tokens', user.headers, { name: 'probe', abilities: ['desktop_signin', 'read', 'crm'], requireHumanApproval: false, stepUpToken: step.json().stepUpToken });
  expect(minted.statusCode, minted.body).toBe(201);
  const start = await inj('POST', '/v1/me/desktop-session', { authorization: `Bearer ${minted.json().token}` }, { client: 'desktop-ctl' });
  expect(start.statusCode, start.body).toBe(200);
  return { authorization: `Bearer ${start.json().tokens.accessToken}` };
}

const sig = (b: string) => { const j = JSON.parse(b); return JSON.stringify({ n: (j.timeline as unknown[]).length, cursor: j.nextCursor }); };

beforeEach(async () => {
  await resetDb(ctx.db);
  owner = await signupUser(ctx.app, { name: 'Owner' });
  await enableUserTokensForTests(ctx.db);
  resetUserTokenLimitersForTests();
  orgId = (await createOrg(ctx.app, owner.headers)).id;
  await ctx.db.update(organizations).set({ plan: 'pro', entitlementOverrides: { 'outreach.enabled': true, 'outreach.api.enabled': true, 'crm.v2.records': true, 'crm.api.enabled': true, 'inbox.enabled': true } }).where(eq(organizations.id, orgId));
  const c = await inj('POST', `/v1/orgs/${orgId}/crm/contacts`, owner.headers, { firstName: 'Priya', lastName: 'Raman', primaryEmail: 'priya@acme.test' });
  contactId = (c.json() as { contact: { id: string } }).contact.id;
  await ctx.db.insert(outreachConfig).values({ orgId, policy: { storeBodies: true, bodyLegalHold: true } });
});

describe('P1: q search through the bound session', () => {
  it('Gmail mailbox-read content: does q reveal a withheld message?', async () => {
    const r = await ctx.db.transaction((tx) => ingestInboxMessage(tx, { OUTREACH_INBOX_INGEST_ENABLED: true }, {
      orgId, ownerUserId: owner.user.id, provider: 'gmail', mailbox: 'owner-mailbox@example.test',
      providerMessageId: 'gmail-probe-1', providerThreadId: null,
      headers: { 'Message-ID': '<probe1@acme.test>', From: 'Priya <priya@acme.test>' },
      subject: 'Acquisition zebracorn terms', preview: 'we accept the quokkaprice offer', bodyText: 'full text',
      at: new Date('2026-08-12T10:00:00.000Z'),
    }));
    expect(r.entryId).toBeTruthy();
    const session = await boundSession(owner);
    const url = (q: string) => `/v1/orgs/${orgId}/crm/contacts/${contactId}/timeline?limit=1&q=${encodeURIComponent(q)}`;
    const hit = await inj('GET', url('zebracorn'), session);
    const snippetHit = await inj('GET', url('quokkaprice'), session);
    const miss = await inj('GET', url('platypusword'), session);
    expect(hit.statusCode, hit.body).toBe(200);
    expect(hit.body).not.toContain('zebracorn');
    console.log('PROBE gmail entryId', r.entryId);
    console.log('PROBE gmail hit', sig(hit.body));
    console.log('PROBE gmail snippetHit', sig(snippetHit.body));
    console.log('PROBE gmail miss', sig(miss.body));
    const ownerView = await inj('GET', url('zebracorn'), owner.headers);
    console.log('PROBE gmail owner-control sees content', ownerView.statusCode, ownerView.body.includes('zebracorn'));
  });

  it('colleague personal and busy_only entries: does q reveal hidden titles?', async () => {
    const colleague = await addMember(ctx, orgId, { role: 'admin', extraPermissions: ['crm:create', 'crm:edit'], name: 'Colleague' });
    const mate = await addMember(ctx, orgId, { role: 'member', name: 'Mate' });
    const p = await inj('POST', `/v1/orgs/${orgId}/crm/timeline`, colleague.headers, { kind: 'task', title: 'Personal wombatsecret note', occursAt: '2026-08-11T14:05:00.000Z', visibility: 'personal', ownerUserId: colleague.user.id, links: [{ subjectKind: 'contact', subjectId: contactId }] });
    expect(p.statusCode, p.body).toBe(201);
    const b = await inj('POST', `/v1/orgs/${orgId}/crm/timeline`, colleague.headers, { kind: 'meeting', title: 'Layoff narwhalplan briefing', occursAt: '2026-08-10T14:05:00.000Z', visibility: 'busy_only', ownerUserId: colleague.user.id, links: [{ subjectKind: 'contact', subjectId: contactId }, { subjectKind: 'user', subjectId: colleague.user.id, role: 'organizer' }] });
    expect(b.statusCode, b.body).toBe(201);
    console.log('PROBE personal entryId', p.json().entry.id, 'busy entryId', b.json().entry.id);
    const session = await boundSession(mate);
    const url = (q: string) => `/v1/orgs/${orgId}/crm/contacts/${contactId}/timeline?limit=1&q=${encodeURIComponent(q)}`;
    for (const q of ['wombatsecret', 'narwhalplan', 'platypusword']) {
      const r = await inj('GET', url(q), session);
      expect(r.statusCode, r.body).toBe(200);
      expect(r.body).not.toContain(q);
      console.log(`PROBE colleague q=${q}`, sig(r.body), r.body.slice(0, 400));
    }
  });
});
