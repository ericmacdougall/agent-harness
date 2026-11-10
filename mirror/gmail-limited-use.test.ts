import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { eq } from 'drizzle-orm';
import { organizations, outreachConfig, outreachMessages, outreachReplyDrafts, projects } from '@bugtracker/db';
import { createOrg, createProject, createTestApp, enableUserTokensForTests, resetDb, signupUser, type TestContext } from './helpers';
import { ingestInboxMessage, type InboxMessageInput } from '../src/modules/outreach/inbox-ingest';
import { gmailContentWithheldFrom } from '../src/lib/gmail-limited-use';
import { isMcpDispatch, mcpDispatchHeaders, withMcpDispatch } from '../src/lib/in-process-dispatch';
import { callInternal, type ToolCallContext } from '../src/modules/mcp/tools';

/**
 * GMAIL MAILBOX-READ CONTENT NEVER REACHES AN AGENT.
 *
 * An org API key, a user token and every MCP tool call are agents (LLMs), so a route that hands them mail read from
 * a Gmail mailbox is sending Gmail content to an AI model, which the privacy page says never happens
 * (`lib/gmail-limited-use.ts`). Each route below is driven for real, with mail written by the REAL ingest
 * (`ingestInboxMessage`, the function `outreach/gmail/sync.ts` calls), and each has two controls: the same agent still
 * receives a hand-logged email and another provider's mailbox read, and a person signed in to the app still receives
 * the Gmail message itself.
 *
 * Most MCP cases present the marker an MCP request's tool calls carry (`mcpDispatchHeaders`) with a person's
 * session, which is what a platform admin's MCP session sends; the last describe block drives the real `/v1/mcp`
 * transport and `call_api` end to end, and proves `callInternal` only
 * stamps it.
 */
const ADMIN_EMAIL = 'gmail-limited-use-admin@e2e.goodqa.app';
const GMAIL_SUBJECT = 'GMAILSUBJECT-91c2 contract question';
const GMAIL_SNIPPET = 'GMAILSNIPPET-91c2 can you do net 60';
const GMAIL_BODY = 'GMAILBODY-91c2 full text of the reply';

let ctx: TestContext;
let owner: Awaited<ReturnType<typeof signupUser>>;
let orgId: string;
let projectId: string;
let contactId: string;
let gmailEntryId: string;
let manualEntryId: string;

type Headers = Record<string, string>;
const get = (headers: Headers, url: string) => ctx.app.inject({ method: 'GET', url, headers });
const asMcp = (headers: Headers): Headers => ({ ...headers, ...mcpDispatchHeaders() });

async function ingest(patch: Partial<InboxMessageInput> = {}) {
  const result = await ctx.db.transaction((tx) =>
    ingestInboxMessage(tx, { OUTREACH_INBOX_INGEST_ENABLED: true }, {
      orgId,
      ownerUserId: owner.user.id,
      provider: 'gmail',
      mailbox: 'owner-mailbox@example.test',
      providerMessageId: `gmail-${Math.random().toString(36).slice(2)}`,
      providerThreadId: null,
      headers: { 'Message-ID': `<${Math.random().toString(36).slice(2)}@acme.test>`, From: 'Priya <priya@acme.test>' },
      subject: GMAIL_SUBJECT,
      preview: GMAIL_SNIPPET,
      bodyText: GMAIL_BODY,
      at: new Date('2026-08-12T10:00:00.000Z'),
      ...patch,
    }),
  );
  if (!result.entryId) throw new Error(`ingest wrote no entry: ${result.status}`);
  return result.entryId;
}

async function mintKey(): Promise<Headers> {
  const res = await ctx.app.inject({
    method: 'POST',
    url: `/v1/orgs/${orgId}/api-keys`,
    headers: owner.headers,
    payload: { name: 'gmail limited use bot', scopes: ['read', 'write'] },
  });
  if (res.statusCode !== 201) throw new Error(`mint failed: ${res.body}`);
  return { authorization: `Bearer ${res.json().token}` };
}

beforeAll(async () => {
  ctx = await createTestApp({ OUTREACH_PIPELINE_VIEW_ENABLED: 'true', INBOX_ENABLED: 'true', PLATFORM_ADMIN_EMAILS: ADMIN_EMAIL });
});
afterAll(async () => {
  await ctx.close();
});

beforeEach(async () => {
  await resetDb(ctx.db);
  // A verified platform admin, so the same person can also open an MCP session with their own session token.
  owner = await signupUser(ctx.app, { email: ADMIN_EMAIL });
  orgId = (await createOrg(ctx.app, owner.headers)).id;
  projectId = (await createProject(ctx.app, owner.headers, orgId)).id;
  await ctx.db
    .update(organizations)
    .set({
      plan: 'pro',
      entitlementOverrides: {
        'outreach.enabled': true,
        'outreach.pipelineView': true,
        'outreach.api.enabled': true,
        'crm.v2.records': true,
        'crm.api.enabled': true,
        'inbox.enabled': true,
      },
    })
    .where(eq(organizations.id, orgId));
  const contact = await ctx.app.inject({
    method: 'POST',
    url: `/v1/orgs/${orgId}/crm/contacts`,
    headers: owner.headers,
    payload: { firstName: 'Priya', lastName: 'Raman', primaryEmail: 'priya@acme.test' },
  });
  contactId = (contact.json() as { contact: { id: string } }).contact.id;
  // Body storage on, under legal hold so the fixed fixture date never ages out of retention.
  await ctx.db.insert(outreachConfig).values({ orgId, policy: { storeBodies: true, bodyLegalHold: true } });
  gmailEntryId = await ingest();
  // Control: another provider's mailbox read is not Google user data.
  await ingest({ provider: 'outlook', subject: 'OUTLOOKREAD-subject', preview: 'OUTLOOKREAD-snippet', bodyText: 'OUTLOOKREAD-body' });
  // Control: an email a person logged by hand. No outreach_messages row.
  const logged = await ctx.app.inject({
    method: 'POST',
    url: `/v1/orgs/${orgId}/crm/timeline`,
    headers: owner.headers,
    payload: {
      kind: 'email',
      direction: 'inbound',
      title: 'MANUALEMAIL-subject',
      body: 'MANUALEMAIL-body',
      occursAt: '2026-08-11T14:05:00.000Z',
      visibility: 'org',
      links: [{ subjectKind: 'contact', subjectId: contactId }],
    },
  });
  if (logged.statusCode !== 201) throw new Error(`log failed: ${logged.body}`);
  manualEntryId = (logged.json() as { entry: { id: string } }).entry.id;
});

it('fixture: ingest recorded the Gmail message as mailbox-read, org-visible, with no project', async () => {
  // If ingest stopped writing these, every absence below would prove nothing.
  const [row] = await ctx.db.select().from(outreachMessages).where(eq(outreachMessages.timelineEntryId, gmailEntryId));
  expect(row).toMatchObject({ provider: 'gmail', provenance: 'mailbox-read', contactId });
  const timeline = await get(owner.headers, `/v1/orgs/${orgId}/crm/contacts/${contactId}/timeline`);
  expect(timeline.body).toContain(GMAIL_SUBJECT);
});

describe('CRM notes read (the bot read of a record)', () => {
  const url = () => `/v1/orgs/${orgId}/crm/records/contact/${contactId}/notes`;

  it('an org API key gets the hand-logged email and the Outlook read, never the Gmail message', async () => {
    const res = await get(await mintKey(), url());
    expect(res.statusCode, res.body).toBe(200);
    expect(res.body).toContain('MANUALEMAIL-body');
    expect(res.body).toContain('OUTLOOKREAD-snippet');
    expect(res.body).not.toContain('GMAILSUBJECT-91c2');
    expect(res.body).not.toContain('GMAILSNIPPET-91c2');
  });

  it('leaves Gmail out for a session too: the route exists for bots', async () => {
    const res = await get(owner.headers, url());
    expect(res.statusCode, res.body).toBe(200);
    expect(res.body).toContain('MANUALEMAIL-body');
    expect(res.body).not.toContain('GMAILSNIPPET-91c2');
  });
});

describe('CRM timeline reads', () => {
  const urls = () => [
    `/v1/orgs/${orgId}/crm/contacts/${contactId}/timeline`,
    `/v1/orgs/${orgId}/crm/contacts/${contactId}`,
    `/v1/orgs/${orgId}/crm/timeline`,
  ];

  it('a person signed in to the app sees the Gmail message (control)', async () => {
    for (const url of urls()) {
      const res = await get(owner.headers, url);
      expect(res.statusCode, `${url} ${res.body}`).toBe(200);
      expect(res.body, url).toContain(GMAIL_SNIPPET);
    }
  });

  it('an MCP tool call never receives it, and still receives the other entries', async () => {
    for (const url of urls()) {
      const res = await get(asMcp(owner.headers), url);
      expect(res.statusCode, `${url} ${res.body}`).toBe(200);
      expect(res.body, url).not.toContain('GMAILSUBJECT-91c2');
      expect(res.body, url).not.toContain('GMAILSNIPPET-91c2');
      expect(res.body, url).toContain('MANUALEMAIL-body');
      expect(res.body, url).toContain('OUTLOOKREAD-snippet');
    }
  });
});

describe('editing or archiving a timeline entry (both return the entry)', () => {
  const patch = (headers: Headers, id: string) =>
    ctx.app.inject({ method: 'PATCH', url: `/v1/orgs/${orgId}/crm/timeline/${id}`, headers, payload: { title: 'RENAMED' } });
  const archive = (headers: Headers, id: string) =>
    ctx.app.inject({ method: 'POST', url: `/v1/orgs/${orgId}/crm/timeline/${id}/archive`, headers });

  it('is a 404 for an MCP call on a Gmail entry, which stays unchanged', async () => {
    expect((await patch(asMcp(owner.headers), gmailEntryId)).statusCode).toBe(404);
    expect((await archive(asMcp(owner.headers), gmailEntryId)).statusCode).toBe(404);
    const timeline = await get(owner.headers, `/v1/orgs/${orgId}/crm/contacts/${contactId}/timeline`);
    expect(timeline.body).toContain(GMAIL_SUBJECT);
    expect(timeline.body).not.toContain('RENAMED');
  });

  it('still works for an MCP call on a hand-logged entry, and for a person on the Gmail entry (controls)', async () => {
    const mcp = await patch(asMcp(owner.headers), manualEntryId);
    expect(mcp.statusCode, mcp.body).toBe(200);
    const person = await patch(owner.headers, gmailEntryId);
    expect(person.statusCode, person.body).toBe(200);
    expect(person.body).toContain('RENAMED');
  });
});

describe('outreach conversation history and unmatched mail', () => {
  it('an org API key gets the history without the Gmail message or its stored body; a person gets all of it', async () => {
    const url = `/v1/orgs/${orgId}/outreach/conversations?recordId=${contactId}&kind=person`;
    const person = await get(owner.headers, url);
    expect(person.statusCode, person.body).toBe(200);
    expect(person.body).toContain(GMAIL_SNIPPET);
    expect(person.body).toContain(GMAIL_BODY);
    const bot = await get(await mintKey(), url);
    expect(bot.statusCode, bot.body).toBe(200);
    expect(bot.body).not.toContain('GMAILSNIPPET-91c2');
    expect(bot.body).not.toContain('GMAILBODY-91c2');
    expect(bot.body).not.toContain('GMAILSUBJECT-91c2');
    expect(bot.body).toContain('OUTLOOKREAD-snippet');
    expect(bot.body).toContain('MANUALEMAIL-body');
  });

  it('unmatched Gmail mail stays out of the queue for an MCP call; the person sees it', async () => {
    await ingest({
      headers: { 'Message-ID': '<stranger-9@elsewhere.test>', From: 'Stranger <who@elsewhere.test>' },
      subject: 'STRANGERGMAIL-subject',
      preview: 'STRANGERGMAIL-snippet',
    });
    await ingest({
      provider: 'outlook',
      headers: { 'Message-ID': '<stranger-10@elsewhere.test>', From: 'Stranger <who2@elsewhere.test>' },
      subject: 'STRANGEROUTLOOK-subject',
      preview: 'STRANGEROUTLOOK-snippet',
    });
    const url = `/v1/orgs/${orgId}/outreach/queue`;
    const person = await get(owner.headers, url);
    expect(person.statusCode, person.body).toBe(200);
    expect(person.body).toContain('STRANGERGMAIL-snippet');
    const mcp = await get(asMcp(owner.headers), url);
    expect(mcp.statusCode, mcp.body).toBe(200);
    expect(mcp.body).not.toContain('STRANGERGMAIL');
    expect(mcp.body).toContain('STRANGEROUTLOOK-snippet');
  });
});

describe('the combined inbox', () => {
  it('is a 404 for an MCP call, as it already is for a key; a person still opens it', async () => {
    const url = `/v1/orgs/${orgId}/inbox/threads`;
    const person = await get(owner.headers, url);
    expect(person.statusCode, person.body).toBe(200);
    expect((await get(asMcp(owner.headers), url)).statusCode).toBe(404);
  });
});

describe('reply-assist drafts', () => {
  it('a draft answering a Gmail reply is dropped for an MCP call; a person still sees its inbound text', async () => {
    const [project] = await ctx.db.select().from(projects).where(eq(projects.id, projectId));
    await ctx.db
      .update(projects)
      .set({
        settings: {
          ...(project!.settings as Record<string, unknown>),
          outreachReplyRules: {
            rule: {
              sequenceId: '00000000-0000-4000-8000-000000000001',
              mode: 'notify',
              provider: 'gmail',
              mailbox: 'owner-mailbox@example.test',
              ownerUserId: owner.user.id,
            },
          },
        },
      })
      .where(eq(projects.id, projectId));
    await ingest({
      subject: 'Re: hello',
      preview: 'REPLYSNIPPET-91c2',
      reply: { text: 'REPLYTEXT-91c2 send me the price sheet', complete: true },
    });
    const drafts = await ctx.db.select().from(outreachReplyDrafts).where(eq(outreachReplyDrafts.orgId, orgId));
    // Fixture guard: the real reply path wrote the draft and it carries the Gmail text.
    expect(drafts).toHaveLength(1);
    expect(JSON.stringify(drafts[0]!.content)).toContain('REPLYTEXT-91c2');
    const url = `/v1/orgs/${orgId}/outreach/projects/${projectId}/replies`;
    const person = await get(owner.headers, url);
    expect(person.statusCode, person.body).toBe(200);
    expect(person.body).toContain('REPLYTEXT-91c2');
    const mcp = await get(asMcp(owner.headers), url);
    expect(mcp.statusCode, mcp.body).toBe(200);
    expect(mcp.body).not.toContain('REPLYTEXT-91c2');
  });
});

describe('who counts as an agent', () => {
  it('keys, user tokens and MCP calls are agents; a person is not; a forged marker is not trusted', () => {
    expect(gmailContentWithheldFrom({ headers: {} }, { apiKeyId: 'k' })).toBe(true);
    expect(gmailContentWithheldFrom({ headers: {} }, { userTokenId: 't' })).toBe(true);
    expect(gmailContentWithheldFrom({ headers: mcpDispatchHeaders() }, {})).toBe(true);
    expect(gmailContentWithheldFrom({ headers: {} }, {})).toBe(false);
    expect(gmailContentWithheldFrom({ headers: { 'x-goodqa-mcp': 'f'.repeat(64) } }, {})).toBe(false);
  });

  it('callInternal stamps the marker inside an MCP request and not outside one', async () => {
    // Outside is what a person's composite route re-dispatch looks like: it must stay a person's read.
    const seen: Array<Record<string, string>> = [];
    const fake = { inject: async (opts: { headers: Record<string, string> }) => { seen.push(opts.headers); return { statusCode: 200, body: '{}' }; } };
    const tool = { app: fake, authorizationHeader: 'Bearer x', remoteAddress: '127.0.0.1' } as unknown as ToolCallContext;
    await withMcpDispatch(() => callInternal(tool, 'GET', '/v1/whoami'));
    await callInternal(tool, 'GET', '/v1/whoami');
    expect(isMcpDispatch(seen[0]!)).toBe(true);
    expect(isMcpDispatch(seen[1]!)).toBe(false);
  });

  it('through the real /v1/mcp transport, call_api with a person\'s session never returns the Gmail message', async () => {
    const url = `/v1/orgs/${orgId}/crm/contacts/${contactId}/timeline`;
    // Control: the same person, the same route, outside MCP.
    expect((await get(owner.headers, url)).body).toContain(GMAIL_SNIPPET);
    const res = await ctx.app.inject({
      method: 'POST',
      url: '/v1/mcp',
      headers: { ...owner.headers, accept: 'application/json, text/event-stream' },
      payload: { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'call_api', arguments: { method: 'GET', path: url } } },
    });
    expect(res.statusCode, res.body).toBe(200);
    // The tool really ran and read the timeline: the hand-logged email is in the result.
    expect(res.body).toContain('MANUALEMAIL-body');
    expect(res.body).not.toContain('GMAILSNIPPET-91c2');
    expect(res.body).not.toContain('GMAILSUBJECT-91c2');
  });
});

describe('goodqa#15561 S1e-a: a desktop session started from a user token (bound door)', () => {
  it('reads contact detail and timeline but never receives the Gmail message, and still receives the other entries', async () => {
    await enableUserTokensForTests(ctx.db);
    const step = await ctx.app.inject({ method: 'POST', url: '/v1/auth/webauthn/step-up', headers: owner.headers, payload: { method: 'password', password: 'password123', purpose: 'user_tokens_manage' } });
    const minted = await ctx.app.inject({ method: 'POST', url: '/v1/me/user-tokens', headers: owner.headers, payload: { name: 'gmail bound', abilities: ['desktop_signin', 'read', 'crm'], requireHumanApproval: false, stepUpToken: step.json().stepUpToken } });
    expect(minted.statusCode, minted.body).toBe(201);
    const start = await ctx.app.inject({ method: 'POST', url: '/v1/me/desktop-session', headers: { authorization: `Bearer ${minted.json().token}` }, payload: { client: 'desktop-ctl' } });
    expect(start.statusCode, start.body).toBe(200);
    const session = { authorization: `Bearer ${start.json().tokens.accessToken}` };
    for (const url of [`/v1/orgs/${orgId}/crm/contacts/${contactId}/timeline`, `/v1/orgs/${orgId}/crm/contacts/${contactId}`]) {
      const res = await get(session, url);
      expect(res.statusCode, `${url} ${res.body}`).toBe(200);
      expect(res.body, url).toContain('MANUALEMAIL-body');
      expect(res.body, url).not.toContain('GMAILSUBJECT-91c2');
      expect(res.body, url).not.toContain('GMAILSNIPPET-91c2');
      // positive control: the signed-in owner sees the Gmail message on the same route
      expect((await get(owner.headers, url)).body, url).toContain(GMAIL_SNIPPET);
    }
  });
});
