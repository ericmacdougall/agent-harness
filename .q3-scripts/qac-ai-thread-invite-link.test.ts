import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { and, eq } from 'drizzle-orm';
import { chatConversationMembers, commanderSettings, inviteLinks, orgMembers, platformSettings } from '@bugtracker/db';
import { createOrg, createTestApp, resetDb, signupUser, uniqueEmail, type TestContext } from './helpers';
import { canonicalCommander } from './commander-fixture';
import { sha256 } from '../src/lib/tokens';

/**
 * goodqa#14903 (Kimi finding qac-privacy-001). A QAC AI thread is stored as a private `channel`
 * conversation, so the channel invite-link route accepted it: an org admin could mint a reusable link
 * that adds anyone to the org AND into the private thread, skipping the thread's own share flow with
 * its history choice. AI threads are shared only through the AI thread share route; an invite link can
 * neither be minted for one nor, if it already exists, admit anyone into one.
 */
let ctx: TestContext;
beforeAll(async () => { ctx = await createTestApp(); });
afterAll(async () => { await ctx.close(); });
beforeEach(async () => { await resetDb(ctx.db); });

async function world() {
  const owner = await signupUser(ctx.app, { name: 'Owner' });
  const org = await createOrg(ctx.app, owner.headers, 'Private threads');
  await canonicalCommander(ctx, org.id, owner.user.id);
  await ctx.db.insert(platformSettings).values({ key: 'commander.threads', value: true, valueType: 'boolean', updatedBy: owner.user.id, reason: 'goodqa#14903 fixture' })
    .onConflictDoUpdate({ target: platformSettings.key, set: { value: true } });
  await ctx.db.update(commanderSettings).set({ threadsEnabled: true }).where(eq(commanderSettings.orgId, org.id));
  const created = await ctx.app.inject({ method: 'POST', url: `/v1/orgs/${org.id}/ai-threads`, headers: owner.headers, payload: {} });
  expect(created.statusCode, created.body).toBe(201);
  const threadId = (created.json() as { conversation: { id: string } }).conversation.id;
  return { owner, org, threadId };
}
const mint = (h: Record<string, string>, orgId: string, payload: object) =>
  ctx.app.inject({ method: 'POST', url: `/v1/orgs/${orgId}/invite-links`, headers: h, payload });

describe('invite links never reach a private QAC AI thread', () => {
  it('refuses to mint a link for an AI thread, and stores no link', async () => {
    const { owner, org, threadId } = await world();
    const res = await mint(owner.headers, org.id, { orgRole: 'member', conversationId: threadId });
    expect(res.statusCode, res.body).toBe(400);
    expect(res.json().error?.message ?? res.body).toMatch(/AI thread/i);
    expect(await ctx.db.select().from(inviteLinks).where(eq(inviteLinks.conversationId, threadId))).toHaveLength(0);
  });

  it('a link that already points at an AI thread admits nobody into it', async () => {
    const { owner, org, threadId } = await world();
    const raw = 'goodqa-14903-preexisting-ai-thread-link-token';
    await ctx.db.insert(inviteLinks).values({ orgId: org.id, conversationId: threadId, orgRole: 'member', tokenHash: sha256(raw),
      expiresAt: new Date(Date.now() + 86_400_000), createdBy: owner.user.id });
    const guest = await signupUser(ctx.app, { email: uniqueEmail('guest') });
    const accepted = await ctx.app.inject({ method: 'POST', url: '/v1/invites/accept', headers: guest.headers, payload: { token: raw } });
    expect(accepted.statusCode, accepted.body).toBe(400);
    expect(await ctx.db.select().from(chatConversationMembers).where(and(eq(chatConversationMembers.conversationId, threadId), eq(chatConversationMembers.userId, guest.user.id)))).toHaveLength(0);
    expect(await ctx.db.select().from(orgMembers).where(and(eq(orgMembers.orgId, org.id), eq(orgMembers.userId, guest.user.id)))).toHaveLength(0);
  });

  it('positive control: a private channel the creator belongs to still mints a link', async () => {
    const { owner, org } = await world();
    const ch = await ctx.app.inject({ method: 'POST', url: `/v1/orgs/${org.id}/chat/channels`, headers: owner.headers,
      payload: { name: 'secret-room', visibility: 'private', memberUserIds: [] } });
    expect(ch.statusCode, ch.body).toBeLessThan(300);
    const res = await mint(owner.headers, org.id, { orgRole: 'member', conversationId: (ch.json() as { conversation: { id: string } }).conversation.id });
    expect(res.statusCode, res.body).toBe(201);
  });
});
