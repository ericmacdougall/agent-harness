import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { and, eq, sql } from 'drizzle-orm';
import { randomUUID } from 'node:crypto';
import { aiThreads, chatConversationMembers, chatConversations, chatMessages, commanderSettings, organizations, orgMembers, platformSettings, qacTurns } from '@bugtracker/db';
import { createOrg, createTestApp, resetDb, signupUser, type TestContext } from './helpers';
import { canonicalCommander } from './commander-fixture';
import { createAiThread, updateAiThread } from '../src/modules/messaging/ai-thread-lifecycle';

/**
 * goodqa#14903 K2 (Kimi create-hang): POST /v1/orgs/:orgId/ai-threads with an optional clientRequestId is idempotent.
 * The key is stored as the first message's client_msg_id; the lookup runs under the per-user ai-thread advisory lock;
 * a match in the caller's own AI thread with the same request replays it (200, replayed: true, nothing new); any other
 * match is 409 client_request_conflict with no detail. The lock wait is bounded (409 create_in_progress).
 */
let ctx: TestContext;
beforeAll(async () => { ctx = await createTestApp(); });
afterAll(async () => { await ctx.close(); });
beforeEach(async () => { await resetDb(ctx.db); });

async function enableThreads(orgId: string, userId: string) {
  await canonicalCommander(ctx, orgId, userId);
  await ctx.db.insert(platformSettings).values({ key: 'commander.threads', value: true, valueType: 'boolean', updatedBy: userId, reason: 'goodqa#14903 K2 fixture' })
    .onConflictDoUpdate({ target: platformSettings.key, set: { value: true } });
  await ctx.db.update(commanderSettings).set({ threadsEnabled: true }).where(eq(commanderSettings.orgId, orgId));
}
async function world() {
  const owner = await signupUser(ctx.app, { name: 'Owner' });
  const org = await createOrg(ctx.app, owner.headers, 'K2 threads');
  await enableThreads(org.id, owner.user.id);
  return { owner, org };
}
const post = (headers: Record<string, string>, orgId: string, payload: object) =>
  ctx.app.inject({ method: 'POST', url: `/v1/orgs/${orgId}/ai-threads`, headers, payload });
async function counts() {
  const one = async (table: typeof aiThreads | typeof chatConversations | typeof chatMessages | typeof chatConversationMembers | typeof qacTurns) =>
    (await ctx.db.select({ n: sql<number>`count(*)::int` }).from(table))[0]!.n;
  return { threads: await one(aiThreads), conversations: await one(chatConversations), messages: await one(chatMessages),
    members: await one(chatConversationMembers), turns: await one(qacTurns) };
}

describe('K2 idempotent AI thread create', () => {
  it('AC-1: a fresh key creates once and the first message carries the key', async () => {
    const { owner, org } = await world();
    const key = randomUUID();
    const res = await post(owner.headers, org.id, { message: 'Plan my week', clientRequestId: key });
    expect(res.statusCode, res.body).toBe(201);
    const body = res.json() as { conversation: { id: string }; message: { id: string }; replayed?: boolean };
    expect(body.replayed ?? false).toBe(false);
    const [msg] = await ctx.db.select().from(chatMessages).where(eq(chatMessages.id, body.message.id));
    expect(msg!.clientMsgId).toBe(key);
    expect(msg!.conversationId).toBe(body.conversation.id);
  });

  it('AC-2: the same request replays the original and writes nothing', async () => {
    const { owner, org } = await world();
    const key = randomUUID();
    const first = await post(owner.headers, org.id, { message: 'Plan my week', clientRequestId: key });
    expect(first.statusCode, first.body).toBe(201);
    const id = (first.json() as { conversation: { id: string } }).conversation.id;
    const before = await counts();
    const [seqBefore] = await ctx.db.select({ lastSeq: chatConversations.lastSeq }).from(chatConversations).where(eq(chatConversations.id, id));
    const again = await post(owner.headers, org.id, { message: 'Plan my week', clientRequestId: key });
    expect(again.statusCode, again.body).toBe(200);
    const body = again.json() as { conversation: { id: string; ai?: unknown }; message: { id: string } | null; replayed: boolean };
    expect(body.replayed).toBe(true);
    expect(body.conversation.id).toBe(id);
    expect(body.conversation.ai).toBeTruthy();
    expect(body.message?.id).toBe((first.json() as { message: { id: string } }).message.id);
    expect(await counts()).toEqual(before);
    const [seqAfter] = await ctx.db.select({ lastSeq: chatConversations.lastSeq }).from(chatConversations).where(eq(chatConversations.id, id));
    expect(seqAfter!.lastSeq).toBe(seqBefore!.lastSeq);
  });

  it('AC-3: two concurrent requests with one key make one thread', async () => {
    const { owner, org } = await world();
    const key = randomUUID();
    // Hold the per-user lock so both requests queue behind it, then release: with the lookup under the lock the
    // second sees the first; a lookup taken before the lock would let both create.
    let release!: () => void;
    const gate = new Promise<void>(r => { release = r; });
    let held!: () => void;
    const holding = new Promise<void>(r => { held = r; });
    const holder = ctx.db.transaction(async (tx) => {
      await tx.execute(sql`select pg_advisory_xact_lock(hashtextextended(${`ai-thread:${org.id}:${owner.user.id}`}, 0))`);
      held();
      await gate;
    });
    await holding;
    const a = post(owner.headers, org.id, { message: 'Same', clientRequestId: key });
    const b = post(owner.headers, org.id, { message: 'Same', clientRequestId: key });
    await new Promise(r => setTimeout(r, 300));
    release();
    await holder;
    const [ra, rb] = await Promise.all([a, b]);
    expect([ra.statusCode, rb.statusCode].sort()).toEqual([200, 201]);
    expect((ra.json() as { conversation: { id: string } }).conversation.id).toBe((rb.json() as { conversation: { id: string } }).conversation.id);
    expect((await counts()).threads).toBe(1);
  });

  it('AC-4: a replay is not charged against the hourly limit; a fresh key at the limit is', async () => {
    const { owner, org } = await world();
    for (let i = 0; i < 59; i += 1) await createAiThread(ctx.db, owner.user.id, org.id, {});
    const key = randomUUID();
    expect((await post(owner.headers, org.id, { message: 'Sixtieth', clientRequestId: key })).statusCode).toBe(201);
    expect((await post(owner.headers, org.id, { message: 'Sixtieth', clientRequestId: key })).statusCode).toBe(200);
    expect((await post(owner.headers, org.id, { message: 'Sixty-first', clientRequestId: randomUUID() })).statusCode).toBe(429);
  });

  it('NEG-1, NEG-2: same key with a different message or project is a conflict and writes nothing', async () => {
    const { owner, org } = await world();
    const key = randomUUID();
    expect((await post(owner.headers, org.id, { message: 'One', clientRequestId: key })).statusCode).toBe(201);
    // The project is created before the snapshot: creating a project adds its own conversation.
    const project = await ctx.app.inject({ method: 'POST', url: `/v1/orgs/${org.id}/projects`, headers: owner.headers, payload: { name: 'P', key: 'KTWO' } });
    const projectId = (project.json() as { project: { id: string } }).project.id;
    const before = await counts();
    const other = await post(owner.headers, org.id, { message: 'Two', clientRequestId: key });
    expect(other.statusCode, other.body).toBe(409);
    expect(other.json().error.code).toBe('client_request_conflict');
    const scoped = await post(owner.headers, org.id, { message: 'One', clientRequestId: key, projectId });
    expect(scoped.statusCode, scoped.body).toBe(409);
    expect(await counts()).toEqual(before);
  });

  it('NEG-3: a key already used in an AI thread of another org is a conflict that reveals nothing', async () => {
    const { owner, org } = await world();
    const orgB = await createOrg(ctx.app, owner.headers, 'Other org');
    await enableThreads(orgB.id, owner.user.id);
    const key = randomUUID();
    const first = await post(owner.headers, orgB.id, { message: 'Secret plan', clientRequestId: key });
    expect(first.statusCode, first.body).toBe(201);
    const res = await post(owner.headers, org.id, { message: 'Secret plan', clientRequestId: key });
    expect(res.statusCode, res.body).toBe(409);
    expect(res.body).not.toContain((first.json() as { conversation: { id: string } }).conversation.id);
    expect(res.body).not.toContain('Secret plan');
  });

  it('NEG-4: another user with the same key value creates their own thread', async () => {
    const { owner, org } = await world();
    const other = await signupUser(ctx.app, { name: 'Other' });
    const orgB = await createOrg(ctx.app, other.headers, 'B');
    await enableThreads(orgB.id, other.user.id);
    const key = randomUUID();
    expect((await post(owner.headers, org.id, { message: 'Hi', clientRequestId: key })).statusCode).toBe(201);
    expect((await post(other.headers, orgB.id, { message: 'Hi', clientRequestId: key })).statusCode).toBe(201);
  });

  it('NEG-5: a deleted first message is a conflict (never a 500); an archived thread replays', async () => {
    const { owner, org } = await world();
    const deletedKey = randomUUID();
    const d = await post(owner.headers, org.id, { message: 'Gone', clientRequestId: deletedKey });
    await ctx.db.update(chatMessages).set({ deletedAt: new Date() }).where(eq(chatMessages.id, (d.json() as { message: { id: string } }).message.id));
    const retry = await post(owner.headers, org.id, { message: 'Gone', clientRequestId: deletedKey });
    expect(retry.statusCode, retry.body).toBe(409);
    const archivedKey = randomUUID();
    const a = await post(owner.headers, org.id, { message: 'Old', clientRequestId: archivedKey });
    const id = (a.json() as { conversation: { id: string } }).conversation.id;
    await updateAiThread(ctx.db, owner.user.id, id, { archived: true });
    const replay = await post(owner.headers, org.id, { message: 'Old', clientRequestId: archivedKey });
    expect(replay.statusCode, replay.body).toBe(200);
    expect((replay.json() as { conversation: { id: string } }).conversation.id).toBe(id);
  });

  it('NEG-6, NEG-18: a key without a message, a malformed key, or a key with a title is refused; a title without a key works', async () => {
    const { owner, org } = await world();
    expect((await post(owner.headers, org.id, { clientRequestId: randomUUID() })).statusCode).toBe(400);
    expect((await post(owner.headers, org.id, { message: 'x', clientRequestId: 'not-a-uuid' })).statusCode).toBe(400);
    const titled = await post(owner.headers, org.id, { message: 'x', title: 'T', clientRequestId: randomUUID() });
    expect(titled.statusCode, titled.body).toBe(400);
    expect(titled.json().error.code).toBe('client_request_title_unsupported');
    expect((await post(owner.headers, org.id, { message: 'x', title: 'T' })).statusCode).toBe(201);
  });

  it('NEG-10: a client without a key keeps today\'s behaviour (no dedupe)', async () => {
    const { owner, org } = await world();
    expect((await post(owner.headers, org.id, { message: 'Same' })).statusCode).toBe(201);
    expect((await post(owner.headers, org.id, { message: 'Same' })).statusCode).toBe(201);
    expect((await counts()).threads).toBe(2);
  });

  it('NEG-14: a key the caller already used for an ordinary message elsewhere is a conflict and leaves nothing behind', async () => {
    const { owner, org } = await world();
    const key = randomUUID();
    const t = await post(owner.headers, org.id, { message: 'Thread A' });
    const conversationId = (t.json() as { conversation: { id: string } }).conversation.id;
    const sent = await ctx.app.inject({ method: 'POST', url: `/v1/chat/conversations/${conversationId}/messages`, headers: owner.headers,
      payload: { body: 'Ordinary send', clientMsgId: key } });
    expect(sent.statusCode, sent.body).toBeLessThan(300);
    const before = await counts();
    const res = await post(owner.headers, org.id, { message: 'New thread', clientRequestId: key });
    expect(res.statusCode, res.body).toBe(409);
    expect(res.json().error.code).toBe('client_request_conflict');
    expect(await counts()).toEqual(before);
  });

  it('NEG-15: a retry after the owner lost the thread membership is a conflict', async () => {
    const { owner, org } = await world();
    const key = randomUUID();
    const a = await post(owner.headers, org.id, { message: 'Mine', clientRequestId: key });
    const id = (a.json() as { conversation: { id: string } }).conversation.id;
    await ctx.db.update(chatConversationMembers).set({ isMember: false })
      .where(and(eq(chatConversationMembers.conversationId, id), eq(chatConversationMembers.userId, owner.user.id)));
    const res = await post(owner.headers, org.id, { message: 'Mine', clientRequestId: key });
    expect(res.statusCode, res.body).toBe(409);
    expect(res.body).not.toContain(id);
  });

  it('NEG-16: a retry behind a held lock gets create_in_progress quickly; a later slow lock does not', async () => {
    const { owner, org } = await world();
    let release!: () => void;
    const gate = new Promise<void>(r => { release = r; });
    let held!: () => void;
    const holding = new Promise<void>(r => { held = r; });
    const holder = ctx.db.transaction(async (tx) => {
      await tx.execute(sql`select pg_advisory_xact_lock(hashtextextended(${`ai-thread:${org.id}:${owner.user.id}`}, 0))`);
      held();
      await gate;
    });
    await holding;
    const started = Date.now();
    await expect(createAiThread(ctx.db, owner.user.id, org.id, { message: 'Wait', clientRequestId: randomUUID() }, { lockTimeoutMs: 200 }))
      .rejects.toMatchObject({ statusCode: 409, code: 'create_in_progress' });
    expect(Date.now() - started).toBeLessThan(3000);
    release();
    await holder;
    expect((await counts()).threads).toBe(0);
    // The timeout must not outlive the advisory lock statement: with the lock free, a create whose later work waits
    // longer than the timeout on another lock (here the commander row) still succeeds.
    let release2!: () => void;
    const gate2 = new Promise<void>(r => { release2 = r; });
    let held2!: () => void;
    const holding2 = new Promise<void>(r => { held2 = r; });
    const rowHolder = ctx.db.transaction(async (tx) => {
      await tx.execute(sql`select 1 from chat_conversations limit 0`);
      await tx.execute(sql`lock table qac_turns in share row exclusive mode`);
      held2();
      await gate2;
    });
    await holding2;
    const slow = createAiThread(ctx.db, owner.user.id, org.id, { message: 'Slow later', clientRequestId: randomUUID() }, { lockTimeoutMs: 200 });
    await new Promise(r => setTimeout(r, 600));
    release2();
    await rowHolder;
    await expect(slow).resolves.toMatchObject({ replayed: false });
  });
  it('NEG-13: a message with a credential-shaped string, sent twice with one key, replays (the hash is over the redacted body)', async () => {
    const { owner, org } = await world();
    await ctx.db.update(organizations).set({ entitlementOverrides: { 'chat.credentialGuard': true } }).where(eq(organizations.id, org.id));
    await ctx.db.insert(platformSettings).values({ key: 'chat.credentialGuard', value: true, valueType: 'boolean', updatedBy: owner.user.id, reason: 'goodqa#14903 K2 fixture' })
      .onConflictDoUpdate({ target: platformSettings.key, set: { value: true } });
    const key = randomUUID();
    const message = 'Use token ghp_0123456789abcdefghijklmnop for the deploy';
    const first = await post(owner.headers, org.id, { message, clientRequestId: key });
    expect(first.statusCode, first.body).toBe(201);
    const [stored] = await ctx.db.select({ body: chatMessages.body }).from(chatMessages).where(eq(chatMessages.clientMsgId, key));
    expect(stored!.body).not.toContain('ghp_0123456789abcdefghijklmnop');
    const before = await counts();
    const again = await post(owner.headers, org.id, { message, clientRequestId: key });
    expect(again.statusCode, again.body).toBe(200);
    expect(again.json().replayed).toBe(true);
    expect((again.json() as { conversation: { id: string } }).conversation.id).toBe((first.json() as { conversation: { id: string } }).conversation.id);
    expect(await counts()).toEqual(before);
  });

  it('NEG-7: a caller removed from the org is refused as without a key, never replayed', async () => {
    const { owner, org } = await world();
    const member = await signupUser(ctx.app, { name: 'Member' });
    await ctx.db.insert(orgMembers).values({ orgId: org.id, userId: member.user.id });
    const key = randomUUID();
    expect((await post(member.headers, org.id, { message: 'Mine', clientRequestId: key })).statusCode).toBe(201);
    await ctx.db.delete(orgMembers).where(and(eq(orgMembers.orgId, org.id), eq(orgMembers.userId, member.user.id)));
    const plain = await post(member.headers, org.id, { message: 'Mine' });
    const retry = await post(member.headers, org.id, { message: 'Mine', clientRequestId: key });
    expect([200, 201, 409]).not.toContain(retry.statusCode);
    expect(retry.statusCode).toBe(plain.statusCode);
    expect(retry.json().error.code).toBe(plain.json().error.code);
    void owner;
  });
});
