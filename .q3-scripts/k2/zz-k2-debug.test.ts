import { afterAll, beforeAll, beforeEach, it } from 'vitest';
import { eq } from 'drizzle-orm';
import { randomUUID } from 'node:crypto';
import { commanderSettings, platformSettings } from '@bugtracker/db';
import { createOrg, createTestApp, resetDb, signupUser, type TestContext } from './helpers';
import { canonicalCommander } from './commander-fixture';
import { createAiThread } from '../src/modules/messaging/ai-thread-lifecycle';

// Throwaway (goodqa#14903 K2): print the error a replay raises. Never committed.
let ctx: TestContext;
beforeAll(async () => { ctx = await createTestApp(); });
afterAll(async () => { await ctx.close(); });
beforeEach(async () => { await resetDb(ctx.db); });

it('prints the replay error', async () => {
  const owner = await signupUser(ctx.app, { name: 'Owner' });
  const org = await createOrg(ctx.app, owner.headers, 'Dbg');
  await canonicalCommander(ctx, org.id, owner.user.id);
  await ctx.db.insert(platformSettings).values({ key: 'commander.threads', value: true, valueType: 'boolean', updatedBy: owner.user.id, reason: 'dbg' })
    .onConflictDoUpdate({ target: platformSettings.key, set: { value: true } });
  await ctx.db.update(commanderSettings).set({ threadsEnabled: true }).where(eq(commanderSettings.orgId, org.id));
  const key = randomUUID();
  await createAiThread(ctx.db, owner.user.id, org.id, { message: 'Plan', clientRequestId: key });
  try {
    await createAiThread(ctx.db, owner.user.id, org.id, { message: 'Plan', clientRequestId: key });
    process.stderr.write('DBG NO_ERROR\n');
  } catch (e) {
    const x = e as { name?: string; message?: string; cause?: { message?: string }; stack?: string };
    process.stderr.write(`DBG_ERR ${x.name} | ${x.message} | ${x.cause?.message} | ${String(x.stack).split('\n').slice(0, 8).join(' || ')}\n`);
  }
});
