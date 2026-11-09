#!/usr/bin/env python3
"""goodqa#14903 K2 red-team fixes, API side (RT-1, RT-5, RT-6). Run from the repo root on claude/qac-kimi-create."""
import sys

F = 'apps/api/src/modules/messaging/ai-thread-lifecycle.ts'


def sub(s: str, old: str, new: str) -> str:
    if s.count(old) != 1:
        sys.exit(f'anchor x{s.count(old)}: {old[:70]!r}')
    return s.replace(old, new)


s = open(F).read()
s = sub(s, "import { requireConversationAccess } from './access';",
        "import { requireConversationAccess } from './access';\nimport { assertMessageHistoryReadable } from './history-floor';")
# RT-5: a non-finite option is a programming error, never a 'NaNms' SQL error.
s = sub(s, "  const lockTimeoutMs = Math.max(1, Math.trunc(options.lockTimeoutMs ?? CREATE_LOCK_TIMEOUT_MS));",
        """  const requested = options.lockTimeoutMs ?? CREATE_LOCK_TIMEOUT_MS;
  if (!Number.isFinite(requested)) throw new Error('lockTimeoutMs must be a finite number');
  const lockTimeoutMs = Math.max(1, Math.trunc(requested));""")
# RT-5: bound value, and restore exactly what was in effect before (not the server default).
s = sub(s, """    // K2: with a key, the wait for this lock (and only this statement) is bounded; the timeout is restored to the
    // configured default right after, so later lock waits in this transaction keep their normal behaviour.
    if (key !== undefined) await tx.execute(sql.raw(`set local lock_timeout = '${lockTimeoutMs}ms'`));""",
        """    // K2: with a key, the wait for this lock (and only this statement) is bounded; the timeout in effect before is
    // restored right after, so later lock waits in this transaction keep their normal behaviour.
    let priorLockTimeout: string | undefined;
    if (key !== undefined) {
      const rows = await tx.execute(sql`select current_setting('lock_timeout') as value`);
      priorLockTimeout = String((rows as unknown as Array<{ value: string }>)[0]?.value ?? '0');
      await tx.execute(sql`select set_config('lock_timeout', ${`${lockTimeoutMs}ms`}, true)`);
    }""")
s = sub(s, "      await tx.execute(sql`set local lock_timeout = default`);",
        "      await tx.execute(sql`select set_config('lock_timeout', ${priorLockTimeout ?? '0'}, true)`);")
# RT-1 + RT-6: replay only the thread's first message, and only if the caller may still read it.
s = sub(s, """  try {
    await requireConversationAccess(tx, userId, orgId, conversation.id);
  } catch {
    throw conflict();
  }
  return { conversation, thread, message: prior, replayed: true };""",
        """  // The key names the thread's FIRST message; a later message that reused it is not this create.
  const [first] = await tx.select({ seq: sql<number>`min(${chatMessages.seq})` }).from(chatMessages)
    .where(eq(chatMessages.conversationId, conversation.id));
  if (prior.seq === null || Number(first?.seq) !== Number(prior.seq)) throw conflict();
  try {
    await requireConversationAccess(tx, userId, orgId, conversation.id);
    // Membership alone is not enough: a raised history floor hides the message from this caller.
    await assertMessageHistoryReadable(tx, conversation.id, prior.seq, userId);
  } catch {
    throw conflict();
  }
  return { conversation, thread, message: prior, replayed: true };""")
open(F, 'w').write(s)
print('K2_RT_API_FIXED')
