#!/usr/bin/env python3
"""goodqa#14903 K2 API: idempotent, lock-bounded AI thread create. Patches ~/wt/q3-kimi-create (arg 1 = worktree)."""
import pathlib, sys

root = pathlib.Path(sys.argv[1])


def sub(path, old, new, count=1):
    p = root / path
    s = p.read_text()
    if s.count(old) != count:
        sys.exit(f'PATCH_MISS {path}: expected {count} of {old[:70]!r}, found {s.count(old)}')
    p.write_text(s.replace(old, new))


L = 'apps/api/src/modules/messaging/ai-thread-lifecycle.ts'
sub(L, "import { and, eq, gte, sql } from 'drizzle-orm';",
    "import { and, eq, gte, isNull, sql } from 'drizzle-orm';")
sub(L, "  aiThreads,\n  chatConversations,\n  chatConversationMembers,",
    "  aiThreads,\n  chatConversations,\n  chatConversationMembers,\n  chatMessages,")
sub(L, "import { Errors } from '../../lib/errors';",
    "import { AppError, Errors, driverError, isUniqueViolation } from '../../lib/errors';\n"
    "import { prepareConversationCredentialBody } from '../credential-guard/service';")
sub(L, "import { appendMessage } from './messages';",
    "import { appendMessage, messageRequestHash } from './messages';\n"
    "\n"
    "/**\n"
    " * goodqa#14903 K2 (Kimi create-hang). A create may carry `clientRequestId`: the same request sent again (a retry\n"
    " * after a lost response, a double submit, a reopen-and-resend) replays the thread it already made instead of making\n"
    " * a second one. The key is stored as the first message's `client_msg_id` (unique per author), looked up under the\n"
    " * per-user advisory lock below, so two racing retries serialize. The lock wait is bounded so a retry queued behind a\n"
    " * stuck original fails fast as a retryable 409 instead of hanging for the whole request deadline.\n"
    " */\n"
    "export const CREATE_LOCK_TIMEOUT_MS = 5_000;\n"
    "const conflict = () => new AppError(409, 'client_request_conflict', 'That request ID was already used for a different request');\n"
    "const inProgress = () => new AppError(409, 'create_in_progress', 'Still starting your last thread. Try again in a moment.');\n"
    "\n"
    "/** The request identity, computed exactly as appendMessage computes a message's `client_request_hash`. */\n"
    "async function createRequestHash(db: DbOrTx, conversationId: string, message: string) {\n"
    "  const prepared = await prepareConversationCredentialBody(db, conversationId, message);\n"
    "  return messageRequestHash({ body: prepared.body, urgency: 'normal', mentions: [], attachmentIds: [], linkedIssueIds: [], linkedMeetingIds: [] });\n"
    "}\n")

# Signature, validation, bounded lock, lookup + replay.
sub(L, "  input: { projectId?: string; title?: string; message?: string },\n) {\n  return db.transaction(async (tx) => {\n    // A guest may create in a live project, but never an org-level General thread.",
    "  input: { projectId?: string; title?: string; message?: string; clientRequestId?: string },\n"
    "  options: { lockTimeoutMs?: number } = {},\n"
    ") {\n"
    "  const key = input.clientRequestId;\n"
    "  if (key !== undefined) {\n"
    "    if (!input.message) throw Errors.badRequest('clientRequestId needs a message');\n"
    "    if (input.title !== undefined) throw new AppError(400, 'client_request_title_unsupported', 'A title cannot be combined with clientRequestId');\n"
    "  }\n"
    "  const lockTimeoutMs = Math.max(1, Math.trunc(options.lockTimeoutMs ?? CREATE_LOCK_TIMEOUT_MS));\n"
    "  try {\n"
    "    return await createAiThreadTx(db, userId, orgId, input, key, lockTimeoutMs);\n"
    "  } catch (error) {\n"
    "    // A concurrent ordinary send with the same author and key, committed or in flight, surfaces here.\n"
    "    if (key !== undefined && isUniqueViolation(error, 'chat_messages_client_msg_uq')) throw conflict();\n"
    "    throw error;\n"
    "  }\n"
    "}\n"
    "\n"
    "async function createAiThreadTx(\n"
    "  db: Db,\n"
    "  userId: string,\n"
    "  orgId: string,\n"
    "  input: { projectId?: string; title?: string; message?: string },\n"
    "  key: string | undefined,\n"
    "  lockTimeoutMs: number,\n"
    "): Promise<{ conversation: typeof chatConversations.$inferSelect; thread: typeof aiThreads.$inferSelect | undefined; message: typeof chatMessages.$inferSelect | null; replayed: boolean }> {\n"
    "  return db.transaction(async (tx) => {\n"
    "    // A guest may create in a live project, but never an org-level General thread.")
sub(L, "    // Serialize the per-user limit across processes; an API-instance limit alone is insufficient.\n"
       "    await tx.execute(\n"
       "      sql`select pg_advisory_xact_lock(hashtextextended(${`ai-thread:${orgId}:${userId}`}, 0))`,\n"
       "    );\n",
    "    // Serialize the per-user limit across processes; an API-instance limit alone is insufficient.\n"
    "    // K2: with a key, the wait for this lock (and only this statement) is bounded; the timeout is restored to the\n"
    "    // configured default right after, so later lock waits in this transaction keep their normal behaviour.\n"
    "    if (key !== undefined) await tx.execute(sql.raw(`set local lock_timeout = '${lockTimeoutMs}ms'`));\n"
    "    try {\n"
    "      await tx.execute(\n"
    "        sql`select pg_advisory_xact_lock(hashtextextended(${`ai-thread:${orgId}:${userId}`}, 0))`,\n"
    "      );\n"
    "    } catch (error) {\n"
    "      if (key !== undefined && driverError(error)?.code === '55P03') throw inProgress();\n"
    "      throw error;\n"
    "    }\n"
    "    if (key !== undefined) {\n"
    "      await tx.execute(sql`set local lock_timeout = default`);\n"
    "      // Read directly, not through the history predicate: a row the caller can no longer see must still be found.\n"
    "      const [prior] = await tx.select().from(chatMessages)\n"
    "        .where(and(eq(chatMessages.authorId, userId), eq(chatMessages.clientMsgId, key))).limit(1);\n"
    "      if (prior) return replayOrConflict(tx, userId, orgId, input, prior);\n"
    "    }\n")
sub(L, "          clientMsgId: null,\n          attachmentIds: [],\n          linkedIssueIds: [],\n          linkedMeetingIds: [],\n        })\n      : null;\n    return { conversation, thread, message: sent?.message ?? null };\n  });\n}",
    "          clientMsgId: key ?? null,\n          attachmentIds: [],\n          linkedIssueIds: [],\n          linkedMeetingIds: [],\n        }).catch((error: unknown) => {\n"
    "          // appendMessage's own reuse-with-different-content 409: one conflict code for this route.\n"
    "          if (key !== undefined && error instanceof AppError && error.statusCode === 409) throw conflict();\n"
    "          throw error;\n"
    "        })\n"
    "      : null;\n"
    "    // appendMessage replays a prior message from ANY conversation of this author: a key an ordinary send used\n"
    "    // between our lookup and this insert must not attach a foreign message to the new thread.\n"
    "    if (key !== undefined && sent?.replayed) throw conflict();\n"
    "    return { conversation, thread, message: sent?.message ?? null, replayed: false };\n"
    "  });\n"
    "}\n"
    "\n"
    "/** A prior message with this key exists: replay only the caller's own AI thread for the same request. */\n"
    "async function replayOrConflict(\n"
    "  tx: DbOrTx,\n"
    "  userId: string,\n"
    "  orgId: string,\n"
    "  input: { projectId?: string; message?: string },\n"
    "  prior: typeof chatMessages.$inferSelect,\n"
    ") {\n"
    "  if (prior.deletedAt !== null || !prior.conversationId) throw conflict();\n"
    "  const [thread] = await tx.select().from(aiThreads)\n"
    "    .where(and(eq(aiThreads.conversationId, prior.conversationId), eq(aiThreads.orgId, orgId), eq(aiThreads.ownerUserId, userId), eq(aiThreads.threadType, 'general')))\n"
    "    .limit(1);\n"
    "  if (!thread) throw conflict();\n"
    "  const [conversation] = await tx.select().from(chatConversations)\n"
    "    .where(and(eq(chatConversations.id, prior.conversationId), isNull(chatConversations.deletedAt))).limit(1);\n"
    "  if (!conversation || (conversation.projectId ?? null) !== (input.projectId ?? null)) throw conflict();\n"
    "  if (prior.clientRequestHash !== (await createRequestHash(tx, conversation.id, input.message!))) throw conflict();\n"
    "  try {\n"
    "    await requireConversationAccess(tx, userId, orgId, conversation.id);\n"
    "  } catch {\n"
    "    throw conflict();\n"
    "  }\n"
    "  return { conversation, thread, message: prior, replayed: true };\n"
    "}")

R = 'apps/api/src/modules/messaging/routes.ts'
sub(R, "message: z.string().trim().min(1).max(20_000).optional() }).strict() } }, async (req, reply) => {\n"
       "    const auth = requireAuth(req);\n"
       "    const result = await createAiThread(app.db, auth.userId, req.params.orgId, req.body);\n"
       "    return reply.code(201).send({ conversation: { ...result.conversation, ai: aiSummary(result.thread) }, message: result.message });",
    "message: z.string().trim().min(1).max(20_000).optional(), clientRequestId: z.uuid().optional() }).strict() } }, async (req, reply) => {\n"
    "    const auth = requireAuth(req);\n"
    "    const result = await createAiThread(app.db, auth.userId, req.params.orgId, req.body);\n"
    "    // goodqa#14903 K2: a replay of the same clientRequestId is 200 with `replayed: true`; a fresh create stays 201.\n"
    "    return reply.code(result.replayed ? 200 : 201).send({ conversation: { ...result.conversation, ai: aiSummary(result.thread) }, message: result.message, ...(result.replayed ? { replayed: true } : {}) });")
print('PATCHED')
