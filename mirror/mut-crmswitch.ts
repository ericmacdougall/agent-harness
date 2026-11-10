import { getCommanderReleaseSetting } from '@bugtracker/db';
import { isZeroWriteRead } from '../modules/user-tokens/zero-write-reads';
import { isAuditedReadMcpRequest } from '../modules/mcp/audited-read-rpc';
import type {} from '@fastify/cookie';
import { verifyPreviewGrant, type VerifiedPreview } from '../modules/preview-grants/service';
import { bindAiInvocation } from '../lib/ai-invocation';
import { SANITY_SCOPED_DRAFT_ROUTES } from '../modules/cms/sanity-key-policy';
import { SANITY_SCOPED_SETUP_ROUTES } from '../modules/cms/sanity-destination-setup/key-policy';
import { featureCardMediaRouteGrant } from '../modules/feature-cards/media-grants';
import { retireOwnerPersonas } from '../lib/persona-offboarding';
import { timingSafeEqual } from 'node:crypto';
import type { FastifyBaseLogger, FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { and, eq, gt, isNull, sql } from 'drizzle-orm';
import {
  attachments,
  apiKeyPersonas,
  apiKeys,
  auditEvents,
  getPlatformSetting,
  commanderSettings,
  orgAgentPolicy,
  organizations,
  orgMembers,
  runners,
  sessions,
  users,
  type Db,
} from '@bugtracker/db';
import { requestClientIp } from '../lib/client-ip';
import { AppError, Errors } from '../lib/errors';
import { isFeatureEnabled } from '../lib/entitlements';
import { isInProcessDispatch } from '../lib/in-process-dispatch';
import { verifyAccessToken } from '../lib/jwt';
import { contactTimelinesOnForOrg, desktopMintingFingerprint, desktopMintingTokenId, desktopRouteDoor, desktopRouteKey, isSessionOnlyOpened } from '../lib/desktop-token-session';
import { loadBoundUserToken } from '../modules/user-tokens/bound-session';
import {
  keyExpiredError,
  keyIsExpired,
  keyPausedError,
  keyPauseState,
  normalizeClientTrace,
  type ApiKeyClientTrace,
  type KeyPauseState,
} from '../lib/key-lifecycle';
import { setApiKeyBoundProjectId, setApiKeyRunnerPersonaId, setApiKeyMaxOrgRole, setApiKeyMaxProjectRole, setApiKeyOrgId, setRequestActor, getRequestActor } from '../lib/request-context';
import { sha256 } from '../lib/tokens';
import { SESSION_HINT_COOKIE, setSessionHintCookie } from '../modules/auth/session-cookies';
import { afterApiKeyAuthenticated } from '../modules/personas/rail-http';
import { personaDataBindingOpensData } from '../modules/custom-data/persona-binding';
import { delegatesQuotasEnforced, isRunnerKey } from '../modules/personas/enforcement-flag';
import { applyUserTokenRoutePolicy, authenticateUserTokenCredential, authenticateUserTokenRequest, doorDetail, boundRouteClassRefusal, userTokenCredentialEnabled, looksLikeUserToken, READ_ONLY_METHODS, type UserTokenCredential, type UserTokenGateDeps } from '../modules/user-tokens/auth-gate';
import { AGENT_HEADER, requestAgentLabel } from '../lib/request-agent';
import { bindRawCommanderOutboundApproval } from '../modules/qa-commander-runtime/outbound-approval';
import { recordUserTokenEvent, userTokenChainState } from '../modules/user-tokens/service';
import { USER_TOKEN_PREFIX } from '@bugtracker/shared';
import { commanderTurnOpensRoute } from '../lib/commander-turn-routes';

export interface AuthContext {
  userId: string;
  sessionId: string;
  email: string;
  /** Present only for API-key auth; used to enforce read-only keys. */
  apiKeyScopes?: string[];
  /**
   * The org an API key was minted for. Present only for API-key auth, and the
   * hard boundary of what that key may touch: the key acts on behalf of its
   * creator, who is usually a member of OTHER orgs too, so without this the
   * credential would carry their whole identity.
   */
  apiKeyOrgId?: string;
  /** The most authority this key may act with — see api_keys.maxOrgRole. */
  apiKeyMaxOrgRole?: string;
  /**
   * The specific key's row id. Present only for API-key auth (same guard as
   * the three fields above). Distinct from `sessionId` (`apikey:<id>`, a
   * string built for logging/replay-cache keys) so callers that need the raw
   * id for a real FK — attributing a created/updated issue or comment to this
   * key (GoodQA board #58/#59) — get a typed field instead of parsing it back
   * out of `sessionId`.
   */
  apiKeyId?: string;
  /**
   * GoodQA board #37: present only for a `user_scoped` API key — one bound to
   * a specific person so an agent handed the key can only see/act on that
   * person's slice of the org ("this agent can only touch MY tickets"),
   * independent of the key CREATOR's own org-wide role (`apiKeyMaxOrgRole`
   * above still applies on top of this — the two narrow independently).
   *
   * Undefined for every key minted before this feature and every key that
   * never sets `api_keys.scoped_to_user_id` — those behave exactly as
   * before, full visibility within `maxOrgRole`. Enforced at the query layer
   * by each issues route (`issueVisibleToScopedUser` /
   * `scopedUserVisibilitySql` in `apps/api/src/modules/issues/service.ts`),
   * not here — this plugin only resolves WHO the caller is, not what they
   * may see.
   */
  apiKeyScopedToUserId?: string;
  /**
   * Board #37/#380: present (as a real boolean, always) only for API-key
   * auth — `apiKeys.canCreateIssues`, independent of `apiKeyScopes`'s
   * issues:write membership, which still gates every OTHER issue write
   * (comment, field update, attach). Only checked by
   * `POST /projects/:projectId/issues`. Undefined for a real user session,
   * where this restriction does not apply at all.
   */
  apiKeyCanCreateIssues?: boolean;
  /** PLAN S0b: `runner` or `standard` (api_keys.kind). Present only for API-key auth. */
  apiKeyKind?: string;
  /** PLAN S0b: the key's project-role ceiling (api_keys.max_project_role), if any. */
  apiKeyMaxProjectRole?: string;
  /** The key's live (unretired) persona, if it wears one. Stamped on governed rows a key writes (gate verdicts). */
  apiKeyPersonaId?: string;
  apiKeyCustody?: 'org_service';
  /**
   * USER TOKENS, review rva finding 1: present only for an org API key minted (or re-scoped) THROUGH a user token
   * (`api_keys.created_by_user_token_id`). Such a key is never its owner's own personal key, even when scoped to them:
   * the personal-principal rules (machines, notes to self) refuse it, so a token cannot mint itself owner mode.
   */
  apiKeyCreatedByUserTokenId?: string;
  /**
   * USER TOKENS (docs/design/USER-TOKENS.md): present only when the request authenticated with a user token (`gqut_`).
   * The request is then authorized AS the owner (`userId` above, their real `email`), exactly as their own session
   * would be, after the auth gate (modules/user-tokens/auth-gate.ts) intersected the route with these abilities.
   * `sessionId` is `usertoken:<id>`: not a `sessions` row (lib/credential-kind.ts).
   */
  userTokenId?: string;
  userTokenName?: string;
  userTokenAgentLabel?: string | null;
  /** As stored on the token (`['all']` stays `['all']`). */
  userTokenAbilities?: string[];
  /** The token's org allow-list; null = every org the owner belongs to. */
  userTokenOrgIds?: string[] | null;
  userTokenRequireHumanApproval?: boolean;
  userTokenExpiresAt?: Date | null;
  /** The approval request this request spent, when it needed one. */
  userTokenApprovalId?: string;
  /**
   * Ruling 101a: the agent a USER-token request names in `X-GoodQA-Agent` (lib/request-agent.ts). A label only: the
   * write is attributed to this agent acting for `userId` and counts as automation for notifications. Never read for
   * authorization; never set for sessions or API keys.
   */
  requestAgent?: string;
}

declare module 'fastify' {
  interface FastifyContextConfig {
    previewReleaseProtected?: boolean;
  }
  interface FastifyRequest {
    auth: AuthContext | null;
    preview: VerifiedPreview | null;
  }
  interface FastifyInstance {
    /** The preview hook requires the same database decoration supplied by buildApp. */
    db: Db;
    authenticate: (req: FastifyRequest, reply: FastifyReply) => Promise<void>;
    /** The credential-only half of `authenticate`, run in `preValidation` (lib/auth-before-validation.ts, goodqa#8010). */
    authenticatePrecheck: (req: FastifyRequest, reply: FastifyReply) => Promise<void>;
  }
}

function safeEqualHex(a: string, b: string): boolean {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  return bufA.length === bufB.length && timingSafeEqual(bufA, bufB);
}

/** What `authenticateApiKey` hands the `authenticate` hook. */
interface ApiKeyAuthentication {
  ctx: AuthContext;
  /**
   * Non-null while the KILL SWITCH is holding this key (its own pause, or the
   * org-wide pause that covers it). The key is NOT authenticated for anything
   * except the one route `isPausedKeyExemptRoute` names; the caller decides.
   */
  pause: KeyPauseState | null;
  /** Record that the key was used (fire-and-forget). Called by the hook only for a request it serves, so a refused request is not "use". */
  recordUse: () => void;
}

type ApiKeyUseLog = Pick<FastifyBaseLogger, 'warn'>;

/**
 * The one route a PAUSED key may still call: `GET /v1/persona/me`, so an agent
 * that has been stopped can ask the server WHY (and tell the person who runs it)
 * instead of only seeing a wall of refusals. It answers with the key's pause
 * state and nothing else the key could act on; every other route, including every
 * other persona route and MCP, refuses a paused key. Matched on the router's own
 * pattern (`req.routeOptions.url`), never on the raw target, for the reason the
 * allowlist below gives: an encoded request path must not be able to slip past.
 */
export const PAUSED_KEY_EXEMPT_ROUTE = 'GET /v1/persona/me';

function isPausedKeyExemptRoute(req: FastifyRequest): boolean {
  return req.method === 'GET' && `${req.method} ${req.routeOptions?.url ?? ''}` === PAUSED_KEY_EXEMPT_ROUTE;
}

/** Read-only credential identity. Membership revocation, pauses and metering remain in authenticateApiKey. */
async function lookupApiKeyCredential(db: Db, token: string, now: Date = new Date()) {
  // bt_<8 hex prefix>_<base64url secret> — the secret itself may contain "_".
  const match = /^bt_([0-9a-f]{8})_./.exec(token);
  const prefix = match?.[1];
  if (!prefix) throw Errors.unauthorized('Invalid API key');
  const candidates = await db
    .select({
      key: apiKeys,
      livePersonaId: apiKeyPersonas.id,
      orgPausedUntil: orgAgentPolicy.agentsPausedUntil,
    })
    .from(apiKeys)
    // A LIVE persona only (not retired): a retired persona turns the key back into a plain one.
    .leftJoin(apiKeyPersonas, and(eq(apiKeyPersonas.apiKeyId, apiKeys.id), isNull(apiKeyPersonas.retiredAt)))
    .leftJoin(orgAgentPolicy, eq(orgAgentPolicy.orgId, apiKeys.orgId))
    .where(and(eq(apiKeys.keyPrefix, prefix), isNull(apiKeys.revokedAt)));
  const tokenHash = sha256(token);
  const found = candidates.find((row) => safeEqualHex(row.key.keyHash, tokenHash));
  if (!found) throw Errors.unauthorized('Invalid API key');
  const key = found.key;
  const serviceCustody = key.custody === 'org_service' && (await getCommanderReleaseSetting(db, 'commander.serviceCustody', key.orgId)) === true;
  if (serviceCustody) {
    // No standing product authority. The identity survives its audit creator. S3 supplies turn grants before release.
    if (!found.livePersonaId) throw Errors.unauthorized('Invalid API key');
    const [designated] = await db.select({ personaId: commanderSettings.personaId, threadsEnabled: commanderSettings.threadsEnabled }).from(commanderSettings).innerJoin(apiKeyPersonas, eq(apiKeyPersonas.id, commanderSettings.personaId)).where(and(eq(commanderSettings.orgId, key.orgId), eq(commanderSettings.personaId, found.livePersonaId), eq(apiKeyPersonas.enabled, true)));
    if (!designated || !designated.threadsEnabled) throw Errors.unauthorized('Commander is switched off');
    const [serviceOrg] = await db.select({ overrides: organizations.entitlementOverrides }).from(organizations).where(eq(organizations.id, key.orgId));
    const overrides = serviceOrg?.overrides as Record<string, unknown> | undefined;
    if (!serviceOrg || overrides?.suspended || overrides?.['qaCommander.optOut'] || overrides?.['qaCommander.killed']) throw Errors.unauthorized('Commander is unavailable');
  }
  // User-custody keys act as their creator; service-custody identity is the persona itself.
  if (!serviceCustody && !key.createdBy) throw Errors.unauthorized('Invalid API key');
  // The credential reached its hard end date. Not persisted: extending `expires_at`
  // revives it, which is the point of an expiry that is not a revocation.
  // Plan S0a: dark behind `delegates.enforceQuotas` (read only once a key IS past its
  // date, so an ordinary request pays nothing), except for a runner key, whose expiry
  // always holds (`isRunnerKey` reads the S0b `api_keys.kind`).
  if (
    key.expiresAt &&
    keyIsExpired(key.expiresAt, now) &&
    (serviceCustody || isRunnerKey(key) || (await delegatesQuotasEnforced(db)))
  ) {
    throw keyExpiredError(key.expiresAt);
  }
  // USER TOKENS (review round 2, finding 8): a key minted (or changed) through a user token lives only while that token
  // and every token above it in its mint chain do -- expiry and revocation INHERITED LIVE, not copied once at mint
  // time. Not behind `delegates.enforceQuotas`: such a key exists only because user tokens do, and this only ever
  // ends a credential early. Only keys tied to a token (`created_by_user_token_id`) pay the read; no key on main is.
  if (!serviceCustody && key.createdByUserTokenId) {
    const chain = await userTokenChainState(db, key.createdByUserTokenId, key.createdBy!);
    if (!chain.found || chain.revoked) throw Errors.unauthorized('Invalid API key');
    if (chain.endsAt && keyIsExpired(chain.endsAt, now)) throw keyExpiredError(chain.endsAt);
  }
  return { ...found, serviceCustody };
}

/**
 * Authenticate an org API key of the form `bt_<8 hex prefix>_<secret>`.
 * The prefix narrows the lookup; the sha256 of the FULL token is compared
 * against the stored hash in constant time.
 *
 * THE KILL SWITCH LIVES HERE (docs/design/AGENT-DELEGATES.md sections 11 and 13),
 * and every lookup below is a fresh read of the database row for THIS request --
 * nothing about a key's state is cached beyond the request, so a pause, an expiry
 * or an org pause takes effect on the very next call, on every route and every
 * transport that authenticates by bearer (REST, the persona routes, MCP -- whose
 * tool calls re-enter this function through `app.inject()` -- and anything added
 * later). The checks, in order:
 *
 *   1. not revoked (the lookup itself);
 *   2. not EXPIRED                          -> 401 `key_expired`;
 *   3. a persona-bearing key's owner is still an org member, else the key is
 *      revoked for good                     -> 401 (see below);
 *   4. PAUSED (the key's own pause, or the org pause that covers it)
 *                                           -> returned as `pause`; the hook answers
 *                                              403 `key_paused` unless the route is the
 *                                              one exempt route.
 *
 * The join to the persona and the org policy rides in the ONE statement that finds
 * the key (both are indexed lookups), so a key with no persona and no policy row
 * costs what it always did. An org with no `org_agent_policy` row has no pause.
 */
export async function authenticateApiKey(
  db: Db,
  token: string,
  client: ApiKeyClientTrace & { inProcess: boolean },
  log: ApiKeyUseLog,
  now: Date = new Date(),
  // Visibility probes verify identity without changing a dark route's state.
  // Ordinary authentication retains durable revocation and usage behavior.
  persistRevocations = true,
): Promise<ApiKeyAuthentication> {
  const found = await lookupApiKeyCredential(db, token, now);
  const { key, serviceCustody } = found;
  // A bot's owner who is no longer a member of the org: the key stops existing,
  // persisted exactly like the scoped-key branch below and for the same reason
  // (membership removal is a hard DELETE with no tombstone, so a re-add must not
  // resurrect anything). The removal route revokes eagerly in its own transaction;
  // this closes the removals that predate it and any future path that forgets.
  // Only a persona-bearing key: a plain integration key's other routes already
  // refuse a non-member through their own access checks, and widening this to
  // every key is a product decision, not a side effect of this lane.
  //
  // Plan S0a: dark behind `delegates.enforceQuotas`. origin/main has no such check: a persona key whose creator left
  // the org kept authenticating (org routes refuse the non-member through their own access checks), and the
  // credential was never revoked. The flag is read only when the owner really is missing, so an ordinary request
  // costs nothing extra. With it off nothing is revoked, retired or audited.
  //
  // PLAN S2a fix-s2a: a RUNNER key is checked on every request even when its persona is no longer live (disabled or
  // retired): an enrolled runner is not dark infrastructure, and its sponsor leaving the org must end it. Not behind
  // `delegates.enforceQuotas`, like the runner-key expiry above.
  if (!serviceCustody && (found.livePersonaId || isRunnerKey(key))) {
    const ownerStillMember = await db
      .select({ userId: orgMembers.userId })
      .from(orgMembers)
      .where(and(eq(orgMembers.orgId, key.orgId), eq(orgMembers.userId, key.createdBy!)))
      .limit(1);
    if (!ownerStillMember[0] && (isRunnerKey(key) || (await delegatesQuotasEnforced(db)))) {
      if (!persistRevocations) throw Errors.unauthorized('Invalid API key');
      await db.transaction(async (tx) => {
        const revoked = await tx
          .update(apiKeys)
          .set({ revokedAt: new Date() })
          .where(and(eq(apiKeys.id, key.id), isNull(apiKeys.revokedAt)))
          .returning({ id: apiKeys.id });
        // Dead in the same instant: the persona stops being offered/mentionable even though the
        // key's own revocation already excludes it everywhere (what the removal route also does).
        await retireOwnerPersonas(tx, {
          ownerId: key.createdBy!, orgId: key.orgId, keyId: key.id, retiredBy: null,
          reason: 'Owner no longer belongs to the organization',
        });
        // Only the request that actually revoked it writes the audit row (a racing second one finds it done).
        if (revoked[0]) {
          await tx.insert(auditEvents).values({
            scope: 'tenant',
            orgId: key.orgId,
            actorKind: 'system',
            actorId: null,
            action: 'api_key.revoked',
            targetKind: 'api_key',
            targetId: key.id,
            changes: { reason: 'owner_not_org_member', ownerUserId: key.createdBy },
          });
        }
      });
      throw Errors.unauthorized('Invalid API key');
    }
  }
  // Board #37 "should presumably auto-revoke": a user-scoped key whose bound
  // person has left the org (their `org_members` row is gone, distinct from
  // their `users` row — which the `scoped_to_user_id` FK's `ON DELETE
  // CASCADE` already handles by deleting the key outright) stops
  // authenticating entirely, the same fail-closed shape as the `createdBy`
  // check above.
  //
  // Backlog-16 (2026-08-29 audit): this used to be RE-DERIVED live from
  // current `org_members` state on every request and nothing was ever
  // persisted, so a member removed and later re-added had their scoped
  // key silently come back to life with no deliberate action — a
  // "revocation" that only held while nobody looked. Membership removal is
  // a genuine hard DELETE with no tombstone (`org_members` has no
  // `deletedAt`), so the row being absent could not double as a sticky
  // fact on its own.
  //
  // Fixed by persisting the denial onto the KEY itself the first time it is
  // observed, using the same `revokedAt` column and one-way semantics as an
  // explicit human revoke (api-keys/service.ts's own "DELETE (revoke)"
  // comment — this product has no un-revoke action anywhere, so once a key
  // is revoked, minting a new one is the only path back). After this,
  // restoring the membership no longer restores the key: the very first
  // `WHERE ... isNull(revokedAt)` lookup above excludes it on every later
  // request, independent of membership state. Awaited (not fire-and-forget
  // like the lastUsedAt bump below) so the fact is durable before this
  // request is denied, not merely implied by the in-flight rejection.
  //
  // This LAZY persist alone still has a gap: a key never presented during
  // the window it is unauthenticated never gets marked, so a remove-then-
  // re-add with no auth attempt in between would silently keep working.
  // `DELETE /orgs/:orgId/members/:userId` (orgs/routes.ts) now also revokes
  // EAGERLY, in the same transaction as the membership row's deletion — the
  // check here stays as defense in depth for keys scoped under any removal
  // that predates that eager revoke, or any future removal path that forgets
  // to add it.
  if (key.scopedToUserId) {
    const stillMember = await db
      .select({ userId: orgMembers.userId })
      .from(orgMembers)
      .where(and(eq(orgMembers.orgId, key.orgId), eq(orgMembers.userId, key.scopedToUserId)))
      .limit(1);
    if (!stillMember[0]) {
      if (!persistRevocations) throw Errors.unauthorized('Invalid API key');
      await db
        .update(apiKeys)
        .set({ revokedAt: new Date() })
        .where(and(eq(apiKeys.id, key.id), isNull(apiKeys.revokedAt)));
      throw Errors.unauthorized('Invalid API key');
    }
  }
  const pause = keyPauseState(
    {
      pausedAt: key.pausedAt,
      pauseReason: key.pauseReason,
      expiresAt: key.expiresAt,
      hasLivePersona: found.livePersonaId !== null,
      orgPausedUntil: found.orgPausedUntil,
    },
    now,
  );
  const keyId = key.id;
  const recordUse = () => {
    // Fire-and-forget: never block the request on usage bookkeeping. The same ONE statement
    // that has always moved `last_used_at` now also records WHERE the key was used from, so
    // this costs no extra write per request. An address or agent that cannot be stored is left
    // out (see `normalizeClientTrace`); a write that still fails is logged -- with the key id
    // and the error class only -- rather than swallowed, because a bookkeeping write that
    // silently stopped would leave `last_used_at` stale with nothing to say why.
    const patch: Partial<typeof apiKeys.$inferInsert> = { lastUsedAt: new Date() };
    // A tool call re-entering through `app.inject()` has no address or agent of its own; the outer
    // `POST /v1/mcp` already recorded the real ones (see lib/in-process-dispatch.ts).
    if (!client.inProcess) {
      if (client.ip) patch.lastUsedIp = client.ip;
      if (client.userAgent) patch.lastUsedUserAgent = client.userAgent;
    }
    void db
      .update(apiKeys)
      .set(patch)
      .where(eq(apiKeys.id, keyId))
      .then(
        () => {},
        (err: unknown) => {
          log.warn({ apiKeyId: keyId, err: err instanceof Error ? err.name : 'error' }, 'api key usage bookkeeping failed');
        },
      );
  };
  return {
    ctx: {
      userId: serviceCustody ? found.livePersonaId! : key.createdBy!,
      apiKeyCustody: serviceCustody ? 'org_service' : undefined,
      sessionId: `apikey:${key.id}`,
      email: '',
      apiKeyScopes: key.scopes ?? [],
      apiKeyOrgId: key.orgId,
      apiKeyMaxOrgRole: key.maxOrgRole,
      apiKeyId: key.id,
      apiKeyScopedToUserId: key.scopedToUserId ?? undefined,
      apiKeyCanCreateIssues: key.canCreateIssues,
      apiKeyKind: key.kind,
      apiKeyMaxProjectRole: key.maxProjectRole ?? undefined,
      apiKeyPersonaId: found.livePersonaId ?? undefined,
      apiKeyCreatedByUserTokenId: key.createdByUserTokenId ?? undefined,
    },
    pause,
    recordUse,
  };
}

const READ_ONLY_REPORT_RUN_ROUTE = '/v1/orgs/:p/crm/reports/:p/run';
export function isReadOnlyApiKeyRoute(method: string, path: string): boolean {
  return READ_ONLY_METHODS.has(method) || (method === 'DELETE' && path === '/v1/mcp') || (method === 'POST' && [READ_ONLY_REPORT_RUN_ROUTE, '/v1/orgs/:p/migrations/ghl/:p/reconcile', '/v1/ai-threads/:p/inference-path/proposal', '/v1/orgs/:p/projects/:p/social-connectors/bindings/:p/operations/:p/readback', '/v1/mcp/write-confirmations/consume', '/v1/orgs/:p/artifacts/latest', '/v1/orgs/:p/projects/:p/memory/retrieve', '/v1/work-coordinators/:p/query', '/v1/work-coordinators/:p/lanes/check'].includes(normalizeRoutePattern(path)));
}

/**
 * Routes an org API key must never reach, because they act on the human behind
 * the key rather than on the key's org: the account/session surface, the
 * identity itself, org creation, and key management (a key must not mint keys).
 */
/**
 * Everything an org API key may reach. A DENYLIST is the wrong shape here.
 *
 * This used to be a list of forbidden prefixes ending in `return true`, so every
 * route added since — 209 of them at the last count — was reachable unless
 * somebody remembered to forbid it. The two documented consumers between them
 * call 23. That is roughly 180 routes open by default that nothing legitimate
 * has ever touched, including deleting projects, changing member roles, and
 * anything added tomorrow by someone who has never read this file.
 *
 * Inverted, the failure mode inverts with it: forgetting to add a route breaks
 * an integration loudly and immediately, instead of quietly widening what a
 * leaked token can do. `api-key-allowlist.test.ts` asserts every entry below
 * resolves to a route that actually exists, so a typo cannot silently forbid
 * something either.
 *
 * Sources, both verified rather than assumed:
 *   - the local stdio MCP server, apps/mcp/src/server.ts
 *   - the desktop recorder, apps/desktop/src/api.ts
 *   - board #122: the remote Streamable-HTTP MCP endpoint,
 *     apps/api/src/modules/mcp/transport-routes.ts + tools.ts (every
 *     curated tool dispatches through this SAME allowlist via
 *     `app.inject()`, so it needs no entries of its own beyond the ones
 *     already justified by the routes it reuses)
 *
 * Adding to this list is a security decision. An entry is justified by a real
 * consumer that calls it, not by "an integration might want it".
 */
/**
 * Resource families, for keys that want to be narrower than "everything".
 *
 * `scopes` was only ever `read` / `write`, enforced by HTTP method alone, so an
 * integration that files bug reports also had permission to upload attachments,
 * spend AI budget and open pull requests. A credential should be able to say
 * what it is for.
 *
 * Backward compatible on purpose: a key carrying NO resource scope behaves
 * exactly as before. Only a key that names at least one family is restricted to
 * the families it names — so every key in existence keeps working, and narrowing
 * one stays a deliberate act.
 */
export const API_KEY_RESOURCES = [
  'ghl_history_reader',
  'mail',
  'roadmap_suggestions',
  'work',
  'issue_types',
  'command_center',
  'work_dashboard',
  'orgs',
  'projects',
  'issues',
  'testing',
  'uploads',
  'ai',
  'github',
  'decisions',
  'mcp',
  'agent_memory',
  'project_memory',
  // Scoped context recall/candidates. Activation and edits remain human-session-only.
  'context_memory',
  'vault',
  'artifacts',
  'documents',
  'surface',
  'notifications',
  // TASK-479 added these three. A key that names NO family is unrestricted, so
  // adding a family cannot widen an existing key; it only gives a deliberately
  // narrowed key a name for surface that had no name before. New surface got a
  // NEW family rather than being folded into an existing one precisely so a key
  // already scoped to e.g. `issues` does not silently gain reach it never asked
  // for as this list grows.
  'agents',
  'chat',
  'stats',
  // Marketing Tools (2026-08-29). Its own family for the same reason as the
  // three above: brand-new surface that touches real third-party spend
  // (Vertex/Veo generation, Apollo enrichment, Klaviyo/Postiz sends) gets a
  // NEW name rather than folding into `projects`, so no existing key scoped
  // to `projects` silently gains reach into it.
  'marketing',
  // Review Studio (plan Part 5.12). Its OWN family for the same reason the
  // three TASK-479 families and `marketing` got theirs: a key already scoped to
  // `projects` must not silently gain reach into a new product area. A key that
  // names NO family stays unrestricted, so adding this widens nothing that
  // exists.
  'experience_reviews',
  // Deploy Assistant (deploy scope DA1-DA4). Its OWN family for the same
  // reason `marketing` and `experience_reviews` got theirs: brand-new product
  // surface must not be silently reachable by a key already scoped to
  // `projects`. A key that names NO family stays unrestricted, so adding this
  // widens nothing that exists.
  'deploy',
  // Inviting people into the org (Eric, 2026-09-07). Deliberately NOT folded
  // into `orgs`: a key narrowed to `orgs` today was narrowed while inviting was
  // impossible, and must not silently acquire the ability to bring a new person
  // into the tenant. Its own name means asking for it is a deliberate act.
  'invites',
  // Native CMS platform (board #505). Its OWN family for the same reason
  // `marketing`, `experience_reviews`, and `deploy` got theirs: brand-new
  // product surface must not be silently reachable by a key already scoped
  // to `projects`. A key that names NO family stays unrestricted, so adding
  // this widens nothing that exists.
  'cms',
  // Billboard (board #765). Its OWN family for the same reason `cms`,
  // `marketing`, `experience_reviews`, and `deploy` got theirs: brand-new
  // product surface must not be silently reachable by a key already scoped
  // to `projects`. FOUNDATION PR: every route below is real (Fastify schema
  // validation + a live access-check chokepoint), even though the handler
  // BODY behind each one is a stub that throws 501 — see
  // `apps/api/src/modules/billboard/routes.ts`'s own header.
  'billboard',
  // CRM v2 C0 (owner decision Q3, docs/design/crm-v2/DESIGN.md section 8.7).
  // Its OWN family for the same reason as every family above: a key already
  // scoped to `projects` or `orgs` must not silently gain customer PII. A key
  // naming NO family is unrestricted, so on top of the family every `crm`
  // route is ALSO dark per org behind the `crm.api.enabled` entitlement
  // (default off): see `CRM_API_KEY_FLAG` in registerAuthPlugin below.
  'crm',
  // PLAN S0b (docs/design/goodqa-agent-platform/PLAN.md section 1.3): the family a GoodQA runner key names for
  // runner-protocol routes (S1 adds them). Its OWN name for the same reason as every family above. A runner key
  // MUST name at least one family (mint refuses otherwise) and may never name one listed in
  // RUNNER_FORBIDDEN_RESOURCE_FAMILIES (api-keys/service.ts: projects, decisions, github, crm, data, outreach, vault).
  'runner',
  // Custom data (docs/design/custom-data/DESIGN.md 5.6, slice D2). Its OWN family for the same reason
  // every family above got one: a key already narrowed to `projects` or `issues` must not silently gain
  // SQL access to the org's databases. A key that names NO family stays unrestricted at the route
  // level, and still gets only the data tier its creator's CAPPED org role allows. DARK: the routes
  // answer an unregistered route's 404 unless the deployment has CUSTOM_DATA_CLUSTER_URL and the org
  // has `customData.enabled`.
  'data',
  // Agent knowledge (approved defaults 2026-10-02, design gq-m1 C.4). Its OWN family, NOT folded into
  // `agent_memory`: a key already narrowed to `agent_memory` must not silently gain the durable store. A key that
  // names no family does reach it (that is how a persona key reaches persona scope), still behind the per-org
  // `agentKnowledge.enabled` entitlement checked below. Runner keys reach it only by naming it: the family is in
  // RUNNER_KEY_SCOPES for NEW enrolments, and a live runner key keeps its old list until it re-enrols.
  'agent_knowledge',
  // Org/project rules and memory: an explicit grant, separate from scratch agent_memory and agent_knowledge.
  // Agents read and propose; governance PATCH routes remain human-session-only.
  'memory',
  // P51 growth system, slice A (docs/design/outreach/SLICE-A-OPEN.md). Its OWN family for the same reason
  // every family above got one: a key narrowed to `crm` must not silently gain the outreach controls. A key
  // naming NO family reaches it (persona keys may suppress and trip: the safe direction), a runner key never
  // (RUNNER_FORBIDDEN_RESOURCE_FAMILIES, plus a kind check below). DARK: every route is the app's own 404 for a
  // key unless the org has BOTH `outreach.enabled` and `outreach.api.enabled` (OUTREACH_API_KEY_FLAGS below).
  // Only the tightening routes are here; lift, list, PATCH config and erase are SESSION_ONLY_ROUTES.
  'outreach',
  // Plan S3, launching agents (docs/AGENT-DAEMON.md). Its OWN family, and EXPLICIT-ONLY (like `data`): a launch carries
  // a prompt and its run's logs, so a key that names no family does not silently reach it. Only the read and SAFER
  // routes are key-reachable (list, read, cancel, revoke); making a registration code and launching are
  // SESSION_ONLY_ROUTES (lopsided rule). Runner keys refused by kind and by RUNNER_FORBIDDEN_RESOURCE_FAMILIES;
  // user-scoped keys refused (USER_SCOPED_KEY_FAMILY_POLICY). DARK: every route is the router's own 404 unless the
  // platform setting `agents.launch` is on for the org.
  'agent_launch',
  // Notes to self + personal files (Eric, 2026-10-03). Its OWN family so a key narrowed to `chat` or `uploads`
  // never silently reaches a person's private notes. Beyond the family, the module itself admits ONLY the user's
  // own personal key (standard, no persona, created_by = scoped_to_user_id): see assertPersonalPrincipal in
  // modules/notes-to-self/routes.ts. Every route is absent when NOTES_TO_SELF_ENABLED=false.
  'notes_to_self',
  // Ticket #377: per-org usage metering (cost figures). Its OWN family so no key narrowed to `orgs` or `stats` gains
  // them; a runner key may never name it. Dark behind the platform setting `usage.metering` (default on).
  'usage',
  // Model-spend metering (lane gq-usage-model-spend-ingest): the WRITE half, its OWN explicit-only family. Recording what
  // agents spent feeds the cost figures and the advisory budget, so a key reaches it only by NAMING `usage:write` (a key
  // that names no family, or only `usage`, `issues` or `orgs`, never does) and an ingest-only key can hold `usage:write`
  // without `usage` and so never read the cost figures back. A runner key may never name it; a user-scoped key is refused.
  'usage:write',
  // GoodQA #430, GoodQA Machines (docs/design/GOODQA-MACHINES.md). Its OWN family so a key narrowed to `issues` or
  // `chat` never silently reaches people's computers. EXPLICIT-ONLY for bot keys (review round 1, finding 6): an org or
  // persona key reaches it only by naming it, and then only under the machine owner's per-key/per-persona GRANT
  // (modules/machines/access.ts); the person's own personal key is the exception (apiKeyReachesMachines). Pairing, granting, approving and resuming are SESSION_ONLY_ROUTES (lopsided rule);
  // runner keys refused by kind and by RUNNER_FORBIDDEN_RESOURCE_FAMILIES. DARK: every route is the router's own 404
  // unless the platform setting `machines.enabled` is on for the org.
  'machines',
  // GoodQA #442 emergency escalation (dark: escalation.enabled). Its OWN family: paging people by phone must never ride
  // along with a key narrowed to `issues` or `orgs`. A runner key may never name it; a user-scoped key is refused.
  'escalation',
] as const;

type ApiKeyResource = (typeof API_KEY_RESOURCES)[number];
type ApiKeyResourceRequirement = ApiKeyResource | readonly ApiKeyResource[];

const API_KEY_ALLOWED_ROUTES: readonly (readonly [string, ApiKeyResourceRequirement])[] = [
  // Polymorphic resources: handlers apply the concrete item's registered family policy.
  ['POST /v1/links', []],
  ['DELETE /v1/links/:p', []],
  ['GET /v1/resolve', []],
  ['GET /v1/orgs/:p/projects/:p/product-research/catalog', 'artifacts'],
  ['GET /v1/orgs/:p/projects/:p/product-research/catalog/:p', 'artifacts'],
  ['GET /v1/orgs/:p/projects/:p/product-research/catalog/operations/:p', 'artifacts'],
  ['POST /v1/orgs/:p/projects/:p/product-research/catalog/import', 'artifacts'],
  ['POST /v1/orgs/:p/projects/:p/product-research/catalog/discover', 'artifacts'],
  ['POST /v1/orgs/:p/projects/:p/product-research/catalog/pdf', 'artifacts'],
  ['POST /v1/orgs/:p/projects/:p/product-research/catalog/operations/:p/stop', 'artifacts'],
  ['POST /v1/orgs/:p/projects/:p/product-research/catalog/:p/questions', 'artifacts'],
  ['POST /v1/orgs/:p/projects/:p/product-research/catalog/questions/:p/reply-evidence', 'artifacts'],
  ['POST /v1/mcp/write-confirmations/consume', []],
  ['GET /v1/orgs/:p/outreach/projects/:p/daily-routine', 'outreach'],
  ['POST /v1/orgs/:p/outreach/projects/:p/daily-routine/batch', 'outreach'],
  ['POST /v1/orgs/:p/outreach/projects/:p/daily-routine/drafts', 'outreach'],
  ['GET /v1/orgs/:p/outreach/report', 'outreach'],
  ['GET /v1/orgs/:p/outreach/audit', 'outreach'],
  ['GET /v1/projects/:p/marketing/prospecting/research', 'marketing'],
  ['POST /v1/projects/:p/marketing/prospecting/research', 'marketing'],
  ['PATCH /v1/projects/:p/marketing/prospecting/research/:p', 'marketing'],
  ['POST /v1/projects/:p/marketing/prospecting/web-search', 'marketing'],
  ['POST /v1/projects/:p/marketing/prospecting/web-fetch', 'marketing'],
  ['POST /v1/projects/:p/marketing/prospecting/competitor-watch', 'marketing'],
  ['GET /v1/projects/:p/marketing/prospecting/competitor-watch/:p', 'marketing'],
  ['PATCH /v1/projects/:p/marketing/prospecting/competitor-watch/:p', 'marketing'],
  ['POST /v1/projects/:p/marketing/prospecting/competitor-watch/:p/run', ['marketing', 'artifacts']],
  ['POST /v1/projects/:p/marketing/prospecting/competitor-watch/:p/stop', 'marketing'],

  // Draft research and reads share the outreach family; approving or editing remains a person's act.
  ['GET /v1/orgs/:p/steve-desk', 'outreach'],
  ['GET /v1/orgs/:p/steve-desk/page', 'outreach'],
  ['POST /v1/orgs/:p/steve-desk/snapshot', 'outreach'],
  ['POST /v1/orgs/:p/mail/inbox-drafts', ['mail', 'crm']],
  ['POST /v1/orgs/:p/mail/inbox-drafts/associations', ['mail', 'crm']],
  ['GET /v1/orgs/:p/mail/inbox-drafts/associations/:p', ['mail', 'crm']],
  ['GET /v1/orgs/:p/mail/inbox-drafts/threads/:p', ['mail', 'crm']],
  ['POST /v1/orgs/:p/mail/inbox-drafts/handoff', ['mail', 'crm']],
  ['GET /v1/orgs/:p/mail/inbox-drafts/:p', ['mail', 'crm']],
  ['PUT /v1/orgs/:p/mail/inbox-drafts/:p', ['mail', 'crm']],
  ['POST /v1/orgs/:p/mail/inbox-drafts/:p/cancel', ['mail', 'crm']],
// Native mx.world mail: every route enforces durable ownership/grants.
  ['GET /v1/orgs/:p/mail/inboxes', 'mail'],
  ['POST /v1/orgs/:p/mail/inboxes', 'mail'],
  ['GET /v1/orgs/:p/mail/identities', 'mail'],
  ['GET /v1/orgs/:p/mail/inboxes/:p/messages', 'mail'],
  ['GET /v1/orgs/:p/mail/inboxes/:p/messages/:p', 'mail'],
  ['GET /v1/orgs/:p/mail/inboxes/:p/latest-code', 'mail'],
  ['POST /v1/orgs/:p/mail/inboxes/:p/send', 'mail'],
  ['POST /v1/orgs/:p/mail/inboxes/:p/messages/:p/reply', 'mail'],
  ['GET /v1/orgs/:p/mail/inboxes/:p/grants', 'mail'],
  ['PUT /v1/orgs/:p/mail/inboxes/:p/grants/:p', 'mail'],
  ['POST /v1/orgs/:p/mail/inboxes/:p/transfer', 'mail'],

  ['GET /v1/commander/actions/:p', 'chat'],
  ['GET /v1/ai-threads/:p/mode', 'chat'],
  ['GET /v1/ai-threads/:p/inference-path', 'chat'],
  // Held validation only; the handler never changes preferences or creates an approval.
  ['POST /v1/ai-threads/:p/inference-path/proposal', 'chat'],
  ['GET /v1/projects/:p/network-campaigns', 'agents'],
  ['POST /v1/projects/:p/network-campaigns', 'agents'],
  ['POST /v1/projects/:p/network-campaigns/:p/stop', 'agents'],
  ['GET /v1/projects/:p/network-campaigns/:p/actions', 'agents'],
  ['POST /v1/projects/:p/network-campaigns/:p/actions', 'agents'],
  ['POST /v1/projects/:p/network-campaigns/:p/actions/:p/run', 'agents'],
  ['GET /v1/projects/:p/network-campaigns/:p/reports', 'agents'],
  ['GET /v1/projects/:p/network-campaigns/:p/recipients/:p/history', 'agents'],
  ['GET /v1/orgs/:p/network-connections', 'agents'],
  ['GET /v1/orgs/:p/network-connections/catalog', 'agents'],
  ['POST /v1/orgs/:p/network-connections/:p/tasks', 'agents'],
  ['POST /v1/roadmap/agent-suggestions', ['issues', 'roadmap_suggestions']],
  // Roadmap tools read curated content and prepare drafts. The module additionally requires an explicit
  // issues grant, live org membership and project create permission. Legacy no-family keys do not opt in.
  ['GET /v1/roadmap', 'issues'],
  ['POST /v1/projects/:p/roadmap/:p/ticket-proposal', 'issues'],
  ['GET /v1/work-coordinators', 'work'],
  ['GET /v1/work-coordinators/:p/view', 'work'],
  ['GET /v1/work-coordinators/:p/items', 'work'],
  ['GET /v1/work-coordinators/:p/items/:p/why', 'work'],
  ['GET /v1/work-coordinators/:p/items/:p/delivery-observation', 'work'],
  ['GET /v1/work-coordinators/:p/items/:p/delivery-acceptance-candidates', 'work'],
  ['GET /v1/work-coordinators/:p/items/:p/delivery-current-acceptance', 'work'],
  ['POST /v1/work-coordinators/:p/lanes', 'work'],
  ['POST /v1/work-coordinators/:p/lanes/:p/test-runs', 'work'],
  ['PATCH /v1/work-coordinators/:p/lanes/:p', 'work'],
  ['POST /v1/work-coordinators/:p/items', 'work'],
  ['POST /v1/work-coordinators/:p/attempts', 'work'],
  ['POST /v1/work-coordinators/:p/lease', 'work'],
  ['POST /v1/work-coordinators/:p/attention', 'work'],
  ['GET /v1/work-coordinators/:p/attention', 'work'],
  ['GET /v1/work-coordinators/:p/attention/stats', 'work'],
  ['GET /v1/work-coordinators/:p/attention/report', 'work'],
  ['GET /v1/work-coordinators/:p/attention/digest', 'work'],
  ['POST /v1/work-coordinators/:p/attention/resolve', 'work'],
  ['POST /v1/work-coordinators/:p/attention/undo', 'work'],
  ['POST /v1/work-coordinators/:p/query', 'work'],
  ['POST /v1/work-coordinators/:p/legacy-bridge', 'work'],
  ['POST /v1/work-coordinators/:p/lanes/check', 'work'],
  ['POST /v1/work-coordinators/:p/manager/claim', 'work'],
  ['POST /v1/work-coordinators/:p/manager/heartbeat', 'work'],
  ['POST /v1/work-coordinators/:p/manager/finish', 'work'],
  ['POST /v1/work-coordinators/:p/items/:p/assign', 'work'],
  ['POST /v1/work-coordinators/:p/items/:p/close-tickets', 'work'],
  ['POST /v1/work-coordinators/:p/items/:p/heartbeat', 'work'],
  ['POST /v1/work-coordinators/:p/items/:p/execution', 'work'],
  ['POST /v1/work-coordinators/:p/items/:p/transition', 'work'],
  ['POST /v1/work-coordinators/:p/items/:p/complete', 'work'],
  ['POST /v1/work-coordinators/:p/items/:p/fail', 'work'],
  ['POST /v1/work-coordinators/:p/items/:p/escalate', 'work'],
  ['POST /v1/work-coordinators/:p/maintain', 'work'],
  ['GET /v1/work-coordinators/:p/children/:p/summary', 'work'],
  ['GET /v1/work-coordinators/:p/children/:p/escalations', 'work'],
  ['POST /v1/work-coordinators/:p/children/:p/assign', 'work'],
  ['POST /v1/work-coordinators/:p/children/:p/steer', 'work'],
  ['POST /v1/work-coordinators/:p/children/:p/escalate', 'work'],

  // Scheduling v1 agent API (docs/design/SCHEDULING-V1.md, Eric 2026-10-07 "agent access: list availability, book,
  // reschedule, cancel"). The `crm` family (a booking upserts a CRM contact), so CRM_API_KEY_FLAG applies too, and
  // the module itself is the app's 404 unless the org has `scheduling.enabled`. Booking runs the PUBLIC page's
  // rules (offered slot, questions, notice); reschedule/cancel need the key's user to host the booking or be an
  // org admin. Publishing pages and editing hours stay SESSION_ONLY_ROUTES.
  ['GET /v1/orgs/:p/scheduling/agent/event-types', 'crm'],
  ['GET /v1/orgs/:p/scheduling/agent/event-types/:p/slots', 'crm'],
  ['POST /v1/orgs/:p/scheduling/agent/event-types/:p/bookings', 'crm'],
  ['GET /v1/orgs/:p/scheduling/agent/bookings', 'crm'],
  ['POST /v1/orgs/:p/scheduling/agent/bookings/:p/reschedule', 'crm'],
  ['POST /v1/orgs/:p/scheduling/agent/bookings/:p/cancel', 'crm'],
  ['GET /v1/orgs/:p/artifacts', ['artifacts', 'chat', 'issues']],
  ['GET /v1/artifacts/:p', ['artifacts', 'chat', 'issues']],
  ['GET /v1/artifacts/:p/versions/:p', ['artifacts', 'chat', 'issues']],
  ['GET /v1/artifacts/:p/versions/:p/content', ['artifacts', 'chat', 'issues']],
  ['GET /v1/artifacts/:p/versions/:p/render', ['artifacts', 'chat', 'issues']],
  ['GET /v1/artifacts/:p/preview', ['artifacts', 'chat', 'issues']],
  ['GET /v1/artifacts/:p/versions/:p/preview', ['artifacts', 'chat', 'issues']],
  ['GET /v1/artifacts/:p/diff', ['artifacts', 'chat', 'issues']],
  ['POST /v1/orgs/:p/artifacts/latest', ['artifacts', 'chat', 'issues']],
  ['POST /v1/orgs/:p/artifacts', 'artifacts'],
  ['POST /v1/artifacts/:p/versions', 'artifacts'],
  ['POST /v1/artifacts/:p/links', 'artifacts'],
  ['DELETE /v1/artifacts/:p/links/:p', 'artifacts'],
  ['PATCH /v1/artifacts/:p', 'artifacts'],
  ['DELETE /v1/artifacts/:p', 'artifacts'],
  ['POST /v1/orgs/:p/my-work/backfill', 'issues'],
  ['GET /v1/orgs/:p/my-work/projection', 'issues'],
  ['GET /v1/me/my-work', 'issues'],
  ['GET /v1/me/my-work/events', 'issues'],
  ['GET /v1/me/my-work/scope', 'issues'],
  ['GET /v1/orgs/:p/my-work', 'issues'],
  ['POST /v1/orgs/:p/work-liveness', 'issues'],
  ['GET /v1/orgs/:p/qac/work', 'chat'],
  ['GET /v1/orgs/:p/qac/work/:p', 'chat'],
  ['GET /v1/orgs/:p/agent-queue', 'issues'],
  ['GET /v1/orgs/:p/agent-queue/next', 'issues'],
  ['POST /v1/orgs/:p/agent-queue/items', 'issues'],
  ['DELETE /v1/orgs/:p/agent-queue/items/:p', 'issues'],
  ['GET /v1/me/my-work/sync', 'issues'],
  ['GET /v1/me/my-work/asks/:p', 'issues'],
  ['GET /v1/orgs/:p/my-work/open-asks', 'issues'],
  ['GET /v1/orgs/:p/my-work/settings', 'issues'],
  ['POST /v1/orgs/:p/my-work/asks/:p/home', 'issues'],

  ['GET /v1/orgs/:p/routines', 'orgs'],
  ['GET /v1/orgs/:p/routines/capability', 'orgs'],
  ['GET /v1/orgs/:p/routines/runs/:p', 'orgs'],
  ['GET /v1/orgs/:p/org-builder/capability', 'orgs'],
  ['GET /v1/orgs/:p/org-builder/drafts/:p', 'orgs'],
  ['POST /v1/orgs/:p/org-builder/draft', 'orgs'],
  ['POST /v1/orgs/:p/org-builder/edit', 'orgs'],
  ['POST /v1/orgs/:p/org-builder/apply', 'orgs'],
  ['POST /v1/orgs/:p/blueprints/export', 'orgs'],
  ['POST /v1/orgs/:p/blueprints/plan', 'orgs'],
  ['POST /v1/orgs/:p/blueprints/apply', 'orgs'],
  ['GET /v1/orgs/:p/blueprints', 'orgs'],
  ['GET /v1/orgs/:p/blueprints/configurations/:p', 'orgs'],
  ['GET /v1/orgs/:p/blueprints/:p', 'orgs'],
  ['GET /v1/orgs/:p/blueprints/applications', 'orgs'],
  ['POST /v1/orgs/:p/imports', 'crm'],
  ['GET /v1/orgs/:p/crm/custom-values', 'crm'],
  ['POST /v1/orgs/:p/crm/custom-values', 'crm'],
  ['PATCH /v1/orgs/:p/crm/custom-values/:p', 'crm'],
  ['DELETE /v1/orgs/:p/crm/custom-values/:p', 'crm'],
  ['GET /v1/orgs/:p/scheduling/event-types/:p/sms-reminders', 'crm'],
  ['GET /v1/orgs/:p/reputation/destinations', 'crm'],
  ['POST /v1/orgs/:p/reputation/destinations', 'crm'],
  ['PUT /v1/orgs/:p/reputation/destinations/:p', 'crm'],
  ['DELETE /v1/orgs/:p/reputation/destinations/:p', 'crm'],
  ['GET /v1/orgs/:p/reputation/settings', 'crm'],
  ['PUT /v1/orgs/:p/reputation/settings', 'crm'],
  ['GET /v1/orgs/:p/reputation/requests', 'crm'],
  ['POST /v1/orgs/:p/reputation/requests', 'crm'],
  ['GET /v1/orgs/:p/reputation/requests/:p', 'crm'],
  ['POST /v1/orgs/:p/reputation/requests/:p/sent', 'crm'],
  ['POST /v1/orgs/:p/reputation/requests/:p/cancel', 'crm'],
  ['GET /v1/orgs/:p/reputation/overview', 'crm'],
  ['GET /v1/orgs/:p/courses', 'crm'],
  ['POST /v1/orgs/:p/courses', 'crm'],
  ['GET /v1/orgs/:p/courses/:p', 'crm'],
  ['PATCH /v1/orgs/:p/courses/:p', 'crm'],
  ['DELETE /v1/orgs/:p/courses/:p', 'crm'],
  ['POST /v1/orgs/:p/courses/:p/modules', 'crm'],
  ['PATCH /v1/orgs/:p/courses/:p/modules/:p', 'crm'],
  ['DELETE /v1/orgs/:p/courses/:p/modules/:p', 'crm'],
  ['POST /v1/orgs/:p/courses/:p/modules/reorder', 'crm'],
  ['POST /v1/orgs/:p/courses/:p/modules/:p/lessons', 'crm'],
  ['PATCH /v1/orgs/:p/courses/:p/modules/:p/lessons/:p', 'crm'],
  ['DELETE /v1/orgs/:p/courses/:p/modules/:p/lessons/:p', 'crm'],
  ['POST /v1/orgs/:p/courses/:p/modules/:p/lessons/reorder', 'crm'],
  ['GET /v1/orgs/:p/courses/:p/enrolments', 'crm'],
  ['POST /v1/orgs/:p/courses/:p/enrolments', 'crm'],
  ['POST /v1/orgs/:p/course-enrolments/:p/revoke', 'crm'],
  ['POST /v1/orgs/:p/course-enrolments/:p/link', 'crm'],
  ['POST /v1/orgs/:p/courses/import/ghl', 'crm'],
  ['POST /v1/orgs/:p/migrations/ghl/:p/history/plan', 'crm'],
  ['POST /v1/orgs/:p/migrations/ghl/:p/history/:p/commit', 'crm'],
  ['POST /v1/orgs/:p/migrations/ghl/:p/tasks/plan', 'crm'],
  ['POST /v1/orgs/:p/migrations/ghl/:p/tasks/commit', 'crm'],
  ['GET /v1/orgs/:p/migrations/ghl/:p/rebuild', 'crm'],
  ['POST /v1/orgs/:p/migrations/ghl/:p/rebuild/inventory', 'crm'],
  ['POST /v1/orgs/:p/migrations/ghl/:p/rebuild/decision', 'crm'],
  ['POST /v1/orgs/:p/migrations/ghl/:p/rebuild/draft', 'crm'],
  ['POST /v1/orgs/:p/migrations/ghl', 'crm'],
  ['GET /v1/orgs/:p/migrations/ghl/:p', 'crm'],
  ['POST /v1/orgs/:p/migrations/ghl/:p/jobs', 'crm'],
  ['POST /v1/orgs/:p/migrations/ghl/:p/reconcile', 'crm'],
  ['POST /v1/orgs/:p/migrations/ghl/:p/decisions', 'crm'],
  ['POST /v1/orgs/:p/migrations/ghl/:p/cutover', 'crm'],
  ['POST /v1/orgs/:p/migrations/ghl/:p/exclusions', 'crm'],
  ['POST /v1/orgs/:p/migrations/ghl/:p/exclusions/resolve', 'crm'],
  ['POST /v1/orgs/:p/migrations/ghl/:p/delta', 'crm'],
  ['POST /v1/orgs/:p/migrations/ghl/:p/final-cutover', 'crm'],
  ['POST /v1/orgs/:p/imports/preview', 'crm'],
  ['GET /v1/orgs/:p/imports/:p', 'crm'],
  ['POST /v1/orgs/:p/imports/:p/commit', 'crm'],
  // --- P51 outreach slice A: the tightening half only (owner default 4; the lopsided rule IS this list). A key may
  // add a suppression, check one, read the config and trip the kill switch; it can never lift, list, re-enable or
  // erase. Central gate: outreach.enabled + outreach.api.enabled (registerAuthPlugin), runners refused by kind.
  ['POST /v1/orgs/:p/outreach/suppressions', 'outreach'],
  ['GET /v1/orgs/:p/outreach/suppressions/check', 'outreach'],
  ['GET /v1/orgs/:p/outreach/config', 'outreach'],
  ['GET /v1/orgs/:p/outreach/deliverability', 'outreach'],
  ['GET /v1/orgs/:p/outreach/linkedin-browser', 'outreach'],
  ['GET /v1/orgs/:p/outreach/linkedin-browser/projects/:p', 'outreach'],
  ['POST /v1/orgs/:p/outreach/linkedin-browser/tasks', 'outreach'],
  ['POST /v1/orgs/:p/outreach/linkedin-browser/tasks/:p/dispatch', 'outreach'],
  ['GET /v1/orgs/:p/outreach/pipeline', 'outreach'],
  ['GET /v1/orgs/:p/outreach/conversations', 'outreach'],
  ['GET /v1/orgs/:p/outreach/queue', 'outreach'],
  ['POST /v1/orgs/:p/outreach/config/trip', 'outreach'],
  // --- P51 outreach slice D: the permit gate (G3) and template reads (G14). A key REQUESTS a permit and the
  // server decides it against its own state; confirm / abandon act only on a permit of this org. Authoring,
  // approving and retiring templates and reading the send ledger are SESSION_ONLY_ROUTES. Runners: refused by kind.
  ['POST /v1/orgs/:p/outreach/permits', 'outreach'],
  ['POST /v1/orgs/:p/outreach/permits/:p/confirm', 'outreach'],
  ['POST /v1/orgs/:p/outreach/permits/:p/abandon', 'outreach'],
  ['GET /v1/orgs/:p/outreach/templates', 'outreach'],
  ['GET /v1/orgs/:p/outreach/templates/:p', 'outreach'],
  ['GET /v1/orgs/:p/outreach/templates/:p/stats', 'outreach'],
  ['POST /v1/orgs/:p/outreach/contacts/:p/email-source', 'outreach'],
  // --- Eric's outreach policy (2026-10-03): read the policy, LOWER a limit (raising stays session-only PATCH
  // /outreach/config), record a contact's published-contact basis (a key must cite the source URL).
  ['GET /v1/orgs/:p/outreach/policy', 'outreach'],
  ['POST /v1/orgs/:p/outreach/policy/tighten', 'outreach'],
  ['POST /v1/orgs/:p/outreach/contacts/:p/basis', 'outreach'],
  // --- P51 outreach slice G7: outbound webhook events. A key may LIST subscriptions (no URL) and UNSUBSCRIBE
  // (both make nothing less safe); subscribing widens what leaves the org, so it is session-only below.
  ['GET /v1/orgs/:p/outreach/webhook-subscriptions', 'outreach'],
  ['DELETE /v1/orgs/:p/outreach/webhook-subscriptions/:p', 'outreach'],
  // --- P51 outreach slice G9: sequences. A key reads sequences, enrols a contact (every step still goes through the
  // permit gate), and makes things SAFER: pause, cancel, report a reply or booking. Authoring a sequence and resuming
  // an enrolment loosen, so they are SESSION_ONLY_ROUTES. Also needs `outreach.sequences` (checked in the handler).
  ['GET /v1/orgs/:p/outreach/sequences', 'outreach'],
  ['GET /v1/orgs/:p/outreach/sequences/:p', 'outreach'],
  // cp-outreach-sequences-bot: who is enrolled, and what stops the sequence starting (both read-only).
  ['GET /v1/orgs/:p/outreach/sequences/:p/enrolments', 'outreach'],
  ['GET /v1/orgs/:p/outreach/sequences/:p/readiness', 'outreach'],
  ['POST /v1/orgs/:p/outreach/sequences/:p/enrolments', 'outreach'],
  ['GET /v1/orgs/:p/outreach/enrolments/:p', 'outreach'],
  ['POST /v1/orgs/:p/outreach/enrolments/:p/pause', 'outreach'],
  ['POST /v1/orgs/:p/outreach/enrolments/:p/cancel', 'outreach'],
  ['POST /v1/orgs/:p/outreach/enrolments/:p/events', 'outreach'],
  // --- P51 BYO sender (dark: also `outreach.byo`, OUTREACH_BYO_ROUTES). An agent sending from its own mailbox
  // polls its send intents, reports replies / bounces / unsubscribes (which only ever ADD suppressions) and may
  // LOWER its own daily cap; raising one is refused in the handler (lopsided). Runners: refused by kind.
  ['GET /v1/orgs/:p/outreach/send-intents', 'outreach'],
  ['POST /v1/orgs/:p/outreach/events/reported', 'outreach'],
  ['POST /v1/orgs/:p/outreach/manual-sends', 'outreach'],
  ['GET /v1/orgs/:p/outreach/external-senders/:p', 'outreach'],
  ['PUT /v1/orgs/:p/outreach/external-senders/:p', 'outreach'],
  // --- GoodQA #358 v2: the registry of LinkedIn accounts (dark: also `outreach.linkedin`, OUTREACH_LINKEDIN_ROUTES).
  // A key may LIST and REMOVE (tightening); registering one is SESSION_ONLY_ROUTES. Runners: refused by kind.
  ['GET /v1/orgs/:p/outreach/linkedin/accounts', 'outreach'],
  ['DELETE /v1/orgs/:p/outreach/linkedin/accounts/:p', 'outreach'],
  // --- P51 Gmail connector: a key may DELIVER a permit through its owner's own connected mailbox (the permit and
  // every send-time re-check still decide). Connecting / disconnecting a mailbox is SESSION_ONLY_ROUTES.
  ['GET /v1/orgs/:p/outreach/gmail/connections', 'outreach'],
  ['POST /v1/orgs/:p/outreach/gmail/connections/:p/check', 'outreach'],
  ['POST /v1/orgs/:p/outreach/sends/:p/deliver', 'outreach'],
  // --- P51 Microsoft 365 connector (docs/design/outreach/OUTLOOK-CONNECTOR.md): a key may DELIVER a permitted send
  // through its owner's own connected mailbox. It can never connect or disconnect one (SESSION_ONLY_ROUTES below).
  ['POST /v1/orgs/:p/outreach/outlook/sends/:p/deliver', 'outreach'],
  // --- P51 outreach, Zoho Mail connector (docs/design/outreach/ZOHO-CONNECTOR.md). A key may DELIVER a permitted send
  // through its own person's connected mailbox, REPORT a reply/bounce/complaint (which can only pause or suppress:
  // the lopsided rule) and read the connection (no secrets). Connecting, setting the app password, disconnecting and
  // resuming a paused mailbox are SESSION_ONLY_ROUTES. Runners: refused by kind (outreach family).
  ['POST /v1/orgs/:p/outreach/zoho/sends/:p/deliver', 'outreach'],
  ['POST /v1/orgs/:p/outreach/mailgun/sends/:p/deliver', 'outreach'],
  ['POST /v1/orgs/:p/outreach/zoho/events', 'outreach'],
  // --- P51 G15: placement tracking. Bots read and record where links/offers are placed; the human-only `verified`
  // flag is refused to keys in the handler (403), and a bot change to a verified row clears it.
  ['GET /v1/orgs/:p/outreach/placements', 'outreach'],
  ['POST /v1/orgs/:p/outreach/placements', 'outreach'],
  ['GET /v1/orgs/:p/outreach/placements/:p', 'outreach'],
  ['PATCH /v1/orgs/:p/outreach/placements/:p', 'outreach'],
  // --- P51 G13: DRAFT-level content and a mailer lead + consent record. Publish / transition / approve / schedule /
  // send / consent withdraw stay on their existing session-only routes; these produce or edit drafts only.
  ['POST /v1/orgs/:p/outreach/drafts/blog-posts', 'outreach'],
  ['PATCH /v1/orgs/:p/outreach/drafts/blog-posts/:p', 'outreach'],
  ['GET /v1/orgs/:p/projects/:p/social-connectors', 'outreach'],
  ['POST /v1/orgs/:p/projects/:p/social-connectors/bindings/:p/operations/:p/readback', 'outreach'],
  ['POST /v1/orgs/:p/projects/:p/social-connectors/week-handoffs', 'outreach'],
  ['POST /v1/orgs/:p/outreach/drafts/social-posts', 'outreach'],
  // Supplied weekly drafts: proposed times only; approval remains session-only.
  ['GET /v1/orgs/:p/projects/:p/marketing/social/weeks', 'outreach'],
  ['POST /v1/orgs/:p/projects/:p/marketing/social/weeks', 'outreach'],
  ['POST /v1/orgs/:p/projects/:p/marketing/social/weeks/preparations', 'outreach'],
  ['GET /v1/orgs/:p/projects/:p/marketing/social/weeks/:p/preparation', 'outreach'],
  ['POST /v1/orgs/:p/projects/:p/marketing/social/weeks/:p/preparation/advance', 'outreach'],
  ['POST /v1/orgs/:p/projects/:p/marketing/social/weeks/:p/preparation/stop', 'outreach'],
  ['GET /v1/orgs/:p/projects/:p/marketing/social/weeks/media', 'outreach'],
  ['GET /v1/orgs/:p/projects/:p/marketing/social/weeks/targets', 'outreach'],
  ['GET /v1/orgs/:p/projects/:p/marketing/social/weeks/:p', 'outreach'],
  ['GET /v1/orgs/:p/projects/:p/marketing/social/weeks/:p/calendar', 'outreach'],
  ['PATCH /v1/orgs/:p/projects/:p/marketing/social/weeks/:p/posts/:p/channels/:p', 'outreach'],
  ['POST /v1/orgs/:p/projects/:p/marketing/social/weeks/:p/request-review', 'outreach'],
  // Campaign handoffs: existing outreach flags/scopes/project checks remain required.
  ['GET /v1/orgs/:p/projects/:p/content-campaigns', 'outreach'],
  ['GET /v1/orgs/:p/projects/:p/content-campaigns/capabilities', 'outreach'],
  ['POST /v1/orgs/:p/projects/:p/content-campaigns', 'outreach'],
  ['GET /v1/orgs/:p/projects/:p/content-campaigns/:p', 'outreach'],
  ['POST /v1/orgs/:p/projects/:p/content-campaigns/:p/stop', 'outreach'],
  ['POST /v1/orgs/:p/projects/:p/content-campaigns/:p/request-review', 'outreach'],
  ['POST /v1/orgs/:p/projects/:p/content-campaigns/:p/assets', 'outreach'],
  ['PATCH /v1/orgs/:p/projects/:p/content-campaigns/:p/posts/:p/channels/:p', 'outreach'],
  ['PATCH /v1/orgs/:p/outreach/drafts/social-posts/:p/channels/:p', 'outreach'],
  ['POST /v1/orgs/:p/outreach/drafts/cms-documents', 'outreach'],
  ['PATCH /v1/orgs/:p/outreach/drafts/cms-documents/:p', 'outreach'],
  ['POST /v1/orgs/:p/outreach/drafts/mailer-leads', 'outreach'],
  ['GET /v1/orgs/:p/outreach/zoho/connection', 'outreach'],
  // --- P51 outreach slice G8: the agent work queue (dark: also `outreach.queue`). A key lists, claims, heartbeats,
  // completes and releases SERVER-enqueued items; it can never create one, and completing performs nothing (every
  // effect still goes through the permit). Runners refused by kind, user-scoped keys by family (both centrally).
  ['GET /v1/orgs/:p/outreach/work-items', 'outreach'],
  ['POST /v1/orgs/:p/outreach/work-items/claim', 'outreach'],
  ['GET /v1/orgs/:p/outreach/work-items/:p', 'outreach'],
  ['POST /v1/orgs/:p/outreach/work-items/:p/heartbeat', 'outreach'],
  ['POST /v1/orgs/:p/outreach/work-items/:p/complete', 'outreach'],
  ['POST /v1/orgs/:p/outreach/work-items/:p/release', 'outreach'],
  // --- P51 outreach slice G16: the lead ledger (dark: also `outreach.leads`). A key captures (citing evidence), reads
  // and DISQUALIFIES a lead; qualifying one is a person's act (SESSION_ONLY_ROUTES + a database trigger).
  ['POST /v1/orgs/:p/outreach/leads', 'outreach'],
  ['POST /v1/orgs/:p/outreach/leads/import', 'outreach'],
  ['GET /v1/orgs/:p/outreach/leads', 'outreach'],
  ['GET /v1/orgs/:p/outreach/leads/:p', 'outreach'],
  ['POST /v1/orgs/:p/outreach/leads/:p/disqualify', 'outreach'],
  // --- Custom data (slice D2): the gated SQL surface bots use. Grants, roles, provisioning and
  // dropping databases are NOT here and will be SESSION_ONLY (DESIGN 5.6); a key reaches only these.
  // D6: the org data status the MCP servers ask before registering the data tools (and the `data_status` tool).
  ['GET /v1/orgs/:p/data', 'data'],
  ['POST /v1/orgs/:p/data/databases/:p/query', 'data'],
  ['POST /v1/orgs/:p/data/databases/:p/explain', 'data'],
  ['GET /v1/orgs/:p/data/databases/:p/describe', 'data'],
  // Slice D3: structured calls compile to SQL and run through the same gate (same tiers, same policy).
  ['POST /v1/orgs/:p/data/databases/:p/tables', 'data'],
  ['PATCH /v1/orgs/:p/data/databases/:p/tables/:p', 'data'],
  ['GET /v1/orgs/:p/data/databases/:p/tables/:p/rows', 'data'],
  ['POST /v1/orgs/:p/data/databases/:p/tables/:p/rows', 'data'],
  ['PATCH /v1/orgs/:p/data/databases/:p/tables/:p/rows', 'data'],
  ['DELETE /v1/orgs/:p/data/databases/:p/tables/:p/rows', 'data'],
  ['POST /v1/orgs/:p/data/databases/:p/tables/:p/query', 'data'],
  ['POST /v1/orgs/:p/data/databases/:p/tables/:p/import', 'data'],
  ['POST /v1/orgs/:p/data/databases/:p/tables/:p/export', 'data'],
  // LIVE-A ruling 3: structured materialized views (DDL class: the gate needs data:manage, i.e. the owner tier).
  ['POST /v1/orgs/:p/data/databases/:p/matviews', 'data'],
  ['POST /v1/orgs/:p/data/databases/:p/matviews/:p/refresh', 'data'],
  ['DELETE /v1/orgs/:p/data/databases/:p/matviews/:p', 'data'],
  // --- CRM v2 C0 (owner decision Q3): CRM opens to API keys and MCP, per org ---
  // Every entry below is in the `crm` family AND dark behind the org's
  // `crm.api.enabled` entitlement (default off; checked centrally in
  // registerAuthPlugin, so off means the app's own 404 for a key and nothing
  // at all changes for a session). Deliberately STILL session-only, in
  // SESSION_ONLY_ROUTES below: contacts export, CSV import, segment
  // materialize, mailboxes and mailer sync (a user's own mailbox), AI assist
  // (private to the requesting human), raising an issue from a contact, and --
  // for this first cut -- every route that returns timeline entries
  // (contact detail and timeline reads/writes, meetings), because an API key
  // acts as its creator and would otherwise read that person's `personal`
  // notes; the v2 notes sugar is the key's way in. Pipelines, deals, the graph
  // and issue links stay session-only until their own slice classifies them.
  ['GET /v1/orgs/:p/projects/:p/business-delivery', 'crm'],
  ['POST /v1/orgs/:p/projects/:p/business-delivery/drafts', 'crm'],
  ['GET /v1/orgs/:p/crm/forms/:p/mapping', 'crm'],
  ['POST /v1/orgs/:p/automations/step-test', 'crm'],
  ['GET /v1/orgs/:p/automations/step-test/input', 'crm'],
  ['GET /v1/orgs/:p/automations', 'crm'],
  ['GET /v1/orgs/:p/automations/health', 'crm'],
  ['GET /v1/orgs/:p/automations/:p/hook', 'crm'],
  ['GET /v1/orgs/:p/automations/:p/schedule', 'crm'],
  ['PUT /v1/orgs/:p/automations/:p/schedule', 'crm'],
  ['POST /v1/orgs/:p/automations/:p/schedule/preview', 'crm'],
  ['GET /v1/orgs/:p/automations/:p/schedule/occurrences', 'crm'],
  ['POST /v1/orgs/:p/automations/:p/hook', 'crm'],
  ['DELETE /v1/orgs/:p/automations/:p/hook', 'crm'],
  ['GET /v1/orgs/:p/automation-recipes', 'crm'],
  ['POST /v1/orgs/:p/automation-recipes/compile', 'crm'],
  ['GET /v1/orgs/:p/automation-assembly', 'crm'],
  ['POST /v1/orgs/:p/automation-assembly/compile', 'crm'],
  ['GET /v1/orgs/:p/automation-nodes', 'crm'],
  ['POST /v1/orgs/:p/automations', 'crm'],
  ['PATCH /v1/orgs/:p/automations/:p', 'crm'],
  ['POST /v1/orgs/:p/automations/:p/enable', 'crm'],
  ['POST /v1/orgs/:p/automations/:p/runs/:p/cancel', 'crm'],
  ['GET /v1/orgs/:p/automations/:p/runs', 'crm'],
  ['GET /v1/orgs/:p/automations/:p/versions', 'crm'],
  ['GET /v1/orgs/:p/automations/:p/versions/:p', 'crm'],
  ['POST /v1/orgs/:p/automations/:p/versions/:p/restore', 'crm'],
  ['POST /v1/orgs/:p/automations/:p/duplicate', 'crm'],
  ['POST /v1/orgs/:p/automations/:p/archive', 'crm'],
  ['POST /v1/orgs/:p/automations/:p/unarchive', 'crm'],

  ['GET /v1/orgs/:p/automations/:p/runs/:p/context', 'crm'],
  ['POST /v1/orgs/:p/automations/:p/runs', 'crm'],
  ['POST /v1/orgs/:p/automations/:p/runs/:p/retry', 'crm'],
  ['PUT /v1/orgs/:p/crm/forms/:p/mapping', 'crm'],
  ['GET /v1/orgs/:p/crm/reports', 'crm'],
  // Native business reports are org-wide CRM reads; handlers recheck membership and refuse project-bound keys.
  ['GET /v1/orgs/:p/business-reports/definitions', 'crm'],
  ['GET /v1/orgs/:p/business-reports/runs', 'crm'],
  ['GET /v1/orgs/:p/business-reports/runs/:p', 'crm'],
  ['GET /v1/orgs/:p/business-reports/runs/:p/metrics/:p/items', 'crm'],
  ['GET /v1/orgs/:p/business-reports/preview', 'crm'],
  ['POST /v1/orgs/:p/crm/reports', 'crm'],
  ['POST /v1/orgs/:p/crm/reports/:p/run', 'crm'],
  ['GET /v1/orgs/:p/crm/reports/:p/export.csv', 'crm'],
  ['GET /v1/orgs/:p/crm/companies', 'crm'],
  ['POST /v1/orgs/:p/crm/companies', 'crm'],
  ['GET /v1/orgs/:p/crm/companies/:p', 'crm'],
  ['PATCH /v1/orgs/:p/crm/companies/:p', 'crm'],
  ['GET /v1/orgs/:p/crm/contacts', 'crm'],
  ['POST /v1/orgs/:p/crm/contacts', 'crm'],
  ['PATCH /v1/orgs/:p/crm/contacts/:p', 'crm'],
  ['POST /v1/orgs/:p/crm/contacts/:p/archive', 'crm'],
  ['POST /v1/orgs/:p/crm/contacts/:p/unarchive', 'crm'],
  ['GET /v1/orgs/:p/crm/tags', 'crm'],
  ['GET /v1/orgs/:p/trigger-links', 'crm'],
  ['POST /v1/orgs/:p/trigger-links', 'crm'],
  ['POST /v1/orgs/:p/trigger-links/import', 'crm'],
  ['GET /v1/orgs/:p/trigger-links/:p', 'crm'],
  ['PATCH /v1/orgs/:p/trigger-links/:p', 'crm'],
  ['DELETE /v1/orgs/:p/trigger-links/:p', 'crm'],
  ['GET /v1/orgs/:p/trigger-links/:p/stats', 'crm'],
  ['POST /v1/orgs/:p/trigger-links/:p/mint', 'crm'],
  ['POST /v1/orgs/:p/crm/tags', 'crm'],
  ['PATCH /v1/orgs/:p/crm/tags/:p', 'crm'],
  ['DELETE /v1/orgs/:p/crm/tags/:p', 'crm'],
  ['GET /v1/orgs/:p/crm/:p/:p/tags', 'crm'],
  ['POST /v1/orgs/:p/crm/:p/:p/tags', 'crm'],
  ['DELETE /v1/orgs/:p/crm/:p/:p/tags/:p', 'crm'],
  ['GET /v1/orgs/:p/crm/fields', 'crm'],
  ['POST /v1/orgs/:p/crm/fields', 'crm'],
  ['POST /v1/orgs/:p/crm/fields/reorder', 'crm'],
  ['PATCH /v1/orgs/:p/crm/fields/:p', 'crm'],
  ['DELETE /v1/orgs/:p/crm/fields/:p', 'crm'],
  ['GET /v1/orgs/:p/crm/:p/:p/fields', 'crm'],
  ['PATCH /v1/orgs/:p/crm/:p/:p/fields', 'crm'],
  ['GET /v1/orgs/:p/crm/segments', 'crm'],
  ['POST /v1/orgs/:p/crm/segments', 'crm'],
  ['GET /v1/orgs/:p/crm/segments/:p', 'crm'],
  ['PATCH /v1/orgs/:p/crm/segments/:p', 'crm'],
  ['DELETE /v1/orgs/:p/crm/segments/:p', 'crm'],
  ['POST /v1/orgs/:p/crm/segments/:p/restore', 'crm'],
  ['GET /v1/orgs/:p/crm/segments/:p/preview', 'crm'],
  ['GET /v1/orgs/:p/crm/segments/:p/materializations', 'crm'],
  ['POST /v1/orgs/:p/crm/records', 'crm'],
  ['GET /v1/orgs/:p/crm/records', 'crm'],
  ['GET /v1/orgs/:p/crm/deals', 'crm'],
  ['GET /v1/orgs/:p/crm/pipelines/:p', 'crm'],
  // Read-only duplicate preview; confirm remains closed to keys and tokens.
  ['GET /v1/orgs/:p/crm/contact-merge/preview', 'crm'],
  ['GET /v1/orgs/:p/crm/records/:p/:p', 'crm'],
  ['PATCH /v1/orgs/:p/crm/records/:p/:p', 'crm'],
  ['PUT /v1/orgs/:p/crm/records/:p/:p/flags', 'crm'],
  ['POST /v1/orgs/:p/crm/records/:p/:p/flags', 'crm'],
  ['PUT /v1/orgs/:p/crm/records/:p/:p/tags', 'crm'],
  ['POST /v1/orgs/:p/crm/records/:p/:p/notes', 'crm'],
  // Demo hotfix 2026-10-14 (bot-crm-api): read back org-visible, project-less notes only (never personal entries).
  ['GET /v1/orgs/:p/crm/records/:p/:p/notes', 'crm'],
  ['GET /v1/orgs/:p/crm/flags', 'crm'],
  // P51 slice B (G1/G11): the keyed upsert routes and the batch. Same family, same central crm.api.enabled
  // gate, each handler ALSO dark behind crm.v2.records and checking the caller's own RBAC. `records::batchUpsert`
  // is Fastify's spelling of the literal path `records:batchUpsert` (a colon starts a param, so a literal one is
  // doubled); normalizeRoutePattern turns it into `records:p` for every comparison, here and in the coverage test.
  ['PUT /v1/orgs/:p/crm/external/:p/:p', 'crm'],
  ['GET /v1/orgs/:p/crm/external/:p/:p', 'crm'],
  ['POST /v1/orgs/:p/crm/records::batchUpsert', 'crm'],
  // CRM v2 lane B (C4 search, flag definitions, company/person archive). Same
  // family and the same central crm.api.enabled gate; each handler is ALSO
  // dark behind crm.v2.records and checks the caller's own RBAC (search:
  // crm:read; flags: crm:manage_fields; archive: crm:archive).
  ['POST /v1/orgs/:p/crm/records/search', 'crm'],
  ['POST /v1/orgs/:p/crm/records/:p/:p/archive', 'crm'],
  ['POST /v1/orgs/:p/crm/flags', 'crm'],
  ['PATCH /v1/orgs/:p/crm/flags/:p', 'crm'],
  ['DELETE /v1/orgs/:p/crm/flags/:p', 'crm'],
  // CRM v2 C5/C6 (relationships, neighbours, paths): same family, same central
  // crm.api.enabled gate, and each route is ALSO dark behind the org's
  // crm.v2.relationships (the route's own 404). Edges join two CRM records and
  // carry no timeline entry, so nothing here can reveal a personal note.
  ['GET /v1/orgs/:p/crm/relationship-types', 'crm'],
  ['POST /v1/orgs/:p/crm/relationship-types', 'crm'],
  ['PATCH /v1/orgs/:p/crm/relationship-types/:p', 'crm'],
  ['POST /v1/orgs/:p/crm/relationships', 'crm'],
  ['GET /v1/orgs/:p/crm/relationships/neighbors', 'crm'],
  ['POST /v1/orgs/:p/crm/relationships/paths', 'crm'],
  ['GET /v1/orgs/:p/crm/relationships/:p', 'crm'],
  ['PATCH /v1/orgs/:p/crm/relationships/:p', 'crm'],
  ['POST /v1/orgs/:p/crm/relationships/:p/end', 'crm'],
  ['DELETE /v1/orgs/:p/crm/relationships/:p', 'crm'],
  ['GET /v1/orgs/:p/crm/records/:p/:p/relationships', 'crm'],
  // CRM v2 C7/C8 (lifecycles, applicability rules): same family, same central
  // crm.api.enabled gate, and each route is ALSO dark behind the org's
  // crm.v2.lifecycles (the route's own 404). Defining needs
  // crm:manage_lifecycles; enrol/transition need crm:edit. No timeline entry
  // is read or written here, so no personal note can leak.
  ['GET /v1/orgs/:p/crm/lifecycles', 'crm'],
  ['POST /v1/orgs/:p/crm/lifecycles', 'crm'],
  ['GET /v1/orgs/:p/crm/lifecycles/:p', 'crm'],
  ['PUT /v1/orgs/:p/crm/lifecycles/:p/draft', 'crm'],
  ['POST /v1/orgs/:p/crm/lifecycles/:p/publish', 'crm'],
  ['POST /v1/orgs/:p/crm/lifecycles/:p/migrate', 'crm'],
  ['GET /v1/orgs/:p/crm/lifecycle-rules', 'crm'],
  ['POST /v1/orgs/:p/crm/lifecycle-rules', 'crm'],
  ['DELETE /v1/orgs/:p/crm/lifecycle-rules/:p', 'crm'],
  // C9/C10 first slice: READ-ONLY. Overdue instances (crm.v2.lifecycles) and CRM webhook subscriptions (crm.v2.webhooks,
  // origin-only URLs). Creating / changing / deleting a webhook receiver stays session-only: a key must never be able to
  // point org data at an address.
  ['GET /v1/orgs/:p/crm/lifecycle-overdue', 'crm'],
  ['GET /v1/orgs/:p/crm/webhook-subscriptions', 'crm'],
  ['GET /v1/orgs/:p/crm/records/:p/:p/lifecycles', 'crm'],
  ['POST /v1/orgs/:p/crm/records/:p/:p/lifecycles', 'crm'],
  ['POST /v1/orgs/:p/crm/records/:p/:p/lifecycles/:p/transition', 'crm'],
  ['GET /v1/orgs/:p/crm/records/:p/:p/lifecycles/:p/history', 'crm'],
  // --- Review Studio: everything a key may reach is a READ or a PROPOSAL ---
  // The dividing line is Part 5.1's own: reads, ordinary edits and
  // approval-REQUESTS are key-reachable; approving, locking, publishing,
  // exporting, granting capabilities and changing a roster are session-only and
  // live in SESSION_ONLY_ROUTES below. Creating an approval request approves
  // nothing, which is exactly why an agent may do it.
  ['GET /v1/projects/:p/experience-reviews', 'experience_reviews'],
  ['POST /v1/projects/:p/experience-reviews', 'experience_reviews'],
  ['GET /v1/experience-reviews/:p', 'experience_reviews'],
  ['PATCH /v1/experience-reviews/:p', 'experience_reviews'],
  ['POST /v1/experience-reviews/:p/setup/:p', 'experience_reviews'],
  ['POST /v1/experience-reviews/:p/setup/dry-run', 'experience_reviews'],
  ['GET /v1/experience-reviews/:p/summary', 'experience_reviews'],
  ['GET /v1/experience-reviews/:p/start', 'experience_reviews'],
  ['GET /v1/experience-reviews/:p/help', 'experience_reviews'],
  // Board #117's identity-resolution carve-out: reading WHO is involved is how
  // an agent names a person. Every write to this roster stays session-only.
  ['GET /v1/experience-reviews/:p/members', 'experience_reviews'],
  ['GET /v1/experience-reviews/:p/role-view', 'experience_reviews'],
  ['PUT /v1/experience-reviews/:p/role-view', 'experience_reviews'],
  ['GET /v1/experience-reviews/:p/governance-policy', 'experience_reviews'],
  ['POST /v1/experience-reviews/:p/approval-requests', 'experience_reviews'],
  ['GET /v1/experience-reviews/:p/approval-requests', 'experience_reviews'],
  ['GET /v1/review-approval-requests/:p', 'experience_reviews'],
  ['GET /v1/experience-reviews/:p/history', 'experience_reviews'],
  ['GET /v1/experience-reviews/:p/search', 'experience_reviews'],

  // --- invitations: bring a person in, but never become one ---
  //
  // Eric, 2026-09-07: "make api keys able to do invites." Safe here because the
  // routes' own defences already close every escalation path, and they close
  // them against the key's CAPPED authority rather than its human's:
  //
  //   1. `requireOrgPermission(..., 'org:manage_members')` — the key's human
  //      must hold the permission at all.
  //   2. `orgRole === 'owner'` is refused outright
  //      (modules/orgs/routes.ts:997).
  //   3. The rank guard `orgRoleAtLeast(myRole, body.orgRole)` (:1004), where
  //      `myRole` came from `requireOrgPermission` -> `getOrgMembership`, which
  //      returns `cappedOrgRole(row.role)` (lib/access.ts:1544). So a key whose
  //      `maxOrgRole` ceiling is `member` cannot invite an `admin` even when the
  //      human behind it is an owner. Verified, not assumed — the whole
  //      argument for opening this route rests on that one call.
  //   4. `assertWithinApiKeyScope` binds the key to its own org.
  //   5. 30 invites/hour per caller, because each one mails an attacker-chosen
  //      address from a verified domain.
  //
  // What this deliberately does NOT relax is the rule two blocks below in
  // SESSION_ONLY_ROUTES: a key still cannot mint another API key. An invite
  // creates a PERSON, who must then authenticate as themselves and who an admin
  // can see and remove; a key creates a bearer credential that needs nobody.
  // Those are different risks and only one of them is opened here.
  //
  // The DELETE is included on purpose. Create-without-revoke is a trap: an
  // agent that mis-addresses an invite would have no way to withdraw it, and
  // the outstanding invite holds a seat. Revoking an unaccepted invite removes
  // nobody's access — this is the one `/invites` DELETE the structural-delete
  // property test carves out, and it says so there.
  ['POST /v1/orgs/:p/invites', 'invites'],
  ['GET /v1/orgs/:p/invites', 'invites'],
  ['POST /v1/orgs/:p/invites/:p/link', 'invites'],
  ['DELETE /v1/orgs/:p/invites/:p', 'invites'],

  // --- desktop recorder: identify itself, then upload and attach evidence ---
  ['GET /v1/me', 'orgs'],
  // Agent discovery lane (2026-10-04): "what can THIS key do here". EVERY authenticated key may ask, whatever families
  // it names -- an empty requirement, so a key narrowed to `crm` (or a runner key) can still learn what it reaches. It
  // answers only for the key's own org (another org id is the non-member 404) and reports states and names, never a
  // secret. Paused keys stay refused (only PAUSED_KEY_EXEMPT_ROUTE answers them). Absent while AGENT_DISCOVERY_ENABLED=false.
  ['GET /v1/capabilities', []],
  ['GET /v1/me/abilities', []],
  ['POST /v1/projects/:p/uploads', 'uploads'],
  ['PUT /v1/uploads/:p/content', 'uploads'],
  ['POST /v1/uploads/:p/complete', 'uploads'],
  // TASK-298: an agent that can file an issue and upload its evidence must be
  // able to read the completed bytes back. The handlers resolve the owning
  // issue/comment before minting a signed URL and enforce user-scope plus
  // category visibility; unrelated project attachments stay unavailable to
  // keys. Both families are required because the credential is crossing from
  // issue data into the private upload store.
  ['GET /v1/uploads/:p/content', ['issues', 'uploads']],
  ['GET /v1/uploads/:p/content/read-target', ['issues', 'uploads']],
  ['POST /v1/issues/:p/attachments', 'uploads'],
  ['POST /v1/step-results/:p/attachments', 'uploads'],
  ['POST /v1/attachments/:p/transcode', 'uploads'],
  // The transcript pair, classified exactly as the transcode trigger and the
  // content reads above are, and for the same reasons. An agent that can upload
  // a recording and read its bytes back can already hear everything a
  // transcript contains -- refusing the text while allowing the audio would not
  // narrow what the credential reaches, only make it harder to use.
  //
  // `GET /v1/attachments/:p/transcript` carries BOTH families for the reason
  // `GET /v1/uploads/:p/content` states directly above: the credential is
  // crossing from issue data into the private upload store, and the handler
  // resolves the owning issue/comment/conversation/meeting boundary before
  // returning a word. A key is additionally refused outright by
  // `assertChatMessageEvidenceReadable` / `assertTimelineEntryEvidenceReadable`
  // for a DM or meeting recording, so no key can read a transcript of either.
  ['POST /v1/attachments/:p/transcribe', 'uploads'],
  ['GET /v1/attachments/:p/transcript', ['issues', 'uploads']],
  // The two READ halves of recording ticket proposals, carrying BOTH families
  // for exactly the reason the transcript read above states: a proposal quotes
  // the transcript verbatim, so reaching one is reaching the recording's
  // content, and the handler resolves the owning issue/comment/conversation/
  // meeting boundary through `resolveAttachmentAuthority` +
  // `assertAttachmentParentEvidenceReadable` before returning a word. A key is
  // additionally refused outright for a DM or meeting recording by
  // `assertChatMessageEvidenceReadable` / `assertTimelineEntryEvidenceReadable`.
  //
  // The two DECISION halves are SESSION_ONLY below, and that is a product rule
  // rather than a security ladder -- see their entry there.
  ['GET /v1/attachments/:p/proposals', ['issues', 'uploads']],
  // STARTING the analysis is classified exactly as the transcode and transcribe
  // triggers above are, and for the identical reason: it is the same act on the
  // same object -- deriving something from bytes the credential could already
  // upload and read back. It creates nothing on a board; it produces PROPOSALS,
  // and the decision routes that turn one into a ticket are session-only below.
  ['POST /v1/attachments/:p/analyze', 'uploads'],
  ['GET /v1/recording-proposals/:p/bug-draft', ['issues', 'uploads']],
  // Same shape as POST /v1/issues/:p/attachments above -- a comment attachment
  // is just a narrower evidence target, not a different authority. See that
  // route's own doc comment (uploads/routes.ts) for why this was previously
  // unreachable regardless of scope: the route did not exist at all.
  ['POST /v1/issues/:p/comments/:p/attachments', 'uploads'],

  // --- MCP: read the workspace ---
  ['GET /v1/orgs', 'orgs'],
  // Reading the key's OWN org. Not called by either consumer directly, but it is
  // the read that `api-keys.test.ts` uses to prove confinement works at all —
  // org A returns 200, org B returns 404 — and a client that lists orgs will
  // want to name the one it is in. A confined read with no side effects.
  ['GET /v1/orgs/:p', 'orgs'],
  // GoodQA board #117: an integration that files/updates issues on someone's
  // behalf (e.g. setting `assigneeId`) has to be able to resolve a human name
  // to a userId, and had no way to — both member-list reads 403'd every API
  // key outright, before the handler's own checks ever ran. Same reasoning as
  // `GET /v1/orgs/:orgId/api-keys/agents` (board #58/#59, right above this
  // list's api-keys entries): identity resolution ("who's on this team, so I
  // can name them") is a lower bar than membership MANAGEMENT, which is what
  // `org:manage_members` gates on the PATCH/PUT/DELETE member routes nearby —
  // those stay off this list entirely. Read-only, no scopes/roles/emails beyond
  // what a project member already sees in the app; the handlers
  // (`requireOrgRole` / `requireProjectRole`, apps/api/src/lib/access.ts)
  // already enforce the same org confinement and role ceiling as every other
  // API-key-reachable read here, unchanged by this entry.
  ['GET /v1/orgs/:p/members', 'orgs'],
  ['GET /v1/orgs/:p/credential-guard', 'orgs'],
  ['GET /v1/orgs/:p/projects', 'projects'],
  ['GET /v1/projects/:p', 'projects'],
  ['GET /v1/projects/:p/members', 'projects'],
  ['GET /v1/projects/:p/issues', 'issues'],
  ['GET /v1/projects/:p/issues/by-number/:p', 'issues'],
  ['GET /v1/projects/:p/test-plans', 'testing'],
  // What a caller may generate, and which environments/surfaces they may pick.
  // `testing` rather than `ai`, unlike the POST it describes: this route reads
  // rows and spends nothing. A key that may list test plans may equally be told
  // that it is not entitled to generate one.
  ['GET /v1/projects/:p/test-plans/generation-options', 'testing'],
  ['GET /v1/projects/:p/missions', 'testing'],
  ['GET /v1/test-plans/:p', 'testing'],
  ['GET /v1/missions/:p', 'testing'],
  ['GET /v1/missions/:p/versions/:p', 'testing'],
  ['GET /v1/issues/:p', 'issues'],
  ['GET /v1/issues/:p/fix-pull-requests', 'github'],
  // POST of this same route was already allowed below, but the read-back
  // never was -- a key could write a comment and never read the thread it
  // just wrote into. No plausible security reason to withhold it once
  // POST + the issue itself are both already allowed; same access floor as
  // GET /v1/issues/:p (requireProjectRole, viewer, org-confined).
  ['GET /v1/issues/:p/comments', 'issues'],
  // TASK-72 durable comment actions use the same issue-level authorization
  // as the issue and comment routes around them. API keys must be able to
  // read back and resolve requests they create; the handlers still enforce
  // org confinement, scoped-user visibility, role ceilings, and target /
  // requester / editor authorization before exposing or mutating a row.
  ['GET /v1/issues/:p/task-actions', 'issues'],
  ['GET /v1/issues/:p/task-action-targets', 'issues'],
  ['PATCH /v1/issues/:p/task-actions/:p', 'issues'],
  // The activity feed for an issue already reachable via GET /v1/issues/:p
  // and whose comments are already reachable above — same "an agent can read
  // what it can already open" reasoning, board #37's scoped-key visibility
  // gate applies here exactly as it does to the comments read.
  ['GET /v1/issues/:p/events', 'issues'],
  // Board #342: goodqa.app measured these as 404 and reported the hierarchy/
  // issue-links FEATURES as missing from production; they were not — #38/#39
  // were already shipped and this exact 403 (not 404) confirmed it once
  // retested here. The routes were just never added to this allowlist. Same
  // access floor as GET /v1/issues/:p (requireProjectRole, viewer,
  // org/project-confined, 404-not-403 on an inaccessible project) —
  // hierarchy/routes.ts's own doc comment for this route explicitly says so
  // (board #162 fix). An agent that can already read an issue can already
  // read its parent-epic breadcrumb; no new information is exposed.
  ['GET /v1/issues/:p/hierarchy', 'issues'],
  // Same reasoning: read is any project member (viewer floor), matching
  // GET /v1/issues/:p already allowed above. issue-links/routes.ts's own
  // module doc comment states this explicitly ("Read is any project
  // member").
  ['GET /v1/issues/:p/links', 'issues'],
  // TASK-484: same "an agent that can already read the issue can already
  // read what points at it" reasoning as the links read directly above.
  ['GET /v1/issues/:p/decisions', 'issues'],
  // Board #153 slice 10 (recovery-integration, 2026-09-11): custom-field
  // rollups are computed, read-only issue metadata -- the same "an agent
  // that can already read the issue can already read this derived view of
  // it" reasoning as hierarchy/links/decisions immediately above. No write
  // route exists here; field DEFINITIONS stay session-only per the
  // `GET /v1/projects/:p/fields` precedent further below.
  ['GET /v1/issues/:p/field-rollups', 'issues'],
  // Write floor is 'developer' per issue-links/routes.ts's own doc comment
  // ("write (create/remove a link) is developer -- the same floor the
  // sibling dependencies module uses for the same reason: recording a real
  // relationship between findings is part of doing the work, not a
  // planning-only privilege"). The handler itself enforces 'developer' on
  // the source project and 'viewer' on the target project (same-org,
  // requireProjectRole 404-not-403 both sides) -- this allowlist entry adds
  // no new authorization surface, it only lets an API key reach the check
  // that was already there for every other caller.
  ['POST /v1/issues/:p/links', 'issues'],
  // Board #298: POST of an attachment was allowed and the read-back never was,
  // so an agent could upload evidence and had no way to confirm it landed --
  // the same asymmetry the comments read (above) closed. Allowlisted only
  // after giving the handler the per-issue category guard it was missing --
  // `assertIssueCategoryReadableForRequest`, the board #37 finding 2 variant,
  // so a USER-SCOPED key is measured against its bound user's grants and not
  // its creator's. A key that can now list attachments still cannot list them
  // for an issue in a category it cannot read, and a scoped key cannot list
  // them for an issue it 404s on at GET /v1/issues/:p.
  //
  // Both families are required (an array is ALL, not any), which is the narrow
  // reading on purpose: the consumer this exists for is an agent that files the
  // issue AND attaches the evidence, so it holds both already. A recorder key
  // scoped to `uploads` alone can still upload; it has no reason to enumerate
  // an issue's evidence. A key naming no families at all is unrestricted, as
  // everywhere else here.
  ['GET /v1/issues/:p/attachments', ['issues', 'uploads']],
  ['GET /v1/issues/:p/files', ['issues', 'uploads']],
  ['GET /v1/issues/:p/files/:p/content', ['issues', 'uploads']],
  // Same "an agent that files the issue AND attaches evidence holds both
  // already" reasoning as the issue-level read directly above, narrowed to
  // one comment's evidence instead of the issue's own gallery.
  ['GET /v1/issues/:p/comments/:p/attachments', ['issues', 'uploads']],
  ['GET /v1/issues/:p/verifications', ['issues', 'testing']],
  // Poll for a requested Suggest Fix run's status/proposal. Same permission
  // floor as GET /v1/issues/:p ('project:view'), see suggest-fix/routes.ts.
  ['GET /v1/issues/:p/suggest-fix/runs/:p', 'ai'],
  // Durable read-back for generate_test_plan. Without this, an AI-scoped MCP
  // key could start a plan but could not recover it after an ambiguous timeout.
  ['GET /v1/projects/:p/ai/generate-plan/:p', 'ai'],
  // Board #371: the notifications feed. Left out of board #299's MCP pass
  // deliberately -- this file's own rule above is "justified by a real
  // consumer that calls it", and none existed yet. list_notifications
  // (apps/mcp/src/server.ts) is that consumer, added in this same change.
  // Same org/scoped-user confinement as every other read here
  // (notifications/routes.ts: apiKeyScopedToUserId ?? userId, keyOrgId-or-
  // active-memberships) -- no new authorization logic, only reachability.
  ['GET /v1/notifications', 'notifications'],
  ['GET /v1/me/notification-deliveries', 'notifications'],

  // --- MCP: file and refine work ---
  ['POST /v1/projects/:p/issues', 'issues'],
  ['PATCH /v1/issues/:p', 'issues'],
  // Archive/unarchive belong here for the same reason PATCH does, and their
  // absence was an oversight rather than a policy: the routes shipped
  // (issues/routes.ts:1998,2004) without ever being registered in this map, so
  // `apiKeyRouteResources` returned undefined and the fail-closed check above
  // 403'd them.
  //
  // The asymmetry that makes this clearly a gap: the same key could already
  // `PATCH` an issue's status to `wont_fix` -- the LESS reversible and more
  // semantically loaded operation -- while being unable to archive, which the
  // route's own docblock describes as gated at `issue:edit` rather than
  // `issue:delete` precisely because "archiving is reversible and meant to be
  // an everyday, low-friction action, unlike deletion". An everyday reversible
  // action is exactly what an integration should be able to do.
  ['POST /v1/issues/:p/archive', 'issues'],
  ['POST /v1/issues/:p/unarchive', 'issues'],
  ['POST /v1/issues/:p/comments', 'issues'],
  // Board #36: an autonomous agent (e.g. a CI-driven test run) marking "dev:
  // pass/fail" after actually exercising a fix is exactly the kind of action
  // a scoped API key exists for. Gated the same as everything else here —
  // issue:manage_verification is still enforced (the KEY CREATOR must hold
  // it), and board #37's scoped-key visibility check applies on top.
  ['PATCH /v1/issues/:p/verification-lanes/:p', 'issues'],
  ['POST /v1/issues/:p/verifications', ['issues', 'testing']],
  // TASK-484: a `type: 'decision'` issue is still just an issue -- 'issues'
  // is the right (and only) resource tag, same as every other issue-scoped
  // write above. Deliberately NOT the pre-existing 'decisions' resource
  // (board #106's unrelated quorum-authority protocol) -- a key scoped to
  // that resource has no business here, and vice versa; see
  // `issue-decisions.ts`'s header comment for the full disambiguation.
  ['PATCH /v1/issues/:p/decision/decider', 'issues'],
  ['POST /v1/issues/:p/decision/answer', 'issues'],
  ['POST /v1/issues/:p/ai/enhance', 'ai'],
  ['POST /v1/projects/:p/ai/generate-plan', 'ai'],
  // The grounded generator (`modules/testing/generate-from-code-routes.ts`).
  // `ai` rather than `testing` for the same reason `generate-plan` above is:
  // the resource an API key must hold is the one that SPENDS, and this route
  // makes a metered Vertex call per screen plus one per proposed step. It
  // writes only a DRAFT plan -- it cannot start a mission -- so a key holding
  // `ai` cannot use it to run anything.
  ['POST /v1/projects/:p/test-plans/generate-from-code', 'ai'],
  ['POST /v1/test-plans/:p/ai/refine', 'ai'],
  ['POST /v1/issues/:p/pull-requests', 'github'],
  // request_fix_suggestion / cancel_fix_suggestion MCP tools. Deliberately no
  // retry/dismiss/apply/revert here: MCP never calls them (suggest-fix/routes.ts
  // header explains why apply/revert stay human-in-the-loop only).
  ['POST /v1/issues/:p/suggest-fix/runs', 'ai'],
  ['POST /v1/issues/:p/suggest-fix/runs/:p/cancel', 'ai'],
  // Still subject to the recording gate: on a mission whose policy is
  // `required`, this is refused for API keys regardless of being listed here.
  ['PUT /v1/missions/:p/step-results', 'testing'],
  // Authoring test plans/missions by API key. GET on these was already listed
  // above (an MCP/CLI client can read a plan and its steps); this is the write
  // half, so the same client can also CREATE one -- `generate_test_plan`
  // already does this via the AI path (`ai` resource, LLM-authored), but the
  // deterministic `/test-plans/import` parser and a plain manual create had no
  // API-key path at all (GoodQA board #200), so any non-interactive tester --
  // an MCP client, a CI job, this repo's own board-driven agents -- could read
  // a plan but never author one without a real browser session.
  ['POST /v1/projects/:p/test-plans/import', 'testing'],
  ['POST /v1/projects/:p/test-plans', 'testing'],
  ['POST /v1/projects/:p/missions', 'testing'],
  // The other half of GoodQA harness#69b9c5d6: CREATE was allowed above but
  // not CORRECT or DELETE, so an API-key-driven automation could author a
  // test plan/mission and then never fix a mistake or clean one up -- worse
  // than not being able to create at all, since the mess only accumulates.
  ['PATCH /v1/test-plans/:p', 'testing'],
  ['PATCH /v1/missions/:p', 'testing'],
  ['DELETE /v1/test-plans/:p', 'testing'],
  ['DELETE /v1/missions/:p', 'testing'],

  // --- board #106: Decision Flow Protocol -- an agent asks a real person
  // for input/approval and polls for the answer with the SAME credential it
  // already files bugs with (ticket item 4, explicit).
  ['POST /v1/orgs/:p/decisions', 'decisions'],
  ['GET /v1/orgs/:p/decisions', 'decisions'],
  ['GET /v1/decisions/:p', 'decisions'],
  // Responding is deliberately allowed too, not just create/poll: the key
  // authenticates AS its creator (same as every other route here), so if
  // that human is themselves a decision's authority, responding through
  // their own agent is that person answering -- no different in kind from
  // the same key already being allowed to comment on an issue on their
  // behalf.
  ['POST /v1/decisions/:p/respond', 'decisions'],
  // P51 slice C (G12): create up to 25 related decisions at once. Same authority as the single create above (an agent
  // asks), dark behind governance.decisions (the route 404s while it is off). Its answering twin,
  // `POST /v1/orgs/:p/decisions::respond-batch`, is deliberately NOT here: a person answers, in a session.
  ['POST /v1/orgs/:p/decisions::batch', 'decisions'],
  // Plan S1a: a key may PROPOSE a governance decision and nothing else in that register. A proposal is never
  // effective by itself (INV-E1); decide, confirm, sign-off and rights writes are session-only routes (later lane).
  ['POST /v1/projects/:p/governance/proposals', 'decisions'],
  // Plan S2a: the runner protocol (docs/design/goodqa-agent-platform/PLAN.md 1.4). Family `runner`, which only a
  // runner key names in practice; the handlers additionally require api_keys.kind = 'runner' and a runner row, and
  // a PENDING runner reaches only the heartbeat. None writes a governed table (governance-route-inventory test).
  ['POST /v1/runners/me/heartbeat', 'runner'],
  ['POST /v1/runners/me/usage', 'runner'],
  ['GET /v1/runners/me/events', 'runner'],
  ['POST /v1/runners/me/claims', 'runner'],
  ['POST /v1/runners/me/items/:p/ack', 'runner'],
  ['POST /v1/runners/me/items/:p/complete', 'runner'],
  ['POST /v1/runners/me/items/:p/fail', 'runner'],
  // fix-3 (S2d note): a runner declines a grant it cannot work; lease-fenced, grants only, writes no governed table.
  ['POST /v1/runners/me/items/:p/decline', 'runner'],
  ['POST /v1/runners/me/items/:p/outputs', 'runner'],
  // Plan S2d: the leased item's text, for the turn (current lease + won claim). Reads no governed table; a
  // `proposal` output is written by the S1a store from inside the outputs handler, never through a governance route.
  ['GET /v1/runners/me/items/:p/source', 'runner'],
  ['POST /v1/runners/me/incidents', 'runner'],
  ['POST /v1/runners/me/incidents/:p/close', 'runner'],
  // Plan S3: launching agents. A key READS daemons and launches and makes things SAFER (cancel, revoke); it never
  // launches and never makes a registration code (SESSION_ONLY_ROUTES). Explicit-only family; runners refused by kind.
  ['GET /v1/orgs/:p/agent-daemons', 'agent_launch'],
  ['POST /v1/orgs/:p/agent-daemons/:p/revoke', 'agent_launch'],
  ['GET /v1/projects/:p/agent-launches', 'agent_launch'],
  ['GET /v1/agent-launches/:p', 'agent_launch'],
  ['POST /v1/agent-launches/:p/cancel', 'agent_launch'],
  // Ticket #361, managed agent hosting (same explicit-only family). A key READS the meter and makes things SAFER:
  // destroy a host, kill the org's hosting, LOWER a cap (the route refuses a key that raises one). Provisioning is
  // SESSION_ONLY (it spends money).
  // GoodQA #430, Machines: a key READS what its grant shows, takes a lease, sends commands under its grant (risky ones
  // wait for the owner's approval), and makes things SAFER (cancel, release, pause, revoke a machine as its admin,
  // revoke its own grant). Pairing, granting, approving, resuming and scheduling jobs are SESSION_ONLY_ROUTES.
  ['GET /v1/orgs/:p/machines', 'machines'],
  ['GET /v1/orgs/:p/machines/snapshot', 'machines'],
  ['GET /v1/orgs/:p/machines/workspace-recipe-receipts', 'machines'],
  ['POST /v1/orgs/:p/machines/setup-grants/sync', 'machines'],
  ['POST /v1/orgs/:p/machines/authority/asks', 'machines'],
  ['GET /v1/orgs/:p/machines/authority/asks', 'machines'],
  ['GET /v1/orgs/:p/machines/authority/asks/:p', 'machines'],
  ['GET /v1/orgs/:p/machines/authority/grants', 'machines'],
  ['GET /v1/machines/:p', 'machines'],
  ['POST /v1/machines/:p/pause', 'machines'],
  ['POST /v1/machines/:p/revoke', 'machines'],
  ['GET /v1/machines/:p/grants', 'machines'],
  ['POST /v1/machines/:p/grants/:p/revoke', 'machines'],
  ['GET /v1/machines/:p/leases', 'machines'],
  ['POST /v1/machines/:p/leases', 'machines'],
  ['POST /v1/machine-leases/:p/renew', 'machines'],
  ['POST /v1/machine-leases/:p/release', 'machines'],
  ['POST /v1/machines/:p/commands', 'machines'],
  ['GET /v1/machine-commands/:p', 'machines'],
  ['GET /v1/machine-commands/:p/stream', 'machines'],
  ['POST /v1/machine-commands/:p/cancel', 'machines'],
  ['POST /v1/machine-commands/:p/attach', 'machines'],
  ['GET /v1/machines/:p/audit', 'machines'],
  ['GET /v1/machine-artifacts/:p/content', 'machines'],
  ['GET /v1/orgs/:p/machine-playbooks', 'machines'],
  ['POST /v1/orgs/:p/machine-playbooks', 'machines'],
  ['DELETE /v1/machine-playbooks/:p', 'machines'],
  ['POST /v1/machines/:p/playbooks/:p/run', 'machines'],
  ['GET /v1/machines/:p/jobs', 'machines'],
  ['POST /v1/machine-jobs/:p/disable', 'machines'],
  ['GET /v1/orgs/:p/workers', 'machines'],
  ['POST /v1/orgs/:p/workers/quotes', 'machines'],
  ['GET /v1/orgs/:p/workers/quotes/:p', 'machines'],
  ['POST /v1/orgs/:p/workers', 'machines'],
  ['POST /v1/orgs/:p/workers/:p/actions', 'machines'],
  ['POST /v1/orgs/:p/workers/:p/commands', 'machines'],
  ['GET /v1/orgs/:p/agent-hosting', 'agent_launch'],
  ['PUT /v1/orgs/:p/agent-hosting/limits', 'agent_launch'],
  ['POST /v1/orgs/:p/agent-hosting/kill', 'agent_launch'],
  ['POST /v1/orgs/:p/agent-hosts/:p/destroy', 'agent_launch'],
  // Browser handoff (docs/design/browser-handoff.md, dark: browserHandoff.enabled). A key ASKS a person (create),
  // reads its own handoffs, cancels them and appends desktop-host audit events: all safer-or-asking acts (C10). It never
  // redeems a link, takes control or presses Done (SESSION_ONLY_ROUTES below). `agents` family; runner keys refused by
  // kind in the handlers; a persona is required to create (the persona sends the DM carrying the link).
  ['GET /v1/orgs/:p/agent-browsers/settings', 'agents'],
  ['GET /v1/orgs/:p/agent-browsers/sessions', 'agents'],
  ['POST /v1/orgs/:p/agent-browsers/sessions', 'agents'],
  ['GET /v1/orgs/:p/agent-browsers/sessions/:p', 'agents'],
  ['POST /v1/orgs/:p/agent-browsers/sessions/:p/actions', 'agents'],
  ['POST /v1/orgs/:p/agent-browsers/sessions/:p/stop', 'agents'],
  ['GET /v1/orgs/:p/agent-browsers/sessions/:p/jobs/:p', 'agents'],
  ['GET /v1/orgs/:p/agent-browsers/sessions/:p/artifacts', 'agents'],
  ['GET /v1/orgs/:p/agent-browsers/sessions/:p/artifacts/:p', 'agents'],
  ['POST /v1/orgs/:p/browser-handoffs', 'agents'],
  ['GET /v1/orgs/:p/browser-handoffs/:p', 'agents'],
  ['POST /v1/orgs/:p/browser-handoffs/:p/cancel', 'agents'],
  ['POST /v1/orgs/:p/browser-audit', 'agents'],

  // --- board #152: Drive documents (typed ref blocks / "spec -> findings" /
  // "insert decision") -- an agent runs a document's ADVISORY actions with
  // the same credential it already files bugs with; the commit route still
  // requires an explicit, possibly-edited findings list from that call
  // ("AI advises, humans decide" -- see documents/service.ts), it is never
  // triggered automatically.
  ['GET /v1/projects/:p/documents', 'documents'],
  ['POST /v1/projects/:p/documents', 'documents'],
  ['GET /v1/documents/:p', 'documents'],
  ['PATCH /v1/documents/:p', 'documents'],
  ['GET /v1/documents/:p/revisions', 'documents'],
  ['POST /v1/documents/:p/restore', 'documents'],
  ['GET /v1/documents/:p/spec-to-findings/preview', 'documents'],
  ['POST /v1/documents/:p/spec-to-findings/commit', 'documents'],
  ['POST /v1/documents/:p/insert-decision', 'documents'],
  ['GET /v1/documents/backlinks/:p/:p', 'documents'],

  // --- board #122: the remote MCP endpoint itself, and the one route its
  // `search_issues` tool needs that nothing else here had opened yet
  // (cross-project org-wide issue search — every OTHER MCP tool reuses a
  // route already allowed above). A pairing-minted key defaults to
  // `scopes: ['read','write']` (no resource restriction, same default as a
  // manually-created key), so this only matters for a deliberately
  // narrowed key.
  //
  // Stateless method refusals still authenticate and require the MCP family.
  ['POST /v1/mcp', 'mcp'],
  ['GET /v1/mcp', 'mcp'],
  ['DELETE /v1/mcp', 'mcp'],
  ['GET /v1/orgs/:p/issues', 'issues'],
  // "What changed since timestamp X" polling feed -- the whole point is for
  // an ordinary org API key (not just a session) to reach it.
  ['GET /v1/orgs/:p/changes', 'issues'],
  // Board #378: the same feed with summaries since the KEY'S OWN last-seen mark, and moving that mark (a key's mark
  // is its own, never its owner's). Same resource as the feed it is built on.
  ['GET /v1/orgs/:p/changes/digest', 'issues'],
  ['PUT /v1/orgs/:p/changes/seen', 'issues'],

  // --- board #121: agent memory. Org/project scope reuse the same
  // read/write floor as their own resources (requireOrgRole/
  // requireProjectRole/requireOrgPermission/requireProjectPermission,
  // called inside the handlers -- unchanged by being reachable here).
  // agent_self is the primary reason this exists at all: it is scoped to
  // THIS credential (`auth.apiKeyId`), so an agent needs its own API key
  // reachable to persist and recall its own state between calls.
  ['GET /v1/orgs/:p/projects/:p/memory/status', 'project_memory'],
  ['GET /v1/orgs/:p/projects/:p/memory', 'project_memory'],
  ['GET /v1/orgs/:p/projects/:p/memory/entry', 'project_memory'],
  ['PUT /v1/orgs/:p/projects/:p/memory', 'project_memory'],
  ['POST /v1/orgs/:p/projects/:p/memory/retrieve', 'project_memory'],
  ['DELETE /v1/orgs/:p/projects/:p/memory/entry', 'project_memory'],
  ['GET /v1/orgs/:p/agent-memory', 'agent_memory'],
  ['GET /v1/persona/turn-context', 'context_memory'],
  ['GET /v1/orgs/:p/context-memory', 'context_memory'],
  ['GET /v1/orgs/:p/context-memory/context', 'context_memory'],
  ['POST /v1/orgs/:p/context-memory', 'context_memory'],
  ['GET /v1/orgs/:p/agent-memory/:p', 'agent_memory'],
  ['PUT /v1/orgs/:p/agent-memory/:p', 'agent_memory'],
  ['DELETE /v1/orgs/:p/agent-memory/:p', 'agent_memory'],
  ['GET /v1/projects/:p/agent-memory', 'agent_memory'],
  ['GET /v1/projects/:p/agent-memory/:p', 'agent_memory'],
  ['PUT /v1/projects/:p/agent-memory/:p', 'agent_memory'],
  ['DELETE /v1/projects/:p/agent-memory/:p', 'agent_memory'],
  ['GET /v1/agent-memory/self', 'agent_memory'],
  ['GET /v1/orgs/:p/memory', 'memory'],
  ['GET /v1/orgs/:p/memory/context', 'memory'],
  ['GET /v1/orgs/:p/memory/status', 'memory'],
  ['GET /v1/orgs/:p/memory/rules', 'memory'],
  ['GET /v1/orgs/:p/memory/export', 'memory'],
  ['GET /v1/orgs/:p/memory/audit', 'memory'],
  ['GET /v1/orgs/:p/memory/:p', 'memory'],
  ['POST /v1/orgs/:p/memory', 'memory'],
  ['GET /v1/projects/:p/memory', 'memory'],
  ['GET /v1/projects/:p/memory/context', 'memory'],
  ['GET /v1/projects/:p/memory/status', 'memory'],
  ['GET /v1/projects/:p/memory/rules', 'memory'],
  ['GET /v1/projects/:p/memory/export', 'memory'],
  ['GET /v1/projects/:p/memory/audit', 'memory'],
  ['GET /v1/projects/:p/memory/:p', 'memory'],
  ['POST /v1/projects/:p/memory', 'memory'],
  // Agent knowledge (dark: agentKnowledge.enabled, checked below with the CRM pattern). No reassign or erasure
  // route here: those are session-only. The handlers decide scope rights (modules/agent-knowledge/service.ts).
  // #381 coordinator (dark: coordinator.bootstrap, checked centrally below before any 403). Every route names
  // `decisions` (a family no runner key may name) and `agent_knowledge` (refused to user-scoped keys), so both key
  // kinds are refused by family as well as by the handler. `setup` is session-only: not listed here.
  ['GET /v1/orgs/:p/coordinator/status', ['issues', 'decisions', 'agent_knowledge', 'agent_memory']],
  ['GET /v1/orgs/:p/coordinator/bootstrap', ['issues', 'decisions', 'agent_knowledge', 'agent_memory']],
  ['POST /v1/orgs/:p/coordinator/checkpoint', ['issues', 'decisions', 'agent_knowledge', 'agent_memory']],
  // Ticket #377: per-org usage metering. Its OWN family: a key narrowed to `orgs` or `stats` must not silently gain
  // the org's cost figures. Runner keys may never name it (RUNNER_FORBIDDEN_RESOURCE_FAMILIES) and the handlers refuse
  // them anyway; the budget PUT is lopsided (a key may only tighten).
  // Demo hotfix 2026-10-14: read-only bot action history (what the assistant did through turn tokens). The handler
  // narrows a non-admin caller (and every turn token's requester who is not an admin) to their own rows.
  ['GET /v1/orgs/:p/bot-actions', 'ai'],
  ['GET /v1/orgs/:p/usage', 'usage'],
  ['PUT /v1/orgs/:p/usage/budget', 'usage'],
  // Capability push 2026-10-14: the assistant's caps and today's use. The PUT (owner's tighter limits) refuses API keys in the handler.
  ['GET /v1/orgs/:p/usage/assistant-limits', 'usage'],
  ['PUT /v1/orgs/:p/usage/assistant-limits', 'usage'],
  // Model-spend metering: the summary read is the `usage` family; recording is the explicit-only `usage:write` family
  // (persona and runner keys are refused in the handler, the budget never blocks a write).
  ['GET /v1/orgs/:p/usage/models', 'usage'],
  ['POST /v1/orgs/:p/usage/model-events', 'usage:write'],
  // GoodQA #442 emergency escalation (dark: escalation.enabled, 404 before auth while off). What a BOT may do: read
  // status, raise (bounded by the org's agent routing policy and escalation.agentRouting), list, read one, cancel ONLY
  // its own. Ack, resolve, confirm, policies, on-call, settings and contact numbers are session-only by design: a bot
  // can never acknowledge for a person or widen who gets woken up.
  ['GET /v1/orgs/:p/escalation/status', 'escalation'],
  ['POST /v1/orgs/:p/escalations', 'escalation'],
  ['GET /v1/orgs/:p/escalations', 'escalation'],
  ['GET /v1/escalations/:p', 'escalation'],
  ['POST /v1/escalations/:p/cancel', 'escalation'],
  // Listed ONLY so a bot gets the explicit refusal (403 escalation_bot_cannot_ack) instead of a generic one: the
  // handler refuses every API key. A bot never acknowledges for a person.
  ['POST /v1/escalations/:p/ack', 'escalation'],
  // Discord integration (dark: discord.enabled, every route the router's 404 while off). Family `orgs`: an org admin's
  // key may read the card, make pairing codes and unpair; runner, persona and user-scoped keys are refused by the
  // handler by name. Adding the bot to a server (install-link) is SESSION_ONLY. No new family on purpose: a new family
  // name would change the served OpenAPI's scope enum while the feature is still dark.
  ['GET /v1/orgs/:p/integrations/discord/status', 'orgs'],
  ['GET /v1/orgs/:p/integrations/discord/installs', 'orgs'],
  ['POST /v1/orgs/:p/integrations/discord/pairing-codes', 'orgs'],
  ['DELETE /v1/orgs/:p/integrations/discord/pairings/:p', 'orgs'],
  ['DELETE /v1/orgs/:p/integrations/discord/installs/:p', 'orgs'],
  // goodqa CLI vault-in-the-env (dark: vaultEnv.enabled, 404 before auth while off; modules/vault-env/routes.ts). A key
  // (a QA Commander instance's persona key, another bot, a `goodqa login` key) lists what it may read and reads values
  // only where the org's allow-list names it; the GCP authorize call is audit + allow-list, the value never passes here.
  // Who may read what (PUT config) is session-only: a key never widens its own reach.
  ['GET /v1/orgs/:p/vault-env', 'vault'],
  ['POST /v1/orgs/:p/vault-env/reveal', 'vault'],
  ['POST /v1/orgs/:p/vault-env/external/authorize', 'vault'],
  ['GET /v1/orgs/:p/vault-env/config', 'vault'],
  ['GET /v1/orgs/:p/agent-knowledge/status', 'agent_knowledge'],
  ['GET /v1/orgs/:p/agent-knowledge', 'agent_knowledge'],
  ['PUT /v1/orgs/:p/agent-knowledge', 'agent_knowledge'],
  // goodqa#13749 knowledge net: about / what-happened read, coverage read + sweep write (static segments, so
  // they are listed BEFORE the `/:p` entry below; the handlers decide scope rights, rides agentKnowledge.enabled).
  ['GET /v1/orgs/:p/agent-knowledge/about', 'agent_knowledge'],
  ['GET /v1/orgs/:p/agent-knowledge/what-happened', 'agent_knowledge'],
  ['GET /v1/orgs/:p/agent-knowledge/coverage', 'agent_knowledge'],
  ['PUT /v1/orgs/:p/agent-knowledge/coverage', 'agent_knowledge'],
  ['GET /v1/orgs/:p/agent-knowledge/:p', 'agent_knowledge'],
  ['POST /v1/orgs/:p/agent-knowledge/:p/supersede', 'agent_knowledge'],
  ['POST /v1/orgs/:p/agent-knowledge/:p/tombstone', 'agent_knowledge'],
  // Persona-memory API: purge (the owning persona's key or an admin session; the handler decides). The org-wide
  // persona erase is session-only and therefore NOT listed (an unlisted route is refused to every key).
  ['POST /v1/orgs/:p/agent-knowledge/:p/purge', 'agent_knowledge'],
  // Persona-memory API gap 6: issue pins (the handlers need issue:edit / project viewer; rides agentKnowledge.enabled).
  ['PUT /v1/issues/:p/pin', 'issues'],
  ['DELETE /v1/issues/:p/pin', 'issues'],
  ['GET /v1/projects/:p/pinned-issues', 'issues'],
  ['GET /v1/agent-memory/self/:p', 'agent_memory'],
  ['PUT /v1/agent-memory/self/:p', 'agent_memory'],
  ['DELETE /v1/agent-memory/self/:p', 'agent_memory'],

  // --- board #123: MCP curated vault tools (board #120's secrets vault),
  // exactly the 5 routes store_secret/get_secret/list_secrets/delete_secret
  // actually call (apps/api/src/modules/mcp/tools.ts) — no more. Every
  // route below still runs its own real permission check unchanged
  // (org:manage_vault/project:manage_vault to create, that secret's own
  // grant to view/manage an existing one); being reachable by an API key
  // widens WHO can call the route, never what the route itself allows once
  // called. Deliberately NOT listed: grants management (no MCP tool exposes
  // it) and POST /vault/admin/rotate-kek (platform-admin + step-up gated —
  // meaningless behind a bearer token, and re-wraps every DEK in the DB).
  ['GET /v1/vault/secrets', 'vault'],
  ['POST /v1/vault/secrets', 'vault'],
  ['PATCH /v1/vault/secrets/:p', 'vault'],
  ['POST /v1/vault/secrets/:p/reveal', 'vault'],
  ['DELETE /v1/vault/secrets/:p', 'vault'],
  // Vault secret requests (2026-10-03, docs/design/vault-secret-requests.md). DARK: every route answers an
  // unregistered route's 404 unless platform setting `vault.requests` and the org's `vaultRequests.enabled` are on.
  // An agent ASKS a member for a credential, reads the request, withdraws it, and reveals the stored value (the
  // reveal handler pins the exact principal that asked and logs the read). Fulfil and decline are SESSION_ONLY:
  // only the person asked, signed in, ever types the value. Runner keys are refused by kind (below) and by
  // RUNNER_FORBIDDEN_RESOURCE_FAMILIES.
  // Attachment sharing (2026-10-03). DARK: every route answers an unregistered route's 404 unless platform setting
  // `attachments.sharing` is on. Keys reach them through the `uploads` family (forward also `chat`); each handler still
  // runs the file's own read gate as the key's human, refuses runner keys by kind, refuses PUBLIC links to every key
  // (only a signed-in person loosens to "anyone with the link"), and confines a user-scoped key to its member's own
  // files (USER_SCOPED_KEY_ALLOWED_ROUTES below). The policy routes and the in-app content route are session-only.
  ['POST /v1/attachments/:p/shares', 'uploads'],
  ['GET /v1/attachments/:p/shares', 'uploads'],
  ['GET /v1/attachment-shares/:p/link', 'uploads'],
  ['POST /v1/attachment-shares/:p/revoke', 'uploads'],
  ['POST /v1/attachments/:p/forward', ['uploads', 'chat']],
  ['POST /v1/secret-requests', 'vault'],
  ['GET /v1/secret-requests', 'vault'],
  ['GET /v1/secret-requests/:p', 'vault'],
  ['POST /v1/secret-requests/:p/revoke', 'vault'],
  ['POST /v1/secret-requests/:p/reveal', 'vault'],
  // SEO data connectors (dark, seo.connectors): the requesting principal runs a READ-ONLY audit from the secret
  // requests it made; the handler pins the exact requester per request (as reveal does) and returns derived data only.
  ['GET /v1/orgs/:p/ahrefs', 'marketing'],
  ['POST /v1/orgs/:p/ahrefs/report', 'marketing'],
  ['POST /v1/orgs/:p/ahrefs/batch', 'marketing'],
  ['GET /v1/projects/:p/ahrefs/publisher-recovery/leads/:p/content-drafts', ['crm', 'cms']],
  ['POST /v1/projects/:p/ahrefs/publisher-recovery/leads/:p/content-drafts', ['crm', 'cms']],
  ['GET /v1/projects/:p/sanity-drafts', ['crm', 'cms']],
  ['POST /v1/projects/:p/sanity-drafts', ['crm', 'cms']],
  ['GET /v1/projects/:p/sanity-drafts/:p', ['crm', 'cms']],
  ['GET /v1/projects/:p/sanity-destination-setup/:p', ['cms', 'vault']],
  ['POST /v1/projects/:p/sanity-destination-setup', ['cms', 'vault']],
  ['GET /v1/projects/:p/sanity-destination-setup/operations/:p', ['cms', 'vault']],
  ['GET /v1/projects/:p/ahrefs/publisher-recovery/workflow', 'crm'],
  ['GET /v1/projects/:p/ahrefs/publisher-recovery/assessments', 'crm'],
  ['GET /v1/projects/:p/ahrefs/publisher-recovery/assessments/:p', 'crm'],
  ['POST /v1/projects/:p/ahrefs/publisher-recovery/leads/:p/drafts', 'crm'],
  ['GET /v1/projects/:p/ahrefs/publisher-recovery', 'crm'],
  ['POST /v1/projects/:p/ahrefs/publisher-recovery', 'crm'],
  ['POST /v1/orgs/:p/seo/audit', 'vault'],

  // --- board #150: surface.* — the Workspace personality's read/propose/
  // apply/explain/diff/reset/intents/profile tool surface (board #149's
  // engine underneath), reachable "over real HTTP" with "bearer/device-
  // pairing auth" per the ticket's own text. This was a REAL gap found
  // while building #150: #149 shipped the routes but never added them here,
  // so no API key of ANY kind — scoped or not — could reach them at all
  // before this entry, silently defeating the ticket's own stated
  // MCP/API-key exposure goal. Every route still runs its own real
  // authorization underneath (requireProjectRole, `mayWrite`'s scope
  // ceiling, the board #37 user-scoped-key write ceiling added in this same
  // pass — see `Viewer.apiKeyScopedToUserId` in `modules/surface/service.ts`)
  // unchanged by being reachable here; this only widens WHO may call the
  // route, never what the route itself allows once called.
  ['GET /v1/projects/:p/surface/:p/resolve', 'surface'],
  ['GET /v1/projects/:p/surface/:p/explain/:p', 'surface'],
  ['GET /v1/projects/:p/surface/:p/patches', 'surface'],
  ['POST /v1/projects/:p/surface/:p/propose', 'surface'],
  ['POST /v1/projects/:p/surface/:p/apply', 'surface'],
  ['POST /v1/projects/:p/surface/:p/patches/:p/revert', 'surface'],
  ['PUT /v1/projects/:p/surface/intent-profile', 'surface'],
  ['GET /v1/projects/:p/surface/intent-profile', 'surface'],
  ['GET /v1/projects/:p/surface/:p/intents', 'surface'],
  ['GET /v1/projects/:p/surface/:p/diff', 'surface'],
  ['POST /v1/projects/:p/surface/:p/reset', 'surface'],

  // ============================================================
  // TASK-479 -- the agent-first classification pass.
  //
  // Everything below was measured, not guessed: 618 distinct routes are
  // registered (867 printRoutes entries, of which 248 HEAD exactly mirror the
  // 248 GET and 1 is `OPTIONS *`). 104 were already listed above. 515 had NO
  // classification at all -- and because the enforcement below is fail-closed
  // (`if (!resources) throw ... 'not available to API keys'`), every one of
  // those 515 was DENIED. Not deliberately denied; denied by omission, with no
  // way for a reader to tell the two apart. That indistinguishability was the
  // actual defect, and `SESSION_ONLY_ROUTES` below is what fixes it.
  //
  // The product decision this encodes (Eric, 2026-08-27): GoodQA is agent-first.
  // A key-driven agent should reach everything a human session can, EXCEPT a
  // narrow deliberate set. So the default outcome here is ALLOW, and the
  // interesting list is the deny list, not this one.
  //
  // Note what did NOT change: every handler's own authorization still runs
  // unchanged -- requireProjectRole, requireOrgRole, requireOrgPermission, the
  // `maxOrgRole` ceiling, board #37's user-scoped-key visibility. Being on this
  // list only lets the request REACH the check that was always there. A key
  // whose creator cannot delete an issue still cannot delete an issue.
  // ============================================================
  // --- TASK-479: org-level reads and workspace configuration ---
  ['GET /v1/desktop/update-status', 'orgs'],
  ['GET /v1/me/dashboards', 'orgs'],
  ['GET /v1/me/issue-filters', 'orgs'],
  ['GET /v1/me/profile', 'orgs'],
  ['GET /v1/orgs/:p/brand', 'orgs'],
  ['GET /v1/orgs/:p/calendar-connection', 'orgs'],
  ['GET /v1/orgs/:p/dm/:p', 'chat'],
  ['GET /v1/orgs/:p/entitlements', 'orgs'],
  // Telephony step 1: read-only org admin status; no contact/provisioning authority.
  ['GET /v1/orgs/:p/telephony/status', 'orgs'],
  ['GET /v1/orgs/:p/initiatives', 'orgs'],
  ['GET /v1/orgs/:p/invite-suggestions', 'orgs'],
  ['GET /v1/orgs/:p/members/:p/competency', 'orgs'],
  ['GET /v1/orgs/:p/members/:p/issue-stats', 'orgs'],
  ['GET /v1/orgs/:p/members/:p/profile', 'orgs'],
  ['GET /v1/orgs/:p/permissions/catalog', 'orgs'],
  ['GET /v1/orgs/:p/portfolios', 'orgs'],
  ['GET /v1/orgs/:p/retention-policy', 'orgs'],
  ['GET /v1/orgs/:p/skills', 'orgs'],
  ['GET /v1/push/vapid-public-key', 'orgs'],
  ['GET /v1/support/tickets', 'orgs'],
  ['GET /v1/support/tickets/:p', 'orgs'],
  ['PATCH /v1/orgs/:p', 'orgs'],
  ['POST /v1/connections/:p/sync', 'orgs'],
  ['POST /v1/desktop/update-status', 'orgs'],
  ['POST /v1/orgs/:p/dm/:p', 'chat'],
  ['POST /v1/orgs/:p/initiatives', 'orgs'],
  ['POST /v1/orgs/:p/portfolios', 'orgs'],
  ['POST /v1/orgs/:p/skills', 'orgs'],
  ['POST /v1/support/tickets', 'orgs'],
  ['POST /v1/support/tickets/:p/messages', 'orgs'],

  // --- TASK-479: project configuration, planning and release surface ---
  ['DELETE /v1/categories/:p', 'projects'],
  ['DELETE /v1/drive/folders/:p', 'projects'],
  ['DELETE /v1/fields/:p', 'projects'],
  ['DELETE /v1/initiatives/:p', 'projects'],
  ['DELETE /v1/pipelines/:p', 'projects'],
  ['DELETE /v1/plan-reviews/:p', 'projects'],
  ['DELETE /v1/plan/views/:p', 'projects'],
  ['DELETE /v1/portfolios/:p', 'projects'],
  ['DELETE /v1/release-mappings/:p', 'projects'],
  ['DELETE /v1/releases/:p', 'projects'],
  ['DELETE /v1/schedules/:p', 'projects'],
  ['DELETE /v1/stages/:p', 'projects'],
  ['DELETE /v1/uptime-monitors/:p', 'projects'],
  ['DELETE /v1/views/:p', 'projects'],
  ['GET /v1/initiatives/:p', 'projects'],
  ['GET /v1/portfolios/:p', 'projects'],
  ['GET /v1/projects/:p/access', 'projects'],
  // Board #298: the closed-stage auto-archive opt-out, same shape/floor as ai-feature-settings above.
  ['GET /v1/projects/:p/archive-settings', 'issues'],
  ['PATCH /v1/projects/:p/archive-settings', 'issues'],
  ['GET /v1/projects/:p/assignees', 'projects'],
  ['GET /v1/projects/:p/categories', 'projects'],
  ['GET /v1/projects/:p/categories/:p/access', 'projects'],
  ['GET /v1/projects/:p/connections', 'projects'],
  ['GET /v1/projects/:p/drive/folders', 'projects'],
  ['GET /v1/projects/:p/drive/files', 'projects'],
  ['GET /v1/projects/:p/fields', 'projects'],
  // THE PRODUCT INDEX (Eric, 2026-09-05). Same shape as TASK-633B's ticket-type
  // decision directly below, and for the same reason: an integration must be
  // able to RESOLVE a surface / flow / page / environment / label id, or it
  // cannot set `surfaceId` when filing a ticket and the axis vocabulary is
  // invisible to every agent. DEFINING that vocabulary -- and, above all,
  // ACCEPTING a derived proposal -- is a human act, so every write is in
  // SESSION_ONLY_ROUTES instead. `product-index/review-queue` is session-only
  // too: it is the accept surface, and a credential that could both propose and
  // accept would be one actor doing both halves of the gate CLAUDE.md's
  // "AI advises; humans decide" exists to keep apart.
  ['GET /v1/projects/:p/product-index', 'projects'],
  ['GET /v1/projects/:p/product-environments', 'projects'],
  ['GET /v1/projects/:p/product-surfaces', 'projects'],
  ['GET /v1/projects/:p/product-nodes', 'projects'],
  ['GET /v1/projects/:p/labels', 'projects'],
  // TASK-633B, Eric's decision 2026-09-01: GET yes, writes no. An integration
  // may RESOLVE a ticket's custom type -- it has to, or it cannot set
  // `issueTypeId` when filing, and the New Ticket type picker's vocabulary
  // would be invisible to every agent. DEFINING the vocabulary is a human act,
  // so POST/PATCH/DELETE/reorder are in SESSION_ONLY_ROUTES instead. HEAD is
  // covered by this GET via `apiKeyRouteResources`'s HEAD->GET fold.
  ['GET /v1/projects/:p/issue-types', 'projects'],
  ['POST /v1/projects/:p/issue-types/ensure-standard-work-types', 'issue_types'],
  ['GET /v1/projects/:p/onboarding-wizard/status', 'projects'],
  ['GET /v1/projects/:p/pipeline', 'projects'],
  ['GET /v1/projects/:p/pipelines', 'projects'],
  ['GET /v1/projects/:p/pipelines/:p/stages', 'projects'],
  ['GET /v1/projects/:p/plan', 'projects'],
  ['GET /v1/projects/:p/plan-canvas-settings', 'projects'],
  ['GET /v1/projects/:p/plan/views', 'projects'],
  ['GET /v1/projects/:p/planning', 'projects'],
  ['GET /v1/projects/:p/planning/backlog', 'projects'],
  ['GET /v1/projects/:p/release-mappings', 'projects'],
  ['GET /v1/projects/:p/release-stages', 'projects'],
  ['GET /v1/projects/:p/releases', 'projects'],
  ['GET /v1/projects/:p/schedules', 'projects'],
  ['GET /v1/projects/:p/stages', 'projects'],
  ['GET /v1/pipelines/:p', 'projects'],
  ['GET /v1/pipelines/:p/stages', 'projects'],
  ['GET /v1/projects/:p/uptime-monitors', 'projects'],
  ['GET /v1/projects/:p/views', 'projects'],
  ['GET /v1/releases/:p', 'projects'],
  ['GET /v1/schedules/:p/runs', 'projects'],
  ['GET /v1/sprints/:p', 'projects'],
  ['GET /v1/sprints/:p/capacity', 'projects'],
  ['GET /v1/sprints/:p/events', 'projects'],
  ['GET /v1/uptime-monitors/:p', 'projects'],
  ['GET /v1/uptime-monitors/:p/checks', 'projects'],
  ['PATCH /v1/categories/:p', 'projects'],
  ['PATCH /v1/drive/folders/:p', 'projects'],
  ['PATCH /v1/fields/:p', 'projects'],
  ['PATCH /v1/initiatives/:p', 'projects'],
  ['PATCH /v1/pipelines/:p', 'projects'],
  ['PATCH /v1/plan-reviews/:p', 'projects'],
  ['PATCH /v1/plan/views/:p', 'projects'],
  ['PATCH /v1/views/:p', 'projects'],
  ['PATCH /v1/portfolios/:p', 'projects'],
  ['PATCH /v1/projects/:p', 'projects'],
  ['PATCH /v1/projects/:p/plan-canvas-settings', 'projects'],
  ['PATCH /v1/projects/:p/planning/backlog/order', 'projects'],
  ['PATCH /v1/release-gates/:p', 'projects'],
  ['PATCH /v1/release-mappings/:p', 'projects'],
  ['PATCH /v1/releases/:p', 'projects'],
  ['PATCH /v1/schedules/:p', 'projects'],
  ['PATCH /v1/sprints/:p', 'projects'],
  ['PATCH /v1/stages/:p', 'projects'],
  ['PATCH /v1/uptime-monitors/:p', 'projects'],
  ['POST /v1/projects/:p/access-strip/dismiss', 'projects'],
  ['POST /v1/projects/:p/categories', 'projects'],
  ['POST /v1/projects/:p/categories/reorder', 'projects'],
  ['POST /v1/projects/:p/drive/folders', 'projects'],
  ['POST /v1/projects/:p/drive/move', 'projects'],
  ['POST /v1/projects/:p/fields', 'projects'],
  ['POST /v1/projects/:p/fields/reorder', 'projects'],
  ['POST /v1/projects/:p/onboarding-wizard/apply-sentence', 'projects'],
  ['POST /v1/projects/:p/onboarding-wizard/preview-sentence', 'projects'],
  ['POST /v1/projects/:p/onboarding-wizard/submit', 'projects'],
  ['POST /v1/projects/:p/pipelines', 'projects'],
  ['POST /v1/projects/:p/pipelines/reorder', 'projects'],
  // TASK-634's copy-a-pipeline route, classified here for the same reason its
  // own siblings already are: `POST /v1/projects/:p/pipelines` (create),
  // `PATCH /v1/pipelines/:p` and `DELETE /v1/pipelines/:p` are all reachable,
  // so a key that can author a pipeline from scratch can already produce every
  // state a copy produces. It grants no new authority. The route runs TWO real
  // permission checks of its own (pipelines/routes.ts:341-345: read role on the
  // SOURCE project, `project:manage_pipelines` on the TARGET), and allowlist
  // membership does not satisfy either -- so cross-project exfiltration and
  // cross-project writes stay gated on the bound human's real roles.
  //
  // NOT an /issue-types route and therefore NOT covered by Eric's GET-yes/
  // writes-no decision; it was simply unclassified on main and fails the same
  // completeness test. Flagged for review in the PR rather than folded in
  // silently.
  ['POST /v1/pipelines/:p/copy', 'projects'],
  ['POST /v1/projects/:p/plan/views', 'projects'],
  ['POST /v1/projects/:p/release-mappings', 'projects'],
  ['POST /v1/projects/:p/release-stages', 'projects'],
  ['POST /v1/projects/:p/releases', 'projects'],
  ['POST /v1/projects/:p/restore', 'projects'],
  ['POST /v1/projects/:p/schedules', 'projects'],
  ['POST /v1/projects/:p/sprints', 'projects'],
  ['POST /v1/projects/:p/stages', 'projects'],
  ['POST /v1/projects/:p/stages/reorder', 'projects'],
  ['POST /v1/pipelines/:p/stages', 'projects'],
  ['POST /v1/pipelines/:p/stages/reorder', 'projects'],
  ['POST /v1/stages/:p/default', 'projects'],
  ['POST /v1/projects/:p/uptime-monitors', 'projects'],
  ['POST /v1/projects/:p/views', 'projects'],
  ['POST /v1/releases/:p/gates', 'projects'],
  ['POST /v1/sprints/:p/cancel', 'projects'],
  ['POST /v1/sprints/:p/complete', 'projects'],
  ['POST /v1/sprints/:p/start', 'projects'],
  ['POST /v1/uptime-monitors/:p/prune', 'projects'],
  ['PUT /v1/sprints/:p/capacity/:p', 'projects'],
  ['PUT /v1/pipelines/:p/stages/order', 'projects'],

  // --- TASK-479: issue detail, relationships and estimation ---
  ['DELETE /v1/dependencies/:p', 'issues'],
  ['DELETE /v1/issue-links/:p', 'issues'],
  ['DELETE /v1/issues/:p/fix-draft', 'issues'],
  ['DELETE /v1/releases/:p/issues/:p', 'issues'],
  ['DELETE /v1/sprints/:p/issues/:p', 'issues'],
  ['GET /v1/issues/:p/comments/:p/revisions', 'issues'],
  ['GET /v1/issues/:p/dependencies', 'issues'],
  ['GET /v1/issues/:p/watchers', 'issues'],
  ['PUT /v1/issues/:p/watchers', 'issues'],
  ['DELETE /v1/issues/:p/watchers', 'issues'],
  ['GET /v1/issues/:p/estimates', 'issues'],
  ['GET /v1/orgs/:p/time/entries', 'issues'],
  ['GET /v1/orgs/:p/time/weekly', 'issues'],
  ['POST /v1/orgs/:p/time/start', 'issues'],
  ['POST /v1/orgs/:p/time/entries', 'issues'],
  ['POST /v1/orgs/:p/time/entries/:p/stop', 'issues'],
  ['PATCH /v1/orgs/:p/time/entries/:p', 'issues'],
  ['DELETE /v1/orgs/:p/time/entries/:p', 'issues'],
  ['GET /v1/issues/:p/fix-draft', 'issues'],
  ['GET /v1/issues/:p/revisions', 'issues'],
  // Exact consumer identity and target scope are enforced again in the handler.
  ['GET /v1/orgs/:p/projects/:p/issues/:p/operations/:p/commit', 'issues'],
  ['GET /v1/issues/:p/suggest-assignees', 'issues'],
  ['GET /v1/sprints/:p/issues', 'issues'],
  ['PATCH /v1/dependencies/:p', 'issues'],
  ['PATCH /v1/issues/:p/comments/:p', 'issues'],
  ['PATCH /v1/sprints/:p/issues/order', 'issues'],
  ['POST /v1/issues/:p/comments/:p/revisions/:p/restore', 'issues'],
  ['POST /v1/issues/:p/dependencies', 'issues'],
  ['POST /v1/issues/:p/reassign', 'issues'],
  ['POST /v1/issues/:p/estimates', 'issues'],
  ['POST /v1/issues/:p/revisions/:p/restore', 'issues'],
  ['POST /v1/releases/:p/issues', 'issues'],
  ['PUT /v1/issues/:p/fix-draft', 'issues'],
  ['PUT /v1/sprints/:p/issues', 'issues'],

  // --- TASK-479: test plans, flows, steps, missions and recordings ---
  ['DELETE /v1/missions/:p/assignees/:p', 'testing'],
  ['DELETE /v1/step-dependencies/:p', 'testing'],
  ['DELETE /v1/test-flows/:p', 'testing'],
  ['DELETE /v1/test-steps/:p', 'testing'],
  ['GET /v1/missions/:p/report', 'testing'],
  ['GET /v1/orgs/:p/missions', 'testing'],
  ['GET /v1/projects/:p/qa-rubrics', 'testing'],
  ['GET /v1/projects/:p/qa-rubrics/:p', 'testing'],
  ['GET /v1/projects/:p/qa-rubrics/standings', 'testing'],
  ['GET /v1/step-results/:p/bug-draft', 'testing'],
  ['PATCH /v1/missions/:p/assignees/:p', 'testing'],
  ['PATCH /v1/projects/:p/qa-rubrics/:p', 'testing'],
  ['PATCH /v1/test-flows/:p', 'testing'],
  ['PATCH /v1/test-steps/:p', 'testing'],
  ['POST /v1/missions/:p/assignees', 'testing'],
  ['POST /v1/missions/:p/recording-sessions', 'testing'],
  ['POST /v1/projects/:p/qa-rubrics', 'testing'],
  ['POST /v1/recording-sessions/:p/end', 'testing'],
  ['POST /v1/recording-sessions/:p/heartbeat', 'testing'],
  // Drives a metered third-party AgentBrowser job -- real money.
  ['POST /v1/test-flows/:p/agent-browser-run', ['testing', 'ai']],
  ['POST /v1/test-flows/:p/steps', 'testing'],
  ['POST /v1/test-plans/:p/flows', 'testing'],
  ['POST /v1/test-plans/:p/reviewers', 'testing'],
  ['POST /v1/test-steps/:p/dependencies', 'testing'],

  // --- TASK-479: evidence attachments ---
  ['DELETE /v1/attachments/:p', 'uploads'],
  ['POST /v1/attachments/:p/restore', 'uploads'],
  ['GET /v1/attachments/:p', 'uploads'],
  ['POST /v1/attachments/:p/tags', 'uploads'],
  ['POST /v1/attachments/:p/tags/remove', 'uploads'],
  ['POST /v1/missions/:p/attachments', 'uploads'],
  ['POST /v1/projects/:p/attachments/link', 'uploads'],
  ['POST /v1/releases/:p/attachments', 'uploads'],
  ['POST /v1/test-plans/:p/attachments', 'uploads'],
  ['POST /v1/test-steps/:p/attachments', 'uploads'],

  // --- TASK-479: AI-assisted authoring and project intelligence ---
  ['DELETE /v1/projects/:p/intelligence/repositories/:p', 'ai'],
  ['GET /v1/issues/:p/suggest-fix/capabilities', 'ai'],
  ['GET /v1/issues/:p/suggest-fix/runs', 'ai'],
  ['GET /v1/projects/:p/ai-feature-settings', 'ai'],
  ['GET /v1/projects/:p/intelligence', 'ai'],
  ['GET /v1/projects/:p/intelligence/chat/citations/:p', 'ai'],
  ['GET /v1/projects/:p/intelligence/chat/conversations', 'ai'],
  ['GET /v1/projects/:p/intelligence/chat/conversations/:p/messages', 'ai'],
  ['GET /v1/projects/:p/intelligence/chat/messages/:p/run', 'ai'],
  ['GET /v1/projects/:p/suggest-fix-capability', 'ai'],
  ['PATCH /v1/projects/:p/ai-feature-settings', 'ai'],
  ['POST /v1/ai/cleanup', 'ai'],
  ['POST /v1/issues/:p/suggest-fix/applications/:p/revert', 'ai'],
  ['POST /v1/issues/:p/suggest-fix/proposals/:p/apply', 'ai'],
  ['POST /v1/issues/:p/suggest-fix/proposals/:p/dismiss', 'ai'],
  ['POST /v1/issues/:p/suggest-fix/runs/:p/retry', 'ai'],
  ['POST /v1/projects/:p/ai/interview', 'ai'],
  ['POST /v1/projects/:p/ai/mockup-generate', 'ai'],
  // Board #612: proposes draft tickets only, writes nothing — same "an
  // integration may ask, a human must confirm" shape as generate-plan/
  // interview above. The route that actually FILES the reviewed drafts
  // (`POST /v1/projects/:p/issues/bulk-create`) is deliberately NOT here —
  // see SESSION_ONLY_ROUTES below.
  ['POST /v1/projects/:p/ai/parse-tickets', 'ai'],
  ['POST /v1/projects/:p/intelligence/chat/conversations', 'ai'],
  ['POST /v1/projects/:p/intelligence/chat/conversations/:p/messages', 'ai'],
  ['POST /v1/projects/:p/intelligence/chat/messages/:p/run/cancel', 'ai'],
  ['POST /v1/projects/:p/intelligence/chat/messages/:p/run/retry', 'ai'],
  ['POST /v1/projects/:p/intelligence/syncs', 'ai'],
  ['PUT /v1/projects/:p/intelligence/repositories/:p', 'ai'],
  ['PUT /v1/projects/:p/intelligence/state', 'ai'],

  // --- TASK-479: source hosting, repositories and scans ---
  ['DELETE /v1/issues/:p/pull-requests/:p', 'github'],
  ['DELETE /v1/repos/:p', 'github'],
  ['GET /v1/orgs/:p/github/installations', 'github'],
  ['GET /v1/orgs/:p/github/installations/:p/repos', 'github'],
  ['GET /v1/projects/:p/code/file', 'github'],
  ['GET /v1/projects/:p/code/tree', 'github'],
  ['GET /v1/projects/:p/repos', 'github'],
  ['GET /v1/repos/:p/scans', 'github'],
  ['GET /v1/scans/:p', 'github'],
  ['POST /v1/issues/:p/export/github', 'github'],
  ['POST /v1/issues/:p/fix-draft/pull-request', 'github'],
  ['POST /v1/projects/:p/repos', 'github'],
  // Reserves AI tokens and launches a Cloud Run job -- real money.
  ['POST /v1/repos/:p/scan', ['github', 'ai']],

  // --- Surface Intelligence D3: scan categories and findings ---
  // READS only. An integration pulling its own findings into another dashboard
  // is exactly what an org key is for, and none of these three writes anything.
  ['GET /v1/projects/:p/scan-categories', 'github'],
  ['GET /v1/projects/:p/scan-findings', 'github'],
  ['GET /v1/projects/:p/scan-findings/summary', 'github'],
  // The org-scoped read of the same catalogue, same reasoning. Its sibling
  // WRITE (`PUT /v1/orgs/:p/scan-categories/:p`) is session-only below,
  // matching the project-scoped pair that was already split that way.
  ['GET /v1/orgs/:p/scan-categories', 'github'],
  // Which repositories an org has connected, and how a connected repository's
  // branches map to environments. Both reads, both the shape of thing an
  // integration pulls into its own dashboard.
  ['GET /v1/orgs/:p/repos', 'github'],
  ['GET /v1/repos/:p/environment-map', 'github'],
  // Same shape as `POST /v1/repos/:p/scan` directly above: reserves AI tokens
  // and launches a Cloud Run job, so it carries `ai` as well as `github`.
  ['POST /v1/repos/:p/branch-scan', ['github', 'ai']],
  // Asks for an AI read of findings. Grouped with the scan trigger rather than
  // with `POST /v1/scan-findings/promote|ignore|reopen` (all session-only):
  // those three CHANGE a finding's state, this one requests analysis.
  ['POST /v1/scan-findings/ai-review', ['github', 'ai']],
  /**
   * The same pass with the SELECTION moved to the server, so the same
   * classification: it requests analysis and writes only `ai_verdict`, never a
   * finding's `state`. Grouping it with `promote|ignore|reopen` below would be
   * classifying it by what it costs rather than by what it changes — and by
   * what it changes it is a read with an opinion attached. The findings it
   * disputes stay `open`, stay counted and stay promotable; it demotes where
   * they are DRAWN and nothing else.
   *
   * `ai` is carried for the same reason `ai-review` carries it: it spends the
   * org's metered review budget through `scan_ai_review_reservations`.
   */
  ['POST /v1/projects/:p/scan-findings/triage', ['github', 'ai']],

  // --- release lanes ---
  // Read only, and classified the same way `GET /v1/projects/:p/product-
  // environments` already is: reading the lane layout is ordinary context for
  // an agent, and every write to it stays session-only.
  ['GET /v1/projects/:p/environment-lanes', 'projects'],

  // --- record-time capture (R5) ---
  // The same surface, and the same family, as the recording-session routes
  // further down: this IS the recorder's own flow — ask the pre-flight
  // questions, open a capture, annotate it live, close it. The desktop
  // recorder authenticates with a key, so denying these would mean the
  // recorder could open a session but not record into it.
  ['GET /v1/projects/:p/recording-captures/preflight', 'testing'],
  ['POST /v1/projects/:p/recording-captures', 'testing'],
  ['GET /v1/projects/:p/recording-captures/:p', 'testing'],
  ['POST /v1/projects/:p/recording-captures/:p/annotations', 'testing'],
  ['GET /v1/projects/:p/recording-captures/:p/feed', 'testing'],
  ['POST /v1/projects/:p/recording-captures/:p/complete', 'testing'],
  ['GET /v1/projects/:p/recording-captures/:p/split', 'testing'],
  ['POST /v1/projects/:p/recording-captures/:p/split', 'testing'],

  // --- splitting a recording into draft tickets (R5) ---
  // Reading, cutting and editing DRAFTS is editorial work on evidence the
  // recorder already captured, so it sits with the rest of `testing`.
  //
  // `POST .../drafts/:p/file` is the deliberate exception and is session-only
  // below. Its own docblock states the rule: "A HUMAN presses this. Nothing
  // files automatically" — the moment CLAUDE.md's "AI advises; humans decide"
  // is either honoured or not. Discarding a draft is not the mirror of filing
  // one: it throws away a suggestion, it does not act on it.
  ['POST /v1/projects/:p/recordings/:p/split', 'testing'],
  ['GET /v1/projects/:p/recordings/:p/split', 'testing'],
  // TASK-544 -- read-only, same shape as the `/split` read above: tells the
  // caller what capture intent a recording was made with. No decision, no
  // spend.
  ['GET /v1/projects/:p/recordings/:p/capture', 'testing'],
  ['GET /v1/projects/:p/recording-splits/:p', 'testing'],
  ['POST /v1/projects/:p/recording-splits/:p/drafts/:p/split', 'testing'],
  ['POST /v1/projects/:p/recording-splits/:p/drafts/:p/discard', 'testing'],
  ['PATCH /v1/projects/:p/recording-splits/:p/drafts/:p', 'testing'],
  ['POST /v1/projects/:p/recording-splits/:p/markers/move', 'testing'],

  // --- TASK-479: decision flow protocol ---

  // --- TASK-479: notification feed and preferences ---
  ['GET /v1/notifications/unread-count', 'notifications'],
  ['POST /v1/notifications/read', 'notifications'],
  ['POST /v1/notifications/read-all', 'notifications'],

  // --- TASK-479: configured agents, quests, nudges and onboarding ---
  ['DELETE /v1/projects/:p/agents/:p/memories/:p', 'agents'],
  ['GET /v1/interactive-agents/catalog', 'agents'],
  ['GET /v1/orgs/:p/agents', 'agents'],
  ['GET /v1/orgs/:p/agents/:p/audit', 'agents'],
  ['GET /v1/orgs/:p/agents/:p/skills', 'agents'],
  ['GET /v1/orgs/:p/interactive-agents', 'agents'],
  ['GET /v1/orgs/:p/nudges/:p/status', 'agents'],
  ['GET /v1/orgs/:p/quests', 'agents'],
  ['GET /v1/projects/:p/agents', 'agents'],
  ['GET /v1/projects/:p/agents/:p', 'agents'],
  ['GET /v1/projects/:p/agents/:p/audit', 'agents'],
  ['GET /v1/projects/:p/agents/:p/deliveries', 'agents'],
  ['GET /v1/projects/:p/agents/:p/findings', 'agents'],
  ['GET /v1/projects/:p/agents/:p/memories', 'agents'],
  ['GET /v1/projects/:p/agents/:p/my-preferences', 'agents'],
  ['GET /v1/projects/:p/agents/:p/runs', 'agents'],
  ['PATCH /v1/orgs/:p/agents/:p/settings', 'agents'],
  ['PATCH /v1/orgs/:p/agents/:p/skills/:p', 'agents'],
  ['PATCH /v1/projects/:p/agents/:p/instance', 'agents'],
  ['PATCH /v1/projects/:p/agents/:p/memories/:p', 'agents'],
  ['PATCH /v1/projects/:p/agents/:p/my-preferences', 'agents'],
  ['POST /v1/estimate-requests/:p/:p', 'agents'],
  ['POST /v1/issues/:p/estimate-requests', 'agents'],
  ['POST /v1/orgs/:p/agents/:p/skills', 'agents'],
  ['POST /v1/orgs/:p/nudges/:p/dismiss', 'agents'],
  ['POST /v1/orgs/:p/nudges/:p/impression', 'agents'],
  ['POST /v1/orgs/:p/nudges/:p/reactivate', 'agents'],
  ['POST /v1/orgs/:p/tour-session/start', 'agents'],
  ['POST /v1/projects/:p/agents/:p/memories', 'agents'],
  // Dispatches a real agent run -- an external provider call that spends AI
  // budget, so it requires `ai` as well as `agents`.
  ['POST /v1/projects/:p/agents/:p/run', ['agents', 'ai']],
  ['POST /v1/projects/:p/agents/:p/runs/:p/cancel', 'agents'],
  ['POST /v1/projects/:p/agents/:p/runs/:p/retry', 'agents'],
  ['PUT /v1/orgs/:p/interactive-agents/:p', 'agents'],

  // --- TASK-479: chat, DMs, polls and activity ---
  ['DELETE /v1/chat/conversations/:p/messages/:p', 'chat'],
  ['GET /v1/chat/conversations/:p/messages', 'chat'],
  ['GET /v1/chat/conversations/:p/status', 'chat'],
  ['POST /v1/chat/conversations/:p/status', 'chat'],
  ['GET /v1/chat/conversations/:p/attachments', 'chat'],
  // Board #679: an author-filtered VIEW of the same messages read directly
  // above, gated by the exact same `requireConversationAccess` membership
  // check -- it only lets a member filter to a former member's messages,
  // never anything a plain unfiltered read wouldn't already return.
  ['GET /v1/chat/conversations/:p/messages/by-author/:p', 'chat'],
  // Board #683: `min: 'viewer'`, deliberately NOT the creator/org-admin
  // moderation gate `PATCH .../archive` below requires -- "get this off MY
  // list", same floor and same everyday-work tier as `PUT .../read`.
  ['PUT /v1/chat/conversations/:p/hide', 'chat'],
  ['PUT /v1/chat/conversations/:p/unhide', 'chat'],
  ['GET /v1/issues/:p/chat', 'chat'],
  ['GET /v1/issues/:p/chat/participants', 'chat'],
  ['GET /v1/issues/:p/poll', 'chat'],
  // Board #679: create-or-fetch a project's chat conversation, reusing the
  // exact same `ensureProjectConversation` the sibling POST route below
  // already calls -- an ordinary project-role-gated read/lazy-create, same
  // tier as `GET /v1/projects/:p/chat` just below.
  ['GET /v1/projects/:p/chat/conversation', 'chat'],
  ['GET /v1/projects/:p/chat', 'chat'],
  ['GET /v1/projects/:p/chat/participants', 'chat'],
  ['PATCH /v1/chat/conversations/:p/messages/:p', 'chat'],
  ['PATCH /v1/chat/messages/:p', 'chat'],
  ['POST /v1/chat/conversations/:p/messages', 'chat'],
  ['POST /v1/chat/conversations/:p/ui-guidance/prepare', 'chat'],
  ['GET /v1/chat/conversations/:p/ui-guidance/:p', 'chat'],
  ['GET /v1/chat/conversations/:p/ui-guidance/:p/receipts', 'chat'],
  // Board #695: SENDING a secure message is everyday work, same tier as an
  // ordinary send just above -- an integration plausibly has a legitimate
  // reason to relay a secret through this channel too, and the route's own
  // DM-only + sealing behaviour doesn't change based on caller type. The
  // REVEAL half is a different story entirely -- see SESSION_ONLY_ROUTES.
  ['POST /v1/chat/conversations/:p/messages/secure', 'chat'],
  // Chat question widget (Eric, 2026-10-02). DARK: the four routes answer an unregistered route's 404 while
  // platform setting `chat.questions` is off. Asking, reading and withdrawing are everyday 'chat' work for an agent
  // (the persona asks a person a multiple-choice question). ANSWERING is reachable by a key only so the route can
  // give a clear 403 `session_required`: the handler refuses every key unless the asker set `allowBotAnswers`,
  // so a person's own key (or a persona of theirs) cannot answer in their name by default.
  ['POST /v1/chat/conversations/:p/issue-proposals', 'chat'],
  ['GET /v1/chat/conversations/:p/issue-proposals/:p', 'chat'],
  ['POST /v1/chat/conversations/:p/questions', 'chat'],
  ['GET /v1/chat/conversations/:p/questions/:p', 'chat'],
  ['POST /v1/chat/conversations/:p/questions/:p/answer', 'chat'],
  ['POST /v1/chat/conversations/:p/questions/:p/withdraw', 'chat'],
  ['POST /v1/issues/:p/chat', 'chat'],
  ['POST /v1/issues/:p/poll', 'chat'],
  ['POST /v1/issues/:p/poll/vote', 'chat'],
  ['POST /v1/projects/:p/chat', 'chat'],

  // --- TASK-479: statistics, reports and triage priority ---
  ['DELETE /v1/report-subscriptions/:p', 'stats'],
  ['GET /v1/orgs/:p/priority', 'stats'],
  ['GET /v1/orgs/:p/report-subscriptions', 'stats'],
  ['GET /v1/orgs/:p/reports/trends', 'stats'],
  ['GET /v1/orgs/:p/stats', 'stats'],
  ['GET /v1/projects/:p/priority', 'stats'],
  ['GET /v1/projects/:p/reports/trends', 'stats'],
  ['GET /v1/projects/:p/stats', 'stats'],
  ['GET /v1/projects/:p/triage', 'stats'],
  ['POST /v1/orgs/:p/report-subscriptions', 'stats'],

  // --- TASK-479, corrected after reading the handlers (see
  // audit/2026-08-27-task-479-route-classification.md) ---
  // The member-floor identity picker. api-keys/routes.ts:139-158 designs it as
  // exactly that: it returns { id, name, ownerId, ownerName } and, in its own
  // words, "a read that leaks no secret, no prefix, and no scope" -- the
  // secret-bearing listing is the SEPARATE GET /v1/orgs/:p/api-keys, gated on
  // org:manage_api_keys, which stays session-only. This is also the entry
  // auth.ts's own board #117 comment above already assumed was here.
  ['GET /v1/orgs/:p/api-keys/agents', 'orgs'],
  // Materializes the caller's ALREADY-RESOLVED effective role as a roster row
  // (`role: access.projectRole`, projects/routes.ts:304). It grants nothing:
  // a caller who cannot already reach the project is refused by
  // requireProjectRole before any insert. Classified session-only on a first
  // pass under the name "join"; the handler says otherwise.
  ['POST /v1/projects/:p/join', 'projects'],
  // Status only -- `agentBrowserConnectionPublicColumns` (uptime/service.ts:59-68)
  // omits the sealed `credentials` column. The PUT that WRITES the plaintext
  // key stays session-only.
  ['GET /v1/orgs/:p/agent-browser-connection', 'orgs'],
  // A growth code and signup URL. Grants access to nothing.
  ['GET /v1/orgs/:p/referral-code', 'orgs'],

  // --- Marketing Tools (2026-08-29): reads, plus internal-only writes with no
  // real-world side effect and no third-party spend. Everything that triggers
  // a real Vertex/Veo/Apollo/Klaviyo/Postiz call, spends money, or reaches
  // outside the org (a scheduled post, a sent email, a published blog post)
  // stays SESSION_ONLY below -- see that list's own new "external side effect
  // or spend" category for the full reasoning, including why the mandatory
  // human-approval-gate endpoints (`.../approve`) are there rather than here:
  // an API key reaching them would defeat the entire point of that gate. ---
  ['GET /v1/projects/:p/marketing/profile', 'marketing'],
  ['GET /v1/projects/:p/marketing/profile/field-meta', 'marketing'],
  ['GET /v1/projects/:p/marketing/voices', 'marketing'],
  // Voice CRUD is internal brand-copy data with no external reach -- same
  // "everyday work" floor as deleting a release or a test plan.
  ['POST /v1/projects/:p/marketing/voices', 'marketing'],
  ['PATCH /v1/projects/:p/marketing/voices/:p', 'marketing'],
  ['DELETE /v1/projects/:p/marketing/voices/:p', 'marketing'],
  ['GET /v1/projects/:p/marketing/assets', 'marketing'],
  ['POST /v1/projects/:p/marketing/assets', 'marketing'],
  ['DELETE /v1/projects/:p/marketing/assets/:p', 'marketing'],
  // Reading an in-flight or finished onboarding scan's status/result. Starting
  // one is the expensive real-money action and stays SESSION_ONLY.
  ['GET /v1/projects/:p/marketing/onboarding/state', 'marketing'],
  // --- Deploy Assistant (deploy scope DA1-DA4) ---
  // Everything here is INTERNAL. The assistant holds no provider credential,
  // pushes no binary and executes nothing (DA1/DA2): a plan is generated text,
  // a step status is the user's own bookkeeping, and a check is a verdict on
  // output a human pasted. So the dividing line that puts marketing's
  // `generate` routes in SESSION_ONLY does not apply to any of these — with the
  // one exception of `/ask`, which IS a real grounded Vertex call and lives in
  // SESSION_ONLY_ROUTES below for exactly the reason blog `generate` does.
  ['GET /v1/projects/:p/deploy/adaptation', 'deploy'],
  ['GET /v1/projects/:p/deploy/questions', 'deploy'],
  ['GET /v1/projects/:p/deploy/plans', 'deploy'],
  ['POST /v1/projects/:p/deploy/plans', 'deploy'],
  ['GET /v1/projects/:p/deploy/plans/:p', 'deploy'],
  ['PATCH /v1/projects/:p/deploy/plans/:p/steps/:p', 'deploy'],
  ['POST /v1/projects/:p/deploy/plans/:p/steps/:p/checks', 'deploy'],
  ['POST /v1/projects/:p/deploy/plans/:p/archive', 'deploy'],
  // --- Native CMS platform (board #505) ---
  // Reads only here, same shape as blog's `GET .../posts` above: a content
  // type or document that already exists is everyday work to look at. The
  // corresponding creates/edits/publish/unpublish/archive/restore are
  // SESSION_ONLY below -- same reasoning as blog's post family: a CMS
  // document can be published and go publicly live, so the whole mutation
  // surface for both documents and the content types that govern their shape
  // is conservatively kept out of API-key reach, not just the publish step.
  ['GET /v1/content-work/status', 'cms'],
  ['GET /v1/orgs/:p/content-work/status', 'cms'],
  ['GET /v1/orgs/:p/content-engagements/:p/content-work/seo', 'cms'],
  ['POST /v1/orgs/:p/content-engagements/:p/content-work/seo/manual-checks', 'cms'],
  ['GET /v1/orgs/:p/content-engagements/:p/content-work/artifacts', 'cms'],
  ['POST /v1/orgs/:p/content-engagements/:p/content-work/artifacts', 'cms'],
  ['GET /v1/orgs/:p/content-engagements/:p/content-work/artifacts/:p', 'cms'],
  ['GET /v1/orgs/:p/content-engagements/:p/content-work/artifacts/:p/body', 'cms'],
  ['PATCH /v1/orgs/:p/content-engagements/:p/content-work/artifacts/:p', 'cms'],
  ['POST /v1/orgs/:p/content-engagements/:p/content-work/artifacts/:p/approve', 'cms'],
  ['POST /v1/orgs/:p/content-engagements/:p/content-work/artifacts/:p/claim', 'cms'],
  // Local workspace preparation is deliberately delegated to cms-scoped keys with write scope:
  // draft sites, design, saved builds, audience evidence, DNS checklists and import plans.
  // These routes do not publish or write provider configuration. Project permissions still apply.
  // CMS document/schema writes, import apply, factory authority and scheduling remain SESSION_ONLY.
  ['GET /v1/projects/:p/site-recipes', 'cms'],
  ['POST /v1/projects/:p/site-drafts', 'cms'],
  ['GET /v1/projects/:p/sites/:p/workspace', 'cms'],
  ['PATCH /v1/projects/:p/sites/:p/workspace', 'cms'],
  ['POST /v1/projects/:p/sites/:p/builds', 'cms'],
  ['GET /v1/projects/:p/sites/:p/builds/:p', 'cms'],
  ['GET /v1/projects/:p/sites/:p/builds/:p/preview', 'cms'],
  ['GET /v1/projects/:p/sites/:p/builds/:p/launch-checks', 'cms'],
  ['GET /v1/projects/:p/sites/:p/recipe-blueprint', 'cms'],
  ['PATCH /v1/projects/:p/sites/:p/audience', 'cms'],
  ['GET /v1/projects/:p/sites/:p/media-kit', 'cms'],
  ['POST /v1/projects/:p/sites/:p/dns-plan', 'cms'],
  ['POST /v1/projects/:p/sites/:p/imports/plan', 'cms'],
  ['GET /v1/projects/:p/cms/content-types', 'cms'],
  ['GET /v1/projects/:p/cms/documents', 'cms'],
  ['GET /v1/cms/content-types/:p', 'cms'],
  ['GET /v1/cms/documents/:p', 'cms'],
  ['GET /v1/cms/documents/:p/versions', 'cms'],
  // Pure, stateless, synchronous markdown->HTML rendering (see the route's own
  // header comment in modules/cms/routes.ts) -- no persistence, no third-party
  // spend, same "everyday work" floor as
  // POST /v1/projects/:p/onboarding-wizard/preview-sentence above.
  ['POST /v1/cms/render-markdown', 'cms'],
  ['GET /v1/projects/:p/marketing/scans/:p', 'marketing'],
  // List only -- same "omits the sealed credentials column" shape as
  // GET /v1/orgs/:p/agent-browser-connection above. The PUT that writes a
  // vault-stored third-party key stays SESSION_ONLY (category 6, storing a
  // third-party credential); DELETE only removes GoodQA's own pointer to an
  // already vault-stored key (the real secret is untouched either way), same
  // "everyday work" floor as any other confined delete.
  ['GET /v1/projects/:p/marketing/integrations', 'marketing'],
  ['DELETE /v1/projects/:p/marketing/integrations/:p', 'marketing'],
  ['GET /v1/projects/:p/marketing/content-issue-links', 'marketing'],
  // Linking marketing content to an internal issue is exactly the same shape
  // as any other issue-link write already on this list -- no external reach.
  ['POST /v1/projects/:p/marketing/content-issue-links', 'marketing'],
  ['DELETE /v1/projects/:p/marketing/content-issue-links/:p', 'marketing'],
  ['GET /v1/projects/:p/marketing/blog/posts', 'marketing'],
  ['GET /v1/projects/:p/marketing/blog/posts/:p', 'marketing'],
  ['GET /v1/projects/:p/marketing/social/postiz-integrations', 'marketing'],
  ['GET /v1/projects/:p/marketing/social/zernio', 'marketing'],
  ['GET /v1/projects/:p/marketing/social/zernio/analytics', 'marketing'],
  ['GET /v1/projects/:p/marketing/social/posts', 'marketing'],
  ['GET /v1/projects/:p/marketing/social/posts/:p', 'marketing'],
  // Reading already-generated media (from a PAST generate call) has no new
  // spend -- issuing a new generate-image/generate-video call is the
  // expensive action and stays SESSION_ONLY.
  ['GET /v1/projects/:p/marketing/social/generated-media/:p', 'marketing'],
  // TASK-504/496 -- Design Studio's durable conversations, same rule as the
  // stateless generate route's own comment below (`POST .../studio/generate`):
  // reading conversations/turns/generations already on record has no new
  // spend and stays API-key reachable; dispatching a NEW turn (which can
  // dispatch a billed generation) is the expensive action and is
  // SESSION_ONLY, same split as generated-media above.
  ['GET /v1/projects/:p/studio/images', 'ai'],
  ['POST /v1/projects/:p/studio/images', 'ai'],
  ['POST /v1/projects/:p/studio/images/copy', 'ai'],
  ['GET /v1/projects/:p/studio/images/:p', 'ai'],
  ['GET /v1/projects/:p/studio/images/:p/inspection', 'ai'],
  ['POST /v1/projects/:p/studio/images/:p/versions', 'ai'],
  ['POST /v1/projects/:p/studio/images/:p/accept', 'ai'],
  ['POST /v1/projects/:p/studio/images/:p/revert', 'ai'],
  ['POST /v1/projects/:p/studio/images/:p/branch', 'ai'],
  ['GET /v1/projects/:p/studio/conversations', 'ai'],
  ['GET /v1/projects/:p/studio/conversations/:p', 'ai'],
  ['GET /v1/projects/:p/studio/generations/:p', 'ai'],
  ['GET /v1/projects/:p/marketing/prospecting/searches', 'marketing'],
  ['GET /v1/projects/:p/marketing/prospecting/searches/:p', 'marketing'],
  ['GET /v1/projects/:p/marketing/prospecting/prospects', 'marketing'],
  ['GET /v1/projects/:p/marketing/prospecting/status', 'marketing'],
  ['GET /v1/projects/:p/marketing/mailer/status', 'marketing'],
  ['GET /v1/projects/:p/marketing/mailer/klaviyo/lists', 'marketing'],
  ['GET /v1/projects/:p/marketing/mailer/klaviyo/segments', 'marketing'],
  ['GET /v1/projects/:p/marketing/mailer/leads', 'marketing'],
  ['GET /v1/projects/:p/marketing/mailer/leads/:p/gate', 'marketing'],
  ['GET /v1/projects/:p/marketing/mailer/leads/:p/consent', 'marketing'],
  ['GET /v1/projects/:p/marketing/mailer/campaigns', 'marketing'],
  ['GET /v1/projects/:p/marketing/mailer/campaigns/:p', 'marketing'],
  ['GET /v1/projects/:p/marketing/seo/analyses', 'marketing'],
  ['GET /v1/projects/:p/marketing/seo/analyses/:p', 'marketing'],

  // --- Everything below landed on main the same day as TASK-479, in PRs this
  // branch's own base predates, so none of it was ever classified. Same
  // completeness-test-driven pass, applied with the SAME categories above --
  // no new rule invented per route. ---
  // Personal feature-card state (ack/opt-out/screenshot): matches the
  // /v1/me/issue-filters GET precedent -- everyday personal UI state, no
  // cross-org reach (unlike the PATCH /v1/notifications/preferences bug this
  // PR itself found, which WAS cross-org because it lived on the user row).
  ['GET /v1/me/scratchpad', 'orgs'],
  // The Drawings tab's canvas, same personal-resource shape as the note above:
  // a read of the caller's OWN scratchpad, no cross-org reach. HEAD is covered by
  // this GET (apiKeyRouteResources maps HEAD onto GET).
  ['GET /v1/me/scratchpad/drawing', 'orgs'],
  // Notes to self (Eric, 2026-10-03): the cross-machine half -- send/list/search notes and push a file through the
  // personal-file pipeline. The module admits only the caller's own self-scoped key (assertPersonalPrincipal).
  // Edit, pin, delete, the read marker and the scratchpad file routes stay session-only.
  ['GET /v1/me/notes-to-self', 'notes_to_self'],
  ['GET /v1/me/notes-to-self/messages', 'notes_to_self'],
  ['POST /v1/me/notes-to-self/messages', 'notes_to_self'],
  ['GET /v1/me/notes-to-self/search', 'notes_to_self'],
  ['POST /v1/me/notes-to-self/attachments', 'notes_to_self'],
  ['PUT /v1/me/files/:p/content', 'notes_to_self'],
  ['POST /v1/me/files/:p/complete', 'notes_to_self'],
  ['GET /v1/me/files/:p/read-target', 'notes_to_self'],
  ['GET /v1/me/files/:p/content', 'notes_to_self'],
  ['GET /v1/me/files/usage', 'notes_to_self'],
  ['GET /v1/me/feature-cards', 'orgs'],
  ['GET /v1/feature-cards/:p/screenshot', 'orgs'],
  // Personal notification archive/unarchive: per-user, local to the caller's
  // own notification list -- not the org-wide email-mute the preferences bug
  // above exposed.
  ['POST /v1/notifications/:p/archive', 'orgs'],
  ['POST /v1/notifications/:p/unarchive', 'orgs'],
  // Chat/messaging: this codebase already treats ordinary send/read/react as
  // 'chat'-family everyday work (POST /v1/chat/conversations/:p/messages was
  // already allowed before this pass) -- these are the same class of action
  // on the newer DM/thread/reaction surface, not a new risk tier.
  ['POST /v1/orgs/:p/chat/dms', 'chat'],
  ['GET /v1/orgs/:p/chat/dms', 'chat'],
  ['POST /v1/orgs/:p/chat/channels', 'chat'],
  // Composite action: creating a line also enrolls its recipe's agent-knowledge seeds.
  ['POST /v1/orgs/:p/chat/lines', ['chat', 'agent_knowledge']],
  ['GET /v1/orgs/:p/chat/lines/:p', 'chat'],
  ['GET /v1/orgs/:p/chat/line-templates', 'chat'],
  ['GET /v1/orgs/:p/chat/line-templates/:p', 'chat'],
  ['GET /v1/orgs/:p/chat/conversations', 'chat'],
  ['GET /v1/orgs/:p/chat/search', 'chat'],
  ['GET /v1/orgs/:p/chat/unread-count', 'chat'],
  // API-key PERSONAS (Eric, 2026-09-29). The member-facing bot directory and
  // "DM this bot" are ordinary chat work. The /v1/persona/* family is the bot's
  // OWN inbox: every handler derives the persona from `auth.apiKeyId` alone and
  // refuses a browser session, so there is nothing to impersonate. Managing a
  // persona (create/patch/delete, adding one to a channel) is session-only, in
  // SESSION_ONLY_ROUTES below, for the same reason a key cannot mint keys.
  ['GET /v1/me/command-center', 'command_center'],
  ['GET /v1/me/command-center/scope', 'command_center'],
  ['GET /v1/orgs/:p/command-center', 'command_center'],
  ['GET /v1/orgs/:p/work-dashboard', 'work_dashboard'],
  ['GET /v1/me/command-center/events', 'command_center'],
  ['GET /v1/orgs/:p/personas', 'chat'],
  ['POST /v1/orgs/:p/personas/:p/dm', 'chat'],
  ['GET /v1/qac/turns/:p/context', 'chat'],
  ['GET /v1/qac/turns/:p/egress', 'chat'],
  ['POST /v1/qac/turns/lease', 'chat'],
  ['POST /v1/persona/turn-grants', 'chat'],
  ['POST /v1/qac/turns/:p/grant', 'chat'],
  // The runtime handler still requires the designated Commander and that org's turn.
  ['POST /v1/qac/turns/:p/complete', 'chat'],
  ['POST /v1/runners/qac/usage', 'chat'],
  ['GET /v1/persona/me', 'chat'],
  ['GET /v1/persona/inbox', 'chat'],
  ['GET /v1/persona/events', 'chat'],
  ['GET /v1/persona/conversations', 'chat'],
  ['GET /v1/persona/conversations/:p/messages', 'chat'],
  ['POST /v1/persona/ai/spend/harness', 'chat'],
  ['POST /v1/persona/conversations/:p/read', 'chat'],
  ['POST /v1/persona/conversations/:p/messages', 'chat'],
  ['POST /v1/persona/dm/:p', 'chat'],
  ['GET /v1/persona/mentions', 'chat'],
  ['POST /v1/persona/mentions/read-all', 'chat'],
  ['GET /v1/persona/mentions/:p/thread', 'chat'],
  ['POST /v1/persona/mentions/:p/read', 'chat'],
  ['POST /v1/persona/mentions/:p/reply', 'chat'],
  // A file posted with a message the persona may already read (its DM, a
  // conversation it was added to, the thread it was mentioned in), handed over
  // as a 5-minute signed URL. Same 'chat' family and same GET-only read as the
  // message reads above, so a read-only key may use it; the handler re-checks the
  // persona's grant and 404s everything else (personas/service.ts).
  ['GET /v1/agent-files/status', 'uploads'],
  ['GET /v1/persona/attachments/:p/metadata', 'chat'],
  ['GET /v1/persona/attachments/:p/read-target', 'chat'],
  ['GET /v1/persona/attachments/:p/content', 'chat'],
  ['GET /v1/persona/attachments/:p/agent-content', 'chat'],
  ['GET /v1/persona/attachments/:p/text', 'chat'],
  ['GET /v1/persona/attachments/:p/transcript', 'chat'],
  ['GET /v1/attachments/:p/agent-content', 'uploads'],
  ['GET /v1/attachments/:p/text', 'uploads'],
  ['GET /v1/me/files/:p', 'notes_to_self'],
  ['GET /v1/me/files/:p/agent-content', 'notes_to_self'],
  ['GET /v1/me/files/:p/text', 'notes_to_self'],
  ['GET /v1/persona/attachments/:p', 'chat'],
  // Discord static pilot bridge (dark: discord.enabled; the unknown route's 404 while the switch does not cover the
  // bot's org). A READ: the switch, which configured people the bot may reach and each thread's head, so the bridge
  // reads a thread only when it moved and never spends the persona's writes to learn membership (review rvf finding 4).
  ['GET /v1/persona/discord/status', 'chat'],
  // Agent chat (docs/design/AGENT-CHAT.md; dark switch agentChat.enabled, default off): the AGENT surface. Same
  // 'chat' family and the same rule as every /v1/persona/* route: the agent is derived from the key alone and the
  // handlers refuse a session, a key with no live persona and a user-scoped key. Runner keys keep their binding (the
  // handlers keep them out of org-wide channels and inside their project). The PEOPLE surface
  // (/v1/orgs/:p/agent-chat/*) is SESSION_ONLY below.
  ['GET /v1/persona/agent-chat/status', 'chat'],
  ['POST /v1/persona/agent-chat/hello', 'chat'],
  ['POST /v1/persona/agent-chat/heartbeat', 'chat'],
  ['GET /v1/persona/agent-chat/roster', 'chat'],
  ['GET /v1/persona/agent-chat/role-history', 'chat'],
  ['POST /v1/persona/agent-chat/roles/request', 'chat'],
  // Coordinator-delegated hive enrollment (dark: agentChat.selfEnroll). Key-reachable 'chat' family; the active
  // coordinator persona lists pending enrollments and approves one (the route handler enforces the coordinator identity,
  // the daily cap and the member-level mint). Dark-flag 404 is enforced in the route's own onRequest hook.
  ['GET /v1/persona/agent-chat/enroll/pending', 'chat'],
  ['POST /v1/persona/agent-chat/enroll/approve', 'chat'],
  ['GET /v1/persona/agent-chat/channels', 'chat'],
  ['POST /v1/persona/agent-chat/channels', 'chat'],
  ['POST /v1/persona/agent-chat/groups', 'chat'],
  ['POST /v1/persona/agent-chat/conversations/:p/join', 'chat'],
  ['POST /v1/persona/agent-chat/conversations/:p/leave', 'chat'],
  ['POST /v1/persona/agent-chat/conversations/:p/resume', 'chat'],
  ['GET /v1/persona/agent-chat/conversations/:p/messages', 'chat'],
  ['POST /v1/persona/agent-chat/conversations/:p/digest', 'chat'],
  ['POST /v1/persona/agent-chat/send', 'chat'],
  ['GET /v1/persona/agent-chat/inbox', 'chat'],
  ['POST /v1/persona/agent-chat/read', 'chat'],
  ['POST /v1/persona/agent-chat/messages/:p/ack', 'chat'],
  ['GET /v1/persona/agent-chat/messages/:p/receipts', 'chat'],
  // Agent chat RELIABLE DELIVERY (docs/agent-chat-reliability.md; dark switch agentChat.reliableDelivery, default off):
  // the persona's own mailbox (stream, long poll, ack, read), its own messages' delivery state, thread digests and the
  // resume pack. Same 'chat' family and the same rule as the agent-chat routes above: the persona is the key's own.
  ['GET /v1/persona/agent-chat/stream', 'chat'],
  ['GET /v1/persona/agent-chat/deliveries', 'chat'],
  ['POST /v1/persona/agent-chat/deliveries/ack', 'chat'],
  ['POST /v1/persona/agent-chat/deliveries/read', 'chat'],
  ['GET /v1/persona/agent-chat/messages/:p/delivery', 'chat'],
  ['POST /v1/persona/agent-chat/messages/:p/redeliver', 'chat'],
  ['GET /v1/persona/agent-chat/sent', 'chat'],
  ['GET /v1/persona/agent-chat/resume', 'chat'],
  ['GET /v1/persona/agent-chat/threads/:p', 'chat'],
  ['POST /v1/persona/agent-chat/threads/:p/remember', 'chat'],
  // The bot's OWN push channel: read its endpoint health + delivery log and
  // switch it back on after the SYSTEM switched it off (never a human disable).
  ['GET /v1/persona/webhooks', 'chat'],
  ['GET /v1/persona/webhooks/:p/deliveries', 'chat'],
  ['POST /v1/persona/webhooks/:p/enable', 'chat'],
  // The account-wide counterpart. Allowed for the same reason
  // `GET /v1/notifications/unread-count` already is, and on the same terms: its
  // handler resolves the org list from memberships and then narrows it with
  // `getApiKeyOrgId()`, so a scoped key sees exactly its own org and can never
  // enumerate its creator's other tenants (`/v1/me` refuses that too). Asserted
  // in `test/messaging-cross-org-unread.test.ts`.
  ['GET /v1/chat/unread-count', 'chat'],
  // Board #762 "Active chats": the cross-org read-only aggregation directly
  // analogous to `GET /v1/chat/unread-count` immediately above -- the org
  // list is resolved server-side from live `org_members` rows inside the
  // handler, never accepted from the caller, so a scoped key sees exactly
  // its own org(s) the same way the unread-count route already does.
  ['GET /v1/chat/active', 'chat'],
  ['PUT /v1/chat/conversations/:p/read', 'chat'],
  // Chat v2 "Mark unread": the caller's OWN read marker moved backwards -- the
  // same personal read state `PUT .../read` directly above already writes, so
  // the same 'chat' family rather than a new risk tier.
  ['PUT /v1/chat/conversations/:p/messages/:p/unread', 'chat'],
  ['PUT /v1/chat/conversations/:p/messages/:p/reactions', 'chat'],
  ['DELETE /v1/chat/conversations/:p/messages/:p/reactions', 'chat'],
  ['GET /v1/chat/conversations/:p/threads/:p', 'chat'],
  ['POST /v1/chat/conversations/:p/threads/:p/replies', 'chat'],
  ['GET /v1/chat/conversations/:p/threads/:p/replies', 'chat'],
  ['POST /v1/chat/conversations/:p/threads/:p/read', 'chat'],
  ['PUT /v1/chat/conversations/:p/threads/:p/follow', 'chat'],
  ['DELETE /v1/chat/conversations/:p/threads/:p/follow', 'chat'],
  // Board #643 Favourites tier: the caller's OWN membership row, same shape as
  // the read-state and mark-unread entries above -- never another member's.
  ['PUT /v1/chat/conversations/:p/favorite', 'chat'],
  ['PUT /v1/chat/conversations/:p/unfavorite', 'chat'],
  // Sidebar v2 aliases retain the chat family and caller identity. Their
  // encapsulated onRequest gate answers 404 before auth while platform off.
  ['GET /v1/orgs/:p/chat/sidebar-v2', 'chat'],
  ['PUT /v1/chat/conversations/:p/pin', 'chat'],
  ['DELETE /v1/chat/conversations/:p/pin', 'chat'],
  // Chat UX A (Tisha #352): mute/unmute -- the caller's OWN member row again,
  // same shape as favorite/unfavorite, for a standard key acting as its owner.
  // A RUNNER key authenticates as its human sponsor, so the route itself
  // refuses `apiKeyKind === 'runner'` (#363 review): otherwise a bot would be
  // writing its sponsor's alert preference, not its own.
  ['PUT /v1/chat/conversations/:p/mute', 'chat'],
  ['PUT /v1/chat/conversations/:p/unmute', 'chat'],
  // Board #762 "Active chats": dismissing the caller's OWN Active-list entry,
  // same shape as the read-state and favorite/unfavorite entries immediately
  // above -- a personal per-conversation watermark on the caller's own
  // membership row, never another member's.
  ['PUT /v1/chat/conversations/:p/active-dismiss', 'chat'],
  // Same shape as the existing POST /v1/issues/:p/attachments entry near the
  // top of this list -- a chat attachment is the same evidence-upload
  // authority, not a different one.
  ['POST /v1/chat/conversations/:p/attachments', ['chat', 'uploads']],
  // AI-summary generation: this codebase already allows bounded single-call
  // AI spend under the 'ai' family (POST /v1/issues/:p/ai/enhance, etc.) --
  // an issue/conversation/thread summary is the same shape (one bounded call
  // against an existing thread), unlike Marketing Tools' unbounded
  // multi-page-crawl jobs above, which is why those stayed SESSION_ONLY.
  ['GET /v1/issues/:p/ai-summary', 'ai'],
  ['POST /v1/issues/:p/ai-summary', 'ai'],
  ['GET /v1/chat/conversations/:p/ai-summary', 'ai'],
  ['POST /v1/chat/conversations/:p/ai-summary', 'ai'],
  ['GET /v1/chat/conversations/:p/threads/:p/ai-summary', 'ai'],
  ['POST /v1/chat/conversations/:p/threads/:p/ai-summary', 'ai'],
  // Chat v2 "Ask AI about this message": one bounded call whose answer goes
  // only to the caller -- the same shape of spend as the summaries above (org
  // quota before, usage meter after) plus its own 10/min route limit.
  ['POST /v1/chat/conversations/:p/messages/:p/ask-ai', 'ai'],

  // --- TASK-533: channel browse/join/leave and message forwarding. Same
  // 'chat'-family everyday work as the send/read/react block above; none of
  // these reaches anything the caller could not already reach. ---
  // The channel DIRECTORY is a second view over the SAME
  // `visibleConversationFilter` predicate `GET /v1/orgs/:p/chat/conversations`
  // (already allowed) uses, restricted to `kind = 'channel'` -- alphabetical
  // and searchable rather than activity-sorted. A private channel the caller
  // cannot already read is not browsable, exactly as it is not listable.
  ['GET /v1/orgs/:p/chat/channels', 'chat'],
  // Joining/leaving writes `chat_conversation_members.is_member` for the
  // caller's OWN membership, and only for a channel the browse predicate above
  // already admitted. `POST /v1/orgs/:p/chat/channels` -- creating a channel
  // outright -- is already allowed, so joining one is not a wider action.
  ['PUT /v1/chat/conversations/:p/join', 'chat'],
  ['DELETE /v1/chat/conversations/:p/leave', 'chat'],
  // Board #612 follow-up ("add people to a channel"). Board #117's carve-out
  // above the /members GET tests applies here too: reading the roster is
  // identity resolution ("who is already in this channel"), not a membership
  // write, so it stays allowed under the same 'chat' resource as join/leave.
  ['GET /v1/chat/conversations/:p/members', 'chat'],
  // OWNER RULING 2026-10-07 (Eric, typed): bots must add existing org members to rooms in an emergency.
  // This one membership write uses the chat family and the handler's same-org, readable-channel, viewer+ gate;
  // it cannot add the caller, admit outsiders or widen read access. User tokens remain non-delegable
  // (lib/user-token-policy.ts); every other membership write stays session-only.
  ['POST /v1/chat/conversations/:p/members', 'chat'],
  // Chat UX A's `GET .../add-candidates` is deliberately NOT here: it returns the
  // whole org directory (names + emails) and the project's access map, which a
  // `chat` key -- a runner's included -- must not read. See SESSION_ONLY_ROUTES.
  // Forwarding posts a NEW message carrying quoted text into a target
  // conversation the caller is separately authorized for (every target goes
  // through its own `requireConversationAccess`). That is
  // `POST /v1/chat/conversations/:p/messages`, which is already allowed, with
  // a body the server composes instead of the client.
  ['POST /v1/chat/conversations/:p/messages/:p/forward', 'chat'],
  // Board #764 ("Create Group From Message"): a strict composition of two
  // already-allowed primitives immediately above -- `assertMayOpenDirectConversation`
  // + `openDirectConversation` is the exact function pair behind
  // `POST /v1/orgs/:p/chat/dms` (naming NEW participants is already an
  // accepted 'chat'-family action there, gated by the same not-a-guest /
  // live-standing / no-block-edge checks), and the copy step is the same
  // requireConversationAccess-gated forwarding posture as `forward` right
  // above. Neither half is a new risk tier on its own, so the composition
  // is not one either.
  ['POST /v1/chat/conversations/:p/messages/:p/branch-to-group', 'chat'],

  // Board #644: save/remind. Same "reaches nothing the caller could not
  // already reach" posture as reactions/forward immediately above -- both
  // routes resolve the message through the SAME `requireConversationAccess`
  // gate every other message action here already uses, and both act only on
  // the CALLER's own per-user state (a bookmark, a reminder), never anyone
  // else's.
  ['PUT /v1/chat/conversations/:p/messages/:p/save', 'chat'],
  ['DELETE /v1/chat/conversations/:p/messages/:p/save', 'chat'],
  ['POST /v1/chat/conversations/:p/messages/:p/remind', 'chat'],
  // Read-only, own data, same shape as `GET /v1/orgs/:p/chat/search` and
  // `GET /v1/chat/unread-count` above -- and (saved-messages specifically)
  // re-verified live through `visibleConversationFilter` on every page, so
  // an API key scoped to a caller who has since lost access to a
  // conversation sees exactly what a session caller would: nothing from it.
  ['GET /v1/orgs/:p/chat/saved-messages', 'chat'],
  ['GET /v1/chat/message-reminders', 'chat'],
  // Cancelling is a bounded write to the CALLER's own reminder row only
  // (`ownedMessageReminder` requires `userId = session`, 404 on anyone
  // else's) -- same posture as `DELETE /v1/chat/conversations/:p/leave`
  // above, which is also an own-state-only write.
  ['DELETE /v1/chat/message-reminders/:p', 'chat'],

  // TASK-544: the per-project ESP connection LIST. Read-only and
  // credential-free by construction -- `listMailerConnections`
  // (`lib/mailer-providers/connections-service.ts:204`) projects provider,
  // status, capabilities, authMethod and timestamps, and never `vaultSecretId`
  // or any secret. Same class as `GET /v1/projects/:p/marketing/mailer/status`
  // already on this list. Every WRITE on the same path -- connect, validate,
  // disconnect, OAuth start -- is SESSION_ONLY below.
  ['GET /v1/projects/:p/marketing/mailer/connections', 'marketing'],

  // Billboard (board #765) -- everyday participation: reading, creating a
  // post, commenting/replying, reacting, editing or deleting YOUR OWN post
  // or comment (ownership-authorized in the handler, same posture as chat
  // message edit/delete directly above), and claiming an attachment. All of
  // this is "sending a message or reacting" in the FOUNDATION PR's own
  // access-chokepoint sense -- the same everyday-work tier the 'chat' block
  // above already puts ordinary send/read/react/edit/delete on. Moderation
  // actions (pin/lock/archive, which apply even to someone else's post and
  // in pin/lock's case have no ownership escape hatch at all -- see
  // `apps/api/src/modules/billboard/access.ts`'s header) are SESSION_ONLY
  // below instead, matching `PATCH /v1/chat/conversations/:p` (channel
  // rename/archive) being session-only for the identical "management/
  // moderation-tier action, not everyday work" reason stated on that entry.
  ['POST /v1/orgs/:p/billboard/discussions', 'billboard'],
  ['POST /v1/projects/:p/billboard/discussions', 'billboard'],
  ['GET /v1/orgs/:p/billboard/discussions', 'billboard'],
  ['GET /v1/projects/:p/billboard/discussions', 'billboard'],
  ['GET /v1/orgs/:p/billboard/discussions/search', 'billboard'],
  ['GET /v1/orgs/:p/billboard/discussions/:p', 'billboard'],
  ['PATCH /v1/orgs/:p/billboard/discussions/:p', 'billboard'],
  ['DELETE /v1/orgs/:p/billboard/discussions/:p', 'billboard'],
  ['PUT /v1/orgs/:p/billboard/discussions/:p/read', 'billboard'],
  ['GET /v1/orgs/:p/billboard/discussions/:p/comments', 'billboard'],
  ['POST /v1/orgs/:p/billboard/discussions/:p/comments', 'billboard'],
  ['PATCH /v1/orgs/:p/billboard/discussions/:p/comments/:p', 'billboard'],
  ['DELETE /v1/orgs/:p/billboard/discussions/:p/comments/:p', 'billboard'],
  ['PUT /v1/orgs/:p/billboard/discussions/:p/reactions', 'billboard'],
  ['DELETE /v1/orgs/:p/billboard/discussions/:p/reactions', 'billboard'],
  ['PUT /v1/orgs/:p/billboard/discussions/:p/comments/:p/reactions', 'billboard'],
  ['DELETE /v1/orgs/:p/billboard/discussions/:p/comments/:p/reactions', 'billboard'],
  ['POST /v1/orgs/:p/billboard/discussions/:p/attachments', 'billboard'],
  ['POST /v1/orgs/:p/billboard/announcements', 'billboard'],
  ['POST /v1/projects/:p/billboard/announcements', 'billboard'],
  ['GET /v1/orgs/:p/billboard/announcements', 'billboard'],
  ['GET /v1/projects/:p/billboard/announcements', 'billboard'],
  ['GET /v1/orgs/:p/billboard/announcements/search', 'billboard'],
  ['GET /v1/orgs/:p/billboard/announcements/:p', 'billboard'],
  ['PATCH /v1/orgs/:p/billboard/announcements/:p', 'billboard'],
  ['DELETE /v1/orgs/:p/billboard/announcements/:p', 'billboard'],
  ['PUT /v1/orgs/:p/billboard/announcements/:p/read', 'billboard'],
  ['GET /v1/orgs/:p/billboard/announcements/:p/comments', 'billboard'],
  ['POST /v1/orgs/:p/billboard/announcements/:p/comments', 'billboard'],
  ['PATCH /v1/orgs/:p/billboard/announcements/:p/comments/:p', 'billboard'],
  ['DELETE /v1/orgs/:p/billboard/announcements/:p/comments/:p', 'billboard'],
  ['PUT /v1/orgs/:p/billboard/announcements/:p/reactions', 'billboard'],
  ['DELETE /v1/orgs/:p/billboard/announcements/:p/reactions', 'billboard'],
  ['PUT /v1/orgs/:p/billboard/announcements/:p/comments/:p/reactions', 'billboard'],
  ['DELETE /v1/orgs/:p/billboard/announcements/:p/comments/:p/reactions', 'billboard'],
  ['POST /v1/orgs/:p/billboard/announcements/:p/attachments', 'billboard'],
];

/**
 * Routes an API key must NEVER reach, stated deliberately rather than by omission.
 *
 * This list does not block anything on its own -- the allowlist above is already
 * fail-closed, so absence from it is refusal. That is exactly why this exists.
 * Before TASK-479 "deliberately human-only" and "nobody got around to it" were
 * the same bit: 515 of 618 routes were simply missing, and reading the code
 * could not tell you which of those two things any given absence meant. The
 * enforced test in `api-key-allowlist.test.ts` now requires every registered
 * route to appear in one of the three lists, so a new route ships with an
 * explicit decision attached or it does not ship.
 *
 * The bar for membership is narrow on purpose -- genuinely dangerous surface,
 * not "unsure". Seven things qualify:
 *   1. credential and session material (password, sessions, device registration);
 *   2. minting a credential -- `POST /orgs/:id/api-keys`, and also
 *      `POST /mcp/pair/requests/:id/approve`, which mints a key through a
 *      different door and would otherwise be the exact "a key must not mint
 *      another key" attack the allowlist header already warns about;
 *   3. payment and billing mutation;
 *   4. membership, roles, invitations, elevations and permission grants --
 *      who may do what;
 *   5. platform super-admin and infrastructure (`/v1/admin/*`, vault KEK rotation);
 *   6. storing a third-party credential (intelligence credential, OAuth installs);
 *   7. Marketing Tools (2026-08-29): an action with a real external side effect
 *      or real third-party spend -- a scheduled/posted social update, a sent
 *      email, a published blog post, or a Vertex/Veo/Apollo generation or
 *      enrichment call. Unlike category 4's "everyday work, permission-gated"
 *      carve-out, these reach OUTSIDE the org (a real human's inbox, a real
 *      social account, real metered spend against a shared per-org budget with
 *      no per-run ceiling) and cannot be undone by anyone's permission check
 *      once they fire. The product itself puts a mandatory human-approval gate
 *      in front of the social/mailer send paths for exactly this reason
 *      (`.../posts/:id/approve`, `.../campaigns/:id/approve`) -- an API key
 *      reaching those endpoints, or the `/send` endpoint directly, would
 *      structurally defeat the one design guarantee that gate exists to give.
 *
 * Deliberately NOT here: anything merely destructive but org-confined and
 * permission-gated. Deleting a release or a test plan is everyday work an agent
 * should be able to do, and the handler's own permission check is what decides
 * whether this particular caller may. Marketing Tools' own internal-only CRUD
 * (voice/asset/content-link management, no external reach) stays on that same
 * "everyday work" footing and is allowlisted above, not here.
 */
/**
 * PLAN S1b: the governance register's session-only routes (see GOVERNANCE_SESSION_ONLY_ROUTES below, which is built
 * from this list). Declared here, before SESSION_ONLY_ROUTES, so the general classification includes them without a
 * second copy that could drift.
 */
const GOVERNANCE_REGISTER_SESSION_ONLY: readonly string[] = [
  'POST /v1/projects/:p/governance/decisions/:p/decide',
  'POST /v1/projects/:p/governance/decisions/:p/confirm',
  'POST /v1/projects/:p/governance/decisions/:p/sign-off',
  'POST /v1/projects/:p/governance/decisions/:p/reject',
  'PUT /v1/projects/:p/governance/rights',
  'PUT /v1/projects/:p/governance/routing',
  'GET /v1/projects/:p/governance/decisions',
  'GET /v1/projects/:p/governance/decisions/:p',
  // PLAN S6a: work admission. A runner key (or any key) admitting work for itself is the exact abuse case 30 closes.
  'POST /v1/projects/:p/governance/admissions',
  // fix-3: closing an admission frees the issue's slot; a key must not do it any more than it may admit.
  'POST /v1/projects/:p/governance/admissions/:p/close',
];

export const SESSION_ONLY_ROUTES: readonly string[] = [
  // goodqa#6370 full issue merge: a destructive move of comments, attachments,
  // assignees and links, confirmed by a person in the issue page dialog. Kept
  // out of API-key reach until goodqa#6366 adopts the MCP tool and decides the
  // key family together with delegated-assignment approval.
  'GET /v1/orgs/:p/issues/:p/merge-preview',
  'POST /v1/orgs/:p/issues/:p/merge',
  'GET /v1/machine-approval/:p/:p',
  'POST /v1/machine-approval/:p/:p/answer',
  'POST /v1/preview-grants',
  'DELETE /v1/preview-grants/:p',
  'POST /v1/admin/preview-testers',
  'DELETE /v1/admin/preview-testers/:p/:p',
  // Reviewed attachment batches require a person session, including status and cancellation.
  'POST /v1/orgs/:p/import-batches',
  'GET /v1/orgs/:p/import-batches/:p',
  'POST /v1/orgs/:p/import-batches/:p/commit',
  'POST /v1/orgs/:p/import-batches/:p/cancel',
  'PUT /v1/orgs/:p/scheduling/event-types/:p/sms-reminders',
  // Connector account authority remains with a signed-in person.
  'POST /v1/orgs/:p/projects/:p/social-connectors/bindings',
  'PATCH /v1/orgs/:p/projects/:p/social-connectors/bindings/:p',
  'POST /v1/orgs/:p/projects/:p/social-connectors/bindings/:p/operations',
  'POST /v1/orgs/:p/projects/:p/social-connectors/bindings/:p/operations/:p/approve',
  'POST /v1/orgs/:p/projects/:p/social-connectors/bindings/:p/operations/:p/execute',
  'POST /v1/orgs/:p/projects/:p/marketing/social/weeks/:p/approve',
  'GET /v1/orgs/:p/outreach/reconciliation',
  'PATCH /v1/orgs/:p/outreach/reconciliation/settings',
  'POST /v1/orgs/:p/outreach/reconciliation/:p/:p',
  'POST /v1/projects/:p/marketing/mailer/campaigns/:p/reconcile',
  // Support policy, approval and customer audit are authenticated-person surfaces.
  'GET /v1/orgs/:p/support-access',
  'PATCH /v1/orgs/:p/support-access',
  'POST /v1/orgs/:p/support-access/requests/:p/approve',
  'POST /v1/orgs/:p/support-access/elevations/:p/revoke',
  'GET /v1/admin/orgs/:p/support-elevation-requests',
  'POST /v1/admin/orgs/:p/support-elevation-requests',
  'POST /v1/admin/orgs/:p/support-elevation-requests/:p/approve',
  'POST /v1/orgs/:p/business-reports/runs',
  // Monday report schedules: an owner/admin session configures, enables and retries delivery; members read their own.
  'GET /v1/orgs/:p/business-reports/schedules',
  'POST /v1/orgs/:p/business-reports/schedules',
  'PATCH /v1/orgs/:p/business-reports/schedules/:p',
  'POST /v1/orgs/:p/business-reports/schedules/:p/occurrences',
  'POST /v1/orgs/:p/business-reports/occurrences/:p/retry',
  // Client engagement management and private costs use current person authority.
  'GET /v1/me/content-clients',
  'POST /v1/orgs/:p/content-engagements',
  'GET /v1/orgs/:p/content-engagements/:p',
  'PATCH /v1/orgs/:p/content-engagements/:p',
  'GET /v1/orgs/:p/content-engagements/:p/client-plan',
  'GET /v1/orgs/:p/content-engagements/:p/blueprint',
  // Screen movement receipts can only be acknowledged by the viewing person.
  'POST /v1/chat/conversations/:p/ui-guidance/:p/receipts',
  'GET /v1/orgs/:p/readiness/outreach',
  // Registered-route census: human account setup, owner provider/spend controls,
  // platform administration and desktop/browser consent already reject keys.
  'POST /v1/admin/access-codes',
  'GET /v1/admin/access-codes',
  'GET /v1/release-authorizations/:p/decision',
  'GET /v1/admin/release-authorizations/:p',
  'PUT /v1/admin/release-authorizations/:p',
  'PATCH /v1/admin/access-codes/:p',
  'GET /v1/admin/ai/spend',
  'GET /v1/admin/ai/privacy',
  'GET /v1/admin/email-deliverability/events',
  'POST /v1/admin/orgs/:p/ai/spend/approve',
  'GET /v1/admin/orgs/:p/qac-runtime',
  'PUT /v1/admin/orgs/:p/qac-runtime',
  'POST /v1/admin/orgs/:p/qac-approve',
  'GET /v1/admin/qac/approvals',
  'POST /v1/admin/qac/runner-key',
  // goodqa#5118: minting/revoking the directive operator token is a verified, recently signed-in platform admin's act.
  'POST /v1/admin/qac/operator-tokens',
  'POST /v1/admin/qac/operator-tokens/:p/revoke',
  // goodqa#5118: directives. The admin mount is a verified platform admin's session; the operator mount is for the
  // scoped `qac.directive` user token only (USER_TOKEN_BEYOND_API_KEY_ROUTES); no org API key or persona key reaches
  // either. The workspace's own history is for its admins, signed in.
  'POST /v1/admin/qac/directives',
  'GET /v1/admin/qac/directives',
  'POST /v1/admin/qac/directives/:p/revoke',
  'POST /v1/qac-operator/directives',
  'GET /v1/qac-operator/directives',
  'POST /v1/qac-operator/directives/:p/revoke',
  'GET /v1/orgs/:p/qac/directives',
  'GET /v1/me/signup-onboarding',
  'POST /v1/orgs/:p/signup-onboarding',
  'GET /v1/me/remote-control/catalog',
  'GET /v1/machines/:p/remote-settings',
  'PUT /v1/machines/:p/remote-settings',
  'POST /v1/orgs/:p/billing/access-code',
  'GET /v1/orgs/:p/ai/spend',
  'GET /v1/orgs/:p/ai/provider',
  // Privacy preferences and attestations require the current human owner's session.
  'GET /v1/orgs/:p/ai/provider/privacy',
  'PATCH /v1/orgs/:p/ai/provider/privacy',
  'POST /v1/orgs/:p/ai/provider/privacy/renew',
  'PUT /v1/orgs/:p/ai/provider',
  'POST /v1/orgs/:p/ai/provider/complete',
  'POST /v1/orgs/:p/machines/remote-sessions/setup',
  'POST /v1/orgs/:p/machines/remote-sessions/:p/agent-browser/activity',
  'GET /v1/orgs/:p/machines/remote-sessions/:p/agent-browser/attachments/:p',
  'PUT /v1/orgs/:p/machines/remote-sessions/:p/agent-browser/consent',
  // goodqa#14920: a user-token delegation route; no org API key ever reaches it (the token path opens it).
  'POST /v1/user-token-delegations/platform-settings/:p/orgs',
  'POST /v1/orgs/:p/machines/remote-sessions/:p/agent-browser/next',
  'POST /v1/orgs/:p/machines/remote-sessions/:p/agent-browser/results/:p',
  'GET /v1/orgs/:p/machines/authority/policy',
  'POST /v1/legal/acceptance',

  // Personal AI preferences, billing consent and anonymous suggestions require a person.
  'GET /v1/orgs/:p/ollander/features',
  'GET /v1/orgs/:p/ollander/credits',
  'PUT /v1/orgs/:p/ollander/credits/threshold',
  'GET /v1/orgs/:p/ollander/memories',
  'POST /v1/orgs/:p/ollander/memories/:p/decision',
  'POST /v1/orgs/:p/ollander/examinations/quote',
  'POST /v1/orgs/:p/ollander/examinations/:p/run',
  'GET /v1/orgs/:p/ollander/examinations/:p',
  'POST /v1/projects/:p/ollander/suggestions',
  'POST /v1/orgs/:p/ollander/suggestions',
  'GET /v1/admin/ollander/suggestions',
  'GET /v1/admin/ollander/features',

  // Approval plans: draft management and named approvals belong to signed-in people.
  'GET /v1/orgs/:p/approval-plans',
  'GET /v1/orgs/:p/approval-plans/capability',
  'POST /v1/orgs/:p/approval-plans',
  'PUT /v1/orgs/:p/approval-plans/:p/configuration',
  'POST /v1/orgs/:p/approval-plans/:p/runs',
  'GET /v1/orgs/:p/approval-plans/runs/:p',
  'POST /v1/orgs/:p/approval-plans/runs/:p/draft',
  'POST /v1/orgs/:p/approval-plans/runs/:p/execute',
  'POST /v1/orgs/:p/approval-plans/runs/:p/decision',
  'GET /v1/orgs/:p/approval-plans/state/:p',
  'GET /v1/orgs/:p/approval-plans/state/:p/versions',
  // Routines: configuring, starting, answering and cancelling are a signed-in person's act
  // (routines/routes.ts person() refuses API keys); keys may only read.
  'POST /v1/orgs/:p/routines',
  'PUT /v1/orgs/:p/routines/:p/configuration',
  'POST /v1/orgs/:p/routines/:p/runs',
  'POST /v1/orgs/:p/routines/runs/:p/steps/:p/respond',
  'POST /v1/orgs/:p/routines/runs/:p/cancel',
  'POST /v1/orgs/:p/routines/trigger/:p',
  // Assistant presentation and the private master seam belong to a signed-in person.
  'GET /v1/orgs/:p/assistant',
  'GET /v1/orgs/:p/commander',
  'GET /v1/orgs/:p/ai-threads',
  'POST /v1/orgs/:p/ai-threads',
  'PATCH /v1/ai-threads/:p',
  // Sharing changes a private audience and is never delegated to a credential.
  'POST /v1/ai-threads/:p/members',
  'DELETE /v1/ai-threads/:p/members/:p',
  'GET /v1/ai-threads/:p/members',
  // S9: letting the Commander into a group chat, or removing it, decides who it reads; a signed-in person's act.
  'GET /v1/chat/conversations/:p/commander-admission',
  'PUT /v1/chat/conversations/:p/commander-admission',
  'DELETE /v1/chat/conversations/:p/commander-admission',
  'PATCH /v1/orgs/:p/assistant',
  'PATCH /v1/orgs/:p/assistant/me',
  'POST /v1/orgs/:p/assistant/master',
  'PUT /v1/orgs/:p/ahrefs',
  'DELETE /v1/orgs/:p/ahrefs',
  'PATCH /v1/orgs/:p/ahrefs/cap',
  'POST /v1/projects/:p/marketing/prospecting/research/review',
  'POST /v1/projects/:p/marketing/prospecting/research/import',
  'POST /v1/projects/:p/marketing/prospecting/research/exclusions',
  'POST /v1/projects/:p/outreach/leads/move',
  'POST /v1/orgs/:p/outreach/linkedin-browser/commands/:p/preflight',

  // Meeting access is always a signed-in personal session, including every session operation.
  'GET /v1/orgs/:p/live-assistant',
  'PATCH /v1/orgs/:p/live-assistant',
  'POST /v1/orgs/:p/live-assistant/transcribe',
  'POST /v1/orgs/:p/live-assistant/sessions',
  'GET /v1/orgs/:p/live-assistant/sessions/:p',
  'POST /v1/orgs/:p/live-assistant/sessions/:p/finish',
  'POST /v1/orgs/:p/live-assistant/sessions/:p/analyze',
  'POST /v1/orgs/:p/live-assistant/sessions/:p/approve-crm',
  'POST /v1/orgs/:p/live-assistant/sessions/:p/attendees',
  'POST /v1/orgs/:p/live-assistant/lookup',
  'POST /v1/orgs/:p/steve-desk/actions',
  'GET /v1/orgs/:p/outreach/projects/:p/replies',
  'PUT /v1/orgs/:p/outreach/projects/:p/reply-rules',
  'POST /v1/orgs/:p/outreach/projects/:p/materials',
  'PUT /v1/orgs/:p/outreach/projects/:p/deals/:p/order-terms',
  'POST /v1/orgs/:p/outreach/projects/:p/deals/:p/order-draft',
  'POST /v1/orgs/:p/outreach/projects/:p/replies/:p/approve',

  'PUT /v1/orgs/:p/outreach/linkedin-browser',
  'POST /v1/orgs/:p/outreach/linkedin-browser/connections',
  'POST /v1/orgs/:p/outreach/linkedin-browser/campaigns',
  'PATCH /v1/orgs/:p/outreach/linkedin-browser/campaigns/:p',
  'POST /v1/orgs/:p/outreach/linkedin-browser/tasks/:p/approve',
  'POST /v1/orgs/:p/outreach/linkedin-browser/tasks/batch',
  'POST /v1/orgs/:p/outreach/linkedin-browser/tasks/approve-batch',
'PUT /v1/orgs/:p/mail/identities/:p/bind',
  'POST /v1/internal/mail/ingest',
  'POST /v1/internal/mail/resend',
  'PUT /v1/orgs/:p/workers/policy',
  'POST /v1/orgs/:p/network-connections',
  'POST /v1/orgs/:p/network-connections/:p/revoke',
  'GET /v1/orgs/:p/ai/inference',
  'PUT /v1/orgs/:p/ai/inference/:p',
  'POST /v1/orgs/:p/ai/inference/resolve',
  'POST /v1/orgs/:p/ai/inference/test',
  'POST /v1/orgs/:p/ai/inference/chat',
  'GET /v1/orgs/:p/ai/inference/usage',
  // Outreach approvals and owner responsibility are person-session decisions.
  'GET /v1/me/outreach',
  'GET /v1/projects/:p/outreach/desk',
  'PUT /v1/projects/:p/outreach/campaigns',
  'GET /v1/projects/:p/outreach/playbook',
  'PUT /v1/projects/:p/outreach/playbook',
  'GET /v1/projects/:p/outreach/close-outs',
  'POST /v1/projects/:p/outreach/close-outs/refresh',
  // Web-form close-outs: a project PM records the form and its submission; nothing is sent.
  'POST /v1/projects/:p/outreach/close-outs/manual',
  'POST /v1/projects/:p/outreach/close-outs/manual/:p/submitted',
  'GET /v1/projects/:p/outreach/daily-batches/today',
  'POST /v1/projects/:p/outreach/daily-batches/today',
  'GET /v1/projects/:p/outreach/daily-drafts',
  'POST /v1/projects/:p/outreach/daily-drafts',
  'PATCH /v1/projects/:p/outreach/daily-drafts/:d',
  'POST /v1/projects/:p/outreach/daily-drafts/:d/copied',
  'POST /v1/projects/:p/outreach/leads/approve',
  'POST /v1/projects/:p/outreach/messages/preview',
  'POST /v1/projects/:p/outreach/messages/approve',
  // Withdrawing an owner approval is the same person decision as giving it (the handler also refuses agent credentials).
  'POST /v1/projects/:p/outreach/approvals/:p/revoke',
  'POST /v1/projects/:p/outreach/messages/schedule',
  'POST /v1/orgs/:p/outreach/connections/responsibility',
  'PATCH /v1/chat/conversations/:p/issue-proposals/:p',
  'POST /v1/chat/conversations/:p/issue-proposals/:p/approve',
  'POST /v1/chat/conversations/:p/issue-proposals/:p/reject',
  // Coordinator setup, imports and authority changes are signed-in administrator actions.
  'POST /v1/work-coordinators',
  'POST /v1/work-coordinators/:p/import',
  'POST /v1/work-coordinators/:p/grants',
  'POST /v1/work-coordinators/:p/grants/:p/revoke',
  // Image spend caps are owner-controlled human settings, not a bot billing escalation.
  'PUT /v1/orgs/:p/studio/images/settings',
  // Preferences, private suggestions, and platform curation are human-only on every transport.
  'GET /v1/roadmap/suggestions/mine',
  'POST /v1/roadmap/suggestions',
  'PUT /v1/roadmap/:p/vote',
  'DELETE /v1/roadmap/:p/vote',
  'GET /v1/admin/roadmap',
  'POST /v1/admin/roadmap/items',
  'PATCH /v1/admin/roadmap/items/:p',
  'POST /v1/admin/roadmap/items/:p/ship',
  'POST /v1/admin/roadmap/suggestions/:p/moderate',
  // Managed browser authority belongs to a signed-in org admin, never a token/key.
  'PUT /v1/orgs/:p/agent-browsers/settings',
  'GET /v1/orgs/:p/agent-browsers/grants',
  'POST /v1/orgs/:p/agent-browsers/grants',
  'POST /v1/orgs/:p/agent-browsers/grants/:p/revoke',
  // Remote consent and its read/revoke routes are all person-only, including user tokens.
  'POST /v1/orgs/:p/machines/remote-sessions',
  'POST /v1/orgs/:p/machines/authority/asks/:p/answer',
  'POST /v1/orgs/:p/machines/authority/grants/:p/revoke',
  'PUT /v1/orgs/:p/machines/authority/policy',
  'GET /v1/orgs/:p/machines/remote-sessions',
  'GET /v1/orgs/:p/machines/remote-sessions/availability',
  'GET /v1/orgs/:p/machines/remote-sessions/:p',
  'PATCH /v1/orgs/:p/machines/remote-sessions/:p',
  'POST /v1/orgs/:p/machines/remote-sessions/:p/stop',
  'POST /v1/orgs/:p/machines/remote-sessions/:p/renew',
  // Consent-owned browser pairing belongs to the person session, never an agent credential.
  'GET /v1/orgs/:p/machines/remote-sessions/:p/browser-pairing',
  'POST /v1/orgs/:p/machines/remote-sessions/:p/browser-pairing/challenge',
  'POST /v1/orgs/:p/machines/remote-sessions/:p/browser-pairing/connected',
  'POST /v1/orgs/:p/machines/remote-sessions/:p/browser-pairing/permit',

  // Current-main writes already reject agent credentials in their handlers; classify every sibling explicitly.
  'PUT /v1/orgs/:p/my-work/settings',
  'PUT /v1/orgs/:p/machines/browser-control',
  'POST /v1/orgs/:p/chat/line-templates',
  'PUT /v1/orgs/:p/chat/line-templates/:p',
  'DELETE /v1/orgs/:p/chat/line-templates/:p',
  // Public-page tracking settings, report and contact attribution: people only in the rough ship (an API-key
  // family is a fast-follow, docs/design/PUBLIC-TRACKING.md).
  'GET /v1/orgs/:p/tracking/settings',
  'PUT /v1/orgs/:p/tracking/settings',
  'GET /v1/orgs/:p/tracking/report',
  'GET /v1/orgs/:p/tracking/contacts/:p/attribution',
  // Member setup is a human settings surface: policy acknowledgement and member-admin setup use signed-in sessions.
  'GET /v1/orgs/:p/member-onboarding/catalog',
  'GET /v1/orgs/:p/member-onboarding/mine',
  'GET /v1/orgs/:p/member-onboarding/members',
  'POST /v1/orgs/:p/member-onboarding/templates',
  'POST /v1/orgs/:p/member-onboarding/assignments',
  'PATCH /v1/orgs/:p/member-onboarding/assignments/:p',
  'POST /v1/orgs/:p/member-onboarding/assignments/:p/acknowledge-policy',
  'POST /v1/orgs/:p/member-onboarding/assignments/:p/credential',
  'POST /v1/orgs/:p/blueprints/approve',
  // goodqa#7791: deleting a saved blueprint has no undo, so no API key may do it.
  'DELETE /v1/orgs/:p/blueprints/:p',
  'POST /v1/orgs/:p/org-builder/approve',
  'POST /v1/orgs/:p/org-builder/cancel',
  'GET /v1/me/user-token-session-actions',
  'GET /v1/orgs/:p/user-token-session-actions',
  'PUT /v1/orgs/:p/user-token-session-actions',
  // Agent work queue (docs/features/agent-queue.md): the ORDER is a person's decision. Reorder / pin / pause and the
  // who-moved-what audit are for signed-in owners and admins; a key (even one an owner minted) reads and enqueues only.
  'PATCH /v1/orgs/:p/agent-queue',
  'GET /v1/orgs/:p/agent-queue/audit',
  // Agent chat, the PEOPLE surface (Settings > Agent channels, the chat widget's agent section): signed-in people only.
  // Agents use /v1/persona/agent-chat/* above; no key reads another org member's view of agent chatter or changes the
  // org's agent-chat settings, and the human override (commands, pause, resume) is a person's act by definition.
  'GET /v1/orgs/:p/agent-chat/overview',
  'GET /v1/orgs/:p/agent-chat/conversations',
  'GET /v1/orgs/:p/agent-chat/conversations/:p',
  'GET /v1/orgs/:p/agent-chat/conversations/:p/messages',
  'POST /v1/orgs/:p/agent-chat/conversations/:p/messages',
  'POST /v1/orgs/:p/agent-chat/conversations/:p/pause',
  'POST /v1/orgs/:p/agent-chat/conversations/:p/resume',
  'POST /v1/orgs/:p/agent-chat/conversations/:p/subscribe',
  'POST /v1/orgs/:p/agent-chat/conversations/:p/unsubscribe',
  'GET /v1/orgs/:p/agent-chat/roster',
  'GET /v1/orgs/:p/agent-chat/dashboard',
  'GET /v1/orgs/:p/agent-chat/audit',
  'GET /v1/orgs/:p/agent-chat/usage',
  'GET /v1/orgs/:p/agent-chat/export',
  'GET /v1/orgs/:p/agent-chat/followups',
  'GET /v1/orgs/:p/agent-chat/settings',
  'PATCH /v1/orgs/:p/agent-chat/settings',
  'GET /v1/orgs/:p/agent-chat/preferences',
  'PUT /v1/orgs/:p/agent-chat/preferences',
  // GoodQA Connect (#433, dark: connect.sessions): opening a session (a live view or tunnel into a machine) LOOSENS, so
  // only a person does it; the rest are that person's (or an org admin's) own session management. The Machines lane adds
  // key access through its grants via its peer kind, not here.
  'POST /v1/orgs/:p/connect/sessions',
  'GET /v1/orgs/:p/connect/sessions',
  'GET /v1/orgs/:p/connect/sessions/:p',
  'POST /v1/orgs/:p/connect/sessions/:p/tokens',
  'POST /v1/orgs/:p/connect/sessions/:p/ice-servers',
  'POST /v1/orgs/:p/connect/sessions/:p/close',
  // USER TOKENS (docs/design/USER-TOKENS.md): managing user tokens is the owner's act, signed in or through one of
  // their own user tokens within its abilities (modules/user-tokens/auth-gate.ts). NO org API key of any kind -- plain,
  // persona or runner -- may list, mint, rotate, change or revoke one, nor touch the approval queue; each handler refuses
  // an `apiKeyId` a second time. The admin pair is a verified platform admin's.
  'GET /v1/me/user-tokens',
  'POST /v1/me/user-tokens',
  'GET /v1/me/user-tokens/:p',
  'PATCH /v1/me/user-tokens/:p',
  'DELETE /v1/me/user-tokens/:p',
  'POST /v1/me/user-tokens/:p/rotate',
  'POST /v1/me/user-tokens/revoke-all',
  'GET /v1/me/user-tokens/:p/events',
  'GET /v1/me/user-tokens/:p/audit',
  // goodqa#15158: a user token (never an org API key) starts a desktop session for its owner.
  'POST /v1/me/desktop-session',
  'GET /v1/me/user-token-approvals',
  'GET /v1/me/user-token-approvals/:p',
  'POST /v1/me/user-token-approvals/:p/approve',
  'POST /v1/me/user-token-approvals/:p/deny',
  'GET /v1/admin/user-tokens',
  // Operational cron metadata belongs to a verified platform administrator's session.
  'GET /v1/admin/cron/last-runs',
  'POST /v1/admin/user-tokens/:p/revoke',
  // Review round 2, finding 3: an org admin, signed in, oversees the member tokens that reach the org.
  'GET /v1/orgs/:p/user-tokens',
  'POST /v1/orgs/:p/user-tokens/:p/revoke',
  // goodqa CLI vault-in-the-env (dark: vaultEnv.enabled): which machine identities may read which secrets into an
  // environment is a signed-in vault manager's decision; no key or token writes it.
  'PUT /v1/orgs/:p/vault-env/config',
  // Customer payments (payments.enabled; modules/customer-payments): billing a business's customers, refunding and
  // paying out are a signed-in PERSON's acts. No key, bot or user token reaches any of them, reads included (they
  // carry customers' money records).
  'GET /v1/orgs/:p/payments/status',
  'GET /v1/orgs/:p/payments/invoice-followups',
  'POST /v1/orgs/:p/payments/invoice-followups',
  'PUT /v1/orgs/:p/payments/settings',
  'GET /v1/orgs/:p/payments/invoices',
  'GET /v1/orgs/:p/payments/statements/:p',
  'GET /v1/orgs/:p/payments/statements/:p/export',
  'POST /v1/orgs/:p/payments/invoices',
  'GET /v1/orgs/:p/payments/invoices/:p',
  'POST /v1/orgs/:p/payments/invoices/:p/void',
  'POST /v1/orgs/:p/payments/invoices/:p/sync',
  'POST /v1/orgs/:p/payments/invoices/:p/record-payment',
  'POST /v1/orgs/:p/payments/invoices/:p/receipt',
  'POST /v1/orgs/:p/payments/invoices/:p/refunds',
  'GET /v1/orgs/:p/payments/summary',
  'GET /v1/orgs/:p/payments/report',
  'GET /v1/orgs/:p/payments/forecast',
  'GET /v1/orgs/:p/payments/plans',
  'POST /v1/orgs/:p/payments/plans',
  'POST /v1/orgs/:p/payments/plans/:p/archive',
  'GET /v1/orgs/:p/payments/subscriptions',
  'POST /v1/orgs/:p/payments/subscriptions',
  'POST /v1/orgs/:p/payments/subscriptions/:p/change-plan',
  'POST /v1/orgs/:p/payments/subscriptions/:p/cancel',
  'POST /v1/orgs/:p/payments/connect/onboarding',
  'POST /v1/orgs/:p/payments/connect/refresh',
  'GET /v1/orgs/:p/payments/payouts',
  'GET /v1/orgs/:p/payments/payouts/available',
  'POST /v1/orgs/:p/payments/payouts',
  'POST /v1/orgs/:p/payments/reconcile',
  'GET /v1/orgs/:p/payments/events',
  // Telephony step 2, calls (dark: TELEPHONY_PROVIDER + telephony.enabled + telephony.voice, 404 before auth while
  // off). Placing a real phone call, routing a number and reading call logs are a PERSON's acts: no key, no bot.
  'GET /v1/orgs/:p/phone/browser',
  'HEAD /v1/orgs/:p/phone/browser',
  'POST /v1/orgs/:p/phone/browser/calls',
  'GET /v1/orgs/:p/phone/browser/calls/:p',
  'HEAD /v1/orgs/:p/phone/browser/calls/:p',
  'POST /v1/orgs/:p/phone/browser/calls/:p/answer',
  'POST /v1/orgs/:p/phone/browser/calls/:p/audio',
  'POST /v1/orgs/:p/phone/browser/calls/:p/finish',
  'POST /v1/orgs/:p/phone/browser/calls/:p/analyze',
  'POST /v1/orgs/:p/phone/browser/calls/:p/approve-crm',
  'GET /v1/orgs/:p/phone/browser/calls/:p/recording',
  'HEAD /v1/orgs/:p/phone/browser/calls/:p/recording',
  'GET /v1/orgs/:p/phone/settings',
  'HEAD /v1/orgs/:p/phone/settings',
  'PUT /v1/orgs/:p/phone/settings',
  'PUT /v1/orgs/:p/phone/agents/:p',
  'POST /v1/orgs/:p/crm/contacts/:p/call',
  'GET /v1/orgs/:p/phone/calls',
  'HEAD /v1/orgs/:p/phone/calls',
  'GET /v1/orgs/:p/phone/calls/:p',
  'HEAD /v1/orgs/:p/phone/calls/:p',
  'GET /v1/orgs/:p/phone/calls/:p/recording',
  'HEAD /v1/orgs/:p/phone/calls/:p/recording',
  // Telephony step 3, texts (dark: TELEPHONY_PROVIDER + telephony.enabled + telephony.sms, 404 before auth while off).
  // Texting a contact, routing a number and reading text threads are a PERSON's acts: no key, no bot. Missed-call
  // text-back is the org's own setting, run by the provider's signed call webhooks, not by a key.
  'GET /v1/orgs/:p/sms/settings',
  'HEAD /v1/orgs/:p/sms/settings',
  'PUT /v1/orgs/:p/sms/settings',
  'GET /v1/orgs/:p/sms/messages',
  'HEAD /v1/orgs/:p/sms/messages',
  'GET /v1/orgs/:p/crm/contacts/:p/sms',
  'HEAD /v1/orgs/:p/crm/contacts/:p/sms',
  'POST /v1/orgs/:p/crm/contacts/:p/sms',
  // GoodQA #442 emergency escalation (dark: escalation.enabled). Who gets woken, how, and whether an emergency is
  // acknowledged, confirmed or resolved is a signed-in person's act; a key (a bot) never reaches these.
  'POST /v1/escalations/:p/resolve',
  'POST /v1/escalations/:p/confirm',
  'GET /v1/orgs/:p/escalation/settings',
  'HEAD /v1/orgs/:p/escalation/settings',
  'PUT /v1/orgs/:p/escalation/settings',
  'GET /v1/orgs/:p/escalation/policies',
  'HEAD /v1/orgs/:p/escalation/policies',
  'POST /v1/orgs/:p/escalation/policies',
  'PUT /v1/orgs/:p/escalation/policies/:p',
  'DELETE /v1/orgs/:p/escalation/policies/:p',
  'GET /v1/orgs/:p/escalation/on-call',
  'HEAD /v1/orgs/:p/escalation/on-call',
  'POST /v1/orgs/:p/escalation/on-call',
  'PUT /v1/orgs/:p/escalation/on-call/:p',
  'DELETE /v1/orgs/:p/escalation/on-call/:p',
  'POST /v1/orgs/:p/escalation/on-call/:p/overrides',
  'DELETE /v1/orgs/:p/escalation/on-call/:p/overrides/:p',
  'GET /v1/orgs/:p/escalation/contacts',
  'HEAD /v1/orgs/:p/escalation/contacts',
  'PUT /v1/orgs/:p/escalation/contacts/:p',
  'DELETE /v1/orgs/:p/escalation/contacts/:p',
  'POST /v1/orgs/:p/escalation/contacts/:p/verify',
  'POST /v1/orgs/:p/escalations/test',
  // Browser handoff (dark: browserHandoff.enabled): only a signed-in human redeems a link, takes control, hands back,
  // presses Done or Skip, or lists an org's open handoffs (the lopsided rule, docs/design/remote-desktop C10).
  'POST /v1/browser-handoffs/redeem',
  'POST /v1/orgs/:p/browser-handoffs/:p/actions',
  'GET /v1/orgs/:p/browser-handoffs',
  // Persona-memory API gap 4: erasing every persona's knowledge is a signed-in org admin's act, never a key's.
  'POST /v1/orgs/:p/agent-knowledge/persona-erase',
  // Memory management changes authoritative rules; bot proposals stay on the explicit allowlist.
  'PATCH /v1/orgs/:p/memory/:p',
  'PATCH /v1/projects/:p/memory/:p',
  'PATCH /v1/orgs/:p/context-memory/:p',
  'POST /v1/orgs/:p/context-memory/:p/review',
  'POST /v1/orgs/:p/context-memory/capture',
  // Attachment sharing (dark: attachments.sharing): the bytes of a grant inside the app (forwarded files are chat
  // content, which keys never read) and the public-link policy (only a signed-in admin, or the person, changes it).
  'GET /v1/attachment-shares/:p/content',
  'GET /v1/orgs/:p/attachment-share-policy',
  'PUT /v1/orgs/:p/attachment-share-policy',
  'GET /v1/me/attachment-share-policy',
  'PUT /v1/me/attachment-share-policy',
  // #381 coordinator: seeding the Coordinator project template is an org admin's or owner's act (Eric 2026-10-03).
  'POST /v1/orgs/:p/coordinator/setup',
  // #381: mirroring git rules can loosen a rule (only humans loosen); launching the coordinator template is an org
  // admin's or owner's act (Eric 2026-10-03).
  'POST /v1/orgs/:p/coordinator/rules-mirror',
  'GET /v1/orgs/:p/coordinator/template',
  // --- P51 outreach slice A: the loosening half (owner default 4, Eric's P51 rule "only humans loosen"). Lifting a
  // suppression, listing the list (a hash-free inventory is still the org's do-not-mail roster), PATCHing the
  // config (enable, dryRun off, caps, hours, sink, approvers) and the G17 privacy erasure of a contact. A verified
  // platform operator's own session may also do these (operator override, audited); no key of any kind can.
  'GET /v1/orgs/:p/outreach/suppressions',
  'DELETE /v1/orgs/:p/outreach/suppressions/:p',
  'POST /v1/orgs/:p/outreach/pipeline/defaults',
  'PATCH /v1/orgs/:p/outreach/config',
  // GoodQA goodqa#15434: the legal sender name and address. No key; a person, or their user token with
  // outreach.sender_identity (lib/user-token-policy.ts USER_TOKEN_SENDER_IDENTITY_ROUTES).
  'GET /v1/orgs/:p/outreach/sender-identity',
  'PUT /v1/orgs/:p/outreach/sender-identity',
  // Combined inbox (docs/design/INBOX-ADAPTER.md): a person's screen in v1. Replying sends from a person's own
  // mailbox or number, and unread/assignment are per person; no key, token or agent reaches it.
  'GET /v1/orgs/:p/inbox/threads',
  'GET /v1/orgs/:p/inbox/summary',
  'GET /v1/orgs/:p/inbox/threads/:p',
  'GET /v1/orgs/:p/inbox/contacts/:p/thread',
  'POST /v1/orgs/:p/inbox/threads/:p/read',
  'PATCH /v1/orgs/:p/inbox/threads/:p',
  'POST /v1/orgs/:p/inbox/threads/:p/messages',
  // Messenger + Instagram connections (docs/design/SOCIAL-INBOX-META.md): connecting a Page hands the org a Meta
  // token, so a person with org:manage_integrations only (modules/social-inbox/routes.ts also refuses agent kinds).
  'GET /v1/orgs/:p/social/zernio',
  'POST /v1/orgs/:p/social/zernio/connect',
  'POST /v1/orgs/:p/social/zernio/sync',
  'PATCH /v1/orgs/:p/social/zernio/accounts/:p',
  'GET /v1/orgs/:p/social/meta',
  'POST /v1/orgs/:p/social/meta/oauth/start',
  'GET /v1/orgs/:p/social/meta/oauth/:p/pages',
  'POST /v1/orgs/:p/social/meta/connections',
  'PATCH /v1/orgs/:p/social/meta/connections/:p',
  'DELETE /v1/orgs/:p/social/meta/connections/:p',
  'DELETE /v1/orgs/:p/crm/contacts/:p',
  // --- P51 G17: legal holds. Human-only on both sides (setting one blocks an erasure; releasing one allows it).
  'GET /v1/orgs/:p/outreach/legal-holds',
  'POST /v1/orgs/:p/outreach/legal-holds',
  'DELETE /v1/orgs/:p/outreach/legal-holds/:p',
  // GoodQA #358 v2: registering a LinkedIn account creates a sending budget (loosening): an org admin's own recent
  // session (or the operator's), never a key.
  'POST /v1/orgs/:p/outreach/linkedin/accounts',
  // --- P51 outreach slice D: template authoring, approval and retirement (G14), and the send ledger (G3).
  'GET /v1/orgs/:p/outreach/template-library',
  'PUT /v1/orgs/:p/outreach/template-library',
  'POST /v1/orgs/:p/outreach/template-preview',
  'POST /v1/orgs/:p/outreach/templates',
  'POST /v1/orgs/:p/outreach/templates/:p/versions',
  'PATCH /v1/orgs/:p/outreach/templates/:p/versions/:p',
  'DELETE /v1/orgs/:p/outreach/templates/:p/versions/:p',
  'POST /v1/orgs/:p/outreach/templates/:p/versions/:p/approve',
  'POST /v1/orgs/:p/outreach/templates/:p/versions/:p/retire',
  'GET /v1/orgs/:p/outreach/ledger',
  // --- P51 outreach slice G7: subscribing an endpoint to outreach events (only humans widen what leaves the org).
  'POST /v1/orgs/:p/outreach/webhook-subscriptions',
  // --- P51 outreach slice G9: authoring a sequence and resuming an enrolment loosen (more sending); people only.
  'POST /v1/orgs/:p/outreach/sequences',
  // cp-outreach-sequences-bot: turning a sequence's pipeline on or off is the owner's act; a Commander TURN grant (never a
  // key) may reach start/pause (lib/commander-turn-routes.ts), and the handler still demands the owner role.
  'POST /v1/orgs/:p/outreach/sequences/:p/start',
  'POST /v1/orgs/:p/outreach/sequences/:p/pause',
  'POST /v1/orgs/:p/outreach/enrolments/:p/resume',
  'POST /v1/orgs/:p/outreach/enrolments/:p/steps/:p/approve',
  // --- P51 outreach slice G16: moving a ledger lead to `qualified` loosens (it can open sending); people only.
  'POST /v1/orgs/:p/outreach/leads/:p/qualify',
  // --- P51 Gmail connector: connecting a mailbox hands GoodQA a sending credential; only a person does that.
  'GET /v1/orgs/:p/outreach/gmail/authorize',
  'GET /v1/orgs/:p/outreach/gmail/connection',
  'DELETE /v1/orgs/:p/outreach/gmail/connection',
  // Batch3 fix: resuming a PAUSED mailbox loosens, so only a person does it (like Zoho's).
  'POST /v1/orgs/:p/outreach/gmail/connection/resume',
  // Warm-up routing and resume choose or re-open a person's own sending domain. A key must not do either.
  'POST /v1/orgs/:p/outreach/route',
  'POST /v1/orgs/:p/outreach/domains/:p/resume',
  'POST /v1/orgs/:p/outreach/domains/:p/dnsbl-check',
  'POST /v1/orgs/:p/outreach/gmail/connection/check',
  'DELETE /v1/orgs/:p/outreach/gmail/connections/:p',
  'PUT /v1/orgs/:p/outreach/gmail/connections/:p/calendar-default',
  'PUT /v1/orgs/:p/outreach/gmail/agent-scopes/:p',

  // --- P51 Microsoft 365 connector: connecting, reading and disconnecting a mailbox are a person's own acts.
  'POST /v1/orgs/:p/outreach/outlook/connect',
  'GET /v1/outreach/outlook/callback',
  'GET /v1/orgs/:p/outreach/outlook/mailbox',
  'DELETE /v1/orgs/:p/outreach/outlook/mailbox',
  'POST /v1/orgs/:p/outreach/outlook/mailbox/resume',
  // --- P51 outreach, Zoho Mail connector: a person connects (OAuth start and the browser callback), pastes the
  // app-specific password, disconnects, and resumes a paused mailbox (only humans loosen). No key, ever.
  // Calendar consent and host binding are human actions, separate from mailbox OAuth.
  'GET /v1/orgs/:p/scheduling/zoho',
  'POST /v1/orgs/:p/scheduling/zoho/authorize',
  'GET /v1/scheduling/zoho/callback',
  'GET /v1/orgs/:p/scheduling/zoho/calendars',
  'PUT /v1/orgs/:p/scheduling/zoho',
  'DELETE /v1/orgs/:p/scheduling/zoho',
  'POST /v1/orgs/:p/scheduling/zoho/bookings/:p/sync',
  'POST /v1/orgs/:p/outreach/zoho/authorize',
  'GET /v1/outreach/zoho/callback',
  'POST /v1/orgs/:p/outreach/mailgun/connection',
  'DELETE /v1/orgs/:p/outreach/mailgun/connections/:p',
  'POST /v1/orgs/:p/outreach/smtp/connection',
  'DELETE /v1/orgs/:p/outreach/smtp/connections/:p',
  'PUT /v1/orgs/:p/outreach/zoho/connection/app-password',
  'DELETE /v1/orgs/:p/outreach/zoho/connection',
  'POST /v1/orgs/:p/outreach/zoho/connection/resume',
  // --- P51 Email Connections wizard (dark: outreach.enabled + outreach.wizard): the cross-connector read model, setup
  // checks, the test step, risk acknowledgements, practice/live and the DNS helper. A person's acts only; no key.
  'GET /v1/orgs/:p/outreach/connections',
  'GET /v1/orgs/:p/outreach/connections/setup-checks',
  'POST /v1/orgs/:p/outreach/connections/:p/test',
  'POST /v1/orgs/:p/outreach/connections/:p/deliverability',
  'GET /v1/orgs/:p/outreach/connections/:p/deliverability/:p',
  'POST /v1/orgs/:p/outreach/connections/:p/acknowledge',
  'POST /v1/orgs/:p/outreach/connections/:p/mode',
  'POST /v1/orgs/:p/outreach/dns-check',
  // --- Plan S2a: the runner sponsor's surface. A key can never make an enrol token (that would let a runner key
  // mint another key through enrolment), confirm a runner, or list them. ---
  'POST /v1/projects/:p/runners/enrol-tokens',
  'POST /v1/projects/:p/runners/:p/confirm',
  'GET /v1/projects/:p/runners',
  // --- Plan S3: a registration code becomes a machine credential, and a launch starts a process on a customer's
  // server. Both LOOSEN (lopsided rule): a person in a signed-in session only, never any key. ---
  'POST /v1/orgs/:p/agent-daemons/registration-codes',
  'POST /v1/projects/:p/agent-launches',
  // Ticket #361: provisioning a managed host spends money: an org owner in a signed-in session only, never any key.
  'POST /v1/orgs/:p/agent-hosts',
  // --- GoodQA #430, Machines: everything that LOOSENS access to a person's computer is that person's own act in a
  // signed-in session: making a pairing code, changing the machine's settings, granting, approving or denying a risky
  // command, confirming a hand-off, resuming, scheduling or running a job. Never any key. ---
  'POST /v1/orgs/:p/machines/pairing-codes',
  'PATCH /v1/machines/:p',
  'POST /v1/machines/:p/resume',
  'POST /v1/machines/:p/grants',
  // goodqa#8414: the owner asks for a presence challenge from a signed-in session (refuseKeys in the handler).
  'POST /v1/machines/:p/presence-challenge',
  // goodqa#14992: lending this computer's desktop browser to an already approved agent, and reconciling or cancelling
  // that exact Allow, is the signed-in owner's own act at the desktop (localOwner also refuses keys and tokens).
  'GET /v1/machines/:p/agent-browser/context',
  'POST /v1/machines/:p/agent-browser/consent',
  'GET /v1/machines/:p/agent-browser/consent/requests/:p',
  'POST /v1/machines/:p/agent-browser/consent/cancel',
  'POST /v1/machine-commands/:p/approve',
  'POST /v1/machine-commands/:p/deny',
  'POST /v1/machine-commands/:p/human-done',
  'POST /v1/machines/:p/jobs',
  'POST /v1/machine-jobs/:p/run',
  // Elevated machine grants for USER TOKENS (Eric 2026-10-05; dark: machines.tokenGrants). An org admin grants a token
  // access to its owner's machines with a fresh step-up; listing and revoking are a person's too. No key and no token
  // (a token never widens itself): the user-token gate refuses these as `signed_in_person`.
  'GET /v1/orgs/:p/machine-token-grants',
  'POST /v1/orgs/:p/machine-token-grants',
  'POST /v1/orgs/:p/machine-token-grants/:p/revoke',
  // Machines enrollment (docs/design/machines-fullcontrol/ENROLLMENT.md; dark: machines.enabled): machine tokens and
  // desktop enrollments are a person's (or their user token's, USER_TOKEN_BEYOND_API_KEY_ROUTES); never an org API key.
  'POST /v1/me/machine-tokens',
  'GET /v1/me/machine-tokens',
  'POST /v1/me/machine-tokens/:p/revoke',
  'POST /v1/me/machine-enrollments',
  'GET /v1/me/machine-enrollments',
  'GET /v1/me/machine-enrollments/:p',
  'POST /v1/me/machine-enrollments/:p/cancel',
  'GET /v1/me/machines',
  // --- The org agent policy (docs/design/AGENT-DELEGATES.md sections 13 and 16) ---
  //
  // `apiKeysMayAssignPeople` and the org master pause are the admin's hard ceiling over EVERY
  // key in the org. A credential that could read or move the ceiling that governs it would not
  // have one, so both the read and the write are a HUMAN SESSION action (edit needs
  // `org:manage_settings` AND the admin role; the read also admits `org:manage_api_keys`).
  'GET /v1/orgs/:p/agent-policy',
  'PATCH /v1/orgs/:p/agent-policy',
  'GET /v1/orgs/:p/agent-policy/commander-ceiling',
  'PUT /v1/orgs/:p/agent-policy/commander-ceiling',
  'GET /v1/orgs/:p/outbound-send-policy',
  'PATCH /v1/orgs/:p/outbound-send-policy',
  // Custom data D4 (DESIGN 5.1, 5.6): data roles, bindings, grants, the reconciler and project assignment
  // change WHO reaches WHAT in the org's databases; a key (a bot) never edits its own reach. Dark like
  // the rest of /data/ (unregistered-route 404 before auth unless configured and entitled).
  'POST /v1/orgs/:p/data/roles',
  'PUT /v1/orgs/:p/data/bindings',
  'DELETE /v1/orgs/:p/data/bindings',
  'POST /v1/orgs/:p/data/grants',
  'DELETE /v1/orgs/:p/data/grants',
  'POST /v1/orgs/:p/data/reconcile',
  'PUT /v1/orgs/:p/data/databases/:p/projects/:p',
  // PROVISION (2026-10-03): creating the org's data database on the cluster, and the admin status view (tier roles,
  // last failure, drift). A person provisions; a key asking a data route of an unprovisioned org gets 409
  // CD-NOT-PROVISIONED-ASK-ADMIN (modules/custom-data/provisioning.ts). Same darkness as the rest of /data/.
  'POST /v1/orgs/:p/data/databases', // data:create/admin bootstrap; project assignment remains separate and session only
  'POST /v1/orgs/:p/data/provision',
  'GET /v1/orgs/:p/data/status',
  // --- Outbound webhooks (chat / ticket comments) ---
  //
  // Registering a receiver points a stream of message text at a URL of the
  // caller's choosing. That is an exfiltration channel if a leaked machine
  // credential can open it, so every route on this family -- including the
  // reads that reveal URLs and delivery state -- is a HUMAN SESSION action
  // (`org:manage_integrations`), same tier as connecting GitHub or Slack.
  // Org API keys stay refused on every one of these. Lane usertoken-webhooks (Eric 2026-10-14) opens list/create/get/
  // update/delete/rotate-secret/test to a USER TOKEN holding settings.security whose owner is an org admin (never a
  // commander turn): lib/user-token-policy.ts USER_TOKEN_WEBHOOK_ADMIN_ROUTES. They must stay listed here.
  'POST /v1/orgs/:p/webhooks',
  'GET /v1/orgs/:p/webhooks',
  'GET /v1/orgs/:p/webhooks/:p',
  'PATCH /v1/orgs/:p/webhooks/:p',
  'DELETE /v1/orgs/:p/webhooks/:p',
  'POST /v1/orgs/:p/webhooks/:p/test',
  'POST /v1/orgs/:p/webhooks/:p/rotate-secret',
  'GET /v1/orgs/:p/webhooks/:p/deliveries',
  'POST /v1/orgs/:p/webhooks/:p/deliveries/:p/redeliver',
  'POST /v1/orgs/:p/webhooks/:p/requeue-failed',
  // TASK-537 -- channel rename/archive/unarchive. Gated to creator/org-admin/
  // project-pm (`mayManageChannel`, modules/messaging/access.ts), which is a
  // USER-identity check (a specific human is "the creator") an API key has
  // no meaningful way to satisfy, and this is a management/moderation-tier
  // action -- same tier as every `/v1/admin/*` console action, all of which
  // are session-only in this file, not "everyday work" like sending a
  // message or reacting.
  'PATCH /v1/chat/conversations/:p',
  'POST /v1/chat/conversations/:p/archive',
  'POST /v1/chat/conversations/:p/unarchive',
  // --- Recording ticket proposals: the DECISION, not the reading ---
  //
  // `bugtracker/CLAUDE.md`, stated as a product rule and not a threat model:
  // "Let AI assign people or manage schedules" is forbidden, and "AI advises;
  // humans decide". An org API key is by definition the automated path — the
  // issue-create route it authenticates stamps `source: 'agent'` on what it
  // files precisely because the caller is not a person. Accepting or dismissing
  // a proposal is the human half of this feature; a credential that could both
  // generate proposals and mark them decided would be one actor doing both
  // halves, which is the same argument the Review Studio approvals below make.
  //
  // This costs an integration nothing it should have had: a key can still read
  // the proposals, read the deterministic draft, and file an ordinary issue
  // through `POST /v1/projects/:p/issues`. What it cannot do is record that a
  // human agreed.
  'POST /v1/recording-proposals/:p/accept',
  'POST /v1/recording-proposals/:p/reject',
  // --- The product index (Eric, 2026-09-05) ---
  // Reading these vocabularies is API-key-allowed (see the block next to
  // `GET /v1/projects/:p/fields`); defining them is not. Two separate reasons,
  // both worth stating:
  //   * a vocabulary is admin data, exactly like `project_fields` and custom
  //     ticket types, whose writes are session-only for the same reason;
  //   * `/decision` and `/review-queue` ARE the human gate. A derivation
  //     proposes; a person accepts. A credential that could do both halves
  //     would make the gate decorative, which is precisely what CLAUDE.md's
  //     "AI advises; humans decide" forbids.
  'GET /v1/projects/:p/product-index/review-queue',
  'POST /v1/projects/:p/product-index/derivations',
  'POST /v1/projects/:p/product-environments',
  'PATCH /v1/projects/:p/product-environments/:p',
  'DELETE /v1/projects/:p/product-environments/:p',
  'POST /v1/projects/:p/product-surfaces',
  'PATCH /v1/projects/:p/product-surfaces/:p',
  'DELETE /v1/projects/:p/product-surfaces/:p',
  'PUT /v1/projects/:p/product-surfaces/:p/targets',
  'POST /v1/projects/:p/product-surfaces/:p/decision',
  'POST /v1/projects/:p/product-surfaces/:p/merge',
  'POST /v1/projects/:p/product-nodes',
  'PATCH /v1/projects/:p/product-nodes/:p',
  'DELETE /v1/projects/:p/product-nodes/:p',
  'POST /v1/projects/:p/product-nodes/:p/decision',
  'POST /v1/projects/:p/product-nodes/:p/merge',
  'POST /v1/projects/:p/labels',
  'PATCH /v1/projects/:p/labels/:p',
  'DELETE /v1/projects/:p/labels/:p',
  'POST /v1/projects/:p/labels/:p/decision',
  'POST /v1/projects/:p/labels/:p/merge',
  // Natural-language filter resolution is read-only, but the same route can
  // make a metered Vertex call when `aiEnabled` is true. The API-key resource
  // gate is route-shaped, not body-shaped, so leaving this first-party until
  // deterministic and metered resolution have separate routes preserves the
  // existing fail-closed behavior and avoids an accidental AI-spend bypass.
  'POST /v1/projects/:p/issues/filter-resolve',
  // --- Surface Intelligence D3: every triage decision is a HUMAN decision ---
  // The product rule for this whole feature is "AI advises, humans decide". A
  // finding is a proposal until a person promotes or ignores it, and a token
  // that could promote would let an automation file its own tickets from its
  // own scan — which is the auto-filing this feature exists not to do.
  // Category enablement is here for the ordinary reason: it changes what runs
  // and what it costs.
  'PUT /v1/projects/:p/scan-categories/:p',
  // The org-scoped twin of the line above, split from its own GET the same way.
  'PUT /v1/orgs/:p/scan-categories/:p',
  'POST /v1/projects/:p/scan-categories/:p/trust',
  // Filing a draft as a real issue. The route's own docblock is the rule:
  // "A HUMAN presses this. Nothing files automatically, no schedule fires it,
  // and the reporter is the caller." That is CLAUDE.md's "AI advises; humans
  // decide" at the exact moment it is honoured or not, so it stays here while
  // the rest of the split editor is key-reachable.
  'POST /v1/projects/:p/recording-splits/:p/drafts/:p/file',

  'POST /v1/scan-findings/promote',
  'POST /v1/scan-findings/ignore',
  'POST /v1/scan-findings/reopen',
  // Board #612 — filing the human-reviewed set of AI-drafted tickets, same
  // reasoning as `POST /v1/scan-findings/promote` directly above: CLAUDE.md's
  // "AI advises; humans decide" must hold even against a leaked or malicious
  // API key, not only against an honest UI. `POST .../ai/parse-tickets`
  // (which only PROPOSES drafts, writes nothing) stays key-reachable above;
  // this route is what turns a reviewed set into real, possibly-assigned
  // issues, so it is not.
  'POST /v1/projects/:p/issues/bulk-create',
  // --- Review Studio (plan Part 5.1's `S` column) ---
  // Category 4 of the list above ("approves, locks, freezes, publishes,
  // executes external writes, changes permissions/credentials, exports
  // restricted evidence"). An approval an API key could grant would defeat the
  // entire action-preview mechanism: the point of a digest-bound approval is
  // that a HUMAN read the preview, and a credential that can both request and
  // approve is one actor doing both halves.
  'POST /v1/experience-reviews/:p/activate',
  'POST /v1/experience-reviews/:p/pause',
  'POST /v1/experience-reviews/:p/resume',
  'POST /v1/experience-reviews/:p/archive',
  'POST /v1/experience-reviews/:p/restore',
  'POST /v1/experience-reviews/:p/duplicate-as-template',
  'PUT /v1/experience-reviews/:p/members',
  'PUT /v1/experience-reviews/:p/governance-policy',
  'GET /v1/experience-reviews/:p/capability-grants',
  'POST /v1/experience-reviews/:p/capability-grants',
  'PATCH /v1/experience-reviews/:p/capability-grants/:p',
  'DELETE /v1/experience-reviews/:p/capability-grants/:p',
  'POST /v1/review-approval-requests/:p/approve',
  'POST /v1/review-approval-requests/:p/reject',
  'POST /v1/review-approval-requests/:p/delegate',
  'POST /v1/review-approval-requests/:p/abstain',
  'POST /v1/review-approval-requests/:p/recuse',
  'POST /v1/experience-reviews/:p/export',
  'POST /v1/projects/:p/experience-reviews/import',
  'GET /v1/orgs/:p/review-retention-policies',
  'POST /v1/orgs/:p/review-retention-policies',
  'PUT /v1/orgs/:p/review-retention-policies/:p',

  // Cross-org "everything this human can see" reads. An API key is minted
  // inside exactly one org, so "every org this identity belongs to" has no
  // meaning for one, and all four of these already refuse a key inside the
  // handler -- issues/routes.ts:1341, issues/routes.ts:1433,
  // issues/my-tasks.ts:255, projects/routes.ts:224. Listing them here does not
  // change behaviour; it stops the allowlist claiming something reachable that
  // the handler then refuses, which is worse than either answer alone.
  // The org-scoped equivalents stay allowlisted: GET /v1/orgs/:p/issues and
  // GET /v1/orgs/:p/projects.
  'GET /v1/me/tasks',
  'GET /v1/me/issues',
  'GET /v1/me/task-work',
  // Board #613. Same "cross-org, no meaning for a key" reasoning as the
  // three routes just above: every unaccepted invite addressed to the
  // CALLER'S OWN account email, across every org the key's creator is not
  // even necessarily a member of yet. A key is minted inside one org and
  // acts on that org's business, not "which other organizations has my
  // creator personally been invited to" -- the same personal-identity
  // concern `POST /v1/invites/accept` (below) is already session-only for.
  'GET /v1/invites/mine',
  'HEAD /v1/invites/mine',
  // Board #91. Same reasoning again: "which of MY organizations does this person
  // also belong to" enumerates the caller's own memberships across tenants, and a
  // key is minted inside exactly one org. Nothing an integration needs, and the
  // one route that discloses another user's membership, so it stays out of the
  // allowlist rather than being narrowed by `getApiKeyOrgId()` the way
  // `GET /v1/chat/unread-count` is. HEAD is covered by this GET.
  'GET /v1/users/:p/shared-orgs',
  'GET /v1/projects',
  // Board #360's PM/owner governance pair. decisions/routes.ts:300-307 states
  // the standing decision in full: "Deliberately NOT in API_KEY_ALLOWED_ROUTES
  // -- this is a PM/owner governance action over people (cancelling work,
  // reassigning who is being waited on), not a read or an agent's own response
  // to a decision it was asked... widening this to API keys is a separate
  // product call if it's ever wanted." TASK-479 is not that product call, so
  // the decision stands. Responding to a decision the agent was actually asked
  // (POST /v1/decisions/:p/respond) remains allowlisted, which is the half that
  // is the agent's own to answer. Matches CLAUDE.md's "AI advises, humans
  // decide".
  'POST /v1/decisions/:p/cancel',
  'POST /v1/decisions/:p/authorities/:p/reassign',
  // P51 slice C (G12): answering many decisions in one request. A person's act, like every other answer that carries
  // authority; a key can still answer ONE decision it was asked via POST /v1/decisions/:p/respond (existing rule).
  'POST /v1/orgs/:p/decisions::respond-batch',

  // Creating a project. This is the most debatable entry in this list and it is
  // deliberately here rather than in the allowlist.
  //
  // Agent-first says a project is ordinary work: the handler requires only
  // `requireOrgRole('member')` plus the plan capacity guard, and an agent that
  // files bugs could reasonably want somewhere to file them. But
  // `api-key-escalation.test.ts` is a leaked-key threat model end to end -- its
  // cases are "cannot invite anyone", "cannot change anyone's org role",
  // "cannot remove a member", and "cannot create another project to hide work
  // in" -- and the first three are already session-only for exactly the reasons
  // that file gives. Allowing the fourth would leave that suite making three
  // true claims and one false one.
  //
  // TASK-479's rule for a consequential write it is genuinely unsure about is to
  // deny it and say so, rather than to quietly widen it, so: denied, and flagged
  // for Eric in the PR. Reading projects (`GET /v1/orgs/:p/projects`) and
  // everything inside one stay allowlisted, so an agent still works normally in
  // projects a human created. Flipping this is a one-line change plus the
  // corresponding case in api-key-escalation.test.ts.
  'POST /v1/orgs/:p/projects',
  // OAuth installation mutates a replayable third-party credential on behalf
  // of a human project manager. API keys must not initiate or complete it.
  'GET /v1/projects/:p/connections/sentry/install',
  'POST /v1/projects/:p/connections/sentry/complete',
  // The @-mention picker. `activity-hub-routes.test.ts` ("returns the
  // authoritative private/default/category audience and keeps API keys off the
  // UI-only endpoint") pins this at 403 for a key. It computes the
  // authoritative audience for a project/issue -- who CAN be mentioned, i.e.
  // who can see a thing -- which is a composed visibility answer built for the
  // compose box, not a data read an integration needs.
  // `GET /v1/projects/:p/assignees` stays allowlisted and is the right route
  // for the "resolve a person to assign" case an agent actually has.
  'GET /v1/projects/:p/mentionables',
  // The conversation-native picker is the same UI-only visibility answer as
  // the project picker above. It additionally returns email addresses so
  // first-party clients can disambiguate duplicate display names; keeping it
  // session-only preserves the fail-closed behavior it had when introduced.
  'GET /v1/chat/conversations/:p/mentionable-members',
  // Chat UX A's Add-people picker (#352/#363 review): the same UI-only people
  // answer as the picker above -- every org member's name and email plus a
  // per-person can-open flag derived from the project's effective roster. A
  // runner key holds `chat` but not `orgs`/`projects`, so allowing this under
  // `chat` handed it the directory and access map those families refuse it.
  'GET /v1/chat/conversations/:p/add-candidates',
  // The broad Activity hub. TASK-349's own test ("keeps broad Activity and
  // notification history session-only for scoped and unscoped API keys",
  // activity-hub-routes.test.ts) states this as a standing decision and asserts
  // 403 for BOTH a scoped and an unscoped key. The narrow, per-consumer read
  // board #371 opened -- GET /v1/notifications, for the MCP list_notifications
  // tool -- stays allowlisted; that is the point of the distinction, and that
  // same test asserts it returns 200.
  'GET /v1/orgs/:p/activity/notifications',
  'GET /v1/orgs/:p/activity/notification-groups',
  'GET /v1/orgs/:p/activity/notification-groups/:p/notifications',
  'POST /v1/orgs/:p/activity/notification-groups/:p/read',
  'GET /v1/orgs/:p/activity/threads',
  // The web client's presence ping (~60s while a session is open). It writes
  // `activeSeconds`/`lastActiveAt` on the HUMAN's org_members row
  // (profiles/routes.ts:119), so a machine credential calling it would
  // manufacture evidence that a person was at their desk. That is writing the
  // human behind the key, and it is the kind of invented availability metric
  // the root CLAUDE.md already rules out.
  'POST /v1/orgs/:p/activity/heartbeat',
  // The WHOLE Slack surface, reads included. `slack-tenant-isolation.test.ts`
  // ("the Slack routes are absent from API_KEY_ALLOWED_ROUTES, and that is
  // deliberate") states this as a standing decision about the credential
  // surface, and its section E is specifically about what can leak. A first
  // pass here allowlisted the two installation/channel READS on the reasoning
  // that a read of channel names is harmless; that test is the better
  // authority, so the decision stands and the reads go back. Widening any part
  // of the Slack surface to API keys is a separate, deliberate call to make
  // against that suite, not a side effect of a classification sweep.
  'GET /v1/orgs/:p/slack/installations',
  'GET /v1/orgs/:p/slack/installations/:p/channels',
  // The human's own notification surface, and a cross-org escape: email mutes
  // live on the USER row, so a key issued for org A that could set them would
  // silence that person's mail in every org they belong to -- a machine
  // credential turning off a human's alerts everywhere. The READ is denied for
  // the same reason and by the same standing decision; both are pinned by
  // api-key-human-surface.test.ts. This pair was the one genuine miss in the
  // TASK-479 pass: the classifier saw "notifications" and allowed them, and
  // that existing test is what caught it.
  'GET /v1/notifications/preferences',
  'PATCH /v1/notifications/preferences',
  // Chat UX do-not-disturb: the same human alert setting; the handler also refuses every agent credential.
  'GET /v1/notifications/dnd',
  'PATCH /v1/notifications/dnd',

  // --- UGC moderation: report, block, and the queue (Apple 1.2 / Play UGC) ---
  //
  // THE WHOLE SURFACE IS SESSION-ONLY, and every part of it for its own reason.
  //
  // REPORTING is an act of a PERSON. `content_reports` exists to put a human's
  // complaint in front of another human, and a machine credential that could
  // file them is a way to manufacture moderator workload at API speed —
  // exactly the flooding the per-reporter unique index was added to prevent,
  // except an attacker with a key can vary the target instead of repeating it.
  // Nothing an agent legitimately does needs to report content; if an
  // integration ever should, that is a deliberate product call with its own
  // rate budget, not a side effect of a classification sweep.
  //
  // READING THE QUEUE would export reported content out of the product under a
  // credential rather than a person. A report carries `content_excerpt`, a
  // frozen copy of what was reported, and the queue is precisely where the
  // excerpts of an org's worst moments are collected in one place. The API-key
  // role ceiling already caps a key below the human who minted it
  // (`api-key-ceiling.test.ts`, "the ceiling bounds message moderation too"),
  // and the cleanest expression of that here is that a key never reaches this
  // surface at all — there is no ceiling to compute for a capability keys do
  // not have.
  //
  // BLOCKING is even more clearly personal. `/v1/me/blocks` is one human's own
  // safety setting about another human, held across every organization they
  // share. A key is minted inside exactly ONE org, so "block this person
  // everywhere I am" has no meaning for it, and a key that could unblock would
  // be a machine credential quietly restoring contact its owner had cut off.
  // Same shape as the `/v1/me/*` cross-org reads above, and the same answer.
  //
  // THE PLATFORM-ADMIN QUEUE is operator surface behind
  // `requireVerifiedPlatformAdmin`; no org-scoped key can satisfy that gate, so
  // listing it here makes the classification match the behaviour instead of
  // advertising a route the handler then refuses.
  'POST /v1/orgs/:p/content-reports',
  'GET /v1/orgs/:p/content-reports',
  'HEAD /v1/orgs/:p/content-reports',
  'GET /v1/orgs/:p/content-reports/:p',
  'HEAD /v1/orgs/:p/content-reports/:p',
  'PATCH /v1/orgs/:p/content-reports/:p',
  'GET /v1/me/blocks',
  'HEAD /v1/me/blocks',
  'GET /v1/me/blocks/:p',
  'HEAD /v1/me/blocks/:p',
  'PUT /v1/me/blocks/:p',
  'DELETE /v1/me/blocks/:p',
  'GET /v1/admin/content-reports',
  'HEAD /v1/admin/content-reports',
  // verified by reading the handler -- see
  // audit/2026-08-27-task-479-route-classification.md
  //
  // orgs/routes.ts:383-385 excludes this one in its own words: "an integration
  // credential has no reason to enumerate a human's whole access map". It
  // returns one person's role plus their access to EVERY project in the org, at
  // a plain 'member' floor.
  'GET /v1/orgs/:p/members/:p/access-summary',
  // One call, caller-supplied body, fans out a DM + notification + queued EMAIL
  // + mobile push to every project member, attributed to a real named human
  // ("<sender> sent you a direct message"). A leaked key turns that into
  // org-wide phishing, and nothing agent-first needs it.
  'POST /v1/projects/:p/thank-team',
  // Drive now uses the same live parent category/user/conversation gate as attachment reads.
  // Both of these are missing the board #37 user-scoped-key visibility check
  // that every sibling issue route applies, so a key scoped to "only MY
  // tickets" could destroy or mass-edit issues it cannot even read. That is a
  // handler bug, filed separately; until it is fixed these must not be
  // reachable by a key at all. `POST /v1/issues/:p/archive` remains the
  // allowlisted, reversible way for an agent to take an issue off the board.
  'DELETE /v1/issues/:p',
  'POST /v1/projects/:p/issues/bulk',

  // platform super-admin
  'GET /v1/admin/agent-runs',
  'GET /v1/admin/agent-runs/dead-letters',
  'GET /v1/admin/agent-template-versions/:p',
  'GET /v1/admin/agent-templates',
  'GET /v1/admin/agent-templates/:p/affected-instances',
  'GET /v1/admin/agent-templates/:p/versions',
  'GET /v1/admin/agent-templates/constraints',
  'GET /v1/admin/agents/scheduler-health',
  'GET /v1/admin/ai-runs',
  'GET /v1/admin/ai-runs/:p/call-events',
  'GET /v1/admin/audit',
  'GET /v1/admin/me',
  'GET /v1/admin/orgs',
  'GET /v1/admin/orgs/:p',
  'GET /v1/admin/orgs/:p/ai-usage',
  'GET /v1/admin/orgs/:p/billing/events',
  'GET /v1/admin/orgs/:p/billing/invoices',
  'GET /v1/admin/orgs/:p/billing/payments',
  'GET /v1/admin/orgs/:p/billing/subscription',
  'GET /v1/admin/orgs/:p/job-health',
  'GET /v1/admin/orgs/:p/support-elevations',
  'GET /v1/admin/referral-metrics',
  'GET /v1/admin/referrals/attributions',
  // TASK-539: internal Sentry PAT readiness dashboard. Session-only for the
  // same reason as every other platform-admin route in this block -- an org
  // API key has no notion of "platform operator" at all.
  'GET /v1/admin/sentry-pat/organizations',
  'GET /v1/admin/sentry-pat/status',
  'GET /v1/admin/settings',
  'GET /v1/admin/stats',
  'GET /v1/admin/support/tickets',
  'GET /v1/admin/users',
  'GET /v1/admin/users/:p',
  'PATCH /v1/admin/agent-template-versions/:p',
  'PATCH /v1/admin/orgs/:p',
  'PATCH /v1/admin/settings/:p',
  'PATCH /v1/admin/support/tickets/:p',
  'POST /v1/admin/agent-runs/:p/cancel',
  'POST /v1/admin/agent-runs/:p/retry',
  'POST /v1/admin/agent-template-versions/:p/preview',
  'POST /v1/admin/agent-template-versions/:p/publish',
  'POST /v1/admin/agent-template-versions/:p/retire',
  'POST /v1/admin/agent-template-versions/:p/test',
  'POST /v1/admin/agent-template-versions/:p/validate',
  'POST /v1/admin/agent-templates',
  'POST /v1/admin/agent-templates/:p/drafts',
  'POST /v1/admin/agent-templates/:p/rollback',
  'POST /v1/admin/audit/export',
  'POST /v1/admin/orgs/:p/support-elevations',
  'POST /v1/admin/referrals/attributions/:p/disqualify',
  'POST /v1/admin/referrals/attributions/:p/requalify',
  // TASK-539: see the GET entries above for the reasoning.
  'POST /v1/admin/sentry-pat/check',
  'POST /v1/admin/support-elevations/:p/revoke',
  'POST /v1/admin/users/:p/revoke-sessions',

  // membership change
  'DELETE /v1/orgs/:p/members/:p',
  'DELETE /v1/orgs/:p/members/:p/notes/:p',
  'DELETE /v1/orgs/:p/members/:p/skills/:p',
  'DELETE /v1/orgs/:p/members/:p/traits/:p',
  'DELETE /v1/projects/:p/members/:p',
  'PATCH /v1/orgs/:p/members/:p',
  'PATCH /v1/orgs/:p/members/:p/grants',
  'PATCH /v1/orgs/:p/members/:p/notes/:p',
  'PATCH /v1/orgs/:p/members/:p/traits/:p',
  'PATCH /v1/projects/:p/members/:p/grants',
  'POST /v1/orgs/:p/members/:p/notes',
  'POST /v1/orgs/:p/members/:p/traits',
  'PUT /v1/orgs/:p/members/:p/skills/:p',
  'PUT /v1/projects/:p/members',

  // device credential registration/revocation
  'DELETE /v1/devices/:p',
  'GET /v1/devices',
  'GET /v1/devices/push-preferences',
  'PATCH /v1/devices/push-preferences',
  'POST /v1/devices/:p/disable',
  'POST /v1/devices/logout',
  'POST /v1/devices/recover-registration',
  'POST /v1/devices/register',

  // account credential + session management
  'DELETE /v1/account',
  'DELETE /v1/account/sessions/:p',
  'GET /v1/account/export',
  'GET /v1/account/security-status',
  'GET /v1/account/sessions',
  'POST /v1/account/password',
  'POST /v1/account/sessions/revoke-others',
  /*
   * TASK-564. The published-calendar-feed mint/rotate surface, in the
   * `account credential` group above rather than merely near it, because that
   * is exactly what it is: `POST` mints a LONG-LIVED BEARER SECRET (a 730-day
   * purpose-scoped JWT that authorises reading this human's whole cross-org
   * calendar with no session), anchored to a `sessions` row it can also
   * revoke. A credential that could mint a second, longer-lived credential
   * for the human behind it is a privilege-escalation primitive, not an
   * everyday agent action.
   *
   * The classification MATCHES THE BEHAVIOUR rather than describing it: both
   * handlers already reject `auth.apiKeyId !== undefined` with a 403
   * (`modules/calendar/feed.ts`), so listing them here makes this file agree
   * with the code instead of advertising a route the handler then refuses.
   * The GET entry covers its auto-registered HEAD twin.
   */
  'GET /v1/me/calendar-feed',
  'POST /v1/me/calendar-feed',

  // QA Commander harness selection (dark, commander.harnessUi): which account or box the org's Commander runs on is a
  // signed-in owner's or admin's decision, never a bot's; the handlers also refuse a key by name.
  'GET /v1/orgs/:p/qa-commander/harness',
  'PUT /v1/orgs/:p/qa-commander/harness',
  'DELETE /v1/orgs/:p/qa-commander/harness',
  'POST /v1/orgs/:p/qa-commander/harness/certify',
  'POST /v1/orgs/:p/qa-commander/harness/deactivate',
  'POST /v1/orgs/:p/qa-commander/harness/test',
  // Discord integration (dark, discord.enabled): adding the bot to a Discord server happens in a person's browser.
  'POST /v1/orgs/:p/integrations/discord/install-link',
  // Discord self-serve DM link (dark): only the person themselves, signed in, links or unlinks their own Discord account.
  'GET /v1/orgs/:p/integrations/discord/my-link',
  'POST /v1/orgs/:p/integrations/discord/my-link',
  'DELETE /v1/orgs/:p/integrations/discord/my-link',

  // QA Commander private network (dark, commander.privateNetwork): connecting the org to a network, and what it is
  // connected to, is a signed-in owner's or admin's decision, never a bot's; the handlers also refuse a key by name.
  'GET /v1/orgs/:p/private-network',
  'PUT /v1/orgs/:p/private-network',
  'DELETE /v1/orgs/:p/private-network',
  'POST /v1/orgs/:p/private-network/test',
  'POST /v1/orgs/:p/private-network/revoke',

  // writes the human behind the key
  'DELETE /v1/me/avatar/uploads/:p',
  'PATCH /v1/me',
  'PATCH /v1/me/profile',
  'POST /v1/me/avatar/uploads',
  'POST /v1/me/avatar/uploads/:p/complete',
  'POST /v1/me/getting-started-prompted',
  'POST /v1/me/welcome-modal-shown',
  'PUT /v1/me/avatar/uploads/:p/content',

  // permission grants
  'DELETE /v1/projects/:p/categories/:p/user-grants/:p',
  'DELETE /v1/vault/secrets/:p/grants/:p/:p',
  'GET /v1/projects/:p/grants',
  'GET /v1/vault/secrets/:p/grants',
  'PUT /v1/projects/:p/categories/:p/role-access',
  'PUT /v1/projects/:p/categories/:p/user-grants',
  'PUT /v1/vault/secrets/:p/grants',
  // Vault secret requests: only the person asked, in a signed-in session, answers (the value is typed by a human).
  'POST /v1/secret-requests/:p/fulfil',
  'POST /v1/secret-requests/:p/decline',
  // SEO data connectors: only the person asked, signed in, connects their Google account to a request.
  'GET /v1/seo/connect/google/start',

  // the human's own saved workspace state
  'DELETE /v1/me/dashboards/:p',
  'DELETE /v1/me/issue-filters',
  'PATCH /v1/me/dashboards/:p',
  'POST /v1/me/dashboards',
  'PUT /v1/me/issue-filters',

  // stores a third-party credential
  'DELETE /v1/orgs/:p/agent-browser-connection',
  'DELETE /v1/projects/:p/intelligence/credential',
  'PUT /v1/orgs/:p/agent-browser-connection',
  'PUT /v1/projects/:p/intelligence/credential',

  // API key minting/管理 — a key must never mint another key
  'DELETE /v1/orgs/:p/api-keys/:p',
  'GET /v1/orgs/:p/api-keys',
  'PATCH /v1/orgs/:p/api-keys/:p',
  'POST /v1/orgs/:p/api-keys',
  // ...nor pause, resume or lengthen a key (its own or another's), nor pause every agent
  // its owner has: the kill switch is the human's brake on the bot, so the bot cannot be
  // the one holding it. AGENT-DELEGATES design section 16 ("The bot (key): NEVER approve,
  // pause, revoke or edit its own delegation").
  'POST /v1/orgs/:p/api-keys/:p/pause',
  'POST /v1/orgs/:p/api-keys/:p/resume',
  'POST /v1/orgs/:p/api-keys/:p/extend',
  'POST /v1/account/agents/pause-all',
  // ...and a key must never edit an identity (its own or another's), or put a
  // bot into a conversation: the persona management surface.
  'DELETE /v1/orgs/:p/api-keys/:p/persona',
  'GET /v1/orgs/:p/api-keys/:p/persona',
  'PATCH /v1/orgs/:p/api-keys/:p/persona',
  'POST /v1/orgs/:p/api-keys/:p/persona',
  'DELETE /v1/orgs/:p/conversations/:p/personas/:p',
  'PUT /v1/orgs/:p/conversations/:p/personas/:p',
  // "Mute this bot" is one person's setting about one bot (design 9.2): the bot may no longer DM,
  // mention or notify them. A key is minted inside one org and acts as its owner, so a key that
  // could un-mute would be a machine credential quietly restoring contact a person had cut off --
  // the same reasoning as `/v1/me/blocks` below. A browser session only, both directions.
  'DELETE /v1/orgs/:p/personas/:p/mute',
  'POST /v1/orgs/:p/personas/:p/mute',

  // A CI hook token is a bearer credential over a repository connection's
  // refresh path, minted behind the same `repo:manage` that created the
  // connection. So the whole trio takes the api-keys decision above, for the
  // same reason and including the reads: POST mints the secret, GET returns
  // the prefix and callback URL that identify it, DELETE revokes it.
  'POST /v1/repos/:p/ci-hook',
  'GET /v1/repos/:p/ci-hook',
  'DELETE /v1/repos/:p/ci-hook',

  // Shareable invite links (board #809): the WHOLE trio, not just minting --
  // takes the api-keys / ci-hook-token decision above, deliberately NOT the
  // email-invites one two blocks below. The distinction that block itself
  // draws is the one that puts these here: "an invite creates a PERSON, who
  // must then authenticate as themselves and who an admin can see and
  // remove; a key creates a bearer credential that needs nobody." A LINK is
  // exactly the second kind -- a bearer capability addressed to nobody,
  // usable by whoever holds the URL, up to `maxUses` times -- not the first.
  // `GET` never returns the token itself (only a sha256 is ever stored), but
  // it is kept alongside `POST`/`DELETE` rather than split out, the same way
  // `GET /v1/orgs/:p/api-keys` stays session-only alongside minting and
  // revoking a key even though it too only returns a prefix, never a secret:
  // reading the credential INVENTORY is part of managing the credential
  // surface, not a separate, lower-trust action.
  'POST /v1/orgs/:p/invite-links',
  'GET /v1/orgs/:p/invite-links',
  'HEAD /v1/orgs/:p/invite-links',
  'DELETE /v1/orgs/:p/invite-links/:p',

  // invitations — ACCEPTING only. Creating, listing, link-minting and revoking
  // moved to API_KEY_ALLOWED_ROUTES (Eric, 2026-09-07); see the reasoning
  // there. Accepting stays session-only and always will: the invitee accepts AS
  // THEMSELVES, and a key acting on behalf of its creating human must never be
  // able to take that step for a different person.
  'POST /v1/invites/accept',

  // privilege elevation
  'DELETE /v1/orgs/:p/elevations/:p',
  'GET /v1/orgs/:p/elevations',
  'PATCH /v1/orgs/:p/elevations/:p',
  'POST /v1/orgs/:p/elevations',

  // role definitions
  'DELETE /v1/orgs/:p/roles/:p',
  'GET /v1/orgs/:p/roles',
  'PATCH /v1/orgs/:p/roles/:p',
  'POST /v1/orgs/:p/roles',

  // guest access grants
  'DELETE /v1/projects/:p/guests/:p',
  'GET /v1/projects/:p/guests',
  'PATCH /v1/projects/:p/guests/:p',
  'POST /v1/projects/:p/guests',

  // external connection credentials
  'DELETE /v1/connections/:p',
  'PATCH /v1/connections/:p',
  'POST /v1/projects/:p/connections',

  // domain verification controls org auto-join
  'DELETE /v1/orgs/:p/domains/:p',
  'GET /v1/orgs/:p/domains',
  'POST /v1/orgs/:p/domains',

  // Slack install/OAuth connection
  'DELETE /v1/orgs/:p/slack/installations/:p',
  'GET /v1/orgs/:p/slack/install',
  'POST /v1/orgs/:p/slack/installations/:p/channels',

  // approving a pairing MINTS an API key
  'POST /v1/mcp/write-confirmations',
  'GET /v1/mcp/pair/requests/:p',
  'POST /v1/mcp/pair/requests/:p/approve',
  'POST /v1/mcp/pair/requests/:p/deny',

  // referral rewards are money
  'GET /v1/orgs/:p/referral-rewards',
  'POST /v1/orgs/:p/referral-code',

  // third-party OAuth connection
  'DELETE /v1/orgs/:p/calendar-connection',
  'GET /v1/orgs/:p/calendar-connection/authorize',
  'GET /v1/integrations/google-calendar/callback',
  // Reads the CONTENT of the connected calendar (event titles, times, places),
  // which is not GoodQA's data and frequently not even the customer's -- it is
  // their counterparties'. Its metadata sibling `GET
  // /v1/orgs/:p/calendar-connection` is API-key readable above because it
  // answers only "is a calendar connected", with no event in it. The grant
  // behind this one was made by a specific human through a consent screen that
  // named the Ops/Reminder agent and this in-product view; widening it to every
  // org-scoped key would be a use that consent never described.
  'GET /v1/orgs/:p/calendar-connection/events',

  // per-device push credential
  'DELETE /v1/push/subscribe',
  'POST /v1/push/subscribe',

  // GitHub App install flow. The picker answers "which of YOUR orgs could take
  // this installation" — it is scoped to one human's memberships across every
  // org, which an org-scoped key cannot mean, and it is the read behind a
  // browser screen finishing an install a person started on github.com.
  // Linking one is the install itself, minus the round-trip: it attaches a
  // GitHub account's repositories to an org, which belongs with the rest of
  // this flow on the human side of the line.
  'GET /v1/github/setup',
  // GitHub's OAuth redirect lands here with no session and no bearer -- the
  // browser carries the signed state cookie instead, which is what the handler
  // verifies. Same shape as /github/setup directly above.
  'GET /v1/github/oauth/callback',
  'GET /v1/github/installations/:p/orgs',
  // The user-OAuth round-trip that proves WHICH installations a human controls.
  // Session-only by nature: the proof it mints is bound to one signed-in person,
  // and an org-scoped API key cannot mean "this human's GitHub account".
  'GET /v1/github/my-installations',
  'GET /v1/github/oauth/start',
  'GET /v1/orgs/:p/github/connect',
  'POST /v1/orgs/:p/github/installations/:p/link',

  // payment/billing
  'POST /v1/orgs/:p/billing/checkout',
  'POST /v1/orgs/:p/billing/portal',
  // Ticket #359 refund records/decisions (dark behind BILLING_REFUND_ADMIN_ENABLED):
  // platform-admin, recent interactive session, never an API key.
  'GET /v1/admin/billing/readiness',
  'POST /v1/admin/billing/orgs/:p/design-partner-grant',
  'GET /v1/admin/billing/refund-requests',
  'POST /v1/admin/billing/refund-requests',
  'POST /v1/admin/billing/refund-requests/:p/decision',

  // org deletion
  'DELETE /v1/orgs/:p',

  // project deletion
  'DELETE /v1/projects/:p',

  // single-secret read is deliberately excluded
  'GET /v1/vault/secrets/:p',

  // plan entitlements (billing-adjacent)
  'PATCH /v1/orgs/:p/entitlements',

  // retention policy governs data destruction
  'PATCH /v1/orgs/:p/retention-policy',

  // session teardown
  'POST /v1/auth/logout',

  // Email step-up codes confirm a person consenting in their own browser. No key or token ever asks for one.
  'POST /v1/auth/step-up/email/send',
  'POST /v1/auth/step-up/email/verify',
  // Board #606: registering and managing passkeys changes the signed-in
  // person's durable authentication factors. An org API key must never be
  // able to attach, rename, enumerate, or remove those credentials.
  'POST /v1/auth/webauthn/register/options',
  'POST /v1/auth/webauthn/register/verify',
  'GET /v1/auth/webauthn/credentials',
  'PATCH /v1/auth/webauthn/credentials/:p',
  'DELETE /v1/auth/webauthn/credentials/:p',
  // AUD-007 -- the step-up confirmation that register/verify and the DELETE
  // above now require. Re-verifying a password, an existing passkey, or a
  // fresh OAuth round trip is HUMAN reauthentication by definition; an org
  // API key has no password to type, no authenticator to assert with, and
  // no browser to complete an OAuth redirect in, so it could never
  // legitimately call this even if it were allowed to. Session-only for the
  // same reason the mutations it gates are.
  'POST /v1/auth/webauthn/step-up',
  'POST /v1/auth/webauthn/step-up/passkey/options',

  // Boards #588/#591: only an already-authenticated native user session may
  // mint a one-use renderer bootstrap. An org API key is never a native
  // account session and must not cross this boundary. iOS has a separate,
  // fixed endpoint so the server — never caller input — owns its restricted
  // App Store surface profile.
  'POST /v1/auth/hosted/mobile/bootstrap',
  'POST /v1/auth/hosted/ios/bootstrap',

  // Browser-first desktop approval is authenticated by the first-party
  // browser cookie and explicitly rejects API keys and Authorization-header
  // overrides before minting the one-time desktop exchange code.
  'POST /v1/auth/oauth/desktop/approve',

  // registers a client installation identity
  'POST /v1/extension/installations',

  // org creation
  'POST /v1/orgs',
  'POST /v1/orgs/:p/members',

  // self-granting project access

  // links a Slack identity to a GoodQA account
  'POST /v1/slack/link',

  // KEK rotation re-wraps every DEK
  'POST /v1/vault/admin/rotate-kek',

  // Deploy Assistant: a real Vertex call with Google Search grounding, on the
  // same footing as marketing's `generate` routes — provider-billed model spend
  // whose whole purpose is to answer a HUMAN's question about a step they are
  // stuck on. An org API key has nobody to answer, so all it could do is spend.
  'POST /v1/projects/:p/deploy/plans/:p/steps/:p/ask',

  // Support AI chat (board #637 phase 2a): same reasoning as the deploy `/ask`
  // route directly above — a real, provider-billed model call whose whole
  // purpose is a conversation with the human on the other end. Never org/
  // project-scoped (a support conversation belongs to the person having it),
  // so it does not belong in API_KEY_ALLOWED_ROUTES's org-scoped section
  // either way. An org API key has nobody to chat with, so all it could do
  // is spend against this route's own tighter rate limit.
  'POST /v1/support/chat',

  // --- Marketing Tools (2026-08-29), category 7: real external side effect or
  // real third-party spend. See this list's own doc comment for the full
  // reasoning, including why the approve/send endpoints are here rather than
  // reachable behind their own mandatory human-approval gate. ---
  // Kicks off the multi-page-crawl + repo-docs + market-research Vertex job --
  // the single most expensive AI call surface in the product, no per-run cap.
  'POST /v1/projects/:p/marketing/onboarding/start',
  'POST /v1/projects/:p/marketing/onboarding/:p/advance',
  'POST /v1/projects/:p/marketing/scans',
  'POST /v1/projects/:p/marketing/scans/:p/confirm',
  // Profile identity feeds every other assistant's generation prompts;
  // integrations write a vault-stored third-party key (category 6 as well).
  'PUT /v1/projects/:p/marketing/profile',
  'PATCH /v1/projects/:p/marketing/profile/field-meta/:p',
  'PUT /v1/projects/:p/marketing/integrations',
  // Blog: generate is a real Vertex grounded-generation call; transition can
  // move a post to 'published' -- real content going live publicly.
  'POST /v1/projects/:p/marketing/blog/posts',
  'PATCH /v1/projects/:p/marketing/blog/posts/:p',
  'DELETE /v1/projects/:p/marketing/blog/posts/:p',
  'POST /v1/projects/:p/marketing/blog/posts/:p/generate',
  'POST /v1/projects/:p/marketing/blog/posts/:p/transition',
  // Native CMS platform (board #505): same reasoning as blog directly above --
  // publish/unpublish move a document to/from publicly-live, and the whole
  // mutation surface for both documents and the content types that govern
  // their shape is kept out of API-key reach, not just the publish step. See
  // API_KEY_ALLOWED_ROUTES above for the reads, which stay everyday work.
  // Exact-revision schedules, reviewed imports and factory acceptance require a person.
  'POST /v1/projects/:p/sites/:p/factory-runs',
  'POST /v1/projects/:p/sites/:p/imports/apply',
  'GET /v1/orgs/:p/projects/:p/site-factory/artifacts/:p/:p',
  'POST /v1/orgs/:p/projects/:p/site-factory/runs',
  'GET /v1/orgs/:p/projects/:p/site-factory/runs/:p',
  'GET /v1/orgs/:p/projects/:p/site-factory/runs/:p/receipt',
  'PUT /v1/orgs/:p/projects/:p/site-factory/runs/:p',
  'POST /v1/orgs/:p/projects/:p/site-factory/runs/:p/approve',
  'POST /v1/orgs/:p/projects/:p/site-factory/runs/:p/resume',
  'POST /v1/orgs/:p/projects/:p/site-factory/runs/:p/cancel',
  'POST /v1/orgs/:p/projects/:p/site-factory/runs/:p/actions/:p/start',
  'POST /v1/orgs/:p/projects/:p/site-factory/runs/:p/actions/:p/record',
  'POST /v1/projects/:p/cms/content-types',
  'PATCH /v1/cms/content-types/:p',
  'POST /v1/cms/content-types/:p/archive',
  'POST /v1/projects/:p/cms/documents',
  'PATCH /v1/cms/documents/:p',
  'POST /v1/cms/documents/:p/publish',
  'POST /v1/cms/documents/:p/unpublish',
  'POST /v1/cms/documents/:p/archive',
  'POST /v1/cms/documents/:p/versions/restore',
  // Social: generate-image/generate-video are real Vertex/Veo spend; approve
  // is the mandatory human-review gate itself; schedule puts a real post on a
  // real connected social account.
  //
  // `concepts/suggest` persists nothing, so it is here for the OTHER reason
  // this list exists: it is a provider-billed model call, and it is step 1 of a
  // wizard whose entire purpose is a human choosing between concepts. An org
  // API key has nobody to present them to, so all it could do is spend money.
  'POST /v1/projects/:p/marketing/social/concepts/suggest',
  'POST /v1/projects/:p/marketing/social/posts/generate',
  'PATCH /v1/projects/:p/marketing/social/posts/:p/channels/:p',
  'POST /v1/projects/:p/marketing/social/posts/:p/approve',
  'POST /v1/projects/:p/marketing/social/posts/:p/channels/:p/schedule',
  'POST /v1/projects/:p/marketing/social/posts/:p/channels/:p/generate-image',
  'POST /v1/projects/:p/marketing/social/posts/:p/channels/:p/generate-video',
  // Prospecting: both spend real Apollo credits (plus Gemini for enrich).
  'POST /v1/projects/:p/marketing/prospecting/searches',
  'PATCH /v1/projects/:p/marketing/prospecting/prospects/:p/review',
  'POST /v1/projects/:p/marketing/prospecting/prospects/:p/enrich',
  // Mailer: leads/consent are CASL/GDPR-significant PII and consent records
  // that must be human-attested, not agent-authored; send literally emails
  // real people and is the single most consequential write in this module.
  'POST /v1/projects/:p/marketing/mailer/leads',
  'POST /v1/projects/:p/marketing/mailer/leads/:p/consent',
  'POST /v1/projects/:p/marketing/mailer/leads/:p/consent/:p/withdraw',
  'POST /v1/projects/:p/marketing/mailer/campaigns',
  'PATCH /v1/projects/:p/marketing/mailer/campaigns/:p',
  'POST /v1/projects/:p/marketing/mailer/campaigns/:p/generate-draft',
  'POST /v1/projects/:p/marketing/mailer/campaigns/:p/approve',
  'POST /v1/projects/:p/marketing/mailer/campaigns/:p/send',
  // SEO: both are real metered external calls (Vertex + PageSpeed / keyword provider).
  'POST /v1/projects/:p/marketing/seo/analyses',
  'POST /v1/projects/:p/marketing/seo/keywords',

  // Same-day-landed routes this branch's base predates -- category 5,
  // `/v1/admin/*` is already stated as platform super-admin surface.
  'POST /v1/admin/feature-cards',
  'GET /v1/admin/feature-cards',
  'GET /v1/admin/feature-cards/:p',
  'PATCH /v1/admin/feature-cards/:p',
  // Media reads/replacements have the separate live-grant carveout above; grant management stays human-only.
  'GET /v1/admin/feature-cards/:p/media',
  'PUT /v1/admin/feature-cards/:p/media',
  'GET /v1/admin/feature-card-media-grants',
  'POST /v1/admin/feature-card-media-grants',
  'POST /v1/admin/feature-card-media-grants/:p/revoke',
  // The DRAFT -> APPROVE gate (Eric, 2026-09-05). Category 5 like the four
  // above, and `approve` is the one that would matter most if it were ever
  // allowlisted: it is the single action that makes a card eligible to be
  // emailed to every confirmed address on the install, so it must be a human
  // with a session, never a key an automation can hold.
  'GET /v1/admin/feature-cards/drafts',
  'POST /v1/admin/feature-cards/:p/approve',
  'DELETE /v1/admin/feature-cards/:p',
  // TASK-515 AI-assisted draft copy (recovery-integration, 2026-09-11): the
  // model proposes title/description text for a platform admin to review
  // before it is even a stored draft. Same category-5 admin-only surface as
  // every other /v1/admin/feature-cards/* route above -- an API key must not
  // be able to spend the platform's AI budget generating announcement copy
  // on its own.
  'POST /v1/admin/feature-cards/generate-draft',
  // Personal scratchpad: matches the existing /v1/me/issue-filters and
  // /v1/me/dashboards precedent immediately below -- reads of a personal
  // resource are allowed above ('orgs'), writes stay session-only. Also
  // matches this list's own tested blanket invariant ("admits no write to
  // the human behind the key" -- every /v1/me/* write is session-only, no
  // exceptions beyond GET /v1/me itself); feature-cards ack/opt-out below
  // were caught by that exact test on a first attempt at allowlisting them.
  'POST /v1/me/scratchpad',
  'POST /v1/me/scratchpad/reorder',
  'PATCH /v1/me/scratchpad/:p',
  'DELETE /v1/me/scratchpad/:p',
  // Writing the drawing is a write under /v1/me, so it is session-only like every
  // other one -- an API key never edits the human's own scratchpad.
  'PUT /v1/me/scratchpad/drawing',
  // Notes to self + personal files (Eric, 2026-10-03): only the additive cross-machine half (send, upload, read,
  // search) is key-reachable (notes_to_self family). Editing, pinning, deleting, the read marker and every
  // scratchpad-file route stay with the human's own session.
  'PATCH /v1/me/notes-to-self/messages/:p',
  'DELETE /v1/me/notes-to-self/messages/:p',
  'POST /v1/me/notes-to-self/read',
  'GET /v1/me/scratchpad/files',
  'POST /v1/me/scratchpad/files',
  'PATCH /v1/me/files/:p',
  'DELETE /v1/me/files/:p',
  'POST /v1/me/feature-cards/:p/ack',
  'POST /v1/me/feature-cards/ack-all',
  'POST /v1/me/feature-cards/opt-out',
  // Commander S1-S3 (lane qac-threads-slice3-fix): the per-viewer Commander identity, the assistant
  // name settings, the private master DM opener and the caller's own AI-thread list. Each answers for ONE
  // signed-in person (their override name, their master thread, their visible threads); an org key has no
  // viewer of its own, and the org rename is an admin-session action by design (DESIGN 11). These were
  // already refused for keys while unclassified (fail closed); listing them keeps that, it widens nothing.
  // Turn grants (user tokens) reach their own allow-list in user-tokens, not this one.

  // TASK-527: routes added after the exhaustive classifier landed must still
  // make an explicit bearer-policy decision. These remain human-session only,
  // preserving the fail-closed runtime behavior they had while unclassified:
  // platform comp administration; commercial comp redemption; third-party
  // credential management; the human's personal reminders; retention export;
  // a Marketing workflow mutation; and a metered interactive AI rewrite with
  // no API-key consumer. Classification is documentation/test coverage here,
  // not a widening of what an org key can reach.
  'GET /v1/admin/comp-codes',
  'GET /v1/admin/comp-codes/orgs',
  'POST /v1/admin/comp-codes',
  'POST /v1/admin/comp-codes/:p/revoke',
  'POST /v1/admin/comp-codes/orgs/:p/revoke',
  // TASK-375 -- self-serve platform-admin grants. Same tier as every other
  // `/v1/admin/*` platform-super-admin console action above, reinforced here:
  // grant/revoke is gated by `requireRecentAuth` (a 30-minute step-up), which
  // is a browser-session concept with no API-key equivalent.
  'GET /v1/admin/platform-admins',
  'POST /v1/admin/platform-admins',
  'POST /v1/admin/platform-admins/:p/revoke',
  // Board #695 -- revealing a secure message's real content. An EVEN
  // STRONGER version of the `requireRecentAuth` argument just above: this
  // route requires a FRESH credential in the request itself (a just-typed
  // password or a just-completed passkey assertion), not merely a session
  // under some step-up age. Both proof methods are browser/human concepts an
  // API key cannot produce -- a key has no password to re-type and no
  // authenticator to re-assert with. SENDING a secure message stays
  // API-key-reachable under `'chat'` above; only the reveal is session-only.
  'POST /v1/chat/conversations/:p/messages/:p/secure/reveal',
  'POST /v1/orgs/:p/comp-code',
  'GET /v1/orgs/:p/provider-keys',
  'PUT /v1/orgs/:p/provider-keys',
  'POST /v1/orgs/:p/provider-keys/:p/validate',
  'DELETE /v1/orgs/:p/provider-keys/:p',
  'GET /v1/orgs/:p/reminders',
  'POST /v1/orgs/:p/reminders',
  'PATCH /v1/orgs/:p/reminders/:p',
  'DELETE /v1/orgs/:p/reminders/:p',
  'POST /v1/orgs/:p/reminders/:p/snooze',
  'GET /v1/orgs/:p/recordings/expiring',
  'POST /v1/projects/:p/marketing/scans/:p/cancel',
  'POST /v1/projects/:p/issues/rewrite-description',

  // Deploy Assistant (DA1/DA4). Whole module, session-only, one decision:
  //   - the connection routes STORE, VERIFY and REVOKE a third-party customer
  //     credential — category 6 of the list above, the same classification the
  //     `provider-keys` quartet directly overhead already carries;
  //   - `/deploy-assistant/ask` is a metered Vertex call with a live Google
  //     Search grounding tool attached — category 7, real third-party spend
  //     against the org's shared AI budget, with the same shape as the
  //     `rewrite-description` entry above;
  //   - the catalog read is grouped with them deliberately rather than
  //     allowlisted on its own. It is the connect wizard's first screen, it has
  //     no CI or agent consumer, and splitting one module across two bearer
  //     policies is how a later route gets classified by proximity to the wrong
  //     neighbour.
  'GET /v1/deploy-providers/catalog',
  'GET /v1/orgs/:p/deploy-connections',
  'POST /v1/orgs/:p/deploy-connections',
  'POST /v1/orgs/:p/deploy-connections/:p/verify',
  'DELETE /v1/orgs/:p/deploy-connections/:p',
  'GET /v1/projects/:p/deploy-connections',
  'POST /v1/projects/:p/deploy-connections',
  'POST /v1/projects/:p/deploy-connections/:p/refresh',
  'POST /v1/orgs/:p/deploy-assistant/ask',

  // TASK-595: a ticket's reverse chat backlinks are intentionally rendered
  // through the signed-in user's conversation visibility. Keeping this
  // session-only prevents an API key from gaining a new path to private DM or
  // channel metadata merely because one message linked the ticket.
  'GET /v1/issues/:p/related-conversations',

  // Current-dev additions after the old TASK-527 candidate: CRM is an
  // authenticated human workflow whose handlers require a CRM org permission
  // (and feature entitlement for writes). It has no API-key consumer, so every
  // route stays outside the allowlist. SUPERSEDED IN PART by CRM v2 C0 (owner
  // decision Q3): the record, tag, field and segment routes moved to the `crm`
  // family of API_KEY_ALLOWED_ROUTES, dark per org; what remains here is still
  // session-only on purpose (see that block's comment for the list and why). Mailer preview prepares an outbound
  // audience and confirmation token and likewise remains a PM session action;
  // the later send route is separately session-only too.
  // Pipelines and deals arrived with CRM slice 7 and take the same decision as
  // the rest of the block: an authenticated human workflow with no API-key
  // consumer. Listed rather than left unclassified so that "deliberately
  // human-only" and "nobody got to it yet" stay different bits.
  'GET /v1/orgs/:p/crm/pipelines',
  'POST /v1/orgs/:p/crm/pipelines',
  'PATCH /v1/orgs/:p/crm/pipelines/:p',
  'DELETE /v1/orgs/:p/crm/pipelines/:p',
  'GET /v1/orgs/:p/crm/pipelines/:p/board',
  'POST /v1/orgs/:p/crm/pipelines/:p/stages',
  'PATCH /v1/orgs/:p/crm/pipelines/:p/stages/:p',
  'DELETE /v1/orgs/:p/crm/pipelines/:p/stages/:p',
  'POST /v1/orgs/:p/crm/pipelines/:p/stages/reorder',
  'POST /v1/orgs/:p/crm/deals',
  'GET /v1/orgs/:p/crm/deals/:p',
  'PATCH /v1/orgs/:p/crm/deals/:p',
  'POST /v1/orgs/:p/crm/deals/:p/stage',
  'POST /v1/orgs/:p/crm/deals/:p/archive',
  'GET /v1/orgs/:p/crm/contacts/export',
  'GET /v1/orgs/:p/crm/contacts/:p',
  'POST /v1/orgs/:p/crm/contacts/:p/issue-links',
  'DELETE /v1/orgs/:p/crm/contacts/:p/issue-links/:p',
  'GET /v1/orgs/:p/crm/contacts/:p/timeline',
  'GET /v1/orgs/:p/crm/timeline',
  'POST /v1/orgs/:p/crm/timeline',
  'PATCH /v1/orgs/:p/crm/timeline/:p',
  'POST /v1/orgs/:p/crm/timeline/:p/archive',
  // Board #509 slice 10 (recovery-integration, 2026-09-11): custom fields,
  // tags and segments are the SAME "authenticated human workflow with no
  // API-key consumer" surface as pipelines/deals/contacts/timeline directly
  // above -- an org's own CRM taxonomy, config Owner+Admin manage by default
  // (see `crm:manage_fields` in packages/shared/src/enums.ts). Reads are
  // listed session-only alongside the writes here rather than split into
  // API_KEY_ALLOWED_ROUTES the way `GET /v1/projects/:p/fields` is, because
  // that split pattern is for the product-index vocabulary specifically
  // (see that block's own comment); every other CRM route, read or write,
  // has been session-only since CRM slice 7 and this keeps the surface
  // consistent rather than introducing a second convention for one module.
  'POST /v1/orgs/:p/crm/segments/:p/materialize',
  /*
   * CRM DEPTH, session-only for the same reason as the block directly above,
   * plus one that is specific to raising a ticket from a contact.
   *
   * `POST .../crm/contacts/:p/issues` CREATES AN ISSUE IN A PROJECT. It is
   * gated on `issue:create` in that project as well as `crm:edit` in the org,
   * and both are resolved against the acting HUMAN. An org API key is a
   * long-lived credential whose holder is not necessarily present when it acts,
   * and a key-driven path that mints tickets into arbitrary projects is a
   * different risk from one that reads a contact list. The project-scoped issue
   * API already exists for automation (`POST /v1/projects/:p/issues`) and is
   * allow-listed there on its own merits; nothing needs a second door.
   *
   * The graph read is session-only for the plainer reason: it composes
   * employment, co-attendance and issue involvement into one answer, and it is
   * exactly the shape of read a leaked long-lived key would be used to
   * exfiltrate a customer map with.
   */
  'POST /v1/orgs/:p/crm/contacts/:p/issues',
  /*
   * MAILBOX CONNECTIVITY. Session-only, and this one is not a judgement call.
   *
   * Every one of these routes acts on the CALLING USER'S OWN mailbox — the
   * handlers read `userId` from the session and never from the request, so
   * "which mailbox" is decided by who is signed in. An org API key has no user
   * behind it at all; letting one reach these routes would either be meaningless
   * (no mailbox to act on) or, worse, would require inventing a way for a
   * long-lived org credential to name a person's mailbox, which is precisely the
   * thing the per-person key `(org_id, user_id, address)` exists to prevent.
   * The connect route additionally accepts a REUSABLE ACCOUNT PASSWORD the user
   * typed; a credential-accepting endpoint reachable by another credential is a
   * pivot, not a feature.
   */
  'GET /v1/orgs/:p/crm/mailboxes',
  'POST /v1/orgs/:p/crm/mailboxes',
  'DELETE /v1/orgs/:p/crm/mailboxes/:p',
  'POST /v1/orgs/:p/crm/mailboxes/:p/sync',
  'GET /v1/orgs/:p/crm/contacts/:p/meetings',
  'POST /v1/orgs/:p/crm/timeline/:p/attendance',
  'GET /v1/orgs/:p/crm/graph',
  /*
   * SCHEDULING LINKS — the owner's half.
   *
   * Session-only for the same reason the CRM block above is, plus one that is
   * specific to this feature: publishing a booking link EXPOSES A COLLEAGUE'S
   * FREE/BUSY TO THE OPEN INTERNET. `requireSchedulingAdmin` gates these on
   * `org:manage_members` — the existing authority over other people's
   * participation in the org — and an org API key is a long-lived credential
   * whose holder is not necessarily present when it acts. Nobody should be able
   * to publish Dana's calendar with a token pasted into a script.
   *
   * `GET .../scheduling/bookings` additionally returns invitee EMAIL ADDRESSES,
   * which is personal data belonging to people who are not GoodQA users and
   * never consented to an integration reading it.
   */
  'GET /v1/orgs/:p/scheduling/links',
  'POST /v1/orgs/:p/scheduling/links',
  'PATCH /v1/orgs/:p/scheduling/links/:p',
  'DELETE /v1/orgs/:p/scheduling/links/:p',
  'POST /v1/orgs/:p/scheduling/links/:p/event-types',
  'PATCH /v1/orgs/:p/scheduling/event-types/:p',
  'GET /v1/orgs/:p/scheduling/bookings',
  // Booking administration (lane 2026-10-06, scheduling v1): org-admin acts on other people's appointments.
  'GET /v1/orgs/:p/scheduling/admin/status',
  'GET /v1/orgs/:p/scheduling/admin/bookings/:p/slots',
  'POST /v1/orgs/:p/scheduling/admin/bookings/:p/cancel',
  'POST /v1/orgs/:p/scheduling/admin/bookings/:p/reschedule',
  'PATCH /v1/orgs/:p/scheduling/admin/bookings/:p/notes',
  'POST /v1/orgs/:p/scheduling/admin/manual',
  // Scheduling v1: a member's OWN availability, personal page and date overrides. Session-only: these publish a
  // person's free/busy to the internet, which is the person's own act, not a key's.
  'GET /v1/orgs/:p/scheduling/me',
  'PUT /v1/orgs/:p/scheduling/me/profile',
  'POST /v1/orgs/:p/scheduling/me/event-types',
  'PATCH /v1/orgs/:p/scheduling/me/event-types/:p',
  'PUT /v1/orgs/:p/scheduling/me/date-overrides/:p',
  'DELETE /v1/orgs/:p/scheduling/me/date-overrides/:p',
  'GET /v1/me/scheduling/upcoming',
  /*
   * CRM AI ASSIST. Session-only, and for a reason of its own rather than by
   * inheritance from the CRM block above.
   *
   * These routes generate advice for A PERSON to read, edit and act on, and
   * `crm_ai_suggestions` rows are PRIVATE TO THE HUMAN WHO REQUESTED THEM (see
   * that table's own header: a briefing is a projection of one viewer's
   * timeline visibility). An org API key authenticates a program, not a
   * person, so an autonomous caller generating briefings on a schedule would
   * be exactly the "AI acts on its own" shape this feature is built to avoid —
   * and would spend the org's AI budget with nobody to attribute it to.
   *
   * `cold-contacts` calls no model at all, but it is a customer-list read and
   * stays with its family rather than becoming the one CRM route a key can
   * walk.
   */
  'GET /v1/orgs/:p/crm/contacts/:p/ai/suggestions',
  'POST /v1/orgs/:p/crm/contacts/:p/ai/briefing',
  'POST /v1/orgs/:p/crm/contacts/:p/ai/followup-draft',
  'POST /v1/orgs/:p/crm/timeline/:p/ai/action-items',
  'POST /v1/orgs/:p/crm/ai/suggestions/:p/resolve',
  'GET /v1/orgs/:p/crm/ai/cold-contacts',
  // "Customers affected" reads CRM contact identity (names, emails, company)
  // off an issue. It is session-only for the same reason as the rest of the
  // family, and one reason of its own: it is the ONE CRM route reachable
  // through an /issues/ path, which an org key CAN otherwise reach, so leaving
  // it unclassified would have widened the key surface into customer PII by
  // accident rather than by decision.
  'GET /v1/issues/:p/crm/contacts',
  /*
   * MEETINGS — the upload ticket for a meeting recording
   * (`modules/uploads/routes.ts`).
   *
   * Session-only, and not by inheritance from the CRM block above: this route
   * mints a signed write into the org's storage bucket against a MEETING, and
   * resolving whether the caller may do that reads attendee identity — who was
   * in the room — which is the same class of data every route in this block is
   * kept away from org API keys for. `requireTimelineEntryUploadAccess` refuses
   * a key outright as well; this classification is what makes that a decision
   * rather than a duplicated assumption, and `api-key-allowlist.test.ts` fails
   * on any route left in neither list.
   *
   */
  'POST /v1/timeline-entries/:p/uploads',
  /*
   * MEETINGS — the calendar itself (`modules/meetings/routes.ts`).
   *
   * Session-only, all eight, and this is NOT inherited from the CRM block
   * above: these routes are gated on ORG MEMBERSHIP, not on a `crm:*`
   * permission, precisely so a free-plan org can book internal meetings
   * without the CRM entitlement. An org API key would therefore reach them
   * with nothing standing in its way, and what it would reach is:
   *
   *   * WHO IS IN A ROOM WITH WHOM, and when. The attendee list is the point
   *     of the feature and it is exactly the "who talks to whom" graph an org
   *     key has never been given anywhere else in this product.
   *   * FREE/BUSY FOR NAMED PEOPLE. `GET .../meetings/availability` reports
   *     every requested member's timezone, whether they have declared working
   *     hours, and the gaps between their commitments. That is a movement
   *     profile of an identified human being, assembled in one request.
   *   * CUSTOMER PII, when a meeting has a CRM contact attached — the same
   *     data the CRM block above is entirely about keeping away from keys.
   *   * A JOIN LINK. `conferencing_url` is a capability, not a label: whoever
   *     holds a Zoom or Meet URL can usually walk into the call.
   *
   * And on the write side, a key could book a real meeting into real people's
   * calendars and email them about it. GoodQA is agent-first and the default
   * in this file is ALLOW, so this is a deliberate carve-out with a reason,
   * not an oversight: an agent has no business scheduling humans (project
   * CLAUDE.md, "Let AI assign people or manage schedules" is a Never — "AI
   * advises; humans decide").
   */
  'GET /v1/orgs/:p/meetings',
  'POST /v1/orgs/:p/meetings',
  'GET /v1/orgs/:p/meetings/availability',
  'GET /v1/orgs/:p/meetings/:p',
  'PATCH /v1/orgs/:p/meetings/:p',
  'POST /v1/orgs/:p/meetings/:p/attendees',
  'DELETE /v1/orgs/:p/meetings/:p/attendees/:p',
  'POST /v1/orgs/:p/meetings/:p/cancel',
  /*
   * RSVP is session-only for a REASON OF ITS OWN, stronger than the eight
   * above rather than inherited from them.
   *
   * An RSVP is a FIRST-PERSON STATEMENT about whether a named human will be
   * somewhere. An org key answering on a member's behalf would be a machine
   * declaring a person's intentions to their colleagues — and, because
   * `declined` also frees that person's time in the availability maths, a
   * machine silently editing when a human can be booked. That is the exact
   * shape of "let AI manage schedules", which project CLAUDE.md lists under
   * Never.
   *
   * Note this route holds NO `crm:*` permission and no entitlement (answering
   * your own invitation is not a CRM write), so there is nothing else in the
   * stack that would stop a key. This entry is the whole gate.
   */
  'POST /v1/orgs/:p/meetings/:p/rsvp',
  'POST /v1/projects/:p/marketing/mailer/campaigns/:p/send-preview',
  // TASK-633B — project-defined ticket TYPES (modules/issue-types/routes.ts).
  // Eric's decision, 2026-09-01: "GET yes, writes no. Integrations may RESOLVE
  // a ticket's custom type; only humans define the vocabulary."
  //
  // The read half is allowlisted above (`GET /v1/projects/:p/issue-types`, which
  // also covers its HEAD twin) because an agent that cannot list the types
  // cannot set `issueTypeId` on an issue it files. These four are the DEFINING
  // half and stay human-only:
  //   * a type is project VOCABULARY, not a work item. Every issue in the
  //     project renders through it, pipelines scope themselves to it
  //     (`selectableIssueTypeKeysForProject`), and fields key off it
  //     (`assertIssueTypeKeysExist`) -- so an agent inventing or renaming one
  //     reshapes the meaning of data humans already filed.
  //   * DELETE is not merely destructive-but-confined, the carve-out the
  //     allowlist normally makes for everyday work: `deleteIssueTypeBodySchema`
  //     carries a REASSIGNMENT target and the handler rewrites every issue that
  //     carried the deleted type (`issuesWithCustomType` ->
  //     `applyCanonicalIssueUpdate`). One call silently re-types an unbounded
  //     set of existing tickets. That is a bulk edit of human-authored data
  //     wearing a delete's clothing.
  //   * reorder is the same vocabulary surface at a different verb; splitting it
  //     from the other three would leave a machine credential able to rewrite
  //     the picker every human sees.
  //
  // This is the same shape as `PUT /v1/projects/:p/categories/:p/role-access`
  // and the other category ACCESS routes already in this list: the reads are
  // reachable, the definitions are not. Widening any of these four is a
  // separate product call, not a classification sweep.
  'POST /v1/projects/:p/issue-types',
  'PATCH /v1/issue-types/:p',
  'DELETE /v1/issue-types/:p',
  'POST /v1/projects/:p/issue-types/reorder',

  /*
   * TASK-564's calendar-feed entries are NOT repeated here.
   *
   * Two lanes each added them, so `SESSION_ONLY_ROUTES` listed
   * `GET`/`POST /v1/me/calendar-feed` twice and `GET /v1/me/calendar.ics` in
   * BOTH this list and `NON_BEARER_ROUTES` -- which is what
   * `api-key-allowlist.test.ts`'s "classifies every route exactly once" was
   * failing on, on pristine `origin/main`, before this slice.
   *
   * The mint/rotate pair keeps the single entry in the `account credential`
   * group above, where its reasoning is. `GET /v1/me/calendar.ics` belongs to
   * `NON_BEARER_ROUTES` alone: it verifies its own purpose-scoped JWT and
   * never calls `app.authenticate`, so "session only" is not a claim it could
   * honour -- a calendar client fetching a subscribed feed has no session at
   * all. Neither list changes behaviour; both are the contract this file
   * states about routes, so a route in two of them states two contradictory
   * things.
   */

  /*
   * TASK-551 -- CRM CSV contact import.
   *
   * The whole CRM block above is session-only, and this is a bulk WRITE into
   * it: one request creates or updates up to 5,000 contacts and companies.
   * Nothing about it is safer than the single-contact `POST .../crm/contacts`
   * already listed there.
   */
  'POST /v1/orgs/:p/crm/contacts/import',

  /*
   * TASK-544 -- every ESP connection WRITE (the read is allowlisted above).
   *
   * `PUT` stores a provider credential in the vault; `DELETE` destroys it;
   * `validate` spends a real outbound call against it; the OAuth `start` is a
   * browser redirect that begins a human consent flow. This is the same
   * posture `GET/PUT /v1/orgs/:p/provider-keys` already has -- a machine
   * credential must not be able to install, exercise or revoke another
   * credential.
   */
  'PUT /v1/projects/:p/marketing/mailer/connections/:p',
  'DELETE /v1/projects/:p/marketing/mailer/connections/:p',
  'POST /v1/projects/:p/marketing/mailer/connections/:p/validate',
  'GET /v1/projects/:p/marketing/mailer/connections/constant_contact/oauth/start',

  /*
   * TASK-553 -- Design Studio image generation.
   *
   * The allowlist's own stated rule, at
   * `GET /v1/projects/:p/marketing/social/generated-media/:p`: reading
   * already-generated media is allowed because "issuing a new
   * generate-image/generate-video call is the expensive action and stays
   * SESSION_ONLY". This IS that call.
   */
  'POST /v1/projects/:p/studio/generate',
  // TASK-504/496 -- creating a conversation shell and posting a turn into
  // one. Posting a turn can dispatch a real, billed generation -- the exact
  // "issuing a new generate call" case the comment above this block already
  // states stays SESSION_ONLY; creating the (free) conversation container is
  // kept in the same bucket rather than splitting one authoring flow across
  // two auth tiers.
  'POST /v1/projects/:p/studio/conversations',
  'POST /v1/projects/:p/studio/conversations/:p/turns',

  /*
   * TASK-550 -- the platform-admin Zernio diagnostic.
   *
   * Reads the operator-managed workspace `ZERNIO_API_KEY`, not any tenant's
   * credential. A platform-admin console action, never a tenant machine one.
   */
  'GET /v1/admin/integrations/zernio',

  /*
   * Board #501 -- external content-request forms, the authoring half.
   *
   * Conservatively SESSION_ONLY rather than API-key-allowed: a form's
   * response data can carry an anonymous stranger's PII (an email, whatever
   * free text they wrote), and `destinations` can be reconfigured to create
   * issues in a different project -- the same sensitivity level TASK-527 drew
   * this exact line at for CRM contacts/companies above. Nothing in board
   * #501 asked for machine/integration access to forms; widen this
   * deliberately, not by default, if that need shows up later.
   */
  'GET /v1/orgs/:p/forms',
  'POST /v1/orgs/:p/forms',
  'GET /v1/orgs/:p/forms/:p',
  'PATCH /v1/orgs/:p/forms/:p',
  'POST /v1/orgs/:p/forms/:p/rotate-link',
  'GET /v1/orgs/:p/forms/:p/invites',
  'POST /v1/orgs/:p/forms/:p/invites',
  'POST /v1/orgs/:p/forms/:p/invites/:p/revoke',
  'POST /v1/orgs/:p/forms/:p/destinations',
  'PATCH /v1/orgs/:p/forms/:p/destinations/:p',
  'GET /v1/orgs/:p/forms/:p/responses',
  'GET /v1/orgs/:p/forms/:p/responses/export.csv',
  // AUD-005: same requireFormAndAccess gate as the response-reading routes
  // above -- an owner who may not see this response payload may not
  // manually retry its destination delivery either.
  'POST /v1/orgs/:p/forms/:p/responses/:p/deliveries/:p/retry',
  // TASK-506 -- Site Builder. Same "authoring surface, session-only through
  // and through, no read/write split" treatment as the forms block above --
  // whole-page/section AI generation is org-BYOK-billed and every other verb
  // here is an authoring or publish action, not routine automation work.
  'POST /v1/projects/:p/sites',
  'GET /v1/projects/:p/sites',
  'GET /v1/projects/:p/sites/:p',
  'GET /v1/projects/:p/sites/:p/versions',
  'GET /v1/projects/:p/sites/:p/deployments',
  'POST /v1/projects/:p/sites/:p/generate',
  'POST /v1/projects/:p/sites/:p/sections',
  'POST /v1/projects/:p/sites/:p/sections/:p/regenerate',
  'PATCH /v1/projects/:p/sites/:p/sections/:p/fields',
  'POST /v1/projects/:p/sites/:p/publish',
  'POST /v1/projects/:p/sites/:p/rollback',

  // Billboard (board #765) -- pin/lock/archive. Moderation/management-tier
  // actions: `billboard:pin`/`billboard:lock` have NO ownership escape hatch
  // at all (always the bundled admin/pm-tier permission, even on your own
  // post -- `apps/api/src/modules/billboard/access.ts`'s header), and
  // `billboard:archive` gates archiving someone else's post the same way
  // `comment:moderate` gates someone else's comment. Same tier as
  // `PATCH /v1/chat/conversations/:p` (channel rename/archive) directly
  // above in this list -- see the `API_KEY_ALLOWED_ROUTES` billboard block's
  // own comment for the everyday-work/moderation-tier split this follows.
  'POST /v1/orgs/:p/billboard/discussions/:p/archive',
  'POST /v1/orgs/:p/billboard/discussions/:p/unarchive',
  'PUT /v1/orgs/:p/billboard/discussions/:p/pin',
  'DELETE /v1/orgs/:p/billboard/discussions/:p/pin',
  'PUT /v1/orgs/:p/billboard/discussions/:p/lock',
  'DELETE /v1/orgs/:p/billboard/discussions/:p/lock',
  'POST /v1/orgs/:p/billboard/announcements/:p/archive',
  'POST /v1/orgs/:p/billboard/announcements/:p/unarchive',
  'PUT /v1/orgs/:p/billboard/announcements/:p/pin',
  'DELETE /v1/orgs/:p/billboard/announcements/:p/pin',
  'PUT /v1/orgs/:p/billboard/announcements/:p/lock',
  'DELETE /v1/orgs/:p/billboard/announcements/:p/lock',
  // --- PLAN S1b: the governance register (decide, confirm, sign-off, reject, rights, routing, the decision log) ---
  ...GOVERNANCE_REGISTER_SESSION_ONLY,
];

/**
 * Routes that never reach this plugin at all, so an API key is not a question
 * they can answer either way.
 *
 * This is a real third category and collapsing it into either list above would
 * be a false statement. A Stripe webhook is not "session only" -- no human
 * session reaches it either; it is authenticated by signature. Cron routes are
 * authenticated by `x-cron-token`. The OAuth start/callback pairs and the
 * public unsubscribe/invite-info routes are deliberately anonymous. Calling any
 * of these "session only" would tell a future reader they are protected by
 * something they are not protected by.
 *
 * Membership was established at runtime, not by naming convention: injecting a
 * credential-less request makes `app.authenticate` throw `noSession` (401
 * `no_session`) before it touches the database, so a route that answers
 * anything else does not pass through the bearer chokepoint. See
 * `apps/api/scripts/list-routes.ts` for the route enumeration this was built on.
 *
 * The anonymous login/native OAuth broker callbacks below have their own
 * provider-state proof; the Google Calendar connection callback is deliberately
 * absent because it now requires the returning user's live GoodQA session.
 * Adding a route here is a claim that it has its OWN auth story. Check that the
 * story exists.
 */
export const NON_BEARER_ROUTES: readonly string[] = [
  // Separate issuer-signed candidate ingestion; ordinary API keys are not authority.
  'POST /v1/work-delivery-acceptance/events',
  'GET /v1/public/learn/:p',
  'GET /v1/public/learn/:p/lessons/:p',
  'POST /v1/public/learn/:p/lessons/:p/complete',
  'GET /v1/public/l/:p',
  'HEAD /v1/public/l/:p',
  // Encapsulated hook validates exact bytes, signature, freshness and binding.
  'POST /v1/social-hooks/unipile-relay/:p',
  // Public legal reads and independently authenticated runner/daemon/webhook/cron routes.
  'POST /v1/runners/qac/usage',
  'POST /v1/agent-daemon/usage',
  'POST /v1/email/resend/webhook',
  'POST /v1/cron/reconcile-billing-money',
  'POST /v1/cron/qac-turn-sweep',
  'POST /v1/cron/qac-welcome-sweep',
  'GET /v1/legal/trust',
  'GET /v1/legal/current',
  'GET /v1/legal/documents/:p',

  // Cron preHandler verifies CRON_TOKEN before nightly conversation reviews.
  'POST /v1/cron/review-ollander-conversations',
  'POST /v1/cron/outreach-daily-digest',
  // Worker enrollment proves provider tags/IP once; lifecycle cron proves its scheduler token.
  'POST /v1/workers/bootstrap',
  'POST /v1/cron/workers-sweep',
  // GoodQA Connect (#433, dark: connect.sessions): a MACHINE credential header (`x-goodqa-daemon-token` today; the
  // Machines lane's peer kind adds its own) exchanges itself for a short agent link token and reads the sessions
  // addressed to that machine. Neither is a bearer route (connect/peer-kinds.ts authenticate()).
  'POST /v1/connect/agent/link-token',
  'GET /v1/connect/agent/sessions/:p',
  // QA Commander harness selection (dark): the HOST (model proxy, health service) with its own harness service token,
  // compared in constant time in modules/qa-commander-harness/routes.ts. Not a session, not an API key; token unset
  // (the default) = the unknown route's 404.
  'POST /v1/internal/qa-commander/harness/resolve',
  'POST /v1/internal/qa-commander/harness/due',
  'POST /v1/internal/qa-commander/harness/checks',
  'POST /v1/internal/qa-commander/harness/alert',
  // QA Commander private network (dark): the BRIDGE with its own service token (QA_COMMANDER_PRIVNET_SERVICE_TOKEN),
  // constant-time in modules/private-network/routes.ts. Token unset (the default) = the unknown route's 404.
  'POST /v1/internal/qa-commander/private-network/resolve',
  'POST /v1/internal/qa-commander/private-network/status',
  // GoodQA #442 emergency escalation provider webhooks: Twilio (X-Twilio-Signature, HMAC-SHA1 over the URL and params)
  // and the GoodQA voice relay (HMAC-SHA256 over timestamp.body, 5-minute window). The signature is the authority;
  // each answers the app's own 404 until its provider secret is configured and 403 to anything unsigned.
  // Telephony step 2 call webhooks: X-Twilio-Signature over the exact public URL + form params is the authority
  // (modules/phone/routes.ts). 404 with no TELEPHONY_PROVIDER, 403 unsigned or forged.
  'POST /v1/phone-hooks/twilio/:p',
  // Customer payments: the Stripe-Signature (HMAC-SHA256 over t.body, any configured secret, 5-minute window) is the
  // authority (modules/customer-payments/webhook.ts). 501 with no PAYMENTS_STRIPE_WEBHOOK_SECRETS, 400 unsigned/forged.
  'POST /v1/payments/stripe-webhook',
  'POST /v1/escalation-hooks/twilio/inbound',
  'POST /v1/escalation-hooks/twilio/status',
  'POST /v1/escalation-hooks/relay',
  // Discord integration (dark): the Discord BRIDGE (tools/discord-bridge) with its own service token, compared in
  // constant time in modules/discord/routes.ts. Not a session, not an API key; token unset (the default) = the unknown
  // route's 404.
  'POST /v1/internal/discord/pairings',
  'POST /v1/internal/discord/resolve',
  'POST /v1/internal/discord/claim',
  'POST /v1/internal/discord/inbound',
  'POST /v1/internal/discord/outbound',
  'POST /v1/internal/discord/guild-removed',
  // P51 Gmail connector: Google's OAuth redirect. No bearer of any kind: the signed one-time `state` is the
  // authorization, and the route is the app's own 404 until that state is proven (dark behind outreach.gmail).
  'GET /v1/outreach/gmail/callback',
  'POST /v1/outreach/gmail/callback',
  'HEAD /v1/outreach/gmail/callback',
  // Messenger + Instagram (docs/design/SOCIAL-INBOX-META.md), the app's own 404 until META_MESSAGING_ENABLED and the
  // Meta app credentials are set. OAuth redirect: the single-use state bound to the initiating browser's cookie is the
  // authority. Webhook: GET is Meta's verify-token handshake; POST is authorised by X-Hub-Signature-256 (HMAC-SHA256
  // of the exact body with the app secret), 403 unsigned or forged.
  'GET /v1/social/meta/oauth/callback',
  'GET /v1/social-hooks/meta',
  'POST /v1/social-hooks/meta',
  'POST /v1/social-hooks/zernio',
  // SEO data connectors: Google's OAuth redirect. No bearer: the signed state plus the still-pending request addressed
  // to the state's person is the authority; the app's own 404 while dark (seo.connectors) or unproven.
  'GET /v1/seo/connect/google/callback',
  'HEAD /v1/seo/connect/google/callback',
  // P51 one-click unsubscribe (RFC 8058): the recipient's mail client or browser. No bearer: the signed `ou1.` token
  // in the path is the authority; anything but a genuine token of an outreach-enabled org is the app's own 404.
  // Attachment sharing: an attachment share link. No bearer needed: the 256-bit `gqs_` token in the path is the
  // authority for a PUBLIC link; team/people/conversation links additionally read an optional session (never a key).
  // Unknown/revoked/expired tokens are the app's own 404, and the whole route is a 404 while `attachments.sharing` is off.
  'GET /v1/share/:p',
  'HEAD /v1/share/:p',
  'GET /v1/public/outreach/unsubscribe/:p',
  'GET /v1/public/reviews/:p',
  'GET /v1/public/reviews/:p/go/:p',
  'POST /v1/public/reviews/:p/feedback',
  'HEAD /v1/public/outreach/unsubscribe/:p',
  'POST /v1/public/outreach/unsubscribe/:p',
  // Microsoft Graph change notifications for Outlook Inboxes: Graph calls it with no bearer. The clientState (sha256
  // compared in constant time) and the subscription id are the authority; a validation token is echoed only while a
  // subscription is being created (outreach/outlook/subscriptions.ts).
  'POST /v1/outreach/outlook/notifications',
  'POST /v1/outreach/mailgun/webhooks/:p/:p',
  // Plan S2a: the box exchanges a one-time `gqe_` enrol token (its own credential, in the body) for a runner key.
  'POST /v1/runners/enrol',
  // Plan S2a: the Unreachable sweep, x-cron-token gated like every /v1/cron route.
  'POST /v1/cron/runners-unreachable-sweep',
  // Plan S3: the daemon redeems a one-time `gqc_` registration code (in the body) for its `gqd_` credential; polls
  // with `x-goodqa-daemon-token`; a run reports with its single-run `x-goodqa-run-token`. None is an API key or a
  // session, and none of the three opens any bearer route (agent-launch/service.ts).
  'POST /v1/agent-daemon/register',
  'GET /v1/agent-daemon/launches/next',
  'POST /v1/agent-runs/:p/start',
  'POST /v1/agent-runs/:p/heartbeat',
  'POST /v1/agent-runs/:p/events',
  'POST /v1/agent-runs/:p/complete',
  // Ticket #361: a managed host enrols itself (no bearer; bound to the provider's view of it: resource id, its own
  // tag, its public IP, inside its window), and the hosting sweep is x-cron-token gated like every /v1/cron route.
  'POST /v1/agent-hosts/enrol',
  'POST /v1/cron/agent-hosts-sweep',
  // GoodQA #430, Machines: the machine agent. Pairing redeems a one-time `gqmp_` code (in the body, proof of key
  // possession in the signature headers); every later call carries `x-goodqa-machine-token` AND an Ed25519 signature
  // over method, path, time, nonce and body (modules/machines/signing.ts). Not an API key, not a session; opens no
  // bearer route. The installers and the release pointer are public (the pairing code is the only authority); the
  // sweep is x-cron-token gated like every /v1/cron route.
  'POST /v1/machine-agent/pair',
  // Enrollment exchange (ENROLLMENT.md section 4): a one-time `gqmx_` secret or a `gqme_` machine token in the body,
  // proof of key possession in the signature headers, exactly as pair.
  'POST /v1/machine-agent/enroll',
  'POST /v1/machine-agent/browser-enroll',
  'GET /v1/machine-agent/commands/next',
  'GET /v1/machine-agent/browser-attachment/:p',
  'POST /v1/machine-agent/commands/:p/result',
  'POST /v1/machine-agent/commands/:p/stream',
  'POST /v1/machine-agent/artifacts',
  'POST /v1/machine-agent/heartbeat',
  'POST /v1/machine-agent/rotate',
  'POST /v1/machine-agent/unpair',
  'POST /v1/machine-agent/leases/end',
  // goodqa#8414: the agent signs the owner's presence challenge over its own channel (token + Ed25519 signature).
  'POST /v1/machine-agent/presence',
  'POST /v1/machine-agent/consent/report',
  'POST /v1/machine-agent/consent/answer',
  'GET /v1/machine-agent/update',
  'GET /v1/machine-agent/install.sh',
  'GET /v1/machine-agent/install.ps1',
  'GET /v1/machine-agent/release',
  'POST /v1/cron/machines-sweep',
  // GoodQA #442: the emergency-escalation ladder tick, x-cron-token gated like every /v1/cron route.
  'POST /v1/cron/escalation-tick',
  'GET /health',
  'GET /ready',
  'GET /v1/ready',
  // Mail half of readiness, split off /v1/ready so a provider blip cannot pull the API from rotation.
  'GET /ready/mail',
  'GET /v1/ready/mail',
  // AUD-028. Same operational-probe category as /health and /ready
  // immediately above -- release-identity, not a session or API-key surface.
  'GET /version',
  'GET /v1/version',
  'GET /v1/agents/unsubscribe',
  'GET /v1/auth/oauth/:p/callback',
  // Browser-first desktop bootstrap and request metadata are anonymous and
  // rate-limited; no account is selected until the cookie-authenticated
  // approval route. Cancel is protected by the exact WEB_ORIGIN + JSON check
  // and can only consume the caller's opaque, short-lived request id.
  'GET /v1/auth/oauth/desktop/start',
  'GET /v1/auth/oauth/desktop/request',
  'GET /v1/auth/oauth/:p/desktop/start',
  'GET /v1/auth/oauth/:p/extension/start',
  'GET /v1/auth/oauth/:p/mobile/callback',
  'GET /v1/auth/oauth/:p/mobile/start',
  'GET /v1/auth/oauth/:p/start',
  'GET /v1/auth/providers',
  'GET /v1/avatars/:p/:p',
  'GET /v1/cron/health',
  'GET /v1/cron/migration-state',
  'GET /v1/cron/webhook-dispatcher-state',
  'GET /v1/feature-cards/:p/screenshot.png',
  'GET /v1/invites/:p/info',
  'GET /v1/mcp/download',
  'GET /v1/claude-code/pack.zip',
  'GET /v1/claude-code/pack.sha256',
  'GET /v1/claude-code/manifest',
  /*
   * TASK-564 — the published ICS calendar feed. Deliberately anonymous, and
   * here is its own auth story, which is the claim membership of this list
   * makes.
   *
   * A calendar client cannot log in. Google, Outlook and Apple fetch a
   * subscribed feed unattended, with no cookie jar and no OAuth, so the URL
   * has to BE the credential. It carries a purpose-scoped HS256 JWT
   * (`purpose: 'calendar-ics-v1'`, `jwt.ts`) that this route verifies itself;
   * it never calls `app.authenticate`, so an API key is not a question this
   * route can answer either way. Same shape as `GET /v1/invites/:p/info` and
   * `GET /v1/notifications/unsubscribe`: a bearer capability URL for a caller
   * who has no session.
   *
   * What stops it being a worse `notifications/unsubscribe`: the token is not
   * merely signed, it is ANCHORED. Every fetch re-checks a dedicated
   * `sessions` row (revokedAt / expiresAt / `users.sessionsValidFrom`), so
   * rotating, revoking it from Active Sessions, or resetting the password all
   * kill an outstanding URL immediately rather than waiting out its 730-day
   * expiry. Its own two-tier rate limiting is in `feed-service.ts` and is
   * deliberately not IP-only, because provider polling shares egress IPs.
   * The GET entry covers its auto-registered HEAD twin.
   */
  'GET /v1/me/calendar.ics',
  // Public agent-skill discovery (2026-09-29): static text/markdown + a JSON index. No caller data,
  // no database; the skill itself tells agents how to authenticate everything else.
  'GET /v1/meta/agent-skill',
  'GET /v1/.well-known/agent-skills',
  'GET /.well-known/agent-skills',
  'GET /v1/meta/capabilities',
  // Agent discovery lane (2026-10-04): public, constant per deployment, no caller data, no database. The changelog,
  // the discovery document and MCP server card (and their API-root twins), and the error catalog.
  'GET /v1/changelog',
  'GET /v1/.well-known/goodqa',
  'GET /.well-known/goodqa',
  'GET /v1/.well-known/mcp',
  'GET /.well-known/mcp',
  'GET /v1/meta/errors',
  'GET /v1/meta/mcp',
  'GET /v1/meta/mcp-remote',
  'GET /v1/notifications/unsubscribe',
  'GET /v1/openapi.json',
  'GET /v1/org-deletion-exports/:p',
  'GET /v1/public/orgs/:p/brand',
  /*
   * SCHEDULING LINKS — the public booking page.
   *
   * Deliberately anonymous: the whole point is that an invitee needs no GoodQA
   * account. Adding a route here is a claim that it has its OWN auth story, so
   * here is this one's, in two halves.
   *
   * The three `/:linkSlug` routes are authorised by PUBLICATION, not by a
   * secret. The owner deliberately published the page; a slug is human-typeable
   * on purpose and is not treated as a credential anywhere. What a guessed slug
   * yields is the page the owner published — event names, durations, host
   * DISPLAY NAMES, and FREE time within the owner's own declared booking
   * window. It yields no event titles, no attendees, no busy intervals, no user
   * ids, no email addresses, and nothing outside that window.
   * `modules/scheduling/routes.ts`'s header enumerates the six enforcement
   * points; `apps/api/test/scheduling-public-privacy.test.ts` asserts them.
   *
   * The four `/bookings/:manageToken` routes are authorised by a 256-bit
   * `randomBytes` secret stored only as a SHA-256 digest
   * (`scheduling_bookings.manage_token_hash`, UNIQUE), delivered once in the
   * invitee's confirmation email. It authorises exactly one row; an unknown
   * token is the same 404 as a nonexistent booking. That is the same shape as
   * `GET /v1/invites/:p/info` and `GET /v1/notifications/unsubscribe` directly
   * above and below: a bearer capability URL for someone who has no account.
   */
  'GET /v1/public/scheduling/:p',
  'GET /v1/public/scheduling/:p/:p/slots',
  'POST /v1/public/scheduling/:p/:p/bookings',
  'GET /v1/public/scheduling/bookings/:p',
  'GET /v1/public/scheduling/bookings/:p/calendar.ics',
  'POST /v1/public/scheduling/bookings/:p/reschedule',
  'POST /v1/public/scheduling/bookings/:p/cancel',
  // Scheduling v1: a person's own page, /book/<org-slug>/<handle>. Authorised by publication exactly like the
  // link page above (it resolves to that person's link and answers the same public DTO); dark (404) unless the
  // org has `scheduling.enabled`.
  'GET /v1/public/scheduling/u/:p/:p',
  'GET /v1/public/scheduling/:p/:p/embed',
  'GET /v1/public/scheduling/embed.js',
  'GET /v1/public/scheduling/embed-client.js',
  'GET /v1/referrals/:p/info',
  'GET /v1/referrals/config',
  'GET /v1/slack/oauth/callback',
  // TASK-544: Constant Contact redirects the human's browser back here with
  // a code and the state we issued. No bearer is presented, exactly like the
  // Slack and OAuth callbacks above it.
  'GET /v1/marketing/mailer/connections/constant_contact/oauth/callback',
  'POST /v1/agents/unsubscribe',
  'POST /v1/auth/forgot-password',
  'POST /v1/auth/login',
  // Board #606: these anonymous passkey login ceremonies authenticate with a
  // server-stored, one-use WebAuthn challenge plus authenticator proof. They
  // cannot pass through the ordinary bearer chokepoint because they create the
  // user session, just like password/OAuth login directly around them.
  'POST /v1/auth/webauthn/login/options',
  'POST /v1/auth/webauthn/login/verify',
  'POST /v1/auth/oauth/apple/native',
  'POST /v1/auth/oauth/desktop/cancel',
  'POST /v1/auth/oauth/desktop/token',
  'POST /v1/auth/oauth/extension/token',
  'POST /v1/auth/oauth/mobile/token',
  'POST /v1/auth/refresh',
  'POST /v1/auth/resend-verification',
  'POST /v1/auth/reset-password',
  'POST /v1/auth/signup',
  'POST /v1/auth/verify-email',
  // Board #588: these two endpoints deliberately do not enter the ordinary
  // bearer chokepoint. Bootstrap consumption authenticates one exact,
  // hash-only one-use code; session inspection authenticates only the
  // purpose-scoped host cookie and rechecks its durable source-session anchor.
  // Both reject ordinary Authorization/API-key/browser-session credentials.
  'POST /v1/hosted/session/bootstrap',
  'GET /v1/hosted/session',
  'POST /v1/billing/webhook',
  // Board #503/#667: Sentry's error-monitor webhook. Same shape as
  // `POST /v1/billing/webhook` directly above -- it verifies its own HMAC
  // signature (`sentry-hook-signature`, keyed by `SENTRY_APP_CLIENT_SECRET`)
  // in `modules/federation/monitor-webhook.ts` and never calls
  // `app.authenticate`, so an API key or session is not a question this
  // route can answer either way.
  'POST /v1/sentry/webhook',
  'POST /v1/hooks/workflows/:p',
  // The CI hook callback. Authenticates with its own prefixed hook token in
  // `X-GoodQA-CI-Token`, never `app.authenticate`, so "session only" is not a
  // claim it could honour — a build runner has no session. Minting and revoking
  // that token is session-only, up in SESSION_ONLY_ROUTES.
  'POST /v1/ci/hooks/:p',
  'POST /v1/cron/archive-expired-issues',
  'POST /v1/cron/backfill-issue-embeddings',
  // #382 vector memory backfill and #381 coordinator stale-lane sweep: cron token, like every /cron route above.
  'POST /v1/cron/backfill-knowledge-embeddings',
  'POST /v1/cron/coordinator-stale-lanes',
  'POST /v1/cron/cleanup',
  // P51 slice G9: the outreach sequence worker. x-cron-token like every sibling; it only REQUESTS permits through
  // the gate (actor `system`) and skips any org without outreach.enabled + outreach.sequences.
  'POST /v1/cron/run-outreach-sequences',
  'POST /v1/cron/outreach-warmup-ramp',
  'POST /v1/cron/outreach-dnsbl-sweep',
  'POST /v1/cron/dispatch-agent-deliveries',
  'POST /v1/cron/dispatch-agent-chat-guard',
  // Board #745. Same cron-token-only shape as every sibling here --
  // resends a queued mobile-push retry, the SEND half of the
  // dispatch-mobile-push/reconcile-mobile-push-receipts pair right below.
  'POST /v1/cron/dispatch-mobile-push-deliveries',
  'POST /v1/cron/feature-cards',
  'POST /v1/cron/dispatch-agent-runs',
  // AUD-005 follow-up: the form-destination-delivery fast tick, same
  // cron-token-only shape as every sibling `/v1/cron/*` entry here.
  'POST /v1/cron/dispatch-form-destination-deliveries',
  // Signed outbound chat/comment webhooks: cron-token only like every sibling here.
  'POST /v1/cron/dispatch-webhook-deliveries',
  'POST /v1/cron/dispatch-intelligence-jobs',
  'POST /v1/cron/dispatch-notification-email-digests',
  // The meeting-reminder DM sweep. Cron-token only, like every sibling here.
  'POST /v1/cron/run-meeting-reminders',
  'POST /v1/cron/run-booking-reminders',
  'POST /v1/cron/dispatch-suggest-fix-runs',
  'POST /v1/cron/drain-acks',
  'POST /v1/cron/expire-plan-grants',
  'POST /v1/cron/poll-connections',
  'POST /v1/cron/process-referral-rewards',
  'POST /v1/cron/reap-agent-runs',
  'POST /v1/cron/reap-intelligence-jobs',
  'POST /v1/cron/reap-stale-site-deployments',
  'POST /v1/cron/reap-suggest-fix-runs',
  'POST /v1/cron/reconcile-agent-email-receipts',
  'POST /v1/cron/reconcile-intelligence-sources',
  'POST /v1/cron/reconcile-mobile-push-receipts',
  // Review Studio (plan Part 5.11). Same story as every other `/v1/cron/*`
  // entry: Cloud Scheduler authenticates with the shared `x-cron-token`
  // secret, checked by the module-level preHandler in cron/routes.ts.
  'POST /v1/cron/rebuild-review-projections',
  'POST /v1/cron/review-audit-sample',
  'POST /v1/cron/review-usage-rollup',
  'POST /v1/cron/expire-review-waivers-and-approvals',
  'POST /v1/cron/run-blocked-issue-reminders',
  'POST /v1/cron/run-crm-follow-up-reminders',
  'POST /v1/cron/run-crm-lifecycle-sla',
  'POST /v1/cron/poll-mailboxes',
  'POST /v1/cron/run-due-soon-issue-reminders',
  'POST /v1/cron/run-overdue-issue-reminders',
  'POST /v1/cron/run-reminders',
  // Board #644. Same story as every other /v1/cron/* entry: Cloud Scheduler
  // authenticates with the shared x-cron-token secret.
  'POST /v1/cron/run-message-reminders',
  'POST /v1/cron/run-schedules',
  'POST /v1/cron/run-triage-reminders',
  'POST /v1/cron/run-user-reminders',
  'POST /v1/cron/run-uptime-checks',
  // AI provider resilience (board request, 2026-09-23). Same cron-token-only
  // shape as every sibling `/v1/cron/*` entry here.
  'POST /v1/cron/check-ai-provider-health',
  'POST /v1/cron/send-feature-cards-digest',
  'POST /v1/cron/send-reports',
  'POST /v1/cron/send-triage-digest',
  'POST /v1/cron/sweep-expired-recordings',
  'POST /v1/github/webhook',
  'POST /v1/mcp/pair/poll',
  'POST /v1/mcp/pair/start',
  'POST /v1/notifications/unsubscribe',
  'POST /v1/slack/events',
  'POST /v1/slack/interactivity',

  /*
   * Board #501 -- the external content-request forms RESPONDENT surface.
   * `publicFormRoutes`/`publicFormUploadRoutes` (`modules/forms/routes.ts`)
   * carry no `app.authenticate` preHandler at all -- FORMS.md §8.1's rule,
   * quoted at the top of that file: an unauthenticated, token-authorized
   * surface can never share a router with routes that assume a session.
   * Every one of these is authorised by the form's own bearer token (the
   * public link or invite token, §4) or, for uploads, additionally by the
   * short-TTL submission ticket minted by `.../access` -- never by a cookie
   * or an org API key, so membership here is correct rather than a gap.
   */
  // Public-page tracking (docs/design/PUBLIC-TRACKING.md): the snippet on every public page. No session.
  'GET /v1/public/tracking/config',
  'POST /v1/public/tracking/view',
  'POST /v1/public/tracking/event',
  'POST /v1/public/forms/:p/access',
  'POST /v1/public/forms/i/:p/access',
  'POST /v1/public/forms/:p/submit',
  'POST /v1/public/forms/i/:p/submit',
  'POST /v1/public/forms/:p/uploads',
  'POST /v1/public/forms/i/:p/uploads',
  'POST /v1/public/forms/:p/uploads/:p/complete',
  'POST /v1/public/forms/i/:p/uploads/:p/complete',
  'PUT /v1/public/forms/uploads/:p/content',
];

/** Param names differ between routes (`:orgId`, `:issueId`); the shape does not. */
export function normalizeRoutePattern(path: string): string {
  // `::` is Fastify's escape for a LITERAL colon (`/decisions::batch` serves `/decisions:batch`). Without this the
  // param regex below would swallow `::batch` and every `/x::verb` route would normalise to the same `/x:p`, so an
  // allowlist entry for one verb would silently authorise every other (P51 slice C: batch create is key-reachable,
  // batch respond is not). Protect the literal colons first and keep them in the key as written (`::`), so an
  // allowlist entry is spelled exactly like the route it names.
  return path.replace(/::/g, '\u0000').replace(/:[^/]+/g, ':p').replace(/\u0000/g, '::');
}

const API_KEY_ALLOWED = new Map(
  API_KEY_ALLOWED_ROUTES.map(([entry, resources]) => {
    const [method, path] = entry.split(' ');
    return [
      `${method} ${normalizeRoutePattern(path!)}`,
      typeof resources === 'string' ? [resources] : resources,
    ] as const;
  }),
);

/**
 * Was: the two attachment-content reads shipped only with TASK-298's final
 * attachment gate, so `TASK_298_ATTACHMENT_FINAL_GATE_ENABLED=false` (the
 * current production phase) denied them to every API key.
 *
 * That coupling was wrong in both directions and is now removed.
 *
 * It denied more than it needed to: an API key acts on behalf of the human who
 * created it and is confined to one org, and a SESSION user could already read
 * exactly these bytes through exactly these routes in this same phase. The
 * gate did not protect the bytes; it only made the key's view inconsistent
 * with its own holder's. The practical result was that
 * `GET /issues/:id/attachments` returned a `url` field the very same
 * credential could not fetch — metadata describing a file precisely while the
 * content 403'd, which reads as a bug rather than a policy.
 *
 * And enabling it would have been the WRONG lever anyway: the flag's other
 * half makes storage reads fail-closed and generation-pinned
 * (`allowUnverifiedGeneration: !flag`, uploads/routes.ts:651,705). Turning it
 * on to grant key access would simultaneously REFUSE every legacy
 * generation-less attachment the backfill has not yet normalized — breaking
 * reads for everyone, including the sessions that work today.
 *
 * So: attachment reads are authorized like every other key-reachable route,
 * via `API_KEY_ALLOWED_ROUTES` and the `['issues','uploads']` resource
 * requirement, and the storage rollout phase remains an independent decision
 * about byte verification. Nothing here changes which BYTES are served or
 * whether generations are pinned.
 *
 * `requireAttachmentReadAccess` is unchanged and still runs: project
 * membership (never uploader identity), category scope resolved through the
 * BOUND user of a scoped key, and the completed-only filter in the final
 * phase.
 */
const TASK_298_FINAL_GATE_API_KEY_ROUTES = new Set<string>([]);

/** The allowlist, for the test that checks every entry is a real route. */
export const apiKeyAllowedRoutes = API_KEY_ALLOWED_ROUTES.map(([entry]) => entry);
/** Each allowlisted route with the key family it requires (read-only; tests pin a new route's family with it). */
export const API_KEY_ALLOWED_ROUTE_FAMILIES: ReadonlyMap<string, ApiKeyResourceRequirement> = new Map(API_KEY_ALLOWED_ROUTES);

export const RUNNER_KEY_KIND = 'runner';

/**
 * PLAN S0b / INV-K1 (docs/design/goodqa-agent-platform/PLAN.md section 1.3): every allowlisted route that writes a
 * release or its links, a sprint or its membership, a release gate or its verdict, or an issue decision.
 *
 *  - A RUNNER key gets 403 on every entry, in every mode of `governance.keyCarveout`. Not flagged.
 *  - Every other key: `carve_out` entries follow the flag (off = allowed, shadow = allowed + audit row,
 *    enforce = 403). `runner_only` entries (quorum respond) stay open to non-runner keys: a person answering a
 *    quorum question through their own client is a signal, never an effective governance decision.
 *
 * `governance-route-inventory.unit.test.ts` fails when an allowlisted write route that touches one of those tables
 * is not listed here, and when GOVERNANCE_EXEMPT_ROUTES names one that does. Add new writers HERE.
 */
export const GOVERNANCE_ROUTES: Readonly<Record<string, 'carve_out' | 'runner_only'>> = {
  'PATCH /v1/release-gates/:p': 'carve_out',
  'POST /v1/releases/:p/gates': 'carve_out',
  'POST /v1/projects/:p/releases': 'carve_out',
  'PATCH /v1/releases/:p': 'carve_out',
  'DELETE /v1/releases/:p': 'carve_out',
  'POST /v1/releases/:p/issues': 'carve_out',
  'DELETE /v1/releases/:p/issues/:p': 'carve_out',
  'POST /v1/projects/:p/release-mappings': 'carve_out',
  'PATCH /v1/release-mappings/:p': 'carve_out',
  'DELETE /v1/release-mappings/:p': 'carve_out',
  'POST /v1/projects/:p/release-stages': 'carve_out',
  'POST /v1/releases/:p/attachments': 'carve_out',
  'POST /v1/projects/:p/sprints': 'carve_out',
  'PATCH /v1/sprints/:p': 'carve_out',
  'POST /v1/sprints/:p/start': 'carve_out',
  'POST /v1/sprints/:p/complete': 'carve_out',
  'POST /v1/sprints/:p/cancel': 'carve_out',
  'PUT /v1/sprints/:p/capacity/:p': 'carve_out',
  'PUT /v1/sprints/:p/issues': 'carve_out',
  'DELETE /v1/sprints/:p/issues/:p': 'carve_out',
  'PATCH /v1/sprints/:p/issues/order': 'carve_out',
  'PATCH /v1/issues/:p/decision/decider': 'carve_out',
  'POST /v1/issues/:p/decision/answer': 'carve_out',
  'POST /v1/decisions/:p/respond': 'runner_only',
};

/**
 * PLAN S1b: the governance register's session-only routes (decide, confirm, sign-off, reject, rights, routing, and
 * the decision-log reads). They are NOT on API_KEY_ALLOWED_ROUTES, so GOVERNANCE_ROUTES (which classifies only
 * allowlisted routes) cannot hold them; they are registered HERE instead, and an API key of any kind (standard,
 * persona, user-scoped, runner) is refused on them before the allowlist is even consulted, so a later allowlist edit
 * cannot quietly open one. `governance-route-inventory.unit.test.ts` fails when a route registered in
 * modules/governance/routes.ts is neither the proposal route nor listed here, or when an entry here is allowlisted.
 */
export const GOVERNANCE_SESSION_ONLY_ROUTES: ReadonlySet<string> = new Set(GOVERNANCE_REGISTER_SESSION_ONLY);

export function isGovernanceSessionOnlyRoute(method: string, path: string): boolean {
  return GOVERNANCE_SESSION_ONLY_ROUTES.has(governanceRouteKey(method, path));
}

/**
 * Allowlisted write routes whose PATH looks governance-shaped but which write none of those tables, each with the
 * reason. The inventory test fails if any of these writes one; an exemption is never for a writer.
 */
export const GOVERNANCE_EXEMPT_ROUTES: Readonly<Record<string, string>> = {
  'POST /v1/orgs/:p/decisions': 'quorum CREATE: asks a question; writes decisions/decision_authorities, not an issue decision, and no answer',
  'POST /v1/orgs/:p/decisions::batch': 'quorum CREATE x25 (P51 slice C): asks questions; writes decisions/decision_authorities/decision_attachments, never an answer',
  'POST /v1/documents/:p/insert-decision': 'embeds a decision reference in a document body; writes documents only',
  'POST /v1/orgs/:p/outreach/work-items/:p/release': "lane G8: 'release' gives back an outreach work-item LEASE (not a product release); writes outreach_work_items only",
  'POST /v1/machine-leases/:p/release': "GoodQA #430: 'release' hands back a MACHINE LEASE (not a product release); writes machine_leases and audit_events only",
  'POST /v1/orgs/:p/migrations/ghl/:p/decisions': 'GHL W1: resolves one HighLevel migration source row (imported/skipped + note); writes ghl_migration_items only; runner keys refused by the route',
  'POST /v1/orgs/:p/migrations/ghl/:p/rebuild/decision': 'GHL W1: records a kept/dropped/undecided rebuild choice with the owner quote; writes ghl_migration_items metadata only, activates nothing; runner keys refused',
};

/**
 * Allowlisted routes that write a governed table only for some bodies, so the route stays open and the HANDLER
 * refuses a runner key on that branch. `POST /v1/projects/:p/issues` with `type: 'decision'` inserts the
 * issue_decisions row (issues/routes.ts); every other issue create is ordinary runner work.
 */
export const GOVERNANCE_BODY_CONDITIONAL_ROUTES: Readonly<Record<string, string>> = {
  'POST /v1/projects/:p/issues':
    "type: 'decision' creates an issue_decisions row and sprintPlacement writes sprint membership; the handler refuses a runner key on either",
};

function governanceRouteKey(method: string, path: string): string {
  return `${method === 'HEAD' ? 'GET' : method} ${normalizeRoutePattern(path)}`;
}

function governanceRouteClass(method: string, path: string): 'carve_out' | 'runner_only' | undefined {
  return GOVERNANCE_ROUTES[governanceRouteKey(method, path)];
}

export type GovernanceKeyCarveoutMode = 'off' | 'shadow' | 'enforce';

/** Anything other than `shadow` or `enforce` reads as `off`: today's behaviour, never a silent partial state. */
export async function governanceKeyCarveoutMode(db: Parameters<typeof getPlatformSetting>[0]): Promise<GovernanceKeyCarveoutMode> {
  const value = await getPlatformSetting(db, 'governance.keyCarveout');
  return value === 'shadow' || value === 'enforce' ? value : 'off';
}

/**
 * The non-runner half of INV-K1's mode table, shared by the preHandler (every `carve_out` route) and by a
 * body-conditional handler (`POST /v1/projects/:p/issues` with `type: 'decision'` or `sprintPlacement`, which
 * writes a governed table only for those bodies, review fix S0b #1): `off` allows, `shadow` allows and writes one
 * `api_key.governance_route_shadow` audit row, `enforce` is 403. Callers decide WHETHER the request is governed
 * and never call this for a session; a runner key is refused before it ever gets here.
 */
export async function applyGovernanceKeyCarveout(
  db: Parameters<typeof getPlatformSetting>[0],
  ctx: AuthContext,
  routeKey: string,
): Promise<void> {
  const mode = await governanceKeyCarveoutMode(db);
  if (mode === 'enforce') {
    throw Errors.forbidden(
      'This route is session-only for API keys (governance.keyCarveout). A person does this in a signed-in session.',
    );
  }
  if (mode === 'shadow' && ctx.userTokenId && !ctx.apiKeyId) {
    // USER TOKENS (review round 1, finding 3): a token is held to the same carve-out as a non-runner key. Its shadow
    // row is the OWNER's (a token acts as its owner; the audit stamp adds via_user_token_id) and names the token.
    await db.insert(auditEvents).values({
      scope: 'platform',
      actorKind: 'user',
      actorId: ctx.userId,
      action: 'user_token.governance_route_shadow',
      targetKind: 'user_token',
      targetId: ctx.userTokenId,
      changes: { route: routeKey, mode },
    });
  } else if (mode === 'shadow') {
    await db.insert(auditEvents).values({
      scope: 'tenant',
      orgId: ctx.apiKeyOrgId ?? null,
      actorKind: 'api_key',
      actorId: ctx.apiKeyId ?? null,
      actingPersonaId: ctx.apiKeyPersonaId ?? null,
      onBehalfOfUserId: ctx.userId,
      action: 'api_key.governance_route_shadow',
      targetKind: 'api_key',
      targetId: ctx.apiKeyId ?? null,
      changes: { route: routeKey, mode },
    });
  }
}

/**
 * The string these rules are matched against MUST be the one the router itself
 * dispatched on, not the raw request target.
 *
 * find-my-way percent-decodes the path before matching, so authorizing on
 * `req.url` let a single encoded character desynchronize the guard from the
 * router: `/v1/%61ccount/sessions` matched no rule here, yet still dispatched to
 * the `/v1/account/sessions` handler. Every rule was bypassable that way —
 * including minting API keys from an API key, and setting a password on an
 * OAuth-only account (which needs no current password), i.e. full account
 * takeover from a leaked integration token.
 *
 * `req.routeOptions.url` is the matched route PATTERN (`/v1/orgs/:orgId/...`),
 * so it cannot be influenced by the client's encoding at all.
 */
function apiKeyRouteResources(method: string, path: string): readonly ApiKeyResource[] | undefined {
  const normalized = normalizeRoutePattern(path);
  // HEAD wherever GET is allowed: it is the same read, without the body.
  const effective = method === 'HEAD' ? 'GET' : method;
  return API_KEY_ALLOWED.get(`${effective} ${normalized}`);
}

function requiresTask298FinalGate(method: string, path: string): boolean {
  const effective = method === 'HEAD' ? 'GET' : method;
  return TASK_298_FINAL_GATE_API_KEY_ROUTES.has(
    `${effective} ${normalizeRoutePattern(path)}`,
  );
}

/**
 * Does this key's scope list confine it to particular resource families?
 *
 * A key with none keeps its legacy coverage except explicit route opt-ins. One that names at least one
 * family is held to those families — which is what lets an integration that only
 * files bug reports be unable to spend AI budget or open pull requests.
 */
function missingApiKeyResources(
  scopes: readonly string[],
  resources: readonly ApiKeyResource[],
  method: string,
  path: string,
): ApiKeyResource[] {
  const named = scopes.filter((s) => (API_KEY_RESOURCES as readonly string[]).includes(s));
  if (resources.length === 3 && resources.includes('artifacts') && resources.includes('chat') && resources.includes('issues')) return named.length === 0 || resources.some(r => named.includes(r)) ? [] : ['artifacts'];
  if (`${method === 'HEAD' ? 'GET' : method} ${normalizeRoutePattern(path)}` === 'GET /v1/agent-files/status') return ['uploads', 'chat', 'notes_to_self'].some(family => apiKeyResourceAllowed(scopes, family)) ? [] : ['uploads'];
  return resources.filter((resource) => !apiKeyResourceAllowedForRoute(scopes, resource, method, path));
}

/**
 * Families a key reaches ONLY by naming them: "no family" (unrestricted, the default for every new key,
 * and so for every chat/persona key) does not include them. `data` is the org's SQL surface (custom data,
 * D2 fix lane review finding 7): a leaked chat key must not be a SQL principal.
 */
// `escalation` (#442): a key reaches paging only by NAMING the family; a key with no families never wakes anyone.
export const EXPLICIT_ONLY_API_KEY_RESOURCES: ReadonlySet<string> = new Set(['roadmap_suggestions', 'data', 'agent_launch', 'machines', 'escalation', 'project_memory', 'memory', 'work', 'usage:write', 'ghl_history_reader']);

/**
 * GoodQA #430, Machines (review round 1, finding 6): `machines` is explicit-only for BOT keys -- an org key or a persona
 * key that names no family does not reach people's computers. The one exception is the person's OWN personal key (a
 * standard key, no persona, scoped to its creator): it is the person, the "maxed owner mode" key on their own machines
 * (modules/machines/access.ts isPersonalPrincipal), so it reaches the family without naming it.
 */
export function apiKeyReachesMachines(
  ctx: Pick<AuthContext, 'apiKeyId' | 'apiKeyScopes' | 'apiKeyKind' | 'apiKeyPersonaId' | 'apiKeyScopedToUserId' | 'userId' | 'userTokenId' | 'apiKeyCreatedByUserTokenId'>,
): boolean {
  // Review rva, finding 1: a user token has no key id, but it is not a session -- it never reaches machines (nor gets
  // the machine MCP tools).
  if (ctx.userTokenId) return false;
  if (!ctx.apiKeyId) return true;
  if (apiKeyResourceAllowed(ctx.apiKeyScopes ?? [], 'machines')) return true;
  const named = (ctx.apiKeyScopes ?? []).some((s) => (API_KEY_RESOURCES as readonly string[]).includes(s));
  return (
    !named &&
    // ... and a key minted through a user token is never the person's own personal key (it names the family or nothing).
    !ctx.apiKeyCreatedByUserTokenId &&
    (ctx.apiKeyKind ?? 'standard') === 'standard' &&
    !ctx.apiKeyPersonaId &&
    ctx.apiKeyScopedToUserId !== undefined &&
    ctx.apiKeyScopedToUserId === ctx.userId
  );
}

/**
 * Security review batch5 round 2, R2-F1: what a USER-SCOPED key (`api_keys.scoped_to_user_id`, "confine this bot to
 * one member") may do in each family. Such a key otherwise authorises as its CREATOR (board #37's design for ordinary
 * routes), so on a family whose handlers check the creator's org permissions it would act with the creator's
 * authority: send from the creator's mailbox, trip the org kill switch, read the whole CRM. The vault, secret
 * requests and agent knowledge each refused it in their own handlers; outreach and CRM v2 did not, which is the gap.
 *
 * ONE table, checked ONCE below for every key request, so a route added to a refused family later is refused without
 * anyone remembering to. Every family MUST declare a policy (the Record type makes a missing one a compile error), and
 * the `R2-F1: route inventory` describe in `apps/api/test/outreach-security-fix2.test.ts` walks every registered route in
 * the new families and fails for any that is key-reachable without landing in a `refused` family (or in USER_SCOPED_KEY_ALLOWED_ROUTES, with a reason).
 * Those families also authenticate in `preValidation`, before their schemas run, so an anonymous caller is 401 rather
 * than a 400 (`apps/api/test/auth-before-validation.test.ts`).
 * `allowed` keeps today's behaviour; a family is opened to scoped keys only by a deliberate edit here.
 */
export const USER_SCOPED_KEY_FAMILY_POLICY: Readonly<Record<ApiKeyResource, 'allowed' | 'refused'>> = Object.freeze({
  ghl_history_reader: 'refused',
  roadmap_suggestions: 'refused',
  work: 'refused',
  issue_types: 'refused',
  command_center: 'refused',
  work_dashboard: 'refused',
  orgs: 'allowed',
  projects: 'allowed',
  issues: 'allowed',
  testing: 'allowed',
  uploads: 'allowed',
  ai: 'allowed',
  github: 'allowed',
  decisions: 'allowed',
  mcp: 'allowed',
  agent_memory: 'allowed',
  project_memory: 'refused',
  context_memory: 'refused',
  vault: 'refused',
  artifacts: 'allowed',
  documents: 'allowed',
  surface: 'allowed',
  notifications: 'allowed',
  agents: 'allowed',
  chat: 'allowed',
  stats: 'allowed',
  marketing: 'allowed',
  experience_reviews: 'allowed',
  deploy: 'allowed',
  invites: 'allowed',
  cms: 'allowed',
  billboard: 'allowed',
  crm: 'refused',
  runner: 'refused',
  data: 'refused',
  agent_knowledge: 'refused',
  // Narrow user-scoped keys must not inherit the creator's shared memory or private-source audiences.
  memory: 'refused',
  usage: 'refused',
  'usage:write': 'refused',
  escalation: 'refused',
  outreach: 'refused',
  // Native mail uses a separate durable identity per key and explicit inbox grants, never the creator's mailbox.
  mail: 'allowed',
  // Plan S3: a user-scoped key would read and cancel launches with its creator's authority. Refused.
  agent_launch: 'refused',
  // GoodQA #430: a user-scoped key acts only as the member it is scoped to; when that member is the key's own creator
  // it is the "maxed owner mode" personal key on their own machines, otherwise it needs its own grant like any key.
  machines: 'allowed',
  // THE ONE FAMILY A USER-SCOPED KEY IS MEANT FOR (Eric, 2026-10-03, "DMing myself to share files and notes across
  // machines"): a personal key pushing a note or a file from another machine. 'allowed' here is necessary but not
  // sufficient -- the module refuses every key that is not the caller's OWN self-scoped standard key, so an admin's
  // key scoped to a member (which authenticates as the admin) can never read that member's notes.
  notes_to_self: 'allowed',
});

/**
 * Key-reachable routes under the new families' paths that a user-scoped key may still use although they are not in a
 * refused family, each with its reason. Empty today; the inventory test reads it.
 */
export const USER_SCOPED_KEY_ALLOWED_ROUTES: Readonly<Record<string, string>> = Object.freeze({
  // Attachment sharing (uploads family, `allowed`): a user-scoped key acts only for its member. The handlers refuse it
  // any file its member did not upload (404), any link but a `users` link naming exactly its member, and any public
  // link (every key is refused public links). Listing/revoking/showing links is limited to links its member created.
  'POST /v1/attachments/:p/shares': 'own files only; a users-scope link naming only its member (handler-enforced)',
  'GET /v1/attachments/:p/shares': 'own files only; lists only links its member created',
  'GET /v1/attachment-shares/:p/link': 'only links its member created',
  'POST /v1/attachment-shares/:p/revoke': 'only links its member created (revoking only ever tightens)',
  'POST /v1/attachments/:p/forward': 'own files only, into conversations its member can read (handler-enforced)',
});

/** The families a user-scoped key is refused on, for this route's resource list (empty: allowed). */
export function userScopedKeyRefusedFamilies(resources: readonly string[], method = '', path = ''): string[] {
  const route = `${method === 'HEAD' ? 'GET' : method} ${normalizeRoutePattern(path)}`;
  const draft = SANITY_SCOPED_DRAFT_ROUTES.has(route);
  const setup = SANITY_SCOPED_SETUP_ROUTES.has(route);
  return resources.filter((r) => USER_SCOPED_KEY_FAMILY_POLICY[r as ApiKeyResource] !== 'allowed' && !(draft && r === 'crm') && !(setup && r === 'vault'));
}

/** The route's API-key resource families (normalized lookup), or undefined when no key may reach it. For tests. */
export function apiKeyResourcesForRoute(method: string, path: string): readonly string[] | undefined {
  return apiKeyRouteResources(method, path);
}

/**
 * The families this API key lacks for ANOTHER route's act that a handler performs inline (empty: allowed). Comment
 * create with `attachmentIds` does exactly what `POST /v1/issues/:p/comments/:p/attachments` does, so it must hold the
 * key to that route's registered grant -- derived from the same allowlist entry, so the two cannot drift. Fails CLOSED:
 * a route no key may reach answers `['route']`, never empty.
 */
export function apiKeyMissingFamiliesForRoute(
  ctx: Pick<AuthContext, 'apiKeyScopes' | 'apiKeyScopedToUserId'>,
  method: string,
  path: string,
): string[] {
  const resources = apiKeyRouteResources(method, path);
  if (!resources) return ['route'];
  const missing: string[] = missingApiKeyResources(ctx.apiKeyScopes ?? [], resources, method, path);
  const refused = ctx.apiKeyScopedToUserId ? userScopedKeyRefusedFamilies(resources, method, path) : [];
  return [...new Set([...missing, ...refused])];
}

export function apiKeyResourceAllowed(scopes: readonly string[], resource: string): boolean {
  const named = scopes.filter((s) => (API_KEY_RESOURCES as readonly string[]).includes(s));
  return named.length === 0 ? !EXPLICIT_ONLY_API_KEY_RESOURCES.has(resource) : named.includes(resource);
}

/** Route-specific opt-ins share the same policy between authorization and generated access documentation. */
export const API_KEY_EXPLICIT_RESOURCE_ROUTE_POLICY: Readonly<Record<string, readonly string[]>> = Object.freeze({
  'GET /v1/roadmap': ['issues'],
  'POST /v1/projects/:p/roadmap/:p/ticket-proposal': ['issues'],
});

export function apiKeyResourceAllowedForRoute(scopes: readonly string[], resource: string, method: string, path: string): boolean {
  const route = `${method === 'HEAD' ? 'GET' : method} ${normalizeRoutePattern(path)}`;
  if (API_KEY_EXPLICIT_RESOURCE_ROUTE_POLICY[route]?.includes(resource) && !scopes.includes(resource)) return false;
  return apiKeyResourceAllowed(scopes, resource);
}

/** Roadmap agents opt in per key without changing flag-off resource grant schemas. */
export function apiKeyReachesRoadmap(
  auth: Pick<AuthContext, 'apiKeyId' | 'apiKeyOrgId' | 'apiKeyScopes' | 'apiKeyKind' | 'apiKeyScopedToUserId' | 'userTokenId'>,
): boolean {
  return Boolean(auth.apiKeyId && auth.apiKeyOrgId && !auth.userTokenId && auth.apiKeyKind !== 'runner' &&
    !auth.apiKeyScopedToUserId && auth.apiKeyScopes?.includes('issues'));
}

/**
 * USER TOKENS (review round 1, finding 3): may an org API key reach this route at all? The user-token gate refuses a
 * token wherever this is false, unless lib/user-token-policy.ts names the route explicitly -- so every route that
 * refuses an API key refuses a token too, and a route added to SESSION_ONLY_ROUTES later is refused to tokens without
 * anyone remembering to.
 */
export function isApiKeyReachableRoute(method: string, path: string): boolean {
  return apiKeyRouteResources(method, path) !== undefined;
}

/**
 * USER TOKENS (review round 1, finding 2): every allowlisted route an org API key with these scopes could reach, for
 * the mint-chain ceiling of a key minted through a user token (modules/api-keys/user-token-ceiling.ts). Deliberately an
 * OVER-approximation: a key that names no family is counted as reaching the explicit-only families too (a persona
 * binding can open `data` to it later, and the token cannot see that coming), and a key without `write` reaches only
 * the reads. Never used to authorize a key -- the real checks above do that.
 */
export function apiKeyRoutesReachableWithScopes(scopes: readonly string[]): Array<{ method: string; path: string }> {
  const named = scopes.filter((s) => (API_KEY_RESOURCES as readonly string[]).includes(s));
  const canWrite = scopes.length === 0 || scopes.includes('write');
  const out: Array<{ method: string; path: string }> = [];
  for (const [key, resources] of API_KEY_ALLOWED) {
    const [method, path] = key.split(' ') as [string, string];
    if (!canWrite && !isReadOnlyApiKeyRoute(method, path)) continue;
    if (named.length > 0 && missingApiKeyResources(scopes, resources, method, path).length > 0) continue;
    out.push({ method, path });
  }
  return out;
}

/** The per-org entitlement that opens the `crm` key family (owner decision Q3). */
export const CRM_API_KEY_FLAG = 'crm.api.enabled' as const;

/** #381: the per-org entitlement that opens the coordinator routes and tools (dark by default). */
export const COORDINATOR_FLAG = 'coordinator.bootstrap' as const;

/** The per-org entitlement that opens the `agent_knowledge` family and its session routes (approved default 8). */
export const AGENT_KNOWLEDGE_FLAG = 'agentKnowledge.enabled' as const;
/** P51 slice A: a key reaches the `outreach` family only when the org has BOTH (the module, and keys into it). */
export const OUTREACH_API_KEY_FLAGS = ['outreach.enabled', 'outreach.api.enabled'] as const;

/** Every outreach route a key could aim at, key-allowed or session-only (normalized `METHOD /v1/...:p` form). */
export const OUTREACH_DARK_ROUTES: ReadonlySet<string> = new Set([
  'POST /v1/orgs/:p/projects/:p/social-connectors/week-handoffs',
  'GET /v1/orgs/:p/projects/:p/social-connectors',
  'POST /v1/orgs/:p/projects/:p/social-connectors/bindings/:p/operations/:p/readback',
  'GET /v1/orgs/:p/projects/:p/marketing/social/weeks',
  'POST /v1/orgs/:p/projects/:p/marketing/social/weeks',
  'POST /v1/orgs/:p/projects/:p/marketing/social/weeks/preparations',
  'GET /v1/orgs/:p/projects/:p/marketing/social/weeks/:p/preparation',
  'POST /v1/orgs/:p/projects/:p/marketing/social/weeks/:p/preparation/advance',
  'POST /v1/orgs/:p/projects/:p/marketing/social/weeks/:p/preparation/stop',
  'GET /v1/orgs/:p/projects/:p/marketing/social/weeks/media',
  'GET /v1/orgs/:p/projects/:p/marketing/social/weeks/targets',
  'GET /v1/orgs/:p/projects/:p/marketing/social/weeks/:p',
  'GET /v1/orgs/:p/projects/:p/marketing/social/weeks/:p/calendar',
  'PATCH /v1/orgs/:p/projects/:p/marketing/social/weeks/:p/posts/:p/channels/:p',
  'POST /v1/orgs/:p/projects/:p/marketing/social/weeks/:p/request-review',
  'POST /v1/orgs/:p/projects/:p/marketing/social/weeks/:p/approve',
  'GET /v1/orgs/:p/outreach/projects/:p/daily-routine',
  'POST /v1/orgs/:p/outreach/projects/:p/daily-routine/batch',
  'POST /v1/orgs/:p/outreach/projects/:p/daily-routine/drafts',
  'GET /v1/orgs/:p/outreach/report',
  'GET /v1/orgs/:p/outreach/audit',
  'POST /v1/orgs/:p/outreach/linkedin-browser/commands/:p/preflight',
  'GET /v1/orgs/:p/steve-desk',
  'GET /v1/orgs/:p/steve-desk/page',
  'POST /v1/orgs/:p/steve-desk/snapshot',
  'POST /v1/orgs/:p/steve-desk/actions',
  'GET /v1/orgs/:p/outreach/projects/:p/replies',
  'PUT /v1/orgs/:p/outreach/projects/:p/reply-rules',
  'POST /v1/orgs/:p/outreach/projects/:p/materials',
  'PUT /v1/orgs/:p/outreach/projects/:p/deals/:p/order-terms',
  'POST /v1/orgs/:p/outreach/projects/:p/deals/:p/order-draft',
  'POST /v1/orgs/:p/outreach/projects/:p/replies/:p/approve',

  'GET /v1/orgs/:p/outreach/pipeline',
  'GET /v1/orgs/:p/outreach/conversations',
  'GET /v1/orgs/:p/outreach/queue',
  'POST /v1/orgs/:p/outreach/pipeline/defaults',
  'GET /v1/orgs/:p/outreach/template-library',
  'PUT /v1/orgs/:p/outreach/template-library',
  'POST /v1/orgs/:p/outreach/template-preview',
  'POST /v1/orgs/:p/outreach/suppressions',
  'GET /v1/orgs/:p/outreach/suppressions/check',
  'GET /v1/orgs/:p/outreach/suppressions',
  'DELETE /v1/orgs/:p/outreach/suppressions/:p',
  'GET /v1/orgs/:p/outreach/config',
  'GET /v1/orgs/:p/outreach/deliverability',
  'POST /v1/orgs/:p/outreach/route',
  'POST /v1/orgs/:p/outreach/domains/:p/resume',
  'POST /v1/orgs/:p/outreach/domains/:p/dnsbl-check',
  'POST /v1/orgs/:p/outreach/config/trip',
  'PATCH /v1/orgs/:p/outreach/config',
  'DELETE /v1/orgs/:p/crm/contacts/:p',
  // G13 / G15 / G17
  'GET /v1/orgs/:p/outreach/placements',
  'POST /v1/orgs/:p/outreach/placements',
  'GET /v1/orgs/:p/outreach/placements/:p',
  'PATCH /v1/orgs/:p/outreach/placements/:p',
  'POST /v1/orgs/:p/outreach/drafts/blog-posts',
  'PATCH /v1/orgs/:p/outreach/drafts/blog-posts/:p',
  'POST /v1/orgs/:p/outreach/drafts/social-posts',
  'PATCH /v1/orgs/:p/outreach/drafts/social-posts/:p/channels/:p',
  'POST /v1/orgs/:p/outreach/drafts/cms-documents',
  'PATCH /v1/orgs/:p/outreach/drafts/cms-documents/:p',
  'POST /v1/orgs/:p/outreach/drafts/mailer-leads',
  'GET /v1/orgs/:p/outreach/legal-holds',
  'POST /v1/orgs/:p/outreach/legal-holds',
  'DELETE /v1/orgs/:p/outreach/legal-holds/:p',
  // slice D
  'POST /v1/orgs/:p/outreach/permits',
  'POST /v1/orgs/:p/outreach/permits/:p/confirm',
  'POST /v1/orgs/:p/outreach/permits/:p/abandon',
  'GET /v1/orgs/:p/outreach/templates',
  'GET /v1/orgs/:p/outreach/templates/:p',
  'GET /v1/orgs/:p/outreach/templates/:p/stats',
  'POST /v1/orgs/:p/outreach/contacts/:p/email-source',
  'GET /v1/orgs/:p/outreach/policy',
  'POST /v1/orgs/:p/outreach/policy/tighten',
  'POST /v1/orgs/:p/outreach/contacts/:p/basis',
  'POST /v1/orgs/:p/outreach/templates',
  'POST /v1/orgs/:p/outreach/templates/:p/versions',
  'PATCH /v1/orgs/:p/outreach/templates/:p/versions/:p',
  'POST /v1/orgs/:p/outreach/templates/:p/versions/:p/approve',
  'POST /v1/orgs/:p/outreach/templates/:p/versions/:p/retire',
  'GET /v1/orgs/:p/outreach/ledger',
  // P51 outreach slice G7 (dark also behind `outreach.webhooks`, checked in the handlers).
  'POST /v1/orgs/:p/outreach/webhook-subscriptions',
  'GET /v1/orgs/:p/outreach/webhook-subscriptions',
  'DELETE /v1/orgs/:p/outreach/webhook-subscriptions/:p',
  // slice G9
  'POST /v1/orgs/:p/outreach/sequences',
  'GET /v1/orgs/:p/outreach/sequences',
  'GET /v1/orgs/:p/outreach/sequences/:p',
  'GET /v1/orgs/:p/outreach/sequences/:p/enrolments',
  'GET /v1/orgs/:p/outreach/sequences/:p/readiness',
  'POST /v1/orgs/:p/outreach/sequences/:p/start',
  'POST /v1/orgs/:p/outreach/sequences/:p/pause',
  'POST /v1/orgs/:p/outreach/sequences/:p/enrolments',
  'GET /v1/orgs/:p/outreach/enrolments/:p',
  'POST /v1/orgs/:p/outreach/enrolments/:p/pause',
  'POST /v1/orgs/:p/outreach/enrolments/:p/cancel',
  'POST /v1/orgs/:p/outreach/enrolments/:p/resume',
  'POST /v1/orgs/:p/outreach/enrolments/:p/events',
  'POST /v1/orgs/:p/outreach/enrolments/:p/steps/:p/approve',
  // BYO sender (also needs outreach.byo: OUTREACH_BYO_ROUTES)
  'GET /v1/orgs/:p/outreach/send-intents',
  'POST /v1/orgs/:p/outreach/events/reported',
  'POST /v1/orgs/:p/outreach/manual-sends',
  'GET /v1/orgs/:p/outreach/external-senders/:p',
  'PUT /v1/orgs/:p/outreach/external-senders/:p',
  // LinkedIn account registry (also needs outreach.linkedin: OUTREACH_LINKEDIN_ROUTES)
  'GET /v1/orgs/:p/outreach/linkedin/accounts',
  'POST /v1/orgs/:p/outreach/linkedin/accounts',
  'DELETE /v1/orgs/:p/outreach/linkedin/accounts/:p',
  // Gmail connector
  'GET /v1/orgs/:p/outreach/gmail/authorize',
  'GET /v1/orgs/:p/outreach/gmail/connection',
  'DELETE /v1/orgs/:p/outreach/gmail/connection',
  'POST /v1/orgs/:p/outreach/gmail/connection/resume',
  'POST /v1/orgs/:p/outreach/gmail/connection/check',
  'DELETE /v1/orgs/:p/outreach/gmail/connections/:p',
  'POST /v1/orgs/:p/outreach/gmail/connections/:p/check',
  'PUT /v1/orgs/:p/outreach/gmail/connections/:p/calendar-default',
  'PUT /v1/orgs/:p/outreach/gmail/agent-scopes/:p',

  'POST /v1/orgs/:p/outreach/sends/:p/deliver',
  // Microsoft 365 connector (also dark behind outreach.outlook)
  'POST /v1/orgs/:p/outreach/outlook/connect',
  'GET /v1/outreach/outlook/callback',
  'GET /v1/orgs/:p/outreach/outlook/mailbox',
  'DELETE /v1/orgs/:p/outreach/outlook/mailbox',
  'POST /v1/orgs/:p/outreach/outlook/mailbox/resume',
  'POST /v1/orgs/:p/outreach/outlook/sends/:p/deliver',
  // Calendar consent and host binding are human actions, separate from mailbox OAuth.
  'GET /v1/orgs/:p/scheduling/zoho',
  'POST /v1/orgs/:p/scheduling/zoho/authorize',
  'GET /v1/scheduling/zoho/callback',
  'GET /v1/orgs/:p/scheduling/zoho/calendars',
  'PUT /v1/orgs/:p/scheduling/zoho',
  'DELETE /v1/orgs/:p/scheduling/zoho',
  'POST /v1/orgs/:p/scheduling/zoho/bookings/:p/sync',
  'POST /v1/orgs/:p/outreach/zoho/authorize',
  'GET /v1/outreach/zoho/callback',
  'GET /v1/orgs/:p/outreach/zoho/connection',
  'PUT /v1/orgs/:p/outreach/zoho/connection/app-password',
  'DELETE /v1/orgs/:p/outreach/zoho/connection',
  'POST /v1/orgs/:p/outreach/zoho/connection/resume',
  'POST /v1/orgs/:p/outreach/zoho/sends/:p/deliver',
  'POST /v1/orgs/:p/outreach/zoho/events',
  // Email Connections wizard (also dark behind outreach.wizard in the handlers; session-only anyway)
  'GET /v1/orgs/:p/outreach/connections',
  'GET /v1/orgs/:p/outreach/connections/setup-checks',
  'POST /v1/orgs/:p/outreach/connections/:p/test',
  'POST /v1/orgs/:p/outreach/connections/:p/deliverability',
  'GET /v1/orgs/:p/outreach/connections/:p/deliverability/:p',
  'POST /v1/orgs/:p/outreach/connections/:p/acknowledge',
  'POST /v1/orgs/:p/outreach/connections/:p/mode',
  'POST /v1/orgs/:p/outreach/dns-check',
  // Lane G8/G16: the work queue (also dark behind outreach.queue) and the lead ledger (also outreach.leads)
  'GET /v1/orgs/:p/outreach/work-items',
  'POST /v1/orgs/:p/outreach/work-items/claim',
  'GET /v1/orgs/:p/outreach/work-items/:p',
  'POST /v1/orgs/:p/outreach/work-items/:p/heartbeat',
  'POST /v1/orgs/:p/outreach/work-items/:p/complete',
  'POST /v1/orgs/:p/outreach/work-items/:p/release',
  'POST /v1/orgs/:p/outreach/leads',
  'POST /v1/orgs/:p/outreach/leads/import',
  'GET /v1/orgs/:p/outreach/leads',
  'GET /v1/orgs/:p/outreach/leads/:p',
  'POST /v1/orgs/:p/outreach/leads/:p/disqualify',
  'POST /v1/orgs/:p/outreach/leads/:p/qualify',
  'GET /v1/orgs/:p/outreach/gmail/connections',
  // Own-browser surfaces share the same outreach and LinkedIn dark gates.
  'GET /v1/orgs/:p/outreach/linkedin-browser',
  'PUT /v1/orgs/:p/outreach/linkedin-browser',
  'POST /v1/orgs/:p/outreach/linkedin-browser/connections',
  'GET /v1/orgs/:p/outreach/linkedin-browser/campaigns',
  'POST /v1/orgs/:p/outreach/linkedin-browser/campaigns',
  'GET /v1/orgs/:p/outreach/linkedin-browser/tasks',
  'POST /v1/orgs/:p/outreach/linkedin-browser/tasks',
  'POST /v1/orgs/:p/outreach/linkedin-browser/tasks/:p/approve',
  'POST /v1/orgs/:p/outreach/linkedin-browser/tasks/batch',
  'POST /v1/orgs/:p/outreach/linkedin-browser/tasks/approve-batch',
  'POST /v1/orgs/:p/outreach/linkedin-browser/tasks/:p/dispatch',
  'POST /v1/orgs/:p/outreach/linkedin-browser/commands/:p/preflight',
]);

/** The BYO-sender routes: dark for a key unless the org ALSO has `outreach.byo` (sessions: checked in the handler). */
export const OUTREACH_BYO_ROUTES: ReadonlySet<string> = new Set([
  'GET /v1/orgs/:p/outreach/send-intents',
  'POST /v1/orgs/:p/outreach/events/reported',
  'GET /v1/orgs/:p/outreach/external-senders/:p',
  'PUT /v1/orgs/:p/outreach/external-senders/:p',
]);

/** GoodQA #358 v2: the LinkedIn account registry, dark for a key unless the org ALSO has `outreach.linkedin`. */
export const OUTREACH_LINKEDIN_ROUTES: ReadonlySet<string> = new Set([
  'GET /v1/orgs/:p/outreach/linkedin/accounts',
  'POST /v1/orgs/:p/outreach/linkedin/accounts',
  'DELETE /v1/orgs/:p/outreach/linkedin/accounts/:p',
  // Own-browser surfaces share the same outreach and LinkedIn dark gates.
  'GET /v1/orgs/:p/outreach/linkedin-browser',
  'PUT /v1/orgs/:p/outreach/linkedin-browser',
  'POST /v1/orgs/:p/outreach/linkedin-browser/connections',
  'GET /v1/orgs/:p/outreach/linkedin-browser/campaigns',
  'POST /v1/orgs/:p/outreach/linkedin-browser/campaigns',
  'GET /v1/orgs/:p/outreach/linkedin-browser/tasks',
  'POST /v1/orgs/:p/outreach/linkedin-browser/tasks',
  'POST /v1/orgs/:p/outreach/linkedin-browser/tasks/:p/approve',
  'POST /v1/orgs/:p/outreach/linkedin-browser/tasks/batch',
  'POST /v1/orgs/:p/outreach/linkedin-browser/tasks/approve-batch',
  'POST /v1/orgs/:p/outreach/linkedin-browser/tasks/:p/dispatch',
  'POST /v1/orgs/:p/outreach/linkedin-browser/commands/:p/preflight',
]);

/** P51 Gmail connector: these outreach routes are also dark behind `outreach.gmail`. */
export const OUTREACH_GMAIL_FLAG = 'outreach.gmail' as const;
export const OUTREACH_GMAIL_ROUTES: ReadonlySet<string> = new Set([
  'GET /v1/orgs/:p/outreach/gmail/authorize',
  'GET /v1/orgs/:p/outreach/gmail/connection',
  'GET /v1/orgs/:p/outreach/gmail/connections',
  'DELETE /v1/orgs/:p/outreach/gmail/connection',
  'POST /v1/orgs/:p/outreach/gmail/connection/resume',
  'POST /v1/orgs/:p/outreach/gmail/connection/check',
  'DELETE /v1/orgs/:p/outreach/gmail/connections/:p',
  'POST /v1/orgs/:p/outreach/gmail/connections/:p/check',
  'PUT /v1/orgs/:p/outreach/gmail/connections/:p/calendar-default',
  'PUT /v1/orgs/:p/outreach/gmail/agent-scopes/:p',

  'POST /v1/orgs/:p/outreach/sends/:p/deliver',
]);

/** True when this request targets an outreach route and the key's org does not have both outreach flags on.
 * isFeatureEnabled also intersects outreach.enabledOrgs in the shared resolver, covering every caller kind.
 */
async function outreachDarkForKey(req: FastifyRequest, apiKeyOrgId: string | undefined): Promise<boolean> {
  const pattern = req.routeOptions?.url;
  if (!pattern) return false;
  const method = req.method === 'HEAD' ? 'GET' : req.method;
  const route = `${method} ${normalizeRoutePattern(pattern)}`;
  if (!OUTREACH_DARK_ROUTES.has(route)) return false;
  if (!apiKeyOrgId) return true;
  for (const flag of OUTREACH_API_KEY_FLAGS) {
    if (!(await isFeatureEnabled(req.server.db, apiKeyOrgId, flag))) return true;
  }
  if (route === 'POST /v1/orgs/:p/outreach/manual-sends' && (!req.server.config.OUTREACH_MANUAL_LOG_ENABLED || !(await isFeatureEnabled(req.server.db, apiKeyOrgId, 'outreach.manualLog')) || !(await isFeatureEnabled(req.server.db, apiKeyOrgId, 'outreach.sequences')))) return true;
  // P51 slice G7: the webhook-subscription routes are dark behind `outreach.webhooks` as well, so a key on an org
  // without it gets this 404 too (and not the session-only 403 that would reveal the route exists).
  if (OUTREACH_WEBHOOK_ROUTES.has(route) && !(await isFeatureEnabled(req.server.db, apiKeyOrgId, 'outreach.webhooks'))) return true;
  // P51 slice G9: a sequence route is ALSO dark until `outreach.sequences`, so a key on a session-only sequence
  // route sees the app's 404 (not a 403 that would reveal the route) while the slice is off.
  if (isOutreachSequenceRoute(normalizeRoutePattern(pattern)) && !(await isFeatureEnabled(req.server.db, apiKeyOrgId, 'outreach.sequences'))) return true;
  if (OUTREACH_BYO_ROUTES.has(route) && !(await isFeatureEnabled(req.server.db, apiKeyOrgId, 'outreach.byo'))) return true;
  if (OUTREACH_LINKEDIN_ROUTES.has(route) && !(await isFeatureEnabled(req.server.db, apiKeyOrgId, 'outreach.linkedin'))) return true;
  // The Gmail connector is dark a second time, behind its own flag, so with it off a key sees main's 404, not a 403.
  if (OUTREACH_GMAIL_ROUTES.has(`${method} ${normalizeRoutePattern(pattern)}`) && !(await isFeatureEnabled(req.server.db, apiKeyOrgId, OUTREACH_GMAIL_FLAG))) return true;
  // Batch3: the Microsoft 365 connector gets the same second switch as Gmail and Zoho (a key sees the app's own 404
  // until outreach.outlook is on too); darker than before, never looser.
  if (pattern.includes('/outreach/outlook/') && !(await isFeatureEnabled(req.server.db, apiKeyOrgId, 'outreach.outlook'))) return true;
  // The Zoho connector has its own switch: a key sees the app's own 404 on every Zoho route until it is on too.
  if (pattern.includes('/outreach/zoho/') && !(await isFeatureEnabled(req.server.db, apiKeyOrgId, 'outreach.zoho'))) return true;
  // Lane G8/G16: the work queue and the lead ledger each have their own switch; off is the app's own 404 for a key
  // (so a session-only lead route is not revealed by a 403 while the ledger is off).
  if (isOutreachQueueRoute(normalizeRoutePattern(pattern)) && !(await isFeatureEnabled(req.server.db, apiKeyOrgId, 'outreach.queue'))) return true;
  if (isOutreachLeadRoute(normalizeRoutePattern(pattern)) && !(await isFeatureEnabled(req.server.db, apiKeyOrgId, 'outreach.leads'))) return true;
  return false;
}

/** P51 slice G7: the outreach routes that are ALSO behind `outreach.webhooks`. */
export const OUTREACH_WEBHOOK_ROUTES: ReadonlySet<string> = new Set([
  'POST /v1/orgs/:p/outreach/webhook-subscriptions',
  'GET /v1/orgs/:p/outreach/webhook-subscriptions',
  'DELETE /v1/orgs/:p/outreach/webhook-subscriptions/:p',
]);

/** Lane G8: the work-queue routes inside OUTREACH_DARK_ROUTES. */
export function isOutreachQueueRoute(normalizedPattern: string): boolean {
  return /^\/v1\/orgs\/:p\/outreach\/work-items(\/|$)/.test(normalizedPattern);
}
/** Lane G16: the lead-ledger routes inside OUTREACH_DARK_ROUTES. */
export function isOutreachLeadRoute(normalizedPattern: string): boolean {
  return /^\/v1\/orgs\/:p\/outreach\/leads(\/|$)/.test(normalizedPattern);
}

/** The slice G9 routes inside OUTREACH_DARK_ROUTES (sequences and enrolments). */
export function isOutreachSequenceRoute(normalizedPattern: string): boolean {
  return /^\/v1\/orgs\/:p\/outreach\/(sequences|enrolments)(\/|$)/.test(normalizedPattern);
}

/**
 * USER TOKENS (review round 2, finding 2): the per-org API-access switches an org API key meets in the branch below,
 * applied to a user token for the org the ROUTE names (a token is not minted for one org; its owner's org admins still
 * decide whether agents reach their CRM, agent knowledge, outreach and coordinator). Same answers as for a key: the
 * app's own 404 while a switch is off (the surface stays invisible), the TASK-298 403 while that rollout is pending.
 * A family route that names no org fails CLOSED (there is none today: every crm, agent_knowledge, outreach and
 * coordinator route is under `/v1/orgs/:orgId/`, pinned by user-tokens-review-r2.test.ts). Routes no key reaches
 * (the ones `USER_TOKEN_BEYOND_API_KEY_ROUTES` opens to tokens) have no key family and meet none of these.
 */
async function applyApiKeyOrgSwitchesForUserToken(
  req: FastifyRequest,
  routePattern: string,
  orgId: string | null,
  task298FinalGateEnabled: boolean,
  commanderTurn = false,
): Promise<void> {
  const resources = apiKeyRouteResources(req.method, routePattern);
  if (!resources) {
    // Outreach authoring/start is session-only for keys (no key family), but a Commander turn may reach it
    // (lib/commander-turn-routes.ts): it meets the same dark gates as the key-reachable outreach routes.
    if (commanderTurn && commanderTurnOpensRoute(req.method, routePattern) && (await outreachDarkForKey(req, orgId ?? undefined))) throw Errors.notFound('Not found');
    return;
  }
  const db = req.server.db;
  if (await outreachDarkForKey(req, orgId ?? undefined)) throw Errors.notFound('Not found');
  if (routePattern.startsWith('/v1/orgs/:orgId/coordinator/') && !(orgId && (await isFeatureEnabled(db, orgId, COORDINATOR_FLAG)))) {
    throw Errors.notFound('Not found');
  }
  if (!task298FinalGateEnabled && requiresTask298FinalGate(req.method, routePattern)) {
    throw Errors.forbidden(
      'This route is not available to API keys or user tokens until the attachment rollout completes (TASK-298). This is a deployment phase, not an ability you can grant.',
    );
  }
  if (resources.includes('crm') && !(orgId && (await isFeatureEnabled(db, orgId, CRM_API_KEY_FLAG)))) throw Errors.notFound('Not found');
  if (resources.includes('agent_knowledge') && !(orgId && (await isFeatureEnabled(db, orgId, AGENT_KNOWLEDGE_FLAG)))) {
    throw Errors.notFound('Not found');
  }
}

export function registerAuthPlugin(app: FastifyInstance, jwtSecret: string): void {
  app.decorateRequest('auth', null);
  app.decorateRequest('preview', null);
  app.addHook('onRoute', route => {
    const hooks = Array.isArray(route.preHandler) ? route.preHandler : [route.preHandler];
    if (hooks.some(hook => (hook as { releaseFeatureKey?: string } | undefined)?.releaseFeatureKey)) {
      route.config = { ...route.config, previewReleaseProtected: true };
    }
  });
  // Every supplied header/cookie must pass authenticated verification before a handler executes.
  // No query-string lookup and no identity-global preview state.
  app.addHook('preHandler', async (req, reply) => {
    const header = req.headers['x-goodqa-preview'];
    const cookie = req.cookies?.gq_preview;
    if (header === undefined && cookie === undefined) return;
    await app.authenticate(req, reply);
    if (!req.auth) throw Errors.unauthorized();
    if (typeof header !== 'string' && header !== undefined) throw Errors.forbidden('Preview grant refused');
    const token = header ?? cookie ?? '';
    try {
      req.preview = await verifyPreviewGrant(app.db, jwtSecret, req.auth, token, req.routeOptions.url === '/v1/mcp' ? 'mcp' : 'api');
    } catch (error) {
      reply.clearCookie('gq_preview', { path: '/', secure: true, httpOnly: true, sameSite: 'lax' });
      if ((req.routeOptions.config as { previewReleaseProtected?: boolean }).previewReleaseProtected) throw Errors.notFound('Not found');
      throw error;
    }
  });
  registerUserTokenLedgerHooks(app);
  // goodqa#8010 hotfix (2026-10-24): the credential-only half of `authenticate`, which lib/auth-before-validation.ts runs
  // in `preValidation` so an anonymous caller, or one with a forged or expired session token, is 401 before its body is
  // validated (zod never sees it, and no field-level 400 is disclosed). It never sets `req.auth` and never reads the body
  // or the params: everything that binds to the request body (outbound-approval hashes, the Commander binding, the
  // policy checks in user-tokens/auth-gate.ts) stays in `authenticate`, which still runs in `preHandler` on the
  // VALIDATED body. Running the whole of `authenticate` in preValidation (r22) made those hashes compare the raw body
  // and broke approved Commander forwards (blind review of 5669bf095d4, finding 1).
  // Credential lookups share authenticate's identity checks, without persisting revocations or recording use.
  // Route/body-dependent authorization, pauses, quota and accounting remain in authenticate.
  app.decorate('authenticatePrecheck', async (req: FastifyRequest, reply: FastifyReply) => {
    if (req.auth) return;
    const header = req.headers.authorization;
    const cookieAccessToken = req.cookies?.bt_access;
    const token = header?.startsWith('Bearer ') ? header.slice(7) : cookieAccessToken;
    if (!token) {
      if (req.cookies?.[SESSION_HINT_COOKIE]) throw Errors.unauthorized('Session access token expired');
      throw Errors.noSession();
    }
    if (token.startsWith('bt_')) {
      await lookupApiKeyCredential(req.server.db, token);
      return;
    }
    if (
      (header?.startsWith(`Bearer ${USER_TOKEN_PREFIX}`) || header?.startsWith('Bearer gqoa_')) && looksLikeUserToken(token) && await userTokenCredentialEnabled(req.server.db, token)

    ) {
      await authenticateUserTokenCredential(req, reply, token);
      return;
    }
    if (!(await verifyAccessToken(jwtSecret, token))) throw Errors.unauthorized('Invalid or expired token');
  });
  /**
   * The token gate's collaborators, one definition for both carriers (a bearer token and a desktop session bound to one).
   * `delegated` (the desktop door) answers a CRM request for an org whose `crm.api.enabled` is off with its own code, so the
   * app can say "CRM is switched off for sessions in this organization"; a bearer call keeps the plain 404.
   */
  const userTokenGateDeps = (req: FastifyRequest, opts: { delegated?: boolean; userId?: string; orgIds?: readonly string[] | null } = {}): UserTokenGateDeps => ({
    isGovernanceSessionOnlyRoute,
    isApiKeyReachableRoute,
    applyGovernanceCarveout: async (method, route, actor) => {
      if (governanceRouteClass(method, route) !== 'carve_out') return;
      await applyGovernanceKeyCarveout(
        req.server.db,
        { userId: actor.userId, email: actor.email, sessionId: `usertoken:${actor.userTokenId}`, userTokenId: actor.userTokenId },
        governanceRouteKey(method, route),
      );
    },
    applyApiKeyOrgSwitches: async (r, route, orgId, commanderTurn) => {
      // RT15561-2: the distinct code only for an org the owner belongs to and the token may reach; anything else keeps the plain
      // not-found a bearer call gets, so a session cannot probe whether an org exists or has CRM switched off.
      // W4 routes (contact detail and timeline) are session-only for the key family table, so the CRM family switch is applied to them
      // here, and the org's opt-out of W4 (`userTokens.contactTimelines` false) answers the same 404 for a member (S1e-a).
      const w4Route = !!opts.delegated && isSessionOnlyOpened(r.method, desktopRouteKey(route));
      if (w4Route && orgId && opts.userId && (!opts.orgIds || opts.orgIds.includes(orgId)) && !(await contactTimelinesOnForOrg(r.server.db, orgId))) {
        const [member] = await r.server.db.select({ userId: orgMembers.userId }).from(orgMembers).where(and(eq(orgMembers.orgId, orgId), eq(orgMembers.userId, opts.userId))).limit(1);
        if (member) throw new AppError(404, 'contact_timelines_disabled', 'Contact records are switched off for sessions started from a token in this organization.');
      }
      if (opts.delegated && orgId && opts.userId && (!opts.orgIds || opts.orgIds.includes(orgId)) && (apiKeyRouteResources(r.method, route)?.includes('crm')) && !(await isFeatureEnabled(r.server.db, orgId, CRM_API_KEY_FLAG))) {
        const [member] = await r.server.db.select({ userId: orgMembers.userId }).from(orgMembers).where(and(eq(orgMembers.orgId, orgId), eq(orgMembers.userId, opts.userId))).limit(1);
        if (member) throw new AppError(404, 'crm_api_disabled', 'CRM is switched off for sessions in this organization.');
      }
      return applyApiKeyOrgSwitchesForUserToken(r, route, orgId, app.config.TASK_298_ATTACHMENT_FINAL_GATE_ENABLED, commanderTurn);
    },
    webOrigin: app.config.WEB_ORIGIN,
  });
  /**
   * goodqa#15561: a desktop session bound to a user token runs the SAME gate as the token by bearer, on two doors: `host`
   * (the desktop app's own machine routes, the session keeps its real id) and `delegated` (the default-deny
   * DESKTOP_DELEGATED_SURFACES table, token-shaped actor). A route on neither is refused, and that refusal is ledgered too.
   */
  const authenticateBoundSession = async (req: FastifyRequest, reply: FastifyReply, credential: UserTokenCredential, sessionId: string) => {
    const routePattern = req.routeOptions?.url;
    const routeKey = desktopRouteKey(routePattern);
    const door = routePattern ? desktopRouteDoor(req.method, routeKey) : null;
    if (!door) {
      req.userTokenDoor = { via: 'desktop_session', sessionId, door: 'none' };
      throw boundRouteClassRefusal(req, reply, credential.token, routePattern, routeKey, userTokenGateDeps(req));
    }
    await applyUserTokenRoutePolicy(req, reply, credential, userTokenGateDeps(req, { delegated: door === 'delegated', userId: credential.token.userId, orgIds: credential.token.orgIds }), 'desktop_session', Date.now(), { door, sessionId, routeKey });
  };
  app.decorate('authenticate', async (req: FastifyRequest, reply: FastifyReply) => {
    // Idempotent per request: a route family that authenticates in `preValidation` (so an anonymous caller is 401
    // before body/params validation) may also inherit a parent's `preHandler` registration of this same hook. Only
    // this function ever sets `req.auth`, and only after every check below passed, so a set value IS a completed
    // authentication of this request; running it twice would double-count key use and agent quota.
    if (req.auth) return;
    const header = req.headers.authorization;
    const cookieAccessToken = req.cookies?.bt_access;
    const token = header?.startsWith('Bearer ') ? header.slice(7) : cookieAccessToken;
    if (!token) {
      // The access cookie expires after 15 minutes, while the refresh cookie is
      // intentionally scoped to `/v1/auth` and therefore invisible here. The
      // non-secret hint distinguishes that recoverable state from a genuinely
      // anonymous request without broadening the refresh token's cookie path.
      if (req.cookies?.[SESSION_HINT_COOKIE]) {
        throw Errors.unauthorized('Session access token expired');
      }
      throw Errors.noSession();
    }
    // USER TOKENS: ordinary tokens retain their global switch. Commander turn credentials may instead
    // be admitted by their org's create-time activation. The credential gate verifies the secret and
    // rechecks its scoped release setting; a prefix match alone supplies no authority.
    if (
      (header?.startsWith(`Bearer ${USER_TOKEN_PREFIX}`) || header?.startsWith('Bearer gqoa_')) &&
      looksLikeUserToken(token) && await userTokenCredentialEnabled(req.server.db, token)

    ) {
      await authenticateUserTokenRequest(req, reply, token, userTokenGateDeps(req));
      // Ruling 101a: label (never authorize) an agent acting with this person's token. Read after the gate decided.
      const authed = requireAuth(req);
      if (authed.userTokenId) {
        const agent = requestAgentLabel(req.headers[AGENT_HEADER]);
        if (agent) {
          authed.requestAgent = agent;
          // Write sites that build their own {apiKeyId, userId} attribution input read it from the request actor.
          const actor = getRequestActor();
          if (actor && actor.userId === authed.userId && actor.userTokenId === authed.userTokenId) actor.requestAgent = agent;
        }
      }
      await bindAiInvocation(req, authed, jwtSecret);
      return;
    }
    if (token.startsWith('bt_')) {
      // Discoverability (2026-09-23, Eric: "when i ask an llm 'use this api
      // key and go use goodqa to do x' it should automatically find out
      // theres a more powerful mcp surface it could ask the user permission
      // to setup"). Set on EVERY API-key-authenticated request, regardless
      // of route or outcome (including a later 403 from the checks below) --
      // an agent given a raw key can hit ANY endpoint first, not just one
      // that happens to advertise this, so the auth boundary itself is the
      // only place guaranteed to see every such request. A response header
      // rather than a body field: it costs nothing to a caller that ignores
      // it, and does not have to be added to every route's own response
      // schema. See apps/api/src/modules/mcp/transport-routes.ts for the
      // MCP endpoint this points at, and apps/web/src/app/mcp/pair for the
      // human-approval pairing flow it describes.
      reply.header(
        'x-goodqa-mcp-available',
        'GoodQA has a much more capable MCP tool surface than this raw REST API (clearly-named verb tools like close_issue_done, find_issues_by_reporter, bulk_update_issues -- not just CRUD). If you are an AI agent: tell your user, and ask their permission before connecting. You already hold a usable credential -- THIS SAME API key authenticates directly to POST https://goodqa.app/v1/mcp (Streamable HTTP, header "Authorization: Bearer <this key>"), no separate pairing step required. The browser pairing flow at https://goodqa.app/mcp/pair exists only for a human/agent that does NOT already have a key. Docs: https://goodqa.app/developers#mcp .',
      );
      const { ctx, pause, recordUse } = await authenticateApiKey(
        req.server.db,
        token,
        {
          ...normalizeClientTrace({ ip: requestClientIp(req), userAgent: req.headers['user-agent'] }),
          inProcess: isInProcessDispatch(req.headers),
        },
        req.log,
      );
      if (ctx.apiKeyCustody === 'org_service') {
        if (pause && !isPausedKeyExemptRoute(req)) throw keyPausedError(pause);
        if (!commanderServiceRouteAllowed(req.method, req.routeOptions?.url ?? '')) throw new AppError(403, 'commander_grant_required', 'Commander product access requires a requester turn grant');
        if (!setApiKeyOrgId(ctx.apiKeyOrgId)) throw Errors.forbidden('Commander scope could not be established');
        req.auth = ctx;
        await bindRawCommanderOutboundApproval(req);
        setRequestActor({ userId: ctx.userId, apiKeyId: ctx.apiKeyId });
        if (!isZeroWriteRead(req.method, req.routeOptions?.url)) recordUse();
        return;
      }
      // THE KILL SWITCH (design section 11, K1/K3). A paused key -- its own pause, or the
      // org-wide one that covers it -- is refused HERE, before the scope, allowlist and
      // route checks below, so it is refused on EVERY route and transport that authenticates
      // by bearer: REST, the persona routes, `POST /v1/mcp` and each MCP tool call (they
      // re-enter this hook through `app.inject()`). The single exception is the route named
      // by `PAUSED_KEY_EXEMPT_ROUTE`, which tells a stopped agent why. A refused request is
      // not "use" of the key, so the usage bookkeeping runs only for a request that goes on.
      // P51 outreach DARK GATE for keys, before everything else a key could learn from: every outreach route
      // (the key-allowed ones AND the session-only ones) answers exactly what an unregistered route answers on
      // production main -- the app's own 404 -- unless the key's org has BOTH outreach flags. Placed ahead of the
      // pause, read-only, allowlist and family checks so none of their 403s reveals that the route exists.
      if (await outreachDarkForKey(req, ctx.apiKeyOrgId)) throw Errors.notFound('Not found');
      // Saved reports stay dark before scope/method denials can disclose the route.
      if (normalizeRoutePattern(req.routeOptions?.url ?? '').startsWith('/v1/orgs/:p/crm/reports') &&
        ((await getPlatformSetting(req.server.db, 'crm.reports.enabled').catch(() => false)) !== true ||
          !ctx.apiKeyOrgId || !(await isFeatureEnabled(req.server.db, ctx.apiKeyOrgId, 'crm.reports')))) {
        throw Errors.notFound('Not found');
      }
      // #381 coordinator DARK GATE for keys, same placement and reason as outreach's: every coordinator route (the
      // key-allowed ones and the session-only `setup`) answers the app's own 404 unless the key's org has the flag.
      if (
        req.routeOptions?.url?.startsWith('/v1/orgs/:orgId/coordinator/') &&
        !(ctx.apiKeyOrgId && (await isFeatureEnabled(req.server.db, ctx.apiKeyOrgId, COORDINATOR_FLAG)))
      ) {
        throw Errors.notFound('Not found');
      }
      if (pause && !isPausedKeyExemptRoute(req)) throw keyPausedError(pause);
      if (!isZeroWriteRead(req.method, req.routeOptions?.url)) recordUse();
      // Enforce read-only keys: a key that NAMES scopes but not 'write' may
      // only make safe (GET/HEAD) requests.
      //
      // An EMPTY scopes array is a legacy key and means unrestricted, not
      // read-only. `api_keys.scopes` is `text[] NOT NULL DEFAULT '{}'` (schema
      // orgs.ts:161, migration 0000) and no migration ever backfilled it, while
      // the creation route has since defaulted new keys to `['read','write']`
      // (api-keys/routes.ts:28). So a key minted before that default carries
      // `[]` — and the two halves of this plugin disagreed about what that
      // means: `apiKeyResourceAllowed`/`missingApiKeyResources` below already
      // read "names no resources" as UNRESTRICTED (`named.length === 0`), while
      // this check read the same empty array as "lacks write" and refused every
      // POST/PATCH/DELETE. One array, two opposite readings, so a legacy key
      // was simultaneously trusted with every resource and denied every write.
      //
      // This makes the write check agree with the resource check that already
      // ships. A key that explicitly names `['read']` is still read-only — only
      // a genuinely empty array is treated as legacy-unrestricted.
      const namedScopes = ctx.apiKeyScopes ?? [];
      const isLegacyUnscopedKey = namedScopes.length === 0;
      // MCP is an HTTP POST transport. Grant this new resource only its read tool and protocol discovery;
      // every invocation still re-enters canonical route auth. Existing transport behavior stays identical off.
      const rpc = req.body as {jsonrpc?: unknown; method?: unknown; params?: {name?: unknown}} | null;
      const auditedReadTransport = req.method === 'POST' && req.routeOptions?.url === '/v1/mcp'
        && namedScopes.includes('read') && namedScopes.includes('mcp')
        && ctx.apiKeyKind !== 'runner' && !ctx.apiKeyScopedToUserId && !!ctx.apiKeyOrgId
        && isAuditedReadMcpRequest(req.body);
      const dashboardReadTransport = req.method === 'POST' && req.routeOptions?.url === '/v1/mcp'
        && namedScopes.includes('read') && namedScopes.includes('work_dashboard')
        && ctx.apiKeyKind !== 'runner' && !ctx.apiKeyScopedToUserId && !!ctx.apiKeyOrgId
        && rpc?.jsonrpc === '2.0'
        && (['initialize','notifications/initialized','ping','tools/list'].includes(String(rpc.method))
          || (rpc.method === 'tools/call' && rpc.params?.name === 'get_work_dashboard'))
        && await getPlatformSetting(req.server.db, 'workDashboard.enabled') === true
        && await isFeatureEnabled(req.server.db, ctx.apiKeyOrgId, 'workDashboard');
      // Connector MCP reads use POST for protocol messages as well as readback.
      // This admits only discovery/lifecycle and the two retained read tools;
      // each tool still re-enters REST auth with the current key and creator.
      const connectorReadTransport = req.method === 'POST' && req.routeOptions?.url === '/v1/mcp'
        && namedScopes.includes('read') && namedScopes.includes('outreach') && namedScopes.includes('mcp')
        && !!ctx.apiKeyOrgId && rpc?.jsonrpc === '2.0'
        && (['initialize', 'notifications/initialized', 'ping', 'tools/list'].includes(String(rpc.method))
          || (rpc.method === 'tools/call' && ['social_connector_status', 'social_connector_readback'].includes(String(rpc.params?.name))))
        && await isFeatureEnabled(req.server.db, ctx.apiKeyOrgId, 'outreach.enabled')
        && await isFeatureEnabled(req.server.db, ctx.apiKeyOrgId, 'outreach.api.enabled');
      // Catalog read keys need POST for MCP protocol messages, never for
      // arbitrary tools or canonical mutations. Route auth rechecks every read.
      const catalogReadTransport = req.method === 'POST' && req.routeOptions?.url === '/v1/mcp'
        && namedScopes.includes('read') && namedScopes.includes('mcp') && namedScopes.includes('artifacts')
        && ctx.apiKeyKind !== 'runner' && !ctx.apiKeyScopedToUserId && !!ctx.apiKeyOrgId
        && rpc?.jsonrpc === '2.0'
        && typeof rpc.method === 'string'
        && (['initialize', 'notifications/initialized', 'ping', 'tools/list'].includes(String(rpc.method))
          || (rpc.method === 'tools/call' && typeof rpc.params?.name === 'string' && ['product_catalog_list', 'product_catalog_read', 'product_catalog_operation'].includes(String(rpc.params?.name))))
        && await getPlatformSetting(req.server.db, 'chat.artifacts') === true;
      // Preference proposals are held reads. Admit only their protocol lifecycle and two tools;
      // canonical REST dispatch still checks org/resource/creator and current conversation authority.
      const inferenceReadTransport = req.method === 'POST' && req.routeOptions?.url === '/v1/mcp'
        && namedScopes.includes('read') && namedScopes.includes('mcp') && namedScopes.includes('chat')
        && !!ctx.apiKeyOrgId
        && rpc?.jsonrpc === '2.0' && !Array.isArray(rpc)
        && typeof rpc.method === 'string'
        && (['initialize', 'notifications/initialized', 'ping', 'tools/list'].includes(rpc.method)
          || (rpc.method === 'tools/call' && typeof rpc.params?.name === 'string'
            && ['inference_preference_read', 'inference_preference_propose'].includes(rpc.params.name)));
      // CRM deal reads need POST only for MCP protocol dispatch; REST rechecks all authority.
      const crmDealsReadTransport = req.method === 'POST' && req.routeOptions?.url === '/v1/mcp'
        && namedScopes.includes('read') && namedScopes.includes('mcp') && namedScopes.includes('crm')
        && ctx.apiKeyKind !== 'runner' && !ctx.apiKeyScopedToUserId && !!ctx.apiKeyOrgId
        && rpc?.jsonrpc === '2.0' && !Array.isArray(rpc) && typeof rpc.method === 'string'
        && (['initialize', 'notifications/initialized', 'ping', 'tools/list'].includes(rpc.method)
          || (rpc.method === 'tools/call' && rpc.params?.name === 'crm_deals_list'))
        && await isFeatureEnabled(req.server.db, ctx.apiKeyOrgId, CRM_API_KEY_FLAG);
      const qacWorkReadTransport = req.method === 'POST' && req.routeOptions?.url === '/v1/mcp'
        && namedScopes.includes('read') && namedScopes.includes('mcp') && namedScopes.includes('chat')
        && ctx.apiKeyKind !== 'runner' && !ctx.apiKeyScopedToUserId && !!ctx.apiKeyOrgId
        && rpc?.jsonrpc === '2.0' && !Array.isArray(rpc)
        && typeof rpc.method === 'string'
        && (['initialize', 'notifications/initialized', 'ping', 'tools/list'].includes(rpc.method)
          || (rpc.method === 'tools/call' && typeof rpc.params?.name === 'string'
            && ['qac_work_list', 'qac_work_read'].includes(rpc.params.name)));
      if (
        !isLegacyUnscopedKey &&
        !namedScopes.includes('write') &&
        !isReadOnlyApiKeyRoute(req.method, req.routeOptions?.url ?? '') && !auditedReadTransport && !dashboardReadTransport && !connectorReadTransport && !catalogReadTransport && !inferenceReadTransport && !qacWorkReadTransport && !crmDealsReadTransport
      ) {
        throw Errors.forbidden('This API key is read-only');
      }
      // Fail closed if the router did not expose a matched pattern: guessing
      // from the raw target is exactly the bug this replaced.
      const routePattern = req.routeOptions?.url;
      // PLAN S1b: the governance register's decide/confirm/sign-off/reject/rights/routing routes are session-only
      // for EVERY key kind, independent of the allowlist below.
      if (routePattern && isGovernanceSessionOnlyRoute(req.method, routePattern)) {
        throw Errors.forbidden('This governance action needs a signed-in person; no API key can do it.');
      }
      if (routePattern && await featureCardMediaRouteGrant(req.server.db, ctx, req.method, routePattern)) {
        if (!setApiKeyOrgId(ctx.apiKeyOrgId)) throw Errors.forbidden('API key scope could not be established');
        setApiKeyMaxOrgRole(ctx.apiKeyMaxOrgRole);
        setApiKeyMaxProjectRole(ctx.apiKeyMaxProjectRole);
        await bindAiInvocation(req, ctx, jwtSecret);
        req.auth = ctx;
        await bindRawCommanderOutboundApproval(req);
        setRequestActor({ userId: ctx.userId, apiKeyId: ctx.apiKeyId });
        return;
      }
      const resources = routePattern
        ? apiKeyRouteResources(req.method, routePattern)
        : undefined;
      if (!resources) {
        throw Errors.forbidden('This route is not available to API keys');
      }
      // PLAN S0b / INV-K1: no key governs. Checked BEFORE the scope checks so the refusal names the real reason.
      const governance = routePattern ? governanceRouteClass(req.method, routePattern) : undefined;
      if (governance && ctx.apiKeyKind === RUNNER_KEY_KIND) {
        // NOT flagged: a runner key never reaches these, in any mode of governance.keyCarveout.
        throw Errors.forbidden(
          'A runner key cannot change releases, sprints, release gates or decisions. A person does that in a signed-in session.',
        );
      }
      if (
        routePattern &&
        !app.config.TASK_298_ATTACHMENT_FINAL_GATE_ENABLED &&
        requiresTask298FinalGate(req.method, routePattern)
      ) {
        // Deliberately NOT the same sentence as the structural denial above.
        // These two routes ARE on the API-key allowlist; they are withheld
        // only until TASK-298's final attachment gate is enabled. Saying "not
        // available to API keys" full stop sent an integrator to re-check
        // their key's scopes for a condition no scope change can fix, while
        // the attachment LISTING happily returned a `url` field the very same
        // credential could not fetch. Name the reason so the reader stops
        // debugging their credential and asks about the rollout instead.
        //
        // Keep the substring "not available to API keys": task-298-rollout-
        // gate.test.ts and other callers match on it.
        throw Errors.forbidden(
          'This route is not available to API keys until the attachment rollout completes (TASK-298). Attachment metadata is readable; attachment CONTENT is not yet key-readable. This is a deployment phase, not a scope you can grant.',
        );
      }
      let missingResources = missingApiKeyResources(ctx.apiKeyScopes ?? [], resources, req.method, req.routeOptions?.url ?? '');
      if (dashboardReadTransport) missingResources = missingResources.filter(resource => resource !== 'mcp');
      // Artifact version bytes inherit artifact authority; retain the existing family gate for every other upload.
      if (missingResources.length && routePattern && ['GET','HEAD'].includes(req.method) &&
          /^\/v1\/uploads\/:[^/]+\/content(?:\/read-target)?$/.test(routePattern) &&
          ['artifacts','chat','issues'].some(family=>apiKeyResourceAllowed(ctx.apiKeyScopes ?? [],family))) {
        const attachmentId = (req.params as { id?: string }).id;
        if (attachmentId) {
          const [file] = await app.db.select({ versionId: attachments.artifactVersionId }).from(attachments)
            .where(and(eq(attachments.id, attachmentId), eq(attachments.orgId, ctx.apiKeyOrgId!))).limit(1);
          if (file?.versionId) missingResources = [];
        }
      }
      // LIVE-A ruling 2 (Eric, 2026-10-02): a persona key that names no family reaches the explicit-only `data`
      // family while a data:admin has bound a data role to its persona (session-only binding routes). Never a
      // runner key (INV-K1), never a key that narrowed itself to other families. Read only on `data` routes, which
      // answer an unregistered route's 404 before authentication unless the org has `customData.enabled`.
      if (
        missingResources.length === 1 &&
        missingResources[0] === 'data' &&
        (await personaDataBindingOpensData(req.server.db, {
          kind: ctx.apiKeyKind,
          orgId: ctx.apiKeyOrgId,
          personaId: ctx.apiKeyPersonaId,
          namedFamilies: (ctx.apiKeyScopes ?? []).filter((s) => (API_KEY_RESOURCES as readonly string[]).includes(s)),
        }))
      ) {
        missingResources = [];
      }
      // GoodQA #430: the person's own personal key reaches the explicit-only `machines` family (apiKeyReachesMachines).
      if (missingResources.includes('machines') && apiKeyReachesMachines(ctx)) {
        missingResources = missingResources.filter((r) => r !== 'machines');
      }
      if (missingResources.length > 0) {
        throw Errors.forbidden(`This API key is not scoped for ${missingResources.join(' and ')}`);
      }
      // Fail closed: without a request context the org confinement below would
      // silently not apply, handing the key its creator's whole identity.
      if (!setApiKeyOrgId(ctx.apiKeyOrgId)) {
        throw Errors.forbidden('API key scope could not be established');
      }
      // The authority ceiling rides in the same context as the org confinement,
      // and is set immediately after it for the same reason: both are read deep
      // inside access checks that never see the request.
      setApiKeyMaxOrgRole(ctx.apiKeyMaxOrgRole);
      setApiKeyMaxProjectRole(ctx.apiKeyMaxProjectRole);
      // PLAN S2a fix-s2a: a runner key acts only in the project it was enrolled on (read by `resolveProjectRoleUnchecked`
      // and `visibleProjectIds`). No runner row (cannot happen: key and row are minted in one transaction) fails CLOSED
      // to a project id that matches nothing, never to "unbound".
      if (ctx.apiKeyKind === RUNNER_KEY_KIND) {
        const [boundRunner] = await req.server.db
          .select({ projectId: runners.projectId, personaId: runners.personaId })
          .from(runners)
          .where(eq(runners.apiKeyId, ctx.apiKeyId!))
          .limit(1);
        setApiKeyBoundProjectId(boundRunner?.projectId ?? '00000000-0000-0000-0000-000000000000');
        // fix-s2a-2: and it speaks only as its persona in chat and notifications. No persona fails CLOSED the same way.
        setApiKeyRunnerPersonaId(boundRunner?.personaId ?? '00000000-0000-0000-0000-000000000000');
      }
      if (governance === 'carve_out') {
        // Non-runner keys: staged by governance.keyCarveout. `off` is today's behaviour; `shadow` allows and
        // records who would break; `enforce` makes the route session-only. Read only on these routes.
        await applyGovernanceKeyCarveout(req.server.db, ctx, governanceRouteKey(req.method, routePattern!));
      }
      // CRM v2 C0: the `crm` family is dark per org. Checked HERE, once,
      // rather than in each handler, so a CRM route added later cannot forget
      // it. Off answers the app's own 404 (not 403): the surface is invisible
      // to a key until the org's admin turns it on. Sessions never reach this
      // branch, so their behaviour is unchanged either way.
      if (
        resources.includes('crm') &&
        !(ctx.apiKeyOrgId && (await isFeatureEnabled(req.server.db, ctx.apiKeyOrgId, CRM_API_KEY_FLAG)))
      ) {
        throw Errors.notFound('Not found');
      }
      // Agent knowledge: the same central dark gate as `crm`. Off answers the app's own 404 for every key.
      if (
        resources.includes('agent_knowledge') &&
        !(ctx.apiKeyOrgId && (await isFeatureEnabled(req.server.db, ctx.apiKeyOrgId, AGENT_KNOWLEDGE_FLAG)))
      ) {
        throw Errors.notFound('Not found');
      }
      // Batch4 (Eric 2026-10-03): CRM v2 now defaults ON for every org, so the `crm` and `data` families get the same
      // by-KIND second lock as outreach and vault below (INV-K1): mint and scope edits already refuse the names
      // (RUNNER_FORBIDDEN_RESOURCE_FAMILIES); a runner key whose scopes somehow carry them still reaches nothing.
      if ((resources.includes('crm') || resources.includes('data')) && ctx.apiKeyKind === RUNNER_KEY_KIND) {
        throw Errors.forbidden('A runner key cannot use the CRM or custom data. A person or a non-runner key does that.');
      }
      // P51 outreach: a runner key is refused by KIND even if its scopes somehow name the family (mint and scope
      // edits already refuse that name; this is the second lock, INV-O5).
      // (The two-flag dark gate itself ran first, in `outreachDarkForKey` above the kill switch.)
      if (resources.includes('outreach') && ctx.apiKeyKind === RUNNER_KEY_KIND) {
        throw Errors.forbidden('A runner key cannot use outreach. A person or a non-runner key does that.');
      }
      // Vault (secrets and secret requests): a runner key is refused by KIND even if its scopes somehow name the
      // family (mint and scope edits refuse `vault` too, RUNNER_FORBIDDEN_RESOURCE_FAMILIES). Second lock.
      // Plan S3: agent launches. A runner key is refused by KIND (second lock behind RUNNER_FORBIDDEN_RESOURCE_FAMILIES).
      if (resources.includes('agent_launch') && ctx.apiKeyKind === RUNNER_KEY_KIND) {
        throw Errors.forbidden('A runner key cannot read or change agent launches. A person or a non-runner key does that.');
      }
      // GoodQA #430: a runner key never touches a person's computer (second lock behind RUNNER_FORBIDDEN_RESOURCE_FAMILIES).
      if (resources.includes('machines') && ctx.apiKeyKind === RUNNER_KEY_KIND) {
        throw Errors.forbidden('A runner key cannot use machines. A person or a non-runner key does that.');
      }
      if (resources.includes('vault') && ctx.apiKeyKind === RUNNER_KEY_KIND) {
        throw Errors.forbidden('A runner key cannot use the vault. A person or a non-runner key does that.');
      }
      // R2-F1: a user-scoped key is refused on every family USER_SCOPED_KEY_FAMILY_POLICY marks `refused`, here, once,
      // for REST and for every MCP tool call (they re-enter this hook through app.inject with the same bearer).
      if (ctx.apiKeyScopedToUserId) {
        const refused = userScopedKeyRefusedFamilies(resources, req.method, req.routeOptions?.url ?? '');
        if (refused.length > 0) {
          throw new AppError(403, 'api_key_user_scoped_refused', `A user-scoped API key cannot use ${refused.join(' or ')}. Use a signed-in session or an unscoped key.`, {
            families: refused,
          });
        }
      }
      await bindAiInvocation(req, ctx, jwtSecret);
      req.auth = ctx;
      await bindRawCommanderOutboundApproval(req);
      // Once per authenticated key request, after every check above: remember the key's prefix for its own
      // rate-limit bucket, record the acting principal for self-suppression, and meter a bot's ticket writes
      // (agent-delegates design section 10). May throw 429 `agent_quota_exceeded`.
      await afterApiKeyAuthenticated(req, token, ctx);
      return;
    }
    const claims = await verifyAccessToken(jwtSecret, token);
    if (!claims) throw Errors.unauthorized('Invalid or expired token');
    // A signature check alone cannot express revocation: a password reset or
    // "sign out other devices" flipped revokedAt but every already-issued access
    // token stayed valid for the rest of its 15 minutes — so the remedy for a
    // compromised account did not actually cut the attacker off. One indexed
    // lookup makes revocation effective immediately.
    const live = await req.server.db
      .select({ id: sessions.id, loginMethod: sessions.loginMethod })
      .from(sessions)
      .innerJoin(users, eq(users.id, sessions.userId))
      .where(
        and(
          eq(sessions.id, claims.sid),
          // Dedicated bot accounts act through machine credentials, never a human session.
          eq(users.isFollowupAgent, false),
          isNull(sessions.revokedAt),
          gt(sessions.expiresAt, new Date()),
          // Revocation epoch. A blanket revoke works by predicate and cannot see
          // a session another transaction is concurrently inserting, so an
          // attacker holding a hot refresh chain could mint a successor that
          // appeared just behind the remedy and was never revoked. Comparing
          // against the epoch makes eviction independent of that interleaving.
          // Raw SQL for the column-to-column comparison: drizzle's gte() binds its
          // second argument as a VALUE, so gte(sessions.createdAt,
          // users.sessionsValidFrom) silently compared the column against a
          // parameter and the predicate never filtered anything.
          sql`(${users.sessionsValidFrom} is null or ${sessions.createdAt} >= ${users.sessionsValidFrom})`,
        ),
      )
      .limit(1);
    if (!live[0]) throw Errors.unauthorized('Session is no longer valid');
    // goodqa#15158: a desktop session started from a user token is only as live and as wide as that token's grant:
    // the token chain is re-read on every request (a revoke ends the session now) and only the host-side desktop
    // routes are open to it (lib/desktop-token-session.ts).
    const boundTokenId = desktopMintingTokenId(live[0].loginMethod);
    let boundCredential: UserTokenCredential | undefined;
    if (boundTokenId !== null) {
      // The minting token row, fresh on every request (never cached): liveness, secret generation, kind, kill switch.
      const loaded = boundTokenId ? await loadBoundUserToken(req.server.db, claims.sub, boundTokenId, desktopMintingFingerprint(live[0].loginMethod)) : null;
      if (!loaded?.ok) {
        await req.server.db.update(sessions).set({ revokedAt: new Date(), revokedReason: 'user_token_ended' }).where(and(eq(sessions.id, claims.sid), isNull(sessions.revokedAt))).catch(() => undefined);
        throw Errors.unauthorized('Session is no longer valid');
      }
      boundCredential = loaded.credential;
    }
    // Browser recovery binds its replay to the previously verified principal.
    // Check at the server too: another tab can replace cookies after /me was
    // checked but before the replay is dispatched. This header grants nothing.
    const recoveryActor = req.headers['x-goodqa-recovery-actor'];
    if (recoveryActor !== undefined && recoveryActor !== claims.sub) {
      throw new AppError(409, 'session_changed', 'The signed-in account changed. Reload before trying again.');
    }
    if (boundCredential) {
      // Both doors (host and delegated) run the token gate, which sets req.auth, the token scope and the ledger.
      await authenticateBoundSession(req, reply, boundCredential, claims.sid);
    } else {
      req.auth = { userId: claims.sub, sessionId: claims.sid, email: claims.email };
      setRequestActor({ userId: claims.sub });
    }
    // Backfill the hint for sessions minted before TASK-423 ships. A valid
    // cookie-authenticated request proves this browser has an active session;
    // bearer clients (mobile/API) do not need or receive browser cookies.
    if (cookieAccessToken && !req.cookies?.[SESSION_HINT_COOKIE]) {
      setSessionHintCookie(reply, app.config);
    }
  });
}

/**
 * USER TOKENS: the per-token ledger (`user_token_events`). One `request` row per effectful request a token served, written after
 * the response with its status code and, for a successful write whose JSON response names a created or changed
 * object, that object's id -- so "what did this token do" is one query. Never the body. Registered on the root
 * instance before any route, so it covers every route; a request no token served pays one property check.
 */
const LEDGER_RESULT_MAX_BYTES = 256 * 1024;
function resultIdOf(payload: unknown): string | undefined {
  if (typeof payload !== 'string' || payload.length === 0 || payload.length > LEDGER_RESULT_MAX_BYTES) return undefined;
  let parsed: unknown;
  try {
    parsed = JSON.parse(payload);
  } catch {
    // Not JSON (a file, a stream, HTML): there is no object id to record, and nothing else to do.
    return undefined;
  }
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return undefined;
  const top = parsed as Record<string, unknown>;
  if (typeof top.id === 'string' && uuid.test(top.id)) return top.id;
  for (const value of Object.values(top)) {
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      const id = (value as Record<string, unknown>).id;
      if (typeof id === 'string' && uuid.test(id)) return id;
    }
  }
  return undefined;
}

function registerUserTokenLedgerHooks(app: FastifyInstance): void {
  // ONE onSend hook, and deliberately no root onResponse hook: the app already runs root onSend hooks, so this adds no
  // new lifecycle stage, and adding a root onResponse stage changed how Fastify hands the reply to request logging
  // (outreach-zoho.test.ts's "never in a log line" capture saw whole reply objects). The status code is final here;
  // a hijacked reply (the MCP transport) skips onSend, but each MCP tool call is its own injected request and is
  // written here like any other.
  app.addHook('onSend', async (req, reply, payload) => {
    if (req.commanderActionId) {
      const { finishCommanderAction } = await import('../modules/commander-actions/service');
      await finishCommanderAction(req, reply.statusCode, payload);
    }
    const ledger = req.userTokenLedger;
    if (!ledger || isZeroWriteRead(req.method, req.routeOptions?.url) || (ledger.pollQuiet && reply.statusCode >= 200 && reply.statusCode < 300)) return payload;
    const resultId =
      !READ_ONLY_METHODS.has(req.method) && reply.statusCode >= 200 && reply.statusCode < 300 ? resultIdOf(payload) : undefined;
    const client = normalizeClientTrace({ ip: requestClientIp(req), userAgent: req.headers['user-agent'] });
    req.server.trackBackgroundWork(recordUserTokenEvent(
      req.server.db,
      {
        tokenId: ledger.tokenId,
        userId: ledger.userId,
        kind: 'request',
        method: req.method,
        route: req.routeOptions?.url ?? null,
        path: req.url,
        statusCode: reply.statusCode,
        ip: client.ip,
        userAgent: client.userAgent,
        requestId: req.id,
        approvalId: ledger.approvalId,
        detail: { ...(resultId ? { resultId } : {}), ...(ledger.machineGrantIds?.length ? { machineGrantIds: ledger.machineGrantIds } : {}), ...doorDetail(req) },
      },
      req.log,
    ));
    return payload;
  });
}

export function requireAuth(req: FastifyRequest): AuthContext {
  if (!req.auth) throw Errors.unauthorized();
  return req.auth;
}

/** Service identity transports only; new routes remain denied until explicitly classified. */
export function commanderServiceRouteAllowed(method: string, route: string): boolean {
  const key = `${method === 'HEAD' ? 'GET' : method.toUpperCase()} ${normalizeRoutePattern(route)}`;
  return new Set([
    'GET /v1/persona/me', 'GET /v1/persona/inbox', 'GET /v1/persona/events',
    'GET /v1/persona/conversations', 'GET /v1/persona/conversations/:p/messages',
    'POST /v1/persona/conversations/:p/read', 'POST /v1/persona/conversations/:p/messages',
    'GET /v1/persona/attachments/:p', 'POST /v1/persona/heartbeat',
    'POST /v1/qac/turns/lease', 'POST /v1/persona/turn-grants', 'POST /v1/qac/turns/:p/grant',
    'POST /v1/qac/turns/:p/complete', 'POST /v1/runners/qac/usage',
  ]).has(key);
}
