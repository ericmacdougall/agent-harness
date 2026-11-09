import { isZeroWriteRead } from './zero-write-reads';

import { oauthAudienceAllowed, enabledOAuthOrgIds } from '../mcp-oauth/audience';
import { authenticateOAuthAccess } from '../mcp-oauth/tokens';
import { OAuthError } from '../mcp-oauth/policy';

import { commanderRequestActionClass, commanderRouteManagesAction } from '../commander-actions/registry';
import { commanderTurnOpensRoute } from '../../lib/commander-turn-routes';
import { effectiveTurnMode } from '../qa-commander-runtime/turn-grants';
import { assertTurnGrantLive, commanderDelegableAbilities } from '../qa-commander-runtime/turn-grants';
import { CEILING_REFUSAL_COPY, ceilingRefusal } from '../qa-commander-runtime/kill-switch';
import { bindCommanderOutboundApproval, hasApprovedCommanderDispatch } from '../qa-commander-runtime/outbound-approval';
import { decideCommanderAction } from '../qa-commander-runtime/action-decision';
import { observeTaintGate } from '../qa-commander-runtime/taint-observe';
import { featureCardMediaRouteAbility, featureCardMediaRouteGrant } from '../feature-cards/media-grants';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { eq, and } from 'drizzle-orm';
import { getPlatformSetting, getCommanderReleaseSetting, userTokens, type DbOrTx } from '@bugtracker/db';
import {
  USER_TOKEN_APPROVAL_HEADER,
  USER_TOKEN_SHAPE,
  expandUserTokenAbilities,
} from '@bugtracker/shared';
import { applyHostDoorWaivers } from '../../lib/desktop-token-session';
import { requestClientIp } from '../../lib/client-ip';
import { AppError, Errors } from '../../lib/errors';
import { isInProcessDispatch } from '../../lib/in-process-dispatch';
import { keyPausedError, normalizeClientTrace } from '../../lib/key-lifecycle';
import { commanderThreadsEnabled } from '../messaging/commander-thread-switch';
import { setRequestActor, setUserTokenScope } from '../../lib/request-context';
import { USER_TOKEN_FEATURE_CARD_ADMIN_ROUTES, USER_TOKEN_ORG_ADMIN_ROUTES, USER_TOKEN_WEBHOOK_ADMIN_ROUTES, USER_TOKEN_BROWSER_GRANT_ROUTES, USER_TOKEN_SENDER_IDENTITY_ROUTES, USER_TOKEN_DELEGATION_ROUTES, USER_TOKEN_MEMBERSHIP_ROUTES, USER_TOKEN_SIGNED_IN_PERSON_RULE, canonicalBodySha256, commanderOutboundAction, missingAbilities, userTokenRouteKey } from '../../lib/user-token-policy';
import { USER_TOKEN_SESSION_PREFIX } from '../../lib/credential-kind';
import { tokenGrantsAdmitRoute } from '../machines/token-grants';
import { assertOwnerCouldPerform } from './ask-precheck';
import { userTokenOrgAdminEnabled, userTokenOwnerIsOrgAdmin } from './org-admin';
import { userTokenFeatureCardsAdminAdmits } from './feature-cards-admin';
import { sessionActionFor, sessionActionPreApproved, sessionActionsEnabled, sessionActionsEnabledForOrg, userTokenRequestRoutePolicy } from './session-actions';
import {
  approvalRequestSummary,
  authenticateUserToken,
  consumeUserTokenApproval,
  recordUserTokenEvent,
  pausedOrgsForUser,
  recordUserTokenUse,
  requestUserTokenApproval,
  userTokenDataAdminAlwaysAsks,
  stripQuerySecrets,
  type UserTokenRow,
} from './service';

// API-key last-use classification; user-token telemetry uses the narrower zero-write observation policy.
export const READ_ONLY_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

/**
 * USER TOKENS: the authentication gate, called by `app.authenticate` (plugins/auth.ts) for a `Bearer gqut_...` header
 * while the platform setting `userTokens.enabled` is on. Order, each step a fresh read (nothing is cached past the
 * request, so a revoke, an expiry or the kill switch takes effect on the very next call):
 *
 *   1. failed-auth lockout for the caller's address (process-local, like the rate limiter's own counters);
 *   2. the token itself: shape, prefix lookup, constant-time hash compare, not revoked, not expired (401);
 *   3. a matched route pattern, or refuse (fail closed, as the API-key allowlist does);
 *   4. per-token request rate (429);
 *   5. NON-DELEGABLE routes (403 `user_token_non_delegable`), whatever the abilities: the explicit list, then the
 *      governance register, then every route no org API key can reach unless the policy opens it to tokens (review
 *      round 1, finding 3: a route that refuses a key refuses a token);
 *   6. the ABILITY ceiling for the route (403 `user_token_ability_missing`, naming what is missing);
 *   7. the org allow-list against an `:orgId` route param (404, the tenancy-hiding answer); deeper org checks happen
 *      in lib/access.ts from the request context set here;
 *   8. the governance carve-out a non-runner key gets on releases, sprints, gates and issue decisions;
 *   9. HUMAN APPROVAL for the sensitive subset when the token requires it -- and, for the custom-data admin routes,
 *      whatever the token says while `userTokens.dataAdmin.alwaysAsk` is on (409 `human_approval_required`, or the
 *      retry's `x-goodqa-approval-id` is spent once; the owner sees the redacted request, finding 6);
 *  10. `req.auth` is the OWNER, exactly as their own session would be, plus the token's facts.
 *
 * A request refused after step 2 is written to the token's ledger as `refused` (with the code), except on listed
 * zero-write observation routes, so the owner sees what their agent tried elsewhere.
 */

declare module 'fastify' {
  interface FastifyRequest {
    /** Set only for a request a user token is serving; read by the ledger hooks in plugins/auth.ts. */
    userTokenLedger?: {
      tokenId: string;
      userId: string;
      approvalId: string | null;
      /** Elevated machines grants this request used (modules/machines/token-grants.ts), recorded on the ledger row. */
      machineGrantIds?: string[];
    };
    /** goodqa#15561: set while a desktop session bound to a user token is the carrier (both doors); the ledger rows say so. */
    userTokenDoor?: { via: 'desktop_session'; sessionId: string; door: 'host' | 'delegated' | 'none' };
    /**
     * goodqa#15561 D9: the token facts of a bound session on the HOST door, where `req.auth` keeps the real session id.
     * Read only by the credential-minting machine routes (modules/machines/enroll/routes.ts `enrollActor`), so a machine
     * credential enrolled through a bound session is capped at the token chain's end, limited to its `orgIds` and linked to it.
     */
    boundUserToken?: { userTokenId: string; userTokenOrgIds: string[] | null; userTokenExpiresAt: Date | null };
  }
}

// ---- failed-auth lockout (per address) ------------------------------------------------------------------------

export const USER_TOKEN_FAILED_AUTH_LIMIT = 20;
export const USER_TOKEN_FAILED_AUTH_WINDOW_MS = 15 * 60_000;
export const USER_TOKEN_LOCKOUT_MS = 15 * 60_000;
const FAILURE_TABLE_MAX = 10_000;
const failures = new Map<string, { count: number; windowStart: number; lockedUntil: number }>();

function lockedOut(address: string, now: number): number | null {
  const entry = failures.get(address);
  if (!entry) return null;
  if (entry.lockedUntil > now) return entry.lockedUntil;
  return null;
}

function noteFailure(address: string, now: number): void {
  let entry = failures.get(address);
  if (!entry || now - entry.windowStart > USER_TOKEN_FAILED_AUTH_WINDOW_MS) {
    entry = { count: 0, windowStart: now, lockedUntil: 0 };
  }
  entry.count += 1;
  if (entry.count >= USER_TOKEN_FAILED_AUTH_LIMIT) entry.lockedUntil = now + USER_TOKEN_LOCKOUT_MS;
  failures.delete(address);
  failures.set(address, entry);
  while (failures.size > FAILURE_TABLE_MAX) {
    const oldest = failures.keys().next().value;
    if (oldest === undefined) break;
    failures.delete(oldest);
  }
}

// ---- per-token request rate -----------------------------------------------------------------------------------

/** Per token, per instance. Above the global limiter's 300/min/address so one busy agent on a shared box is bounded by its own budget. */
export const USER_TOKEN_REQUESTS_PER_MINUTE = 600;
let requestsPerMinute = USER_TOKEN_REQUESTS_PER_MINUTE;
const rates = new Map<string, { windowStart: number; count: number }>();

function rateAllowed(tokenId: string, now: number): { ok: true } | { ok: false; retryAfterSeconds: number } {
  let entry = rates.get(tokenId);
  if (!entry || now - entry.windowStart >= 60_000) {
    entry = { windowStart: now, count: 0 };
    rates.set(tokenId, entry);
  }
  entry.count += 1;
  if (rates.size > FAILURE_TABLE_MAX) {
    const oldest = rates.keys().next().value;
    if (oldest !== undefined && oldest !== tokenId) rates.delete(oldest);
  }
  if (entry.count > requestsPerMinute) {
    return { ok: false, retryAfterSeconds: Math.max(1, Math.ceil((entry.windowStart + 60_000 - now) / 1000)) };
  }
  return { ok: true };
}

/** Test seam: forget every lockout and rate counter, and put the per-token rate back to its real value. */
export function resetUserTokenLimitersForTests(): void {
  failures.clear();
  rates.clear();
  requestsPerMinute = USER_TOKEN_REQUESTS_PER_MINUTE;
}

/** Test seam: a smaller per-token rate, so a test does not have to send 600 requests to see the 601st refused. */
export function setUserTokenRateLimitForTests(perMinute: number): void {
  requestsPerMinute = perMinute;
}

// ---- the gate -------------------------------------------------------------------------------------------------

export interface UserTokenGateDeps {
  /** plugins/auth.ts's `isGovernanceSessionOnlyRoute`, passed in to keep this module free of an import cycle. */
  isGovernanceSessionOnlyRoute: (method: string, route: string) => boolean;
  /** plugins/auth.ts's `isApiKeyReachableRoute`: may an org API key reach this route at all (review r1 finding 3)? */
  isApiKeyReachableRoute: (method: string, route: string) => boolean;
  /**
   * plugins/auth.ts: on a `carve_out` governance route (releases, sprints, gates, issue decisions) apply the
   * `governance.keyCarveout` mode a non-runner key gets (off / shadow + audit / enforce 403). Review r1 finding 3: a
   * token went around it, because only the key path of the auth plugin applied it.
   */
  applyGovernanceCarveout: (method: string, route: string, actor: { userId: string; email: string; userTokenId: string }) => Promise<void>;
  /**
   * Review round 2, finding 2: plugins/auth.ts's per-org API-access switches -- the outreach, coordinator, `crm` and
   * `agent_knowledge` dark gates (the app's own 404) and the TASK-298 gate -- applied for the org the ROUTE names (a
   * token has no org of its own; a family route that names none fails closed). Before this only a key met them, so an
   * org admin who closed CRM to agents (`crm.api.enabled` off) still had every member's token reading it.
   */
  applyApiKeyOrgSwitches: (req: FastifyRequest, route: string, orgId: string | null, commanderTurn?: boolean) => Promise<void>;
  webOrigin: string;
}

/** The ledger detail that names a desktop-session carrier; empty for a bearer call (its rows are unchanged). */
export function doorDetail(req: FastifyRequest): Record<string, unknown> {
  return req.userTokenDoor ? { via: req.userTokenDoor.via, sessionId: req.userTokenDoor.sessionId } : {};
}

export function refusal(req: FastifyRequest, token: UserTokenRow, routePattern: string | undefined, err: AppError): AppError {
  // Observation refusals share the successful-request policy; other reads retain their denial audit.
  if (isZeroWriteRead(req.method, routePattern)) return err;
  const client = normalizeClientTrace({ ip: requestClientIp(req), userAgent: req.headers['user-agent'] });
  req.server.trackBackgroundWork(recordUserTokenEvent(
    req.server.db,
    {
      tokenId: token.id,
      userId: token.userId,
      kind: 'refused',
      method: req.method,
      route: routePattern ?? null,
      path: req.url,
      statusCode: err.statusCode,
      ip: client.ip,
      userAgent: client.userAgent,
      requestId: req.id,
      detail: { code: err.code, ...doorDetail(req) },
    },
    req.log,
  ));
  return err;
}

export function looksLikeUserToken(token: string): boolean {
  return USER_TOKEN_SHAPE.test(token) || /^gqoa_[0-9a-f]{12}_[A-Za-z0-9_-]{43}$/.test(token);
}

/** Parser admission only: a matching prefix never authenticates a secret. The credential gate still verifies it. */
export async function userTokenCredentialEnabled(db: DbOrTx, presented: string): Promise<boolean> {
  if ((await getPlatformSetting(db, 'userTokens.enabled')) === true ||
      (await getPlatformSetting(db, 'userTokens.commanderTurnsOnly')) === true) return true;
  const prefix = USER_TOKEN_SHAPE.exec(presented)?.[1];
  if (!prefix) return false;
  const candidates = await db.select({ orgIds: userTokens.orgIds }).from(userTokens)
    .where(and(eq(userTokens.tokenPrefix, prefix), eq(userTokens.createdVia, 'commander_turn')));
  for (const candidate of candidates) {
    if (candidate.orgIds?.length === 1 &&
        await getCommanderReleaseSetting(db, 'userTokens.commanderTurnsOnly', candidate.orgIds[0]!)) return true;
  }
  return false;
}

/** `userTokens.membership` (default ON). A failed read is OFF: the routes fall back to signed-in only. */
export async function userTokenMembershipEnabled(db: import('@bugtracker/db').DbOrTx): Promise<boolean> {
  return (await getPlatformSetting(db, 'userTokens.membership').catch(() => false)) === true;
}

/**
 * The platform kill switch `userTokens.enabled` (a Commander turn credential may instead be admitted by its org's own
 * release setting). Shared by the bearer credential step and the desktop-session load (goodqa#15561 D1): a switch turned off
 * ends a bound session exactly as it ends a bearer call.
 */
export async function userTokensPlatformAllows(db: DbOrTx, token: Pick<UserTokenRow, 'createdVia' | 'orgIds'>): Promise<boolean> {
  if ((await getPlatformSetting(db, 'userTokens.enabled')) === true) return true;
  return token.createdVia === 'commander_turn' && token.orgIds?.length === 1 && (await getCommanderReleaseSetting(db, 'userTokens.commanderTurnsOnly', token.orgIds[0]!)) === true;
}

/** Credential-only verification shared with preValidation. No body, route policy, ledger or usage writes.
 * Unknown credentials retain the existing per-address failure counter; successful probes do not meter use. */
export async function authenticateUserTokenCredential(
  req: FastifyRequest,
  reply: FastifyReply,
  presented: string,
  now = Date.now(),
) {
  const address = requestClientIp(req);
  const locked = lockedOut(address, now);
  if (locked) {
    reply.header('retry-after', String(Math.max(1, Math.ceil((locked - now) / 1000))));
    throw new AppError(429, 'user_token_locked_out', 'Too many failed user-token attempts from this address. Try again later.');
  }
  let found;
  try {
    found = presented.startsWith('gqoa_') ? await authenticateOAuthAccess(req.server.db, presented, new Date(now)) : await authenticateUserToken(req.server.db, presented, new Date(now));
  } catch (err) {
    // An expired token is a real token presented by its holder, not a guess; only unknown tokens count towards lockout.
    if (!(err instanceof AppError && err.code === 'user_token_expired')) noteFailure(address, now);
    if (err instanceof OAuthError) throw Errors.unauthorized('Invalid OAuth token');
    throw err;
  }
  const { token } = found;

  if (token.audience && !oauthAudienceAllowed(req.routeOptions.url, req.headers)) throw Errors.unauthorized('Invalid token audience');
  if (token.createdVia === 'oauth' && (await getPlatformSetting(req.server.db, 'mcp.oauth.enabled')) !== true) throw Errors.unauthorized('OAuth is disabled');
  if (token.createdVia === 'oauth') {
    const { organizations } = await import('@bugtracker/db');
    const { inArray } = await import('drizzle-orm');
    const orgs = token.orgIds?.length ? await req.server.db.select({ id: organizations.id, overrides: organizations.entitlementOverrides }).from(organizations).where(inArray(organizations.id, token.orgIds)) : [];
    // Narrow the effective allow-list before establishing request scope, including project/issue routes and list_orgs.
    token.orgIds = enabledOAuthOrgIds(orgs);
  }
  if (!(await userTokensPlatformAllows(req.server.db, token))) throw Errors.unauthorized('User tokens are disabled');

  return found;
}

export async function authenticateUserTokenRequest(
  req: FastifyRequest,
  reply: FastifyReply,
  presented: string,
  deps: UserTokenGateDeps,
): Promise<void> {
  const now = Date.now();
  await applyUserTokenRoutePolicy(req, reply, await authenticateUserTokenCredential(req, reply, presented, now), deps, 'bearer', now);
}

/** Which door reached the gate: a `Bearer gqut_` header, or a desktop session bound to the token (goodqa#15561). */
export type UserTokenGateVia = 'bearer' | 'desktop_session';
/** A desktop session bound to the token, as the plugin resolved it: which door, the session's real id, the route key. */
export interface BoundDoorContext { door: 'host' | 'delegated'; sessionId: string; routeKey: string }
export type UserTokenCredential = Awaited<ReturnType<typeof authenticateUserTokenCredential>>;

/**
 * goodqa#15561 S1a: everything the gate does AFTER the credential is proven (steps 3 to 10 above), extracted unchanged so a
 * second credential carrier (a desktop session bound to a user token) can run the SAME policy instead of a second copy.
 * The bearer path calls it with `via: 'bearer'` and behaves exactly as before; the credential step (lockout, secret,
 * revoke, expiry, the `userTokens.enabled` kill switch) stays in `authenticateUserTokenCredential`.
 */
export async function applyUserTokenRoutePolicy(
  req: FastifyRequest,
  reply: FastifyReply,
  credential: UserTokenCredential,
  deps: UserTokenGateDeps,
  via: UserTokenGateVia,
  now = Date.now(),
  bound?: BoundDoorContext,
): Promise<void> {
  const { token, user, effectiveExpiresAt } = credential;
  if ((via === 'desktop_session') !== !!bound) throw Errors.forbidden('A desktop session reaches the token gate only through a bound door');
  if (bound) {
    // The bound token is a human-minted token. The commander-grant, continuation and session-action branches below are
    // unreachable for it: an oauth or commander_turn token is never the bound token (loadBoundUserToken), and session actions are refused.
    if (token.createdVia === 'commander_turn' || token.createdVia === 'oauth') throw Errors.unauthorized('Session is no longer valid');
    req.userTokenDoor = { via: 'desktop_session', sessionId: bound.sessionId, door: bound.door };
  }
  const grant = token.createdVia === 'commander_turn' ? await assertTurnGrantLive(req.server.db, token, new Date(now)) : undefined;
  let continuationApproval: { id: string; reason: string } | undefined;
  let imageEffectContinuation = false;
  // This server-created continuation can dispatch only its exact approved request.
  if (grant?.turn.provider === 'commander_action' && !hasApprovedCommanderDispatch(req, token)) {
    // The parent decision can race an owner disabling Commander threads. Re-read the
    // switch here so the nested exact request fails closed rather than completing a
    // write that can no longer receive its durable executed receipt.
    if (!(await commanderThreadsEnabled(req.server.db, grant.turn.orgId))) {
      throw Errors.forbidden('Commander threads are disabled');
    }
    const { userTokenApprovals } = await import('@bugtracker/db');
    const { eq } = await import('drizzle-orm');
    const [approval] = await req.server.db.select().from(userTokenApprovals).where(eq(userTokenApprovals.tokenId, token.id));
    const query = req.url.includes('?') ? req.url.slice(req.url.indexOf('?') + 1) : '';
    if (approval && req.headers[USER_TOKEN_APPROVAL_HEADER] === approval.id && approval.reason === 'commander.outbound')
      imageEffectContinuation = await (await import('../studio/image-continuation')).imageChatContinuationApproved(req, req.server.db, token, approval);
    if (!approval || req.headers[USER_TOKEN_APPROVAL_HEADER] !== approval.id || req.method !== approval.method || stripQuerySecrets(req.url) !== approval.path || (!imageEffectContinuation && canonicalBodySha256({ body: req.body ?? null, query }) !== approval.bodySha256)) {
      throw new AppError(409, 'approval_mismatch', 'This continuation can run only the exact approved request');
    }
    continuationApproval = approval;
    if (imageEffectContinuation) req.commanderImageEffectApproval = approval.id;
  }
  const sessionActionsOn = !grant && await sessionActionsEnabled(req.server.db);

  const routePattern = req.routeOptions?.url;
  if (!routePattern) throw refusal(req, token, routePattern, Errors.forbidden('This route is not available to user tokens'));

  const rate = rateAllowed(token.id, now);
  if (!rate.ok) {
    reply.header('retry-after', String(rate.retryAfterSeconds));
    // Deliberately NOT written to the ledger: a token over its rate would otherwise turn every refused request into a
    // database write, which is the load the limit exists to shed. One log line (ids only) instead.
    req.log.warn({ userTokenId: token.id, route: routePattern }, 'user token rate limited');
    throw new AppError(429, 'user_token_rate_limited', 'This user token is sending too many requests. Slow down.', {
      retryAfterSeconds: rate.retryAfterSeconds,
    });
  }

  // Review round 2, finding 2: the org's API-access switches first, as for a key (their 404 reveals nothing the
  // refusals below would). The org is the one the route names.
  const params = (req.params ?? {}) as Record<string, unknown>;
  const routeOrgId = typeof params.orgId === 'string' ? params.orgId.toLowerCase() : null;
  if (routeOrgId) params.orgId = routeOrgId; // Canonical scope reaches handlers too (including signed OAuth state).
  try {
    await deps.applyApiKeyOrgSwitches(req, routePattern, routeOrgId, !!grant);
  } catch (err) {
    if (err instanceof AppError) throw refusal(req, token, routePattern, err);
    throw err;
  }

  // goodqa#5168 (P0.7): the org's Commander ceiling (full / no_outbound / read_only, the stricter of the platform's and
  // the org admin's; qa-commander-runtime/kill-switch.ts). For every Commander turn grant, BEFORE any route policy or
  // action-class decision below, and whether or not AI threads are on: an incident switch must not depend on them.
  if (grant) {
    const blocked = ceilingRefusal(grant.ceiling, req.method, routePattern, req.body);
    if (blocked) throw refusal(req, token, routePattern, new AppError(403, 'commander_ceiling', CEILING_REFUSAL_COPY[blocked.rule], blocked));
  }

  const candidate = sessionActionFor(req.method, routePattern);
  const orgOptIn = !!(sessionActionsOn && candidate && routeOrgId && await sessionActionsEnabledForOrg(req.server.db, routeOrgId));
  const { policy, sessionAction, disabled } = userTokenRequestRoutePolicy(req.method, routePattern, deps.isApiKeyReachableRoute(req.method, routePattern), sessionActionsOn, orgOptIn);
  if (bound) {
    // A desktop session never reaches a session action (its grant is an explicit human grant to a token, not to a screen).
    if (candidate) throw refusal(req, token, routePattern, new AppError(403, 'user_token_non_delegable', 'A desktop session cannot perform session actions.', { rule: 'session_action' }));
    // Host door: the same gate, with the three named waivers (lib/desktop-token-session.ts applyHostDoorWaivers).
    if (bound.door === 'host') applyHostDoorWaivers(req.method, bound.routeKey, policy);
  }
  // Outreach authoring/start (lib/commander-turn-routes.ts): the few person-only routes a Commander TURN GRANT -- and
  // only that credential -- may reach. Everything below still applies (abilities, org list, tiered action card).
  if (grant && commanderTurnOpensRoute(req.method, routePattern)) policy.signedInPersonOnly = false;
  if (grant && ((req.method === 'POST' && routePattern === '/v1/me/user-tokens') || policy.signedInPersonOnly || sessionActionFor(req.method, routePattern) || USER_TOKEN_MEMBERSHIP_ROUTES.has(userTokenRouteKey(req.method, routePattern)) || USER_TOKEN_ORG_ADMIN_ROUTES.has(userTokenRouteKey(req.method, routePattern)) || USER_TOKEN_FEATURE_CARD_ADMIN_ROUTES.has(userTokenRouteKey(req.method, routePattern)) || USER_TOKEN_WEBHOOK_ADMIN_ROUTES.has(userTokenRouteKey(req.method, routePattern)) || USER_TOKEN_BROWSER_GRANT_ROUTES.has(userTokenRouteKey(req.method, routePattern)) || USER_TOKEN_SENDER_IDENTITY_ROUTES.has(userTokenRouteKey(req.method, routePattern)) || USER_TOKEN_DELEGATION_ROUTES.has(userTokenRouteKey(req.method, routePattern)))) throw refusal(req, token, routePattern, new AppError(403, 'user_token_non_delegable', 'Commander turns cannot change permissions or perform signed-in actions'));
  const mediaAbility = featureCardMediaRouteAbility(req.method, routePattern);
  if (mediaAbility) {
    let grantId: string | null;
    try { grantId = await featureCardMediaRouteGrant(req.server.db, { userTokenId: token.id, userTokenAbilities: token.abilities }, req.method, routePattern); }
    catch (err) { if (err instanceof AppError) throw refusal(req, token, routePattern, err); throw err; }
    // Only these exact media/read routes use the independent platform grant.
    if (grantId) {
      policy.nonDelegable = null;
      policy.signedInPersonOnly = false;
      policy.abilities = [];
      policy.approvalReason = null;
      policy.approvalAlways = false;
    }
  }
  if (disabled) throw refusal(req, token, routePattern, new AppError(403, 'user_token_non_delegable', 'Session actions require the platform gate and the org owner’s opt-in.', { rule: 'session_actions_disabled' }));
  if (sessionAction) {
    // Explicit opt-in only: `all`, operator tokens and token-minted descendants do not silently gain these powers.
    if (!token.abilities.includes(sessionAction.ability) || !token.sessionActionGrantedAt) throw refusal(req, token, routePattern, new AppError(403, 'user_token_ability_missing', 'This session action requires an explicit human grant.', { missing: [sessionAction.ability] }));
  }
  // The one elevatable rule (`machines`): an org admin's live elevated grant for THIS token, whose level covers the
  // method, in the route's org when it names one, while `machines.tokenGrants` is on and the token holds `machines`
  // (modules/machines/token-grants.ts). Otherwise the rule refuses exactly as before.
  const elevated =
    !bound &&
    policy.nonDelegable?.elevatedBy === 'machine_token_grant' &&
    (await tokenGrantsAdmitRoute(req.server.db, { userTokenId: token.id, userId: user.id, userTokenAbilities: token.abilities }, req.method, routeOrgId)) !== null;
  if (policy.nonDelegable && !elevated) {
    throw refusal(req, token, routePattern, new AppError(403, 'user_token_non_delegable', policy.nonDelegable.reason, {
      rule: policy.nonDelegable.code,
    }));
  }
  if (deps.isGovernanceSessionOnlyRoute(req.method, routePattern)) {
    throw refusal(req, token, routePattern, new AppError(403, 'user_token_non_delegable', 'This governance action needs a signed-in person; no token can do it.', {
      rule: 'governance_sign_off',
    }));
  }
  // Driver usertoken-admin: the project-membership opening has its own kill switch (`userTokens.membership`, default
  // on). Off, or unreadable: the route is signed-in only again, refused with the same rule as before it opened.
  if (!policy.signedInPersonOnly && USER_TOKEN_MEMBERSHIP_ROUTES.has(userTokenRouteKey(req.method, routePattern)) && !(await userTokenMembershipEnabled(req.server.db))) {
    policy.signedInPersonOnly = true;
  }
  if (USER_TOKEN_ORG_ADMIN_ROUTES.has(userTokenRouteKey(req.method, routePattern)) && !(await userTokenOrgAdminEnabled(req.server.db, req.server.config, user.email))) {
    policy.signedInPersonOnly = true;
  }
  // Lane cards-admin: the feature-card and roadmap admin openings admit only a `platform.admin` token whose owner is a
  // platform admin, while `userTokens.featureCardsAdmin` is on. Anyone else is refused exactly as before the opening.
  if (USER_TOKEN_FEATURE_CARD_ADMIN_ROUTES.has(userTokenRouteKey(req.method, routePattern)) && !(await userTokenFeatureCardsAdminAdmits(req.server.db, req.server.config, user, token.abilities))) {
    policy.signedInPersonOnly = true;
  }
  // Lane usertoken-webhooks: the org webhook openings admit only a token whose owner is an admin of the route's org (the
  // handler then re-checks org:manage_integrations / registrant ownership). Anyone else is refused exactly as before.
  if (!policy.signedInPersonOnly && USER_TOKEN_WEBHOOK_ADMIN_ROUTES.has(userTokenRouteKey(req.method, routePattern)) && !(await userTokenOwnerIsOrgAdmin(req.server.db, user.id, routeOrgId))) {
    policy.signedInPersonOnly = true;
  }
  // Eric 2026-11-06: the agent-browser grant openings admit only a token whose owner is an admin of the route's org (the
  // handler re-checks the admin role, the key's org, project and origins). Anyone else is refused exactly as before.
  if (!policy.signedInPersonOnly && USER_TOKEN_BROWSER_GRANT_ROUTES.has(userTokenRouteKey(req.method, routePattern)) && !(await userTokenOwnerIsOrgAdmin(req.server.db, user.id, routeOrgId))) {
    policy.signedInPersonOnly = true;
  }
  // Review round 1, finding 3: no org API key can reach this route, and it is not one the policy opens to tokens.
  if (policy.signedInPersonOnly) {
    throw refusal(req, token, routePattern, new AppError(403, 'user_token_non_delegable', USER_TOKEN_SIGNED_IN_PERSON_RULE.reason, {
      rule: USER_TOKEN_SIGNED_IN_PERSON_RULE.code,
    }));
  }

  // QAC upgrades P0.9 (goodqa#5170): the Commander action policy applies to EVERY turn grant, not only where AI threads
  // are on (they default to off). The switch decides only how a Tiered turn asks: the thread action card
  // (prepareCommanderAction, `actionGrant`) with threads on, the user-token approval (approveUrl) with them off -- the
  // latter only while `commander.threadsOffApprovals` is on (default off, pending the owner's UX ruling). `never` and
  // Plan refuse in every org regardless.
  // Route-managed writes (lease/complete/usage, issue proposals, machine leases) keep their own gates.
  const policyGrant = grant && !commanderRouteManagesAction(req.method, routePattern) ? grant : undefined;
  const threadsOn = policyGrant ? await commanderThreadsEnabled(req.server.db, policyGrant.turn.orgId) : false;
  const actionGrant = policyGrant && threadsOn ? policyGrant : undefined;
  const liveMode = policyGrant ? await effectiveTurnMode(req.server.db, policyGrant.turn, policyGrant.scope.thread) : undefined;
  const actionClass = policyGrant ? commanderRequestActionClass(req.method, routePattern, req.body) : undefined;
  const commanderMode = grant?.turn.effectiveMode === 'plan' || liveMode === 'plan' ? 'plan' : grant?.turn.effectiveMode === 'bypass' && liveMode === 'bypass' ? 'bypass' : 'tiered';
  // The threads-off ask is held behind `commander.threadsOffApprovals` (default off) until the owner rules on its UX.
  // Read only when it could matter; an unreadable setting asks (fail closed).
  const threadsOffApprovals =
    !!policyGrant && !threadsOn && !!actionClass && actionClass !== 'read' && actionClass !== 'never'
      ? (await getPlatformSetting(req.server.db, 'commander.threadsOffApprovals').catch(() => true)) === true
      : false;
  const decision = policyGrant && actionClass
    ? decideCommanderAction({
        trigger: policyGrant.turn.trigger,
        mode: commanderMode,
        actionClass,
        threadsEnabled: threadsOn,
        threadsOffApprovals,
        stage: 'gate',
        lateOutbound: !!commanderOutboundAction(req.method, routePattern),
      })
    : undefined;
  if (decision?.kind === 'refuse') throw refusal(req, token, routePattern, new AppError(403, decision.code, decision.message, decision.code === 'user_token_ability_missing' ? { missing: decision.missing } : undefined));
  // goodqa#14905 (QAC Q2, shadow): record taint and would-decisions for TURN-scoped tokens only; never changes the decision above.
  if (policyGrant && actionClass && decision) {
    await observeTaintGate(req.server.db, req.log, {
      turn: policyGrant.turn, method: req.method, routePattern, stage: 'gate', enforced: decision, markTaint: !commanderOutboundAction(req.method, routePattern),
      decisionInput: { trigger: policyGrant.turn.trigger, mode: commanderMode, actionClass, threadsEnabled: threadsOn, threadsOffApprovals, stage: 'gate', lateOutbound: !!commanderOutboundAction(req.method, routePattern) },
    });
  }
  const held = expandUserTokenAbilities(token.abilities);
  // Plan stores only read. Registered retrieval POSTs are reads too; legacy policy
  // calls them writes because of their HTTP method. Keep the product operation
  // ceiling tied to the fail-closed registry and retain every handler's RBAC.
  const planRead = !!policyGrant && commanderMode === 'plan' && actionClass === 'read' && held.has('read');
  if ((grant?.turn.effectiveMode === 'plan' && ['GET', 'HEAD'].includes(req.method) && held.has('read')) || planRead) {
    for (const ability of commanderDelegableAbilities()) {
      if (ability !== 'write') held.add(ability);
    }
  }
  const required = planRead ? policy.abilities.filter(ability => ability !== 'write') : policy.abilities;
  const missing = missingAbilities(held, required);
  if (missing.length > 0) {
    throw refusal(req, token, routePattern, new AppError(403, 'user_token_ability_missing', `This user token does not have the ${missing.join(', ')} abilit${missing.length === 1 ? 'y' : 'ies'} this route needs.`, {
      missing: token.createdVia === 'oauth' ? missing.map(a => `goodqa:${a}`) : missing,
      required: token.createdVia === 'oauth' ? policy.abilities.map(a => `goodqa:${a}`) : policy.abilities,
    }));
  }

  // The org allow-list, first line: a route that names its org. Deeper org checks (a project's or an issue's org) run
  // in lib/access.ts from the request context set just below.
  if (token.orgIds && routeOrgId && !token.orgIds.includes(routeOrgId)) {
    throw refusal(req, token, routePattern, Errors.notFound('Organization not found'));
  }

  // Review round 2, finding 3: the org master pause. A token is an agent; where its owner's org admins paused agents
  // it stops, on a route naming that org here and on a project/issue route at the lib/access.ts chokepoints.
  const pausedOrgs = await pausedOrgsForUser(req.server.db, user.id, new Date(now));
  const pausedUntil = routeOrgId ? pausedOrgs.get(routeOrgId) : undefined;
  if (pausedUntil) {
    throw refusal(req, token, routePattern, keyPausedError({ scope: 'org', reason: null, pausedAt: null, until: pausedUntil }));
  }

  // Fail closed: without a request context the allow-list and the platform-admin ceiling would silently not apply.
  if (!setUserTokenScope({ tokenId: token.id, orgIds: token.orgIds, platformAdmin: held.has('platform.admin'), pausedOrgs, commanderTurnId: token.commanderTurnId, audienceUserIds: grant?.scope.audience.map(human => human.userId), projectIds: token.projectIds, conversationScope: grant ? grant.scope.conversationScope.filter((id) => token.conversationScope?.includes(id)) : token.conversationScope })) {
    throw Errors.forbidden('User token scope could not be established');
  }

  // Governance carve-out, as for a non-runner key (before asking the owner: an enforced refusal is not approvable).
  try {
    await deps.applyGovernanceCarveout(req.method, routePattern, { userId: user.id, email: user.email, userTokenId: token.id });
  } catch (err) {
    if (err instanceof AppError) throw refusal(req, token, routePattern, err);
    throw err;
  }

  let approvalId: string | null = imageEffectContinuation ? continuationApproval!.id : null;
  const commanderOutbound = !!grant && bindCommanderOutboundApproval(req, token);
  // Lane gq-ut-data: the custom-data admin routes ask even a token whose own switch is off, while the platform setting
  // `userTokens.dataAdmin.alwaysAsk` is on (its default; read only when it could matter, and fail closed).
  if ((actionGrant && actionClass !== 'read' && actionClass !== 'write_undoable') || decision?.kind === 'ask') policy.approvalReason ??= actionClass ?? 'write_no_undo';
  // Edits may change the body's class, but every exact continuation still spends
  // its original approval once and reuses its one durable action receipt.
  if (continuationApproval) policy.approvalReason = continuationApproval.reason;
  // Outbound effects retain main's late guard, which binds the dynamic recipient
  // and attachment facts before it consumes its own exact permit.
  const legacyMustAsk =
    !commanderOutbound &&
    policy.approvalReason !== null &&
    (sessionAction ? sessionAction.sensitive && !sessionActionPreApproved(token, sessionAction.ability, now) : (token.requireHumanApproval || (policy.approvalAlways && (await userTokenDataAdminAlwaysAsks(req.server.db)))));
  const mustAsk =
    (!!continuationApproval && !imageEffectContinuation) ||
    legacyMustAsk ||
    (decision?.kind === 'ask' && !commanderOutbound);
  if (mustAsk && policy.approvalReason) {
    // The approval is bound to the method, the path WITHOUT its query values (stored, shown to the owner) and one digest
    // over the request body AND the raw query string -- so a query value is bound but never stored (it can carry a
    // secret someone pasted into a URL).
    const queryIndex = req.url.indexOf('?');
    const rawQuery = queryIndex >= 0 ? req.url.slice(queryIndex + 1) : '';
    const bodySha256 = canonicalBodySha256({ body: req.body ?? null, query: rawQuery });
    const displayPath = stripQuerySecrets(req.url);
    const header = req.headers[USER_TOKEN_APPROVAL_HEADER];
    const presentedApproval = typeof header === 'string' ? header.trim() : undefined;
    if (!presentedApproval) {
      // An enforced refusal is not approvable: refuse what the owner could never do BEFORE asking them to approve it.
      try {
        await assertOwnerCouldPerform(req.server.db, user.id, req.method, routePattern, params, req.body);
      } catch (err) {
        if (err instanceof AppError) throw refusal(req, token, routePattern, err);
        throw err;
      }
      const approval = await requestUserTokenApproval(req.server.db, {
        token,
        method: req.method,
        route: routePattern,
        path: displayPath,
        bodySha256,
        reason: policy.approvalReason,
        orgId: routeOrgId,
        webOrigin: deps.webOrigin,
        request: approvalRequestSummary(req.body, rawQuery),
      });
      const action = actionGrant ? await (await import('../commander-actions/service')).prepareCommanderAction(req, token, actionGrant.turn, approval.id, true) : undefined;
      throw refusal(
        req,
        token,
        routePattern,
        new AppError(409, 'human_approval_required', `This action (${policy.approvalReason}) needs its owner's approval first. Ask them to approve it, then retry the same request with the ${USER_TOKEN_APPROVAL_HEADER} header.`, {
          actionId: action?.id,
          approvalId: approval.id,
          status: approval.status,
          reason: policy.approvalReason,
          expiresAt: approval.expiresAt.toISOString(),
          header: USER_TOKEN_APPROVAL_HEADER,
          approveUrl: `${deps.webOrigin.replace(/\/+$/, '')}/account/user-tokens?approval=${approval.id}`,
        }),
      );
    }
    try {
      // Session actions spend inside the handler's action+audit transaction, never in this earlier gate.
      const spent = sessionAction ? { id: presentedApproval } : await consumeUserTokenApproval(req.server.db, {
        approvalId: presentedApproval,
        token,
        method: req.method,
        path: displayPath,
        bodySha256,
      });
      approvalId = spent.id;
    } catch (err) {
      if (err instanceof AppError) throw refusal(req, token, routePattern, err);
      throw err;
    }
  }

  if (actionGrant && actionClass !== 'read') await (await import('../commander-actions/service')).prepareCommanderAction(req, token, actionGrant.turn, approvalId, false);

  if (bound?.door === 'host') {
    // The host door keeps the REAL session: the presence proof and the consent audit read its id as a sessions uuid.
    req.auth = { userId: user.id, sessionId: bound.sessionId, email: user.email };
    req.boundUserToken = { userTokenId: token.id, userTokenOrgIds: token.orgIds ? [...token.orgIds] : null, userTokenExpiresAt: effectiveExpiresAt };
  } else req.auth = {
    userId: user.id,
    sessionId: `${USER_TOKEN_SESSION_PREFIX}${token.id}`,
    // The owner's real address, so every live check that reads it (the platform-admin allowlist among them) answers as
    // it would for the owner signed in. The `platform.admin` ability ceiling is applied inside those checks.
    email: user.email,
    userTokenId: token.id,
    userTokenName: token.name,
    userTokenAgentLabel: token.agentLabel,
    userTokenAbilities: token.abilities.filter((a) => sessionActionsOn || !a.startsWith('session:')),
    userTokenOrgIds: token.orgIds ? [...token.orgIds] : null,
    userTokenRequireHumanApproval: token.requireHumanApproval,
    // Finding 8 (round 2): the LIVE end (its own or an ancestor's, whichever is first), so a key minted now inherits it.
    userTokenExpiresAt: effectiveExpiresAt,
    userTokenApprovalId: sessionAction ? undefined : approvalId ?? undefined,
  };
  if (sessionAction && routeOrgId) {
    const q = req.url.indexOf('?');
    req.userTokenSessionAction = { ...sessionAction, orgId: routeOrgId, approvalId: approvalId ?? undefined, bodySha256: canonicalBodySha256({ body: req.body ?? null, query: q < 0 ? '' : req.url.slice(q + 1) }) };
  }
  setRequestActor(bound?.door === 'host' ? { userId: user.id } : { userId: user.id, userTokenId: token.id });
  const client = normalizeClientTrace({ ip: requestClientIp(req), userAgent: req.headers['user-agent'] });
  if (!isZeroWriteRead(req.method, routePattern)) {
    req.server.trackBackgroundWork(recordUserTokenUse(req.server.db, token.id, { ...client, inProcess: isInProcessDispatch(req.headers) }, req.log));
  }
  req.userTokenLedger = { tokenId: token.id, userId: user.id, approvalId: sessionAction ? null : approvalId };
}
