import { sql } from 'drizzle-orm';
import { machines, organizations, auditEvents, type DbOrTx } from '@bugtracker/db';
import { eq } from 'drizzle-orm';
import type { FastifyRequest } from 'fastify';
import { expandUserTokenAbilities } from '@bugtracker/shared';

/**
 * goodqa#15158: a desktop session started from a user token (POST /v1/me/desktop-session) is BOUND to that token.
 *
 * The binding is the session's `login_method`, `user_token_desktop:<token id>`. Token rotation (refresh) carries
 * `login_method` forward unchanged, so every session in the chain stays bound without touching the rotation code. Three
 * rules follow from the binding, each enforced where the session is used, so the session can never be stronger,
 * longer-lived or harder to revoke than the token that started it:
 *   1. LIVENESS: the minting token (and every token above it) must be live on every authenticated request and every
 *      refresh. A revoked or expired token ends the session at once.
 *   2. LIFETIME: `createSession` (mint and every rotation) caps the session's expiry at the earliest end of the token chain.
 *   3. SCOPE: a bound session may call only the routes the desktop app needs as a host (`desktopTokenSessionMayUse`). It is
 *      never "a person signed in": it cannot prove recent authentication, delete the account, sign other devices out,
 *      mint keys or tokens, or reach any session-only route.
 */
export const USER_TOKEN_DESKTOP_LOGIN_PREFIX = 'user_token_desktop:';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** `fingerprint` = first 16 hex of the token's stored hash: the secret generation the session was started under. */
export function desktopLoginMethodFor(tokenId: string, fingerprint: string): string {
  return `${USER_TOKEN_DESKTOP_LOGIN_PREFIX}${tokenId}:${fingerprint}`;
}

/** The minting token id when `loginMethod` is a bound desktop session; null otherwise. A malformed bound value yields the empty marker (never "unbound"). */
export function desktopMintingTokenId(loginMethod: string | null | undefined): string | null {
  if (typeof loginMethod !== 'string' || !loginMethod.startsWith(USER_TOKEN_DESKTOP_LOGIN_PREFIX)) return null;
  const id = loginMethod.slice(USER_TOKEN_DESKTOP_LOGIN_PREFIX.length).split(':')[0] ?? '';
  return UUID.test(id) ? id.toLowerCase() : '';
}

/** The secret generation a bound session was started under; '' for a malformed binding (never matches). */
export function desktopMintingFingerprint(loginMethod: string | null | undefined): string {
  if (typeof loginMethod !== 'string' || !loginMethod.startsWith(USER_TOKEN_DESKTOP_LOGIN_PREFIX)) return '';
  const fp = loginMethod.split(':')[2] ?? '';
  return /^[0-9a-f]{16}$/.test(fp) ? fp : '';
}

/**
 * goodqa#15561 (D6): what a token must hold to START a desktop session (mint and every refresh): the right to sign in
 * and to read. It no longer needs `machines`, `write` or `tokens.create_other_keys` just to open the app (a CRM-view
 * token would otherwise have to carry the ability to mint org API keys). What a session can DO is the token gate's
 * answer for each route (`applyUserTokenRoutePolicy`), so a token without `machines` keeps a working app for the
 * delegated surfaces and is refused the machine routes (`user_token_ability_missing`), exactly as a bearer call is.
 */
export const DESKTOP_SESSION_REQUIRED_ABILITIES = ['desktop_signin', 'read'] as const;
/** Per request only the sign-in right is required: narrowing `read` or anything else narrows the session through the gate, it does not end it. */
export const DESKTOP_SESSION_LIVE_ABILITIES = ['desktop_signin'] as const;

export interface DesktopBindingState {
  live: boolean;
  /** Earliest end among the token and every token above it; null when none expires. */
  endsAt: Date | null;
}

/** Live means: found for this owner, and neither it nor any ancestor is revoked or past its end. */
export async function desktopBindingState(db: DbOrTx, userId: string, tokenId: string, fingerprint: string | null, now = new Date()): Promise<DesktopBindingState> {
  if (!UUID.test(tokenId)) return { live: false, endsAt: null };
  // Secret generation: a rotation changes the stored hash, so a session started (or refreshed) under an older secret
  // is dead, whatever the timing of the rotation relative to a concurrent refresh. null = no check (minting reads the row itself).
  if (fingerprint !== null) {
    const hrow = (await db.execute(sql`select left(token_hash, 16) as fp, abilities from user_tokens where id = ${tokenId} and user_id = ${userId}`)) as unknown as Array<{ fp: string; abilities: string[] }>;
    if (!hrow[0] || hrow[0].fp !== fingerprint) return { live: false, endsAt: null };
    const held = expandUserTokenAbilities(hrow[0].abilities ?? []);
    if (!DESKTOP_SESSION_REQUIRED_ABILITIES.every((a) => held.has(a))) return { live: false, endsAt: null };
  }
  const rows = (await db.execute(sql`
    with recursive chain as (
      select id, created_by_token_id, expires_at, revoked_at from user_tokens where id = ${tokenId} and user_id = ${userId}
      union
      select p.id, p.created_by_token_id, p.expires_at, p.revoked_at
        from user_tokens p join chain c on p.id = c.created_by_token_id
       where p.user_id = ${userId}
    )
    select count(*)::int as n,
           coalesce(bool_or(revoked_at is not null), false) as revoked,
           min(expires_at) as ends_at
      from chain`)) as unknown as Array<{ n: number; revoked: boolean; ends_at: Date | string | null }>;
  const row = rows[0];
  if (!row || row.n === 0 || row.revoked === true) return { live: false, endsAt: null };
  const endsAt = row.ends_at === null ? null : new Date(row.ends_at);
  if (endsAt && endsAt.getTime() <= now.getTime()) return { live: false, endsAt };
  return { live: true, endsAt };
}

/**
 * The routes a token-bound desktop session may call: what the desktop app does as a HOST (enroll this computer, show
 * its state, run the agent-browser consent). Spelled like userTokenRouteKey (`METHOD /v1/path/:p`). Creating a remote
 * session (the controller side), granting or approving controllers, keys, tokens, billing, account and every other
 * route are NOT here.
 */
const ALLOWED: ReadonlySet<string> = new Set([
  'GET /v1/me',
  'GET /v1/orgs',
  'GET /v1/notifications',
  'GET /v1/notifications/unread-count',
  'GET /v1/desktop/update-status',
  'GET /v1/me/machines',
  // The desktop's own machine routes (apps/desktop agent-browser/main.ts): who this computer is, the presence proof, and
  // the agent-browser context and consent (the subtree below).
  'GET /v1/machines/:p',
  'POST /v1/machines/:p/presence-challenge',
  // goodqa#15158: choose which agents may use THIS computer's internal browser (merge-only, browser-only; handler in modules/machines/remote-setup.ts).
  'POST /v1/machines/:p/browser-setup',
  'GET /v1/me/remote-control/catalog',
  'GET /v1/me/machine-enrollments',
  'POST /v1/me/machine-enrollments',
  'GET /v1/me/machine-enrollments/:p',
  'POST /v1/me/machine-enrollments/:p/cancel',
  'GET /v1/orgs/:p/machines',
  'GET /v1/orgs/:p/personas',
  'GET /v1/orgs/:p/api-keys/agents',
  'GET /v1/orgs/:p/machines/remote-sessions',
  'GET /v1/orgs/:p/machines/remote-sessions/availability',
  'GET /v1/orgs/:p/machines/remote-sessions/:p',
  'POST /v1/orgs/:p/machines/remote-sessions/:p/stop',
  'POST /v1/orgs/:p/machines/remote-sessions/:p/renew',
]);
export const DESKTOP_TOKEN_SESSION_ROUTES: readonly string[] = [...ALLOWED];

/** The host-side subtrees of ONE remote session (consent, activity, attachments, browser pairing): any method, any suffix. */
const ALLOWED_SUBTREES: readonly RegExp[] = [
  /^\/v1\/machines\/:p\/agent-browser(\/|$)/,
  /^\/v1\/orgs\/:p\/machines\/remote-sessions\/:p\/agent-browser(\/|$)/,
  /^\/v1\/orgs\/:p\/machines\/remote-sessions\/:p\/browser-pairing(\/|$)/,
];

/** A route pattern as the allow-list spells it: every `:param` is `:p` (a literal `::` stays). Same rule as plugins/auth.ts normalizeRoutePattern. */
export function desktopRouteKey(routePattern: string | undefined): string {
  return (routePattern ?? '').replace(/::/g, '\u0000').replace(/:[^/]+/g, ':p').replace(/\u0000/g, '::');
}

export function desktopTokenSessionMayUse(method: string, routeKey: string): boolean {
  const m = method.toUpperCase() === 'HEAD' ? 'GET' : method.toUpperCase();
  return ALLOWED.has(`${m} ${routeKey}`) || ALLOWED_SUBTREES.some((re) => re.test(routeKey));
}

/**
 * goodqa#15561 D4: the DELEGATED door. Routes a bound session may call because the token's own abilities cover them, not
 * because the desktop needs them as a host. DEFAULT-DENY: a route is delegated only if it is spelled here, with the token
 * abilities it expects (a test pins `userTokenRoutePolicy(...).abilities` of every entry to this list, and that none is
 * non-delegable, session-only or governance sign-off). Generated from the S0 inventory
 * (test/snapshots/desktop-surface-inventory.json), never from a prefix. v1 is CRM only: the contact and company lists, saved
 * views (segments), the v2 record reads and the writes the CRM pages make. NOT outreach (the `crm` ability covers it in API
 * use; sending has no approval UX in the desktop app), NOT import/export/AI/call/SMS/timeline/contact-detail (session-only for
 * every credential today: a person's PII and mail were kept human-only; promoting one is a per-route security decision),
 * NOT field/lifecycle/relationship-type definitions, reports, webhooks, bulk jobs or external upserts (not called by those pages).
 * `entitlements` and `members` are the two non-CRM reads the CRM list page makes; a token with `read` reaches both by bearer.
 */
export interface DesktopDelegatedSurface { surface: 'crm'; route: string; abilities: readonly string[] }
const crm = (route: string, abilities: readonly string[]): DesktopDelegatedSurface => ({ surface: 'crm', route, abilities });
const CRM_READ = ['crm', 'read'] as const;
const CRM_WRITE = ['crm', 'write'] as const;
const CRM_DELETE = ['crm', 'data.delete', 'write'] as const;
export const DESKTOP_DELEGATED_SURFACES: readonly DesktopDelegatedSurface[] = [
  // reads: the list page, saved views, record reads
  crm('GET /v1/orgs/:p/crm/contacts', CRM_READ),
  crm('GET /v1/orgs/:p/crm/companies', CRM_READ),
  crm('GET /v1/orgs/:p/crm/companies/:p', CRM_READ),
  crm('GET /v1/orgs/:p/crm/deals', CRM_READ),
  crm('GET /v1/orgs/:p/crm/segments', CRM_READ),
  crm('GET /v1/orgs/:p/crm/segments/:p', CRM_READ),
  crm('GET /v1/orgs/:p/crm/segments/:p/preview', CRM_READ),
  crm('GET /v1/orgs/:p/crm/segments/:p/materializations', CRM_READ),
  crm('GET /v1/orgs/:p/crm/records', CRM_READ),
  crm('GET /v1/orgs/:p/crm/records/:p/:p', CRM_READ),
  crm('GET /v1/orgs/:p/crm/records/:p/:p/notes', CRM_READ),
  crm('GET /v1/orgs/:p/crm/records/:p/:p/relationships', CRM_READ),
  crm('GET /v1/orgs/:p/crm/records/:p/:p/lifecycles', CRM_READ),
  crm('GET /v1/orgs/:p/crm/fields', CRM_READ),
  crm('GET /v1/orgs/:p/crm/tags', CRM_READ),
  crm('GET /v1/orgs/:p/crm/:p/:p/fields', CRM_READ),
  crm('GET /v1/orgs/:p/crm/:p/:p/tags', CRM_READ),
  // W4 (goodqa#15561 S1e-a, user answer "Yes, on by default"): contact detail and the contact timeline, for the bound session only.
  crm('GET /v1/orgs/:p/crm/contacts/:p', CRM_READ),
  crm('GET /v1/orgs/:p/crm/contacts/:p/timeline', CRM_READ),
  crm('GET /v1/orgs/:p/entitlements', ['read']),
  crm('GET /v1/orgs/:p/members', ['read']),
  // writes: need `write` AND the owner's own role permission (the handler's requireOrgPermission, untouched)
  crm('POST /v1/orgs/:p/crm/contacts', CRM_WRITE),
  crm('PATCH /v1/orgs/:p/crm/contacts/:p', CRM_WRITE),
  crm('POST /v1/orgs/:p/crm/contacts/:p/archive', CRM_WRITE),
  crm('POST /v1/orgs/:p/crm/contacts/:p/unarchive', CRM_WRITE),
  crm('POST /v1/orgs/:p/crm/companies', CRM_WRITE),
  crm('PATCH /v1/orgs/:p/crm/companies/:p', CRM_WRITE),
  crm('POST /v1/orgs/:p/crm/segments', CRM_WRITE),
  crm('PATCH /v1/orgs/:p/crm/segments/:p', CRM_WRITE),
  crm('POST /v1/orgs/:p/crm/segments/:p/restore', CRM_WRITE),
  crm('DELETE /v1/orgs/:p/crm/segments/:p', CRM_DELETE),
  crm('POST /v1/orgs/:p/crm/records', CRM_WRITE),
  crm('PATCH /v1/orgs/:p/crm/records/:p/:p', CRM_WRITE),
  crm('POST /v1/orgs/:p/crm/records/:p/:p/archive', CRM_WRITE),
  crm('POST /v1/orgs/:p/crm/records/:p/:p/notes', CRM_WRITE),
  crm('PATCH /v1/orgs/:p/crm/:p/:p/fields', CRM_WRITE),
  crm('POST /v1/orgs/:p/crm/:p/:p/tags', CRM_WRITE),
  crm('DELETE /v1/orgs/:p/crm/:p/:p/tags/:p', CRM_DELETE),
];
const DELEGATED: ReadonlyMap<string, DesktopDelegatedSurface> = new Map(DESKTOP_DELEGATED_SURFACES.map((s) => [s.route, s]));

/**
 * W4: the two routes that are session-only for every credential (contact detail) or a session action behind the platform switch,
 * the org owner's opt-in and a `session:crm_timeline` grant (the contact timeline), and that a BOUND desktop session reads with
 * just `crm` + `read`, with no opt-in and no switch (the user's answer "Yes, on by default"). The bearer door is NOT touched: a
 * bearer call with the same token keeps today's answers. The one deliberate exception to "bound is a subset of bearer", pinned
 * by test (exact set) so a new route cannot join silently.
 */
export const DESKTOP_SESSION_ONLY_OPENED: ReadonlySet<string> = new Set([
  'GET /v1/orgs/:p/crm/contacts/:p',
  'GET /v1/orgs/:p/crm/contacts/:p/timeline',
]);
/** Exact string keys; HEAD maps to GET (methodOf), so a HEAD on either route is covered the same way and answers the same. */
export function isSessionOnlyOpened(method: string, routeKey: string): boolean {
  return DESKTOP_SESSION_ONLY_OPENED.has(`${methodOf(method)} ${routeKey}`);
}
/** Org opt-OUT for W4: on unless an org admin sets the entitlement override `userTokens.contactTimelines` to exactly false. */
export const CONTACT_TIMELINES_KEY = 'userTokens.contactTimelines';
export async function contactTimelinesOnForOrg(db: DbOrTx, orgId: string): Promise<boolean> {
  const [org] = await db.select({ overrides: organizations.entitlementOverrides }).from(organizations).where(eq(organizations.id, orgId)).limit(1);
  return (org?.overrides as Record<string, unknown> | null | undefined)?.[CONTACT_TIMELINES_KEY] !== 'never';
}

export type DesktopDoor = 'host' | 'delegated';

/**
 * Polling reads the desktop app and its web shell issue on a timer (unread counts, notification list, remote-session availability,
 * the machine and org lists, the update check). For a bound session they take the same observation policy as the listed
 * zero-write reads: no ledger row and no last-use update for a request that is ALLOWED, so a desktop left open does not write
 * about 15 rows a minute per window for nothing. A REFUSED poll is still ledgered (the trail of a stolen session probing). Bearer
 * calls are unchanged. Real work (CRM reads and writes, enrollment, consent) is always ledgered. The chat unread polls join this
 * list when Messages is delegated (S1c). goodqa#15561 ledger-load measurement.
 */
export const DESKTOP_POLL_ROUTES: ReadonlySet<string> = new Set([
  'GET /v1/me', 'GET /v1/orgs', 'GET /v1/notifications', 'GET /v1/notifications/unread-count', 'GET /v1/desktop/update-status',
  'GET /v1/me/machines', 'GET /v1/orgs/:p/machines', 'GET /v1/orgs/:p/machines/remote-sessions/availability',
]);
export function isDesktopPollRoute(method: string, routePattern: string | undefined): boolean {
  return !!routePattern && DESKTOP_POLL_ROUTES.has(`${methodOf(method)} ${desktopRouteKey(routePattern)}`);
}

/** Surfaces the app has pages for: their routes outside the table are explained by the token policy's own refusal where one exists (see boundRouteClassRefusal). */
const EXPLAINED_SURFACES: readonly RegExp[] = [/^\/v1\/orgs\/:p\/crm(\/|$)/];
export function desktopExplainedSurface(routeKey: string): boolean { return EXPLAINED_SURFACES.some((re) => re.test(routeKey)); }

function methodOf(method: string): string { return method.toUpperCase() === 'HEAD' ? 'GET' : method.toUpperCase(); }

/** `host` (the desktop's own routes), `delegated` (the table above), or null: refuse `desktop_token_session_scope`. HEAD is GET. */
export function desktopRouteDoor(method: string, routeKey: string): DesktopDoor | null {
  if (desktopTokenSessionMayUse(method, routeKey)) return 'host';
  return DELEGATED.has(`${methodOf(method)} ${routeKey}`) ? 'delegated' : null;
}

/**
 * goodqa#15561 D3: the host door runs the SAME token gate as every other route. Exactly these waivers exist, each pinned by
 * a test, because the allow-list is the reason those routes exist for a session:
 *   W1 the `machines` non-delegable rule is waived on the allow-listed machine routes (the route still needs `machines`);
 *   W2 `signedInPersonOnly` is waived on the host routes that are session-only for every credential today (the catalog,
 *      presence, browser setup, remote-session reads and the agent-browser subtrees); each of those needs `machines`;
 *   W3 approval is waived on the machine-enrollment routes only, because the session's own mint already asked
 *      (`approval: 'desktop_signin'`); enrollment carries the token facts (NEG-29), so it stays capped and revocable.
 * D6: every host route except the base reads below also needs the `machines` ability.
 */
export const HOST_BASE_READ_ROUTES: ReadonlySet<string> = new Set([
  'GET /v1/me', 'GET /v1/orgs', 'GET /v1/notifications', 'GET /v1/notifications/unread-count', 'GET /v1/desktop/update-status',
]);
export const HOST_APPROVAL_WAIVED_ROUTES: ReadonlySet<string> = new Set(['POST /v1/me/machine-enrollments', 'POST /v1/me/machine-enrollments/:p/cancel']);

/**
 * RT15561-1: the waivers below exist for the desktop app signed in with a token that holds the host set it always needed
 * (before D6 a session could not start without all three). A token holding only some of them, now able to start a session
 * (D6 needs just `desktop_signin` and `read`), gets the plain bearer policy on the host routes: no waiver, so the machines
 * non-delegable rule and the session-only rule refuse it exactly as they refuse the token by bearer.
 */
export const HOST_WAIVER_ABILITIES = ['machines', 'write', 'tokens.create_other_keys'] as const;

interface HostPolicyShape {
  nonDelegable: { code: string } | null;
  signedInPersonOnly: boolean;
  abilities: string[];
  approvalReason: string | null;
  approvalAlways: boolean;
}
/** Mutates `policy` (a fresh object per request) for the host door. Returns which waivers fired, for the ledger and the tests. */
export function applyHostDoorWaivers(method: string, routeKey: string, policy: HostPolicyShape, held: ReadonlySet<string>, createdVia: string): Array<'W1' | 'W2' | 'W3'> {
  const key = `${methodOf(method)} ${routeKey}`;
  const fired: Array<'W1' | 'W2' | 'W3'> = [];
  if (!HOST_WAIVER_ABILITIES.every((a) => held.has(a))) return fired;
  // The operator token is the non-expiring, agent-held orchestrator token: admitted as a bound token for the base reads and the
  // delegated CRM door, but never given the machine waivers (it is refused those by bearer; RT15561 delta F1).
  if (createdVia === 'operator') return fired;
  if (policy.nonDelegable?.code === 'machines') { policy.nonDelegable = null; fired.push('W1'); }
  if (policy.signedInPersonOnly) { policy.signedInPersonOnly = false; fired.push('W2'); }
  if (!HOST_BASE_READ_ROUTES.has(key) && !policy.abilities.includes('machines')) policy.abilities = [...policy.abilities, 'machines'].sort();
  if (HOST_APPROVAL_WAIVED_ROUTES.has(key) && policy.approvalReason !== null) { policy.approvalReason = null; policy.approvalAlways = false; fired.push('W3'); }
  return fired;
}

/** Ends every desktop session bound to one of these tokens (a rotation or a revoke). Idempotent. */
export async function revokeDesktopSessionsFor(db: DbOrTx, userId: string, tokenIds: readonly string[]): Promise<void> {
  if (tokenIds.length === 0) return;
  // A bound session's login_method is `<prefix><tokenId>:<fingerprint>`; match every secret generation of the token
  // (a rotation changes the fingerprint, so an exact match on one generation would end nothing).
  const prefixes = tokenIds.map((id) => `${USER_TOKEN_DESKTOP_LOGIN_PREFIX}${id}:%`);
  await db.execute(sql`update sessions set revoked_at = now(), revoked_reason = 'user_token_ended'
    where user_id = ${userId} and revoked_at is null and login_method like any (array[${sql.join(prefixes.map((m) => sql`${m}`), sql`, `)}]::text[])`);
}

/** Org entitlement override: when true, consent and pairing need the machine presence proof (an owner at the computer). Default OFF. */
export const PRESENCE_MODE_KEY = 'desktop.agentBrowserPresence';

/** The routes a bound session may use that change what an agent may do in the owner's browser. */
const CONSENT_ROUTE = /^(\/v1\/machines\/:p\/browser-setup$|\/v1\/orgs\/:p\/machines\/remote-sessions\/:p\/(agent-browser\/consent|browser-pairing(\/|$))|\/v1\/machines\/:p\/agent-browser\/consent(\/|$))/;
export function isConsentRoute(routeKey: string): boolean { return CONSENT_ROUTE.test(routeKey); }

/** Presence mode for the request's org (route org, or the machine's org). Fails CLOSED (mode on) when the org cannot be resolved. */
export async function presenceModeOn(db: DbOrTx, req: FastifyRequest): Promise<boolean> {
  const params = (req.params ?? {}) as { orgId?: string; machineId?: string };
  const bodyOrg = (req.body as { orgId?: unknown } | undefined)?.orgId;
  const orgIds = new Set<string>();
  if (params.orgId) orgIds.add(params.orgId);
  // N1 (goodqa#15237): a machine shared into another org is governed by EVERY org the request names: the machine's home
  // org and the org the body acts for. Presence mode on in any of them applies.
  if (typeof bodyOrg === 'string') orgIds.add(bodyOrg);
  if (params.machineId) {
    const [m] = await db.select({ orgId: machines.orgId }).from(machines).where(eq(machines.id, params.machineId)).limit(1).catch(() => []);
    if (m?.orgId) orgIds.add(m.orgId);
  }
  if (orgIds.size === 0) return true;
  for (const orgId of orgIds) {
    const [org] = await db.select({ o: organizations.entitlementOverrides }).from(organizations).where(eq(organizations.id, orgId)).limit(1).catch(() => []);
    if (!org) return true;
    if ((org.o as Record<string, unknown> | null)?.[PRESENCE_MODE_KEY] === true) return true;
  }
  return false;
}

/** Audits a consent or pairing change made through a token-bound session: who, which token, old and new origins. Never a secret. */
export async function auditBoundConsent(db: DbOrTx, req: FastifyRequest, d: { orgId: string; targetId: string; oldOrigins: string[] | null; newOrigins: string[] | null }): Promise<void> {
  const sid = req.auth?.sessionId;
  if (!sid) return;
  const rows = (await db.execute(sql`select login_method from sessions where id = ${sid}::uuid`).catch(() => [])) as unknown as Array<{ login_method: string | null }>;
  const tokenId = desktopMintingTokenId(rows[0]?.login_method);
  if (!tokenId) return;
  await db.insert(auditEvents).values({
    scope: 'tenant', orgId: d.orgId, actorKind: 'user', actorId: req.auth!.userId,
    action: 'agent_browser.consent_changed_via_user_token', targetKind: 'remote_session', targetId: d.targetId,
    changes: { userTokenId: tokenId, oldOrigins: d.oldOrigins, newOrigins: d.newOrigins },
  });
}
