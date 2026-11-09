import { createHash } from 'node:crypto';
import { USER_TOKEN_ABILITIES, type UserTokenAbility } from '@bugtracker/shared';

/**
 * USER TOKENS: what a route needs from a token (docs/design/USER-TOKENS.md section 4). Pure, synchronous, and keyed on
 * the ROUTER'S matched pattern (`req.routeOptions.url`, e.g. `/v1/orgs/:orgId`), never on the raw request target, so an
 * encoded or dotted path cannot slip past a rule (the same discipline as the API-key allowlist in plugins/auth.ts).
 *
 * Every registered route gets an answer -- there is no "unlisted" -- in three layers:
 *
 *   1. NON-DELEGABLE (`USER_TOKEN_NON_DELEGABLE_RULES`): refused for every token, whatever its abilities, so a leaked
 *      token can never lock its owner out or take the account over (sign-in and sessions, password, passkeys, account
 *      deletion and export, revealing a secret value, deciding its own approvals, revoke-all, device/pairing/feed
 *      registration, outside-account linking). The auth plugin adds the governance sign-off routes to this layer.
 *   2. REQUIRED ABILITIES: `read` for a safe method, `write` for any other, plus every family/action ability whose rule
 *      matches (`USER_TOKEN_ABILITY_RULES`); every DELETE also needs `data.delete`. The token must hold ALL of them
 *      (`all` holds everything). This is a ceiling on top of the owner's own live permissions, which every route
 *      still checks as it would for the owner signed in.
 *   3. HUMAN APPROVAL (`approvalReason`): the sensitive subset (deleting data, deleting an org, billing, security
 *      settings, vault grants, minting user tokens, platform-admin writes) that a token with
 *      `requireHumanApproval` may only perform after its owner approved that exact request.
 *
 * `apps/api/test/user-tokens-policy.test.ts` runs this over every route the app registers and pins the invariants
 * (every DELETE needs data.delete, every admin route needs platform.admin, every rule matches a real route, ...).
 */

export const SAFE_METHODS: ReadonlySet<string> = new Set(['GET', 'HEAD', 'OPTIONS']);

/** Every bearer GoodQA Machines route, by shape (the agent's own `/v1/machine-agent/**` is not a bearer route at all). */
export const MACHINES_BEARER_ROUTE =
  /^\/v1\/(orgs\/:[A-Za-z]+\/)?(machines|machine-leases|machine-commands|machine-artifacts|machine-playbooks|machine-jobs)(\/|$)/;

export interface NonDelegableRule {
  /** Limit to these methods; omitted = every method. */
  methods?: readonly string[];
  pattern: RegExp;
  /** Stable machine code, returned in the 403's details. */
  code: string;
  /** Plain-language reason shown to the caller. */
  reason: string;
  /**
   * The ONE way past this rule, when set: `machine_token_grant` = an org admin's elevated machines grant for this token
   * (modules/machines/token-grants.ts; Eric 2026-10-05). The gate then admits the token only while the platform setting
   * `machines.tokenGrants` is on, the token holds the `machines` ability, and it has a live grant whose level covers the
   * method (in the route's org when the route names one). Everything else about the rule -- its code, its reason, its
   * refusal -- is unchanged.
   */
  elevatedBy?: 'machine_token_grant';
}

/**
 * Layer 1. Each entry is pinned by the policy test to match at least one registered route, so a renamed route cannot
 * silently fall out of this list.
 */
export const USER_TOKEN_NON_DELEGABLE_RULES: readonly NonDelegableRule[] = [
  { code: 'commander_decisions', methods: ['POST'], pattern: /^\/v1\/commander\/actions\/:[A-Za-z]+\/(approve|reject|edit|undo)$/, reason: 'A Commander cannot decide or undo its own requests.' },
  { code: 'commander_settings', methods: ['PATCH'], pattern: /^\/v1\/orgs\/:[A-Za-z]+\/commander$/, reason: 'Only an administrator session may change Commander settings.' },
  { code: 'commander_mention_admission', methods: ['PUT', 'DELETE'], pattern: /^\/v1\/chat\/conversations\/:[A-Za-z]+\/commander-admission$/, reason: 'Only a signed-in person may let the assistant into a conversation or remove it, and a Commander cannot admit itself.' },
  { code: 'ai_thread_membership', methods: ['POST', 'DELETE'], pattern: /^\/v1\/ai-threads\/:id\/members(?:\/:userId)?$/, reason: 'Only a signed-in person may change private AI thread membership.' },
  {
    // OWNER RULING 2026-10-07 admits org keys only; removing the key denial must not admit user tokens.
    methods: ['POST'],
    pattern: /^\/v1\/chat\/conversations\/:[A-Za-z]+\/members$/,
    code: 'channel_members',
    reason: 'A user token cannot add people to a channel. Use a signed-in session or an org API key.',
  },
  { methods: ['POST'], pattern: /^\/v1\/me\/user-tokens$/, code: 'token_mint', reason: 'Only a signed-in human can mint a user token.' },
  { pattern: /^\/v1\/(me\/user-token-session-actions|orgs\/:[A-Za-z]+\/user-token-session-actions)$/, code: 'session_action_grants', reason: 'Session action grants and org opt-in are managed by a signed-in human.' },
  {
    pattern: /^\/v1\/auth(\/|$)/,
    code: 'identity_and_sessions',
    reason: 'Signing in, sessions, passkeys (two-factor) and sign-in links act on your identity itself. Do this signed in.',
  },
  {
    pattern: /^\/v1\/account(\/|$)/,
    code: 'account',
    reason: 'Your password, sessions, data export and account deletion can only be changed by you, signed in.',
  },
  {
    pattern: /^\/v1\/hosted(\/|$)/,
    code: 'identity_and_sessions',
    reason: 'A hosted app session is a sign-in. Do this signed in.',
  },
  {
    pattern: /^\/v1\/devices(\/|$)/,
    code: 'devices',
    reason: 'Registering a device binds it to a signed-in session.',
  },
  {
    pattern: /^\/v1\/push\/subscribe$/,
    code: 'devices',
    reason: 'Push subscriptions belong to a signed-in browser.',
  },
  {
    pattern: /^\/v1\/extension\/installations$/,
    code: 'devices',
    reason: 'Registering a browser extension belongs to a signed-in browser.',
  },
  {
    pattern: /^\/v1\/mcp\/pair(\/|$)/,
    code: 'pairing',
    reason: 'Approving an MCP device pairing is a person-present ceremony.',
  },
  {
    pattern: /^\/v1\/me\/calendar-feed$/,
    code: 'calendar_feed',
    reason: 'A calendar feed link is a sign-in credential of its own.',
  },
  {
    pattern: /^\/v1\/(github\/oauth|slack\/link)(\/|$)/,
    code: 'account_linking',
    reason: 'Linking an outside account to yours is done signed in.',
  },
  {
    // Review round 1, finding 7: EVERY reveal -- a vault secret, a requested secret, a secure chat message -- by shape,
    // so a reveal route added later is covered without anyone remembering to list it.
    methods: ['GET', 'POST'],
    pattern: /^\/v1\/.*\/reveal$/,
    code: 'secret_value',
    reason: 'A user token can never reveal a secret value.',
  },
  {
    // Review round 1, finding 8: starting (or finishing) an OAuth connection binds an outside account -- a mailbox, a
    // calendar, a GitHub or Slack install -- to the person or the org. A browser round trip a person makes, never a token.
    methods: ['GET', 'POST'],
    pattern: /^\/v1\/(?!auth\/).*\/(authorize|connect|install|callback|oauth\/start)$/,
    code: 'account_linking',
    reason: 'Connecting an outside account (OAuth) is done by you, signed in.',
  },
  {
    // Review round 1, finding 8: a person paused it (a key, a mailbox, a sequence); undoing that stop is a person's act.
    methods: ['POST'],
    pattern: /^\/v1\/.*\/resume$/,
    code: 'resume_paused',
    reason: 'Resuming something that was paused is done by a person signed in.',
  },
  {
    // Review round 1, finding 8: joining an organization is the person's own consent.
    methods: ['POST'],
    pattern: /^\/v1\/invites\/accept$/,
    code: 'invite_accept',
    reason: 'Accepting an invitation is done by you, signed in.',
  },
  {
    pattern: /^\/v1\/me\/user-token-approvals\/:[A-Za-z]+\/(approve|deny)$/,
    code: 'own_approval',
    reason: 'A token can never approve or deny an approval request; the owner does that signed in.',
  },
  {
    pattern: /^\/v1\/me\/user-tokens\/revoke-all$/,
    code: 'revoke_all',
    reason: 'Revoking every token at once is done signed in.',
  },
  {
    // Review rva, finding 1 (HIGH): GoodQA Machines drive a person's REAL computer (exec, files, clipboard, screen). An
    // org API key reaches them only by naming the family and holding the owner's grant; a token, which no grant can
    // name, reached them as its owner (owner mode, every member's audit for an admin) with plain read/write. Every
    // bearer machines route, by shape (the agent's own `/v1/machine-agent/**` is not a bearer route at all).
    pattern: MACHINES_BEARER_ROUTE,
    code: 'machines',
    reason: 'A user token cannot use machines. Use a signed-in session, your own personal API key, or a key the machine owner granted.',
    // Eric 2026-10-05: "yes, but add the elevated grant options too". The refusal above stays the default.
    elevatedBy: 'machine_token_grant',
  },
];

export interface AbilityRule {
  /** Limit to these methods; omitted = every method. `WRITE` is shorthand for every non-safe method. */
  methods?: readonly string[] | 'WRITE';
  pattern: RegExp;
  abilities: readonly UserTokenAbility[];
  /** When set, a token with `requireHumanApproval` needs its owner's approval for this route; the value is the reason. */
  approval?: string;
  /**
   * Lane gq-ut-data: ask first EVEN for a token whose `requireHumanApproval` is off, while the platform setting
   * `userTokens.dataAdmin.alwaysAsk` is on (its default). Needs `approval` on the same rule.
   */
  approvalAlways?: true;
}

const ID = ':[A-Za-z]+';
const re = (source: string) => new RegExp(source);

/**
 * Layer 2 and 3. EVERY matching rule contributes (an org webhook write needs `settings.security`; an org API key mint
 * needs `agents.manage` AND `tokens.create_other_keys`).
 */
export const USER_TOKEN_ABILITY_RULES: readonly AbilityRule[] = [
  { pattern: re(`^/v1/orgs/${ID}/work-dashboard$`), abilities: ['issues'] },
  { pattern: re(`^/v1/(me|orgs/${ID})/command-center(/|$)`), abilities: ['issues'] },
  // ---- platform ----------------------------------------------------------------------------------------------
  { pattern: /^\/v1\/(admin|cron)(\/|$)/, abilities: ['platform.admin'] },
  { pattern: /^\/v1\/vault\/admin(\/|$)/, abilities: ['platform.admin'] },
  // Reading the org's entitlements is any member's read (and an org key's); changing them is a platform admin's.
  { methods: 'WRITE', pattern: re(`^/v1/orgs/${ID}/entitlements$`), abilities: ['platform.admin'] },
  { methods: 'WRITE', pattern: /^\/v1\/(admin|cron|vault\/admin)(\/|$)/, abilities: [], approval: 'platform.admin' },
  { methods: 'WRITE', pattern: re(`^/v1/orgs/${ID}/entitlements$`), abilities: [], approval: 'platform.admin' },

  // ---- orgs and projects ---------------------------------------------------------------------------------------
  { methods: ['POST'], pattern: /^\/v1\/orgs$/, abilities: ['orgs.create'] },
  { methods: ['DELETE'], pattern: re(`^/v1/orgs/${ID}$`), abilities: ['org.delete'], approval: 'org.delete' },
  { methods: ['POST'], pattern: re(`^/v1/orgs/${ID}/projects$`), abilities: ['projects.create'] },

  // ---- members -------------------------------------------------------------------------------------------------
  {
    methods: 'WRITE',
    pattern: re(`^/v1/orgs/${ID}/(members|invites|invite-links|roles|elevations)(/|$)`),
    abilities: ['members.manage'],
  },
  { methods: 'WRITE', pattern: re(`^/v1/orgs/${ID}/members(/${ID})?$`), abilities: [], approval: 'members.manage' },
  { methods: 'WRITE', pattern: re(`^/v1/projects/${ID}/(members|access-grants|guests)(/|$)`), abilities: ['members.manage'], approval: 'members.manage' },

  // ---- agents and keys -----------------------------------------------------------------------------------------
  {
    methods: 'WRITE',
    pattern: re(
      `^/v1/orgs/${ID}/(api-keys|personas|agents|agent-policy|interactive-agents|agent-daemons|agent-hosts|agent-hosting|agent-browser-connection|coordinator)(/|$)`,
    ),
    abilities: ['agents.manage'],
  },
  { methods: 'WRITE', pattern: re(`^/v1/projects/${ID}/runners(/|$)`), abilities: ['agents.manage'] },
  {
    pattern: /^\/v1\/(runners|persona|agent-daemon|agent-runs|agent-launches|agent-hosts)(\/|$)/,
    abilities: ['agents.manage'],
  },
  // Review round 1, finding 2: minting another credential is minting, so a token that asks first asks for these too --
  // and the owner sees the exact scopes asked for (finding 6). Re-scoping or extending a key is minting by another name.
  {
    methods: ['POST'],
    pattern: re(`^/v1/orgs/${ID}/api-keys$`),
    abilities: ['tokens.create_other_keys'],
    approval: 'tokens.create_other_keys',
  },
  {
    methods: ['PATCH'],
    pattern: re(`^/v1/orgs/${ID}/api-keys/${ID}$`),
    abilities: ['tokens.create_other_keys'],
    approval: 'tokens.create_other_keys',
  },
  {
    methods: ['POST'],
    pattern: re(`^/v1/orgs/${ID}/api-keys/${ID}/extend$`),
    abilities: ['tokens.create_other_keys'],
    approval: 'tokens.create_other_keys',
  },
  {
    methods: ['POST'],
    pattern: re(`^/v1/orgs/${ID}/agent-daemons/registration-codes$`),
    abilities: ['tokens.create_other_keys'],
    approval: 'tokens.create_other_keys',
  },
  { methods: ['POST'], pattern: re(`^/v1/orgs/${ID}/agent-hosts$`), abilities: ['tokens.create_other_keys'], approval: 'tokens.create_other_keys' },
  {
    methods: ['POST'],
    pattern: re(`^/v1/projects/${ID}/runners/enrol-tokens$`),
    abilities: ['tokens.create_other_keys'],
    approval: 'tokens.create_other_keys',
  },

  // ---- user tokens (this feature) ------------------------------------------------------------------------------
  {
    methods: ['POST'],
    pattern: /^\/v1\/me\/user-tokens$/,
    abilities: ['tokens.create_user_tokens'],
    approval: 'tokens.create_user_tokens',
  },
  {
    methods: ['POST'],
    pattern: re(`^/v1/me/user-tokens/${ID}/rotate$`),
    abilities: ['tokens.create_user_tokens'],
    approval: 'tokens.create_user_tokens',
  },
  // A PATCH can widen a token (within the actor's own ceiling): minting by another name, so it asks too.
  {
    methods: ['PATCH'],
    pattern: re(`^/v1/me/user-tokens/${ID}$`),
    abilities: ['tokens.create_user_tokens'],
    approval: 'tokens.create_user_tokens',
  },

  // ---- families ------------------------------------------------------------------------------------------------
  {
    pattern: re(
      `^/v1/(issues|attachments|issue-types)(/|$)|^/v1/projects/${ID}/(issues|pinned-issues|issue-types|attachments)(/|$)|^/v1/orgs/${ID}/issues(/|$)|^/v1/me/(issues|tasks|task-work|my-work|issue-filters)(/|$)`,
    ),
    abilities: ['issues'],
  },
  // goodqa#15545 (main w82e317378d9): the sender-identity route alone is outside the crm family. It is org settings,
  // gated by its own ability below (`outreach.sender_identity`, never on a Commander turn, PUT asks first), so the
  // owner's agent can hold it without holding every contact. Only the exact path is exempt; the census pins it.
  { pattern: re(`^/v1/orgs/${ID}/(crm|outreach(?!/sender-identity$))(/|$)|^/v1/outreach(/|$)`), abilities: ['crm'] },
  // OAuth decision 1: a CRM grant never sends outreach without its owner's approval.
  { methods: ['POST'], pattern: re(`^/v1/orgs/${ID}/outreach/(?:[^/]+/)?sends/${ID}/deliver$|^/v1/projects/${ID}/outreach/messages/schedule$`), abilities: ['crm'], approval: 'outreach.send' },

  { pattern: re(`^/v1/orgs/${ID}/data(/|$)`), abilities: ['custom_data'] },
  // Lane gq-ut-data (Eric 2026-10-04): the custom-data ADMIN routes -- provisioning the org's database and changing WHO
  // reaches WHAT in it (data roles, bindings, grants, the reconciler). Session-only for every org API key; opened to a
  // user token holding data.admin (USER_TOKEN_BEYOND_API_KEY_ROUTES), still within its owner's own data:admin (the
  // handler re-checks it live), and never raising the owner's own data role (modules/custom-data/routes.ts). They ask
  // the owner first by default even when the token's own approval switch is off (`approvalAlways`).
  {
    methods: 'WRITE',
    pattern: re(`^/v1/orgs/${ID}/data/(provision|roles|bindings|grants|reconcile)$`),
    abilities: ['data.admin'],
    approval: 'data.admin',
    approvalAlways: true,
  },
  { pattern: re(`^/v1/orgs/${ID}/(agent-knowledge|agent-memory)(/|$)|^/v1/projects/${ID}/agent-memory(/|$)|^/v1/agent-memory(/|$)`), abilities: ['knowledge'] },
  // Memory reads/proposals are knowledge actions. Governance PATCH is not key reachable, so remains session only.
  { pattern: re(`^/v1/(orgs|projects)/${ID}/memory(/|$)|^/v1/orgs/${ID}/projects/${ID}/memory(/|$)`), abilities: ['knowledge'] },
  { pattern: /^\/v1\/(secret-requests|vault)(\/|$)/, abilities: ['secrets.request'] },
  {
    methods: 'WRITE',
    pattern: re(`^/v1/vault/secrets/${ID}/grants(/|$)`),
    abilities: ['settings.security'],
    approval: 'vault.grants',
  },

  // ---- billing -------------------------------------------------------------------------------------------------
  {
    methods: 'WRITE',
    pattern: re(`^/v1/orgs/${ID}/(billing|comp-code|referral-code|usage/budget|usage/assistant-limits)(/|$)`),
    abilities: ['billing.manage'],
    approval: 'billing.manage',
  },

  // ---- security settings ---------------------------------------------------------------------------------------
  { methods: ['PATCH'], pattern: re(`^/v1/orgs/${ID}$`), abilities: ['settings.security'], approval: 'settings.security' },
  {
    methods: 'WRITE',
    pattern: re(
      `^/v1/orgs/${ID}/(agent-policy|attachment-share-policy|domains|retention-policy|review-retention-policies|provider-keys|webhooks|roles|elevations|deploy-connections|calendar-connection|slack|github|members/${ID}/grants)(/|$)`,
    ),
    abilities: ['settings.security'],
    approval: 'settings.security',
  },
  { methods: 'WRITE', pattern: /^\/v1\/connections(\/|$)/, abilities: ['settings.security'], approval: 'settings.security' },
  // Lane usertoken-webhooks (Eric 2026-10-14): reading an org's webhooks reveals receiver URLs and delivery state, so a
  // token reads them only with the same `settings.security` its writes need (above). No approval for a read.
  { methods: ['GET'], pattern: re(`^/v1/orgs/${ID}/webhooks(/|$)`), abilities: ['settings.security'] },

  // ---- GoodQA goodqa#15434: the legal sender name and address on outreach mail, its own ability, reads too.
  { pattern: re(`^/v1/orgs/${ID}/outreach/sender-identity$`), abilities: ['outreach.sender_identity'] },
  { methods: 'WRITE', pattern: re(`^/v1/orgs/${ID}/outreach/sender-identity$`), abilities: [], approval: 'outreach.sender_identity' },
  // ---- agent-browser grants (Eric 2026-11-06): the dedicated ability, for reads too (a grant lists keys, projects and sites).
  { pattern: re(`^/v1/orgs/${ID}/agent-browsers/grants(/|$)`), abilities: ['agent_browser_grants'] },
  { methods: 'WRITE', pattern: re(`^/v1/orgs/${ID}/agent-browsers/grants(/|$)`), abilities: [], approval: 'agent_browser_grants' },
  // goodqa#15158: a desktop session for the owner. Its own ability; a token that asks first asks here too.
  // goodqa#15561 D6: to START a session a token needs the right to sign in and to read, nothing else (the mint is not a write:
  // what the session can do is the gate's answer for each later route). Pinned to DESKTOP_SESSION_REQUIRED_ABILITIES by test.
  { methods: ['POST'], pattern: /^\/v1\/me\/desktop-session$/, abilities: ['desktop_signin', 'read'], approval: 'desktop_signin' },
  // ---- goodqa#14920: delegated platform-setting appends need the platform.admin ceiling (the handler re-checks the
  // delegation, the owner's verified platform admin and org admin, and the exact allow-listed key).
  { pattern: /^\/v1\/user-token-delegations(\/|$)/, abilities: ['platform.admin'] },
  // ---- routines (goodqa#8445): the routine writes opened to tokens below need the dedicated ability, not plain write.
  { methods: 'WRITE', pattern: re(`^/v1/orgs/${ID}/routines(/|$)`), abilities: ['routines'] },

  // ---- machines (elevated grant only; the non-delegable `machines` rule refuses every token without one) ----------
  { pattern: MACHINES_BEARER_ROUTE, abilities: ['machines'] },
  // Machines enrollment: the person's own machine tokens, enrollments and machine metadata (never a lease or a command).
  { pattern: /^\/v1\/me\/(machine-tokens|machine-enrollments|machines)(\/|$)/, abilities: ['machines'] },
  {
    methods: ['POST'],
    pattern: /^\/v1\/me\/(machine-tokens|machine-enrollments)$/,
    abilities: ['tokens.create_other_keys'],
    approval: 'tokens.create_other_keys',
  },

  // ---- destructive POSTs (DELETE is handled for every route below) ---------------------------------------------
  {
    methods: ['POST'],
    pattern: /\/(purge|persona-erase|destroy|kill)$/,
    abilities: ['data.delete'],
    approval: 'data.delete',
  },
];

/**
 * DELETE routes that do NOT need `data.delete`: revoking a token is the safety action, and a token that can be used at
 * all must be able to end itself (or the tokens it minted) without extra powers.
 */
export const DELETE_WITHOUT_DATA_DELETE: readonly RegExp[] = [re(`^/v1/me/user-tokens/${ID}$`)];

export interface UserTokenRoutePolicy {
  /** Set when no token may use this route at all. */
  nonDelegable: NonDelegableRule | null;
  /**
   * Review round 1, finding 3: no org API key can reach this route (it is on plugins/auth.ts's SESSION_ONLY_ROUTES or
   * NON_BEARER_ROUTES), and it is not on `USER_TOKEN_BEYOND_API_KEY_ROUTES`. The gate then refuses every token with
   * `USER_TOKEN_SIGNED_IN_PERSON_RULE` -- after the explicit rules and the governance register, so their own codes win.
   */
  signedInPersonOnly: boolean;
  /** Every ability the token must hold (sorted, deduplicated). */
  abilities: UserTokenAbility[];
  /** The approval reason when a token with `requireHumanApproval` must get its owner's approval first; null otherwise. */
  approvalReason: string | null;
  /**
   * Lane gq-ut-data: true when the approval applies whatever the token's `requireHumanApproval` (while the platform
   * setting `userTokens.dataAdmin.alwaysAsk` is on, its default). Only ever true with an `approvalReason`.
   */
  approvalAlways: boolean;
}

function methodMatches(methods: AbilityRule['methods'], method: string): boolean {
  if (methods === undefined) return true;
  if (methods === 'WRITE') return !SAFE_METHODS.has(method);
  return methods.includes(method);
}

/**
 * Transport routes whose own method says nothing about what the request does: `POST /v1/mcp` carries MCP tool calls,
 * and every tool call re-enters `app.authenticate` through `app.inject()` with the same bearer, where IT is checked
 * against its own route. So opening the transport needs only `read`.
 */
export const TRANSPORT_ROUTES: ReadonlySet<string> = new Set(['/v1/mcp']);

/**
 * goodqa#5118 (REQUIRED 3, lane ruling D3): the QA Commander directive OPERATOR surface. Every /v1/admin route needs
 * `platform.admin` plus the owner's approval (pinned by user-tokens-policy.test.ts), so the scoped operator credential
 * gets its own mount of the same handlers. The rule is EXCLUSIVE: exactly `qac.directive` -- no `read`/`write`
 * baseline, so a token holding only that ability reaches nothing else, and no approval step, because the credential
 * itself is the platform admin's per-use, org-scoped, <= 7-day approval. Handlers re-check the token live (owner still
 * a verified platform admin, org in its list, exactly this one ability) on every call.
 */
export const QAC_OPERATOR_ROUTE = /^\/v1\/qac-operator\/directives(\/|$)/;
export const QAC_OPERATOR_ROUTE_KEYS = [
  'POST /v1/qac-operator/directives',
  'GET /v1/qac-operator/directives',
  'POST /v1/qac-operator/directives/:p/revoke',
] as const;

/** Lane usertoken-webhooks: the org webhook management routes a user token may use (see the opening below). */
const USER_TOKEN_WEBHOOK_ADMIN_ROUTE_KEYS = [
  'GET /v1/orgs/:p/webhooks',
  'POST /v1/orgs/:p/webhooks',
  'GET /v1/orgs/:p/webhooks/:p',
  'PATCH /v1/orgs/:p/webhooks/:p',
  'DELETE /v1/orgs/:p/webhooks/:p',
  'POST /v1/orgs/:p/webhooks/:p/rotate-secret',
  'POST /v1/orgs/:p/webhooks/:p/test',
] as const;

/**
 * Eric 2026-11-06: the org agent-browser grant routes a user token may use (ability `agent_browser_grants`).
 * Refused as `signed_in_person` (as before the opening) for a token whose owner is not an admin of the route's org,
 * refused to every commander turn, and still refused to every org API key (plugins/auth.ts SESSION_ONLY_ROUTES).
 */
/**
 * GoodQA goodqa#15434: the sender-identity routes a user token may use (ability `outreach.sender_identity`). The
 * handler re-checks org:manage_settings live; every org API key stays refused (plugins/auth.ts SESSION_ONLY_ROUTES)
 * and every Commander turn is refused (auth-gate.ts).
 */
const USER_TOKEN_SENDER_IDENTITY_ROUTE_KEYS = ['GET /v1/orgs/:p/outreach/sender-identity', 'PUT /v1/orgs/:p/outreach/sender-identity'] as const;
export const USER_TOKEN_SENDER_IDENTITY_ROUTES: ReadonlySet<string> = new Set(USER_TOKEN_SENDER_IDENTITY_ROUTE_KEYS);

const USER_TOKEN_BROWSER_GRANT_ROUTE_KEYS = [
  'GET /v1/orgs/:p/agent-browsers/grants',
  'POST /v1/orgs/:p/agent-browsers/grants',
  'POST /v1/orgs/:p/agent-browsers/grants/:p/revoke',
] as const;
export const USER_TOKEN_BROWSER_GRANT_ROUTES: ReadonlySet<string> = new Set(USER_TOKEN_BROWSER_GRANT_ROUTE_KEYS);

/**
 * goodqa#14920: the user-token DELEGATION routes. Token-only (a session or an org API key is refused), refused to every
 * Commander turn; the handler requires the live delegation (modules/user-tokens/delegations.ts).
 */
const USER_TOKEN_DELEGATION_ROUTE_KEYS = ['POST /v1/user-token-delegations/platform-settings/:p/orgs'] as const;
export const USER_TOKEN_DELEGATION_ROUTES: ReadonlySet<string> = new Set(USER_TOKEN_DELEGATION_ROUTE_KEYS);

/**
 * Lane usertoken-webhooks: refused as `signed_in_person` (as before the opening) for a token whose owner is not an
 * admin of the route's org, and refused to every commander turn.
 */
export const USER_TOKEN_WEBHOOK_ADMIN_ROUTES: ReadonlySet<string> = new Set(USER_TOKEN_WEBHOOK_ADMIN_ROUTE_KEYS);

/**
 * Review round 1, finding 3. An org API key reaches ~830 of ~1570 routes; every other route is SESSION_ONLY (a person
 * signed in) or NON_BEARER. Before this a user token reached all of them its abilities allowed, so every "a person
 * must do this" check spelled `if (auth.apiKeyId)` -- 590 session-only routes and the handler-level gates -- waved a
 * token through as if it were the person at the keyboard (approving a mailer campaign, connecting a mailbox, changing
 * data permissions, answering decisions in a batch). The rule is now the API key's rule: a token reaches a route only
 * where a key could, or where this list names it. Each entry is a deliberate opening of a session-only route to
 * tokens, pinned by user-tokens-route-census.test.ts (exact set; each must be a real session-only route; each write
 * needs an ability beyond read/write, and the mints ask first). Spelled like SESSION_ONLY_ROUTES (`:p` params).
 */
export const USER_TOKEN_BEYOND_API_KEY_ROUTES: readonly string[] = [
  // This feature: the owner's own tokens and the approval queue a token reads (deciding is non-delegable).
  'GET /v1/me/user-tokens',
  'GET /v1/me/user-tokens/:p',
  'PATCH /v1/me/user-tokens/:p',
  'DELETE /v1/me/user-tokens/:p',
  'POST /v1/me/user-tokens/:p/rotate',
  'GET /v1/me/user-tokens/:p/events',
  'GET /v1/me/user-tokens/:p/audit',
  'GET /v1/me/user-token-approvals',
  'GET /v1/me/user-token-approvals/:p',
  // Eric's ask (2026-10-04): create orgs and projects (orgs.create, projects.create); delete them only with
  // org.delete / data.delete and, for a token that asks first, the owner's approval.
  'POST /v1/orgs',
  'DELETE /v1/orgs/:p',
  'POST /v1/orgs/:p/projects',
  'DELETE /v1/projects/:p',
  // ... and agents: org API keys and the persona a key wears (agents.manage; minting, re-scoping and extending a key
  // also need tokens.create_other_keys, ask first, stay inside the token and die with it). Resuming a paused key is
  // non-delegable.
  'GET /v1/orgs/:p/api-keys',
  'POST /v1/orgs/:p/api-keys',
  'PATCH /v1/orgs/:p/api-keys/:p',
  'DELETE /v1/orgs/:p/api-keys/:p',
  'POST /v1/orgs/:p/api-keys/:p/pause',
  'POST /v1/orgs/:p/api-keys/:p/extend',
  'GET /v1/orgs/:p/api-keys/:p/persona',
  'POST /v1/orgs/:p/api-keys/:p/persona',
  'PATCH /v1/orgs/:p/api-keys/:p/persona',
  'DELETE /v1/orgs/:p/api-keys/:p/persona',
  // Lane gq-ut-data (Eric 2026-10-04: "enable data and all new functions for all orgs", "get everything really done"):
  // the custom-data admin routes. An org API key (a bot) still never edits its own reach; a user token is its owner,
  // so it may do what its owner may as an org data admin -- with data.admin AND custom_data, inside its org allow-list,
  // asking the owner first by default even when its approval switch is off, audited (audit_events.via_user_token_id
  // and the token's ledger), never raising its owner's own data role, and 409 CD-NOT-PROVISIONED-ASK-ADMIN from the
  // permission edits on an org that is not provisioned (provision is its own, explicit call). Still closed: the status
  // view (GET .../data/status) and assigning a database to a project.
  'POST /v1/orgs/:p/data/provision',
  'POST /v1/orgs/:p/data/roles',
  'PUT /v1/orgs/:p/data/bindings',
  'DELETE /v1/orgs/:p/data/bindings',
  'POST /v1/orgs/:p/data/grants',
  'DELETE /v1/orgs/:p/data/grants',
  'POST /v1/orgs/:p/data/reconcile',
  // Machines enrollment (Eric 2026-10-05: "you have a user token, you should be able to make machine tokens yourself";
  // docs/design/machines-fullcontrol/ENROLLMENT.md). Minting a machine token and starting an enrollment need `machines`
  // AND `tokens.create_other_keys` and ask first; listing, revoking, cancelling and reading the person's OWN machines'
  // metadata need `machines`. None of these leases or commands: the `machines` rule above still refuses that.
  'POST /v1/me/machine-tokens',
  'GET /v1/me/machine-tokens',
  'POST /v1/me/machine-tokens/:p/revoke',
  'POST /v1/me/machine-enrollments',
  'GET /v1/me/machine-enrollments',
  'GET /v1/me/machine-enrollments/:p',
  'POST /v1/me/machine-enrollments/:p/cancel',
  'GET /v1/me/machines',
  // Driver usertoken-admin (Eric 2026-10-06: "if my user token can't do something you need, you must upgrade the APIs
  // to make it able to"; the orchestrator had to write project_members rows by hand in production). Staffing a
  // project: `members.manage` (asks first when the token asks), the handler's own `pm`-or-org-admin check decides
  // whether this owner may, and the audit row carries `via_user_token_id`. Removal is a DELETE, so it also needs
  // `data.delete`. Kill switch: platform setting `userTokens.membership` (USER_TOKEN_MEMBERSHIP_ROUTES below). Still
  // org creation additionally needs the bootstrap-email orgAdmin rollout. Membership uses live org authority. Elevations, custom
  // roles, project grants and guests remain signed-in only -- docs/design/USER-TOKEN-MEMBERSHIP.md.
  'POST /v1/orgs',
  'POST /v1/orgs/:p/members',
  'PATCH /v1/orgs/:p/members/:p',
  'DELETE /v1/orgs/:p/members/:p',
  'POST /v1/orgs/:p/invite-links',
  'GET /v1/orgs/:p/invite-links',
  'DELETE /v1/orgs/:p/invite-links/:p',
  'PUT /v1/projects/:p/members',
  'DELETE /v1/projects/:p/members/:p',
  // Lane cards-admin (Eric 2026-10-13: "make it so my session token can fix whats new cards"): editing and approving
  // What's New cards and managing Coming soon roadmap items, for a token holding `platform.admin` whose owner is a
  // platform admin (checked in the gate AND by each handler's requireVerifiedPlatformAdmin). Kill switch
  // `userTokens.featureCardsAdmin`; see USER_TOKEN_FEATURE_CARD_ADMIN_ROUTES below. Creating, discarding and
  // AI-drafting cards, suggestion moderation and every other /v1/admin route stay signed-in only.
  'PATCH /v1/admin/feature-cards/:p',
  'POST /v1/admin/feature-cards/:p/approve',
  'GET /v1/admin/roadmap',
  'POST /v1/admin/roadmap/items',
  'PATCH /v1/admin/roadmap/items/:p',
  'POST /v1/admin/roadmap/items/:p/ship',
  // Demo hotfix (Eric 2026-10-14: the bot must create a daily routine for the person it is talking to). A user token
  // (a commander turn included) may create, configure/pause, run now and cancel routines as its owner; the handlers
  // still require the owner to be an org admin with org:manage_settings. Answering a named person's checkpoint
  // and firing event triggers stay signed-in only.
  'POST /v1/orgs/:p/routines',
  'PUT /v1/orgs/:p/routines/:p/configuration',
  'POST /v1/orgs/:p/routines/:p/runs',
  'POST /v1/orgs/:p/routines/runs/:p/cancel',
  // Lane usertoken-webhooks (Eric 2026-10-14: "you dont need me to do things, you have my user token.. and if that
  // token cant do something, you need to make it do so"; the orchestrator could not register a DM webhook receiver).
  // Managing the org's outbound webhooks as their owner: every route needs `settings.security` (writes ask first when
  // the token asks), the gate admits only a token whose owner is an admin of the route's org, never a commander turn
  // (USER_TOKEN_WEBHOOK_ADMIN_ROUTES below), the handler re-checks org:manage_integrations / registrant ownership, and
  // the audit rows carry `via_user_token_id`. Deliveries, redeliver and requeue stay signed-in only; org API keys stay
  // refused on all of them (plugins/auth.ts SESSION_ONLY_ROUTES).
  ...USER_TOKEN_WEBHOOK_ADMIN_ROUTE_KEYS,
  // Eric 2026-11-06: agent-browser grants (agent_browser_grants; owner must be an admin of the org; see above).
  ...USER_TOKEN_BROWSER_GRANT_ROUTE_KEYS,
  // GoodQA goodqa#15434: the sender identity (outreach.sender_identity; see above).
  ...USER_TOKEN_SENDER_IDENTITY_ROUTE_KEYS,
  // goodqa#15158: the owner's desktop sign-in (desktop_signin; the handler refuses an org-scoped token and anything but a token).
  'POST /v1/me/desktop-session',
  // goodqa#14920: delegated platform-setting appends (platform.admin + the live delegation; see above).
  ...USER_TOKEN_DELEGATION_ROUTE_KEYS,
  // goodqa#5118: the QA Commander directive operator mount (QAC_OPERATOR_ROUTE). Exactly `qac.directive`, which only a
  // platform admin can mint (POST /v1/admin/qac/operator-tokens) and which `all` never includes. Org API keys and
  // persona keys never reach it (plugins/auth.ts SESSION_ONLY_ROUTES); the handlers re-verify the token on every call.
  ...QAC_OPERATOR_ROUTE_KEYS,
];

/**
 * Lane cards-admin: the feature-card and roadmap admin routes a platform admin's token may use. Closed again (refused as
 * `signed_in_person`, as before) while the platform setting `userTokens.featureCardsAdmin` is off or unreadable, and
 * for any token whose owner is not a platform admin; never open to a commander turn.
 */
export const USER_TOKEN_FEATURE_CARD_ADMIN_ROUTES: ReadonlySet<string> = new Set([
  'PATCH /v1/admin/feature-cards/:p',
  'POST /v1/admin/feature-cards/:p/approve',
  'GET /v1/admin/roadmap',
  'POST /v1/admin/roadmap/items',
  'PATCH /v1/admin/roadmap/items/:p',
  'POST /v1/admin/roadmap/items/:p/ship',
]);

/** The routes the `userTokens.membership` kill switch closes again (refused as `signed_in_person` while it is off). */
export const USER_TOKEN_MEMBERSHIP_ROUTES: ReadonlySet<string> = new Set(['PUT /v1/projects/:p/members', 'DELETE /v1/projects/:p/members/:p']);

/** New org operations are separately rolled out to the bootstrap allowlist, with an immediate kill switch. */
export const USER_TOKEN_ORG_ADMIN_ROUTES: ReadonlySet<string> = new Set([
  'POST /v1/orgs',
]);

const BEYOND_API_KEY = new Set(USER_TOKEN_BEYOND_API_KEY_ROUTES);

/** `METHOD /v1/...:p`, the spelling of SESSION_ONLY_ROUTES (plugins/auth.ts normalizeRoutePattern; `::` is a literal). */
export function userTokenRouteKey(method: string, route: string): string {
  const m = method.toUpperCase() === 'HEAD' ? 'GET' : method.toUpperCase();
  return `${m} ${route.replace(/::/g, '\u0000').replace(/:[^/]+/g, ':p').replace(/\u0000/g, '::')}`;
}

/** Outbound effects use matched router patterns, for direct HTTP and MCP alike. */
export function commanderOutboundAction(method: string, route: string) {
  const key = userTokenRouteKey(method, route);
  if (key === 'PATCH /v1/chat/conversations/:p/messages/:p') return 'message_edit' as const;
  if (key === 'PATCH /v1/chat/messages/:p') return 'legacy_edit' as const;
  if (/^POST \/v1\/chat\/conversations\/:p\/(messages(?:\/secure|\/:p\/(?:forward|branch-to-group))?|threads\/:p\/replies|questions|issue-proposals)$/.test(key)) return 'message' as const;
  if (key === 'POST /v1/orgs/:p/dm/:p') return 'direct' as const;
  if (key === 'POST /v1/orgs/:p/chat/dms') return 'open_dm' as const;
  if (key === 'POST /v1/attachments/:p/shares') return 'attachment_share' as const;
  if (key === 'POST /v1/attachments/:p/forward') return 'attachment_forward' as const;
  if (key === 'GET /v1/attachment-shares/:p/link') return 'attachment_link' as const;
  if (key === 'POST /v1/projects/:p/chat' || key === 'POST /v1/issues/:p/chat') return 'legacy_chat' as const;
  return null;
}

export const USER_TOKEN_SIGNED_IN_PERSON_RULE: NonDelegableRule = {
  pattern: /^\/v1\//,
  code: 'signed_in_person',
  reason: 'This needs a person signed in. No org API key can do it, and no user token can either.',
};

/**
 * `apiKeyReachable` is plugins/auth.ts's `isApiKeyReachableRoute` for the same route: required, so a caller cannot
 * forget the finding-3 rule by leaving it out.
 */
export function userTokenRoutePolicy(method: string, route: string, apiKeyReachable: boolean, sessionActionsOn = true): UserTokenRoutePolicy {
  const m = method.toUpperCase();
  const legacyMint = !sessionActionsOn && userTokenRouteKey(m, route) === 'POST /v1/me/user-tokens';
  const signedInPersonOnly = !apiKeyReachable && !BEYOND_API_KEY.has(userTokenRouteKey(m, route)) && !legacyMint;
  // The transport method is not a product action; GET/DELETE authenticate before the stateless 405.
  if (TRANSPORT_ROUTES.has(route)) return { nonDelegable: null, signedInPersonOnly, abilities: ['read'], approvalReason: null, approvalAlways: false };
  // goodqa#5118: exclusive -- the operator ability and nothing else (see QAC_OPERATOR_ROUTE).
  if (QAC_OPERATOR_ROUTE.test(route)) return { nonDelegable: null, signedInPersonOnly, abilities: ['qac.directive'], approvalReason: null, approvalAlways: false };
  const nonDelegable =
    USER_TOKEN_NON_DELEGABLE_RULES.find((rule) => (sessionActionsOn || rule.code !== 'token_mint') && (!rule.methods || rule.methods.includes(m)) && rule.pattern.test(route)) ?? null;
  const artifactPoll = m === 'POST' && (/^\/v1\/orgs\/[^/]+\/artifacts\/latest$/.test(route) || route === '/v1/me/desktop-session');
  const abilities = new Set<UserTokenAbility>([SAFE_METHODS.has(m) || artifactPoll ? 'read' : 'write']);
  let approvalReason: string | null = null;
  let approvalAlways = false;
  for (const rule of USER_TOKEN_ABILITY_RULES) {
    if (!methodMatches(rule.methods, m) || !rule.pattern.test(route)) continue;
    for (const a of rule.abilities) abilities.add(a);
    if (rule.approval && !approvalReason) approvalReason = rule.approval;
    if (rule.approval && rule.approvalAlways) approvalAlways = true;
  }
  if (m === 'DELETE' && !DELETE_WITHOUT_DATA_DELETE.some((p) => p.test(route))) {
    abilities.add('data.delete');
    approvalReason ??= 'data.delete';
  }
  return { nonDelegable, signedInPersonOnly, abilities: [...abilities].sort(), approvalReason, approvalAlways };
}

/** The abilities in `required` the token does not hold. `all` (expanded by the caller) holds everything. */
export function missingAbilities(held: ReadonlySet<UserTokenAbility>, required: readonly UserTokenAbility[]): UserTokenAbility[] {
  return required.filter((a) => !held.has(a));
}

/** Every concrete ability, in a stable order: the expansion of `all`. */
export const ALL_ABILITIES: readonly UserTokenAbility[] = USER_TOKEN_ABILITIES;

/**
 * The request body digest an approval is bound to: sha256 over a canonical JSON (object keys sorted at every depth), so
 * the same body sent with its keys in another order matches, and any changed value does not. An absent body is the
 * digest of the empty string.
 */
export function canonicalBodySha256(body: unknown): string {
  const text = body === undefined || body === null ? '' : canonicalJson(body);
  return createHash('sha256').update(text).digest('hex');
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Buffer.isBuffer(value)) return JSON.stringify({ $buffer: createHash('sha256').update(value).digest('hex') });
  if (Array.isArray(value)) return `[${value.map((v) => canonicalJson(v)).join(',')}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(',')}}`;
}

/**
 * MINT-CHAIN rule for the OTHER keys a user token can mint (docs/design/USER-TOKENS.md section 5): an org API key
 * minted (or re-scoped, or extended) by a user token may not carry more than the token itself.
 *
 * Review round 1, finding 2: this was a hand-kept family -> ability map, and it was wrong where it mattered -- a
 * `write` key can DELETE, so a token without `data.delete` minted a key that deleted what the token could not. It is
 * now COMPUTED: the abilities a key needs are the union of what this policy demands of a token on every route the key
 * could reach (plugins/auth.ts `apiKeyRoutesReachableWithScopes`, an over-approximation). So the key's ceiling is the
 * token's own rule, route by route, and cannot drift from it. Routes no token may use at all (`nonDelegable`) are not
 * counted: a key reaching one (a persona key reading back the secret IT requested) is the key's own designed
 * boundary, not a power the token holds.
 */
export function abilitiesForApiKeyReach(routes: ReadonlyArray<{ method: string; path: string }>): UserTokenAbility[] {
  const out = new Set<UserTokenAbility>();
  for (const r of routes) {
    const p = userTokenRoutePolicy(r.method, r.path, true);
    if (p.nonDelegable) continue;
    for (const a of p.abilities) out.add(a);
  }
  return [...out].sort();
}

/**
 * Refusal facts (or null) for a user token minting/changing an org API key. `held` is the token's expanded abilities;
 * `required` what the key's scopes reach (`abilitiesForApiKeyReach`, undefined = scopes not being changed);
 * `keyExpiresAt` the key's end (null = never); `tokenExpiresAt` the token's.
 */
export function apiKeyMintExceedsUserToken(input: {
  held: ReadonlySet<UserTokenAbility>;
  required?: readonly UserTokenAbility[];
  keyExpiresAt?: Date | null;
  tokenExpiresAt: Date | null;
}): { missing: UserTokenAbility[]; expiryTooLate: boolean } | null {
  const missing = input.required ? missingAbilities(input.held, input.required) : [];
  const expiryTooLate =
    input.tokenExpiresAt !== null &&
    input.keyExpiresAt !== undefined &&
    (input.keyExpiresAt === null || input.keyExpiresAt.getTime() > input.tokenExpiresAt.getTime());
  return missing.length > 0 || expiryTooLate ? { missing, expiryTooLate } : null;
}
