import sys
p = 'auth-gate.ts'
s = open(p).read()


def rep(old, new, count=1):
    global s
    assert s.count(old) == count, (s.count(old), old[:70])
    s = s.replace(old, new)


# 1. module augmentation
rep("""      machineGrantIds?: string[];
    };
  }
}""", """      machineGrantIds?: string[];
    };
    /** goodqa#15561: set while a desktop session bound to a user token is the carrier (both doors); the ledger rows say so. */
    userTokenDoor?: { via: 'desktop_session'; sessionId: string; door: 'host' | 'delegated' };
    /**
     * goodqa#15561 D9: the token facts of a bound session on the HOST door, where `req.auth` keeps the real session id.
     * Read only by the credential-minting machine routes (modules/machines/enroll/routes.ts `enrollActor`), so a machine
     * credential enrolled through a bound session is capped at the token chain's end, limited to its `orgIds` and linked to it.
     */
    boundUserToken?: { userTokenId: string; userTokenOrgIds: string[] | null; userTokenExpiresAt: Date | null };
  }
}""")

# 2. refusal
rep("""function refusal(req: FastifyRequest, token: UserTokenRow, routePattern: string | undefined, err: AppError): AppError {""",
    """/** The ledger detail that names a desktop-session carrier; empty for a bearer call (its rows are unchanged). */
export function doorDetail(req: FastifyRequest): Record<string, unknown> {
  return req.userTokenDoor ? { via: req.userTokenDoor.via, sessionId: req.userTokenDoor.sessionId } : {};
}

export function refusal(req: FastifyRequest, token: UserTokenRow, routePattern: string | undefined, err: AppError): AppError {""")
rep("""      detail: { code: err.code },
    },
    req.log,
  ));
  return err;""", """      detail: { code: err.code, ...doorDetail(req) },
    },
    req.log,
  ));
  return err;""")

# 3. kill switch shared
rep("""  if ((await getPlatformSetting(req.server.db, 'userTokens.enabled')) !== true && !(token.createdVia === 'commander_turn' && token.orgIds?.length === 1 && (await getCommanderReleaseSetting(req.server.db, 'userTokens.commanderTurnsOnly', token.orgIds[0]!)) === true)) throw Errors.unauthorized('User tokens are disabled');
""", """  if (!(await userTokensPlatformAllows(req.server.db, token))) throw Errors.unauthorized('User tokens are disabled');
""")
rep("""/** Credential-only verification shared with preValidation.""", """/**
 * The platform kill switch `userTokens.enabled` (a Commander turn credential may instead be admitted by its org's own
 * release setting). Shared by the bearer credential step and the desktop-session load (goodqa#15561 D1): a switch turned off
 * ends a bound session exactly as it ends a bearer call.
 */
export async function userTokensPlatformAllows(db: DbOrTx, token: Pick<UserTokenRow, 'createdVia' | 'orgIds'>): Promise<boolean> {
  if ((await getPlatformSetting(db, 'userTokens.enabled')) === true) return true;
  return token.createdVia === 'commander_turn' && token.orgIds?.length === 1 && (await getCommanderReleaseSetting(db, 'userTokens.commanderTurnsOnly', token.orgIds[0]!)) === true;
}

/** Credential-only verification shared with preValidation.""")

# 4. apply signature
rep("""export type UserTokenGateVia = 'bearer' | 'desktop_session';""", """export type UserTokenGateVia = 'bearer' | 'desktop_session';
/** A desktop session bound to the token, as the plugin resolved it: which door, the session's real id, the route key. */
export interface BoundDoorContext { door: 'host' | 'delegated'; sessionId: string; routeKey: string }""")
rep("""  via: UserTokenGateVia,
  now = Date.now(),
): Promise<void> {
  const { token, user, effectiveExpiresAt } = credential;
  // The bearer door is the only caller until S1b; the parameter exists so the second door cannot be added without naming itself.
  void via;
""", """  via: UserTokenGateVia,
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
""")

# 5. policy: host waivers, session-action guard, elevation off for bound
rep("""  const { policy, sessionAction, disabled } = userTokenRequestRoutePolicy(req.method, routePattern, deps.isApiKeyReachableRoute(req.method, routePattern), sessionActionsOn, orgOptIn);
""", """  const { policy, sessionAction, disabled } = userTokenRequestRoutePolicy(req.method, routePattern, deps.isApiKeyReachableRoute(req.method, routePattern), sessionActionsOn, orgOptIn);
  if (bound) {
    // A desktop session never reaches a session action (its grant is an explicit human grant to a token, not to a screen).
    if (candidate) throw refusal(req, token, routePattern, new AppError(403, 'user_token_non_delegable', 'A desktop session cannot perform session actions.', { rule: 'session_action' }));
    // Host door: the same gate, with the three named waivers (lib/desktop-token-session.ts applyHostDoorWaivers).
    if (bound.door === 'host') applyHostDoorWaivers(req.method, bound.routeKey, policy);
  }
""")
rep("""  const elevated =
    policy.nonDelegable?.elevatedBy === 'machine_token_grant' &&""", """  const elevated =
    !bound &&
    policy.nonDelegable?.elevatedBy === 'machine_token_grant' &&""")

# 6. imports
rep("""import { requestClientIp } from '../../lib/client-ip';""", """import { applyHostDoorWaivers } from '../../lib/desktop-token-session';
import { requestClientIp } from '../../lib/client-ip';""")

# 7. final auth shape
rep("""  req.auth = {
    userId: user.id,
    sessionId: `${USER_TOKEN_SESSION_PREFIX}${token.id}`,""", """  if (bound?.door === 'host') {
    // The host door keeps the REAL session: the presence proof and the consent audit read its id as a sessions uuid.
    req.auth = { userId: user.id, sessionId: bound.sessionId, email: user.email };
    req.boundUserToken = { userTokenId: token.id, userTokenOrgIds: token.orgIds ? [...token.orgIds] : null, userTokenExpiresAt: effectiveExpiresAt };
  } else req.auth = {
    userId: user.id,
    sessionId: `${USER_TOKEN_SESSION_PREFIX}${token.id}`,""")
rep("""  setRequestActor({ userId: user.id, userTokenId: token.id });
  const client""", """  setRequestActor(bound?.door === 'host' ? { userId: user.id } : { userId: user.id, userTokenId: token.id });
  const client""")
open(p, 'w').write(s)
print('ok')
