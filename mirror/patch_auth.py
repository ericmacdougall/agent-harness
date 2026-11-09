import sys
p = sys.argv[1]
s = open(p).read()


def rep(old, new, count=1):
    global s
    assert s.count(old) == count, (s.count(old), old[:80])
    s = s.replace(old, new)


rep("import { desktopBindingState, desktopMintingFingerprint, desktopMintingTokenId, desktopRouteKey, desktopTokenSessionMayUse } from '../lib/desktop-token-session';",
    "import { desktopMintingFingerprint, desktopMintingTokenId, desktopRouteDoor, desktopRouteKey } from '../lib/desktop-token-session';\nimport { loadBoundUserToken } from '../modules/user-tokens/bound-session';")
rep("import { authenticateUserTokenCredential, authenticateUserTokenRequest, userTokenCredentialEnabled, looksLikeUserToken, READ_ONLY_METHODS } from '../modules/user-tokens/auth-gate';",
    "import { applyUserTokenRoutePolicy, authenticateUserTokenCredential, authenticateUserTokenRequest, doorDetail, refusal as userTokenRefusal, userTokenCredentialEnabled, looksLikeUserToken, READ_ONLY_METHODS, type UserTokenCredential, type UserTokenGateDeps } from '../modules/user-tokens/auth-gate';")

# bearer branch: deps built by a shared function
old_bearer = """      await authenticateUserTokenRequest(req, reply, token, {
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
        applyApiKeyOrgSwitches: (r, route, orgId, commanderTurn) => applyApiKeyOrgSwitchesForUserToken(r, route, orgId, app.config.TASK_298_ATTACHMENT_FINAL_GATE_ENABLED, commanderTurn),
        webOrigin: app.config.WEB_ORIGIN,
      });
"""
rep(old_bearer, "      await authenticateUserTokenRequest(req, reply, token, userTokenGateDeps(req));\n")

rep("""  app.decorate('authenticate', async (req: FastifyRequest, reply: FastifyReply) => {
    // Idempotent per request:""", """  /**
   * The token gate's collaborators, one definition for both carriers (a bearer token and a desktop session bound to one).
   * `delegated` (the desktop door) answers a CRM request for an org whose `crm.api.enabled` is off with its own code, so the
   * app can say "CRM is switched off for sessions in this organization"; a bearer call keeps the plain 404.
   */
  const userTokenGateDeps = (req: FastifyRequest, opts: { delegated?: boolean } = {}): UserTokenGateDeps => ({
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
      if (opts.delegated && orgId && apiKeyRouteResources(r.method, route)?.includes('crm') && !(await isFeatureEnabled(r.server.db, orgId, CRM_API_KEY_FLAG))) {
        throw new AppError(404, 'crm_api_disabled', 'CRM is switched off for sessions in this organization.');
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
      throw userTokenRefusal(req, credential.token, routePattern, new AppError(403, 'desktop_token_session_scope', 'This desktop session was started from a user token and can only do what the desktop app needs.'));
    }
    await applyUserTokenRoutePolicy(req, reply, credential, userTokenGateDeps(req, { delegated: door === 'delegated' }), 'desktop_session', Date.now(), { door, sessionId, routeKey });
  };
  app.decorate('authenticate', async (req: FastifyRequest, reply: FastifyReply) => {
    // Idempotent per request:""")

# bound branch
rep("""    const boundTokenId = desktopMintingTokenId(live[0].loginMethod);
    if (boundTokenId !== null) {
      if (!boundTokenId || !(await desktopBindingState(req.server.db, claims.sub, boundTokenId, desktopMintingFingerprint(live[0].loginMethod))).live) {
        await req.server.db.update(sessions).set({ revokedAt: new Date(), revokedReason: 'user_token_ended' }).where(and(eq(sessions.id, claims.sid), isNull(sessions.revokedAt))).catch(() => undefined);
        throw Errors.unauthorized('Session is no longer valid');
      }
      if (!desktopTokenSessionMayUse(req.method, desktopRouteKey(req.routeOptions.url))) {
        throw new AppError(403, 'desktop_token_session_scope', 'This desktop session was started from a user token and can only do what the desktop app needs.');
      }
    }
""", """    const boundTokenId = desktopMintingTokenId(live[0].loginMethod);
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
""")
rep("""    req.auth = { userId: claims.sub, sessionId: claims.sid, email: claims.email };
    setRequestActor({ userId: claims.sub });
    // Backfill the hint""", """    if (boundCredential) {
      // Both doors (host and delegated) run the token gate, which sets req.auth, the token scope and the ledger.
      await authenticateBoundSession(req, reply, boundCredential, claims.sid);
    } else {
      req.auth = { userId: claims.sub, sessionId: claims.sid, email: claims.email };
      setRequestActor({ userId: claims.sub });
    }
    // Backfill the hint""")

# ledger detail
rep("""        detail: { ...(resultId ? { resultId } : {}), ...(ledger.machineGrantIds?.length ? { machineGrantIds: ledger.machineGrantIds } : {}) },""",
    """        detail: { ...(resultId ? { resultId } : {}), ...(ledger.machineGrantIds?.length ? { machineGrantIds: ledger.machineGrantIds } : {}), ...doorDetail(req) },""")
open(p, 'w').write(s)
print('ok')
