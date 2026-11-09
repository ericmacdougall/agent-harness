import sys
p = sys.argv[1]
s = open(p).read()


def rep(old, new):
    global s
    assert s.count(old) == 1, (s.count(old), old[:90])
    s = s.replace(old, new)


rep("throw boundRouteClassRefusal(req, credential.token, routePattern, routeKey, userTokenGateDeps(req));",
    "throw boundRouteClassRefusal(req, reply, credential.token, routePattern, routeKey, userTokenGateDeps(req));")
rep("const userTokenGateDeps = (req: FastifyRequest, opts: { delegated?: boolean } = {}): UserTokenGateDeps => ({",
    "const userTokenGateDeps = (req: FastifyRequest, opts: { delegated?: boolean; userId?: string; orgIds?: readonly string[] | null } = {}): UserTokenGateDeps => ({")
rep("""      if (opts.delegated && orgId && apiKeyRouteResources(r.method, route)?.includes('crm') && !(await isFeatureEnabled(r.server.db, orgId, CRM_API_KEY_FLAG))) {
        throw new AppError(404, 'crm_api_disabled', 'CRM is switched off for sessions in this organization.');
      }""", """      // RT15561-2: the distinct code only for an org the owner belongs to and the token may reach; anything else keeps the plain
      // not-found a bearer call gets, so a session cannot probe whether an org exists or has CRM switched off.
      if (opts.delegated && orgId && opts.userId && (!opts.orgIds || opts.orgIds.includes(orgId)) && apiKeyRouteResources(r.method, route)?.includes('crm') && !(await isFeatureEnabled(r.server.db, orgId, CRM_API_KEY_FLAG))) {
        const [member] = await r.server.db.select({ userId: orgMembers.userId }).from(orgMembers).where(and(eq(orgMembers.orgId, orgId), eq(orgMembers.userId, opts.userId))).limit(1);
        if (member) throw new AppError(404, 'crm_api_disabled', 'CRM is switched off for sessions in this organization.');
      }""")
rep("userTokenGateDeps(req, { delegated: door === 'delegated' })",
    "userTokenGateDeps(req, { delegated: door === 'delegated', userId: credential.token.userId, orgIds: credential.token.orgIds })")
open(p, 'w').write(s)
print('ok')
