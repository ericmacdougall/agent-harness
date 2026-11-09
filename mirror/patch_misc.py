import re
import sys

root = sys.argv[1]  # the worktree's apps/api


def patch(path, edits):
    full = f'{root}/{path}'
    s = open(full).read()
    for old, new, count in edits:
        assert s.count(old) == count, (path, s.count(old), old[:80])
        s = s.replace(old, new)
    open(full, 'w').write(s)


# enrollment: the token facts of a bound session (NEG-29)
p = 'src/modules/machines/enroll/routes.ts'
s = open(f'{root}/{p}').read()
assert s.count('enrollActor(auth)') == 2 or True
s = s.replace("""function enrollActor(auth: AuthContext): EnrollActor {
  if (isAgentCredential(auth) && !auth.userTokenId) throw Errors.forbidden('Machine tokens and enrollments are a person\\'s (signed in) or their user token\\'s; never an org API key');
  return {
    userId: auth.userId,
    userTokenId: auth.userTokenId ?? null,
    userTokenOrgIds: auth.userTokenOrgIds ?? null,
    userTokenExpiresAt: auth.userTokenExpiresAt ?? null,
  };
}""", """function enrollActor(auth: AuthContext, req: FastifyRequest): EnrollActor {
  if (isAgentCredential(auth) && !auth.userTokenId) throw Errors.forbidden('Machine tokens and enrollments are a person\\'s (signed in) or their user token\\'s; never an org API key');
  // goodqa#15561 D9: a desktop session bound to a user token keeps its real session id (presence proof, consent audit), so the
  // token's facts travel separately: the machine credential is then capped at the token chain's end, limited to the token's
  // `orgIds`, linked to it, and refused once the token is revoked, exactly as when the token enrolls by bearer.
  const bound = req.boundUserToken;
  return {
    userId: auth.userId,
    userTokenId: auth.userTokenId ?? bound?.userTokenId ?? null,
    userTokenOrgIds: auth.userTokenOrgIds ?? bound?.userTokenOrgIds ?? null,
    userTokenExpiresAt: auth.userTokenExpiresAt ?? bound?.userTokenExpiresAt ?? null,
  };
}""")
assert 'req: FastifyRequest): EnrollActor' in s
n_before = s.count('enrollActor(auth)') + s.count('enrollActor(requireAuth(req))')
s = s.replace('enrollActor(auth)', 'enrollActor(auth, req)').replace('enrollActor(requireAuth(req))', 'enrollActor(requireAuth(req), req)')
assert n_before >= 6, n_before
open(f'{root}/{p}', 'w').write(s)

# policy line: the desktop-session mint needs desktop_signin + read (D6), and a POST that is not a write
patch('src/lib/user-token-policy.ts', [
    ("""  { methods: ['POST'], pattern: /^\\/v1\\/me\\/desktop-session$/, abilities: ['desktop_signin', 'machines', 'read', 'tokens.create_other_keys'], approval: 'desktop_signin' },""",
     """  // goodqa#15561 D6: to START a session a token needs the right to sign in and to read, nothing else (the mint is not a write:
  // what the session can do is the gate's answer for each later route). Pinned to DESKTOP_SESSION_REQUIRED_ABILITIES by test.
  { methods: ['POST'], pattern: /^\\/v1\\/me\\/desktop-session$/, abilities: ['desktop_signin', 'read'], approval: 'desktop_signin' },""", 1),
    ("""  const artifactPoll = m === 'POST' && /^\\/v1\\/orgs\\/[^/]+\\/artifacts\\/latest$/.test(route);""",
     """  const artifactPoll = m === 'POST' && (/^\\/v1\\/orgs\\/[^/]+\\/artifacts\\/latest$/.test(route) || route === '/v1/me/desktop-session');""", 1),
])
# request gate type: a refused out-of-table route has no door
patch('src/modules/user-tokens/auth-gate.ts', [
    ("door: 'host' | 'delegated' };\n    /**\n     * goodqa#15561 D9", "door: 'host' | 'delegated' | 'none' };\n    /**\n     * goodqa#15561 D9", 1),
])
print('ok')
