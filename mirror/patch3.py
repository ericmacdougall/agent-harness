import sys
p = sys.argv[1]
s = open(p).read()


def rep(old, new):
    global s
    assert s.count(old) == 1, (s.count(old), old[:80])
    s = s.replace(old, new)


rep("""      throw userTokenRefusal(req, credential.token, routePattern, new AppError(403, 'desktop_token_session_scope', 'This desktop session was started from a user token and can only do what the desktop app needs.'));""",
    """      throw boundRouteClassRefusal(req, credential.token, routePattern, routeKey, userTokenGateDeps(req));""")
rep("refusal as userTokenRefusal, ", "boundRouteClassRefusal, ")
open(p, 'w').write(s)
print('ok')
