import sys


def patch(path, edits):
    s = open(path).read()
    for old, new in edits:
        assert s.count(old) == 1, (path, s.count(old), old[:90])
        s = s.replace(old, new)
    open(path, 'w').write(s)


# spec review F1/F6 and polling D9 scope: refusals stay ledgered (the stolen-session trail), chat polls wait for S1c
patch('desktop-token-session.ts', [
    ("""  'GET /v1/chat/unread-count', 'GET /v1/orgs/:p/chat/unread-count', 'GET /v1/chat/active',
]);""", """]);"""),
    (""" * zero-write reads: no ledger row (allowed or refused) and no last-use update, so a desktop left open does not write about 15
 * rows a minute per window for nothing. Bearer calls are unchanged. Real work (CRM reads and writes, enrollment, consent) is
 * always ledgered. goodqa#15561 ledger-load measurement.""", """ * zero-write reads: no ledger row and no last-use update for a request that is ALLOWED, so a desktop left open does not write
 * about 15 rows a minute per window for nothing. A REFUSED poll is still ledgered (the trail of a stolen session probing). Bearer
 * calls are unchanged. Real work (CRM reads and writes, enrollment, consent) is always ledgered. The chat unread polls join this
 * list when Messages is delegated (S1c). goodqa#15561 ledger-load measurement."""),
])
patch('auth-gate.ts', [
    ("""  // Observation refusals share the successful-request policy; other reads retain their denial audit.
  if (ledgerQuiet(req, routePattern)) return err;""", """  // Observation refusals share the successful-request policy; other reads retain their denial audit. A refused desktop poll is
  // still written: it is the only trail of a stolen session probing.
  if (isZeroWriteRead(req.method, routePattern)) return err;"""),
])
patch('bound-session.ts', [
    ("""/**
 * Token kinds that may be the bound token: a token the owner minted signed in (`session`) or, legacy, through a parent
 * token (`user_token`). `oauth` (an MCP grant), `commander_turn` (a server-created per-turn credential) and `operator` /
 * `pairing` (never produced for a token that can hold `desktop_signin`) are refused (goodqa#15561 Q9).
 */
export const BOUND_ALLOWED_CREATED_VIA: ReadonlySet<string> = new Set(['session', 'user_token']);""", """/**
 * Token kinds that may be the bound token: a token the owner minted signed in (`session`), legacy through a parent token
 * (`user_token`), or by the operator script (`operator`: the orchestrator token, every ability, no expiry; a session bound to
 * it can do nothing its owner-held token cannot do by bearer). `oauth` (an MCP grant, whose abilities cannot include
 * `desktop_signin`), `commander_turn` (a server-created per-turn credential) and `pairing` are refused (goodqa#15561 Q9).
 * `operator` is admitted because the operator script mints it with `desktop_signin` and the live desktop may be bound to one:
 * refusing it would end that session on deploy. Defense in depth only, the token gate is the boundary (a legacy child minted
 * by a parent token is `user_token` whatever the root).
 */
export const BOUND_ALLOWED_CREATED_VIA: ReadonlySet<string> = new Set(['session', 'user_token', 'operator']);"""),
])
patch('auth-gate.ts', [
    ("""    if (token.createdVia === 'commander_turn' || token.createdVia === 'oauth') throw Errors.unauthorized('Session is no longer valid');""",
     """    if (token.createdVia === 'commander_turn' || token.createdVia === 'oauth') throw Errors.unauthorized('Session is no longer valid');"""),
]) if False else None

s = open('user-token-desktop-session-delegation.test.ts').read()
old = "for (const kind of ['oauth', 'operator', 'pairing']) {"
assert s.count(old) == 1
s = s.replace(old, "for (const kind of ['oauth', 'pairing']) {")
old = """      expect(res.statusCode, kind).toBe(401);
    }
    expect(token.id).toBeTruthy();"""
assert s.count(old) == 1
s = s.replace(old, """      expect(res.statusCode, kind).toBe(401);
      const ended = await ctx.db.select().from(sessions).where(and(eq(sessions.userId, w.owner.user.id), like(sessions.loginMethod, `user_token_desktop:${t.token.id}:%`)));
      expect(ended.every((r) => r.revokedAt && r.revokedReason === 'user_token_ended'), kind).toBe(true);
    }
    // the operator script mints an all-ability orchestrator token; a session bound to it is admitted (it can do what the token can)
    const op = await bound(CRM_SESSION);
    await ctx.db.execute(sql`update user_tokens set created_via = 'operator' where id = ${op.token.id}::uuid`);
    expect((await inj('GET', crmUrl('/contacts'), op.session.headers)).statusCode).toBe(200);
    expect(token.id).toBeTruthy();""")
# NEG-13: pin the refusal codes, not any 4xx
for who in ('noRead', 'noSignin'):
    old = f"expect((await inj('POST', '/v1/me/desktop-session', {who}.headers, {{ client: 'desktop-ctl' }})).statusCode).toBeGreaterThanOrEqual(400);"
    assert s.count(old) == 1, who
    s = s.replace(old, f"const r_{who} = await inj('POST', '/v1/me/desktop-session', {who}.headers, {{ client: 'desktop-ctl' }});\n    expect(r_{who}.statusCode, r_{who}.body).toBe(403);\n    expect(codeOf(r_{who})).toBe('user_token_ability_missing');")
# refused polls stay ledgered
old = """    await inj('GET', '/v1/me', token.headers);
    await inj('GET', crmUrl('/contacts'), session.headers);
    await new Promise((r) => setTimeout(r, 400));
    expect(await count()).toBe(rows0 + 2);"""
assert s.count(old) == 1
s = s.replace(old, """    await inj('GET', '/v1/me', token.headers);
    await inj('GET', crmUrl('/contacts'), session.headers);
    await new Promise((r) => setTimeout(r, 400));
    expect(await count()).toBe(rows0 + 2);
    // a REFUSED poll is the trail of a stolen session: it is written
    await ctx.db.update(userTokens).set({ abilities: ['desktop_signin', 'crm'] }).where(eq(userTokens.id, token.id));
    expect((await inj('GET', '/v1/me', session.headers)).statusCode).toBe(403);
    await new Promise((r) => setTimeout(r, 400));
    expect(await count()).toBe(rows0 + 3);""")
open('user-token-desktop-session-delegation.test.ts', 'w').write(s)
print('ok')
