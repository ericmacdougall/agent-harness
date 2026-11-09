p = 'user-token-desktop-session-delegation.test.ts'
s = open(p).read()


def rep(old, new):
    global s
    assert s.count(old) == 1, (s.count(old), old[:80])
    s = s.replace(old, new)


rep("""/secure/reveal`, { method: 'password', password: 'password123' }],""", """/secure/reveal`, { method: 'password', currentPassword: 'password123' }],""")
# child token: fixture asks first; a session needs the mint without a pending approval
rep("""    const childToken = { headers: bearer((child.json() as { token: string }).token) };
""", """    const childToken = { headers: bearer((child.json() as { token: string }).token) };
    await ctx.db.update(userTokens).set({ requireHumanApproval: false }).where(eq(userTokens.createdByTokenId, parent.id));
""")
# NEG-16: touch only the bound sessions, never the owner's own browser session
rep("""      await ctx.db.update(sessions).set(mutate(token.id)).where(and(eq(sessions.userId, w.owner.user.id), isNull(sessions.revokedAt)));""",
    """      await ctx.db.update(sessions).set(mutate(token.id)).where(and(eq(sessions.userId, w.owner.user.id), isNull(sessions.revokedAt), like(sessions.loginMethod, 'user_token_desktop:%')));""")
rep("""    await ctx.db.update(sessions).set({ loginMethod: 'user_token_desktop:11111111-1111-4111-8111-111111111111:0000000000000000' }).where(and(eq(sessions.userId, w.owner.user.id), isNull(sessions.revokedAt)));""",
    """    await ctx.db.update(sessions).set({ loginMethod: 'user_token_desktop:11111111-1111-4111-8111-111111111111:0000000000000000' }).where(and(eq(sessions.userId, w.owner.user.id), isNull(sessions.revokedAt), like(sessions.loginMethod, 'user_token_desktop:%')));""")
rep("import { and, eq, isNull } from 'drizzle-orm';", "import { and, eq, isNull, like } from 'drizzle-orm';")
# NEG-19: switching back on must overwrite (the helper only inserts when missing)
rep("""    await enableUserTokensForTests(ctx.db);

    for (const kind of""", """    await ctx.db.execute(sql`update platform_settings set value = 'true'::jsonb where key = 'userTokens.enabled'`);

    for (const kind of""")
rep("""    const { sql } = await import('drizzle-orm');
""", "")
rep("import { and, eq, isNull, like } from 'drizzle-orm';", "import { and, eq, isNull, like, sql } from 'drizzle-orm';")
open(p, 'w').write(s)
print('ok')
