p = 'gmail-limited-use.test.ts'
s = open(p).read()
s = s.replace("import { createOrg, createProject, createTestApp, resetDb, signupUser, type TestContext } from './helpers';",
              "import { createOrg, createProject, createTestApp, enableUserTokensForTests, resetDb, signupUser, type TestContext } from './helpers';", 1)
s += '''
describe('goodqa#15561 S1e-a: a desktop session started from a user token (bound door)', () => {
  it('reads contact detail and timeline but never receives the Gmail message, and still receives the other entries', async () => {
    await enableUserTokensForTests(ctx.db);
    const step = await ctx.app.inject({ method: 'POST', url: '/v1/auth/webauthn/step-up', headers: owner.headers, payload: { method: 'password', password: 'password123', purpose: 'user_tokens_manage' } });
    const minted = await ctx.app.inject({ method: 'POST', url: '/v1/me/user-tokens', headers: owner.headers, payload: { name: 'gmail bound', abilities: ['desktop_signin', 'read', 'crm'], requireHumanApproval: false, stepUpToken: step.json().stepUpToken } });
    expect(minted.statusCode, minted.body).toBe(201);
    const start = await ctx.app.inject({ method: 'POST', url: '/v1/me/desktop-session', headers: { authorization: `Bearer ${minted.json().token}` }, payload: { client: 'desktop-ctl' } });
    expect(start.statusCode, start.body).toBe(200);
    const session = { authorization: `Bearer ${start.json().tokens.accessToken}` };
    for (const url of [`/v1/orgs/${orgId}/crm/contacts/${contactId}/timeline`, `/v1/orgs/${orgId}/crm/contacts/${contactId}`]) {
      const res = await get(session, url);
      expect(res.statusCode, `${url} ${res.body}`).toBe(200);
      expect(res.body, url).toContain('MANUALEMAIL-body');
      expect(res.body, url).not.toContain('GMAILSUBJECT-91c2');
      expect(res.body, url).not.toContain('GMAILSNIPPET-91c2');
      // positive control: the signed-in owner sees the Gmail message on the same route
      expect((await get(owner.headers, url)).body, url).toContain(GMAIL_SNIPPET);
    }
  });
});
'''
open(p, 'w').write(s)
print('ok')
