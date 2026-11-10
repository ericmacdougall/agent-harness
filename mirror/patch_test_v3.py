p = 'user-token-contact-timeline-default.test.ts'
s = open(p).read()


def sub(old, new):
    global s
    assert s.count(old) == 1, (s.count(old), old[:80])
    s = s.replace(old, new)


# NEG-4: pin the outsider status set
sub("      expect(r.statusCode, `${u} ${r.body}`).toBeGreaterThanOrEqual(403);\n      expect(r.body).not.toContain('Ada');",
    "      expect([403, 404], `${u} ${r.body}`).toContain(r.statusCode);\n      expect(r.body).not.toContain('Ada');")

# NEG-12: a real HEAD request, and PATCH/DELETE pinned
a = s.index("  it('HEAD on the two routes behaves like GET")
b = s.index("  it('both keys are on the delegated door")
s = s[:a] + """  it('HEAD is covered exactly like GET on the two routes (200 with crm, refused without), and no other method on those paths is opened', async () => {
    const { session } = await bound(['desktop_signin', 'read', 'write', 'crm']);
    for (const u of [detail(w.org.id, contactA), timeline(w.org.id, contactA)]) {
      const h = await inj('HEAD', u, session.headers);
      expect(h.statusCode, `HEAD ${u}`).toBe(200);
    }
    const noCrm = await bound(['desktop_signin', 'read']);
    for (const u of [detail(w.org.id, contactA), timeline(w.org.id, contactA)]) {
      const h = await inj('HEAD', u, noCrm.session.headers);
      expect(h.statusCode, `HEAD no crm ${u}`).toBe(403);
    }
    // PATCH on the detail path stays the ordinary CRM write door (allowed by crm+write, owner role), never a W4 path
    const patchR = await inj('PATCH', detail(w.org.id, contactA), session.headers, { firstName: 'Zed' });
    expect(patchR.statusCode, patchR.body).toBe(200);
    const del = await inj('DELETE', detail(w.org.id, contactA), session.headers);
    expect(del.statusCode).toBe(403);
    expect(['user_token_non_delegable', 'desktop_token_session_scope']).toContain(codeOf(del));
    // POST on the timeline path is the existing session-only timeline create, still refused to a bound session
    const post = await inj('POST', `/v1/orgs/${w.org.id}/crm/timeline`, session.headers, { kind: 'task', title: 'x', occursAt: '2026-08-11T14:05:00.000Z', links: [] });
    expect(post.statusCode).toBe(403);
  });
""" + s[b:]

s += '''
describe('NEG-1 (rest): read and desktop_signin are needed to start and to keep a session', () => {
  it('a token without read cannot start a session; removing read or desktop_signin mid-session refuses or ends it', async () => {
    const noRead = await mint(w.owner, ['desktop_signin', 'crm']);
    const start = await inj('POST', '/v1/me/desktop-session', noRead.headers, { client: 'desktop-ctl' });
    expect(start.statusCode, start.body).toBeGreaterThanOrEqual(400);
    for (const drop of ['read', 'desktop_signin']) {
      const { token, session } = await bound(CRM);
      expect((await inj('GET', detail(w.org.id, contactA), session.headers)).statusCode).toBe(200);
      await ctx.db.update(userTokens).set({ abilities: CRM.filter((a) => a !== drop) }).where(eq(userTokens.id, token.id));
      const r = await inj('GET', detail(w.org.id, contactA), session.headers);
      expect([401, 403], `${drop} removed: ${r.body}`).toContain(r.statusCode);
      expect(r.body).not.toContain('Ada');
    }
  });
});
'''
open(p, 'w').write(s)
print('ok')
