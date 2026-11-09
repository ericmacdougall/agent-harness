import sys
root = sys.argv[1]  # apps/api/test


def patch(name, edits):
    path = f'{root}/{name}'
    s = open(path).read()
    for old, new in edits:
        assert s.count(old) == 1, (name, s.count(old), old[:80])
        s = s.replace(old, new)
    open(path, 'w').write(s)


patch('user-token-desktop-session-rt3.test.ts', [
    ("""    await ctx.db.update(userTokens).set({ abilities: ['read', 'write', 'desktop_signin'] }).where(eq(userTokens.id, t.id));
    expect((await inj('GET', '/v1/me', b)).statusCode).toBe(401);""",
     """    // goodqa#15561 D6: per request only desktop_signin keeps the session alive (narrowing anything else narrows it through the gate)
    await ctx.db.update(userTokens).set({ abilities: ['read', 'write', 'machines', 'tokens.create_other_keys'] }).where(eq(userTokens.id, t.id));
    expect((await inj('GET', '/v1/me', b)).statusCode).toBe(401);"""),
    ("""    const required = new Set<string>(DESKTOP_SESSION_REQUIRED_ABILITIES);""",
     """    // goodqa#15561 D6: starting a session needs desktop_signin + read; the host routes need the host set the waivers name
    const required = new Set<string>([...DESKTOP_SESSION_REQUIRED_ABILITIES, ...HOST_WAIVER_ABILITIES]);"""),
])
s = open(f'{root}/user-token-desktop-session-rt3.test.ts').read()
assert s.count("DESKTOP_SESSION_REQUIRED_ABILITIES") >= 2
import re
m = re.search(r"import \{([^}]*)DESKTOP_SESSION_REQUIRED_ABILITIES([^}]*)\} from '../src/lib/desktop-token-session';", s)
assert m, 'import'
s = s.replace(m.group(0), m.group(0).replace("DESKTOP_SESSION_REQUIRED_ABILITIES", "DESKTOP_SESSION_REQUIRED_ABILITIES, HOST_WAIVER_ABILITIES", 1))
open(f'{root}/user-token-desktop-session-rt3.test.ts', 'w').write(s)

patch('user-token-desktop-session.test.ts', [
    ("""  it('a token listing exactly the five required abilities is enough; missing any one is refused', async () => {
    const owner = await signupUser(ctx.app, { name: 'Owner' });
    const five = ['write', 'read', 'machines', 'tokens.create_other_keys', 'desktop_signin'];
    const token = await mint(owner, { abilities: five });
    const r = await inject('POST', URL, token.headers, BODY);
    expect(r.statusCode, r.body).toBe(200);
    for (const drop of five) {
      const narrow = await mint(owner, { abilities: five.filter((a) => a !== drop), name: 'no ' + drop });
      const refused = await inject('POST', URL, narrow.headers, BODY);
      expect(refused.statusCode, drop + ' ' + refused.body).toBe(403);
    }
  });""", """  it('goodqa#15561 D6: a token needs exactly desktop_signin and read to start a session; dropping either is refused, dropping machines, write or tokens.create_other_keys is not', async () => {
    const owner = await signupUser(ctx.app, { name: 'Owner' });
    const five = ['write', 'read', 'machines', 'tokens.create_other_keys', 'desktop_signin'];
    const token = await mint(owner, { abilities: five });
    const r = await inject('POST', URL, token.headers, BODY);
    expect(r.statusCode, r.body).toBe(200);
    for (const drop of five) {
      const narrow = await mint(owner, { abilities: five.filter((a) => a !== drop), name: 'no ' + drop });
      const res = await inject('POST', URL, narrow.headers, BODY);
      const needed = drop === 'desktop_signin' || drop === 'read';
      expect(res.statusCode, drop + ' ' + res.body).toBe(needed ? 403 : 200);
    }
  });"""),
])

patch('user-tokens-policy.test.ts', [
    ("""r.method === 'GET' || (r.method==='POST' && r.url==='/v1/orgs/:orgId/artifacts/latest') ? 'read' : 'write');""",
     """r.method === 'GET' || (r.method==='POST' && (r.url==='/v1/orgs/:orgId/artifacts/latest' || r.url==='/v1/me/desktop-session')) ? 'read' : 'write');"""),
])
print('ok')
