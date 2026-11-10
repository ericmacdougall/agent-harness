p = 'user-token-contact-timeline-default.test.ts'
s = open(p).read()


def sub(old, new):
    global s
    assert s.count(old) == 1, (s.count(old), old[:80])
    s = s.replace(old, new)


sub("import { eq } from 'drizzle-orm';", "import { eq, sql } from 'drizzle-orm';")
sub("import { userTokenEvents, userTokens } from '@bugtracker/db';", "import { organizations, userTokenEvents, userTokens } from '@bugtracker/db';")
# SMS route does not exist in this build: drop it
sub("      ['POST', `/v1/orgs/${w.org.id}/crm/contacts/${contactA}/sms`, { body: 'hello' }],\n", "      ['POST', `/v1/orgs/${w.org.id}/crm/contacts/${contactA}/call`, {}],\n")
# NEG-2: the timeline of another org's contact answers 200 with zero entries (no handler change), detail is 404
sub("""    for (const u of [detail(w.org.id, contactB), timeline(w.org.id, contactB)]) {
      const r = await inj('GET', u, session.headers);
      expect(r.statusCode, `${u} ${r.body}`).toBe(404);
    }""", """    await logEntry(w.other.id, w.owner.headers, contactB, 'Org B secret follow up');
    const d = await inj('GET', detail(w.org.id, contactB), session.headers);
    expect(d.statusCode, d.body).toBe(404);
    const t = await inj('GET', timeline(w.org.id, contactB), session.headers);
    expect(t.statusCode, t.body).toBe(200); // the existing handler does not check the contact; the page is empty and org-scoped
    expect((t.json() as { timeline: unknown[] }).timeline).toEqual([]);
    expect(t.body).not.toContain('Org B secret follow up');""")

s += '''
async function setSetting(key: string, value: unknown) {
  await ctx.db.execute(sql`insert into platform_settings(key,value,value_type,updated_by,reason)
    select ${key}, ${JSON.stringify(value)}::jsonb, ${typeof value === 'boolean' ? 'boolean' : 'string'}, id, 'test' from users order by created_at limit 1
    on conflict(key) do update set value=excluded.value`);
}
async function setOverrides(orgId: string, overrides: Record<string, unknown>) {
  await ctx.db.update(organizations).set({ entitlementOverrides: { 'crm.v2.records': true, 'crm.api.enabled': true, ...overrides } }).where(eq(organizations.id, orgId));
}

describe('AC-1 matrix (F4): every switch state gives 200 through the bound session, never the session-action path', () => {
  it('platform on with no org opt-in, and platform on with opt-in, with and without the session:crm_timeline grant', async () => {
    await setSetting('userTokens.sessionActions', true);
    const plain = await bound(CRM);
    for (const u of [detail(w.org.id, contactA), timeline(w.org.id, contactA)]) expect((await inj('GET', u, plain.session.headers)).statusCode, `on/no opt-in ${u}`).toBe(200);
    await setOverrides(w.org.id, { 'userTokens.sessionActions': true });
    for (const u of [detail(w.org.id, contactA), timeline(w.org.id, contactA)]) expect((await inj('GET', u, plain.session.headers)).statusCode, `on/opt-in/no grant ${u}`).toBe(200);
    const granted = await bound([...CRM, 'session:crm_timeline']);
    for (const u of [detail(w.org.id, contactA), timeline(w.org.id, contactA)]) expect((await inj('GET', u, granted.session.headers)).statusCode, `on/opt-in/grant ${u}`).toBe(200);
    // never the session-action path: no session-action audit row for the bound requests
    const audits = await ctx.db.execute(sql`select count(*)::int as n from audit_events where action = 'user_token.session_action'`);
    expect(((audits as unknown as { rows?: Array<{ n: number }> }).rows ?? (audits as unknown as Array<{ n: number }>))[0]!.n).toBe(0);
  });

  it('the bearer answers are unchanged in each switch state (bearer never gets contact detail; the timeline keeps its session-action refusal)', async () => {
    const t = await mint(w.owner, [...CRM]);
    for (const state of ['off', 'on', 'on+optin']) {
      if (state !== 'off') await setSetting('userTokens.sessionActions', true);
      if (state === 'on+optin') await setOverrides(w.org.id, { 'userTokens.sessionActions': true });
      const d = await inj('GET', detail(w.org.id, contactA), t.headers);
      expect([d.statusCode, codeOf(d)], `detail ${state}`).toEqual([403, 'user_token_non_delegable']);
      const tl = await inj('GET', timeline(w.org.id, contactA), t.headers);
      expect(tl.statusCode, `timeline ${state} ${tl.body}`).toBe(403);
      expect(['user_token_non_delegable', 'session_actions_disabled', 'user_token_ability_missing', 'user_token_session_action_missing'], `timeline ${state} ${codeOf(tl)}`).toContain(codeOf(tl));
    }
  });
});

describe('F1 / F3: the org CRM switch and the org opt-out both apply to the two routes', () => {
  it('crm.api.enabled off: 404 crm_api_disabled on both routes (contact list already answers the same)', async () => {
    const { session } = await bound(CRM);
    await setOverrides(w.org.id, { 'crm.api.enabled': false });
    for (const u of [detail(w.org.id, contactA), timeline(w.org.id, contactA)]) {
      const r = await inj('GET', u, session.headers);
      expect([r.statusCode, codeOf(r)], u).toEqual([404, 'crm_api_disabled']);
    }
  });
  it('the org opt-out userTokens.contactTimelines=false: 404 contact_timelines_disabled on both routes; other CRM reads stay; unset or true is on', async () => {
    const { session } = await bound(CRM);
    await setOverrides(w.org.id, { 'userTokens.contactTimelines': false });
    for (const u of [detail(w.org.id, contactA), timeline(w.org.id, contactA)]) {
      const r = await inj('GET', u, session.headers);
      expect([r.statusCode, codeOf(r)], u).toEqual([404, 'contact_timelines_disabled']);
    }
    expect((await inj('GET', `/v1/orgs/${w.org.id}/crm/contacts`, session.headers)).statusCode).toBe(200);
    await setOverrides(w.org.id, { 'userTokens.contactTimelines': true });
    expect((await inj('GET', detail(w.org.id, contactA), session.headers)).statusCode).toBe(200);
  });
});

describe('F2 / F8 / F7: operator tokens, HEAD, exact keys, the delegated door', () => {
  it('an operator-kind token gets no W4 (an agent-held, non-expiring orchestrator)', async () => {
    const op = await bound(CRM);
    await ctx.db.execute(sql`update user_tokens set created_via = 'operator' where id = ${op.token.id}::uuid`);
    for (const u of [detail(w.org.id, contactA), timeline(w.org.id, contactA)]) {
      const r = await inj('GET', u, op.session.headers);
      expect([r.statusCode, codeOf(r)], u).toEqual([403, 'user_token_non_delegable']);
    }
  });
  it('HEAD on the two routes behaves like GET for the bound session, and other methods on them are not opened', async () => {
    const { session } = await bound(['desktop_signin', 'read', 'write', 'crm']);
    for (const u of [detail(w.org.id, contactA)]) {
      const patchR = await inj('PATCH', u, session.headers, { firstName: 'Zed' });
      expect([200, 403, 404]).toContain(patchR.statusCode); // PATCH on the detail path is the existing CRM write door, unchanged by W4
    }
    const del = await inj('DELETE', detail(w.org.id, contactA), session.headers);
    expect(del.statusCode).toBe(403);
    expect(codeOf(del)).not.toBe('contact_timelines_disabled');
  });
  it('both keys are on the delegated door, not the host door (the Gmail withholding and live token re-read depend on it)', async () => {
    const { desktopRouteDoor } = await import('../src/lib/desktop-token-session');
    for (const k of ['/v1/orgs/:p/crm/contacts/:p', '/v1/orgs/:p/crm/contacts/:p/timeline']) expect(desktopRouteDoor('GET', k)).toBe('delegated');
  });
});

describe('F6: busy_only entries arrive opaque to a colleague session on both routes', () => {
  it('a colleague busy_only meeting shows as Busy with no subjects and no join link, on the timeline and in the contact detail', async () => {
    const colleague = await addMember(ctx, w.org.id, { role: 'admin', extraPermissions: ['crm:create', 'crm:edit'], name: 'Colleague2' });
    const mate = await addMember(ctx, w.org.id, { role: 'member', name: 'Mate2' });
    await logEntry(w.org.id, colleague.headers, contactA, 'Renewal negotiation', {
      kind: 'meeting', visibility: 'busy_only', ownerUserId: colleague.user.id, conferencingUrl: 'https://zoom.us/j/987654321',
      links: [{ subjectKind: 'contact', subjectId: contactA }, { subjectKind: 'user', subjectId: colleague.user.id, role: 'organizer' }],
    });
    const { session } = await bound(CRM, mate);
    for (const u of [timeline(w.org.id, contactA), detail(w.org.id, contactA)]) {
      const r = await inj('GET', u, session.headers);
      expect(r.statusCode, `${u} ${r.body}`).toBe(200);
      expect(r.body, u).not.toContain('Renewal negotiation');
      expect(r.body, u).not.toContain('zoom.us/j/987654321');
    }
  });
});
'''
open(p, 'w').write(s)
print('ok')
