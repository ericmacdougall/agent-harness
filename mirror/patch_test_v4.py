p = 'user-token-contact-timeline-default.test.ts'
s = open(p).read()
s += '''
describe('NEG-13 (red-team N1): a bound session cannot probe withheld entries through q, pinned or the cursor', () => {
  it('q and pinned are refused on the timeline; a page showing no visible entry gives no cursor and no withheld id', async () => {
    const colleague = await addMember(ctx, w.org.id, { role: 'admin', extraPermissions: ['crm:create', 'crm:edit'], name: 'Colleague3' });
    const mate = await addMember(ctx, w.org.id, { role: 'member', name: 'Mate3' });
    const hiddenId = await logEntry(w.org.id, colleague.headers, contactA, 'Personal wombatsecret note', {
      visibility: 'personal', ownerUserId: colleague.user.id, occursAt: '2026-09-01T10:00:00.000Z',
    });
    const { session } = await bound(CRM, mate);
    for (const qs of ['?q=wombatsecret', '?q=platypusword', '?pinned=true']) {
      const r = await inj('GET', `${timeline(w.org.id, contactA)}${qs}`, session.headers);
      expect([r.statusCode, codeOf(r)], qs).toEqual([400, 'user_token_filter_unsupported']);
      expect(r.body).not.toContain(hiddenId);
    }
    // newest raw row is the colleague personal entry: limit=1 shows nothing visible, and must not hand back its id or time
    const page = await inj('GET', `${timeline(w.org.id, contactA)}?limit=1`, session.headers);
    expect(page.statusCode, page.body).toBe(200);
    expect(page.body).not.toContain(hiddenId);
    expect(page.body).not.toContain('2026-09-01');
    expect((page.json() as { nextCursor: string | null }).nextCursor).toBeNull();
    // the contact detail embeds the same first page and must not name it either
    const d = await inj('GET', detail(w.org.id, contactA), session.headers);
    expect(d.body).not.toContain(hiddenId);
    // control: the colleague signed in sees the entry and a person's own paging is unchanged
    const own = await inj('GET', `${timeline(w.org.id, contactA)}?q=wombatsecret`, colleague.headers);
    expect(own.statusCode, own.body).toBe(200);
    expect(own.body).toContain(hiddenId);
  });
});
'''
open(p, 'w').write(s)
print('ok')
