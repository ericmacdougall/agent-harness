p = 'user-token-contact-timeline-default.test.ts'
s = open(p).read()
s += '''
describe('NEG-13 positive control (acceptance X1): paging still works for a bound session', () => {
  it('limit=1 over two visible entries returns the visible-entry cursor, and following it returns the other entry once', async () => {
    const newerId = await logEntry(w.org.id, w.owner.headers, contactA, 'Newer follow up', { occursAt: '2026-09-02T09:00:00.000Z' });
    const { session } = await bound(CRM);
    const page1 = await inj('GET', `${timeline(w.org.id, contactA)}?limit=1`, session.headers);
    expect(page1.statusCode, page1.body).toBe(200);
    const j1 = page1.json() as { timeline: Array<{ id: string; title: string }>; nextCursor: string | null };
    expect(j1.timeline.map((e) => e.id)).toEqual([newerId]);
    expect(j1.nextCursor).toBe(`2026-09-02T09:00:00.000Z|${newerId}`);
    const page2 = await inj('GET', `${timeline(w.org.id, contactA)}?limit=1&cursor=${encodeURIComponent(j1.nextCursor!)}`, session.headers);
    expect(page2.statusCode, page2.body).toBe(200);
    const j2 = page2.json() as { timeline: Array<{ id: string; title: string }>; nextCursor: string | null };
    expect(j2.timeline.map((e) => e.title)).toEqual(['Shared follow up']);
    expect(j2.timeline.map((e) => e.id)).not.toContain(newerId);
  });
});
'''
open(p, 'w').write(s)
print('ok')
