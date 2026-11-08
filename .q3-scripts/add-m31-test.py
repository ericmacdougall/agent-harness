"""Insert the posting-hour cap test (kills M31) after the backlog test in qac-run-reports-s3a.test.ts. Runs on t2-dev."""
import pathlib, sys

p = pathlib.Path(sys.argv[1])
src = p.read_text()
anchor = "    for (const r of backlog.slice(0, 6)) expect(await reportRow(r.id), r.id).toMatchObject({ state: 'posted' });\n  });\n"
assert src.count(anchor) == 1, 'anchor not unique'
test = """  it('caps count the hour a report is posted, not the hour its run finished (main D1)', async () => {
    const { w, workflowId, conversationId } = await turnDraft();
    // Six runs finish at 09:40-09:45 and are posted at 09:50, filling that posting hour's cap of 6.
    const first = [];
    for (let i = 0; i < 6; i++) first.push(await finishedRun(w.orgId, workflowId, { finishedAt: new Date(NOW.getTime() - (50 - i) * 60_000) }));
    expect(await postRunReports(ctx.db, new Date(NOW.getTime() - 40 * 60_000))).toMatchObject({ posted: 6, collapsed: 0 });
    // A seventh run finishes at 09:55 but is first handled at 10:02, in a new posting hour with room: it is reported.
    // Counting by finish hour would see 09:00's six posts and collapse it instead.
    const late = await finishedRun(w.orgId, workflowId, { finishedAt: new Date(NOW.getTime() - 35 * 60_000) });
    expect(await postRunReports(ctx.db, new Date(NOW.getTime() - 28 * 60_000))).toMatchObject({ posted: 1, collapsed: 0 });
    expect(await reportRow(late.id)).toMatchObject({ state: 'posted' });
    const msgs = await reportsIn(conversationId);
    expect(msgs.filter((m) => m.body.startsWith('Run report:'))).toHaveLength(7);
    expect(msgs.filter((m) => m.body.startsWith('More runs of'))).toHaveLength(0);
  });
"""
p.write_text(src.replace(anchor, anchor + test))
print('inserted')
