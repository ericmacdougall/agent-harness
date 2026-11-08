"""S3a red-team M1 (long-wait runs never enqueued) and M2 (one collapsed line per thread-hour). Runs on t2-dev
in the S3a worktree root. Every anchor must match exactly once."""
import pathlib

def sub(text, old, new, label):
    assert text.count(old) == 1, f'{label}: anchor count {text.count(old)}'
    return text.replace(old, new)

rr = pathlib.Path('apps/api/src/modules/automations/run-reports.ts')
s = rr.read_text()
s = sub(s, "import { automationsOn } from './engine';",
        "import { automationsOn } from './engine';\nimport { MAX_WAIT_DAYS } from './schemas';", 'import')
s = sub(s, """export function renderCollapsedLine(name: string, orgSlug: string): string {
  return `More runs of “${safeRoutineName(name)}” finished; they are not reported here. All runs: ${automationsPath(orgSlug)}`;
}
""", """export function renderCollapsedLine(name: string, orgSlug: string): string {
  return `More runs of “${safeRoutineName(name)}” finished; they are not reported here. All runs: ${automationsPath(orgSlug)}`;
}

/** The one line a full thread gets per UTC hour, whichever routine's run hit the cap. */
export function renderThreadCollapsedLine(orgSlug: string): string {
  return `More routine runs finished this hour; they are not reported here. All runs: ${automationsPath(orgSlug)}`;
}
""", 'renderer')
s = sub(s, """        thread: sql<number>`count(*) filter (where ${workflowRunReports.state} = 'posted')::int`,
""", """        thread: sql<number>`count(*) filter (where ${workflowRunReports.state} = 'posted')::int`,
        // Any collapsed line already posted in this thread this hour, by any of its routines.
        anyLine: sql<number>`count(*) filter (where ${workflowRunReports.state} = 'collapsed' and ${workflowRunReports.messageId} is not null)::int`,
""", 'capCounts')
s = sub(s, """    const isOverCap = (c: Awaited<ReturnType<typeof capCounts>>) => (c?.posted ?? 0) >= RUN_REPORT_HOURLY_CAP || (c?.thread ?? 0) >= RUN_REPORT_THREAD_HOURLY_CAP;
""", """    const isOverCap = (c: Awaited<ReturnType<typeof capCounts>>) => (c?.posted ?? 0) >= RUN_REPORT_HOURLY_CAP || (c?.thread ?? 0) >= RUN_REPORT_THREAD_HOURLY_CAP;
    const threadFull = (c: Awaited<ReturnType<typeof capCounts>>) => (c?.thread ?? 0) >= RUN_REPORT_THREAD_HOURLY_CAP;
    // A full thread gets one line per hour in all (M2); a routine at its own cap gets its own line once.
    const lineDone = (c: Awaited<ReturnType<typeof capCounts>>) => (threadFull(c) ? (c?.anyLine ?? 0) : (c?.line ?? 0)) > 0;
""", 'helpers')
s = sub(s, "    if (isOverCap(early) && (early?.line ?? 0) > 0) return collapseQuietly();\n",
        "    if (isOverCap(early) && lineDone(early)) return collapseQuietly();\n", 'early')
s = sub(s, "    if (isOverCap(counts) && (counts?.line ?? 0) > 0) return collapseQuietly();\n",
        "    if (isOverCap(counts) && lineDone(counts)) return collapseQuietly();\n", 'counts')
s = sub(s, "      const sent = await postAsCommander(tx, persona, row.orgId, thread.conversationId, creator, `run-summary-collapsed:${row.workflowId}:${hourKey(now)}`, renderCollapsedLine(w.name, org.slug));\n",
        """      const sent = threadFull(counts)
        ? await postAsCommander(tx, persona, row.orgId, thread.conversationId, creator, `run-summary-collapsed-thread:${thread.conversationId}:${hourKey(now)}`, renderThreadCollapsedLine(org.slug))
        : await postAsCommander(tx, persona, row.orgId, thread.conversationId, creator, `run-summary-collapsed:${row.workflowId}:${hourKey(now)}`, renderCollapsedLine(w.name, org.slug));
""", 'post')
# M1: a run may wait up to MAX_WAIT_DAYS before it finishes; bound created_at by that, not by 7 days.
s = sub(s, "  const created = new Date(now.getTime() - 7 * 24 * HOUR);\n",
        "  // A run can wait up to MAX_WAIT_DAYS before it finishes (red-team M1); finished_at does the real bounding.\n  const created = new Date(now.getTime() - (MAX_WAIT_DAYS + 2) * 24 * HOUR);\n", 'created')
rr.write_text(s)

t = pathlib.Path('apps/api/test/qac-run-reports-s3a.test.ts')
u = t.read_text()
u = sub(u, """    expect(msgs.filter((m) => m.body.startsWith('More runs of'))).toEqual([expect.objectContaining({ body: expect.stringContaining('“Third routine”') })]);
  });
});
""", """    expect(msgs.filter((m) => m.body.startsWith('More routine runs finished this hour'))).toHaveLength(1);
    expect(msgs.filter((m) => m.body.startsWith('More runs of'))).toHaveLength(0);
  });
  it('twenty routines in one thread: 12 reports and exactly one line for the hour, never one line per routine (M2)', async () => {
    const { w, workflowId, conversationId } = await turnDraft();
    const ids = [workflowId];
    for (let i = 2; i <= 20; i++) {
      const res = await inject('POST', `/orgs/${w.orgId}/automations`, w.owner.headers, routine(w.owner.user.id, `Routine ${i}`));
      expect(res.statusCode, res.body).toBe(201);
      ids.push(res.json().workflow.id);
      await ctx.db.insert(workflowReportThreads).values({ workflowId: res.json().workflow.id, orgId: w.orgId, conversationId });
    }
    let minute = 50;
    for (const id of ids) await finishedRun(w.orgId, id, { finishedAt: new Date(NOW.getTime() - minute-- * 60_000) });
    expect(await postRunReports(ctx.db, NOW)).toMatchObject({ posted: 12, collapsed: 8 });
    expect(await postRunReports(ctx.db, new Date(NOW.getTime() + 60_000))).toMatchObject({ posted: 0 });
    const msgs = await reportsIn(conversationId);
    expect(msgs).toHaveLength(13);
    expect(msgs.filter((m) => m.body.startsWith('More routine runs finished this hour'))).toHaveLength(1);
  });
});
""", 'thread-tests')
u = sub(u, """describe('NEG-7 fair share across tenants', () => {
""", """describe('M1 long waits: a run that waited longer than a week is still reported once', () => {
  it('a run created 30 days ago that finishes now is enqueued and posted', async () => {
    const { w, workflowId, conversationId } = await turnDraft();
    const run = await finishedRun(w.orgId, workflowId, { createdAt: new Date(NOW.getTime() - 30 * 24 * HOUR), finishedAt: new Date(NOW.getTime() - 5 * 60_000) });
    expect(await postRunReports(ctx.db, NOW)).toMatchObject({ enqueued: 1, posted: 1 });
    expect(await reportRow(run.id)).toMatchObject({ state: 'posted' });
    expect((await reportsIn(conversationId)).filter((m) => m.body.startsWith('Run report:'))).toHaveLength(1);
  });
});

describe('NEG-7 fair share across tenants', () => {
""", 'm1-test')
t.write_text(u)
print('ok')
