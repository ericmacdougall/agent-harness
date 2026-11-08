"""S3a delta review N2 (a routine's own line hid the thread line) and N3 (stale docs and docs needle).
Runs at the S3a worktree root."""
import pathlib

def sub(text, old, new, label):
    assert text.count(old) == 1, f'{label}: anchor count {text.count(old)}'
    return text.replace(old, new)

rr = pathlib.Path('apps/api/src/modules/automations/run-reports.ts')
s = rr.read_text()
s = sub(s, """        // Any collapsed line already posted in this thread this hour, by any of its routines.
        anyLine: sql<number>`count(*) filter (where ${workflowRunReports.state} = 'collapsed' and ${workflowRunReports.messageId} is not null)::int`,
""", """        // The thread-level line already posted in this thread this hour (a routine's own line does not count).
        anyLine: sql<number>`count(*) filter (where ${workflowRunReports.state} = 'collapsed' and ${workflowRunReports.messageId} is not null and ${workflowRunReports.reason} = 'thread_cap')::int`,
""", 'anyLine')
s = sub(s, """      await tx.update(workflowRunReports).set({ state: 'collapsed', messageId: sent, handledAt: now }).where(eq(workflowRunReports.runId, runId));
      await audit(tx, row.orgId, row.workflowId, { runId, outcome: 'collapsed', messageId: sent });
      return 'collapsed';
    }
""", """      await tx.update(workflowRunReports).set({ state: 'collapsed', messageId: sent, handledAt: now, reason: threadFull(counts) ? 'thread_cap' : 'workflow_cap' }).where(eq(workflowRunReports.runId, runId));
      await audit(tx, row.orgId, row.workflowId, { runId, outcome: 'collapsed', messageId: sent });
      return 'collapsed';
    }
""", 'mark')
rr.write_text(s)

d = pathlib.Path('docs/qa-commander/WORKFLOW-DRAFTS.md')
t = d.read_text()
t = sub(t, """  (`More runs of “<name>” finished; they are not reported here. ...`; under the thread cap each workflow posts
  its own line), and later runs over the cap that hour are not reported at all.""", """  (`More runs of “<name>” finished; they are not reported here. ...`). A full thread gets one line for the hour in all
  (`More routine runs finished this hour; they are not reported here. ...`), so a thread sees at most 12 reports and two
  lines per hour; later runs over the cap that hour are not reported at all.""", 'cap-doc')
t = sub(t, """Reports add no power to any credential: the sweep reads runs and posts; stopping, retrying and duplicating a routine
are unchanged. Known limit: the check runs when a report is posted. If the owner of the AI thread later shares it with
full history, the new reader sees earlier reports, just as they see the drafting conversation the routine came from.
""", """Reports add no power to any credential: the sweep reads runs and posts; stopping, retrying and duplicating a routine
are unchanged. The audience is checked when a report is posted, and sharing a report thread with full history needs
`crm:read` for every invitee (`history_needs_crm_read`; sharing from now on stays open). An invite link can never be
minted for, or admit anyone into, an AI thread.
""", 'share-doc')
d.write_text(t)

tt = pathlib.Path('apps/api/test/qac-run-reports-s3a.test.ts')
u = tt.read_text()
u = sub(u, "'at most 40 of one org', 'its own line'])", "'at most 40 of one org', 'one line for the hour in all', 'history_needs_crm_read'])", 'needle')
u = sub(u, """describe('M3 sharing a report thread with full history needs crm:read', () => {
""", """describe('N2 a routine line never hides the thread line', () => {
  it('A at its own cap posts its line; when the thread then fills, the thread line still posts once', async () => {
    const { w, workflowId, conversationId } = await turnDraft();
    const ids = [workflowId];
    for (const name of ['B routine', 'C routine']) {
      const res = await inject('POST', `/orgs/${w.orgId}/automations`, w.owner.headers, routine(w.owner.user.id, name));
      expect(res.statusCode, res.body).toBe(201);
      ids.push(res.json().workflow.id);
      await ctx.db.insert(workflowReportThreads).values({ workflowId: res.json().workflow.id, orgId: w.orgId, conversationId });
    }
    let minute = 55;
    const at = () => ({ finishedAt: new Date(NOW.getTime() - minute-- * 60_000) });
    for (let i = 0; i < 7; i++) await finishedRun(w.orgId, ids[0]!, at());
    for (let i = 0; i < 7; i++) await finishedRun(w.orgId, ids[1]!, at());
    const c = await finishedRun(w.orgId, ids[2]!, at());
    await postRunReports(ctx.db, NOW);
    const msgs = await reportsIn(conversationId);
    expect(msgs.filter((m) => m.body.startsWith('Run report:'))).toHaveLength(12);
    expect(msgs.filter((m) => m.body.startsWith('More runs of'))).toHaveLength(1);
    expect(msgs.filter((m) => m.body.startsWith('More routine runs finished this hour'))).toHaveLength(1);
    expect(await reportRow(c.id)).toMatchObject({ state: 'collapsed' });
  });
});

describe('M3 sharing a report thread with full history needs crm:read', () => {
""", 'n2-test')
tt.write_text(u)
print('ok')
