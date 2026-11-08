"""S3a red-team M3 (second half): a thread that receives routine run reports is never shared with full history
to someone without crm:read. Runs at the S3a worktree root."""
import pathlib

def sub(text, old, new, label):
    assert text.count(old) == 1, f'{label}: anchor count {text.count(old)}'
    return text.replace(old, new)

p = pathlib.Path('apps/api/src/modules/messaging/ai-thread-sharing.ts')
s = p.read_text()
s = sub(s, "  orgMembers,\n  type Db,\n", "  orgMembers,\n  workflowReportThreads,\n  type Db,\n", 'db-import')
s = sub(s, "import { requireOrgRole, requireProjectRole } from '../../lib/access';",
        "import { effectiveOrgPermissionSet, requireOrgRole, requireProjectRole } from '../../lib/access';", 'access-import')
s = sub(s, """    const floor = input.history === 'full' ? 0 : conversation.lastSeq + 1;
""", """    // Earlier messages of a thread that receives routine run reports include those reports (goodqa#15200); only
    // someone who may read the CRM may see them. Sharing "from now" stays open: later reports recheck the audience.
    if (input.history === 'full') {
      const [bound] = await tx.select({ workflowId: workflowReportThreads.workflowId }).from(workflowReportThreads)
        .where(and(eq(workflowReportThreads.orgId, conversation.orgId), eq(workflowReportThreads.conversationId, id))).limit(1);
      if (bound) for (const invitee of invitees) {
        if (!(await effectiveOrgPermissionSet(tx, invitee, conversation.orgId)).has('crm:read'))
          throw new AppError(400, 'history_needs_crm_read', 'This thread has routine run reports. Share it from now on, or give this person CRM read access first.');
      }
    }
    const floor = input.history === 'full' ? 0 : conversation.lastSeq + 1;
""", 'check')
p.write_text(s)

t = pathlib.Path('apps/api/test/qac-run-reports-s3a.test.ts')
u = t.read_text()
u = sub(u, """describe('NEG-7 fair share across tenants', () => {
""", """describe('M3 sharing a report thread with full history needs crm:read', () => {
  it('refuses full history to a member without crm:read, allows from now, and allows full history with crm:read', async () => {
    const t = await turnDraft();
    const reader = await signupUser(ctx.app, { name: 'S3a share no-crm', email: `s3a-share-${randomUUID()}@e2e.goodqa.app` });
    const where = and(eq(customRoles.orgId, t.w.orgId), eq(customRoles.scope, 'org'), eq(customRoles.wireKey, 'member'), eq(customRoles.isBuiltin, true));
    const [preset] = await ctx.db.select({ permissions: customRoles.permissions }).from(customRoles).where(where);
    await ctx.db.update(customRoles).set({ permissions: (preset!.permissions as string[]).filter((p) => !p.startsWith('crm:')) }).where(where);
    await ctx.db.insert(orgMembers).values({ orgId: t.w.orgId, userId: reader.user.id, role: 'member' });
    const admin = await signupUser(ctx.app, { name: 'S3a share admin', email: `s3a-share-adm-${randomUUID()}@e2e.goodqa.app` });
    await ctx.db.insert(orgMembers).values({ orgId: t.w.orgId, userId: admin.user.id, role: 'admin' });
    const share = (userIds: string[], history: 'full' | 'from_now') => ctx.app.inject({ method: 'POST', url: `/v1/ai-threads/${t.conversationId}/members`, headers: t.w.owner.headers, payload: { userIds, history } });
    const member = async (userId: string) => (await ctx.db.select().from(chatConversationMembers).where(and(eq(chatConversationMembers.conversationId, t.conversationId), eq(chatConversationMembers.userId, userId))))[0];
    const refused = await share([reader.user.id], 'full');
    expect(refused.statusCode, refused.body).toBe(400);
    expect(refused.body).toContain('history_needs_crm_read');
    expect(await member(reader.user.id)).toBeUndefined();
    const fromNow = await share([reader.user.id], 'from_now');
    expect(fromNow.statusCode, fromNow.body).toBe(200);
    expect((await member(reader.user.id))?.historyFromSeq).toBeGreaterThan(0);
    const full = await share([admin.user.id], 'full');
    expect(full.statusCode, full.body).toBe(200);
    expect((await member(admin.user.id))?.historyFromSeq).toBe(0);
  });
});

describe('NEG-7 fair share across tenants', () => {
""", 'test')
t.write_text(u)
print('ok')
