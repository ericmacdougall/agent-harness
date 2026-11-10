import subprocess

subprocess.run(['scp', '-q', 't2-dev:wt-15561/apps/api/src/modules/crm/routes.ts', 'routes.ts.crm'], check=True)
p = 'routes.ts.crm'
s = open(p).read()


def sub(old, new):
    global s
    assert s.count(old) == 1, (s.count(old), old[:80])
    s = s.replace(old, new)


sub("""/**
 * A contact's timeline, made visible AND made complete:""", """/**
 * goodqa#15561 S1e-a (red-team N1): a desktop session started from a user token reads the contact timeline (W4). Withholding
 * (personal entries, Gmail mailbox reads, busy_only titles) happens AFTER paging, so a free-text `q` or `pinned` filter and the
 * server's keyset `nextCursor` would answer "does a withheld entry match this word" and name its id and time. For that reader:
 * `q` and `pinned` are refused, and `nextCursor` is derived from the last entry the reader can see (null when the page shows
 * none, which ends paging; a stated limit when a whole page is withheld).
 */
function isTokenSessionReader(req: FastifyRequest): boolean {
  return req.userTokenDoor?.via === 'desktop_session';
}
function refuseHiddenMatchFilters(req: FastifyRequest, query: { q?: unknown; pinned?: unknown }): void {
  if (isTokenSessionReader(req) && (query.q || query.pinned)) {
    throw new AppError(400, 'user_token_filter_unsupported', 'A desktop session started from a token cannot search or filter the contact timeline.');
  }
}
function readerCursor(req: FastifyRequest, raw: string | null, visible: Array<{ id: string; occursAt?: unknown }>): string | null {
  if (!raw || !isTokenSessionReader(req)) return raw;
  const last = visible[visible.length - 1];
  if (!last || last.occursAt === undefined) return null;
  const at = last.occursAt instanceof Date ? last.occursAt : new Date(String(last.occursAt));
  return Number.isNaN(at.getTime()) ? null : `${at.toISOString()}|${last.id}`;
}

/**
 * A contact's timeline, made visible AND made complete:""")

sub("""    const reportedIssues = await reportedIssuesForViewer(app, auth, req.params.orgId, candidateIssues);
    // The server reports what the caller may see (CLAUDE.md); the client
    // renders from this one answer rather than re-deriving it.
    return {
      contact,
      company,
      timeline: await forTimelineReader(req, auth, timelineWithSubjects(rawTimeline, auth.userId, visibleIds)),
      timelineNextCursor: rawTimeline.nextCursor,""", """    const reportedIssues = await reportedIssuesForViewer(app, auth, req.params.orgId, candidateIssues);
    const readerTimeline = await forTimelineReader(req, auth, timelineWithSubjects(rawTimeline, auth.userId, visibleIds));
    // The server reports what the caller may see (CLAUDE.md); the client
    // renders from this one answer rather than re-deriving it.
    return {
      contact,
      company,
      timeline: readerTimeline,
      timelineNextCursor: readerCursor(req, rawTimeline.nextCursor, readerTimeline as Array<{ id: string; occursAt?: unknown }>),""")

sub("""        const { role } = await requireOrgPermission(db, auth.userId, req.params.orgId, 'crm:read');
        const [rawTimeline, visibleIds] = await Promise.all([
          crm.contactTimeline(db, req.params.orgId, req.params.contactId, req.query),
          visibleProjectIds(db, auth.userId, req.params.orgId, role),
        ]);
        return {
          timeline: await forTimelineReader(req, auth, timelineWithSubjects(rawTimeline, auth.userId, visibleIds)),""",
    """        const { role } = await requireOrgPermission(db, auth.userId, req.params.orgId, 'crm:read');
        refuseHiddenMatchFilters(req, req.query);
        const [rawTimeline, visibleIds] = await Promise.all([
          crm.contactTimeline(db, req.params.orgId, req.params.contactId, req.query),
          visibleProjectIds(db, auth.userId, req.params.orgId, role),
        ]);
        const readerTimeline = await forTimelineReader(req, auth, timelineWithSubjects(rawTimeline, auth.userId, visibleIds));
        return {
          timeline: readerTimeline,""")
sub("""          nextCursor: rawTimeline.nextCursor,
        };
      });
    },
  );

  /**
   * THE ORG-LEVEL TIMELINE READ""", """          nextCursor: readerCursor(req, rawTimeline.nextCursor, readerTimeline as Array<{ id: string; occursAt?: unknown }>),
        };
      });
    },
  );

  /**
   * THE ORG-LEVEL TIMELINE READ""")
open(p, 'w').write(s)
print('ok')
