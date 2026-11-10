import { withSessionAction } from '../user-tokens/session-actions';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { and, eq, inArray } from 'drizzle-orm';
import {
  CRM_AI_SUGGESTION_OUTPUT_MAX_CHARS,
  crmCompanies,
  crmContacts,
  issues,
  organizations,
  timelineEntries,
  users,
  userProfiles,
} from '@bugtracker/db';
import {
  canSeeTimelineEntryDetails,
  crmAiBriefingBodySchema,
  crmAiFollowupBodySchema,
  crmAiResolveBodySchema,
  crmColdContactsQuerySchema,
  createCrmCompanyBodySchema,
  createCrmContactBodySchema,
  createIssueFromContactBodySchema,
  createTimelineEntryBodySchema,
  crmGraphQuerySchema,
  idSchema,
  label,
  linkContactIssueBodySchema,
  listCrmContactsQuerySchema,
  listCrmTimelineQuerySchema,
  setTimelineAttendanceBodySchema,
  updateCrmCompanyBodySchema,
  updateCrmContactBodySchema,
  updateTimelineEntryBodySchema,
  type ContactMeetingDto,
} from '@bugtracker/shared';
import { z } from 'zod';
import {
  assertWithinApiKeyScope,
  effectiveOrgPermissionSet,
  requireIssueAccess,
  requireOrgPermission,
  requireProjectPermission,
  visibleProjectIds,
  type DbOrTx,
} from '../../lib/access';
import { assertIssueCategoryReadableForRequest } from '../../lib/category-access';
import { requireFeature } from '../../lib/entitlements';
import { AppError, Errors } from '../../lib/errors';
import { gmailContentWithheldFrom, gmailMailboxReadEntryIds, withoutGmailMailboxReadEntries } from '../../lib/gmail-limited-use';
import { hideExternalKeyFromV1 } from './v1-external-key';
import {
  createNotifications,
  createNotifier,
  type CommittedNotificationInput,
  type NotificationInput,
} from '../../lib/notify';
/**
 * ONE COPY, TWO CALLERS. `timelineForViewer` was a module-private helper in
 * THIS file until the meetings/calendar lane needed the identical rule. A
 * second copy of a visibility projection is how two surfaces come to disagree
 * about what `busy_only` means, so it moved to `lib/` unchanged and this module
 * now imports what it used to declare.
 *
 * Its sibling `assertTimelineIssueLinksVisible` was lifted in the same pass and
 * DELIBERATELY still lives here as well. See the doc comment on the local copy
 * below: deleting it is a measured gate regression, not a cleanup.
 */
import { timelineForViewer, viewerSeesTimelineDetails } from '../../lib/timeline-visibility';
import { crmIssuesForViewer } from '../../lib/crm-issue-visibility';
import { meteredVertexSummary } from '../../lib/ai-usage';
import { getVertexAiClient, MAX_REASONING_THINKING_LEVEL } from '../../lib/vertex-ai';
import { requireAuth } from '../../plugins/auth';
import { issueVisibleToScopedUser } from '../issues/service';
import * as crm from './service';
import { afterBookingChange, loadBookingRow } from '../scheduling/routes';
import { lockBookingForEntry, prepareBookingMoveForEntry, syncBookingFromTimelineEntry } from '../scheduling/meetings-bridge';
import * as crmAi from './ai';
import * as depth from './depth';

/**
 * The one place the provider string is written. Stored on every suggestion row
 * so an old row keeps saying what actually produced it if this ever changes,
 * rather than being retroactively re-attributed by a later constant.
 */
const CRM_AI_PROVIDER = 'vertex_ai';

/** The browser knows the reader's current zone even when their profile still defaults to UTC. */
async function viewerTimeZone(db: DbOrTx, userId: string, requested?: string): Promise<string> {
  const profile = requested === undefined
    ? (await db.select({ timezone: userProfiles.timezone }).from(userProfiles)
      .where(eq(userProfiles.userId, userId)).limit(1))[0]
    : undefined;
  const timeZone = requested ?? profile?.timezone ?? 'UTC';
  try {
    new Intl.DateTimeFormat('en-US', { timeZone });
    return timeZone;
  } catch {
    return 'UTC';
  }
}

const orgParams = z.object({ orgId: idSchema });
const contactParams = orgParams.extend({ contactId: idSchema });
const companyParams = orgParams.extend({ companyId: idSchema });
const entryParams = orgParams.extend({ entryId: idSchema });
const contactIssueLinkParams = contactParams.extend({ issueId: idSchema });
const issueParams = z.object({ issueId: idSchema });
const suggestionParams = orgParams.extend({ suggestionId: idSchema });

/**
 * The contact timeline's paging controls.
 *
 * `.pick`ed off `listCrmTimelineQuerySchema` rather than re-declared, so the
 * cursor format and the 1-100 limit cannot drift apart between the org read and
 * the per-contact one — they are the same keyset over the same two columns. The
 * filters are deliberately not picked up: `contactId` is already the path, and
 * a second way to spell it would be a second thing to keep in agreement.
 */
const contactTimelineQuery = listCrmTimelineQuerySchema.pick({
  fieldChanges: true,
  cursor: true,
  limit: true,
  /*
   * `q` and `pinned` join the picked set for the same reason the two above are
   * picked rather than re-declared: they are the SAME filters over the same
   * column, and a second spelling is a second thing to keep in agreement. They
   * are also the two the record page needs most — "find the note where they
   * mentioned SOC 2" and "show me the standing context" are questions about ONE
   * contact far more often than about the whole org.
   */
  q: true,
  pinned: true,
});

type ReportedIssue = Awaited<ReturnType<typeof crm.contactReportedIssues>>[number];
type ContactTimelineEntry = Awaited<ReturnType<typeof crm.contactTimeline>>['entries'][number];
/** What the PATCH and archive routes hand back — one `timeline_entries` row. */
type WritableTimelineEntry = Awaited<ReturnType<typeof crm.updateTimelineEntry>>;

/**
 * A CRM contact is org-scoped, but the issues shown on it are not.
 *
 * ONE COPY, TWO CALLERS — the same move, and the same reason, as
 * `timelineForViewer` above. This was a module-private helper here until the
 * DEAL record (slice 7, TASK-507) needed the identical rule for the issues on
 * an account, so it moved to `lib/crm-issue-visibility.ts` unchanged and this
 * module now imports what it used to declare.
 */
const reportedIssuesForViewer = crmIssuesForViewer<ReportedIssue>;

/**
 * An agent may not edit or archive an entry read from a Gmail mailbox: both routes return the entry, and for an
 * agent it does not exist (`lib/gmail-limited-use.ts`). Same 404 as an entry the reader cannot see, checked before
 * anything changes.
 */
async function refuseGmailEntryForAgent(
  req: FastifyRequest,
  auth: { apiKeyId?: string | null; userTokenId?: string | null },
  orgId: string,
  entryId: string,
): Promise<void> {
  if (!gmailContentWithheldFrom(req, auth)) return;
  if ((await gmailMailboxReadEntryIds(req.server.db, orgId, [entryId])).size > 0) {
    throw Errors.notFound('Timeline entry not found');
  }
}

/**
 * A timeline page as this reader may receive it. An agent (API key, user token, MCP tool call) never receives an
 * entry read from a Gmail mailbox, because an agent is an AI model (`lib/gmail-limited-use.ts`); a person signed in
 * to the app sees it unchanged. Applied after paging, like `timelineForViewer`, so `nextCursor` stays the server's
 * keyset value and a short page does not stop paging early.
 */
async function forTimelineReader<T extends { id: string }>(
  req: FastifyRequest,
  auth: { apiKeyId?: string | null; userTokenId?: string | null; orgId?: string },
  entries: T[],
): Promise<T[]> {
  if (!gmailContentWithheldFrom(req, auth)) return entries;
  const orgId = (req.params as { orgId: string }).orgId;
  return withoutGmailMailboxReadEntries(req.server.db, orgId, entries);
}

/**
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
  return null;
  const at = last.occursAt instanceof Date ? last.occursAt : new Date(String(last.occursAt));
  return Number.isNaN(at.getTime()) ? null : `${at.toISOString()}|${last.id}`;
}

/**
 * A contact's timeline, made visible AND made complete: the same
 * `timelineForViewer` contract as before, plus the `subjects` the org-level
 * read has always carried and this one never did.
 *
 * A meeting linked to a customer and to three teammates showed on the org
 * timeline naming all four, and on that customer's own record naming nobody —
 * the record page's whole job is to be the fuller view. Booking a meeting makes
 * that gap load-bearing rather than merely odd, because attendees are the point
 * of a meeting row.
 *
 * **`canSeeTimelineEntryDetails` gates the subjects, not just the fields.**
 * This is the same rule the org timeline states in its own words and it is the
 * one a calendar-shaped surface gets wrong: an entry the reader may not open
 * arrives from `timelineForViewer` already collapsed to the single word "Busy",
 * and naming the customer a colleague is meeting beside it would restore,
 * through the side door, precisely the detail the block was hiding. Blocked
 * entries get `[]`, never the resolved names.
 *
 * Top-level and non-generic on purpose — see `withVisibleProjectContext` below
 * for the full argument about what `access-chokepoint-contract.test.ts` can and
 * cannot see.
 */
function timelineWithSubjects(
  page: Awaited<ReturnType<typeof crm.contactTimeline>>,
  viewerUserId: string,
  visibleIds: string[] | null,
): (ContactTimelineEntry & {
  subjects: ReturnType<typeof page.subjects.get>;
  author: ReturnType<typeof page.authors.get> | null;
})[] {
  return timelineForViewer(page.entries, viewerUserId, visibleIds).map((entry) => {
    const detailed = canSeeTimelineEntryDetails(entry, viewerUserId);
    return {
      ...entry,
      subjects: detailed ? (page.subjects.get(entry.id) ?? []) : [],
      /*
       * The author is gated by the SAME predicate as the subjects, and for the
       * same reason. `timelineForViewer` has already nulled `createdBy` on a
       * blocked row; resolving that id to a NAME and attaching it beside the
       * word "Busy" would put back exactly what the block removed, narrowing an
       * opaque one-hour hold down to one named colleague's calendar.
       */
      author: detailed && entry.createdBy ? (page.authors.get(entry.createdBy) ?? null) : null,
    };
  });
}

/**
 * A CONTACT'S APPOINTMENTS, projected for ONE reader.
 *
 * Top-level and non-generic on purpose, exactly like `timelineWithSubjects` and
 * `withVisibleProjectContext` beside it: `access-chokepoint-contract.test.ts`
 * resolves "this route is guarded" by a fixed point over MODULE-level functions
 * matched with `/(?:async\s+)?function\s+(\w+)\s*\(/`, so a helper hidden inside
 * the plugin closure — or one written `function name<T extends …>(` — is
 * invisible to it and the route it guards reads as unguarded. A guard the guard
 * cannot see is not a guard.
 *
 * ## Attendance widens visibility, and it has to
 *
 * `canSeeTimelineEntryDetails` knows only the two identities the ROW carries,
 * owner and author. A guest at a `busy_only` meeting is neither, so without the
 * attendance set an invited colleague opens a customer record and sees the
 * meeting THEY ARE IN as the single word "Busy". The participants are already
 * loaded for rendering, so the set is free here — which is the same reason
 * `lib/timeline-visibility.ts` takes it as a parameter rather than looking it up.
 *
 * ## Participants are gated on DETAIL, never on the block
 *
 * An entry the reader may not open arrives from `timelineForViewer` already
 * collapsed to "Busy". Naming its guest list beside it would restore, through
 * the side door, precisely what the block hides — "a meeting with the
 * acquisition lawyers" is legible from the guest list alone. Blocked rows get
 * `[]` and an `unreviewed` outcome, never the names and never a no-show count,
 * which would leak the same thing as arithmetic.
 */
function contactMeetingsForViewer(
  page: Awaited<ReturnType<typeof depth.contactMeetings>>,
  viewerUserId: string,
  visibleIds: string[] | null,
  now: Date,
) {
  const attendedEntryIds = new Set(
    [...page.participants.entries()]
      .filter(([, list]) => list.some((p) => p.subjectKind === 'user' && p.subjectId === viewerUserId))
      .map(([entryId]) => entryId),
  );

  function project(rows: typeof page.upcoming): ContactMeetingDto[] {
    return timelineForViewer(rows, viewerUserId, visibleIds, attendedEntryIds).map((entry) => {
      const attends = attendedEntryIds.has(entry.id);
      const detailed = attends || canSeeTimelineEntryDetails(entry, viewerUserId);
      const participants = detailed ? (page.participants.get(entry.id) ?? []) : [];
      return {
        id: entry.id,
        title: entry.title,
        status: entry.status,
        occursAt: entry.occursAt.toISOString(),
        endsAt: entry.endsAt ? entry.endsAt.toISOString() : null,
        allDay: entry.allDay,
        timezone: entry.timezone,
        location: entry.location,
        conferencingUrl: entry.conferencingUrl,
        outcome: detailed
          ? depth.meetingOutcome(entry, participants, now)
          : // A blocked row still occupies time, so "upcoming" versus "already
            // happened" is exactly what a free/busy block is allowed to say —
            // and nothing more.
            depth.meetingOutcome(entry, [], now),
        participants,
        noShowCount: participants.filter((p) => p.attendance === 'no_show').length,
        followUpToId: detailed ? entry.followUpToId : null,
        followUpCount: detailed ? (page.followUpCounts.get(entry.id) ?? 0) : 0,
      };
    });
  }

  const upcoming = project(page.upcoming);
  const past = project(page.past);
  return {
    upcoming,
    past,
    noShowMeetings: past.filter((m) => m.outcome === 'no_show').length,
    unreviewedMeetings: past.filter((m) => m.outcome === 'unreviewed').length,
  };
}

/**
 * DROP THE ISSUE NODES THIS READER MAY NOT OPEN, and every edge that touched
 * them.
 *
 * `crm:read` is an ORG permission; issue visibility is refined by project
 * membership, private categories, `task_only` project roles and user-scoped API
 * keys. A graph node carrying `#482 Checkout crashes on Safari` is issue content,
 * so an org-level permission emitting one would route around all four
 * refinements — the same argument `timelineSubjectRefSchema` records for keeping
 * issue subjects off the timeline.
 *
 * The filter is `visibleProjectIds`, the coarser of the two available answers,
 * and that is deliberate for a BULK read: the finer per-issue chokepoint
 * (`requireIssueAccess` plus the category refinement) is one query per issue, and
 * a graph can name a hundred. Coarser here means strictly FEWER nodes than the
 * contact record's own "Bugs affecting them" panel shows, never more — a private
 * category inside a visible project is still filtered, because such an issue
 * cannot be reached from this route without the panel that authorises it.
 *
 * `visibleIds === null` means unrestricted (an admin under `open_to_admins`),
 * which is `visibleProjectIds`' own contract and is NOT the same as "no visible
 * projects".
 */
function graphForViewer(
  graph: Awaited<ReturnType<typeof depth.crmGraph>>,
  visibleIds: string[] | null,
) {
  const visible = visibleIds === null ? null : new Set(visibleIds);
  const dropped = new Set<string>();
  const nodes = graph.nodes.filter((node) => {
    if (node.kind !== 'issue') return true;
    const projectId = graph.issueProjectByNodeKey.get(node.key);
    if (visible !== null && (!projectId || !visible.has(projectId))) {
      dropped.add(node.key);
      return false;
    }
    return true;
  });
  return {
    nodes,
    edges: graph.edges.filter((edge) => !dropped.has(edge.from) && !dropped.has(edge.to)),
    /*
     * A graph that lost nodes to permissions is truncated in the sense that
     * matters to the reader: it is not the whole answer. Saying so is the same
     * honesty the node cap already owes — "nobody else here knows them" is a
     * conclusion people act on.
     */
    truncated: graph.truncated || dropped.size > 0,
  };
}

/**
 * The WRITE path's half of the project-context rule the read path has always
 * applied.
 *
 * `timelineForViewer` blanks an entry's `projectId` when the caller cannot open
 * that project — CRM activity is deliberately an org record, but its project
 * context is not. The PATCH and archive routes returned the raw row, so a
 * member holding `crm:edit` learned the project id of an entry attached to a
 * project they cannot open, purely by editing something else about it.
 *
 * Small, and exactly the asymmetry `access-chokepoint-contract.test.ts` exists
 * to catch: it failed both routes for resolving project-scoped data without
 * going through `visibleProjectIds`. Adding them to that file's ALLOW_LIST
 * would have been the wrong answer — the routes genuinely return a project id,
 * so they genuinely owe the same filter the GET pays.
 *
 * Top-level rather than nested inside `crmRoutes`, and NOT generic, both on
 * purpose. That test resolves "safe wrapper" by a fixed point over MODULE-level
 * functions matched with `/(?:async\s+)?function\s+(\w+)\s*\(/`, so a helper
 * hidden inside the plugin closure — or one written
 * `function name<T extends …>(`, where the type parameters sit between the name
 * and the paren — is invisible to it, and both routes keep reading as routes
 * that never called a chokepoint. A guard the guard cannot see is not a guard.
 */
async function withVisibleProjectContext(
  db: Parameters<typeof visibleProjectIds>[0],
  args: { userId: string; orgId: string; role: Parameters<typeof visibleProjectIds>[3] },
  entry: WritableTimelineEntry,
): Promise<WritableTimelineEntry> {
  if (entry.projectId === null) return entry;
  const visibleIds = await visibleProjectIds(db, args.userId, args.orgId, args.role);
  if (visibleIds === null || visibleIds.includes(entry.projectId)) return entry;
  return { ...entry, projectId: null };
}

/**
 * WHY THIS STILL LIVES HERE now that `lib/timeline-guards.ts` exists.
 *
 * The body below is identical to that module's export and the two must be kept
 * identical; the lift was meant to delete this copy. It cannot be deleted yet,
 * and the reason is a property of the GATE rather than of the code.
 *
 * `access-chokepoint-contract.test.ts` decides "this route is guarded" by a
 * fixed point over MODULE-level functions declared in the module's own source,
 * seeded with `requireProjectRole` / `visibleProjectIds` / `requireIssueAccess`
 * and friends. It cannot follow an import into `lib/`. Delete this function and
 * `POST /orgs/:orgId/crm/timeline` becomes, verbatim, "1 project-scoped route
 * resolves access WITHOUT going through the chokepoint" — measured, not
 * predicted. The route is a candidate because it calls
 * `crm.createTimelineEntry`, which writes `timeline_entries.project_id`, and
 * the only chokepoint call it has ever made is the `requireIssueAccess` inside
 * THIS function.
 *
 * Allow-listing the route would be the wrong answer: the guard is real and the
 * route genuinely owes it. The right answer is to teach that classifier to
 * follow `apps/api/src/lib/*.ts`, which makes it STRICTER everywhere and
 * touches every module at once — its own reviewed change, not a passenger on a
 * CRM read fix. Until then, one duplicated guard carrying this note beats a
 * gate that has quietly stopped watching.
 *
 * ---
 *
 * The PER-ISSUE half of a timeline link's authorization.
 *
 * `crm.createTimelineEntry` establishes that every linked id belongs to the
 * org; that is a tenancy question and it has no request context. Whether THIS
 * caller may see THIS issue is a different question with a different answer
 * (private categories, `task_only` project roles, a user-scoped API key), and
 * the product already has exactly one chokepoint for it.
 *
 * Without this, `crm:create` alone would let a member attach an activity to --
 * and, through the entry they get back, confirm the existence of -- an issue in
 * a project they cannot open. The sibling `POST /contacts/:id/issue-links`
 * route below runs this identical sequence for the identical reason; the
 * timeline path is the half that never had it.
 */
async function assertTimelineIssueLinksVisible(
  tx: DbOrTx,
  auth: { userId: string; apiKeyScopedToUserId?: string },
  orgId: string,
  links: readonly { subjectKind: string; subjectId: string }[],
): Promise<void> {
  const issueIds = [
    ...new Set(links.filter((l) => l.subjectKind === 'issue').map((l) => l.subjectId)),
  ];
  for (const issueId of issueIds) {
    const [issue] = await tx
      .select({
        id: issues.id,
        projectId: issues.projectId,
        assigneeId: issues.assigneeId,
        reporterId: issues.reporterId,
        categoryId: issues.categoryId,
      })
      .from(issues)
      .where(eq(issues.id, issueId))
      .limit(1);
    if (!issue) throw Errors.notFound('Issue not found');
    const access = await requireIssueAccess(tx, auth.userId, issue, { lock: 'share' });
    if (access.project.orgId !== orgId) throw Errors.notFound('Issue not found');
    if (
      auth.apiKeyScopedToUserId &&
      !(await issueVisibleToScopedUser(tx, issue, auth.apiKeyScopedToUserId))
    ) {
      throw Errors.notFound('Issue not found');
    }
    if (access.projectRole !== 'task_only') {
      await assertIssueCategoryReadableForRequest(tx, auth, orgId, issue);
    }
  }
}

/**
 * CRM core routes (design-reconciliation slice 1 -- "a contact record that
 * shows their bugs"). See docs/design/CRM-DESIGN.md.
 *
 * Every route: `requireOrgPermission` first (membership resolves before
 * anything else, so a non-member gets 404 rather than 403 --
 * CRM-DESIGN.md section 6.3), then `requireFeature(..., 'crm.enabled')` on
 * every WRITE route (the free-plan gate -- CRM-DESIGN.md section 8's five
 * binding steps). Reads are not entitlement-gated: an org that downgrades
 * must not lose visibility into data it already holds (Eric's dunning
 * decision -- gate access, do not destroy).
 */
/**
 * Booking-linked meetings edited from the contact timeline use the scheduling lifecycle.
 * The booking row is locked before the timeline row, matching the Meetings screen.
 */
async function commitTimelineBooking(
  app: FastifyInstance,
  orgId: string,
  entryId: string,
  userId: string,
  mutate: (tx: DbOrTx) => Promise<unknown>,
  changes?: { occursAt?: string; endsAt?: string | null; status?: string },
): Promise<Awaited<ReturnType<typeof crm.updateTimelineEntry>>> {
  let calendarCheck: Awaited<ReturnType<typeof prepareBookingMoveForEntry>> = null;
  if (changes) {
    const [current] = await app.db.select(crm.timelineEntryColumns).from(timelineEntries)
      .where(and(eq(timelineEntries.id, entryId), eq(timelineEntries.orgId, orgId))).limit(1);
    if (!current || current.archivedAt || !viewerSeesTimelineDetails(current, userId)) throw Errors.notFound('Timeline entry not found');
    if ((changes.status ?? current.status) !== 'cancelled') {
      const occursAt = changes.occursAt ? new Date(changes.occursAt) : current.occursAt;
      const endsAt = changes.endsAt !== undefined ? (changes.endsAt ? new Date(changes.endsAt) : null) : current.endsAt;
      if (endsAt !== null && endsAt.getTime() < occursAt.getTime()) {
        throw new AppError(400, 'crm_timeline_invalid_interval', 'An entry cannot end before it starts.');
      }
      calendarCheck = await prepareBookingMoveForEntry(app, orgId, entryId, { occursAt, endsAt });
    }
  }

  const { entry, changed } = await app.db.transaction(async (tx) => {
    const booking = await lockBookingForEntry(tx, orgId, entryId);
    await mutate(tx);
    const read = async () => {
      const [row] = await tx.select(crm.timelineEntryColumns).from(timelineEntries)
        .where(and(eq(timelineEntries.id, entryId), eq(timelineEntries.orgId, orgId)))
        .limit(1);
      if (!row) throw Errors.notFound('Timeline entry not found');
      return row;
    };
    const afterMutate = await read();
    const changed = booking ? await syncBookingFromTimelineEntry(tx, booking, afterMutate, userId, calendarCheck) : null;
    return { entry: changed ? await read() : afterMutate, changed };
  });
  if (changed) {
    const loaded = await loadBookingRow(app, changed.booking);
    await afterBookingChange(app, {
      booking: changed.booking,
      eventType: loaded.eventType,
      link: loaded.link,
      hostUserIds: loaded.hosts.map((host) => host.userId),
      manageToken: null,
      kind: changed.kind,
    });
  }
  return entry;
}

export async function crmRoutes(app: FastifyInstance): Promise<void> {
  const r = app.withTypeProvider<ZodTypeProvider>();
  // Authenticate BEFORE validation (hygiene 2026-10-03): an anonymous caller gets 401, never a 400 naming the fields.
  r.addHook('preValidation', app.authenticate);
  // P51 G1: the v1 routes never expose the CRM v2 external key (see v1-external-key.ts).
  hideExternalKeyFromV1(app);
  const notifier = createNotifier(app);

  /*
   * Notification/activity/email audit, 2026-09-10. Three small helpers shared
   * by every notify-on-assignment site below, kept here rather than in
   * `./service.ts` so the notification write stays beside the route's own
   * `app.db.transaction`/`notifier.sendEmails` split -- the same reason
   * `orgs/routes.ts`'s invite-accept handler builds its notification inline
   * rather than inside a service function.
   */

  async function orgSlugFor(db: DbOrTx, orgId: string): Promise<string> {
    const [org] = await db.select({ slug: organizations.slug }).from(organizations).where(eq(organizations.id, orgId)).limit(1);
    return org?.slug ?? orgId;
  }

  async function actorNameFor(db: DbOrTx, userId: string): Promise<string> {
    const [row] = await db.select({ name: users.name }).from(users).where(eq(users.id, userId)).limit(1);
    return row?.name ?? 'Someone';
  }

  function contactDisplayName(contact: { firstName: string | null; lastName: string | null; primaryEmail: string | null }): string {
    const name = [contact.firstName, contact.lastName].filter(Boolean).join(' ').trim();
    return name || contact.primaryEmail || 'this contact';
  }

  /* ---------------------------------------------------------------------- */
  /* Companies                                                              */
  /* ---------------------------------------------------------------------- */

  r.get('/orgs/:orgId/crm/companies', { schema: { params: orgParams } }, async (req) => {
    const auth = requireAuth(req);
    await requireOrgPermission(app.db, auth.userId, req.params.orgId, 'crm:read');
    const companies = await crm.listCompanies(app.db, req.params.orgId);
    return { companies };
  });

  r.post(
    '/orgs/:orgId/crm/companies',
    { schema: { params: orgParams, body: createCrmCompanyBodySchema } },
    async (req, reply) => {
      const auth = requireAuth(req);
      await requireOrgPermission(app.db, auth.userId, req.params.orgId, 'crm:create');
      await requireFeature(app.db, req.params.orgId, 'crm.enabled');
      let committedNotification: CommittedNotificationInput | null = null;
      const company = await app.db.transaction(async (tx) => {
        const created = await crm.createCompany(tx, { orgId: req.params.orgId, userId: auth.userId, body: req.body });
        // Board: notification/activity/email audit, 2026-09-10. Fired only
        // when the new owner is someone besides the creator -- the standard
        // "actor !== recipient" guard (`issue_owner_changed`'s own doc
        // comment in enums.ts), since a person who just gave themself
        // ownership already knows.
        if (created.ownerUserId && created.ownerUserId !== auth.userId) {
          const actorName = await actorNameFor(tx, auth.userId);
          const notifs: NotificationInput[] = [
            {
              userId: created.ownerUserId,
              orgId: req.params.orgId,
              type: 'crm_owner_assigned',
              title: `${actorName} made you the owner of ${created.name}`,
              link: `/o/${await orgSlugFor(tx, req.params.orgId)}/crm/companies/${created.id}`,
              data: { entityType: 'company', entityId: created.id },
            },
          ];
          const inserted = await createNotifications(tx, notifs, { queueEmail: true });
          committedNotification = { ...notifs[0]!, notificationId: inserted[0]!.id };
        }
        return created;
      });
      if (committedNotification) notifier.sendEmails([committedNotification]);
      return reply.status(201).send({ company });
    },
  );

  r.get('/orgs/:orgId/crm/companies/:companyId', { schema: { params: companyParams } }, async (req) => {
    const auth = requireAuth(req);
    await requireOrgPermission(app.db, auth.userId, req.params.orgId, 'crm:read');
    const company = await crm.getCompany(app.db, req.params.orgId, req.params.companyId);
    return { company };
  });

  r.patch(
    '/orgs/:orgId/crm/companies/:companyId',
    { schema: { params: companyParams, body: updateCrmCompanyBodySchema } },
    async (req) => {
      const auth = requireAuth(req);
      await requireOrgPermission(app.db, auth.userId, req.params.orgId, 'crm:edit');
      await requireFeature(app.db, req.params.orgId, 'crm.enabled');
      let committedNotification: CommittedNotificationInput | null = null;
      const company = await app.db.transaction(async (tx) => {
        // Read the PRE-update owner so a PATCH that leaves `ownerUserId`
        // untouched, or reassigns it back to who already held it, never
        // re-notifies -- only an actual change of owner is "assigned".
        const [before] = await tx
          .select({ ownerUserId: crmCompanies.ownerUserId })
          .from(crmCompanies)
          .where(and(eq(crmCompanies.id, req.params.companyId), eq(crmCompanies.orgId, req.params.orgId)))
          .limit(1);
        const updated = await crm.updateCompany(tx, {
          orgId: req.params.orgId,
          companyId: req.params.companyId,
          userId: auth.userId,
          body: req.body,
        });
        if (
          req.body.ownerUserId !== undefined &&
          updated.ownerUserId &&
          updated.ownerUserId !== before?.ownerUserId &&
          updated.ownerUserId !== auth.userId
        ) {
          const actorName = await actorNameFor(tx, auth.userId);
          const notifs: NotificationInput[] = [
            {
              userId: updated.ownerUserId,
              orgId: req.params.orgId,
              type: 'crm_owner_assigned',
              title: `${actorName} made you the owner of ${updated.name}`,
              link: `/o/${await orgSlugFor(tx, req.params.orgId)}/crm/companies/${updated.id}`,
              data: { entityType: 'company', entityId: updated.id },
            },
          ];
          const inserted = await createNotifications(tx, notifs, { queueEmail: true });
          committedNotification = { ...notifs[0]!, notificationId: inserted[0]!.id };
        }
        return updated;
      });
      if (committedNotification) notifier.sendEmails([committedNotification]);
      return { company };
    },
  );

  /* ---------------------------------------------------------------------- */
  /* Contacts                                                               */
  /* ---------------------------------------------------------------------- */

  r.get(
    '/orgs/:orgId/crm/contacts',
    { schema: { params: orgParams, querystring: listCrmContactsQuerySchema } },
    async (req) => {
      const auth = requireAuth(req);
      await requireOrgPermission(app.db, auth.userId, req.params.orgId, 'crm:read');
      return crm.listContacts(app.db, req.params.orgId, req.query);
    },
  );

  /** The whole customer list. Gated separately from crm:read -- reading one contact and downloading every contact are different risks (CRM-DESIGN.md section 6.1). */
  r.get('/orgs/:orgId/crm/contacts/export', { schema: { params: orgParams } }, async (req) => {
    const auth = requireAuth(req);
    await requireOrgPermission(app.db, auth.userId, req.params.orgId, 'crm:export');
    const contacts = await crm.exportContacts(app.db, req.params.orgId);
    return { contacts };
  });

  r.post(
    '/orgs/:orgId/crm/contacts',
    { schema: { params: orgParams, body: createCrmContactBodySchema } },
    async (req, reply) => {
      const auth = requireAuth(req);
      await requireOrgPermission(app.db, auth.userId, req.params.orgId, 'crm:create');
      await requireFeature(app.db, req.params.orgId, 'crm.enabled');
      let committedNotification: CommittedNotificationInput | null = null;
      const contact = await app.db.transaction(async (tx) => {
        const created = await crm.createContact(tx, { orgId: req.params.orgId, userId: auth.userId, body: req.body });
        if (created.ownerUserId && created.ownerUserId !== auth.userId) {
          const actorName = await actorNameFor(tx, auth.userId);
          const notifs: NotificationInput[] = [
            {
              userId: created.ownerUserId,
              orgId: req.params.orgId,
              type: 'crm_owner_assigned',
              title: `${actorName} made you the owner of ${contactDisplayName(created)}`,
              link: `/o/${await orgSlugFor(tx, req.params.orgId)}/crm/${created.id}`,
              data: { entityType: 'contact', entityId: created.id },
            },
          ];
          const inserted = await createNotifications(tx, notifs, { queueEmail: true });
          committedNotification = { ...notifs[0]!, notificationId: inserted[0]!.id };
        }
        return created;
      });
      if (committedNotification) notifier.sendEmails([committedNotification]);
      return reply.status(201).send({ contact });
    },
  );

  /** "A contact record that shows their bugs" — the slice's own headline. */
  r.get('/orgs/:orgId/crm/contacts/:contactId', { schema: { params: contactParams } }, async (req) => {
    const auth = requireAuth(req);
    const { org, role, permissions } = await requireOrgPermission(
      app.db,
      auth.userId,
      req.params.orgId,
      'crm:read',
    );
    const contact = await crm.getContact(app.db, req.params.orgId, req.params.contactId);
    const [company, rawTimeline, candidateIssues, visibleIds, openFollowUpCount] =
      await Promise.all([
        contact.companyId ? crm.getCompany(app.db, req.params.orgId, contact.companyId) : null,
        crm.contactTimeline(app.db, req.params.orgId, contact.id),
        crm.contactReportedIssues(app.db, req.params.orgId, contact),
        visibleProjectIds(app.db, auth.userId, req.params.orgId, role),
        crm.contactOpenFollowUpCount(app.db, req.params.orgId, contact.id, auth.userId),
      ]);
    const reportedIssues = await reportedIssuesForViewer(app, auth, req.params.orgId, candidateIssues);
    const readerTimeline = await forTimelineReader(req, auth, timelineWithSubjects(rawTimeline, auth.userId, visibleIds));
    // The server reports what the caller may see (CLAUDE.md); the client
    // renders from this one answer rather than re-deriving it.
    return {
      contact,
      company,
      timeline: readerTimeline,
      timelineNextCursor: readerCursor(req, rawTimeline.nextCursor, readerTimeline as Array<{ id: string; occursAt?: unknown }>),
      /*
       * COUNTED, NOT DERIVED — and this is the half of the paging change that
       * is easy to miss.
       *
       * `timeline` above is now one PAGE. The contact record renders a warning
       * badge for outstanding follow-ups, and it used to build that number by
       * filtering the array in this response, which was correct only while the
       * array was the contact's entire history. The moment it became a page,
       * the same expression started answering a different question: "open
       * follow-ups among the 50 most recent activities". A customer with 60
       * logged calls and 14 open commitments would have been shown "2 open".
       *
       * So the server answers the question the badge is actually asking, over
       * the whole history and with the viewer's own visibility applied, and the
       * client renders that one answer instead of guessing from a page. Paired
       * with `timelineNextCursor`, which is what lets the page say "showing the
       * 50 most recent" rather than silently implying it has shown everything.
       */
      openFollowUpCount,
      reportedIssues,
      permissions: [...permissions],
      org: { id: org.id, role },
    };
  });

  r.patch(
    '/orgs/:orgId/crm/contacts/:contactId',
    { schema: { params: contactParams, body: updateCrmContactBodySchema } },
    async (req) => {
      const auth = requireAuth(req);
      await requireOrgPermission(app.db, auth.userId, req.params.orgId, 'crm:edit');
      await requireFeature(app.db, req.params.orgId, 'crm.enabled');
      let committedNotification: CommittedNotificationInput | null = null;
      const contact = await app.db.transaction(async (tx) => {
        const [before] = await tx
          .select({ ownerUserId: crmContacts.ownerUserId })
          .from(crmContacts)
          .where(and(eq(crmContacts.id, req.params.contactId), eq(crmContacts.orgId, req.params.orgId)))
          .limit(1);
        const updated = await crm.updateContact(tx, {
          orgId: req.params.orgId,
          contactId: req.params.contactId,
          userId: auth.userId,
          body: req.body,
        });
        if (
          req.body.ownerUserId !== undefined &&
          updated.ownerUserId &&
          updated.ownerUserId !== before?.ownerUserId &&
          updated.ownerUserId !== auth.userId
        ) {
          const actorName = await actorNameFor(tx, auth.userId);
          const notifs: NotificationInput[] = [
            {
              userId: updated.ownerUserId,
              orgId: req.params.orgId,
              type: 'crm_owner_assigned',
              title: `${actorName} made you the owner of ${contactDisplayName(updated)}`,
              link: `/o/${await orgSlugFor(tx, req.params.orgId)}/crm/${updated.id}`,
              data: { entityType: 'contact', entityId: updated.id },
            },
          ];
          const inserted = await createNotifications(tx, notifs, { queueEmail: true });
          committedNotification = { ...notifs[0]!, notificationId: inserted[0]!.id };
        }
        return updated;
      });
      if (committedNotification) notifier.sendEmails([committedNotification]);
      return { contact };
    },
  );

  r.post(
    '/orgs/:orgId/crm/contacts/:contactId/archive',
    { schema: { params: contactParams } },
    async (req) => {
      const auth = requireAuth(req);
      await requireOrgPermission(app.db, auth.userId, req.params.orgId, 'crm:archive');
      await requireFeature(app.db, req.params.orgId, 'crm.enabled');
      const contact = await app.db.transaction((tx) =>
        crm.archiveContact(tx, { orgId: req.params.orgId, contactId: req.params.contactId, userId: auth.userId }),
      );
      return { contact };
    },
  );

  /** goodqa#7576: restore an archived contact. Same gates as archive; see `unarchiveContact` for the 404/409 contract. */
  r.post(
    '/orgs/:orgId/crm/contacts/:contactId/unarchive',
    { schema: { params: contactParams } },
    async (req) => {
      const auth = requireAuth(req);
      await requireOrgPermission(app.db, auth.userId, req.params.orgId, 'crm:archive');
      await requireFeature(app.db, req.params.orgId, 'crm.enabled');
      const contact = await app.db.transaction((tx) =>
        crm.unarchiveContact(tx, { orgId: req.params.orgId, contactId: req.params.contactId, userId: auth.userId }),
      );
      return { contact };
    },
  );

  /** Manual half of "shows their bugs" -- link an issue this contact reported (CRM-DESIGN.md section 7.3). */
  r.post(
    '/orgs/:orgId/crm/contacts/:contactId/issue-links',
    { schema: { params: contactParams, body: linkContactIssueBodySchema } },
    async (req, reply) => {
      const auth = requireAuth(req);
      await requireOrgPermission(app.db, auth.userId, req.params.orgId, 'crm:edit');
      await requireFeature(app.db, req.params.orgId, 'crm.enabled');
      let committedNotification: CommittedNotificationInput | null = null;
      const link = await app.db.transaction(async (tx) => {
        const [issue] = await tx
          .select({
            id: issues.id,
            number: issues.number,
            projectId: issues.projectId,
            assigneeId: issues.assigneeId,
            reporterId: issues.reporterId,
            categoryId: issues.categoryId,
          })
          .from(issues)
          .where(eq(issues.id, req.body.issueId))
          .limit(1);
        if (!issue) throw Errors.notFound('Issue not found');
        const access = await requireIssueAccess(tx, auth.userId, issue, { lock: 'share' });
        if (access.project.orgId !== req.params.orgId) throw Errors.notFound('Issue not found');
        if (
          auth.apiKeyScopedToUserId &&
          !(await issueVisibleToScopedUser(tx, issue, auth.apiKeyScopedToUserId))
        ) {
          throw Errors.notFound('Issue not found');
        }
        if (access.projectRole !== 'task_only') {
          await assertIssueCategoryReadableForRequest(tx, auth, req.params.orgId, issue);
        }
        const created = await crm.linkContactToIssue(tx, {
          orgId: req.params.orgId,
          contactId: req.params.contactId,
          issueId: req.body.issueId,
          userId: auth.userId,
          reason: req.body.reason,
        });
        // Board: notification/activity/email audit, 2026-09-10. Notifies the
        // CONTACT'S OWNER, not the issue's assignee/reporter — the person who
        // owns the customer relationship is who needs to know a support
        // ticket now exists for it, and they may not be a member of the
        // linked issue's project at all (`data.projectId`/`data.issueId`
        // below let the read-time visibility gate apply THEIR OWN project and
        // category access before showing it — see
        // `PROJECT_SCOPED_NOTIFICATION_TYPES`/`ISSUE_NOTIFICATION_TYPES` in
        // apps/api/src/modules/activity/routes.ts).
        const [contact] = await tx
          .select({
            ownerUserId: crmContacts.ownerUserId,
            firstName: crmContacts.firstName,
            lastName: crmContacts.lastName,
            primaryEmail: crmContacts.primaryEmail,
          })
          .from(crmContacts)
          .where(eq(crmContacts.id, req.params.contactId))
          .limit(1);
        if (contact?.ownerUserId && contact.ownerUserId !== auth.userId) {
          const actorName = await actorNameFor(tx, auth.userId);
          const notifs: NotificationInput[] = [
            {
              userId: contact.ownerUserId,
              orgId: req.params.orgId,
              type: 'crm_issue_linked',
              title: `${actorName} linked issue #${issue.number} to ${contactDisplayName(contact)}`,
              link: `/projects/${issue.projectId}/issues/${issue.number}`,
              data: { projectId: issue.projectId, issueId: issue.id, contactId: req.params.contactId },
            },
          ];
          const inserted = await createNotifications(tx, notifs, { queueEmail: false });
          committedNotification = { ...notifs[0]!, notificationId: inserted[0]!.id };
        }
        return created;
      });
      if (committedNotification) notifier.sendEmails([committedNotification]);
      return reply.status(201).send({ link });
    },
  );

  /**
   * Undo the route directly above. It shipped in 0178 with no counterpart, so
   * a customer linked to the wrong bug stayed linked to it forever.
   *
   * Gated on `crm:edit` in the OWNING ORG and nothing else — deliberately NOT
   * on being able to open the linked issue, unlike the POST. Three reasons,
   * and they are the whole argument:
   *   1. It discloses no issue field. The handler reads nothing from `issues`
   *      and the 204 carries no body.
   *   2. Requiring project access to REMOVE what an org-level CRM permission
   *      created makes the mistake permanently unfixable the moment the person
   *      who made it loses access to that project — exactly the "a link you
   *      cannot remove" failure this route exists to end.
   *   3. The only thing left to infer is "does a link exist between this
   *      contact and this issue, inside my own org", and the caller already
   *      holds `crm:edit` there, which lets them read and rewrite every
   *      contact in it anyway.
   * `requireFeature` still applies: it is a write, and every CRM write is
   * plan-gated (see this module's header).
   */
  r.delete(
    '/orgs/:orgId/crm/contacts/:contactId/issue-links/:issueId',
    { schema: { params: contactIssueLinkParams } },
    async (req, reply) => {
      const auth = requireAuth(req);
      await requireOrgPermission(app.db, auth.userId, req.params.orgId, 'crm:edit');
      await requireFeature(app.db, req.params.orgId, 'crm.enabled');
      await app.db.transaction((tx) =>
        crm.unlinkContactFromIssue(tx, {
          orgId: req.params.orgId,
          contactId: req.params.contactId,
          issueId: req.params.issueId,
          userId: auth.userId,
        }),
      );
      return reply.status(204).send();
    },
  );

  /* ---------------------------------------------------------------------- */
  /* The issue side of the same link — "Customers affected"                 */
  /* ---------------------------------------------------------------------- */

  /**
   * The reverse of "a contact record that shows their bugs": which customers
   * this bug affects, on the ISSUE record. It is the half that makes the CRM
   * part of the bug tracker rather than a second product sharing a login — no
   * standalone CRM can answer it, because the bugs live here.
   *
   * TWO INDEPENDENT GATES, in this order, because they answer different
   * questions:
   *
   *   1. THE ISSUE. Resolved through `requireIssueAccess` plus the same
   *      API-key-scope and category refinements as the issue detail route, so
   *      a caller who cannot open the issue learns nothing at all (404, the
   *      same answer they already get from the issue itself).
   *
   *   2. THE CRM. `crm:read` is checked WITHOUT `requireOrgPermission`, on
   *      purpose: this is an embedded panel on a page the caller is entitled
   *      to read, and a 403 here has only two possible renderings, both wrong
   *      — it either fails the whole issue page, or it gets shown as "no
   *      customers affected", which is the product stating a falsehood about
   *      the business. So a caller without `crm:read` gets 200 with
   *      `canRead: false` and an empty list, and the panel says the true
   *      thing. Same shape as `rbac/routes.ts`'s catalog gate: resolve
   *      membership first, then decide.
   *
   * Nothing `requireOrgPermission` would have enforced is lost by not calling
   * it. Membership and org standing are already proved: `requireIssueAccess`
   * resolves through `resolveProjectRoleUnchecked`, which calls
   * `assertOrgActive` on every one of its paths (lib/access.ts:384, :395), so a
   * suspended org fails above this line. The one thing it does that
   * `effectiveOrgPermissionSet` does not is the API-key tenant boundary, hence
   * the explicit `assertWithinApiKeyScope` — kept even though this route is
   * session-only today (plugins/auth.ts' SESSION_ONLY_ROUTES), because a future
   * allowlisting must not silently become a cross-tenant read.
   *
   * `canUnlink` is the server's own `crm:edit` answer, so the panel's remove
   * button and the DELETE route above cannot disagree.
   */
  r.get('/issues/:issueId/crm/contacts', { schema: { params: issueParams } }, async (req) => {
    const auth = requireAuth(req);
    const [issue] = await app.db
      .select({
        id: issues.id,
        projectId: issues.projectId,
        assigneeId: issues.assigneeId,
        reporterId: issues.reporterId,
        categoryId: issues.categoryId,
      })
      .from(issues)
      .where(eq(issues.id, req.params.issueId))
      .limit(1);
    if (!issue) throw Errors.notFound('Issue not found');

    const access = await requireIssueAccess(app.db, auth.userId, issue);
    const orgId = access.project.orgId;
    assertWithinApiKeyScope(orgId);
    if (
      auth.apiKeyScopedToUserId &&
      !(await issueVisibleToScopedUser(app.db, issue, auth.apiKeyScopedToUserId))
    ) {
      throw Errors.notFound('Issue not found');
    }
    if (access.projectRole !== 'task_only') {
      await assertIssueCategoryReadableForRequest(app.db, auth, orgId, issue);
    }

    const held = await effectiveOrgPermissionSet(app.db, auth.userId, orgId);
    if (!held.has('crm:read')) return { contacts: [], canRead: false, canUnlink: false };
    const contacts = await crm.issueLinkedContacts(app.db, orgId, issue);
    return { contacts, canRead: true, canUnlink: held.has('crm:edit') };
  });

  /* ---------------------------------------------------------------------- */
  /* Timeline                                                               */
  /* ---------------------------------------------------------------------- */

  r.post(
    '/orgs/:orgId/crm/timeline',
    { schema: { params: orgParams, body: createTimelineEntryBodySchema } },
    async (req, reply) => {
      const auth = requireAuth(req);
      await requireOrgPermission(app.db, auth.userId, req.params.orgId, 'crm:create');
      await requireFeature(app.db, req.params.orgId, 'crm.enabled');
      let committedNotification: CommittedNotificationInput | null = null;
      const result = await withSessionAction(req, app.db, (db) => db.transaction(async (tx) => {
        await assertTimelineIssueLinksVisible(tx, auth, req.params.orgId, req.body.links);
        const created = await crm.createTimelineEntry(tx, {
          orgId: req.params.orgId,
          userId: auth.userId,
          body: req.body,
        });
        // Board: notification/activity/email audit, 2026-09-10. Only for the
        // three "someone owes work" kinds a timeline entry can carry — a
        // logged `note`/`email`/`event`/`form_response` has no owed-work
        // semantics to assign. Guards actor !== recipient the same as every
        // other assignment type here.
        const ownerUserId = created.entry.ownerUserId;
        if (
          ownerUserId &&
          ownerUserId !== auth.userId &&
          (created.entry.kind === 'call' || created.entry.kind === 'task' || created.entry.kind === 'meeting')
        ) {
          const actorName = await actorNameFor(tx, auth.userId);
          const kindLabel = label('timelineKind', created.entry.kind);
          const orgSlug = await orgSlugFor(tx, req.params.orgId);
          // Board #628: a `kind: 'meeting'` timeline entry has a real,
          // addressable destination -- the same `entryId` `more/meeting/
          // [entryId].tsx` and `GET /v1/orgs/:orgId/meetings/:entryId`
          // already resolve by. Route precisely to it, mirroring
          // `notifyMeetingAttendees`'s exact `?meeting=` link shape
          // (`apps/api/src/modules/meetings/routes.ts`) instead of the
          // generic CRM index every kind used to get. `call`/`task`/`note`/
          // `email` kinds have no per-entry screen yet and keep the
          // existing generic link, unchanged.
          const isMeeting = created.entry.kind === 'meeting';
          // Two flat, independently-scannable template literals rather than
          // one nested inside a ternary inside another: apps/api/test/
          // notification-link-routes.test.ts reads `link:` literals as text
          // and cannot resolve a backtick nested inside a `${...}`
          // interpolation, mirroring the working pattern at
          // apps/api/src/modules/meetings/routes.ts:759.
          const activityLink = isMeeting
            ? `/o/${orgSlug}/calendar?meeting=${created.entry.id}`
            : `/o/${orgSlug}/crm`;
          const notifs: NotificationInput[] = [
            {
              userId: ownerUserId,
              orgId: req.params.orgId,
              type: 'crm_activity_assigned',
              title: `${actorName} assigned you a ${kindLabel.toLowerCase()}: ${created.entry.title}`,
              link: activityLink,
              data: isMeeting
                ? {
                    entryId: created.entry.id,
                    kind: created.entry.kind,
                    meetingId: created.entry.id,
                    target: {
                      kind: 'calendar_meeting',
                      version: 1,
                      meetingId: created.entry.id,
                      orgId: req.params.orgId,
                    },
                  }
                : { entryId: created.entry.id, kind: created.entry.kind },
            },
          ];
          const inserted = await createNotifications(tx, notifs, { queueEmail: true });
          committedNotification = { ...notifs[0]!, notificationId: inserted[0]!.id };
        }
        return created;
      }));
      if (committedNotification) notifier.sendEmails([committedNotification]);
      return reply.status(201).send(result);
    },
  );

  r.get(
    '/orgs/:orgId/crm/contacts/:contactId/timeline',
    { schema: { params: contactParams, querystring: contactTimelineQuery } },
    async (req) => {
      return withSessionAction(req, app.db, async (db) => {
        const auth = requireAuth(req);
        const { role } = await requireOrgPermission(db, auth.userId, req.params.orgId, 'crm:read');
        refuseHiddenMatchFilters(req, req.query);
        const [rawTimeline, visibleIds] = await Promise.all([
          crm.contactTimeline(db, req.params.orgId, req.params.contactId, req.query),
          visibleProjectIds(db, auth.userId, req.params.orgId, role),
        ]);
        const readerTimeline = await forTimelineReader(req, auth, timelineWithSubjects(rawTimeline, auth.userId, visibleIds));
        return {
          timeline: readerTimeline,
          /*
           * The server's own keyset value, never "did we return a full page".
           * `timelineForViewer` runs AFTER the page is fetched, so a page can come
           * back short because a colleague's `personal` entries were removed from
           * it -- counting rows would stop paging early and hide the rest of the
           * customer's history. Same rule, same words, as the org timeline.
           */
          nextCursor: readerCursor(req, rawTimeline.nextCursor, readerTimeline as Array<{ id: string; occursAt?: unknown }>),
        };
      });
    },
  );

  /**
   * THE ORG-LEVEL TIMELINE READ — the follow-up queue, the account rollup and
   * the activity feed, all one route.
   *
   * Part A registered a POST here and a per-contact GET and nothing else, so
   * the CRM had no home screen: there was no way to ask "what do I owe" or
   * "what happened this week" without opening contacts one at a time and
   * already knowing which ones.
   *
   * The visibility contract is the SAME `timelineForViewer` the contact
   * timeline uses, applied AFTER the page is fetched. That means a page can
   * come back shorter than `limit` because somebody else's personal entries
   * were removed from it — which is correct and is why `nextCursor` is the
   * server's own keyset value rather than "did we return a full page".
   * Filtering inside the query instead would leak the entries' existence into
   * the count.
   */
  r.get(
    '/orgs/:orgId/crm/timeline',
    { schema: { params: orgParams, querystring: listCrmTimelineQuerySchema } },
    async (req) => {
      return withSessionAction(req, app.db, async (db) => {
        const auth = requireAuth(req);
        const { role } = await requireOrgPermission(db, auth.userId, req.params.orgId, 'crm:read');
        const [result, visibleIds] = await Promise.all([
          crm.listTimeline(db, req.params.orgId, req.query),
          visibleProjectIds(db, auth.userId, req.params.orgId, role),
        ]);
        const visible = await forTimelineReader(req, auth, timelineForViewer(result.entries, auth.userId, visibleIds));
        return {
          entries: visible.map((entry) => ({
            ...entry,
            /*
             * A `busy_only` entry the viewer may not open arrives from
             * `timelineForViewer` already stripped to the single word "Busy".
             * Its subjects must go with it: naming the customer a colleague is
             * meeting would restore, through the side door, exactly the detail
             * the block was hiding.
             */
            subjects: canSeeTimelineEntryDetails(entry, auth.userId)
              ? (result.subjects.get(entry.id) ?? [])
              : [],
            /* Same gate as `subjects` — see `timelineWithSubjects` for the argument. */
            author:
              canSeeTimelineEntryDetails(entry, auth.userId) && entry.createdBy
                ? (result.authors.get(entry.createdBy) ?? null)
                : null,
          })),
          nextCursor: result.nextCursor,
        };
      });
    },
  );

  /**
   * Edit one entry — complete a follow-up, reschedule a meeting, correct a
   * logged call.
   *
   * `crm:edit`, not a narrower "own entries only" rule: CRM activity is
   * org-visible by decision (design §3), a team covering for someone on leave
   * has to be able to close their follow-ups, and the entries a member must
   * NOT touch are already excluded by the visibility check inside
   * `updateTimelineEntry` rather than by ownership.
   */
  r.patch(
    '/orgs/:orgId/crm/timeline/:entryId',
    { schema: { params: entryParams, body: updateTimelineEntryBodySchema } },
    async (req) => {
      const auth = requireAuth(req);
      const { role } = await requireOrgPermission(app.db, auth.userId, req.params.orgId, 'crm:edit');
      await requireFeature(app.db, req.params.orgId, 'crm.enabled');
      await refuseGmailEntryForAgent(req, auth, req.params.orgId, req.params.entryId);
      const entry = await commitTimelineBooking(app, req.params.orgId, req.params.entryId, auth.userId, (tx) =>
        crm.updateTimelineEntry(tx, {
          orgId: req.params.orgId,
          entryId: req.params.entryId,
          userId: auth.userId,
          body: req.body,
        }),
        req.body,
      );
      return {
        entry: await withVisibleProjectContext(
          app.db,
          { userId: auth.userId, orgId: req.params.orgId, role },
          entry,
        ),
      };
    },
  );

  /** Soft-archive one entry. `crm:archive`, matching the contact archive beside it. */
  r.post(
    '/orgs/:orgId/crm/timeline/:entryId/archive',
    { schema: { params: entryParams } },
    async (req) => {
      const auth = requireAuth(req);
      const { role } = await requireOrgPermission(
        app.db,
        auth.userId,
        req.params.orgId,
        'crm:archive',
      );
      await requireFeature(app.db, req.params.orgId, 'crm.enabled');
      await refuseGmailEntryForAgent(req, auth, req.params.orgId, req.params.entryId);
      const entry = await commitTimelineBooking(app, req.params.orgId, req.params.entryId, auth.userId, (tx) =>
        crm.archiveTimelineEntry(tx, {
          orgId: req.params.orgId,
          entryId: req.params.entryId,
          userId: auth.userId,
        }),
      );
      return {
        entry: await withVisibleProjectContext(
          app.db,
          { userId: auth.userId, orgId: req.params.orgId, role },
          entry,
        ),
      };
    },
  );


  /* ---------------------------------------------------------------------- */
  /* AI assist — every route here PROPOSES. None of them writes a CRM record. */
  /* ---------------------------------------------------------------------- */

  /**
   * This viewer's own recent AI suggestions for one contact, plus whether the
   * feature can run at all.
   *
   * `available` exists so the panel can disable its buttons honestly instead of
   * offering a control that is refused on click: `lib/vertex-ai.ts` throws
   * `ai_summary_not_configured` when `GCP_PROJECT` is empty, and a deployment
   * without Vertex credentials is a real, shipped state (that file's own
   * "HONESTY NOTE").
   *
   * *** REQUESTER-SCOPED. *** `listContactSuggestions` takes the authenticated
   * user as a mandatory predicate — see `packages/db/src/schema/crm-ai.ts`'s
   * header. A briefing is a projection of ONE person's timeline visibility, so
   * serving a colleague's briefing to someone holding `crm:read` would hand
   * them prose summarising entries the timeline itself collapses to "Busy".
   *
   * `acceptedEntries` carries the timeline entries these suggestions became,
   * with project context resolved through `visibleProjectIds` — the same debt
   * `withVisibleProjectContext`'s doc comment describes the PATCH route paying.
   * An entry id alone would be useless to the panel and a raw `projectId` would
   * be the exact leak that helper exists to close.
   */
  r.get(
    '/orgs/:orgId/crm/contacts/:contactId/ai/suggestions',
    { schema: { params: contactParams } },
    async (req) => {
      const auth = requireAuth(req);
      const { role } = await requireOrgPermission(app.db, auth.userId, req.params.orgId, 'crm:read');
      // Proves the contact exists in THIS org before anything keyed on its id
      // is returned; without it a caller could probe another tenant's contact
      // ids through an empty-vs-404 difference.
      await crm.getContact(app.db, req.params.orgId, req.params.contactId);
      const [rows, visibleIds] = await Promise.all([
        crmAi.listContactSuggestions(app.db, {
          orgId: req.params.orgId,
          contactId: req.params.contactId,
          requestedBy: auth.userId,
        }),
        visibleProjectIds(app.db, auth.userId, req.params.orgId, role),
      ]);
      const acceptedIds = rows
        .map((row) => row.acceptedEntryId)
        .filter((id): id is string => id !== null);
      const acceptedEntries =
        acceptedIds.length === 0
          ? []
          : timelineForViewer(
              await app.db
                .select()
                .from(timelineEntries)
                .where(
                  and(
                    eq(timelineEntries.orgId, req.params.orgId),
                    inArray(timelineEntries.id, acceptedIds),
                  ),
                ),
              auth.userId,
              visibleIds,
            );
      return {
        suggestions: rows.map(crmAi.toSuggestionDto),
        acceptedEntries,
        available: app.config.GCP_PROJECT !== '',
      };
    },
  );

  /**
   * PRE-MEETING BRIEFING — Gemini on Vertex AI reads this contact's whole
   * VISIBLE history and writes a one-minute brief.
   *
   * Nothing is written to the CRM. The result is a `crm_ai_suggestions` row in
   * `draft` and a response body; a human reads it, and if they want it on the
   * record they create an ordinary note through the composer and then call
   * `.../ai/suggestions/:id/resolve`.
   *
   * `crm:create`, not `crm:read`, and the reason is the same one
   * `POST /issues/:issueId/ai-summary` states for requiring `tester`: this
   * spends the org's AI budget, so the people who can put work into the CRM can
   * spend it and nobody else can. The rate limit is that route's, verbatim —
   * this is a one-click control an impatient person will click repeatedly.
   *
   * `visibleProjectIds` is genuinely load-bearing here rather than decorative:
   * it is handed to `buildContactContext`, which runs the timeline through
   * `timelineForViewer` BEFORE a single character reaches the model.
   */
  r.post(
    '/orgs/:orgId/crm/contacts/:contactId/ai/briefing',
    {
      config: { rateLimit: { max: 10, timeWindow: '1 minute' } },
      schema: { params: contactParams, body: crmAiBriefingBodySchema },
    },
    async (req, reply) => {
      const auth = requireAuth(req);
      const { role } = await requireOrgPermission(
        app.db,
        auth.userId,
        req.params.orgId,
        'crm:create',
      );
      await requireFeature(app.db, req.params.orgId, 'crm.enabled');
      const contact = await crm.getContact(app.db, req.params.orgId, req.params.contactId);
      const visibleIds = await visibleProjectIds(app.db, auth.userId, req.params.orgId, role);
      const context = await crmAi.buildContactContext(app.db, {
        viewerTimeZone: await viewerTimeZone(app.db, auth.userId, req.body.timeZone),
        orgId: req.params.orgId,
        contact,
        viewerUserId: auth.userId,
        visibleProjectIds: visibleIds,
        ...(req.body.purpose ? { purpose: req.body.purpose } : {}),
      });

      const vertex = getVertexAiClient(app.config);
      // Same "max reasoning, max tokens" instruction Eric gave for the issue
      // summary, through the same reserve-then-settle meter: the reservation
      // has to cover thinking tokens as well as prose, or a 2xx comes back
      // with an empty candidate that finished on MAX_TOKENS.
      const result = await meteredVertexSummary(app.db, req.params.orgId, vertex, {
        systemPrompt: crmAi.CRM_AI_BRIEFING_SYSTEM_PROMPT,
        content: context.text,
        thinkingLevel: MAX_REASONING_THINKING_LEVEL,
        maxOutputTokens: app.config.VERTEX_AI_SUMMARY_MAX_OUTPUT_TOKENS,
      });

      const row = await crmAi.insertSuggestion(app.db, {
        orgId: req.params.orgId,
        kind: 'contact_briefing',
        contactId: contact.id,
        sourceEntryId: null,
        provider: CRM_AI_PROVIDER,
        model: app.config.VERTEX_AI_SUMMARY_MODEL,
        output: result.text.slice(0, CRM_AI_SUGGESTION_OUTPUT_MAX_CHARS),
        actionItems: null,
        sourceSummary: context.sourceSummary,
        requestedBy: auth.userId,
      });
      return reply.status(201).send({ suggestion: crmAi.toSuggestionDto(row) });
    },
  );

  /**
   * FOLLOW-UP DRAFT — text for a human to edit and send THEMSELVES.
   *
   * There is no transport anywhere in this module. The route returns a subject
   * line and a body; nothing is queued, nothing is addressed, nothing leaves
   * the building. CLAUDE.md's "AI advises, humans decide" is not satisfied by a
   * confirmation dialog in front of an automatic send — it is satisfied by
   * there being no send.
   *
   * `doNotContact` is passed into the prompt as a prominent instruction rather
   * than being silently honoured, and is ALSO refused here: drafting outreach to
   * someone who asked not to be contacted is not a thing this product should
   * make one click easier, and a model instruction is not an enforcement
   * mechanism.
   */
  r.post(
    '/orgs/:orgId/crm/contacts/:contactId/ai/followup-draft',
    {
      config: { rateLimit: { max: 10, timeWindow: '1 minute' } },
      schema: { params: contactParams, body: crmAiFollowupBodySchema },
    },
    async (req, reply) => {
      const auth = requireAuth(req);
      const { role } = await requireOrgPermission(
        app.db,
        auth.userId,
        req.params.orgId,
        'crm:create',
      );
      await requireFeature(app.db, req.params.orgId, 'crm.enabled');
      const contact = await crm.getContact(app.db, req.params.orgId, req.params.contactId);
      if (contact.doNotContact) {
        throw Errors.conflict(
          'This contact is marked do-not-contact, so no outreach can be drafted for them.',
        );
      }
      const visibleIds = await visibleProjectIds(app.db, auth.userId, req.params.orgId, role);
      const context = await crmAi.buildContactContext(app.db, {
        viewerTimeZone: await viewerTimeZone(app.db, auth.userId, req.body.timeZone),
        orgId: req.params.orgId,
        contact,
        viewerUserId: auth.userId,
        visibleProjectIds: visibleIds,
        ...(req.body.tone ? { tone: req.body.tone } : {}),
        ...(req.body.goal ? { goal: req.body.goal } : {}),
      });

      const vertex = getVertexAiClient(app.config);
      const result = await meteredVertexSummary(app.db, req.params.orgId, vertex, {
        systemPrompt: crmAi.CRM_AI_FOLLOWUP_SYSTEM_PROMPT,
        content: context.text,
        thinkingLevel: MAX_REASONING_THINKING_LEVEL,
        maxOutputTokens: app.config.AI_REWRITE_MAX_OUTPUT_TOKENS,
        timeoutMs: app.config.AI_REWRITE_TIMEOUT_MS,
      });

      const row = await crmAi.insertSuggestion(app.db, {
        orgId: req.params.orgId,
        kind: 'followup_draft',
        contactId: contact.id,
        sourceEntryId: null,
        provider: CRM_AI_PROVIDER,
        model: app.config.VERTEX_AI_SUMMARY_MODEL,
        output: result.text.slice(0, CRM_AI_SUGGESTION_OUTPUT_MAX_CHARS),
        actionItems: null,
        sourceSummary: context.sourceSummary,
        requestedBy: auth.userId,
      });
      return reply.status(201).send({ suggestion: crmAi.toSuggestionDto(row) });
    },
  );

  /**
   * NEXT STEPS FROM ONE ACTIVITY — the note you just typed, turned into a list
   * of proposed follow-ups.
   *
   * The output is a LIST OF TITLES AND REASONS. It carries no owner and no due
   * date, the prompt forbids the model from stating either, and
   * `crmAiActionItemSchema` has no field to hold one — three independent layers,
   * because CLAUDE.md's "never let AI assign people or manage schedules" is the
   * rule this feature would be most tempting to break.
   *
   * `viewerSeesTimelineDetails` is the read gate, not `crm:read` alone: a
   * `personal` entry belonging to a colleague is one this viewer may not read,
   * and summarising it would be a laundering path around the timeline's own
   * projection. It is the SAME predicate `timelineForViewer` applies, taken from
   * the same module so the two cannot drift.
   */
  r.post(
    '/orgs/:orgId/crm/timeline/:entryId/ai/action-items',
    {
      config: { rateLimit: { max: 10, timeWindow: '1 minute' } },
      schema: { params: entryParams },
    },
    async (req, reply) => {
      const auth = requireAuth(req);
      const { role } = await requireOrgPermission(
        app.db,
        auth.userId,
        req.params.orgId,
        'crm:create',
      );
      await requireFeature(app.db, req.params.orgId, 'crm.enabled');
      const [entry] = await app.db
        .select()
        .from(timelineEntries)
        .where(
          and(
            eq(timelineEntries.id, req.params.entryId),
            eq(timelineEntries.orgId, req.params.orgId),
          ),
        )
        .limit(1);
      if (!entry || entry.archivedAt) throw Errors.notFound('Timeline entry not found');
      if (!viewerSeesTimelineDetails(entry, auth.userId)) {
        // 404, not 403: that this entry exists is itself what `personal` hides.
        throw Errors.notFound('Timeline entry not found');
      }
      // After the visibility check, so the 409 cannot confirm that a hidden entry exists.
      if (await crmAi.isGmailMailboxReadEntry(app.db, { orgId: req.params.orgId, entryId: entry.id })) {
        throw new AppError(
          409,
          'gmail_content_not_for_ai',
          'This email was read from a connected Gmail mailbox, and Gmail content is never sent to AI.',
        );
      }
      if (entry.body.trim() === '') {
        throw Errors.conflict('This activity has no notes to extract next steps from.');
      }

      const vertex = getVertexAiClient(app.config);
      const result = await meteredVertexSummary(app.db, req.params.orgId, vertex, {
        systemPrompt: crmAi.CRM_AI_ACTION_ITEMS_SYSTEM_PROMPT,
        content: crmAi.buildEntryActionItemContext(entry, await viewerTimeZone(app.db, auth.userId)),
        thinkingLevel: MAX_REASONING_THINKING_LEVEL,
        maxOutputTokens: app.config.VERTEX_AI_SUMMARY_MAX_OUTPUT_TOKENS,
      });
      const items = crmAi.parseActionItems(result.text);

      const row = await crmAi.insertSuggestion(app.db, {
        orgId: req.params.orgId,
        kind: 'action_items',
        contactId: null,
        sourceEntryId: entry.id,
        provider: CRM_AI_PROVIDER,
        model: app.config.VERTEX_AI_SUMMARY_MODEL,
        output: result.text.slice(0, CRM_AI_SUGGESTION_OUTPUT_MAX_CHARS),
        actionItems: items,
        sourceSummary: null,
        requestedBy: auth.userId,
      });
      return reply.status(201).send({
        suggestion: crmAi.toSuggestionDto(row),
        sourceEntry: await withVisibleProjectContext(
          app.db,
          { userId: auth.userId, orgId: req.params.orgId, role },
          entry,
        ),
      });
    },
  );

  /**
   * THE HUMAN DECISION, recorded.
   *
   * This is the route that makes "AI advises, humans decide" checkable rather
   * than merely stated: without it, nothing anywhere would record that a person
   * read the machine's advice and answered it. `entryId` names the timeline
   * entry they created from the suggestion, when they created one — optional
   * even on accept, because reading a briefing before a call and never writing
   * anything down is a legitimate way to use it, and forcing a fake id to
   * express that would corrupt the ledger.
   *
   * Verifying `entryId` belongs to this org happens inside `resolveSuggestion`;
   * `withVisibleProjectContext` then pays the project-context debt on the row
   * this route hands back, exactly as the PATCH route above does.
   */
  r.post(
    '/orgs/:orgId/crm/ai/suggestions/:suggestionId/resolve',
    { schema: { params: suggestionParams, body: crmAiResolveBodySchema } },
    async (req) => {
      const auth = requireAuth(req);
      const { role } = await requireOrgPermission(
        app.db,
        auth.userId,
        req.params.orgId,
        'crm:create',
      );
      await requireFeature(app.db, req.params.orgId, 'crm.enabled');
      const row = await app.db.transaction((tx) =>
        crmAi.resolveSuggestion(tx, {
          orgId: req.params.orgId,
          suggestionId: req.params.suggestionId,
          requestedBy: auth.userId,
          decision: req.body.decision,
          ...(req.body.entryId ? { entryId: req.body.entryId } : {}),
        }),
      );
      let entry: WritableTimelineEntry | null = null;
      if (row.acceptedEntryId) {
        const [found] = await app.db
          .select()
          .from(timelineEntries)
          .where(
            and(
              eq(timelineEntries.id, row.acceptedEntryId),
              eq(timelineEntries.orgId, req.params.orgId),
            ),
          )
          .limit(1);
        entry = found
          ? await withVisibleProjectContext(
              app.db,
              { userId: auth.userId, orgId: req.params.orgId, role },
              found,
            )
          : null;
      }
      return { suggestion: crmAi.toSuggestionDto(row), entry };
    },
  );

  /**
   * WHICH RELATIONSHIPS HAVE GONE QUIET — and this route calls NO MODEL.
   *
   * "Cold" is `max(occurs_at)` and a subtraction. Asking a language model to
   * rank contacts by staleness would be slower, would spend the org's AI budget
   * on a question SQL answers exactly, and could silently omit a real account.
   * The AI half of the feature is the BRIEFING a person generates for a contact
   * this list surfaced — see `listColdContacts`' own doc comment.
   *
   * `crm:read`, matching `GET /orgs/:orgId/crm/contacts`: this is a filtered
   * view of contacts the same permission already exposes, not a new disclosure.
   * `visibleProjectIds` is load-bearing — each row carries the last touch's
   * project context, which must be stripped for a viewer who cannot open that
   * project, the same debt every other CRM route pays.
   */
  r.get(
    '/orgs/:orgId/crm/ai/cold-contacts',
    { schema: { params: orgParams, querystring: crmColdContactsQuerySchema } },
    async (req) => {
      const auth = requireAuth(req);
      const { role } = await requireOrgPermission(app.db, auth.userId, req.params.orgId, 'crm:read');
      const visibleIds = await visibleProjectIds(app.db, auth.userId, req.params.orgId, role);
      const contacts = await crmAi.listColdContacts(app.db, {
        orgId: req.params.orgId,
        viewerUserId: auth.userId,
        visibleProjectIds: visibleIds,
        ...(req.query.days === undefined ? {} : { days: req.query.days }),
        ...(req.query.limit === undefined ? {} : { limit: req.query.limit }),
      });
      return { contacts, thresholdDays: req.query.days ?? crmAi.CRM_COLD_CONTACT_DEFAULT_DAYS };
    },
  );

  /* ---------------------------------------------------------------------- */
  /* CRM DEPTH — tickets from a contact, meeting tracking, the graph         */
  /* ---------------------------------------------------------------------- */

  /**
   * RAISE A TICKET FROM A CONTACT — the issue, the customer link and the
   * provenance link, in one call and one transaction.
   *
   * TWO INDEPENDENT PERMISSIONS, and both are load-bearing:
   *
   *   1. `crm:edit` in the ORG, because this writes a `crm_contact_issue_links`
   *      row against a contact record.
   *   2. `issue:create` in the NAMED PROJECT, because it creates an issue there.
   *      Not `crm:edit` standing in for it: an org-level CRM permission must
   *      never become a way to file tickets into a project the caller cannot
   *      open. `requireProjectPermission` resolves through `requireProjectRole`,
   *      which answers 404 for a project the caller cannot see, so a caller
   *      cannot use this route to discover which project ids exist either.
   *
   * The project is also re-checked against THIS org, because
   * `requireProjectPermission` proves the caller may create issues in that
   * project — not that the project belongs to the org whose contact is being
   * written. Without it, a member of two orgs could attach org A's contact to an
   * issue in org B's project and the CRM link row would carry org A's `org_id`
   * pointing at org B's data.
   */
  r.post(
    '/orgs/:orgId/crm/contacts/:contactId/issues',
    { schema: { params: contactParams, body: createIssueFromContactBodySchema } },
    async (req, reply) => {
      const auth = requireAuth(req);
      await requireOrgPermission(app.db, auth.userId, req.params.orgId, 'crm:edit');
      await requireFeature(app.db, req.params.orgId, 'crm.enabled');
      const access = await requireProjectPermission(
        app.db,
        auth.userId,
        req.body.projectId,
        'issue:create',
      );
      if (access.project.orgId !== req.params.orgId) throw Errors.notFound('Project not found');

      const result = await app.db.transaction(async (tx) => {
        /*
         * `fromEntryId` names a timeline entry, and being able to link to one
         * proves it exists. Resolving it through the SAME visibility rule the
         * read path uses stops this parameter being an existence oracle for a
         * colleague's `personal` rows, and answers 404 rather than 403 so the
         * refusal matches what that caller already sees.
         */
        if (req.body.fromEntryId) {
          const [entry] = await tx
            .select({
              id: timelineEntries.id,
              visibility: timelineEntries.visibility,
              ownerUserId: timelineEntries.ownerUserId,
              createdBy: timelineEntries.createdBy,
              archivedAt: timelineEntries.archivedAt,
            })
            .from(timelineEntries)
            .where(
              and(
                eq(timelineEntries.id, req.body.fromEntryId),
                eq(timelineEntries.orgId, req.params.orgId),
              ),
            )
            .limit(1);
          if (!entry || entry.archivedAt) throw Errors.notFound('Timeline entry not found');
          if (!viewerSeesTimelineDetails(entry, auth.userId)) {
            throw Errors.notFound('Timeline entry not found');
          }
        }
        return depth.createIssueFromContact(tx, {
          orgId: req.params.orgId,
          contactId: req.params.contactId,
          userId: auth.userId,
          body: req.body,
        });
      });
      return reply.status(201).send(result);
    },
  );

  /**
   * A CONTACT'S APPOINTMENTS — what is coming, what already happened, and who
   * actually turned up.
   *
   * The timeline below it answers "what have we done with this person"; this
   * answers the two questions a timeline is bad at. A chronological feed cannot
   * say "you have three meetings with them next week" without the reader doing
   * date arithmetic in their head, and it cannot say "they have missed the last
   * two" at all.
   *
   * Visibility is the SAME `timelineForViewer` contract as every other timeline
   * read, with attendance widening it exactly as the meetings module does: an
   * invited colleague must not see the meeting they are attending as the single
   * word "Busy". Participants are gated on the DETAIL predicate, never merely on
   * the block one — a guest list rendered beside an opaque block restores
   * precisely the detail the block exists to hide.
   */
  r.get(
    '/orgs/:orgId/crm/contacts/:contactId/meetings',
    { schema: { params: contactParams } },
    async (req) => {
      const auth = requireAuth(req);
      const { role } = await requireOrgPermission(app.db, auth.userId, req.params.orgId, 'crm:read');
      const now = new Date();
      const [page, visibleIds] = await Promise.all([
        depth.contactMeetings(app.db, req.params.orgId, req.params.contactId, now),
        visibleProjectIds(app.db, auth.userId, req.params.orgId, role),
      ]);
      return contactMeetingsForViewer(page, auth.userId, visibleIds, now);
    },
  );

  /**
   * RECORD WHO TURNED UP.
   *
   * `crm:edit`, the same permission that edits any other fact about an activity,
   * and the same visibility gate: `updateTimelineEntry`'s rule is that a caller
   * who may not SEE an entry may not edit it either, answering 404 so the
   * refusal cannot be used to confirm the row exists. Attendance is no
   * different — it is a fact about a meeting somebody may not be allowed to know
   * happened.
   */
  r.post(
    '/orgs/:orgId/crm/timeline/:entryId/attendance',
    { schema: { params: entryParams, body: setTimelineAttendanceBodySchema } },
    async (req) => {
      const auth = requireAuth(req);
      const { role } = await requireOrgPermission(app.db, auth.userId, req.params.orgId, 'crm:edit');
      await requireFeature(app.db, req.params.orgId, 'crm.enabled');
      const result = await app.db.transaction(async (tx) => {
        const [entry] = await tx
          .select({
            id: timelineEntries.id,
            visibility: timelineEntries.visibility,
            ownerUserId: timelineEntries.ownerUserId,
            createdBy: timelineEntries.createdBy,
            archivedAt: timelineEntries.archivedAt,
          })
          .from(timelineEntries)
          .where(
            and(
              eq(timelineEntries.id, req.params.entryId),
              eq(timelineEntries.orgId, req.params.orgId),
            ),
          )
          .limit(1);
        if (!entry || entry.archivedAt) throw Errors.notFound('Timeline entry not found');
        if (!viewerSeesTimelineDetails(entry, auth.userId)) {
          throw Errors.notFound('Timeline entry not found');
        }
        return depth.setTimelineAttendance(tx, {
          orgId: req.params.orgId,
          entryId: req.params.entryId,
          body: req.body,
        });
      });
      return {
        updated: result.updated,
        participants: result.participants,
        /*
         * The refreshed entry, through the SAME project-context filter the PATCH
         * and archive routes beside it pay. It returns a `projectId`, so it owes
         * the same answer: CRM activity is deliberately an org record, but its
         * project context is not, and a member holding `crm:edit` must not learn
         * the project id of an entry attached to a project they cannot open just
         * by recording who turned up to it.
         */
        entry: await withVisibleProjectContext(
          app.db,
          { userId: auth.userId, orgId: req.params.orgId, role },
          result.entry,
        ),
      };
    },
  );

  /**
   * THE RELATIONSHIP GRAPH, rooted at one contact or one company.
   *
   * Every edge is a row somebody already wrote — employment, co-attendance at a
   * meeting, involvement in a bug, account ownership. There is no inferred edge
   * and no strength score, for the reason `CLAUDE.md` gives about "Risk 8.6/10":
   * arithmetic over data this sparse reads as knowledge and is a guess.
   *
   * ISSUE NODES ARE FILTERED PER READER, here rather than in the query. Issue
   * visibility is refined by project membership and private categories that an
   * org-level `crm:read` must not route around, and a graph is a bulk read with
   * no per-row projection in front of it — so the graph builder returns the
   * project id for each issue node and this route drops the ones the reader
   * cannot open, along with every edge that touched them. Meetings are handled
   * inside the builder by the stricter rule available to a bulk read: only `org`
   * visibility contributes an edge at all.
   */
  r.get(
    '/orgs/:orgId/crm/graph',
    { schema: { params: orgParams, querystring: crmGraphQuerySchema } },
    async (req) => {
      const auth = requireAuth(req);
      const { role } = await requireOrgPermission(app.db, auth.userId, req.params.orgId, 'crm:read');
      const [graph, visibleIds] = await Promise.all([
        depth.crmGraph(app.db, req.params.orgId, req.query),
        visibleProjectIds(app.db, auth.userId, req.params.orgId, role),
      ]);
      return graphForViewer(graph, visibleIds);
    },
  );

}
