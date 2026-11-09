import sys


def patch(path, edits):
    s = open(path).read()
    for old, new in edits:
        assert s.count(old) == 1, (path, s.count(old), old[:90])
        s = s.replace(old, new)
    open(path, 'w').write(s)


patch('desktop-token-session.ts', [
    ("""export type DesktopDoor = 'host' | 'delegated';""", """export type DesktopDoor = 'host' | 'delegated';

/**
 * Polling reads the desktop app and its web shell issue on a timer (unread counts, notification list, remote-session availability,
 * the machine and org lists, the update check). For a bound session they take the same observation policy as the listed
 * zero-write reads: no ledger row (allowed or refused) and no last-use update, so a desktop left open does not write about 15
 * rows a minute per window for nothing. Bearer calls are unchanged. Real work (CRM reads and writes, enrollment, consent) is
 * always ledgered. goodqa#15561 ledger-load measurement.
 */
export const DESKTOP_POLL_ROUTES: ReadonlySet<string> = new Set([
  'GET /v1/me', 'GET /v1/orgs', 'GET /v1/notifications', 'GET /v1/notifications/unread-count', 'GET /v1/desktop/update-status',
  'GET /v1/me/machines', 'GET /v1/orgs/:p/machines', 'GET /v1/orgs/:p/machines/remote-sessions/availability',
  'GET /v1/chat/unread-count', 'GET /v1/orgs/:p/chat/unread-count', 'GET /v1/chat/active',
]);
export function isDesktopPollRoute(method: string, routePattern: string | undefined): boolean {
  return !!routePattern && DESKTOP_POLL_ROUTES.has(`${methodOf(method)} ${desktopRouteKey(routePattern)}`);
}"""),
])

patch('auth-gate.ts', [
    ("import { applyHostDoorWaivers, desktopExplainedSurface } from '../../lib/desktop-token-session';",
     "import { applyHostDoorWaivers, desktopExplainedSurface, isDesktopPollRoute } from '../../lib/desktop-token-session';"),
    ("""/** The ledger detail that names a desktop-session carrier;""", """/**
 * True when this request leaves no ledger row and no last-use write: the listed zero-write observation reads (any credential)
 * and, for a bound desktop session only, its polling reads (DESKTOP_POLL_ROUTES).
 */
export function ledgerQuiet(req: FastifyRequest, routePattern: string | undefined): boolean {
  return isZeroWriteRead(req.method, routePattern) || (!!req.userTokenDoor && isDesktopPollRoute(req.method, routePattern));
}

/** The ledger detail that names a desktop-session carrier;"""),
    ("""  // Observation refusals share the successful-request policy; other reads retain their denial audit.
  if (isZeroWriteRead(req.method, routePattern)) return err;""", """  // Observation refusals share the successful-request policy; other reads retain their denial audit.
  if (ledgerQuiet(req, routePattern)) return err;"""),
    ("""  if (!isZeroWriteRead(req.method, routePattern)) {
    req.server.trackBackgroundWork(recordUserTokenUse(""", """  if (!ledgerQuiet(req, routePattern)) {
    req.server.trackBackgroundWork(recordUserTokenUse("""),
])
