p = 'user-token-desktop-surface-inventory.test.ts'
s = open(p).read()


def rep(old, new):
    global s
    assert s.count(old) == 1, (s.count(old), old[:70])
    s = s.replace(old, new)


rep("""import { desktopRouteKey, desktopTokenSessionMayUse } from '../src/lib/desktop-token-session';""",
    """import { DESKTOP_DELEGATED_SURFACES, HOST_APPROVAL_WAIVED_ROUTES, HOST_BASE_READ_ROUTES, desktopRouteDoor, desktopRouteKey } from '../src/lib/desktop-token-session';""")
rep("""  desktop: 'host' | 'scope';""", """  desktop: 'host' | 'delegated' | 'scope';""")
rep(""" * `desktop` is what the bound session gets today (`host`, or `scope` = refused `desktop_token_session_scope`).""",
    """ * `desktop` is what the bound session gets: `host` (the desktop's own routes), `delegated` (the default-deny table of
 * lib/desktop-token-session.ts) or `scope` (refused `desktop_token_session_scope`). Every host route is listed whatever its path.""")
rep("""    .filter((r) => IN_SCOPE.some((re) => re.test(r.url)))
    .map((r) => ({
      route: `${r.method} ${r.url}`,
      desktop: (desktopTokenSessionMayUse(r.method, desktopRouteKey(r.url)) ? 'host' : 'scope') as 'host' | 'scope',
      token: classifyToken(r.method, r.url),
    }))""", """    .map((r) => ({ r, door: desktopRouteDoor(r.method, desktopRouteKey(r.url)) }))
    .filter(({ r, door }) => door === 'host' || IN_SCOPE.some((re) => re.test(r.url)))
    .map(({ r, door }) => ({
      route: `${r.method} ${r.url}`,
      desktop: (door ?? 'scope') as InventoryRow['desktop'],
      token: classifyToken(r.method, r.url),
    }))""")
rep("""    expect(rows.filter((r) => r.desktop === 'host').map((r) => r.route).sort()).toEqual(
      ['GET /v1/me', 'GET /v1/notifications', 'GET /v1/notifications/unread-count', 'GET /v1/orgs', 'GET /v1/orgs/:orgId/personas'].sort(),
    );
  });
});""", """  });
});

describe('the bound session\\'s doors are pinned to the code (goodqa#15561 AC-6, NEG-30)', () => {
  const key = (method: string, url: string) => `${method} ${desktopRouteKey(url)}`;

  it('every delegated entry is a registered route, token-reachable, never non-delegable, session-only or governance sign-off, and declares exactly the abilities the policy computes', () => {
    const registered = new Map(registeredRoutes().map((r) => [key(r.method, r.url), r]));
    for (const entry of DESKTOP_DELEGATED_SURFACES) {
      const r = registered.get(entry.route);
      expect(r, `${entry.route} is not a registered route`).toBeDefined();
      const p = userTokenRoutePolicy(r!.method, r!.url, authPlugin.isApiKeyReachableRoute(r!.method, r!.url));
      expect(p.nonDelegable, entry.route).toBeNull();
      expect(p.signedInPersonOnly, entry.route).toBe(false);
      expect(authPlugin.isGovernanceSessionOnlyRoute(r!.method, r!.url), entry.route).toBe(false);
      expect([...p.abilities].sort(), entry.route).toEqual([...entry.abilities].sort());
      expect(desktopRouteDoor(r!.method, r!.url.replace(/:[A-Za-z]+/g, ':p')), entry.route).toBe('delegated');
      // CRM only in v1, and never outreach, auth or account
      expect(entry.route, entry.route).toMatch(/^(GET|POST|PATCH|DELETE) \\/v1\\/orgs\\/:p\\/(crm(\\/|$)|entitlements$|members$)/);
      expect(entry.route).not.toMatch(/outreach|\\/auth\\/|\\/account/);
    }
    expect(new Set(DESKTOP_DELEGATED_SURFACES.map((e) => e.route)).size).toBe(DESKTOP_DELEGATED_SURFACES.length);
  });

  it('W2: the host routes that are session-only for every credential are exactly this list (a route added to the host list without classification fails here)', () => {
    const host = registeredRoutes().filter((r) => desktopRouteDoor(r.method, desktopRouteKey(r.url)) === 'host');
    const sessionOnly = host
      .filter((r) => userTokenRoutePolicy(r.method, r.url, authPlugin.isApiKeyReachableRoute(r.method, r.url)).signedInPersonOnly)
      .map((r) => `${r.method} ${r.url}`)
      .sort();
    expect(sessionOnly).toEqual([...W2_ROUTES].sort());
  });

  it('W3 and the base reads are real host routes, and the waiver never names a route outside the machine-enrollment pair', () => {
    const hostKeys = new Set(registeredRoutes().filter((r) => desktopRouteDoor(r.method, desktopRouteKey(r.url)) === 'host').map((r) => key(r.method, r.url)));
    expect([...HOST_APPROVAL_WAIVED_ROUTES].sort()).toEqual(['POST /v1/me/machine-enrollments', 'POST /v1/me/machine-enrollments/:p/cancel']);
    for (const k of [...HOST_APPROVAL_WAIVED_ROUTES, ...HOST_BASE_READ_ROUTES]) expect(hostKeys.has(k), k).toBe(true);
  });
});

/** Filled from the first run (see the snapshot's `host` rows with `refused:signed_in_person`); a change is a deliberate edit. */
const W2_ROUTES: readonly string[] = [];""")
open(p, 'w').write(s)
print('ok')
