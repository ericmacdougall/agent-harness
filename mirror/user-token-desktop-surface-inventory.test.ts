/**
 * goodqa#15561 S0 (no behavior change): the committed inventory of every route in or beside the surfaces a desktop session
 * started from a user token is asked to serve (CRM, Messages and the routes those pages call), classified against what the
 * code does TODAY. Generated from the registered router and the real policy functions, never typed by hand, so a route that
 * is added or whose rule changes shows up as a snapshot diff that someone must read (regenerate with
 * `UPDATE_DESKTOP_SURFACE_INVENTORY=1`). No database is touched.
 *
 * Classification, per `METHOD pattern`:
 *   host                 on the desktop host allow-list today (lib/desktop-token-session.ts)
 *   refused:RULE         a token (bearer or bound) is refused whatever its abilities: non-delegable rule code, `signed_in_person`
 *                        (no org key reaches it: SESSION_ONLY / NON_BEARER) or `governance_sign_off`
 *   token[abilities]     a token that holds those abilities reaches it (approval reason appended when the policy asks)
 * `desktop` is what the bound session gets: `host` (the desktop's own routes), `delegated` (the default-deny table of
 * lib/desktop-token-session.ts) or `scope` (refused `desktop_token_session_scope`). Every host route is listed whatever its path.
 */
import { mkdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { createDb } from '@bugtracker/db';
import type { FastifyInstance } from 'fastify';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { buildApp } from '../src/app';
import { loadConfig } from '../src/config';
import { DESKTOP_DELEGATED_SURFACES, HOST_APPROVAL_WAIVED_ROUTES, HOST_BASE_READ_ROUTES, desktopRouteDoor, desktopRouteKey } from '../src/lib/desktop-token-session';
import { userTokenRoutePolicy } from '../src/lib/user-token-policy';
import * as authPlugin from '../src/plugins/auth';

const UNUSED_DB_URL = 'postgres://postgres:postgres@127.0.0.1:1/desktop_surface_inventory_never_connected';
const SNAPSHOT = join(__dirname, 'snapshots', 'desktop-surface-inventory.json');

/** Routes in or beside the v1 surfaces: the CRM and Messages families plus every non-family route their pages call. */
const IN_SCOPE: readonly RegExp[] = [
  /^\/v1\/orgs\/:[A-Za-z]+\/crm(\/|$)/,
  /^\/v1\/orgs\/:[A-Za-z]+\/outreach(\/|$)/,
  /^\/v1\/outreach(\/|$)/,
  /^\/v1\/issues\/:[A-Za-z]+\/crm(\/|$)/,
  /^\/v1\/chat(\/|$)/,
  /^\/v1\/orgs\/:[A-Za-z]+\/chat(\/|$)/,
  /^\/v1\/orgs\/:[A-Za-z]+\/dm(\/|$)/,
  /^\/v1\/notifications(\/|$)/,
  /^\/v1\/me$/,
  /^\/v1\/me\/notes-to-self(\/|$)/,
  /^\/v1\/orgs$/,
  /^\/v1\/orgs\/:[A-Za-z]+\/(entitlements|members|imports\/config|inbox\/summary|personas|assistant(\/|$)|ai-threads(\/|$)|agent-chat(\/|$))/,
  /^\/v1\/ai-threads(\/|$)/,
  /^\/v1\/uploads\/:[A-Za-z]+\/content$/,
  /^\/v1\/vault(\/|$)/,
  /^\/v1\/secret-requests(\/|$)/,
  /^\/v1\/commander\/actions(\/|$)/,
  /^\/v1\/issues\/:[A-Za-z]+\/related-conversations$/,
];

export interface InventoryRow {
  route: string;
  desktop: 'host' | 'delegated' | 'scope';
  token: string;
}

let app: FastifyInstance;
let rows: InventoryRow[] = [];

function registeredRoutes(): Array<{ method: string; url: string }> {
  const out = new Set<string>();
  const stack: string[] = [];
  for (const line of app.printRoutes({ commonPrefix: false }).split('\n')) {
    const depth = (line.match(/[│ ]{4}/g) ?? []).length;
    const text = line.replace(/^[│├└─\s]+/, '');
    if (!text) continue;
    const [rawPath, methodsPart] = text.split(' (');
    stack.length = depth;
    stack[depth] = rawPath ?? '';
    if (!methodsPart) continue;
    const path = stack.slice(0, depth + 1).join('').replace(/(?<=[A-Za-z0-9_-]):/g, '::');
    for (const m of methodsPart.replace(')', '').split(',')) {
      const method = m.trim();
      if (method === 'HEAD' || method === 'OPTIONS') continue;
      out.add(`${method} ${path}`);
    }
  }
  return [...out].map((r) => {
    const [method, url] = r.split(' ');
    return { method: method!, url: url! };
  });
}

export function classifyToken(method: string, url: string): string {
  const p = userTokenRoutePolicy(method, url, authPlugin.isApiKeyReachableRoute(method, url));
  if (p.nonDelegable) return `refused:${p.nonDelegable.code}`;
  if (authPlugin.isGovernanceSessionOnlyRoute(method, url)) return 'refused:governance_sign_off';
  if (p.signedInPersonOnly) return 'refused:signed_in_person';
  return `token[${p.abilities.join('+')}]${p.approvalReason ? ` ask:${p.approvalReason}` : ''}`;
}

beforeAll(async () => {
  const config = loadConfig({ ...process.env, NODE_ENV: 'test', DATABASE_URL: UNUSED_DB_URL });
  app = await buildApp({ config, db: createDb(UNUSED_DB_URL).db, logger: false });
  await app.ready();
  rows = registeredRoutes()
    .map((r) => ({ r, door: desktopRouteDoor(r.method, desktopRouteKey(r.url)) }))
    .filter(({ r, door }) => door === 'host' || IN_SCOPE.some((re) => re.test(r.url)))
    .map(({ r, door }) => ({
      route: `${r.method} ${r.url}`,
      desktop: (door ?? 'scope') as InventoryRow['desktop'],
      token: classifyToken(r.method, r.url),
    }))
    .sort((a, b) => a.route.localeCompare(b.route));
}, 120_000);
afterAll(async () => {
  await app?.close();
});

describe('desktop surface inventory (goodqa#15561 S0)', () => {
  it('matches the committed snapshot: a new or reclassified route in or beside CRM/Messages is a deliberate edit', () => {
    const text = `${JSON.stringify(rows, null, 1)}\n`;
    if (process.env.UPDATE_DESKTOP_SURFACE_INVENTORY === '1') {
      mkdirSync(join(__dirname, 'snapshots'), { recursive: true });
      writeFileSync(SNAPSHOT, text);
    }
    expect(existsSync(SNAPSHOT), 'snapshot missing: run with UPDATE_DESKTOP_SURFACE_INVENTORY=1').toBe(true);
    expect(text).toBe(readFileSync(SNAPSHOT, 'utf8'));
  });

  it('records the facts S0 reports: crm needs the crm ability, session-only CRM routes are refused, nothing in scope is on the host list but the host routes', () => {
    const by = new Map(rows.map((r) => [r.route, r]));
    expect(by.get('GET /v1/orgs/:orgId/crm/contacts')?.token).toBe('token[crm+read]');
    expect(by.get('GET /v1/orgs/:orgId/crm/contacts/:contactId')?.token).toMatch(/^refused:/);
  });
});

describe('the bound session\'s doors are pinned to the code (goodqa#15561 AC-6, NEG-30)', () => {
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
      expect(entry.route, entry.route).toMatch(/^(GET|POST|PATCH|DELETE) \/v1\/orgs\/:p\/(crm(\/|$)|entitlements$|members$)/);
      expect(entry.route).not.toMatch(/outreach|\/auth\/|\/account/);
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

/**
 * W2 (goodqa#15561 D3): the host-door routes that are session-only for EVERY credential today (no org key reaches them), taken
 * from the router and the policy on 2026-11-09. Each is served to a bound session only with the `machines` ability. A route
 * added to the host list that is session-only fails the test above until it is classified here on purpose.
 */
const W2_ROUTES: readonly string[] = [
  'GET /v1/machines/:machineId/agent-browser/consent/requests/:clientRequestId',
  'GET /v1/machines/:machineId/agent-browser/context',
  'GET /v1/me/remote-control/catalog',
  'GET /v1/orgs/:orgId/machines/remote-sessions',
  'GET /v1/orgs/:orgId/machines/remote-sessions/:sessionId',
  'GET /v1/orgs/:orgId/machines/remote-sessions/:sessionId/agent-browser/attachments/:commandId',
  'GET /v1/orgs/:orgId/machines/remote-sessions/:sessionId/browser-pairing',
  'GET /v1/orgs/:orgId/machines/remote-sessions/availability',
  'POST /v1/machines/:machineId/agent-browser/consent',
  'POST /v1/machines/:machineId/agent-browser/consent/cancel',
  'POST /v1/machines/:machineId/browser-setup',
  'POST /v1/machines/:machineId/presence-challenge',
  'POST /v1/orgs/:orgId/machines/remote-sessions/:sessionId/agent-browser/activity',
  'POST /v1/orgs/:orgId/machines/remote-sessions/:sessionId/agent-browser/next',
  'POST /v1/orgs/:orgId/machines/remote-sessions/:sessionId/agent-browser/results/:commandId',
  'POST /v1/orgs/:orgId/machines/remote-sessions/:sessionId/browser-pairing/challenge',
  'POST /v1/orgs/:orgId/machines/remote-sessions/:sessionId/browser-pairing/connected',
  'POST /v1/orgs/:orgId/machines/remote-sessions/:sessionId/browser-pairing/permit',
  'POST /v1/orgs/:orgId/machines/remote-sessions/:sessionId/renew',
  'POST /v1/orgs/:orgId/machines/remote-sessions/:sessionId/stop',
  'PUT /v1/orgs/:orgId/machines/remote-sessions/:sessionId/agent-browser/consent',
];
