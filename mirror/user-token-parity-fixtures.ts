/**
 * goodqa#15561: the routes the bearer-vs-bound parity checks (AC-13) walk, drawn from the route census. Shared by the
 * bearer half (user-token-bearer-parity.test.ts, green on the baseline by design) and the bound-session half
 * (user-token-desktop-session-delegation.test.ts). `:org`, `:other` and `:seg` are filled per test.
 */
import { eq, sql } from 'drizzle-orm';
import { organizations } from '@bugtracker/db';
import { createOrg, signupUser, type TestContext } from './helpers';

export interface ParityRoute { method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'; url: string; body?: unknown; note?: string }

const ZERO = '00000000-0000-4000-8000-000000000000';

export const PARITY_ROUTES: readonly ParityRoute[] = [
  // host door today (lib/desktop-token-session.ts ALLOWED)
  { method: 'GET', url: '/v1/me' },
  { method: 'GET', url: '/v1/orgs' },
  { method: 'GET', url: '/v1/notifications' },
  { method: 'GET', url: '/v1/notifications/unread-count' },
  { method: 'GET', url: '/v1/desktop/update-status' },
  { method: 'GET', url: '/v1/me/machines' },
  { method: 'GET', url: `/v1/machines/${ZERO}` },
  { method: 'POST', url: `/v1/machines/${ZERO}/presence-challenge`, body: {} },
  { method: 'POST', url: `/v1/machines/${ZERO}/browser-setup`, body: {} },
  { method: 'GET', url: '/v1/me/remote-control/catalog' },
  { method: 'GET', url: '/v1/me/machine-enrollments' },
  { method: 'POST', url: '/v1/me/machine-enrollments', body: {} },
  { method: 'GET', url: `/v1/me/machine-enrollments/${ZERO}` },
  { method: 'POST', url: `/v1/me/machine-enrollments/${ZERO}/cancel`, body: {} },
  { method: 'GET', url: '/v1/orgs/:org/machines' },
  { method: 'GET', url: '/v1/orgs/:org/personas' },
  { method: 'GET', url: '/v1/orgs/:org/api-keys/agents' },
  { method: 'GET', url: '/v1/orgs/:org/machines/remote-sessions' },
  { method: 'GET', url: '/v1/orgs/:org/machines/remote-sessions/availability' },
  { method: 'GET', url: `/v1/orgs/:org/machines/remote-sessions/${ZERO}` },
  { method: 'POST', url: `/v1/orgs/:org/machines/remote-sessions/${ZERO}/stop`, body: {} },
  { method: 'POST', url: `/v1/orgs/:org/machines/remote-sessions/${ZERO}/renew`, body: {} },
  { method: 'GET', url: `/v1/orgs/:org/machines/remote-sessions/${ZERO}/agent-browser/consent` },
  // CRM (the v1 delegated surface) and the page-support reads
  { method: 'GET', url: '/v1/orgs/:org/crm/contacts' },
  { method: 'GET', url: '/v1/orgs/:org/crm/companies' },
  { method: 'GET', url: '/v1/orgs/:org/crm/segments' },
  { method: 'GET', url: '/v1/orgs/:org/crm/segments/:seg' },
  { method: 'GET', url: '/v1/orgs/:org/crm/segments/:seg/preview' },
  { method: 'GET', url: '/v1/orgs/:org/crm/records?kind=contact' },
  { method: 'POST', url: '/v1/orgs/:org/crm/contacts', body: { firstName: 'Parity', lastName: 'Probe', email: 'parity-probe@example.test' } },
  { method: 'DELETE', url: '/v1/orgs/:org/crm/segments/:seg' },
  { method: 'GET', url: `/v1/orgs/:org/crm/contacts/${ZERO}`, note: 'session-only for every token' },
  { method: 'GET', url: '/v1/orgs/:org/crm/contacts/export', note: 'session-only for every token' },
  { method: 'GET', url: '/v1/orgs/:org/entitlements' },
  { method: 'GET', url: '/v1/orgs/:org/members' },
  // Messages
  { method: 'GET', url: '/v1/orgs/:org/chat/sidebar-v2' },
  { method: 'GET', url: `/v1/chat/conversations/${ZERO}/messages` },
  { method: 'POST', url: `/v1/chat/conversations/${ZERO}/messages`, body: { body: 'parity' } },
  { method: 'POST', url: '/v1/notifications/read-all', body: {} },
  { method: 'PATCH', url: '/v1/notifications/dnd', body: {} },
  { method: 'POST', url: `/v1/chat/conversations/${ZERO}/messages/${ZERO}/secure/reveal`, body: {} },
  // never delegable
  { method: 'POST', url: '/v1/me/user-tokens', body: { name: 'x', abilities: ['read'] } },
  { method: 'DELETE', url: '/v1/account', body: { confirmEmail: 'x@example.test' } },
  { method: 'POST', url: '/v1/orgs/:org/api-keys', body: { name: 'k', scopes: ['read'] } },
];

export function fill(url: string, ids: { org: string; other?: string; seg: string }): string {
  return url.replace(':org', ids.org).replace(':other', ids.other ?? ids.org).replace(':seg', ids.seg);
}

/** `status code` of a response: what the gate (or, past it, the handler) answered. Never a body. */
export function answerOf(res: { statusCode: number; json: () => unknown }): string {
  let code = '';
  try { code = (res.json() as { error?: { code?: string } })?.error?.code ?? ''; } catch { /* not JSON */ }
  return `${res.statusCode} ${code}`.trim();
}

/**
 * Two orgs the owner belongs to (CRM on, plan pro so writes are entitled), one saved view in the first, and the machines
 * surface switched on (without it every machine route is the router's own bare 404 and the gate is never reached).
 */
export async function setupParityWorld(ctx: TestContext) {
  const owner = await signupUser(ctx.app, { name: 'Owner' });
  await ctx.db.execute(sql`insert into platform_settings (key, value, value_type, updated_by, reason)
    values ('machines.enabled', '"all"'::jsonb, 'string', ${owner.user.id}::uuid, 'parity test')
    on conflict (key) do update set value = excluded.value`);
  const org = await createOrg(ctx.app, owner.headers, 'Parity Org');
  const other = await createOrg(ctx.app, owner.headers, 'Other Org');
  for (const id of [org.id, other.id]) {
    await ctx.db.update(organizations).set({ plan: 'pro', entitlementOverrides: { 'crm.v2.records': true, 'crm.api.enabled': true } }).where(eq(organizations.id, id));
  }
  const seg = await ctx.app.inject({ method: 'POST', url: `/v1/orgs/${org.id}/crm/segments`, headers: owner.headers,
    payload: { name: 'Parity view', subjectKind: 'contact', filterJson: { clauses: [{ kind: 'attribute', key: 'hasEmail', op: 'eq', value: true }] } } });
  if (seg.statusCode !== 201) throw new Error(`parity segment: ${seg.statusCode} ${seg.body}`);
  const segId = (seg.json() as { segment: { id: string } }).segment.id;
  return { owner, org, other, segId, ids: { org: org.id, other: other.id, seg: segId } };
}
