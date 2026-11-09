/**
 * goodqa#15561 click-test kit: disposable seed for a LOCAL stack (never production). Reads API_URL and DATABASE_URL and
 * SECRETS_DIR from the environment. Creates a disposable owner (password in a 0600 file), one org with CRM on, a saved view,
 * a few contacts, and tokens: crm (desktop_signin+read+crm, created via the session path), nocrm (desktop_signin+read) and
 * everything-minus-nothing is NOT created. Token values and the bound session tokens go to 0600 files only; stdout carries
 * ids and file paths, never a value.
 */
import { mkdirSync, writeFileSync, chmodSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { join } from 'node:path';
import { createDb, organizations, users } from '@bugtracker/db';
import { eq, sql } from 'drizzle-orm';

const API = process.env.API_URL!;
const DIR = process.env.SECRETS_DIR!;
mkdirSync(DIR, { recursive: true, mode: 0o700 });
const { db, client } = createDb(process.env.DATABASE_URL!, { max: 2 });

async function call(method: string, path: string, headers: Record<string, string>, body?: unknown) {
  const res = await fetch(`${API}${path}`, { method, headers: { 'content-type': 'application/json', ...headers }, body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await res.text();
  let json: any = null;
  try { json = JSON.parse(text); } catch { /* not json */ }
  if (res.status >= 300) throw new Error(`${method} ${path} -> ${res.status} ${text.slice(0, 300)}`);
  return json;
}
const write = (name: string, value: string) => { const p = join(DIR, name); writeFileSync(p, value, { mode: 0o600 }); chmodSync(p, 0o600); return p; };

const email = `click-owner-${randomBytes(3).toString('hex')}@e2e.goodqa.app`;
const password = `Pw-${randomBytes(9).toString('base64url')}`;
const signup = await call('POST', '/v1/auth/signup', {}, { email, password, name: 'Click Owner' });
await db.update(users).set({ emailVerifiedAt: new Date() }).where(eq(users.email, email));
await db.execute(sql`insert into platform_settings (key, value, value_type, updated_by, reason)
  values ('userTokens.enabled', 'true'::jsonb, 'boolean', ${signup.user.id}::uuid, 'click-test kit')
  on conflict (key) do update set value = excluded.value`);
const owner = { authorization: `Bearer ${signup.tokens.accessToken}` };
const org = (await call('POST', '/v1/orgs', owner, { name: 'Click Org' })).org;
await db.update(organizations).set({ plan: 'pro', entitlementOverrides: { 'crm.v2.records': true, 'crm.api.enabled': true } }).where(eq(organizations.id, org.id));
for (const [first, last] of [['Ada', 'Lovelace'], ['Grace', 'Hopper'], ['Alan', 'Turing']]) {
  await call('POST', `/v1/orgs/${org.id}/crm/contacts`, owner, { firstName: first, lastName: last, primaryEmail: `${first.toLowerCase()}@e2e.goodqa.app` });
}
const seg = (await call('POST', `/v1/orgs/${org.id}/crm/segments`, owner, { name: 'Everyone with email', subjectKind: 'contact', filterJson: { clauses: [{ kind: 'attribute', key: 'hasEmail', op: 'eq', value: true }] } })).segment;

async function mint(name: string, abilities: string[]) {
  const step = await call('POST', '/v1/auth/webauthn/step-up', owner, { method: 'password', password, purpose: 'user_tokens_manage' });
  const r = await call('POST', '/v1/me/user-tokens', owner, { name, abilities, requireHumanApproval: false, stepUpToken: step.stepUpToken });
  return { id: r.userToken.id as string, token: r.token as string };
}
const crm = await mint('click crm', ['desktop_signin', 'read', 'crm']);
const nocrm = await mint('click no-crm', ['desktop_signin', 'read']);
const files: Record<string, string> = {
  ownerPasswordFile: write('owner.password', password),
  crmTokenFile: write('crm.token', crm.token),
  nocrmTokenFile: write('nocrm.token', nocrm.token),
};
for (const [label, t] of [['crm', crm], ['nocrm', nocrm]] as const) {
  const s = await call('POST', '/v1/me/desktop-session', { authorization: `Bearer ${t.token}` }, { client: 'desktop-ctl' });
  files[`${label}SessionAccessFile`] = write(`${label}.session.access`, s.tokens.accessToken);
  files[`${label}SessionRefreshFile`] = write(`${label}.session.refresh`, s.tokens.refreshToken);
}
console.log(JSON.stringify({ ownerEmail: email, orgId: org.id, orgSlug: org.slug, segmentId: seg.id, crmTokenId: crm.id, nocrmTokenId: nocrm.id, files }, null, 1));
await client.end();
