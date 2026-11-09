/**
 * goodqa#15561 S1a: the bearer half of the AC-13 parity test, written BEFORE the gate is extracted into
 * `applyUserTokenRoutePolicy` and green on the baseline by design: it pins what a bearer token is answered on the 40+ routes
 * of `user-token-parity-fixtures.ts` for five token shapes (read-only, read+crm, read+write, narrowed by orgIds, and one that
 * asks first). The extraction must leave every answer byte-identical (NEG-15); S1b's bound-session test compares its answers
 * to these. Regenerate only on purpose: `UPDATE_BEARER_PARITY=1`.
 */
import { mkdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { resetUserTokenLimitersForTests } from '../src/modules/user-tokens/auth-gate';
import { createTestApp, enableUserTokensForTests, resetDb, type TestContext } from './helpers';
import { PARITY_ROUTES, answerOf, fill, setupParityWorld } from './user-token-parity-fixtures';

type H = Record<string, string>;
const SNAPSHOT = join(__dirname, 'snapshots', 'bearer-parity.json');
let ctx: TestContext;
beforeAll(async () => { ctx = await createTestApp(); });
afterAll(async () => { await ctx?.close(); });
beforeEach(async () => { await resetDb(ctx.db); });
const inj = (method: string, url: string, headers: H, payload?: unknown) =>
  ctx.app.inject({ method: method as 'POST', url, headers, ...(payload === undefined ? {} : { payload: payload as object }) });

async function mint(owner: { headers: H }, body: Record<string, unknown>) {
  await enableUserTokensForTests(ctx.db);
  const step = await inj('POST', '/v1/auth/webauthn/step-up', owner.headers, { method: 'password', password: 'password123', purpose: 'user_tokens_manage' });
  const res = await inj('POST', '/v1/me/user-tokens', owner.headers, { name: 'parity', ...body, stepUpToken: step.json().stepUpToken });
  expect(res.statusCode, res.body).toBe(201);
  return { authorization: `Bearer ${(res.json() as { token: string }).token}` } as H;
}

describe('bearer parity baseline (goodqa#15561 S1a, AC-13 bearer half)', () => {
  it('answers every parity route for every token shape exactly as pinned', async () => {
    const { owner, other, ids } = await setupParityWorld(ctx);
    const tokens: Record<string, H> = {
      read: await mint(owner, { abilities: ['read'], requireHumanApproval: false }),
      readCrm: await mint(owner, { abilities: ['read', 'crm'], requireHumanApproval: false }),
      readWrite: await mint(owner, { abilities: ['read', 'write'], requireHumanApproval: false }),
      orgNarrowed: await mint(owner, { abilities: ['read', 'write', 'crm', 'data.delete'], orgIds: [other.id], requireHumanApproval: false }),
      asksFirst: await mint(owner, { abilities: ['read', 'write', 'crm', 'data.delete'], requireHumanApproval: true }),
    };
    const out: Record<string, string> = {};
    for (const [name, headers] of Object.entries(tokens)) {
      resetUserTokenLimitersForTests();
      for (const r of PARITY_ROUTES) {
        const res = await inj(r.method, fill(r.url, ids), headers, r.body);
        out[`${name} ${r.method} ${r.url}`] = answerOf(res);
      }
    }
    const text = `${JSON.stringify(out, null, 1)}\n`;
    if (process.env.UPDATE_BEARER_PARITY === '1') { mkdirSync(join(__dirname, 'snapshots'), { recursive: true }); writeFileSync(SNAPSHOT, text); }
    expect(existsSync(SNAPSHOT), 'snapshot missing: UPDATE_BEARER_PARITY=1').toBe(true);
    expect(text).toBe(readFileSync(SNAPSHOT, 'utf8'));
    expect(PARITY_ROUTES.length).toBeGreaterThanOrEqual(30);
  }, 240_000);
});
