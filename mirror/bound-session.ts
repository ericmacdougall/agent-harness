import { and, eq } from 'drizzle-orm';
import { userTokens, users, type DbOrTx } from '@bugtracker/db';
import { expandUserTokenAbilities } from '@bugtracker/shared';
import { DESKTOP_SESSION_LIVE_ABILITIES } from '../../lib/desktop-token-session';
import { userTokensPlatformAllows, type UserTokenCredential } from './auth-gate';
import { userTokenChainState } from './service';

/**
 * goodqa#15561 D2: the minting token of a desktop session bound to it (`user_token_desktop:<id>:<fingerprint>`), loaded fresh
 * on EVERY bound request as the full `UserTokenRow` the token gate needs (owner, secret generation, abilities, `orgIds`,
 * `projectIds`, `conversationScope`, `requireHumanApproval`, `createdVia`, chain-live end). Nothing is cached, so a narrowing,
 * a revoke, an expiry, a rotation or the platform kill switch applies on the next request, on both doors.
 *
 * `ok: false` ends the session (the caller answers 401 and revokes the session row, `user_token_ended`).
 */
export type BoundTokenLoad = { ok: true; credential: UserTokenCredential } | { ok: false; reason: BoundEndReason };
export type BoundEndReason = 'malformed' | 'not_found' | 'rotated' | 'kind' | 'revoked' | 'expired' | 'ability' | 'switch_off';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Token kinds that may be the bound token: a token the owner minted signed in (`session`), legacy through a parent token
 * (`user_token`), or by the operator script (`operator`: the orchestrator token, every ability, no expiry; bound to it a session
 * gets the base reads and the delegated CRM door but NO host waivers, so it reaches no machine route the token is refused by bearer). `oauth` (an MCP grant, whose abilities cannot include
 * `desktop_signin`), `commander_turn` (a server-created per-turn credential) and `pairing` are refused (goodqa#15561 Q9).
 * `operator` is admitted because the operator script mints it with `desktop_signin` and the live desktop may be bound to one:
 * refusing it would end that session on deploy. Defense in depth only, the token gate is the boundary (a legacy child minted
 * by a parent token is `user_token` whatever the root).
 */
export const BOUND_ALLOWED_CREATED_VIA: ReadonlySet<string> = new Set(['session', 'user_token', 'operator']);

export async function loadBoundUserToken(db: DbOrTx, userId: string, tokenId: string, fingerprint: string, now = new Date()): Promise<BoundTokenLoad> {
  if (!UUID.test(tokenId) || !/^[0-9a-f]{16}$/.test(fingerprint)) return { ok: false, reason: 'malformed' };
  const [found] = await db
    .select({ token: userTokens, user: { id: users.id, email: users.email, name: users.name } })
    .from(userTokens)
    .innerJoin(users, eq(users.id, userTokens.userId))
    .where(and(eq(userTokens.id, tokenId), eq(userTokens.userId, userId)))
    .limit(1);
  if (!found) return { ok: false, reason: 'not_found' };
  const { token } = found;
  // Secret generation: a rotation changes the stored hash, so a session started under an older secret is dead.
  if (token.tokenHash.slice(0, 16) !== fingerprint) return { ok: false, reason: 'rotated' };
  if (!BOUND_ALLOWED_CREATED_VIA.has(token.createdVia)) return { ok: false, reason: 'kind' };
  if (token.revokedAt) return { ok: false, reason: 'revoked' };
  const chain = await userTokenChainState(db, token.id, userId);
  if (!chain.found || chain.revoked) return { ok: false, reason: 'revoked' };
  if (chain.endsAt && chain.endsAt.getTime() <= now.getTime()) return { ok: false, reason: 'expired' };
  const held = expandUserTokenAbilities(token.abilities);
  if (!DESKTOP_SESSION_LIVE_ABILITIES.every((a) => held.has(a))) return { ok: false, reason: 'ability' };
  if (!(await userTokensPlatformAllows(db, token))) return { ok: false, reason: 'switch_off' };
  return { ok: true, credential: { token, user: found.user, effectiveExpiresAt: chain.endsAt } };
}
