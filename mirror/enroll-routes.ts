/**
 * Machines ENROLLMENT routes (docs/design/machines-fullcontrol/ENROLLMENT.md). Registered INSIDE the machines plugin
 * (routes.ts), so `machines.enabled` off answers the router's own 404 first (before authentication) and the exchange
 * reads the raw body its signature covers.
 *
 * Who may call:
 *   - `/v1/me/machine-*` and `/v1/me/machines`: the person signed in, or a USER TOKEN acting as them (abilities in
 *     lib/user-token-policy.ts: `machines`, plus `tokens.create_other_keys` to mint or start). Never an org API key
 *     (SESSION_ONLY_ROUTES in plugins/auth.ts; refused here a second time), never a machine token.
 *   - `POST /v1/machine-agent/enroll`: the AGENT, proving it holds the private half of `publicKey` (NON_BEARER_ROUTES).
 *
 * None of these routes leases, commands, or reads another person's machine: a user token still cannot OPERATE machines
 * (user_token_non_delegable, rule `machines`, on every bearer machines route; ENROLLMENT.md section 5).
 */
import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { idSchema } from '@bugtracker/shared';
import { z } from 'zod';
import { isAgentCredential } from '../../../lib/credential-kind';
import { AppError, Errors } from '../../../lib/errors';
import { requireRecentAuth } from '../../../lib/platform-admin';
import { requireAuth, type AuthContext } from '../../../plugins/auth';
import { POLL_WAIT_SECONDS, TOKEN_ROTATE_AFTER_SECONDS, machinesFlag, verifyPairSignature, type AgentRequest } from '../service';
import { enrollAgentBody, enrollmentStartBody, machineTokenCreateBody, machineTokenListQuery } from './schemas';
import {
  cancelEnrollment,
  createMachineToken,
  exchangeEnrollment,
  findEnrollment,
  listEnrollments,
  listMachineTokens,
  ownMachines,
  revokeMachineToken,
  serializeEnrollment,
  serializeMachineToken,
  startEnrollment,
  withinAllowList,
  type EnrollActor,
} from './service';

const SMALL_BODY = 16 * 1024;
const FACTS_BODY = 512 * 1024;
const tokenParams = z.object({ tokenId: idSchema });
const enrollmentParams = z.object({ enrollmentId: idSchema });

/**
 * The deprecated pairing routes (ENROLLMENT.md section 6): kept working for agents already in the field, out of the
 * served document and the docs, and every answer says so.
 * TODO(2026-12-31, L-Enroll): delete both routes, the pairing-code writer and the web form once no agent has paired with
 * a code for 30 days (`select max(used_at) from machine_pairing_codes`).
 */
export const LEGACY_PAIRING_ROUTES: ReadonlySet<string> = new Set(['/v1/orgs/:orgId/machines/pairing-codes', '/v1/machine-agent/pair']);
export const LEGACY_PAIRING_DEPRECATION_LINK = '</docs/design/machines-fullcontrol/ENROLLMENT.md>; rel="deprecation"';

/** A person signed in, or a user token acting as them; never an org API key. */
function enrollActor(auth: AuthContext): EnrollActor {
  if (isAgentCredential(auth) && !auth.userTokenId) throw Errors.forbidden('Machine tokens and enrollments are a person\'s (signed in) or their user token\'s; never an org API key');
  return {
    userId: auth.userId,
    userTokenId: auth.userTokenId ?? null,
    userTokenOrgIds: auth.userTokenOrgIds ?? null,
    userTokenExpiresAt: auth.userTokenExpiresAt ?? null,
  };
}

export function registerMachineEnrollRoutes(app: FastifyInstance, deps: { apiUrl: () => string }): void {
  const r = app.withTypeProvider<ZodTypeProvider>();
  const authenticate = app.authenticate;

  // Deprecation notice on the two legacy pairing answers (behaviour otherwise byte-for-byte unchanged).
  app.addHook('onSend', async (req, reply, payload) => {
    if (LEGACY_PAIRING_ROUTES.has(req.routeOptions?.url ?? '')) {
      reply.header('deprecation', 'true');
      reply.header('link', LEGACY_PAIRING_DEPRECATION_LINK);
    }
    return payload;
  });

  /** A real session needs a recent sign-in to bring a machine in (the old pairing code's rule); a user token cannot prove one and needs none. */
  const recentIfSession = async (req: FastifyRequest, auth: AuthContext) => {
    if (!auth.userTokenId) await requireRecentAuth(app.db, req);
  };
  const enrollCommand = (flag: '--token' | '--exchange', value: string) => `goodqa-machine enroll ${flag} ${value} --api ${deps.apiUrl()}`;

  // -- machine tokens ---------------------------------------------------------------------------------------------

  r.post('/me/machine-tokens', { preHandler: authenticate, bodyLimit: SMALL_BODY, schema: { body: machineTokenCreateBody } }, async (req, reply) => {
    const auth = requireAuth(req);
    const actor = enrollActor(auth);
    await recentIfSession(req, auth);
    const { row, token } = await createMachineToken(app.db, actor, req.body);
    return reply.status(201).send({
      machineToken: serializeMachineToken(row),
      token,
      enroll: { command: enrollCommand('--token', token), exchangeRoute: 'POST /v1/machine-agent/enroll' },
    });
  });

  r.get('/me/machine-tokens', { preHandler: authenticate, schema: { querystring: machineTokenListQuery } }, async (req) => {
    const actor = enrollActor(requireAuth(req));
    const rows = (await listMachineTokens(app.db, actor.userId, req.query.status === 'active')).filter((t) => withinAllowList(actor, t.orgIds));
    return { machineTokens: rows.map((t) => serializeMachineToken(t)) };
  });

  r.post('/me/machine-tokens/:tokenId/revoke', { preHandler: authenticate, bodyLimit: SMALL_BODY, schema: { params: tokenParams } }, async (req) => {
    const actor = enrollActor(requireAuth(req));
    return { machineToken: serializeMachineToken(await revokeMachineToken(app.db, actor, req.params.tokenId)) };
  });

  // -- desktop enrollments --------------------------------------------------------------------------------------------

  r.post('/me/machine-enrollments', { preHandler: authenticate, bodyLimit: SMALL_BODY, schema: { body: enrollmentStartBody } }, async (req, reply) => {
    const auth = requireAuth(req);
    const actor = enrollActor(auth);
    await recentIfSession(req, auth);
    const { row, secret } = await startEnrollment(app.db, actor, req.body);
    return reply.status(201).send({
      enrollment: await serializeEnrollment(app.db, row),
      enrollSecret: secret,
      exchange: { command: enrollCommand('--exchange', secret), route: 'POST /v1/machine-agent/enroll' },
    });
  });

  r.get('/me/machine-enrollments', { preHandler: authenticate }, async (req) => {
    const actor = enrollActor(requireAuth(req));
    const rows = (await listEnrollments(app.db, actor.userId)).filter((e) => withinAllowList(actor, e.orgIds));
    return { enrollments: await Promise.all(rows.map((e) => serializeEnrollment(app.db, e))) };
  });

  r.get('/me/machine-enrollments/:enrollmentId', { preHandler: authenticate, schema: { params: enrollmentParams } }, async (req) => {
    const actor = enrollActor(requireAuth(req));
    const e = await findEnrollment(app.db, actor.userId, req.params.enrollmentId);
    if (!withinAllowList(actor, e.orgIds)) throw Errors.notFound('Enrollment not found');
    return { enrollment: await serializeEnrollment(app.db, e) };
  });

  r.post('/me/machine-enrollments/:enrollmentId/cancel', { preHandler: authenticate, bodyLimit: SMALL_BODY, schema: { params: enrollmentParams } }, async (req) => {
    const actor = enrollActor(requireAuth(req));
    return { enrollment: await serializeEnrollment(app.db, await cancelEnrollment(app.db, actor, req.params.enrollmentId)) };
  });

  // -- the person's own machines: metadata only (a user token may read this; it still cannot operate them) -----------

  r.get('/me/machines', { preHandler: authenticate }, async (req) => {
    const actor = enrollActor(requireAuth(req));
    const flag = await machinesFlag(app.db);
    const allowed = (orgId: string) => flag.enabledFor(orgId) && (actor.userTokenOrgIds === null || actor.userTokenOrgIds.includes(orgId));
    return { machines: await ownMachines(app.db, actor.userId, allowed) };
  });

  // -- the agent's exchange ---------------------------------------------------------------------------------------------

  r.post('/machine-agent/enroll', { bodyLimit: FACTS_BODY, schema: { body: enrollAgentBody } }, async (req, reply) => {
    const agentReq: AgentRequest = { method: req.method, url: req.url, headers: req.headers, rawBody: req.machineRawBody ?? Buffer.alloc(0) };
    // Proof of possession first (as the old pair): the body is signed by the key it registers. A request with a token
    // header is not an enrollment (the agent's own credential never enrolls anything).
    const rawNonce = req.headers['x-goodqa-machine-nonce'];
    const nonce = Array.isArray(rawNonce) ? rawNonce[0] : rawNonce;
    if (req.headers['x-goodqa-machine-token'] !== undefined || !nonce || !/^[A-Za-z0-9_-]{16,64}$/.test(nonce) || !verifyPairSignature(agentReq, req.body.publicKey)) {
      throw new AppError(401, 'machine_auth_failed', 'Machine authentication failed');
    }
    const { enrollment, machines } = await exchangeEnrollment(app.db, req.body, {
      publicKey: req.body.publicKey,
      nonce,
    });
    const list = machines.map((m) => ({ machine: { id: m.machine.id, orgId: m.machine.orgId, name: m.machine.name }, token: m.token }));
    return reply.status(201).send({
      enrollment: { id: enrollment.id, status: enrollment.status },
      machines: list,
      machine: list[0]!.machine,
      token: list[0]!.token,
      preset: enrollment.preset,
      rotateAfterSeconds: TOKEN_ROTATE_AFTER_SECONDS,
      pollWaitSeconds: POLL_WAIT_SECONDS,
      serverTime: Date.now(),
    });
  });
}

