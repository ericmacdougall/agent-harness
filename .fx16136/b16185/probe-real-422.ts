// goodqa#16185 PENDING_REAL_TEST 16185-real-422 (non-editing probe, fake values only).
// The real buildServer and realDockerDeps call the real docker CLI, which talks to a real
// create-guard in front of the real docker.sock. On main the guard has no hold, so the held case
// uses the #16136 guard from bt-guard (3e478c28) when GUARD_SRC is given.
// Usage (in apps/job-dispatcher of the 16185 worktree): GUARD_SRC=<path to create-guard.ts> npx tsx <this> <out.json>
import type { AddressInfo } from 'node:net';
import { writeFileSync } from 'node:fs';
import { buildServer, realDockerDeps } from './src/server';
import { loadConfig } from './src/config';

const MARKER = 'FAKEsecretMARKER0123456789abcdefghijKLMN';
const guardMod = await import(process.env.GUARD_SRC ?? './src/create-guard');
const guard = guardMod.createGuardServer({
  upstream: { socketPath: '/var/run/docker.sock' },
  allowedImages: ['postgres:16'],
  heldEnv: { key: 'TRANSCODER_MODE', value: 'transcribe' },
});
await new Promise<void>((r) => guard.listen(0, '127.0.0.1', r));
process.env.DOCKER_HOST = `tcp://127.0.0.1:${(guard.address() as AddressInfo).port}`;

const lines: string[] = [];
const config = {
  ...loadConfig({
    JOB_DISPATCH_TOKEN: 'probe-token-not-real',
    JOB_IMAGE_SCAN: 'busybox:1.36',
    JOB_IMAGE_TRANSCODE: 'postgres:16',
    JOB_IMAGE_INTELLIGENCE_WORKER: 'postgres:16',
    JOB_IMAGE_SUGGEST_FIX_WORKER: 'postgres:16',
  }),
  jobBaseEnv: {
    scan: { API_KEY: MARKER },
    transcode: { GCS_BUCKET: MARKER, SHORT_FLAG: '1', REGION: 'europe-west1' },
    'intelligence-worker': {},
    'suggest-fix-worker': {},
  },
};
const app = buildServer(config, realDockerDeps, { logStream: { write: (l: string) => lines.push(l) } });
const auth = { authorization: 'Bearer probe-token-not-real' };
const held = await app.inject({ method: 'POST', url: '/jobs/transcode/run', headers: auth, payload: { env: { TRANSCODER_MODE: 'transcribe' } } });
const notAllowed = await app.inject({ method: 'POST', url: '/jobs/scan/run', headers: auth, payload: {} });
await app.close();
await new Promise((r) => guard.close(r));
const all = [held.body, notAllowed.body, ...lines].join('\n');
const leaked = [];
for (let i = 0; i + 8 <= MARKER.length; i += 1) if (all.includes(MARKER.slice(i, i + 8))) leaked.push(i);
const out = {
  held: { status: held.statusCode, body: held.json() },
  notAllowlisted: { status: notAllowed.statusCode, body: notAllowed.json() },
  logLines: lines.length,
  markerWindowsLeaked: leaked.length,
  heldTagPresent: held.body.includes('TRANSCODER_MODE=transcribe is held on this guard'),
};
writeFileSync(process.argv[2], JSON.stringify(out, null, 1));
console.log(JSON.stringify({ heldStatus: out.held.status, naStatus: out.notAllowlisted.status, leaked: leaked.length, tag: out.heldTagPresent }));
process.exit(0);
