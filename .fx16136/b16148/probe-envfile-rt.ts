// goodqa#16148 AC-6 (2) real-engine round trip (fake values only). The real dockerRunDetached
// (--env-file) drives the real docker CLI through a real create-guard (bt-guard 3e478c28 source,
// with the transcribe hold) into the real daemon. The job prints its env as hex; the probe
// compares the bytes with the intended env.
// Usage (apps/job-dispatcher of the step-2 worktree): GUARD_SRC=<create-guard.ts> npx tsx <this> <out.json>
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { writeFileSync } from 'node:fs';
import type { AddressInfo } from 'node:net';
import { dockerRunDetached } from './src/docker';
import { JOB_SECURITY_PROFILE } from './src/jobs';

const run = promisify(execFile);
const IMAGE = 'busybox:1.36';
const guardMod = await import(process.env.GUARD_SRC!);
const guard = guardMod.createGuardServer({
  upstream: { socketPath: '/var/run/docker.sock' },
  allowedImages: [IMAGE],
  heldEnv: { key: 'TRANSCODER_MODE', value: 'transcribe' },
});
await new Promise<void>((r) => guard.listen(0, '127.0.0.1', r));
process.env.DOCKER_HOST = `tcp://127.0.0.1:${(guard.address() as AddressInfo).port}`;

const env: Record<string, string> = {
  V_LEAD: '  leading',
  V_INNER: 'in  ner',
  V_TRAIL: 'trailing  ',
  V_EQ: 'a=b==c',
  V_HASH: '#x # y',
  V_EMPTY: '',
  V_QUOTES: `"d" 'q'`,
  V_BACKSLASH: 'a\\b\\\\c\\n',
  V_UTF8: 'café 日本 \u{1F600}',
  // base env key names of every restored job kind, with fake values
  DATABASE_URL: 'postgres://fake:fake@db/fake',
  OPENROUTER_API_KEY: 'sk-fake-0000',
  GCS_BUCKET: 'fake-bucket',
  PROJECT_INTELLIGENCE_KEYRING: 'fake-keyring',
  GITHUB_APP_ID: '12345',
  API_PUBLIC_URL: 'https://fake.example',
};
const results: Record<string, unknown> = {};
for (const [name, profile] of Object.entries(JOB_SECURITY_PROFILE)) {
  const r = await dockerRunDetached('docker', IMAGE, ['sh', '-c', 'for k in $(env | cut -d= -f1 | grep "^[VDOGPA]" ); do printf "%s=" "$k"; printenv "$k" | od -An -tx1 | tr -d " \\n"; echo; done; sleep 8'], env, 30_000, profile);
  await new Promise((res) => setTimeout(res, 3000));
  const logs = await run('docker', ['logs', r.containerId], { env: { ...process.env, DOCKER_HOST: 'unix:///var/run/docker.sock' } });
  const got: Record<string, string> = {};
  for (const line of logs.stdout.split('\n').filter(Boolean)) {
    const i = line.indexOf('=');
    got[line.slice(0, i)] = Buffer.from(line.slice(i + 1), 'hex').toString('utf8').replace(/\n$/, '');
  }
  const mismatches = Object.keys(env).filter((k) => got[k] !== env[k]);
  results[name] = { mismatches, keys: Object.keys(got).length };
}
let held = '';
try {
  await dockerRunDetached('docker', IMAGE, ['true'], { TRANSCODER_MODE: 'transcribe', FAKE: 'x' }, 30_000, JOB_SECURITY_PROFILE.transcode, ['x']);
} catch (e) {
  held = (e as Error).message;
}
results.held = held;
await new Promise((r) => guard.close(r));
writeFileSync(process.argv[2], JSON.stringify(results, null, 1));
console.log(JSON.stringify(results));
process.exit(0);
