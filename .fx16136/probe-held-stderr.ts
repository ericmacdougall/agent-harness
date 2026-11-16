// goodqa#16148 probe (non-editing): the real docker CLI's stderr for a held create through the real create-guard.
// Fake values only. Run from apps/job-dispatcher: npx tsx <this file> <out.json>
import { execFile } from 'node:child_process';
import { writeFileSync, mkdtempSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { AddressInfo } from 'node:net';
import { createGuardServer } from './src/create-guard';

const IMAGE = 'postgres:16';

function run(args: string[], env: NodeJS.ProcessEnv): Promise<{ code: number | null; stderr: string; stdout: string }> {
  return new Promise((resolve) => {
    execFile('docker', args, { env, timeout: 30_000 }, (err, stdout, stderr) => {
      resolve({ code: err ? ((err as { code?: number }).code ?? -1) : 0, stdout: String(stdout), stderr: String(stderr) });
    });
  });
}

const guard = createGuardServer({
  upstream: { socketPath: '/var/run/docker.sock' },
  allowedImages: [IMAGE],
  heldEnv: { key: 'TRANSCODER_MODE', value: 'transcribe' },
});
await new Promise<void>((r) => guard.listen(0, '127.0.0.1', r));
const port = (guard.address() as AddressInfo).port;
const env = { ...process.env, DOCKER_HOST: `tcp://127.0.0.1:${port}` };
const base = ['run', '-d', '--rm', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--read-only'];
const dir = mkdtempSync(join(tmpdir(), 'probe16148-'));
chmodSync(dir, 0o700);
const ef = join(dir, 'e');
writeFileSync(ef, 'TRANSCODER_MODE=transcribe\nFAKE_BASE=1\nREGION=europe-west1\n', { mode: 0o600 });
const results: Record<string, unknown> = {};
results.held_e = await run([...base, '-e', 'TRANSCODER_MODE=transcribe', IMAGE, 'true'], env);
results.held_envfile = await run([...base, '--env-file', ef, IMAGE, 'true'], env);
results.not_allowlisted = await run([...base, 'busybox:1.36', 'true'], env);
results.bad_ref = await run([...base, 'Not_A::ref', 'true'], env);
await new Promise((r) => guard.close(r));
results.daemon_unreachable = await run(['run', '--rm', IMAGE, 'true'], { ...process.env, DOCKER_HOST: 'tcp://127.0.0.1:1' });
writeFileSync(process.argv[2], JSON.stringify(results, null, 1));
console.log('wrote', process.argv[2]);
process.exit(0);
