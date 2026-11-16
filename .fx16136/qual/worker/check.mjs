// Stand-in intelligence-worker for the PR 1377 runtime qualification kit (q7). NOT the real worker.
// It proves only that a job launched by the real job-dispatcher (through the create-guard, the docker-socket-proxy and
// the host daemon) receives GITHUB_APP_PRIVATE_KEY from the mounted key file. It prints one fixed line with no value:
//   QUAL_WORKER key=<present|absent> match=<yes|no>
// match compares sha256(GITHUB_APP_PRIVATE_KEY) with WORKER_LEASE_OWNER (the one env key a caller may set for this
// kind); the kit sends the sha256 of its own dummy key there. It stays up 8 s so the kit's sampler and log read see it.
import { createHash } from 'node:crypto';

const key = process.env.GITHUB_APP_PRIVATE_KEY;
const want = process.env.WORKER_LEASE_OWNER || '';
const got = key === undefined ? '' : createHash('sha256').update(key, 'utf8').digest('hex');
const match = key !== undefined && want.length === 64 && got === want;
console.log(`QUAL_WORKER key=${key === undefined ? 'absent' : 'present'} match=${match ? 'yes' : 'no'}`);
setTimeout(() => process.exit(match ? 0 : 1), 8000);
