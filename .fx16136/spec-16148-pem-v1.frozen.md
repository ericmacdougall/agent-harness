# Spec: Self-host dispatcher job env missing keys: intelligence, suggest-fix, transcription and frames fail after #16136 images ship (key names only)

Ticket: GoodQA goodqa#16148
Author: agent:a9dc66afb96703739 (claude-opus-5-5)
Click-test: required
Sign-off: main
Review-policy: standard
Revision: v1, the GitHub App private key path only (main's choice 2b, a file-mounted secret, relayed by the lead 2026-11-16; not the user's words). Reviews required: two, from different models (secret handling).

## Outcome

The intelligence worker on self-host production receives GITHUB_APP_PRIVATE_KEY without any person or agent copying, typing or reformatting the key: a host-side script derives a root-held file from the existing /etc/goodqa/api.env on every deploy, the job dispatcher reads that file when it launches an intelligence job, and no log, record or command output ever contains the value. intelligence-worker stays held until this is live and the other missing keys are set.

## Scope

- In:
  - infra/selfhost/app/derive-job-secrets.sh (new, runs on the app host as root): derives /etc/goodqa/job-secrets/github-app-private-key from the GITHUB_APP_PRIVATE_KEY line of /etc/goodqa/api.env.
  - infra/selfhost/app/compose.yaml: the job-dispatcher service mounts /etc/goodqa/job-secrets read-only at /run/goodqa-secrets; nothing else mounts it (the create-guard still refuses Binds and Mounts for job containers, create-guard.ts around line 220, so job containers never see the file).
  - apps/job-dispatcher/src/config.ts and server.ts: a `JOB_ENV_KIND__VAR_FILE=PATH` key supplies VAR to that kind's job env, read from the file at each launch.
  - infra/release-harness rw-ship.sh: runs the derive script on the VM before the switch, and refuses a release that unholds intelligence-worker when derivation failed.
  - The dispatcher.env key NAME `JOB_ENV_INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY_FILE=/run/goodqa-secrets/github-app-private-key` (a path, not a secret), added through the existing push-env path.
- Out:
  - The values of the other missing keys (PROJECT_INTELLIGENCE_KEYRING for intelligence and suggest-fix, GITHUB_APP_ID, API_PUBLIC_URL, GCP_PROJECT): single-line, set by a person or main through infra/selfhost/app/set-secret-env.sh, as the ticket says. No agent reads or writes a value.
  - The transcription provider decision (no Vertex AI, the user's standing rule): main's call.
  - Lifting the intelligence hold: a separate, sourced release decision after AC-1 to AC-8 pass.
  - The existing exposure of every job secret in the job container's config and the dispatcher's `docker run -e` argv (docker.ts line 191): unchanged here, named as a risk.

## Acceptance criteria

- AC-1: Derivation. `derive-job-secrets.sh` reads only the GITHUB_APP_PRIVATE_KEY line of /etc/goodqa/api.env (root:root 0600) and writes its value byte for byte (no decoding: the worker's decodePrivateKey, apps/intelligence-worker/src/github.ts:51, accepts raw or base64 PEM) to /etc/goodqa/job-secrets/github-app-private-key, owner the dispatcher image's runtime uid (`node`, read from the image, never assumed), mode 0400, directory 0500 with the same owner. It writes a temporary file in that directory under umask 077, fsyncs it and renames it into place; an unchanged value leaves the file untouched (compared with cmp, never printed). Its only output is `job secret github-app-private-key: written|unchanged|REFUSED REASON` (REASON is a fixed phrase). Verify by: bats or pytest with a fake api.env holding a fake key: owner, mode, byte equality, idempotency (mtime unchanged on a second run), no temp file left after a kill between write and rename. Source: inferred: from ticket:GoodQA goodqa#16148 -- main's choice 2b (relayed by the lead), host-side derive on every deploy
- AC-2: Mount. Only the job-dispatcher service mounts /etc/goodqa/job-secrets, read-only, at /run/goodqa-secrets. Verify by: real `docker compose config` shows the bind on job-dispatcher only, `read_only: true`, and no other service has it. Source: inferred: from ticket:GoodQA goodqa#16148 -- least privilege
- AC-3: Injection. For a key `JOB_ENV_KIND__VAR_FILE`, the dispatcher reads the file at each launch of that kind and passes VAR with the file's content (one trailing newline removed) in the job env, the same way JOB_ENV_KIND__VAR does today (config.ts parseJobBaseEnv). The path must be an absolute path under /run/goodqa-secrets/, a regular file (not a symlink), at most 64 KiB. Other kinds are unaffected. Verify by: vitest on buildServer with a temp secrets dir: the docker run args carry VAR for that kind only. Source: inferred: from ticket:GoodQA goodqa#16148 -- the existing JOB_ENV mechanism, extended by name
- AC-4: Fail closed per kind. If the file is missing, unreadable, empty, a symlink, over 64 KiB or outside the allowed directory, or both VAR and VAR_FILE are set for the kind, a launch of that kind answers 501 with a named error (`job env file for KIND__VAR: REASON`), never invokes docker, and logs the same named error with the key name and path only. 501 is definitive_not_started for the API (job-dispatch.ts:112), so intelligence jobs are re-queued with attempts restored, as for a held kind. Boot never fails on this, so other kinds keep running; boot logs one status line per _FILE key (ok or the named error). Verify by: vitest, one case per reason, asserting status 501, deps.run not called, and the log line. Source: inferred: from ticket:GoodQA goodqa#16148 -- fail closed without taking down other kinds
- AC-5: No value anywhere. With a fake key whose value contains a unique marker, none of these contains the marker or any 16-byte substring of it: the derive script's stdout and stderr, rw-ship's output and run directory, the dispatcher's log (boot, launch, every refusal), the API's view of the 501 body, and the test runner's output. Verify by: the fake-key tests above grep every captured stream and file for the marker. Source: ticket:GoodQA goodqa#16148
- AC-6: Release wiring. rw-ship runs the derive script on the VM after the image load and before the switch, on every deploy. If it reports REFUSED and intelligence-worker is not held, the release refuses before the switch (exit 2, nothing switched); if intelligence-worker is held, it warns and continues. The deploy record carries the status word only. Verify by: pytest in infra/release-harness with the fake VM: written, unchanged, REFUSED with hold, REFUSED without hold. Source: inferred: from ticket:GoodQA goodqa#16148 -- intelligence-worker stays held until this works
- AC-7: Rotation. When the GITHUB_APP_PRIVATE_KEY line in api.env changes, the next deploy rewrites the file, and the next intelligence launch carries the new value without a dispatcher restart (the file is read per launch). Verify by: a test that runs derive, launches, changes the fake value, re-derives, launches again and sees the new value in the second launch's env and never the old one. Source: inferred: from ticket:GoodQA goodqa#16148 -- rotation must not need a person
- AC-8: Live, names only. After an authorized deploy: on the app host, read-only, `stat -c '%U %a %s'` of the derived file (owner, mode, nonzero size; never its content) and the dispatcher boot status line `ok` for INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY_FILE. The end-to-end intelligence check (goodqa#16136 AC-12 Level 2) runs only after main lifts the hold. Verify by: the live-test record. Source: ticket:GoodQA goodqa#16148

## Negative cases

- NEG-1 (AC-1): api.env without a GITHUB_APP_PRIVATE_KEY line, with two such lines, with an empty value, or unreadable: REFUSED with a named reason, the existing derived file left as it was, nothing printed but the status line. Source: inferred: from ticket:GoodQA goodqa#16148 -- a missing or malformed source must never overwrite a good derived file
- NEG-2 (AC-1): /etc/goodqa/job-secrets is a symlink, is owned by another user, or the target file is a symlink: REFUSED, nothing written through the link. Source: inferred: from ticket:GoodQA goodqa#16148 -- untrusted paths on a shared host
- NEG-3 (AC-4): missing file; unreadable file (mode 000); empty file; file of only a newline; symlink to a readable file; 65 KiB file; path outside /run/goodqa-secrets (including `..` traversal); both JOB_ENV_INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY and its _FILE set. Each answers 501 with its own named error, no docker call, no value in the log. Source: inferred: from ticket:GoodQA goodqa#16148 -- lead's list (missing or unreadable, empty, both KEY and KEY_FILE)
- NEG-4 (AC-5): a test-only broken variant that logs the merged env on refusal must fail the no-value test (proves the test is not vacuous). Source: inferred: from ticket:GoodQA goodqa#16148 -- the no-value test must not pass vacuously
- NEG-5 (AC-7): rotation while a launch reads the file: the reader sees the old or the new value, never a partial file (rename is atomic in the same directory). Source: inferred: from ticket:GoodQA goodqa#16148 -- concurrent rotation and launch
- NEG-6 (AC-6): derive REFUSED with SELFHOST_JOB_HOLD=none: the release refuses before the switch and the live stack is unchanged. Source: inferred: from ticket:GoodQA goodqa#16148 -- no unheld launch without its key
- NEG-7 (AC-3): a request body env that sets GITHUB_APP_PRIVATE_KEY or *_FILE cannot override or read the file (the request env cannot name a _FILE key, and the request env still merges over base as today only for allowed keys). Source: inferred: from ticket:GoodQA goodqa#16148 -- the request body is untrusted input

## Resource budget

Host: vm:t2-dev
Capacity: 110 GB memory, 48 cores, 643 GB disk (50 GB free; stop under 30 GB)
Fan-out: agents=0 jobs=1 processes=4 browser_pages=0 test_workers=1
Peak memory: 2 GB (method: the existing release-harness and dispatcher vitest suites on t2-dev peak under 2 GB)
CPU: 2 cores (method: same suites)
Disk: 1 GB (method: test fixtures and temp dirs only, no image builds)
Network: 10 MB (method: git push of small diffs)
Wall time: 30 min
Cap and kill: timeout 900 on each pytest or vitest run; nothing long-running
Checkpoint: each green step committed and pushed on the feature branch; tests are idempotent and use temp dirs under the run's SCRATCH, so it resumes by rerunning the same test command from the last pushed commit

## Risks

- Every job secret, this one included, is already passed as `docker run -e` and so appears in the job container's config and the docker CLI's argv on the host (docker.ts:191): readable by root and the docker group. Not changed here; follow-up to move job env to an env-file or stdin.
- The derive script copies a secret between root-held files on the host. It is reviewed as security code; it never echoes, logs, hashes or transmits the value, and the tests prove it with a fake key.
- The derived file's owner is the dispatcher image's runtime uid; if a future image changes its user, the read fails closed (AC-4) and intelligence launches answer 501 until the next derive.
- The worker receives the value exactly as stored in api.env. If api.env holds a form decodePrivateKey does not accept, the worker fails at its own startup with its own error (Level 2), never silently.
- Domain: auth/secrets. Two reviews from different models are required before attach.
