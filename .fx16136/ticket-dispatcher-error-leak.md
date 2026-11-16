The job-dispatcher can put job secrets into its 422 error body, the API log and the job row. This affects the live self-host release.

Source: #16148 PEM spec v1 adversarial review, finding S2. The lead confirmed it in code at the released base b3604eae and at PR 1370 c4a1d054 and relayed it on 2026-11-16. It is not the user's request. No secret value was read for this ticket.

**Code path**
- apps/job-dispatcher/src/docker.ts, around line 216: when `docker run` fails, the message is built from `stderr || err.message`.
- Node's execFile error message is `Command failed: <the full command line>`. That command line includes every `-e KEY=VALUE` (docker.ts, around line 191), so it holds every job secret passed to that kind, for example DATABASE_URL.
- err.message is used whenever stderr is empty: the docker CLI exits nonzero without writing to stderr, it is killed, or maxBuffer overflows.
- Even a non-empty stderr can echo the argv back.
- apps/job-dispatcher/src/server.ts, around line 166-171: the 422 body carries `error: error.message`.
- The API then:
  - logs the first 300 characters for transcription launches (recordings/routes.ts, defaultTranscribeSpawner);
  - stores the message in intelligence jobs' lastErrorMessage (packages/db, up to 1000 characters). That column may be shown to org users.

**Fix**
- Never put err.message or err.cmd into a returned or logged message.
- Use stderr only, after redacting every env value passed to that launch by exact substring.
- Cap the length.
- Tests, failing first, each asserting that a 32-character or longer fake secret marker (raw, base64, hex and JSON-escaped forms) is absent from the 422 body, the dispatcher log, the API log line and the job row:
  - a stub docker that exits 1 with empty stderr;
  - a stub whose stderr echoes its argv;
  - a maxBuffer overflow;
  - a killed process.

**Can it ship on its own ahead of #16148?** Yes. It is a self-contained dispatcher change (docker.ts error text and its tests). It does not depend on the derive script, the mount or the `--env-file` change, and it protects the secrets passed today. It ships with any release that builds the job-dispatcher image (the #16136 release builds it). Main decides the order and whether it rides with #16136.

**Acceptance:** the tests above pass, and the 422 body for a docker failure still carries the redacted stderr text, so operators can diagnose the failure.
