# PR review packet (whole PR): goodqa#16185, the docker failure message is a category and never stderr (goodqa#16148 build step 1)

Ticket: GoodQA goodqa#16185 (also GoodQA goodqa#16148, spec v4 core 5d317b21, attached comment ef963731)
Repo: ericmacdougall/bugtracker, branch fix/16185-docker-failure-category, draft PR #1372
Base: e944908725d03a25b5730ef873229f71e6eec57d (origin/main)
Expected HEAD: 3b7cde1a97478251ff15dde8c5a9768e7b4e493b

Commits (base..HEAD):
- 127f23570fc2 fix(job-dispatcher): docker failure says a category, never stderr
- 3b7cde1a9747 test(job-dispatcher): capture server logs in the held 422 case

## Scope
apps/job-dispatcher only: src/docker.ts, src/server.ts, test/docker-failure-message.test.ts (new), test/server.test.ts (one expectation now names the new seventh argument). No API, infra or release-harness change.

## Claims to verify
1. On a docker launch failure, no 422, 504 or 500 body, and no dispatcher log line, carries docker's stderr, err.message or err.cmd. The 422 message is always `docker run failed: CATEGORY (stderr N bytes)`, with CATEGORY from a fixed set of five. (AC-7)
2. At most one allow-listed first line is appended. The held-mode guard refusal is emitted from the constant set HELD_REFUSAL_LINES and is never copied from stderr; a line that only looks like a held refusal is not trusted. (R5)
3. For any other allowed line, secret-source values are removed from the full stderr, longest first, before any cut. The line is dropped on:
   - an 8-byte window of a value in raw, base64 (three alignments), hex upper or lower, JSON-escaped or decimal-byte form, also checked with backslashes removed;
   - a value under 8 bytes appearing as a whole token;
   - any byte outside printable ASCII.
   It is then cut to 200 characters. (AC-7, NEG-11)
4. Only the kind's base env is a secret source. The server passes `Object.values(config.jobBaseEnv[kind])`, and the request env is not redacted. If `dockerRunDetached` gets no list, every env value is treated as secret. (P1, NEG-17)
5. Short base values (1, true, on, this, guard, daemon, europe-west1, held, e) never change the held line. (NEG-17, R5)
6. The tests are not vacuous: two broken variants each fail. (NEG-5)

## Build conditions mapped to tests
- P1 (secret sources only): `P1: an allow-listed request value ... is not redacted`; the server.test expectation `['postgres://base', 'sk-base']`.
- P1 held stub with the real held env: the server case `a held transcribe refusal` sends request env TRANSCODER_MODE=transcribe with base values marker, 1 and europe-west1, and asserts the held text.
- R5 (classify held first, append from the constant, NEG-17 words): `REAL held refusal ...`, `every held-guard reason form ...`, `NEG-17 / R5: short base values ...`, `a line that only looks like a held refusal ...`.
- R5 residual risk: stated in the docker.ts header and in Risks below. AC-7 text to be folded in at the next spec edit.
- Q1 deferral: the cross-constant test (held-env.ts through the real guard vs ac13-count.py HELD_TAG) is a pre-merge condition of the first PR to land after goodqa#16136 1369 and 1371. Not in this PR.

## Evidence (t2-dev)
At HEAD 3b7cde1a in apps/job-dispatcher, with a clean worktree:

```
$ timeout 900 npx vitest run
 Test Files  13 passed | 1 skipped (14)
      Tests  315 passed | 14 skipped (329)
exit 0
$ timeout 600 npx tsc --noEmit
exit 0
```

- Fail first: `npx vitest run test/docker-failure-message.test.ts` on origin/main e9449087 with only the new test file gives 34 failed. The leak cases fail on content (`leaked ...`, `expected 'docker run failed before starting a c...' to be 'docker run failed: other (stderr 0 by...'`), not only on the missing export.
- After: `npx vitest run` (apps/job-dispatcher) gives 13 files passed, 1 skipped; 315 tests passed, 14 skipped. The skips are the docker-socket integration suites, unchanged. `npx tsc --noEmit` exits 0.
- NEG-5 (`neg5-16185.sh`):
  - variant A, which returns err.message: 15 failed of 36;
  - variant B, which logs the merged env on a docker refusal: 1 failed of 36;
  - restored: 36 passed.
- Real engine (WAL w80166140e2a): the real buildServer and realDockerDeps, the real docker CLI and the real create-guard (bt-guard 3e478c28 source, heldEnv TRANSCODER_MODE=transcribe) in front of the real docker.sock.
  - The held transcode gives 422 `docker run failed: guard_refused (stderr 186 bytes): docker: Error response from daemon: job-dispatcher-create-guard: refused (create refused: TRANSCODER_MODE=transcribe is held on this guard)`.
  - An image not on the allow-list gives 422 guard_refused with the image-ref line.
  - 0 eight-char marker windows appear across both bodies and 4 log lines.
- Real stderr strings used as fixtures (WAL w276c9ce4c41): the held line is 139 chars, the bad ref starts `docker: invalid reference format`, and an unreachable daemon gives `Cannot connect to the Docker daemon at ...` with exit 1.

## Source diff (apps/job-dispatcher/src only; the test file is on the branch)
