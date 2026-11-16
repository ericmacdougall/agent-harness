# Adversarial spec review: goodqa#16136 (self-host dispatcher job images)

Reviewer: agent:a5a2642f07434bbc9 (claude-opus-5-5), adversarial role
Date: 2026-11-15
Spec reviewed: frozen copy `spec-16136.frozen.md`, sha256 `858c5e5b2b6772da53199a7529b1341593269f7c293d609a4e2f38f4ea8dc2cc` (verified; the live spec had the same hash at review time)
Code read (read-only, t2-dev): harness `config/goodqa-release/bin/{rw-ship.sh,selfhost-ctl.py,test_rw_ship_selfhost.py,RELEASE_BINDING}` at 1786659bb; bugtracker `infra/selfhost/app/{compose.yaml,env-keys.json}`, `infra/do/job-dispatcher-docker-proxy.env`, `infra/deploy-jobs.sh`, `apps/job-dispatcher/src/{config.ts,create-guard-main.ts,create-guard.ts,docker.ts,jobs.ts}`, the worker `context.ts` files, at bugtracker f6ed90c2ccd; `~/release-kit/ship.sh`; the ship logs of 2026-11-14T21:37Z and 2026-11-15T20:22Z.
No production access of any kind was used.
Location note: the requested report path in `agent-af3f19d243286a8a7/review-16136/` was refused by this agent's worktree-isolation guard, so the report sits here, in the author's untracked `.fx16136/` scratch directory. Main can copy it.

## Verdict: ACCEPT_WITH_CONDITIONS

The core design is sound and I confirmed it on a real engine. On a containerd image store, a `repo@sha256:<image id>` ref resolves after `docker save | docker load`, is bound to its repository, and keeps the exact string in the create body that the guard matches. It does not weaken AUD-031: the guard still accepts only exact allowlisted strings, and every new value is a content address the store verifies. The image work is urgent and worth shipping.

Two parts of the spec must change before attach:

1. Its acceptance flow (AC-5 to AC-8) depends on worker env that is very likely missing in production but is declared out of scope.
2. Its presence check protects only the instant of the pin. It does not protect the window in which jobs actually run.

The numbered conditions are C1 to C8 at the end.

## Findings (ranked)

### F1. HIGH (likely, evidence from repo files). AC-6 to AC-8 will probably fail on env the spec puts out of scope, and the outcome promises transcripts that no AC checks.

`infra/selfhost/app/env-keys.json` is the CC8.1 drift-gate list of key names on the VM, with a baseline read 2026-10-15 and last changed 2026-11-04. Its `dispatcher` key names are compared below with what each worker reads (`apps/*/src/context.ts`) and with what `infra/deploy-jobs.sh` set on Cloud Run:

| Job | Key the worker reads | In the self-host dispatcher env? |
|---|---|---|
| intelligence-worker | PROJECT_INTELLIGENCE_KEYRING | absent |
| intelligence-worker | GITHUB_APP_ID, GITHUB_APP_PRIVATE_KEY | absent (the spec names only these) |
| suggest-fix-worker | PROJECT_INTELLIGENCE_KEYRING (decrypts the project OpenRouter credential) | absent |
| transcode, transcribe mode | GCP_PROJECT (`transcribe.ts:233` fails closed) | absent |
| transcode, frames mode | API_PUBLIC_URL (fails closed) | absent |

Only DATABASE_URL, NODE_ENV, OPENROUTER_API_KEY, SPACES_* and STORAGE_DRIVER exist per kind.

The consequences:

- Suggest Fix, intelligence ingestion and transcription will likely fail even with the images present.
- The Outcome promises "playable recordings and transcripts", but AC-6 checks only MP4 and poster. A transcode-only success would pass AC-6 while transcription stays broken.
- If the env is a follow-up, the ticket can never reach DONE_LIVE against its own AC-7 and AC-8.

Settle it before deploy with no production access: read env-keys.json and compare it with the env each worker reads. Optionally, read back the key names only from the dispatcher container env, with no values.

Fix (C1): add a pre-deploy env-readiness AC that lists the required keys per kind. Then either:

- bring the env keys into scope, as a separate secret-handling change with its own review, or
- relabel AC-7 and AC-8, plus transcription, as `TARGET_MISMATCH` against the ticket's outcome, and split them into a linked ticket created now, not "if the live proof shows it".

Add an AC for one transcription, or remove transcripts from the Outcome.

### F2. HIGH (confirmed by probe). The pin is anchored only by the per-release tag, so a tag removal or a routine `docker image prune -a` silently breaks every job again.

On the containerd store, `goodqa-scan@sha256:ID` resolves only while some image record named `goodqa-scan:<tag>` with that target exists. Probe P3 showed this: I untagged the image but kept it under another repository, and `inspect repo@ID` then gave "No such image".

The job images are not used by any long-running container. `docker image prune -a`, the usual operator response on a full disk, therefore deletes exactly the current job images, while api, web and dispatcher survive because their containers are running.

The spec's mitigation is "the same retention as the existing api, web and dispatcher tags". In fact no retention exists anywhere (grep of harness `config/goodqa-release` and bugtracker `infra/selfhost`). Seven images per release will accumulate on the VM, which makes a manual prune likely.

Nothing would notice afterwards:

- The presence check runs only at pin time.
- `state.missing` covers only the four service pins.
- `up` checks only the four services.

This is the same silent failure that this ticket is about, and it lasted a month.

Fix (C2):
- (a) `state` must report the job refs and their resolution, and put any unresolved ref in `missing`.
- (b) The post-switch verification in rw-ship must run `image-ids` on the four job refs and treat a miss as a switch failure, so the rollback runs.
- (c) Add a recurring read-only check, through ops-watch or the existing release postcheck, that alerts when any `JOB_IMAGE_*` ref stops resolving.
- (d) Write the "never `docker image prune -a` on the app VM" constraint into the runbook, and file the retention ticket now.

### F3. MEDIUM (confirmed). A wrong presence-check implementation passes the spec's tests.

The fake docker in `test_rw_ship_selfhost.py` resolves `image inspect` by exact dict key. So all of these pass `test_ctl_pin_refuses_missing_job_image` as written:

- a check that inspects the tag `goodqa-scan:<tag>`
- a check that inspects the bare `sha256:ID`
- a check that resolves the ref without comparing the returned Id with the digest

On the real engine, only inspecting the exact compose string `goodqa-JOB@sha256:ID` and requiring `.Id == sha256:ID` proves what the switch will use.

Fix (C3):
- The spec must require the check to inspect exactly the string written to compose and to compare the Id.
- The fake must model containerd resolution: `repo@digest` resolves only if a same-repo name with that target exists.
- Add negative tests for: a tag removed but content kept, a wrong repo with the right id, and an Id mismatch.

### F4. MEDIUM. A classic-store host and the AC-4 proof do not exercise the production launch path.

On the classic (overlay2) store, a loaded image has no RepoDigests, and `repo@sha256:<config id>` does not resolve. The design fails closed only if F3's exact-ref check is in place.

Fix (C4): add an explicit refusal when `docker info` does not report the containerd snapshotter, with a message saying why. Production evidence for AC-4 should be a read-only `docker info -f '{{json .DriverStatus}}'`, not inference from the dispatcher image.

AC-4 also uses `docker create --pull never` from a root shell. Production instead runs `docker run --rm -d ...` (default `--pull missing`) through the guard and then the socket proxy (IMAGES=0). The proof should run the real guard on t2-dev, with `GUARD_ENV=production` and the four refs, then `DOCKER_HOST=<guard> docker run` the dispatcher's exact argv form. That is the only pre-deploy check that the exact string the CLI sends matches the allowlist.

Probe P2 showed that `Config.Image` keeps the `repo@sha256:` string as typed, which suggests it will match, but the guard path itself was not run. With IMAGES=0 a missing image fails closed: the pull attempt is denied.

### F5. MEDIUM. The fingerprint decision is unstated, and both choices have a rollback consequence.

`state()` hashes only the service pins, image ids and release env into `fp`. The fp is used for "production unchanged" before the switch, `--expect-fp` restores and `active_id`. The spec says only "state reports the job pins".

- If the job pins enter `fp`, every fp recorded before this change (rollback.json, `restore --expect-fp` for pre-fence stamps) stops matching, and those restores refuse.
- If they stay out, a change to the job pins alone is invisible to the fp checks. The `.rw-pin` file-hash fence still covers compose.yaml.

Fix (C5): state the choice in the spec. I recommend keeping the job pins outside the `fp` core but reporting them in `state`, with a test that the fp of an unchanged stack is identical before and after this change.

### F6. MEDIUM. The anchor rewrite and the presence check are tested only against fake `docker compose`.

AC-2 claims the job-dispatcher resolves the same four values "through the anchor". With the fake docker, `compose config` is stubbed, so the merge key `<<: *job-images` is never resolved by a real parser.

A YAML merge key is overridden by any explicit `JOB_IMAGE_*` key in the job-dispatcher's own `environment`. A later edit could split the guard allowlist from the dispatcher config, and a text-only check would not see it.

Fix (C6):
- Add one test on t2-dev that runs the real `docker compose config --format json` on the prepared bugtracker compose.yaml. It must assert that both services' four `JOB_IMAGE_*` values equal the pins.
- The rewrite must refuse unless each key appears exactly once in the whole file, inside the create-guard block.
- The presence check should take its image list from the resolved config (`services.*.image` plus both services' `JOB_IMAGE_*`), not from regex lines. A text scan misses `${VAR}` interpolation and anchors that define `image:`.

### F7. MEDIUM. AC-9 can pass vacuously.

`grep -c '"statusCode":422'` returns 0 if the dispatcher's log line uses another key or spacing, or if no job request arrives in the 30-minute window.

Fix (C7):
- Record a positive control first: the same command over a pre-deploy window must return a count above 0, given today's failures.
- Require at least one request per job kind inside the window. Tie it to AC-5 to AC-8.

### F8. MEDIUM. AC-7 is underdetermined.

AC-7 assumes several things:

- a cron caller of `/v1/cron/dispatch-intelligence-jobs` exists on self-host
- a due intelligence job exists for an owned project
- "container exits 0" means success

A worker that claims nothing, or that records a job failure and then exits cleanly, would satisfy "exits 0".

Fix (C8):
- Name the owned project and the product-API action that makes a job due.
- Define success as the job record reaching a terminal success with an output timestamp later than the deploy, read through the product API.
- Keep NEG-8's verbatim evidence.

AC-5, AC-6 and AC-8 should also name the owned or disposable test project and the cleanup.

### F9. LOW-MEDIUM. Rollback is not blocked, but it is silent about the jobs.

NEG-7 is right that `restore` must not run the presence check. On the first release, a rollback restores the DigitalOcean pins. On later releases, it restores older local pins that may have been pruned (F2). Either way the stack comes back "healthy" with every job broken.

Fix: have `restore` and the rollback print a non-blocking WARN that lists any job ref that does not resolve, and have the deploy note say "jobs down after rollback".

A first deploy against the DigitalOcean pins is otherwise handled correctly by checking the prepared text (AC-3). Keep `test_presence_check_uses_prepared_compose`.

### F10. LOW. Build time and disk: the timeout risk is small, but the spec's measurement plan is too narrow.

The 2026-11-14 and 2026-11-15 ship logs show a whole release takes about 9 minutes:

- promote api: about 1.5 to 2.5 minutes
- web: about 3 minutes
- job-dispatcher: 4 to 22 seconds, warm
- save and load: about 40 to 50 seconds

Four Node workers add perhaps 5 to 15 minutes. That is well inside the 60-minute TimeoutStartSec. However, the transcoder's `COPY . .` busts its layer cache on every release, so its `pnpm install` reruns each time.

Measure all four cold and warm, plus the save and load of seven images, in one rehearsal. Do not measure just one image.

The build box is at 93% with 51G free, and the VM's disk headroom is unchecked before `docker load`. A load that fails part way aborts before the switch, so it fails closed, but a full VM disk hurts the running services. State the new `SELFHOST_BUILD_MIN_FREE_GB` value, and add a VM free-disk check before the transfer.

### F11. LOW. Delivery runs UNBOUND from a dirty working tree.

`~/release-kit/ship.sh` runs `~/repos/harness/config/goodqa-release/bin/rw-ship.sh` from the t2-dev checkout. Every recent ship log says "release scripts: UNBOUND (no RELEASE_BINDING in ship.conf)", and `git status` there shows local modifications.

These scripts run as root on production. "Live" for this ticket should mean that the ship log of the proving release shows the sha256 of the merged rw-ship.sh and selfhost-ctl.py. Say so in the delivery AC. Binding the release scripts is a separate ticket.

### F12. LOW (process). The owner's WAL intent planned production SELECTs.

The owner's WAL intent `wa3241a24b1a` planned "SELECT/logs only" against production to find the first failing tick and the affected org ids. Production database reads are forbidden by any route. Main's note `w7de20d04913` says the figures now come from the compose pin history and the product API, and I found no evidence that a query ran for this ticket.

The spec should state that no production database query was used for #16136. If one was, it must be disclosed like the #16135 one.

### F13. INFO. AUD-031 and the guard: no way found for the guard to accept an image it should refuse.

- The guard matches `Image` by exact string. The new allowlist values come only from host-reported ids after the id-verified load.
- The engine binds `repo@digest` to the repository (P2: the wrong repo with the right id gives "No such image").
- A normalized `docker.io/library/...` form, a bare id or another digest are all different strings, so they are refused.
- A compromised dispatcher cannot pull (IMAGES=0).

The trust root moves from "digest pushed to DOCR" to "a local content address on the VM". Anyone who can tamper with that is already root on the VM.

NEG-2 (repo-to-key binding, partial set, metacharacters) and NEG-3 are the right negative cases. Keep NEG-2's partial-set refusal: the guard itself tolerates empty keys.

## Conditions before attach

- C1: an env-readiness AC per job kind, plus either env in scope or AC-7, AC-8 and transcription relabelled `TARGET_MISMATCH` with a linked ticket filed now. Fix the transcripts claim in the Outcome (F1).
- C2: job refs in `state.missing`, a post-switch job-ref check that triggers rollback, a recurring resolution alert, and a prune warning plus a retention ticket (F2).
- C3: the presence check uses the exact compose string with an Id comparison, and the fake docker models containerd resolution, with the three negative tests (F3).
- C4: an explicit containerd-store refusal, and AC-4 proven through the real guard path, with production `docker info` evidence (F4).
- C5: the fingerprint decision stated and tested (F5).
- C6: one real `docker compose config` test of the anchor, single-occurrence enforcement, and the image list taken from the resolved config (F6).
- C7: a positive control and a per-kind request floor for AC-9 (F7).
- C8: AC-7 success defined precisely, and test projects and cleanup named for AC-5 to AC-8 (F8).

F9 to F11 are recommended and can become tickets.

## Probes run (all on t2-dev, through `run_probe.py`)

| id | declaration | bound | outcome |
|---|---|---|---|
| P1 | `--class external-write --worst-case "creates and removes a 1-file FROM-scratch image and two stopped containers in the t2-dev docker daemon; leftover tagged image if cleanup fails"` | `--timeout-s 120 --max-file-mb 50 --max-procs 64`, no network | completed rc 0, peak RSS 0.08 GB, 24 s. Its stdout was lost to the report wrapper, so it was rerun as P2. |
| P2 | same as P1 (output captured to a file) | same | completed rc 0 (rerun of P1). Engine 29.1.3, containerd snapshotter. The id is unchanged by save and load. `inspect repo@id` ok. `inspect wrongrepo@id` No such image. `create --pull never repo@id` ok. `create wrongrepo@id` refused. `Config.Image` keeps the `repo@sha256:` string. |
| P3 | `--class external-write --worst-case "builds, retags and removes a 1-file FROM-scratch image in the t2-dev docker daemon; leftover tag if cleanup fails"` | `--timeout-s 120 --max-file-mb 50 --max-procs 64`, no network | completed rc 0. After the repo tag was removed, with the content kept under another repo, `inspect repo@id` gave No such image (F2). |

Cleanup: two containers in "created" state left by P1 and P2 (my own, identified by their `rv16136probe-*@sha256` image) and their images were removed by hand afterwards. A final check found 0 leftover probe images. No hostile resource probes (memory, disk fill, hang) were needed: the change parses only operator-controlled CLI arguments and compose text.

## Not examined

- the implementation diff (none exists yet; this is a spec review)
- the production host, its compose.yaml, its env, its dispatcher logs and its actual disk headroom (no production access, by instruction)
- the real dispatcher log line format for 422 responses
- whether a self-host cron calls the intelligence dispatch route
- real build times of the four worker images
- whether the api passes any secret through the per-request `env` override (`apps/api/src/lib/job-dispatch.ts:142`; I saw no keyring passed, but did not trace every call site)
- the goodqa#16130 staging gate's readiness
- OWASP ASVS: not applicable beyond V14 configuration and V10 supply-chain themes (pinned images, least privilege on the proxy); no compliance claim is made
