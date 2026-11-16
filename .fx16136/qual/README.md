# PR 1377 runtime qualification kit (goodqa#16148)

This kit runs the release controller (`infra/release-harness/selfhost-ctl.py`) and the job-secret path at one exact
bugtracker commit against a **real docker daemon**. Use an owned host only (t2-dev). **Never run it on a production host**:
`qualify.sh` refuses hostnames that look like one. It uses dummy keys only and needs no session context.

## Run it

On t2-dev, as a user in the `docker` group with passwordless `sudo` (the ctl runs as root, the same as on the VM):

    bash qualify.sh <40-hex head sha> <bugtracker git checkout> --python <python with pytest> [--work DIR] [--floor GB]

Example:

    bash ~/repos/fx-16136/qual/qualify.sh <HEAD> ~/repos/fx-16136/bt-16148-gate --python ~/repos/fx-16136/venv/bin/python

- The checkout only has to contain the commit. The kit runs `git archive <head>` into its own run directory and never
  touches the checkout's working tree.
- A run takes about 10–20 minutes. Most of that is the dispatcher image build on the first run, plus the pytest fixture rows.
- Exit code 0 means every check passed and cleanup completed. Anything else is FAIL.

## Output

- **Log:** `<work>/qual-<head8>-<utc stamp>/qual.log`. The default `<work>` is `~/qual-runs`. The log path is printed first.
- **Per-check lines:** each check writes `CHECK <id> PASS|FAIL [<label>] <detail>`.
- **Final lines:** a `SUMMARY` table, then `CLEANUP complete|INCOMPLETE`, then
  `QUAL RESULT PASS|FAIL n/13 head=… run=… log=…`.
- **Machine-readable:** `summary.json` in the same directory.
- **Fixed count:** there are 13 checks. A check that did not run counts as FAIL, so the kit cannot pass vacuously.
- **Hashes:** the log records the sha256 of every kit file. It also records the head's `selfhost-ctl.py`, `rw-ship.sh`,
  `cmdline-sampler.py`, `compose.yaml` and the dispatcher Dockerfile.

## Disk floor

The kit checks free space on `/` before the archive, before the image builds and before every check. Under 28G
(`--floor`), it stops, cleans up and fails.

## Cleanup guarantee

The kit removes only what this run created:

- the compose project `qual-<run>`, with its containers, networks and volumes (`compose down --volumes`);
- containers this run caused: the job container, the client container and the trial-boot containers named
  `goodqa-trial-qual-<run>*`;
- the image tags it built or tagged (all of them contain `qual-<run>`);
- the base or proxy images it pulled, if they were absent before the run;
- the root-owned temp dirs under its run directory, via a path-guarded `sudo rm`.

It runs no `prune`. One thing remains by design: BuildKit cache entries from the two builds, since the cache is shared.
`qual.log` and `summary.json` are kept. Cleanup also runs on failure and on SIGINT or SIGTERM. Anything it could not
remove is listed in `CLEANUP INCOMPLETE` and fails the run.

## Isolation

- **Project:** compose project `qual-<run>`, built from the head's own `compose.yaml`. The host paths `/etc/goodqa/...`
  are moved into the run directory, and each rewrite is logged. The kit also writes an `.env` with
  `SITE_ADDRESS=qual.invalid`.
- **Services:** only `job-dispatcher-docker-proxy`, `job-dispatcher-create-guard` and `job-dispatcher` are started.
  Caddy, api and web are never started, and no host port is published.
- **Controller:** every ctl call passes `--dir`, `--env-dir` and `--project`, so it never touches the defaults
  (`/opt/goodqa`, `/etc/goodqa`, project `goodqa`).
- **Images:**
  - the dispatcher image is really built from the head;
  - api, web, scan, transcode and suggest-fix are tags of the stand-in worker image (`worker/`);
  - a "bad dispatcher" is the stand-in under the dispatcher's name; it cannot start the dispatcher entrypoint, so the
    switch fails.
- **Dummy values:** a random dummy token and a dummy key, shaped like the derive output (one line with literal `\n`).
  The key file is root:64910 0440 in a root 0711 dir, as `derive-job-secrets.py` makes it. The values are never put on
  argv and never logged.
- **Proxy:** the docker-socket-proxy mounts the host's real docker socket, as in the product design. The job container
  it starts is a sibling on the host daemon.

## Checks: what each proves, and what it does not

| id | label | proves | does not prove |
|---|---|---|---|
| q0 | REAL | t2-dev's docker layout (containerd image store, external containerd). The prod side is read from `infra/selfhost/app/install-docker.sh` only and labelled **ASSUMPTION** | that prod's live daemon matches. No agent reads prod |
| q1 | REAL | the real `docker compose config` resolves the ctl's re-pin of the product compose for the guard and the dispatcher | anything at run time |
| q2 | REAL | the ctl disk gate reports the docker root and the containerd root that really holds the loaded image. The oracle is the content blob on disk, not ctl output | prod's root path |
| q3 | REAL | `image-ids` resolves loaded refs to their real ids and job refs to their own digest. An unknown ref resolves to none | refs produced by a real `docker save \| docker load` transfer |
| q4 | REAL | `trial-boot` of the head dispatcher image reads a dummy key file: ok. Control: a non-dispatcher image is not ok | — |
| q5 | REAL | gate (b) `envfile-key`: canonical file 1/1. Controls: line removed gives 0; a twin line gives 2 (canonical 1) | — |
| q6 | REAL | `pin` then `up-dispatcher` on the real daemon. Gate (c) `disp-boot`: ok. The create-guard is listening | api and web health (never started) |
| q7 | STAND-IN | a job launched over HTTP goes through the real dispatcher, create-guard, proxy and daemon. The stand-in worker sees `GITHUB_APP_PRIVATE_KEY` equal to the dummy key (sha256 match). The dummy key never appears in dispatcher logs. The sampler PASSes with at least 1 run, using `--env-file` only | that the **real** intelligence-worker uses the key correctly (the worker is a stand-in) |
| q8 | REAL | sampler controls: no launch gives NO_SAMPLE (exit 1); `--seconds 0 --expect-runs 0` is refused (exit 2) | — |
| q9a | REAL (ctl) | gate (c) fails after a switch. The re-hold pin and up-dispatcher hold the worker. Restoring the re-hold, then the switch, brings back the state fp and the worker line byte-equal, and gate (c) is ok again | rw-ship.sh's choice to do this (see qF) |
| q9b | REAL (ctl) | the switch fails (the dispatcher is never ready) and the re-hold also fails. Restoring both brings back the state fp and the worker line byte-equal | rw-ship.sh's exit 5 versus 8 decision (see qF) |
| q10 | REAL (ctl) | the migrated branch, without a database: switch, gate (c) fails, re-hold. The worker is held, the switched release stays, nothing is restored | the migration itself, or rw-ship.sh's exit 8 (see qF) |
| qF | FIXTURE | rw-ship.sh's decisions (re-hold, rollback, exit 5 or 8, forward-only after a migration) in the named tests of `test_rw_ship_jobsecret_gate.py` at the head, run against a fake VM | anything on a real daemon |

**Not exercised end to end:** a full `rw-ship.sh` selfhost run was not executed. That run builds seven images,
transfers them with `docker save | docker load`, runs the promote gates and migrates a database. Doing it on t2-dev would
mean building and loading every product image, a git origin with promote gates, and a database. The kit instead runs the
controller steps that `rw-ship.sh` performs on the VM (REAL and REAL (ctl)), and the script's own decision logic only in
its fixture tests (FIXTURE).
