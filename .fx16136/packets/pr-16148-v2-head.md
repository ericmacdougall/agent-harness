# PR review packet v2 (whole PR, after the code-review delta): goodqa#16148 step 2, job env via a private --env-file, the GitHub App key as an allow-listed JOB_ENVFILE, and its host apply

Ticket: GoodQA goodqa#16148 (spec v4 core 5d317b21, attached comment ef963731; lead build conditions R1–R6, P1–P4)
Repo: ericmacdougall/bugtracker, branch fix/16148-job-envfile, draft PR #1373
Base: c9d61ac1aa3a575781e5e5fc9430bee993be1e86 (fix/16185-docker-failure-category, draft PR #1372; stacked, merge #1372 first)
Expected HEAD: 97bfac5172322d3eddc3cf7d43e951421624dd67

Commits (base..HEAD):
- 87b4654d088 fix(job-dispatcher): pass job env via a private --env-file
- 50cf25dbc1f feat(job-dispatcher): add allow-listed JOB_ENVFILE env, read per launch
- d5262a72089 feat(selfhost): add derive-job-secrets.py for the GitHub App key
- 0f78fe314b7 test(selfhost): prove derive refuses links that look conforming
- a9dffadc0eb feat(selfhost): add the AC-11 host apply for job secrets
- d80d04299c0 feat(selfhost): check in the job-secret mount and add the apply wrapper
- 3330aa2e65a feat(selfhost): add the post-deploy docker cmdline sampler
- 158ec0db4b6 test(selfhost): prove the job-secret mount survives a pin and rollback
- f29da1848b3 fix(selfhost): fail closed on a derive swap; catch clustered -e (code review F2, F3)
- 97bfac51723 merge of fix/16185 at c9d61ac1 (code review F4; a merge, so neither published branch is rewritten)

## Scope
- apps/job-dispatcher:
  - src: docker.ts, server.ts, config.ts, index.ts, and the new job-env-file.ts;
  - tests: test/env-file.test.ts (new), test/job-env-file.test.ts (new), test/docker.test.ts.
- infra/selfhost/app:
  - derive-job-secrets.py, apply-job-secrets-host.py, apply-job-secrets.sh, cmdline-sampler.py;
  - compose.yaml (2 lines) and env-keys.json (1 key);
  - their tests and run_derive_tests.sh.
- infra: selfhost-job-secrets-drift.test.mjs and release-harness/test_selfhost_ctl_job_secrets.py (tests only).
- Out of scope:
  - the rw-ship per-deploy gate (AC-8, P3, P4, NEG-12, NEG-19, the per-deploy derive stream). That is a later PR stacked on goodqa#16136 1370 and 1371.
  - the rh copy of the lock cross-check, which is deferred.
  - selfhost-ctl.py and rw-ship.sh themselves, which are unchanged.

## Claims to verify
1. AC-1 and AC-2: every dispatcher launch passes env through `--env-file`, never through `-e`. The file is written per launch in a fresh 0700 mkdtemp directory, opened O_EXCL|O_NOFOLLOW with mode 0600, and removed in finally. Stale `goodqa-envfile-*` directories are swept at boot. Keys must match ENV_KEY_PATTERN; a value with NUL, CR or LF is refused. A bad request value gives 400, and a bad base value or a write failure gives 501, with nothing launched.
2. AC-4 and AC-5: only `INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY` may come from a JOB_ENVFILE.
   - The dispatcher reads it per launch from /run/goodqa-secrets with O_RDONLY|O_NOFOLLOW|O_NONBLOCK, fstat S_ISREG, and a 64 KiB cap.
   - At boot it logs one status line per key, names only.
   - Any other JOB_ENVFILE key, a path outside the directory, or a bad file stops it with no value logged.
3. AC-9 and NEG-1–3, NEG-13: derive-job-secrets.py turns the api.env GITHUB_APP_PRIVATE_KEY line into /etc/goodqa/job-secrets/github-app-private-key.
   - The file is root:goodqa-jobsecret (gid 64910), 0440, in a root 0711 directory, written temp-then-rename with an inode check. Links and non-regular files are refused.
   - It prints exactly one status line and never a value; a refusal exits 2.
4. AC-11, AC-3, R1 and R2: apply-job-secrets-host.py.
   - It inserts exactly two marked lines at the end of the job-dispatcher block: `group_add: ["64910"]` and the read-only `/etc/goodqa/job-secrets:/run/goodqa-secrets:ro` mount.
   - It appends the one JOB_ENVFILE key line to dispatcher.env.
   - It refuses on any conflict or before derive has run.
   - It validates with `docker compose config -q` before any file changes, then writes env and then compose through directory fds, keeping owner and mode.
   - Backups are O_EXCL, root 0600, and the newest 3 are kept.
   - It is idempotent. `restore` removes only the marked lines and the exact key line, keeping any later pin or key, and refuses a changed marked line.
5. R3 and R4: apply-job-secrets.sh runs from the runner.
   - It takes flock -n on `<lane>/locks/gq-promote.lock`, the LOCKF of rw-ship.sh on main; a test checks the two paths are equal. It exits 75 when the lock is held or gq-promote.inflight.json exists.
   - A mutating run bumps the deploy epoch.
   - It streams both scripts to the VM as `sudo python3 -I -`; nothing is installed on the VM.
   - Anything other than exactly one written or unchanged line from derive stops it with nothing else applied.
6. NEG-16: the checked-in compose.yaml and env-keys.json are byte-for-byte what the host apply leaves. The drift gate is green on an applied VM and red without either repo change.
7. Sonnet v4 condition: on a fake VM, the real selfhost-ctl.py `pin` (next release) and `restore` (its rollback) keep the two marked lines. The rollback of a release pinned before the apply is refused by the existing fence (exit 3), so it cannot drop them.
8. AC-6 (3), NEG-18, P2 and R6: cmdline-sampler.py.
   - It is read-only, unprivileged, scoped to the dispatcher container's cgroup (resolved at sample time) and polls every 50 ms.
   - It keeps flag names only; raw argv is never stored.
   - It fails on -e, --env or an attached form, and NO_SAMPLE fails, so a silent sampler never passes.
9. The tests are not vacuous: every broken variant listed below fails.
10. F2 (code review a5a2642f): on a post-rename inode mismatch, derive unlinks the name (never its target), so the dispatcher sees the key as missing. Both swap tests assert that nothing is left at the target.
11. F3: a single-dash token is read as pflag reads a shorthand cluster. The booleans d, i, t and P chain, and an e anywhere in the chain records -e(cluster), which is BAD. The first value-taking shorthand ends the chain. NEG-18 adds -de, -ieK=V and -dite.
12. Tickets from the same review, not fixed here (lead ruling):
    - goodqa#16195 (F1): the apply and restore write order, compose first and env last. It is a spec change, because it flips NEG-14 and H2.
    - goodqa#16196 (F5): the root-only tests must not pass by skipping in CI.

## Build conditions mapped to tests
- R1 (restore fence or minimal restore):
  - `test_restore_keeps_a_later_release_pin_and_a_later_env_key` and `test_restore_refuses_a_changed_marked_line`;
  - `test_rollback_of_a_release_pinned_before_the_apply_is_refused_and_keeps_the_mount`.
- R2 (backups O_EXCL/O_NOFOLLOW, root 0600, retention):
  - `test_apply_then_apply_again_then_restore` (owner and mode of each backup), `test_neg15_existing_backup_is_never_overwritten`, `test_prune_keeps_the_newest_three_backups`;
  - the derive tests for /etc/goodqa and the secrets dir.
- R3 (derive streamed): `test_apply_streams_derive_then_host_apply_under_the_lock` (the stdin sha256 equals each script), `test_derive_refused_stops_before_the_host_apply` (4 forms).
- R4 (deploy lock): `test_lock_held_refuses_with_75_and_calls_nothing`, `test_release_in_flight_refuses_with_75`, and the drift test `R4: the host-apply wrapper takes the deploy lock rw-ship takes`.
- R5 (held line from constants; NEG-17 words): done in the step-1 PR #1372, unchanged here.
- R6 (sampler resolves the cgroup at sample time, about 50 ms, unprivileged):
  - `test_neg18_other_cgroup_is_not_sampled`, `test_cgroup_v1_docker_path_is_matched`, `test_a_short_lived_process_is_seen_by_polling`, `test_runs_unprivileged_on_the_real_proc`;
  - the container id is a caller argument, so it is resolved per sample run.
- P2 (positive control): `test_positive_control_no_sample_fails`.
- NEG-14 (partial apply): `test_neg14_stopped_between_files`. NEG-15 (failed validation): `test_neg15_invalid_compose_changes_nothing`.
- NEG-16: the four NEG-16 and AC-11 cases in infra/selfhost-job-secrets-drift.test.mjs.
- NEG-18: `test_neg18_planted_marker_in_every_form_never_reaches_output` (6 argv forms, every 8-char window checked).
- The selfhost-ctl fence refuses rollback to a release pinned before the apply. This is now tested (claim 7), and it is the intended behaviour: the mount must never be removed by a stale rollback. To roll such a release back, an operator first runs `apply-job-secrets.sh restore`.
- Sonnet: WAL ids w3f9d85d1129 and w0e0906c66fa go into the AC-6, AC-7 and AC-8 sources at the next spec edit, together with the R1–R6 text.

## Deviations (disclosed, each with its ruling)
1. An empty env passes no `--env-file` at all, rather than an empty file. The lead accepted this as a disclosed deviation. Tested in env-file.test.ts.
2. R2 on compose.yaml: on prod the compose dir belongs to the passwordless-sudo login user (ubuntu:root 755; compose.yaml ubuntu:ubuntu 664; read-only finding WAL w02dccb8d90d). Root-only ownership of compose.yaml is therefore not achievable without changing the deploy model. The apply keeps its owner and mode, and writes through a directory fd that refuses links. The full rule holds for /etc/goodqa, dispatcher.env backups and the secrets dir. The lead accepted this as a disclosed deviation and risk.
3. R3: derive is streamed, never installed, so AC-11 drops its "installed derive" item (lead ruling, R3 streamed approved). The per-deploy derive stream in rw-ship comes in the rw-ship gate PR.
4. AC-11 restore semantics: `restore` removes the marked lines and the exact key line rather than putting a stamped backup back. This keeps later release pins and env keys (R1). The stamped backups are still written and kept (3) for manual recovery.
5. The rh copy of the lock-path cross-check is deferred (lead ruling). This PR checks the wrapper against main's rw-ship.sh only, and the rh packet says the same.

## Ship order (each step with its stated check; main authorizes each step)
1. Merge #1372 (step 1), then this PR. Check: the merged main HEAD contains 158ec0db's tree, and the CI focused suites listed under Evidence pass.
2. From merge until step 4 passes, the CC8.1 `selfhost-topology-drift` gate is red against the live VM. The checked-in compose and env-keys now name the mount and key, and the VM does not have them yet. This fails closed: no release can promote until the host apply runs, so steps 3 and 4 must follow the merge before any other promotion.
3. The prod operator assigned by main runs from the runner `RW_LANE_ROOT=<lane> infra/selfhost/app/apply-job-secrets.sh --check`. Check: every item reads `absent` and none reads `conflict`; derive --check reads absent. On any conflict, stop.
4. `apply-job-secrets.sh apply`, then `--check` again. Checks:
   - derive prints `job secret github-app-private-key: written`;
   - the host prints `job secrets host apply: applied`;
   - `--check` shows every item `present`, exit 0;
   - then `node infra/selfhost-plan.mjs` (the drift gate, read-only over ssh) exits 0 with `no drift`.
   If the drift gate exits 1, stop and run `apply-job-secrets.sh restore`; its check is that `--check` shows everything `absent` and the drift gate is back at its pre-merge result.
5. The next normal rw-ship release recreates job-dispatcher on the new image with the mount (no separate recreate). Checks:
   - the dispatcher boot log shows the JOB_ENVFILE status line for INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY, name only;
   - `cmdline-sampler.py --container <dispatcher id> --seconds 120 --expect-runs N` prints verdict PASS with runs_with_env_flag 0 (PENDING_REAL_TEST p16148-sampler-live).
6. AC-10 live checks per spec v4 after that deploy. intelligence-worker stays held until main lifts the hold.
Rollback of step 4 is `apply-job-secrets.sh restore`. Rollback of step 5 is the normal selfhost-ctl restore, which keeps the mount (claim 7).

## Evidence (t2-dev)
At HEAD 97bfac5172322d3eddc3cf7d43e951421624dd67, with a clean worktree (status-lines=0) and 31G free:

```
$ cd apps/job-dispatcher && timeout 900 npx vitest run
 Test Files  15 passed | 1 skipped (16)
      Tests  363 passed | 14 skipped (377)
exit 0
$ cd apps/job-dispatcher && timeout 600 npx tsc --noEmit
exit 0
$ bash infra/selfhost/app/run_derive_tests.sh
Ran 61 tests in 1.281s
OK (skipped=41)
Ran 61 tests in 3.134s
OK (skipped=2)
exit 0
$ cd infra/selfhost/app && DERIVE_TEST_TMP=$PWD/../../../.scratch timeout 300 python3 -m unittest test_apply_job_secrets_wrapper test_cmdline_sampler
Ran 20 tests in 5.107s
OK
exit 0
$ timeout 300 node --test infra/selfhost-job-secrets-drift.test.mjs infra/selfhost-plan.test.mjs infra/selfhost/app/qa-closure-topology.test.mjs
# tests 23
# pass 23
# fail 0
exit 0
$ timeout 600 $HOME/repos/fx-16136/venv/bin/python -m pytest -q -p no:cacheprovider infra/release-harness/test_selfhost_ctl_job_secrets.py infra/release-harness/test_selfhost_ctl.py
1584 passed in 110.08s (0:01:50)
exit 0
```

- run_derive_tests.sh runs twice. The first pass is on the host: parse tests and the real `docker compose config` parity, with 41 root-only tests skipped. The second is as root in a throwaway python:3.12-slim container (pinned digest, --network none), with 2 host-only tests skipped.
- Fail first:
  - job-env-file.test.ts: 21 of 23 failed with the server unwired.
  - The new drift test: 5 failures before the compose and env-keys change.
  - The pin-survival test was written against the unchanged selfhost-ctl.py and proven by variant C1.
- Broken variants (each restored after; `git status` clean):
  - derive V1–V5 all fail;
  - host apply: H1 no validation, H2 compose written before env, H3 a backup overwritten, H4 restore drops later lines, H5 other services ignored, H6 links followed. All FAILED.
  - wrapper: W1 no lock, W2 no in-flight check, W3 derive result ignored, W4 no epoch bump. All FAILED.
  - sampler, rerun at 97bfac51: S1 keeps raw argv, S2 no cgroup filter, S3 no positive control, S4 attached short flag kept whole, and S5 e inside a cluster ignored (F3). All FAILED.
  - F2 and F3 fail first: before the source fix, run_derive_tests.sh FAILED (failures=2, both swap tests) in the root container, and test_cmdline_sampler FAILED (failures=1, the cluster test).
  - selfhost-ctl: C1, the pin rewrite drops the marked block, fails the pin-survival test. C2, no restore fence, fails the pre-apply rollback test.
- Real engine (REALLY_TESTED):
  - w5eff9b17217: the --env-file round trip;
  - w9cce3d7b822: a real env-file round trip on all 4 profiles with 0 mismatches, and the held refusal still fires;
  - w276c9ce4c41: the real held stderr is the same with -e or --env-file.

## Full diff (base c9d61ac1..HEAD 97bfac51)
