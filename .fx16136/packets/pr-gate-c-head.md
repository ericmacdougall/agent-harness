# PR review packet (whole PR, compact): goodqa#16148 rw-ship job-secret gate, carrying the 1371 job-image forward-port and the 1373 job env-file content

Tickets: GoodQA goodqa#16148 (gate and 1373 content), GoodQA goodqa#16136 (1371 content). Related tickets: goodqa#16195, #16196, #16198, #16208, #16210, #16218.
Repo: ericmacdougall/bugtracker. Branch fix/16148-rwship-gate, draft PR #1377 into main.
Base: origin/main 179c3ab1a8770c7bf184caef2a21798b8713a92b. It contains #1343, #1372 (2065c788) and #1369 (179c3ab1).
Expected HEAD: 679c278a1aad04dadddc53d9ae76722173161661 (pushed; fast-forward 5ead8901 -> ab028a6b -> 679c278a)

**This is one receipt for all three sections.** Neither 1371 nor 1373 has a receipt of its own, and no earlier verdict carries over. Judge every section directly.

**Compact form.** Main's packet cap is 150,000 bytes. This packet replaces pr-gate.md (a1105cd9, 394,747 bytes, refused for size).
- Read the snapshot at `--pr 1377`.
- The diff below gives full hunks (-U1) only for the risky code: secret and env handling, the host apply and its wrapper, the fail-closed gates (disk, derive-blob, boot-check, AC-13 bounds), and the rw-ship unhold gate.
- Every other changed file is named with its diffstat, so open it in the snapshot.

Redaction: rw-ship.sh in the committed tree holds the default SELFHOST_APP host address on one context line. That line is not inside these -U1 hunks, and the packet contains no dotted address. The tree has the real value.

## Section ranges (each reachable from HEAD 679c278a)
- **Section A, 1371 content:** `ed296b0a..bff96cc5`. Commits: f7e602bd, f59392bb, 59501565, bff96cc5.
- **Section B, 1373 content:** `c9d61ac1..97bfac51`, plus 80b26c7e.
  - 97bfac51 is the 1373 content the gate branch carries. d9cb6162 joins it into the gate; its parents are bff96cc5 and 97bfac51.
  - 80b26c7e is the 1372 UTF-8 residue fix (docker.ts and test/docker-failure-message.test.ts, 2 files; parent c9d61ac1). It is not reachable from HEAD. It is in the reviewed snapshot through base main 179c3ab1, where #1372 is merged (2065c788).
  - 5dd6865c is the head of the open PR #1373. It is 97bfac51 joined with 80b26c7e, so `c9d61ac1..97bfac51` plus 80b26c7e is equivalent to it. 5dd6865c is not reachable from HEAD and is not used as an endpoint.
  - Three 1373 files are changed again by later gate commits. Those changes are in Section C:
    - test_selfhost_ctl_job_secrets.py (7a5b5a01);
    - cmdline-sampler.py and its test (4a142511);
    - the derive-job-secrets.py docstring (4a142511).
- **Section C, gate delta:** `d9cb6162..679c278a`. Commits: 7a5b5a01, 4aa75203, 4a142511, b3e183b7, 8c519f5f, 5ead8901, ab028a6b, 679c278a.
- Also in the history but already on main, so not reviewed here: e9449087 (#1351), and 127f2357, 3b7cde1a and c9d61ac1 (1372 step 1).
- **Net against main:** 35 files, +5489/-75.

## Section A (1371): job images on main (goodqa#16136 AC-1 to AC-19)
Diffstat `ed296b0a..bff96cc5`, 6 files, +1407/-40. `[H]` marks files with hunks below.
```
[H] infra/release-harness/rw-ship.sh            126
[H] infra/release-harness/selfhost-ctl.py       241
[H] infra/release-harness/ac13-count.py         148
    infra/release-harness/README.md              20
    infra/release-harness/test_ac13_count.py    147
    infra/release-harness/test_rw_ship_selfhost.py 765
```
**What and why:** the four job images ship pinned by digest with the release, so jobs never run a stale or mutable image.
1. The images are built from the release SHA and loaded with the app images. Each pin is `goodqa-JOB@sha256:<VM id>`, once, in the create-guard &job-images block. The real `docker compose config` resolves it for both services, and presence is checked on the resolved compose.
2. SELFHOST_JOB_HOLD defaults to `intelligence-worker,transcribe`. It accepts only `none` or a strict list of those two; anything else exits 2 before any build. Held lines are marked `# held`.
3. Only a dispatcher image that refuses a malformed GUARD_HELD_ENV gets `--guard-hold TRANSCODER_MODE=transcribe`. After the switch, `guard-log` must report the hold, or the stack rolls back.
4. **Disk gate.** `disk` measures DockerRootDir and, on a containerd store, the containerd root. An unresolvable root refuses, and rw-ship exits 11 before any load.
5. The fp equals the pre-change ctl on the same stack. Held refs are never reported missing. A job ref that stops resolving after the switch rolls back.
6. ac13-count.py counts the AC-13 job outcomes in the window.

**Fail first:** F1 and F2 each failed on their pre-fix sources in the forward-port runs. The ThroughputProcess tests that fail on the old rh base pass on main, with nothing deselected. Test file: test_rw_ship_selfhost.py.

## Section B (1373): job env through a private --env-file, the GitHub App key as an allow-listed JOB_ENVFILE, and the host apply
Diffstat `c9d61ac1..97bfac51` is 21 files, +2879/-15. 80b26c7e adds 2 files, +69/-2: docker.ts (9 lines) and test/docker-failure-message.test.ts (62 lines, new). Together that is 22 files, +2948/-17, the same as the 1373 PR head 5dd6865c.
```
[H] apps/job-dispatcher/src/config.ts                 7
[H] apps/job-dispatcher/src/docker.ts                87  (+9 in 80b26c7e, hunk shown separately)
[H] apps/job-dispatcher/src/index.ts                  8
[H] apps/job-dispatcher/src/job-env-file.ts         144
[H] apps/job-dispatcher/src/server.ts                31
[H] infra/selfhost/app/apply-job-secrets-host.py    350
[H] infra/selfhost/app/apply-job-secrets.sh          59
[H] infra/selfhost/app/derive-job-secrets.py        336
[H] infra/selfhost/app/compose.yaml                   2
[H] infra/selfhost/app/env-keys.json                  1
    infra/selfhost/app/cmdline-sampler.py           132  (read-only verifier, named only)
    infra/selfhost/app/run_derive_tests.sh           16
    apps/job-dispatcher/test/docker-failure-message.test.ts 62
    apps/job-dispatcher/test/docker.test.ts          19
    apps/job-dispatcher/test/env-file.test.ts       211
    apps/job-dispatcher/test/job-env-file.test.ts   204
    infra/release-harness/test_selfhost_ctl_job_secrets.py 106
    infra/selfhost-job-secrets-drift.test.mjs        95
    infra/selfhost/app/test_apply_job_secrets_host.py 296
    infra/selfhost/app/test_apply_job_secrets_wrapper.py 147
    infra/selfhost/app/test_cmdline_sampler.py      168
    infra/selfhost/app/test_derive_job_secrets.py   475
```
**What and why:** job secrets must never appear in a process command line or in logs.

7. **AC-1/AC-2.** Every dispatcher launch passes env through `--env-file`, never `-e`.
   - The file is written per launch in a fresh 0700 mkdtemp directory, opened O_EXCL|O_NOFOLLOW with mode 0600, and removed in finally.
   - Stale `goodqa-envfile-*` directories are swept at boot.
   - An empty env passes no --env-file at all; that is a disclosed deviation.
8. **AC-4/AC-5.** Only `INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY` may come from a JOB_ENVFILE.
   - It is read per launch from /run/goodqa-secrets with O_RDONLY|O_NOFOLLOW|O_NONBLOCK, fstat S_ISREG and a 64 KiB cap.
   - At boot the dispatcher logs names only.
   - Any other key, a path outside the directory, or a bad file stops it, with no value logged.
9. **AC-9 (derive-job-secrets.py).** It writes the api.env GITHUB_APP_PRIVATE_KEY to /etc/goodqa/job-secrets/github-app-private-key.
   - The file is root:64910, 0440, in a root 0711 directory, written temp-then-rename with an inode check.
   - Links and non-regular files are refused. It prints one status line and never a value.
   - On a post-rename inode mismatch it unlinks the name, never its target.
10. **AC-11 (host apply).**
    - It adds exactly two marked compose lines (group_add 64910 and the read-only mount) and one dispatcher.env key line.
    - It runs `docker compose config -q` before any write. Backups are O_EXCL, root 0600, newest 3 kept.
    - `restore` removes only its own lines.
    - The wrapper takes the rw-ship deploy lock (flock -n, exit 75 when held). It streams both scripts as `sudo python3 -I -` and bumps the deploy epoch.
11. **NEG-16.** The checked-in compose.yaml and env-keys.json are byte-for-byte what the host apply leaves; the drift gate is red without either change.
12. **AC-6 (3) sampler.** It is read-only and keeps flag names only. It fails on -e, --env, an attached form, or an `e` inside a boolean cluster (d, i, t, P and q). NO_SAMPLE fails.
13. **80b26c7e.** The residue threshold and the redaction filter count UTF-8 bytes, so a multi-byte secret fragment never stays in a 422 body.

**Fail first:**
- At 97bfac51, job-env-file.test.ts failed 21 of 23 with the server unwired.
- The drift test failed 5 times before the compose and env-keys change.
- F2 failed first (failures=2, the swap tests, in the root container), and so did F3 (the cluster test).
- Every broken variant failed: derive V1-V5, host apply H1-H6, wrapper W1-W4, sampler S1-S5, and ctl C1 and C2.
- 80b26c7e: on c9d61ac1 with only the new tests, 11 failed and 41 passed; at 80b26c7e, 52 passed. A broken variant (the check back on value.length) gave 11 failed.

## Section C (gate): rw-ship job-secret unhold gate (spec v4 AC-8, P3, P4) and the 1370 fail-closed fixes
Diffstat `d9cb6162..679c278a`, 18 files, +1268/-63.
```
[H] apps/job-dispatcher/src/boot-check.ts            41
[H] apps/job-dispatcher/src/index.ts                 24
[H] infra/release-harness/ac13-count.py              65
[H] infra/release-harness/install-d2.sh              23
[H] infra/release-harness/rw-ship.sh                 94
[H] infra/release-harness/selfhost-ctl.py           157
[H] infra/selfhost/app/derive-job-secrets.py          5
    infra/selfhost/app/cmdline-sampler.py             6  (adds q to the cluster set)
    apps/job-dispatcher/test/boot-check.test.ts      86
    infra/release-harness/test_ac13_count.py        116
    infra/release-harness/test_install_d2_upgrade.py 63
    infra/release-harness/test_runner_ship_adapter.py 3
    infra/release-harness/test_rw_release_authority_d2.py 6
    infra/release-harness/test_rw_ship_jobsecret_gate.py 199
    infra/release-harness/test_rw_ship_selfhost.py  187
    infra/release-harness/test_selfhost_ctl_gate.py 209
    infra/release-harness/test_selfhost_ctl_job_secrets.py 42
    infra/selfhost/app/test_cmdline_sampler.py        5
```
**What and why:** a release may unhold the job secrets only once the derive, the env names, a trial boot and a post-switch check all pass. Each fails closed.

14. **Derive-blob (8c519f5f, 5ead8901).**
    - install-d2.sh writes an optional 8th binding field, `derive-blob <40hex>`. validate_binding accepts only that one last line, equal to the blob at the bound commit.
    - rw-ship streams derive-job-secrets.py over the existing ssh route only when the blob matches. Otherwise it refuses, or keeps a held release held.
15. **Pre-switch gates (5ead8901).** (a) derive, (b) dispatcher env names, and the P3 trial boot. Each exits 2 before any switch.
16. **Gate (c), after the guard check.**
    - On failure it re-holds with `${STAMP}h` and exits 8 if migrations were applied.
    - Otherwise it restores h, then STAMP, then up, and exits 5.
    - A failed restore records `${STAMP}h2`.
    - The audit record and PIN_FP carry jobSecretGate.
17. **ctl verbs (b3e183b7).** `envfile-key`, `disp-boot`, `trial-boot` and `up-dispatcher` print status words only.
    - trial-boot runs the exact digest with --rm, --network none, --read-only, --cap-drop ALL, no-new-privileges, --user node, --group-add 64910, --pids-limit 64 and --memory 256m, with no socket and no env_file.
    - The container is always removed, timeout included.
18. **Boot-check (4aa75203).** `--boot-check` is a CLI flag only. It exits 0 only when at least one key is configured and every line is ok, 1 on an error, 2 on a refusal, and 3 with no key. The normal start is unchanged.
19. **AC-13 bounds and the 1370 fixes (ab028a6b, 679c278a).**
    - ac13-count.py fails closed on unreadable records: INCONCLUSIVE, exit 1.
    - An unusable completion time stays untimed and never borrows the start time.
    - A time must be a finite float or an int within +-2**53, and a JSON verdict is always printed.
    - store_is_containerd refuses any DriverStatus that is not a non-empty list of exactly-two-string rows.
    - job_lines counts JOB_IMAGE_* only under the guard's `environment`. presence_check compares every key, held ones included, in both services with exact parity.
20. **PIN2 (5ead8901).** test_rw_release_authority_d2.py PIN2 gains `+ sh.JOBARGS`. It fails on bff96cc5 itself, so it is a 1371 test bug.

No assertion is deleted or relaxed. Retargeted tests are listed in the 7a5b5a01 and 5ead8901 commit messages.

**Fail first, per commit:**

| Commit | Before | After |
|---|---|---|
| 7a5b5a01 | 1 failed | 2 passed |
| 4aa75203 | 1 failed (old index.ts) | 7 passed |
| 4a142511 | failures=1 | 12 OK |
| b3e183b7 | 23 failed | 23 passed |
| 8c519f5f (`-k derive`) | 2 failed | 49 passed |
| 5ead8901 | 33 failed (test_rw_ship_jobsecret_gate.py) | 33 passed |
| ab028a6b | 9 failed (ac13) and 25 failed (store/job-key) | 18 passed and 28 passed |
| 679c278a | 1 failed (OverflowError, no JSON verdict) | 19 passed |

Broken variants each fail: G1-G15 (b3e183b7), I1-I4 (8c519f5f), M1-M15 (5ead8901), and an unbounded-int variant (679c278a).

## Tests on the joined tree 234acbbf (all sections)
The tree is the join of 679c278a with origin/main 179c3ab1: scratch commit 234acbbf660d2de0cec1b07ac08c1f857e6a5f75, not pushed, clean. The join is clean, with docker.ts auto-resolved. Run on t2-dev with 36G free.
```
$ cd apps/job-dispatcher && timeout 900 npx vitest run                    [B, C]
      Tests  456 passed | 15 skipped (471)
exit 0
$ cd apps/job-dispatcher && timeout 600 npx tsc --noEmit                  [B, C]
exit 0
$ bash infra/selfhost/app/run_derive_tests.sh                             [B, C]
Ran 61 tests  OK (skipped=41)   host
Ran 61 tests  OK (skipped=2)    root, python:3.12-slim, --network none
exit 0
$ cd infra/selfhost/app && python3 -m unittest test_apply_job_secrets_wrapper test_cmdline_sampler   [B, C]
Ran 20 tests  OK
exit 0
$ node --test infra/selfhost-job-secrets-drift.test.mjs infra/selfhost-plan.test.mjs infra/selfhost/app/qa-closure-topology.test.mjs   [B]
# tests 23  # pass 23  # fail 0
exit 0
$ cd infra/release-harness && pytest -q test_ac13_count.py test_rw_ship_jobsecret_gate.py test_rw_ship_selfhost.py test_rw_release_authority_d2.py test_install_d2_upgrade.py test_runner_ship_adapter.py test_rw_runtime_root.py test_selfhost_ctl.py test_selfhost_ctl_gate.py test_selfhost_ctl_job_secrets.py   [A, B, C]
1963 passed, 1 skipped in 993.93s
exit 0
```
- The release-harness run sets a fake git identity. Without one, test_fast_ship_propagates_root_to_installed_adapter fails with "Committer identity unknown", the same way at bff96cc5.
- **goodqa#16218, a disclosed intermittent failure.** The first identical release-harness run on 234acbbf gave 5 failed, 1958 passed, all in test_rw_runtime_root.py:
  - two_roots_ship_and_rollback_independently;
  - failed_switch_rollback_uses_custom_root;
  - executed_ship_and_rollback_never_open_legacy_root;
  - root_with_spaces_is_preserved;
  - runtime_boundary_negative_controls[embedded-db-root].

  That file alone gave 25 passed, and the full rerun is green. 679c278a touches only the ac13 files. The likely cause, unverified, is the fixed 0.3 s lock-holder sleeps. The tracebacks were not kept. Treat it as a known flake.
- Real engine checks (REALLY_TESTED, 1373 work):
  - w5eff9b17217: the --env-file round trip.
  - w9cce3d7b822: all 4 profiles with 0 mismatches; the held refusal still fires.
  - w276c9ce4c41: the held stderr is the same with -e or --env-file.
- Still PENDING_REAL_TEST, gated in the window: p16148-sampler-live, p16148-gate-c-live, p16148-trial-boot-live and p16136-ac4-real-guard.

## Landing window order (lead-corrected; main authorizes each step)
1. `apply-job-secrets.sh --check`. Then the env-name check (dispenv-names-check.py, sha256 a20c5236…) as step 0 of the host apply.
2. `apply-job-secrets.sh apply`.
3. A new binding with the derive-blob line (install-d2.sh).
4. The first release, still HELD. Checks: drift gate green, dispatcher boot line ok, cmdline sampler PASS (p16148-sampler-live).
5. The unhold, as a later separate release, only after every intelligence-worker key is set via set-secret-env. Open question goodqa#16208: confirm on the host which selfhost-ctl.py copy set-secret-env.sh runs, by name and path only.

Access: the runner's existing ssh route and key, and non-interactive `sudo python3 -I -`. No vault entry, no password.

## Risks
- **Fail-open closures (the review focus).** Each of these was fail-open before this branch.
  - ac13-count.py: unreadable records PASSed; a completion time borrowed its start time; NaN, Infinity and 1e999 counted as times; a huge int crashed with no verdict.
  - store_is_containerd: a failed discovery read as classic, and malformed rows were accepted.
  - job_lines and presence_check: a held key under `labels` passed, and held keys were left out of parity.
  - rw-ship: an unhold could happen without the derive, env-name, trial-boot and gate (c) checks.
- **Drift gate:** from the join until the host apply, the CC8.1 drift gate is red against the live VM. That fails closed: nothing promotes until window steps 1 and 2.
- **Flake:** test_rw_runtime_root.py, goodqa#16218 (above).
- **Deferred:**
  - the Q1 cross-constant test;
  - the rh port of the gate;
  - goodqa#16195 (apply write order);
  - goodqa#16196 (root-only tests skip in CI);
  - goodqa#16208 (rh base failures, set-secret-env ctl copy);
  - goodqa#16210 (rh overflow port).
- Nothing is merged, deployed or tagged.

## Risky hunks (-U1). Each section header line starts with `### SECTION`
