# PR review packet (whole PR): goodqa#16148 rw-ship job-secret gate, carrying the 1371 job-image forward-port and the 1373 job env-file content

Tickets: GoodQA goodqa#16148 (gate and 1373 content), GoodQA goodqa#16136 (1371 content). Related tickets: goodqa#16195, #16196, #16198, #16208, #16210.
Repo: ericmacdougall/bugtracker. Branch fix/16148-rwship-gate, draft PR #1377 into main.
Base: origin/main 179c3ab1a8770c7bf184caef2a21798b8713a92b. It contains #1343, #1372 (2065c788) and #1369 (179c3ab1). #1366 was not among main's last 8 first-parent commits; its presence is not separately verified here.
Expected HEAD: 679c278a1aad04dadddc53d9ae76722173161661 (pushed; fast-forward from 5ead8901 -> ab028a6b -> 679c278a)

One receipt covers all three parts. main ruled that the gate receipt also covers the 1371 and 1373 content: no 1373 receipt exists, and 1371 gets no solo receipt. No earlier verdict carries over. Judge every section directly.

## What the branch carries (exact ranges)
- **Section A, 1371 content:** `ed296b0a..bff96cc5`, from the common base with main to the 1371 head. Commits: f7e602bd, f59392bb, 59501565, bff96cc5.
- **Section B, 1373 content:** `c9d61ac1..5dd6865c`, from the 1373 base to the 1373 head (PR #1373 is OPEN at 5dd6865c).
  - The gate branch itself carries this content only up to **97bfac51**, joined into the gate by d9cb6162 (parents bff96cc5 and 97bfac51).
  - 5dd6865c is 97bfac51 plus one join: the 1372 UTF-8 residue fix 80b26c7e (apps/job-dispatcher/src/docker.ts and test/docker-failure-message.test.ts, 2 files). The gate branch does not have it. It reaches the reviewed tree from origin/main, where #1372 is merged (2065c788). So `c9d61ac1..5dd6865c` is exactly the 1373 content of the tree under review once it joins main.
  - Later gate commits change three 1373 files. They are in Section C:
    - 7a5b5a01 changes test_selfhost_ctl_job_secrets.py;
    - 4a142511 changes cmdline-sampler.py and its test;
    - 4a142511 also changes the derive-job-secrets.py docstring.
- **Section C, gate delta:** `d9cb6162..679c278a`. Commits: 7a5b5a01, 4aa75203, 4a142511, b3e183b7, 8c519f5f, 5ead8901, ab028a6b, 679c278a.
- The gate's history also holds main commit e9449087 (#1351) and the 1372 step-1 commits 127f2357, 3b7cde1a and c9d61ac1. Those are all already on main and are not part of this review.
- **Net diff against main,** `git diff origin/main <merge of 679c278a with origin/main>`: 35 files, +5489/-75.

Redaction: one context line in rw-ship.sh (Section A) holds the default SELFHOST_APP host address. In this packet it reads `<IP-REDACTED>`; the committed tree has the real value. Nothing else in the diff is altered.

## Claims to verify

### Section A (1371): job images on main (goodqa#16136 AC-1 to AC-19, review F1, F2)
1. The four job images are built from the release SHA and loaded with the app images.
   - Each pin is `goodqa-JOB@sha256:<VM id>`, once, in the create-guard &job-images block.
   - The real `docker compose config` resolves the anchor for both services.
   - Presence is checked on the resolved prepared compose, and each job ref resolves to its own digest.
2. SELFHOST_JOB_HOLD defaults to `intelligence-worker,transcribe`. It is accepted only as `none` or a strict comma list of those two; anything else exits 2 before any build. Held lines are marked `# held`.
3. Only a dispatcher image that refuses a malformed GUARD_HELD_ENV gets `--guard-hold TRANSCODER_MODE=transcribe`. After the switch, `guard-log` must report the hold, or the stack rolls back.
4. `disk` measures DockerRootDir and, on a containerd store, the containerd root. Any root it cannot resolve refuses, and rw-ship exits 11 before any load.
5. The fp equals the pre-change ctl on the same stack. Held refs are never reported missing. A job ref that stops resolving after the switch rolls back.

### Section B (1373): job env through a private --env-file, the GitHub App key as an allow-listed JOB_ENVFILE, and the host apply
6. **AC-1/AC-2.** Every dispatcher launch passes env through `--env-file`, never `-e`.
   - The file is written per launch in a fresh 0700 mkdtemp directory, opened O_EXCL|O_NOFOLLOW with mode 0600, and removed in finally.
   - Stale `goodqa-envfile-*` directories are swept at boot.
   - An empty env passes no --env-file at all; that is a disclosed deviation the lead accepted.
7. **AC-4/AC-5.** Only `INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY` may come from a JOB_ENVFILE.
   - It is read per launch from /run/goodqa-secrets with O_RDONLY|O_NOFOLLOW|O_NONBLOCK, fstat S_ISREG and a 64 KiB cap.
   - At boot the dispatcher logs one status line per key, names only.
   - Any other key, a path outside the directory, or a bad file stops it, with no value logged.
8. **AC-9 (derive-job-secrets.py).** It turns the api.env GITHUB_APP_PRIVATE_KEY line into /etc/goodqa/job-secrets/github-app-private-key.
   - The file is root:64910, 0440, in a root 0711 directory, written temp-then-rename with an inode check.
   - Links and non-regular files are refused.
   - It prints one status line and never a value.
   - On a post-rename inode mismatch it unlinks the name, never its target.
9. **AC-11 (apply-job-secrets-host.py and apply-job-secrets.sh).**
   - The host apply adds exactly two marked compose lines (group_add 64910 and the read-only mount) and one dispatcher.env key line.
   - It validates with `docker compose config -q` before any write. Backups are O_EXCL, root 0600, newest 3 kept.
   - `restore` removes only its own lines and keeps any later pin or key.
   - The wrapper takes the rw-ship deploy lock (flock -n, exit 75 when held or a release is in flight). It streams both scripts as `sudo python3 -I -` and bumps the deploy epoch.
10. **NEG-16.** The checked-in compose.yaml and env-keys.json are byte-for-byte what the host apply leaves; the drift gate is red without either change. The real selfhost-ctl pin and restore keep the two marked lines.
11. **AC-6 (3) (cmdline-sampler.py).**
    - It is read-only and unprivileged, scoped to the dispatcher cgroup, and polls every 50 ms.
    - It keeps flag names only.
    - It fails on -e, --env, an attached form, or an `e` inside a boolean shorthand cluster. The cluster set is d, i, t, P and q; q comes from Section C, 4a142511.
    - NO_SAMPLE fails.
12. **The 1372 fix in this range, 80b26c7e.** The residue threshold and the redaction filter count UTF-8 bytes (`byteLength`), so a multi-byte secret fragment is never left in a 422 body.

### Section C (gate): rw-ship job-secret unhold gate (spec v4 AC-8, P3, P4) and the 1370 fail-closed fixes
13. **Derive stream (8c519f5f, 5ead8901).**
    - install-d2.sh writes an optional 8th binding field, `derive-blob <40hex>`, when the candidate holds derive-job-secrets.py. validate_binding accepts only that one last line, equal to the blob at the bound commit.
    - rw-ship streams derive-job-secrets.py over the existing ssh route only when the blob equals the binding line. Otherwise it refuses, or keeps a held release held.
14. **Pre-switch gates (5ead8901).** These are (a) derive, (b) dispatcher env names, and the P3 trial boot. Each exits 2 before any switch.
15. **Gate (c), after the guard check (5ead8901).**
    - On failure it re-holds with `${STAMP}h` and exits 8 if migrations were applied.
    - Otherwise it restores h, then STAMP, then up, and exits 5.
    - A failed restore records `${STAMP}h2`.
    - The audit record and PIN_FP carry jobSecretGate.
16. **ctl verbs (b3e183b7).** `envfile-key`, `disp-boot`, `trial-boot` and `up-dispatcher` print status words only.
    - trial-boot runs the exact digest with --rm, --network none, --read-only, --cap-drop ALL, no-new-privileges, --user node, --group-add 64910, --pids-limit 64 and --memory 256m, with no socket and no env_file.
    - The container is always removed, timeout included.
17. **--boot-check (4aa75203).** A CLI flag only, never env. It exits 0 only when at least one key is configured and every line is the exact ok form, 1 on an error, 2 on a config refusal, and 3 with no key. The normal start is unchanged.
18. **The 1370 fixes ported (ab028a6b, 679c278a).**
    - ac13-count.py fails closed on records it cannot read (malformed, orphan, invalid status or time, no completion): verdict INCONCLUSIVE, exit 1.
    - An unusable completion time stays untimed and never becomes the start time.
    - A time must be a finite float, or an int within +-2**53. Otherwise it is untimed, and a JSON verdict is always printed (no traceback).
    - store_is_containerd refuses any DriverStatus that is not a non-empty list of exactly-two-string rows.
    - job_lines counts JOB_IMAGE_* only under the guard's `environment`. presence_check compares every key, held ones included ("" resolved), in both resolved services with exact parity.
19. **PIN2 test fix (5ead8901).** test_rw_release_authority_d2.py PIN2 gains `+ sh.JOBARGS`. It failed on 1371 itself (bff96cc5), so it is a 1371 test bug, not a gate regression.
20. No earlier assertion is deleted or relaxed. Retargeted tests are listed in the commit messages: 7a5b5a01 and the 5ead8901 fixture.

## Landing window order (lead-corrected; main authorizes each step)
1. `apply-job-secrets.sh --check`. Then the env-name check (dispenv-names-check.py, sha256 a20c5236…) as step 0 of the host apply, by the same tooling.
2. `apply-job-secrets.sh apply`.
3. A new binding with the derive-blob line (install-d2.sh).
4. The first release, still HELD. Checks: drift gate green, dispatcher boot line ok, cmdline sampler PASS (PENDING_REAL_TEST p16148-sampler-live).
5. The unhold, as a later separate release, only after every intelligence-worker key is set via set-secret-env. Open question goodqa#16208: confirm on the host which selfhost-ctl.py copy set-secret-env.sh runs, by name and path only.

Access for the window: the runner's existing ssh route and key, and non-interactive `sudo python3 -I -`. No vault entry and no password.

## Evidence (t2-dev)
All suites ran on the join of 679c278a with origin/main 179c3ab1: scratch commit 234acbbf660d2de0cec1b07ac08c1f857e6a5f75 (parents 679c278a and 179c3ab1). It is not pushed, its status was clean (status-lines=0), and there was 36G free at the start. The join is clean; docker.ts auto-resolved.
```
$ cd apps/job-dispatcher && timeout 900 npx vitest run
 Test Files  18 passed | 1 skipped (19)
      Tests  456 passed | 15 skipped (471)
exit 0
$ cd apps/job-dispatcher && timeout 600 npx tsc --noEmit
exit 0
$ bash infra/selfhost/app/run_derive_tests.sh
Ran 61 tests in 1.170s
OK (skipped=41)
Ran 61 tests in 2.655s
OK (skipped=2)
exit 0
$ cd infra/selfhost/app && DERIVE_TEST_TMP=$PWD/../../../.scratch timeout 300 python3 -m unittest test_apply_job_secrets_wrapper test_cmdline_sampler
Ran 20 tests in 5.608s
OK
exit 0
$ timeout 300 node --test infra/selfhost-job-secrets-drift.test.mjs infra/selfhost-plan.test.mjs infra/selfhost/app/qa-closure-topology.test.mjs
# tests 23
# pass 23
# fail 0
exit 0
$ cd infra/release-harness && pytest -q test_ac13_count.py test_rw_ship_jobsecret_gate.py test_rw_ship_selfhost.py test_rw_release_authority_d2.py test_install_d2_upgrade.py test_runner_ship_adapter.py test_rw_runtime_root.py test_selfhost_ctl.py test_selfhost_ctl_gate.py test_selfhost_ctl_job_secrets.py
1963 passed, 1 skipped in 993.93s (0:16:33)
exit 0
```
- run_derive_tests.sh runs twice: on the host (41 root-only tests skipped), and as root in a throwaway python:3.12-slim container with --network none (2 host-only tests skipped).
- The release-harness run sets a fake git committer and author identity. Without one, test_fast_ship_propagates_root_to_installed_adapter fails with "Committer identity unknown". That is an environment cause, and the test fails the same way at bff96cc5.
- **Disclosed intermittent failure.** The first run of the identical release-harness command on 234acbbf gave 5 failed, 1958 passed. All 5 failures were in test_rw_runtime_root.py:
  - two_roots_ship_and_rollback_independently;
  - failed_switch_rollback_uses_custom_root;
  - executed_ship_and_rollback_never_open_legacy_root;
  - root_with_spaces_is_preserved;
  - runtime_boundary_negative_controls[embedded-db-root].

  On the same tree, test_rw_runtime_root.py alone gave 25 passed, and the full rerun above is green. The earlier full run on the ab028a6b join gave 1937 passed and 0 failed. 679c278a touches only ac13 files, which this test file does not use. The tracebacks of the failing run were not kept.

  The likely cause is timing under load: the file waits on lock holders with fixed 0.3 s sleeps. That cause is unverified. It is ticketed as goodqa#16218; keep the tracebacks next time it reproduces. Treat it as a known flake, not as evidence about this diff.

Fail first, commit-bound, from each change's own run (the failing and the fixed code at the stated commits):
- **Section A (1371, recorded in the pr-fwd v2, v3 and v4 packets).**
  - F1 and F2 each failed first on their pre-fix sources.
  - The ThroughputProcess tests that fail on the old rh base pass on main, with nothing deselected on main.
- **Section B (1373).**
  - At 97bfac51, job-env-file.test.ts failed 21 of 23 with the server unwired.
  - The drift test failed 5 times before the compose and env-keys change.
  - F2 failed first (failures=2, both swap tests, in the root container), and F3 failed first (the cluster test).
  - Every broken variant failed: derive V1-V5, host apply H1-H6, wrapper W1-W4, sampler S1-S5, and selfhost-ctl C1 (the pin rewrite drops the marked block) and C2 (no restore fence).
  - 80b26c7e (1372): on c9d61ac1 with only the new tests, docker-failure-message.test.ts gave 11 failed, 41 passed; at 80b26c7e it gave 52 passed. A broken variant (the residue check back on value.length) gave 11 failed.
- **Section C (gate).**
  - 7a5b5a01: 1 failed before, 2 passed after.
  - 4aa75203: the boot-check entrypoint test failed (1) with the old index.ts; 7 passed after.
  - 4a142511: test_cmdline_sampler FAILED (failures=1) before; 12 OK after.
  - b3e183b7: 23 failed on the old ctl, 23 passed after. Variants G1-G15 each fail.
  - 8c519f5f: `-k derive` gave 2 failed on the old installer, 49 passed after. Variants I1-I4 each fail.
  - 5ead8901: test_rw_ship_jobsecret_gate.py gave 33 failed on the pre-gate rw-ship.sh, 33 passed after. Mutants M1-M15 each fail. PIN2 fails at bff96cc5 itself.
  - ab028a6b: on the 5ead8901 sources, 9 failed (ac13) and 25 failed (the store and job-key tests); after, 18 and 28 passed.
  - 679c278a: 1 failed on ab028a6b (an OverflowError traceback, no JSON verdict); 19 passed after. The unbounded-int variant gave 1 failed.

Real engine checks, recorded as REALLY_TESTED in the 1373 work:
- w5eff9b17217: the --env-file round trip.
- w9cce3d7b822: a real env-file round trip on all 4 profiles with 0 mismatches; the held refusal still fires.
- w276c9ce4c41: the held stderr is the same with -e or --env-file.

Still PENDING_REAL_TEST, gated in the landing window: p16148-sampler-live, p16148-gate-c-live and p16148-trial-boot-live. AC-4 real-guard (p16136-ac4-real-guard) also stays pending.

## Risks
- **Fail-open closures (the review focus).** Each item below was fail-open before this branch and now fails closed.
  - ac13-count.py:
    - unreadable records PASSed;
    - an unusable completion time borrowed its start time, so a pre-window start with a 500 completion was dropped;
    - NaN, Infinity and 1e999 counted as times;
    - a huge int crashed with no verdict, or with --until could have been read as a usable time and dropped.
  - store_is_containerd: a failed discovery was read as classic, and malformed rows were accepted.
  - job_lines and presence_check: a held key under `labels` passed, and held keys were left out of the parity check.
  - rw-ship: an unhold could happen without the derive, env-name, trial-boot and gate (c) checks.
- **Drift gate.** From the join until the host apply runs, the CC8.1 drift gate is red against the live VM. That fails closed: no release promotes until steps 1 and 2 of the window.
- **Flaky test:** test_rw_runtime_root.py fails intermittently under load (5 failures, green on rerun), tracked in goodqa#16218. The likely cause is fixed 0.3 s lock-holder sleeps; that is unverified.
- **Deferred:**
  - the Q1 cross-constant test (held-env.ts is now on main, so it can be written after this lands);
  - the rh port of the gate;
  - goodqa#16195 (apply write order);
  - goodqa#16196 (root-only tests skipping in CI);
  - goodqa#16208 (the rh base failures and the set-secret-env ctl copy);
  - goodqa#16210 (the rh overflow port).
- Nothing is merged, deployed or tagged.

## Diff (sections A, B, C; each section's header line starts with `### SECTION`)
