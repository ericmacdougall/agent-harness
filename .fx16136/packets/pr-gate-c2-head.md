# PR review packet (whole PR, compact v2): goodqa#16148 rw-ship job-secret gate + 1371 job images + 1373 job env-file + F1 disk-gate fix

Tickets: goodqa#16148 (gate, 1373 content), goodqa#16136 (1371 content, F1). Related: #16195, #16196, #16198, #16208, #16210, #16218, #16221.
Repo: ericmacdougall/bugtracker. Branch fix/16148-rwship-gate, draft PR #1377 into main.
Base: origin/main 179c3ab1a8770c7bf184caef2a21798b8713a92b (contains #1343, #1372 2065c788, #1369).
Expected HEAD: 51ae3d5299b9b207cc896fc61e9e988f6e75d564 (pushed; fast-forward 679c278a -> 5eafc9a0 -> f6e45adc -> efa4c409 -> 51ae3d52).
Net vs main: 35 files, +5971/-75.

One receipt for all sections. 1371 and 1373 have no receipts of their own; no earlier verdict carries over.
Compact form (cap 150,000 bytes): read the snapshot at `--pr 1377`. Hunks below are -U0 for A, B and C and -U2 for D, and cover only risky code: secret and env handling, host apply, the fail-closed gates (disk, derive-blob, boot-check, AC-13 bounds) and the unhold gate. Every other file is named with its diffstat.
Redaction: rw-ship.sh holds the default SELFHOST_APP host address on one line outside these hunks; the packet has no dotted address.

## Ranges, each checked with `git merge-base --is-ancestor <c> 51ae3d52` (all ok, t2-dev)
179c3ab1, ed296b0a, bff96cc5, c9d61ac1, 97bfac51, 80b26c7e, d9cb6162, 679c278a, 5eafc9a0, f6e45adc.
- **A, 1371:** `ed296b0a..bff96cc5` (f7e602bd, f59392bb, 59501565, bff96cc5).
- **B, 1373:** `c9d61ac1..97bfac51` plus 80b26c7e (1372 UTF-8 residue fix, docker.ts and its test, parent c9d61ac1). 80b26c7e is in HEAD through the main join 5eafc9a0 (main 179c3ab1 has #1372). 5dd6865c, the open 1373 PR head, equals 97bfac51 joined with 80b26c7e and is not an endpoint here. 7a5b5a01 and 4a142511 later touch three 1373 files (Section C).
- **C, gate:** `d9cb6162..679c278a` (7a5b5a01, 4aa75203, 4a142511, b3e183b7, 8c519f5f, 5ead8901, ab028a6b, 679c278a).
- **Join:** 5eafc9a0, parents 679c278a and 179c3ab1, clean (docker.ts auto-resolved).
- **D, F1 (receipt bth-pr73-v5, raised on bugtracker-harness PR 73, same bytes here):** `5eafc9a0..51ae3d52` (f6e45adc fix, efa4c409 and 51ae3d52 tests). Ported to the rh line as bugtracker PR #1384 (730429f8..5daddbbf).

## A (1371): job images, goodqa#16136 AC-1..19. 6 files +1407/-40
[H] rw-ship.sh 126, selfhost-ctl.py 241, ac13-count.py 148. Named: README.md 20, test_ac13_count.py 147, test_rw_ship_selfhost.py 765.
Job images ship digest-pinned (`goodqa-JOB@sha256:<VM id>`, one &job-images block, compose-resolved for both services, presence-checked). SELFHOST_JOB_HOLD defaults to `intelligence-worker,transcribe`; anything but `none` or a strict list exits 2 before build. `--guard-hold TRANSCODER_MODE=transcribe` only for a guard that refuses a malformed GUARD_HELD_ENV; after the switch `guard-log` must report it or the stack rolls back. Disk gate exits 11 before load (D replaces how the containerd root is found). Fail first: F1 and F2 of the forward-port failed on pre-fix sources.

## B (1373): env via private --env-file, the GitHub App key as an allow-listed JOB_ENVFILE, host apply. 21 files +2879/-15, plus 80b26c7e 2 files +69/-2
[H] dispatcher config.ts 7, docker.ts 87 (+9 in 80b26c7e), index.ts 8, job-env-file.ts 144, server.ts 31; selfhost/app apply-job-secrets-host.py 350, apply-job-secrets.sh 59, derive-job-secrets.py 336, compose.yaml 2, env-keys.json 1. Named: cmdline-sampler.py 132 (read-only verifier), run_derive_tests.sh 16; tests docker-failure-message 62, docker 19, env-file 211, job-env-file 204, test_selfhost_ctl_job_secrets.py 106, selfhost-job-secrets-drift.test.mjs 95, test_apply_job_secrets_host.py 296, _wrapper 147, test_cmdline_sampler.py 168, test_derive_job_secrets.py 475.
- Every launch passes env through `--env-file` (0700 mkdtemp, O_EXCL|O_NOFOLLOW 0600, removed in finally; stale dirs swept at boot), never `-e`.
- Only INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY may come from /run/goodqa-secrets (O_NOFOLLOW|O_NONBLOCK, S_ISREG, 64 KiB); boot logs names only.
- derive-job-secrets.py writes the key root:64910 0440 (temp-then-rename, inode check, no links, one status line, never a value).
- Host apply adds two marked compose lines and one env key, validates with `docker compose config -q` first, O_EXCL root 0600 backups, restore removes only its own lines; wrapper takes the deploy lock (exit 75), streams `sudo python3 -I -`.
- 80b26c7e: residue threshold and redaction count UTF-8 bytes.
Fail first: job-env-file.test.ts 21/23 failed unwired; drift test 5 failed before compose/env-keys; F2/F3 failed first; variants V1-5, H1-6, W1-4, S1-5, C1-2 each fail; 80b26c7e 11 failed before, 52 passed after, value.length variant 11 failed.

## C (gate): unhold gate (spec v4 AC-8, P3, P4) and the 1370 fail-closed fixes. 18 files +1268/-63
[H] boot-check.ts 41, index.ts 24, ac13-count.py 65, install-d2.sh 23, rw-ship.sh 94, selfhost-ctl.py 157, derive-job-secrets.py 5. Named: cmdline-sampler.py 6, tests boot-check 86, test_ac13_count 116, test_install_d2_upgrade 63, test_runner_ship_adapter 3, test_rw_release_authority_d2 6, test_rw_ship_jobsecret_gate 199, test_rw_ship_selfhost 187, test_selfhost_ctl_gate 209, test_selfhost_ctl_job_secrets 42, test_cmdline_sampler 5.
- Binding `derive-blob <40hex>` (one last line, equal to the blob at the bound commit); derive streamed only when it matches, else refuse or stay held.
- Pre-switch: derive, dispatcher env names, P3 trial boot (exit 2). Gate (c) after the guard check: re-hold `${STAMP}h` exit 8 after migrations, else restore h, STAMP, up, exit 5; failed restore `${STAMP}h2`.
- ctl verbs envfile-key, disp-boot, trial-boot (--rm, no network, read-only, cap-drop ALL, no-new-privileges, user node, group 64910, pids 64, 256m, no socket, always removed), up-dispatcher.
- `--boot-check` CLI flag: 0 only with at least one key all ok; 1, 2, 3 otherwise.
- ac13-count.py fails closed (INCONCLUSIVE exit 1); times finite float or int within 2**53; store_is_containerd needs exactly-two-string rows; job_lines only under the guard `environment`; presence parity covers held keys.
Fail first: 7a5b5a01 1 failed/2 passed; 4aa75203 1 failed/7 passed; 4a142511 failures=1/12 OK; b3e183b7 23 failed/23 passed (G1-15); 8c519f5f 2 failed/49 passed (I1-4); 5ead8901 33 failed/33 passed (M1-15); ab028a6b 9+25 failed/18+28 passed; 679c278a 1 failed (OverflowError)/19 passed.

## D (F1): the disk gate measures the store of the containerd docker uses. 3 files +473/-13
[H] selfhost-ctl.py 191, rw-ship.sh 5. Named: test_rw_ship_selfhost.py 290.
- Before: DockerRootDir plus a bare `containerd config dump`, which can name a root that is not the store docker uses.
- Endpoint order: docker info .Containerd.Address (Docker 27+); else the one process named dockerd holding docker's API socket and its `--containerd`; else its daemon.json `containerd` (`--config-file`, else /etc/docker/daemon.json; unparseable refuses); else both default sockets (/run/containerd, dockerd-managed /var/run/docker/containerd): exactly one live, or both with the same root.
- Then exactly one LISTEN inode at the path (/proc/net/unix) and exactly one holder among the socket owner's processes in this pid namespace; its `--root`, else the top-level `root` of its `--config` (section keys ignored, empty imports allowed, non-empty refuse, twice refuses), realpath, must exist.
- As root (the VM, `sudo python3 -`) an unreadable process refuses; unprivileged it is skipped, and refuses if no holder is visible.
- Each failure has its own message; rw-ship prints it after `VM image store: unresolved` (exit 11, NO DISK, nothing loaded). No new dependency or privilege.
- Retargeted, not removed: test_vm_disk_unresolved_containerd_root_refuses cases containerd-fail/containerd-noroot (failures of the removed dump) are now no-listener and old-docker-no-dockerd, same exit-11 assertions plus the reason.
- New: test_transcribe_hold_old_guard_that_just_listens_holds_transcode (fixture control guard-old-timeout had no test).
Fail first: new F1 tests with the 5eafc9a0 ctl -> 27 failed (DID NOT RAISE, alt-root measured, rc 0 not 11); after -> 47 passed. Mutants M1 holder count, M2 default disagreement, M3 dockerd count, M4 section stop, M5 two sockets, M6 imports, M7 root exists, M8 as-root refusal, M9 no-holder refusal -> each fails at least one test (M8 survived the first run; efa4c409/51ae3d52 add the tests that catch it). Old-guard variant (timeout counts as support) -> 1 failed.

## Tests (t2-dev)
Join 5eafc9a0 (all sections A-C), status clean, 33G free:
```
$ cd apps/job-dispatcher && npx vitest run
      Tests  456 passed | 15 skipped (471)
exit 0
$ cd apps/job-dispatcher && npx tsc --noEmit
exit 0
$ bash infra/selfhost/app/run_derive_tests.sh
Ran 61 tests  OK (skipped=2) (root container; host run OK, skipped=41)
exit 0
$ python3 -m unittest test_apply_job_secrets_wrapper test_cmdline_sampler
Ran 20 tests  OK
exit 0
$ node --test infra/selfhost-job-secrets-drift.test.mjs infra/selfhost-plan.test.mjs infra/selfhost/app/qa-closure-topology.test.mjs
# pass 23  # fail 0
exit 0
$ pytest -q (release-harness: test_ac13_count test_rw_ship_jobsecret_gate test_rw_ship_selfhost test_rw_release_authority_d2 test_install_d2_upgrade test_runner_ship_adapter test_rw_runtime_root test_selfhost_ctl test_selfhost_ctl_gate test_selfhost_ctl_job_secrets)
1963 passed, 1 skipped in 1010.87s
exit 0
```
D, f6e45adc (separate worktree):
```
$ pytest -q test_rw_ship_selfhost.py test_rw_release_authority_d2.py test_selfhost_ctl.py test_selfhost_ctl_gate.py test_selfhost_ctl_job_secrets.py test_rw_ship_jobsecret_gate.py
1843 passed, 1 skipped in 823.74s
exit 0
$ pytest -q test_rw_ship_selfhost.py -k "f1_ or vm_disk or unresolved_containerd or measures_dockers"   (51ae3d52)
47 passed
exit 0
```
- goodqa#16218 (test_rw_runtime_root.py, 5 intermittent failures under load, likely fixed 0.3 s lock sleeps, unverified) did not recur; keep tracebacks if it does.
- release-harness needs a git identity (fake one set); without it test_fast_ship_propagates_root_to_installed_adapter fails the same at bff96cc5.
- Real engine (1373, REALLY_TESTED): w5eff9b17217 env-file round trip; w9cce3d7b822 4 profiles 0 mismatches, held refusal fires; w276c9ce4c41 held stderr same with -e or --env-file.
- PENDING_REAL_TEST: p16148-sampler-live, p16148-gate-c-live, p16148-trial-boot-live, p16136-ac4-real-guard.

## Landing window order (main authorizes each step; no agent runs anything on the prod VM)
0. Information only, not a precondition: the operator notes `docker version --format '{{.Server.Version}}'` on the VM. Below 27 the gate takes the dockerd/daemon.json/default-socket path; it refuses (exit 11) when that is ambiguous.
1. `apply-job-secrets.sh --check`, then the env-name check (dispenv-names-check.py, sha256 a20c5236…) as step 0 of the host apply.
2. `apply-job-secrets.sh apply`.
3. New binding with the derive-blob line (install-d2.sh).
4. First release still HELD: drift gate green, dispatcher boot line ok, cmdline sampler PASS.
5. Unhold as a later release, after every intelligence-worker key is set via set-secret-env (goodqa#16208: confirm which selfhost-ctl.py copy set-secret-env.sh runs, by name and path only).
Access: the runner's ssh route and key, non-interactive `sudo python3 -I -`. No vault entry, no password.

## Risks
- Fail-open closures (review focus): ac13 unreadable records, borrowed times, NaN/huge ints; store discovery; held keys under labels and out of parity; unhold without derive/env-name/trial-boot/gate (c); and (D) the disk gate measuring a containerd root docker does not use.
- D on the VM: an unexpected layout (two live default sockets with different roots, a socket-activated containerd held by two processes, imports in the containerd config) refuses every release with exit 11 and a named reason; that is the intended fail-closed direction, and the reason names the fix.
- From the join until the host apply, the CC8.1 drift gate is red against the live VM; nothing promotes until window steps 1-2.
- Deferred: Q1 cross-constant test; rh port of the gate (D is ported, #1384); #16195, #16196, #16208, #16210.
- Nothing is merged, deployed or tagged.

## Risky hunks. Each section header line starts with `### SECTION`
