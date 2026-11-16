# PR review packet (whole PR): goodqa#16148 rw-ship job-secret gate, carrying the 1371 job-image forward-port and the 1373 job env-file content

Tickets: GoodQA goodqa#16148 (gate and 1373 content), GoodQA goodqa#16136 (1371 content). Related tickets: goodqa#16195, #16196, #16198, #16208, #16210.
Repo: ericmacdougall/bugtracker. Branch fix/16148-rwship-gate.
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
__EVIDENCE__

## Diff (sections A, B, C; each section's header line starts with `### SECTION`)
