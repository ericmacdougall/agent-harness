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
```diff
### SECTION A: 1371 content, ed296b0a..bff96cc5 (common base with main .. 1371 head)
diff --git a/infra/release-harness/README.md b/infra/release-harness/README.md
index 98cf382ad1a..8ad93dfa984 100644
--- a/infra/release-harness/README.md
+++ b/infra/release-harness/README.md
@@ -25,6 +25,26 @@ Tests (run from the lane root `bin/`): `test_rw_release_authority_d2.py`, `test_
 `e11-boundary-check.sh` reports whether a process identity can reach production credentials (E11). Lanes are currently
 EXPOSED.
 
+## Job images (goodqa#16136)
+
+The job-dispatcher starts four job images (scan, transcode, intelligence-worker, suggest-fix-worker). Each is an exact
+`JOB_IMAGE_*` value in the create-guard's `&job-images` block of `infra/selfhost/app/compose.yaml`; the dispatcher inherits
+that block. This `rw-ship.sh` builds those images from the release SHA, loads them with the app images, and pins each as
+`goodqa-<job>@<image id on the VM>`. `selfhost-ctl.py pin` refuses a pin unless every release-managed ref resolves on the
+host, and it requires the containerd image store. `state` reports `jobs`, `jobs_held` and `jobs_missing`.
+
+- Holds: `SELFHOST_JOB_HOLD` in `biz/release-waves/ship.conf` defaults to `intelligence-worker,transcribe`; `none` lifts it.
+  A held kind's line becomes `KEY: "" # held`: the dispatcher answers 501 "no image configured" (docker is never called)
+  and the guard has no image for it, so it never starts, even if an older image of it is on the host. `transcribe` is held at the guard (`GUARD_HELD_ENV=TRANSCODER_MODE=
+  transcribe`) while MP4 runs. If the release's own guard does not refuse a malformed `GUARD_HELD_ENV` (probed by running
+  the built image), the whole transcode image is held instead. Lifting a hold is main's decision.
+- Not every entry point rebuilds job images. The harness copy `~/repos/harness/bin/rw-ship.sh` (used by `ship-fast`,
+  `wave-loop` and `wave-revert-ship`) re-pins only the four service image lines. A release through it keeps whatever job
+  pins `compose.yaml` already has; goodqa#16146 AC-7 covers that entry point.
+- Never run `docker image prune -a` on the app host. The job images are loaded, never pushed, so a pruned job image
+  cannot be pulled back: its kind stops launching until the next full release. `state.jobs_missing` and goodqa#16150 watch
+  for that.
+
 ## Permanent runtime contract (`RW_LANE_ROOT`)
 
 Set `RW_LANE_ROOT` to an existing absolute directory on a persistent local filesystem for **every** ship, settle,
diff --git a/infra/release-harness/ac13-count.py b/infra/release-harness/ac13-count.py
new file mode 100755
index 00000000000..9913d48a6f4
--- /dev/null
+++ b/infra/release-harness/ac13-count.py
@@ -0,0 +1,148 @@
+#!/usr/bin/env python3
+"""goodqa#16136 AC-13: count job-dispatcher launch responses per job kind from its container log, fail closed.
+
+Reads the dispatcher's Fastify JSON log (`docker logs --timestamps` output; any prefix before the first `{` is ignored).
+A "request completed" line carries res.statusCode and the reqId of the "incoming request" line that carries the URL;
+only POST /jobs/<kind>/run requests are counted. Nothing but statusCode, URL, reqId and time is read, so no request
+body, header or env value is ever printed.
+
+  --mode pre   positive control: the window must hold at least one 422 (proves the matcher sees launch failures).
+  --mode post  after a release:
+     2xx on any kind                                   -> ok
+     501 on a kind named by --held-empty                -> held (its JOB_IMAGE_* line is "" # held), excluded
+     422 on transcode with --guard-held-transcribe      -> held ONLY when matched one-to-one, within --pair-seconds
+                                                           (default 5), to its own API line `transcribe: failed to
+                                                           launch job` whose 422 body names the guard reason
+                                                           `TRANSCODER_MODE=transcribe is held on this guard`
+     any other non-2xx on any kind (501 on a non-held kind, 422 on a non-held kind, 5xx, 4xx) -> failure
+     --require-2xx KIND: at least one 2xx for KIND, else failure
+  API input (--refusals, repeatable): one file per api replica (`docker logs --timestamps <replica>`), or one
+  `docker compose logs --timestamps api` file whose lines carry a `<replica> | ` prefix. Every replica must be read:
+  the JSON names the replicas seen, and --api-replicas N fails the run when that count differs.
+  Pairing reads both logs over the window widened by --pair-seconds on each side, so a held launch that straddles a
+  window edge still pairs; an unmatched 422 or held API line inside the window, an in-window API launch-failure line
+  for any other reason, and an API launch-failure line without a readable timestamp are failures.
+Exit 0 PASS, 1 FAIL, 2 usage or unreadable input. Output: one JSON object.
+"""
+import argparse, calendar, json, re, sys, time
+
+KINDS = ('scan', 'transcode', 'intelligence-worker', 'suggest-fix-worker')
+HOLDABLE = ('intelligence-worker', 'transcode')
+ROUTE = re.compile(r'^/jobs/([a-z-]+)/run(?:\?.*)?$')
+HELD_TAG = 'TRANSCODER_MODE=transcribe is held on this guard'
+API_MARK = 'transcribe: failed to launch job'
+API_LINE = re.compile(r'^(?:(\S+)\s+\|\s+)?(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?Z\s')
+
+
+def records(path):
+    with open(path, encoding='utf-8', errors='replace') as f:
+        for line in f:
+            i = line.find('{')
+            if i < 0: continue
+            try: r = json.loads(line[i:])
+            except ValueError: continue
+            if isinstance(r, dict): yield r
+
+
+def inside(t, since, until):
+    return (since is None or t >= since) and (until is None or t < until)
+
+
+def launches(path):
+    """[(time, kind, status)] for every completed POST /jobs/<kind>/run with a numeric time."""
+    pending, out = {}, []
+    for r in records(path):
+        rid, msg = r.get('reqId'), r.get('msg')
+        if msg == 'incoming request':
+            req = r.get('req') or {}
+            m = ROUTE.match(str(req.get('url', '')))
+            if req.get('method') == 'POST' and m: pending[rid] = m.group(1)
+            else: pending.pop(rid, None)
+        elif msg == 'request completed' and rid in pending:
+            kind = pending.pop(rid)
+            st = (r.get('res') or {}).get('statusCode'); t = r.get('time')
+            if isinstance(st, int) and isinstance(t, (int, float)): out.append((t, kind, st))
+    return out
+
+
+def api_lines(paths):
+    """([held times], [other-reason times], untimed count, replicas seen) from the api replica logs."""
+    held, other, untimed, replicas = [], [], 0, set()
+    for n, path in enumerate(paths):
+        with open(path, encoding='utf-8', errors='replace') as f:
+            for line in f:
+                if not line.strip(): continue
+                m = API_LINE.match(line)
+                if m: replicas.add((n, m.group(1)))
+                if API_MARK not in line: continue
+                if not m: untimed += 1; continue
+                t = calendar.timegm(time.strptime(m.group(2), '%Y-%m-%dT%H:%M:%S')) * 1000 + int((m.group(3) or '0')[:3].ljust(3, '0'))
+                (held if 'job-dispatch transcode failed (422)' in line and HELD_TAG in line else other).append(t)
+    return held, other, untimed, sorted('%d:%s' % (n, p or 'file') for n, p in replicas)
+
+
+def pair(a, b, tol):
+    """Greedy in time order: each a matched to the earliest unmatched b within tol. Returns (unmatched a, unmatched b)."""
+    b = sorted(b); used = [False] * len(b); ua = []
+    for t in sorted(a):
+        for i, u in enumerate(b):
+            if not used[i] and abs(u - t) <= tol: used[i] = True; break
+        else: ua.append(t)
+    return ua, [u for i, u in enumerate(b) if not used[i]]
+
+
+def main(argv=None):
+    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
+    ap.add_argument('log'); ap.add_argument('--mode', choices=('pre', 'post'), required=True)
+    ap.add_argument('--held-empty', action='append', default=[], choices=HOLDABLE)
+    ap.add_argument('--guard-held-transcribe', action='store_true')
+    ap.add_argument('--refusals', action='append', default=[], help='api replica log (docker logs --timestamps); repeat per replica')
+    ap.add_argument('--api-replicas', type=int, help='the number of api replicas that must be read')
+    ap.add_argument('--pair-seconds', type=float, default=5.0)
+    ap.add_argument('--require-2xx', action='append', default=[], choices=KINDS)
+    ap.add_argument('--since', type=int); ap.add_argument('--until', type=int)
+    a = ap.parse_args(argv)
+    if a.guard_held_transcribe and 'transcode' in a.held_empty:
+        ap.error('--guard-held-transcribe and --held-empty transcode are exclusive (a held-empty transcode never reaches the guard)')
+    if a.guard_held_transcribe and not a.refusals:
+        ap.error('--guard-held-transcribe needs --refusals: a held transcription 422 is excluded only when matched to its API launch-failure line')
+    tol = int(a.pair_seconds * 1000)
+    try:
+        got = launches(a.log)
+        held_api, other_api, untimed, replicas = api_lines(a.refusals) if a.refusals else ([], [], 0, [])
+    except OSError as e:
+        print(json.dumps({'verdict': 'FAIL', 'error': 'unreadable input: %s' % e.strerror})); return 2
+    inwin = [(t, k, st) for t, k, st in got if inside(t, a.since, a.until)]
+    counts = {}
+    for _, k, st in inwin: counts.setdefault(k, {}).setdefault(str(st), 0); counts[k][str(st)] += 1
+    failures, held = [], {}
+    if a.mode == 'pre':
+        if not any(st == 422 for _, _, st in inwin): failures.append('positive control: no 422 in the window (the matcher proves nothing)')
+    else:
+        for t, k, st in inwin:
+            if 200 <= st < 300: continue
+            if st == 501 and k in a.held_empty: held[k] = held.get(k, 0) + 1; continue
+            if st == 422 and k == 'transcode' and a.guard_held_transcribe: continue
+            failures.append('%s %d at %s' % (k, st, t))
+        if a.guard_held_transcribe:
+            lo = None if a.since is None else a.since - tol; hi = None if a.until is None else a.until + tol
+            tc = [t for t, k, st in got if k == 'transcode' and st == 422 and inside(t, lo, hi)]
+            ua, ub = pair(tc, [t for t in held_api if inside(t, lo, hi)], tol)
+            ua = [t for t in ua if inside(t, a.since, a.until)]; ub = [t for t in ub if inside(t, a.since, a.until)]
+            for t in ua: failures.append('transcode 422 at %s has no held API launch-failure line within %ss' % (t, a.pair_seconds))
+            for t in ub: failures.append('held API launch-failure line at %s has no transcode 422 within %ss' % (t, a.pair_seconds))
+            held['transcode'] = sum(1 for t, k, st in inwin if k == 'transcode' and st == 422) - len(ua)
+        bad = [t for t in other_api if inside(t, a.since, a.until)]
+        if bad: failures.append('%d transcription launch-failure lines with another reason' % len(bad))
+        if untimed: failures.append('%d transcription launch-failure lines without a readable timestamp' % untimed)
+        if a.api_replicas is not None and a.refusals and len(replicas) != a.api_replicas:
+            failures.append('read %d api replicas, expected %d' % (len(replicas), a.api_replicas))
+        for k in a.require_2xx:
+            if not any(kk == k and 200 <= st < 300 for _, kk, st in inwin): failures.append('no 2xx for %s' % k)
+    print(json.dumps({'verdict': 'FAIL' if failures else 'PASS', 'mode': a.mode, 'counts': counts, 'held_excluded': held,
+                      'api_replicas': len(replicas), 'api_replica_sources': replicas, 'failures': failures}, sort_keys=True))
+    return 1 if failures else 0
+
+
+if __name__ == '__main__':
+    sys.exit(main())
diff --git a/infra/release-harness/rw-ship.sh b/infra/release-harness/rw-ship.sh
index 1cc387057df..59de044354d 100755
--- a/infra/release-harness/rw-ship.sh
+++ b/infra/release-harness/rw-ship.sh
@@ -216,7 +216,7 @@ if [ "$TARGET" = selfhost ]; then
   SH_APP=$(shconf SELFHOST_APP ubuntu@<IP-REDACTED>); SH_DIR=$(shconf SELFHOST_DIR /opt/goodqa/infra/selfhost/app)
   SH_ENV=$(shconf SELFHOST_ENV_DIR /etc/goodqa); SH_PROJECT=$(shconf SELFHOST_PROJECT goodqa)
   SH_FREEZE_UNTIL=$(shconf SELFHOST_SCHEMA_FREEZE_UNTIL 2026-10-15T02:31:00Z); SH_UP_TIMEOUT=$(shconf SELFHOST_UP_TIMEOUT 300)
-  SH_MIN_FREE_GB=$(shconf SELFHOST_BUILD_MIN_FREE_GB 15); MIGLOG="$RD/migrate-*.txt"
+  SH_MIN_FREE_GB=$(shconf SELFHOST_BUILD_MIN_FREE_GB 30); SH_VM_MIN_FREE_GB=$(shconf SELFHOST_VM_MIN_FREE_GB 20); MIGLOG="$RD/migrate-*.txt"
   printf -v SH_CTL 'sudo python3 - --dir %q --env-dir %q --project %q' "$SH_DIR" "$SH_ENV" "$SH_PROJECT"
   vmctl(){ ssh -o ConnectTimeout=15 -o BatchMode=yes -o ServerAliveInterval=30 "$SH_APP" "$SH_CTL $*" < "$TOOLS/bin/selfhost-ctl.py"; }
   sh_state(){ local i j; for i in 1 2 3; do j=$(vmctl state 2>/dev/null | grep -m1 '^{'); [ -n "$j" ] && { printf '%s' "$j"; return 0; }; sleep 5; done; return 1; }
@@ -556,8 +556,21 @@ PY
 if [ "$TARGET" = selfhost ]; then
   # IMAGES (self-host): the product's gates via promote.sh --app=api WITHOUT --apply, then web + job-dispatcher built here
   FREE=$(df --output=avail -BG "$S" 2>/dev/null | tail -1 | tr -dc 0-9)
-  [ "${FREE:-0}" -ge "$SH_MIN_FREE_GB" ] || { say "NO DISK (infrastructure, exit 11): ${FREE:-?}G free on this box, $SH_MIN_FREE_GB G needed to build three images; nothing built or switched"; dbx "$NAME" deploy-failed "$BEFORE" "infrastructure: ${FREE:-?}G free on the build box (needs $SH_MIN_FREE_GB); nothing went live; run $RD"; exit 11; }
+  [ "${FREE:-0}" -ge "$SH_MIN_FREE_GB" ] || { say "NO DISK (infrastructure, exit 11): ${FREE:-?}G free on this box, $SH_MIN_FREE_GB G needed to build seven images; nothing built or switched"; dbx "$NAME" deploy-failed "$BEFORE" "infrastructure: ${FREE:-?}G free on the build box (needs $SH_MIN_FREE_GB); nothing went live; run $RD"; exit 11; }
   TAG=${SHA:0:12}-$STAMP; IMG_API=goodqa-api:$TAG; IMG_WEB=goodqa-web:$TAG; IMG_DISP=goodqa-job-dispatcher:$TAG
+  # JOB IMAGES (goodqa#16136): the dispatcher's four job images are built and loaded with the app images and pinned as
+  # goodqa-<job>@<image id on the VM>. SELFHOST_JOB_HOLD (default intelligence-worker,transcribe; "none" = no hold) blocks a
+  # kind (its line becomes "" # held, so the dispatcher refuses it with 501 and the guard has no image for it), or holds
+  # transcription at the guard (GUARD_HELD_ENV) while MP4 runs.
+  # One canonical form (review F1): "none", or kinds joined by single commas with no spaces or empty items. held() reads
+  # this same validated string, so a value that is accepted can never release a kind it names.
+  JHOLD=$(shconf SELFHOST_JOB_HOLD intelligence-worker,transcribe)
+  if [ "$JHOLD" = none ]; then JHOLD=""
+  elif ! [[ "$JHOLD" =~ ^(intelligence-worker|transcribe)(,(intelligence-worker|transcribe))*$ ]]; then
+    say "ABORT: SELFHOST_JOB_HOLD '$(printf '%s' "$JHOLD" | tr -c 'a-z0-9,-' '?' | cut -c1-60)' is not none or a comma list of intelligence-worker, transcribe (no spaces, no empty items); nothing built or switched"
+    dbx "$NAME" deploy-failed "$BEFORE" "bad SELFHOST_JOB_HOLD; nothing went live; run $RD"; exit 2
+  fi
+  held(){ case ",$JHOLD," in *",$1,"*) return 0;; esac; return 1; }
   PROMOTED=registry.digitalocean.com/goodqa-prod/bugtracker-api:deploy-${SHA:0:8}
   mkdir -p "$RD/tmp"
   ADMISSION_START=$SECONDS
@@ -584,9 +597,22 @@ if [ "$TARGET" = selfhost ]; then
   bash infra/do/promote.sh --app=api --deployment-scope=selfhost --sha="$SHA" --qualify-only --build-receipt="$GATE_RECEIPT" > "$RD/admission-readback.log" 2>&1 || exit 3
   # Plan only commands here. The helper owns each process group, log, terminal
   # result and exact image ID. Gate evidence is independently rechecked by API.
-  python3 - "$RD" "$SHA" "$IMG_API" "$IMG_WEB" "$IMG_DISP" "$PROMOTED" "$GATE_RECEIPT" <<'PY_PLAN' || exit 3
+  JOBIMGS=(); JOBKEYS=(); JOBSPECS=(); HOLDARGS=""; GUARDARGS=""; HOLDNOTE=""
+  # transcribe held: transcode is built provisionally; after the build, the built dispatcher image's guard is probed
+  # (AC-17/D1: by behaviour, never by source text). Only a guard that implements GUARD_HELD_ENV refuses to start on a
+  # malformed value; any other outcome holds the whole transcode image instead.
+  for j in "scan apps/scan-worker/Dockerfile JOB_IMAGE_SCAN" "transcode apps/transcoder/Dockerfile JOB_IMAGE_TRANSCODE" \
+           "intelligence-worker apps/intelligence-worker/Dockerfile JOB_IMAGE_INTELLIGENCE_WORKER" \
+           "suggest-fix-worker apps/suggest-fix-worker/Dockerfile JOB_IMAGE_SUGGEST_FIX_WORKER"; do
+    read -r J F K <<< "$j"
+    if held "$J"; then
+      HOLDARGS="$HOLDARGS --job-hold $K"; [ "$J" = transcode ] || HOLDNOTE="$HOLDNOTE $J"; continue; fi
+    JOBSPECS+=("$J=$F=goodqa-$J:$TAG"); JOBIMGS+=("goodqa-$J:$TAG"); JOBKEYS+=("$K")
+  done
+  say "job images: building ${JOBIMGS[*]:-none}; held:${HOLDNOTE:- none}"
+  python3 - "$RD" "$SHA" "$IMG_API" "$IMG_WEB" "$IMG_DISP" "$PROMOTED" "$GATE_RECEIPT" "${JOBSPECS[@]}" <<'PY_PLAN' || exit 3
 import json, shlex, sys
-rd, sha, api, web, disp, promoted, receipt = sys.argv[1:]
+rd, sha, api, web, disp, promoted, receipt = sys.argv[1:8]
 api_command = shlex.join(['bash', 'infra/do/promote.sh', '--app=api', '--deployment-scope=selfhost', '--sha='+sha, '--build-receipt='+receipt]) + ' && ' + shlex.join(['docker', 'tag', promoted, api])
 jobs = [dict(name='api', image=api, argv=['bash', '-c', api_command])]
 for app, image in [('web', web), ('job-dispatcher', disp)]:
@@ -595,28 +621,70 @@ for app, image in [('web', web), ('job-dispatcher', disp)]:
     argv += ['--label', 'org.opencontainers.image.revision='+sha, '-t', image, '--load', rd+'/src']
     jobs.append(dict(name=app, image=image, argv=argv))
 json.dump(dict(sha=sha, recordDir=rd, jobs=jobs), open(rd+'/build-plan.json', 'w'))
+# goodqa#16136: the dispatcher job images, built from the same context in further plans of at most three jobs each,
+# because rw-image-jobs.py owns at most three image commands (RESOURCE_ADMITTED maxJobs=3).
+specs = sys.argv[8:]
+for n, start in enumerate(range(0, len(specs), 3), 1):
+    batch = []
+    for spec in specs[start:start + 3]:
+        app, dockerfile, image = spec.split('=', 2)
+        batch.append(dict(name=app, image=image, argv=['nice', '-n', '5', 'docker', 'buildx', 'build', '--platform', 'linux/amd64', '--pull',
+                                                       '-f', dockerfile, '--label', 'org.opencontainers.image.revision='+sha, '-t', image, '--load', rd+'/src']))
+    d = '%s/job-images-%d' % (rd, n)
+    __import__('os').makedirs(d, exist_ok=True)
+    json.dump(dict(sha=sha, recordDir=d, jobs=batch), open(d+'/build-plan.json', 'w'))
 PY_PLAN
-  TMPDIR=$RD/tmp python3 infra/release-harness/rw-image-jobs.py --plan "$RD/build-plan.json" &
-  BUILD_DRIVER=$!
-  wait "$BUILD_DRIVER"; rc=$?; BUILD_DRIVER=""
-  [ "$rc" = 0 ] || { say "ABORT: image jobs rc=$rc (terminal results in jobs.json)"; dbx "$NAME" deploy-failed "$BEFORE" "image jobs rc=$rc; nothing went live; run $RD"; exit 3; }
+  for PLAN in "$RD/build-plan.json" "$RD"/job-images-*/build-plan.json; do
+    [ -f "$PLAN" ] || continue
+    TMPDIR=$RD/tmp python3 infra/release-harness/rw-image-jobs.py --plan "$PLAN" &
+    BUILD_DRIVER=$!
+    wait "$BUILD_DRIVER"; rc=$?; BUILD_DRIVER=""
+    [ "$rc" = 0 ] || { say "ABORT: image jobs rc=$rc (terminal results in $(dirname "$PLAN")/jobs.json)"; dbx "$NAME" deploy-failed "$BEFORE" "image jobs rc=$rc; nothing went live; run $RD"; exit 3; }
+  done
   mkdir -p audit/promotion-receipts
   cp "$GATE_RECEIPT" "audit/promotion-receipts/${SHA:0:8}-api-$STAMP.json" || exit 3
   git add -A infra audit && git "${GI[@]}" commit -q -m "chore(deploy): retain verified API admission and build boundary for ${SHA:0:12}"
+  if held transcribe; then
+    timeout 60 docker run --rm --network none --read-only --tmpfs /tmp --entrypoint node_modules/.bin/tsx -e GUARD_ENV=dev \
+         -e JOB_IMAGE_SCAN=goodqa-scan@sha256:0000000000000000000000000000000000000000000000000000000000000000 \
+         -e GUARD_HELD_ENV=TRANSCODER_MODE "$IMG_DISP" src/create-guard-main.ts > "$RD/guard-probe.txt" 2>&1; prc=$?
+    if [ "$prc" != 0 ] && [ "$prc" != 124 ] && grep -q 'GUARD_HELD_ENV must be' "$RD/guard-probe.txt"; then
+      GUARDARGS=" --guard-hold TRANSCODER_MODE=transcribe"; HOLDNOTE="$HOLDNOTE transcribe(guard)"
+      say "guard probe: the built guard refuses a malformed GUARD_HELD_ENV (rc=$prc), so transcription is held at the guard and MP4 runs"
+    else
+      HOLDNOTE="$HOLDNOTE transcode(whole image)"
+      say "transcode held: guard lacks GUARD_HELD_ENV in this release (probe rc=$prc), so the whole transcode image is held (its line emptied; the dispatcher refuses every transcode launch)"
+      NJI=(); NJK=()
+      for i in "${!JOBIMGS[@]}"; do [ "${JOBKEYS[$i]}" = JOB_IMAGE_TRANSCODE ] && { docker image rm "${JOBIMGS[$i]}" >/dev/null 2>&1; continue; }
+        NJI+=("${JOBIMGS[$i]}"); NJK+=("${JOBKEYS[$i]}"); done
+      JOBIMGS=("${NJI[@]}"); JOBKEYS=("${NJK[@]}"); HOLDARGS="$HOLDARGS --job-hold JOB_IMAGE_TRANSCODE"
+    fi
+  fi
   rm -rf "$RD/src" "$RD/tmp"
-  python3 - "$RD/jobs.json" <<'PY_IDS' || exit 3
-import json, subprocess, sys
-for job in json.load(open(sys.argv[1]))['jobs']:
+  python3 - "$RD" "${HOLDARGS}" <<'PY_IDS' || exit 3
+import glob, json, subprocess, sys
+rd, holds = sys.argv[1:3]
+jobs = [j for f in [rd + '/jobs.json'] + sorted(glob.glob(rd + '/job-images-*/jobs.json')) for j in json.load(open(f))['jobs']]
+for job in jobs:
+    if job['name'] == 'transcode' and '--job-hold JOB_IMAGE_TRANSCODE' in holds: continue   # removed on purpose by the hold
     now = subprocess.check_output(['docker', 'image', 'inspect', '-f', '{{.Id}}', job['image']], text=True).strip()
     if now != job['imageId']: raise SystemExit('REFUSED: image changed after build')
 PY_IDS
   TRANSFER_START=$SECONDS
+  # Review F2: the VM needs room for twice what is loaded (layers plus unpacked snapshots), and at least the floor.
+  LOADBYTES=0; for i in "$IMG_API" "$IMG_WEB" "$IMG_DISP" "${JOBIMGS[@]}"; do
+    b=$(docker image inspect -f '{{.Size}}' "$i" 2>/dev/null); [[ "$b" =~ ^[0-9]+$ ]] || b=x; [ "$b" = x ] && { LOADBYTES=x; break; }
+    LOADBYTES=$((LOADBYTES + b)); done
+  if [ "$LOADBYTES" = x ]; then VMNEED=x; else VMNEED=$(( (2 * LOADBYTES + (1 << 30) - 1) >> 30 )); [ "$VMNEED" -ge "$SH_VM_MIN_FREE_GB" ] || VMNEED=$SH_VM_MIN_FREE_GB; fi
+  VMDISK=$(vmctl disk 2>/dev/null | grep -m1 '^{'); VMFREE=$(printf '%s' "$VMDISK" | python3 -c 'import json,sys; print(json.load(sys.stdin)["free_gb"])' 2>/dev/null)
+  say "VM image store: $(printf '%s' "${VMDISK:-unresolved}" | cut -c1-900); need ${VMNEED}G (2 x ${LOADBYTES} bytes to load, floor ${SH_VM_MIN_FREE_GB}G)"
+  [ "$VMNEED" != x ] && [ "${VMFREE:-0}" -ge "$VMNEED" ] 2>/dev/null || { say "NO DISK on the VM (infrastructure, exit 11): ${VMFREE:-?}G free on $SH_APP, ${VMNEED}G needed before loading seven images; nothing switched"; dbx "$NAME" deploy-failed "$BEFORE" "infrastructure: ${VMFREE:-?}G free on the VM (needs $SH_VM_MIN_FREE_GB); nothing went live; run $RD"; exit 11; }
   say "images to $SH_APP: docker save | docker load"
-  docker save "$IMG_API" "$IMG_WEB" "$IMG_DISP" | ssh -o ConnectTimeout=15 -o BatchMode=yes -o ServerAliveInterval=30 "$SH_APP" 'sudo docker load' > "$RD/image-load.log" 2>&1
+  docker save "$IMG_API" "$IMG_WEB" "$IMG_DISP" "${JOBIMGS[@]}" | ssh -o ConnectTimeout=15 -o BatchMode=yes -o ServerAliveInterval=30 "$SH_APP" 'sudo docker load' > "$RD/image-load.log" 2>&1
   rc="${PIPESTATUS[0]} ${PIPESTATUS[1]}"
   [ "$rc" = "0 0" ] || { say "ABORT: image transfer failed (save/load rc $rc)"; dbx "$NAME" deploy-failed "$BEFORE" "image transfer rc $rc; nothing went live; run $RD"; exit 3; }
-  LOCALIDS=$(for i in "$IMG_API" "$IMG_WEB" "$IMG_DISP"; do printf '%s=%s\n' "$i" "$(docker image inspect -f '{{.Id}}' "$i" 2>/dev/null)"; done)
-  REMOTEIDS=$(vmctl image-ids "$IMG_API" "$IMG_WEB" "$IMG_DISP" 2>/dev/null | grep -m1 '^{')
+  LOCALIDS=$(for i in "$IMG_API" "$IMG_WEB" "$IMG_DISP" "${JOBIMGS[@]}"; do printf '%s=%s\n' "$i" "$(docker image inspect -f '{{.Id}}' "$i" 2>/dev/null)"; done)
+  REMOTEIDS=$(vmctl image-ids "$IMG_API" "$IMG_WEB" "$IMG_DISP" "${JOBIMGS[@]}" 2>/dev/null | grep -m1 '^{')
   IDCHK=$(python3 - "$REMOTEIDS" "$LOCALIDS" <<'PY'
 import json, sys
 try: r = json.loads(sys.argv[1])
@@ -632,17 +700,23 @@ PY
   [ "$IDCHK" = OK ] || { say "ABORT: the images on $SH_APP are not the ones built here: $IDCHK"; dbx "$NAME" deploy-failed "$BEFORE" "image id mismatch after transfer ($IDCHK); nothing went live; run $RD"; exit 3; }
   printf 'transfer %s\n' "$((SECONDS-TRANSFER_START))" >> "$RD/wall-times.txt"
   say "images on $SH_APP, ids match: $(printf '%s ' $LOCALIDS | cut -c1-400)"
+  JOBARGS=""; JOBREFS=()
+  for i in "${!JOBIMGS[@]}"; do
+    ref=$(python3 -c 'import json,sys; r=json.loads(sys.argv[1]); print(sys.argv[2].split(":")[0] + "@" + r[sys.argv[2]])' "$REMOTEIDS" "${JOBIMGS[$i]}") || { say "ABORT: no VM image id for ${JOBIMGS[$i]}"; dbx "$NAME" deploy-failed "$BEFORE" "job image id unreadable; nothing went live; run $RD"; exit 3; }
+    JOBARGS="$JOBARGS --job-image ${JOBKEYS[$i]}=$ref"; JOBREFS+=("$ref")
+  done
   mkdir -p audit/selfhost-deploys
-  python3 - "$NAME" "$SHA" "$STAMP" "$SH_APP" "$LOCALIDS" "$SH_BEFORE" > "audit/selfhost-deploys/${SHA:0:8}-$STAMP.json" <<'PY'
+  python3 - "$NAME" "$SHA" "$STAMP" "$SH_APP" "$LOCALIDS" "$SH_BEFORE" "$HOLDNOTE" > "audit/selfhost-deploys/${SHA:0:8}-$STAMP.json" <<'PY'
 import json, sys
-name, sha, stamp, host, ids, before = sys.argv[1:7]
+name, sha, stamp, host, ids, before, holds = sys.argv[1:8]
 print(json.dumps({'release': name, 'sha': sha, 'stamp': stamp, 'host': host, 'deploymentId': 'selfhost-' + stamp,
-                  'images': dict(l.split('=', 1) for l in ids.split('\n') if l), 'previous': json.loads(before or '{}')}, indent=1, sort_keys=True))
+                  'images': dict(l.split('=', 1) for l in ids.split('\n') if l), 'previous': json.loads(before or '{}'),
+                  'jobHolds': holds.split()}, indent=1, sort_keys=True))
 PY
   git add audit/selfhost-deploys && git "${GI[@]}" commit -q --no-verify -m "chore(deploy): self-host deploy record for ${SHA:0:12} ($NAME)
 
 Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
-  docker image rm "$IMG_API" "$IMG_WEB" "$IMG_DISP" "$PROMOTED" >/dev/null 2>&1   # local copies only (this box is short of disk); VM 102 holds them
+  docker image rm "$IMG_API" "$IMG_WEB" "$IMG_DISP" "${JOBIMGS[@]}" "$PROMOTED" >/dev/null 2>&1   # local copies only (this box is short of disk); VM 102 holds them
 else
 for app in api web; do
   say "promote $app start"
@@ -708,7 +782,7 @@ if [ "$TARGET" = selfhost ]; then
   # SWITCH (self-host): one step for api + web + job-dispatcher: re-pin (backups, validated, atomic replace), up, health, version
   say "switch the self-host stack live"; preswitch api $API; infl switch-api
   SWITCH_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
-  vmctl pin --stamp "$STAMP" --sha "$SHA" --deploy-id "selfhost-$STAMP" --api "$IMG_API" --web "$IMG_WEB" --disp "$IMG_DISP" > "$RD/pin.txt" 2>&1; rc=$?
+  vmctl pin --stamp "$STAMP" --sha "$SHA" --deploy-id "selfhost-$STAMP" --api "$IMG_API" --web "$IMG_WEB" --disp "$IMG_DISP"$JOBARGS$HOLDARGS$GUARDARGS > "$RD/pin.txt" 2>&1; rc=$?
   say "re-pin compose.yaml + release env rc=$rc"
   if [ $rc -ne 0 ]; then head -3 "$RD/pin.txt" | cut -c1-300 | tee -a "$LOG"
     if [ $rc = 3 ]; then say "the re-pin was refused before any file changed; nothing went live"; dbx "$NAME" deploy-failed "$BEFORE" "re-pin refused (nothing changed); nothing went live; run $RD"; exit 4; fi
@@ -718,6 +792,20 @@ if [ "$TARGET" = selfhost ]; then
   vmctl up --timeout "$SH_UP_TIMEOUT" > "$RD/up.txt" 2>&1; rc=$?
   say "up: $(grep -m1 '^UP_' "$RD/up.txt" | cut -c1-400) (rc=$rc)"
   [ $rc -eq 0 ] && grep -q '^UP_OK' "$RD/up.txt" || sh_fail_rollback "the new stack did not come up healthy"
+  if [ ${#JOBREFS[@]} -gt 0 ]; then   # goodqa#16136: the pinned job refs must still resolve, each to its own digest
+    JR=$(vmctl image-ids "${JOBREFS[@]}" 2>/dev/null | grep -m1 '^{')
+    JOK=$(python3 -c 'import json,sys
+try: r=json.loads(sys.argv[1])
+except Exception: print("UNREADABLE"); sys.exit()
+bad=[k for k in sys.argv[2:] if r.get(k)!=k.split("@",1)[1]]; print("OK" if not bad else "UNRESOLVED "+" ".join(bad))' "$JR" "${JOBREFS[@]}")
+    say "job image refs on the VM: $JOK"
+    [ "$JOK" = OK ] || sh_fail_rollback "job image refs do not resolve after the switch ($JOK)"
+  fi
+  if [ -n "$GUARDARGS" ]; then        # D1: the running guard itself must say it enforces the hold
+    GH=""; for i in 1 2 3 4 5 6; do GH=$(vmctl guard-log 2>/dev/null | grep -m1 '^{'); case "$GH" in *'"held": "TRANSCODER_MODE=transcribe"'*) break;; esac; sleep 2; done
+    say "guard startup log: $(printf '%s' "$GH" | cut -c1-200)"
+    case "$GH" in *'"held": "TRANSCODER_MODE=transcribe"'*) ;; *) sh_fail_rollback "the running guard does not report the transcription hold";; esac
+  fi
   v=""; for i in $(seq 1 18); do v=$(live_sha); [ "$v" = "$SHA" ] && break; sleep 10; done
   [ "$v" = "$SHA" ] || sh_fail_rollback "the API reports ${v:-nothing}, not $SHA"
   say "API reports $SHA"
diff --git a/infra/release-harness/selfhost-ctl.py b/infra/release-harness/selfhost-ctl.py
index 3f80a1eff74..44943ff819a 100644
--- a/infra/release-harness/selfhost-ctl.py
+++ b/infra/release-harness/selfhost-ctl.py
@@ -17,12 +17,29 @@ compared before the switch (production still where this run found it) and before
 Commands (exit 0 ok; 2 usage; 3 refused, NOTHING was changed; 4 failed part way, files may have changed; 5 not healthy):
   set-secret-env --svc S --keys K,...   stdin NUL key/value pairs; add or update, private backup + atomic write; names only\n  remove-secret-env --svc S --keys K,... remove exactly named keys with the same backup/write contract\n  state                          one JSON line: fp, pins, image ids, release env, running containers
   image-ids REF...               one JSON line {ref: image id or null}
+  disk                           one JSON line {"free_gb": N, "paths": {...}}: the least free space across the filesystems
+                                 that hold the active runtime's data: docker's DockerRootDir and, with the containerd image
+                                 store, containerd's configured root (`containerd config dump`). Refused (exit 3) when any
+                                 of them cannot be resolved or measured.
+  guard-log                      one JSON line {"listening": bool, "held": VALUE|null}: what the running create-guard's own
+                                 startup line says it enforces (goodqa#16136 D1: the hold is proven by the guard, not the file)
   pin --stamp S --sha SHA --deploy-id D --api REF --web REF --disp REF
                                  backs up compose.yaml, api.env and web.env to <file>.pre-rw-<S> (refuses if one exists),
                                  validates the new compose file with `docker compose config -q`, then replaces each file
                                  with os.replace (env files first, compose.yaml last). Prints the new state.
                                  Before any file changes it writes .rw-pin-<S>.json beside compose.yaml: the sha256 of each
                                  file before (= its backup) and after the re-pin (the fence `restore` checks).
+                                 --job-image KEY=goodqa-<job>@sha256:<64 hex> / --job-hold KEY (goodqa#16136): every one of
+                                 the four JOB_IMAGE_* keys must be named exactly once by one of the two. --job-image rewrites
+                                 that key's line in the create-guard's &job-images anchor (the job-dispatcher inherits it, and
+                                 each key must appear exactly once in the whole file, in that block); --job-hold writes the
+                                 line as `KEY: "" # held`: the guard drops an empty value from its allowlist and the
+                                 dispatcher answers 501 "no image configured" without calling docker, so a held kind never
+                                 starts even if an older image of it is on this host. Refused unless the docker store is containerd (only there does a loaded,
+                                 never-pushed image resolve as repo@<image id>). Before any file changes, every release-
+                                 managed ref in the RESOLVED prepared compose (the four service images and every non-held
+                                 JOB_IMAGE_* value, on both the guard and the dispatcher) must resolve on this host by its
+                                 exact string, a job ref to its own digest; other (pulled, third-party) images only WARN.
   restore --stamp S [--expect-fp FP]
                                  puts the three <file>.pre-rw-<S> copies back the same way. Prints the restored state.
                                  FENCED (defensible-systems D2, 2026-10-14): refuses (exit 3, nothing changed) unless every
@@ -30,6 +47,8 @@ Commands (exit 0 ok; 2 usage; 3 refused, NOTHING was changed; 4 failed part way,
                                  driver (an earlier run's rollback.json, a run that lost the deploy lock) can never revert a
                                  NEWER release. A stamp with no .rw-pin record (pinned before this fence) restores only with
                                  --expect-fp equal to the live fingerprint the caller read.
+                                 Never runs the presence check: after restoring it prints WARN lines for job refs and core
+                                 images that do not resolve (a rollback is never blocked; `up` never pulls).
   up [--timeout N]               `docker compose up -d --no-deps` api web job-dispatcher job-dispatcher-create-guard, then
                                  waits until every service runs exactly its configured replicas, all on the pinned image id,
                                  api and web healthy. Prints UP_OK / UP_FAIL.
@@ -50,6 +69,27 @@ REF_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._/:@+-]{0,250}$')
 URL_RE = re.compile(r'postgres(?:ql)?://\S+', re.I)
 
 
+# goodqa#16136: the four dispatcher job images. Each key's value is the guard allowlist entry for that job kind, so the
+# repository is fixed per key and the value must be a content address (AUD-031) of an image loaded by the release.
+JOB_KEYS = {'JOB_IMAGE_SCAN': 'goodqa-scan', 'JOB_IMAGE_TRANSCODE': 'goodqa-transcode',
+            'JOB_IMAGE_INTELLIGENCE_WORKER': 'goodqa-intelligence-worker',
+            'JOB_IMAGE_SUGGEST_FIX_WORKER': 'goodqa-suggest-fix-worker'}
+JOB_BLOCK = 'job-dispatcher-create-guard'
+HOLDABLE_KEYS = ('JOB_IMAGE_INTELLIGENCE_WORKER', 'JOB_IMAGE_TRANSCODE')   # the only kinds a release may hold
+HELD_VALUE = '""'   # goodqa#16136: a held job line's value; an empty string, never an image ref
+JOB_LINE_RE = re.compile(r'^      (JOB_IMAGE_[A-Z0-9_]+):[ \t]*(\S*)(?:[ \t]+#[ \t]*(held))?[ \t]*$')
+# goodqa#16136 G3: the only non-held value: a digest-pinned image ref, optionally in matching quotes (no YAML null, no
+# `~`, no ${...} interpolation, no tag)
+JOB_PIN_VALUE_RE = re.compile(r'^(["\']?)[a-z0-9][a-z0-9._/:-]*@sha256:[0-9a-f]{64}\1$')
+# goodqa#16136 AC-16: the create-guard's mode hold; the only value a release may set.
+GUARD_HOLD_ALLOWED = ('TRANSCODER_MODE=transcribe',)
+GUARD_LINE_RE = re.compile(r'^      GUARD_HELD_ENV:[ \t]*(\S*)[ \t]*$')
+
+
+def job_ref_ok(key, ref):
+    return re.fullmatch(re.escape(JOB_KEYS[key]) + r'@sha256:[0-9a-f]{64}', ref) is not None
+
+
 class Refused(Exception):
     pass
 
@@ -108,6 +148,114 @@ class Stack:
             lines[idx[0]] = '    image: %s # %s' % (ref, note)
         return '\n'.join(lines)
 
+    # ---- the four JOB_IMAGE_* lines (goodqa#16136): exactly once each in the whole file, inside the create-guard block
+    @staticmethod
+    def job_lines(text):
+        lines = text.split('\n'); res = {}; cur = None; in_svc = False
+        for i, l in enumerate(lines):
+            if l.rstrip() == 'services:': in_svc = True; cur = None; continue
+            if l and not l.startswith(' ') and not l.startswith('#'): in_svc = False; cur = None
+            m = re.match(r'^  ([A-Za-z0-9_.-]+):\s*(#.*)?$', l)
+            if in_svc and m: cur = m.group(1); continue
+            if 'JOB_IMAGE_' not in l.split('#', 1)[0]: continue
+            m = JOB_LINE_RE.match(l)
+            if not m or not in_svc or cur != JOB_BLOCK:
+                raise Refused('compose.yaml line %d names a JOB_IMAGE_* key outside the %s &job-images block (the guard '
+                              'allowlist and the dispatcher config could diverge)' % (i + 1, JOB_BLOCK))
+            k = m.group(1)
+            if k not in JOB_KEYS: raise Refused('compose.yaml line %d: unknown job image key %s' % (i + 1, k))
+            if k in res: raise Refused('compose.yaml: %s appears more than once' % k)
+            v, marked = m.group(2), bool(m.group(3))
+            if (marked or v in ('""', "''")) and k not in HOLDABLE_KEYS:
+                raise Refused('compose.yaml line %d: %s cannot be held (only %s)' % (i + 1, k, ', '.join(HOLDABLE_KEYS)))
+            if marked and v != HELD_VALUE:
+                raise Refused('compose.yaml line %d: %s is marked # held but its value is not ""' % (i + 1, k))
+            if v in ('""', "''") and not marked:
+                raise Refused('compose.yaml line %d: %s is empty without the # held marker' % (i + 1, k))
+            if not marked and not JOB_PIN_VALUE_RE.match(v):
+                raise Refused('compose.yaml line %d: %s must be a digest-pinned image ref or "" # held (got %s)'
+                              % (i + 1, k, re.sub(r'[^A-Za-z0-9@:/._${}~"\'-]', '?', v)[:40] or 'no value'))
+            res[k] = i
+        miss = sorted(set(JOB_KEYS) - set(res))
+        if miss: raise Refused('compose.yaml: job image key(s) missing from the %s block: %s' % (JOB_BLOCK, ' '.join(miss)))
+        return lines, res
+
+    def jobs(self, text=None):
+        text = open(self.compose).read() if text is None else text
+        lines, res = self.job_lines(text)
+        return {k: JOB_LINE_RE.match(lines[i]).group(2) for k, i in res.items()}
+
+    def held_keys(self, text=None):
+        text = open(self.compose).read() if text is None else text
+        lines, res = self.job_lines(text)
+        return sorted(k for k, i in res.items() if JOB_LINE_RE.match(lines[i]).group(3))
+
+    def rejob(self, text, new, held=()):
+        lines, res = self.job_lines(text)
+        for k, ref in new.items():
+            lines[res[k]] = '      %s: %s' % (k, ref)
+        for k in held:
+            lines[res[k]] = '      %s: %s # held' % (k, HELD_VALUE)
+        return '\n'.join(lines)
+
+    def guard_hold(self, text=None):
+        text = open(self.compose).read() if text is None else text
+        hits = [l for l in text.split('\n') if 'GUARD_HELD_ENV' in l.split('#', 1)[0]]
+        if not hits: return None
+        if len(hits) > 1 or not GUARD_LINE_RE.match(hits[0]): raise Refused('compose.yaml: GUARD_HELD_ENV must be one plain line')
+        return GUARD_LINE_RE.match(hits[0]).group(1) or None
+
+    def set_guard_hold(self, text, value):
+        self.guard_hold(text)                                 # validates: at most one plain line
+        lines = [l for l in text.split('\n') if 'GUARD_HELD_ENV' not in l.split('#', 1)[0]]
+        if value:
+            _, res = self.job_lines('\n'.join(lines))
+            lines.insert(min(res.values()), '      GUARD_HELD_ENV: ' + value)
+        return '\n'.join(lines)
+
+    def store_roots(self):
+        """Review F2: the data roots the runtime itself reports; anything unresolved refuses."""
+        r = docker('info', '-f', '{{.DockerRootDir}}', timeout=60)
+        root = r.stdout.strip() if r.returncode == 0 else ''
+        if not root.startswith('/') or '\n' in root: raise Refused('cannot resolve the docker data root (docker info DockerRootDir)')
+        roots = [root]
+        if self.store_is_containerd():
+            try: c = subprocess.run(['containerd', 'config', 'dump'], capture_output=True, text=True, timeout=60)
+            except (OSError, subprocess.SubprocessError) as e: raise Refused('cannot run containerd config dump: %s' % type(e).__name__)
+            m = re.search(r'^root\s*=\s*(["\x27])([^"\x27\n]+)\1\s*$', c.stdout, re.M) if c.returncode == 0 else None
+            if not m or not m.group(2).startswith('/'): raise Refused('cannot resolve the containerd root (containerd config dump)')
+            roots.append(m.group(2))
+        return roots
+
+    def free_gb(self, path):
+        try: r = subprocess.run(['df', '-Pk', path], capture_output=True, text=True, timeout=60)
+        except (OSError, subprocess.SubprocessError) as e: raise Refused('cannot measure %s: %s' % (path, type(e).__name__))
+        rows = [l.split() for l in r.stdout.strip().split('\n')[1:]] if r.returncode == 0 else []
+        if len(rows) != 1 or len(rows[0]) < 6 or not rows[0][3].isdigit(): raise Refused('cannot measure free space of %s' % path)
+        return int(rows[0][3]) // (1 << 20)
+
+    def store_is_containerd(self):
+        r = docker('info', '-f', '{{json .DriverStatus}}', timeout=60)
+        return r.returncode == 0 and 'io.containerd.snapshotter' in r.stdout
+
+    def resolved(self, text):
+        """`docker compose config --format json` of TEXT (anchors and merge keys resolved by compose itself)."""
+        tmp = os.path.join(self.dir, '.compose.rw-resolve.yaml')
+        open(tmp, 'w').write(text)
+        try:
+            r = self.dc('config', '--format', 'json', files=[tmp], timeout=60)
+            if r.returncode != 0: raise Refused('docker compose config --format json failed: ' + r.stderr.strip()[-300:])
+            try: return json.loads(r.stdout)['services']
+            except Exception: raise Refused('docker compose config --format json gave no services')
+        finally:
+            try: os.remove(tmp)
+            except OSError: pass
+
+    def job_ids_ok(self, refs):
+        """Refs (job form) that do not resolve on this host to exactly their own digest."""
+        ids = self.image_ids(sorted(set(refs)))
+        return sorted(r for r in set(refs) if ids.get(r) != r.split('@', 1)[1])
+
     # ---- env files (format: raw, KEY=VALUE per line)
     def release_env(self, svc, text=None):
         text = open(self.envs[svc]).read() if text is None else text
@@ -157,7 +305,14 @@ class Stack:
         for c in self.containers():
             if c['service'] in SERVICES:
                 run.setdefault(c['service'], []).append('%s:%s:%s' % ((c['image'] or '?')[:19], c['status'], c['health'] or '-'))
-        return dict(core, fp=fp, running=run, missing=sorted(r for r, i in ids.items() if not i))
+        try:
+            jobs = self.jobs(); jobs_held = self.held_keys(); guard_hold = self.guard_hold()
+            jobs_missing = self.job_ids_ok([v for k, v in jobs.items() if k not in jobs_held])
+        except Refused as e: jobs = {'error': str(e)}; jobs_held = []; jobs_missing = []; guard_hold = None
+        # goodqa#16136: jobs and jobs_missing stay OUTSIDE the fp core (every fp recorded before them still matches) and
+        # outside `missing` (rw-ship refuses a release while `missing` is non-empty: no rollback target).
+        return dict(core, fp=fp, running=run, missing=sorted(r for r, i in ids.items() if not i),
+                    jobs=jobs, jobs_held=jobs_held, jobs_missing=jobs_missing, guard_hold=guard_hold)
 
     def replicas(self):
         r = self.dc('config', '--format', 'json', timeout=60)
@@ -279,7 +434,55 @@ def cmd_pin(stk, a):
     pin_apply(stk, a, *prep)
 
 
+def parse_job_args(images, holds):
+    """--job-image KEY=REF and --job-hold KEY -> ({key: ref}, {held keys}), or Refused. All four keys, each exactly once."""
+    new, held = {}, set()
+    for it in images or ():
+        k, sep, v = it.partition('=')
+        name = re.sub(r'[^A-Za-z0-9_]', '?', k)[:60]
+        if not sep or k not in JOB_KEYS: raise Refused('--job-image %s is not a job image key (only %s)' % (name, ', '.join(sorted(JOB_KEYS))))
+        if k in new: raise Refused('--job-image %s given more than once' % k)
+        if not job_ref_ok(k, v): raise Refused('--job-image %s must be %s@sha256:<64 hex>' % (k, JOB_KEYS[k]))
+        new[k] = v
+    for k in holds or ():
+        name = re.sub(r'[^A-Za-z0-9_]', '?', k)[:60]
+        if k not in JOB_KEYS: raise Refused('--job-hold %s is not a job image key' % name)
+        if k not in HOLDABLE_KEYS: raise Refused('--job-hold %s: that kind cannot be held (only %s)' % (k, ', '.join(HOLDABLE_KEYS)))
+        if k in held or k in new: raise Refused('--job-hold %s given more than once or also with --job-image' % k)
+        held.add(k)
+    left = sorted(set(JOB_KEYS) - set(new) - held)
+    if left: raise Refused('every job image key needs --job-image or --job-hold; missing: ' + ' '.join(left))
+    return new, held
+
+
+def presence_check(stk, comp, held):
+    """Every release-managed ref the RESOLVED prepared compose names must be on this host (exact string; a job ref by its
+    own digest). Pulled third-party images only warn. Raises Refused; returns the warnings."""
+    svcs = stk.resolved(comp)
+    want_jobs = {k: v for k, v in stk.jobs(comp).items() if k not in held}
+    for s in (JOB_BLOCK, 'job-dispatcher'):
+        envs = (svcs.get(s) or {}).get('environment') or {}
+        got = {k: envs.get(k) for k in want_jobs}
+        if got != want_jobs: raise Refused('resolved compose: %s does not carry the pinned job images (%s)' % (s, got))
+    managed = {(svcs.get(s) or {}).get('image') for s in SERVICES}
+    bad = [r for r in managed if not r or not stk.image_ids([r])[r]]
+    bad += stk.job_ids_ok(list(want_jobs.values()))
+    if bad: raise Refused('image(s) not present on this host: ' + ' '.join(sorted(str(b) for b in bad)))
+    warns = []
+    for s, d in sorted(svcs.items()):
+        r = (d or {}).get('image')
+        if s not in SERVICES and r and not stk.image_ids([r])[r]: warns.append('WARN third-party image not present on this host: ' + r)
+    return warns
+
+
 def pin_prepare(stk, a):
+    new_jobs, held = parse_job_args(getattr(a, 'job_image', None), getattr(a, 'job_hold', None))
+    gh = list(getattr(a, 'guard_hold', None) or [])
+    if len(gh) > 1 or (gh and gh[0] not in GUARD_HOLD_ALLOWED):
+        raise Refused('--guard-hold may be given once, only as %s' % ' or '.join(GUARD_HOLD_ALLOWED))
+    if new_jobs and not stk.store_is_containerd():
+        raise Refused('the docker image store is not containerd: a loaded image would not resolve as repo@<image id> '
+                      '(docker info DriverStatus has no io.containerd.snapshotter)')
     for x in (a.api, a.web, a.disp):
         if not REF_RE.match(x): raise Refused('bad image ref %r' % x)
     if not re.match(r'^[0-9a-f]{40}$', a.sha): raise Refused('bad sha')
@@ -294,7 +497,14 @@ def pin_prepare(stk, a):
     old = open(stk.compose).read(); stk.pins(old)
     comp = stk.repin(old, new_pins, 'rw-ship %s %s' % (a.sha[:12], a.stamp))
     if stk.pins(comp) != new_pins: raise Refused('re-pin self-check failed')
+    before_jobs = stk.jobs(old)
+    comp = stk.rejob(comp, new_jobs, held)
+    comp = stk.set_guard_hold(comp, gh[0] if gh else None)
+    want = dict(before_jobs, **new_jobs, **{k: HELD_VALUE for k in held})
+    if stk.jobs(comp) != want or stk.held_keys(comp) != sorted(held) or stk.guard_hold(comp) != (gh[0] if gh else None):
+        raise Refused('job image re-pin self-check failed')
     validate_compose(stk, comp)
+    for w in presence_check(stk, comp, held): out(w)
     envs = {s: stk.set_env(s, {'RELEASE_SOURCE_SHA': a.sha, 'RELEASE_DEPLOYMENT_ID': a.deploy_id}) for s in ('api', 'web')}
     return files, baks, comp, envs
 
@@ -339,9 +549,23 @@ def cmd_restore(stk, a):
         for f, b in zip(files, baks): write_like(f, open(b).read(), b)
     except Exception as e:
         raise RuntimeError('restore failed part way (%s)' % e)
+    restore_warnings(stk)
     out(stk.state())
 
 
+def restore_warnings(stk):
+    """goodqa#16136: a rollback is never blocked, but it must say what it brought back that cannot run."""
+    try:
+        pins = stk.pins(); ids = stk.image_ids(sorted(set(pins.values())))
+        core = sorted({r for r in pins.values() if not ids.get(r)})
+        if core: out('WARN core image missing: ' + ' '.join(core) + ' (up runs with --pull never and will fail rather than pull)')
+        try: hk = stk.held_keys(); down = stk.job_ids_ok([v for k, v in stk.jobs().items() if k not in hk])
+        except Refused as e: down = ['(job image lines unreadable: %s)' % e]
+        if down: out('WARN jobs down after rollback: ' + ' '.join(down))
+    except Exception as e:
+        out('WARN restore could not check images: %s: %s' % (type(e).__name__, e))
+
+
 def restore_fence(stk, a, files, baks):
     """Production must still be what run <stamp> left: each file equal to what that run wrote or to its own backup (a part-way
     pin or an earlier restore). Anything else means a newer release or a person changed it after that run: never reverted."""
@@ -366,7 +590,7 @@ def restore_fence(stk, a, files, baks):
 
 
 def cmd_up(stk, a):
-    r = stk.dc('up', '-d', '--no-deps', *SERVICES, timeout=a.timeout + 120)
+    r = stk.dc('up', '-d', '--no-deps', '--pull', 'never', *SERVICES, timeout=a.timeout + 120)
     if r.returncode != 0:
         out('UP_FAIL docker compose up rc=%d: %s' % (r.returncode, r.stderr.strip().replace('\n', ' | ')[-400:])); return 5
     want = stk.replicas(); pins = stk.pins(); ids = stk.image_ids(sorted(set(pins.values())))
@@ -443,6 +667,10 @@ def main(argv):
     sub.add_parser('state'); ii = sub.add_parser('image-ids'); ii.add_argument('refs', nargs='+')
     pn = sub.add_parser('pin')
     for k in ('--stamp', '--sha', '--deploy-id', '--api', '--web', '--disp'): pn.add_argument(k, required=True)
+    pn.add_argument('--job-image', action='append', default=[], metavar='KEY=REF')
+    pn.add_argument('--job-hold', action='append', default=[], metavar='KEY')
+    pn.add_argument('--guard-hold', action='append', default=[], metavar='KEY=VALUE')
+    sub.add_parser('disk'); sub.add_parser('guard-log')
     rs = sub.add_parser('restore'); rs.add_argument('--stamp', required=True); rs.add_argument('--expect-fp')
     up = sub.add_parser('up'); up.add_argument('--timeout', type=int, default=300); up.add_argument('--every', type=float, default=3)
     mg = sub.add_parser('migrate'); mg.add_argument('--image', required=True); mg.add_argument('--mode', choices=('dry', 'apply'), required=True)
@@ -456,6 +684,15 @@ def main(argv):
     stk = Stack(a.dir, a.env_dir, a.project)
     try:
         if a.cmd == 'state': out(stk.state()); return 0
+        if a.cmd == 'guard-log':
+            r = stk.dc('logs', '--no-color', '--no-log-prefix', '--tail', '200', JOB_BLOCK, timeout=60)
+            ls = [l for l in r.stdout.split('\n') if 'job-dispatcher-create-guard listening' in l]
+            m = re.search(r'heldEnv=(\S+)', ls[-1]) if ls else None
+            held = m.group(1) if m and m.group(1) != 'none' else None
+            out({'listening': bool(ls), 'held': held}); return 0
+        if a.cmd == 'disk':
+            paths = {p: stk.free_gb(p) for p in stk.store_roots()}
+            out({'free_gb': min(paths.values()), 'paths': paths}); return 0
         if a.cmd == 'image-ids':
             for r in a.refs:
                 if not REF_RE.match(r): raise Refused('bad image ref %r' % r)
diff --git a/infra/release-harness/test_ac13_count.py b/infra/release-harness/test_ac13_count.py
new file mode 100644
index 00000000000..ed8b633812b
--- /dev/null
+++ b/infra/release-harness/test_ac13_count.py
@@ -0,0 +1,147 @@
+"""goodqa#16136 AC-13 matcher (ac13-count.py): every non-2xx launch on a non-held kind is a failure."""
+import json, os, subprocess, sys
+
+HERE = os.path.dirname(os.path.abspath(__file__))
+TOOL = os.path.join(HERE, 'ac13-count.py')
+T0 = 1_800_000_000_000
+
+
+def _log(tmp_path, launches, name='disp.log'):
+    lines = []
+    for i, (kind, st) in enumerate(launches):
+        rid = 'req-%d' % (i % 3)   # reqIds repeat (a restart resets them); pairing must follow order
+        lines.append('2026-11-16T00:00:%02dZ ' % (i % 60) + json.dumps({'level': 30, 'time': T0 + i, 'reqId': rid, 'msg': 'incoming request',
+                     'req': {'method': 'POST', 'url': '/jobs/%s/run' % kind}}))
+        lines.append(json.dumps({'level': 30, 'time': T0 + i, 'reqId': rid, 'msg': 'request completed', 'res': {'statusCode': st}}))
+    lines.append(json.dumps({'level': 30, 'time': T0, 'reqId': 'req-9', 'msg': 'incoming request', 'req': {'method': 'GET', 'url': '/healthz'}}))
+    lines.append(json.dumps({'level': 30, 'time': T0, 'reqId': 'req-9', 'msg': 'request completed', 'res': {'statusCode': 503}}))
+    p = tmp_path / name; p.write_text('\n'.join(lines) + '\n'); return str(p)
+
+
+def run(*args):
+    r = subprocess.run([sys.executable, TOOL] + list(args), capture_output=True, text=True)
+    return r.returncode, json.loads(r.stdout) if r.stdout.strip() else r.stderr
+
+
+OK = [('scan', 200), ('transcode', 202), ('suggest-fix-worker', 200)]
+REQ = ['--require-2xx', 'scan', '--require-2xx', 'transcode', '--require-2xx', 'suggest-fix-worker']
+
+
+def test_post_pass_with_held_intelligence_501(tmp_path):
+    rc, o = run(_log(tmp_path, OK + [('intelligence-worker', 501)] * 3), '--mode', 'post', '--held-empty', 'intelligence-worker', *REQ)
+    assert rc == 0 and o['verdict'] == 'PASS' and o['held_excluded'] == {'intelligence-worker': 3}, o
+
+
+def test_501_on_a_non_held_kind_fails(tmp_path):
+    for kind in ('scan', 'suggest-fix-worker', 'transcode'):
+        rc, o = run(_log(tmp_path, OK + [(kind, 501)]), '--mode', 'post', '--held-empty', 'intelligence-worker', *REQ)
+        assert rc == 1 and any(f.startswith('%s 501' % kind) for f in o['failures']), (kind, o)
+
+
+def test_422_and_other_non_2xx_on_a_non_held_kind_fail(tmp_path):
+    for kind, st in (('scan', 422), ('suggest-fix-worker', 504), ('transcode', 422), ('scan', 429), ('intelligence-worker', 422)):
+        rc, o = run(_log(tmp_path, OK + [(kind, st)]), '--mode', 'post', '--held-empty', 'intelligence-worker', *REQ)
+        assert rc == 1 and any(f.startswith('%s %d' % (kind, st)) for f in o['failures']), (kind, st, o)
+
+
+S = 1000   # ms
+BODY = ('{"error":"docker run failed before starting a container: docker: Error response from daemon: '
+        'job-dispatcher-create-guard: refused (create refused: TRANSCODER_MODE=transcribe is held on this guard)","started":false}')
+
+
+def _iso(ms):
+    import datetime
+    return datetime.datetime.fromtimestamp(ms / 1000, datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
+
+
+def _disp(tmp_path, events, name='disp.log'):
+    """events: [(ms offset from T0, kind, status)] as the dispatcher logs them."""
+    lines = []
+    for n, (dt, kind, st) in enumerate(events):
+        rid = 'req-%d' % (n % 2)
+        lines.append(json.dumps({'level': 30, 'time': T0 + dt, 'reqId': rid, 'msg': 'incoming request', 'req': {'method': 'POST', 'url': '/jobs/%s/run' % kind}}))
+        lines.append(json.dumps({'level': 30, 'time': T0 + dt, 'reqId': rid, 'msg': 'request completed', 'res': {'statusCode': st}}))
+    p = tmp_path / name; p.write_text('\n'.join(lines) + '\n'); return str(p)
+
+
+def _api(tmp_path, held, other=(), untimed=0, prefix=None, name='api.log', extra=()):
+    """API replica lines as `docker logs --timestamps` (or, with prefix, `docker compose logs --timestamps api`) prints them."""
+    pre = (prefix + '  | ') if prefix else ''
+    rows = [pre + '%s transcribe: failed to launch job CloudJobLaunchError: job-dispatch transcode failed (422): %s' % (_iso(T0 + dt), BODY) for dt in held]
+    rows += [pre + '%s transcribe: failed to launch job CloudJobLaunchError: job-dispatch transcode failed (422): '
+             '{"error":"docker run failed before starting a container: Unable to find image","started":false}' % _iso(T0 + dt) for dt in other]
+    rows += [pre + 'transcribe: failed to launch job CloudJobLaunchError: job-dispatch transcode failed (422): ' + BODY] * untimed
+    rows += [pre + '%s {"level":30,"msg":"unrelated api line"}' % _iso(T0), pre + '    at HttpJobDispatchClient.runJob (job-dispatch.js:1:1)']
+    rows += list(extra)
+    p = tmp_path / name; p.write_text('\n'.join(rows) + '\n'); return str(p)
+
+
+OKT = [(1 * S, 'scan', 200), (2 * S, 'transcode', 202), (3 * S, 'suggest-fix-worker', 200)]
+HT = ['--mode', 'post', '--held-empty', 'intelligence-worker', '--guard-held-transcribe'] + REQ
+WIN = ['--since', str(T0), '--until', str(T0 + 30 * S)]
+
+
+def test_held_transcription_422_pairs_with_its_own_api_line(tmp_path):
+    d = _disp(tmp_path, OKT + [(10 * S, 'transcode', 422), (20 * S, 'transcode', 422)])
+    rc, o = run(d, *HT, *WIN, '--refusals', _api(tmp_path, [11 * S, 19 * S]))
+    assert rc == 0 and o['held_excluded']['transcode'] == 2 and o['api_replicas'] == 1, o
+    # G1: equal counts are not enough; each 422 needs its own API line within 5 s
+    rc, o = run(d, *HT, *WIN, '--refusals', _api(tmp_path, [10 * S, 28 * S]))
+    assert rc == 1 and any('20' in f and 'has no held API launch-failure line' in f for f in o['failures']), o
+    assert any('has no transcode 422' in f for f in o['failures']), o
+    for held in ([11 * S], [11 * S, 19 * S, 25 * S], []):
+        rc, o = run(d, *HT, *WIN, '--refusals', _api(tmp_path, held))
+        assert rc == 1, (held, o)
+    rc, o = run(d, *HT, *WIN, '--refusals', _api(tmp_path, [11 * S, 19 * S], other=[5 * S]))
+    assert rc == 1 and any('another reason' in f for f in o['failures']), o
+    rc, o = run(d, *HT, *WIN, '--refusals', _api(tmp_path, [11 * S, 19 * S], untimed=1))
+    assert rc == 1 and any('without a readable timestamp' in f for f in o['failures']), o
+
+
+def test_held_launch_straddling_the_window_edge(tmp_path):
+    # the 422 is in the window, its API line just after it: they pair
+    rc, o = run(_disp(tmp_path, OKT + [(29 * S + 900, 'transcode', 422)]), *HT, *WIN, '--refusals', _api(tmp_path, [31 * S]))
+    assert rc == 0 and o['held_excluded']['transcode'] == 1, o
+    # the 422 just before the window, its API line inside it: the line is paired, not an orphan
+    rc, o = run(_disp(tmp_path, OKT + [(-1 * S, 'transcode', 422)]), *HT, *WIN, '--refusals', _api(tmp_path, [1 * S]))
+    assert rc == 0, o
+    # beyond the 5 s tolerance nothing pairs
+    rc, o = run(_disp(tmp_path, OKT + [(29 * S + 900, 'transcode', 422)]), *HT, *WIN, '--refusals', _api(tmp_path, [40 * S]))
+    assert rc == 1 and any('has no held API launch-failure line' in f for f in o['failures']), o
+
+
+def test_every_api_replica_is_read(tmp_path):
+    d = _disp(tmp_path, OKT + [(10 * S, 'transcode', 422), (20 * S, 'transcode', 422)])
+    a1 = _api(tmp_path, [10 * S], name='api-1.log'); a2 = _api(tmp_path, [20 * S], name='api-2.log')
+    rc, o = run(d, *HT, *WIN, '--api-replicas', '2', '--refusals', a1, '--refusals', a2)
+    assert rc == 0 and o['api_replicas'] == 2 and o['held_excluded']['transcode'] == 2, o
+    rc, o = run(d, *HT, *WIN, '--api-replicas', '2', '--refusals', a1)
+    assert rc == 1 and 'read 1 api replicas, expected 2' in o['failures'], o
+    assert any('has no held API launch-failure line' in f for f in o['failures']), o
+    # one `docker compose logs --timestamps api` file holding both replicas
+    both = tmp_path / 'api-compose.log'
+    both.write_text(open(_api(tmp_path, [10 * S], prefix='api-1', name='c1')).read() + open(_api(tmp_path, [20 * S], prefix='api-2', name='c2')).read())
+    rc, o = run(d, *HT, *WIN, '--api-replicas', '2', '--refusals', str(both))
+    assert rc == 0 and o['api_replicas'] == 2, o
+
+
+def test_guard_held_transcribe_needs_refusals(tmp_path):
+    rc, err = run(_log(tmp_path, OK), '--mode', 'post', '--guard-held-transcribe')
+    assert rc == 2 and 'needs --refusals' in err, err
+
+
+def test_floors_and_positive_control(tmp_path):
+    rc, o = run(_log(tmp_path, [('scan', 200)]), '--mode', 'post', *REQ)
+    assert rc == 1 and 'no 2xx for transcode' in o['failures'] and 'no 2xx for suggest-fix-worker' in o['failures'], o
+    rc, o = run(_log(tmp_path, OK), '--mode', 'pre')
+    assert rc == 1 and 'positive control' in o['failures'][0], o
+    rc, o = run(_log(tmp_path, OK + [('intelligence-worker', 422)] * 6), '--mode', 'pre')
+    assert rc == 0 and o['counts']['intelligence-worker'] == {'422': 6}, o
+
+
+def test_window_and_unreadable(tmp_path):
+    log = _log(tmp_path, OK + [('scan', 500)])
+    rc, o = run(log, '--mode', 'post', '--until', str(T0 + 3), *REQ)
+    assert rc == 0, o
+    rc, o = run(str(tmp_path / 'absent.log'), '--mode', 'post')
+    assert rc == 2 and o['verdict'] == 'FAIL', o
diff --git a/infra/release-harness/test_rw_ship_selfhost.py b/infra/release-harness/test_rw_ship_selfhost.py
index 66d0fb10f89..47f88218644 100644
--- a/infra/release-harness/test_rw_ship_selfhost.py
+++ b/infra/release-harness/test_rw_ship_selfhost.py
@@ -13,6 +13,9 @@ Pinned properties:
   * after a migration this run applied, NOTHING rolls back (exit 8), the inflight record stays, the next run refuses (9)
   * image ids that differ after transfer, a missing previous image, production changed under the run, a bad DEPLOY_TARGET,
     a full build disk: refused before the switch, pins untouched
+  * goodqa#16136: the four dispatcher job images (scan, transcode, intelligence-worker, suggest-fix-worker) are built,
+    transferred, id-checked and pinned as goodqa-<job>@<host image id> in the &job-images anchor; every image the prepared
+    compose names must be on the host before the switch; job pins roll back with compose.yaml; restore never runs that check
   * NEGATIVE CONTROLS: mutated copies of rw-ship.sh (no migration hold, no schema freeze, migrations after the switch) are
     caught by these same assertions
 Run: cd bin && python3 -m pytest -q -p no:cacheprovider test_rw_ship_selfhost.py   (RW_SHIP_UNDER_TEST=<path> for a copy)
@@ -73,7 +76,7 @@ def W(n, v): json.dump(v, open(os.path.join(st, n), 'w'), indent=1)
 def mark(n): return os.path.exists(os.path.join(os.environ['FAKE_STATE'], n))
 def markv(n): return open(os.path.join(os.environ['FAKE_STATE'], n)).read().strip()
 def log(m): open(os.path.join(os.environ['FAKE_STATE'], 'docker.log'), 'a').write('%s %s\n' % (side, m))
-if a[0] == 'info': print(os.environ['FAKE_STATE']); sys.exit(0)
+if a[0] == 'info' and 'DriverStatus' not in ' '.join(a): print(os.environ['FAKE_STATE']); sys.exit(0)
 if a[:2] == ['buildx', 'inspect']:
     if mark('container-builder'):
         print('Driver: docker-container\nNodes:\nEndpoint: default\nStatus: running'); sys.exit(0)
@@ -82,9 +85,35 @@ if a[:2] == ['context', 'show']: print('default'); sys.exit(0)
 if a[0] == 'context':
     print('ssh://unaccounted-builder' if mark('remote-docker') else 'unix:///var/run/docker.sock'); sys.exit(0)
 imgs = J('images-%s.json' % side, {})
+def resolve(ref):
+    if ref in imgs: return imgs[ref]
+    m = re.match(r'^([^@]+)@(sha256:[0-9a-f]{64})$', ref)        # containerd store: repo@<image id> of a tag of that repo
+    if m and any(k.split(':')[0] == m.group(1) and v == m.group(2) for k, v in imgs.items() if '@' not in k):
+        if mark('id-skew') and ref.startswith(markv('id-skew')): return 'sha256:' + 'f' * 64
+        return m.group(2)
+    return None
+if a[0] == 'info':
+    print('[["Backing Filesystem","extfs"],["Supports d_type","true"]]' if mark('classic-store') else '[["driver-type","io.containerd.snapshotter.v1"]]')
+    sys.exit(0)
+if a[0] == 'run' and 'src/create-guard-main.ts' in a:          # goodqa#16136 D1: probe of the built guard
+    env = dict(a[i + 1].split('=', 1) for i, x in enumerate(a) if x == '-e'); log('GUARDPROBE held=%s' % env.get('GUARD_HELD_ENV'))
+    if mark('guard-held-support') and '=' not in env.get('GUARD_HELD_ENV', '='):
+        print('Error: GUARD_HELD_ENV must be KEY=VALUE', file=sys.stderr)   # then a real node stack trace (seen on t2-dev)
+        for n in range(12): print('    at frame%d (node:internal/modules/esm/module_job:%d:25)' % (n, n), file=sys.stderr)
+        print('Node.js v22', file=sys.stderr); sys.exit(1)
+    print('job-dispatcher-create-guard listening on :2376'); sys.exit(124 if mark('guard-old-timeout') else 0)
+if a[:2] == ['image', 'inspect']: log('INSPECT ' + repr(a[2:]))
+if a[:2] == ['image', 'inspect'] and '{{.Size}}' in a:          # goodqa#16136 F2: bytes the run will load
+    if not resolve(a[-1]) or mark('size-unreadable'): sys.exit(1)
+    print(markv('image-size') if mark('image-size') else 1 << 20); sys.exit(0)
+if a[:2] == ['image', 'inspect'] and side == 'local' and mark('inspect-once') and markv('inspect-once') in a[-1]:
+    # goodqa#16136: the image is there for the build receipt's own inspect, then gone (removed or re-tagged) by the recheck
+    n = os.path.join(os.environ['FAKE_STATE'], 'inspect-count'); c = int(open(n).read()) if os.path.exists(n) else 0
+    open(n, 'w').write(str(c + 1))
+    if c >= 1: sys.exit(1)
 if a[:2] == ['image', 'inspect']:
-    ref = a[-1]
-    if ref in imgs: print(imgs[ref]); sys.exit(0)
+    i = resolve(a[-1])
+    if i: print(i); sys.exit(0)
     sys.exit(1)
 if a[0] == 'tag':
     imgs[a[2]] = imgs[a[1]] if a[1] in imgs else sys.exit(1); W('images-%s.json' % side, imgs); sys.exit(0)
@@ -137,9 +166,21 @@ if a[0] == 'compose':
     if sub == 'config' and '-q' in rest:
         if mark('compose-invalid'): print('invalid', file=sys.stderr); sys.exit(1)
         sys.exit(0)
-    if sub == 'config':
-        print(json.dumps({'services': {'api': {'deploy': {'replicas': 2}}, 'web': {'deploy': {'replicas': 2}}, 'job-dispatcher': {},
-                                       'job-dispatcher-create-guard': {}, 'caddy': {}}})); sys.exit(0)
+    if sub == 'config':                                       # resolved config: images, and the &job-images anchor merged
+        text = open(files[0]).read(); p0 = {}; jp = {}; cur = None
+        for l in text.split('\n'):
+            m = re.match(r'^    image:\s*(\S+)', l)
+            if m and cur: p0[cur] = m.group(1)
+            m = re.match(r'^  ([A-Za-z0-9_.-]+):\s*(#.*)?$', l)
+            if m: cur = m.group(1); continue
+            m = re.match(r'^      (JOB_IMAGE_[A-Z0-9_]+):\s*(\S+)', l)
+            if m and cur: jp.setdefault(cur, {})[m.group(1)] = m.group(2)
+        g = jp.get('job-dispatcher-create-guard', {})
+        svcs = {s: {'image': i} for s, i in p0.items()}
+        for s in ('api', 'web'): svcs.setdefault(s, {})['deploy'] = {'replicas': 2}
+        svcs.setdefault('job-dispatcher-create-guard', {})['environment'] = dict(g)
+        svcs.setdefault('job-dispatcher', {})['environment'] = dict(g, **jp.get('job-dispatcher', {}))
+        print(json.dumps({'services': svcs})); sys.exit(0)
     text = open(files[0]).read()
     def pins(t):
         p = {}; cur = None
@@ -150,10 +191,12 @@ if a[0] == 'compose':
             if m and cur: p[cur] = m.group(1)
         return p
     if sub == 'up':
+        if '--pull' in rest:
+            i = rest.index('--pull'); log('PULL ' + rest[i + 1]); rest = rest[:i] + rest[i + 2:]
         svcs = [x for x in rest if not x.startswith('-')]; p = pins(text)
         envf = re.search(r'path:[ \t]*([^\n]+/api\.env)', text).group(1)
         sha = re.search(r'^RELEASE_SOURCE_SHA=(\S+)$', open(envf).read(), re.M).group(1)
-        missing = [p[s] for s in svcs if p[s] not in imgs]
+        missing = [p[s] for s in svcs if not resolve(p[s])]
         if missing: print('no such image ' + ' '.join(missing), file=sys.stderr); sys.exit(1)
         cons = [c for c in cons if c['service'] not in svcs]
         bad = markv('unhealthy-ref') if mark('unhealthy-ref') else None
@@ -161,8 +204,11 @@ if a[0] == 'compose':
             for n in range(2 if s in ('api', 'web') else 1):
                 h = ('unhealthy' if bad and bad in p['api'] and s == 'api' else 'healthy') if s in ('api', 'web') else None
                 cons.append({'id': '%s-%d-%s' % (s, n, len(cons)), 'name': 'goodqa-%s-%d' % (s, n + 1), 'service': s,
-                             'image': imgs[p[s]], 'status': 'running', 'health': h})
+                             'image': resolve(p[s]), 'status': 'running', 'health': h})
         W('containers.json', cons); log('UP api=%s web=%s disp=%s sha=%s' % (p['api'], p['web'], p['job-dispatcher'], sha))
+        if mark('untag-after-up') and sha in markv('untag-after-up'):   # a person untags a job image right after the switch
+            pre = markv('untag-after-up').split()[0]
+            W('images-%s.json' % side, {k: v for k, v in imgs.items() if not k.startswith(pre)})
         live = 'f' * 40 if mark('wrong-version-for') and markv('wrong-version-for') == sha else sha
         open(os.path.join(os.environ['FAKE_STATE'], 'live'), 'w').write(live); sys.exit(0)
     if sub == 'run':
@@ -180,6 +226,12 @@ if a[0] == 'compose':
         open(os.path.join(os.environ['FAKE_STATE'], 'migrated'), 'a').write('%d\n' % pend)
         print('MIG_OK applied %d (476 -> %d)' % (pend, 476 + pend)); sys.exit(0)
     if sub == 'logs':
+        if 'job-dispatcher-create-guard' in rest:
+            m = re.search(r'^      GUARD_HELD_ENV:[ \t]*(\S+)', text, re.M)
+            if not mark('guard-log-missing'):
+                print('job-dispatcher-create-guard listening on :2376, upstream={}, allowedImages=4' +
+                      (', heldEnv=%s' % (m.group(1) if m else 'none') if mark('guard-held-support') else ''))
+            sys.exit(0)
         for n in range(80): print('{"severity":"INFO","msg":"incoming request %d"}' % n)
         if mark('schema-errors'): print('{"severity":"ERROR","code":"42P01","msg":"relation does not exist"}')
         sys.exit(0)
@@ -215,16 +267,46 @@ services:
     image: goodqa-job-dispatcher:base
     environment: &job-images
       GUARD_ENV: production
+      JOB_IMAGE_SCAN: registry.digitalocean.com/goodqa-prod/bugtracker-scan@sha256:{d1}
+      JOB_IMAGE_TRANSCODE: registry.digitalocean.com/goodqa-prod/bugtracker-transcode@sha256:{d2}
+      JOB_IMAGE_INTELLIGENCE_WORKER: registry.digitalocean.com/goodqa-prod/bugtracker-intelligence-worker@sha256:{d3}
+      JOB_IMAGE_SUGGEST_FIX_WORKER: registry.digitalocean.com/goodqa-prod/bugtracker-suggest-fix-worker@sha256:{d4}
 
   job-dispatcher:
     image: goodqa-job-dispatcher:base
     environment:
       <<: *job-images
+      JOB_DISPATCHER_ENV: production
 
 networks:
   edge: {{}}
 '''
 
+JOBS = {'JOB_IMAGE_SCAN': ('scan', 'apps/scan-worker'), 'JOB_IMAGE_TRANSCODE': ('transcode', 'apps/transcoder'),
+        'JOB_IMAGE_INTELLIGENCE_WORKER': ('intelligence-worker', 'apps/intelligence-worker'),
+        'JOB_IMAGE_SUGGEST_FIX_WORKER': ('suggest-fix-worker', 'apps/suggest-fix-worker')}
+DO_DIG = {'d1': '4f' * 32, 'd2': 'de' * 32, 'd3': '5a' * 32, 'd4': 'd5' * 32}
+BASE_JOBS = {'JOB_IMAGE_SCAN': 'registry.digitalocean.com/goodqa-prod/bugtracker-scan@sha256:' + DO_DIG['d1'],
+             'JOB_IMAGE_TRANSCODE': 'registry.digitalocean.com/goodqa-prod/bugtracker-transcode@sha256:' + DO_DIG['d2'],
+             'JOB_IMAGE_INTELLIGENCE_WORKER': 'registry.digitalocean.com/goodqa-prod/bugtracker-intelligence-worker@sha256:' + DO_DIG['d3'],
+             'JOB_IMAGE_SUGGEST_FIX_WORKER': 'registry.digitalocean.com/goodqa-prod/bugtracker-suggest-fix-worker@sha256:' + DO_DIG['d4']}
+
+
+def compose_text(env):
+    return COMPOSE.format(env=env, **DO_DIG)
+
+
+def job_pins(text):
+    """{KEY: value} for JOB_IMAGE_* lines, per service block: {'svc': {...}}."""
+    res = {}; cur = None
+    for l in text.split('\n'):
+        m = re.match(r'^  ([A-Za-z0-9_.-]+):\s*(#.*)?$', l)
+        if m: cur = m.group(1); continue
+        m = re.match(r'^      (JOB_IMAGE_[A-Z_]+):\s*(\S+)', l)
+        if m and cur: res.setdefault(cur, {})[m.group(1)] = m.group(2)
+    return res
+
+
 PROMOTE = r'''#!/usr/bin/env bash
 printf '%s\n' "$@" > "$FAKE_STATE/promote-argv"
 Q=no; RO=""
@@ -237,6 +319,29 @@ echo "promote gates passed $APP $SHA (TMPDIR=$TMPDIR)"
 '''
 
 
+CONTAINERD = r'''#!/usr/bin/env bash
+# fake containerd: `config dump` reports a root under the fixture (goodqa#16136 F2)
+[ "$*" = "config dump" ] || exit 2
+[ -e "$FAKE_STATE/containerd-fail" ] && exit 1
+[ -e "$FAKE_STATE/containerd-noroot" ] && { echo "version = 2"; exit 0; }
+printf "version = 2\nroot = '%s'\nstate = '/run/containerd'\n" "$FAKE_STATE/containerd-root"
+'''
+
+VMDF = r'''#!/usr/bin/env bash
+# fake df for the VM side only: FAKE_STATE/vmdf-docker or vmdf-containerd = free KiB, or "fail"; otherwise the real df
+if [ "${FAKE_SIDE:-}" = remote ] && [ "$1" = -Pk ]; then
+  case "$2" in "$FAKE_STATE") n=docker;; "$FAKE_STATE/containerd-root") n=containerd;; *) n="";; esac
+  if [ -n "$n" ]; then
+    v=104857600; [ -e "$FAKE_STATE/vmdf-$n" ] && v=$(cat "$FAKE_STATE/vmdf-$n")
+    [ "$v" = fail ] && exit 1
+    printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\nfixture-%s 209715200 1 %s 1%% /%s\n' "$n" "$v" "$n"; exit 0
+  fi
+fi
+for d in $(printf '%s' "$PATH" | tr ':' ' '); do [ "$d/df" != "$0" ] && [ -x "$d/df" ] && [ "$(cd "$d" && pwd)" != "$(cd "$(dirname "$0")" && pwd)" ] && exec "$d/df" "$@"; done
+exit 127
+'''
+
+
 class SRoot(base.Root):
     def __init__(self, b, freeze_until='2020-01-01T00:00:00Z', extra_conf=''):
         super().__init__(b)
@@ -246,19 +351,21 @@ class SRoot(base.Root):
                            (os.path.join(b, 'stub', 'docker'), DOCKER)):
             open(path, 'w').write(body); os.chmod(path, 0o755)
         open(os.path.join(b, 'bin', 'selfhost-ctl.py'), 'w').write(open(CTL).read())
+        for path, body in ((os.path.join(b, 'stub', 'containerd'), CONTAINERD), (os.path.join(b, 'stub', 'df'), VMDF)):
+            open(path, 'w').write(body); os.chmod(path, 0o755)
         node = os.path.join(b, 'stub/node')
         body = Path(node).read_text() if 'Path' in globals() else open(node).read()
         body = body.replace("else:\n    log('NODE '", "elif a and (a[0].endswith('dockerfile-tzdata-policy.mjs') or a[0].endswith('build-boundary.mjs')): pass\nelse:\n    log('NODE '")
         open(node, 'w').write(body)
         live = self.get('live')
-        open(os.path.join(self.vm, 'compose.yaml'), 'w').write(COMPOSE.format(env=self.envd))
+        open(os.path.join(self.vm, 'compose.yaml'), 'w').write(compose_text(self.envd))
         for f in ('api', 'web'):
             p = os.path.join(self.envd, f + '.env')
             open(p, 'w').write('DATABASE_URL=postgres://doadmin:pw@10.0.0.6/bugtracker\nRELEASE_SOURCE_SHA=%s\nRELEASE_DEPLOYMENT_ID=selfhost-base\nX=1\n' % live)
             os.chmod(p, 0o600)
         with open(os.path.join(b, 'biz/release-waves/ship.conf'), 'a') as f:
             f.write('SELFHOST_APP=ubuntu@fake-vm\nSELFHOST_DIR=%s\nSELFHOST_ENV_DIR=%s\nSELFHOST_PROJECT=goodqa\n'
-                    'SELFHOST_SCHEMA_FREEZE_UNTIL=%s\nSELFHOST_UP_TIMEOUT=1\nSELFHOST_BUILD_MIN_FREE_GB=0\n%s' % (self.vm, self.envd, freeze_until, extra_conf))
+                    'SELFHOST_SCHEMA_FREEZE_UNTIL=%s\nSELFHOST_UP_TIMEOUT=1\nSELFHOST_BUILD_MIN_FREE_GB=0\nSELFHOST_VM_MIN_FREE_GB=0\nSELFHOST_JOB_HOLD=none\n%s' % (self.vm, self.envd, freeze_until, extra_conf))
         # Keep the scheduler and image policy in the immutable fixture source.
         import shutil
         os.makedirs(os.path.join(self.repo, 'infra/release-harness'), exist_ok=True)
@@ -267,7 +374,8 @@ class SRoot(base.Root):
             shutil.copyfile(os.path.join(HERE, '../..', rel), os.path.join(self.repo, rel))
         # the product repo's promote.sh for this root: gates + local api build, no --apply
         open(os.path.join(self.repo, 'infra/do/promote.sh'), 'w').write(PROMOTE)
-        for d in ('apps/web', 'apps/job-dispatcher'): os.makedirs(os.path.join(self.repo, d), exist_ok=True)
+        for d in ('apps/web', 'apps/job-dispatcher') + tuple(v[1] for v in JOBS.values()):
+            os.makedirs(os.path.join(self.repo, d), exist_ok=True); open(os.path.join(self.repo, d, 'Dockerfile'), 'w').write('FROM scratch\n')
         open(os.path.join(self.repo, 'apps/web/Dockerfile'), 'w').write('FROM scratch\n')
         open(os.path.join(self.repo, 'apps/job-dispatcher/Dockerfile'), 'w').write('FROM scratch\n')
         base.git('add', '-A', cwd=self.repo); base.git('commit', '-q', '-m', 'selfhost fixture', cwd=self.repo)
@@ -275,7 +383,8 @@ class SRoot(base.Root):
         # the VM: the three base images present, the stack up on them
         os.makedirs(os.path.join(self.st, 'docker'), exist_ok=True)
         json.dump({'registry.example/bugtracker-api@sha256:aaa': 'sha256:' + 'a' * 64, 'goodqa-web:base': 'sha256:' + 'b' * 64,
-                   'goodqa-web:other': 'sha256:' + 'e' * 64, 'goodqa-job-dispatcher:base': 'sha256:' + 'c' * 64},
+                   'goodqa-web:other': 'sha256:' + 'e' * 64, 'goodqa-job-dispatcher:base': 'sha256:' + 'c' * 64,
+                   'caddy@sha256:cad': 'sha256:' + '9' * 64},
                   open(os.path.join(self.st, 'docker', 'images-remote.json'), 'w'))
         self.vmdocker('compose', '-p', 'goodqa', '-f', os.path.join(self.vm, 'compose.yaml'), 'up', '-d', '--no-deps',
                       'api', 'web', 'job-dispatcher', 'job-dispatcher-create-guard')
@@ -301,6 +410,9 @@ class SRoot(base.Root):
         return {s: re.search(r'^  %s:\n(?:    .*\n)*?    image: (\S+)' % re.escape(s), t, re.M).group(1)
                 for s in ('api', 'web', 'job-dispatcher', 'job-dispatcher-create-guard')}
 
+    def jobs(self, svc='job-dispatcher-create-guard'):
+        return job_pins(open(os.path.join(self.vm, 'compose.yaml')).read()).get(svc, {})
+
     def env_sha(self, f='api'):
         return re.search(r'^RELEASE_SOURCE_SHA=(\S+)$', open(os.path.join(self.envd, f + '.env')).read(), re.M).group(1)
 
@@ -318,6 +430,7 @@ def R(tmp_path):
 
 def unchanged(R, before_live):
     assert R.pins() == BASE_PINS, R.pins()
+    assert R.jobs() == BASE_JOBS, R.jobs()
     assert R.env_sha('api') == before_live and R.env_sha('web') == before_live
     assert 'UP ' not in R.dlog(), 'nothing may be brought up'
     assert not [f for f in os.listdir(R.vm) if '.pre-rw-' in f], 'no re-pin may have happened'
@@ -350,6 +463,38 @@ def test_selfhost_release_ships(R):
     assert len(recs) == 1
 
 
+def test_selfhost_release_ships_job_images(R):
+    """goodqa#16136 AC-1/AC-2: the four job images are built from the release sha, loaded on the VM with matching ids, and
+    the &job-images anchor (guard; the dispatcher inherits it) is pinned to goodqa-<job>@<VM image id>."""
+    sha = R.release('release/wave-60j'); rc, out = R.run('release/wave-60j', sha)
+    assert rc == 0, out
+    vm_imgs = json.load(open(os.path.join(R.st, 'docker', 'images-remote.json')))
+    tag = R.pins()['api'].split(':', 1)[1]
+    want = {}
+    for key, (job, _) in JOBS.items():
+        ref = 'goodqa-%s:%s' % (job, tag)
+        assert ref in vm_imgs, 'job image %s was not transferred to the VM' % ref
+        assert 'BUILD ' + ref in R.dlog(), 'job image %s was not built' % ref
+        want[key] = 'goodqa-%s@%s' % (job, vm_imgs[ref])
+    assert R.jobs() == want, R.jobs()
+    assert all(re.fullmatch(r'goodqa-[a-z-]+@sha256:[0-9a-f]{64}', v) for v in R.jobs().values()), 'AUD-031 digest form'
+    assert R.jobs('job-dispatcher') == {}, 'the dispatcher keeps inheriting the anchor, no divergent copy'
+    rec = subprocess.run(['git', 'show', 'main:' + subprocess.run(['git', 'ls-tree', '-r', '--name-only', 'main', 'audit/selfhost-deploys'],
+                          cwd=R.origin, capture_output=True, text=True).stdout.split()[0]], cwd=R.origin, capture_output=True, text=True).stdout
+    assert all('goodqa-%s:%s' % (j, tag) in rec for j, _ in JOBS.values()), 'the deploy record lists the job images'
+
+
+def test_job_images_build_failure_changes_nothing(R):
+    before = R.get('live'); R.put('fail-build', 'goodqa-transcode'); sha = R.release('release/wave-60k')
+    rc, out = R.run('release/wave-60k', sha)
+    assert rc == 3 and 'job-images-' in out, out
+    rd = os.path.join(R.F, 'biz/release-waves/deploys')
+    receipts = [os.path.join(dp, f) for dp, _, fs in os.walk(rd) for f in fs if f == 'jobs.json' and 'job-images-' in dp]
+    jobs = [j for r in receipts for j in json.load(open(r))['jobs']]
+    assert [j['name'] for j in jobs if j['state'] == 'failed'] == ['transcode'], jobs
+    unchanged(R, before)
+
+
 def test_migrations_applied_before_the_switch(R):
     R.put('mig-pending', '2'); sha = R.release('release/wave-61')
     rc, out = R.run('release/wave-61', sha)
@@ -375,7 +520,7 @@ def test_migration_urls_are_redacted_by_the_controller(tmp_path):
     st = tmp_path / 'state'; (st / 'docker').mkdir(parents=True); stub = tmp_path / 'stub'; stub.mkdir()
     (stub / 'docker').write_text(DOCKER); os.chmod(stub / 'docker', 0o755)
     vm = tmp_path / 'vm'; env = tmp_path / 'env'; vm.mkdir(); env.mkdir()
-    (vm / 'compose.yaml').write_text(COMPOSE.format(env=env))
+    (vm / 'compose.yaml').write_text(compose_text(env))
     for f in ('api', 'web'): (env / (f + '.env')).write_text('RELEASE_SOURCE_SHA=%s\nRELEASE_DEPLOYMENT_ID=x\n' % ('1' * 40))
     (st / 'docker' / 'images-remote.json').write_text(json.dumps({'img:new': 'sha256:' + '9' * 64}))
     (st / 'mig-fail-dry').write_text('')
@@ -432,6 +577,7 @@ def test_failed_switch_rolls_back_to_previous_pins(R, how):
     rc, out = R.run('release/wave-66', sha)
     assert rc == 5, out
     assert R.pins() == BASE_PINS, 'compose.yaml back on the previous pins'
+    assert R.jobs() == BASE_JOBS, 'the job image pins roll back with compose.yaml'
     assert R.env_sha('api') == before and R.get('live') == before
     assert 'ROLLED BACK' in out and R.state_of('release/wave-66')[0] == 'deploy-failed'
     assert not R.contains(sha) and not os.path.exists(R.infl)
@@ -518,6 +664,24 @@ def test_full_build_disk_is_infrastructure(tmp_path):
         R.cleanup()
 
 
+def test_rw_ship_build_floor_counts_seven_images(tmp_path):
+    # goodqa#16136 AC-1: rw-ship's own build-disk floor (after the runtime preflight) refuses before any image job.
+    R = SRoot(str(tmp_path))
+    try:
+        conf = os.path.join(R.F, 'biz/release-waves/ship.conf')
+        txt = open(conf).read(); open(conf, 'w').write(txt.replace('SELFHOST_BUILD_MIN_FREE_GB=0', 'SELFHOST_BUILD_MIN_FREE_GB=1'))
+        df = os.path.join(R.F, 'stub', 'df')
+        real = [d for d in os.environ['PATH'].split(':') if os.path.isfile(os.path.join(d, 'df'))][0]
+        open(df, 'w').write('#!/bin/bash\ncase "$*" in *--output=avail*) printf "Avail\\n0G\\n"; exit 0;; esac\nexec %s/df "$@"\n' % real)
+        os.chmod(df, 0o755)
+        sha = R.release('release/wave-75b'); rc, out = R.run('release/wave-75b', sha)
+        assert rc == 11 and 'NO DISK (infrastructure, exit 11): 0G free' in out and 'seven images' in out, out
+        assert 'BUILD' not in R.dlog() and R.pins() == BASE_PINS
+        assert not any('job-images-' in dp for dp, _, _ in os.walk(os.path.join(R.F, 'biz/release-waves/deploys')))
+    finally:
+        R.cleanup()
+
+
 def test_schema_errors_after_switch_are_not_verified(R):
     R.put('schema-errors', ''); sha = R.release('release/wave-76')
     rc, out = R.run('release/wave-76', sha)
@@ -589,12 +753,14 @@ def ctl_fixture(tmp_path, envtext=None):
     st = tmp_path / 'state'; (st / 'docker').mkdir(parents=True); stub = tmp_path / 'stub'; stub.mkdir()
     (stub / 'docker').write_text(DOCKER); os.chmod(stub / 'docker', 0o755)
     vm = tmp_path / 'vm'; env = tmp_path / 'env'; vm.mkdir(); env.mkdir()
-    (vm / 'compose.yaml').write_text(COMPOSE.format(env=env))
+    (vm / 'compose.yaml').write_text(compose_text(env))
     for f in ('api', 'web'):
         (env / (f + '.env')).write_text(envtext if envtext is not None else 'A=1\nRELEASE_SOURCE_SHA=%s\nRELEASE_DEPLOYMENT_ID=old\n' % ('1' * 40))
         os.chmod(env / (f + '.env'), 0o600)
     (st / 'docker' / 'images-remote.json').write_text(json.dumps({'registry.example/bugtracker-api@sha256:aaa': 'sha256:a', 'goodqa-web:base': 'sha256:b',
-                                                                  'goodqa-job-dispatcher:base': 'sha256:c', 'n:api': 'sha256:1', 'n:web': 'sha256:2', 'n:disp': 'sha256:3'}))
+                                                                  'goodqa-job-dispatcher:base': 'sha256:c', 'n:api': 'sha256:1', 'n:web': 'sha256:2', 'n:disp': 'sha256:3',
+                                                                  'caddy@sha256:cad': 'sha256:9',
+                                                                  **{'goodqa-%s:t1' % j: 'sha256:' + JID[j] for j, _ in JOBS.values()}}))
     e = dict(os.environ, PATH=str(stub) + ':' + os.environ['PATH'], FAKE_STATE=str(st), FAKE_SIDE='remote')
     def ctl(*a):
         r = subprocess.run(['python3', CTL, '--dir', str(vm), '--env-dir', str(env), *a], env=e, capture_output=True, text=True)
@@ -603,21 +769,31 @@ def ctl_fixture(tmp_path, envtext=None):
     return ctl, snap, st, vm, env
 
 
-PIN = ('pin', '--stamp', 'S1', '--sha', '2' * 40, '--deploy-id', 'selfhost-S1', '--api', 'n:api', '--web', 'n:web', '--disp', 'n:disp')
+def J(o):
+    return json.loads(next(l for l in o.split('\n') if l.startswith('{')))
+
+
+JID = {'scan': '1' * 64, 'transcode': '2' * 64, 'intelligence-worker': '3' * 64, 'suggest-fix-worker': '4' * 64}
+NEW_JOBS = {k: 'goodqa-%s@sha256:%s' % (j, JID[j]) for k, (j, _) in JOBS.items()}
+JOBARGS = tuple(x for k, v in NEW_JOBS.items() for x in ('--job-image', '%s=%s' % (k, v)))
+PIN0 = ('pin', '--stamp', 'S1', '--sha', '2' * 40, '--deploy-id', 'selfhost-S1', '--api', 'n:api', '--web', 'n:web', '--disp', 'n:disp')
+PIN = PIN0 + JOBARGS
 
 
 def test_ctl_pin_then_restore_round_trips(tmp_path):
     ctl, snap, st, vm, env = ctl_fixture(tmp_path); before = snap()
     rc0, s0 = ctl('state'); rc, s1 = ctl(*PIN)
     assert rc0 == 0 and rc == 0, s1
-    a, b = json.loads(s0), json.loads(s1)
+    a, b = J(s0), J(s1)
     assert b['pins'] == {'api': 'n:api', 'web': 'n:web', 'job-dispatcher': 'n:disp', 'job-dispatcher-create-guard': 'n:disp'}
     assert b['env']['api']['RELEASE_SOURCE_SHA'] == '2' * 40 and b['env']['web']['RELEASE_DEPLOYMENT_ID'] == 'selfhost-S1'
     assert a['fp'] != b['fp'] and 'A=1' in open(env / 'api.env').read(), 'other env lines are kept'
+    assert a['jobs'] == BASE_JOBS and b['jobs'] == NEW_JOBS, b.get('jobs')
+    assert job_pins(open(vm / 'compose.yaml').read()) == {'job-dispatcher-create-guard': NEW_JOBS}
     assert oct(os.stat(env / 'api.env').st_mode & 0o777) == '0o600'
     assert ctl(*PIN)[0] == 3, 'a reused stamp is refused (its backups would be overwritten)'
     rc, s2 = ctl('restore', '--stamp', 'S1')
-    assert rc == 0 and json.loads(s2)['fp'] == a['fp'] and snap() == before
+    assert rc == 0 and J(s2)['fp'] == a['fp'] and snap() == before
 
 
 @pytest.mark.parametrize('case', ['no-release-key', 'missing-image', 'invalid-compose', 'bad-sha'])
@@ -748,7 +924,9 @@ def install_real_promote(r):
            'infra/lib/promotion-gate.mjs', 'infra/lib/release-clean-tree.sh', 'infra/lib/release-image-policy.sh',
            'infra/ops-launch/freeze.py', 'infra/ops-launch/common.py', 'infra/ops-launch/freeze-policy.json', 'infra/build-boundary.mjs',
            'infra/dockerfile-tzdata-policy.mjs', 'infra/dockerfile-user-policy.mjs', 'infra/base-image-policy.mjs',
-           'apps/api/Dockerfile', 'apps/web/Dockerfile', 'apps/job-dispatcher/Dockerfile')
+           'apps/api/Dockerfile', 'apps/web/Dockerfile', 'apps/job-dispatcher/Dockerfile',
+           'apps/scan-worker/Dockerfile', 'apps/transcoder/Dockerfile', 'apps/intelligence-worker/Dockerfile',
+           'apps/suggest-fix-worker/Dockerfile')   # goodqa#16136: the job images are production Dockerfiles too
     for rel in files:
         target=Path(r.repo,rel); target.parent.mkdir(parents=True,exist_ok=True)
         shutil.copyfile(source/rel,target)
@@ -820,3 +998,552 @@ class PromotionPhases(unittest.TestCase):
                 self.assertNotIn('BUILD ',r.dlog())
                 self.assertEqual(len(r.get('gates.log').splitlines()),4)
             finally: r.cleanup()
+
+
+# ---------------------------------------------------------------- goodqa#16136: job image pins + presence check (selfhost-ctl)
+def _swap(args, key, value):
+    a = list(args); i = a.index('%s=%s' % (key, NEW_JOBS[key])); a[i] = '%s=%s' % (key, value) if value is not None else None
+    if value is None: del a[i - 1:i + 1]
+    return a
+
+
+@pytest.mark.parametrize('case', ['mutable-tag', 'wrong-repo', 'unknown-key', 'duplicate-key', 'partial-set', 'metachar',
+                                  'bare-id', 'do-ref', 'no-job-args'])
+def test_ctl_job_images_refusals_change_nothing(tmp_path, case):
+    """NEG-2: every --job-image value that is not exactly goodqa-<the key's own job>@sha256:<64 hex>, once per key, all four."""
+    ctl, snap, st, vm, env = ctl_fixture(tmp_path); before = snap()
+    S = 'JOB_IMAGE_SCAN'
+    args = {'mutable-tag': lambda: _swap(PIN, S, 'goodqa-scan:latest'),
+            'wrong-repo': lambda: _swap(PIN, 'JOB_IMAGE_INTELLIGENCE_WORKER', NEW_JOBS[S]),
+            'unknown-key': lambda: list(PIN) + ['--job-image', 'JOB_IMAGE_EVIL=goodqa-scan@sha256:' + JID['scan']],
+            'duplicate-key': lambda: list(PIN) + ['--job-image', '%s=%s' % (S, NEW_JOBS[S])],
+            'partial-set': lambda: _swap(PIN, 'JOB_IMAGE_TRANSCODE', None),
+            'metachar': lambda: _swap(PIN, S, NEW_JOBS[S] + '\n      GUARD_ENV: dev'),
+            'bare-id': lambda: _swap(PIN, S, 'sha256:' + JID['scan']),
+            'do-ref': lambda: _swap(PIN, S, BASE_JOBS[S]),
+            'no-job-args': lambda: list(PIN0)}[case]()
+    rc, o = ctl(*args)
+    assert rc in (2, 3) and (rc == 2 or o.startswith('REFUSED')), (rc, o)
+    assert snap() == before and not [f for f in os.listdir(vm) + os.listdir(env) if 'pre-rw' in f or 'rw-pin' in f]
+
+
+@pytest.mark.parametrize('case', ['job-image-absent', 'other-repo-same-id', 'tag-removed-content-kept', 'id-mismatch'])
+def test_ctl_pin_refuses_missing_job_image(tmp_path, case):
+    """NEG-1 / AC-3: a release-managed job ref the host cannot resolve, by the exact compose string with a matching Id,
+    refuses the pin before any change. The fake models the containerd store: repo@digest resolves only while a
+    same-repo tag targets that id."""
+    ctl, snap, st, vm, env = ctl_fixture(tmp_path); before = snap()
+    p = st / 'docker' / 'images-remote.json'; d = json.loads(p.read_text())
+    args = list(PIN)
+    if case == 'job-image-absent': d.pop('goodqa-suggest-fix-worker:t1')
+    if case == 'other-repo-same-id': args = _swap(PIN, 'JOB_IMAGE_SCAN', 'goodqa-scan@sha256:' + JID['transcode'])
+    if case == 'tag-removed-content-kept': d['other-repo:t1'] = d.pop('goodqa-scan:t1')
+    if case == 'id-mismatch': (st / 'id-skew').write_text('goodqa-transcode@')
+    p.write_text(json.dumps(d))
+    rc, o = ctl(*args)
+    assert rc == 3 and o.startswith('REFUSED') and 'not present on this host' in o, o
+    assert snap() == before and not [f for f in os.listdir(vm) + os.listdir(env) if 'pre-rw' in f or 'rw-pin' in f]
+
+
+def test_presence_check_uses_prepared_compose(tmp_path):
+    """AC-3: the live compose still names the DO-registry job refs, which no host has; the check reads the PREPARED text,
+    so the first release of this fix is not refused by the very pins it replaces."""
+    ctl, snap, st, vm, env = ctl_fixture(tmp_path)
+    assert all(v not in json.loads((st / 'docker' / 'images-remote.json').read_text()) for v in BASE_JOBS.values())
+    rc, o = ctl(*PIN)
+    assert rc == 0, o
+    assert J(o)['missing'] == [] and J(o)['jobs'] == NEW_JOBS and J(o)['jobs_missing'] == []
+
+
+def test_ctl_job_images_divergent_dispatcher_copy_refuses(tmp_path):
+    """The dispatcher must inherit the guard's anchor: a JOB_IMAGE_* line in any other service block would let the two diverge."""
+    ctl, snap, st, vm, env = ctl_fixture(tmp_path)
+    c = vm / 'compose.yaml'; c.write_text(c.read_text().replace('      JOB_DISPATCHER_ENV: production\n',
+                                                                 '      JOB_DISPATCHER_ENV: production\n      JOB_IMAGE_SCAN: x@sha256:' + '0' * 64 + '\n'))
+    before = snap(); rc, o = ctl(*PIN)
+    assert rc == 3 and 'JOB_IMAGE' in o, o
+    assert snap() == before
+
+
+def test_restore_never_runs_the_presence_check(tmp_path):
+    """NEG-7: an emergency rollback to the previous compose proceeds even though its (DO) job refs are not on the host."""
+    ctl, snap, st, vm, env = ctl_fixture(tmp_path); before = snap()
+    assert ctl(*PIN)[0] == 0
+    rc, o = ctl('restore', '--stamp', 'S1')
+    assert rc == 0 and snap() == before, o
+    assert J(o)['jobs'] == BASE_JOBS
+
+
+
+# ---------------------------------------------------------------- goodqa#16136 spec v2
+INTEL = 'JOB_IMAGE_INTELLIGENCE_WORKER'
+HELD = '""'   # goodqa#16136: a held job line's value
+
+
+def _conf(R, key, value):
+    c = os.path.join(R.F, 'biz/release-waves/ship.conf'); lines = [l for l in open(c).read().split('\n') if not l.startswith(key + '=')]
+    if value is not None: lines.insert(0, '%s=%s' % (key, value))
+    open(c, 'w').write('\n'.join(lines))
+
+
+def test_default_holds_intelligence_worker(R):
+    """AC-10a: with no SELFHOST_JOB_HOLD in ship.conf, intelligence-worker is held: its line is unchanged, it is not
+    built, and the run says so. The other three are pinned to their loaded ids."""
+    _conf(R, 'SELFHOST_JOB_HOLD', None); sha = R.release('release/wave-60h'); rc, out = R.run('release/wave-60h', sha)
+    assert rc == 0, out
+    j = R.jobs(); assert j[INTEL] == HELD, j
+    assert j['JOB_IMAGE_TRANSCODE'] == HELD, 'default also holds transcribe; this guard cannot, so all of transcode'
+    assert all(re.fullmatch(r'goodqa-[a-z-]+@sha256:[0-9a-f]{64}', v) for k, v in j.items() if k not in (INTEL, 'JOB_IMAGE_TRANSCODE')), j
+    assert 'BUILD goodqa-intelligence-worker' not in R.dlog() and 'held: intelligence-worker' in out and 'guard lacks GUARD_HELD_ENV' in out, out
+
+
+def test_bad_job_hold_value_refuses_before_building(R):
+    before = R.get('live'); _conf(R, 'SELFHOST_JOB_HOLD', 'intelligence'); sha = R.release('release/wave-60b')
+    rc, out = R.run('release/wave-60b', sha)
+    assert rc == 2 and 'SELFHOST_JOB_HOLD' in out, out
+    assert 'BUILD' not in R.dlog(); unchanged(R, before)
+
+
+def test_vm_disk_low_stops_before_transfer(R):
+    """NEG-6: the VM's own free space is checked before docker load."""
+    before = R.get('live'); _conf(R, 'SELFHOST_VM_MIN_FREE_GB', '999999'); sha = R.release('release/wave-60v')
+    rc, out = R.run('release/wave-60v', sha)
+    assert rc == 11 and 'NO DISK' in out and 'VM' in out, out
+    assert 'LOAD' not in R.dlog(); unchanged(R, before)
+
+
+def test_job_ref_unresolved_after_switch_rolls_back(R):
+    """AC-7: a job ref that stops resolving right after the switch is a switch failure: the previous pins come back."""
+    before = R.get('live'); sha = R.release('release/wave-60u'); R.put('untag-after-up', 'goodqa-scan: ' + sha)
+    rc, out = R.run('release/wave-60u', sha)
+    assert rc == 5 and 'job image refs' in out and 'ROLLED BACK' in out, out
+    assert R.pins() == BASE_PINS and R.jobs() == BASE_JOBS and R.get('live') == before
+
+
+def test_job_images_id_mismatch_after_transfer_refuses(R):
+    """NEG-5: only a job image arrives different on the VM."""
+    before = R.get('live'); sha = R.release('release/wave-60m')
+    R.put('load-corrupt', '')
+    rc, out = R.run('release/wave-60m', sha)
+    assert rc == 3 and 'goodqa-scan:' in out and 'not the ones built here' in out, out
+    unchanged(R, before)
+
+
+def test_ctl_pin_refuses_classic_store(tmp_path):
+    """AC-5: on a classic (overlay2) store a loaded image's repo@id does not resolve: refuse, change nothing."""
+    ctl, snap, st, vm, env = ctl_fixture(tmp_path); before = snap(); (st / 'classic-store').write_text('')
+    rc, o = ctl(*PIN)
+    assert rc == 3 and 'containerd' in o, o
+    assert snap() == before
+
+
+def test_third_party_ref_absent_warns_not_refuses(tmp_path):
+    """AC-3: a pulled third-party image (caddy) that does not resolve is a WARN, never a refusal of every release."""
+    ctl, snap, st, vm, env = ctl_fixture(tmp_path)
+    p = st / 'docker' / 'images-remote.json'; d = json.loads(p.read_text()); d.pop('caddy@sha256:cad'); p.write_text(json.dumps(d))
+    rc, o = ctl(*PIN)
+    assert rc == 0 and 'WARN third-party image not present on this host: caddy@sha256:cad' in o, o
+
+
+def test_ctl_job_hold_empties_line_and_skips_presence(tmp_path):
+    """AC-10a: --job-hold writes the held value "" (a launch block) and exempts the key from the presence check."""
+    ctl, snap, st, vm, env = ctl_fixture(tmp_path)
+    args = _swap(PIN, INTEL, None) + ['--job-hold', INTEL]
+    rc, o = ctl(*args)
+    assert rc == 0, o
+    want = dict(NEW_JOBS); want[INTEL] = HELD
+    assert J(o)['jobs'] == want and J(o)['jobs_missing'] == [] and J(o)['jobs_held'] == [INTEL], o
+    args2 = _swap(PIN, INTEL, None) + ['--job-hold', INTEL, '--job-hold', INTEL]; args2[args2.index('S1')] = 'S2'
+    rc2, o2 = ctl(*args2)
+    assert rc2 == 3, 'a repeated hold is refused'
+
+
+@pytest.mark.parametrize('case', ['fresh', 'untagged'])
+def test_state_reports_job_refs_and_missing(tmp_path, case):
+    """AC-6 / NEG-11: state lists the job refs, and any that stop resolving land in jobs_missing (not missing)."""
+    ctl, snap, st, vm, env = ctl_fixture(tmp_path)
+    assert ctl(*PIN)[0] == 0
+    if case == 'untagged':
+        p = st / 'docker' / 'images-remote.json'; d = json.loads(p.read_text()); d.pop('goodqa-scan:t1'); p.write_text(json.dumps(d))
+    rc, o = ctl('state'); s = J(o)
+    assert rc == 0 and s['jobs'] == NEW_JOBS and s['missing'] == []
+    assert s['jobs_missing'] == ([NEW_JOBS['JOB_IMAGE_SCAN']] if case == 'untagged' else []), s
+    if case == 'untagged':
+        args = list(PIN); args[args.index('S1')] = 'S2'
+        rc2, o2 = ctl(*args)
+        assert rc2 == 3 and 'not present on this host' in o2, 'a later pin refuses until the release reloads it'
+
+
+def test_fp_unchanged_by_job_pin_reporting(tmp_path):
+    """AC-6 / C5: the job pins stay outside the fp core; the b3604eae ctl (same tree as the installed 5a78109) and this ctl agree on the fp of the same stack."""
+    ctl, snap, st, vm, env = ctl_fixture(tmp_path)
+    old = tmp_path / 'selfhost-ctl.b3604eae.py'
+    src = subprocess.run(['git', 'show', 'b3604eaec1c6eac8a0f2558ca7f8ebd24cdc7254:infra/release-harness/selfhost-ctl.py'], cwd=HERE, capture_output=True, text=True)
+    assert src.returncode == 0, src.stderr
+    old.write_text(src.stdout)
+    e = dict(os.environ, PATH=str(tmp_path / 'stub') + ':' + os.environ['PATH'], FAKE_STATE=str(st), FAKE_SIDE='remote')
+    r = subprocess.run(['python3', str(old), '--dir', str(vm), '--env-dir', str(env), 'state'], env=e, capture_output=True, text=True)
+    assert r.returncode == 0, r.stdout + r.stderr
+    rc, o = ctl('state')
+    assert rc == 0 and J(o)['fp'] == J(r.stdout)['fp']
+
+
+def test_restore_warns_jobs_down_and_never_runs_presence_check(tmp_path):
+    """AC-8: the first rollback restores the DO refs: restore proceeds, and says the jobs are down."""
+    ctl, snap, st, vm, env = ctl_fixture(tmp_path); before = snap()
+    assert ctl(*PIN)[0] == 0
+    rc, o = ctl('restore', '--stamp', 'S1')
+    assert rc == 0 and snap() == before, o
+    assert 'WARN jobs down after rollback:' in o and BASE_JOBS['JOB_IMAGE_SCAN'] in o, o
+
+
+def test_restore_core_image_missing_warns_and_up_never_pulls(tmp_path):
+    """AC-8 / NEG-7: restore with a pruned core image still restores and warns; up then fails and never pulls."""
+    ctl, snap, st, vm, env = ctl_fixture(tmp_path); before = snap()
+    assert ctl(*PIN)[0] == 0
+    p = st / 'docker' / 'images-remote.json'; d = json.loads(p.read_text()); d.pop('goodqa-web:base'); p.write_text(json.dumps(d))
+    rc, o = ctl('restore', '--stamp', 'S1')
+    assert rc == 0 and snap() == before and 'WARN core image missing: goodqa-web:base' in o, o
+    rc2, o2 = ctl('up', '--timeout', '1')
+    assert rc2 == 5 and o2.startswith('UP_FAIL'), o2
+    assert 'PULL never' in open(st / 'docker.log').read(), 'up must run with --pull never'
+
+
+@pytest.mark.skipif(os.environ.get('RW_REAL_COMPOSE') != '1', reason='real docker compose run: set RW_REAL_COMPOSE=1 (t2-dev)')
+def test_real_compose_resolves_anchor_for_both_services(tmp_path):
+    """AC-2 / C6: the real `docker compose config` of the product compose.yaml, re-pinned by this ctl's own rewrite, gives
+    both the guard and the dispatcher exactly the four new values (the YAML merge key is resolved by compose, not a regex)."""
+    import importlib.util
+    spec = importlib.util.spec_from_file_location('shctl', CTL); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
+    src = os.path.join(HERE, '..', 'selfhost', 'app', 'compose.yaml')
+    text = open(src).read()
+    for envf in sorted(set(re.findall(r'path:[ \t]*(\S+\.env)', text)) | set(re.findall(r'env_file:[ \t]*(\S+\.env)', text))):
+        fake = tmp_path / os.path.basename(envf); fake.write_text('X=1\n'); text = text.replace(envf, str(fake))
+    stk = m.Stack(str(tmp_path), str(tmp_path), 'rwtest')
+    new = {k: 'goodqa-%s@sha256:%s' % (j, JID[j]) for k, (j, _) in JOBS.items()}
+    out_text = stk.rejob(text, new)
+    (tmp_path / 'compose.yaml').write_text(out_text)
+    r = subprocess.run(['docker', 'compose', '-p', 'rwtest', '-f', str(tmp_path / 'compose.yaml'), 'config', '--format', 'json'],
+                       capture_output=True, text=True, cwd=str(tmp_path),
+                       env=dict(os.environ, **{v: 'rwtest.invalid' for v in re.findall(r'\$\{([A-Z0-9_]+):?\?', text)}))
+    assert r.returncode == 0, r.stderr[-800:]
+    svcs = json.loads(r.stdout)['services']
+    for s in ('job-dispatcher-create-guard', 'job-dispatcher'):
+        got = {k: v for k, v in (svcs[s].get('environment') or {}).items() if k.startswith('JOB_IMAGE_')}
+        assert got == new, (s, got)
+
+
+
+# ---------------------------------------------------------------- goodqa#16136 spec v2.1: transcription guard hold + coupling
+GUARD_SRC = 'apps/job-dispatcher/src/create-guard-main.ts'
+
+
+def _guard_source(R, supports, text=None):
+    """supports: the built guard behaves (fake docker marker); text: its source mentions GUARD_HELD_ENV (default: same)."""
+    if supports: R.put('guard-held-support', '')
+    text = supports if text is None else text
+    d = os.path.join(R.repo, os.path.dirname(GUARD_SRC)); os.makedirs(d, exist_ok=True)
+    open(os.path.join(R.repo, GUARD_SRC), 'w').write('// guard\n' + ('const held = process.env.GUARD_HELD_ENV;\n' if text else ''))
+    base.git('add', '-A', cwd=R.repo); base.git('commit', '-q', '-m', 'guard source', cwd=R.repo)
+    base.git('push', '-q', 'origin', 'HEAD:main', cwd=R.repo)
+
+
+def _guard_line(R):
+    t = open(os.path.join(R.vm, 'compose.yaml')).read()
+    return [l.strip() for l in t.split('\n') if 'GUARD_HELD_ENV' in l]
+
+
+def test_transcribe_hold_with_guard_support_pins_transcode(R):
+    """AC-16/AC-17: the release's guard implements GUARD_HELD_ENV: transcode (MP4) is pinned, transcription is held at
+    the guard by its one line, and the run log and deploy record name the hold."""
+    _guard_source(R, True); _conf(R, 'SELFHOST_JOB_HOLD', 'transcribe')
+    sha = R.release('release/wave-61t'); rc, out = R.run('release/wave-61t', sha)
+    assert rc == 0, out
+    assert re.fullmatch(r'goodqa-transcode@sha256:[0-9a-f]{64}', R.jobs()['JOB_IMAGE_TRANSCODE']), R.jobs()
+    assert _guard_line(R) == ['GUARD_HELD_ENV: TRANSCODER_MODE=transcribe'], _guard_line(R)
+    assert 'guard probe: the built guard refuses' in out and 'guard startup log:' in out, out
+    rec = subprocess.run(['git', 'show', 'main:' + subprocess.run(['git', 'ls-tree', '-r', '--name-only', 'main', 'audit/selfhost-deploys'],
+                          cwd=R.origin, capture_output=True, text=True).stdout.split()[0]], cwd=R.origin, capture_output=True, text=True).stdout
+    assert '"transcribe(guard)"' in rec, rec
+
+
+def test_transcribe_hold_without_guard_support_holds_transcode(R):
+    """AC-17: the release's guard has no GUARD_HELD_ENV: the whole transcode image is held, its line emptied (MP4 waits),
+    so no transcription container can start in between."""
+    _guard_source(R, False); _conf(R, 'SELFHOST_JOB_HOLD', 'transcribe')
+    sha = R.release('release/wave-61n'); rc, out = R.run('release/wave-61n', sha)
+    assert rc == 0, out
+    assert R.jobs()['JOB_IMAGE_TRANSCODE'] == HELD, R.jobs()
+    assert 'guard lacks GUARD_HELD_ENV' in out and 'GUARDPROBE' in R.dlog(), out
+    loads = [l for l in R.dlog().split('\n') if 'LOAD' in l]
+    assert loads and not any('goodqa-transcode' in l for l in loads), loads
+    assert _guard_line(R) == []
+
+
+def test_transcribe_hold_string_present_behaviour_absent_holds_transcode(R):
+    """D1: the source names GUARD_HELD_ENV but the built guard starts anyway on a malformed value: hold all of transcode."""
+    _guard_source(R, False, text=True); _conf(R, 'SELFHOST_JOB_HOLD', 'transcribe')
+    sha = R.release('release/wave-61s'); rc, out = R.run('release/wave-61s', sha)
+    assert rc == 0, out
+    assert R.jobs()['JOB_IMAGE_TRANSCODE'] == HELD and 'guard lacks GUARD_HELD_ENV' in out, out
+    assert 'GUARDPROBE' in R.dlog() and _guard_line(R) == []
+
+
+def test_guard_not_reporting_hold_after_switch_rolls_back(R):
+    """D1: the running guard's startup line must name the hold; if it does not, the switch is rolled back."""
+    before = R.get('live'); _guard_source(R, True); _conf(R, 'SELFHOST_JOB_HOLD', 'transcribe'); R.put('guard-log-missing', '')
+    sha = R.release('release/wave-61g'); rc, out = R.run('release/wave-61g', sha)
+    assert rc == 5 and 'does not report the transcription hold' in out and 'ROLLED BACK' in out, out
+    assert R.pins() == BASE_PINS and R.jobs() == BASE_JOBS and R.get('live') == before
+
+
+def test_guard_hold_line_written_and_recorded(tmp_path):
+    """AC-16: ctl writes exactly one GUARD_HELD_ENV line in the create-guard block; state reports it; a pin without
+    --guard-hold removes it again (the hold is per release, never left behind silently)."""
+    ctl, snap, st, vm, env = ctl_fixture(tmp_path)
+    rc, o = ctl(*(list(PIN) + ['--guard-hold', 'TRANSCODER_MODE=transcribe']))
+    assert rc == 0 and J(o)['guard_hold'] == 'TRANSCODER_MODE=transcribe', o
+    t = open(vm / 'compose.yaml').read()
+    assert t.count('GUARD_HELD_ENV') == 1 and job_pins(t) == {'job-dispatcher-create-guard': NEW_JOBS}
+    args = list(PIN); args[args.index('S1')] = 'S2'
+    rc2, o2 = ctl(*args)
+    assert rc2 == 0 and J(o2)['guard_hold'] is None and 'GUARD_HELD_ENV' not in open(vm / 'compose.yaml').read(), o2
+
+
+@pytest.mark.parametrize('value', ['TRANSCODER_MODE=Transcribe', 'TRANSCODER_MODE=frames', 'OTHER=transcribe', 'TRANSCODER_MODE', 'twice'])
+def test_ctl_guard_hold_refusals(tmp_path, value):
+    """NEG-14: --guard-hold takes exactly one value, TRANSCODER_MODE=transcribe; anything else changes nothing."""
+    ctl, snap, st, vm, env = ctl_fixture(tmp_path); before = snap()
+    extra = ['--guard-hold', 'TRANSCODER_MODE=transcribe'] * 2 if value == 'twice' else ['--guard-hold', value]
+    rc, o = ctl(*(list(PIN) + extra))
+    assert rc == 3 and o.startswith('REFUSED'), o
+    assert snap() == before
+
+
+def test_held_line_marked_and_excluded_from_jobs_missing(tmp_path):
+    """B4: a held key's line carries `# held`; state lists it in jobs_held and never in jobs_missing."""
+    ctl, snap, st, vm, env = ctl_fixture(tmp_path)
+    rc, o = ctl(*(_swap(PIN, INTEL, None) + ['--job-hold', INTEL]))
+    assert rc == 0, o
+    assert '      %s: "" # held' % INTEL in open(vm / 'compose.yaml').read()
+    s = J(ctl('state')[1]); assert s['jobs_held'] == [INTEL] and s['jobs_missing'] == [], s
+
+
+# ---- goodqa#16136 review F1: one canonical SELFHOST_JOB_HOLD; an accepted value never releases a kind it names
+@pytest.mark.parametrize('value', ['intelligence-worker, transcribe', 'intelligence-worker transcribe', 'intelligence-worker\ttranscribe',
+                                   'transcribe,', ',transcribe', 'transcribe,,intelligence-worker', ' none', 'none ', 'transcribe ', ','],
+                         ids=['comma-space', 'space', 'tab', 'trailing-comma', 'leading-comma', 'empty-item', 'space-none', 'none-space',
+                              'trailing-space', 'only-comma'])
+def test_noncanonical_job_hold_refuses_before_building(R, value):
+    before = R.get('live'); _conf(R, 'SELFHOST_JOB_HOLD', value); sha = R.release('release/wave-60f')
+    rc, out = R.run('release/wave-60f', sha)
+    assert rc == 2 and 'SELFHOST_JOB_HOLD' in out and 'nothing built or switched' in out, out
+    assert 'BUILD' not in R.dlog() and 'GUARDPROBE' not in R.dlog(); unchanged(R, before)
+
+
+def test_canonical_job_hold_holds_every_named_kind(R):
+    _conf(R, 'SELFHOST_JOB_HOLD', 'transcribe,intelligence-worker'); sha = R.release('release/wave-60g')
+    rc, out = R.run('release/wave-60g', sha)
+    assert rc == 0, out
+    j = R.jobs(); assert j[INTEL] == HELD and j['JOB_IMAGE_TRANSCODE'] == HELD, j
+    assert 'BUILD goodqa-intelligence-worker' not in R.dlog() and 'GUARDPROBE' in R.dlog(), R.dlog()
+
+
+# ---- goodqa#16136 review F2: the VM disk gate measures the runtime's own data roots and fails closed
+def _vm_disk_refused(R, name, sha_note):
+    before = R.get('live'); _conf(R, 'SELFHOST_VM_MIN_FREE_GB', '1'); sha = R.release(name)
+    rc, out = R.run(name, sha)
+    assert rc == 11 and 'NO DISK on the VM' in out, out
+    assert 'LOAD' not in R.dlog(); unchanged(R, before)
+    return out
+
+
+def test_vm_disk_containerd_root_full_refuses_while_docker_root_has_room(R):
+    R.put('vmdf-containerd', '0')
+    out = _vm_disk_refused(R, 'release/wave-60d1', 'containerd full')
+    assert '"free_gb": 0' in out and 'containerd-root' in out, out
+
+
+def test_vm_disk_docker_root_full_refuses_while_containerd_root_has_room(R):
+    R.put('vmdf-docker', '0'); _vm_disk_refused(R, 'release/wave-60d2', 'docker full')
+
+
+@pytest.mark.parametrize('mark', ['containerd-fail', 'containerd-noroot'])
+def test_vm_disk_unresolved_containerd_root_refuses(R, mark):
+    R.put(mark, ''); out = _vm_disk_refused(R, 'release/wave-60d3', mark)
+    assert 'unresolved' in out, out
+
+
+def test_vm_disk_stat_failure_refuses(R):
+    R.put('vmdf-containerd', 'fail'); out = _vm_disk_refused(R, 'release/wave-60d4', 'stat fails')
+    assert 'unresolved' in out, out
+
+
+def test_vm_disk_needs_twice_the_incoming_image_bytes(R):
+    # 7 images of 8 GiB need 112 GiB; the fixture VM has 100 GiB free on both roots, above the 1 GiB floor
+    R.put('image-size', str(8 << 30)); out = _vm_disk_refused(R, 'release/wave-60d5', 'incoming bytes')
+    assert '112G needed' in out, out
+
+
+def test_vm_disk_unreadable_image_size_refuses(R):
+    R.put('size-unreadable', ''); out = _vm_disk_refused(R, 'release/wave-60d6', 'size unknown')
+    assert 'xG needed' in out, out
+
+
+def test_vm_disk_reports_both_roots(R):
+    _conf(R, 'SELFHOST_VM_MIN_FREE_GB', '1'); sha = R.release('release/wave-60d7'); rc, out = R.run('release/wave-60d7', sha)
+    assert rc == 0, out
+    line = next(l for l in out.split('\n') if 'VM image store:' in l)
+    assert '"free_gb": 100' in line and 'containerd-root' in line and '"paths"' in line, line
+
+
+# ---- goodqa#16136 AC-18: the id recheck skips transcode only when the whole-image hold removed it on purpose
+def test_id_recheck_refuses_missing_transcode_without_a_hold(R):
+    before = R.get('live'); R.put('inspect-once', 'goodqa-transcode:'); sha = R.release('release/wave-60r')
+    rc, out = R.run('release/wave-60r', sha)
+    assert rc == 3, out
+    assert 'BUILD goodqa-transcode' in R.dlog() and 'LOAD' not in R.dlog(); unchanged(R, before)
+
+
+def test_id_recheck_skips_transcode_removed_by_the_whole_image_hold(R):
+    _guard_source(R, False); _conf(R, 'SELFHOST_JOB_HOLD', 'transcribe'); R.put('inspect-once', 'goodqa-transcode:')
+    sha = R.release('release/wave-60s'); rc, out = R.run('release/wave-60s', sha)
+    assert rc == 0 and 'the whole transcode image is held' in out, out
+    assert R.jobs()['JOB_IMAGE_TRANSCODE'] == HELD, R.jobs()
+    assert 'goodqa-transcode' not in next(l for l in R.dlog().split('\n') if l.startswith('local LOAD') or ' LOAD ' in l), R.dlog()
+
+
+# ---- goodqa#16136: a hold blocks launches; it never relies on the old image being absent from the host
+def _old_images_present(R):
+    import hashlib
+    p = os.path.join(R.st, 'docker', 'images-remote.json'); imgs = json.load(open(p))
+    for k, ref in BASE_JOBS.items(): imgs[ref] = 'sha256:' + hashlib.sha256(ref.encode()).hexdigest()
+    json.dump(imgs, open(p, 'w'))
+
+
+def test_held_kind_never_starts_even_with_its_old_image_on_the_host(R):
+    """Both services get "" for every held kind (the dispatcher answers 501, the guard has no image for it); unheld
+    kinds get their new loaded refs."""
+    _old_images_present(R); _conf(R, 'SELFHOST_JOB_HOLD', None)
+    sha = R.release('release/wave-62h'); rc, out = R.run('release/wave-62h', sha)
+    assert rc == 0, out
+    pins = job_pins(open(os.path.join(R.vm, 'compose.yaml')).read())
+    for svc in ('job-dispatcher-create-guard', 'job-dispatcher'):
+        j = pins.get(svc) or pins['job-dispatcher-create-guard']
+        assert j[INTEL] == HELD and j['JOB_IMAGE_TRANSCODE'] == HELD, (svc, j)
+        for k in ('JOB_IMAGE_SCAN', 'JOB_IMAGE_SUGGEST_FIX_WORKER'):
+            assert re.fullmatch(r'goodqa-[a-z-]+@sha256:[0-9a-f]{64}', j[k]), (svc, k, j)
+    assert ('      %s: "" # held' % INTEL) in open(os.path.join(R.vm, 'compose.yaml')).read()
+
+
+def test_unholding_restores_a_real_pin(R):
+    _conf(R, 'SELFHOST_JOB_HOLD', 'intelligence-worker'); sha = R.release('release/wave-62u'); rc, out = R.run('release/wave-62u', sha)
+    assert rc == 0 and R.jobs()[INTEL] == HELD, (out, R.jobs())
+    _conf(R, 'SELFHOST_JOB_HOLD', 'none'); sha2 = R.release('release/wave-62v'); rc2, out2 = R.run('release/wave-62v', sha2)
+    assert rc2 == 0, out2
+    assert re.fullmatch(r'goodqa-intelligence-worker@sha256:[0-9a-f]{64}', R.jobs()[INTEL]), R.jobs()
+    line = next(l for l in open(os.path.join(R.vm, 'compose.yaml')).read().split('\n') if INTEL + ':' in l)
+    assert '# held' not in line, line
+
+
+def test_held_value_never_reaches_docker(R):
+    _old_images_present(R); _conf(R, 'SELFHOST_JOB_HOLD', None)
+    sha = R.release('release/wave-62d'); rc, out = R.run('release/wave-62d', sha)
+    assert rc == 0, out
+    log = R.dlog().split('\n')
+    inspects = [l for l in log if ' INSPECT ' in ' ' + l]
+    assert inspects, 'the fixture must log image inspects'
+    for l in inspects:   # the held value is never an image argument
+        assert ", '']" not in l and "'\"\"'" not in l, l
+    # before the switch the run reads the live stack (old refs included); once the new stack is up, a held kind's old
+    # ref is never looked up again (it is no longer in compose)
+    up = next(i for i, l in enumerate(log) if l.startswith('remote UP') and sha in l)
+    assert any(' INSPECT ' in ' ' + l for l in log[up:]), 'the post-switch checks must inspect something'
+    for l in log[up:]:
+        assert BASE_JOBS[INTEL] not in l and BASE_JOBS['JOB_IMAGE_TRANSCODE'] not in l, l
+
+
+def test_real_compose_held_kind_is_empty_for_both_services(tmp_path):
+    """The real `docker compose config`: a held key resolves to "" on both the guard and the dispatcher."""
+    import importlib.util
+    spec = importlib.util.spec_from_file_location('shctl', CTL); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
+    src = os.path.join(HERE, '..', 'selfhost', 'app', 'compose.yaml')
+    text = open(src).read()
+    for envf in sorted(set(re.findall(r'path:[ \t]*(\S+\.env)', text)) | set(re.findall(r'env_file:[ \t]*(\S+\.env)', text))):
+        fake = tmp_path / os.path.basename(envf); fake.write_text('X=1\n'); text = text.replace(envf, str(fake))
+    stk = m.Stack(str(tmp_path), str(tmp_path), 'rwtest')
+    new = {k: 'goodqa-%s@sha256:%s' % (j, JID[j]) for k, (j, _) in JOBS.items() if k != INTEL}
+    (tmp_path / 'compose.yaml').write_text(stk.rejob(text, new, held=[INTEL]))
+    r = subprocess.run(['docker', 'compose', '-p', 'rwtest', '-f', str(tmp_path / 'compose.yaml'), 'config', '--format', 'json'],
+                       capture_output=True, text=True, cwd=str(tmp_path),
+                       env=dict(os.environ, **{v: 'rwtest.invalid' for v in re.findall(r'\$\{([A-Z0-9_]+):?\?', text)}))
+    assert r.returncode == 0, r.stderr[-800:]
+    svcs = json.loads(r.stdout)['services']
+    for s in ('job-dispatcher-create-guard', 'job-dispatcher'):
+        got = {k: v for k, v in (svcs[s].get('environment') or {}).items() if k.startswith('JOB_IMAGE_')}
+        assert got == dict(new, **{INTEL: ''}), (s, got)
+
+
+# ---- goodqa#16136 E4: "" is a held value only with the # held marker and only on a holdable key
+def _ctl_mod():
+    import importlib.util
+    spec = importlib.util.spec_from_file_location('shctl_e4', CTL); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
+    return m
+
+
+def _real_compose_with(m, edits):
+    text = open(os.path.join(HERE, '..', 'selfhost', 'app', 'compose.yaml')).read()
+    lines, res = m.Stack.job_lines(text)
+    for k, line in edits.items(): lines[res[k]] = '      %s: %s' % (k, line)
+    return '\n'.join(lines)
+
+
+@pytest.mark.parametrize('key,line,err', [
+    ('JOB_IMAGE_INTELLIGENCE_WORKER', '""', 'empty without the # held marker'),
+    ('JOB_IMAGE_TRANSCODE', "''", 'empty without the # held marker'),
+    ('JOB_IMAGE_SCAN', '"" # held', 'JOB_IMAGE_SCAN cannot be held'),
+    ('JOB_IMAGE_SUGGEST_FIX_WORKER', '"" # held', 'JOB_IMAGE_SUGGEST_FIX_WORKER cannot be held'),
+    ('JOB_IMAGE_SCAN', '""', 'JOB_IMAGE_SCAN cannot be held'),
+    ('JOB_IMAGE_INTELLIGENCE_WORKER', 'goodqa-intelligence-worker@sha256:' + 'a' * 64 + ' # held', 'marked # held but its value is not ""'),
+])
+def test_empty_job_value_needs_marker_and_holdable_key(key, line, err):
+    m = _ctl_mod()
+    with pytest.raises(m.Refused) as e:
+        m.Stack.job_lines(_real_compose_with(m, {key: line}))
+    assert err in str(e.value), str(e.value)
+
+
+def test_held_empty_lines_on_holdable_keys_are_accepted():
+    m = _ctl_mod()
+    text = _real_compose_with(m, {'JOB_IMAGE_INTELLIGENCE_WORKER': '"" # held', 'JOB_IMAGE_TRANSCODE': '"" # held'})
+    stk = m.Stack('/nonexistent', '/nonexistent', 'rwtest')
+    assert stk.held_keys(text) == ['JOB_IMAGE_INTELLIGENCE_WORKER', 'JOB_IMAGE_TRANSCODE']
+    assert stk.jobs(text)['JOB_IMAGE_TRANSCODE'] == '""'
+
+
+@pytest.mark.parametrize('key', ['JOB_IMAGE_SCAN', 'JOB_IMAGE_SUGGEST_FIX_WORKER'])
+def test_job_hold_refuses_a_non_holdable_kind(key):
+    m = _ctl_mod()
+    imgs = ['%s=%s@sha256:%s' % (k, j, 'b' * 64) for k, j in m.JOB_KEYS.items() if k != key]
+    with pytest.raises(m.Refused) as e:
+        m.parse_job_args(imgs, [key])
+    assert 'that kind cannot be held' in str(e.value), str(e.value)
+
+
+# ---- goodqa#16136 G3: a job line is a digest-pinned ref or "" # held, nothing else (NEG-16)
+@pytest.mark.parametrize('line', ['', '~', 'null', '${X:-}', '"${JOB_IMAGE_TRANSCODE_REF}"', 'goodqa-transcode:latest',
+                                  '"goodqa-transcode@sha256:' + 'a' * 64 + "'"])
+def test_job_line_value_must_be_a_pin_or_held(line):
+    m = _ctl_mod()
+    with pytest.raises(m.Refused) as e:
+        m.Stack.job_lines(_real_compose_with(m, {'JOB_IMAGE_TRANSCODE': line}))
+    assert 'must be a digest-pinned image ref or "" # held' in str(e.value), str(e.value)
+
+
+@pytest.mark.parametrize('line', ['goodqa-transcode@sha256:' + 'c' * 64, '"goodqa-transcode@sha256:' + 'c' * 64 + '"',
+                                  "'registry.digitalocean.com/goodqa-prod/bugtracker-transcode@sha256:" + 'c' * 64 + "'"])
+def test_job_line_accepts_plain_or_quoted_pins(line):
+    m = _ctl_mod()
+    lines, res = m.Stack.job_lines(_real_compose_with(m, {'JOB_IMAGE_TRANSCODE': line}))
+    assert 'JOB_IMAGE_TRANSCODE' in res
+
### SECTION B: 1373 content, c9d61ac1..5dd6865c (1373 base .. 1373 head, incl. the 1372 docker.ts fix 80b26c7e)
diff --git a/apps/job-dispatcher/src/config.ts b/apps/job-dispatcher/src/config.ts
index e5e0da9948f..dbe98b0b0af 100644
--- a/apps/job-dispatcher/src/config.ts
+++ b/apps/job-dispatcher/src/config.ts
@@ -1,3 +1,4 @@
+import { JOB_ENVFILE_DIR, parseJobEnvFiles, type JobEnvFiles } from './job-env-file';
 import { z } from 'zod';
 import { JOB_KINDS, type JobKind } from './jobs';
 
@@ -61,6 +62,10 @@ const envSchema = z.object({
 export type Config = z.infer<typeof envSchema> & {
   jobImages: Record<JobKind, string>;
   jobBaseEnv: Record<JobKind, Record<string, string>>;
+  /** goodqa#16148 AC-4: allow-listed JOB_ENVFILE_KIND__VAR keys (paths only; files are read per launch). */
+  jobEnvFiles: JobEnvFiles;
+  /** The only directory a JOB_ENVFILE path may live in. Compiled, never read from the env. */
+  jobEnvFileDir: string;
 };
 
 type JobImageEnvKey =
@@ -132,5 +137,5 @@ export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
       );
     }
   }
-  return { ...parsed, jobImages, jobBaseEnv };
+  return { ...parsed, jobImages, jobBaseEnv, jobEnvFiles: parseJobEnvFiles(env), jobEnvFileDir: JOB_ENVFILE_DIR };
 }
diff --git a/apps/job-dispatcher/src/docker.ts b/apps/job-dispatcher/src/docker.ts
index 5a1feab52ab..80a553e0d66 100644
--- a/apps/job-dispatcher/src/docker.ts
+++ b/apps/job-dispatcher/src/docker.ts
@@ -12,6 +12,9 @@
  * a shell unless `shell: true` is passed — it is not passed here).
  */
 import { execFile, type ExecFileException } from 'node:child_process';
+import { chmodSync, closeSync, constants as fsConstants, fchmodSync, lstatSync, mkdtempSync, openSync, readdirSync, rmSync, unlinkSync, writeSync } from 'node:fs';
+import { tmpdir } from 'node:os';
+import { join } from 'node:path';
 
 interface ExecFileResult {
   stdout: string;
@@ -249,6 +252,11 @@ function valueForms(value: string): string[] {
   ];
 }
 
+/** The residue rule is in UTF-8 bytes (receipt pr1372-v1): a value of 6 CJK characters is 18 bytes, not 6. */
+function byteLength(value: string): number {
+  return Buffer.byteLength(value, 'utf8');
+}
+
 function escapeRegExp(s: string): string {
   return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
 }
@@ -260,7 +268,7 @@ function hasResidue(rawLine: string, values: readonly string[]): boolean {
 
 function hasResidueIn(line: string, values: readonly string[]): boolean {
   for (const value of values) {
-    if (value.length < MIN_WINDOW) {
+    if (byteLength(value) < MIN_WINDOW) {
       if (new RegExp(`(^|[^A-Za-z0-9])${escapeRegExp(value)}($|[^A-Za-z0-9])`).test(line)) return true;
       continue;
     }
@@ -290,7 +298,7 @@ export function describeDockerFailure(stderr: string, secretValues: readonly str
 
   const values = [...new Set(secretValues.filter((v) => v.length > 0))];
   let redacted = stderr;
-  for (const value of [...values].filter((v) => v.length >= MIN_WINDOW).sort((a, b) => b.length - a.length)) {
+  for (const value of [...values].filter((v) => byteLength(v) >= MIN_WINDOW).sort((a, b) => byteLength(b) - byteLength(a))) {
     redacted = redacted.split(value).join('[redacted]');
   }
   const line = (redacted.split('\n', 1)[0] ?? '').replace(/\r$/, '').trimEnd().slice(0, SCAN_LIMIT);
@@ -301,6 +309,80 @@ export function describeDockerFailure(stderr: string, secretValues: readonly str
   return `${head}: ${cut}`;
 }
 
+/**
+ * goodqa#16148 spec v4 AC-6: job env goes to docker through `--env-file`, never `-e KEY=VALUE`.
+ * A docker CLI process's argv is world-readable in the host PID namespace (/proc/PID/cmdline).
+ *
+ * Each launch gets a fresh mkdtemp directory (0700) under the dispatcher's tmpfs /tmp, holding
+ * one file (O_CREAT|O_EXCL|O_NOFOLLOW, 0600) with one `KEY=VALUE` line per variable. A line
+ * without `=` is never written (docker would fill it from the CLI's own environment). The
+ * directory is removed in a finally on every path. docker reads the value verbatim after the
+ * first `=` (probed on t2-dev: spaces, quotes, `#`, `=` and an empty value round-trip), but a
+ * line cannot carry CR, LF or NUL, so those are refused, with a named error that never holds the
+ * value. Boot removes any leftover directory (sweepStaleEnvFileDirs).
+ */
+export const ENVFILE_DIR_PREFIX = 'goodqa-envfile-';
+export const ENV_KEY_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*$/;
+
+/** A job env that cannot be written to an env-file. Never carries a value. */
+export class JobEnvError extends Error {
+  constructor(message: string) {
+    super(message);
+    this.name = 'JobEnvError';
+  }
+}
+
+function describeKey(key: string): string {
+  return /^[\x21-\x7e]{1,128}$/.test(key) && !key.includes('=') ? key : `(a key of ${key.length} chars)`;
+}
+
+/** Why this env entry cannot be written, naming the key only; null when it can. */
+export function envEntryProblem(key: string, value: string): string | null {
+  if (!ENV_KEY_PATTERN.test(key)) return `env key ${describeKey(key)} is not a valid name`;
+  if (/[\r\n\0]/.test(value)) return `env ${key}: value holds CR, LF or NUL`;
+  if (Buffer.from(value, 'utf8').toString('utf8') !== value) return `env ${key}: value is not valid UTF-8`;
+  return null;
+}
+
+function writeLaunchEnvFile(env: Record<string, string>): { dir: string; file: string } | null {
+  const entries = Object.entries(env);
+  for (const [key, value] of entries) {
+    const problem = envEntryProblem(key, value);
+    if (problem) throw new JobEnvError(`job ${problem}`);
+  }
+  if (entries.length === 0) return null;
+  const dir = mkdtempSync(join(tmpdir(), ENVFILE_DIR_PREFIX));
+  try {
+    chmodSync(dir, 0o700);
+    const file = join(dir, 'env');
+    const fd = openSync(file, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW, 0o600);
+    try {
+      fchmodSync(fd, 0o600);
+      writeSync(fd, Buffer.from(entries.map(([k, v]) => `${k}=${v}\n`).join(''), 'utf8'));
+    } finally {
+      closeSync(fd);
+    }
+    return { dir, file };
+  } catch (error) {
+    rmSync(dir, { recursive: true, force: true });
+    throw error;
+  }
+}
+
+/** Boot: remove leftover per-launch env-file directories (and unlink, never follow, a symlink). */
+export function sweepStaleEnvFileDirs(root: string = tmpdir()): number {
+  let removed = 0;
+  for (const name of readdirSync(root)) {
+    if (!name.startsWith(ENVFILE_DIR_PREFIX)) continue;
+    const path = join(root, name);
+    const st = lstatSync(path);
+    if (st.isSymbolicLink() || !st.isDirectory()) unlinkSync(path);
+    else rmSync(path, { recursive: true, force: true });
+    removed += 1;
+  }
+  return removed;
+}
+
 /**
  * `secretValues`: the values from a secret source (the dispatcher's base env for the kind) that a
  * failure message must never carry (goodqa#16185). Omitted, every env value is treated as secret.
@@ -332,12 +414,13 @@ export async function dockerRunDetached(
   if (security.pidsLimit) {
     execArgs.push(`--pids-limit=${security.pidsLimit}`);
   }
-  for (const [key, value] of Object.entries(env)) {
-    execArgs.push('-e', `${key}=${value}`);
-  }
+  // goodqa#16148 AC-6: validated and written before docker is touched; removed in the finally.
+  const envFile = writeLaunchEnvFile(env);
+  if (envFile) execArgs.push('--env-file', envFile.file);
   execArgs.push(image, ...args);
 
   let stdout: string;
+  try {
   try {
     const result = await execFileAsync(dockerBin, execArgs, { timeout: timeoutMs, maxBuffer: 1024 * 1024 });
     stdout = result.stdout;
@@ -359,6 +442,9 @@ export async function dockerRunDetached(
     const stderr = typeof err.stderr === 'string' ? err.stderr : '';
     throw new DockerLaunchError('synchronous_failure', describeDockerFailure(stderr, secretValues));
   }
+  } finally {
+    if (envFile) rmSync(envFile.dir, { recursive: true, force: true });
+  }
 
   const containerId = stdout.trim();
   if (!containerId) {
diff --git a/apps/job-dispatcher/src/index.ts b/apps/job-dispatcher/src/index.ts
index 34a28a5ce0f..262038cc3c4 100644
--- a/apps/job-dispatcher/src/index.ts
+++ b/apps/job-dispatcher/src/index.ts
@@ -1,11 +1,19 @@
 import { loadConfig } from './config';
 import { configureExecutionStore, reconcileExecutions } from './executions';
+import { sweepStaleEnvFileDirs } from './docker';
+import { bootEnvFileStatusLines } from './job-env-file';
 import { buildServer, realDockerDeps } from './server';
 
 const config = loadConfig();
 const app = buildServer(config);
 
 async function main(): Promise<void> {
+  // goodqa#16148 AC-6: a crash between writing a launch env-file and its finally leaves a
+  // directory on the tmpfs; remove any before serving.
+  app.log.info({ removed: sweepStaleEnvFileDirs() }, 'job-dispatcher: swept stale env-file dirs');
+  // goodqa#16148 AC-5: one status line per JOB_ENVFILE key (names and status only); rw-ship's
+  // unhold gate reads `job env file KIND__VAR: ok` from this container's log. Never fails boot.
+  for (const line of bootEnvFileStatusLines(config)) app.log.info(line);
   // D3: reload the persisted registry and reconcile it against the daemon
   // BEFORE accepting requests, so admission control starts from the real
   // number of live job containers, not 0.
diff --git a/apps/job-dispatcher/src/job-env-file.ts b/apps/job-dispatcher/src/job-env-file.ts
new file mode 100644
index 00000000000..e1a94dcfbbc
--- /dev/null
+++ b/apps/job-dispatcher/src/job-env-file.ts
@@ -0,0 +1,144 @@
+/**
+ * goodqa#16148 spec v4 AC-4, AC-5, AC-9: file-backed job env.
+ *
+ * `JOB_ENVFILE_<KIND>__<VAR>=<PATH>` in the dispatcher's own env makes <VAR> part of that kind's
+ * job env, read from <PATH> at every launch (so a rotated file is picked up without a restart).
+ * Only keys in the compiled allow-list are honoured; any other JOB_ENVFILE_ key is ignored and
+ * named at boot. The prefix differs from `JOB_ENV_I...` at its eighth character, so an older
+ * dispatcher (which matches only `JOB_ENV_<KIND>__`) ignores these keys entirely.
+ *
+ * The read never resolves the path twice and never follows a link: PATH must be absolute, hold no
+ * `..` segment, and have exactly the secrets directory as its parent; it is opened
+ * O_RDONLY|O_NOFOLLOW|O_NONBLOCK (a FIFO cannot block the launch), fstat on the same fd must show
+ * a regular file, and at most 64 KiB + 1 byte is read from that fd. One trailing LF is removed.
+ * Every failure is a fixed phrase that names the key and never holds the value.
+ */
+import { closeSync, constants as fsConstants, fstatSync, openSync, readSync } from 'node:fs';
+import { dirname, isAbsolute } from 'node:path';
+import type { JobKind } from './jobs';
+import { JOB_KINDS } from './jobs';
+
+export const JOB_ENVFILE_PREFIX = 'JOB_ENVFILE_';
+export const JOB_ENVFILE_ALLOWLIST: ReadonlySet<string> = new Set(['INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY']);
+/** The only directory a JOB_ENVFILE path may live in: the job-dispatcher's read-only secrets mount. */
+export const JOB_ENVFILE_DIR = '/run/goodqa-secrets';
+export const JOB_ENVFILE_MAX_BYTES = 64 * 1024;
+
+export interface JobEnvFileEntry {
+  /** `INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY` */
+  id: string;
+  kind: JobKind;
+  varName: string;
+  path: string;
+}
+
+export interface JobEnvFiles {
+  entries: JobEnvFileEntry[];
+  ignored: string[];
+}
+
+function envPrefixForKind(kind: JobKind): string {
+  return kind.toUpperCase().replace(/-/g, '_');
+}
+
+export function parseJobEnvFiles(env: NodeJS.ProcessEnv): JobEnvFiles {
+  const entries: JobEnvFileEntry[] = [];
+  const ignored: string[] = [];
+  for (const [key, value] of Object.entries(env)) {
+    if (value === undefined || !key.startsWith(JOB_ENVFILE_PREFIX)) continue;
+    const id = key.slice(JOB_ENVFILE_PREFIX.length);
+    const kind = JOB_KINDS.find((k) => id.startsWith(`${envPrefixForKind(k)}__`));
+    if (!kind || !JOB_ENVFILE_ALLOWLIST.has(id)) {
+      ignored.push(key);
+      continue;
+    }
+    entries.push({ id, kind, varName: id.slice(envPrefixForKind(kind).length + 2), path: value });
+  }
+  ignored.sort();
+  return { entries, ignored };
+}
+
+export type JobEnvFileRead = { ok: true; value: string } | { ok: false; reason: string };
+
+export function readJobEnvFile(path: string, allowedDir: string): JobEnvFileRead {
+  if (!isAbsolute(path) || path.split('/').includes('..') || dirname(path) !== allowedDir) {
+    return { ok: false, reason: 'path outside the secrets directory' };
+  }
+  let fd: number;
+  try {
+    fd = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK);
+  } catch (error) {
+    const code = (error as NodeJS.ErrnoException).code;
+    if (code === 'ENOENT') return { ok: false, reason: 'missing' };
+    if (code === 'ELOOP') return { ok: false, reason: 'is a symlink' };
+    if (code === 'EACCES' || code === 'EPERM') return { ok: false, reason: 'unreadable' };
+    return { ok: false, reason: `cannot open (${code ?? 'error'})` };
+  }
+  try {
+    if (!fstatSync(fd).isFile()) return { ok: false, reason: 'not a regular file' };
+    const buf = Buffer.alloc(JOB_ENVFILE_MAX_BYTES + 1);
+    let total = 0;
+    for (;;) {
+      let n: number;
+      try {
+        n = readSync(fd, buf, total, buf.length - total, null);
+      } catch (error) {
+        const code = (error as NodeJS.ErrnoException).code;
+        if (code === 'EACCES' || code === 'EPERM') return { ok: false, reason: 'unreadable' };
+        return { ok: false, reason: `cannot read (${code ?? 'error'})` };
+      }
+      if (n === 0) break;
+      total += n;
+      if (total > JOB_ENVFILE_MAX_BYTES) return { ok: false, reason: 'over 64 KiB' };
+    }
+    let bytes = buf.subarray(0, total);
+    if (bytes.length > 0 && bytes[bytes.length - 1] === 0x0a) bytes = bytes.subarray(0, bytes.length - 1);
+    if (bytes.length === 0) return { ok: false, reason: 'empty' };
+    if (bytes.includes(0x0d) || bytes.includes(0x0a) || bytes.includes(0x00)) return { ok: false, reason: 'value holds CR, LF or NUL' };
+    const value = bytes.toString('utf8');
+    if (!Buffer.from(value, 'utf8').equals(bytes)) return { ok: false, reason: 'value is not valid UTF-8' };
+    return { ok: true, value };
+  } finally {
+    closeSync(fd);
+  }
+}
+
+export function envFileError(entry: Pick<JobEnvFileEntry, 'id'>, reason: string): string {
+  return `job env file for ${entry.id}: ${reason}`;
+}
+
+/** Resolve a kind's file-backed env for one launch, or the first named error. */
+export function resolveJobEnvFiles(
+  files: JobEnvFiles,
+  allowedDir: string,
+  kind: JobKind,
+  baseEnv: Record<string, string>,
+): { ok: true; env: Record<string, string> } | { ok: false; error: string } {
+  const env: Record<string, string> = {};
+  for (const entry of files.entries) {
+    if (entry.kind !== kind) continue;
+    if (Object.prototype.hasOwnProperty.call(baseEnv, entry.varName)) {
+      return { ok: false, error: envFileError(entry, 'both JOB_ENV_ and JOB_ENVFILE_ are set') };
+    }
+    const read = readJobEnvFile(entry.path, allowedDir);
+    if (!read.ok) return { ok: false, error: envFileError(entry, read.reason) };
+    env[entry.varName] = read.value;
+  }
+  return { ok: true, env };
+}
+
+/** Boot: one status line per JOB_ENVFILE key (rw-ship's unhold gate reads `: ok`). Never throws. */
+export function bootEnvFileStatusLines(config: { jobEnvFiles: JobEnvFiles; jobEnvFileDir: string }): string[] {
+  const lines: string[] = [];
+  for (const entry of config.jobEnvFiles.entries) {
+    let read: JobEnvFileRead;
+    try {
+      read = readJobEnvFile(entry.path, config.jobEnvFileDir);
+    } catch {
+      read = { ok: false, reason: 'cannot read (error)' };
+    }
+    lines.push(read.ok ? `job env file ${entry.id}: ok` : envFileError(entry, read.reason));
+  }
+  for (const key of config.jobEnvFiles.ignored) lines.push(`job env file key ignored (not allow-listed): ${key}`);
+  return lines;
+}
diff --git a/apps/job-dispatcher/src/server.ts b/apps/job-dispatcher/src/server.ts
index 01c48106344..9b97563af0b 100644
--- a/apps/job-dispatcher/src/server.ts
+++ b/apps/job-dispatcher/src/server.ts
@@ -30,6 +30,7 @@
  * is a new service free to use the more standard form; same "one shared
  * secret in an env var, checked at the door" convention either way.
  */
+import { resolveJobEnvFiles } from './job-env-file';
 import { timingSafeEqual } from 'node:crypto';
 import Fastify, { type FastifyInstance } from 'fastify';
 import type { Config } from './config';
@@ -37,6 +38,8 @@ import {
   dockerRunDetached,
   inspectContainer,
   DockerLaunchError,
+  JobEnvError,
+  envEntryProblem,
   type ContainerInspection,
   type ContainerSecurityProfile,
   type DockerRunResult,
@@ -152,7 +155,28 @@ export function buildServer(config: Config, deps: DockerDeps = realDockerDeps, o
     if (refused.length > 0) {
       return reply.code(400).send({ error: `env not settable by a caller for ${kind}: ${refused.join(', ')}` });
     }
-    const mergedEnv = { ...config.jobBaseEnv[kind], ...validation.env };
+    // goodqa#16148 AC-6 / NEG-8: an env-file line cannot carry CR, LF or NUL. A request value is
+    // the caller's fault (400); a base value is a dispatcher misconfiguration (501). Key names only.
+    for (const [key, value] of Object.entries(validation.env)) {
+      const problem = envEntryProblem(key, value);
+      if (problem) return reply.code(400).send({ error: `request ${problem}` });
+    }
+    // goodqa#16148 AC-4/AC-5: file-backed env, read now (per launch); a failure is per kind and
+    // definitive (501, docker never called), logged with the key name and reason only.
+    const fileEnv = resolveJobEnvFiles(config.jobEnvFiles, config.jobEnvFileDir, kind, config.jobBaseEnv[kind]);
+    if (!fileEnv.ok) {
+      req.log.error({ jobKind: kind }, fileEnv.error);
+      return reply.code(501).send({ error: fileEnv.error });
+    }
+    const baseEnv = { ...config.jobBaseEnv[kind], ...fileEnv.env };
+    for (const [key, value] of Object.entries(baseEnv)) {
+      const problem = envEntryProblem(key, value);
+      if (problem) {
+        req.log.error({ jobKind: kind }, `job-dispatcher: base ${problem}`);
+        return reply.code(501).send({ error: `job base ${problem}` });
+      }
+    }
+    const mergedEnv = { ...baseEnv, ...validation.env };
 
     try {
       const result = await deps.run(
@@ -166,7 +190,7 @@ export function buildServer(config: Config, deps: DockerDeps = realDockerDeps, o
         JOB_SECURITY_PROFILE[kind],
         // goodqa#16185 / #16148 P1: only the base env is a secret source; the caller's allow-listed
         // request env is not redacted from a failure message.
-        Object.values(config.jobBaseEnv[kind]),
+        Object.values(baseEnv),
       );
       const execution = recordExecution(kind, result.containerId, result.startedAt);
       return reply.code(200).send({
@@ -175,6 +199,9 @@ export function buildServer(config: Config, deps: DockerDeps = realDockerDeps, o
         startedAt: result.startedAt,
       });
     } catch (error) {
+      if (error instanceof JobEnvError) {
+        return reply.code(501).send({ error: error.message });
+      }
       if (error instanceof DockerLaunchError) {
         if (error.reason === 'synchronous_failure') {
           return reply.code(422).send({ error: error.message, started: false });
diff --git a/apps/job-dispatcher/test/docker-failure-message.test.ts b/apps/job-dispatcher/test/docker-failure-message.test.ts
index d7794682b50..59e82d7d95e 100644
--- a/apps/job-dispatcher/test/docker-failure-message.test.ts
+++ b/apps/job-dispatcher/test/docker-failure-message.test.ts
@@ -319,3 +319,65 @@ describe('F4 (code review goodqa#16148): a huge first line is cut before the res
     expect(msg).toContain('[redacted]');
   }, 30_000);
 });
+
+describe('receipt pr1372-v1 BLOCK: the 8-byte residue rule counts UTF-8 bytes, not UTF-16 code units', () => {
+  // Fake secrets only: short in code units, at least 8 bytes in UTF-8.
+  const CJK = '秘密鍵値六字'; // 6 code units, 18 bytes
+  const LATIN = 'éèêë'; // 4 code units, 8 bytes
+  const prefix = 'docker: Error response from daemon: job-dispatcher-create-guard: refused (';
+  const forms: Array<[string, (v: string) => string]> = [
+    ['base64', (v) => b64(v)],
+    ['base64, other alignment', (v) => b64(`x${v}`)],
+    ['hex', (v) => Buffer.from(v, 'utf8').toString('hex')],
+    ['HEX', (v) => Buffer.from(v, 'utf8').toString('hex').toUpperCase()],
+    ['decimal bytes', (v) => [...Buffer.from(v, 'utf8')].join(' ')],
+  ];
+  const cases = [CJK, LATIN].flatMap((v) => forms.map(([n, f]) => [`${v.length} units / ${Buffer.byteLength(v)} bytes, ${n}`, v, f(v)] as const));
+
+  it.each(cases)('%s: only the category and the byte count come out', (_name, value, echo) => {
+    const stderr = `${prefix}got ${echo})\n`;
+    expect(value.length).toBeLessThan(8);
+    expect(Buffer.byteLength(value, 'utf8')).toBeGreaterThanOrEqual(8);
+    expect(describeDockerFailure(stderr, [value])).toBe(
+      `docker run failed: guard_refused (stderr ${Buffer.byteLength(stderr, 'utf8')} bytes)`,
+    );
+  });
+
+  it('a value under 8 bytes keeps the exact-token rule (short base values never shred a line)', () => {
+    const msg = describeDockerFailure(`${prefix}Image must be one of the 1 pre-approved job images, got "abc")\n`, ['éé']);
+    expect(msg).toContain('got "abc")');
+  });
+
+  it('server: the 422 body for an encoded echo of a short-in-units secret is the category and byte count only', async () => {
+    clearExecutionsForTesting();
+    const TOKEN = 'shim-token-not-real';
+    const logs: string[] = [];
+    const app = buildServer({
+      ...loadConfig({
+        JOB_DISPATCH_TOKEN: TOKEN,
+        JOB_IMAGE_SCAN: 'ar/scan:tag',
+        JOB_IMAGE_TRANSCODE: 'ar/transcode:tag',
+        JOB_IMAGE_INTELLIGENCE_WORKER: 'ar/iw:tag',
+        JOB_IMAGE_SUGGEST_FIX_WORKER: 'ar/sf:tag',
+      }),
+      jobBaseEnv: { scan: {}, transcode: { GCS_BUCKET: CJK }, 'intelligence-worker': {}, 'suggest-fix-worker': {} },
+    }, { run: dockerRunDetached, inspect: vi.fn() } as never, { logStream: { write: (line: string) => logs.push(line) } });
+    app.addHook('onSend', async (_req, _reply, payload) => {
+      logs.push(String(payload));
+      return payload;
+    });
+    for (const [, f] of forms) {
+      const stderr = `${prefix}got ${f(CJK)})\n`;
+      respondFailure(stderr);
+      const res = await app.inject({ method: 'POST', url: '/jobs/transcode/run', headers: { authorization: `Bearer ${TOKEN}` }, payload: {} });
+      expect(res.statusCode).toBe(422);
+      expect((res.json() as { error: string }).error).toBe(
+        `docker run failed: guard_refused (stderr ${Buffer.byteLength(stderr, 'utf8')} bytes)`,
+      );
+      for (const [, g] of forms) {
+        expect(res.body).not.toContain(g(CJK).slice(0, 12));
+        for (const l of logs) expect(l).not.toContain(g(CJK).slice(0, 12));
+      }
+    }
+  });
+});
diff --git a/apps/job-dispatcher/test/docker.test.ts b/apps/job-dispatcher/test/docker.test.ts
index c183fec0b7b..5494163c9f3 100644
--- a/apps/job-dispatcher/test/docker.test.ts
+++ b/apps/job-dispatcher/test/docker.test.ts
@@ -49,15 +49,17 @@ describe('dockerRunDetached', () => {
     expect(file).toBe('docker');
     // Every element is its own argv entry -- confirms no shell-string
     // concatenation is possible for injection regardless of value content.
+    // goodqa#16148 AC-6: the env goes through a private --env-file, never `-e KEY=VALUE`.
     expect(args).toEqual([
       'run',
       '--rm',
       '-d',
-      '-e',
-      'SCAN_CLONE_TOKEN=ghs_fake',
+      '--env-file',
+      expect.stringMatching(/goodqa-envfile-[^/]+\/env$/),
       'registry.example/bugtracker/scan:tag',
       'scan-id-1',
     ]);
+    expect(args.join(' ')).not.toContain('ghs_fake');
     expect((options as { timeout: number }).timeout).toBe(5000);
   });
 
@@ -72,11 +74,10 @@ describe('dockerRunDetached', () => {
       NO_HARDENING,
     );
     const [, args] = execFileMock.mock.calls[0]!;
-    expect(args).toContain('-e');
-    // The dangerous value is the ENTIRE next argv element, not split by the
-    // shell metacharacters it contains -- there is no shell to split it.
-    expect(args).toContain('PAYLOAD=$(rm -rf /); echo pwned `whoami`');
-    expect(args).toHaveLength(6); // run, --rm, -d, -e, KEY=VALUE, image -- one element each
+    // goodqa#16148 AC-6: the value never reaches argv at all; it rides in the env-file.
+    expect(args).not.toContain('-e');
+    expect((args as string[]).join(' ')).not.toContain('whoami');
+    expect(args).toHaveLength(6); // run, --rm, -d, --env-file, PATH, image -- one element each
   });
 
   it('classifies a synchronous docker failure (bad image) as synchronous_failure — proven not started', async () => {
@@ -137,8 +138,8 @@ describe('AUD-032: dockerRunDetached security profile flags', () => {
       '--read-only',
       '--tmpfs',
       '/tmp:rw,noexec,nosuid,size=1024m',
-      '-e',
-      'K=V',
+      '--env-file',
+      expect.stringMatching(/goodqa-envfile-[^/]+\/env$/),
       'image:tag',
       'arg1',
     ]);
diff --git a/apps/job-dispatcher/test/env-file.test.ts b/apps/job-dispatcher/test/env-file.test.ts
new file mode 100644
index 00000000000..eed31c7487a
--- /dev/null
+++ b/apps/job-dispatcher/test/env-file.test.ts
@@ -0,0 +1,211 @@
+/**
+ * goodqa#16148 spec v4 AC-6 (1), NEG-8, NEG-9, NEG-10: every job env reaches docker through a
+ * private --env-file, never `-e KEY=VALUE` on the command line (/proc/PID/cmdline is
+ * world-readable in the host PID namespace).
+ *
+ * The stub docker records its argv and inspects the env-file at call time: mode 0600 in a fresh
+ * 0700 directory under TMPDIR, exactly one `KEY=VALUE` line per variable. Both are gone after the
+ * call on every path (success, docker failure, timeout, a synchronous throw).
+ */
+import { lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, statSync, symlinkSync, writeFileSync, existsSync } from 'node:fs';
+import { join } from 'node:path';
+import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
+
+const execFileMock = vi.fn();
+vi.mock('node:child_process', () => ({
+  execFile: (...args: unknown[]) => execFileMock(...args),
+}));
+
+const { dockerRunDetached, sweepStaleEnvFileDirs, envEntryProblem, JobEnvError, NO_HARDENING, ENVFILE_DIR_PREFIX } = await import('../src/docker');
+const { buildServer } = await import('../src/server');
+const { loadConfig } = await import('../src/config');
+const { clearExecutionsForTesting } = await import('../src/executions');
+
+type Callback = (error: Error | null, stdout?: string, stderr?: string) => void;
+
+interface Seen {
+  args: string[];
+  fileMode: number;
+  dirMode: number;
+  content: Buffer;
+  path: string;
+  dir: string;
+}
+
+let root = '';
+const savedTmp = process.env.TMPDIR;
+
+beforeEach(() => {
+  const base = join(process.cwd(), '.scratch');
+  mkdirSync(base, { recursive: true });
+  root = mkdtempSync(join(base, 'envfile-test-'));
+  process.env.TMPDIR = root;
+  clearExecutionsForTesting();
+});
+
+afterEach(() => {
+  execFileMock.mockReset();
+  if (savedTmp === undefined) delete process.env.TMPDIR;
+  else process.env.TMPDIR = savedTmp;
+});
+
+/** Stub docker: snapshot the env-file at call time, then behave as `mode` says. */
+function stubDocker(mode: 'ok' | 'fail' | 'timeout' | 'throw', seen: Seen[]) {
+  execFileMock.mockImplementationOnce((_file: string, args: string[], _opts: unknown, cb: Callback) => {
+    const i = args.indexOf('--env-file');
+    const path = i >= 0 ? args[i + 1]! : '';
+    const dir = path ? path.slice(0, path.lastIndexOf('/')) : '';
+    seen.push({
+      args: [...args],
+      fileMode: path ? statSync(path).mode & 0o777 : -1,
+      dirMode: dir ? statSync(dir).mode & 0o777 : -1,
+      content: path ? readFileSync(path) : Buffer.alloc(0),
+      path,
+      dir,
+    });
+    if (mode === 'throw') throw new Error('spawn EACCES');
+    if (mode === 'ok') return cb(null, 'cid123\n', '');
+    if (mode === 'timeout') return cb(Object.assign(new Error('timed out'), { killed: true, signal: 'SIGTERM' }), '', '');
+    return cb(Object.assign(new Error('Command failed'), { code: 125, stderr: 'docker: boom' }), '', 'docker: boom');
+  });
+}
+
+const ENV = {
+  A_PLAIN: 'value',
+  B_SPACES: '  lead inner  trail  ',
+  C_EQ: 'x=y==z',
+  D_HASH: '#not-a-comment # inner',
+  E_EMPTY: '',
+  F_QUOTES: `"double" 'single'`,
+  G_BACKSLASH: 'a\\b\\\\c\\n',
+  H_UTF8: 'café 日本 \u{1F600}',
+};
+
+function expectedFile(env: Record<string, string>): Buffer {
+  return Buffer.from(Object.entries(env).map(([k, v]) => `${k}=${v}\n`).join(''), 'utf8');
+}
+
+describe('AC-6 (1): env reaches docker only through --env-file', () => {
+  it('argv holds --env-file and no value; the file is 0600 in a fresh 0700 dir with one KEY=VALUE line each, and both are gone afterwards', async () => {
+    const seen: Seen[] = [];
+    stubDocker('ok', seen);
+    const res = await dockerRunDetached('docker', 'img:tag', ['arg1'], ENV, 5000, NO_HARDENING);
+    expect(res.containerId).toBe('cid123');
+    const s = seen[0]!;
+    expect(s.args).toEqual(['run', '--rm', '-d', '--env-file', s.path, 'img:tag', 'arg1']);
+    expect(s.args).not.toContain('-e');
+    for (const v of Object.values(ENV).filter((x) => x.length > 0)) {
+      for (const a of s.args) expect(a.includes(v), `argv element carries a value: ${a}`).toBe(false);
+    }
+    expect(s.fileMode).toBe(0o600);
+    expect(s.dirMode).toBe(0o700);
+    expect(s.dir.startsWith(join(root, ENVFILE_DIR_PREFIX))).toBe(true);
+    expect(s.content.equals(expectedFile(ENV))).toBe(true);
+    expect(existsSync(s.dir)).toBe(false);
+    expect(readdirSync(root)).toEqual([]);
+  });
+
+  it.each(['fail', 'timeout', 'throw'] as const)('NEG-9: the env-file and its dir are removed when docker %s', async (mode) => {
+    const seen: Seen[] = [];
+    stubDocker(mode, seen);
+    await expect(dockerRunDetached('docker', 'img:tag', [], { K: 'secret-value-123' }, 5000, NO_HARDENING)).rejects.toBeTruthy();
+    expect(seen).toHaveLength(1);
+    expect(existsSync(seen[0]!.path)).toBe(false);
+    expect(readdirSync(root)).toEqual([]);
+  });
+
+  it('two launches never share a directory', async () => {
+    const seen: Seen[] = [];
+    stubDocker('ok', seen);
+    stubDocker('ok', seen);
+    await dockerRunDetached('docker', 'i', [], { K: 'a' }, 5000, NO_HARDENING);
+    await dockerRunDetached('docker', 'i', [], { K: 'b' }, 5000, NO_HARDENING);
+    expect(seen[0]!.dir).not.toBe(seen[1]!.dir);
+  });
+});
+
+describe('NEG-10: invalid keys or values are refused before anything is written', () => {
+  it.each([
+    ['empty key', { '': 'v' }],
+    ['key with =', { 'A=B': 'v' }],
+    ['key with space', { 'A B': 'v' }],
+    ['non-ASCII key', { 'CAFÉ': 'v' }],
+    ['key starting with a digit', { '1A': 'v' }],
+    ['value with LF', { K: 'a\nb' }],
+    ['value with CR', { K: 'a\rb' }],
+    ['value with NUL', { K: 'a\u0000b' }],
+    ['value that is not valid UTF-8 (lone surrogate)', { K: 'a\ud800b' }],
+  ])('%s', async (_name, env) => {
+    await expect(dockerRunDetached('docker', 'i', [], env as Record<string, string>, 5000, NO_HARDENING)).rejects.toBeInstanceOf(JobEnvError);
+    expect(execFileMock).not.toHaveBeenCalled();
+    expect(readdirSync(root)).toEqual([]);
+  });
+
+  it('the refusal names the key, never the value', () => {
+    const problem = envEntryProblem('API_KEY', 'super-secret-value\nx');
+    expect(problem).toContain('API_KEY');
+    expect(problem).not.toContain('super-secret-value');
+  });
+});
+
+describe('boot sweep of stale env-file dirs', () => {
+  it('removes leftover goodqa-envfile-* dirs, leaves other entries, and never follows a symlink', () => {
+    const stale = join(root, `${ENVFILE_DIR_PREFIX}stale1`);
+    mkdirSync(stale, { mode: 0o700 });
+    writeFileSync(join(stale, 'env'), 'K=old-secret\n', { mode: 0o600 });
+    const other = join(root, 'unrelated');
+    mkdirSync(other);
+    const outside = mkdtempSync(join(process.cwd(), '.scratch', 'outside-'));
+    writeFileSync(join(outside, 'keep'), 'keep');
+    symlinkSync(outside, join(root, `${ENVFILE_DIR_PREFIX}link`));
+    const removed = sweepStaleEnvFileDirs(root);
+    expect(removed).toBe(2);
+    expect(existsSync(stale)).toBe(false);
+    expect(existsSync(other)).toBe(true);
+    expect(() => lstatSync(join(root, `${ENVFILE_DIR_PREFIX}link`))).toThrow();
+    expect(readFileSync(join(outside, 'keep'), 'utf8')).toBe('keep');
+  });
+});
+
+describe('server: request env 400, base env 501, never docker', () => {
+  const TOKEN = 'shim-token-not-real';
+  const auth = { authorization: `Bearer ${TOKEN}` };
+  function config(base: Record<string, string> = {}) {
+    return {
+      ...loadConfig({
+        JOB_DISPATCH_TOKEN: TOKEN,
+        JOB_IMAGE_SCAN: 'ar/scan:tag',
+        JOB_IMAGE_TRANSCODE: 'ar/transcode:tag',
+        JOB_IMAGE_INTELLIGENCE_WORKER: 'ar/iw:tag',
+        JOB_IMAGE_SUGGEST_FIX_WORKER: 'ar/sf:tag',
+      }),
+      jobBaseEnv: { scan: base, transcode: {}, 'intelligence-worker': {}, 'suggest-fix-worker': {} },
+    };
+  }
+
+  it.each([['LF', 'ghs_a\nb'], ['CR', 'ghs_a\rb'], ['NUL', 'ghs_a\u0000b']])('NEG-8: a request env value with %s answers 400', async (_n, value) => {
+    const run = vi.fn();
+    const app = buildServer(config(), { run, inspect: vi.fn() } as never);
+    const res = await app.inject({ method: 'POST', url: '/jobs/scan/run', headers: auth, payload: { env: { SCAN_CLONE_TOKEN: value } } });
+    expect(res.statusCode).toBe(400);
+    expect(run).not.toHaveBeenCalled();
+    expect(res.body).not.toContain('ghs_a');
+  });
+
+  it('a base env value with LF answers 501 with a named error and no value', async () => {
+    const run = vi.fn();
+    const app = buildServer(config({ DATABASE_URL: 'postgres://secret\nx' }), { run, inspect: vi.fn() } as never);
+    const res = await app.inject({ method: 'POST', url: '/jobs/scan/run', headers: auth, payload: {} });
+    expect(res.statusCode).toBe(501);
+    expect(res.json().error).toContain('DATABASE_URL');
+    expect(res.body).not.toContain('postgres://secret');
+    expect(run).not.toHaveBeenCalled();
+  });
+
+  it('a JobEnvError from the launcher answers 501', async () => {
+    const run = vi.fn().mockRejectedValue(new JobEnvError('job env K: value holds CR, LF or NUL'));
+    const app = buildServer(config(), { run, inspect: vi.fn() } as never);
+    const res = await app.inject({ method: 'POST', url: '/jobs/scan/run', headers: auth, payload: {} });
+    expect(res.statusCode).toBe(501);
+  });
+});
diff --git a/apps/job-dispatcher/test/job-env-file.test.ts b/apps/job-dispatcher/test/job-env-file.test.ts
new file mode 100644
index 00000000000..adb26697d65
--- /dev/null
+++ b/apps/job-dispatcher/test/job-env-file.test.ts
@@ -0,0 +1,204 @@
+/**
+ * goodqa#16148 spec v4 AC-4, AC-5, AC-9, NEG-4, NEG-6: an allow-listed `JOB_ENVFILE_KIND__VAR=PATH`
+ * supplies VAR to that kind's job env, read from a file under the secrets dir at every launch.
+ * Failures are per kind: 501 `job env file for KIND__VAR: REASON`, docker never called, the same
+ * line logged with key name and path only. Boot logs one status line per key and never fails.
+ * All values are fake.
+ */
+import { chmodSync, mkdirSync, mkdtempSync, renameSync, symlinkSync, writeFileSync } from 'node:fs';
+import { execFileSync } from 'node:child_process';
+import { join } from 'node:path';
+import { Worker } from 'node:worker_threads';
+import { beforeEach, describe, expect, it, vi } from 'vitest';
+import { loadConfig } from '../src/config';
+import { clearExecutionsForTesting } from '../src/executions';
+import { buildServer } from '../src/server';
+import { bootEnvFileStatusLines, readJobEnvFile, JOB_ENVFILE_ALLOWLIST } from '../src/job-env-file';
+
+const TOKEN = 'shim-token-not-real';
+const auth = { authorization: `Bearer ${TOKEN}` };
+const KEY = 'JOB_ENVFILE_INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY';
+const FAKE_PEM = '-----BEGIN FAKE KEY-----MIIFAKEfakeFAKEfake0123456789-----END FAKE KEY-----';
+
+let dir = '';
+beforeEach(() => {
+  const base = join(process.cwd(), '.scratch');
+  mkdirSync(base, { recursive: true });
+  dir = mkdtempSync(join(base, 'secrets-'));
+  clearExecutionsForTesting();
+});
+
+function config(env: Record<string, string> = {}) {
+  return {
+    ...loadConfig({
+      JOB_DISPATCH_TOKEN: TOKEN,
+      JOB_IMAGE_SCAN: 'ar/scan:tag',
+      JOB_IMAGE_TRANSCODE: 'ar/transcode:tag',
+      JOB_IMAGE_INTELLIGENCE_WORKER: 'ar/iw:tag',
+      JOB_IMAGE_SUGGEST_FIX_WORKER: 'ar/sf:tag',
+      ...env,
+    }),
+    jobEnvFileDir: dir,
+  };
+}
+
+function okRun() {
+  return vi.fn().mockResolvedValue({ containerId: 'c1', startedAt: '2026-11-16T00:00:00.000Z' });
+}
+
+async function launch(cfg: ReturnType<typeof config>, run = okRun(), kind = 'intelligence-worker', lines: string[] = []) {
+  const app = buildServer(cfg, { run, inspect: vi.fn() } as never, { logStream: { write: (l: string) => lines.push(l) } });
+  const res = await app.inject({ method: 'POST', url: `/jobs/${kind}/run`, headers: auth, payload: {} });
+  return { res, run, lines };
+}
+
+describe('AC-4: injection', () => {
+  it('the allow-listed key supplies VAR to intelligence-worker only, read at launch, one trailing LF removed', async () => {
+    writeFileSync(join(dir, 'github-app-private-key'), `${FAKE_PEM}\n`);
+    const cfg = config({ [KEY]: join(dir, 'github-app-private-key'), JOB_ENV_INTELLIGENCE_WORKER__OTHER: 'o' });
+    const { res, run } = await launch(cfg);
+    expect(res.statusCode).toBe(200);
+    const env = run.mock.calls[0]![3] as Record<string, string>;
+    expect(env.GITHUB_APP_PRIVATE_KEY).toBe(FAKE_PEM);
+    expect(env.OTHER).toBe('o');
+    // The value is a secret source: it is in the redaction list (goodqa#16185).
+    expect(run.mock.calls[0]![6]).toContain(FAKE_PEM);
+    for (const kind of ['scan', 'transcode', 'suggest-fix-worker']) {
+      const other = await launch(cfg, okRun(), kind);
+      expect(other.res.statusCode).toBe(200);
+      expect((other.run.mock.calls[0]![3] as Record<string, string>).GITHUB_APP_PRIVATE_KEY).toBeUndefined();
+    }
+  });
+
+  it('only INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY is allow-listed', () => {
+    expect([...JOB_ENVFILE_ALLOWLIST]).toEqual(['INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY']);
+  });
+
+  it('a non-allow-listed JOB_ENVFILE key is ignored and logged by name at boot', async () => {
+    writeFileSync(join(dir, 'x'), 'secret-x');
+    const cfg = config({ JOB_ENVFILE_SCAN__DATABASE_URL: join(dir, 'x') });
+    const { res, run } = await launch(cfg, okRun(), 'scan');
+    expect(res.statusCode).toBe(200);
+    expect((run.mock.calls[0]![3] as Record<string, string>).DATABASE_URL).toBeUndefined();
+    expect(bootEnvFileStatusLines(cfg)).toContain('job env file key ignored (not allow-listed): JOB_ENVFILE_SCAN__DATABASE_URL');
+  });
+
+  it('JOB_ENV_KIND__VAR ending in _FILE keeps its literal meaning', async () => {
+    const cfg = config({ JOB_ENV_INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY_FILE: '/some/path' });
+    const { run } = await launch(cfg);
+    expect((run.mock.calls[0]![3] as Record<string, string>).GITHUB_APP_PRIVATE_KEY_FILE).toBe('/some/path');
+    expect((run.mock.calls[0]![3] as Record<string, string>).GITHUB_APP_PRIVATE_KEY).toBeUndefined();
+  });
+});
+
+describe('AC-5 / NEG-4: fail closed per kind', () => {
+  const name = 'github-app-private-key';
+  const cases: Array<[string, () => string, RegExp]> = [
+    ['missing file', () => join(dir, name), /: missing$/],
+    ['unreadable (mode 000)', () => { writeFileSync(join(dir, name), FAKE_PEM); chmodSync(join(dir, name), 0o000); return join(dir, name); }, /: unreadable$/],
+    ['empty', () => { writeFileSync(join(dir, name), ''); return join(dir, name); }, /: empty$/],
+    ['only a newline', () => { writeFileSync(join(dir, name), '\n'); return join(dir, name); }, /: empty$/],
+    ['a symlink to a readable file', () => { writeFileSync(join(dir, 'real'), FAKE_PEM); symlinkSync(join(dir, 'real'), join(dir, name)); return join(dir, name); }, /: is a symlink$/],
+    ['a FIFO', () => { execFileSync('mkfifo', [join(dir, name)]); return join(dir, name); }, /: not a regular file$/],
+    ['a directory', () => { mkdirSync(join(dir, name)); return join(dir, name); }, /: not a regular file$/],
+    ['a 65 KiB file', () => { writeFileSync(join(dir, name), 'A'.repeat(65 * 1024)); return join(dir, name); }, /: over 64 KiB$/],
+    ['a path outside the secrets dir', () => { writeFileSync(join(dir, '..', 'outside-key'), FAKE_PEM); return join(dir, '..', 'outside-key'); }, /: path outside the secrets directory$/],
+    ['.. traversal', () => `${dir}/../${dir.split('/').pop()}/${name}`, /: path outside the secrets directory$/],
+    ['a relative path', () => 'github-app-private-key', /: path outside the secrets directory$/],
+    ['a CR inside the value', () => { writeFileSync(join(dir, name), 'abc\rdef\n'); return join(dir, name); }, /: value holds CR, LF or NUL$/],
+    ['an inner LF', () => { writeFileSync(join(dir, name), 'abc\ndef\n'); return join(dir, name); }, /: value holds CR, LF or NUL$/],
+    ['a NUL', () => { writeFileSync(join(dir, name), 'abc\u0000def'); return join(dir, name); }, /: value holds CR, LF or NUL$/],
+    ['invalid UTF-8', () => { writeFileSync(join(dir, name), Buffer.from([0x41, 0xff, 0x42])); return join(dir, name); }, /: value is not valid UTF-8$/],
+  ];
+
+  it.each(cases)('%s: 501, docker not called, the named line logged without the value', async (_n, setup, reason) => {
+    const path = setup();
+    const { res, run, lines } = await launch(config({ [KEY]: path }));
+    expect(res.statusCode).toBe(501);
+    const error = (res.json() as { error: string }).error;
+    expect(error.startsWith('job env file for INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY: ')).toBe(true);
+    expect(error).toMatch(reason);
+    expect(run).not.toHaveBeenCalled();
+    expect(lines.some((l) => l.includes(error))).toBe(true);
+    for (const l of [...lines, res.body]) expect(l).not.toContain('MIIFAKEfake');
+    // Other kinds are unaffected.
+    const other = await launch(config({ [KEY]: path }), okRun(), 'scan');
+    expect(other.res.statusCode).toBe(200);
+  });
+
+  it('both JOB_ENV_ and JOB_ENVFILE_ for the same VAR: 501', async () => {
+    writeFileSync(join(dir, name), FAKE_PEM);
+    const { res, run } = await launch(config({ [KEY]: join(dir, name), JOB_ENV_INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY: 'inline' }));
+    expect(res.statusCode).toBe(501);
+    expect(res.json().error).toBe('job env file for INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY: both JOB_ENV_ and JOB_ENVFILE_ are set');
+    expect(run).not.toHaveBeenCalled();
+  });
+
+  it('boot status lines: ok, or the named error; never the content; boot never throws', () => {
+    writeFileSync(join(dir, name), FAKE_PEM);
+    expect(bootEnvFileStatusLines(config({ [KEY]: join(dir, name) }))).toEqual(['job env file INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY: ok']);
+    expect(bootEnvFileStatusLines(config({ [KEY]: join(dir, 'nope') }))).toEqual([
+      'job env file for INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY: missing',
+    ]);
+    expect(bootEnvFileStatusLines(config())).toEqual([]);
+  });
+});
+
+describe('AC-9 / NEG-6: rotation', () => {
+  it('a changed file is used by the next launch without a restart, never the old value', async () => {
+    const path = join(dir, 'github-app-private-key');
+    writeFileSync(path, 'OLDfakeVALUE-0001');
+    const cfg = config({ [KEY]: path });
+    const app = buildServer(cfg, { run: okRun(), inspect: vi.fn() } as never);
+    const run = okRun();
+    const app2 = buildServer(cfg, { run, inspect: vi.fn() } as never);
+    void app;
+    await app2.inject({ method: 'POST', url: '/jobs/intelligence-worker/run', headers: auth, payload: {} });
+    writeFileSync(join(dir, '.tmp'), 'NEWfakeVALUE-0002');
+    renameSync(join(dir, '.tmp'), path);
+    await app2.inject({ method: 'POST', url: '/jobs/intelligence-worker/run', headers: auth, payload: {} });
+    expect((run.mock.calls[0]![3] as Record<string, string>).GITHUB_APP_PRIVATE_KEY).toBe('OLDfakeVALUE-0001');
+    expect((run.mock.calls[1]![3] as Record<string, string>).GITHUB_APP_PRIVATE_KEY).toBe('NEWfakeVALUE-0002');
+  });
+
+  it('NEG-6: 200 reads while another thread renames in a loop each see exactly the old or the new value', async () => {
+    const path = join(dir, 'github-app-private-key');
+    const A = `A${'a'.repeat(4000)}`;
+    const B = `B${'b'.repeat(6000)}`;
+    writeFileSync(path, A);
+    const worker = new Worker(
+      `const { writeFileSync, renameSync } = require('node:fs');
+       const { workerData, parentPort } = require('node:worker_threads');
+       let i = 0, stop = false;
+       parentPort.on('message', () => { stop = true; });
+       (function loop() {
+         for (let k = 0; k < 50 && !stop; k += 1) {
+           const t = workerData.dir + '/.t' + (i % 2);
+           writeFileSync(t, i % 2 ? workerData.A : workerData.B);
+           renameSync(t, workerData.path);
+           i += 1;
+           if (i === 1) parentPort.postMessage('started');
+         }
+         if (!stop) setImmediate(loop); else parentPort.postMessage(i);
+       })();`,
+      { eval: true, workerData: { dir, path, A, B } },
+    );
+    await new Promise((res) => worker.once('message', res));
+    const seen = new Set<string>();
+    for (let n = 0; n < 200; n += 1) {
+      const r = readJobEnvFile(path, dir);
+      expect(r.ok).toBe(true);
+      const v = (r as { value: string }).value;
+      expect(v === A || v === B).toBe(true);
+      seen.add(v[0]!);
+      await new Promise((res) => setTimeout(res, 1));
+    }
+    const renames = await new Promise<number>((res) => {
+      worker.once('message', res);
+      worker.postMessage('stop');
+    });
+    await worker.terminate();
+    expect(renames).toBeGreaterThan(0);
+    expect(seen.size).toBe(2);
+  });
+});
diff --git a/infra/release-harness/test_selfhost_ctl_job_secrets.py b/infra/release-harness/test_selfhost_ctl_job_secrets.py
new file mode 100644
index 00000000000..f14d55b5217
--- /dev/null
+++ b/infra/release-harness/test_selfhost_ctl_job_secrets.py
@@ -0,0 +1,106 @@
+"""goodqa#16148 spec v4 AC-11 (Sonnet v4 condition): on a fake VM, the job-dispatcher secrets mount and group_add that
+the host apply put in compose.yaml survive the real selfhost-ctl.py `pin` (the next release) and its `restore`
+(that release's rollback). The fence refuses the rollback of a release pinned before the apply, so it can never remove them.
+Fake docker on PATH; fake files only; no network, secrets or containers.
+Run: python3 -m pytest -q infra/release-harness/test_selfhost_ctl_job_secrets.py
+"""
+import importlib.util
+import os
+import subprocess
+import sys
+from pathlib import Path
+
+import pytest
+
+HERE = Path(__file__).resolve().parent
+ROOT = HERE.parent.parent
+CTL = HERE / 'selfhost-ctl.py'
+APP = ROOT / 'infra/selfhost/app'
+
+spec = importlib.util.spec_from_file_location('apply_host', APP / 'apply-job-secrets-host.py')
+ah = importlib.util.module_from_spec(spec)
+spec.loader.exec_module(ah)
+
+FAKE_DOCKER = '''#!/bin/sh
+echo "$*" >> "$FAKE_VM/docker.log"
+if [ "$1" = image ] && [ "$2" = inspect ]; then printf 'sha256:%s\\n' "$(printf %s "$5" | sha256sum | cut -c1-64)"; exit 0; fi
+exit 0
+'''
+SHA_A, SHA_B = 'a' * 40, 'b' * 40
+
+
+def env_text(sha, dep):
+    return 'KEEP=x\nRELEASE_SOURCE_SHA=%s\nRELEASE_DEPLOYMENT_ID=%s\n' % (sha, dep)
+
+
+@pytest.fixture
+def vm(tmp_path, monkeypatch):
+    d, e, b = tmp_path / 'app', tmp_path / 'etc', tmp_path / 'bin'
+    for p in (d, e, b):
+        p.mkdir()
+    (b / 'docker').write_text(FAKE_DOCKER)
+    (b / 'docker').chmod(0o755)
+    for s in ('api', 'web'):
+        (e / (s + '.env')).write_text(env_text('0' * 40, 'dep-0'))
+    monkeypatch.setenv('PATH', '%s:%s' % (b, os.environ['PATH']))
+    monkeypatch.setenv('FAKE_VM', str(tmp_path))
+    return d, e
+
+
+def ctl(vm, *argv):
+    d, e = vm
+    r = subprocess.run([sys.executable, '-B', str(CTL), '--dir', str(d), '--env-dir', str(e), *argv],
+                       capture_output=True, text=True, timeout=60)
+    return r.returncode, r.stdout
+
+
+def pin(vm, stamp, sha, tag):
+    return ctl(vm, 'pin', '--stamp', stamp, '--sha', sha, '--deploy-id', 'dep-' + stamp,
+               '--api', 'goodqa-api:' + tag, '--web', 'goodqa-web:' + tag, '--disp', 'goodqa-job-dispatcher:' + tag)
+
+
+def marked(text):
+    """The marked AC-11 lines, each checked to sit in the job-dispatcher block and nowhere else."""
+    lines = text.split('\n')
+    start = lines.index('  job-dispatcher:')
+    end = next(i for i in range(start + 1, len(lines)) if lines[i] and not lines[i].startswith('    '))
+    block = lines[start:end]
+    return [l for l in (ah.GROUP_LINE, ah.VOL_LINE) if l in block and lines.count(l) == 1]
+
+
+def compose(vm):
+    return (vm[0] / 'compose.yaml').read_text()
+
+
+def test_mount_survives_the_next_release_pin_and_its_rollback(vm):
+    applied = (APP / 'compose.yaml').read_text()          # the checked-in file is what the host apply leaves
+    assert marked(applied) == [ah.GROUP_LINE, ah.VOL_LINE]
+    (vm[0] / 'compose.yaml').write_text(applied)
+    rc, out = pin(vm, 'S1', SHA_A, 'aaaa-1')
+    assert rc == 0, out
+    after_pin = compose(vm)
+    assert 'goodqa-job-dispatcher:aaaa-1 # rw-ship' in after_pin
+    assert marked(after_pin) == [ah.GROUP_LINE, ah.VOL_LINE], 'pin dropped the AC-11 lines'
+    assert ah.compose_restore(after_pin) != after_pin
+    rc, out = pin(vm, 'S2', SHA_B, 'bbbb-2')
+    assert rc == 0, out
+    assert marked(compose(vm)) == [ah.GROUP_LINE, ah.VOL_LINE]
+    rc, out = ctl(vm, 'restore', '--stamp', 'S2')       # release S2 rolled back to S1
+    assert rc == 0, out
+    assert compose(vm) == after_pin
+    assert marked(compose(vm)) == [ah.GROUP_LINE, ah.VOL_LINE], 'rollback dropped the AC-11 lines'
+
+
+def test_rollback_of_a_release_pinned_before_the_apply_is_refused_and_keeps_the_mount(vm):
+    before = ah.compose_restore((APP / 'compose.yaml').read_text())
+    assert marked(before) == []
+    (vm[0] / 'compose.yaml').write_text(before)
+    rc, out = pin(vm, 'S1', SHA_A, 'aaaa-1')
+    assert rc == 0, out
+    applied = ah.compose_apply(compose(vm))                # the host apply runs after release S1
+    (vm[0] / 'compose.yaml').write_text(applied)
+    rc, out = ctl(vm, 'restore', '--stamp', 'S1')
+    assert rc == 3, out
+    assert out.startswith('REFUSED') and 'a stale rollback is refused' in out, out
+    assert compose(vm) == applied
+    assert marked(compose(vm)) == [ah.GROUP_LINE, ah.VOL_LINE]
diff --git a/infra/selfhost-job-secrets-drift.test.mjs b/infra/selfhost-job-secrets-drift.test.mjs
new file mode 100644
index 00000000000..0d65542d75b
--- /dev/null
+++ b/infra/selfhost-job-secrets-drift.test.mjs
@@ -0,0 +1,95 @@
+// goodqa#16148 spec v4 AC-3, AC-11 and NEG-16: the checked-in self-host files match what the AC-11 host apply leaves
+// on the VM, so the CC8.1 selfhost-topology-drift gate (infra/selfhost-plan.mjs) is green after the apply and red
+// without the checked-in change. Also the R4 cross-check: the host-apply wrapper takes the same deploy lock as rw-ship.
+import { test } from 'node:test'
+import assert from 'node:assert/strict'
+import { spawnSync } from 'node:child_process'
+import { readFileSync } from 'node:fs'
+import { join, resolve, dirname } from 'node:path'
+import { fileURLToPath } from 'node:url'
+import { planSelfhostDrift, loadDesired } from './selfhost-plan.mjs'
+
+const HERE = dirname(fileURLToPath(import.meta.url))
+const ROOT = resolve(HERE, '..')
+const APP = join(ROOT, 'infra/selfhost/app')
+const desired = loadDesired(ROOT)
+const KEY = 'JOB_ENVFILE_INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY'
+
+/** Run a function of apply-job-secrets-host.py on text, through python (the code the VM runs). */
+function hostApply(fn, text) {
+  const code = [
+    'import importlib.util, sys',
+    `s = importlib.util.spec_from_file_location("a", ${JSON.stringify(join(APP, 'apply-job-secrets-host.py'))})`,
+    'm = importlib.util.module_from_spec(s); s.loader.exec_module(m)',
+    `sys.stdout.write(getattr(m, ${JSON.stringify(fn)})(sys.stdin.read()) if ${JSON.stringify(fn)} != "consts" else "\\n".join([m.GROUP_LINE, m.VOL_LINE, m.ENV_LINE]))`,
+  ].join('\n')
+  const r = spawnSync('python3', ['-I', '-c', code], { input: text, encoding: 'utf8' })
+  assert.equal(r.status, 0, r.stderr)
+  return r.stdout
+}
+
+function block(compose, service) {
+  const lines = compose.split('\n')
+  const start = lines.indexOf(`  ${service}:`)
+  assert.ok(start >= 0, service)
+  let end = start + 1
+  while (end < lines.length && (lines[end] === '' || lines[end].startsWith('    '))) end += 1
+  return lines.slice(start, end)
+}
+
+test('AC-3: only job-dispatcher has the read-only secrets mount and group_add 64910', () => {
+  const [groupLine, volLine] = hostApply('consts', '').split('\n')
+  const disp = block(desired.compose, 'job-dispatcher')
+  assert.ok(disp.includes(groupLine), 'job-dispatcher group_add')
+  assert.ok(disp.includes(volLine), 'job-dispatcher mount')
+  assert.match(volLine, /"\/etc\/goodqa\/job-secrets:\/run\/goodqa-secrets:ro"/)
+  const elsewhere = desired.compose.split('\n').filter((l) => (l.includes('job-secrets') || l.includes('64910')) && !disp.includes(l))
+  assert.deepEqual(elsewhere, [], 'no other service mounts the secrets or gets the group')
+  assert.ok(disp.includes('    read_only: true') && disp.includes('    tmpfs: ["/tmp"]'))
+})
+
+test('AC-11: the host apply on the pre-change compose yields exactly the checked-in compose, and restore undoes it', () => {
+  const before = hostApply('compose_restore', desired.compose)
+  assert.notEqual(before, desired.compose)
+  assert.equal(hostApply('compose_apply', before), desired.compose)
+  assert.equal(hostApply('compose_apply', desired.compose), desired.compose, 'idempotent')
+})
+
+test('AC-11: env-keys.json names the dispatcher JOB_ENVFILE key, and only for the dispatcher', () => {
+  assert.ok(desired.env.dispatcher.includes(KEY))
+  assert.ok(!desired.env.api.includes(KEY) && !desired.env.web.includes(KEY))
+  const envLine = hostApply('consts', '').split('\n')[2]
+  assert.equal(envLine.split('=')[0], KEY)
+})
+
+test('NEG-16: an applied VM is no drift against the checked-in files', () => {
+  assert.deepEqual(planSelfhostDrift(desired, { compose: desired.compose, env: desired.env }), [])
+})
+
+test('NEG-16: the gate goes red if env-keys.json lacks the key (against an applied VM)', () => {
+  const stale = { ...desired, env: { ...desired.env, dispatcher: desired.env.dispatcher.filter((k) => k !== KEY) } }
+  const p = planSelfhostDrift(stale, { compose: desired.compose, env: desired.env })
+  assert.equal(p.length, 1, p.join('\n'))
+  assert.match(p[0], new RegExp(`dispatcher\\.env has key\\(s\\) not checked in: ${KEY}`))
+})
+
+test('NEG-16: the gate goes red if the checked-in compose lacks the mount (against an applied VM)', () => {
+  const stale = { ...desired, compose: hostApply('compose_restore', desired.compose) }
+  const p = planSelfhostDrift(stale, { compose: desired.compose, env: desired.env })
+  assert.equal(p.length, 1, p.join('\n'))
+  // The gate compares line by line, so the two inserted lines also shift every later line.
+  assert.match(p[0], /compose\.yaml differs on \d+ line/)
+  assert.ok(p[0].includes('group_add: [\\"64910\\"] # goodqa#16148 AC-11'), p[0])
+})
+
+test('R4: the host-apply wrapper takes the deploy lock rw-ship takes (main copy of rw-ship.sh)', () => {
+  const ship = readFileSync(join(ROOT, 'infra/release-harness/rw-ship.sh'), 'utf8')
+  const m = /^LOCKF=\$S\/(\S+?);/m.exec(ship)
+  assert.ok(m, 'rw-ship.sh LOCKF line')
+  const wrapper = readFileSync(join(APP, 'apply-job-secrets.sh'), 'utf8')
+  const w = /^LOCK_REL=(\S+)$/m.exec(wrapper)
+  assert.ok(w, 'wrapper LOCK_REL line')
+  assert.equal(w[1], m[1])
+  assert.match(ship, /INFL=\$\{LOCKF%\.lock\}\.inflight\.json/)
+  assert.match(wrapper, /inflight\.json/)
+})
diff --git a/infra/selfhost/app/apply-job-secrets-host.py b/infra/selfhost/app/apply-job-secrets-host.py
new file mode 100755
index 00000000000..30596fa52d3
--- /dev/null
+++ b/infra/selfhost/app/apply-job-secrets-host.py
@@ -0,0 +1,350 @@
+#!/usr/bin/env python3
+"""apply-job-secrets-host.py -- goodqa#16148 spec v4 AC-11 (build conditions R1 to R4).
+
+Applies, on the self-host app VM, the parts of the job-secret wiring that no release applies:
+  * in the live compose.yaml, the job-dispatcher service gets two marked lines:
+        group_add: ["64910"] # goodqa#16148 AC-11
+        volumes: ["/etc/goodqa/job-secrets:/run/goodqa-secrets:ro"] # goodqa#16148 AC-11
+  * /etc/goodqa/dispatcher.env gets the key line
+        JOB_ENVFILE_INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY=/run/goodqa-secrets/github-app-private-key
+    (a path, not a secret; raw env_file lines cannot carry a comment, so this line is matched exactly).
+The goodqa-jobsecret group and the /etc/goodqa/job-secrets directory are created by
+derive-job-secrets.py, which apply-job-secrets.sh streams first under the same deploy lock; this
+script only checks them. It never reads or prints a secret value and never recreates a container.
+
+Not run directly: apply-job-secrets.sh (on the release runner) takes the deploy lock and streams
+it as root:  ssh <app> sudo python3 -I - --dir D --env-dir E (--check | apply --stamp S | restore)
+
+  --check   read-only; one line per item: `<item>: present|absent|conflict`.
+  apply     refuses unless every item is present or absent (no conflict); validates the new
+            compose with `docker compose config -q` before any file changes; writes a backup of
+            each file it will change (<file>.pre-16148-<S>, O_EXCL|O_NOFOLLOW, root 0600, kept for the
+            newest 3 stamps); then dispatcher.env, then compose.yaml, each through a directory fd,
+            a temp file and a rename, keeping the file's owner and mode. Idempotent.
+  restore   removes exactly the lines apply inserted (R1): a later release pin or set-secret-env
+            key is kept. Refuses if a marked line was changed.
+Exit 0 ok, 2 refused.
+"""
+import argparse
+import os
+import re
+import secrets
+import stat
+import subprocess
+import sys
+
+MARK = '# goodqa#16148 AC-11'
+GROUP_LINE = '    group_add: ["64910"] ' + MARK
+VOL_LINE = '    volumes: ["/etc/goodqa/job-secrets:/run/goodqa-secrets:ro"] ' + MARK
+ENV_KEY = 'JOB_ENVFILE_INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY'
+ENV_LINE = ENV_KEY + '=/run/goodqa-secrets/github-app-private-key'
+SECRETS_DIR = 'job-secrets'
+GID = 64910
+GROUP = 'goodqa-jobsecret'
+BACKUP_INFIX = '.pre-16148-'
+KEEP_BACKUPS = 3
+STAMP_RE = re.compile(r'^\d{8}T\d{6}Z$')
+
+
+class Refused(Exception):
+    pass
+
+
+# ---- safe file io (directory fd, no links, temp + rename) --------------------------------------
+def open_dir(path):
+    try:
+        return os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
+    except OSError:
+        raise Refused('%s is missing, a symlink or not a directory' % path)
+
+
+def read_file(dfd, name):
+    try:
+        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dfd)
+    except FileNotFoundError:
+        raise Refused('%s is missing' % name)
+    except OSError:
+        raise Refused('%s is a symlink or unreadable' % name)
+    try:
+        st = os.fstat(fd)
+        if not stat.S_ISREG(st.st_mode):
+            raise Refused('%s is not a regular file' % name)
+        chunks = []
+        while True:
+            b = os.read(fd, 65536)
+            if not b:
+                break
+            chunks.append(b)
+        return b''.join(chunks), st
+    finally:
+        os.close(fd)
+
+
+def write_new(dfd, name, data, uid, gid, mode):
+    """Create `name` (must not exist) with O_EXCL|O_NOFOLLOW, owner and mode set on the fd."""
+    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dfd)
+    try:
+        os.fchown(fd, uid, gid)
+        os.fchmod(fd, mode)
+        view = memoryview(data)
+        while view:
+            view = view[os.write(fd, view):]
+        os.fsync(fd)
+    finally:
+        os.close(fd)
+
+
+def replace_file(dfd, name, data, st, hooks=None, validate=None):
+    tmp = '.%s.tmp-%s' % (name, secrets.token_hex(6))
+    write_new(dfd, tmp, data, st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode))
+    try:
+        if validate:
+            validate(tmp)
+        if hooks and hooks.get('before_rename_' + name):
+            hooks['before_rename_' + name]()
+        os.rename(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd)
+        os.fsync(dfd)
+    except BaseException:
+        try:
+            os.unlink(tmp, dir_fd=dfd)
+        except OSError:
+            pass
+        raise
+
+
+# ---- compose edits ---------------------------------------------------------------------------
+def _service_block(lines, service):
+    """(start, end) line indexes of `  service:` up to the next top-level or service key."""
+    try:
+        start = lines.index('  %s:' % service)
+    except ValueError:
+        raise Refused('compose.yaml has no %s service' % service)
+    end = start + 1
+    while end < len(lines) and (lines[end] == '' or lines[end].startswith('    ') or lines[end].lstrip().startswith('#')):
+        end += 1
+    while end > start + 1 and lines[end - 1].strip() == '':
+        end -= 1
+    return start, end
+
+
+def compose_status(text):
+    lines = text.split('\n')
+    start, end = _service_block(lines, 'job-dispatcher')
+    block = lines[start:end]
+    out = {}
+    for item, want, key in (('group_add', GROUP_LINE, '    group_add:'), ('mount', VOL_LINE, '    volumes:')):
+        have = [l for l in block if l.startswith(key)]
+        if have == [want]:
+            out[item] = 'present'
+        elif not have and not any(MARK in l and l.startswith(key) for l in lines):
+            out[item] = 'absent'
+        else:
+            out[item] = 'conflict'
+    if sum(1 for l in lines if '/etc/goodqa/job-secrets' in l or '64910' in l) != sum(1 for l in block if l in (GROUP_LINE, VOL_LINE)):
+        out['mount'] = 'conflict'
+    return out
+
+
+def compose_apply(text):
+    lines = text.split('\n')
+    st = compose_status(text)
+    _start, end = _service_block(lines, 'job-dispatcher')
+    add = [l for item, l in (('group_add', GROUP_LINE), ('mount', VOL_LINE)) if st[item] == 'absent']
+    return '\n'.join(lines[:end] + add + lines[end:])
+
+
+def compose_restore(text):
+    lines = text.split('\n')
+    marked = [l for l in lines if MARK in l]
+    if any(l not in (GROUP_LINE, VOL_LINE) for l in marked):
+        raise Refused('a goodqa#16148 marked line in compose.yaml was changed; restore by hand')
+    return '\n'.join(l for l in lines if l not in (GROUP_LINE, VOL_LINE))
+
+
+# ---- dispatcher.env edits --------------------------------------------------------------------
+def env_status(data):
+    lines = data.split(b'\n')
+    have = [l for l in lines if l.lstrip().startswith(ENV_KEY.encode() + b'=') or l.strip() == ENV_KEY.encode()]
+    if have == [ENV_LINE.encode()]:
+        return 'present'
+    if not have:
+        return 'absent'
+    return 'conflict'
+
+
+def env_apply(data):
+    if env_status(data) == 'present':
+        return data
+    if data and not data.endswith(b'\n'):
+        raise Refused('dispatcher.env does not end with a newline')
+    return data + ENV_LINE.encode() + b'\n'
+
+
+def env_restore(data):
+    st = env_status(data)
+    if st == 'conflict':
+        raise Refused('dispatcher.env holds another %s line; restore by hand' % ENV_KEY)
+    if st == 'absent':
+        return data
+    lines = data.split(b'\n')
+    i = lines.index(ENV_LINE.encode())
+    return b'\n'.join(lines[:i] + lines[i + 1:])
+
+
+# ---- group and directory (made by derive; checked here) -------------------------------------
+def _getent(*args):
+    try:
+        r = subprocess.run(['getent', *args], capture_output=True, text=True, timeout=10)
+    except (OSError, subprocess.TimeoutExpired):
+        raise Refused('getent failed')
+    return r.stdout if r.returncode == 0 else ''
+
+
+def group_status():
+    rows = [l.split(':') for l in (_getent('group', GROUP) + _getent('group', str(GID))).splitlines() if l.count(':') >= 3]
+    if not rows:
+        return 'absent'
+    if all(r[0] == GROUP and r[2] == str(GID) and r[3] == '' for r in rows):
+        return 'present'
+    return 'conflict'
+
+
+def dir_status(env_dfd):
+    try:
+        st = os.stat(SECRETS_DIR, dir_fd=env_dfd, follow_symlinks=False)
+    except FileNotFoundError:
+        return 'absent'
+    if stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and st.st_gid == 0 and stat.S_IMODE(st.st_mode) == 0o711:
+        return 'present'
+    return 'conflict'
+
+
+# ---- commands --------------------------------------------------------------------------------
+def status_lines(a):
+    ddfd, edfd = open_dir(a.dir), open_dir(a.env_dir)
+    try:
+        comp, _ = read_file(ddfd, 'compose.yaml')
+        env, _ = read_file(edfd, 'dispatcher.env')
+        cs = compose_status(comp.decode('utf-8'))
+        return [
+            ('compose job-dispatcher group_add', cs['group_add']),
+            ('compose job-dispatcher mount', cs['mount']),
+            ('dispatcher.env ' + ENV_KEY, env_status(env)),
+            ('group ' + GROUP, group_status()),
+            ('dir /etc/goodqa/' + SECRETS_DIR, dir_status(edfd)),
+        ]
+    finally:
+        os.close(ddfd)
+        os.close(edfd)
+
+
+def backup(dfd, name, data, stamp):
+    write_new(dfd, name + BACKUP_INFIX + stamp, data, 0, 0, 0o600)
+
+
+def prune_backups(dfd, name):
+    pat = re.compile(re.escape(name + BACKUP_INFIX) + r'(\d{8}T\d{6}Z)$')
+    found = sorted((m.group(1), e) for e in os.listdir(dfd) for m in [pat.match(e)] if m)
+    for _s, entry in found[:-KEEP_BACKUPS]:
+        if stat.S_ISREG(os.stat(entry, dir_fd=dfd, follow_symlinks=False).st_mode):
+            os.unlink(entry, dir_fd=dfd)
+
+
+def validate_compose(dir_path, tmp_name):
+    r = subprocess.run(['docker', 'compose', '-f', os.path.join(dir_path, tmp_name), '--project-directory', dir_path, 'config', '-q'],
+                       capture_output=True, timeout=120)
+    if r.returncode != 0:
+        raise Refused('the new compose.yaml does not validate (docker compose config -q exit %d)' % r.returncode)
+
+
+def cmd_apply(a, hooks=None):
+    if not STAMP_RE.match(a.stamp or ''):
+        raise Refused('--stamp must be YYYYMMDDTHHMMSSZ')
+    items = status_lines(a)
+    bad = [i for i, s in items if s == 'conflict']
+    if bad:
+        raise Refused('conflict: ' + ', '.join(bad))
+    if dict(items)['group ' + GROUP] != 'present' or dict(items)['dir /etc/goodqa/' + SECRETS_DIR] != 'present':
+        raise Refused('the group or the secrets directory is absent: derive-job-secrets.py must run first')
+    ddfd, edfd = open_dir(a.dir), open_dir(a.env_dir)
+    try:
+        comp, cst = read_file(ddfd, 'compose.yaml')
+        env, est = read_file(edfd, 'dispatcher.env')
+        new_comp = compose_apply(comp.decode('utf-8')).encode('utf-8')
+        new_env = env_apply(env)
+        if new_comp == comp and new_env == env:
+            return 'unchanged'
+        # Validate before any file changes: a temp copy of the new compose, then removed.
+        if new_comp != comp:
+            probe = '.compose.yaml.validate-%s' % secrets.token_hex(6)
+            write_new(ddfd, probe, new_comp, cst.st_uid, cst.st_gid, stat.S_IMODE(cst.st_mode))
+            try:
+                validate_compose(a.dir, probe)
+            finally:
+                os.unlink(probe, dir_fd=ddfd)
+        if new_env != env:
+            backup(edfd, 'dispatcher.env', env, a.stamp)
+        if new_comp != comp:
+            backup(ddfd, 'compose.yaml', comp, a.stamp)
+        if new_env != env:
+            replace_file(edfd, 'dispatcher.env', new_env, est, hooks)
+        if hooks and hooks.get('between_files'):
+            hooks['between_files']()
+        if new_comp != comp:
+            replace_file(ddfd, 'compose.yaml', new_comp, cst, hooks)
+        prune_backups(edfd, 'dispatcher.env')
+        prune_backups(ddfd, 'compose.yaml')
+        return 'applied'
+    finally:
+        os.close(ddfd)
+        os.close(edfd)
+
+
+def cmd_restore(a):
+    ddfd, edfd = open_dir(a.dir), open_dir(a.env_dir)
+    try:
+        comp, cst = read_file(ddfd, 'compose.yaml')
+        env, est = read_file(edfd, 'dispatcher.env')
+        new_comp = compose_restore(comp.decode('utf-8')).encode('utf-8')
+        new_env = env_restore(env)
+        if new_comp != comp:
+            replace_file(ddfd, 'compose.yaml', new_comp, cst)
+        if new_env != env:
+            replace_file(edfd, 'dispatcher.env', new_env, est)
+        return 'restored' if (new_comp != comp or new_env != env) else 'nothing to restore'
+    finally:
+        os.close(ddfd)
+        os.close(edfd)
+
+
+def run(argv, hooks=None):
+    p = argparse.ArgumentParser(prog='apply-job-secrets-host.py')
+    p.add_argument('--dir', required=True)
+    p.add_argument('--env-dir', required=True)
+    p.add_argument('--check', action='store_true')
+    p.add_argument('cmd', nargs='?', choices=['apply', 'restore'])
+    p.add_argument('--stamp')
+    a = p.parse_args(argv)
+    try:
+        if a.check == bool(a.cmd):
+            raise Refused('give exactly one of --check, apply, restore')
+        if a.check:
+            return ['%s: %s' % (i, s) for i, s in status_lines(a)], 0
+        if a.cmd == 'apply':
+            return ['job secrets host apply: ' + cmd_apply(a, hooks)], 0
+        return ['job secrets host restore: ' + cmd_restore(a)], 0
+    except Refused as e:
+        return ['job secrets host %s: REFUSED %s' % (a.cmd or 'check', e)], 2
+    except OSError as e:
+        return ['job secrets host %s: REFUSED os error (%s)' % (a.cmd or 'check', type(e).__name__)], 2
+
+
+def main():
+    argv = sys.argv[1:]
+    lines, code = run(argv)
+    sys.stdout.write(''.join(l + '\n' for l in lines))
+    return code
+
+
+if __name__ == '__main__':
+    sys.exit(main())
diff --git a/infra/selfhost/app/apply-job-secrets.sh b/infra/selfhost/app/apply-job-secrets.sh
new file mode 100755
index 00000000000..544050f6ac9
--- /dev/null
+++ b/infra/selfhost/app/apply-job-secrets.sh
@@ -0,0 +1,59 @@
+#!/bin/bash
+# apply-job-secrets.sh -- goodqa#16148 spec v4 AC-11 (lead rulings R3, R4). Runs on the release runner.
+#
+#   RW_LANE_ROOT=<lane root> infra/selfhost/app/apply-job-secrets.sh --check | apply | restore
+#
+# Under the one deploy lock rw-ship.sh takes (<lane root>/locks/gq-promote.lock; flock -n, exit 75 when held) and
+# never while a release is in flight (gq-promote.inflight.json present, exit 75), it streams two scripts to the app
+# VM as root, exactly as rw-ship streams selfhost-ctl.py (nothing is installed on the VM):
+#   1. derive-job-secrets.py: creates the goodqa-jobsecret group, the 0711 secrets dir and the 0440 file from
+#      api.env. Anything but `written` or `unchanged` stops here with nothing else applied (exit 2).
+#   2. apply-job-secrets-host.py: the job-dispatcher mount and group_add in the live compose.yaml and the
+#      JOB_ENVFILE key line in dispatcher.env (backups, validation, marked-line restore).
+# A mutating run bumps the deploy epoch, so an rw-ship run that started earlier loses its authority (fencing).
+# Containers are not recreated: the next release's dispatcher recreate picks the mount up.
+# Output: the VM's status lines (names and status only; no value is ever read here). APPLY_SSH overrides ssh (tests).
+set -uo pipefail
+LOCK_REL=locks/gq-promote.lock
+HERE="$(cd "$(dirname "$0")" && pwd)"
+say(){ printf 'apply-job-secrets: %s\n' "$*"; }
+MODE="${1:-}"
+case "$MODE" in --check|apply|restore) ;; *) say "REFUSED usage: apply-job-secrets.sh --check|apply|restore"; exit 2;; esac
+S="${RW_LANE_ROOT:-}"
+[ -n "$S" ] && [ -d "$S" ] || { say "REFUSED: RW_LANE_ROOT is not set to the lane root"; exit 2; }
+case "$(realpath -m "$S")/" in */.scratch/*|/tmp/*) [ "${APPLY_TEST_MODE:-}" = 1 ] || { say "REFUSED: runner root must be permanent"; exit 2; };; esac
+shconf(){ sed -n "s/^$1=//p" "$S/biz/release-waves/ship.conf" 2>/dev/null | head -1; }
+APP="$(shconf SELFHOST_APP)"; DIR="$(shconf SELFHOST_DIR)"; ENVD="$(shconf SELFHOST_ENV_DIR)"
+DIR="${DIR:-/opt/goodqa/infra/selfhost/app}"; ENVD="${ENVD:-/etc/goodqa}"
+[ -n "$APP" ] || { say "REFUSED: SELFHOST_APP is not set in biz/release-waves/ship.conf"; exit 2; }
+SSH="${APPLY_SSH:-ssh}"
+LOCKF="$S/$LOCK_REL"; EPOCHF="${LOCKF%.lock}.epoch"; INFL="${LOCKF%.lock}.inflight.json"; HOLDER="${LOCKF%.lock}.holder"
+mkdir -p "$(dirname "$LOCKF")"
+exec 8>>"$LOCKF" || { say "REFUSED: cannot open the deploy lock $LOCKF"; exit 2; }
+flock -n 8 || { say "REFUSED: the deploy lock is held ($(head -c 200 "$HOLDER" 2>/dev/null | tr '\n' ' ')): nothing done"; exit 75; }
+[ -e "$INFL" ] && { say "REFUSED: a release is in flight ($INFL): nothing done"; exit 75; }
+if [ "$MODE" != --check ]; then
+  E0=$(tr -dc 0-9 < "$EPOCHF" 2>/dev/null); EPOCH=$(( ${E0:-0} + 1 ))
+  printf '%s\n' "$EPOCH" > "$EPOCHF.$$" && mv -f "$EPOCHF.$$" "$EPOCHF"
+  printf 'apply-job-secrets pid=%s host=%s started=%s epoch=%s what=%s\n' "$$" "$(hostname)" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$EPOCH" "$MODE" > "$HOLDER"
+  trap 'grep -q "^apply-job-secrets pid=$$ " "$HOLDER" 2>/dev/null && rm -f "$HOLDER"' EXIT
+fi
+vm(){ "$SSH" -o ConnectTimeout=15 -o BatchMode=yes -o ServerAliveInterval=30 "$APP" "$1" < "$2"; }
+case "$MODE" in
+  --check)
+    vm "sudo python3 -I - --check" "$HERE/derive-job-secrets.py"
+    printf -v CMD 'sudo python3 -I - --dir %q --env-dir %q --check' "$DIR" "$ENVD"
+    vm "$CMD" "$HERE/apply-job-secrets-host.py"; exit $?;;
+  apply)
+    OUT=$(vm "sudo python3 -I -" "$HERE/derive-job-secrets.py" 2>/dev/null); RC=$?
+    printf '%s\n' "$OUT" | head -3
+    case "$RC:$OUT" in
+      "0:job secret github-app-private-key: written"|"0:job secret github-app-private-key: unchanged") ;;
+      *) say "REFUSED: derive did not report written or unchanged (rc $RC): nothing else applied"; exit 2;;
+    esac
+    printf -v CMD 'sudo python3 -I - --dir %q --env-dir %q apply --stamp %q' "$DIR" "$ENVD" "$(date -u +%Y%m%dT%H%M%SZ)"
+    vm "$CMD" "$HERE/apply-job-secrets-host.py"; exit $?;;
+  restore)
+    printf -v CMD 'sudo python3 -I - --dir %q --env-dir %q restore' "$DIR" "$ENVD"
+    vm "$CMD" "$HERE/apply-job-secrets-host.py"; exit $?;;
+esac
diff --git a/infra/selfhost/app/cmdline-sampler.py b/infra/selfhost/app/cmdline-sampler.py
new file mode 100755
index 00000000000..a667806f3a0
--- /dev/null
+++ b/infra/selfhost/app/cmdline-sampler.py
@@ -0,0 +1,132 @@
+#!/usr/bin/env python3
+"""cmdline-sampler.py -- goodqa#16148 spec v4 AC-6 (3), NEG-18 (build conditions P2, R6).
+
+A read-only, unprivileged, post-deploy check that no docker CLI started by the job-dispatcher carries a job env value
+on its command line (/proc/PID/cmdline is world-readable in the host PID namespace). It looks only at processes
+whose /proc/PID/cgroup names the job-dispatcher container (`--container ID`, resolved by the caller at sample time),
+polls about every 50 ms for `--seconds`, and keeps only flag NAMES and the argv length of each `docker run`:
+  * a long flag is cut at its first `=`, and kept only if it is on the allow-list, else recorded as `--(other)`;
+  * a short flag with an attached value (`-eK=V`) is recorded as `-e(attached)`; others as `-x` if allow-listed;
+    a cluster is read as pflag reads it, so `-de` and `-ieK=V` record `-e(cluster)`;
+  * a non-flag token is only counted. Raw argv is never stored, printed or written.
+Result (one JSON line): verdict PASS | FAIL | NO_SAMPLE, label "sampled" (not exhaustive). FAIL: any observed run has
+-e, -e(attached), -e(cluster), --env or --env(attached). NO_SAMPLE (also a failure): fewer than `--expect-runs` runs seen, so a
+silent sampler can never pass. Exit 0 only on PASS.
+  python3 -I cmdline-sampler.py --container <64-hex id> --seconds 120 --expect-runs 3
+"""
+import argparse
+import json
+import os
+import re
+import sys
+import time
+
+ALLOWED_LONG = {'--rm', '--env-file', '--env', '--cap-drop', '--security-opt', '--read-only', '--tmpfs', '--memory',
+                '--memory-swap', '--cpus', '--pids-limit', '--detach', '--name', '--label', '--network', '--user'}
+ALLOWED_SHORT = {'-d', '-e', '-i', '-t', '-u'}
+# docker run's boolean shorthands: pflag lets these cluster (-dit), and any other shorthand takes the rest as its value.
+BOOL_SHORT = set('ditP')
+BAD = {'-e', '-e(attached)', '-e(cluster)', '--env', '--env(attached)'}
+ID_RE = re.compile(r'^[0-9a-f]{12,64}$')
+
+
+def sanitize(argv):
+    """Flag names only. argv[0] is the docker binary; argv[1] must be `run`."""
+    flags = []
+    for tok in argv[2:]:
+        if tok.startswith('--'):
+            name, eq, _ = tok.partition('=')
+            if name not in ALLOWED_LONG:
+                name = '--(other)'
+            flags.append(name + ('(attached)' if eq and name in ('--env',) else ''))
+        elif tok.startswith('-') and len(tok) >= 2:
+            flags.append(short_flag(tok))
+    return {'argc': len(argv), 'flags': flags}
+
+
+def short_flag(tok):
+    """A single-dash token, read the way pflag reads a shorthand cluster (code review F3): booleans chain, `e` anywhere
+    in the chain is an env flag (-de, -ieK=V), and the first value-taking shorthand ends the chain."""
+    short = tok[:2]
+    if len(tok) == 2:
+        return short if short in ALLOWED_SHORT else '-(other)'
+    for i, c in enumerate(tok[1:]):
+        if c == 'e':
+            return '-e(attached)' if i == 0 else '-e(cluster)'
+        if c not in BOOL_SHORT:
+            break
+    return (short if short in ALLOWED_SHORT else '-(other)') + '(attached)'
+
+
+def in_container(cgroup_text, container):
+    return any(('docker-%s.scope' % container) in l or ('/docker/%s' % container) in l for l in cgroup_text.splitlines())
+
+
+def scan(proc, container, seen, runs):
+    try:
+        pids = [p for p in os.listdir(proc) if p.isdigit()]
+    except OSError:
+        return
+    for pid in pids:
+        base = os.path.join(proc, pid)
+        try:
+            with open(os.path.join(base, 'cgroup')) as f:
+                if not in_container(f.read(), container):
+                    continue
+            with open(os.path.join(base, 'cmdline'), 'rb') as f:
+                raw = f.read()
+            try:
+                with open(os.path.join(base, 'stat')) as f:
+                    start = f.read().rsplit(')', 1)[-1].split()[19]
+            except (OSError, IndexError):
+                start = ''
+        except OSError:
+            continue
+        key = (pid, start)
+        if key in seen:
+            continue
+        argv = [a.decode('utf-8', 'replace') for a in raw.split(b'\0') if a]
+        if len(argv) >= 2 and os.path.basename(argv[0]) == 'docker' and argv[1] == 'run':
+            seen.add(key)
+            runs.append(sanitize(argv))
+        del argv, raw
+
+
+def run(argv):
+    p = argparse.ArgumentParser(prog='cmdline-sampler.py')
+    p.add_argument('--container', required=True)
+    p.add_argument('--seconds', type=float, default=60.0)
+    p.add_argument('--expect-runs', type=int, default=1)
+    p.add_argument('--interval', type=float, default=0.05)
+    p.add_argument('--proc', default='/proc')
+    a = p.parse_args(argv)
+    if not ID_RE.match(a.container):
+        return {'verdict': 'FAIL', 'label': 'sampled', 'error': 'container id must be 12-64 lowercase hex'}, 1
+    seen, runs = set(), []
+    end = time.monotonic() + a.seconds
+    polls = 0
+    while time.monotonic() < end and len(runs) < max(a.expect_runs, 1) * 10:
+        scan(a.proc, a.container, seen, runs)
+        polls += 1
+        time.sleep(a.interval)
+    bad = [r for r in runs if BAD.intersection(r['flags'])]
+    if len(runs) < a.expect_runs:
+        verdict = 'NO_SAMPLE'
+    elif bad:
+        verdict = 'FAIL'
+    else:
+        verdict = 'PASS'
+    out = {'verdict': verdict, 'label': 'sampled', 'runs_seen': len(runs), 'expect_runs': a.expect_runs, 'polls': polls,
+           'runs_with_env_file': sum(1 for r in runs if '--env-file' in r['flags']), 'runs_with_env_flag': len(bad),
+           'runs': runs}
+    return out, 0 if verdict == 'PASS' else 1
+
+
+def main():
+    out, code = run(sys.argv[1:])
+    sys.stdout.write(json.dumps(out, sort_keys=True) + '\n')
+    return code
+
+
+if __name__ == '__main__':
+    sys.exit(main())
diff --git a/infra/selfhost/app/compose.yaml b/infra/selfhost/app/compose.yaml
index 2bf2999c2fd..1858d5cad2d 100644
--- a/infra/selfhost/app/compose.yaml
+++ b/infra/selfhost/app/compose.yaml
@@ -120,6 +120,8 @@ services:
     # dispatch-app reaches the guard only; edge lets the api call it. No route to the proxy.
     networks: [dispatch-app, edge]
     mem_limit: 384m
+    group_add: ["64910"] # goodqa#16148 AC-11
+    volumes: ["/etc/goodqa/job-secrets:/run/goodqa-secrets:ro"] # goodqa#16148 AC-11
 
 networks:
   edge: {}
diff --git a/infra/selfhost/app/derive-job-secrets.py b/infra/selfhost/app/derive-job-secrets.py
new file mode 100755
index 00000000000..d2c3cde6090
--- /dev/null
+++ b/infra/selfhost/app/derive-job-secrets.py
@@ -0,0 +1,336 @@
+#!/usr/bin/env python3
+"""derive-job-secrets.py -- goodqa#16148 spec v4 AC-1, AC-2, AC-9.
+
+Run as root on the self-host app VM, as `python3 -I derive-job-secrets.py [--check]`. It derives
+/etc/goodqa/job-secrets/github-app-private-key (root:goodqa-jobsecret 0440, in a root:root 0711
+directory) from the GITHUB_APP_PRIVATE_KEY line of /etc/goodqa/api.env. Only the job-dispatcher
+mounts that directory (read-only, group_add 64910), and the dispatcher reads the file per launch
+(JOB_ENVFILE_INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY).
+
+Output is exactly one line, never the value:
+    job secret github-app-private-key: written | unchanged | REFUSED <reason>
+    job secret github-app-private-key: same | different | REFUSED <reason>        (--check)
+Exit 0 on written/unchanged/same/different, 2 on REFUSED.
+
+Parsing matches Docker Compose 5.6.0 `env_file: format: raw` (probed with fake values):
+  - `#` lines are comments; leading whitespace before the key is dropped;
+  - a line splits on its first `=`; the value is verbatim (quotes, trailing spaces, inner `#` kept);
+  - a final CR is stripped; a key holding whitespace (an `export KEY=` line) makes compose refuse.
+derive is stricter: it refuses no line, more than one line, an `export` form, an empty value, a
+value byte outside printable ASCII 0x20-0x7E, and any line compose itself would refuse.
+
+The value is written byte for byte (no decoding). Every write is relative to a directory fd that
+was opened O_DIRECTORY|O_NOFOLLOW and checked with fstat; the file is created under a random
+temp name with O_CREAT|O_EXCL|O_NOFOLLOW, fchown/fchmod on the fd, written, fsynced, renamed
+within the directory fd, and the directory is fsynced. An unchanged value leaves the file alone.
+The value never appears in argv, output, a log or a hash.
+"""
+import os
+import secrets
+import subprocess
+import sys
+
+NAME = 'github-app-private-key'
+SOURCE_KEY = 'GITHUB_APP_PRIVATE_KEY'
+GROUP = 'goodqa-jobsecret'
+GID = 64910
+DIR_MODE = 0o711
+FILE_MODE = 0o440
+MAX_SOURCE = 1024 * 1024
+
+
+class Refused(Exception):
+    pass
+
+
+def _p(root, path):
+    return os.path.join(root, path.lstrip('/')) if root != '/' else path
+
+
+# ---- AC-1: parse ----------------------------------------------------------------------------
+def parse_api_env(data):
+    """Return the GITHUB_APP_PRIVATE_KEY value (bytes) exactly as compose would deliver it, or raise Refused."""
+    found = []
+    for raw in data.split(b'\n'):
+        line = raw[:-1] if raw.endswith(b'\r') else raw
+        stripped = line.lstrip(b' \t')
+        if stripped == b'' or stripped.startswith(b'#'):
+            continue
+        key, eq, value = stripped.partition(b'=')
+        if not eq:
+            if any(c in key for c in b' \t'):
+                raise Refused('api.env has a line compose would refuse')
+            continue
+        if key.split()[:2] == [b'export', SOURCE_KEY.encode()] or key.startswith(b'export ' + SOURCE_KEY.encode()):
+            raise Refused('export form')
+        if any(c in key for c in b' \t\x0b\x0c'):
+            raise Refused('api.env has a line compose would refuse')
+        if key == SOURCE_KEY.encode():
+            found.append(value)
+    if not found:
+        raise Refused('no GITHUB_APP_PRIVATE_KEY line')
+    if len(found) > 1:
+        raise Refused('more than one GITHUB_APP_PRIVATE_KEY line')
+    value = found[0]
+    if value == b'':
+        raise Refused('empty value')
+    if any(b < 0x20 or b > 0x7e for b in value):
+        raise Refused('value holds a byte outside printable ASCII')
+    return value
+
+
+def read_source(root):
+    path = _p(root, '/etc/goodqa/api.env')
+    try:
+        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
+    except OSError:
+        raise Refused('api.env unreadable')
+    try:
+        st = os.fstat(fd)
+        if not _is_reg(st.st_mode):
+            raise Refused('api.env is not a regular file')
+        chunks, total = [], 0
+        while True:
+            b = os.read(fd, 65536)
+            if not b:
+                break
+            total += len(b)
+            if total > MAX_SOURCE:
+                raise Refused('api.env too large')
+            chunks.append(b)
+        return b''.join(chunks)
+    finally:
+        os.close(fd)
+
+
+def _is_reg(mode):
+    import stat
+    return stat.S_ISREG(mode)
+
+
+def _is_dir(mode):
+    import stat
+    return stat.S_ISDIR(mode)
+
+
+# ---- AC-2: the group (files and NSS) --------------------------------------------------------
+def _group_rows(text):
+    rows = []
+    for line in text.splitlines():
+        parts = line.split(':')
+        if len(parts) >= 4 and parts[0] and parts[2].isdigit():
+            rows.append((parts[0], int(parts[2]), [m for m in parts[3].split(',') if m]))
+    return rows
+
+
+def _passwd_primary_gids(text):
+    out = []
+    for line in text.splitlines():
+        parts = line.split(':')
+        if len(parts) >= 4 and parts[3].isdigit():
+            out.append((parts[0], int(parts[3])))
+    return out
+
+
+def _read_text(path):
+    try:
+        with open(path, 'r', encoding='utf-8', errors='replace') as f:
+            return f.read()
+    except FileNotFoundError:
+        return ''
+
+
+def _getent(*args):
+    try:
+        r = subprocess.run(['getent', *args], capture_output=True, text=True, timeout=10)
+    except (OSError, subprocess.TimeoutExpired):
+        raise Refused('getent failed')
+    if r.returncode == 2:
+        return ''
+    if r.returncode != 0:
+        raise Refused('getent failed')
+    return r.stdout
+
+
+def check_group(root):
+    """Return True if the group exists correctly, False if absent; raise Refused on any collision."""
+    sources = [_read_text(_p(root, '/etc/group')), _getent('group', GROUP) + _getent('group', str(GID))]
+    present = False
+    for text in sources:
+        for name, gid, members in _group_rows(text):
+            if name == GROUP and gid != GID:
+                raise Refused('group name goodqa-jobsecret has another gid')
+            if gid == GID and name != GROUP:
+                raise Refused('gid 64910 has another name')
+            if name == GROUP and gid == GID:
+                if members:
+                    raise Refused('group goodqa-jobsecret has members')
+                present = True
+    for text in (_read_text(_p(root, '/etc/passwd')), _getent('passwd')):
+        for _user, gid in _passwd_primary_gids(text):
+            if gid == GID:
+                raise Refused('an account has gid 64910 as its primary group')
+    return present
+
+
+def ensure_group(root):
+    if check_group(root):
+        return
+    cmd = ['groupadd', '-r', '-g', str(GID), GROUP]
+    if root != '/':
+        cmd[1:1] = ['-R', root]
+    try:
+        r = subprocess.run(cmd, capture_output=True, timeout=30)
+    except (OSError, subprocess.TimeoutExpired):
+        raise Refused('groupadd failed')
+    if r.returncode != 0:
+        raise Refused('groupadd failed')
+    if not check_group(root):
+        raise Refused('group not present after groupadd')
+
+
+# ---- AC-2: directory and file ---------------------------------------------------------------
+def _check_parent(root):
+    parent = _p(root, '/etc/goodqa')
+    try:
+        pfd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
+    except OSError:
+        raise Refused('/etc/goodqa is missing, a symlink or not a directory')
+    st = os.fstat(pfd)
+    if st.st_uid != 0 or st.st_mode & 0o022:
+        os.close(pfd)
+        raise Refused('/etc/goodqa is not root-owned or is group or world writable')
+    return pfd
+
+
+def open_secrets_dir(root, create):
+    pfd = _check_parent(root)
+    try:
+        try:
+            dfd = os.open('job-secrets', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=pfd)
+        except FileNotFoundError:
+            if not create:
+                return None
+            os.mkdir('job-secrets', 0o700, dir_fd=pfd)
+            dfd = os.open('job-secrets', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=pfd)
+            os.fchown(dfd, 0, 0)
+            os.fchmod(dfd, DIR_MODE)
+            os.fsync(pfd)
+        except OSError:
+            raise Refused('job-secrets is a symlink or not a directory')
+        st = os.fstat(dfd)
+        if not _is_dir(st.st_mode) or st.st_uid != 0 or st.st_gid != 0 or (st.st_mode & 0o7777) != DIR_MODE:
+            os.close(dfd)
+            raise Refused('job-secrets has another owner, mode or type')
+        return dfd
+    finally:
+        os.close(pfd)
+
+
+def read_existing(dfd):
+    """The current file's bytes, None if absent; refuse a link, a non-regular file or wrong owner/mode."""
+    try:
+        fd = os.open(NAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dfd)
+    except FileNotFoundError:
+        return None
+    except OSError:
+        raise Refused('the secret file is a symlink or unreadable')
+    try:
+        st = os.fstat(fd)
+        if not _is_reg(st.st_mode) or st.st_uid != 0 or st.st_gid != GID or (st.st_mode & 0o7777) != FILE_MODE:
+            raise Refused('the secret file has another owner, mode or type')
+        chunks = []
+        while True:
+            b = os.read(fd, 65536)
+            if not b:
+                break
+            chunks.append(b)
+        return b''.join(chunks)
+    finally:
+        os.close(fd)
+
+
+def sweep_temps(dfd):
+    for entry in os.listdir(dfd):
+        if entry.startswith('.tmp-'):
+            os.unlink(entry, dir_fd=dfd)
+
+
+def write_secret(dfd, value, hooks):
+    tmp = '.tmp-' + secrets.token_hex(8)
+    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dfd)
+    try:
+        # The fd stays open until the check after the rename, so its inode cannot be freed and
+        # its number reused by a swapped-in link.
+        own = os.fstat(fd)
+        os.fchown(fd, 0, GID)
+        os.fchmod(fd, FILE_MODE)
+        view = memoryview(value)
+        while view:
+            n = os.write(fd, view)
+            view = view[n:]
+        os.fsync(fd)
+        if hooks and hooks.get('before_rename'):
+            hooks['before_rename'](tmp)
+        os.rename(tmp, NAME, src_dir_fd=dfd, dst_dir_fd=dfd)
+        os.fsync(dfd)
+        # The name must now be the very inode this run wrote through its fd (never a swapped-in link).
+        now = os.stat(NAME, dir_fd=dfd, follow_symlinks=False)
+        if not _is_reg(now.st_mode) or (now.st_dev, now.st_ino) != (own.st_dev, own.st_ino):
+            # The rename already put the foreign file or link at NAME: remove that name (never what it points
+            # to), so the dispatcher sees the key as missing instead of using it (code review F2).
+            try:
+                os.unlink(NAME, dir_fd=dfd)
+            except FileNotFoundError:
+                pass
+            raise Refused('the secret file changed during the write')
+    except BaseException:
+        try:
+            os.unlink(tmp, dir_fd=dfd)
+        except OSError:
+            pass
+        raise
+    finally:
+        os.close(fd)
+
+
+def run(argv, root='/', hooks=None):
+    check = argv == ['--check']
+    if argv not in ([], ['--check']):
+        return 'REFUSED usage: derive-job-secrets.py [--check]', 2
+    try:
+        value = parse_api_env(read_source(root))
+        if check:
+            check_group(root)
+            dfd = open_secrets_dir(root, create=False)
+            if dfd is None:
+                return 'different', 0
+            try:
+                return ('same' if read_existing(dfd) == value else 'different'), 0
+            finally:
+                os.close(dfd)
+        ensure_group(root)
+        dfd = open_secrets_dir(root, create=True)
+        try:
+            sweep_temps(dfd)
+            if read_existing(dfd) == value:
+                return 'unchanged', 0
+            write_secret(dfd, value, hooks)
+            return 'written', 0
+        finally:
+            os.close(dfd)
+    except Refused as e:
+        return 'REFUSED ' + str(e), 2
+    except OSError as e:
+        return 'REFUSED os error (%s)' % (type(e).__name__,), 2
+
+
+def main(root='/'):
+    # The CLI always works on the real root; tests import this module and pass a fake root.
+    word, code = run(sys.argv[1:], root=root)
+    sys.stdout.write('job secret %s: %s\n' % (NAME, word))
+    return code
+
+
+if __name__ == '__main__':
+    sys.exit(main())
diff --git a/infra/selfhost/app/env-keys.json b/infra/selfhost/app/env-keys.json
index d6ec9a98301..4072b0c4ee6 100644
--- a/infra/selfhost/app/env-keys.json
+++ b/infra/selfhost/app/env-keys.json
@@ -137,6 +137,7 @@
     "AI_SPEND_SDK_PRICES_JSON",
     "GOOGLE_APPLICATION_CREDENTIALS_JSON",
     "JOB_DISPATCH_TOKEN",
+    "JOB_ENVFILE_INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY",
     "JOB_ENV_INTELLIGENCE_WORKER__DATABASE_URL",
     "JOB_ENV_INTELLIGENCE_WORKER__NODE_ENV",
     "JOB_ENV_INTELLIGENCE_WORKER__OPENROUTER_API_KEY",
diff --git a/infra/selfhost/app/run_derive_tests.sh b/infra/selfhost/app/run_derive_tests.sh
new file mode 100755
index 00000000000..bae9d99e023
--- /dev/null
+++ b/infra/selfhost/app/run_derive_tests.sh
@@ -0,0 +1,16 @@
+#!/bin/bash
+# goodqa#16148: run the derive-job-secrets.py and apply-job-secrets-host.py tests. Parse and compose-parity tests run on this
+# host (needs the docker compose CLI); the ownership tests need root and run in a throwaway
+# container (--rm, --network none, this directory read-only, a scratch dir for fake roots).
+# Fake values only. Usage: infra/selfhost/app/run_derive_tests.sh [SCRATCH_DIR]
+set -euo pipefail
+HERE="$(cd "$(dirname "$0")" && pwd)"
+SCRATCH="${1:-$HERE/../../../.scratch/derive-tests}"
+IMAGE="${DERIVE_TEST_IMAGE:-python:3.12-slim}"
+mkdir -p "$SCRATCH"
+SCRATCH="$(cd "$SCRATCH" && pwd)"
+echo "== host: parse + compose parity"
+( cd "$HERE" && DERIVE_TEST_TMP="$SCRATCH" timeout 600 python3 -m unittest -v test_derive_job_secrets test_apply_job_secrets_host 2>&1 | tail -n 30 )
+echo "== container (root): ownership, races, NEG-1/2/3/13, no value in output or argv"
+docker run --rm --network none -v "$HERE:/t:ro" -v "$SCRATCH:/scratch" -e DERIVE_TEST_TMP=/scratch -w /t \
+  "$IMAGE" timeout 600 python3 -m unittest -v test_derive_job_secrets test_apply_job_secrets_host 2>&1 | tail -n 30
diff --git a/infra/selfhost/app/test_apply_job_secrets_host.py b/infra/selfhost/app/test_apply_job_secrets_host.py
new file mode 100644
index 00000000000..0336fbcde18
--- /dev/null
+++ b/infra/selfhost/app/test_apply_job_secrets_host.py
@@ -0,0 +1,296 @@
+"""goodqa#16148 spec v4 AC-11, NEG-14, NEG-15 and build conditions R1, R2: apply-job-secrets-host.py.
+
+Root-only (backups are root 0600 via fchown): run_derive_tests.sh runs this in the throwaway
+container next to the derive tests. Fake host trees only; stub getent and docker on PATH.
+"""
+import importlib.util
+import os
+import shutil
+import stat
+import tempfile
+import time
+import unittest
+
+HERE = os.path.dirname(os.path.abspath(__file__))
+spec = importlib.util.spec_from_file_location('apply_host', os.path.join(HERE, 'apply-job-secrets-host.py'))
+ah = importlib.util.module_from_spec(spec)
+spec.loader.exec_module(ah)
+IS_ROOT = os.geteuid() == 0
+
+COMPOSE = '''services:
+  api:
+    image: goodqa-api:abc # rw-ship abc
+    env_file:
+      - path: /etc/goodqa/api.env
+        format: raw
+  job-dispatcher:
+    <<: *hardening
+    image: goodqa-job-dispatcher:abc-1 # rw-ship abc 1
+    read_only: true
+    tmpfs: ["/tmp"]
+    env_file:
+      - path: /etc/goodqa/dispatcher.env
+        format: raw
+    networks: [dispatch-app, edge]
+    mem_limit: 384m
+
+  job-dispatcher-create-guard:
+    image: goodqa-job-dispatcher:abc-1
+    group_add: ["999"]
+
+networks:
+  edge: {}
+'''
+ENV = b'JOB_DISPATCH_TOKEN=fake-token\nJOB_ENV_SCAN__NODE_ENV=production\n'
+
+STUB_GETENT = '''#!/bin/sh
+f="$FAKE_ROOT/nss-group"; [ -f "$f" ] || exit 2
+grep -E "^($2):|^[^:]*:[^:]*:($2):" "$f" || exit 2
+'''
+STUB_DOCKER = '''#!/bin/sh
+echo "$*" >> "$FAKE_ROOT/docker.log"
+[ -f "$FAKE_ROOT/compose-invalid" ] && exit 1
+exit 0
+'''
+
+
+@unittest.skipUnless(IS_ROOT, 'needs root (backups are root 0600): runs in the throwaway container')
+class HostApplyTests(unittest.TestCase):
+    def setUp(self):
+        self.root = tempfile.mkdtemp(prefix='apply-root-', dir=os.environ.get('DERIVE_TEST_TMP'))
+        self.dir = os.path.join(self.root, 'opt/goodqa/infra/selfhost/app')
+        self.env_dir = os.path.join(self.root, 'etc/goodqa')
+        os.makedirs(self.dir)
+        os.makedirs(self.env_dir, mode=0o700)
+        with open(self.p('compose'), 'w') as f:
+            f.write(COMPOSE)
+        os.chown(self.p('compose'), 1000, 1000)
+        os.chmod(self.p('compose'), 0o664)
+        with open(self.p('env'), 'wb') as f:
+            f.write(ENV)
+        os.chmod(self.p('env'), 0o600)
+        bin_dir = os.path.join(self.root, 'bin')
+        os.makedirs(bin_dir)
+        for n, body in (('getent', STUB_GETENT), ('docker', STUB_DOCKER)):
+            with open(os.path.join(bin_dir, n), 'w') as f:
+                f.write(body)
+            os.chmod(os.path.join(bin_dir, n), 0o755)
+        self.saved = dict(os.environ)
+        os.environ['PATH'] = bin_dir + ':' + os.environ['PATH']
+        os.environ['FAKE_ROOT'] = self.root
+
+    def tearDown(self):
+        os.environ.clear()
+        os.environ.update(self.saved)
+        shutil.rmtree(self.root, ignore_errors=True)
+
+    def p(self, which):
+        return {'compose': os.path.join(self.dir, 'compose.yaml'), 'env': os.path.join(self.env_dir, 'dispatcher.env')}[which]
+
+    def read(self, which):
+        with open(self.p(which), 'rb') as f:
+            return f.read()
+
+    def derive_done(self):
+        """What derive-job-secrets.py leaves: the group (seen through NSS) and the 0711 directory."""
+        with open(os.path.join(self.root, 'nss-group'), 'w') as f:
+            f.write('goodqa-jobsecret:x:64910:\n')
+        d = os.path.join(self.env_dir, 'job-secrets')
+        os.mkdir(d)
+        os.chown(d, 0, 0)
+        os.chmod(d, 0o711)
+
+    def run_cmd(self, *argv, hooks=None):
+        return ah.run(['--dir', self.dir, '--env-dir', self.env_dir, *argv], hooks=hooks)
+
+    def check(self):
+        lines, code = self.run_cmd('--check')
+        self.assertEqual(code, 0)
+        return dict(l.rsplit(': ', 1) for l in lines)
+
+    # ---- AC-11 ----
+    def test_check_on_a_fresh_host(self):
+        self.assertEqual(set(self.check().values()), {'absent'})
+
+    def test_apply_refuses_before_derive(self):
+        lines, code = self.run_cmd('apply', '--stamp', '20261116T030000Z')
+        self.assertEqual(code, 2)
+        self.assertIn('derive-job-secrets.py must run first', lines[0])
+        self.assertEqual(self.read('compose'), COMPOSE.encode())
+        self.assertEqual(self.read('env'), ENV)
+
+    def test_apply_then_apply_again_then_restore(self):
+        self.derive_done()
+        cst0 = os.stat(self.p('compose'))
+        self.assertEqual(self.run_cmd('apply', '--stamp', '20261116T030000Z'), (['job secrets host apply: applied'], 0))
+        self.assertEqual(set(self.check().values()), {'present'})
+        comp = self.read('compose').decode()
+        block = comp[comp.index('  job-dispatcher:\n'):comp.index('  job-dispatcher-create-guard:')]
+        self.assertIn(ah.GROUP_LINE + '\n', block)
+        self.assertIn(ah.VOL_LINE + '\n', block)
+        self.assertTrue(self.read('env').endswith(ah.ENV_LINE.encode() + b'\n'))
+        cst = os.stat(self.p('compose'))
+        self.assertEqual((cst.st_uid, cst.st_gid, stat.S_IMODE(cst.st_mode)), (cst0.st_uid, cst0.st_gid, 0o664))
+        for which, orig in (('compose', COMPOSE.encode()), ('env', ENV)):
+            b = self.p(which) + '.pre-16148-20261116T030000Z'
+            bst = os.lstat(b)
+            self.assertEqual((bst.st_uid, bst.st_gid, stat.S_IMODE(bst.st_mode)), (0, 0, 0o600))
+            with open(b, 'rb') as f:
+                self.assertEqual(f.read(), orig)
+        m = (os.stat(self.p('compose')).st_mtime_ns, os.stat(self.p('env')).st_mtime_ns)
+        time.sleep(0.02)
+        self.assertEqual(self.run_cmd('apply', '--stamp', '20261116T030100Z'), (['job secrets host apply: unchanged'], 0))
+        self.assertEqual((os.stat(self.p('compose')).st_mtime_ns, os.stat(self.p('env')).st_mtime_ns), m)
+        self.assertFalse(os.path.exists(self.p('env') + '.pre-16148-20261116T030100Z'))
+        self.assertEqual(self.run_cmd('restore'), (['job secrets host restore: restored'], 0))
+        self.assertEqual(self.read('compose'), COMPOSE.encode())
+        self.assertEqual(self.read('env'), ENV)
+
+    def test_apply_validates_compose_with_docker(self):
+        self.derive_done()
+        self.run_cmd('apply', '--stamp', '20261116T030000Z')
+        log = open(os.path.join(self.root, 'docker.log')).read()
+        self.assertIn('compose -f %s/.compose.yaml.validate-' % self.dir, log)
+        self.assertIn('config -q', log)
+        self.assertEqual([e for e in os.listdir(self.dir) if 'validate' in e or '.tmp-' in e], [])
+
+    # ---- R1: restore keeps later changes ----
+    def test_restore_keeps_a_later_release_pin_and_a_later_env_key(self):
+        self.derive_done()
+        self.run_cmd('apply', '--stamp', '20261116T030000Z')
+        comp = self.read('compose').decode().replace('goodqa-job-dispatcher:abc-1 # rw-ship abc 1', 'goodqa-job-dispatcher:def-2 # rw-ship def 2')
+        with open(self.p('compose'), 'w') as f:
+            f.write(comp)
+        with open(self.p('env'), 'ab') as f:
+            f.write(b'LATER_KEY=added-after\n')
+        self.assertEqual(self.run_cmd('restore')[1], 0)
+        self.assertEqual(self.read('compose'), COMPOSE.replace('abc-1 # rw-ship abc 1', 'def-2 # rw-ship def 2').encode())
+        self.assertEqual(self.read('env'), ENV + b'LATER_KEY=added-after\n')
+
+    def test_restore_refuses_a_changed_marked_line(self):
+        self.derive_done()
+        self.run_cmd('apply', '--stamp', '20261116T030000Z')
+        comp = self.read('compose').decode().replace('/run/goodqa-secrets:ro"]', '/run/goodqa-secrets:rw"]')
+        with open(self.p('compose'), 'w') as f:
+            f.write(comp)
+        lines, code = self.run_cmd('restore')
+        self.assertEqual(code, 2)
+        self.assertIn('marked line in compose.yaml was changed', lines[0])
+
+    # ---- NEG-14: partial apply ----
+    def test_neg14_stopped_between_files(self):
+        self.derive_done()
+
+        def stop():
+            raise KeyboardInterrupt('stopped between the two writes')
+
+        with self.assertRaises(KeyboardInterrupt):
+            self.run_cmd('apply', '--stamp', '20261116T030000Z', hooks={'between_files': stop})
+        st = self.check()
+        self.assertEqual(st['dispatcher.env ' + ah.ENV_KEY], 'present')
+        self.assertEqual(st['compose job-dispatcher mount'], 'absent')
+        self.assertEqual(st['compose job-dispatcher group_add'], 'absent')
+        self.assertEqual(self.read('compose'), COMPOSE.encode())
+        self.assertEqual(self.run_cmd('apply', '--stamp', '20261116T030500Z'), (['job secrets host apply: applied'], 0))
+        self.assertEqual(set(self.check().values()), {'present'})
+        self.assertEqual(self.run_cmd('restore')[1], 0)
+        self.assertEqual(self.read('compose'), COMPOSE.encode())
+        self.assertEqual(self.read('env'), ENV)
+
+    # ---- NEG-15: failed apply leaves everything ----
+    def test_neg15_invalid_compose_changes_nothing(self):
+        self.derive_done()
+        open(os.path.join(self.root, 'compose-invalid'), 'w').close()
+        lines, code = self.run_cmd('apply', '--stamp', '20261116T030000Z')
+        self.assertEqual(code, 2)
+        self.assertIn('does not validate', lines[0])
+        self.assertEqual(self.read('compose'), COMPOSE.encode())
+        self.assertEqual(self.read('env'), ENV)
+        self.assertEqual(sorted(os.listdir(self.dir)), ['compose.yaml'])
+        self.assertEqual(sorted(e for e in os.listdir(self.env_dir) if e != 'job-secrets'), ['dispatcher.env'])
+
+    def test_neg15_existing_backup_is_never_overwritten(self):
+        self.derive_done()
+        b = self.p('env') + '.pre-16148-20261116T030000Z'
+        with open(b, 'wb') as f:
+            f.write(b'earlier backup')
+        lines, code = self.run_cmd('apply', '--stamp', '20261116T030000Z')
+        self.assertEqual(code, 2)
+        with open(b, 'rb') as f:
+            self.assertEqual(f.read(), b'earlier backup')
+        self.assertEqual(self.read('compose'), COMPOSE.encode())
+        self.assertEqual(self.read('env'), ENV)
+
+    # ---- conflicts and unsafe paths ----
+    def _conflict(self, compose=None, env=None, expect=None):
+        self.derive_done()
+        if compose is not None:
+            with open(self.p('compose'), 'w') as f:
+                f.write(compose)
+        if env is not None:
+            with open(self.p('env'), 'wb') as f:
+                f.write(env)
+        before = (self.read('compose'), self.read('env'))
+        self.assertEqual(self.check()[expect], 'conflict')
+        lines, code = self.run_cmd('apply', '--stamp', '20261116T030000Z')
+        self.assertEqual(code, 2)
+        self.assertIn('conflict', lines[0])
+        self.assertEqual((self.read('compose'), self.read('env')), before)
+
+    def test_conflict_dispatcher_has_other_volumes(self):
+        self._conflict(compose=COMPOSE.replace('    mem_limit: 384m\n', '    mem_limit: 384m\n    volumes: ["/x:/y"]\n'), expect='compose job-dispatcher mount')
+
+    def test_conflict_other_service_mounts_the_secrets(self):
+        self._conflict(compose=COMPOSE.replace('    group_add: ["999"]\n', '    volumes: ["/etc/goodqa/job-secrets:/s:ro"]\n'), expect='compose job-dispatcher mount')
+
+    def test_conflict_env_key_with_another_value(self):
+        self._conflict(env=ENV + ah.ENV_KEY.encode() + b'=/elsewhere\n', expect='dispatcher.env ' + ah.ENV_KEY)
+
+    def test_conflict_dir_with_wrong_mode(self):
+        self.derive_done()
+        os.chmod(os.path.join(self.env_dir, 'job-secrets'), 0o755)
+        self.assertEqual(self.check()['dir /etc/goodqa/job-secrets'], 'conflict')
+        self.assertEqual(self.run_cmd('apply', '--stamp', '20261116T030000Z')[1], 2)
+
+    def test_symlinked_compose_is_refused(self):
+        self.derive_done()
+        real = os.path.join(self.root, 'real-compose.yaml')
+        os.rename(self.p('compose'), real)
+        os.symlink(real, self.p('compose'))
+        lines, code = self.run_cmd('apply', '--stamp', '20261116T030000Z')
+        self.assertEqual(code, 2)
+        self.assertIn('symlink', lines[0])
+        with open(real) as f:
+            self.assertEqual(f.read(), COMPOSE)
+
+    def test_symlinked_env_dir_is_refused(self):
+        lines, code = ah.run(['--dir', self.dir, '--env-dir', os.path.join(self.root, 'envlink'), '--check'])
+        self.assertEqual(code, 2)
+        os.symlink(self.env_dir, os.path.join(self.root, 'envlink'))
+        lines, code = ah.run(['--dir', self.dir, '--env-dir', os.path.join(self.root, 'envlink'), '--check'])
+        self.assertEqual(code, 2)
+        self.assertIn('symlink', lines[0])
+
+    # ---- R2: retention ----
+    def test_prune_keeps_the_newest_three_backups(self):
+        names = ['dispatcher.env.pre-16148-2026111%dT000000Z' % i for i in range(1, 6)]
+        for n in names:
+            with open(os.path.join(self.env_dir, n), 'w') as f:
+                f.write('b')
+        with open(os.path.join(self.env_dir, 'dispatcher.env.pre-16148-notastamp'), 'w') as f:
+            f.write('keep')
+        dfd = ah.open_dir(self.env_dir)
+        try:
+            ah.prune_backups(dfd, 'dispatcher.env')
+        finally:
+            os.close(dfd)
+        left = sorted(e for e in os.listdir(self.env_dir) if '.pre-16148-' in e)
+        self.assertEqual(left, sorted(names[2:] + ['dispatcher.env.pre-16148-notastamp']))
+
+    def test_usage(self):
+        self.assertEqual(self.run_cmd()[1], 2)
+        self.assertEqual(self.run_cmd('apply', '--stamp', 'bad')[1], 2)
+
+
+if __name__ == '__main__':
+    unittest.main()
diff --git a/infra/selfhost/app/test_apply_job_secrets_wrapper.py b/infra/selfhost/app/test_apply_job_secrets_wrapper.py
new file mode 100644
index 00000000000..fdf56d15bbf
--- /dev/null
+++ b/infra/selfhost/app/test_apply_job_secrets_wrapper.py
@@ -0,0 +1,147 @@
+"""goodqa#16148 spec v4 AC-11 with R3 and R4: apply-job-secrets.sh (runner side). A stub ssh records each call (its
+command and a sha256 of what was streamed on stdin) and answers from a script. No VM, no secrets.
+Run: python3 -m unittest -v test_apply_job_secrets_wrapper
+"""
+import fcntl
+import hashlib
+import os
+import shutil
+import subprocess
+import tempfile
+import unittest
+
+HERE = os.path.dirname(os.path.abspath(__file__))
+WRAPPER = os.path.join(HERE, 'apply-job-secrets.sh')
+
+
+def sha(path):
+    with open(path, 'rb') as f:
+        return hashlib.sha256(f.read()).hexdigest()
+
+
+STUB_SSH = r'''#!/usr/bin/env python3
+import hashlib, json, os, sys
+root = os.environ['STUB_ROOT']
+data = sys.stdin.buffer.read()
+cmd = sys.argv[-1]
+with open(os.path.join(root, 'calls.jsonl'), 'a') as f:
+    f.write(json.dumps({'argv': sys.argv[1:], 'cmd': cmd, 'stdin': hashlib.sha256(data).hexdigest()}) + '\n')
+derive = 'derive' if data.split(b'\n')[1].startswith(b'"""derive-job-secrets.py') else 'host'
+answer = open(os.path.join(root, 'answer-' + derive)).read() if os.path.exists(os.path.join(root, 'answer-' + derive)) else '0|ok'
+rc, out = answer.split('|', 1)
+sys.stdout.write(out + '\n')
+sys.exit(int(rc))
+'''
+
+
+class WrapperTests(unittest.TestCase):
+    def setUp(self):
+        self.root = tempfile.mkdtemp(prefix='apply-wrap-', dir=os.environ.get('DERIVE_TEST_TMP'))
+        self.lane = os.path.join(self.root, 'lane')
+        os.makedirs(os.path.join(self.lane, 'biz/release-waves'))
+        with open(os.path.join(self.lane, 'biz/release-waves/ship.conf'), 'w') as f:
+            f.write('SELFHOST_APP=ubuntu@app.invalid\nSELFHOST_DIR=/opt/goodqa/infra/selfhost/app\nSELFHOST_ENV_DIR=/etc/goodqa\n')
+        self.ssh = os.path.join(self.root, 'ssh')
+        with open(self.ssh, 'w') as f:
+            f.write(STUB_SSH)
+        os.chmod(self.ssh, 0o755)
+        self.answer('derive', '0|job secret github-app-private-key: written')
+        self.answer('host', '0|job secrets host apply: applied')
+
+    def tearDown(self):
+        shutil.rmtree(self.root, ignore_errors=True)
+
+    def answer(self, which, text):
+        with open(os.path.join(self.root, 'answer-' + which), 'w') as f:
+            f.write(text)
+
+    def run_wrapper(self, *args, env_extra=None):
+        env = dict(os.environ, RW_LANE_ROOT=self.lane, APPLY_SSH=self.ssh, STUB_ROOT=self.root, APPLY_TEST_MODE='1')
+        env.update(env_extra or {})
+        return subprocess.run(['bash', WRAPPER, *args], env=env, capture_output=True, text=True, timeout=60)
+
+    def calls(self):
+        p = os.path.join(self.root, 'calls.jsonl')
+        if not os.path.exists(p):
+            return []
+        import json
+        return [json.loads(l) for l in open(p)]
+
+    def lockf(self, suffix='.lock'):
+        return os.path.join(self.lane, 'locks', 'gq-promote' + suffix)
+
+    def test_apply_streams_derive_then_host_apply_under_the_lock(self):
+        r = self.run_wrapper('apply')
+        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
+        c = self.calls()
+        self.assertEqual(len(c), 2)
+        self.assertEqual(c[0]['stdin'], sha(os.path.join(HERE, 'derive-job-secrets.py')))
+        self.assertEqual(c[0]['cmd'], 'sudo python3 -I -')
+        self.assertEqual(c[1]['stdin'], sha(os.path.join(HERE, 'apply-job-secrets-host.py')))
+        self.assertRegex(c[1]['cmd'], r'^sudo python3 -I - --dir /opt/goodqa/infra/selfhost/app --env-dir /etc/goodqa apply --stamp \d{8}T\d{6}Z$')
+        self.assertIn('ubuntu@app.invalid', c[0]['argv'])
+        self.assertEqual(open(self.lockf('.epoch')).read().strip(), '1')
+        self.assertFalse(os.path.exists(self.lockf('.holder')), 'holder removed after the run')
+
+    def test_lock_held_refuses_with_75_and_calls_nothing(self):
+        os.makedirs(os.path.dirname(self.lockf()), exist_ok=True)
+        with open(self.lockf(), 'a') as f:
+            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
+            r = self.run_wrapper('apply')
+        self.assertEqual(r.returncode, 75, r.stdout)
+        self.assertIn('deploy lock is held', r.stdout)
+        self.assertEqual(self.calls(), [])
+
+    def test_release_in_flight_refuses_with_75(self):
+        os.makedirs(os.path.dirname(self.lockf()), exist_ok=True)
+        with open(self.lockf('.inflight.json'), 'w') as f:
+            f.write('{}')
+        for mode in ('apply', 'restore', '--check'):
+            r = self.run_wrapper(mode)
+            self.assertEqual(r.returncode, 75, mode + r.stdout)
+        self.assertEqual(self.calls(), [])
+
+    def test_derive_refused_stops_before_the_host_apply(self):
+        for answer in ('2|job secret github-app-private-key: REFUSED no GITHUB_APP_PRIVATE_KEY line',
+                       '0|job secret github-app-private-key: written\nextra line',
+                       '0|',
+                       '255|ssh: connect to host app.invalid: Connection refused'):
+            open(os.path.join(self.root, 'calls.jsonl'), 'w').close()
+            self.answer('derive', answer)
+            r = self.run_wrapper('apply')
+            self.assertEqual(r.returncode, 2, answer + r.stdout)
+            self.assertIn('nothing else applied', r.stdout)
+            self.assertEqual(len(self.calls()), 1, answer)
+
+    def test_check_is_read_only_and_does_not_bump_the_epoch(self):
+        r = self.run_wrapper('--check')
+        self.assertEqual(r.returncode, 0, r.stdout)
+        c = self.calls()
+        self.assertEqual(c[0]['cmd'], 'sudo python3 -I - --check')
+        self.assertTrue(c[1]['cmd'].endswith(' --check'))
+        self.assertFalse(os.path.exists(self.lockf('.epoch')))
+
+    def test_restore_streams_only_the_host_apply(self):
+        r = self.run_wrapper('restore')
+        self.assertEqual(r.returncode, 0, r.stdout)
+        c = self.calls()
+        self.assertEqual(len(c), 1)
+        self.assertTrue(c[0]['cmd'].endswith(' restore'))
+
+    def test_host_apply_failure_is_the_exit_code(self):
+        self.answer('host', '2|job secrets host apply: REFUSED conflict: dispatcher.env X')
+        r = self.run_wrapper('apply')
+        self.assertEqual(r.returncode, 2)
+
+    def test_refusals_without_config(self):
+        self.assertEqual(self.run_wrapper('bogus').returncode, 2)
+        self.assertEqual(self.run_wrapper('apply', env_extra={'RW_LANE_ROOT': ''}).returncode, 2)
+        os.unlink(os.path.join(self.lane, 'biz/release-waves/ship.conf'))
+        r = self.run_wrapper('apply')
+        self.assertEqual(r.returncode, 2)
+        self.assertIn('SELFHOST_APP is not set', r.stdout)
+        self.assertEqual(self.calls(), [])
+
+
+if __name__ == '__main__':
+    unittest.main()
diff --git a/infra/selfhost/app/test_cmdline_sampler.py b/infra/selfhost/app/test_cmdline_sampler.py
new file mode 100644
index 00000000000..bd3e97c035e
--- /dev/null
+++ b/infra/selfhost/app/test_cmdline_sampler.py
@@ -0,0 +1,168 @@
+"""goodqa#16148 spec v4 AC-6 (3), NEG-18 (P2, R6): cmdline-sampler.py against a fake /proc tree. Unprivileged.
+Run: python3 -m unittest -v test_cmdline_sampler
+"""
+import importlib.util
+import io
+import json
+import os
+import shutil
+import subprocess
+import sys
+import tempfile
+import threading
+import time
+import unittest
+
+HERE = os.path.dirname(os.path.abspath(__file__))
+SCRIPT = os.path.join(HERE, 'cmdline-sampler.py')
+spec = importlib.util.spec_from_file_location('sampler', SCRIPT)
+sampler = importlib.util.module_from_spec(spec)
+spec.loader.exec_module(sampler)
+
+CID = 'ab' * 32
+OTHER = 'cd' * 32
+MARKER = 'FAKEsamplerMARKER0123456789abcdefXYZ'
+
+
+class SamplerTests(unittest.TestCase):
+    def setUp(self):
+        self.proc = tempfile.mkdtemp(prefix='fakeproc-', dir=os.environ.get('DERIVE_TEST_TMP'))
+        self.next_pid = 100
+
+    def tearDown(self):
+        shutil.rmtree(self.proc, ignore_errors=True)
+
+    def add(self, argv, container=CID, style='systemd'):
+        pid = str(self.next_pid)
+        self.next_pid += 1
+        d = os.path.join(self.proc, pid)
+        os.makedirs(d)
+        cg = '0::/system.slice/docker-%s.scope\n' % container if style == 'systemd' else '12:pids:/docker/%s\n' % container
+        with open(os.path.join(d, 'cgroup'), 'w') as f:
+            f.write(cg)
+        with open(os.path.join(d, 'cmdline'), 'wb') as f:
+            f.write(b'\0'.join(a.encode() for a in argv) + b'\0')
+        with open(os.path.join(d, 'stat'), 'w') as f:
+            f.write('%s (docker) S ' % pid + ' '.join(['1'] * 18) + ' %s 0 0\n' % (1000 + int(pid)))
+        return pid
+
+    def sample(self, *extra, seconds='0.3'):
+        return sampler.run(['--container', CID, '--proc', self.proc, '--seconds', seconds, '--interval', '0.01', *extra])
+
+    def test_env_file_launch_passes_and_records_names_only(self):
+        self.add(['/usr/bin/docker', 'run', '--rm', '-d', '--cap-drop=ALL', '--env-file', '/tmp/goodqa-envfile-x/env', 'img@sha256:' + 'a' * 64, 'arg'])
+        out, code = self.sample('--expect-runs', '1')
+        self.assertEqual((out['verdict'], code), ('PASS', 0))
+        self.assertEqual(out['label'], 'sampled')
+        self.assertEqual(out['runs'][0]['flags'], ['--rm', '-d', '--cap-drop', '--env-file'])
+        self.assertNotIn('goodqa-envfile', json.dumps(out))
+
+    def test_neg18_planted_marker_in_every_form_never_reaches_output(self):
+        for argv in (['docker', 'run', '-e', 'K=' + MARKER, 'img'],
+                     ['docker', 'run', '-eK=' + MARKER, 'img'],
+                     ['docker', 'run', '--env=K=' + MARKER, 'img'],
+                     ['docker', 'run', '--env-file=' + MARKER, 'img'],
+                     ['docker', 'run', '--' + MARKER + '=x', 'img'],
+                     ['docker', 'run', '-' + MARKER, 'img']):
+            self.add(argv)
+        buf = io.StringIO()
+        saved = sys.stdout
+        sys.stdout = buf
+        try:
+            argv0 = sys.argv
+            sys.argv = ['cmdline-sampler.py', '--container', CID, '--proc', self.proc, '--seconds', '0.2', '--interval', '0.01', '--expect-runs', '6']
+            code = sampler.main()
+        finally:
+            sys.stdout = saved
+            sys.argv = argv0
+        text = buf.getvalue()
+        self.assertEqual(code, 1)
+        out = json.loads(text)
+        self.assertEqual(out['verdict'], 'FAIL')
+        for i in range(0, len(MARKER) - 7):
+            self.assertNotIn(MARKER[i:i + 8], text)
+        flags = [r['flags'] for r in out['runs']]
+        self.assertIn(['-e'], flags)
+        self.assertIn(['-e(attached)'], flags)
+        self.assertIn(['--env(attached)'], flags)
+        self.assertIn(['--env-file'], flags)
+        self.assertIn(['--(other)'], flags)
+        self.assertIn(['-(other)(attached)'], flags)
+        self.assertEqual(os.listdir(os.path.dirname(self.proc)).count(os.path.basename(self.proc)), 1)
+
+    def test_neg18_clustered_short_flags_with_e_fail(self):
+        # F3: pflag accepts clustered shorthands, so -de K=V and -ieK=V carry an env value too.
+        for argv in (['docker', 'run', '-de', 'K=' + MARKER, 'img'],
+                     ['docker', 'run', '-ieK=' + MARKER, 'img'],
+                     ['docker', 'run', '-dite', 'K=' + MARKER, 'img']):
+            shutil.rmtree(self.proc)
+            os.makedirs(self.proc)
+            self.add(argv)
+            out, code = self.sample('--expect-runs', '1')
+            self.assertEqual((out['verdict'], code), ('FAIL', 1), argv[2])
+            self.assertEqual(out['runs_with_env_flag'], 1)
+            text = json.dumps(out)
+            for i in range(0, len(MARKER) - 7):
+                self.assertNotIn(MARKER[i:i + 8], text)
+
+    def test_clusters_without_an_env_flag_still_pass(self):
+        # Booleans only, and an e that is part of a value-taking flag's value (-w example), are not env flags.
+        self.add(['docker', 'run', '-dit', '-wexample', '--env-file', '/x', 'img'])
+        out, code = self.sample('--expect-runs', '1')
+        self.assertEqual((out['verdict'], code), ('PASS', 0))
+        self.assertEqual(out['runs'][0]['flags'], ['-d(attached)', '-(other)(attached)', '--env-file'])
+
+    def test_neg18_other_cgroup_is_not_sampled(self):
+        self.add(['docker', 'run', '-e', 'K=' + MARKER, 'img'], container=OTHER)
+        self.add(['docker', 'run', '--env-file', '/x', 'img'])
+        out, code = self.sample('--expect-runs', '1')
+        self.assertEqual((out['verdict'], out['runs_seen']), ('PASS', 1))
+
+    def test_cgroup_v1_docker_path_is_matched(self):
+        self.add(['docker', 'run', '-e', 'K=v', 'img'], style='v1')
+        out, _ = self.sample('--expect-runs', '1')
+        self.assertEqual(out['verdict'], 'FAIL')
+
+    def test_positive_control_no_sample_fails(self):
+        out, code = self.sample('--expect-runs', '2')
+        self.assertEqual((out['verdict'], code), ('NO_SAMPLE', 1))
+        self.add(['docker', 'run', '--env-file', '/x', 'img'])
+        out, code = self.sample('--expect-runs', '2')
+        self.assertEqual((out['verdict'], code), ('NO_SAMPLE', 1))
+
+    def test_non_run_docker_commands_and_other_binaries_are_ignored(self):
+        self.add(['docker', 'inspect', 'abc'])
+        self.add(['node', 'run', '-e', 'K=v'])
+        out, _ = self.sample('--expect-runs', '1')
+        self.assertEqual(out['verdict'], 'NO_SAMPLE')
+
+    def test_a_short_lived_process_is_seen_by_polling(self):
+        def later():
+            time.sleep(0.1)
+            pid = self.add(['docker', 'run', '--env-file', '/x', 'img'])
+            time.sleep(0.15)
+            shutil.rmtree(os.path.join(self.proc, pid))
+        t = threading.Thread(target=later)
+        t.start()
+        out, code = self.sample('--expect-runs', '1', seconds='0.5')
+        t.join()
+        self.assertEqual((out['verdict'], code), ('PASS', 0))
+
+    def test_same_process_counted_once(self):
+        self.add(['docker', 'run', '--env-file', '/x', 'img'])
+        out, _ = self.sample('--expect-runs', '1')
+        self.assertEqual(out['runs_seen'], 1)
+
+    def test_bad_container_id_refused(self):
+        out, code = sampler.run(['--container', 'not-hex', '--proc', self.proc, '--seconds', '0'])
+        self.assertEqual((out['verdict'], code), ('FAIL', 1))
+
+    def test_runs_unprivileged_on_the_real_proc(self):
+        r = subprocess.run([sys.executable, '-I', SCRIPT, '--container', CID, '--seconds', '0.2', '--expect-runs', '0'],
+                           capture_output=True, text=True, timeout=30)
+        self.assertEqual(r.returncode, 0, r.stderr)
+        self.assertEqual(json.loads(r.stdout)['verdict'], 'PASS')
+
+
+if __name__ == '__main__':
+    unittest.main()
diff --git a/infra/selfhost/app/test_derive_job_secrets.py b/infra/selfhost/app/test_derive_job_secrets.py
new file mode 100644
index 00000000000..fdb30b3656d
--- /dev/null
+++ b/infra/selfhost/app/test_derive_job_secrets.py
@@ -0,0 +1,475 @@
+"""goodqa#16148 spec v4 AC-1, AC-2, AC-9, NEG-1, NEG-2, NEG-3, NEG-13: derive-job-secrets.py.
+
+Fake values only. The ownership tests need root (fchown to 0:64910), so they run in a throwaway
+container: run_derive_tests.sh starts one with this directory mounted and --network none. The
+compose parity test needs the docker compose CLI and runs on the host (it skips elsewhere).
+Run:  python3 -m unittest -v test_derive_job_secrets
+"""
+import importlib.util
+import json
+import os
+import shutil
+import signal
+import stat
+import subprocess
+import sys
+import tempfile
+import textwrap
+import time
+import unittest
+
+HERE = os.path.dirname(os.path.abspath(__file__))
+SCRIPT = os.path.join(HERE, 'derive-job-secrets.py')
+spec = importlib.util.spec_from_file_location('derive_job_secrets', SCRIPT)
+derive = importlib.util.module_from_spec(spec)
+spec.loader.exec_module(derive)
+
+MARKER = 'FAKEpemMARKER0123456789abcdefghijKLMNOPqrst'
+IS_ROOT = os.geteuid() == 0
+LINE = 'job secret github-app-private-key: '
+
+STUB_GETENT = r'''#!/usr/bin/env python3
+import os, sys
+root = os.environ['FAKE_NSS_ROOT']
+with open(os.path.join(root, 'argv.log'), 'a') as f:
+    f.write(repr(sys.argv) + '\n')
+db = sys.argv[1]
+files = {'group': ['etc/group', 'nss-group'], 'passwd': ['etc/passwd', 'nss-passwd']}[db]
+rows = []
+for rel in files:
+    p = os.path.join(root, rel)
+    if os.path.exists(p):
+        rows += [l for l in open(p).read().splitlines() if l]
+if len(sys.argv) > 2:
+    want = sys.argv[2]
+    rows = [r for r in rows if r.split(':')[0] == want or r.split(':')[2] == want]
+    if not rows:
+        sys.exit(2)
+print('\n'.join(rows))
+'''
+
+STUB_GROUPADD = r'''#!/usr/bin/env python3
+import os, sys
+root = os.environ['FAKE_NSS_ROOT']
+with open(os.path.join(root, 'argv.log'), 'a') as f:
+    f.write(repr(sys.argv) + '\n')
+args = sys.argv[1:]
+assert args[:2] == ['-R', root], args
+with open(os.path.join(root, 'etc/group'), 'a') as f:
+    f.write('%s:x:%s:\n' % (args[-1], args[args.index('-g') + 1]))
+'''
+
+
+class FakeHost:
+    def __init__(self, api_env=None):
+        self.root = tempfile.mkdtemp(prefix='derive-root-', dir=os.environ.get('DERIVE_TEST_TMP'))
+        os.chmod(self.root, 0o755)
+        os.makedirs(self.p('etc/goodqa'), mode=0o755)
+        os.chmod(self.p('etc/goodqa'), 0o755)
+        with open(self.p('etc/group'), 'w') as f:
+            f.write('root:x:0:\nadm:x:4:syslog\n')
+        with open(self.p('etc/passwd'), 'w') as f:
+            f.write('root:x:0:0:root:/root:/bin/bash\n')
+        self.bin = self.p('stub-bin')
+        os.makedirs(self.bin)
+        for name, body in (('getent', STUB_GETENT), ('groupadd', STUB_GROUPADD)):
+            with open(os.path.join(self.bin, name), 'w') as f:
+                f.write(body)
+            os.chmod(os.path.join(self.bin, name), 0o755)
+        self.sentinel = self.p('sentinel')
+        with open(self.sentinel, 'w') as f:
+            f.write('sentinel')
+        if api_env is not None:
+            self.write_api_env(api_env)
+
+    def p(self, rel):
+        return os.path.join(self.root, rel)
+
+    def write_api_env(self, data):
+        if isinstance(data, str):
+            data = data.encode()
+        with open(self.p('etc/goodqa/api.env'), 'wb') as f:
+            f.write(data)
+
+    def env(self):
+        return {'PATH': self.bin + ':' + os.environ['PATH'], 'FAKE_NSS_ROOT': self.root}
+
+    def run(self, argv=(), hooks=None):
+        saved = dict(os.environ)
+        os.environ.update(self.env())
+        try:
+            return derive.run(list(argv), root=self.root, hooks=hooks)
+        finally:
+            os.environ.clear()
+            os.environ.update(saved)
+
+    def secret(self):
+        return self.p('etc/goodqa/job-secrets/github-app-private-key')
+
+    def sentinel_state(self):
+        st = os.lstat(self.sentinel)
+        return (st.st_uid, st.st_gid, st.st_mode, open(self.sentinel, 'rb').read())
+
+    def close(self):
+        shutil.rmtree(self.root, ignore_errors=True)
+
+
+def api(value, extra=''):
+    return 'DATABASE_URL=postgres://fake\n%sGITHUB_APP_PRIVATE_KEY=%s\nOTHER=1\n' % (extra, value)
+
+
+class ParseTests(unittest.TestCase):
+    """AC-1: the value exactly as compose `format: raw` would deliver it."""
+
+    def ok(self, text, expected):
+        self.assertEqual(derive.parse_api_env(text.encode()), expected.encode())
+
+    def refused(self, text, reason):
+        with self.assertRaises(derive.Refused) as cm:
+            derive.parse_api_env(text if isinstance(text, bytes) else text.encode())
+        self.assertEqual(str(cm.exception), reason)
+
+    def test_derive_parse_plain(self):
+        self.ok(api(MARKER), MARKER)
+
+    def test_derive_parse_base64_with_equals(self):
+        self.ok(api('TUlJRkFLRQ=='), 'TUlJRkFLRQ==')
+
+    def test_derive_parse_double_quoted(self):
+        self.ok(api('"%s"' % MARKER), '"%s"' % MARKER)
+
+    def test_derive_parse_single_quoted(self):
+        self.ok(api("'%s'" % MARKER), "'%s'" % MARKER)
+
+    def test_derive_parse_trailing_spaces(self):
+        self.ok(api(MARKER + '   '), MARKER + '   ')
+
+    def test_derive_parse_inner_hash_kept(self):
+        self.ok(api('abc # def'), 'abc # def')
+
+    def test_derive_parse_leading_key_whitespace(self):
+        self.ok('  GITHUB_APP_PRIVATE_KEY=%s\n' % MARKER, MARKER)
+
+    def test_derive_parse_crlf(self):
+        self.ok('A=1\r\nGITHUB_APP_PRIVATE_KEY=%s\r\nB=2\r\n' % MARKER, MARKER)
+
+    def test_derive_parse_comment_line_ignored(self):
+        self.ok('#GITHUB_APP_PRIVATE_KEY=commented\n' + api(MARKER), MARKER)
+
+    def test_derive_parse_export(self):
+        self.refused('export GITHUB_APP_PRIVATE_KEY=%s\n' % MARKER, 'export form')
+
+    def test_derive_parse_duplicate(self):
+        self.refused(api(MARKER) + 'GITHUB_APP_PRIVATE_KEY=second\n', 'more than one GITHUB_APP_PRIVATE_KEY line')
+
+    def test_derive_parse_missing(self):
+        self.refused('DATABASE_URL=x\n', 'no GITHUB_APP_PRIVATE_KEY line')
+
+    def test_derive_parse_empty(self):
+        self.refused(api(''), 'empty value')
+
+    def test_derive_parse_tab(self):
+        self.refused(api('abc\tdef'), 'value holds a byte outside printable ASCII')
+
+    def test_derive_parse_cr_inside(self):
+        self.refused(b'GITHUB_APP_PRIVATE_KEY=ab\rcd\n', 'value holds a byte outside printable ASCII')
+
+    def test_derive_parse_non_ascii(self):
+        self.refused('GITHUB_APP_PRIVATE_KEY=caf\u00e9\n', 'value holds a byte outside printable ASCII')
+
+    def test_derive_parse_invalid_utf8(self):
+        self.refused(b'GITHUB_APP_PRIVATE_KEY=ab\xffcd\n', 'value holds a byte outside printable ASCII')
+
+    def test_derive_parse_line_compose_refuses(self):
+        self.refused('BAD KEY=1\n' + api(MARKER), 'api.env has a line compose would refuse')
+
+
+@unittest.skipUnless(shutil.which('docker') and not IS_ROOT, 'compose parity runs on the host with the docker CLI')
+class ComposeParityTests(unittest.TestCase):
+    """AC-1 parity: derive's value equals what the real `docker compose config` gives the api service."""
+
+    COMPOSE = os.path.join(HERE, 'compose.yaml')
+
+    def test_api_env_file_is_format_raw(self):
+        text = open(self.COMPOSE).read()
+        block = text[text.index('\n  api:\n'):]
+        block = block[:block.index('\n  web:\n')]
+        self.assertIn('      - path: /etc/goodqa/api.env\n        format: raw\n', block)
+
+    def test_derive_value_equals_compose_value(self):
+        accepted = [MARKER, 'TUlJRkFLRQ==', '"%s"' % MARKER, "'%s'" % MARKER, MARKER + '   ', 'abc # def', 'x=y=z']
+        tmp = tempfile.mkdtemp(prefix='parity-', dir=os.environ.get('DERIVE_TEST_TMP'))
+        try:
+            for i, value in enumerate(accepted):
+                for eol in ('\n', '\r\n'):
+                    envp = os.path.join(tmp, 'api-%d.env' % i)
+                    with open(envp, 'w', newline='') as f:
+                        f.write('A=1%sGITHUB_APP_PRIVATE_KEY=%s%sB=2%s' % (eol, value, eol, eol))
+                    comp = os.path.join(tmp, 'compose.yaml')
+                    with open(comp, 'w') as f:
+                        f.write(textwrap.dedent('''\
+                            services:
+                              api:
+                                image: busybox:1.36
+                                env_file:
+                                  - path: %s
+                                    format: raw
+                            ''' % envp))
+                    out = subprocess.run(['docker', 'compose', '-f', comp, 'config', '--format', 'json'],
+                                         capture_output=True, text=True, timeout=60, check=True).stdout
+                    composed = json.loads(out)['services']['api']['environment']['GITHUB_APP_PRIVATE_KEY']
+                    derived = derive.parse_api_env(open(envp, 'rb').read()).decode()
+                    self.assertEqual(derived, composed, 'value %d eol %r' % (i, eol))
+        finally:
+            shutil.rmtree(tmp, ignore_errors=True)
+
+
+@unittest.skipUnless(IS_ROOT, 'ownership tests need root: run_derive_tests.sh runs them in a throwaway container')
+class DeriveTests(unittest.TestCase):
+    def setUp(self):
+        self.h = FakeHost(api(MARKER))
+
+    def tearDown(self):
+        self.h.close()
+
+    def assert_file_ok(self, value=MARKER):
+        st = os.lstat(self.h.secret())
+        self.assertTrue(stat.S_ISREG(st.st_mode))
+        self.assertEqual((st.st_uid, st.st_gid, st.st_mode & 0o7777), (0, 64910, 0o440))
+        d = os.lstat(os.path.dirname(self.h.secret()))
+        self.assertEqual((d.st_uid, d.st_gid, d.st_mode & 0o7777), (0, 0, 0o711))
+        self.assertEqual(open(self.h.secret(), 'rb').read(), value.encode())
+
+    # ---- AC-2 ----
+    def test_written_then_unchanged(self):
+        self.assertEqual(self.h.run(), ('written', 0))
+        self.assert_file_ok()
+        self.assertIn('goodqa-jobsecret:x:64910:', open(self.h.p('etc/group')).read())
+        m1 = os.lstat(self.h.secret()).st_mtime_ns
+        time.sleep(0.02)
+        self.assertEqual(self.h.run(), ('unchanged', 0))
+        self.assertEqual(os.lstat(self.h.secret()).st_mtime_ns, m1)
+
+    def test_no_temp_left_after_abrupt_stop_between_write_and_rename(self):
+        pid = os.fork()
+        if pid == 0:
+            try:
+                self.h.run(hooks={'before_rename': lambda _t: os.kill(os.getpid(), signal.SIGKILL)})
+            finally:
+                os._exit(3)
+        _, status = os.waitpid(pid, 0)
+        self.assertTrue(os.WIFSIGNALED(status))
+        d = os.path.dirname(self.h.secret())
+        self.assertTrue(any(n.startswith('.tmp-') for n in os.listdir(d)))
+        self.assertFalse(os.path.exists(self.h.secret()))
+        self.assertEqual(self.h.run(), ('written', 0))
+        self.assertEqual(sorted(os.listdir(d)), ['github-app-private-key'])
+        self.assert_file_ok()
+
+    def test_symlink_planted_at_target_before_rename_never_touches_outside(self):
+        before = self.h.sentinel_state()
+        self.h.run()  # create dir and file
+        os.unlink(self.h.secret())
+        self.h.write_api_env(api(MARKER + 'X'))
+
+        def plant(_tmp):
+            os.symlink(self.h.sentinel, self.h.secret())
+
+        self.assertEqual(self.h.run(hooks={'before_rename': plant}), ('written', 0))
+        self.assert_file_ok(MARKER + 'X')
+        self.assertEqual(self.h.sentinel_state(), before)
+
+    def test_temp_swapped_for_a_link_before_rename_is_refused(self):
+        before = self.h.sentinel_state()
+
+        def swap(tmp):
+            d = os.path.dirname(self.h.secret())
+            os.unlink(os.path.join(d, tmp))
+            os.symlink(self.h.sentinel, os.path.join(d, tmp))
+
+        word, code = self.h.run(hooks={'before_rename': swap})
+        self.assertEqual((word, code), ('REFUSED the secret file changed during the write', 2))
+        self.assertEqual(self.h.sentinel_state(), before)
+        # F2: the swapped-in link is not left as the live secret; the dispatcher fails closed as missing.
+        self.assertFalse(os.path.lexists(self.h.secret()))
+        self.assertEqual(self.h.run(), ('written', 0))  # the next run writes the real file
+        self.assert_file_ok(MARKER)
+
+    def test_temp_swapped_for_a_hardlink_before_rename_is_refused(self):
+        # A regular file that is not the one this run wrote: only the inode check can tell.
+        other = self.h.p('etc/other-key')
+        with open(other, 'wb') as f:
+            f.write(b'other-bytes')
+        os.chown(other, 0, 64910)
+        os.chmod(other, 0o440)
+
+        def swap(tmp):
+            d = os.path.dirname(self.h.secret())
+            os.unlink(os.path.join(d, tmp))
+            os.link(other, os.path.join(d, tmp))
+
+        self.assertEqual(self.h.run(hooks={'before_rename': swap}), ('REFUSED the secret file changed during the write', 2))
+        self.assertEqual(open(other, 'rb').read(), b'other-bytes')
+        # F2: the foreign inode is not left at the target name.
+        self.assertFalse(os.path.lexists(self.h.secret()))
+
+    # ---- AC-9 ----
+    def test_check_same_different(self):
+        self.assertEqual(self.h.run(['--check']), ('different', 0))
+        self.h.run()
+        self.assertEqual(self.h.run(['--check']), ('same', 0))
+        self.h.write_api_env(api(MARKER + 'NEW'))
+        self.assertEqual(self.h.run(['--check']), ('different', 0))
+        self.assertEqual(self.h.run(), ('written', 0))
+        self.assert_file_ok(MARKER + 'NEW')
+        self.assertEqual(self.h.run(['--check']), ('same', 0))
+
+    def test_check_writes_nothing(self):
+        self.h.run(['--check'])
+        self.assertFalse(os.path.exists(os.path.dirname(self.h.secret())))
+        self.assertNotIn('goodqa-jobsecret', open(self.h.p('etc/group')).read())
+
+    # ---- NEG-1 ----
+    def test_refusals_leave_the_old_file(self):
+        self.h.run()
+        m = os.lstat(self.h.secret()).st_mtime_ns
+        for text, reason in [
+            ('DATABASE_URL=x\n', 'no GITHUB_APP_PRIVATE_KEY line'),
+            (api(MARKER) + 'GITHUB_APP_PRIVATE_KEY=x\n', 'more than one GITHUB_APP_PRIVATE_KEY line'),
+            ('export GITHUB_APP_PRIVATE_KEY=x\n', 'export form'),
+            (api(''), 'empty value'),
+            (b'GITHUB_APP_PRIVATE_KEY=a\rb\n', 'value holds a byte outside printable ASCII'),
+            (api('a\tb'), 'value holds a byte outside printable ASCII'),
+            (b'GITHUB_APP_PRIVATE_KEY=a\x01b\n', 'value holds a byte outside printable ASCII'),
+        ]:
+            self.h.write_api_env(text)
+            self.assertEqual(self.h.run(), ('REFUSED ' + reason, 2))
+            self.assert_file_ok()
+            self.assertEqual(os.lstat(self.h.secret()).st_mtime_ns, m)
+        os.chmod(self.h.p('etc/goodqa/api.env'), 0o000)
+        os.rename(self.h.p('etc/goodqa/api.env'), self.h.p('etc/goodqa/api.env.gone'))
+        self.assertEqual(self.h.run(), ('REFUSED api.env unreadable', 2))
+        self.assert_file_ok()
+
+    # ---- NEG-2 ----
+    def _refused_and_sentinel(self, setup):
+        before = self.h.sentinel_state()
+        setup()
+        word, code = self.h.run()
+        self.assertEqual(code, 2, word)
+        self.assertTrue(word.startswith('REFUSED '))
+        self.assertEqual(self.h.sentinel_state(), before)
+        return word
+
+    def test_neg2_dir_is_symlink(self):
+        os.makedirs(self.h.p('elsewhere'))
+        self._refused_and_sentinel(lambda: os.symlink(self.h.p('elsewhere'), self.h.p('etc/goodqa/job-secrets')))
+        self.assertEqual(os.listdir(self.h.p('elsewhere')), [])
+
+    def test_neg2_dir_symlink_to_a_conforming_dir(self):
+        # The link target has the right owner and mode, so only O_NOFOLLOW refuses it.
+        os.makedirs(self.h.p('elsewhere'))
+        os.chown(self.h.p('elsewhere'), 0, 0)
+        os.chmod(self.h.p('elsewhere'), 0o711)
+        self._refused_and_sentinel(lambda: os.symlink(self.h.p('elsewhere'), self.h.p('etc/goodqa/job-secrets')))
+        self.assertEqual(os.listdir(self.h.p('elsewhere')), [])
+
+    def test_neg2_target_symlink_to_a_conforming_file_with_the_same_value(self):
+        # Without O_NOFOLLOW this would read as `unchanged`.
+        def s():
+            self.h.run()
+            os.unlink(self.h.secret())
+            twin = self.h.p('etc/twin')
+            with open(twin, 'wb') as f:
+                f.write(MARKER.encode())
+            os.chown(twin, 0, 64910)
+            os.chmod(twin, 0o440)
+            os.symlink(twin, self.h.secret())
+        self.assertEqual(self._refused_and_sentinel(s), 'REFUSED the secret file is a symlink or unreadable')
+
+    def test_neg2_dir_owned_by_non_root(self):
+        def s():
+            os.mkdir(self.h.p('etc/goodqa/job-secrets'), 0o711)
+            os.chown(self.h.p('etc/goodqa/job-secrets'), 1000, 1000)
+        self.assertEqual(self._refused_and_sentinel(s), 'REFUSED job-secrets has another owner, mode or type')
+
+    def test_neg2_dir_group_writable(self):
+        def s():
+            os.mkdir(self.h.p('etc/goodqa/job-secrets'))
+            os.chmod(self.h.p('etc/goodqa/job-secrets'), 0o731)
+        self._refused_and_sentinel(s)
+
+    def test_neg2_parent_world_writable(self):
+        self._refused_and_sentinel(lambda: os.chmod(self.h.p('etc/goodqa'), 0o757))
+
+    def test_neg2_target_is_symlink(self):
+        def s():
+            self.h.run()
+            os.unlink(self.h.secret())
+            os.symlink(self.h.sentinel, self.h.secret())
+        self._refused_and_sentinel(s)
+
+    def test_neg2_target_is_directory(self):
+        def s():
+            self.h.run()
+            os.unlink(self.h.secret())
+            os.mkdir(self.h.secret())
+        self._refused_and_sentinel(s)
+
+    # ---- NEG-3 ----
+    def _group_refused(self, group_lines, reason, passwd_lines=''):
+        with open(self.h.p('etc/group'), 'a') as f:
+            f.write(group_lines)
+        with open(self.h.p('etc/passwd'), 'a') as f:
+            f.write(passwd_lines)
+        self.assertEqual(self.h.run(), ('REFUSED ' + reason, 2))
+        self.assertFalse(os.path.exists(self.h.secret()))
+
+    def test_neg3_gid_taken_by_another_name(self):
+        self._group_refused('other:x:64910:\n', 'gid 64910 has another name')
+
+    def test_neg3_group_has_member(self):
+        self._group_refused('goodqa-jobsecret:x:64910:alice\n', 'group goodqa-jobsecret has members')
+
+    def test_neg3_name_has_another_gid(self):
+        self._group_refused('goodqa-jobsecret:x:64911:\n', 'group name goodqa-jobsecret has another gid')
+
+    def test_neg3_primary_gid(self):
+        self._group_refused('', 'an account has gid 64910 as its primary group', 'svc:x:999:64910::/:/bin/false\n')
+
+    # ---- NEG-13 (NSS only) ----
+    def _nss_refused(self, rel, line, reason):
+        with open(self.h.p(rel), 'w') as f:
+            f.write(line)
+        self.assertEqual(self.h.run(), ('REFUSED ' + reason, 2))
+        self.assertFalse(os.path.exists(self.h.secret()))
+
+    def test_neg13_nss_gid_other_name(self):
+        self._nss_refused('nss-group', 'ldapgrp:x:64910:\n', 'gid 64910 has another name')
+
+    def test_neg13_nss_member(self):
+        self._nss_refused('nss-group', 'goodqa-jobsecret:x:64910:bob\n', 'group goodqa-jobsecret has members')
+
+    def test_neg13_nss_primary_gid(self):
+        self._nss_refused('nss-passwd', 'ldapuser:x:5000:64910::/:/bin/false\n', 'an account has gid 64910 as its primary group')
+
+    # ---- AC-7: the value never in output or any spawned argv ----
+    def test_value_never_in_stdout_stderr_or_argv(self):
+        env = dict(os.environ, **self.h.env())
+        code = 'import importlib.util,sys; s=importlib.util.spec_from_file_location("d", %r); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); sys.exit(m.main(root=%r))' % (SCRIPT, self.h.root)
+        for argv in ([], [], ['--check']):
+            r = subprocess.run([sys.executable, '-I', '-c', code, *argv], env=env, capture_output=True, timeout=60)
+            out = r.stdout.decode() + r.stderr.decode()
+            self.assertEqual(r.stderr, b'')
+            self.assertEqual(len(r.stdout.decode().splitlines()), 1)
+            self.assertTrue(r.stdout.decode().startswith(LINE))
+            for i in range(0, len(MARKER) - 15):
+                self.assertNotIn(MARKER[i:i + 16], out)
+        log = open(self.h.p('argv.log')).read()
+        self.assertTrue(log)
+        for i in range(0, len(MARKER) - 15):
+            self.assertNotIn(MARKER[i:i + 16], log)
+
+
+if __name__ == '__main__':
+    unittest.main()
### SECTION C: gate delta, d9cb6162..679c278a (after joining 1371 and 1373 .. gate head)
diff --git a/apps/job-dispatcher/src/boot-check.ts b/apps/job-dispatcher/src/boot-check.ts
new file mode 100644
index 00000000000..0ec81c472c2
--- /dev/null
+++ b/apps/job-dispatcher/src/boot-check.ts
@@ -0,0 +1,41 @@
+/**
+ * goodqa#16148 spec v4 AC-8 / P3: the trial boot. Before an unholding switch, rw-ship runs the release's dispatcher
+ * image once, isolated, with the CLI flag `--boot-check` and a throwaway secrets directory holding a fake value.
+ * This mode only loads the config and prints the JOB_ENVFILE boot status lines (names and status only), then
+ * exits. It binds no port and never runs docker. It is selected by argv alone (lead ruling Q2), so no compose or
+ * env change can turn it on in a serving container.
+ *
+ * Exit: 0 when at least one key is configured and every line is `job env file KIND__VAR: ok`; 1 when any line is
+ * not ok (an error or an ignored key); 2 when the config is refused (error name only); 3 when no key is configured.
+ */
+import { loadConfig } from './config';
+import { bootEnvFileStatusLines, JOB_ENVFILE_DIR } from './job-env-file';
+
+export const BOOT_CHECK_FLAG = '--boot-check';
+
+export function isBootCheck(argv: readonly string[]): boolean {
+  return argv.length === 1 && argv[0] === BOOT_CHECK_FLAG;
+}
+
+const OK_LINE = /^job env file [A-Z0-9_]+__[A-Z0-9_]+: ok$/;
+
+export function runBootCheck(
+  env: NodeJS.ProcessEnv,
+  write: (line: string) => void,
+  envFileDir: string = JOB_ENVFILE_DIR,
+): number {
+  let config;
+  try {
+    config = loadConfig(env);
+  } catch (error) {
+    write(`boot check: config refused (${error instanceof Error ? error.name : 'unknown'})`);
+    return 2;
+  }
+  const lines = bootEnvFileStatusLines({ jobEnvFiles: config.jobEnvFiles, jobEnvFileDir: envFileDir });
+  if (lines.length === 0) {
+    write('boot check: no JOB_ENVFILE key configured');
+    return 3;
+  }
+  for (const line of lines) write(line);
+  return lines.every((l) => OK_LINE.test(l)) ? 0 : 1;
+}
diff --git a/apps/job-dispatcher/src/index.ts b/apps/job-dispatcher/src/index.ts
index 262038cc3c4..1bf92c47faa 100644
--- a/apps/job-dispatcher/src/index.ts
+++ b/apps/job-dispatcher/src/index.ts
@@ -1,13 +1,11 @@
-import { loadConfig } from './config';
+import { isBootCheck, runBootCheck } from './boot-check';
+import { loadConfig, type Config } from './config';
 import { configureExecutionStore, reconcileExecutions } from './executions';
 import { sweepStaleEnvFileDirs } from './docker';
 import { bootEnvFileStatusLines } from './job-env-file';
 import { buildServer, realDockerDeps } from './server';
 
-const config = loadConfig();
-const app = buildServer(config);
-
-async function main(): Promise<void> {
+async function main(config: Config, app: ReturnType<typeof buildServer>): Promise<void> {
   // goodqa#16148 AC-6: a crash between writing a launch env-file and its finally leaves a
   // directory on the tmpfs; remove any before serving.
   app.log.info({ removed: sweepStaleEnvFileDirs() }, 'job-dispatcher: swept stale env-file dirs');
@@ -26,7 +24,15 @@ async function main(): Promise<void> {
   app.log.info({ port: config.PORT }, 'job-dispatcher listening');
 }
 
-main().catch((error) => {
-  app.log.error(error, 'job-dispatcher failed to start');
-  process.exit(1);
-});
+// goodqa#16148 AC-8 / P3: rw-ship's isolated trial boot. Selected by the CLI argument only (never env), so a serving
+// container cannot enter it; it prints the JOB_ENVFILE status lines and exits without a server, port or docker.
+if (isBootCheck(process.argv.slice(2))) {
+  process.exitCode = runBootCheck(process.env, (line) => process.stdout.write(`${line}\n`));
+} else {
+  const config = loadConfig();
+  const app = buildServer(config);
+  main(config, app).catch((error) => {
+    app.log.error(error, 'job-dispatcher failed to start');
+    process.exit(1);
+  });
+}
diff --git a/apps/job-dispatcher/test/boot-check.test.ts b/apps/job-dispatcher/test/boot-check.test.ts
new file mode 100644
index 00000000000..adafaaaa8bf
--- /dev/null
+++ b/apps/job-dispatcher/test/boot-check.test.ts
@@ -0,0 +1,86 @@
+/**
+ * goodqa#16148 spec v4 AC-8 / P3: the release's trial boot runs the dispatcher image with the CLI flag `--boot-check`.
+ * Lead ruling (Q2): a CLI flag only, never an env var; no port, no docker; prints the JOB_ENVFILE boot lines and exits
+ * 0 only when every line is `ok`. Fake values only.
+ */
+import { mkdtempSync, readFileSync, rmSync, writeFileSync, chmodSync } from 'node:fs';
+import { tmpdir } from 'node:os';
+import { join } from 'node:path';
+import { afterEach, beforeEach, describe, expect, it } from 'vitest';
+import { BOOT_CHECK_FLAG, isBootCheck, runBootCheck } from '../src/boot-check';
+
+const KEY = 'JOB_ENVFILE_INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY';
+// One line, as derive writes it (the file value may not hold CR or LF).
+const FAKE = '-----BEGIN FAKE KEY-----\\nFAKEbootCHECKmarker0123456789\\n-----END FAKE KEY-----\n';
+
+describe('--boot-check (trial boot only)', () => {
+  let dir: string;
+  let out: string[];
+  const write = (l: string) => out.push(l);
+  beforeEach(() => {
+    dir = mkdtempSync(join(tmpdir(), 'boot-check-'));
+    out = [];
+  });
+  afterEach(() => rmSync(dir, { recursive: true, force: true }));
+
+  function secret(body = FAKE, mode = 0o440): string {
+    const p = join(dir, 'github-app-private-key');
+    writeFileSync(p, body);
+    chmodSync(p, mode);
+    return p;
+  }
+
+  it('is selected only by exactly one CLI argument, the flag itself', () => {
+    expect(BOOT_CHECK_FLAG).toBe('--boot-check');
+    expect(isBootCheck(['--boot-check'])).toBe(true);
+    expect(isBootCheck([])).toBe(false);
+    expect(isBootCheck(['--boot-check', 'x'])).toBe(false);
+    expect(isBootCheck(['--boot-check=1'])).toBe(false);
+    expect(isBootCheck(['-boot-check'])).toBe(false);
+  });
+
+  it('the entrypoint reads the flag from argv only: no env var can switch it on', () => {
+    const src = readFileSync(join(__dirname, '../src/index.ts'), 'utf8');
+    expect(src).toMatch(/isBootCheck\(process\.argv\.slice\(2\)\)/);
+    // Code only: comments may name what the module avoids.
+    const mod = readFileSync(join(__dirname, '../src/boot-check.ts'), 'utf8')
+      .replace(/\/\*[\s\S]*?\*\//g, '')
+      .replace(/\/\/.*$/gm, '');
+    expect(mod).not.toMatch(/process\.env/);
+    expect(mod).not.toMatch(/listen|node:child_process|docker/i);
+    // A normal start (no argv) never takes the boot-check path, whatever the env says.
+    expect(isBootCheck([])).toBe(false);
+  });
+
+  it('ok: prints the exact ok line and exits 0', () => {
+    const code = runBootCheck({ JOB_DISPATCH_TOKEN: 'fake-token', [KEY]: secret() }, write, dir);
+    expect(code).toBe(0);
+    expect(out).toEqual(['job env file INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY: ok']);
+    expect(out.join('\n')).not.toContain('FAKEbootCHECK');
+  });
+
+  it('a missing file is a non-zero exit with the error line (no value)', () => {
+    const code = runBootCheck({ JOB_DISPATCH_TOKEN: 'fake-token', [KEY]: join(dir, 'github-app-private-key') }, write, dir);
+    expect(code).toBe(1);
+    expect(out).toHaveLength(1);
+    expect(out[0]).toMatch(/^job env file for INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY: /);
+  });
+
+  it('no JOB_ENVFILE key at all is a non-zero exit (a trial must exercise the key)', () => {
+    expect(runBootCheck({ JOB_DISPATCH_TOKEN: 'fake-token' }, write, dir)).toBe(3);
+    expect(out).toEqual(['boot check: no JOB_ENVFILE key configured']);
+  });
+
+  it('an ignored (not allow-listed) key is a non-zero exit even beside an ok line', () => {
+    const env = { JOB_DISPATCH_TOKEN: 'fake-token', [KEY]: secret(), JOB_ENVFILE_SCAN__OTHER: join(dir, 'x') };
+    expect(runBootCheck(env, write, dir)).toBe(1);
+    expect(out).toContain('job env file INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY: ok');
+    expect(out.some((l) => l.startsWith('job env file key ignored'))).toBe(true);
+  });
+
+  it('a config refusal prints the error name only and exits 2', () => {
+    const code = runBootCheck({ [KEY]: secret() }, write, dir);
+    expect(code).toBe(2);
+    expect(out).toEqual(['boot check: config refused (Error)']);
+  });
+});
diff --git a/infra/release-harness/ac13-count.py b/infra/release-harness/ac13-count.py
index 9913d48a6f4..1ca2e2cc58d 100755
--- a/infra/release-harness/ac13-count.py
+++ b/infra/release-harness/ac13-count.py
@@ -22,9 +22,17 @@ body, header or env value is ever printed.
   Pairing reads both logs over the window widened by --pair-seconds on each side, so a held launch that straddles a
   window edge still pairs; an unmatched 422 or held API line inside the window, an in-window API launch-failure line
   for any other reason, and an API launch-failure line without a readable timestamp are failures.
-Exit 0 PASS, 1 FAIL, 2 usage or unreadable input. Output: one JSON object.
+UNKNOWN records (receipt pr1370-v1 F1) never let a run PASS. Each one is a record the matcher cannot vouch for:
+  - a line holding `{` that is not a JSON object (malformed);
+  - a "request completed" with no "incoming request" for its reqId (an orphan: it can be an in-window 500);
+  - a launch completion whose statusCode is not an integer 100-599 (a bool is not one) or whose time is not a finite
+    number (NaN, Infinity, 1e999 are not); such a completion keeps its own time, or none, never its start time;
+  - a launch "incoming request" with no completion (superseded by a reused reqId, or still open at the end of the log).
+It counts when its time is inside the window, or when it has no usable time. Any such record makes the verdict
+INCONCLUSIVE (exit 1) unless a failure already makes it FAIL.
+Exit 0 PASS, 1 FAIL or INCONCLUSIVE, 2 usage or unreadable input. Output: one JSON object.
 """
-import argparse, calendar, json, re, sys, time
+import argparse, calendar, json, math, re, sys, time
 
 KINDS = ('scan', 'transcode', 'intelligence-worker', 'suggest-fix-worker')
 HOLDABLE = ('intelligence-worker', 'transcode')
@@ -35,13 +43,25 @@ API_LINE = re.compile(r'^(?:(\S+)\s+\|\s+)?(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.
 
 
 def records(path):
+    """Each JSON object line, or None for a line holding `{` that is not one (counted as unknown, never skipped)."""
     with open(path, encoding='utf-8', errors='replace') as f:
         for line in f:
             i = line.find('{')
             if i < 0: continue
             try: r = json.loads(line[i:])
-            except ValueError: continue
-            if isinstance(r, dict): yield r
+            except ValueError: yield None; continue
+            yield r if isinstance(r, dict) else None
+
+
+MAX_TIME = 2 ** 53   # epoch ms; larger ints are not times (and would overflow a float conversion)
+
+
+def num(v):
+    """A usable time: a finite int or float, never a bool. NaN, Infinity and 1e999 (receipt pr1370-v2b F2) are None,
+    and so is an int beyond +-2**53 (receipt pr1370-v2c F1: it never reaches a float conversion, so no traceback)."""
+    if isinstance(v, bool): return None
+    if isinstance(v, int): return v if -MAX_TIME <= v <= MAX_TIME else None
+    return v if isinstance(v, float) and math.isfinite(v) else None
 
 
 def inside(t, since, until):
@@ -49,20 +69,27 @@ def inside(t, since, until):
 
 
 def launches(path):
-    """[(time, kind, status)] for every completed POST /jobs/<kind>/run with a numeric time."""
-    pending, out = {}, []
+    """([(time, kind, status)] for every completed POST /jobs/<kind>/run, [(time or None, why)] unknown records)."""
+    pending, out, unknown = {}, [], []
     for r in records(path):
+        if r is None: unknown.append((None, 'malformed')); continue
         rid, msg = r.get('reqId'), r.get('msg')
         if msg == 'incoming request':
-            req = r.get('req') or {}
+            req = r.get('req') if isinstance(r.get('req'), dict) else {}
             m = ROUTE.match(str(req.get('url', '')))
-            if req.get('method') == 'POST' and m: pending[rid] = m.group(1)
-            else: pending.pop(rid, None)
-        elif msg == 'request completed' and rid in pending:
-            kind = pending.pop(rid)
-            st = (r.get('res') or {}).get('statusCode'); t = r.get('time')
-            if isinstance(st, int) and isinstance(t, (int, float)): out.append((t, kind, st))
-    return out
+            prev = pending.pop(rid, None)
+            if prev and prev[0]: unknown.append((prev[1], 'no completion'))
+            pending[rid] = (m.group(1) if req.get('method') == 'POST' and m else None, num(r.get('time')))
+        elif msg == 'request completed':
+            if rid not in pending: unknown.append((num(r.get('time')), 'orphan completion')); continue
+            kind, t_in = pending.pop(rid)
+            if not kind: continue
+            res = r.get('res') if isinstance(r.get('res'), dict) else {}
+            st, t = res.get('statusCode'), num(r.get('time'))
+            if isinstance(st, int) and not isinstance(st, bool) and 100 <= st <= 599 and t is not None: out.append((t, kind, st))
+            else: unknown.append((t, 'invalid status or time'))   # an unusable time stays None, never the start time (v2b F1)
+    unknown += [(t_in, 'no completion') for kind, t_in in pending.values() if kind]
+    return out, unknown
 
 
 def api_lines(paths):
@@ -108,11 +135,14 @@ def main(argv=None):
         ap.error('--guard-held-transcribe needs --refusals: a held transcription 422 is excluded only when matched to its API launch-failure line')
     tol = int(a.pair_seconds * 1000)
     try:
-        got = launches(a.log)
+        got, unknown = launches(a.log)
         held_api, other_api, untimed, replicas = api_lines(a.refusals) if a.refusals else ([], [], 0, [])
     except OSError as e:
         print(json.dumps({'verdict': 'FAIL', 'error': 'unreadable input: %s' % e.strerror})); return 2
     inwin = [(t, k, st) for t, k, st in got if inside(t, a.since, a.until)]
+    unk = {}
+    for t, why in unknown:
+        if t is None or inside(t, a.since, a.until): unk[why] = unk.get(why, 0) + 1
     counts = {}
     for _, k, st in inwin: counts.setdefault(k, {}).setdefault(str(st), 0); counts[k][str(st)] += 1
     failures, held = [], {}
@@ -139,9 +169,10 @@ def main(argv=None):
             failures.append('read %d api replicas, expected %d' % (len(replicas), a.api_replicas))
         for k in a.require_2xx:
             if not any(kk == k and 200 <= st < 300 for _, kk, st in inwin): failures.append('no 2xx for %s' % k)
-    print(json.dumps({'verdict': 'FAIL' if failures else 'PASS', 'mode': a.mode, 'counts': counts, 'held_excluded': held,
+    verdict = 'FAIL' if failures else 'INCONCLUSIVE' if unk else 'PASS'
+    print(json.dumps({'verdict': verdict, 'mode': a.mode, 'counts': counts, 'held_excluded': held, 'unknown': unk,
                       'api_replicas': len(replicas), 'api_replica_sources': replicas, 'failures': failures}, sort_keys=True))
-    return 1 if failures else 0
+    return 0 if verdict == 'PASS' else 1
 
 
 if __name__ == '__main__':
diff --git a/infra/release-harness/install-d2.sh b/infra/release-harness/install-d2.sh
index 3572a3ea157..f335f811ccc 100644
--- a/infra/release-harness/install-d2.sh
+++ b/infra/release-harness/install-d2.sh
@@ -24,6 +24,8 @@ paths = ('bin/rw-runtime.sh', 'bin/rw-ship.sh', 'bin/selfhost-ctl.py',
          'bin/rw-rollback.sh', 'biz/prod-db-pool-20261013/ship-fast.sh')
 conf_rel = 'biz/release-waves/ship.conf'
 source_path = 'infra/release-harness'
+# goodqa#16148: rw-ship streams derive-job-secrets.py from the bound commit only when its blob is this recorded one.
+derive_path = 'infra/selfhost/app/derive-job-secrets.py'
 # Missing promisor objects must fail locally, never trigger Git's lazy fetch.
 git_env = dict(os.environ, GIT_OPTIONAL_LOCKS='0', GIT_NO_LAZY_FETCH='1', GIT_TERMINAL_PROMPT='0')
 
@@ -61,16 +63,29 @@ def committed(commit):
         result[rel] = git('cat-file', 'blob', spec)
     return result
 
+def derive_blob(commit):
+    """The blob id of derive-job-secrets.py at COMMIT (a regular blob), or None when the commit has no such file."""
+    entry = git('ls-tree', commit, '--', derive_path)
+    if not entry:
+        return None
+    m = re.fullmatch(rb'(100644|100755) blob ([0-9a-f]{40})\t' + re.escape(derive_path.encode()) + rb'\n', entry)
+    require(m is not None, 'derive-job-secrets.py at the commit is not a regular blob')
+    return m.group(2).decode()
+
 def validate_binding(data, files):
     try:
         lines = data.decode('ascii').splitlines()
     except UnicodeError:
         raise Refused('binding must be ASCII')
     fields = [line for line in lines if not line.startswith('#')]
-    require(len(fields) == 7 and re.fullmatch(r'commit [0-9a-f]{40}', fields[0]), 'invalid binding grammar/completeness')
+    require(len(fields) in (7, 8) and re.fullmatch(r'commit [0-9a-f]{40}', fields[0]), 'invalid binding grammar/completeness')
     require(fields[1] == 'path ' + source_path, 'invalid binding source path')
+    if len(fields) == 8:  # goodqa#16148: exactly one optional last line, and nothing else new
+        m = re.fullmatch(r'derive-blob ([0-9a-f]{40})', fields[7])
+        require(m is not None, 'invalid binding derive-blob grammar')
+        require(derive_blob(fields[0][7:]) == m.group(1), 'derive-blob is not the derive-job-secrets.py blob at the bound commit')
     recorded = {}
-    for line in fields[2:]:
+    for line in fields[2:7]:
         m = re.fullmatch(r'([0-9a-f]{64})  (\S+)', line)
         require(m is not None, 'invalid binding hash/path grammar')
         sha, rel = m.groups()
@@ -233,8 +248,10 @@ try:
         desired = dict(live)
         for rel in paths:
             desired[rel] = {'data': candidate[rel], 'mode': live[rel]['mode']}
+        blob_id = derive_blob(commit)  # goodqa#16148: absent = a 7-field binding (held releases only)
         data = ('# defensible-systems D2: exact reviewed runtime\ncommit ' + commit + '\npath ' + source_path + '\n' +
-                ''.join(digest(candidate[p]) + '  ' + p + '\n' for p in paths)).encode()
+                ''.join(digest(candidate[p]) + '  ' + p + '\n' for p in paths) +
+                ('derive-blob ' + blob_id + '\n' if blob_id else '')).encode()
         desired[binding_rel] = {'data': data, 'mode': live[binding_rel]['mode']}
     try:
         # Configuration stays byte-identical on upgrade. Rollback restores its saved bytes.
diff --git a/infra/release-harness/rw-ship.sh b/infra/release-harness/rw-ship.sh
index 59de044354d..9f23b02487f 100755
--- a/infra/release-harness/rw-ship.sh
+++ b/infra/release-harness/rw-ship.sh
@@ -240,6 +240,65 @@ print(v if isinstance(v,str) else ("" if v is None else json.dumps(v,sort_keys=T
       if [ -n "$BEFORE" ] && [ "$v" = "$BEFORE" ]; then say "ROLLED BACK: live API is $v again"; dbx "$NAME" deploy-failed "$v" "$1; rolled back to the previous stack $RB_API; run $RD"; exit 5; fi; fi
     KEEP=1; say "ROLLBACK NOT CONFIRMED (exit 8): $1, then the restore did not come back healthy at $BEFORE (live API ${v:-unreadable}). A person must look now: $RD/rollback.json"
     dbx "$NAME" deploy-unverified "${v:--}" "$1 and the rollback was not confirmed (live ${v:-unreadable}); run $RD"; exit 8; }
+  # JOB-SECRET UNHOLD GATE (goodqa#16148 spec v4 AC-8). intelligence-worker is released only when (a) derive-job-secrets.py,
+  # streamed from the BOUND release commit (never this working tree) and only when its blob is the derive-blob the release
+  # binding records, wrote or kept the key file; (b) dispatcher.env names it exactly once; (P3) a hardened trial boot of THIS
+  # dispatcher image reads a fixed fake key ok; and after the switch (c) the RECREATED dispatcher logged the key ok. Only
+  # status words cross: no value, no log text, no derive reason.
+  JS_DERIVE_PATH=infra/selfhost/app/derive-job-secrets.py
+  js_derive(){ local c b got out rc
+    case "${BWHY:-}" in OK*) ;; *) echo REFUSED-unbound; return 0;; esac
+    c=$(sed -n 's/^commit \([0-9a-f]\{40\}\)$/\1/p' "$RBIND" 2>/dev/null | head -1)
+    b=$(sed -n 's/^derive-blob \([0-9a-f]\{40\}\)$/\1/p' "$RBIND" 2>/dev/null | head -1)
+    [ -n "$c" ] && [ -n "$b" ] || { echo REFUSED-no-derive-blob; return 0; }
+    got=$(git -C "$REPO" rev-parse -q --verify "$c:$JS_DERIVE_PATH" 2>/dev/null)
+    [ -n "$got" ] || { echo REFUSED-not-in-bound-commit; return 0; }
+    [ "$got" = "$b" ] || { echo REFUSED-blob-mismatch; return 0; }
+    out=$(set -o pipefail; git -C "$REPO" cat-file blob "$b" | timeout 120 ssh -o ConnectTimeout=15 -o BatchMode=yes "$SH_APP" 'sudo python3 -I -' 2>/dev/null); rc=$?
+    case "$rc:$out" in
+      "0:job secret github-app-private-key: written") echo written;;
+      "0:job secret github-app-private-key: unchanged") echo unchanged;;
+      "2:job secret github-app-private-key: REFUSED "*) case "$out" in *$'\n'*|*$'\r'*) echo garbled;; *) echo REFUSED-derive;; esac;;
+      124:*|255:*) echo unreachable;;
+      *) echo garbled;; esac; }
+  js_blob(){ sed -n 's/^derive-blob \([0-9a-f]\{40\}\)$/\1/p' "$RBIND" 2>/dev/null | head -1; }
+  js_refuse(){ say "REFUSED (job-secret unhold gate, exit 2): $1. intelligence-worker is not released; nothing migrated or switched"
+    dbx "$NAME" deploy-failed "$BEFORE" "job-secret unhold gate: $1; nothing went live; run $RD"; exit 2; }
+  js_rehold(){ # js_rehold <stamp>: pin this release with intelligence-worker held, recreate ONLY the dispatcher and its guard
+    local HJ="" k
+    for k in "${!JOBKEYS[@]}"; do
+      if [ "${JOBKEYS[$k]}" = JOB_IMAGE_INTELLIGENCE_WORKER ]; then HJ="$HJ --job-hold ${JOBKEYS[$k]}"; else HJ="$HJ --job-image ${JOBKEYS[$k]}=${JOBREFS[$k]}"; fi
+    done
+    vmctl pin --stamp "$1" --sha "$SHA" --deploy-id "selfhost-$STAMP" --api "$IMG_API" --web "$IMG_WEB" --disp "$IMG_DISP"$HJ$HOLDARGS$GUARDARGS > "$RD/pin-$1.txt" 2>&1 || return 1
+    NEW_API=$(jget "$(grep -m1 '^{' "$RD/pin-$1.txt")" fp); NEW_WEB=$NEW_API
+    vmctl up-dispatcher --timeout "$SH_UP_TIMEOUT" > "$RD/up-$1.txt" 2>&1 && grep -q '^UP_OK' "$RD/up-$1.txt"; }
+  js_nohold(){ KEEP=1; say "HOLD NOT RE-APPLIED (exit 8): $1. intelligence-worker may be released without a verified key. A person must hold it now: SELFHOST_JOB_HOLD=intelligence-worker,transcribe in ship.conf and re-run, or selfhost-ctl.py pin ... --job-hold JOB_IMAGE_INTELLIGENCE_WORKER then up-dispatcher (run $RD)"
+    dbx "$NAME" deploy-unverified "$(live_sha)" "$1; HOLD NOT RE-APPLIED: intelligence-worker released without a verified GITHUB_APP_PRIVATE_KEY file; run $RD"; exit 8; }
+  js_hold_fail(){ # js_hold_fail <why>: gate (c) failed after the switch. Re-hold FIRST (dispatcher only), then roll back as usual
+    say "$1: re-holding intelligence-worker (job-dispatcher and its guard only) before anything else"
+    rb_guard "re-holding intelligence-worker ($1)" api || lost "re-hold refused ($1); intelligence-worker is NOT re-held"
+    infl rehold
+    js_rehold "${STAMP}h" || js_nohold "$1, then the dispatcher-only re-hold failed ($(grep -m1 -E '^(UP_|REFUSED|FAILED)' "$RD/up-${STAMP}h.txt" "$RD/pin-${STAMP}h.txt" 2>/dev/null | cut -d: -f2- | cut -c1-200))"
+    say "intelligence-worker re-held (stack ${NEW_API:-unreadable})"
+    [ "${MIG_APPLIED:-0}" = 0 ] || mig_hold "$1 (intelligence-worker was re-held)"
+    rb_guard "rolling back ($1)" api || lost "rollback refused ($1); intelligence-worker is re-held"
+    infl rollback
+    vmctl restore --stamp "${STAMP}h" > "$RD/restore-${STAMP}h.txt" 2>&1 || {
+      KEEP=1; say "ROLLBACK NOT CONFIRMED (exit 8): $1; intelligence-worker is re-held at this release, but the re-hold did not restore. A person must look now: $RD/rollback.json"
+      dbx "$NAME" deploy-unverified "$(live_sha)" "$1; intelligence-worker re-held, rollback not done (re-hold restore failed); run $RD"; exit 8; }
+    NEW_API=$PIN_FP; NEW_WEB=$PIN_FP
+    if ! vmctl restore --stamp "$STAMP" > "$RD/restore.txt" 2>&1; then
+      head -3 "$RD/restore.txt" | cut -c1-300 | tee -a "$LOG"
+      js_rehold "${STAMP}h2" || js_nohold "$1, then the rollback did not restore and the second re-hold failed"
+      KEEP=1; say "ROLLBACK NOT CONFIRMED (exit 8): $1; the previous stack did not restore, intelligence-worker is re-held at this release. A person must look now: $RD/rollback.json"
+      dbx "$NAME" deploy-unverified "$(live_sha)" "$1; intelligence-worker re-held, rollback not done; run $RD"; exit 8
+    fi
+    local v="" rc; vmctl up --timeout "$SH_UP_TIMEOUT" > "$RD/up-rollback.txt" 2>&1; rc=$?
+    say "rollback up: $(grep -m1 '^UP_' "$RD/up-rollback.txt" | cut -c1-300) (rc=$rc)"
+    if [ $rc = 0 ]; then for i in $(seq 1 18); do v=$(live_sha); [ -n "$BEFORE" ] && [ "$v" = "$BEFORE" ] && break; sleep 10; done
+      if [ -n "$BEFORE" ] && [ "$v" = "$BEFORE" ]; then say "ROLLED BACK: live API is $v again (the previous pins, intelligence-worker as it was)"; dbx "$NAME" deploy-failed "$v" "$1; intelligence-worker re-held, then rolled back to the previous stack $RB_API; run $RD"; exit 5; fi; fi
+    KEEP=1; say "ROLLBACK NOT CONFIRMED (exit 8): $1, then the restore did not come back healthy at $BEFORE (live API ${v:-unreadable}). A person must look now: $RD/rollback.json"
+    dbx "$NAME" deploy-unverified "${v:--}" "$1 and the rollback was not confirmed (live ${v:-unreadable}); run $RD"; exit 8; }
 fi
 # --- RELEASE-SCRIPT BINDING (defensible-systems D2 / E06, 2026-10-14). The release scripts live in an ignored lane root, so
 # what runs could be any edit. ship.conf RELEASE_BINDING=<file> names a binding: "commit <sha>", "path <dir in the product
@@ -705,13 +764,33 @@ PY
     ref=$(python3 -c 'import json,sys; r=json.loads(sys.argv[1]); print(sys.argv[2].split(":")[0] + "@" + r[sys.argv[2]])' "$REMOTEIDS" "${JOBIMGS[$i]}") || { say "ABORT: no VM image id for ${JOBIMGS[$i]}"; dbx "$NAME" deploy-failed "$BEFORE" "job image id unreadable; nothing went live; run $RD"; exit 3; }
     JOBARGS="$JOBARGS --job-image ${JOBKEYS[$i]}=$ref"; JOBREFS+=("$ref")
   done
+  DISP_PRE=""
+  if held intelligence-worker; then
+    if [ -n "$RBIND" ]; then JSD=$(js_derive); else JSD=skipped-unbound; fi
+    say "job secret (intelligence-worker held, not gated): derive $JSD"; JSGATE="held derive=$JSD"
+  else
+    say "job secret gate: intelligence-worker is released by this run; derive blob $(js_blob | cut -c1-12)"
+    JSD=$(js_derive); say "job secret gate (a) derive from the bound commit: $JSD"
+    case "$JSD" in written|unchanged) ;; *) js_refuse "(a) derive-job-secrets.py did not write or keep the key file ($JSD)";; esac
+    JSK=$(jget "$(vmctl envfile-key 2>/dev/null | grep -m1 '^{')" count)
+    say "job secret gate (b) key lines in dispatcher.env: ${JSK:-unreadable}"
+    [ "$JSK" = 1 ] || js_refuse "(b) dispatcher.env names the key ${JSK:-an unreadable number of} time(s), not once"
+    DREF=goodqa-job-dispatcher@$(python3 -c 'import json,sys
+try: print(json.loads(sys.argv[1]).get(sys.argv[2]) or "")
+except Exception: print("")' "$REMOTEIDS" "$IMG_DISP")
+    JST=$(jget "$(vmctl trial-boot --image "$DREF" --stamp "$STAMP" 2>/dev/null | grep -m1 '^{')" status)
+    say "job secret gate: trial boot of $DREF: ${JST:-unreadable}"
+    [ "$JST" = ok ] || js_refuse "the trial boot of the new dispatcher image did not read the key file (${JST:-unreadable})"
+    DISP_PRE=$(jget "$(vmctl disp-boot 2>/dev/null | grep -m1 '^{')" id)
+    JSGATE="released derive=$JSD key-lines=1 trial=ok"
+  fi
   mkdir -p audit/selfhost-deploys
-  python3 - "$NAME" "$SHA" "$STAMP" "$SH_APP" "$LOCALIDS" "$SH_BEFORE" "$HOLDNOTE" > "audit/selfhost-deploys/${SHA:0:8}-$STAMP.json" <<'PY'
+  python3 - "$NAME" "$SHA" "$STAMP" "$SH_APP" "$LOCALIDS" "$SH_BEFORE" "$HOLDNOTE" "$JSGATE" > "audit/selfhost-deploys/${SHA:0:8}-$STAMP.json" <<'PY'
 import json, sys
-name, sha, stamp, host, ids, before, holds = sys.argv[1:8]
+name, sha, stamp, host, ids, before, holds, jsgate = sys.argv[1:9]
 print(json.dumps({'release': name, 'sha': sha, 'stamp': stamp, 'host': host, 'deploymentId': 'selfhost-' + stamp,
                   'images': dict(l.split('=', 1) for l in ids.split('\n') if l), 'previous': json.loads(before or '{}'),
-                  'jobHolds': holds.split()}, indent=1, sort_keys=True))
+                  'jobHolds': holds.split(), 'jobSecretGate': jsgate}, indent=1, sort_keys=True))
 PY
   git add audit/selfhost-deploys && git "${GI[@]}" commit -q --no-verify -m "chore(deploy): self-host deploy record for ${SHA:0:12} ($NAME)
 
@@ -787,7 +866,7 @@ if [ "$TARGET" = selfhost ]; then
   if [ $rc -ne 0 ]; then head -3 "$RD/pin.txt" | cut -c1-300 | tee -a "$LOG"
     if [ $rc = 3 ]; then say "the re-pin was refused before any file changed; nothing went live"; dbx "$NAME" deploy-failed "$BEFORE" "re-pin refused (nothing changed); nothing went live; run $RD"; exit 4; fi
     sh_fail_rollback "the re-pin failed part way (rc=$rc)"; fi
-  NEW_API=$(jget "$(grep -m1 '^{' "$RD/pin.txt")" fp); NEW_WEB=$NEW_API; infl switch-api
+  NEW_API=$(jget "$(grep -m1 '^{' "$RD/pin.txt")" fp); NEW_WEB=$NEW_API; PIN_FP=$NEW_API; infl switch-api
   say "stack pinned: ${NEW_API:-unreadable} (was $RB_API); docker compose up"
   vmctl up --timeout "$SH_UP_TIMEOUT" > "$RD/up.txt" 2>&1; rc=$?
   say "up: $(grep -m1 '^UP_' "$RD/up.txt" | cut -c1-400) (rc=$rc)"
@@ -806,6 +885,13 @@ bad=[k for k in sys.argv[2:] if r.get(k)!=k.split("@",1)[1]]; print("OK" if not
     say "guard startup log: $(printf '%s' "$GH" | cut -c1-200)"
     case "$GH" in *'"held": "TRANSCODER_MODE=transcribe"'*) ;; *) sh_fail_rollback "the running guard does not report the transcription hold";; esac
   fi
+  if ! held intelligence-worker; then   # goodqa#16148 AC-8 (c): the RECREATED dispatcher (a new container) logged the key ok
+    DID=""; DST=""; for i in 1 2 3 4 5 6; do DB=$(vmctl disp-boot 2>/dev/null | grep -m1 '^{'); DID=$(jget "$DB" id); DST=$(jget "$DB" status)
+      [ -n "$DID" ] && [ "$DID" != "$DISP_PRE" ] && [ "$DST" = ok ] && break; sleep 5; done
+    say "job secret gate (c) dispatcher boot line: ${DST:-unreadable} (container ${DID:0:12}, before the switch ${DISP_PRE:0:12})"
+    if [ -z "$DID" ] || [ "$DID" = "$DISP_PRE" ]; then js_hold_fail "the job-dispatcher was not recreated by the switch (gate c)"; fi
+    [ "$DST" = ok ] || js_hold_fail "the recreated job-dispatcher did not log the GitHub App key file ok (${DST:-unreadable}, gate c)"
+  fi
   v=""; for i in $(seq 1 18); do v=$(live_sha); [ "$v" = "$SHA" ] && break; sleep 10; done
   [ "$v" = "$SHA" ] || sh_fail_rollback "the API reports ${v:-nothing}, not $SHA"
   say "API reports $SHA"
diff --git a/infra/release-harness/selfhost-ctl.py b/infra/release-harness/selfhost-ctl.py
index 44943ff819a..75124930f9d 100644
--- a/infra/release-harness/selfhost-ctl.py
+++ b/infra/release-harness/selfhost-ctl.py
@@ -23,6 +23,20 @@ Commands (exit 0 ok; 2 usage; 3 refused, NOTHING was changed; 4 failed part way,
                                  of them cannot be resolved or measured.
   guard-log                      one JSON line {"listening": bool, "held": VALUE|null}: what the running create-guard's own
                                  startup line says it enforces (goodqa#16136 D1: the hold is proven by the guard, not the file)
+  envfile-key                    goodqa#16148 AC-8 (b): one JSON line {"count": N}, how many lines of dispatcher.env are exactly
+                                 the JOB_ENVFILE key line for the GitHub App key. A count only; no line is ever printed.
+  disp-boot                      goodqa#16148 AC-8 (c): one JSON line {"id", "started", "status"} for the running job-dispatcher
+                                 container. Its own log, bounded by --since <its StartedAt> and --tail, is read here and never
+                                 printed or kept. status = ok (the exact boot line), missing (no line), error:<reason word>,
+                                 no-container or ambiguous.
+  trial-boot --image goodqa-job-dispatcher@sha256:<64 hex> --stamp S
+                                 goodqa#16148 AC-8 / P3: runs that exact image once with --boot-check, isolated: --rm,
+                                 --network none, --read-only, --cap-drop ALL, no-new-privileges, a non-root user, pids and
+                                 memory limits, no socket, no env_file. A fresh 0711 dir holds a FIXED fake marker (never the
+                                 real key) as root:64910 0440. 60 s timeout = timeout (and the container is removed). Prints
+                                 {"status": ok|fail|timeout|refused, "rc": N}; the container's output is never printed.
+  up-dispatcher [--timeout N]    goodqa#16148 AC-8 / P4: `docker compose up -d --no-deps` job-dispatcher and its guard ONLY,
+                                 then waits as `up` does for those two. UP_OK / UP_FAIL.
   pin --stamp S --sha SHA --deploy-id D --api REF --web REF --disp REF
                                  backs up compose.yaml, api.env and web.env to <file>.pre-rw-<S> (refuses if one exists),
                                  validates the new compose file with `docker compose config -q`, then replaces each file
@@ -151,15 +165,17 @@ class Stack:
     # ---- the four JOB_IMAGE_* lines (goodqa#16136): exactly once each in the whole file, inside the create-guard block
     @staticmethod
     def job_lines(text):
-        lines = text.split('\n'); res = {}; cur = None; in_svc = False
+        lines = text.split('\n'); res = {}; cur = None; in_svc = False; sub = None
         for i, l in enumerate(lines):
-            if l.rstrip() == 'services:': in_svc = True; cur = None; continue
-            if l and not l.startswith(' ') and not l.startswith('#'): in_svc = False; cur = None
+            if l.rstrip() == 'services:': in_svc = True; cur = None; sub = None; continue
+            if l and not l.startswith(' ') and not l.startswith('#'): in_svc = False; cur = None; sub = None
             m = re.match(r'^  ([A-Za-z0-9_.-]+):\s*(#.*)?$', l)
-            if in_svc and m: cur = m.group(1); continue
+            if in_svc and m: cur = m.group(1); sub = None; continue
+            m = re.match(r'^    ([A-Za-z0-9_.<-]+):', l)               # review bth-pr73-v4b F1: the service key a line is under
+            if in_svc and cur and m: sub = m.group(1)
             if 'JOB_IMAGE_' not in l.split('#', 1)[0]: continue
             m = JOB_LINE_RE.match(l)
-            if not m or not in_svc or cur != JOB_BLOCK:
+            if not m or not in_svc or cur != JOB_BLOCK or sub != 'environment':
                 raise Refused('compose.yaml line %d names a JOB_IMAGE_* key outside the %s &job-images block (the guard '
                               'allowlist and the dispatcher config could diverge)' % (i + 1, JOB_BLOCK))
             k = m.group(1)
@@ -235,8 +251,16 @@ class Stack:
         return int(rows[0][3]) // (1 << 20)
 
     def store_is_containerd(self):
-        r = docker('info', '-f', '{{json .DriverStatus}}', timeout=60)
-        return r.returncode == 0 and 'io.containerd.snapshotter' in r.stdout
+        """True for the containerd image store, False for a classic one, REFUSED when the store cannot be discovered
+        (receipt pr1370-v1 F2): a failed or unreadable `docker info` DriverStatus is never read as classic."""
+        try: r = docker('info', '-f', '{{json .DriverStatus}}', timeout=60)
+        except (OSError, subprocess.SubprocessError) as e: raise Refused('cannot discover the docker image store (docker info DriverStatus: %s)' % type(e).__name__)
+        try: ds = json.loads(r.stdout) if r.returncode == 0 else None
+        except ValueError: ds = None
+        # every row is exactly [name, value], two strings (receipt pr1370-v2b F3: [[]], one- and three-element rows refuse)
+        if not (isinstance(ds, list) and ds and all(isinstance(x, list) and len(x) == 2 and all(isinstance(y, str) for y in x) for x in ds)):
+            raise Refused('cannot discover the docker image store (docker info DriverStatus %s)' % ('rc=%d' % r.returncode if r.returncode else 'unreadable'))
+        return any('io.containerd.snapshotter' in y for x in ds for y in x)
 
     def resolved(self, text):
         """`docker compose config --format json` of TEXT (anchors and merge keys resolved by compose itself)."""
@@ -459,11 +483,17 @@ def presence_check(stk, comp, held):
     """Every release-managed ref the RESOLVED prepared compose names must be on this host (exact string; a job ref by its
     own digest). Pulled third-party images only warn. Raises Refused; returns the warnings."""
     svcs = stk.resolved(comp)
+    marked = set(stk.held_keys(comp))
     want_jobs = {k: v for k, v in stk.jobs(comp).items() if k not in held}
+    # review bth-pr73-v4b F1: every key, held ones included ("" in the resolved env), under environment, in both services
+    want_env = {k: ('' if k in marked else v) for k, v in stk.jobs(comp).items()}
     for s in (JOB_BLOCK, 'job-dispatcher'):
-        envs = (svcs.get(s) or {}).get('environment') or {}
-        got = {k: envs.get(k) for k in want_jobs}
-        if got != want_jobs: raise Refused('resolved compose: %s does not carry the pinned job images (%s)' % (s, got))
+        envs = (svcs.get(s) or {}).get('environment')
+        if not isinstance(envs, dict): raise Refused('resolved compose: %s has no environment mapping' % s)
+        got = {k: envs[k] for k in envs if k.startswith('JOB_IMAGE_')}
+        if got != want_env:
+            raise Refused('resolved compose: %s environment does not carry exactly the job image lines (%s)'
+                          % (s, ', '.join('%s=%s' % (k, 'held' if got.get(k) == '' else 'set' if k in got else 'missing') for k in sorted(set(want_env) | set(got)))))
     managed = {(svcs.get(s) or {}).get('image') for s in SERVICES}
     bad = [r for r in managed if not r or not stk.image_ids([r])[r]]
     bad += stk.job_ids_ok(list(want_jobs.values()))
@@ -589,22 +619,116 @@ def restore_fence(stk, a, files, baks):
         raise Refused('live fingerprint is %s, not --expect-fp %s: production changed; nothing restored' % (live, a.expect_fp))
 
 
-def cmd_up(stk, a):
-    r = stk.dc('up', '-d', '--no-deps', '--pull', 'never', *SERVICES, timeout=a.timeout + 120)
+# ---- goodqa#16148 AC-8: the job-secret unhold gate (names and status words only; no value, no log text leaves here)
+JOBSECRET_KEY_LINE = 'JOB_ENVFILE_INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY=/run/goodqa-secrets/github-app-private-key'
+DISP_OK_LINE = 'job env file INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY: ok'
+DISP_ERR_PREFIX = 'job env file for INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY: '
+DISP_ERR_WORDS = {'missing': 'missing-file', 'is a symlink': 'symlink', 'unreadable': 'unreadable',
+                  'not a regular file': 'not-regular', 'over 64 KiB': 'too-large', 'empty': 'empty',
+                  'value holds CR, LF or NUL': 'bad-bytes', 'value is not valid UTF-8': 'bad-utf8',
+                  'path outside the secrets directory': 'outside-dir', 'cannot read (error)': 'read-error'}
+DISP_LOG_TAIL = 2000
+TRIAL_IMAGE_RE = re.compile(r'^goodqa-job-dispatcher@sha256:[0-9a-f]{64}$')
+TRIAL_STAMP_RE = re.compile(r'^[A-Za-z0-9._-]{1,80}$')
+TRIAL_MARKER = 'goodqa-trial-boot-fixed-fake-marker-not-a-key'   # fixed; never derived from the real key
+TRIAL_TIMEOUT = 60
+TRIAL_GID = 64910
+TRIAL_FLAGS = ('--rm', '--network', 'none', '--read-only', '--tmpfs', '/tmp', '--cap-drop', 'ALL',
+               '--security-opt', 'no-new-privileges', '--user', 'node', '--group-add', str(TRIAL_GID),
+               '--pids-limit', '64', '--memory', '256m')
+
+
+def cmd_envfile_key(stk, a):
+    path = os.path.join(stk.env_dir, 'dispatcher.env')
+    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
+    with os.fdopen(fd, 'rb') as f:
+        n = sum(1 for l in f.read().split(b'\n') if l.rstrip(b'\r') == JOBSECRET_KEY_LINE.encode())
+    out({'count': n}); return 0
+
+
+def disp_status(log_text):
+    """Status word of the GitHub App key boot line in a dispatcher log (pino JSON lines; `msg` compared exactly)."""
+    err = None
+    for l in log_text.split('\n'):
+        try: msg = json.loads(l).get('msg')
+        except Exception: continue
+        if not isinstance(msg, str): continue
+        if msg == DISP_OK_LINE: return 'ok'
+        if msg.startswith(DISP_ERR_PREFIX) and err is None:
+            err = 'error:' + DISP_ERR_WORDS.get(msg[len(DISP_ERR_PREFIX):], 'other')
+    return err or 'missing'
+
+
+def cmd_disp_boot(stk, a):
+    ids = docker('ps', '-q', '--no-trunc', '--filter', 'label=com.docker.compose.project=' + stk.project,
+                 '--filter', 'label=com.docker.compose.service=job-dispatcher', '--filter', 'status=running',
+                 timeout=60).stdout.split()
+    ids = [i for i in ids if re.match(r'^[0-9a-f]{12,64}$', i)]
+    if len(ids) != 1:
+        out({'id': None, 'started': None, 'status': 'no-container' if not ids else 'ambiguous'}); return 0
+    cid = ids[0]
+    started = docker('inspect', '-f', '{{.State.StartedAt}}', cid, timeout=60).stdout.strip()
+    if not re.match(r'^\d{4}-\d\d-\d\dT[0-9:.]+Z$', started):
+        out({'id': cid, 'started': None, 'status': 'unreadable'}); return 0
+    r = docker('logs', '--since', started, '--tail', str(DISP_LOG_TAIL), cid, timeout=60)
+    status = disp_status((r.stdout or '') + '\n' + (r.stderr or '')) if r.returncode == 0 else 'unreadable'
+    del r
+    out({'id': cid, 'started': started, 'status': status}); return 0
+
+
+def trial_argv(name, image, secrets_dir):
+    return ['run', *TRIAL_FLAGS, '--name', name,
+            '-e', 'JOB_DISPATCH_TOKEN=trial-fake-token', '-e', JOBSECRET_KEY_LINE,
+            '-v', secrets_dir + ':/run/goodqa-secrets:ro',
+            '--entrypoint', 'node_modules/.bin/tsx', image, 'src/index.ts', '--boot-check']
+
+
+def cmd_trial_boot(stk, a):
+    if not TRIAL_IMAGE_RE.match(a.image) or not TRIAL_STAMP_RE.match(a.stamp):
+        out({'status': 'refused', 'rc': None}); return 3
+    if stk.image_ids([a.image]).get(a.image) != a.image.split('@', 1)[1]:
+        out({'status': 'refused', 'rc': None}); return 3
+    import tempfile
+    name = 'goodqa-trial-' + a.stamp
+    d = tempfile.mkdtemp(prefix='goodqa-trial-')
+    try:
+        os.chmod(d, 0o711)
+        f = os.path.join(d, 'github-app-private-key')
+        fd = os.open(f, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
+        with os.fdopen(fd, 'w') as fh: fh.write(TRIAL_MARKER + '\n')
+        os.chown(f, 0, TRIAL_GID); os.chmod(f, 0o440)
+        try:
+            r = docker(*trial_argv(name, a.image, d), timeout=TRIAL_TIMEOUT)
+        except subprocess.TimeoutExpired:
+            out({'status': 'timeout', 'rc': None}); return 5
+        ok = r.returncode == 0 and DISP_OK_LINE in r.stdout.split('\n')
+        del r
+        out({'status': 'ok' if ok else 'fail', 'rc': 0 if ok else 1}); return 0 if ok else 5
+    finally:
+        docker('rm', '-f', name, timeout=60)
+        shutil.rmtree(d, ignore_errors=True)
+
+
+def cmd_up_dispatcher(stk, a):
+    return cmd_up(stk, a, services=('job-dispatcher', 'job-dispatcher-create-guard'))
+
+
+def cmd_up(stk, a, services=SERVICES):
+    r = stk.dc('up', '-d', '--no-deps', '--pull', 'never', *services, timeout=a.timeout + 120)
     if r.returncode != 0:
         out('UP_FAIL docker compose up rc=%d: %s' % (r.returncode, r.stderr.strip().replace('\n', ' | ')[-400:])); return 5
     want = stk.replicas(); pins = stk.pins(); ids = stk.image_ids(sorted(set(pins.values())))
     end = time.time() + a.timeout; why = 'not checked'
     while True:
         cs = stk.containers(); bad = []
-        for s in SERVICES:
+        for s in services:
             mine = [c for c in cs if c['service'] == s and c['status'] in ('running', 'restarting', 'created')]
             ok = [c for c in mine if c['status'] == 'running' and c['image'] == ids[pins[s]]
                   and (s not in HEALTHY or c['health'] == 'healthy')]
             if len(ok) != want[s] or len(mine) != want[s]:
                 bad.append('%s %d/%d ready (%s)' % (s, len(ok), want[s], ', '.join('%s %s %s' % (c['name'], c['status'], c['health'] or '-') for c in mine) or 'none'))
         if not bad:
-            out('UP_OK ' + json.dumps({s: want[s] for s in SERVICES}, sort_keys=True)); return 0
+            out('UP_OK ' + json.dumps({s: want[s] for s in services}, sort_keys=True)); return 0
         why = '; '.join(bad)
         if time.time() >= end: break
         time.sleep(a.every)
@@ -671,6 +795,9 @@ def main(argv):
     pn.add_argument('--job-hold', action='append', default=[], metavar='KEY')
     pn.add_argument('--guard-hold', action='append', default=[], metavar='KEY=VALUE')
     sub.add_parser('disk'); sub.add_parser('guard-log')
+    sub.add_parser('envfile-key'); sub.add_parser('disp-boot')
+    tb = sub.add_parser('trial-boot'); tb.add_argument('--image', required=True); tb.add_argument('--stamp', required=True)
+    ud = sub.add_parser('up-dispatcher'); ud.add_argument('--timeout', type=int, default=300); ud.add_argument('--every', type=float, default=3)
     rs = sub.add_parser('restore'); rs.add_argument('--stamp', required=True); rs.add_argument('--expect-fp')
     up = sub.add_parser('up'); up.add_argument('--timeout', type=int, default=300); up.add_argument('--every', type=float, default=3)
     mg = sub.add_parser('migrate'); mg.add_argument('--image', required=True); mg.add_argument('--mode', choices=('dry', 'apply'), required=True)
@@ -697,7 +824,7 @@ def main(argv):
             for r in a.refs:
                 if not REF_RE.match(r): raise Refused('bad image ref %r' % r)
             out(stk.image_ids(a.refs)); return 0
-        return {'set-secret-env': cmd_secret_env, 'remove-secret-env': cmd_secret_env, 'pin': cmd_pin, 'restore': cmd_restore, 'up': cmd_up, 'migrate': cmd_migrate, 'logs': cmd_logs}[a.cmd](stk, a) or 0
+        return {'set-secret-env': cmd_secret_env, 'remove-secret-env': cmd_secret_env, 'pin': cmd_pin, 'restore': cmd_restore, 'up': cmd_up, 'up-dispatcher': cmd_up_dispatcher, 'envfile-key': cmd_envfile_key, 'disp-boot': cmd_disp_boot, 'trial-boot': cmd_trial_boot, 'migrate': cmd_migrate, 'logs': cmd_logs}[a.cmd](stk, a) or 0
     except Refused as e:
         out('REFUSED ' + str(e)); return 3
     except Exception as e:
diff --git a/infra/release-harness/test_ac13_count.py b/infra/release-harness/test_ac13_count.py
index ed8b633812b..635dac0855f 100644
--- a/infra/release-harness/test_ac13_count.py
+++ b/infra/release-harness/test_ac13_count.py
@@ -145,3 +145,119 @@ def test_window_and_unreadable(tmp_path):
     assert rc == 0, o
     rc, o = run(str(tmp_path / 'absent.log'), '--mode', 'post')
     assert rc == 2 and o['verdict'] == 'FAIL', o
+
+
+# ---- receipt pr1370-v1 F1: a record the matcher cannot correlate or read never lets a run PASS
+def _raw(tmp_path, extra, base=OK, name='disp.log'):
+    p = _log(tmp_path, base, name); open(p, 'a').write('\n'.join(extra) + '\n'); return p
+
+
+def _done(rid, st, t=T0 + 50):
+    return json.dumps({'level': 30, 'time': t, 'reqId': rid, 'msg': 'request completed', 'res': {'statusCode': st}})
+
+
+def _start(rid, kind='scan', t=T0 + 50):
+    return json.dumps({'level': 30, 'time': t, 'reqId': rid, 'msg': 'incoming request', 'req': {'method': 'POST', 'url': '/jobs/%s/run' % kind}})
+
+
+def test_orphan_in_window_500_is_never_pass(tmp_path):
+    rc, o = run(_raw(tmp_path, [_done('req-orphan', 500)]), '--mode', 'post', *REQ)
+    assert rc == 1 and o['verdict'] == 'INCONCLUSIVE' and o['unknown'] == {'orphan completion': 1}, o
+
+
+def test_orphan_outside_the_window_is_ignored_and_untimed_counts(tmp_path):
+    rc, o = run(_raw(tmp_path, [_done('req-orphan', 500, t=T0 - 10)]), '--mode', 'post', '--since', str(T0), *REQ)
+    assert rc == 0 and o['verdict'] == 'PASS', o
+    untimed = json.dumps({'level': 30, 'reqId': 'req-orphan', 'msg': 'request completed', 'res': {'statusCode': 500}})
+    rc, o = run(_raw(tmp_path, [untimed]), '--mode', 'post', '--since', str(T0), *REQ)
+    assert rc == 1 and o['verdict'] == 'INCONCLUSIVE', o
+
+
+def test_malformed_lines_are_unknown(tmp_path):
+    for bad in ('2026-11-16T00:00:59Z {"level":30,"reqId":"req-1","msg":"request completed","res":{"statusCode":500', '[{"a":1}]', '{"x": 1} trailing'):
+        rc, o = run(_raw(tmp_path, [bad]), '--mode', 'post', *REQ)
+        assert rc == 1 and o['verdict'] == 'INCONCLUSIVE' and o['unknown'] == {'malformed': 1}, (bad, o)
+
+
+def test_invalid_status_or_time_on_a_launch_is_unknown(tmp_path):
+    for st, t in (('500', T0 + 50), (True, T0 + 50), (None, T0 + 50), (99, T0 + 50), (600, T0 + 50), (500.0, T0 + 50), (200, 'later'), (200, True)):
+        line = json.dumps({'level': 30, 'time': t, 'reqId': 'req-x', 'msg': 'request completed', 'res': {'statusCode': st}})
+        rc, o = run(_raw(tmp_path, [_start('req-x'), line]), '--mode', 'post', *REQ)
+        assert rc == 1 and o['verdict'] == 'INCONCLUSIVE' and o['unknown'] == {'invalid status or time': 1}, (st, t, o)
+    line = json.dumps({'level': 30, 'time': T0 + 50, 'reqId': 'req-x', 'msg': 'request completed', 'res': 'oops'})
+    rc, o = run(_raw(tmp_path, [_start('req-x'), line]), '--mode', 'post', *REQ)
+    assert rc == 1 and o['unknown'] == {'invalid status or time': 1}, o
+
+
+def test_a_launch_without_its_completion_is_unknown(tmp_path):
+    rc, o = run(_raw(tmp_path, [_start('req-x')]), '--mode', 'post', *REQ)
+    assert rc == 1 and o['verdict'] == 'INCONCLUSIVE' and o['unknown'] == {'no completion': 1}, o
+    rc, o = run(_raw(tmp_path, [_start('req-x'), _start('req-x', t=T0 + 51), _done('req-x', 200, t=T0 + 51)]), '--mode', 'post', *REQ)
+    assert rc == 1 and o['unknown'] == {'no completion': 1}, 'a reused reqId supersedes the first launch'
+
+
+def test_a_non_launch_request_still_pairs_and_counts_nothing(tmp_path):
+    health = json.dumps({'level': 30, 'time': T0 + 50, 'reqId': 'req-h', 'msg': 'incoming request', 'req': {'method': 'GET', 'url': '/healthz'}})
+    rc, o = run(_raw(tmp_path, [health, _done('req-h', 503)]), '--mode', 'post', *REQ)
+    assert rc == 0 and o['verdict'] == 'PASS' and o['unknown'] == {}, o
+
+
+def test_unknown_also_blocks_the_positive_control_and_a_failure_still_wins(tmp_path):
+    rc, o = run(_raw(tmp_path, [_done('req-orphan', 500)], base=OK + [('scan', 422)]), '--mode', 'pre')
+    assert rc == 1 and o['verdict'] == 'INCONCLUSIVE', o
+    rc, o = run(_raw(tmp_path, [_done('req-orphan', 500)], base=OK + [('scan', 500)]), '--mode', 'post', *REQ)
+    assert rc == 1 and o['verdict'] == 'FAIL' and o['unknown'] == {'orphan completion': 1}, o
+
+
+# ---- receipt pr1370-v2b F1: an unusable completion time never borrows the start time (a pre-window start, a 500 done)
+def test_unusable_completion_time_is_untimed_not_the_start_time(tmp_path):
+    for bad_t in (None, 'later', True):
+        d = {'level': 30, 'reqId': 'req-x', 'msg': 'request completed', 'res': {'statusCode': 500}}
+        if bad_t is not None: d['time'] = bad_t
+        rc, o = run(_raw(tmp_path, [_start('req-x', t=T0 - 10), json.dumps(d)]), '--mode', 'post', '--since', str(T0), *REQ)
+        assert rc == 1 and o['verdict'] == 'INCONCLUSIVE' and o['unknown'] == {'invalid status or time': 1}, (bad_t, o)
+    # an unusable STATUS keeps its own usable completion time: outside the window it is ignored
+    d = {'level': 30, 'time': T0 - 5, 'reqId': 'req-x', 'msg': 'request completed', 'res': {'statusCode': '500'}}
+    rc, o = run(_raw(tmp_path, [_start('req-x', t=T0 - 10), json.dumps(d)]), '--mode', 'post', '--since', str(T0), *REQ)
+    assert rc == 0 and o['verdict'] == 'PASS', o
+
+
+# ---- receipt pr1370-v2b F2: NaN, Infinity and 1e999 are not times; each is an untimed unknown (paired, orphan, unfinished)
+NONFINITE = ('NaN', 'Infinity', '-Infinity', '1e999')
+
+
+def _line(rid, msg, t_raw, st=500):
+    body = '"res": {"statusCode": %d}' % st if msg == 'request completed' else '"req": {"method": "POST", "url": "/jobs/scan/run"}'
+    return '{"level": 30, "time": %s, "reqId": "%s", "msg": "%s", %s}' % (t_raw, rid, msg, body)
+
+
+def test_non_finite_times_are_untimed_unknowns(tmp_path):
+    since = ('--since', str(T0), '--until', str(T0 + 10 ** 9))
+    for raw in NONFINITE:
+        cases = (
+            ('paired', [_start('req-x', t=T0 - 10), _line('req-x', 'request completed', raw)], 'invalid status or time'),
+            ('orphan', [_line('req-o', 'request completed', raw)], 'orphan completion'),
+            ('unfinished', [_line('req-u', 'incoming request', raw)], 'no completion'),
+        )
+        for name, lines, why in cases:
+            rc, o = run(_raw(tmp_path, lines), '--mode', 'post', *since, *REQ)
+            assert rc == 1 and o['verdict'] == 'INCONCLUSIVE' and o['unknown'] == {why: 1}, (raw, name, o)
+    # a non-finite time on a 2xx is never counted as an in-window ok either
+    rc, o = run(_raw(tmp_path, [_start('req-x'), _line('req-x', 'request completed', 'NaN', st=200)], base=[]), '--mode', 'post', '--require-2xx', 'scan')
+    assert rc == 1 and o['unknown'] == {'invalid status or time': 1}, o
+
+
+# ---- receipt pr1370-v2c F1 (Low): a huge JSON integer time gives a structured verdict, never a traceback
+def test_huge_integer_time_is_an_untimed_unknown_with_a_json_verdict(tmp_path):
+    huge = '1' + '0' * 400
+    since = ('--since', str(T0))
+    cases = (
+        ('paired', [_start('req-x', t=T0 - 10), _line('req-x', 'request completed', huge)], 'invalid status or time'),
+        ('orphan', [_line('req-o', 'request completed', huge)], 'orphan completion'),
+        ('unfinished', [_line('req-u', 'incoming request', huge)], 'no completion'),
+        ('past-float-range', [_line('req-o', 'request completed', str(2 ** 1100))], 'orphan completion'),
+    )
+    for name, lines, why in cases:
+        rc, o = run(_raw(tmp_path, lines), '--mode', 'post', *since, *REQ)
+        assert isinstance(o, dict), (name, 'no JSON verdict: ' + str(o)[-300:])
+        assert rc == 1 and o['verdict'] == 'INCONCLUSIVE' and o['unknown'] == {why: 1}, (name, o)
diff --git a/infra/release-harness/test_install_d2_upgrade.py b/infra/release-harness/test_install_d2_upgrade.py
index 17d4174214e..e65b2ee4d4c 100644
--- a/infra/release-harness/test_install_d2_upgrade.py
+++ b/infra/release-harness/test_install_d2_upgrade.py
@@ -446,3 +446,66 @@ def test_promisor_missing_object_refuses_locally(f, tmp_path):
     assert r.returncode == 3, r.stdout + r.stderr
     assert not marker.exists(), 'missing object contacted promisor transport'
     assert f.snapshot() == before
+
+
+
+# ---- goodqa#16148: one optional `derive-blob <40hex>` line, recorded from the candidate commit and checked against it
+DERIVE = 'infra/selfhost/app/derive-job-secrets.py'
+
+
+def with_derive(f, base, body=b'print("fake derive, not the real script")\n'):
+    """A commit = BASE's tree + derive-job-secrets.py (commit-tree: HEAD, index and checkout untouched)."""
+    env = dict(os.environ, GIT_INDEX_FILE=str(f.repo.parent / ('derive-index-' + base[:8])), GIT_AUTHOR_NAME='t',
+               GIT_AUTHOR_EMAIL='t@example.com', GIT_COMMITTER_NAME='t', GIT_COMMITTER_EMAIL='t@example.com')
+    def run(*a, inp=None):
+        return subprocess.run(['git', '-C', str(f.repo), *a], env=env, input=inp, capture_output=True, check=True).stdout.decode().strip()
+    run('read-tree', base)
+    h = run('hash-object', '-w', '--stdin', inp=body)
+    run('update-index', '--add', '--cacheinfo', '100644,%s,%s' % (h, DERIVE))
+    return run('commit-tree', run('write-tree'), '-p', base, '-m', 'add derive'), h
+
+
+def fields(data):
+    return [l for l in data.decode().splitlines() if not l.startswith('#')]
+
+
+def test_install_records_the_derive_blob_of_the_candidate(f):
+    c, h = with_derive(f, NEW)
+    r = f.run('apply', '--commit', c, '--skip-until', '2000-01-01T00:00:00Z')
+    assert r.returncode == 0, r.stdout + r.stderr
+    b = fields(f.bf.read_bytes())
+    assert len(b) == 8 and b[0] == 'commit ' + c and b[7] == 'derive-blob ' + h, b
+    after = f.snapshot()
+    r = f.run('apply', '--commit', c)
+    assert r.returncode == 0 and 'identical reviewed runtime' in r.stdout, r.stdout + r.stderr
+    assert f.snapshot() == after
+
+
+def test_a_candidate_without_derive_installs_a_seven_field_binding(f):
+    """Still installs; rw-ship then ships only held releases (test_rw_ship_jobsecret_gate: no-blob held ships, unheld refuses)."""
+    r = f.apply('--skip-until', '2000-01-01T00:00:00Z')
+    assert r.returncode == 0, r.stdout + r.stderr
+    b = fields(f.bf.read_bytes())
+    assert len(b) == 7 and not any(l.startswith('derive-blob') for l in b), b
+
+
+@pytest.mark.parametrize('fault', ['file-missing', 'blob-mismatch', 'duplicate', 'unknown-8th', 'not-last'])
+def test_a_bad_derive_blob_line_in_the_live_binding_refuses_read_only(f, fault):
+    c, h = with_derive(f, OLD)
+    base = fields(binding(OLD))
+    if fault == 'file-missing': lines = base + ['derive-blob ' + h]              # OLD itself has no derive file
+    else: lines = ['commit ' + c] + base[1:]
+    if fault == 'blob-mismatch': lines.append('derive-blob ' + '0' * 40)
+    if fault == 'duplicate': lines += ['derive-blob ' + h] * 2
+    if fault == 'unknown-8th': lines.append('derive-path ' + DERIVE)
+    if fault == 'not-last': lines.insert(2, 'derive-blob ' + h)
+    f.bf.write_text('\n'.join(lines) + '\n')
+    f.refuse('apply', '--commit', NEW)
+
+
+def test_a_good_derive_blob_line_in_the_live_binding_is_accepted(f):
+    """Control for the refusals above: the same live binding with its correct line validates."""
+    c, h = with_derive(f, OLD)
+    f.bf.write_text('\n'.join(['commit ' + c] + fields(binding(OLD))[1:] + ['derive-blob ' + h]) + '\n')
+    r = f.run('check', '--commit', NEW)
+    assert r.returncode == 0 and 'validated current binding and candidate' in r.stdout, r.stdout + r.stderr
diff --git a/infra/release-harness/test_runner_ship_adapter.py b/infra/release-harness/test_runner_ship_adapter.py
index 7d95cede417..7891b090396 100644
--- a/infra/release-harness/test_runner_ship_adapter.py
+++ b/infra/release-harness/test_runner_ship_adapter.py
@@ -43,6 +43,9 @@ def adapter(tmp_path):
         target = Path(r.F, rel); target.parent.mkdir(parents=True, exist_ok=True)
         shutil.copyfile(ROOT / name, target); shutil.copyfile(ROOT / name, committed / name)
         lines.append(hashlib.sha256(target.read_bytes()).hexdigest() + '  ' + rel)
+    derive = Path(sh.DERIVE_SRC).read_bytes()             # goodqa#16148: the bound commit also carries derive-job-secrets.py
+    Path(r.repo, sh.DERIVE_PATH).parent.mkdir(parents=True, exist_ok=True); Path(r.repo, sh.DERIVE_PATH).write_bytes(derive)
+    lines.append('derive-blob ' + sh.blob_sha(derive))
     sh.base.git('add', '.', cwd=r.repo); sh.base.git('commit', '-qm', 'reviewed five-file binding', cwd=r.repo)
     lines.insert(0, 'commit ' + sh.base.git('rev-parse', 'HEAD', cwd=r.repo))
     binding = Path(r.F, 'bin/RELEASE_BINDING'); binding.write_text('\n'.join(lines) + '\n')
diff --git a/infra/release-harness/test_rw_release_authority_d2.py b/infra/release-harness/test_rw_release_authority_d2.py
index a1fc08aa40c..c179328268e 100644
--- a/infra/release-harness/test_rw_release_authority_d2.py
+++ b/infra/release-harness/test_rw_release_authority_d2.py
@@ -120,7 +120,7 @@ def ctl2(tmp_path):
     return run, snap, vm, env
 
 
-PIN2 = ('pin', '--stamp', 'S2', '--sha', '3' * 40, '--deploy-id', 'selfhost-S2', '--api', 'n:web', '--web', 'n:api', '--disp', 'n:disp')
+PIN2 = ('pin', '--stamp', 'S2', '--sha', '3' * 40, '--deploy-id', 'selfhost-S2', '--api', 'n:web', '--web', 'n:api', '--disp', 'n:disp') + sh.JOBARGS   # 1371: pin needs every job key
 
 
 def test_ctl_restore_of_an_older_stamp_is_refused_after_a_newer_pin(tmp_path):
@@ -187,11 +187,15 @@ def bind(R, tamper=None):
     d = os.path.join(R.repo, 'infra/release-harness'); os.makedirs(d, exist_ok=True)
     names = ('rw-ship.sh', 'selfhost-ctl.py', 'rw-rollback.sh', 'rw-runtime.sh')
     for n in names: open(os.path.join(d, n), 'wb').write(open(os.path.join(R.F, 'bin', n), 'rb').read())
+    derive = open(sh.DERIVE_SRC, 'rb').read()          # goodqa#16148: the bound commit also carries derive-job-secrets.py
+    os.makedirs(os.path.join(R.repo, os.path.dirname(sh.DERIVE_PATH)), exist_ok=True)
+    open(os.path.join(R.repo, sh.DERIVE_PATH), 'wb').write(derive)
     base.git('add', '-A', cwd=R.repo); base.git('commit', '-q', '-m', 'bind release scripts', cwd=R.repo)
     c = base.git('rev-parse', 'HEAD', cwd=R.repo); base.git('push', '-q', 'origin', 'HEAD:refs/heads/release-harness', cwd=R.repo)
     lines = ['commit ' + c, 'path infra/release-harness']
     for n in names:
         lines.append('%s  bin/%s' % (hashlib.sha256(open(os.path.join(R.F, 'bin', n), 'rb').read()).hexdigest(), n))
+    lines.append('derive-blob ' + sh.blob_sha(derive))
     bf = os.path.join(R.F, 'bin', 'RELEASE_BINDING'); open(bf, 'w').write('\n'.join(lines) + '\n'); R.conf('RELEASE_BINDING=' + bf)
     if tamper == 'installed-edit':
         with open(os.path.join(R.F, 'bin', 'selfhost-ctl.py'), 'a') as f: f.write('\n# edited after review\n')
diff --git a/infra/release-harness/test_rw_ship_jobsecret_gate.py b/infra/release-harness/test_rw_ship_jobsecret_gate.py
new file mode 100644
index 00000000000..daa61a33357
--- /dev/null
+++ b/infra/release-harness/test_rw_ship_jobsecret_gate.py
@@ -0,0 +1,199 @@
+"""goodqa#16148 spec v4 AC-8: bin/rw-ship.sh's job-secret unhold gate, whole script, on the fake VM of test_rw_ship_selfhost.py.
+
+intelligence-worker is released only when, before anything is migrated or switched:
+  (a) derive-job-secrets.py, streamed from the BOUND release commit (never the working tree) and only when its blob equals the
+      binding's derive-blob line, prints exactly `job secret github-app-private-key: written|unchanged` with rc 0;
+  (b) dispatcher.env names JOB_ENVFILE_INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY exactly once;
+  (P3) a hardened trial boot of THIS dispatcher image, by its VM digest, reads a fixed fake key ok;
+and after the switch (c) a NEW dispatcher container logged the key ok. A (c) failure re-holds intelligence-worker FIRST by a
+dispatcher-only recreate (P4 / NEG-19), then rolls back as usual (exit 5), or stops at exit 8 after a migration or when the
+re-hold or the rollback fails. Held releases are never gated: a failed derive only warns.
+Run: cd infra/release-harness && python3 -m pytest -q -p no:cacheprovider test_rw_ship_jobsecret_gate.py
+     (RW_SHIP_UNDER_TEST=<path> for a mutant copy)
+"""
+import json, os, re, subprocess
+
+import pytest
+
+import test_rw_ship_selfhost as sh
+from test_rw_ship_selfhost import INTEL, HELD, BASE_PINS, BASE_JOBS, _conf, bind_release, blob_sha
+
+LINE = 'job secret github-app-private-key: '
+DERIVE_BLOB = blob_sha(open(sh.DERIVE_SRC, 'rb').read())
+FULL = 'api,web,job-dispatcher,job-dispatcher-create-guard'
+DISP_ONLY = 'job-dispatcher,job-dispatcher-create-guard'
+MARK = 'PLANTED-REASON-7f3a'          # a derive reason / log text that must never reach the run output
+
+
+@pytest.fixture
+def R(tmp_path):
+    r = sh.SRoot(str(tmp_path)); yield r; r.cleanup()
+
+
+def ups(R): return re.findall(r'^remote UPSVCS (\S+)$', R.dlog(), re.M)
+def rd(R):
+    d = os.path.join(R.F, 'biz/release-waves/deploys'); return os.path.join(d, sorted(os.listdir(d))[-1])
+def derive_runs(R): return len(R.get('derive-runs').split())
+def audit(R, sha):
+    names = subprocess.run(['git', 'ls-tree', '-r', '--name-only', 'main', 'audit/selfhost-deploys'], cwd=R.origin,
+                           capture_output=True, text=True).stdout.split()
+    n = [x for x in names if sha[:8] in x]
+    return json.loads(subprocess.run(['git', 'show', 'main:' + n[0]], cwd=R.origin, capture_output=True, text=True).stdout) if n else None
+def refused_before_anything(R, before, out):
+    assert 'REFUSED (job-secret unhold gate, exit 2)' in out, out
+    assert R.pins() == BASE_PINS and R.jobs() == BASE_JOBS and R.env_sha('api') == before
+    assert 'MIGRATE' not in R.dlog() and ups(R) == [] and R.get('live') == before
+    assert not [f for f in os.listdir(R.vm) if '.pre-rw-' in f]
+
+
+# ---------------------------------------------------------------- the released path
+def test_unheld_release_passes_every_gate_in_order(R):
+    sha = R.release('release/js-1'); rc, out = R.run('release/js-1', sha)
+    assert rc == 0, out
+    assert 'release scripts: bound, OK 4 file(s)' in out, 'the derive-blob line is not a bound file'
+    assert R.get('derive-streamed').strip() == DERIVE_BLOB, 'derive must be the bound blob'
+    assert 'gate (a) derive from the bound commit: written' in out and 'gate (b) key lines in dispatcher.env: 1' in out, out
+    disp = R.pins()['job-dispatcher']; vm_id = json.load(open(os.path.join(R.st, 'docker', 'images-remote.json')))[disp]
+    trial = json.loads(R.get('trial-argv'))
+    assert trial[trial.index('--boot-check') - 2] == 'goodqa-job-dispatcher@' + vm_id, 'the trial boots THIS image by digest'
+    assert ('trial boot of goodqa-job-dispatcher@%s: ok' % vm_id) in out and 'gate (c) dispatcher boot line: ok' in out, out
+    log = R.dlog()
+    assert log.index('TRIAL ') < log.index('MIGRATE dry') < log.index('UPSVCS'), 'every pre-switch gate runs before migrations'
+    ssh = R.get('ssh.log'); assert ssh.index('sudo python3 -I -') < ssh.index(' migrate '), ssh
+    assert ups(R) == [FULL], 'one switch, no re-hold'
+    assert re.fullmatch(r'goodqa-intelligence-worker@sha256:[0-9a-f]{64}', R.jobs()[INTEL]), R.jobs()
+    assert audit(R, sha)['jobSecretGate'] == 'released derive=written key-lines=1 trial=ok'
+    assert 'RM -f goodqa-trial-' in log, 'the trial container is always removed'
+
+
+@pytest.mark.parametrize('body,code,word,ok', [
+    (LINE + 'written\n', 0, 'written', True),
+    (LINE + 'unchanged\n', 0, 'unchanged', True),
+    (LINE + 'REFUSED no %s line\n' % MARK, 2, 'REFUSED-derive', False),
+    (LINE + 'written\nextra line\n', 0, 'garbled', False),
+    (LINE + 'written\r\n', 0, 'garbled', False),
+    (LINE + 'REFUSED x\n', 0, 'garbled', False),
+    (LINE + 'written\n', 2, 'garbled', False),
+    ('', 0, 'garbled', False),
+    (LINE + 'REFUSED a\n' + LINE + 'REFUSED b\n', 2, 'garbled', False),
+    (None, 255, 'unreachable', False),
+])
+def test_unheld_derive_outcomes(R, body, code, word, ok):
+    before = R.get('live')
+    if body is None: R.put('derive-ssh-fail', '')
+    else: R.put('derive-out', body); R.put('derive-rc', str(code))
+    sha = R.release('release/js-2'); rc, out = R.run('release/js-2', sha)
+    assert ('gate (a) derive from the bound commit: ' + word) in out, out
+    assert MARK not in out and MARK not in R.runlogs(), 'a derive reason never leaves the VM'
+    if ok: assert rc == 0, out
+    else:
+        assert rc == 2, out; refused_before_anything(R, before, out)
+        assert 'TRIAL' not in R.dlog() and R.state_of('release/js-2')[0] == 'deploy-failed'
+
+
+@pytest.mark.parametrize('case', ['refused', 'ssh-fail', 'unbound', 'no-blob'])
+def test_held_release_is_not_gated(R, case):
+    _conf(R, 'SELFHOST_JOB_HOLD', 'intelligence-worker')
+    if case == 'refused': R.put('derive-out', LINE + 'REFUSED no source line\n'); R.put('derive-rc', '2')
+    if case == 'ssh-fail': R.put('derive-ssh-fail', '')
+    if case == 'unbound': R.autobind = False
+    if case == 'no-blob': bind_release(R, derive=None)
+    sha = R.release('release/js-3'); rc, out = R.run('release/js-3', sha)
+    assert rc == 0, out
+    assert R.jobs()[INTEL] == HELD and 'TRIAL' not in R.dlog() and 'gate (c)' not in out
+    word = {'refused': 'REFUSED-derive', 'ssh-fail': 'unreachable', 'unbound': 'skipped-unbound', 'no-blob': 'REFUSED-no-derive-blob'}[case]
+    assert ('derive ' + word) in out and audit(R, sha)['jobSecretGate'] == 'held derive=' + word, out
+    assert ('derive-runs' in os.listdir(R.st)) == (case in ('refused', 'ssh-fail'))
+
+
+# ---------------------------------------------------------------- where derive comes from (lead ruling Q1)
+def test_tampered_working_tree_derive_is_ignored(R):
+    tampered = b'print("job secret github-app-private-key: written")\n'
+    p = os.path.join(R.repo, sh.DERIVE_PATH); os.makedirs(os.path.dirname(p), exist_ok=True); open(p, 'wb').write(tampered)
+    sha = R.release('release/js-4')
+    open(p, 'wb').write(tampered + b'# and edited again after the release commit\n')
+    rc, out = R.run('release/js-4', sha)
+    assert rc == 0, out
+    assert R.get('derive-streamed').strip() == DERIVE_BLOB != blob_sha(tampered), 'only the bound blob is streamed'
+
+
+@pytest.mark.parametrize('how,word', [
+    ('unbound', 'REFUSED-unbound'),
+    ('no-file-no-line', 'REFUSED-no-derive-blob'),
+    ('line-without-file', 'REFUSED-not-in-bound-commit'),
+    ('blob-mismatch', 'REFUSED-blob-mismatch'),
+    ('other-content', 'REFUSED-blob-mismatch'),
+])
+def test_derive_source_must_be_the_bound_blob(R, how, word):
+    before = R.get('live')
+    if how == 'unbound': R.autobind = False
+    if how == 'no-file-no-line': bind_release(R, derive=None)
+    if how == 'line-without-file': bind_release(R, derive=None, blob=DERIVE_BLOB)
+    if how == 'blob-mismatch': bind_release(R, blob='0' * 40)
+    if how == 'other-content': bind_release(R, derive=b'print(1)\n', blob=DERIVE_BLOB)
+    sha = R.release('release/js-5'); rc, out = R.run('release/js-5', sha)
+    assert rc == 2 and ('derive from the bound commit: ' + word) in out, out
+    refused_before_anything(R, before, out)
+    assert 'derive-runs' not in os.listdir(R.st), 'nothing is streamed to the VM'
+
+
+# ---------------------------------------------------------------- (b) and the trial boot
+@pytest.mark.parametrize('body,word', [('', '0'), ('{k}\n{k}\n', '2'), ('{k} \n', '0'), ('#{k}\n', '0'), ('symlink', 'unreadable')])
+def test_key_line_must_be_there_exactly_once(R, body, word):
+    before = R.get('live'); p = os.path.join(R.envd, 'dispatcher.env')
+    if body == 'symlink':
+        os.rename(p, p + '.real'); os.symlink(p + '.real', p)
+    else: open(p, 'w').write('JOB_DISPATCH_TOKEN=x\n' + body.format(k=sh.JOBSECRET_KEY_LINE))
+    sha = R.release('release/js-6'); rc, out = R.run('release/js-6', sha)
+    assert rc == 2 and ('gate (b) key lines in dispatcher.env: ' + word) in out, out
+    refused_before_anything(R, before, out); assert 'TRIAL' not in R.dlog()
+
+
+def test_trial_boot_failure_refuses_and_cleans_up(R):
+    before = R.get('live'); R.put('trial', 'fail'); sha = R.release('release/js-7'); rc, out = R.run('release/js-7', sha)
+    assert rc == 2 and 'trial boot of the new dispatcher image did not read the key file (fail)' in out, out
+    refused_before_anything(R, before, out)
+    assert 'RM -f goodqa-trial-' in R.dlog()
+
+
+# ---------------------------------------------------------------- (c) after the switch: re-hold first, then roll back
+@pytest.mark.parametrize('line,word', [('', 'missing'), ('job env file for INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY: is a symlink', 'error:symlink')])
+def test_gate_c_failure_reholds_then_rolls_back(R, line, word):
+    before = R.get('live'); R.put('disp-boot-line', line); sha = R.release('release/js-8'); rc, out = R.run('release/js-8', sha)
+    assert rc == 5, out
+    assert ('gate (c) dispatcher boot line: ' + word) in out and 'ROLLED BACK' in out, out
+    assert ups(R) == [FULL, DISP_ONLY, FULL], 're-hold (dispatcher only) BEFORE the rollback up'
+    assert out.index('intelligence-worker re-held') < out.index('ROLLED BACK'), out
+    r = rd(R); stamp = os.path.basename(r)
+    assert os.path.exists(os.path.join(r, 'pin-%sh.txt' % stamp)) and os.path.exists(os.path.join(R.vm, 'compose.yaml.pre-rw-%sh' % stamp))
+    assert R.pins() == BASE_PINS and R.jobs() == BASE_JOBS and R.get('live') == before
+    assert R.state_of('release/js-8')[0] in ('rolled-back', 'deploy-failed') and not R.contains(sha)
+
+
+def test_gate_c_requires_a_new_container(R):
+    R.put('disp-same-hex', ''); sha = R.release('release/js-9'); rc, out = R.run('release/js-9', sha)
+    assert rc == 5 and 'was not recreated by the switch (gate c)' in out, out
+    assert ups(R) == [FULL, DISP_ONLY, FULL]
+
+
+def test_gate_c_failure_after_a_migration_holds_and_stops(R):
+    R.put('mig-pending', '1'); R.put('disp-boot-line', ''); sha = R.release('release/js-10'); rc, out = R.run('release/js-10', sha)
+    assert rc == 8 and 'ROLLBACK REFUSED' in out and 'intelligence-worker was re-held' in out, out
+    assert ups(R) == [FULL, DISP_ONLY], 'no rollback across a migration, only the re-hold'
+    assert R.jobs()[INTEL] == HELD and R.pins()['api'].startswith('goodqa-api:' + sha[:12])
+    assert R.state_of('release/js-10')[0] == 'deploy-unverified' and os.path.exists(R.infl)
+
+
+def test_rehold_failure_is_exit_8_and_touches_nothing_else(R):
+    R.put('disp-boot-line', ''); R.put('up-fail-disp-only', ''); sha = R.release('release/js-11'); rc, out = R.run('release/js-11', sha)
+    assert rc == 8 and 'HOLD NOT RE-APPLIED' in out and 'JOB_IMAGE_INTELLIGENCE_WORKER' in out, out
+    assert ups(R) == [FULL] and 'UPSVCS-FAILED ' + DISP_ONLY in R.dlog(), 'only the dispatcher pair was tried'
+    assert 'ROLLED BACK' not in out and R.state_of('release/js-11')[0] == 'deploy-unverified' and os.path.exists(R.infl)
+
+
+def test_rollback_restore_failure_reholds_again(R):
+    R.put('disp-boot-line', ''); R.put('restore-fail', ''); sha = R.release('release/js-12'); rc, out = R.run('release/js-12', sha)
+    assert rc == 8 and 'ROLLBACK NOT CONFIRMED' in out and 'intelligence-worker is re-held' in out, out
+    stamp = os.path.basename(rd(R))
+    assert ups(R) == [FULL, DISP_ONLY, DISP_ONLY] and os.path.exists(os.path.join(rd(R), 'pin-%sh2.txt' % stamp))
+    assert R.jobs()[INTEL] == HELD and R.state_of('release/js-12')[0] == 'deploy-unverified'
diff --git a/infra/release-harness/test_rw_ship_selfhost.py b/infra/release-harness/test_rw_ship_selfhost.py
index 47f88218644..12b931ddac8 100644
--- a/infra/release-harness/test_rw_ship_selfhost.py
+++ b/infra/release-harness/test_rw_ship_selfhost.py
@@ -20,7 +20,7 @@ Pinned properties:
     caught by these same assertions
 Run: cd bin && python3 -m pytest -q -p no:cacheprovider test_rw_ship_selfhost.py   (RW_SHIP_UNDER_TEST=<path> for a copy)
 """
-import json, os, re, subprocess, sys
+import hashlib, json, os, re, subprocess, sys
 
 import pytest
 
@@ -44,9 +44,24 @@ if [[ "$*" = *'docker info'* ]]; then printf '%s\n' "$FAKE_STATE"; exit 0; fi
 echo "SSH $host $*" >> "$FAKE_STATE/ssh.log"
 # anything but the fake VM (e.g. the DO path's build-machine migration ssh) never runs here: answer like the DO-suite stub
 [ "$host" = ubuntu@fake-vm ] || { cat >/dev/null; echo "MIG_PENDING 0"; echo "MIG_OK none"; exit 0; }
+if [ "$*" = "sudo python3 -I -" ]; then   # goodqa#16148: the derive-job-secrets.py stream; record WHAT was streamed
+  git hash-object --stdin > "$FAKE_STATE/derive-streamed"; echo x >> "$FAKE_STATE/derive-runs"
+  [ -e "$FAKE_STATE/derive-ssh-fail" ] && exit 255
+  if [ -e "$FAKE_STATE/derive-out" ]; then cat "$FAKE_STATE/derive-out"; else echo "job secret github-app-private-key: written"; fi
+  exit "$(cat "$FAKE_STATE/derive-rc" 2>/dev/null || echo 0)"
+fi
+if [ -e "$FAKE_STATE/restore-fail" ] && [[ "$*" =~ \ restore\ --stamp\ [0-9]{8}T[0-9]{6}Z$ ]]; then   # goodqa#16148: the run's own restore fails
+  cat >/dev/null; echo "REFUSED fake restore failure"; exit 3
+fi
 FAKE_SIDE=remote exec bash -c "$*"
 '''
-SUDO = '#!/bin/sh\nexec "$@"\n'
+SUDO = r"""#!/bin/sh
+# goodqa#16148: trial-boot chowns its fake marker to root:64910 (the VM runs this as root; the test does not). Only that
+# call is neutralised; the streamed selfhost-ctl.py is otherwise run byte for byte.
+if [ "$1" = python3 ] && [ "$2" = - ]; then case " $* " in *" trial-boot "*) shift 2
+  exec python3 -c 'import os, sys; os.chown = lambda *a, **k: None; sys.argv[0] = "-"; exec(compile(sys.stdin.read(), "<stdin>", "exec"), {"__name__": "__main__"})' "$@";; esac; fi
+exec "$@"
+"""
 
 DOCKER = r'''#!/usr/bin/env python3
 import hashlib, json, os, re, sys, fcntl, time
@@ -93,6 +108,8 @@ def resolve(ref):
         return m.group(2)
     return None
 if a[0] == 'info':
+    if mark('driverstatus-fail'): print('Cannot connect to the Docker daemon', file=sys.stderr); sys.exit(1)
+    if mark('driverstatus-out'): print(open(os.path.join(os.environ['FAKE_STATE'], 'driverstatus-out')).read()); sys.exit(0)
     print('[["Backing Filesystem","extfs"],["Supports d_type","true"]]' if mark('classic-store') else '[["driver-type","io.containerd.snapshotter.v1"]]')
     sys.exit(0)
 if a[0] == 'run' and 'src/create-guard-main.ts' in a:          # goodqa#16136 D1: probe of the built guard
@@ -152,6 +169,29 @@ if a[0] == 'load':
         open(c, 'w').write(t.replace('goodqa-web:base', 'goodqa-web:other'))
     sys.exit(0)
 cons = J('containers.json', [])
+DISP_OK = 'job env file INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY: ok'
+def hexid(c): return c.get('hex') or hashlib.sha256(c['id'].encode()).hexdigest()
+if a[0] == 'ps' and 'label=com.docker.compose.service=job-dispatcher' in a:   # goodqa#16148 disp-boot
+    log('DISPPS'); print('\n'.join(hexid(c) for c in cons if c['service'] == 'job-dispatcher' and c['status'] == 'running')); sys.exit(0)
+if a[0] == 'inspect' and a[1:3] == ['-f', '{{.State.StartedAt}}']:
+    c = [c for c in cons + J('gone.json', []) if hexid(c) == a[3]]
+    if not c: sys.exit(1)
+    print(c[0].get('started', '2026-11-15T00:00:00.000000000Z')); sys.exit(0)
+if a[0] == 'logs' and '--since' in a:
+    c = [c for c in cons + J('gone.json', []) if hexid(c) == a[-1]]
+    log('DISPLOGS %s since=%s tail=%s' % (a[-1][:12], a[a.index('--since') + 1], a[a.index('--tail') + 1] if '--tail' in a else '-'))
+    if not c or mark('disp-logs-fail'): sys.exit(1)
+    for n in range(5): print('{"level":30,"msg":"incoming request %d"}' % n)
+    if c[0].get('boot'): print(json.dumps({'level': 30, 'msg': c[0]['boot']}))
+    sys.exit(0)
+if a[0] == 'run' and '--boot-check' in a:                     # goodqa#16148 trial-boot
+    img = a[a.index('--boot-check') - 2]; log('TRIAL %s' % img)
+    open(os.path.join(os.environ['FAKE_STATE'], 'trial-argv'), 'w').write(json.dumps(a))
+    if not resolve(img): sys.exit(125)
+    if (markv('trial') if mark('trial') else 'ok') == 'ok': print(DISP_OK); sys.exit(0)
+    print('job env file for INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY: missing'); sys.exit(1)
+if a[0] == 'rm':
+    log('RM ' + ' '.join(a[1:])); sys.exit(0)
 if a[0] == 'ps':
     print('\n'.join(c['id'] for c in cons)); sys.exit(0)
 if a[0] == 'inspect':
@@ -167,19 +207,26 @@ if a[0] == 'compose':
         if mark('compose-invalid'): print('invalid', file=sys.stderr); sys.exit(1)
         sys.exit(0)
     if sub == 'config':                                       # resolved config: images, and the &job-images anchor merged
-        text = open(files[0]).read(); p0 = {}; jp = {}; cur = None
+        text = open(files[0]).read(); p0 = {}; jp = {}; lab = {}; cur = None; sub = None
         for l in text.split('\n'):
             m = re.match(r'^    image:\s*(\S+)', l)
             if m and cur: p0[cur] = m.group(1)
             m = re.match(r'^  ([A-Za-z0-9_.-]+):\s*(#.*)?$', l)
-            if m: cur = m.group(1); continue
+            if m: cur = m.group(1); sub = None; continue
+            m = re.match(r'^    ([A-Za-z0-9_.<-]+):', l)
+            if m and cur: sub = m.group(1)
             m = re.match(r'^      (JOB_IMAGE_[A-Z0-9_]+):\s*(\S+)', l)
-            if m and cur: jp.setdefault(cur, {})[m.group(1)] = m.group(2)
+            if m and cur:
+                v = '' if m.group(2) in ('""', "''") else m.group(2)
+                (jp if sub == 'environment' else lab).setdefault(cur, {})[m.group(1)] = v
+        if mark('resolved-drop-held'):                      # compose resolves the dispatcher without a held key
+            for k in [k for k, v in jp.get('job-dispatcher-create-guard', {}).items() if v == '']: jp.setdefault('job-dispatcher', {})[k] = None
         g = jp.get('job-dispatcher-create-guard', {})
         svcs = {s: {'image': i} for s, i in p0.items()}
         for s in ('api', 'web'): svcs.setdefault(s, {})['deploy'] = {'replicas': 2}
         svcs.setdefault('job-dispatcher-create-guard', {})['environment'] = dict(g)
-        svcs.setdefault('job-dispatcher', {})['environment'] = dict(g, **jp.get('job-dispatcher', {}))
+        svcs.setdefault('job-dispatcher', {})['environment'] = {k: v for k, v in dict(g, **jp.get('job-dispatcher', {})).items() if v is not None}
+        for s, kv in lab.items(): svcs.setdefault(s, {})['labels'] = dict(kv)
         print(json.dumps({'services': svcs})); sys.exit(0)
     text = open(files[0]).read()
     def pins(t):
@@ -194,10 +241,13 @@ if a[0] == 'compose':
         if '--pull' in rest:
             i = rest.index('--pull'); log('PULL ' + rest[i + 1]); rest = rest[:i] + rest[i + 2:]
         svcs = [x for x in rest if not x.startswith('-')]; p = pins(text)
+        if mark('up-fail-disp-only') and sorted(svcs) == ['job-dispatcher', 'job-dispatcher-create-guard']:
+            log('UPSVCS-FAILED ' + ','.join(svcs)); print('fake: dispatcher up failed', file=sys.stderr); sys.exit(1)
         envf = re.search(r'path:[ \t]*([^\n]+/api\.env)', text).group(1)
         sha = re.search(r'^RELEASE_SOURCE_SHA=(\S+)$', open(envf).read(), re.M).group(1)
         missing = [p[s] for s in svcs if not resolve(p[s])]
         if missing: print('no such image ' + ' '.join(missing), file=sys.stderr); sys.exit(1)
+        gone = [c for c in cons if c['service'] in svcs]; W('gone.json', J('gone.json', []) + gone)
         cons = [c for c in cons if c['service'] not in svcs]
         bad = markv('unhealthy-ref') if mark('unhealthy-ref') else None
         for s in svcs:
@@ -205,6 +255,15 @@ if a[0] == 'compose':
                 h = ('unhealthy' if bad and bad in p['api'] and s == 'api' else 'healthy') if s in ('api', 'web') else None
                 cons.append({'id': '%s-%d-%s' % (s, n, len(cons)), 'name': 'goodqa-%s-%d' % (s, n + 1), 'service': s,
                              'image': resolve(p[s]), 'status': 'running', 'health': h})
+        g = J('gen.json', 0) + 1; W('gen.json', g); prev = [c for c in gone if c['service'] == 'job-dispatcher' and 'hex' in c]
+        for c in cons:                                        # goodqa#16148: what disp-boot reads
+            if 'hex' in c: continue
+            c['hex'] = hashlib.sha256(('%s/%d' % (c['id'], g)).encode()).hexdigest()
+            c['started'] = '2026-11-15T01:%02d:%02d.123456789Z' % (g // 60 % 60, g % 60)
+            if c['service'] == 'job-dispatcher':
+                c['boot'] = markv('disp-boot-line') if mark('disp-boot-line') else DISP_OK
+                if mark('disp-same-hex') and prev: c.update({k: prev[-1][k] for k in ('hex', 'started', 'boot')})
+        log('UPSVCS ' + ','.join(svcs))
         W('containers.json', cons); log('UP api=%s web=%s disp=%s sha=%s' % (p['api'], p['web'], p['job-dispatcher'], sha))
         if mark('untag-after-up') and sha in markv('untag-after-up'):   # a person untags a job image right after the switch
             pre = markv('untag-after-up').split()[0]
@@ -342,6 +401,38 @@ exit 127
 '''
 
 
+JOBSECRET_KEY_LINE = 'JOB_ENVFILE_INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY=/run/goodqa-secrets/github-app-private-key'
+DERIVE_SRC = os.path.join(HERE, '..', 'selfhost', 'app', 'derive-job-secrets.py')
+DERIVE_PATH = 'infra/selfhost/app/derive-job-secrets.py'
+BOUND = ('rw-ship.sh', 'selfhost-ctl.py', 'rw-rollback.sh', 'rw-runtime.sh')
+
+
+def blob_sha(body): return subprocess.run(['git', 'hash-object', '--stdin'], input=body, capture_output=True, check=True).stdout.decode().strip()
+
+
+def bind_release(R, derive=b'', blob=None):
+    """goodqa#16148: bind this root's installed release scripts AND infra/selfhost/app/derive-job-secrets.py to one commit
+    (commit-tree: no branch, HEAD and main untouched), then write RELEASE_BINDING with its derive-blob line.
+    derive=None leaves derive out of the commit; blob overrides the recorded derive-blob (None = the committed one)."""
+    env = dict(os.environ, GIT_INDEX_FILE=os.path.join(R.F, 'tmp', 'bind.index'), GIT_AUTHOR_NAME='t', GIT_AUTHOR_EMAIL='t@example.com',
+               GIT_COMMITTER_NAME='t', GIT_COMMITTER_EMAIL='t@example.com')
+    def g(*a, body=None):
+        return subprocess.run(['git', *a], cwd=R.repo, env=env, input=body, capture_output=True, check=True).stdout.decode().strip()
+    entries = [('infra/release-harness/' + n, open(os.path.join(R.F, 'bin', n), 'rb').read()) for n in BOUND]
+    if derive is not None: entries.append((DERIVE_PATH, derive or open(DERIVE_SRC, 'rb').read()))
+    if os.path.exists(env['GIT_INDEX_FILE']): os.unlink(env['GIT_INDEX_FILE'])
+    for path, body in entries: g('update-index', '--add', '--cacheinfo', '100644,%s,%s' % (g('hash-object', '-w', '--stdin', body=body), path))
+    c = g('commit-tree', g('write-tree'), '-m', 'bind release scripts')
+    subprocess.run(['git', 'push', '-q', 'origin', c + ':refs/heads/release-harness-bind'], cwd=R.repo, env=env,
+                   capture_output=True)   # best effort: the objects are already in R.repo; a test may cut origin off
+    lines = ['commit ' + c, 'path infra/release-harness'] + ['%s  bin/%s' % (hashlib.sha256(b).hexdigest(), n) for n, (_, b) in zip(BOUND, entries)]
+    if blob is None and derive is not None: blob = blob_sha(entries[-1][1])
+    if blob: lines.append('derive-blob ' + blob)
+    bf = os.path.join(R.F, 'bin', 'RELEASE_BINDING'); open(bf, 'w').write('\n'.join(lines) + '\n')
+    _conf(R, 'RELEASE_BINDING', bf)
+    return c
+
+
 class SRoot(base.Root):
     def __init__(self, b, freeze_until='2020-01-01T00:00:00Z', extra_conf=''):
         super().__init__(b)
@@ -363,6 +454,8 @@ class SRoot(base.Root):
             p = os.path.join(self.envd, f + '.env')
             open(p, 'w').write('DATABASE_URL=postgres://doadmin:pw@10.0.0.6/bugtracker\nRELEASE_SOURCE_SHA=%s\nRELEASE_DEPLOYMENT_ID=selfhost-base\nX=1\n' % live)
             os.chmod(p, 0o600)
+        p = os.path.join(self.envd, 'dispatcher.env')
+        open(p, 'w').write('JOB_DISPATCH_TOKEN=fake-dispatch-token\n' + JOBSECRET_KEY_LINE + '\n'); os.chmod(p, 0o600)
         with open(os.path.join(b, 'biz/release-waves/ship.conf'), 'a') as f:
             f.write('SELFHOST_APP=ubuntu@fake-vm\nSELFHOST_DIR=%s\nSELFHOST_ENV_DIR=%s\nSELFHOST_PROJECT=goodqa\n'
                     'SELFHOST_SCHEMA_FREEZE_UNTIL=%s\nSELFHOST_UP_TIMEOUT=1\nSELFHOST_BUILD_MIN_FREE_GB=0\nSELFHOST_VM_MIN_FREE_GB=0\nSELFHOST_JOB_HOLD=none\n%s' % (self.vm, self.envd, freeze_until, extra_conf))
@@ -391,6 +484,15 @@ class SRoot(base.Root):
         assert self.get('live') == live
         open(os.path.join(self.st, 'docker.log'), 'w').write('')
 
+    autobind = True                  # goodqa#16148: bind at the first run unless the test set RELEASE_BINDING or opted out
+
+    def start(self, name, sha, smoke='auto', wrap=None, **kw):
+        conf = os.path.join(self.F, 'biz/release-waves/ship.conf')    # a test may remove ship.conf on purpose
+        present = os.path.exists(conf) and all(os.path.exists(os.path.join(self.F, 'bin', n)) for n in BOUND)
+        if self.autobind and present and 'RELEASE_BINDING=' not in open(conf).read():   # a removed file: rw-ship refuses itself
+            bind_release(self)
+        return super().start(name, sha, smoke, wrap=wrap, **kw)
+
     def env(self, smoke, **kw):
         kw.setdefault('DEPLOY_TARGET', 'selfhost'); return super().env(smoke, **kw)
 
@@ -1547,3 +1649,76 @@ def test_job_line_accepts_plain_or_quoted_pins(line):
     lines, res = m.Stack.job_lines(_real_compose_with(m, {'JOB_IMAGE_TRANSCODE': line}))
     assert 'JOB_IMAGE_TRANSCODE' in res
 
+
+
+# ---- receipt pr1370-v1 F2: a failed DriverStatus discovery is not a classic store (fail closed, never DockerRootDir only)
+DISCOVERY_FAILURES = [('rc', None), ('empty', ''), ('not-json', 'template: info: bad'), ('null', 'null'), ('object', '{}'),
+                      ('empty-list', '[]'), ('not-pairs', '["driver-type"]'),
+                      # receipt pr1370-v2b F3: a row is exactly two strings (each case names the snapshotter, so a lax check ships)
+                      ('empty-row', '[[]]'), ('one-element', '[["io.containerd.snapshotter.v1"]]'),
+                      ('three-element', '[["driver-type","io.containerd.snapshotter.v1","x"]]'),
+                      ('short-after-good', '[["driver-type","io.containerd.snapshotter.v1"],["x"]]')]
+
+
+@pytest.mark.parametrize('name,body', DISCOVERY_FAILURES)
+def test_vm_disk_refuses_when_the_store_cannot_be_discovered(R, name, body):
+    """The containerd root is full; a discovery failure read as 'classic' would measure only DockerRootDir and ship."""
+    if body is None: R.put('driverstatus-fail', '')
+    else: R.put('driverstatus-out', body)
+    R.put('vmdf-containerd', '0')
+    out = _vm_disk_refused(R, 'release/wave-60d5', name)
+    assert 'VM image store: unresolved' in out, out          # rw-ship keeps the ctl refusal off its own log
+
+
+@pytest.mark.parametrize('name,body', DISCOVERY_FAILURES)
+def test_ctl_pin_refuses_when_the_store_cannot_be_discovered(tmp_path, name, body):
+    ctl, snap, st, vm, env = ctl_fixture(tmp_path); before = snap()
+    if body is None: (st / 'driverstatus-fail').write_text('')
+    else: (st / 'driverstatus-out').write_text(body)
+    rc, o = ctl(*PIN)
+    assert rc == 3 and 'cannot discover the docker image store' in o, o
+    assert snap() == before
+
+
+def test_classic_store_is_still_told_apart(tmp_path):
+    ctl, snap, st, vm, env = ctl_fixture(tmp_path); (st / 'driverstatus-out').write_text('[["Backing Filesystem","extfs"],["Supports d_type","true"]]')
+    rc, o = ctl(*PIN)
+    assert rc == 3 and 'is not containerd' in o and 'cannot discover' not in o, o
+
+
+# ---- receipt bth-pr73-v4b F1: a JOB_IMAGE_* key, held or not, counts only under environment, in both services
+HOLD_INTEL = ('--job-hold', 'JOB_IMAGE_INTELLIGENCE_WORKER')
+PIN_HELD = PIN0 + tuple(x for k, v in NEW_JOBS.items() if k != 'JOB_IMAGE_INTELLIGENCE_WORKER' for x in ('--job-image', '%s=%s' % (k, v))) + HOLD_INTEL
+
+
+def _move_intel_to_labels(vm, held):
+    p = vm / 'compose.yaml'; t = p.read_text()
+    line = next(l for l in t.split('\n') if l.startswith('      JOB_IMAGE_INTELLIGENCE_WORKER:'))
+    new = '      JOB_IMAGE_INTELLIGENCE_WORKER: "" # held' if held else line
+    t = t.replace(line + '\n', '')
+    t = t.replace('  job-dispatcher-create-guard:\n    image: goodqa-job-dispatcher:base\n',
+                  '  job-dispatcher-create-guard:\n    image: goodqa-job-dispatcher:base\n    labels:\n' + new + '\n')
+    p.write_text(t)
+
+
+@pytest.mark.parametrize('held', [True, False])
+def test_job_key_under_labels_is_refused(tmp_path, held):
+    ctl, snap, st, vm, env = ctl_fixture(tmp_path); _move_intel_to_labels(vm, held); before = snap()
+    rc, o = ctl(*(PIN_HELD if held else PIN))
+    assert rc == 3 and 'outside the job-dispatcher-create-guard &job-images block' in o, o
+    assert snap() == before
+
+
+def test_held_key_pin_passes_and_is_held_in_both_resolved_envs(tmp_path):
+    ctl, snap, st, vm, env = ctl_fixture(tmp_path)
+    rc, o = ctl(*PIN_HELD)
+    assert rc == 0, o
+    assert J(o)['jobs_held'] == ['JOB_IMAGE_INTELLIGENCE_WORKER'], o
+
+
+def test_resolved_compose_dropping_a_held_key_is_refused(tmp_path):
+    """The text parser sees the held line, but the RESOLVED dispatcher env lacks it: parity fails closed."""
+    ctl, snap, st, vm, env = ctl_fixture(tmp_path); (st / 'resolved-drop-held').write_text(''); before = snap()
+    rc, o = ctl(*PIN_HELD)
+    assert rc == 3 and 'job-dispatcher environment does not carry exactly the job image lines' in o and 'JOB_IMAGE_INTELLIGENCE_WORKER=missing' in o, o
+    assert snap() == before
diff --git a/infra/release-harness/test_selfhost_ctl_gate.py b/infra/release-harness/test_selfhost_ctl_gate.py
new file mode 100644
index 00000000000..2f0ce80bb4d
--- /dev/null
+++ b/infra/release-harness/test_selfhost_ctl_gate.py
@@ -0,0 +1,209 @@
+"""goodqa#16148 spec v4 AC-8 (P3, P4) and the lead's gate rulings: the selfhost-ctl verbs envfile-key, disp-boot,
+trial-boot and up-dispatcher. A python fake docker on PATH; fake values only; no network, socket or containers.
+Run: python3 -m pytest -q infra/release-harness/test_selfhost_ctl_gate.py
+"""
+import argparse
+import importlib.util
+import json
+import os
+import subprocess
+import sys
+from pathlib import Path
+
+import pytest
+
+HERE = Path(__file__).resolve().parent
+CTL = HERE / 'selfhost-ctl.py'
+spec = importlib.util.spec_from_file_location('selfhost_ctl', CTL)
+ctl = importlib.util.module_from_spec(spec)
+spec.loader.exec_module(ctl)
+
+KEYLINE = 'JOB_ENVFILE_INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY=/run/goodqa-secrets/github-app-private-key'
+OK = 'job env file INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY: ok'
+PLANT = 'FAKEgateLOGmarkerQWERTYuiopZXCVbnmXYZ'  # no digit runs (timestamps hold digits)
+CID = 'c0ffee' * 10 + 'abcd'
+IMG = 'goodqa-job-dispatcher@sha256:' + 'd' * 64
+# The trial hardening flags, written out here (not imported), so dropping one in selfhost-ctl.py fails a test.
+REQUIRED_TRIAL_FLAGS = [('--rm',), ('--network', 'none'), ('--read-only',), ('--cap-drop', 'ALL'),
+                        ('--security-opt', 'no-new-privileges'), ('--user', 'node'), ('--pids-limit', '64'),
+                        ('--memory', '256m'), ('--group-add', '64910'), ('--tmpfs', '/tmp')]
+
+FAKE_DOCKER = r'''#!/usr/bin/env python3
+import json, os, sys, time
+F = os.environ['FAKE_D']; a = sys.argv[1:]
+def rd(n, d=''):
+    p = os.path.join(F, n); return open(p).read() if os.path.exists(p) else d
+open(os.path.join(F, 'calls.jsonl'), 'a').write(json.dumps(a) + '\n')
+if a[:2] == ['image', 'inspect']:
+    r = a[-1]; print(r.split('@', 1)[1] if '@' in r else 'sha256:' + '0' * 64); sys.exit(0)
+if a[:1] == ['ps']: print(rd('ps.txt')); sys.exit(0)
+if a[:1] == ['inspect']: print(rd('started.txt', '2026-11-16T04:00:00.123456789Z')); sys.exit(0)
+if a[:1] == ['logs']: sys.stdout.write(rd('logs.txt')); sys.exit(int(rd('logs-rc', '0') or 0))
+if a[:1] == ['run']:
+    name = a[a.index('--name') + 1]
+    live = set(rd('live.txt').split()); live.add(name); open(os.path.join(F, 'live.txt'), 'w').write('\n'.join(live))
+    d = [x.split(':')[0] for x in a if x.endswith(':/run/goodqa-secrets:ro')][0]
+    open(os.path.join(F, 'seen-value'), 'w').write(open(os.path.join(d, 'github-app-private-key')).read())
+    mode = rd('run-mode', 'ok').strip()
+    if mode == 'hang': time.sleep(30)
+    print('PLANT-' + os.environ.get('PLANT', '')); print('job env file INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY: ok' if mode == 'ok' else 'job env file for INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY: missing')
+    if '--rm' in a:
+        live.discard(name); open(os.path.join(F, 'live.txt'), 'w').write('\n'.join(live))
+    sys.exit(0 if mode == 'ok' else 1)
+if a[:2] == ['rm', '-f']:
+    live = set(rd('live.txt').split()); live.discard(a[2]); open(os.path.join(F, 'live.txt'), 'w').write('\n'.join(live)); sys.exit(0)
+sys.exit(0)
+'''
+
+
+@pytest.fixture
+def fake(tmp_path, monkeypatch):
+    b, d, e = tmp_path / 'bin', tmp_path / 'app', tmp_path / 'etc'
+    for p in (b, d, e):
+        p.mkdir()
+    (b / 'docker').write_text(FAKE_DOCKER)
+    (b / 'docker').chmod(0o755)
+    monkeypatch.setenv('PATH', '%s:%s' % (b, os.environ['PATH']))
+    monkeypatch.setenv('FAKE_D', str(tmp_path))
+    monkeypatch.setenv('PLANT', PLANT)
+    return tmp_path
+
+
+def calls(fake):
+    p = fake / 'calls.jsonl'
+    return [json.loads(l) for l in p.read_text().splitlines()] if p.exists() else []
+
+
+def cli(fake, *argv):
+    r = subprocess.run([sys.executable, '-B', str(CTL), '--dir', str(fake / 'app'), '--env-dir', str(fake / 'etc'), *argv],
+                       capture_output=True, text=True, timeout=60)
+    return r.returncode, r.stdout, r.stderr
+
+
+# ---- (b) envfile-key ----
+def test_envfile_key_counts_only_the_exact_line(fake):
+    (fake / 'etc/dispatcher.env').write_text('\n'.join([
+        'JOB_DISPATCH_TOKEN=' + PLANT, KEYLINE, '# ' + KEYLINE, KEYLINE + ' ', KEYLINE.replace('goodqa-secrets', 'x'), '']))
+    rc, out, err = cli(fake, 'envfile-key')
+    assert (rc, json.loads(out)) == (0, {'count': 1})
+    assert PLANT not in out + err
+    (fake / 'etc/dispatcher.env').write_text('A=1\n')
+    assert json.loads(cli(fake, 'envfile-key')[1]) == {'count': 0}
+
+
+def test_envfile_key_refuses_a_symlink(fake):
+    (fake / 'real.env').write_text(KEYLINE + '\n')
+    os.symlink(fake / 'real.env', fake / 'etc/dispatcher.env')
+    rc, out, _ = cli(fake, 'envfile-key')
+    assert rc == 4 and out.startswith('FAILED OSError'), out
+
+
+# ---- (c) disp-boot ----
+def pino(msg):
+    return json.dumps({'level': 30, 'time': 1, 'pid': 7, 'hostname': 'vm', 'msg': msg})
+
+
+@pytest.mark.parametrize('lines,status', [
+    ([pino('job-dispatcher: swept stale env-file dirs'), pino(OK)], 'ok'),
+    ([pino('job env file for INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY: missing')], 'error:missing-file'),
+    ([pino('job env file for INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY: is a symlink')], 'error:symlink'),
+    ([pino('job env file for INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY: ' + PLANT)], 'error:other'),
+    ([pino('job env file key ignored (not allow-listed): JOB_ENVFILE_SCAN__X')], 'missing'),
+    ([OK], 'missing'),                                           # a plain (non-pino) line is not the dispatcher's log line
+    ([pino('x ' + OK)], 'missing'), ([pino(OK + ' ')], 'missing'),
+    ([], 'missing'),
+])
+def test_disp_status_matches_the_exact_line_only(lines, status):
+    assert ctl.disp_status('\n'.join(lines)) == status
+
+
+def test_disp_boot_reads_only_this_container_bounded_and_leaks_nothing(fake):
+    (fake / 'ps.txt').write_text(CID + '\n')
+    (fake / 'logs.txt').write_text('\n'.join([pino('JOB_DISPATCH_TOKEN=' + PLANT), pino(PLANT), pino(OK), PLANT]) + '\n')
+    rc, out, err = cli(fake, 'disp-boot')
+    res = json.loads(out)
+    assert rc == 0 and res == {'id': CID, 'started': '2026-11-16T04:00:00.123456789Z', 'status': 'ok'}
+    for i in range(len(PLANT) - 7):
+        assert PLANT[i:i + 8] not in out + err
+    logs = [c for c in calls(fake) if c[:1] == ['logs']]
+    assert logs == [['logs', '--since', '2026-11-16T04:00:00.123456789Z', '--tail', '2000', CID]]
+    ps = [c for c in calls(fake) if c[:1] == ['ps']][0]
+    assert 'label=com.docker.compose.service=job-dispatcher' in ps and 'status=running' in ps
+    assert not list(fake.rglob('*.log')), 'no log copy is kept'
+
+
+@pytest.mark.parametrize('ps,status', [('', 'no-container'), (CID + '\n' + 'ab' * 32 + '\n', 'ambiguous')])
+def test_disp_boot_without_exactly_one_container(fake, ps, status):
+    (fake / 'ps.txt').write_text(ps)
+    assert json.loads(cli(fake, 'disp-boot')[1]) == {'id': None, 'started': None, 'status': status}
+    assert not [c for c in calls(fake) if c[:1] == ['logs']]
+
+
+def test_disp_boot_unreadable_log_is_not_ok(fake):
+    (fake / 'ps.txt').write_text(CID)
+    (fake / 'logs.txt').write_text(pino(OK))
+    (fake / 'logs-rc').write_text('1')
+    assert json.loads(cli(fake, 'disp-boot')[1])['status'] == 'unreadable'
+
+
+# ---- P3 trial-boot ----
+def trial(fake, monkeypatch, capsys, image=IMG, stamp='S1', timeout=None):
+    monkeypatch.setattr(ctl.os, 'chown', lambda *a, **k: None)          # the VM runs this as root; the test does not
+    if timeout is not None:
+        monkeypatch.setattr(ctl, 'TRIAL_TIMEOUT', timeout)
+    stk = ctl.Stack(str(fake / 'app'), str(fake / 'etc'), 'goodqa')
+    code = ctl.cmd_trial_boot(stk, argparse.Namespace(image=image, stamp=stamp))
+    text = capsys.readouterr().out
+    return code, json.loads(text.strip().splitlines()[-1]), text
+
+
+def run_argv(fake):
+    return [c for c in calls(fake) if c[:1] == ['run']]
+
+
+def test_trial_boot_ok_is_isolated_and_hardened(fake, monkeypatch, capsys):
+    code, res, text = trial(fake, monkeypatch, capsys)
+    assert (code, res) == (0, {'status': 'ok', 'rc': 0})
+    [argv] = run_argv(fake)
+    for flag in REQUIRED_TRIAL_FLAGS:
+        i = argv.index(flag[0])
+        assert tuple(argv[i:i + len(flag)]) == flag, flag
+    assert argv[argv.index('--entrypoint') + 2:] == [IMG, 'src/index.ts', '--boot-check'], 'the exact digest, never a tag'
+    joined = ' '.join(argv)
+    assert 'docker.sock' not in joined and '--env-file' not in joined and '--privileged' not in joined
+    assert '--network host' not in joined and not any(x.startswith('--env-file') for x in argv)
+    assert (fake / 'seen-value').read_text() == ctl.TRIAL_MARKER + '\n', 'a fixed fake marker only'
+    assert 'PLANT-' not in text and PLANT not in text, 'the container output is never printed'
+    assert ['rm', '-f', 'goodqa-trial-S1'] in calls(fake)
+    assert not [p for p in Path('/tmp').glob('goodqa-trial-*') if p.stat().st_uid == os.getuid() and (p / 'github-app-private-key').exists()]
+
+
+def test_trial_boot_fail_line_is_fail(fake, monkeypatch, capsys):
+    (fake / 'run-mode').write_text('fail')
+    code, res, _ = trial(fake, monkeypatch, capsys)
+    assert (code, res) == (5, {'status': 'fail', 'rc': 1})
+
+
+def test_trial_boot_timeout_removes_the_container(fake, monkeypatch, capsys):
+    (fake / 'run-mode').write_text('hang')
+    code, res, _ = trial(fake, monkeypatch, capsys, timeout=1)
+    assert (code, res) == (5, {'status': 'timeout', 'rc': None})
+    assert ['rm', '-f', 'goodqa-trial-S1'] in calls(fake)
+    assert (fake / 'live.txt').read_text().split() == [], 'no goodqa-trial-* container is left'
+
+
+@pytest.mark.parametrize('image,stamp', [('goodqa-job-dispatcher:abc-1', 'S1'), ('evil@sha256:' + 'd' * 64, 'S1'),
+                                         (IMG, 'bad stamp'), (IMG, '')])
+def test_trial_boot_refuses_a_tag_or_bad_input(fake, monkeypatch, capsys, image, stamp):
+    code, res, _ = trial(fake, monkeypatch, capsys, image=image, stamp=stamp)
+    assert (code, res['status']) == (3, 'refused')
+    assert not run_argv(fake)
+
+
+# ---- P4 up-dispatcher ----
+def test_up_dispatcher_recreates_only_the_dispatcher_and_guard(fake):
+    (fake / 'app/compose.yaml').write_text('services:\n')
+    cli(fake, 'up-dispatcher', '--timeout', '1', '--every', '0.1')
+    ups = [c for c in calls(fake) if c[:1] == ['compose'] and 'up' in c]
+    assert len(ups) == 1
+    assert ups[0][ups[0].index('up'):] == ['up', '-d', '--no-deps', '--pull', 'never', 'job-dispatcher', 'job-dispatcher-create-guard']
diff --git a/infra/release-harness/test_selfhost_ctl_job_secrets.py b/infra/release-harness/test_selfhost_ctl_job_secrets.py
index f14d55b5217..7f0f6151267 100644
--- a/infra/release-harness/test_selfhost_ctl_job_secrets.py
+++ b/infra/release-harness/test_selfhost_ctl_job_secrets.py
@@ -4,6 +4,7 @@ the host apply put in compose.yaml survive the real selfhost-ctl.py `pin` (the n
 Fake docker on PATH; fake files only; no network, secrets or containers.
 Run: python3 -m pytest -q infra/release-harness/test_selfhost_ctl_job_secrets.py
 """
+import hashlib
 import importlib.util
 import os
 import subprocess
@@ -21,10 +22,32 @@ spec = importlib.util.spec_from_file_location('apply_host', APP / 'apply-job-sec
 ah = importlib.util.module_from_spec(spec)
 spec.loader.exec_module(ah)
 
-FAKE_DOCKER = '''#!/bin/sh
-echo "$*" >> "$FAKE_VM/docker.log"
-if [ "$1" = image ] && [ "$2" = inspect ]; then printf 'sha256:%s\\n' "$(printf %s "$5" | sha256sum | cut -c1-64)"; exit 0; fi
-exit 0
+# A fake docker in python. It reports the containerd image store, resolves a job ref (repo@sha256:...) to its own
+# digest and any other ref to a stable id, and answers `compose config --format json` from the file itself (service
+# images and the merged &job-images lines), as the 1371 selfhost-ctl pin needs. Every call is logged.
+FAKE_DOCKER = '''#!/usr/bin/env python3
+import hashlib, json, os, re, sys
+a = sys.argv[1:]
+open(os.path.join(os.environ['FAKE_VM'], 'docker.log'), 'a').write(' '.join(a) + '\\n')
+if a[:1] == ['info']:
+    print('[["io.containerd.snapshotter.v1", "overlayfs"]]'); sys.exit(0)
+if a[:2] == ['image', 'inspect']:
+    r = a[-1]
+    print(r.split('@', 1)[1] if '@' in r else 'sha256:' + hashlib.sha256(r.encode()).hexdigest()); sys.exit(0)
+if a[:1] == ['compose'] and 'config' in a and '--format' in a:
+    text = open(a[a.index('-f') + 1]).read(); svcs = {}; jobs = {}; cur = None
+    for l in text.split('\\n'):
+        m = re.match(r'^  ([A-Za-z0-9_.-]+):\\s*(#.*)?$', l)
+        if m: cur = m.group(1); svcs.setdefault(cur, {}); continue
+        m = re.match(r'^    image:\\s*(\\S+)', l)
+        if m and cur: svcs[cur]['image'] = m.group(1)
+        m = re.match(r'^      (JOB_IMAGE_[A-Z0-9_]+):\\s*(\\S*)', l)
+        if m and cur: jobs.setdefault(cur, {})[m.group(1)] = m.group(2).strip('"')
+    g = jobs.get('job-dispatcher-create-guard', {})
+    for s in ('job-dispatcher-create-guard', 'job-dispatcher'):
+        svcs.setdefault(s, {})['environment'] = dict(g, **jobs.get(s, {}))
+    print(json.dumps({'services': svcs})); sys.exit(0)
+sys.exit(0)
 '''
 SHA_A, SHA_B = 'a' * 40, 'b' * 40
 
@@ -54,9 +77,18 @@ def ctl(vm, *argv):
     return r.returncode, r.stdout
 
 
+def job_args(tag):
+    # The 1371 pin names every job key: scan and suggest-fix by content address, the two holdable kinds held.
+    d = lambda job: 'sha256:' + hashlib.sha256((job + tag).encode()).hexdigest()
+    return ['--job-image', 'JOB_IMAGE_SCAN=goodqa-scan@' + d('scan'),
+            '--job-image', 'JOB_IMAGE_SUGGEST_FIX_WORKER=goodqa-suggest-fix-worker@' + d('suggest-fix'),
+            '--job-hold', 'JOB_IMAGE_INTELLIGENCE_WORKER', '--job-hold', 'JOB_IMAGE_TRANSCODE']
+
+
 def pin(vm, stamp, sha, tag):
     return ctl(vm, 'pin', '--stamp', stamp, '--sha', sha, '--deploy-id', 'dep-' + stamp,
-               '--api', 'goodqa-api:' + tag, '--web', 'goodqa-web:' + tag, '--disp', 'goodqa-job-dispatcher:' + tag)
+               '--api', 'goodqa-api:' + tag, '--web', 'goodqa-web:' + tag, '--disp', 'goodqa-job-dispatcher:' + tag,
+               *job_args(tag))
 
 
 def marked(text):
diff --git a/infra/selfhost/app/cmdline-sampler.py b/infra/selfhost/app/cmdline-sampler.py
index a667806f3a0..523c708fb74 100755
--- a/infra/selfhost/app/cmdline-sampler.py
+++ b/infra/selfhost/app/cmdline-sampler.py
@@ -24,8 +24,10 @@ import time
 ALLOWED_LONG = {'--rm', '--env-file', '--env', '--cap-drop', '--security-opt', '--read-only', '--tmpfs', '--memory',
                 '--memory-swap', '--cpus', '--pids-limit', '--detach', '--name', '--label', '--network', '--user'}
 ALLOWED_SHORT = {'-d', '-e', '-i', '-t', '-u'}
-# docker run's boolean shorthands: pflag lets these cluster (-dit), and any other shorthand takes the rest as its value.
-BOOL_SHORT = set('ditP')
+# docker run's boolean shorthands (-d detach, -i interactive, -t tty, -P publish-all, -q quiet; goodqa#16198 added q):
+# pflag lets these cluster (-dit), and any other shorthand takes the rest as its value. Checked against `docker run --help`
+# of docker CLI 29.1.3 (t2-dev, 2026-11-16): exactly d, i, P, q and t are boolean shorthands.
+BOOL_SHORT = set('ditPq')
 BAD = {'-e', '-e(attached)', '-e(cluster)', '--env', '--env(attached)'}
 ID_RE = re.compile(r'^[0-9a-f]{12,64}$')
 
diff --git a/infra/selfhost/app/derive-job-secrets.py b/infra/selfhost/app/derive-job-secrets.py
index d2c3cde6090..a523738d498 100755
--- a/infra/selfhost/app/derive-job-secrets.py
+++ b/infra/selfhost/app/derive-job-secrets.py
@@ -24,6 +24,11 @@ was opened O_DIRECTORY|O_NOFOLLOW and checked with fstat; the file is created un
 temp name with O_CREAT|O_EXCL|O_NOFOLLOW, fchown/fchmod on the fd, written, fsynced, renamed
 within the directory fd, and the directory is fsynced. An unchanged value leaves the file alone.
 The value never appears in argv, output, a log or a hash.
+
+SINGLE INSTANCE (goodqa#16198): run this only through apply-job-secrets.sh or rw-ship, which hold the deploy lock,
+or by hand only while no such run holds it. Two concurrent runs can each see the other's rename as a changed file;
+the fail-closed unlink then removes the other run's fresh file. That still fails closed (the key reads as missing,
+no value is exposed), and the next single run repairs it.
 """
 import os
 import secrets
diff --git a/infra/selfhost/app/test_cmdline_sampler.py b/infra/selfhost/app/test_cmdline_sampler.py
index bd3e97c035e..c973865e509 100644
--- a/infra/selfhost/app/test_cmdline_sampler.py
+++ b/infra/selfhost/app/test_cmdline_sampler.py
@@ -94,7 +94,10 @@ class SamplerTests(unittest.TestCase):
         # F3: pflag accepts clustered shorthands, so -de K=V and -ieK=V carry an env value too.
         for argv in (['docker', 'run', '-de', 'K=' + MARKER, 'img'],
                      ['docker', 'run', '-ieK=' + MARKER, 'img'],
-                     ['docker', 'run', '-dite', 'K=' + MARKER, 'img']):
+                     ['docker', 'run', '-dite', 'K=' + MARKER, 'img'],
+                     # goodqa#16198 (D1): -q (--quiet) is a boolean shorthand too.
+                     ['docker', 'run', '-qe', 'K=' + MARKER, 'img'],
+                     ['docker', 'run', '-qieK=' + MARKER, 'img']):
             shutil.rmtree(self.proc)
             os.makedirs(self.proc)
             self.add(argv)
```
