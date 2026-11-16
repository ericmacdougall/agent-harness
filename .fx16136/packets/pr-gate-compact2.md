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
```diff
### SECTION A (1371): git diff -U0 ed296b0a..bff96cc5 -- rw-ship.sh selfhost-ctl.py ac13-count.py
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
@@ -219 +219 @@ if [ "$TARGET" = selfhost ]; then
-  SH_MIN_FREE_GB=$(shconf SELFHOST_BUILD_MIN_FREE_GB 15); MIGLOG="$RD/migrate-*.txt"
+  SH_MIN_FREE_GB=$(shconf SELFHOST_BUILD_MIN_FREE_GB 30); SH_VM_MIN_FREE_GB=$(shconf SELFHOST_VM_MIN_FREE_GB 20); MIGLOG="$RD/migrate-*.txt"
@@ -559 +559 @@ if [ "$TARGET" = selfhost ]; then
-  [ "${FREE:-0}" -ge "$SH_MIN_FREE_GB" ] || { say "NO DISK (infrastructure, exit 11): ${FREE:-?}G free on this box, $SH_MIN_FREE_GB G needed to build three images; nothing built or switched"; dbx "$NAME" deploy-failed "$BEFORE" "infrastructure: ${FREE:-?}G free on the build box (needs $SH_MIN_FREE_GB); nothing went live; run $RD"; exit 11; }
+  [ "${FREE:-0}" -ge "$SH_MIN_FREE_GB" ] || { say "NO DISK (infrastructure, exit 11): ${FREE:-?}G free on this box, $SH_MIN_FREE_GB G needed to build seven images; nothing built or switched"; dbx "$NAME" deploy-failed "$BEFORE" "infrastructure: ${FREE:-?}G free on the build box (needs $SH_MIN_FREE_GB); nothing went live; run $RD"; exit 11; }
@@ -560,0 +561,13 @@ if [ "$TARGET" = selfhost ]; then
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
@@ -587 +600,14 @@ if [ "$TARGET" = selfhost ]; then
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
@@ -589 +615 @@ import json, shlex, sys
-rd, sha, api, web, disp, promoted, receipt = sys.argv[1:]
+rd, sha, api, web, disp, promoted, receipt = sys.argv[1:8]
@@ -597,0 +624,12 @@ json.dump(dict(sha=sha, recordDir=rd, jobs=jobs), open(rd+'/build-plan.json', 'w
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
@@ -599,4 +637,7 @@ PY_PLAN
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
@@ -605,0 +647,16 @@ PY_PLAN
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
@@ -607,3 +664,6 @@ PY_PLAN
-  python3 - "$RD/jobs.json" <<'PY_IDS' || exit 3
-import json, subprocess, sys
-for job in json.load(open(sys.argv[1]))['jobs']:
+  python3 - "$RD" "${HOLDARGS}" <<'PY_IDS' || exit 3
+import glob, json, subprocess, sys
+rd, holds = sys.argv[1:3]
+jobs = [j for f in [rd + '/jobs.json'] + sorted(glob.glob(rd + '/job-images-*/jobs.json')) for j in json.load(open(f))['jobs']]
+for job in jobs:
+    if job['name'] == 'transcode' and '--job-hold JOB_IMAGE_TRANSCODE' in holds: continue   # removed on purpose by the hold
@@ -613,0 +674,8 @@ PY_IDS
+  # Review F2: the VM needs room for twice what is loaded (layers plus unpacked snapshots), and at least the floor.
+  LOADBYTES=0; for i in "$IMG_API" "$IMG_WEB" "$IMG_DISP" "${JOBIMGS[@]}"; do
+    b=$(docker image inspect -f '{{.Size}}' "$i" 2>/dev/null); [[ "$b" =~ ^[0-9]+$ ]] || b=x; [ "$b" = x ] && { LOADBYTES=x; break; }
+    LOADBYTES=$((LOADBYTES + b)); done
+  if [ "$LOADBYTES" = x ]; then VMNEED=x; else VMNEED=$(( (2 * LOADBYTES + (1 << 30) - 1) >> 30 )); [ "$VMNEED" -ge "$SH_VM_MIN_FREE_GB" ] || VMNEED=$SH_VM_MIN_FREE_GB; fi
+  VMDISK=$(vmctl disk 2>/dev/null | grep -m1 '^{'); VMFREE=$(printf '%s' "$VMDISK" | python3 -c 'import json,sys; print(json.load(sys.stdin)["free_gb"])' 2>/dev/null)
+  say "VM image store: $(printf '%s' "${VMDISK:-unresolved}" | cut -c1-900); need ${VMNEED}G (2 x ${LOADBYTES} bytes to load, floor ${SH_VM_MIN_FREE_GB}G)"
+  [ "$VMNEED" != x ] && [ "${VMFREE:-0}" -ge "$VMNEED" ] 2>/dev/null || { say "NO DISK on the VM (infrastructure, exit 11): ${VMFREE:-?}G free on $SH_APP, ${VMNEED}G needed before loading seven images; nothing switched"; dbx "$NAME" deploy-failed "$BEFORE" "infrastructure: ${VMFREE:-?}G free on the VM (needs $SH_VM_MIN_FREE_GB); nothing went live; run $RD"; exit 11; }
@@ -615 +683 @@ PY_IDS
-  docker save "$IMG_API" "$IMG_WEB" "$IMG_DISP" | ssh -o ConnectTimeout=15 -o BatchMode=yes -o ServerAliveInterval=30 "$SH_APP" 'sudo docker load' > "$RD/image-load.log" 2>&1
+  docker save "$IMG_API" "$IMG_WEB" "$IMG_DISP" "${JOBIMGS[@]}" | ssh -o ConnectTimeout=15 -o BatchMode=yes -o ServerAliveInterval=30 "$SH_APP" 'sudo docker load' > "$RD/image-load.log" 2>&1
@@ -618,2 +686,2 @@ PY_IDS
-  LOCALIDS=$(for i in "$IMG_API" "$IMG_WEB" "$IMG_DISP"; do printf '%s=%s\n' "$i" "$(docker image inspect -f '{{.Id}}' "$i" 2>/dev/null)"; done)
-  REMOTEIDS=$(vmctl image-ids "$IMG_API" "$IMG_WEB" "$IMG_DISP" 2>/dev/null | grep -m1 '^{')
+  LOCALIDS=$(for i in "$IMG_API" "$IMG_WEB" "$IMG_DISP" "${JOBIMGS[@]}"; do printf '%s=%s\n' "$i" "$(docker image inspect -f '{{.Id}}' "$i" 2>/dev/null)"; done)
+  REMOTEIDS=$(vmctl image-ids "$IMG_API" "$IMG_WEB" "$IMG_DISP" "${JOBIMGS[@]}" 2>/dev/null | grep -m1 '^{')
@@ -634,0 +703,5 @@ PY
+  JOBARGS=""; JOBREFS=()
+  for i in "${!JOBIMGS[@]}"; do
+    ref=$(python3 -c 'import json,sys; r=json.loads(sys.argv[1]); print(sys.argv[2].split(":")[0] + "@" + r[sys.argv[2]])' "$REMOTEIDS" "${JOBIMGS[$i]}") || { say "ABORT: no VM image id for ${JOBIMGS[$i]}"; dbx "$NAME" deploy-failed "$BEFORE" "job image id unreadable; nothing went live; run $RD"; exit 3; }
+    JOBARGS="$JOBARGS --job-image ${JOBKEYS[$i]}=$ref"; JOBREFS+=("$ref")
+  done
@@ -636 +709 @@ PY
-  python3 - "$NAME" "$SHA" "$STAMP" "$SH_APP" "$LOCALIDS" "$SH_BEFORE" > "audit/selfhost-deploys/${SHA:0:8}-$STAMP.json" <<'PY'
+  python3 - "$NAME" "$SHA" "$STAMP" "$SH_APP" "$LOCALIDS" "$SH_BEFORE" "$HOLDNOTE" > "audit/selfhost-deploys/${SHA:0:8}-$STAMP.json" <<'PY'
@@ -638 +711 @@ import json, sys
-name, sha, stamp, host, ids, before = sys.argv[1:7]
+name, sha, stamp, host, ids, before, holds = sys.argv[1:8]
@@ -640 +713,2 @@ print(json.dumps({'release': name, 'sha': sha, 'stamp': stamp, 'host': host, 'de
-                  'images': dict(l.split('=', 1) for l in ids.split('\n') if l), 'previous': json.loads(before or '{}')}, indent=1, sort_keys=True))
+                  'images': dict(l.split('=', 1) for l in ids.split('\n') if l), 'previous': json.loads(before or '{}'),
+                  'jobHolds': holds.split()}, indent=1, sort_keys=True))
@@ -645 +719 @@ Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
-  docker image rm "$IMG_API" "$IMG_WEB" "$IMG_DISP" "$PROMOTED" >/dev/null 2>&1   # local copies only (this box is short of disk); VM 102 holds them
+  docker image rm "$IMG_API" "$IMG_WEB" "$IMG_DISP" "${JOBIMGS[@]}" "$PROMOTED" >/dev/null 2>&1   # local copies only (this box is short of disk); VM 102 holds them
@@ -711 +785 @@ if [ "$TARGET" = selfhost ]; then
-  vmctl pin --stamp "$STAMP" --sha "$SHA" --deploy-id "selfhost-$STAMP" --api "$IMG_API" --web "$IMG_WEB" --disp "$IMG_DISP" > "$RD/pin.txt" 2>&1; rc=$?
+  vmctl pin --stamp "$STAMP" --sha "$SHA" --deploy-id "selfhost-$STAMP" --api "$IMG_API" --web "$IMG_WEB" --disp "$IMG_DISP"$JOBARGS$HOLDARGS$GUARDARGS > "$RD/pin.txt" 2>&1; rc=$?
@@ -720,0 +795,14 @@ if [ "$TARGET" = selfhost ]; then
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
diff --git a/infra/release-harness/selfhost-ctl.py b/infra/release-harness/selfhost-ctl.py
index 3f80a1eff74..44943ff819a 100644
--- a/infra/release-harness/selfhost-ctl.py
+++ b/infra/release-harness/selfhost-ctl.py
@@ -19,0 +20,6 @@ Commands (exit 0 ok; 2 usage; 3 refused, NOTHING was changed; 4 failed part way,
+  disk                           one JSON line {"free_gb": N, "paths": {...}}: the least free space across the filesystems
+                                 that hold the active runtime's data: docker's DockerRootDir and, with the containerd image
+                                 store, containerd's configured root (`containerd config dump`). Refused (exit 3) when any
+                                 of them cannot be resolved or measured.
+  guard-log                      one JSON line {"listening": bool, "held": VALUE|null}: what the running create-guard's own
+                                 startup line says it enforces (goodqa#16136 D1: the hold is proven by the guard, not the file)
@@ -25,0 +32,11 @@ Commands (exit 0 ok; 2 usage; 3 refused, NOTHING was changed; 4 failed part way,
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
@@ -32,0 +50,2 @@ Commands (exit 0 ok; 2 usage; 3 refused, NOTHING was changed; 4 failed part way,
+                                 Never runs the presence check: after restoring it prints WARN lines for job refs and core
+                                 images that do not resolve (a rollback is never blocked; `up` never pulls).
@@ -52,0 +72,21 @@ URL_RE = re.compile(r'postgres(?:ql)?://\S+', re.I)
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
@@ -110,0 +151,108 @@ class Stack:
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
@@ -160 +308,8 @@ class Stack:
-        return dict(core, fp=fp, running=run, missing=sorted(r for r, i in ids.items() if not i))
+        try:
+            jobs = self.jobs(); jobs_held = self.held_keys(); guard_hold = self.guard_hold()
+            jobs_missing = self.job_ids_ok([v for k, v in jobs.items() if k not in jobs_held])
+        except Refused as e: jobs = {'error': str(e)}; jobs_held = []; jobs_missing = []; guard_hold = None
+        # goodqa#16136: jobs and jobs_missing stay OUTSIDE the fp core (every fp recorded before them still matches) and
+        # outside `missing` (rw-ship refuses a release while `missing` is non-empty: no rollback target).
+        return dict(core, fp=fp, running=run, missing=sorted(r for r, i in ids.items() if not i),
+                    jobs=jobs, jobs_held=jobs_held, jobs_missing=jobs_missing, guard_hold=guard_hold)
@@ -281,0 +437,41 @@ def cmd_pin(stk, a):
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
@@ -282,0 +479,7 @@ def pin_prepare(stk, a):
+    new_jobs, held = parse_job_args(getattr(a, 'job_image', None), getattr(a, 'job_hold', None))
+    gh = list(getattr(a, 'guard_hold', None) or [])
+    if len(gh) > 1 or (gh and gh[0] not in GUARD_HOLD_ALLOWED):
+        raise Refused('--guard-hold may be given once, only as %s' % ' or '.join(GUARD_HOLD_ALLOWED))
+    if new_jobs and not stk.store_is_containerd():
+        raise Refused('the docker image store is not containerd: a loaded image would not resolve as repo@<image id> '
+                      '(docker info DriverStatus has no io.containerd.snapshotter)')
@@ -296,0 +500,6 @@ def pin_prepare(stk, a):
+    before_jobs = stk.jobs(old)
+    comp = stk.rejob(comp, new_jobs, held)
+    comp = stk.set_guard_hold(comp, gh[0] if gh else None)
+    want = dict(before_jobs, **new_jobs, **{k: HELD_VALUE for k in held})
+    if stk.jobs(comp) != want or stk.held_keys(comp) != sorted(held) or stk.guard_hold(comp) != (gh[0] if gh else None):
+        raise Refused('job image re-pin self-check failed')
@@ -297,0 +507 @@ def pin_prepare(stk, a):
+    for w in presence_check(stk, comp, held): out(w)
@@ -341,0 +552 @@ def cmd_restore(stk, a):
+    restore_warnings(stk)
@@ -344,0 +556,13 @@ def cmd_restore(stk, a):
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
@@ -369 +593 @@ def cmd_up(stk, a):
-    r = stk.dc('up', '-d', '--no-deps', *SERVICES, timeout=a.timeout + 120)
+    r = stk.dc('up', '-d', '--no-deps', '--pull', 'never', *SERVICES, timeout=a.timeout + 120)
@@ -445,0 +670,4 @@ def main(argv):
+    pn.add_argument('--job-image', action='append', default=[], metavar='KEY=REF')
+    pn.add_argument('--job-hold', action='append', default=[], metavar='KEY')
+    pn.add_argument('--guard-hold', action='append', default=[], metavar='KEY=VALUE')
+    sub.add_parser('disk'); sub.add_parser('guard-log')
@@ -458,0 +687,9 @@ def main(argv):
+        if a.cmd == 'guard-log':
+            r = stk.dc('logs', '--no-color', '--no-log-prefix', '--tail', '200', JOB_BLOCK, timeout=60)
+            ls = [l for l in r.stdout.split('\n') if 'job-dispatcher-create-guard listening' in l]
+            m = re.search(r'heldEnv=(\S+)', ls[-1]) if ls else None
+            held = m.group(1) if m and m.group(1) != 'none' else None
+            out({'listening': bool(ls), 'held': held}); return 0
+        if a.cmd == 'disk':
+            paths = {p: stk.free_gb(p) for p in stk.store_roots()}
+            out({'free_gb': min(paths.values()), 'paths': paths}); return 0
### SECTION B (1373): git diff -U0 c9d61ac1..97bfac51 -- dispatcher src, host apply, wrapper, derive, compose, env-keys
diff --git a/apps/job-dispatcher/src/config.ts b/apps/job-dispatcher/src/config.ts
index e5e0da9948f..dbe98b0b0af 100644
--- a/apps/job-dispatcher/src/config.ts
+++ b/apps/job-dispatcher/src/config.ts
@@ -0,0 +1 @@
+import { JOB_ENVFILE_DIR, parseJobEnvFiles, type JobEnvFiles } from './job-env-file';
@@ -63,0 +65,4 @@ export type Config = z.infer<typeof envSchema> & {
+  /** goodqa#16148 AC-4: allow-listed JOB_ENVFILE_KIND__VAR keys (paths only; files are read per launch). */
+  jobEnvFiles: JobEnvFiles;
+  /** The only directory a JOB_ENVFILE path may live in. Compiled, never read from the env. */
+  jobEnvFileDir: string;
@@ -135 +140 @@ export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
-  return { ...parsed, jobImages, jobBaseEnv };
+  return { ...parsed, jobImages, jobBaseEnv, jobEnvFiles: parseJobEnvFiles(env), jobEnvFileDir: JOB_ENVFILE_DIR };
diff --git a/apps/job-dispatcher/src/docker.ts b/apps/job-dispatcher/src/docker.ts
index 5a1feab52ab..23d41d6a51b 100644
--- a/apps/job-dispatcher/src/docker.ts
+++ b/apps/job-dispatcher/src/docker.ts
@@ -14,0 +15,3 @@ import { execFile, type ExecFileException } from 'node:child_process';
+import { chmodSync, closeSync, constants as fsConstants, fchmodSync, lstatSync, mkdtempSync, openSync, readdirSync, rmSync, unlinkSync, writeSync } from 'node:fs';
+import { tmpdir } from 'node:os';
+import { join } from 'node:path';
@@ -303,0 +307,74 @@ export function describeDockerFailure(stderr: string, secretValues: readonly str
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
@@ -335,3 +412,3 @@ export async function dockerRunDetached(
-  for (const [key, value] of Object.entries(env)) {
-    execArgs.push('-e', `${key}=${value}`);
-  }
+  // goodqa#16148 AC-6: validated and written before docker is touched; removed in the finally.
+  const envFile = writeLaunchEnvFile(env);
+  if (envFile) execArgs.push('--env-file', envFile.file);
@@ -340,0 +418 @@ export async function dockerRunDetached(
+  try {
@@ -361,0 +440,3 @@ export async function dockerRunDetached(
+  } finally {
+    if (envFile) rmSync(envFile.dir, { recursive: true, force: true });
+  }
diff --git a/apps/job-dispatcher/src/index.ts b/apps/job-dispatcher/src/index.ts
index 34a28a5ce0f..262038cc3c4 100644
--- a/apps/job-dispatcher/src/index.ts
+++ b/apps/job-dispatcher/src/index.ts
@@ -2,0 +3,2 @@ import { configureExecutionStore, reconcileExecutions } from './executions';
+import { sweepStaleEnvFileDirs } from './docker';
+import { bootEnvFileStatusLines } from './job-env-file';
@@ -8,0 +11,6 @@ async function main(): Promise<void> {
+  // goodqa#16148 AC-6: a crash between writing a launch env-file and its finally leaves a
+  // directory on the tmpfs; remove any before serving.
+  app.log.info({ removed: sweepStaleEnvFileDirs() }, 'job-dispatcher: swept stale env-file dirs');
+  // goodqa#16148 AC-5: one status line per JOB_ENVFILE key (names and status only); rw-ship's
+  // unhold gate reads `job env file KIND__VAR: ok` from this container's log. Never fails boot.
+  for (const line of bootEnvFileStatusLines(config)) app.log.info(line);
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
@@ -32,0 +33 @@
+import { resolveJobEnvFiles } from './job-env-file';
@@ -39,0 +41,2 @@ import {
+  JobEnvError,
+  envEntryProblem,
@@ -155 +158,22 @@ export function buildServer(config: Config, deps: DockerDeps = realDockerDeps, o
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
@@ -169 +193 @@ export function buildServer(config: Config, deps: DockerDeps = realDockerDeps, o
-        Object.values(config.jobBaseEnv[kind]),
+        Object.values(baseEnv),
@@ -177,0 +202,3 @@ export function buildServer(config: Config, deps: DockerDeps = realDockerDeps, o
+      if (error instanceof JobEnvError) {
+        return reply.code(501).send({ error: error.message });
+      }
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
diff --git a/infra/selfhost/app/compose.yaml b/infra/selfhost/app/compose.yaml
index 2bf2999c2fd..1858d5cad2d 100644
--- a/infra/selfhost/app/compose.yaml
+++ b/infra/selfhost/app/compose.yaml
@@ -122,0 +123,2 @@ services:
+    group_add: ["64910"] # goodqa#16148 AC-11
+    volumes: ["/etc/goodqa/job-secrets:/run/goodqa-secrets:ro"] # goodqa#16148 AC-11
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
@@ -139,0 +140 @@
+    "JOB_ENVFILE_INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY",
### SECTION B+ (1372 fix, in HEAD through the main join 5eafc9a0): git diff -U0 80b26c7e^..80b26c7e -- apps/job-dispatcher/src/docker.ts
diff --git a/apps/job-dispatcher/src/docker.ts b/apps/job-dispatcher/src/docker.ts
index 5a1feab52ab..bf59009634d 100644
--- a/apps/job-dispatcher/src/docker.ts
+++ b/apps/job-dispatcher/src/docker.ts
@@ -251,0 +252,5 @@ function valueForms(value: string): string[] {
+/** The residue rule is in UTF-8 bytes (receipt pr1372-v1): a value of 6 CJK characters is 18 bytes, not 6. */
+function byteLength(value: string): number {
+  return Buffer.byteLength(value, 'utf8');
+}
+
@@ -263 +268 @@ function hasResidueIn(line: string, values: readonly string[]): boolean {
-    if (value.length < MIN_WINDOW) {
+    if (byteLength(value) < MIN_WINDOW) {
@@ -293 +298 @@ export function describeDockerFailure(stderr: string, secretValues: readonly str
-  for (const value of [...values].filter((v) => v.length >= MIN_WINDOW).sort((a, b) => b.length - a.length)) {
+  for (const value of [...values].filter((v) => byteLength(v) >= MIN_WINDOW).sort((a, b) => byteLength(b) - byteLength(a))) {
### SECTION C (gate): git diff -U0 d9cb6162..679c278a -- dispatcher src, ac13-count.py, install-d2.sh, rw-ship.sh, selfhost-ctl.py, derive-job-secrets.py
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
@@ -1 +1,2 @@
-import { loadConfig } from './config';
+import { isBootCheck, runBootCheck } from './boot-check';
+import { loadConfig, type Config } from './config';
@@ -7,4 +8 @@ import { buildServer, realDockerDeps } from './server';
-const config = loadConfig();
-const app = buildServer(config);
-
-async function main(): Promise<void> {
+async function main(config: Config, app: ReturnType<typeof buildServer>): Promise<void> {
@@ -29,4 +27,12 @@ async function main(): Promise<void> {
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
diff --git a/infra/release-harness/ac13-count.py b/infra/release-harness/ac13-count.py
index 9913d48a6f4..1ca2e2cc58d 100755
--- a/infra/release-harness/ac13-count.py
+++ b/infra/release-harness/ac13-count.py
@@ -25 +25,9 @@ body, header or env value is ever printed.
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
@@ -27 +35 @@ Exit 0 PASS, 1 FAIL, 2 usage or unreadable input. Output: one JSON object.
-import argparse, calendar, json, re, sys, time
+import argparse, calendar, json, math, re, sys, time
@@ -37,0 +46 @@ def records(path):
+    """Each JSON object line, or None for a line holding `{` that is not one (counted as unknown, never skipped)."""
@@ -43,2 +52,13 @@ def records(path):
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
@@ -52,2 +72,2 @@ def launches(path):
-    """[(time, kind, status)] for every completed POST /jobs/<kind>/run with a numeric time."""
-    pending, out = {}, []
+    """([(time, kind, status)] for every completed POST /jobs/<kind>/run, [(time or None, why)] unknown records)."""
+    pending, out, unknown = {}, [], []
@@ -54,0 +75 @@ def launches(path):
+        if r is None: unknown.append((None, 'malformed')); continue
@@ -57 +78 @@ def launches(path):
-            req = r.get('req') or {}
+            req = r.get('req') if isinstance(r.get('req'), dict) else {}
@@ -59,7 +80,13 @@ def launches(path):
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
@@ -111 +138 @@ def main(argv=None):
-        got = launches(a.log)
+        got, unknown = launches(a.log)
@@ -115,0 +143,3 @@ def main(argv=None):
+    unk = {}
+    for t, why in unknown:
+        if t is None or inside(t, a.since, a.until): unk[why] = unk.get(why, 0) + 1
@@ -142 +172,2 @@ def main(argv=None):
-    print(json.dumps({'verdict': 'FAIL' if failures else 'PASS', 'mode': a.mode, 'counts': counts, 'held_excluded': held,
+    verdict = 'FAIL' if failures else 'INCONCLUSIVE' if unk else 'PASS'
+    print(json.dumps({'verdict': verdict, 'mode': a.mode, 'counts': counts, 'held_excluded': held, 'unknown': unk,
@@ -144 +175 @@ def main(argv=None):
-    return 1 if failures else 0
+    return 0 if verdict == 'PASS' else 1
diff --git a/infra/release-harness/install-d2.sh b/infra/release-harness/install-d2.sh
index 3572a3ea157..f335f811ccc 100644
--- a/infra/release-harness/install-d2.sh
+++ b/infra/release-harness/install-d2.sh
@@ -26,0 +27,2 @@ source_path = 'infra/release-harness'
+# goodqa#16148: rw-ship streams derive-job-secrets.py from the bound commit only when its blob is this recorded one.
+derive_path = 'infra/selfhost/app/derive-job-secrets.py'
@@ -63,0 +66,9 @@ def committed(commit):
+def derive_blob(commit):
+    """The blob id of derive-job-secrets.py at COMMIT (a regular blob), or None when the commit has no such file."""
+    entry = git('ls-tree', commit, '--', derive_path)
+    if not entry:
+        return None
+    m = re.fullmatch(rb'(100644|100755) blob ([0-9a-f]{40})\t' + re.escape(derive_path.encode()) + rb'\n', entry)
+    require(m is not None, 'derive-job-secrets.py at the commit is not a regular blob')
+    return m.group(2).decode()
+
@@ -70 +81 @@ def validate_binding(data, files):
-    require(len(fields) == 7 and re.fullmatch(r'commit [0-9a-f]{40}', fields[0]), 'invalid binding grammar/completeness')
+    require(len(fields) in (7, 8) and re.fullmatch(r'commit [0-9a-f]{40}', fields[0]), 'invalid binding grammar/completeness')
@@ -71,0 +83,4 @@ def validate_binding(data, files):
+    if len(fields) == 8:  # goodqa#16148: exactly one optional last line, and nothing else new
+        m = re.fullmatch(r'derive-blob ([0-9a-f]{40})', fields[7])
+        require(m is not None, 'invalid binding derive-blob grammar')
+        require(derive_blob(fields[0][7:]) == m.group(1), 'derive-blob is not the derive-job-secrets.py blob at the bound commit')
@@ -73 +88 @@ def validate_binding(data, files):
-    for line in fields[2:]:
+    for line in fields[2:7]:
@@ -235,0 +251 @@ try:
+        blob_id = derive_blob(commit)  # goodqa#16148: absent = a 7-field binding (held releases only)
@@ -237 +253,2 @@ try:
-                ''.join(digest(candidate[p]) + '  ' + p + '\n' for p in paths)).encode()
+                ''.join(digest(candidate[p]) + '  ' + p + '\n' for p in paths) +
+                ('derive-blob ' + blob_id + '\n' if blob_id else '')).encode()
diff --git a/infra/release-harness/rw-ship.sh b/infra/release-harness/rw-ship.sh
index 59de044354d..9f23b02487f 100755
--- a/infra/release-harness/rw-ship.sh
+++ b/infra/release-harness/rw-ship.sh
@@ -242,0 +243,59 @@ print(v if isinstance(v,str) else ("" if v is None else json.dumps(v,sort_keys=T
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
@@ -707,0 +767,20 @@ PY
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
@@ -709 +788 @@ PY
-  python3 - "$NAME" "$SHA" "$STAMP" "$SH_APP" "$LOCALIDS" "$SH_BEFORE" "$HOLDNOTE" > "audit/selfhost-deploys/${SHA:0:8}-$STAMP.json" <<'PY'
+  python3 - "$NAME" "$SHA" "$STAMP" "$SH_APP" "$LOCALIDS" "$SH_BEFORE" "$HOLDNOTE" "$JSGATE" > "audit/selfhost-deploys/${SHA:0:8}-$STAMP.json" <<'PY'
@@ -711 +790 @@ import json, sys
-name, sha, stamp, host, ids, before, holds = sys.argv[1:8]
+name, sha, stamp, host, ids, before, holds, jsgate = sys.argv[1:9]
@@ -714 +793 @@ print(json.dumps({'release': name, 'sha': sha, 'stamp': stamp, 'host': host, 'de
-                  'jobHolds': holds.split()}, indent=1, sort_keys=True))
+                  'jobHolds': holds.split(), 'jobSecretGate': jsgate}, indent=1, sort_keys=True))
@@ -790 +869 @@ if [ "$TARGET" = selfhost ]; then
-  NEW_API=$(jget "$(grep -m1 '^{' "$RD/pin.txt")" fp); NEW_WEB=$NEW_API; infl switch-api
+  NEW_API=$(jget "$(grep -m1 '^{' "$RD/pin.txt")" fp); NEW_WEB=$NEW_API; PIN_FP=$NEW_API; infl switch-api
@@ -808,0 +888,7 @@ bad=[k for k in sys.argv[2:] if r.get(k)!=k.split("@",1)[1]]; print("OK" if not
+  if ! held intelligence-worker; then   # goodqa#16148 AC-8 (c): the RECREATED dispatcher (a new container) logged the key ok
+    DID=""; DST=""; for i in 1 2 3 4 5 6; do DB=$(vmctl disp-boot 2>/dev/null | grep -m1 '^{'); DID=$(jget "$DB" id); DST=$(jget "$DB" status)
+      [ -n "$DID" ] && [ "$DID" != "$DISP_PRE" ] && [ "$DST" = ok ] && break; sleep 5; done
+    say "job secret gate (c) dispatcher boot line: ${DST:-unreadable} (container ${DID:0:12}, before the switch ${DISP_PRE:0:12})"
+    if [ -z "$DID" ] || [ "$DID" = "$DISP_PRE" ]; then js_hold_fail "the job-dispatcher was not recreated by the switch (gate c)"; fi
+    [ "$DST" = ok ] || js_hold_fail "the recreated job-dispatcher did not log the GitHub App key file ok (${DST:-unreadable}, gate c)"
+  fi
diff --git a/infra/release-harness/selfhost-ctl.py b/infra/release-harness/selfhost-ctl.py
index 44943ff819a..75124930f9d 100644
--- a/infra/release-harness/selfhost-ctl.py
+++ b/infra/release-harness/selfhost-ctl.py
@@ -25,0 +26,14 @@ Commands (exit 0 ok; 2 usage; 3 refused, NOTHING was changed; 4 failed part way,
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
@@ -154 +168 @@ class Stack:
-        lines = text.split('\n'); res = {}; cur = None; in_svc = False
+        lines = text.split('\n'); res = {}; cur = None; in_svc = False; sub = None
@@ -156,2 +170,2 @@ class Stack:
-            if l.rstrip() == 'services:': in_svc = True; cur = None; continue
-            if l and not l.startswith(' ') and not l.startswith('#'): in_svc = False; cur = None
+            if l.rstrip() == 'services:': in_svc = True; cur = None; sub = None; continue
+            if l and not l.startswith(' ') and not l.startswith('#'): in_svc = False; cur = None; sub = None
@@ -159 +173,3 @@ class Stack:
-            if in_svc and m: cur = m.group(1); continue
+            if in_svc and m: cur = m.group(1); sub = None; continue
+            m = re.match(r'^    ([A-Za-z0-9_.<-]+):', l)               # review bth-pr73-v4b F1: the service key a line is under
+            if in_svc and cur and m: sub = m.group(1)
@@ -162 +178 @@ class Stack:
-            if not m or not in_svc or cur != JOB_BLOCK:
+            if not m or not in_svc or cur != JOB_BLOCK or sub != 'environment':
@@ -238,2 +254,10 @@ class Stack:
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
@@ -461,0 +486 @@ def presence_check(stk, comp, held):
+    marked = set(stk.held_keys(comp))
@@ -462,0 +488,2 @@ def presence_check(stk, comp, held):
+    # review bth-pr73-v4b F1: every key, held ones included ("" in the resolved env), under environment, in both services
+    want_env = {k: ('' if k in marked else v) for k, v in stk.jobs(comp).items()}
@@ -464,3 +491,6 @@ def presence_check(stk, comp, held):
-        envs = (svcs.get(s) or {}).get('environment') or {}
-        got = {k: envs.get(k) for k in want_jobs}
-        if got != want_jobs: raise Refused('resolved compose: %s does not carry the pinned job images (%s)' % (s, got))
+        envs = (svcs.get(s) or {}).get('environment')
+        if not isinstance(envs, dict): raise Refused('resolved compose: %s has no environment mapping' % s)
+        got = {k: envs[k] for k in envs if k.startswith('JOB_IMAGE_')}
+        if got != want_env:
+            raise Refused('resolved compose: %s environment does not carry exactly the job image lines (%s)'
+                          % (s, ', '.join('%s=%s' % (k, 'held' if got.get(k) == '' else 'set' if k in got else 'missing') for k in sorted(set(want_env) | set(got)))))
@@ -592,2 +622,96 @@ def restore_fence(stk, a, files, baks):
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
@@ -600 +724 @@ def cmd_up(stk, a):
-        for s in SERVICES:
+        for s in services:
@@ -607 +731 @@ def cmd_up(stk, a):
-            out('UP_OK ' + json.dumps({s: want[s] for s in SERVICES}, sort_keys=True)); return 0
+            out('UP_OK ' + json.dumps({s: want[s] for s in services}, sort_keys=True)); return 0
@@ -673,0 +798,3 @@ def main(argv):
+    sub.add_parser('envfile-key'); sub.add_parser('disp-boot')
+    tb = sub.add_parser('trial-boot'); tb.add_argument('--image', required=True); tb.add_argument('--stamp', required=True)
+    ud = sub.add_parser('up-dispatcher'); ud.add_argument('--timeout', type=int, default=300); ud.add_argument('--every', type=float, default=3)
@@ -700 +827 @@ def main(argv):
-        return {'set-secret-env': cmd_secret_env, 'remove-secret-env': cmd_secret_env, 'pin': cmd_pin, 'restore': cmd_restore, 'up': cmd_up, 'migrate': cmd_migrate, 'logs': cmd_logs}[a.cmd](stk, a) or 0
+        return {'set-secret-env': cmd_secret_env, 'remove-secret-env': cmd_secret_env, 'pin': cmd_pin, 'restore': cmd_restore, 'up': cmd_up, 'up-dispatcher': cmd_up_dispatcher, 'envfile-key': cmd_envfile_key, 'disp-boot': cmd_disp_boot, 'trial-boot': cmd_trial_boot, 'migrate': cmd_migrate, 'logs': cmd_logs}[a.cmd](stk, a) or 0
diff --git a/infra/selfhost/app/derive-job-secrets.py b/infra/selfhost/app/derive-job-secrets.py
index d2c3cde6090..a523738d498 100755
--- a/infra/selfhost/app/derive-job-secrets.py
+++ b/infra/selfhost/app/derive-job-secrets.py
@@ -26,0 +27,5 @@ The value never appears in argv, output, a log or a hash.
+
+SINGLE INSTANCE (goodqa#16198): run this only through apply-job-secrets.sh or rw-ship, which hold the deploy lock,
+or by hand only while no such run holds it. Two concurrent runs can each see the other's rename as a changed file;
+the fail-closed unlink then removes the other run's fresh file. That still fails closed (the key reads as missing,
+no value is exposed), and the next single run repairs it.
### SECTION D (F1, bth-pr73-v5): git diff -U2 5eafc9a0..51ae3d52 -- selfhost-ctl.py rw-ship.sh
diff --git a/infra/release-harness/rw-ship.sh b/infra/release-harness/rw-ship.sh
index 9f23b02487f..996b2b8ea20 100755
--- a/infra/release-harness/rw-ship.sh
+++ b/infra/release-harness/rw-ship.sh
@@ -736,6 +736,7 @@ PY_IDS
     LOADBYTES=$((LOADBYTES + b)); done
   if [ "$LOADBYTES" = x ]; then VMNEED=x; else VMNEED=$(( (2 * LOADBYTES + (1 << 30) - 1) >> 30 )); [ "$VMNEED" -ge "$SH_VM_MIN_FREE_GB" ] || VMNEED=$SH_VM_MIN_FREE_GB; fi
-  VMDISK=$(vmctl disk 2>/dev/null | grep -m1 '^{'); VMFREE=$(printf '%s' "$VMDISK" | python3 -c 'import json,sys; print(json.load(sys.stdin)["free_gb"])' 2>/dev/null)
-  say "VM image store: $(printf '%s' "${VMDISK:-unresolved}" | cut -c1-900); need ${VMNEED}G (2 x ${LOADBYTES} bytes to load, floor ${SH_VM_MIN_FREE_GB}G)"
+  VMOUT=$(vmctl disk 2>/dev/null); VMDISK=$(printf '%s\n' "$VMOUT" | grep -m1 '^{'); VMWHY=$(printf '%s\n' "$VMOUT" | grep -m1 '^REFUSED ' | cut -c1-400)
+  VMFREE=$(printf '%s' "$VMDISK" | python3 -c 'import json,sys; print(json.load(sys.stdin)["free_gb"])' 2>/dev/null)
+  say "VM image store: $(printf '%s' "${VMDISK:-unresolved${VMWHY:+ ($VMWHY)}}" | cut -c1-900); need ${VMNEED}G (2 x ${LOADBYTES} bytes to load, floor ${SH_VM_MIN_FREE_GB}G)"
   [ "$VMNEED" != x ] && [ "${VMFREE:-0}" -ge "$VMNEED" ] 2>/dev/null || { say "NO DISK on the VM (infrastructure, exit 11): ${VMFREE:-?}G free on $SH_APP, ${VMNEED}G needed before loading seven images; nothing switched"; dbx "$NAME" deploy-failed "$BEFORE" "infrastructure: ${VMFREE:-?}G free on the VM (needs $SH_VM_MIN_FREE_GB); nothing went live; run $RD"; exit 11; }
   say "images to $SH_APP: docker save | docker load"
diff --git a/infra/release-harness/selfhost-ctl.py b/infra/release-harness/selfhost-ctl.py
index 75124930f9d..56efdefedb7 100644
--- a/infra/release-harness/selfhost-ctl.py
+++ b/infra/release-harness/selfhost-ctl.py
@@ -113,4 +113,135 @@ def out(obj):
 
 
+# ---- receipt bth-pr73-v5 F1: which containerd serves docker, and where it keeps its data
+CTD_DEFAULT_CONFIG = '/etc/containerd/config.toml'   # containerd's own defaults when its command line names neither
+CTD_DEFAULT_ROOT = '/var/lib/containerd'
+CTD_DEFAULT_SOCKETS = ('/run/containerd/containerd.sock', '/var/run/docker/containerd/containerd.sock')
+DOCKERD_DEFAULT_CONFIG = '/etc/docker/daemon.json'
+
+
+class NoListener(Refused):
+    """Nothing listens on a socket path (the default-socket probe tolerates this for one of its two paths)."""
+
+
+def proc_argv(pid):
+    try: raw = open('/proc/%s/cmdline' % pid, 'rb').read()
+    except OSError: raise Refused('process %s went away or cannot be read' % pid)
+    args = raw.decode('utf-8', 'surrogateescape').split('\0')
+    if args and args[-1] == '': args.pop()
+    if not args: raise Refused('process %s has no command line' % pid)
+    return args
+
+
+def proc_comm(pid):
+    try: return open('/proc/%s/comm' % pid).read().strip()
+    except OSError: return ''
+
+
+def cli_flags(args, names, prog):
+    """Values of the long flags NAMES ({spelling: key}) in ARGS[1:]: --x v, --x=v, -x v (Go flag forms). A repeated flag
+    or one without a value refuses."""
+    opts, i = {}, 1
+    while i < len(args):
+        a = args[i]; i += 1
+        if not a.startswith('-') or a in ('-', '--'): continue
+        name, eq, val = a.lstrip('-').partition('=')
+        if name not in names: continue
+        if not eq:
+            if i >= len(args): raise Refused('%s --%s has no value' % (prog, name))
+            val = args[i]; i += 1
+        key = names[name]
+        if key in opts: raise Refused('%s --%s is given twice' % (prog, key))
+        if not val.startswith('/') and not val.startswith('unix:///') or '\n' in val:
+            raise Refused('%s --%s is not an absolute path' % (prog, key))
+        opts[key] = val
+    return opts
+
+
+def socket_holders(path):
+    """Pids holding the one listening unix socket bound at PATH. /proc/net/unix gives its inode; holders are looked for
+    among the processes of the socket file's owner (only they can have bound it; the ctl runs as root on the VM), each in
+    this pid namespace. NoListener when none listens; several listening inodes, an unreadable process of that owner,
+    or a holder in another pid namespace refuse."""
+    want = os.path.realpath(path)
+    try: rows = open('/proc/net/unix').read().split('\n')[1:]
+    except OSError as e: raise Refused('cannot read /proc/net/unix: %s' % type(e).__name__)
+    inodes = set()
+    for row in rows:
+        f = row.split(None, 7)                               # Num RefCount Protocol Flags Type St Inode Path
+        if len(f) == 8 and f[3] == '00010000' and f[5] == '01' and f[7].startswith('/') and os.path.realpath(f[7]) == want:
+            inodes.add(f[6])
+    if not inodes: raise NoListener('nothing listens on %s' % path)
+    if len(inodes) > 1: raise Refused('%d sockets listen on %s, expected exactly one' % (len(inodes), path))
+    tag = 'socket:[%s]' % inodes.pop()
+    try: uid = os.stat(want).st_uid
+    except OSError as e: raise Refused('cannot stat the socket %s: %s' % (path, type(e).__name__))
+    myns = os.readlink('/proc/self/ns/pid')
+    holders, hidden = [], []
+
+    def unreadable(pid):
+        # as root (always so on the VM: `sudo python3 -`) every process can be read, so one that cannot is a refusal;
+        # unprivileged (the test suite), processes of another security context are reported only if nothing holds PATH
+        if os.geteuid() == 0: raise Refused('cannot inspect process %s (holder search for %s)' % (pid, path))
+        hidden.append(pid)
+    for pid in sorted((x for x in os.listdir('/proc') if x.isdigit()), key=int):
+        try:
+            if os.stat('/proc/' + pid).st_uid != uid: continue
+            fds = os.listdir('/proc/%s/fd' % pid)
+        except FileNotFoundError: continue                   # exited meanwhile
+        except PermissionError: unreadable(pid); continue
+        for fd in fds:
+            try: hit = os.readlink('/proc/%s/fd/%s' % (pid, fd)) == tag
+            except FileNotFoundError: hit = False
+            except PermissionError: unreadable(pid); break
+            if hit:
+                try: ns = os.readlink('/proc/%s/ns/pid' % pid)
+                except OSError: raise Refused('cannot inspect process %s (holder search for %s)' % (pid, path))
+                if ns != myns: raise Refused('the holder of %s is in another pid namespace' % path)
+                holders.append(pid); break
+    if not holders and hidden: raise Refused('cannot inspect %d processes; no holder of %s found' % (len(hidden), path))
+    return holders
+
+
+def containerd_root_at(path):
+    holders = socket_holders(path)
+    if len(holders) != 1:
+        raise Refused('%d processes hold the containerd socket %s, expected exactly one' % (len(holders), path))
+    return containerd_root_of(proc_argv(holders[0]))
+
+
+def containerd_root_of(args):
+    """The existing data root (realpath) of the containerd process with command line ARGS: its --root, else the
+    top-level root of its --config file (containerd's default config and root when unnamed). Keys inside [tables]
+    (plugin root_path and the like) are not the daemon root. A non-empty imports, a repeated top-level root, an
+    unreadable named config or a root that does not exist refuse."""
+    opts = cli_flags(args, {'root': 'root', 'config': 'config', 'c': 'config'}, 'containerd')
+    if 'root' in opts: root = opts['root']
+    else:
+        cfg = opts.get('config', CTD_DEFAULT_CONFIG)
+        try: text = open(cfg).read()
+        except FileNotFoundError:
+            if 'config' in opts: raise Refused('containerd --config %s does not exist' % cfg)
+            text = ''
+        except (OSError, UnicodeDecodeError) as e: raise Refused('cannot read the containerd config %s: %s' % (cfg, type(e).__name__))
+        top = []
+        for line in text.split('\n'):
+            if re.match(r'^\s*\[', line): break
+            top.append(line)
+        body = '\n'.join(top)
+        im = re.search(r'^\s*imports\s*=\s*\[([^\]]*)\]', body, re.M)
+        if (im and re.sub(r'(#[^\n]*)|[\s,]', '', im.group(1))) or (not im and re.search(r'^\s*imports\s*=', body, re.M)):
+            raise Refused('the containerd config %s uses imports, which can override its root' % cfg)
+        hits = [l for l in top if re.match(r'^\s*root\s*=', l)]
+        if len(hits) > 1: raise Refused('the containerd config %s sets root %d times' % (cfg, len(hits)))
+        if not hits: root = CTD_DEFAULT_ROOT
+        else:
+            m = re.match(r'^\s*root\s*=\s*(["\x27])([^"\x27\\\n]*)\1\s*(#.*)?$', hits[0])
+            if not m or not m.group(2).startswith('/'): raise Refused('the containerd config %s has an unreadable root' % cfg)
+            root = m.group(2)
+    real = os.path.realpath(root)
+    if not os.path.isdir(real): raise Refused('the containerd root %s does not exist' % root)
+    return real
+
+
 def docker(*a, check=False, timeout=None, cwd=None):
     r = subprocess.run(['docker', *a], capture_output=True, text=True, timeout=timeout, cwd=cwd)
@@ -236,12 +367,60 @@ class Stack:
         if not root.startswith('/') or '\n' in root: raise Refused('cannot resolve the docker data root (docker info DockerRootDir)')
         roots = [root]
-        if self.store_is_containerd():
-            try: c = subprocess.run(['containerd', 'config', 'dump'], capture_output=True, text=True, timeout=60)
-            except (OSError, subprocess.SubprocessError) as e: raise Refused('cannot run containerd config dump: %s' % type(e).__name__)
-            m = re.search(r'^root\s*=\s*(["\x27])([^"\x27\n]+)\1\s*$', c.stdout, re.M) if c.returncode == 0 else None
-            if not m or not m.group(2).startswith('/'): raise Refused('cannot resolve the containerd root (containerd config dump)')
-            roots.append(m.group(2))
+        if self.store_is_containerd(): roots.append(self.containerd_root())
         return roots
 
+    def containerd_root(self):
+        """Receipt bth-pr73-v5 F1: the data root of the containerd that serves THIS docker, never a default `containerd
+        config dump`. The endpoint comes from, in order: docker info .Containerd.Address (Docker Engine 27+); the one
+        dockerd's --containerd flag; its daemon.json "containerd" key; else the two default sockets (system containerd
+        and dockerd's own managed one), of which exactly one may be live, or both with the same root. The one process
+        holding that endpoint's one listening socket is found through /proc (the ctl runs as root on the VM), and its own
+        --root, or the top-level root of its own --config file, is the store. Every unresolved or ambiguous step refuses
+        with its own message; rw-ship then reports the store unresolved and stops (NO DISK, exit 11) before any load."""
+        try: r = docker('info', '-f', '{{json .Containerd}}', timeout=60)
+        except (OSError, subprocess.SubprocessError) as e: raise Refused('cannot run docker info for the containerd address: %s' % type(e).__name__)
+        try: info = json.loads(r.stdout) if r.returncode == 0 else None
+        except ValueError: info = None
+        addr = info.get('Address') if isinstance(info, dict) else None
+        if addr in (None, ''):                              # Docker < 27 has no .Containerd: ask the daemon itself
+            dargs = proc_argv(self.dockerd_pid())
+            opts = cli_flags(dargs, {'containerd': 'containerd', 'config-file': 'config-file'}, 'dockerd')
+            if 'containerd' in opts: addr = opts['containerd']
+            else:
+                cfg = opts.get('config-file', DOCKERD_DEFAULT_CONFIG)
+                try: d = json.loads(open(cfg).read())
+                except FileNotFoundError:
+                    if 'config-file' in opts: raise Refused('dockerd --config-file %s does not exist' % cfg)
+                    d = {}
+                except (OSError, ValueError, UnicodeDecodeError): raise Refused('dockerd daemon.json %s cannot be parsed' % cfg)
+                if not isinstance(d, dict): raise Refused('dockerd daemon.json %s cannot be parsed' % cfg)
+                addr = d.get('containerd') or None
+        if addr is not None:
+            if isinstance(addr, str) and addr.startswith('unix://'): addr = addr[len('unix://'):]
+            if not isinstance(addr, str) or not addr.startswith('/') or '\n' in addr:
+                raise Refused('docker\'s containerd address is not an absolute unix socket path')
+            return containerd_root_at(addr)
+        live = {}
+        for s in CTD_DEFAULT_SOCKETS:
+            try: live[s] = containerd_root_at(s)
+            except NoListener: pass
+        if not live: raise Refused('no containerd listens on either default socket (%s)' % ', '.join(CTD_DEFAULT_SOCKETS))
+        if len(set(live.values())) > 1:
+            raise Refused('both default containerd sockets are live with different roots (%s); docker\'s store is ambiguous'
+                          % ', '.join('%s=%s' % kv for kv in sorted(live.items())))
+        return next(iter(live.values()))
+
+    def dockerd_pid(self):
+        """The one dockerd holding docker's own API socket (the endpoint this docker CLI talks to)."""
+        try: r = docker('context', 'inspect', '-f', '{{.Endpoints.docker.Host}}', timeout=60)
+        except (OSError, subprocess.SubprocessError) as e: raise Refused('cannot read docker\'s API endpoint: %s' % type(e).__name__)
+        host = r.stdout.strip() if r.returncode == 0 else ''
+        if not host.startswith('unix:///') or '\n' in host: raise Refused('docker\'s API endpoint is not a local unix socket; dockerd cannot be found')
+        try: holders = socket_holders(host[len('unix://'):])
+        except NoListener: raise Refused('no dockerd: nothing listens on docker\'s API socket %s' % host[len('unix://'):])
+        ds = [pid for pid in holders if proc_comm(pid) == 'dockerd']
+        if len(ds) != 1: raise Refused('%d dockerd processes hold docker\'s API socket, expected exactly one' % len(ds))
+        return ds[0]
+
     def free_gb(self, path):
         try: r = subprocess.run(['df', '-Pk', path], capture_output=True, text=True, timeout=60)
```

Reply with PASS or FAIL and findings (severity, file:line, reproducer) for HEAD 51ae3d5299b9b207cc896fc61e9e988f6e75d564, judging sections A, B, C and D directly against the snapshot.
