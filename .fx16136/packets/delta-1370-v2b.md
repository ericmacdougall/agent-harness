# PR review packet v2b (delta only): PR #1370 receipt pr1370-v1 BLOCK fixes F1, F2, F3, plus harness PR 73 receipt bth-pr73-v4b F1

Tickets: GoodQA goodqa#16136 (and goodqa#16208, which tracks the base failures below; this diff does not cover it) (F1, F2, F3, 73-F1) and GoodQA goodqa#16148 (the installer derive-blob line, lead ruling option 1).
Sources:
- main's exact-head receipt receipts/bugtracker-pr1370-v1.md, BLOCK: F1 and F2 are fail-open release gates, and F3 asks for evidence.
- receipts/bth-pr73-v4b.md F1, which main folded into this batch because it touches the same file.

Repo: ericmacdougall/bugtracker
Reviewed before: #1370 at c4a1d054fb53e0e0b9661c9c088046d7596e7b51 (fix/16136-job-images-rh)
Expected HEAD: c1d221810a20926ddc869ad010b10faea8a4c4d5 (#1370, fast-forward)

Commits in this delta:
- 1b80fe608be fix(release-harness): fail closed on AC-13 records it cannot read (F1)
- dda2b2c6959 fix(release-harness): refuse an unknown image store and off-env job keys (F2, 73-F1)
- c1d221810a2 feat(release-harness): record an optional derive-blob binding line (goodqa#16148 installer, ported here because rh carries its own install-d2.sh)

## Claims to verify
1. **F1, ac13-count.py.** A record the matcher cannot vouch for is counted as `unknown` by reason. The reasons are:
   - malformed: a line holding `{` that is not a JSON object;
   - orphan completion;
   - invalid status or time: a launch completion whose statusCode is not an int in 100-599 (a bool is not one), or whose time is not a number;
   - no completion: a launch start never completed, or superseded by a reused reqId.

   An unknown counts when its time is inside the window or it has no usable time. Any counted unknown gives verdict INCONCLUSIVE with exit 1, never PASS. A real failure still wins as FAIL. A non-launch request (GET /healthz) still pairs and counts nothing.
2. **F2, selfhost-ctl.py `store_is_containerd`.** It returns True or False only for a readable, non-empty JSON list of string lists. A non-zero rc, a timeout or OSError, empty output, non-JSON, `null`, `{}`, `[]` or a non-pair list raises Refused. So the VM disk gate (`disk` verb, rw-ship exit 11 "VM image store: unresolved") and `pin` both stop, and the store is never read as classic. A real classic DriverStatus still gets the "is not containerd" refusal.
3. **73-F1, `job_lines`.** It tracks the 4-space key a line sits under inside each service. A JOB_IMAGE_* line counts only under the create-guard's `environment:`, so under `labels:` it is refused, held or not.

   **73-F1, `presence_check`.** It compares every JOB_IMAGE_* key, held ones included, in the RESOLVED compose:
   - a held key resolves to "" in `services.<svc>.environment`;
   - this applies to both the guard and the dispatcher;
   - parity is exact: no missing key and no extra key;
   - an environment that is not a mapping is refused.
4. **Test fixture.** The fake `docker compose config` now resolves JOB_IMAGE_* lines by their sub-key (environment or labels) and turns "" into an empty string, as compose does. `resolved-drop-held` simulates a resolved dispatcher env without the held key.
5. **Installer (goodqa#16148, same change as the gate PR).**
   - `install-d2.sh` writes `derive-blob <40hex>` as the 8th binding field when the candidate commit holds infra/selfhost/app/derive-job-secrets.py as a regular blob.
   - `validate_binding` accepts exactly that one optional last line, equal to the blob at the bound commit.
   - It refuses, read-only, a missing file, a mismatching blob, a duplicate, an unknown 8th field, and the line out of place.
   - A candidate without the file still installs a 7-field binding. rh has no unhold gate yet, so this changes nothing at rh's rw-ship.
6. Every fix has failing-first tests and broken variants, and no earlier assertion was changed.

## F3: evidence, commit-bound (t2-dev, 31G free)
Fail first, new tests on the c4a1d054 source:
```
$ pytest -q test_ac13_count.py                                         (c4a1d054 ac13-count.py)
7 failed, 9 passed in 1.28s
$ pytest -q test_rw_ship_selfhost.py -k "cannot_be_discovered or classic_store"   (c4a1d054 selfhost-ctl.py)
14 failed, 2 passed, 121 deselected in 24.50s
$ pytest -q test_rw_ship_selfhost.py -k "labels or held_key_pin_passes or dropping_a_held"   (c4a1d054 selfhost-ctl.py)
3 failed, 1 passed, 137 deselected in 2.62s
$ pytest -q test_install_d2_upgrade.py -k derive                        (c4a1d054 install-d2.sh)
2 failed, 6 passed, 41 deselected in 7.45s
```
At HEAD c1d221810a20926ddc869ad010b10faea8a4c4d5 (rerun with exit status):
```
$ pytest -q test_ac13_count.py
16 passed in 1.54s
exit 0
$ pytest -q test_rw_ship_selfhost.py -k "cannot_be_discovered or classic_store"
16 passed, 125 deselected in 14.22s
exit 0
$ pytest -q test_rw_ship_selfhost.py -k "labels or held_key_pin_passes or dropping_a_held"
4 passed, 137 deselected in 1.34s
exit 0
$ pytest -q test_install_d2_upgrade.py test_installed_binding_upgrade.py test_install_fixture_sparse.py
54 passed in 59.86s
exit 0
```
Broken variants of ac13-count.py, each against `test_ac13_count.py`:
```
A1 orphan skipped            3 failed, 13 passed
A2 malformed skipped         1 failed, 15 passed
A3 invalid skipped           1 failed, 15 passed
A4 open launch skipped       1 failed, 15 passed
A5 unknown passes            6 failed, 10 passed
A6 bool status admitted      1 failed, 15 passed
```
For F2 the broken variant is the c4a1d054 source (14 failed above). The installer variants were run against the identical gate-branch installer, with `-k derive`:
```
I1 no blob check             2 failed, 6 passed
I2 any 8th field             1 failed, 7 passed
I3 duplicates admitted       1 failed, 7 passed
I4 no line written           1 failed, 7 passed
```
Regression, same command at both heads:
```
$ pytest -q test_ac13_count.py test_rw_ship_selfhost.py test_rw_release_authority_d2.py test_selfhost_ctl.py
c4a1d054: 945 failed   HEAD: 945 failed   (failing test ids identical: `comm` of the sorted FAILED lists is empty both ways)
```
**Tracked separately in GoodQA goodqa#16208.** This diff neither covers nor changes those 945 base failures. #16208 also carries the open set-secret-env ctl-copy question.

### Why the base itself fails 945 tests (read-only diagnosis, from git history; nothing was run for it)
The 1370 branch does not sit on main's product line. Its base commit is b3604eaec1c, "chore(release): pin the installed runtime helper line for GoodQA 14377", on origin/base/release-bound-14377.

That commit replaced rw-runtime.sh, rw-ship.sh and selfhost-ctl.py with the OLDER installed-runtime bytes. Its own message says: "DELIBERATELY OFF main ... It must never be merged". It changed no test files. So the branch carries main's newer tests against the older scripts. That was a direct byte replacement, not a merge or a port. The tests ran ahead of the scripts at that point.

- **940 test_selfhost_ctl.py failures.** This test file is unchanged since the merge-base 9deb6d83dfed. Its last change is caf247f290d (goodqa#12707 B1). It drives the `set-secret-env` and `remove-secret-env` verbs.
  - `git show <rev>:infra/release-harness/selfhost-ctl.py | grep -c set-secret-env` gives 7 at origin/main and at 9deb6d83, and 0 at b3604eae, c4a1d054 and HEAD.
  - The older ctl's argparse has no such verbs, so every test gets `invalid choice` with rc 2. The cause is real code, not the environment. The tests target main's ctl.
- **4 ThroughputProcess failures.** These tests expect main's concurrent build pipeline: deploys/*/jobs.json, an API-boundary export list, child build pids, and exit 3 on a receipt changed after qualification.
  - The older rw-ship.sh has no jobs.json and no boundary handling: grep counts are 0 and 0 at HEAD, against 2 and 4 at origin/main.
  - Earlier packets recorded that these tests pass on main (pr-fwd-v2/v3) and fail identically at b3604eae (pr-restage-v2/v3). The cause is real code, not the environment.
- **1 d2 failure.** test_ctl_restore_of_an_older_stamp_is_refused_after_a_newer_pin: PIN2 lacks job args. This is a real test bug. It is also on 1371 and is fixed in the gate PR.

**Effect on the 1370 receipt.** The receipt relies on test_ac13_count.py, the job, hold, guard and VM-disk cases in test_rw_ship_selfhost.py, and the installer tests. None of them is among the 945, and every one of them passes at HEAD.
- test_selfhost_ctl.py tests the secret-env verbs, which this branch neither has nor changes. It is no evidence for or against 1370.
- One open question, filed in goodqa#16208: the release window unholds only after `set-secret-env`. That verb is absent from this branch's selfhost-ctl.py. infra/selfhost/app/set-secret-env.sh may load the ctl from the app checkout rather than from the installed runtime, but I have not verified which copy the host runs. Settle that before the window. It is a question, not a finding.

**Earlier "127 passed, 4 deselected" (pr-rh-v4.md).** That was a different selection: `RW_REAL_COMPOSE=1 pytest -q test_rw_ship_selfhost.py test_ac13_count.py --deselect` with exactly these 4 tests:
- ThroughputProcess::test_api_only_boundary_refusal_starts_zero_image_jobs
- ThroughputProcess::test_cancelled_ship_reaps_owned_builds_before_exit
- ThroughputProcess::test_failed_build_never_transfers_or_switches
- ThroughputProcess::test_receipt_changed_after_qualification_starts_zero_jobs

That run excluded test_selfhost_ctl.py and test_rw_release_authority_d2.py, so the 940 and the PIN2 failure were never in it. The 945 figure comes from the wider four-file run above. These deselections and failures were not hidden. They are pre-existing at base b3604eae and are not fixed in this delta.

**AC-4 real-guard path: PENDING, and the release is gated on it.**
- `PENDING_REAL_TEST p16136-ac4-real-guard` (WAL w65f256f1e2a).
- The check: load a goodqa-<job> image locally and create it as repo@<image id> through the REAL job-dispatcher-create-guard, on an owned lab or staging host; the create must be allowed and the container start.
- Not run: t2-dev is at 31G free, at its 30G floor for heavy Docker work. It needs a lab host with room. Until it has a REALLY_TESTED entry, 1370 must not ship with job images released.

## Delta diff (c4a1d054..c1d22181)
```diff
diff --git a/infra/release-harness/ac13-count.py b/infra/release-harness/ac13-count.py
index 9913d48a6f4..f1e4b01efd6 100755
--- a/infra/release-harness/ac13-count.py
+++ b/infra/release-harness/ac13-count.py
@@ -22,7 +22,14 @@ body, header or env value is ever printed.
   Pairing reads both logs over the window widened by --pair-seconds on each side, so a held launch that straddles a
   window edge still pairs; an unmatched 422 or held API line inside the window, an in-window API launch-failure line
   for any other reason, and an API launch-failure line without a readable timestamp are failures.
-Exit 0 PASS, 1 FAIL, 2 usage or unreadable input. Output: one JSON object.
+UNKNOWN records (receipt pr1370-v1 F1) never let a run PASS. Each one is a record the matcher cannot vouch for:
+  - a line holding `{` that is not a JSON object (malformed);
+  - a "request completed" with no "incoming request" for its reqId (an orphan: it can be an in-window 500);
+  - a launch completion whose statusCode is not an integer 100-599 (a bool is not one) or whose time is not a number;
+  - a launch "incoming request" with no completion (superseded by a reused reqId, or still open at the end of the log).
+It counts when its time is inside the window, or when it has no usable time. Any such record makes the verdict
+INCONCLUSIVE (exit 1) unless a failure already makes it FAIL.
+Exit 0 PASS, 1 FAIL or INCONCLUSIVE, 2 usage or unreadable input. Output: one JSON object.
 """
 import argparse, calendar, json, re, sys, time
 
@@ -35,13 +42,18 @@ API_LINE = re.compile(r'^(?:(\S+)\s+\|\s+)?(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.
 
 
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
+def num(v):
+    return v if isinstance(v, (int, float)) and not isinstance(v, bool) else None
 
 
 def inside(t, since, until):
@@ -49,20 +61,27 @@ def inside(t, since, until):
 
 
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
+            else: unknown.append((t if t is not None else t_in, 'invalid status or time'))
+    unknown += [(t_in, 'no completion') for kind, t_in in pending.values() if kind]
+    return out, unknown
 
 
 def api_lines(paths):
@@ -108,11 +127,14 @@ def main(argv=None):
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
@@ -139,9 +161,10 @@ def main(argv=None):
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
diff --git a/infra/release-harness/selfhost-ctl.py b/infra/release-harness/selfhost-ctl.py
index 58861fa3d56..00b60ae95a1 100644
--- a/infra/release-harness/selfhost-ctl.py
+++ b/infra/release-harness/selfhost-ctl.py
@@ -174,15 +174,17 @@ class Stack:
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
@@ -258,8 +260,15 @@ class Stack:
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
+        if not (isinstance(ds, list) and ds and all(isinstance(x, list) and all(isinstance(y, str) for y in x) for x in ds)):
+            raise Refused('cannot discover the docker image store (docker info DriverStatus %s)' % ('rc=%d' % r.returncode if r.returncode else 'unreadable'))
+        return any('io.containerd.snapshotter' in y for x in ds for y in x)
 
     def resolved(self, text):
         """`docker compose config --format json` of TEXT (anchors and merge keys resolved by compose itself)."""
@@ -428,11 +437,17 @@ def presence_check(stk, comp, held):
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
diff --git a/infra/release-harness/test_ac13_count.py b/infra/release-harness/test_ac13_count.py
index ed8b633812b..8582a9b9202 100644
--- a/infra/release-harness/test_ac13_count.py
+++ b/infra/release-harness/test_ac13_count.py
@@ -145,3 +145,65 @@ def test_window_and_unreadable(tmp_path):
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
diff --git a/infra/release-harness/test_rw_ship_selfhost.py b/infra/release-harness/test_rw_ship_selfhost.py
index 7575156843f..fd912ea870d 100644
--- a/infra/release-harness/test_rw_ship_selfhost.py
+++ b/infra/release-harness/test_rw_ship_selfhost.py
@@ -93,6 +93,8 @@ def resolve(ref):
         return m.group(2)
     return None
 if a[0] == 'info':
+    if mark('driverstatus-fail'): print('Cannot connect to the Docker daemon', file=sys.stderr); sys.exit(1)
+    if mark('driverstatus-out'): print(open(os.path.join(os.environ['FAKE_STATE'], 'driverstatus-out')).read()); sys.exit(0)
     print('[["Backing Filesystem","extfs"],["Supports d_type","true"]]' if mark('classic-store') else '[["driver-type","io.containerd.snapshotter.v1"]]')
     sys.exit(0)
 if a[0] == 'run' and 'src/create-guard-main.ts' in a:          # goodqa#16136 D1: probe of the built guard
@@ -162,19 +164,26 @@ if a[0] == 'compose':
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
@@ -1504,3 +1513,72 @@ def test_job_line_accepts_plain_or_quoted_pins(line):
     lines, res = m.Stack.job_lines(_real_compose_with(m, {'JOB_IMAGE_TRANSCODE': line}))
     assert 'JOB_IMAGE_TRANSCODE' in res
 
+
+
+# ---- receipt pr1370-v1 F2: a failed DriverStatus discovery is not a classic store (fail closed, never DockerRootDir only)
+DISCOVERY_FAILURES = [('rc', None), ('empty', ''), ('not-json', 'template: info: bad'), ('null', 'null'), ('object', '{}'),
+                      ('empty-list', '[]'), ('not-pairs', '["driver-type"]')]
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
```
## Risks
- F1: a log that is truncated at its start, or rotated mid-request, now gives INCONCLUSIVE instead of PASS. That is intended: the operator re-reads a complete window.
- F2: a docker that reports a `null` DriverStatus (some drivers) now refuses the disk gate and pin. That fails closed; containerd stores always report the snapshotter.
- 73-F1: a compose that keeps JOB_IMAGE_* keys under the guard's environment through a list form (`- KEY=V`) is refused by job_lines, as before; only the mapping form is supported.
- The 1371 copy (bff96cc5) and the gate branch carry the same three bugs. The gate PR ports F1, F2 and 73-F1 onto them; it is sent separately.
- Nothing is merged or deployed.
