# PR review packet v2c (delta only): PR #1370, receipt pr1370-v2b BLOCK fixes F1, F2, F3

Tickets: GoodQA goodqa#16136. Base failures that this diff does not cover are tracked in goodqa#16208.
Source: main's exact-head receipt receipts/bugtracker-pr1370-v2b.md, BLOCK, with three material fail-open findings.

Repo: ericmacdougall/bugtracker
Reviewed before: #1370 at c1d221810a20926ddc869ad010b10faea8a4c4d5 (fix/16136-job-images-rh), packet v2b
Expected HEAD: 6c187f88018ed4f0f75e001210cd1f09f976f0db (fast-forward)

Commits in this delta:
- 86f0f898bba80cc26cdee9d831c6ac542a234423 fix(release-harness): keep unusable AC-13 times untimed, finite only (F1, F2)
- 6c187f88018ed4f0f75e001210cd1f09f976f0db fix(release-harness): require two-string DriverStatus rows (F3)

## Claims to verify
1. **F1 (ac13-count.py, the paired-completion branch).** When a launch completion's time is unusable, the unknown record keeps None, never the start time. An untimed unknown always counts, so a start before --since followed by a 500 completion with no usable time now gives INCONCLUSIVE (exit 1). When only the status is unusable, the record keeps its own usable completion time, so outside the window it is still ignored.
2. **F2 (`num()`).** A time must be a finite int or float, and never a bool. `math.isfinite` rejects NaN, Infinity, -Infinity and 1e999 (json.loads gives inf), so each of them becomes None, an untimed unknown. The rule applies to paired completions ('invalid status or time'), orphan completions ('orphan completion') and unfinished launches ('no completion'). A 2xx with a NaN time is never counted as an in-window ok.
3. **F3 (`store_is_containerd`).** Every DriverStatus row must be exactly `[name, value]`, two strings. `[[]]`, a one-element row, a three-element row, and a short row after a good one all raise Refused. Each negative case names `io.containerd.snapshotter`, so a lax check would read it as containerd and ship. The refusal reaches both the VM disk gate (rw-ship exit 11 'VM image store: unresolved') and `pin` (rc 3, nothing changed). A real classic store still gets 'is not containerd'.
4. No earlier assertion is changed or removed. The four F3 cases are added to the existing DISCOVERY_FAILURES list, which parametrizes both the disk test and the pin test.

## Evidence (t2-dev), commit-bound
Fail first: the new tests against the c1d22181 sources.
```
$ pytest -q test_ac13_count.py
FAILED test_ac13_count.py::test_unusable_completion_time_is_untimed_not_the_start_time
FAILED test_ac13_count.py::test_non_finite_times_are_untimed_unknowns
2 failed, 16 passed in 1.60s
$ pytest -q test_rw_ship_selfhost.py -k "cannot_be_discovered or classic_store"
FAILED ...test_vm_disk_refuses_when_the_store_cannot_be_discovered[empty-row-[[]]]
FAILED ...test_vm_disk_refuses_when_the_store_cannot_be_discovered[one-element-...]
FAILED ...test_vm_disk_refuses_when_the_store_cannot_be_discovered[three-element-...]
FAILED ...test_vm_disk_refuses_when_the_store_cannot_be_discovered[short-after-good-...]
FAILED ...test_ctl_pin_refuses_when_the_store_cannot_be_discovered[empty-row|one-element|three-element|short-after-good]  (4)
8 failed, 16 passed, 125 deselected in 25.47s
```
At HEAD 6c187f88:
```
$ pytest -q test_ac13_count.py
18 passed in 2.02s
exit 0
$ pytest -q test_rw_ship_selfhost.py -k "cannot_be_discovered or classic_store"
24 passed, 125 deselected in 22.10s
exit 0
```
Broken variants, each applied to the HEAD source and then restored with `cmp`:
```
V1 start-time fallback restored (t if t is not None else t_in)   test_ac13_count.py  -> 2 failed, 16 passed
V2 math.isfinite dropped from num()                               test_ac13_count.py  -> 1 failed, 17 passed
V3 row length check dropped (any-length string rows)              store -k subset     -> 8 failed, 16 passed
```
Regression at HEAD (34G free on t2-dev):
```
$ pytest -q test_ac13_count.py test_rw_ship_selfhost.py test_rw_release_authority_d2.py test_install_d2_upgrade.py
5 failed, 237 passed, 1 skipped in 523.60s
```
All 5 failures are pre-existing base failures, tracked in goodqa#16208 and present at c1d22181 and at the base b3604eae: the 4 ThroughputProcess tests and the d2 PIN2 test. No other test fails. test_selfhost_ctl.py (the 940, also #16208) is not in this run.

Follow-up: 1371 and the gate branch fix/16148-rwship-gate carry the same ac13-count.py and store_is_containerd code. These fixes, with the v2 F1, F2 and 73-F1 fixes, are ported there next and sent in the gate packet.

## Delta diff (c1d22181..6c187f88)
```diff
diff --git a/infra/release-harness/ac13-count.py b/infra/release-harness/ac13-count.py
index f1e4b01efd6..b00b4842d7a 100755
--- a/infra/release-harness/ac13-count.py
+++ b/infra/release-harness/ac13-count.py
@@ -25,13 +25,14 @@ body, header or env value is ever printed.
 UNKNOWN records (receipt pr1370-v1 F1) never let a run PASS. Each one is a record the matcher cannot vouch for:
   - a line holding `{` that is not a JSON object (malformed);
   - a "request completed" with no "incoming request" for its reqId (an orphan: it can be an in-window 500);
-  - a launch completion whose statusCode is not an integer 100-599 (a bool is not one) or whose time is not a number;
+  - a launch completion whose statusCode is not an integer 100-599 (a bool is not one) or whose time is not a finite
+    number (NaN, Infinity, 1e999 are not); such a completion keeps its own time, or none, never its start time;
   - a launch "incoming request" with no completion (superseded by a reused reqId, or still open at the end of the log).
 It counts when its time is inside the window, or when it has no usable time. Any such record makes the verdict
 INCONCLUSIVE (exit 1) unless a failure already makes it FAIL.
 Exit 0 PASS, 1 FAIL or INCONCLUSIVE, 2 usage or unreadable input. Output: one JSON object.
 """
-import argparse, calendar, json, re, sys, time
+import argparse, calendar, json, math, re, sys, time
 
 KINDS = ('scan', 'transcode', 'intelligence-worker', 'suggest-fix-worker')
 HOLDABLE = ('intelligence-worker', 'transcode')
@@ -53,7 +54,8 @@ def records(path):
 
 
 def num(v):
-    return v if isinstance(v, (int, float)) and not isinstance(v, bool) else None
+    """A usable time: a finite int or float, never a bool. NaN, Infinity and 1e999 (receipt pr1370-v2b F2) are None."""
+    return v if isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v) else None
 
 
 def inside(t, since, until):
@@ -79,7 +81,7 @@ def launches(path):
             res = r.get('res') if isinstance(r.get('res'), dict) else {}
             st, t = res.get('statusCode'), num(r.get('time'))
             if isinstance(st, int) and not isinstance(st, bool) and 100 <= st <= 599 and t is not None: out.append((t, kind, st))
-            else: unknown.append((t if t is not None else t_in, 'invalid status or time'))
+            else: unknown.append((t, 'invalid status or time'))   # an unusable time stays None, never the start time (v2b F1)
     unknown += [(t_in, 'no completion') for kind, t_in in pending.values() if kind]
     return out, unknown
 
diff --git a/infra/release-harness/selfhost-ctl.py b/infra/release-harness/selfhost-ctl.py
index 00b60ae95a1..4ecaa4e75aa 100644
--- a/infra/release-harness/selfhost-ctl.py
+++ b/infra/release-harness/selfhost-ctl.py
@@ -266,7 +266,8 @@ class Stack:
         except (OSError, subprocess.SubprocessError) as e: raise Refused('cannot discover the docker image store (docker info DriverStatus: %s)' % type(e).__name__)
         try: ds = json.loads(r.stdout) if r.returncode == 0 else None
         except ValueError: ds = None
-        if not (isinstance(ds, list) and ds and all(isinstance(x, list) and all(isinstance(y, str) for y in x) for x in ds)):
+        # every row is exactly [name, value], two strings (receipt pr1370-v2b F3: [[]], one- and three-element rows refuse)
+        if not (isinstance(ds, list) and ds and all(isinstance(x, list) and len(x) == 2 and all(isinstance(y, str) for y in x) for x in ds)):
             raise Refused('cannot discover the docker image store (docker info DriverStatus %s)' % ('rc=%d' % r.returncode if r.returncode else 'unreadable'))
         return any('io.containerd.snapshotter' in y for x in ds for y in x)
 
diff --git a/infra/release-harness/test_ac13_count.py b/infra/release-harness/test_ac13_count.py
index 8582a9b9202..92866f75773 100644
--- a/infra/release-harness/test_ac13_count.py
+++ b/infra/release-harness/test_ac13_count.py
@@ -207,3 +207,41 @@ def test_unknown_also_blocks_the_positive_control_and_a_failure_still_wins(tmp_p
     assert rc == 1 and o['verdict'] == 'INCONCLUSIVE', o
     rc, o = run(_raw(tmp_path, [_done('req-orphan', 500)], base=OK + [('scan', 500)]), '--mode', 'post', *REQ)
     assert rc == 1 and o['verdict'] == 'FAIL' and o['unknown'] == {'orphan completion': 1}, o
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
diff --git a/infra/release-harness/test_rw_ship_selfhost.py b/infra/release-harness/test_rw_ship_selfhost.py
index fd912ea870d..2abc36f00ad 100644
--- a/infra/release-harness/test_rw_ship_selfhost.py
+++ b/infra/release-harness/test_rw_ship_selfhost.py
@@ -1517,7 +1517,11 @@ def test_job_line_accepts_plain_or_quoted_pins(line):
 
 # ---- receipt pr1370-v1 F2: a failed DriverStatus discovery is not a classic store (fail closed, never DockerRootDir only)
 DISCOVERY_FAILURES = [('rc', None), ('empty', ''), ('not-json', 'template: info: bad'), ('null', 'null'), ('object', '{}'),
-                      ('empty-list', '[]'), ('not-pairs', '["driver-type"]')]
+                      ('empty-list', '[]'), ('not-pairs', '["driver-type"]'),
+                      # receipt pr1370-v2b F3: a row is exactly two strings (each case names the snapshotter, so a lax check ships)
+                      ('empty-row', '[[]]'), ('one-element', '[["io.containerd.snapshotter.v1"]]'),
+                      ('three-element', '[["driver-type","io.containerd.snapshotter.v1","x"]]'),
+                      ('short-after-good', '[["driver-type","io.containerd.snapshotter.v1"],["x"]]')]
 
 
 @pytest.mark.parametrize('name,body', DISCOVERY_FAILURES)
```
## Risks
- F1/F2: a log with non-finite or unusable times now gives INCONCLUSIVE instead of PASS. That is intended: it fails closed.
- F3: a docker that reports DriverStatus rows other than name/value pairs now refuses the disk gate and pin. That also fails closed.
- Nothing is merged, tagged or deployed.
