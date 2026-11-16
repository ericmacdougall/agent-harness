# PR review packet v3: bugtracker PR #1377 (fix/16148-rwship-gate), the five v2 findings; delta over 51ae3d52

Ticket: GoodQA goodqa#16148
Repo: ericmacdougall/bugtracker, branch fix/16148-rwship-gate, PR #1377.
Expected HEAD: 69c7fd115811dd0d193bad6c13d4243b960e16c6 (pushed; origin/fix/16148-rwship-gate equals it)
Receipt snapshot base: 179c3ab1a8770c7bf184caef2a21798b8713a92b (unchanged from v2).
Ancestry (t2-dev): `git merge-base --is-ancestor 179c3ab1 69c7fd11` true; `git merge-base --is-ancestor 51ae3d52 69c7fd11` true (fast-forward, one commit). `git diff --check 51ae3d52 69c7fd11` clean.
Answers: receipts/bugtracker-pr1377-gate-v2.md (Codex, R3), BLOCK at 51ae3d52 with F1 High, F2 High, F3 Med, F4 Med, F5 Med. Round 2 on PR 1377.
This packet is the delta 51ae3d52..69c7fd11 only; packet v2 (pr-gate-compact2.md, sha256 20808cd9ca3d) covers 179c3ab1..51ae3d52 and is unchanged.
Redaction: one diff context line (rw-ship.sh SELFHOST_APP default) carries an address; it is shown as <IP>. Nothing else is altered.

Commit: 69c7fd115811dd0d193bad6c13d4243b960e16c6 fix(release-harness): close the five 1377 v2 review findings (11 files, +505 -45).

## Findings, fixes, tests, fail-first

| v2 finding | Fix (69c7fd11) | Tests (new or changed) | At 51ae3d52 code | At 69c7fd11 | Broken variant |
|---|---|---|---|---|---|
| F1 High: quoted `root`/`imports` key misread (selfhost-ctl.py:231-236) | `ctd_config_root`: tomllib when it imports; else strict reader `ctd_top_strict`; both refuse non-empty imports, case variants of root/imports, repeated root, non-absolute or missing root | test_f1_containerd_config_refusals (21 configs x tomllib/fallback), test_f1_quoted_root_key_is_never_the_default_root (receipt reproducer, both quotings), test_f1_real_world_containerd_configs_are_accepted_with_the_right_root, test_f1_strict_reader_agrees_with_tomllib_whenever_it_accepts | `-k f1_`: 42 failed, 35 passed | 77 passed | V1a strict reader accepts quoted keys: 5 failed; V1b no case check: 5 failed |
| F2 High: failures before gate (c) leave intelligence-worker unheld (rw-ship.sh:874/882/887/889-894) | `sh_fail_rollback` re-holds first (js_hold_fail) once `up` ran and until gate (c) passed; re-hold failure: after a migration exit 8, before one roll back and verify (below) | 8 new whole-script test functions (11 cases) in test_rw_ship_jobsecret_gate.py (listed below), gate (c) re-hold-failure test split by migration | jobsecret file: 19 failed (F2 cases plus F3/F4 below) | 48 passed | V2a no re-hold before gate (c): 4 failed; V2b rollback not verified: 1 failed |
| F3 Med: boot `ok` while every launch 501 (job-env-file.ts:120-140) | `envFileConflict` shared by launch and boot; boot prints the conflict line; trial boot exits 1; selfhost-ctl maps the line to `error:conflict` | job-env-file.test.ts (boot line equals the launch error), boot-check.test.ts (exit 1), test_selfhost_ctl_gate disp_status case, gate (c) whole-script case | vitest 2 failed; ctl_gate disp_status 1 failed; gate (c) case 1 failed | pass | V3a boot ignores conflict: 2 failed; V3b ctl word dropped: 1 failed |
| F4 Med: a second key assignment passes gate (b) (selfhost-ctl.py:820-825) | `envfile-key` prints `count` = non-comment lines naming the key at all (any syntax, JOB_ENV_ twin included) and `canonical` = byte-exact lines; gate (b) passes only 1 and 1 | test_envfile_key_counts_only_the_exact_line (fixed: the old test accepted the duplicate), test_envfile_key_counts_every_line_naming_the_key (14 cases incl. the receipt reproducer), whole-script gate (b) cases | 15 failed (ctl_gate) and 7 whole-script | pass | V4 count only canonical lines: 11 failed |
| F5 Med: out-of-range float time hides a failure (ac13-count.py:59-64) | `num()`: the +-2**53 bound applies to floats | test_out_of_range_float_time_is_an_untimed_unknown (receipt reproducer for 5 values, orphan/paired/unfinished), test_in_range_float_times_are_still_times | 1 failed (reproducer verdict PASS) | 2 passed | V5 float bound dropped: 1 failed |

Fail-first commands (t2-dev, new tests applied on top of the 51ae3d52 code, log delta/v3/ff-base-51ae3d52.log), then the same at the fix (ff-fixed.log):
```
pytest -q test_ac13_count.py -k "out_of_range or in_range_float"           base: 1 failed, 1 passed       fixed: 2 passed
pytest -q test_selfhost_ctl_gate.py -k "envfile_key or disp_status"         base: 16 failed, 11 passed     fixed: 27 passed
pytest -q test_rw_ship_selfhost.py -k f1_                                   base: 42 failed, 35 passed     fixed: 77 passed
pytest -q test_rw_ship_jobsecret_gate.py                                    base: 19 failed, 29 passed     fixed: 48 passed
npx vitest run test/job-env-file.test.ts test/boot-check.test.ts           base: 2 failed, 30 passed      fixed: 32 passed
```
At 51ae3d52 the tomllib-path cases of F1 fail on the assertion that the module uses tomllib (it has none); the fallback-path cases fail on their own assertions (quoted root measured as the default root, quoted imports accepted, case variants accepted, multi-line strings accepted).

Broken variants (variants_v3.sh at 69c7fd11: edit one file, run its tests, `git checkout` it; "tree after: 0 changed"):
```
V1a strict reader accepts quoted keys              -> 5 failed, 41 passed
V1b no case check on root/imports                  -> 5 failed, 37 passed
V2a pre-gate-c failures not re-held                -> 4 failed
V2b rollback after a failed re-hold not verified   -> 1 failed
V3a boot status ignores the conflict (TS)          -> 2 failed, 30 passed
V3b gate (c) word for the conflict dropped         -> 1 failed, 10 passed
V4  envfile-key counts only canonical lines        -> 11 failed, 5 passed
V5  float bound dropped                            -> 1 failed, 1 passed
```

Affected suites at 69c7fd11 (clean tree, t2-dev, log delta/v3/suite-69c7fd11.log):
```
$ cd infra/release-harness && python3 -m pytest -q -p no:cacheprovider -rs test_rw_ship_selfhost.py test_rw_release_authority_d2.py test_selfhost_ctl.py test_selfhost_ctl_gate.py test_selfhost_ctl_job_secrets.py test_rw_ship_jobsecret_gate.py test_ac13_count.py
SKIPPED [1] test_rw_ship_selfhost.py:1404: real docker compose run: set RW_REAL_COMPOSE=1 (t2-dev)
1998 passed, 1 skipped in 1348.03s
exit 0
$ cd apps/job-dispatcher && npx tsc --noEmit -p .
exit 0
$ cd apps/job-dispatcher && npx vitest run
Test Files  18 passed | 1 skipped (19)
Tests  458 passed | 15 skipped (473)
exit 0
```
(The t2-dev checkout is sparse; apps/transcoder/src was added to it so held-env.test.ts can import ../../transcoder/src/mode, which the test needs at base too.)

## F1 detail: the two parsers
- tomllib (python >= 3.11): the whole file must parse (duplicate keys, `root.x` redefinitions and any syntax error refuse: "is not valid TOML"); `root` and `imports` are the top-level keys of the document, so a quoted key resolves exactly and a table or inline-table `root` is never the daemon root.
- Strict reader (no tomllib; the VM's python is not known to us, so both paths are tested with the fallback forced by setting the module's `tomllib` to None): above the first `[` line every line is a comment, a blank, or one bare key `[A-Za-z0-9_-]+` set to a basic string without backslash, a literal string, a decimal integer, true/false, or a one-line array of such strings (trailing comma allowed). `"""` or `'''` anywhere in that region refuses ("multi-line string"); any other line refuses ("cannot be read safely without tomllib"), so quoted keys, dotted keys, inline tables, escapes, hex numbers and multi-line arrays refuse. Repeated `root` or `imports` refuses.
- Both: a top-level key equal to root or imports ignoring case but not lowercase refuses ("spells root as 'Root'"); containerd's Go decoder may match keys case-insensitively and that is not verified here. Non-empty or non-array imports refuses; a root that is not an absolute string, or does not exist, refuses.
- Lead ruling (this round): the wider fallback grammar (ints, booleans, literal strings, one-line arrays) is approved because the literal-basic-string-only grammar refuses every real containerd config; parity test: wherever the strict reader accepts, its root equals tomllib's (8 configs incl. the `containerd config default` v2 output and Docker's containerd.io package config).

## F2 detail: the rule and why it differs from the lead's first wording
- `SH_UP_RAN=1` is set right before the switch's `vmctl up`; `JS_C_OK=1` right after gate (c) passes. While up ran, gate (c) has not passed and this release does not hold intelligence-worker, `sh_fail_rollback` hands over to `js_hold_fail`: re-hold first (pin with the hold, recreate the dispatcher and guard only), then the forward-only stop after a migration (exit 8) or the usual rollback (exit 5). Covered: up not healthy (:874), job refs unresolved (:882), guard not reporting its hold (:887); the API-version check (:897) runs after gate (c), so the dispatcher's key is already verified there.
- Out of scope, stated: the partial re-pin failure (:869) happens before any `up`; nothing was recreated, so no unheld dispatcher can be running. Its existing handling is unchanged.
- Re-hold fails, after a migration: exit 8 HOLD NOT RE-APPLIED, no rollback (forward-only), state deploy-unverified, inflight kept.
- Re-hold fails, no migration (lead ruling wa5b72dea2cf): a re-hold pin that went through (only its `up` failed) is undone first (`restore --stamp <stamp>h`; without this the run's own restore is refused as stale, found by the tests), then the usual restore and `up`; exit 5 only when the live API is back at BEFORE AND the restored JOB_IMAGE_INTELLIGENCE_WORKER is `held` or byte for byte the value read before the run ("same-as-before"); otherwise exit 8 HOLD NOT RE-APPLIED. The log names the pre-run value, the restored value and the branch.
- Why not "held only" (the lead's first wording): after a release passes gate (c) the worker is normally released, so a clean rollback to that already-accepted release would always end at exit 8 (e.g. :882, test_job_ref_unresolved_after_switch_rolls_back, exit 5 today, where the re-hold pin refuses the missing job image). Restoring the exact pre-run state of an accepted release is safe; the hazard is only the NEW unheld dispatcher. The lead approved this rule.
- The pre-run value comes from the VM state read before anything changed (selfhost-before.json). If it is unreadable or ambiguous (jobs unreadable, key missing, not a string), a release that unholds intelligence-worker refuses up front (exit 2, before derive, migrations or the switch).
- Gate (c) failures use the same path, so a gate (c) re-hold failure without a migration now rolls back too (was exit 8 without a rollback). The old test is now test_rehold_failure_after_a_migration_is_exit_8_and_touches_nothing_else; test_gate_c_rehold_failure_without_a_migration_rolls_back_to_the_previous_release covers the new branch.
- New whole-script tests: test_pre_gate_c_failure_after_a_migration_reholds_before_the_forward_only_stop[unhealthy, guard] (the receipt's case: unheld worker, one migration, readiness fails: re-held, then exit 8), test_pre_gate_c_failure_without_a_migration_reholds_then_rolls_back[unhealthy, guard], test_pre_gate_c_rehold_failure_without_a_migration_rolls_back_to_the_verified_previous_release[held, released], test_pre_gate_c_rehold_failure_when_the_restore_is_not_the_previous_value_is_exit_8, test_pre_gate_c_rehold_failure_after_a_migration_stops_without_a_rollback, test_gate_c_rehold_failure_without_a_migration_rolls_back_to_the_previous_release, test_job_ref_unresolved_before_gate_c_ends_on_the_previous_release, test_unreadable_pre_run_intelligence_worker_refuses_before_anything.
- Test-fixture additions (fake VM ssh only): `state-jobs-error` (the state verb reports unreadable job lines) and `restore-intel-drift` (a restore lands a different intelligence-worker line).
- The forward-only negative control `no-migration-hold` now runs with intelligence-worker held (an unheld release now re-holds first and stops in js_hold_fail's own mig_hold, so the mutated line was unreachable); a new test_no_automatic_rollback_after_a_migration_with_intelligence_worker_held covers the plain path directly.

## F3/F4 detail
- F4 also catches the F3 conflict before migrations: a `JOB_ENV_INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY=` line names the key, so count is 2 and gate (b) refuses (lead ruling: right place). F3's boot-status fix stays as a second layer for env that does not come from dispatcher.env.
- Gate (b) log line: `key lines in dispatcher.env: <count> (canonical <n>)`; the refusal names both numbers.

## Not exercised (disclosed)
- Real VM python version, containerd config and Docker version; the live guard (PENDING_REAL_TEST p16136-ac4-real-guard) and the sampler/gate-(c)/trial-boot live checks named in v2 remain pending for the landing window.
- The release line (#1384) port of F1 is next (F2 has no counterpart there: no job-secret gate; F5 belongs to goodqa#16210, updated to carry the float bound).

## Delta diff (51ae3d52..69c7fd11)
```diff
diff --git a/apps/job-dispatcher/src/boot-check.ts b/apps/job-dispatcher/src/boot-check.ts
index 0ec81c472c2..a46f6b23bb7 100644
--- a/apps/job-dispatcher/src/boot-check.ts
+++ b/apps/job-dispatcher/src/boot-check.ts
@@ -31,7 +31,7 @@ export function runBootCheck(
     write(`boot check: config refused (${error instanceof Error ? error.name : 'unknown'})`);
     return 2;
   }
-  const lines = bootEnvFileStatusLines({ jobEnvFiles: config.jobEnvFiles, jobEnvFileDir: envFileDir });
+  const lines = bootEnvFileStatusLines({ jobEnvFiles: config.jobEnvFiles, jobEnvFileDir: envFileDir, jobBaseEnv: config.jobBaseEnv });
   if (lines.length === 0) {
     write('boot check: no JOB_ENVFILE key configured');
     return 3;
diff --git a/apps/job-dispatcher/src/job-env-file.ts b/apps/job-dispatcher/src/job-env-file.ts
index e1a94dcfbbc..929c8a935db 100644
--- a/apps/job-dispatcher/src/job-env-file.ts
+++ b/apps/job-dispatcher/src/job-env-file.ts
@@ -107,6 +107,17 @@ export function envFileError(entry: Pick<JobEnvFileEntry, 'id'>, reason: string)
   return `job env file for ${entry.id}: ${reason}`;
 }
 
+/** The phrase rw-ship's gate (c) maps to `error:conflict` (selfhost-ctl.py DISP_ERR_WORDS). */
+export const ENVFILE_CONFLICT = 'both JOB_ENV_ and JOB_ENVFILE_ are set';
+
+/**
+ * The one conflict check launch and boot share (receipt bugtracker-pr1377-gate-v2 F3): the kind's own JOB_ENV_ var for
+ * the same VAR makes every launch 501, so boot must not report that key `ok`.
+ */
+export function envFileConflict(entry: Pick<JobEnvFileEntry, 'varName'>, baseEnv: Record<string, string> | undefined): boolean {
+  return baseEnv !== undefined && Object.prototype.hasOwnProperty.call(baseEnv, entry.varName);
+}
+
 /** Resolve a kind's file-backed env for one launch, or the first named error. */
 export function resolveJobEnvFiles(
   files: JobEnvFiles,
@@ -117,9 +128,7 @@ export function resolveJobEnvFiles(
   const env: Record<string, string> = {};
   for (const entry of files.entries) {
     if (entry.kind !== kind) continue;
-    if (Object.prototype.hasOwnProperty.call(baseEnv, entry.varName)) {
-      return { ok: false, error: envFileError(entry, 'both JOB_ENV_ and JOB_ENVFILE_ are set') };
-    }
+    if (envFileConflict(entry, baseEnv)) return { ok: false, error: envFileError(entry, ENVFILE_CONFLICT) };
     const read = readJobEnvFile(entry.path, allowedDir);
     if (!read.ok) return { ok: false, error: envFileError(entry, read.reason) };
     env[entry.varName] = read.value;
@@ -128,9 +137,17 @@ export function resolveJobEnvFiles(
 }
 
 /** Boot: one status line per JOB_ENVFILE key (rw-ship's unhold gate reads `: ok`). Never throws. */
-export function bootEnvFileStatusLines(config: { jobEnvFiles: JobEnvFiles; jobEnvFileDir: string }): string[] {
+export function bootEnvFileStatusLines(config: {
+  jobEnvFiles: JobEnvFiles;
+  jobEnvFileDir: string;
+  jobBaseEnv: Record<JobKind, Record<string, string>>;
+}): string[] {
   const lines: string[] = [];
   for (const entry of config.jobEnvFiles.entries) {
+    if (envFileConflict(entry, config.jobBaseEnv[entry.kind])) {
+      lines.push(envFileError(entry, ENVFILE_CONFLICT));
+      continue;
+    }
     let read: JobEnvFileRead;
     try {
       read = readJobEnvFile(entry.path, config.jobEnvFileDir);
diff --git a/apps/job-dispatcher/test/boot-check.test.ts b/apps/job-dispatcher/test/boot-check.test.ts
index adafaaaa8bf..9b23764e2f4 100644
--- a/apps/job-dispatcher/test/boot-check.test.ts
+++ b/apps/job-dispatcher/test/boot-check.test.ts
@@ -66,6 +66,16 @@ describe('--boot-check (trial boot only)', () => {
     expect(out[0]).toMatch(/^job env file for INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY: /);
   });
 
+  it('receipt 1377-v2 F3: JOB_ENV_ and JOB_ENVFILE_ for the same key is a non-zero exit, never the ok line', () => {
+    const code = runBootCheck(
+      { JOB_DISPATCH_TOKEN: 'fake-token', [KEY]: secret(), JOB_ENV_INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY: 'inline' },
+      write,
+      dir,
+    );
+    expect(code).toBe(1);
+    expect(out).toEqual(['job env file for INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY: both JOB_ENV_ and JOB_ENVFILE_ are set']);
+  });
+
   it('no JOB_ENVFILE key at all is a non-zero exit (a trial must exercise the key)', () => {
     expect(runBootCheck({ JOB_DISPATCH_TOKEN: 'fake-token' }, write, dir)).toBe(3);
     expect(out).toEqual(['boot check: no JOB_ENVFILE key configured']);
diff --git a/apps/job-dispatcher/test/job-env-file.test.ts b/apps/job-dispatcher/test/job-env-file.test.ts
index adb26697d65..28a899411e7 100644
--- a/apps/job-dispatcher/test/job-env-file.test.ts
+++ b/apps/job-dispatcher/test/job-env-file.test.ts
@@ -134,6 +134,19 @@ describe('AC-5 / NEG-4: fail closed per kind', () => {
     expect(run).not.toHaveBeenCalled();
   });
 
+  it('receipt 1377-v2 F3: boot status reports the JOB_ENV_/JOB_ENVFILE_ conflict that makes every launch 501', async () => {
+    writeFileSync(join(dir, name), FAKE_PEM);
+    const cfg = config({ [KEY]: join(dir, name), JOB_ENV_INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY: 'inline' });
+    const want = 'job env file for INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY: both JOB_ENV_ and JOB_ENVFILE_ are set';
+    expect(bootEnvFileStatusLines(cfg)).toEqual([want]);
+    const { res } = await launch(cfg);
+    expect(res.json().error).toBe(want); // the same phrase at boot and at launch
+    // a JOB_ENV_ var for ANOTHER kind is not a conflict
+    expect(bootEnvFileStatusLines(config({ [KEY]: join(dir, name), JOB_ENV_SCAN__GITHUB_APP_PRIVATE_KEY: 'x' }))).toEqual([
+      'job env file INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY: ok',
+    ]);
+  });
+
   it('boot status lines: ok, or the named error; never the content; boot never throws', () => {
     writeFileSync(join(dir, name), FAKE_PEM);
     expect(bootEnvFileStatusLines(config({ [KEY]: join(dir, name) }))).toEqual(['job env file INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY: ok']);
diff --git a/infra/release-harness/ac13-count.py b/infra/release-harness/ac13-count.py
index 1ca2e2cc58d..785e3c5bf0e 100755
--- a/infra/release-harness/ac13-count.py
+++ b/infra/release-harness/ac13-count.py
@@ -58,10 +58,12 @@ MAX_TIME = 2 ** 53   # epoch ms; larger ints are not times (and would overflow a
 
 def num(v):
     """A usable time: a finite int or float, never a bool. NaN, Infinity and 1e999 (receipt pr1370-v2b F2) are None,
-    and so is an int beyond +-2**53 (receipt pr1370-v2c F1: it never reaches a float conversion, so no traceback)."""
+    and so is an int beyond +-2**53 (receipt pr1370-v2c F1: it never reaches a float conversion, so no traceback), and a
+    finite float beyond +-2**53 (receipt bugtracker-pr1377-gate-v2 F5: 1e100 would otherwise fall outside every window and
+    vanish instead of counting as unknown)."""
     if isinstance(v, bool): return None
     if isinstance(v, int): return v if -MAX_TIME <= v <= MAX_TIME else None
-    return v if isinstance(v, float) and math.isfinite(v) else None
+    return v if isinstance(v, float) and math.isfinite(v) and -MAX_TIME <= v <= MAX_TIME else None
 
 
 def inside(t, since, until):
diff --git a/infra/release-harness/rw-ship.sh b/infra/release-harness/rw-ship.sh
index 996b2b8ea20..586788df103 100755
--- a/infra/release-harness/rw-ship.sh
+++ b/infra/release-harness/rw-ship.sh
@@ -210,7 +210,7 @@ active_id(){ local a i; for i in 1 2 3; do a=$(doctl apps list-deployments $1 --
 # --- deploy target (2026-10-14): selfhost (default) or do. Everything DO-only below sits behind [ "$TARGET" = do ].
 TARGET=${DEPLOY_TARGET:-selfhost}
 case "$TARGET" in do|selfhost) ;; *) say "REFUSED: DEPLOY_TARGET=$TARGET (allowed: selfhost, do); nothing done"; exit 2;; esac
-MIGLOG="ssh build machine: ~/rw/mig-*.log"; MIG_APPLIED=0; SWITCH_AT=""; SH_BEFORE=""
+MIGLOG="ssh build machine: ~/rw/mig-*.log"; MIG_APPLIED=0; SWITCH_AT=""; SH_BEFORE=""; SH_UP_RAN=""; JS_C_OK=""; INTEL_PRE=""
 if [ "$TARGET" = selfhost ]; then
   shconf(){ local v; v=$(sed -n "s/^$1=//p" "$S/biz/release-waves/ship.conf" 2>/dev/null | head -1); printf '%s' "${v:-$2}"; }
   SH_APP=$(shconf SELFHOST_APP ubuntu@<IP>); SH_DIR=$(shconf SELFHOST_DIR /opt/goodqa/infra/selfhost/app)
@@ -232,6 +232,9 @@ print(v if isinstance(v,str) else ("" if v is None else json.dumps(v,sort_keys=T
   mig_hold(){ KEEP=1; say "ROLLBACK REFUSED (exit 8): $1, but this run applied $MIG_APPLIED forward-only migration(s) before the switch, and nothing is rolled back automatically across a migration. Production is left as it is (stack ${NEW_API:-unknown}). A person decides; the previous pins and the restore command are in $RD/rollback.json"
     dbx "$NAME" deploy-unverified "$(live_sha)" "$1; rollback refused: $MIG_APPLIED migration(s) applied by this run (forward-only); previous stack $RB_API, restore command in $RD/rollback.json; run $RD"; exit 8; }
   sh_fail_rollback(){ # sh_fail_rollback <why>: the switch went wrong after this run changed the stack
+    # receipt bugtracker-pr1377-gate-v2 F2: once the switch's `up` ran and until gate (c) passed, a released
+    # intelligence-worker may be running without a verified key: re-hold it FIRST, whatever failed
+    if [ -n "${SH_UP_RAN:-}" ] && [ -z "${JS_C_OK:-}" ] && ! held intelligence-worker; then js_hold_fail "$1"; fi
     [ "${MIG_APPLIED:-0}" = 0 ] || mig_hold "$1"
     say "$1: rolling the self-host stack back to $RB_API"
     if [ -n "$NEW_API" ]; then rb_guard "rolling back ($1)" api || lost "rollback refused ($1)"; else authz "rolling back ($1)" || lost "rollback refused ($1)"; fi
@@ -274,11 +277,39 @@ print(v if isinstance(v,str) else ("" if v is None else json.dumps(v,sort_keys=T
     vmctl up-dispatcher --timeout "$SH_UP_TIMEOUT" > "$RD/up-$1.txt" 2>&1 && grep -q '^UP_OK' "$RD/up-$1.txt"; }
   js_nohold(){ KEEP=1; say "HOLD NOT RE-APPLIED (exit 8): $1. intelligence-worker may be released without a verified key. A person must hold it now: SELFHOST_JOB_HOLD=intelligence-worker,transcribe in ship.conf and re-run, or selfhost-ctl.py pin ... --job-hold JOB_IMAGE_INTELLIGENCE_WORKER then up-dispatcher (run $RD)"
     dbx "$NAME" deploy-unverified "$(live_sha)" "$1; HOLD NOT RE-APPLIED: intelligence-worker released without a verified GITHUB_APP_PRIVATE_KEY file; run $RD"; exit 8; }
+  js_intel(){ # js_intel <state json>: "held", or the JOB_IMAGE_INTELLIGENCE_WORKER value, or nothing when unreadable/ambiguous
+    python3 -c 'import json,sys
+try: s=json.loads(sys.argv[1])
+except Exception: sys.exit()
+j=s.get("jobs") if isinstance(s,dict) else None
+if not isinstance(j,dict) or "error" in j: sys.exit()
+v=j.get("JOB_IMAGE_INTELLIGENCE_WORKER"); h=s.get("jobs_held")
+if not isinstance(v,str) or not v or "\n" in v or not isinstance(h,list): sys.exit()
+print("held" if "JOB_IMAGE_INTELLIGENCE_WORKER" in h else v)' "$1" 2>/dev/null; }
+  js_rehold_failed(){ # js_rehold_failed <why>: the dispatcher-only re-hold failed. After a migration: stop (exit 8). Before any
+    # (lead ruling wa5b72dea2cf): roll back; exit 5 only when the previous release is back (live API at BEFORE) and its
+    # intelligence-worker line is held or byte for byte what it was before this run; anything else is exit 8.
+    [ "${MIG_APPLIED:-0}" = 0 ] || js_nohold "$1"
+    say "$1; no migration was applied, so rolling the self-host stack back to $RB_API"
+    rb_guard "rolling back ($1)" api || lost "rollback refused ($1); intelligence-worker is NOT re-held"
+    infl rollback; local v="" iw="" how="" rbok=1
+    # a re-hold pin that went through (only its up failed) installed files of its own: undo it first, or the run's own
+    # restore is refused as stale (compose changed after this run installed it)
+    if grep -q '^{' "$RD/pin-${STAMP}h.txt" 2>/dev/null; then
+      vmctl restore --stamp "${STAMP}h" > "$RD/restore-${STAMP}h.txt" 2>&1 || { rbok=""; head -3 "$RD/restore-${STAMP}h.txt" | cut -c1-300 | tee -a "$LOG"; }; fi
+    if [ -n "$rbok" ] && sh_rollback; then for i in $(seq 1 18); do v=$(live_sha); [ -n "$BEFORE" ] && [ "$v" = "$BEFORE" ] && break; sleep 10; done; fi
+    iw=$(js_intel "$(sh_state)")
+    if [ "$iw" = held ]; then how=held; elif [ -n "$iw" ] && [ "$iw" = "$INTEL_PRE" ]; then how=same-as-before; fi
+    say "intelligence-worker after the rollback: ${iw:-unreadable} (before this run: ${INTEL_PRE:-unreadable})"
+    if [ -n "$BEFORE" ] && [ "$v" = "$BEFORE" ] && [ -n "$how" ]; then
+      say "ROLLED BACK: live API is $v again; intelligence-worker on the restored release: $how"
+      dbx "$NAME" deploy-failed "$v" "$1; rolled back to the previous stack $RB_API (intelligence-worker $how); run $RD"; exit 5; fi
+    js_nohold "$1; the rollback did not restore a verified previous release (live API ${v:-unreadable}, intelligence-worker ${iw:-unreadable}, before this run ${INTEL_PRE:-unreadable})"; }
   js_hold_fail(){ # js_hold_fail <why>: gate (c) failed after the switch. Re-hold FIRST (dispatcher only), then roll back as usual
     say "$1: re-holding intelligence-worker (job-dispatcher and its guard only) before anything else"
     rb_guard "re-holding intelligence-worker ($1)" api || lost "re-hold refused ($1); intelligence-worker is NOT re-held"
     infl rehold
-    js_rehold "${STAMP}h" || js_nohold "$1, then the dispatcher-only re-hold failed ($(grep -m1 -E '^(UP_|REFUSED|FAILED)' "$RD/up-${STAMP}h.txt" "$RD/pin-${STAMP}h.txt" 2>/dev/null | cut -d: -f2- | cut -c1-200))"
+    js_rehold "${STAMP}h" || js_rehold_failed "$1, then the dispatcher-only re-hold failed ($(grep -m1 -E '^(UP_|REFUSED|FAILED)' "$RD/up-${STAMP}h.txt" "$RD/pin-${STAMP}h.txt" 2>/dev/null | cut -d: -f2- | cut -c1-200))"
     say "intelligence-worker re-held (stack ${NEW_API:-unreadable})"
     [ "${MIG_APPLIED:-0}" = 0 ] || mig_hold "$1 (intelligence-worker was re-held)"
     rb_guard "rolling back ($1)" api || lost "rollback refused ($1); intelligence-worker is re-held"
@@ -771,11 +802,14 @@ PY
     say "job secret (intelligence-worker held, not gated): derive $JSD"; JSGATE="held derive=$JSD"
   else
     say "job secret gate: intelligence-worker is released by this run; derive blob $(js_blob | cut -c1-12)"
+    INTEL_PRE=$(js_intel "$SH_BEFORE")   # the VM state read before anything changed (selfhost-before.json)
+    say "job secret gate: intelligence-worker before this run: ${INTEL_PRE:-unreadable}"
+    [ -n "$INTEL_PRE" ] || js_refuse "the VM state before this run does not name one readable JOB_IMAGE_INTELLIGENCE_WORKER value, so a failed switch could not prove its rollback"
     JSD=$(js_derive); say "job secret gate (a) derive from the bound commit: $JSD"
     case "$JSD" in written|unchanged) ;; *) js_refuse "(a) derive-job-secrets.py did not write or keep the key file ($JSD)";; esac
-    JSK=$(jget "$(vmctl envfile-key 2>/dev/null | grep -m1 '^{')" count)
-    say "job secret gate (b) key lines in dispatcher.env: ${JSK:-unreadable}"
-    [ "$JSK" = 1 ] || js_refuse "(b) dispatcher.env names the key ${JSK:-an unreadable number of} time(s), not once"
+    JSKJ=$(vmctl envfile-key 2>/dev/null | grep -m1 '^{'); JSK=$(jget "$JSKJ" count); JSC=$(jget "$JSKJ" canonical)
+    say "job secret gate (b) key lines in dispatcher.env: ${JSK:-unreadable}${JSK:+ (canonical ${JSC:-unreadable})}"
+    [ "$JSK" = 1 ] && [ "$JSC" = 1 ] || js_refuse "(b) dispatcher.env names the key ${JSK:-an unreadable number of} time(s), ${JSC:-unreadable} of them the canonical line; it must be exactly the one canonical line"
     DREF=goodqa-job-dispatcher@$(python3 -c 'import json,sys
 try: print(json.loads(sys.argv[1]).get(sys.argv[2]) or "")
 except Exception: print("")' "$REMOTEIDS" "$IMG_DISP")
@@ -869,6 +903,7 @@ if [ "$TARGET" = selfhost ]; then
     sh_fail_rollback "the re-pin failed part way (rc=$rc)"; fi
   NEW_API=$(jget "$(grep -m1 '^{' "$RD/pin.txt")" fp); NEW_WEB=$NEW_API; PIN_FP=$NEW_API; infl switch-api
   say "stack pinned: ${NEW_API:-unreadable} (was $RB_API); docker compose up"
+  SH_UP_RAN=1   # from here a released intelligence-worker may be running: every failure re-holds it first (F2)
   vmctl up --timeout "$SH_UP_TIMEOUT" > "$RD/up.txt" 2>&1; rc=$?
   say "up: $(grep -m1 '^UP_' "$RD/up.txt" | cut -c1-400) (rc=$rc)"
   [ $rc -eq 0 ] && grep -q '^UP_OK' "$RD/up.txt" || sh_fail_rollback "the new stack did not come up healthy"
@@ -892,6 +927,7 @@ bad=[k for k in sys.argv[2:] if r.get(k)!=k.split("@",1)[1]]; print("OK" if not
     say "job secret gate (c) dispatcher boot line: ${DST:-unreadable} (container ${DID:0:12}, before the switch ${DISP_PRE:0:12})"
     if [ -z "$DID" ] || [ "$DID" = "$DISP_PRE" ]; then js_hold_fail "the job-dispatcher was not recreated by the switch (gate c)"; fi
     [ "$DST" = ok ] || js_hold_fail "the recreated job-dispatcher did not log the GitHub App key file ok (${DST:-unreadable}, gate c)"
+    JS_C_OK=1
   fi
   v=""; for i in $(seq 1 18); do v=$(live_sha); [ "$v" = "$SHA" ] && break; sleep 10; done
   [ "$v" = "$SHA" ] || sh_fail_rollback "the API reports ${v:-nothing}, not $SHA"
diff --git a/infra/release-harness/selfhost-ctl.py b/infra/release-harness/selfhost-ctl.py
index 56efdefedb7..3143fe55b6e 100644
--- a/infra/release-harness/selfhost-ctl.py
+++ b/infra/release-harness/selfhost-ctl.py
@@ -75,6 +75,8 @@ Commands (exit 0 ok; 2 usage; 3 refused, NOTHING was changed; 4 failed part way,
 Tests: bin/test_rw_ship_selfhost.py (fake docker; this file runs for real there).
 """
 import argparse, hashlib, json, os, re, shutil, subprocess, sys, time
+try: import tomllib                     # python >= 3.11: the containerd config is read as TOML, exactly
+except ImportError: tomllib = None      # older python: the strict reader below accepts only forms it cannot misread
 
 SERVICES = ('api', 'web', 'job-dispatcher', 'job-dispatcher-create-guard')
 HEALTHY = ('api', 'web')                      # services with a healthcheck in compose.yaml
@@ -223,26 +225,69 @@ def containerd_root_of(args):
             if 'config' in opts: raise Refused('containerd --config %s does not exist' % cfg)
             text = ''
         except (OSError, UnicodeDecodeError) as e: raise Refused('cannot read the containerd config %s: %s' % (cfg, type(e).__name__))
-        top = []
-        for line in text.split('\n'):
-            if re.match(r'^\s*\[', line): break
-            top.append(line)
-        body = '\n'.join(top)
-        im = re.search(r'^\s*imports\s*=\s*\[([^\]]*)\]', body, re.M)
-        if (im and re.sub(r'(#[^\n]*)|[\s,]', '', im.group(1))) or (not im and re.search(r'^\s*imports\s*=', body, re.M)):
-            raise Refused('the containerd config %s uses imports, which can override its root' % cfg)
-        hits = [l for l in top if re.match(r'^\s*root\s*=', l)]
-        if len(hits) > 1: raise Refused('the containerd config %s sets root %d times' % (cfg, len(hits)))
-        if not hits: root = CTD_DEFAULT_ROOT
-        else:
-            m = re.match(r'^\s*root\s*=\s*(["\x27])([^"\x27\\\n]*)\1\s*(#.*)?$', hits[0])
-            if not m or not m.group(2).startswith('/'): raise Refused('the containerd config %s has an unreadable root' % cfg)
-            root = m.group(2)
+        root = ctd_config_root(text, cfg)
     real = os.path.realpath(root)
     if not os.path.isdir(real): raise Refused('the containerd root %s does not exist' % root)
     return real
 
 
+# The strict reader (no tomllib). Above the first table header every line is a comment, a blank, or ONE bare key set to a
+# basic string without escapes, a literal string, a decimal integer, true/false, or a one-line array of such strings.
+# Anything else (quoted or dotted keys, inline tables, escapes, multi-line strings or arrays, other numbers) refuses.
+_TS = r"""(?:"[^"\\\n]*"|'[^'\n]*')"""
+CTD_TOP_LINE = re.compile(r'^[ \t]*(?P<k>[A-Za-z0-9_-]+)[ \t]*=[ \t]*(?P<v>%s|[+-]?[0-9]+|true|false|\[[ \t]*(?:%s[ \t]*,[ \t]*)*(?:%s[ \t]*,?[ \t]*)?\])[ \t]*(?:#[^\n]*)?$' % (_TS, _TS, _TS))
+
+
+def ctd_top_strict(text, cfg):
+    """{top-level key: [raw value, ...]} read by the strict grammar above, or Refused."""
+    top = []
+    for n, line in enumerate(text.split('\n'), 1):
+        line = line.rstrip('\r')
+        if re.match(r'^[ \t]*\[', line): break
+        top.append((n, line))
+    region = '\n'.join(l for _, l in top)
+    if '"""' in region or "\x27\x27\x27" in region:
+        raise Refused('the containerd config %s has a multi-line string above its first table, which %s' % (cfg, CTD_NOSAFE))
+    keys = {}
+    for n, line in top:
+        s = line.strip()
+        if not s or s.startswith('#'): continue
+        m = CTD_TOP_LINE.match(line)
+        if not m: raise Refused('the containerd config %s line %d %s' % (cfg, n, CTD_NOSAFE))
+        keys.setdefault(m.group('k'), []).append(m.group('v'))
+    return keys
+
+
+CTD_NOSAFE = 'cannot be read safely without tomllib (python < 3.11)'
+
+
+def ctd_config_root(text, cfg):
+    """containerd's top-level root from the text of its config file (CTD_DEFAULT_ROOT when it sets none), or Refused.
+    tomllib when it imports, else the strict reader; both refuse a non-empty imports, a root or imports key spelled in
+    another case (containerd's decoder may match it), and a root that is not an absolute path string."""
+    if tomllib is not None:
+        try: doc = tomllib.loads(text)
+        except tomllib.TOMLDecodeError as e: raise Refused('the containerd config %s is not valid TOML (%s)' % (cfg, str(e)[:120]))
+        keys = list(doc)
+        root, imports = doc.get('root'), doc.get('imports', [])
+    else:
+        top = ctd_top_strict(text, cfg)
+        keys = list(top)
+        for k in ('root', 'imports'):
+            if len(top.get(k, [])) > 1: raise Refused('the containerd config %s sets %s %d times' % (cfg, k, len(top[k])))
+        raw_root, raw_imports = (top.get('root') or [None])[0], (top.get('imports') or ['[]'])[0]
+        root = raw_root[1:-1] if raw_root and raw_root[0] in '"\x27' else (0 if raw_root is not None else None)
+        imports = [] if re.fullmatch(r'\[[ \t]*\]', raw_imports) else ['?']
+    for k in keys:
+        if k.lower() in ('root', 'imports') and k != k.lower():
+            raise Refused('the containerd config %s spells %s as %r' % (cfg, k.lower(), k))
+    if not isinstance(imports, list) or imports:
+        raise Refused('the containerd config %s uses imports, which can override its root' % cfg)
+    if root is None: return CTD_DEFAULT_ROOT
+    if not isinstance(root, str) or not root.startswith('/'): raise Refused('the containerd config %s has an unreadable root' % cfg)
+    return root
+
+
 def docker(*a, check=False, timeout=None, cwd=None):
     r = subprocess.run(['docker', *a], capture_output=True, text=True, timeout=timeout, cwd=cwd)
     if check and r.returncode != 0:
@@ -805,7 +850,8 @@ DISP_ERR_PREFIX = 'job env file for INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY:
 DISP_ERR_WORDS = {'missing': 'missing-file', 'is a symlink': 'symlink', 'unreadable': 'unreadable',
                   'not a regular file': 'not-regular', 'over 64 KiB': 'too-large', 'empty': 'empty',
                   'value holds CR, LF or NUL': 'bad-bytes', 'value is not valid UTF-8': 'bad-utf8',
-                  'path outside the secrets directory': 'outside-dir', 'cannot read (error)': 'read-error'}
+                  'path outside the secrets directory': 'outside-dir', 'cannot read (error)': 'read-error',
+                  'both JOB_ENV_ and JOB_ENVFILE_ are set': 'conflict'}
 DISP_LOG_TAIL = 2000
 TRIAL_IMAGE_RE = re.compile(r'^goodqa-job-dispatcher@sha256:[0-9a-f]{64}$')
 TRIAL_STAMP_RE = re.compile(r'^[A-Za-z0-9._-]{1,80}$')
@@ -818,11 +864,16 @@ TRIAL_FLAGS = ('--rm', '--network', 'none', '--read-only', '--tmpfs', '/tmp', '-
 
 
 def cmd_envfile_key(stk, a):
+    """Gate (b): `count` is every non-comment line of dispatcher.env that names the key at all (any assignment syntax, a
+    JOB_ENV_ twin included), `canonical` the lines that are byte for byte the canonical line. rw-ship passes only 1 and 1
+    (receipt bugtracker-pr1377-gate-v2 F4: a second, different assignment changes the effective value)."""
     path = os.path.join(stk.env_dir, 'dispatcher.env')
     fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
     with os.fdopen(fd, 'rb') as f:
-        n = sum(1 for l in f.read().split(b'\n') if l.rstrip(b'\r') == JOBSECRET_KEY_LINE.encode())
-    out({'count': n}); return 0
+        lines = [l.rstrip(b'\r') for l in f.read().split(b'\n')]
+    name = JOBSECRET_KEY_LINE.split('=', 1)[0][len('JOB_ENVFILE_'):].encode()
+    named = [l for l in lines if name in l and not l.lstrip().startswith(b'#')]
+    out({'count': len(named), 'canonical': sum(1 for l in named if l == JOBSECRET_KEY_LINE.encode())}); return 0
 
 
 def disp_status(log_text):
diff --git a/infra/release-harness/test_ac13_count.py b/infra/release-harness/test_ac13_count.py
index 635dac0855f..fa163928839 100644
--- a/infra/release-harness/test_ac13_count.py
+++ b/infra/release-harness/test_ac13_count.py
@@ -261,3 +261,33 @@ def test_huge_integer_time_is_an_untimed_unknown_with_a_json_verdict(tmp_path):
         rc, o = run(_raw(tmp_path, lines), '--mode', 'post', *since, *REQ)
         assert isinstance(o, dict), (name, 'no JSON verdict: ' + str(o)[-300:])
         assert rc == 1 and o['verdict'] == 'INCONCLUSIVE' and o['unknown'] == {why: 1}, (name, o)
+
+
+# ---- receipt bugtracker-pr1377-gate-v2 F5 (Medium): a FINITE float beyond +-2**53 is not a time either
+OUT_OF_RANGE = ('1e100', '-1e100', '9007199254740994.0', '-9007199254740994.0', '1.7976931348623157e308')
+
+
+def test_out_of_range_float_time_is_an_untimed_unknown(tmp_path):
+    ok = [_start('req-a', t=1000), _done('req-a', 200, t=1001)]
+    win = ('--mode', 'post', '--since', '0', '--until', '2000', '--require-2xx', 'scan')
+    for raw in OUT_OF_RANGE:
+        # the receipt's reproducer: one valid 2xx scan launch, and a scan completion with status 500 at an out-of-range time
+        rc, o = run(_raw(tmp_path, ok + [_line('req-o', 'request completed', raw)], base=[]), *win)
+        assert isinstance(o, dict) and o['verdict'] != 'PASS' and rc != 0, (raw, o)
+        assert rc == 1 and o['verdict'] == 'INCONCLUSIVE' and o['unknown'] == {'orphan completion': 1}, (raw, o)
+        # paired with its own launch: the completion time is unusable, never the start time
+        rc, o = run(_raw(tmp_path, ok + [_start('req-x', t=1500), _line('req-x', 'request completed', raw)], base=[]), *win)
+        assert rc == 1 and o['unknown'] == {'invalid status or time': 1}, (raw, o)
+        # a launch that never completes, started at that time
+        rc, o = run(_raw(tmp_path, ok + [_line('req-u', 'incoming request', raw)], base=[]), *win)
+        assert rc == 1 and o['unknown'] == {'no completion': 1}, (raw, o)
+
+
+def test_in_range_float_times_are_still_times(tmp_path):
+    win = ('--mode', 'post', '--since', '0', '--until', '2000', '--require-2xx', 'scan')
+    for raw in ('1001.5', '9007199254740992.0'):
+        t_in = raw == '1001.5'
+        lines = [_start('req-a', t=1000), _line('req-a', 'request completed', raw, st=200)]
+        rc, o = run(_raw(tmp_path, lines, base=[]), *win)
+        if t_in: assert rc == 0 and o['verdict'] == 'PASS', (raw, o)
+        else: assert o['unknown'] == {} and o['verdict'] != 'PASS', (raw, o)   # a usable time, outside the window
diff --git a/infra/release-harness/test_rw_ship_jobsecret_gate.py b/infra/release-harness/test_rw_ship_jobsecret_gate.py
index daa61a33357..d6d1c325706 100644
--- a/infra/release-harness/test_rw_ship_jobsecret_gate.py
+++ b/infra/release-harness/test_rw_ship_jobsecret_gate.py
@@ -138,7 +138,15 @@ def test_derive_source_must_be_the_bound_blob(R, how, word):
 
 
 # ---------------------------------------------------------------- (b) and the trial boot
-@pytest.mark.parametrize('body,word', [('', '0'), ('{k}\n{k}\n', '2'), ('{k} \n', '0'), ('#{k}\n', '0'), ('symlink', 'unreadable')])
+@pytest.mark.parametrize('body,word', [
+    ('', '0 (canonical 0)'), ('{k}\n{k}\n', '2 (canonical 2)'), ('{k} \n', '1 (canonical 0)'), ('#{k}\n', '0 (canonical 0)'),
+    ('symlink', 'unreadable'),
+    # receipt bugtracker-pr1377-gate-v2 F4: a second assignment to the key, even a different one, refuses
+    ('{k}\nJOB_ENVFILE_INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY=/run/goodqa-secrets/other-key\n', '2 (canonical 1)'),
+    ('JOB_ENVFILE_INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY=/run/goodqa-secrets/other-key\n', '1 (canonical 0)'),
+    # F3 at gate (b): a JOB_ENV_ value for the same key refuses before any migration
+    ('{k}\nJOB_ENV_INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY=inline\n', '2 (canonical 1)'),
+])
 def test_key_line_must_be_there_exactly_once(R, body, word):
     before = R.get('live'); p = os.path.join(R.envd, 'dispatcher.env')
     if body == 'symlink':
@@ -157,7 +165,8 @@ def test_trial_boot_failure_refuses_and_cleans_up(R):
 
 
 # ---------------------------------------------------------------- (c) after the switch: re-hold first, then roll back
-@pytest.mark.parametrize('line,word', [('', 'missing'), ('job env file for INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY: is a symlink', 'error:symlink')])
+@pytest.mark.parametrize('line,word', [('', 'missing'), ('job env file for INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY: is a symlink', 'error:symlink'),
+    ('job env file for INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY: both JOB_ENV_ and JOB_ENVFILE_ are set', 'error:conflict')])
 def test_gate_c_failure_reholds_then_rolls_back(R, line, word):
     before = R.get('live'); R.put('disp-boot-line', line); sha = R.release('release/js-8'); rc, out = R.run('release/js-8', sha)
     assert rc == 5, out
@@ -184,8 +193,9 @@ def test_gate_c_failure_after_a_migration_holds_and_stops(R):
     assert R.state_of('release/js-10')[0] == 'deploy-unverified' and os.path.exists(R.infl)
 
 
-def test_rehold_failure_is_exit_8_and_touches_nothing_else(R):
-    R.put('disp-boot-line', ''); R.put('up-fail-disp-only', ''); sha = R.release('release/js-11'); rc, out = R.run('release/js-11', sha)
+def test_rehold_failure_after_a_migration_is_exit_8_and_touches_nothing_else(R):
+    R.put('mig-pending', '1'); R.put('disp-boot-line', ''); R.put('up-fail-disp-only', '')
+    sha = R.release('release/js-11'); rc, out = R.run('release/js-11', sha)
     assert rc == 8 and 'HOLD NOT RE-APPLIED' in out and 'JOB_IMAGE_INTELLIGENCE_WORKER' in out, out
     assert ups(R) == [FULL] and 'UPSVCS-FAILED ' + DISP_ONLY in R.dlog(), 'only the dispatcher pair was tried'
     assert 'ROLLED BACK' not in out and R.state_of('release/js-11')[0] == 'deploy-unverified' and os.path.exists(R.infl)
@@ -197,3 +207,102 @@ def test_rollback_restore_failure_reholds_again(R):
     stamp = os.path.basename(rd(R))
     assert ups(R) == [FULL, DISP_ONLY, DISP_ONLY] and os.path.exists(os.path.join(rd(R), 'pin-%sh2.txt' % stamp))
     assert R.jobs()[INTEL] == HELD and R.state_of('release/js-12')[0] == 'deploy-unverified'
+
+
+# ---------------------------------------------------------------- receipt bugtracker-pr1377-gate-v2 F2 (High)
+# Once the switch's `up` has run, and until gate (c) passes, EVERY failure re-holds intelligence-worker first (dispatcher
+# only), then: after a migration, the forward-only stop (exit 8); before any, the rollback (exit 5). When the re-hold itself
+# fails: after a migration, exit 8 HOLD NOT RE-APPLIED; before any, roll back and exit 5 only when the restored release is
+# the previous one AND its JOB_IMAGE_INTELLIGENCE_WORKER is held or byte-for-byte what it was before this run (lead ruling
+# wa5b72dea2cf); otherwise exit 8.
+def _pre_c_failure(R, how, sha):
+    if how == 'unhealthy': R.put('unhealthy-ref', sha[:12]); return 'the new stack did not come up healthy'
+    if how == 'guard':
+        R.put('guard-log-missing', ''); return 'the running guard does not report the transcription hold'
+    raise AssertionError(how)
+
+
+def _setup(R, how):
+    if how == 'guard': sh._guard_source(R, True); sh._conf(R, 'SELFHOST_JOB_HOLD', 'transcribe')
+
+
+def _hold_base(R):
+    p = os.path.join(R.vm, 'compose.yaml'); t = open(p).read()
+    t2 = re.sub(r'^(      JOB_IMAGE_INTELLIGENCE_WORKER:).*$', r'\1 "" # held', t, flags=re.M)
+    assert t2 != t; open(p, 'w').write(t2)
+
+
+@pytest.mark.parametrize('how', ['unhealthy', 'guard'])
+def test_pre_gate_c_failure_after_a_migration_reholds_before_the_forward_only_stop(R, how):
+    """The receipt's case: intelligence-worker released, one migration applied, the new stack fails readiness."""
+    _setup(R, how); R.put('mig-pending', '1'); sha = R.release('release/js-20'); why = _pre_c_failure(R, how, sha)
+    rc, out = R.run('release/js-20', sha)
+    assert rc == 8 and why in out and 'ROLLBACK REFUSED' in out and 'intelligence-worker was re-held' in out, out
+    assert out.index('intelligence-worker re-held') < out.index('ROLLBACK REFUSED'), out
+    assert ups(R) == [FULL, DISP_ONLY], 'the dispatcher-only re-hold, and no rollback across the migration'
+    assert R.jobs()[INTEL] == HELD
+    assert 'gate (c)' not in out and R.state_of('release/js-20')[0] == 'deploy-unverified' and os.path.exists(R.infl)
+
+
+@pytest.mark.parametrize('how', ['unhealthy', 'guard'])
+def test_pre_gate_c_failure_without_a_migration_reholds_then_rolls_back(R, how):
+    _setup(R, how); before = R.get('live'); sha = R.release('release/js-21'); why = _pre_c_failure(R, how, sha)
+    rc, out = R.run('release/js-21', sha)
+    assert rc == 5 and why in out and 'ROLLED BACK' in out, out
+    assert out.index('intelligence-worker re-held') < out.index('ROLLED BACK'), out
+    assert ups(R) == [FULL, DISP_ONLY, FULL], 're-hold (dispatcher only) BEFORE the rollback up'
+    assert R.pins() == BASE_PINS and R.jobs() == BASE_JOBS and R.get('live') == before
+
+
+@pytest.mark.parametrize('base', ['held', 'released'])
+def test_pre_gate_c_rehold_failure_without_a_migration_rolls_back_to_the_verified_previous_release(R, base):
+    if base == 'held': _hold_base(R)
+    pre = R.jobs()[INTEL]; before = R.get('live'); R.put('up-fail-disp-only', '')
+    sha = R.release('release/js-22'); _pre_c_failure(R, 'unhealthy', sha); rc, out = R.run('release/js-22', sha)
+    assert rc == 5 and 'the dispatcher-only re-hold failed' in out and 'ROLLED BACK' in out, out
+    word = 'held' if base == 'held' else 'same-as-before'
+    assert ('intelligence-worker on the restored release: ' + word) in out, out
+    assert ('intelligence-worker before this run: ' + ('held' if base == 'held' else pre)) in out, out
+    assert ups(R) == [FULL, FULL] and 'UPSVCS-FAILED ' + DISP_ONLY in R.dlog()
+    assert R.jobs()[INTEL] == pre and R.get('live') == before and 'HOLD NOT RE-APPLIED' not in out
+
+
+def test_pre_gate_c_rehold_failure_when_the_restore_is_not_the_previous_value_is_exit_8(R):
+    """The rollback "succeeds" but the restored intelligence-worker line is neither held nor what it was: exit 8."""
+    R.put('up-fail-disp-only', ''); sha = R.release('release/js-23'); _pre_c_failure(R, 'unhealthy', sha)
+    # a backup that restores a DIFFERENT intelligence-worker value (as if someone re-pinned it during the run)
+    R.put('restore-intel-drift', 'goodqa-intelligence-worker@sha256:' + 'e' * 64)
+    rc, out = R.run('release/js-23', sha)
+    assert rc == 8 and 'HOLD NOT RE-APPLIED' in out and 'ROLLED BACK' not in out, out
+    assert R.state_of('release/js-23')[0] == 'deploy-unverified' and os.path.exists(R.infl)
+
+
+def test_pre_gate_c_rehold_failure_after_a_migration_stops_without_a_rollback(R):
+    R.put('mig-pending', '1'); R.put('up-fail-disp-only', ''); sha = R.release('release/js-24'); _pre_c_failure(R, 'unhealthy', sha)
+    rc, out = R.run('release/js-24', sha)
+    assert rc == 8 and 'HOLD NOT RE-APPLIED' in out and 'ROLLED BACK' not in out and 'ROLLBACK REFUSED' not in out, out
+    assert ups(R) == [FULL], 'no rollback across a migration'
+
+
+def test_gate_c_rehold_failure_without_a_migration_rolls_back_to_the_previous_release(R):
+    before = R.get('live'); R.put('disp-boot-line', ''); R.put('up-fail-disp-only', '')
+    sha = R.release('release/js-25'); rc, out = R.run('release/js-25', sha)
+    assert rc == 5 and 'ROLLED BACK' in out and 'intelligence-worker on the restored release: same-as-before' in out, out
+    assert ups(R) == [FULL, FULL] and R.pins() == BASE_PINS and R.jobs() == BASE_JOBS and R.get('live') == before
+
+
+def test_job_ref_unresolved_before_gate_c_ends_on_the_previous_release(R):
+    """Line 882: the re-hold pin names the same job refs, so it can refuse; the rollback still restores the previous release."""
+    before = R.get('live'); sha = R.release('release/js-26'); R.put('untag-after-up', 'goodqa-scan: ' + sha)
+    rc, out = R.run('release/js-26', sha)
+    assert rc == 5 and 'job image refs' in out and 'ROLLED BACK' in out, out
+    assert 're-holding intelligence-worker' in out, 'the re-hold is attempted first'
+    assert R.pins() == BASE_PINS and R.jobs() == BASE_JOBS and R.get('live') == before
+
+
+def test_unreadable_pre_run_intelligence_worker_refuses_before_anything(R):
+    """Lead ruling wa5b72dea2cf: the pre-run value is read at the start; unreadable or ambiguous refuses up front."""
+    before = R.get('live'); R.put('state-jobs-error', '')
+    sha = R.release('release/js-27'); rc, out = R.run('release/js-27', sha)
+    assert rc == 2 and 'intelligence-worker before this run: unreadable' in out, out
+    refused_before_anything(R, before, out)
diff --git a/infra/release-harness/test_rw_ship_selfhost.py b/infra/release-harness/test_rw_ship_selfhost.py
index c3268faf678..08aafc49697 100644
--- a/infra/release-harness/test_rw_ship_selfhost.py
+++ b/infra/release-harness/test_rw_ship_selfhost.py
@@ -53,6 +53,16 @@ fi
 if [ -e "$FAKE_STATE/restore-fail" ] && [[ "$*" =~ \ restore\ --stamp\ [0-9]{8}T[0-9]{6}Z$ ]]; then   # goodqa#16148: the run's own restore fails
   cat >/dev/null; echo "REFUSED fake restore failure"; exit 3
 fi
+if [ -e "$FAKE_STATE/state-jobs-error" ] && [[ "$*" =~ \ state$ ]]; then   # 1377 v3: no readable intelligence-worker value
+  FAKE_SIDE=remote bash -c "$*" | python3 -c 'import json, sys
+for l in sys.stdin:
+    if l.startswith("{"): j = json.loads(l); j["jobs"] = {"error": "fake: unreadable job lines"}; l = json.dumps(j) + "\n"
+    sys.stdout.write(l)'; exit "${PIPESTATUS[0]}"
+fi
+if [ -e "$FAKE_STATE/restore-intel-drift" ] && [[ "$*" =~ \ restore\ --stamp\ [0-9]{8}T[0-9]{6}Z$ ]]; then   # 1377 v3: the restore lands a different value
+  FAKE_SIDE=remote bash -c "$*"; rc=$?; d=$(printf '%s' "$*" | sed -E 's/.*--dir ([^ ]+).*/\1/'); v=$(cat "$FAKE_STATE/restore-intel-drift")
+  sed -i -E "s|^(      JOB_IMAGE_INTELLIGENCE_WORKER:).*$|\1 $v|" "$d/compose.yaml"; exit $rc
+fi
 FAKE_SIDE=remote exec bash -c "$*"
 '''
 SUDO = r"""#!/bin/sh
@@ -780,6 +790,14 @@ def test_no_automatic_rollback_after_a_migration(R, how):
     assert rc2 == 9 and 'unknown' in out2, out2
 
 
+def test_no_automatic_rollback_after_a_migration_with_intelligence_worker_held(R):
+    """The plain forward-only path (no re-hold: intelligence-worker is held by this release)."""
+    _conf(R, 'SELFHOST_JOB_HOLD', 'intelligence-worker'); R.put('mig-pending', '1'); sha = R.release('release/wave-68h')
+    R.put('unhealthy-ref', sha[:12]); rc, out = R.run('release/wave-68h', sha)
+    assert rc == 8 and 'ROLLBACK REFUSED' in out and 'forward-only' in out and 're-holding' not in out, out
+    assert R.pins()['api'].startswith('goodqa-api:' + sha[:12]) and R.state_of('release/wave-68h')[0] == 'deploy-unverified'
+
+
 # ---------------------------------------------------------------- refusals before the switch
 def test_image_id_mismatch_after_transfer_refuses(R):
     before = R.get('live'); R.put('load-corrupt', ''); sha = R.release('release/wave-69')
@@ -905,6 +923,8 @@ def test_negative_controls_are_caught(tmp_path, name, monkeypatch):
     try:
         R.put('mig-pending', '1'); sha = R.release('release/wave-80')
         if name == 'no-migration-hold':
+            # intelligence-worker held: the plain post-switch path (an unheld one re-holds first, receipt 1377-v2 F2)
+            _conf(R, 'SELFHOST_JOB_HOLD', 'intelligence-worker')
             R.put('unhealthy-ref', sha[:12]); rc, out = R.run('release/wave-80', sha)
             assert rc != 8 and R.pins() == BASE_PINS, 'the mutant rolled back across a migration: the real test asserts exit 8 + pins kept'
         elif name == 'no-schema-freeze':
@@ -1882,17 +1902,156 @@ def test_f1_section_only_root_means_the_default_root(F1):
     assert F1.measured() == F1.root('default-root')
 
 
+# receipt bugtracker-pr1377-gate-v2 F1: every config case runs under tomllib AND under the strict reader used when tomllib
+# does not import (python < 3.11; the VM's python is not known here), forced by setting the module's tomllib to None.
+PARSERS = ['tomllib', 'fallback']
+NOSAFE = 'cannot be read safely without tomllib'
+
+
+def _parser(F1, monkeypatch, parser):
+    if parser == 'fallback': monkeypatch.setattr(F1.M, 'tomllib', None, raising=False)
+    else: assert getattr(F1.M, 'tomllib', None) is not None, 'selfhost-ctl.py must use tomllib when it imports'
+
+
+def _cfg(F1, body, sock='ctd.sock', name='ctd.toml'):
+    cfg = F1.st / name; cfg.write_text(body % {'r': F1.st / 'containerd-root'})
+    F1.ctd(sock, ['--config', str(cfg)]); F1.put('ctd-address', F1.sock(sock))
+
+
+@pytest.mark.parametrize('parser', PARSERS)
 @pytest.mark.parametrize('body,why', [
-    ("imports = ['/etc/containerd/conf.d/*.toml']\nroot = '%(r)s'\n", 'uses imports'),
-    ("imports = [\n  '/x.toml',\n]\nroot = '%(r)s'\n", 'uses imports'),
-    ("root = '%(r)s'\nroot = '/other'\n", 'sets root 2 times'),
-    ("root = 'relative/root'\n", 'has an unreadable root'),
-    ("root = '%(r)s/missing'\n", 'does not exist'),
+    ("imports = ['/etc/containerd/conf.d/*.toml']\nroot = '%(r)s'\n", {'tomllib': 'uses imports', 'fallback': 'uses imports'}),
+    ("imports = [\n  '/x.toml',\n]\nroot = '%(r)s'\n", {'tomllib': 'uses imports', 'fallback': NOSAFE}),
+    ("root = '%(r)s'\nroot = '/other'\n", {'tomllib': 'is not valid TOML', 'fallback': 'sets root 2 times'}),
+    ("root = 'relative/root'\n", {'tomllib': 'has an unreadable root', 'fallback': 'has an unreadable root'}),
+    ("root = '%(r)s/missing'\n", {'tomllib': 'does not exist', 'fallback': 'does not exist'}),
+    # quoted imports keys
+    ('"imports" = ["/x.toml"]\nroot = \'%(r)s\'\n', {'tomllib': 'uses imports', 'fallback': NOSAFE}),
+    ("'imports' = ['/x.toml']\nroot = '%(r)s'\n", {'tomllib': 'uses imports', 'fallback': NOSAFE}),
+    # case variants containerd's Go decoder may match: refused on both paths
+    ("Root = '%(r)s'\n", {'tomllib': 'spells root as', 'fallback': 'spells root as'}),
+    ("IMPORTS = ['/x.toml']\n", {'tomllib': 'spells imports as', 'fallback': 'spells imports as'}),
+    ('"ROOT" = "%(r)s"\n', {'tomllib': 'spells root as', 'fallback': NOSAFE}),
+    # forms the strict reader never guesses at; tomllib reads them exactly (None: the measured root is the real root)
+    ("root.x = 1\nroot = '%(r)s'\n", {'tomllib': 'is not valid TOML', 'fallback': NOSAFE}),
+    ("x = {root = '/elsewhere'}\nroot = '%(r)s'\n", {'tomllib': None, 'fallback': NOSAFE}),
+    ("y = 'a'\nx.root = '/elsewhere'\nroot = '%(r)s'\n", {'tomllib': None, 'fallback': NOSAFE}),
+    ('root = """%(r)s"""\n', {'tomllib': None, 'fallback': 'multi-line string'}),
+    ("root = \'\'\'\n%(r)s\'\'\'\n", {'tomllib': None, 'fallback': 'multi-line string'}),
+    ('root = "%(r)s\\u0074"\n', {'tomllib': 'does not exist', 'fallback': NOSAFE}),
+    ('root = 5\n', {'tomllib': 'has an unreadable root', 'fallback': 'has an unreadable root'}),
+    ("version = 0x2\nroot = '%(r)s'\n", {'tomllib': None, 'fallback': NOSAFE}),
+    ('root = "%(r)s" # say """ in a comment\n', {'tomllib': None, 'fallback': 'multi-line string'}),
+    ('imports = []\nimports = []\n', {'tomllib': 'is not valid TOML', 'fallback': 'sets imports 2 times'}),
+    ('root = [\n', {'tomllib': 'is not valid TOML', 'fallback': NOSAFE}),
+])
+def test_f1_containerd_config_refusals(F1, monkeypatch, parser, body, why):
+    _parser(F1, monkeypatch, parser); _cfg(F1, body)
+    if why[parser] is None: assert F1.measured() == F1.root(), body
+    else: _refused(F1, why[parser])
+
+
+@pytest.mark.parametrize('parser', PARSERS)
+@pytest.mark.parametrize('body', ['"root" = "%(r)s"\n', "'root' = '%(r)s'\n"])
+def test_f1_quoted_root_key_is_never_the_default_root(F1, monkeypatch, parser, body):
+    """The receipt's reproducer: a valid quoted root key. tomllib reads the real root; the strict reader refuses."""
+    _parser(F1, monkeypatch, parser); _cfg(F1, body)
+    if parser == 'tomllib': assert F1.measured() == F1.root()
+    else: _refused(F1, NOSAFE)
+
+
+# `containerd config default` (v1.7, version 2): its top-level region and the start of its tables; and the config Docker's
+# containerd.io package installs. Real-world configs both parsers must accept with the right root.
+CTD_V2_DEFAULT = """disabled_plugins = []
+imports = []
+oom_score = 0
+plugin_dir = ""
+required_plugins = []
+root = "%(r)s"
+state = "/run/containerd"
+temp = ""
+version = 2
+
+[cgroup]
+  path = ""
+
+[debug]
+  address = ""
+  format = ""
+  gid = 0
+  level = ""
+  uid = 0
+
+[grpc]
+  address = "/run/containerd/containerd.sock"
+  gid = 0
+  max_recv_message_size = 16777216
+  max_send_message_size = 16777216
+  tcp_address = ""
+  uid = 0
+
+[plugins]
+
+  [plugins."io.containerd.gc.v1.scheduler"]
+    deletion_threshold = 0
+    mutation_threshold = 100
+    pause_threshold = 0.02
+    schedule_delay = "0s"
+    startup_delay = "100ms"
+
+  [plugins."io.containerd.grpc.v1.cri"]
+    device_ownership_from_security_context = false
+    sandbox_image = "registry.k8s.io/pause:3.8"
+    root = "/var/lib/containerd/io.containerd.grpc.v1.cri"
+
+  [plugins."io.containerd.snapshotter.v1.overlayfs"]
+    mount_options = []
+    root_path = ""
+    sync_remove = false
+"""
+CTD_DOCKER_PACKAGE = """#   Copyright 2018-2022 Docker Inc.
+
+#   Licensed under the Apache License, Version 2.0 (the "License");
+#   you may not use this file except in compliance with the License.
+
+disabled_plugins = ["cri"]
+
+#root = "/var/lib/containerd"
+#state = "/run/containerd"
+#subreaper = true
+#oom_score = 0
+
+#[grpc]
+#  address = "/run/containerd/containerd.sock"
+#  uid = 0
+#  gid = 0
+
+#[debug]
+#  address = "/run/containerd/debug.sock"
+#  uid = 0
+#  gid = 0
+#  level = "info"
+"""
+
+
+@pytest.mark.parametrize('parser', PARSERS)
+def test_f1_real_world_containerd_configs_are_accepted_with_the_right_root(F1, monkeypatch, parser):
+    _parser(F1, monkeypatch, parser)
+    _cfg(F1, CTD_V2_DEFAULT); assert F1.measured() == F1.root()
+    _cfg(F1, CTD_DOCKER_PACKAGE, sock='ctd2.sock', name='ctd2.toml')
+    assert F1.measured() == F1.root('default-root'), 'every root line is commented out: the default root'
+
+
+@pytest.mark.parametrize('body', [
+    CTD_V2_DEFAULT, CTD_DOCKER_PACKAGE, "version = 2\nroot = '%(r)s'   # the daemon root\nimports = []\n[plugins.x]\n  root = '/elsewhere'\n",
+    "version = 2\n[plugins.x]\n  root = '%(r)s'\n", "  root = '%(r)s'\n\n# c\n", 'enabled = true\nroot="%(r)s"#c\n',
+    "disabled_plugins = ['a', \"b\",]\nroot = '%(r)s'\n", "oom_score = -999\nroot = '%(r)s'\r\n",
 ])
-def test_f1_containerd_config_refusals(F1, body, why):
-    cfg = F1.st / 'ctd.toml'; cfg.write_text(body % {'r': F1.st / 'containerd-root'})
-    F1.ctd('ctd.sock', ['--config', str(cfg)]); F1.put('ctd-address', F1.sock('ctd.sock'))
-    _refused(F1, why)
+def test_f1_strict_reader_agrees_with_tomllib_whenever_it_accepts(F1, monkeypatch, body):
+    """Parity: a config the strict reader accepts measures the same root as tomllib."""
+    _cfg(F1, body); want = F1.measured()
+    monkeypatch.setattr(F1.M, 'tomllib', None, raising=False)
+    assert F1.measured() == want, body
 
 
 def test_f1_named_config_missing_refuses(F1):
diff --git a/infra/release-harness/test_selfhost_ctl_gate.py b/infra/release-harness/test_selfhost_ctl_gate.py
index 2f0ce80bb4d..c1acb67a16f 100644
--- a/infra/release-harness/test_selfhost_ctl_gate.py
+++ b/infra/release-harness/test_selfhost_ctl_gate.py
@@ -85,10 +85,35 @@ def test_envfile_key_counts_only_the_exact_line(fake):
     (fake / 'etc/dispatcher.env').write_text('\n'.join([
         'JOB_DISPATCH_TOKEN=' + PLANT, KEYLINE, '# ' + KEYLINE, KEYLINE + ' ', KEYLINE.replace('goodqa-secrets', 'x'), '']))
     rc, out, err = cli(fake, 'envfile-key')
-    assert (rc, json.loads(out)) == (0, {'count': 1})
+    # receipt bugtracker-pr1377-gate-v2 F4: the padded and the other-path assignments are assignments too
+    assert (rc, json.loads(out)) == (0, {'count': 3, 'canonical': 1})
     assert PLANT not in out + err
     (fake / 'etc/dispatcher.env').write_text('A=1\n')
-    assert json.loads(cli(fake, 'envfile-key')[1]) == {'count': 0}
+    assert json.loads(cli(fake, 'envfile-key')[1]) == {'count': 0, 'canonical': 0}
+
+
+OTHER = KEYLINE.replace('/github-app-private-key', '/other-key')
+INLINE = 'JOB_ENV_INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY=inline-fake'
+
+
+@pytest.mark.parametrize('lines,want', [
+    ([KEYLINE], (1, 1)),
+    ([KEYLINE, OTHER], (2, 1)),                      # the receipt's reproducer: a later assignment wins
+    ([OTHER, KEYLINE], (2, 1)),
+    ([OTHER], (1, 0)),
+    ([KEYLINE, KEYLINE], (2, 2)),
+    ([KEYLINE + ' '], (1, 0)), (['  ' + KEYLINE], (1, 0)), (['export ' + KEYLINE], (1, 0)),
+    ([KEYLINE.replace('=', ' = ', 1)], (1, 0)), ([KEYLINE.replace('=', ':', 1)], (1, 0)),
+    ([KEYLINE, INLINE], (2, 1)),                     # the F3 conflict, caught here before any migration
+    ([KEYLINE, 'JOB_ENVFILE_INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY'], (2, 1)),
+    (['# ' + KEYLINE, '  #' + OTHER, KEYLINE], (1, 1)),
+    (['A=1'], (0, 0)),
+])
+def test_envfile_key_counts_every_line_naming_the_key(fake, lines, want):
+    (fake / 'etc/dispatcher.env').write_text('\n'.join(['JOB_DISPATCH_TOKEN=' + PLANT] + lines + ['']))
+    rc, out, err = cli(fake, 'envfile-key')
+    assert (rc, json.loads(out)) == (0, {'count': want[0], 'canonical': want[1]}), out
+    assert PLANT not in out + err
 
 
 def test_envfile_key_refuses_a_symlink(fake):
@@ -99,6 +124,12 @@ def test_envfile_key_refuses_a_symlink(fake):
 
 
 # ---- (c) disp-boot ----
+# The dispatcher's own phrase (apps/job-dispatcher/src/job-env-file.ts), read from its source so the two cannot drift.
+_TS = (HERE.parent.parent / 'apps/job-dispatcher/src/job-env-file.ts').read_text()
+assert "'both JOB_ENV_ and JOB_ENVFILE_ are set'" in _TS
+CONFLICT_LINE = 'job env file for INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY: both JOB_ENV_ and JOB_ENVFILE_ are set'
+
+
 def pino(msg):
     return json.dumps({'level': 30, 'time': 1, 'pid': 7, 'hostname': 'vm', 'msg': msg})
 
@@ -108,6 +139,8 @@ def pino(msg):
     ([pino('job env file for INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY: missing')], 'error:missing-file'),
     ([pino('job env file for INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY: is a symlink')], 'error:symlink'),
     ([pino('job env file for INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY: ' + PLANT)], 'error:other'),
+    ([pino(CONFLICT_LINE)], 'error:conflict'),             # receipt bugtracker-pr1377-gate-v2 F3
+    ([pino(CONFLICT_LINE), pino(OK)], 'ok'),               # (a later ok line from the same boot cannot happen; exact match only)
     ([pino('job env file key ignored (not allow-listed): JOB_ENVFILE_SCAN__X')], 'missing'),
     ([OK], 'missing'),                                           # a plain (non-pino) line is not the dispatcher's log line
     ([pino('x ' + OK)], 'missing'), ([pino(OK + ' ')], 'missing'),
```

Reply with PASS or FAIL and findings (severity, file:line, reproducer) for HEAD 69c7fd115811dd0d193bad6c13d4243b960e16c6.
