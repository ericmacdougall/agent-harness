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
