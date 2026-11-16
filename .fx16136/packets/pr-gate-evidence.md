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

  The likely cause is timing under load: the file waits on lock holders with fixed 0.3 s sleeps. That cause is unverified. Treat this as a known flake to ticket, not as evidence about this diff.

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
- **Deferred:**
  - the Q1 cross-constant test (held-env.ts is now on main, so it can be written after this lands);
  - the rh port of the gate;
  - goodqa#16195 (apply write order);
  - goodqa#16196 (root-only tests skipping in CI);
  - goodqa#16208 (the rh base failures and the set-secret-env ctl copy);
  - goodqa#16210 (the rh overflow port).
- Nothing is merged, deployed or tagged.
