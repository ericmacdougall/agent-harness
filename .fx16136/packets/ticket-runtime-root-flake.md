infra/release-harness/test_rw_runtime_root.py failed intermittently: 5 failures in one full release-harness run under load, and green when rerun.

Where it happened: t2-dev, on the scratch join of fix/16148-rwship-gate 679c278a with origin/main 179c3ab1 (scratch commit 234acbbf, clean tree). The run was ac13, jobsecret_gate, rw_ship_selfhost, d2, install_d2_upgrade, runner_ship_adapter, rw_runtime_root, selfhost_ctl, selfhost_ctl_gate and selfhost_ctl_job_secrets.

The first run gave 5 failed and 1958 passed. All 5 were in test_rw_runtime_root.py:
- test_two_roots_ship_and_rollback_independently
- test_failed_switch_rollback_uses_custom_root
- test_executed_ship_and_rollback_never_open_legacy_root
- test_root_with_spaces_is_preserved
- test_runtime_boundary_negative_controls[embedded-db-root]

The same file alone on the same tree then gave 25 passed. The identical full command, rerun, gave 1963 passed and 1 skipped. The previous full run, on the ab028a6b join, gave 0 failed.

Likely cause, unverified: the file waits on lock holders with fixed 0.3 s sleeps (for example `holder = subprocess.Popen(['flock', '--no-fork', ...]); base.time.sleep(.3)`). Under load the holder may not hold the lock yet when the test proceeds. The tracebacks of the failing run were not kept.

Next time it reproduces:
1. Keep the full tracebacks (pytest -rf, output to a file).
2. Check whether each failure follows a lock-holder wait.
3. Fix by waiting for a positive signal that the holder holds the lock, instead of a fixed sleep.

Refs: goodqa#16148 (gate packet, under Risk), goodqa#16136.
