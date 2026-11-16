Parent: goodqa#16148. Source: the goodqa#16148 code review by a5a2642f, finding F5 (LOW), report .fx16136/review-opus-code-16148.md sha fb747cce. The lead ruled it a ticket.

**Problem.** Two test sets in infra/selfhost/app are guarded with `unittest.skipUnless(IS_ROOT)`, and only `run_derive_tests.sh` runs them, as root inside a throwaway python:3.12-slim container (--network none):
- HostApplyTests in test_apply_job_secrets_host.py;
- the derive ownership, race and inode tests in test_derive_job_secrets.py.

Nothing in CI calls run_derive_tests.sh; a search outside infra/selfhost/app finds no wiring. Any other way of running the suite reports `OK (skipped=41)`. That is a green result with none of these run:
- the R1, R2, NEG-14 and NEG-15 host-apply tests;
- the derive NEG-1/2/3/13 ownership and inode tests;
- the F2 swap tests.

**Proposed fix (either one, or both).**
1. Wire `bash infra/selfhost/app/run_derive_tests.sh` into the CI or release-test gate (infra/release-test-gate.mjs) on a runner that has docker.
2. Make a non-root run fail instead of skip, unless an explicit opt-out such as DERIVE_TESTS_ALLOW_SKIP=1 is set. A skipped root suite then can never read as green.

**Acceptance.**
- A CI run of the selfhost tests either executes the root container pass or fails.
- A test proves that a plain `python3 -m unittest test_derive_job_secrets` as non-root without the opt-out exits non-zero.
- The goodqa#16148 packet's evidence block is unchanged.
