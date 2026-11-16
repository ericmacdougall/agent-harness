Parent: goodqa#16148. Source: the delta code review by a5a2642f, finding D1 (LOW), report review-opus-code-16148-delta.md sha 8c7050e0. The lead ruled it a ticket. PR #1373 HEAD 97bfac51 stays frozen.

**1. The sampler misses `-qe K=V` (D1).** In infra/selfhost/app/cmdline-sampler.py, `BOOL_SHORT = set('ditP')` lacks `q`, which is docker run's `--quiet` boolean shorthand. The cluster walk therefore stops at `q`, and `docker run -qe K=V img` records `-(other)(attached)` instead of `-e(cluster)`. The run passes even though it carries an env value in argv.
- Fix: `BOOL_SHORT = set('ditPq')`.
- Add `-qe K=V` and `-qieK=V` cases to `test_neg18_clustered_short_flags_with_e_fail`. They must fail first against the current set.
- Recheck the set against `docker run --help` from the docker CLI version on the app VM (names only), and note the version in a comment.

**2. Derive is single-instance (docstring note).** derive-job-secrets.py assumes one run at a time. The wrapper runs it under the deploy lock, but a hand-run `sudo python3 derive-job-secrets.py` racing the wrapper could see the other run's rename as a mismatch. The F2 fail-closed unlink would then remove that run's freshly written file. The result fails closed (the key reads as missing; no value exposed), and the next run repairs it.
- Fix: state in the module docstring that derive must run only through apply-job-secrets.sh, under the deploy lock, or by hand only while no wrapper run holds the lock.
- Optionally take a flock on a lock file in the secrets dir inside derive itself.

**Delivery.** This lands with the rw-ship gate PR of goodqa#16148, or in a small follow-up. It does not change PR #1373.

**Acceptance.**
- The new NEG-18 cases fail before the change and pass after.
- The docstring states the single-instance rule.
- If the optional flock is added, a test shows a second concurrent derive refuses without touching the file.
