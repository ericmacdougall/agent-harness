Parent: goodqa#16148 (spec v4 AC-11, NEG-14). Source: the goodqa#16148 code review by a5a2642f, finding F1 (LOW), report .fx16136/review-opus-code-16148.md sha fb747cce. The lead ruled it a ticket rather than a fix in PR 1373.

**Problem.** infra/selfhost/app/apply-job-secrets-host.py applies changes in this order: dispatcher.env first (the JOB_ENVFILE key line), then compose.yaml (the mount and group_add). restore goes in the same order.

If apply stops between the two writes, the host has the key without the mount. NEG-14 asserts this state on purpose, and a rerun of apply completes it.

In that state:
- The drift gate goes red, which blocks a normal rw-ship release.
- A manual `docker compose up` of job-dispatcher does not check the gate. It would start a dispatcher whose JOB_ENVFILE path points at a directory that is not mounted. Per job-env-file.ts, the dispatcher then fails closed for that key and no value leaks, but it is a confusing half-state.

**Proposed fix.**
- apply: write compose first and env last.
- restore: remove in the reverse order, env first and compose last.

A half-done apply then leaves the mount without the key. That state is harmless: an unused read-only mount and group.

**Spec change.** This flips NEG-14 (the asserted partial state) and the H2 broken variant ("compose written before env" becomes the correct order). It needs the next spec edit of goodqa#16148, with reviews per spec_policy, before the code changes.

**Acceptance.**
- NEG-14 reworded so the partial state is the mount without the key.
- test_neg14_stopped_between_files updated and failing first against the current order.
- A restore stopped part way leaves no key without its mount.
- H2 inverted.
