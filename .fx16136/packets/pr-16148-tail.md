
## Risks
- The drift gate is red from merge until the host apply (ship order step 2). It fails closed, blocking promotions, so steps 3 and 4 must follow the merge directly.
- The compose.yaml on prod stays writable by the sudo login user (deviation 2). A person with that login can already change the stack, so this PR does not widen access.
- Before the host apply, dispatcher.env has no JOB_ENVFILE key, so a dispatcher on the new image reads no file and passes no key. intelligence-worker is held, so nothing consumes it yet. Between the apply and the next recreate, the running dispatcher keeps its old env and mounts. Only the recreate in ship order step 5 activates the key.
- The sampler is labelled `sampled`, not exhaustive: a docker run shorter than about 50 ms can be missed. NO_SAMPLE fails, so silence never passes, and AC-1 is enforced in code and unit tests regardless.
- Any later release pin keeps the mount (claim 7). Rolling back to a release pinned before the apply is refused by the fence. That is intended, and an operator runs `apply-job-secrets.sh restore` first if it is ever needed.
- Nothing is merged or deployed. Merge, the prod operator and the ship are main's call.
