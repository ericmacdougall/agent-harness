# Adversarial delta review: goodqa#16148 PEM spec v4 (secret handling)

Reviewer: agent:a5a2642f07434bbc9 (claude-opus-5-5), adversarial role
Date: 2026-11-15

Inputs (verified):
- `spec-16148-pem-v4.frozen.md`, sha256 `1059c86dc3d88559b39c9e2c265c675f8e60707555451abb0cdcc526b4813508`
- `spec-16148-pem-v3-to-v4.diff`, sha256 `eda97873f3b98d77bfd9019db3865f7f86f3083e13473de090ce7485e696e75f`
- the live `.fx16136/spec-16148-pem.md`, identical to the frozen copy (sha256 1059c86d)

Location: written uncommitted to the author's `.fx16136/` at the lead's instruction.

Code read (read-only, t2-dev): bugtracker `apps/job-dispatcher/src/create-guard.ts` at c4a1d054 (the refusal message format `job-dispatcher-create-guard: refused (${reason})`), plus `selfhost-ctl.py`'s restore fence from earlier rounds.

No secret, no /etc/goodqa path and no production was read.

## Verdict: ACCEPT (recorded against 5d317b21), with must-dos R1 to R4 on AC-11 and build notes R5 and R6

P1 to P4 are closed. The new AC-11 host-apply step is the right answer to Q3, but as written its restore can silently undo later production changes. R1 to R4 are additive safeguards that fit inside AC-11's text and its verify list. They must be in the implementation and its tests before the host apply runs on production.

## P1 to P4

| | Status | Where |
|---|---|---|
| P1 request env not redacted; the held reason survives | CLOSED, with R5 | AC-7 redacts secret-source values only; NEG-17 runs the real held request env with short base values `1`, `true`, `europe-west1`; the cross-constant test against ac13-count.py HELD_TAG is moved to the first PR after #16136 1369 and 1371 (Q1) |
| P2 sampler contract | CLOSED, with R6 | AC-6 (3): the flag-name allow-list, cut at `=`, `-e(attached)`, cgroup scoping, NO_SAMPLE as a positive control, the four planted-marker forms; NEG-18 |
| P3 trial-boot isolation | CLOSED | AC-8: `--rm`, `--network none`, no socket, a fake token, no env_file, its own temp secrets directory, a 60 s timeout; the argv is asserted |
| P4 a failed re-pin | CLOSED | AC-8 and NEG-19: exit 8, `HOLD NOT RE-APPLIED`, the manual command, a `--no-deps` recreate of the dispatcher and guard only |

## (a) The short-value whole-token rule

**Can a short base value drop the held reason line?** Yes, in principle.

The full first line is roughly `docker: Error response from daemon: job-dispatcher-create-guard: refused (… TRANSCODER_MODE=transcribe is held on this guard)`. Its whole tokens include `docker`, `Error`, `response`, `from`, `daemon`, `job`, `dispatcher`, `create`, `guard`, `refused`, `is`, `held`, `on` and `this`. A secret-source base value equal to any of them would drop the line: for example a future `JOB_ENV_*__FEATURE=on`, or a value such as `daemon` or `guard`.

None of today's base value shapes match (NODE_ENV, STORAGE_DRIVER, SPACES_*, DATABASE_URL, OPENROUTER_API_KEY). The failure mode is also safe: AC-13 FAILs and nothing leaks. It is a robustness gap, not a security one.

**Residual leak.** A secret-source value shorter than 8 bytes that appears inside a longer token (for example `xab12y` containing `ab12`) is neither removed nor matched as a token, so it would survive. Real secrets are far longer than 8 bytes, so this is acceptable when stated.

**R5 (build note).**
- Classify the guard's held refusal before any redaction: if the first line contains the fixed held phrase, append that phrase from the constant, not from stderr. Then no base value can erase it.
- Extend NEG-17 with base values equal to `on`, `this` and `guard`. The test must still pass after the classify-first rule.
- State the under-8-byte residual in AC-7.

## (b) AC-11, `apply-job-secrets-host.py`

The design is sound: `--check`, a dated backup, validation, atomic writes, idempotency and restore. Four gaps follow.

### R1 (must-do): restore must be fenced, or it silently reverts later changes

`restore --stamp S` "puts the backed-up files back byte for byte".
- Suppose a step-3 release has re-pinned images in compose.yaml after the apply. Restoring the pre-apply compose bytes then silently reverts every image pin and every job pin to the older release. The guard allowlist and the dispatcher move with it, while api.env's RELEASE_* do not, which leaves a mixed stack.
- Likewise, restoring dispatcher.env after a person sets the other missing keys (PROJECT_INTELLIGENCE_KEYRING and the rest, through set-secret-env.sh) silently deletes them.

Fix: as selfhost-ctl's `restore_fence` already does, record the sha256 of each file before and after the apply. Have restore refuse, with nothing changed, unless each file still equals exactly what the apply wrote, or its own backup. Or restore structurally, removing only the inserted lines. Add pytest cases for "compose re-pinned after apply" and "dispatcher.env gained a key after apply", both refused.

### R2 (must-do): the dispatcher.env backup is a second copy of every job secret

- Create the backup with O_CREAT|O_EXCL|O_NOFOLLOW in the same root-owned directory, with fchown and fchmod by fd matching the original (root:root 0600), never wider.
- State how long backups are kept and who deletes them. They are secret-bearing and must not accumulate unseen.
- Apply the same fd-based write rules as AC-2 to every temp and target file. /opt/goodqa/infra/selfhost/app may be owned by the checkout user rather than root, which is the S1 pattern: never resolve a path twice there as root.
- Add a pytest that asserts the backup's mode and owner.

### R3 (must-do): where the installed derive script lives

rw-ship runs derive as root on every deploy. If the installed copy sits in a directory or file a non-root account can write, that account gets root code execution on the next deploy.

Either install it root:root 0755 in a root-owned directory (for example `/usr/local/lib/goodqa/`), with apply refusing if any path component is writable by group, world or another uid. Or, better, stream it from the reviewed release kit on each run, exactly as rw-ship already streams selfhost-ctl.py, so no installed copy exists. The binding check (#16136 AC-15) should then cover its sha.

### R4 (must-do): exclude concurrent releases

A host apply that overlaps a release's pin could be overwritten by the pin's compose write, or could overwrite it. apply and restore must take the same deploy lock rw-ship uses, or refuse while a `gq-ship-*` unit or a `.rw-pin` without a completed state is in flight. Add a pytest case.

### Partial apply (NEG-14) and the operator

NEG-14 is sound: a per-item `--check`, a completing rerun, and restore after a stop between the two writes. With R1, restore after a partial apply must accept "file equals its backup" for the item that was not yet written.

The production operator is unassigned. That is correct: no agent writes to production without main's authorization. The open item must be resolved by name before step 2, and the live record must name who ran it.

## (c) Ship order and rollback: sound, with one note

The order (merge, host apply, drift gate, then the step-3 release with intelligence held) is right. An older dispatcher ignores both the mount and the JOB_ENVFILE key.

A release rollback keeps the mount and group_add, because the restored compose was backed up after the apply. This is harmless: the older dispatcher does not read the file.

Note: after the host apply, selfhost-ctl's restore fence will (correctly) refuse to roll back any release that was pinned before the apply, because compose changed after that run installed it. Document this so an operator does not force it. Once R1 is in place, the host-apply restore must also be fenced against later release pins.

## (d) The sampler: sound, with R6

R6 (build note):
- Resolve the dispatcher's container id and cgroup at sample time. The release recreates the container, so a cached cgroup samples nothing, and NO_SAMPLE catches that.
- Poll well under the roughly one-second life of a docker CLI process, for example every 50 ms.
- Run the sampler as an unprivileged user, since /proc/PID/cmdline is world-readable, so a sampler bug cannot write as root.
- NO_SAMPLE as a positive control is correct, and so is the honest "sampled, not exhaustive" label.

## Not examined

- the implementation (none yet)
- the ownership of /opt/goodqa/infra/selfhost/app on production
- the rw-ship deploy-lock mechanism by name
- set-secret-env.sh and push-env.sh
- production
