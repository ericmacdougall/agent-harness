# Adversarial delta review: goodqa#16148 PEM spec v3 (secret handling)

Reviewer: agent:a5a2642f07434bbc9 (claude-opus-5-5), adversarial role
Date: 2026-11-15

Inputs (verified):
- `spec-16148-pem-v3.frozen.md`, sha256 and core `e002c59f11652005a7f0d24e4b832a1ef372f09638476d4de0cb7de3a729a1df`
- `spec-16148-pem-v2-to-v3.diff`, sha256 `f8ea1d14c93d310c370002bec64c7b52895b49ed7001f4c3ff0fa9eb9c8c07b5`
- the live `.fx16136/spec-16148-pem.md`, identical

Location: written uncommitted to the author's `.fx16136/` at the lead's instruction.

Code context: from earlier rounds (create-guard.ts, docker.ts, jobs.ts, the #16136 hold reason text). No secret, no /etc/goodqa path and no production was read.

## Verdict: ACCEPT (recorded against e002c59f), with must-dos P1 and P2 and build notes P3 and P4

P1 is a contradiction inside AC-7. AC-7's own required test ("a guard held refusal whose reason line must survive") catches it, provided that test uses the real launch env. P1 pins the resolution. P2 closes a leak path in the new sampler. Both must be in the implementation before merge.

## M1, M2 and N1 to N4

| | Status | Where |
|---|---|---|
| M1 docker stderr not forwarded | CLOSED, with P1 | AC-7: a fixed category and byte count, three allow-listed prefixes, redaction before the cut, an 8-byte-substring drop, a 200-character truncation; NEG-11 stub forms |
| M2 the hold re-applied before rollback under mig_hold | CLOSED, with P4 | AC-8 and NEG-12: a hold-only re-pin, the dispatcher and guard recreated, exit 8 |
| N1 NSS-aware group checks | CLOSED | AC-2 and NEG-13: getent group and passwd, primary-gid collisions |
| N2 per-launch 0700 directory, boot sweep, key validation | CLOSED | AC-4, AC-6 and NEG-10 |
| N3 ASCII-only PEM, refusal of non-UTF-8 | CLOSED | AC-1 (printable ASCII 0x20-0x7E) and AC-6 |
| N4 trial boot, (c) read by container id and start time | CLOSED, with P3 | AC-8 |

Sonnet's real-engine round trip (AC-6 (2)) is a strong addition. It covers whitespace, `=`, `#`, quotes, backslashes, empty values and non-ASCII, for every kind's base env, through the real guard.

## P1 (must-do): AC-7's redaction erases the #16136 held reason, so AC-13 pairing breaks

AC-7 removes "every non-empty env value of that launch" from the stderr line. A held-transcription launch's env always contains the request value `TRANSCODER_MODE=transcribe`, so the value `transcribe` is removed from the guard's reason line:
- `… TRANSCODER_MODE=transcribe is held on this guard`
- becomes `… TRANSCODER_MODE= is held on this guard`

#16136 AC-13 (ac13-count.py `HELD_TAG`) matches the full phrase, so every held 422 goes unpaired and AC-13 FAILs on every deploy. It fails closed, but the spec's claim that the reason "stays visible, so goodqa#16136 AC-13 pairing still works" is false under its own rule. Short non-secret base values (for example `production`, a region code) can likewise mangle other allow-listed lines.

Fix:
- Redact only values from secret-bearing sources: the base env (`JOB_ENV_*`) and `JOB_ENVFILE_*` values.
- Request-env values are the API's allow-listed, non-secret keys (TRANSCODER_MODE), so they are not redacted. Equivalently, classify the guard-held refusal before redaction: if the first line contains the guard's fixed held phrase, set CATEGORY=guard_refused and append that phrase from a constant, never from stderr.
- The AC-7 stub case "a guard held refusal whose reason line must survive" must run with the real held launch env (`TRANSCODER_MODE=transcribe` plus a base env), and must assert that ac13-count.py's `HELD_TAG` matches the resulting API line.
- If the spec text is amended, a one-line clarification in AC-7 suffices.

## P2 (must-do): the /proc cmdline sampler can itself leak

Two leak paths in the sampler as specified:
- **Attached flag values.** "Flag names present" is unsafe if flags are found by taking tokens that start with `-`. The docker CLI accepts attached forms: `--env=KEY=VALUE`, `-eKEY=VALUE`, and `--env-file=PATH`. A regression to any of those would be printed verbatim as a "flag name", which leaks exactly the value the scan exists to catch.
- **Unrelated processes.** Matching all docker CLI processes also samples operator commands such as `docker exec … -e …`.

Fix:
- Print only names from a fixed allow-list of known docker run flags, with each token cut at the first `=`. A short flag is cut to two characters, with an attached-value form recorded as, for example, `-e<attached>`. Any other token is printed only as a count.
- Assert absence by name, after that normalisation: `-e`, `--env` and `-e<attached>` must not appear.
- Restrict sampling to processes whose cgroup is the job-dispatcher container's.
- Never write the raw cmdline to disk. Keep it in memory and discard it.
- Add a test with planted `--env=K=MARKER` and `-eK=MARKER` argv, asserting that the marker appears in no output.

## P3 (build note): N4 trial-boot isolation

The trial dispatcher run on the VM must:
- use `--network none`, with no docker socket and no `DOCKER_HOST`
- get a fake `JOB_DISPATCH_TOKEN`, with no `env_file` and no `/etc/goodqa` mount
- be read-only, use its own throwaway secrets directory (removed afterwards), and run with a short timeout and `--rm`

It is read by its own container id. That way it cannot launch anything, reach the API, or see a real secret.

## P4 (build note): when the hold-only re-pin itself fails

If the M2 re-pin or the recreation of the dispatcher and guard fails (for example a pin REFUSED or an up failure), intelligence may still be unheld with no key. Specify the outcome:
- exit 8 with a distinct message ("HOLD NOT RE-APPLIED"), an ops alert, and the exact manual command
- add a pytest case

Also, the targeted recreate must be `up --no-deps job-dispatcher job-dispatcher-create-guard` only, not the four-service `up`.

## NEG-10 (keys without `=`): sound

The key regex `^[A-Za-z_][A-Za-z0-9_]*$` makes a key containing `=`, and so a key-only env-file line (which docker would fill from the CLI's own environment), impossible to write. NEG-10 tests it before anything touches /tmp.

## Not examined

- the implementation
- the exact text of every create-guard refusal reason (P1 assumes that only the held phrase is needed by AC-13)
- set-secret-env.sh and push-env.sh
- production
