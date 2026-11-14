# Spec: bg_job wait-remote and an infrastructure outcome for ssh resets (goodqa#15565 items 7 and 8)

Ticket: GoodQA goodqa#15565
Author: agent:af9e33704216a1ea1 (claude-sonnet-5-5)
Click-test: not-applicable (a CLI helper with no UI; the proof is a live run against t2-dev from the Mac, recorded as REALLY_TESTED after install)
Sign-off: main
Review-policy: standard

## Outcome

An agent that must wait on a remote host for a line to appear in a log file (a suite finishing on t2-dev) runs one command, `bg_job.py wait-remote`, instead of a hand-written `until ...; done; cmd | tail` loop; and an ssh connection reset (exit 255) is reported as an infrastructure outcome with its own exit code instead of as a task failure.

## Scope

- In: a new `bg_job.py wait-remote --host H --file F --until-file-line TEXT --timeout S [--poll P] [--max-infra-polls N]` that runs one FIXED remote command per poll, retries that poll once on an ssh connection failure, and ends with a distinct exit code (5, INFRA) when the connection keeps failing; `bg_job.py wait --ssh-job`, which reports a job whose recorded exit status is 255 as INFRA (exit 5) instead of a plain failure; bg_lint's wait-loop advice names `wait-remote`; docs row in HARNESS.md or docs/operations.md; tests and a mutant script.
- Out: any wrapper that runs a caller-supplied remote command (it would hide the remote command text from command_guard, which judges ssh commands by their text, so it is deliberately not built); a retry loop longer than one retry per poll; changing the exit code of `wait` for jobs without `--ssh-job`; `launch`.

## Acceptance criteria

- AC-1: `wait-remote` exits 0 and prints `LINE_FOUND host=H file=F` when the last 64 KiB of the remote file contain a line containing TEXT as a fixed substring (not a pattern); it prints no remote content. Verify by: `python3 -B -m unittest tests.test_bg_job_remote` (a stub ssh whose output is controlled). Source: ticket:GoodQA goodqa#15565
- AC-2: the file not existing yet (the remote `tail` exits 1) is not an error: the wait continues until the line appears or the timeout (exit 3, TIMEOUT, one high alert like wait-file). `--timeout` is required, 1 to 86400 seconds, and bounds the whole wait. Verify by: stub ssh returning exit 1 then the line; stub never matching with a short timeout. Source: ticket:GoodQA goodqa#15565
- AC-3: the remote command is fixed: argv `[SSH, -o BatchMode=yes, -o ConnectTimeout=10, -o ServerAliveInterval=5, -o ServerAliveCountMax=2, --, HOST, "tail -c 65536 -- " + shlex.quote(FILE)]` with SSH the fixed `/usr/bin/ssh`, no shell on the local side, no caller text in the option positions. HOST must match `^([A-Za-z0-9._-]{1,32}@)?[A-Za-z0-9][A-Za-z0-9.-]{0,62}$`; FILE is 1 to 512 characters without NUL, newline or carriage return; TEXT is 1 to 200 characters without NUL or newline. Anything else is refused with exit 64 before ssh runs. Verify by: tests over host and path injection forms (leading dash, `-oProxyCommand=`, spaces, `;`, `$(...)`, backticks, newline, NUL, over-long) asserting no ssh call is made for a bad host and that a hostile file name reaches ssh only as one quoted word. Source: inferred: from ticket:GoodQA goodqa#15565 -- the same injection surface as scp/rsync destinations (PR 219) -- the remote command must not be shaped by caller text.
- AC-4: an ssh connection failure (exit 255, or the 30 s call bound expiring) is retried ONCE immediately; a poll whose attempt and retry both fail counts as an infrastructure poll; `--max-infra-polls` (default 3, 1 to 20) consecutive infrastructure polls end the wait with `INFRA host=H polls=N` and exit 5, one high alert with reason infra; a successful poll resets the count. The wait never reports a job failure for these. Verify by: stub ssh returning 255 once (poll succeeds on the retry), 255 always (exit 5 after N polls), 255 twice then ok (count resets). Source: ticket:GoodQA goodqa#15565
- AC-5: any other remote failure (the stub exits with a status other than 0, 1 or 255, for example a permission error from `tail`) ends the wait with `UNPROVEN ... reason=remote command failed (exit n)` and exit 2, no retry. Verify by: stub exit 2. Source: inferred: from ticket:GoodQA goodqa#15565 -- bg_job's fail-closed rule (exit 2 = no trustworthy result).
- AC-6: `wait --ssh-job` prints `INFRA name=N EXIT_STATUS=255 (an ssh connection failure, not a job failure)` and exits 5 when the job's status file says 255; without the flag the output and exit code are unchanged (1 for 255). Verify by: tests on both. Source: ticket:GoodQA goodqa#15565
- AC-7: bg_lint's wait-loop advice names `bg_job.py wait-remote` for a remote wait. Verify by: the bg_lint test. Source: ticket:GoodQA goodqa#15565
- AC-8: exit codes are documented in the module docstring and in docs/operations.md: 0 found, 2 unproven, 3 timeout, 5 infra, 64 usage. Verify by: a test that the docstring lists them. Source: inferred: from ticket:GoodQA goodqa#15565 -- the existing bg_job contract.

## Negative cases

- NEG-1 (AC-3): host `-oProxyCommand=touch /x`, `-F/etc/passwd`, `h ost`, `h;id`, `a@b@c`, empty, 100 characters. Expected: exit 64, no ssh call. Source: inferred: from ticket:GoodQA goodqa#15565 -- option injection through the host word.
- NEG-2 (AC-3): file `x; touch /tmp/pwn`, `$(id)`, `` `id` ``, `a\nb`, `a\0b`, 513 characters, `-rf`. Expected: refused (control characters, length) or passed to ssh as one shell-quoted word after `--` (never parsed as an option or a second command); the test asserts the exact remote string. Source: inferred: from ticket:GoodQA goodqa#15565 -- command injection through the path.
- NEG-3 (AC-1): the remote file contains TEXT only inside a longer word or in an earlier part beyond the last 64 KiB. Expected: a longer word still matches (substring by design); text beyond the window does not. Source: inferred: from ticket:GoodQA goodqa#15565 -- bounded read.
- NEG-4 (AC-1): remote output is huge or binary or contains instructions. Expected: nothing from it is printed; the read is bounded by `tail -c` and a 64 KiB local capture cap. Source: inferred: from ticket:GoodQA goodqa#15565 -- remote data is untrusted data, not instructions.
- NEG-5 (AC-4): ssh hangs. Expected: the 30 s per-call bound ends it, counted as an infrastructure failure; the overall timeout still bounds the wait. Source: inferred: from ticket:GoodQA goodqa#15565 -- resource limits.
- NEG-6 (AC-4): a reset during the retry window that succeeds on the retry. Expected: no INFRA, the wait goes on. Source: ticket:GoodQA goodqa#15565
- NEG-7 (AC-2): `--timeout` missing, 0, negative, NaN, 100000; `--poll` outside 0.05 to 60; `--max-infra-polls` 0 or 21. Expected: exit 64 (the same validation wait-file has). Source: inferred: from ticket:GoodQA goodqa#15565 -- an unbounded or NaN timeout would let a waiter sit for ever, the item 8 failure
- NEG-8 (AC-6): a job that exited 255 for a reason that is not ssh. Expected: with `--ssh-job` it is reported as INFRA (the caller asked for ssh semantics); without the flag nothing changes. Source: inferred: from ticket:GoodQA goodqa#15565 -- opt-in semantics.
- NEG-9 (AC-3): ssh binary override. Expected: the CLI offers no way to change the ssh binary or add ssh options; tests replace the module constant only. Source: inferred: from ticket:GoodQA goodqa#15565 -- no caller-supplied program.

## Resource budget

Host: mac
Fan-out: agents=1 jobs=0 processes=1 browser_pages=0 test_workers=1
Peak memory: under 0.1 GB (method: stub ssh and one polling loop)
CPU: 1 core, mostly sleeping (method: poll default 1 s, bounded by the timeout)
Disk: under 1 MB (method: no files written)
Network: one small ssh call per poll, at most 64 KiB returned (method: tail -c 65536)
Wall time: the caller's --timeout, at most 24 h
Cap and kill: the foreground command is bounded by --timeout; each ssh call by a 30 s bound
Checkpoint: idempotent steps only (each poll is a read-only call that can be repeated); it holds no state, so it resumes by simply running the same command again

## Risks

- A caller waits on a remote file that another process rewrites: the last 64 KiB are re-read each poll, so a line can appear and be overwritten between polls; mitigation: the doc says to wait on an append-only log.
- A flaky link ends the wait early with INFRA: bounded by `--max-infra-polls`, and INFRA is not a task failure, so the caller reruns the wait.
- The helper becomes a remote reader of arbitrary files: it is read-only (`tail`), and the same ssh access exists through a plain ssh command that command_guard judges; the guard still judges the `bg_job.py wait-remote` command text for secret paths (the file argument is on the command line).

## Domain checklist

Domains: auth, delete, devices, money, release

Detected from: repository-wide path names (the change touches only bg_job.py, bg_lint.py, tests and docs).

Domain-gate: pre-account-hijack waived (no authentication flow is added or changed)
Domain-gate: lookalike-identifier waived (no account identifier handling is involved)
Domain-gate: request-device-binding waived (no approval or login flow is involved)
Domain-gate: link-expiry-single-use waived (no link or token is issued or consumed)
Domain-gate: session-fixation waived (no session handling is touched)
Domain-gate: rate-limit-enumeration waived (no account lookup is involved)
Domain-gate: store-billing-exposure waived (no account state or billing is touched)
Domain-gate: backup-before-delete waived (nothing is deleted; the remote command is a read-only tail)
Domain-gate: unpushed-work-detection waived (no checkout or branch is touched)
Domain-gate: dry-run-diff waived (nothing is removed)
Domain-gate: scope-pinning waived (nothing is removed; the one remote read is a single quoted path, see AC-3 and NEG-2)
Domain-gate: cross-host-approval-portability waived (no approval is involved)
Domain-gate: idempotent-retry waived (the one retry repeats a read-only call; AC-4)
Domain-gate: device-identity-binding waived (no device enrollment or grant is touched)
Domain-gate: unattended-recovery waived (a dead link ends in a distinct INFRA exit and an alert, AC-4)
Domain-gate: grant-durability waived (no grant is created)
Domain-gate: remote-exec-audit waived (the remote command is fixed and read-only; no caller-supplied remote command is run, see Scope Out)
Domain-gate: factory-reset-guard waived (no wipe or unenroll path is involved)
Domain-gate: idempotency-key waived (no money movement is involved)
Domain-gate: double-submit waived (no money flow or form is involved)
Domain-gate: currency-precision waived (no amounts are involved)
Domain-gate: refund-reversal-path waived (no money movement is involved)
Domain-gate: ledger-reconciliation waived (no ledger is involved)
Domain-gate: authorization-vs-capture waived (no payment is involved)
Domain-gate: derived-gate-floor-with-ratchet waived (no release gate is changed)
Domain-gate: artifact-inventory-mirrored waived (no signed artifact is produced)
Domain-gate: self-update-e2e waived (installed by the normal ah install-files batch)
Domain-gate: transport-proof waived (the live run over the real ssh route to t2-dev is the proof)
Domain-gate: rollback-not-blocked waived (no release or rollback path is touched)
Domain-gate: staging-exists waived (a local helper; the t2-dev run after install is the live proof)
