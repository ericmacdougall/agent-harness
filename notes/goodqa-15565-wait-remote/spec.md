# Spec: bg_job wait-remote and an infrastructure outcome for ssh resets (goodqa#15565 items 7 and 8)

Ticket: GoodQA goodqa#15565
Author: agent:af9e33704216a1ea1 (claude-sonnet-5-5)
Click-test: not-applicable (a CLI helper with no UI; the proof is a live run against t2-dev from the Mac, recorded as REALLY_TESTED after install)
Sign-off: main
Review-policy: standard

## Outcome

An agent that must wait on a remote host for a line to appear in a log file (a suite finishing on t2-dev) runs one command, `bg_job.py wait-remote`, instead of a hand-written `until ...; done; cmd | tail` loop; and an ssh connection reset (exit 255) is reported as an infrastructure outcome with its own exit code instead of as a task failure.

## Scope

- In: a new `bg_job.py wait-remote --host H --file F --until-file-line TEXT --timeout S [--poll P] [--max-infra-polls N] [--fail-line TEXT] [--include-existing]` that runs one FIXED remote command per poll, retries that poll once on an ssh connection failure, and ends with a distinct exit code (5, INFRA) when the connection keeps failing; `bg_job.py wait --ssh-job`, which reports a job whose recorded exit status is 255 as INFRA (exit 5) instead of a plain failure; bg_lint's wait-loop advice names `wait-remote`; docs row in HARNESS.md or docs/operations.md; tests and a mutant script.
- Out: any wrapper that runs a caller-supplied remote command (decision D1: a retry can run a non-idempotent command twice; main to confirm, item 7 is partly met until then); a retry loop longer than one retry per poll; changing the exit code of `wait` for jobs without `--ssh-job`; `launch`.

## Decisions (owner, labelled; main to confirm)

- D1 (resolved by main, WAL wa0d7fa0b484, labelled inferred: NOT the user's choice; item 7 stays TARGET_MISMATCH in reports until the user says otherwise): item 7 asks for "a retry-once wrapper with a distinct INFRA exit". Retry and INFRA stay inside the `wait-remote` polls (a fixed, read-only, idempotent remote command) and the `wait --ssh-job` INFRA report; there is NO generic retry wrapper, because a retry can run a non-idempotent command twice. Item 7 is PARTLY MET; the generic idempotent-only wrapper is the follow-up ticket goodqa#15951 (explicit idempotent flag, the command text stays visible to command_guard).
- D2 (owner design, review F1): a wait only counts bytes appended after its first poll (the size is recorded then); `--include-existing` is an explicit opt-in to match what is already in the file.
- D3 (owner design, reviews F2/H1): the fixed remote command tells "not there yet" (exit 10) apart from "unreadable or not a regular file" (exit 11); any other non-zero status is UNPROVEN.

- D4 (owner design, review round 3): the launch-then-wait race (a run that finishes before the wait's first look) is closed by the caller's choice: a run with its OWN fresh log uses `--include-existing`; a log appended across runs takes its size before the launch and passes `--from-offset N`. The default (appended bytes only) is the safe one against a stale earlier result. A rewrite that regrows past the old offset within one poll is not detected (limit: wait on an append-only log); a dangling symlink at FILE is exit 10 for ever and ends as a TIMEOUT; a remote symlink named by FILE is followed.

## Acceptance criteria

- AC-1: `wait-remote` exits 0 and prints `LINE_FOUND host=H file=F` when TEXT (a fixed substring, not a pattern) appears in bytes appended to the remote file after the first poll (or anywhere in the file with `--include-existing`); it prints no remote content. Matching spans poll boundaries (the last len(TEXT)-1 bytes are carried, and cleared on a reset). The next offset is the previous offset plus the content bytes RECEIVED in that poll, never the size the remote reports (the 64 KiB read cap can outrun it), so coverage across polls is complete; when a poll returns a full 64 KiB the next poll runs at once. The local capture cap is 64 KiB plus the size line. Verify by: `python3 -B -m unittest tests.test_bg_job_remote` (a stub ssh whose output is controlled). Source: ticket:GoodQA goodqa#15565
- AC-2: the remote command is fixed, built from one template with only an integer offset and the shell-quoted FILE substituted: `[ -e F ] || exit 10; [ -f F ] && [ -r F ] || exit 11; wc -c reading F on stdin, || exit 12; { tail -c +OFFSET -- F; echo __bgjob_rc=$? sent to stderr; } | head -c 65536` (the pipeline reports head's status, so the read status of `tail` travels as a marker on stderr: a missing marker or a tail status other than 0, or 141 on a full 64 KiB read cut off by `head`, is UNPROVEN, exit 2, never a match), run as `[SSH, -o BatchMode=yes, -o ConnectTimeout=10, -o ServerAliveInterval=5, -o ServerAliveCountMax=2, --, HOST, template]` with SSH the fixed `/usr/bin/ssh`, no shell on the local side, no caller text in option positions. The remote host is assumed to have a POSIX login shell. The baseline is 0 until the first successful read of an existing file (an absent file, or connection failures, leave it at 0, so a file created after the wait started is read from byte 0); that first read of an existing file sets it to the size unless `--include-existing` or `--from-offset N` (D4). The output must be shaped as a size line matching `^\s*[0-9]+$` followed by content; anything else (a login banner or rc echo before the size, empty output, a garbled size) is UNPROVEN, exit 2, never a reset or a re-read. `tail -c +N` is 1-based, so the template substitutes OFFSET+1. A size smaller than the recorded offset (truncation, rotation) resets the offset to 0. Verify by: tests asserting the exact argv and template for ordinary and hostile file names. Source: ticket:GoodQA goodqa#15565
- AC-3: arguments are validated before any ssh call, exit 64 on failure. HOST matches `^([A-Za-z0-9._-]{1,32}@)?[A-Za-z0-9][A-Za-z0-9.-]{0,62}$`; FILE is 1 to 512 characters, without NUL, newline or carriage return, and NOT starting with `~` (message: "use an absolute path or a path relative to the remote home"); TEXT and `--fail-line` TEXT are 1 to 200 characters without NUL or newline; `--timeout` is required, 1 to 86400 seconds (bounds the whole wait); `--poll` 0.05 to 60; `--max-infra-polls` 1 to 20 (default 3). Verify by: injection and range tests (NEG-1, NEG-2, NEG-7). Source: inferred: from ticket:GoodQA goodqa#15565 -- caller text must not shape the remote command, and a wait must be bounded
- AC-4: FILE (a relative FILE is relative to the REMOTE home, so it is judged as written and as `~/FILE`, quoted as one word; the guard resolves paths against the local cwd and home, so a home-anchored protected path is also a case) is judged with command_guard before ssh runs: it is refused (exit 64) when `command_guard.raw_sensitive` or a `decide` on a plain read of that path would block it (credential and protected harness locations such as the GoodQA user token, gq-browser keys, ~/.ssh keys). If command_guard cannot be imported the command is refused. A path the guard does not know about is a stated limit. Verify by: tests with those paths. Source: inferred: from ticket:GoodQA goodqa#15565 -- the found or timeout answer is a substring oracle over any remote file, so the secret-read rules must apply to FILE as they apply to `ssh host cat FILE`
- AC-5: remote exit 10 (file absent) is "not yet": the wait continues until the line appears or the timeout (exit 3, TIMEOUT, one high alert). Exit 11 or any other status that is not 0, 10 or 255 ends the wait at once with `UNPROVEN ... reason=remote command failed (exit n)`, exit 2, no retry. Verify by: stub exits 0 (with and without a match), 10, 11, 2. Source: ticket:GoodQA goodqa#15565
- AC-6: an ssh connection failure (exit 255, or the 30 s per-call bound expiring) is retried ONCE immediately; a poll whose attempt and retry both fail counts as an infrastructure poll; `--max-infra-polls` consecutive infrastructure polls end the wait with `INFRA host=H polls=N` and exit 5 with one high alert (reason infra); a successful poll resets the count. Bounded first line of ssh's stderr (at most 160 printable ASCII characters) is printed with the INFRA line. If the whole bounded stderr (the first 2000 bytes, not only the printed line) says `Permission denied`, `Host key verification failed` or `Could not resolve hostname`, it is NOT infrastructure: it ends the wait at once with `UNPROVEN ... reason=ssh refused (the bounded line)`, exit 2, no retry. Verify by: stubs returning 255 once, always, twice then ok, and 255 with each refusal text. Source: ticket:GoodQA goodqa#15565
- AC-7: optional `--fail-line TEXT` ends the wait early when TEXT appears in the new bytes (same matching as AC-1): it prints `FAIL_LINE_FOUND host=H file=F` and exits 1 (the awaited run reported failure); when both lines are present in one poll, the failure wins. Verify by: tests with both. Source: inferred: from ticket:GoodQA goodqa#15565 -- a suite that crashes after printing a failure line should not make the caller wait out the timeout, the item 8 failure
- AC-8: `wait --ssh-job` prints `INFRA name=N EXIT_STATUS=255 (an ssh connection failure, not a job failure)` and exits 5 when the job's status file says 255; without the flag the output and exit code are unchanged (1 for 255). Verify by: tests on both. Source: ticket:GoodQA goodqa#15565
- AC-9: bg_lint's wait-loop advice names `bg_job.py wait-remote` for a remote wait; the module docstring and docs/operations.md list the exit codes (0 found, 1 failure line, 2 unproven, 3 timeout, 5 infra, 64 usage) and state the limits (a path the guard does not know, ssh config ProxyCommand, LocalCommand and RemoteCommand apply as for plain ssh, a POSIX login shell on the remote, wait on an append-only log, start the wait before the run). Verify by: the bg_lint test and a docstring test. Source: ticket:GoodQA goodqa#15565
- AC-10: `--from-offset N` (an integer 0 to 2^50, not combinable with `--include-existing`) starts the examined position at N, so a line written between the caller's size reading and the wait's first poll is found. Verify by: tests. Source: ticket:GoodQA goodqa#15565
- AC-11: `--timeout` bounds the WHOLE wait, ssh time included. One monotonic deadline is passed into every attempt; each attempt is cut at the smaller of 30 s and the remaining budget; no retry starts when no budget is left; a result (a match included) that arrives after the deadline is not accepted, the wait ends TIMEOUT. Verify by: tests with a slow attempt, a retry that would exhaust the budget, and a match arriving late. Source: ticket:GoodQA goodqa#15565
- AC-12: the ssh capture is bounded in bytes: both streams are read with a hard cap (stdout 64 KiB plus the size line, stderr 2000 bytes), never buffered whole. On overflow the process is stopped and reaped (no zombie), and the poll ends UNPROVEN (stdout) or counts as a failed connection (stderr), never a match. Verify by: stub ssh programs that flood stdout, flood stderr, and hang, asserting the bytes read, a prompt return and that the process is gone. Source: ticket:GoodQA goodqa#15565
- AC-13: the real template, run in a local POSIX sh, gives exit 10 for a missing file, 11 for a directory, and for a normal read the size line, the bytes and marker `__bgjob_rc=0`; a failing `tail` (a partial read) shows in the marker and ends UNPROVEN. Verify by: tests running the template in /bin/sh with a missing file, a directory, a normal file, a file over 64 KiB, and a fake failing `tail` on PATH. Source: ticket:GoodQA goodqa#15565

## Negative cases

- NEG-1 (AC-3): host `-oProxyCommand=touch /x`, `-F/etc/passwd`, `h ost`, `h;id`, `a@b@c`, empty, 100 characters. Expected: exit 64, no ssh call. Source: inferred: from ticket:GoodQA goodqa#15565 -- option injection through the host word
- NEG-2 (AC-2, AC-3): file `x; touch /tmp/pwn`, `$(id)`, `` `id` ``, `a\nb`, `a\0b`, 513 characters, `-rf`, `~/logs/x`. Expected: control characters, length and a leading tilde are refused; the others reach ssh only as one shell-quoted word after the template's fixed words (the test asserts the exact remote string). Source: inferred: from ticket:GoodQA goodqa#15565 -- command injection through the path, and a silent never-found tilde path
- NEG-3 (AC-1): the remote file already contains TEXT before the first poll. Expected: the wait does NOT end (D2); with `--include-existing` it does. TEXT split across two polls matches; TEXT beyond a truncation reset is judged on the new content. Source: inferred: from ticket:GoodQA goodqa#15565 -- an appended log holds the earlier run's result
- NEG-4 (AC-1): remote output is huge, binary or contains instructions. Expected: nothing from it is printed; the read is bounded by `head -c` remotely and a 64 KiB local capture cap. Source: inferred: from ticket:GoodQA goodqa#15565 -- remote data is untrusted data
- NEG-5 (AC-6): ssh hangs. Expected: the 30 s per-call bound ends it, counted as an infrastructure failure; the overall timeout still bounds the wait. Source: inferred: from ticket:GoodQA goodqa#15565 -- resource limits
- NEG-6 (AC-6): a reset that succeeds on the retry. Expected: no INFRA, the wait goes on. Source: ticket:GoodQA goodqa#15565
- NEG-7 (AC-3): `--timeout` missing, 0, negative, NaN, 100000; `--poll` outside 0.05 to 60; `--max-infra-polls` 0 or 21. Expected: exit 64. Source: inferred: from ticket:GoodQA goodqa#15565 -- an unbounded or NaN timeout would let a waiter sit for ever, the item 8 failure
- NEG-8 (AC-8): a job that exited 255 for a reason that is not ssh. Expected: with `--ssh-job` it is reported as INFRA (the caller asked for ssh semantics, and EXIT_STATUS=255 stays visible); without the flag nothing changes. Source: inferred: from ticket:GoodQA goodqa#15565 -- opt-in semantics
- NEG-9 (AC-2): ssh binary override. Expected: the CLI offers no way to change the ssh binary or add ssh options; tests replace the module constant only. Source: inferred: from ticket:GoodQA goodqa#15565 -- no caller-supplied program
- NEG-10 (AC-4): `--file .config/goodqa/user-token`, a `gq-browser` key path, `.ssh/id_ed25519`, the absolute form under the remote home, `.kube/config`, `/home/u/.aws/credentials`, and a home-anchored protected path. Expected: exit 64 before any ssh call, with the guard's reason. Source: inferred: from ticket:GoodQA goodqa#15565 -- the substring oracle over a secret file
- NEG-11 (AC-5): the file is a directory or unreadable (remote exit 11). Expected: UNPROVEN, exit 2, quickly, not a timeout. Source: inferred: from ticket:GoodQA goodqa#15565 -- an error must not wait out the timeout
- NEG-12 (AC-6): ssh prints `Permission denied (publickey)`, `Host key verification failed` (also as a multi-line changed-key banner with a `Warning: Permanently added` line first and the failure line near the end) or `Could not resolve hostname` with exit 255. Expected: UNPROVEN exit 2 with the bounded line, no retry, not INFRA. Source: inferred: from ticket:GoodQA goodqa#15565 -- an auth or host-key problem is not a transient reset
- NEG-13 (AC-1): the text sits at byte 70000 of one burst of new bytes (and in the middle of a 200 KiB burst). Expected: found within a few polls, none of the burst skipped. Source: inferred: from ticket:GoodQA goodqa#15565 -- an offset taken from the reported size would skip bytes past the read cap
- NEG-14 (AC-1): more than 64 KiB arrives between two polls with the fail line early and the text late. Expected: exit 1 (FAIL_LINE_FOUND), not 0. Source: inferred: from ticket:GoodQA goodqa#15565 -- a skipped middle would turn a failed run into a pass
- NEG-15 (AC-2): the file is created between polls with the text already in it (connection failures, then absent, then created): found, the baseline is 0 until a successful read of an existing file. Connection failures, then an existing file that already holds the line: treated as pre-existing (the code cannot tell a line written while the link was down from an earlier run's), so the default times out; the documented patterns are `--include-existing` for a fresh log or `--from-offset`. Source: inferred: from ticket:GoodQA goodqa#15565 -- a silent wait to timeout while the line is present
- NEG-16 (AC-10): the run writes its line between the caller's size reading and the first poll. Expected: found with `--from-offset`; without it (default) the line is before the baseline and the wait times out, which AC-9 documents. Source: inferred: from ticket:GoodQA goodqa#15565 -- the launch-then-wait race
- NEG-17 (AC-2): a banner line before the size, an empty output, or a garbled size. Expected: UNPROVEN, exit 2, no reset and no re-read of the file. Source: inferred: from ticket:GoodQA goodqa#15565 -- remote noise must not reset the position and match an earlier run
- NEG-18 (AC-11): the first attempt fails slowly (1.3 s) with a 1 s timeout. Expected: no retry, TIMEOUT within a few seconds. Source: inferred: from ticket:GoodQA goodqa#15565 -- a retry past the deadline breaks the bound
- NEG-19 (AC-11): the remote answers with the awaited line after the deadline. Expected: TIMEOUT, not LINE_FOUND. Source: inferred: from ticket:GoodQA goodqa#15565 -- a late result must not be accepted
- NEG-20 (AC-12): the remote (or a banner) floods stdout or stderr. Expected: capture stops at the cap, the process is stopped and reaped, exit 2 (stdout) or a failed connection (stderr), memory stays bounded. Source: inferred: from ticket:GoodQA goodqa#15565 -- an unbounded buffer is a resource exhaustion
- NEG-21 (AC-13): `tail` fails after printing some bytes, or the marker is missing. Expected: UNPROVEN exit 2, never a match on the partial data. Source: inferred: from ticket:GoodQA goodqa#15565 -- the pipeline would otherwise hide the read failure

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

- A caller waits on a remote file that another process rewrites: only appended bytes are read (a shrink resets the offset), so a line written and then truncated between polls can be missed; mitigation: the doc says to wait on an append-only log and to start the wait before the run.
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
Domain-gate: remote-exec-audit waived (the remote command is a fixed read-only template; no caller-supplied remote command is run, see D1; the file argument is judged by command_guard, AC-4)
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

## Reviews

Spec core sha256: `6cf8696a92f3196d8ea6562080f040d3efdf98e1c8670159af7b3ca7f21ee2cc`

| Role | Verdict | Reviewer | Kind | Source | Bound to |
|---|---|---|---|---|---|
| adversarial | ACCEPT | a0c568dfa08e7eb86 (red-team) | agent | WAL-verified red-team agent | current |
| acceptance | ACCEPT | a5d878417503c1093 (red-team) | agent | WAL-verified red-team agent | current |
