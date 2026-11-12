# Spec: Sanctioned audited remote hook install: ah install-files --host

Ticket: GoodQA goodqa#15742
Author: agent:af9e33704216a1ea1 (Sonnet 5.5)
Click-test: required
Sign-off: main
Review-policy: standard

## Outcome

A merged hook file can be installed on a remote host (t2-dev, ah-mac-mini) through one audited command, `ah install-files --host HOST --repo PATH --from-ref SHA --file NAME [--file NAME ...] [--ticket GoodQA project#N] [--dry-run]` (and undone with `ah install-files --host HOST --rollback RUN_ID`), that takes the bytes from a git commit, backs up what is there, replaces each file atomically, reads its sha256 back, compares the host's own self-test before and after, rolls back automatically when the result is worse, and writes an audit row on both ends, so a remote install no longer needs a hand-typed `cp`, `mv` or `scp` into a guarded path (the 2026-11-11 t2-dev install of command_guard.py was blocked as `cp` and then done with `scp`, a second route around a guard).

## Scope

- In: a new module `harness/hooks/ah_install.py`, an `ah install-files` subcommand in `ah.py`, the module added to both installer file lists; the bytes come from `git cat-file blob SHA:harness/hooks/NAME` in a local repository, SHA a full 40-hex commit that is an ancestor of that repository's `origin/main` (merged code only); names only from the installer's own `HOOKS` tuple at that commit (read with `ast`, never imported); hosts only from the allowlist `t2-dev` and `ah-mac-mini` (ASSUMPTION A1: dev2 is gone after the pve shutdown); the remote home is `~/.claude/hooks` on the host; transport is `ssh -o BatchMode=yes` running a constant, fixed remote program (`python3 -I -c SCRIPT OP ARGS`, the script text is part of this module, never caller-supplied) with the file bytes on stdin; a `--dry-run` that prints the plan (host, files, old and new sha256 as the host reports them) and changes nothing on the host; `--rollback RUN_ID` restoring the backups the Mac audit row of that run names.
- Out: the Mac itself (`install.py` and the selective installers stay the route there); the Codex home on remote hosts; `settings.json` and `CLAUDE.md` edits; any name outside the installer list; any caller-chosen path or bytes; any change to a guard (the command runs in process, the guards cannot see it; ASSUMPTION A2: any caller may run it, the calling agent id is in every audit row, main may restrict it later); any automatic run from a hook; Windows hosts.
- Decisions (owner assumptions, none is a user decision): A1 host allowlist; A2 not restricted to main; A3 the self-test is `python3 -I ~/.claude/hooks/command_guard.py check "ls -la"` (allow expected) and `python3 -I ~/.claude/hooks/doctor.py check --json --no-canary` on the host (the failing checks are the findings whose status is not WIRED), because those are the host's own existing checks.

## Acceptance criteria

- AC-1: For each requested file the command (a) reads the host's current sha256 (absent is allowed), (b) when the file exists copies it to `NAME.bak-pre-SHA8` on the host (SHA8 the first eight hex of the NEW content sha256) and keeps a copy of the old bytes in the caller's own `~/.agent-harness/install-backups/RUN_ID/`, (c) uploads the new bytes to the temporary name `.NAME.ah-install-tmp` in the same directory, created exclusively with mode 0600, over ssh stdin, (d) compares the sha256 of the temporary file with the sha256 of the git blob, (e) sets the live file's mode (the old file's, else 0644) and renames the temporary file over the live name atomically and fsyncs the directory, (f) reads the sha256 of the live file back, and reports old sha, new sha and backup name per file. Verify by: `python3 -B -m unittest tests.test_ah_install` (a fake ssh runner that runs the constant remote script against a temporary HOME). Source: ticket:GoodQA goodqa#15742
- AC-2: The host self-test runs before any write and again after the last rename: the `command_guard.py check` verdict and exit code, and the set of failing checks of `doctor.py check --json`; after an install the verdict must be unchanged and the failing set a subset of the failing set before; anything else (a new failing check, a changed verdict, a non-zero exit, a self-test that cannot run) rolls EVERY file of this run back from its backup (a file that did not exist before is removed by its fixed temporary-style name only), reads the shas back, and reports ROLLED_BACK with the reason; a self-test that cannot run BEFORE any write refuses the run. Verify by: the same suite with a fake host whose self-test degrades, one that already fails some checks (the baseline), and one that cannot run. Source: ticket:GoodQA goodqa#15742
- AC-3: Only these inputs are accepted, all checked before any ssh call: `--host` in the allowlist; `--repo` an existing git repository; `--from-ref` a full 40-hex lowercase commit sha that exists and is an ancestor of `origin/main`; each `--file` a bare name (letters, digits, `_`, `-`, `.`, no slash, no dot segment, no leading dot) listed in `HOOKS` at that commit and present as a blob at `harness/hooks/NAME`; no duplicate name; between 1 and 20 names; the blob at most 4 MiB; optional `--ticket` of the form `GoodQA project#N`; `--rollback RUN_ID` of the form `ins-` plus 12 hex. Everything else refuses with exit 2 and a named reason. Verify by: the same suite, one subtest per bad input. Source: ticket:GoodQA goodqa#15742
- AC-4: An audit row is appended to the Mac's `~/.agent-harness/install-audit.jsonl` and fsynced BEFORE the first remote write (start: run id, host, repo, ref, files, new sha256s, old shas, caller session and agent) and after the run (result: installed, rolled_back, refused, already_current or unknown, per file old and new sha and backup name); a failed Mac audit write stops the run before any ssh write; one row is appended to `~/.agent-harness/install-audit.jsonl` on the host at the end of a run that wrote anything (best effort: a failure there is reported, not fatal); the result is `unknown` whenever the outcome of a remote step cannot be known (a lost answer after the first remote write, the same rule as `ah worktree-remove`), never installed or refused, with the host named; with `--ticket` one comment is posted naming the ref, the files and the shas (a failure to post is reported, not fatal). Verify by: the same suite. Source: ticket:GoodQA goodqa#15742
- AC-5: Unattended safety: a rerun with the same ref and files is a no-op per file (the live sha equals the new sha: already_current, no backup, no write); two runs on the same host cannot interleave (a lock directory `.ah-install-lock` in the hooks directory created with `mkdir`, holding the run id, older than 10 minutes treated as stale and replaced with a note in the result, released only by its own run id and in every path); an interrupted upload leaves only the fixed temporary name which the next run replaces; an existing temporary name that is not a regular file refuses the file. Verify by: the same suite (rerun, two runs, stale and fresh lock, interrupted upload, collision). Source: ticket:GoodQA goodqa#15742
- AC-6: `--dry-run` validates every input exactly as a real run, reads the host's current sha256 of each file and the self-test baseline over ssh (read-only operations only), prints the plan per file (new, replaced or already_current, old sha, new sha, the backup name it would use), writes only a `dry_run` audit row on the Mac, and changes nothing on the host (the host's hooks directory listing, sizes, mtimes and inodes are identical before and after). Verify by: the same suite. Source: ticket:GoodQA goodqa#15742
- AC-7: `--rollback RUN_ID` restores, for the files of that run in the Mac audit row, each backup onto its live name by the same temporary-name, sha-check and atomic-rename steps, only when the backup's sha256 equals the old sha the row recorded, then runs the self-test and writes its own audit rows; it is never blocked by a failing self-test (it reports the result instead), and a file that was newly created by the run is removed by its fixed name only. Verify by: the same suite (rollback after a good install, after a degraded one, with a tampered backup). Source: ticket:GoodQA goodqa#15742
- AC-8: Real proof by main on t2-dev at a merged ref: `--dry-run` for the files of a merged PR, then the real install, with the before and after shas, the self-test results, the audit rows on both ends and the ticket comment saved under the work directory, then `--rollback RUN_ID` of that run (restoring the old files, self-test compared) and a second real install of the same ref (restoring the new ones), each with its saved output; the live hooks directory ends at the new shas. The owner types no scp, cp or mv. Verify by: the saved outputs. Source: ticket:GoodQA goodqa#15742

## Negative cases

- NEG-1 (AC-3): a host outside the allowlist, a shell metacharacter or a leading dash in the host, a ref that is a branch name, an abbreviated or uppercase sha, a sha that is not an ancestor of origin/main, a name with a slash or `..` or a leading dot, a name not in the installer list at that ref, a duplicate name, more than 20 names, an empty list, an oversized blob, a malformed ticket and a malformed run id must all refuse before any ssh call. Source: ticket:GoodQA goodqa#15742
- NEG-2 (AC-1): a wrong upload (the remote sha256 differs from the blob) leaves the live file untouched and removes the temporary file; a read-back sha that differs after the rename rolls the run back. Source: ticket:GoodQA goodqa#15742
- NEG-3 (AC-1): the live target is a symlink or a directory, the temporary name exists as a symlink or directory, or the backup name already holds different bytes: refuse that file, so the run, without writing anything for it. Source: ticket:GoodQA goodqa#15742
- NEG-4 (AC-2): the self-test before the install already fails some checks (as on t2-dev, where Codex files are missing): that baseline is recorded and only NEW failures count. Source: ticket:GoodQA goodqa#15742
- NEG-5 (AC-2): after a rollback the live sha equals the old sha for every file of the run, including files already replaced earlier in the same run, and the lock is released. Source: ticket:GoodQA goodqa#15742
- NEG-6 (AC-4): a lost ssh answer after the first remote write is recorded as unknown with the host named; a lost answer before any write is recorded as refused (nothing was written); the Mac audit write failing stops the run before any ssh write. Source: ticket:GoodQA goodqa#15742
- NEG-7 (AC-5): a lock younger than 10 minutes refuses the run; an older one is replaced and said so; nothing is ever deleted but this lock by its fixed name and run id. Source: ticket:GoodQA goodqa#15742
- NEG-8 (AC-6): a dry run changes nothing on the host (listing, sizes, mtimes, inodes) and creates no lock. Source: ticket:GoodQA goodqa#15742
- NEG-9 (AC-7): a backup whose sha256 differs from the recorded old sha is refused, not restored; an unknown run id, a run of another host and a run already rolled back refuse. Source: ticket:GoodQA goodqa#15742
- NEG-10 (AC-1): the file bytes never come from a caller path: a worktree edit of the same name, an unmerged commit and a name outside the list change nothing about what is uploaded or refuse. Source: ticket:GoodQA goodqa#15742
- NEG-11 (AC-8): no scp, cp or mv is typed for this install and no file outside the installer list is written on the host. Source: ticket:GoodQA goodqa#15742

Domain-gate: backup-before-delete waived (covered by AC-1 and AC-7: every replaced file is backed up on the host and in the caller's directory with its sha256 before anything is written, NEG-3 and NEG-9 pin refusal on a bad or mismatched backup, and the only file the tool ever removes is a temporary or newly created file by its fixed name)
Domain-gate: unpushed-work-detection waived (no checkout, worktree or branch is removed; the source is a merged commit, AC-3)
Domain-gate: dry-run-diff waived (covered by AC-6 and NEG-8: the dry run prints the exact plan and a real run acts on the same validated inputs)
Domain-gate: scope-pinning waived (covered by AC-3, AC-5 and NEG-1: the tool writes only names from the installer list inside one fixed directory, by fixed temporary and backup names, never a glob or caller path, and refuses a symlink or directory at any target)
Domain-gate: cross-host-approval-portability waived (no approval is involved: the host is an argument checked against an allowlist and every row names the host)
Domain-gate: idempotent-retry waived (covered by AC-5: a rerun is a no-op per file, an interrupted run leaves only fixed temporary names, and a lock is stale after ten minutes)
Domain-gate: pre-account-hijack waived (no authentication or account flow is involved)
Domain-gate: lookalike-identifier waived (no accounts are involved; host names are matched exactly against the allowlist, NEG-1)
Domain-gate: request-device-binding waived (no login or approval link is involved)
Domain-gate: link-expiry-single-use waived (no emailed link or token is involved)
Domain-gate: session-fixation waived (no sessions are involved)
Domain-gate: rate-limit-enumeration waived (no account lookup is involved)
Domain-gate: store-billing-exposure waived (no billing or entitlement is involved)
Domain-gate: device-identity-binding waived (the host identity is the ssh host key checked by the operator's own ssh configuration with BatchMode; the tool adds only an allowlist of names and records the host in every row)
Domain-gate: unattended-recovery waived (covered by AC-2 and AC-5: a bad install rolls back automatically with nobody present, a stale lock is replaced, and BatchMode means no prompt can block)
Domain-gate: grant-durability waived (no grants or approvals are involved)
Domain-gate: remote-exec-audit waived (covered by AC-4: an audit row on the Mac before the first remote write and after the run, one on the host, the actor and agent recorded, no secret in any row)
Domain-gate: factory-reset-guard waived (no device wipe or unenroll is involved)
Domain-gate: idempotency-key waived (no money movement is involved)
Domain-gate: double-submit waived (no money movement or form is involved; two concurrent runs are handled by the lock, AC-5)
Domain-gate: currency-precision waived (no amounts are involved)
Domain-gate: refund-reversal-path waived (no money movement is involved)
Domain-gate: ledger-reconciliation waived (no ledger is involved)
Domain-gate: authorization-vs-capture waived (no payments are involved)
Domain-gate: derived-gate-floor-with-ratchet waived (no release gate or count floor is involved)
Domain-gate: artifact-inventory-mirrored waived (no signed artifact is built; the old bytes are kept on the host and on the Mac)
Domain-gate: self-update-e2e waived (this tool installs the hook files, it is not an updater of itself; AC-8 is the real run on t2-dev)
Domain-gate: transport-proof waived (covered by AC-8: the real transport, ssh to t2-dev with the constant remote script, is exercised by main with saved output, and the unit suite runs the same script through a fake runner)
Domain-gate: rollback-not-blocked waived (covered by AC-7: the manual rollback runs whatever the self-test says and only reports its result)
Domain-gate: staging-exists waived (the rehearsal is the dry run of AC-6 and the rollback on a disposable HOME in AC-8 before main installs on the live hooks directory)

## Resource budget

Host: mac
Fan-out: agents=2 jobs=1 processes=4 browser_pages=0 test_workers=1
Peak memory: 0.3 GB (method: unit tests with a fake ssh runner on a temporary directory)
CPU: 2 cores (method: the suite takes under a minute)
Disk: 0.05 GB (method: temporary directories; a real install writes a few hook files and their backups of about 0.4 MB each)
Network: 5 MB (method: ssh with the file bytes on stdin, a handful of short calls)
Wall time: 180 min
Cap and kill: foreground; each ssh call has a timeout and a failure after the first remote write is recorded as unknown, never retried silently
Checkpoint: not required (under 10 min per step); every step is idempotent (a rerun with the same ref is a no-op per file) and a run resumes by being rerun, with the audit rows as the record

## Risks

- A remote overwrite of a guard or hook file can break the host guard: mitigation, backup first, atomic rename, sha read-back, the host's own self-test compared with its baseline, automatic rollback, names only from the installer list, merged code only.
- The command becomes a way around the Mac guard that protects hook paths: mitigation, it can install only merged, listed files from a git commit (no caller-chosen path or bytes), it is audited on both ends with the caller recorded, and the Mac guard still refuses hand-typed cp, mv and scp into those paths; ASSUMPTION A2 (any caller may run it) is for main to confirm or restrict.
- A lost connection leaves a half state: mitigation, the outcome is unknown and named, the backup and the fixed temporary name are recoverable, and a rerun finishes or rolls back.
- The constant remote script is code that runs on the host: mitigation, it is part of this module (reviewed, hashed in the audit row), never built from caller input, takes only validated arguments, and runs with `python3 -I`.
- A stale local origin/main could admit code that is no longer merged: mitigation, stated limit; the audit row records the sha and main's checkout is the repository used.
