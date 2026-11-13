# Spec: remove-worktree can never succeed on t2-dev (uninspectable sd-pam and sg-docker processes)

Ticket: GoodQA goodqa#15870
Author: agent:af9e33704216a1ea1 (claude-sonnet-5-5)
Click-test: not-applicable (a CLI verifier with no UI; the proof is the real run of `ah worktree-remove` on t2-dev against a clean pushed worktree after install, recorded by main)
Sign-off: main
Review-policy: standard

## Outcome

`command_guard.py remove-worktree` (and `ah worktree-remove`) removes a clean, pushed, registered linked worktree on t2-dev while the user's systemd sd-pam helpers, tailscaled session helpers and the long-lived `sg docker` pgpool client keep running, instead of refusing every worktree with "N process(es) of this user cannot be inspected". A process that really uses the worktree still blocks, and every process that was skipped is named in the result. The refusal for ignored files lists the offending paths.

## Scope

- In: harness/hooks/command_guard.py `busy_scan`, a classifier for an unreadable same-user process (`unreadable_verdict`), `verify_worktree` (the skipped list), the ignored-file refusal text (two sites); harness/hooks/ah_worktree.py passes the skipped list into the audit row and the answer; tests; a mutant script.
- Out: other users' processes (still skipped, as before), open files other than the working directory (a stated limit of the scan, unchanged), the removal itself, any change to which worktrees are removable, the hook form of the rule (only the verifier's scan is changed, and the hook form shares `busy_scan` so its behaviour for the same processes follows).

## Assumptions (labelled; none is a user decision)

- D1 The cwd of a setgid or privilege-separation helper cannot be read by the same user, and no other tool (lsof, fuser) can read it either, so "judged from the worktree side" means: what ties the unreadable process to this worktree. Evidence used: its readable command line, its name class, and its start time against the worktree creation time. Source: ticket:GoodQA goodqa#15870
- D2 An unreadable same-user process is judged in this order. (a) The scanner's own ancestors (the caller's session, on t2-dev an unreadable `tailscaled be-child` whose command line carries the very command being run) are skipped and reported. (b) Its command line cannot be read: refuse. (c) Its command line names the worktree: refuse. (d) A shell, editor or interpreter (bash, python3, node, vim, make, git, tmux and similar; they may sit in a working directory whatever their start time): refuse. (e) A known long-lived helper whose name AND command line agree (`(sd-pam)`, `systemd --user`, `ssh-agent`, `gpg-agent --supervised`, `tailscaled be-child`, and the harness's pgpool test client `docker run ... --label pgpool.tool=`): skipped whatever its start time. (f) Every other process (a wrapper such as sg, an agent CLI, pytest, a compiler, a renamed node app, a headless browser, any docker client): by time, because it cannot have been launched from the worktree before the worktree existed, so one that started BEFORE the worktree was created is skipped and reported, and one that started after it, or whose start time or the worktree creation time is unknown, refuses. Source: inferred: from ticket:GoodQA goodqa#15870 -- "ignore unreadable processes whose cwd or exe can't be in the worktree, and say which were skipped".
- D3 The worktree creation time is the modification time of its `.git` file (written once by `git worktree add`). Source: inferred: from ticket:GoodQA goodqa#15870 -- a process that started before the worktree existed cannot have been launched from it.
- D4 This deliberately loosens the earlier rule of PR 214 (receipt r1 F1), which refused every unreadable docker client, tailscaled, gpg-agent and sd-pam process: that rule made the verifier unusable on t2-dev (the 2026-11-13 release was blocked on disk space) and the removed worktree is clean and published, so the worst case of a skipped process that still uses it is a deleted working directory under that process; a live WRITER that the rules fail to tie to the worktree could lose what it writes after the cleanliness check, which is why every program that started after the worktree was created refuses (D2 f) and only known helpers and programs older than the worktree are skipped. Decision source: main's instruction for this ticket. Source: ticket:GoodQA goodqa#15870

## Acceptance criteria

- AC-1: with the real t2-dev unreadable set (two sd-pam, tailscaled session helpers, the pgpool docker client started before the worktree, gpg-agent, a chrome helper) the scan reports no busy and no unreadable process and lists all of them as skipped; `verify_worktree` returns removable true with `skipped_processes` naming them. Verify by: `python3 -B -m unittest tests.test_worktree_inuse`. Source: ticket:GoodQA goodqa#15870
- AC-2: a process whose cwd is readable and inside the worktree still blocks removal, whatever else is skipped. Verify by: the same suite. Source: ticket:GoodQA goodqa#15870
- AC-3: an unreadable process still blocks when its command line names the worktree, when it is a shell, editor or interpreter (even if it started before the worktree), when it is any other program (a wrapper such as sg, an agent CLI, pytest, a compiler, a docker client without the pgpool label) that started after the worktree was created, and when a start time, the creation time or the command line is unknown; the real sg parent of the pgpool client and the known helpers are skipped; the scanner's own ancestors never block. Verify by: the same suite. Source: inferred: from ticket:GoodQA goodqa#15870 -- see D2: the unreadable-process rule and its reasons.
- AC-4: the refusal "it holds an ignored file or folder that is not a whole regenerable build directory" lists up to five offending paths and a count of the rest, printable ASCII, bounded. Verify by: the same suite. Source: ticket:GoodQA goodqa#15870
- AC-5: `ah worktree-remove` carries `skipped_processes` into its audit row and its answer. Verify by: `python3 -B -m unittest tests.test_ah_worktree_remove tests.test_worktree_hooks_rule`. Source: ticket:GoodQA goodqa#15870
- AC-6: the guard suites that share these code paths still pass. Verify by: `python3 -B -m unittest tests.test_command_guard tests.test_command_guard_owned_checkout tests.test_command_guard_no_backup`. Source: inferred: from ticket:GoodQA goodqa#15870 -- the shared scan must keep its other behaviour.

## Negative cases

- NEG-1 (AC-2): a node process with its cwd inside the worktree blocks removal even while four unreadable helpers are skipped. Source: ticket:GoodQA goodqa#15870
- NEG-2 (AC-3): an unreadable `docker compose -f the-worktree-path/compose.yml up` blocks. Source: inferred: from ticket:GoodQA goodqa#15870 -- see D2 (a): the command line ties it to the worktree.
- NEG-3 (AC-3): an unreadable bash, python3, node, vim, git, make or tmux blocks even when it started before the worktree (an interactive shell run through sg is the real finding of goodqa#15739; the shell child of an sg wrapper has a readable cwd and is checked directly). Source: inferred: from ticket:GoodQA goodqa#15870 -- see D2 (b): a shell may sit in the worktree.
- NEG-4 (AC-3): an unreadable sg wrapper, docker client, agent CLI, pytest, compiler or headless browser that started after the worktree was created blocks, and one that started before it is skipped and reported. Source: inferred: from ticket:GoodQA goodqa#15870 -- see D2 (c): a client started after the worktree may use it.
- NEG-5 (AC-3): unknown start time, unknown creation time or an unreadable command line fail closed. Source: inferred: from ticket:GoodQA goodqa#15870 -- see D2 (c) and (d): unknown evidence fails closed.
- NEG-6 (AC-1, AC-2): failing-first: the new suite fails against origin/main and against each broken variant (tests/mutants_worktree_inuse.py: unreadable always blocks, always skipped, command line ignored, shells skipped, start time ignored, unknown times skipped, skipped not reported, readable cwd ignored, ignored paths not listed, creation time unreadable). Source: ticket:GoodQA goodqa#15870
- NEG-7 (AC-1): another user's unreadable process stays skipped and a same-user process whose real uid cannot be read still fails the scan closed (the earlier cases of the existing suites). Source: inferred: from ticket:GoodQA goodqa#15870 -- unchanged behaviour.

## Resource budget

Host: mac
Fan-out: agents=2 jobs=1 processes=1 browser_pages=0 test_workers=1
Peak memory: 0.3 GB (method: a unittest process with small temporary git repositories)
CPU: 1 core (method: single-threaded unittest)
Disk: 0.05 GB (method: a few temporary repositories)
Network: 0 MB (method: none; the live check on t2-dev is main's)
Wall time: 5 min
Cap and kill: none needed (short focused tests)
Checkpoint: not required (under 10 min and 4 GB)

## Risks

- A skipped process may still have the worktree as its working directory (its name or command line can be set by the process, and a setgid helper's cwd cannot be read): stated limit, accident prevention and not an access control; the worktree is clean and published, so the effect is a deleted working directory under that process. Skipped processes are always listed in the result and the audit row.
- A program that started after the worktree was created but never used it still blocks (conservative); the operator lets it end. On t2-dev a worktree OLDER than a long-lived unreadable process that is not a known helper (for example a browser started after it) is refused until that process ends.
- The worktree creation time is the `.git` file's mtime: `git worktree repair` and `git worktree move` rewrite it and `cp -a` or `rsync -t` of a worktree preserves an old one, either of which skews "created" (stated limit). A command line that names the worktree by a relative path, and a name or command line set by the process itself, are missed (accident prevention, not an access control).
- Review history: the first draft skipped any unreadable process whose name was not on a deny list; the independent review showed that the real sg parent of the pgpool client would block every worktree, that the caller's own tailscaled session ancestor would block `ssh t2-dev remove-worktree`, and that a deny list would skip an agent CLI or pytest started in the worktree (a live writer); the order above is the result.
- Time-based reasoning: the worktree creation time is the `.git` file's mtime; a clock change or a restored file could mislead it; unknown values fail closed.
- The real /proc readers run only on Linux; the Mac suite covers them with a faked /proc and the live run on t2-dev is main's proof.

## Domain checklist

Domains: auth, delete, devices, money, release

The change loosens one safety refusal of a worktree removal tool and adds a report; the removal still requires a clean, published, registered linked worktree and the same audit. It adds no authentication, account, device, money or release behaviour.

Domain-gate: pre-account-hijack waived (no authentication flow is added or changed; only the process scan of a worktree removal and a report change)
Domain-gate: lookalike-identifier waived (no identifier handling is involved)
Domain-gate: request-device-binding waived (no approval or login flow is involved)
Domain-gate: link-expiry-single-use waived (no link or token is issued or consumed)
Domain-gate: session-fixation waived (no session handling is touched)
Domain-gate: rate-limit-enumeration waived (no account lookup or response text for an account is involved)
Domain-gate: store-billing-exposure waived (no account state or billing is touched)
Domain-gate: backup-before-delete waived (unchanged: the verifier still requires the HEAD to be live on an allowlisted remote, so the commits are the verified copy; this change touches only the process scan)
Domain-gate: unpushed-work-detection waived (unchanged: the verifier still refuses unpushed commits, stashes, dirty or untracked files before any removal; this change touches the process scan and one message)
Domain-gate: dry-run-diff waived (unchanged: verify-worktree is the read-only preview and remove-worktree acts on the same verified path and head)
Domain-gate: scope-pinning waived (unchanged: one literal absolute path, directory identity compared before and after, HEAD pinned with expect_head)
Domain-gate: cross-host-approval-portability waived (unchanged: no approval is involved; the verifier runs on the host that owns the worktree)
Domain-gate: idempotent-retry waived (unchanged: a rerun of a removed worktree is refused as missing; this change adds no state)
Domain-gate: device-identity-binding waived (no device enrollment or grant is touched)
Domain-gate: unattended-recovery waived (the tool removes nothing without a clean verified worktree and recovery is unchanged)
Domain-gate: grant-durability waived (no grant or approval is created)
Domain-gate: remote-exec-audit waived (unchanged: the removal is audited on the host and the skipped processes are now added to the audit row)
Domain-gate: factory-reset-guard waived (no wipe or unenroll path is involved)
Domain-gate: idempotency-key waived (no money movement is involved)
Domain-gate: double-submit waived (no money flow or form is involved)
Domain-gate: currency-precision waived (no amounts are involved)
Domain-gate: refund-reversal-path waived (no money movement is involved)
Domain-gate: ledger-reconciliation waived (no ledger is involved)
Domain-gate: authorization-vs-capture waived (no payment is involved)
Domain-gate: derived-gate-floor-with-ratchet waived (no release gate is changed)
Domain-gate: artifact-inventory-mirrored waived (no signed artifact is produced)
Domain-gate: self-update-e2e waived (the install is the normal harness batch install with ah install-files)
Domain-gate: transport-proof waived (no integration transport is added)
Domain-gate: rollback-not-blocked waived (no release or rollback path is touched)
Domain-gate: staging-exists waived (a local verifier change; the real run on t2-dev is main's live proof)
