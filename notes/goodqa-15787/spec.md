# Spec: command_guard: refuse bulk staging in a shared original checkout

Ticket: GoodQA goodqa#15787
Author: agent:af9e33704216a1ea1 (claude-sonnet-5-5)
Click-test: not-applicable (a command-text guard rule with no UI; the proof is the real guard decision on the commands in the tests, plus one live Bash call by main after install)
Sign-off: main
Review-policy: standard

## Outcome

In a shared original checkout (the main working tree, whose `.git` is a directory) that has uncommitted changes, an agent shell that stages or commits EVERYTHING (`git add -A`, `--all`, `.`, `:/`, `-u`, `git commit -a`) gets a finding that names the sanctioned form: stage explicit paths, or work in your own linked worktree. This stops one session from sweeping another session's uncommitted changes into its commit. The rule ships in warn mode (D2) and can be switched to enforce by policy.

## Scope

- In: `git add` and `git stage` with a tree-wide pathspec or `-A`, `--all`, `-u`, `--update`; `git commit` with `-a` or `--all` (also inside a short cluster such as `-am`); the target checkout is the one the command acts on (`-C`, `--work-tree`, `GIT_WORK_TREE`, the cwd); only when it is an original checkout with changes; `-c alias.X=...` with an unknown subcommand is judged as a possible bulk form; a new `bulk_staging` finding category with its own mode.
- Out: persistent git aliases from a config file (`git ca` for `commit -a`; the guard sees command text only), a bulk staging done by a script or another tool that speaks git itself, `git checkout .` and `git restore .` (destructive discards, a separate rule), a stash or reset (already covered by the owned-checkout rule for owned checkouts), a linked worktree (the agent's own), a clean original checkout.

## Assumptions (labelled; none is a user decision)

- D1 "Shared original checkout" = the nearest `.git` above the target directory is a directory (not a `gitdir:` file) AND `git status --porcelain` is non-empty. A clean tree sweeps nothing, so it is allowed. Source: inferred: from ticket:GoodQA goodqa#15787 -- the ticket names the original checkout and "changes the agent did not make", which the guard cannot know, so any dirt counts.
- D2 Default mode is `warn` (like broad_kill), enforceable per policy (`modes.bulk_staging`), because the ticket rates the false-positive risk medium and the guard is installed on every session. Recommendation to main: switch to enforce after the warn counts are checked. Source: inferred: from ticket:GoodQA goodqa#15787 -- "refuse or warn".
- D3 The check fails open: if the directory is not a repository, git is missing or the status call times out (2 s), nothing is reported. Source: inferred: from ticket:GoodQA goodqa#15787 -- accident prevention, not an access control.
- D4 The rule applies to every caller (main and sub-agents): the shared checkout is shared with main's own sessions too. Source: inferred: from ticket:GoodQA goodqa#15787.

## Acceptance criteria

- AC-1: in an original checkout with uncommitted changes, these commands produce a `bulk-staging` finding (a block under enforce mode, a warn in the default mode): `git add -A`, `git add --all`, `git add .`, `git add ./`, `git add -- .`, `git add :/`, `git add ':(top)'`, `git add -u`, `git add --update`, `git stage -A`, `git commit -a -m x`, `git commit -am x`, `git commit --all`, `git commit -sa -m x`, and the same behind `git -C the-original-checkout`, `--work-tree=the-original-checkout`, `GIT_WORK_TREE=the-original-checkout git ...` and a command that `cd`s into it. Verify by: `python3 -B -m unittest tests.test_command_guard_bulk_staging`. Source: ticket:GoodQA goodqa#15787
- AC-2: these stay allowed with no finding: `git add path/file`, `git add sub/dir/`, `git add sub/.`, `git add -p`, `git add -N file`, `git commit -m "fix -a"`, `git commit -m msg path`, `git commit --amend --no-edit`, any of the bulk forms in a linked worktree (a `.git` file), in a clean original checkout, in a directory that is not a repository, and with `git -C a-linked-worktree` from an original checkout cwd. Verify by: the same suite. Source: ticket:GoodQA goodqa#15787
- AC-3: `git -c alias.x='add -A' x` and any unknown subcommand behind a `-c alias.` produce the finding in a dirty original checkout; a known read subcommand behind an alias does not. Verify by: the same suite. Source: ticket:GoodQA goodqa#15787
- AC-4: the finding names the sanctioned form (stage explicit paths, or `git worktree add`) and has its own category `bulk_staging`; under `modes.bulk_staging = enforce` the decision is `block`, in the default mode `warn`; the other categories' modes are unchanged. Verify by: the same suite. Source: ticket:GoodQA goodqa#15787
- AC-5: existing guard behaviour does not change. Verify by: `python3 -B -m unittest tests.test_command_guard tests.test_command_guard_owned_checkout tests.test_command_guard_no_backup`. Source: inferred: from ticket:GoodQA goodqa#15787 -- a new rule must not alter other verdicts.

## Negative cases

- NEG-1 (AC-2): a path literally named `.` inside a subdirectory (`git add sub/.`, `git add ./sub/file`) is an explicit path and is not a tree-wide pathspec. Source: ticket:GoodQA goodqa#15787
- NEG-2 (AC-1): a `-c alias.` expansion (`git -c alias.a='add -A' a`) is judged, not skipped. Source: ticket:GoodQA goodqa#15787
- NEG-3 (AC-1, AC-2): `-C` with another directory judges THAT directory: `git -C the-original-checkout add -A` from a worktree cwd is a finding, and `git -C a-linked-worktree add -A` from the original checkout cwd is not. Source: ticket:GoodQA goodqa#15787
- NEG-4 (AC-1): pathspec magic that means the whole tree (`:/`, `:(top)`) is a finding. Source: ticket:GoodQA goodqa#15787
- NEG-5 (AC-2): `-m` and `-F` values are not read as flags: `git commit -m "-a"` and `git commit -ma` (message `a`) are allowed. Source: inferred: from ticket:GoodQA goodqa#15787 -- a message text must not trigger a refusal.
- NEG-6 (AC-1): the failing-first control: with the rule removed the new suite fails (run against the unchanged code and against broken variants in tests/mutants_bulk_staging.py). Source: ticket:GoodQA goodqa#15787
- NEG-7 (AC-1): a status call that cannot run (not a repository, git missing, timeout) reports nothing and never raises. Source: inferred: from ticket:GoodQA goodqa#15787 -- fail-open for accident prevention.

## Resource budget

Host: mac
Fan-out: agents=2 jobs=1 processes=1 browser_pages=0 test_workers=1
Peak memory: 0.3 GB (method: a unittest process with small temporary git repositories)
CPU: 1 core (method: single-threaded unittest)
Disk: 0.05 GB (method: a few temporary repositories)
Network: 0 MB (method: none)
Wall time: 5 min
Cap and kill: none needed (short focused tests; the status call has a 2 s timeout)
Checkpoint: not required (under 10 min and 4 GB)

## Risks

- A false warning or refusal on a legitimate bulk commit in a dirty original checkout: mitigation, warn by default, the sanctioned form is one explicit-path command, linked worktrees and clean trees are exempt, the allowed neighbours are pinned.
- A persistent alias, a script, or another git front end stages everything unseen: stated limit, the guard sees command text only.
- The status call runs git in a repository the caller controls: mitigation, the existing hardened helper (fsmonitor off, hooks off, sanitized environment, 2 s timeout, output bounded).
- The status call adds latency to every `git add` and `git commit`: mitigation, only for bulk forms, only once per command, bounded at 2 s.

## Domain checklist

Domains: auth, delete, devices, money, release

The change adds a command-text rule for `git add` and `git commit`; it adds no authentication, account, deletion, device, money or release behaviour.

Domain-gate: pre-account-hijack waived (no authentication flow is added or changed; one command-text rule for git add and git commit)
Domain-gate: lookalike-identifier waived (no identifier handling is involved)
Domain-gate: request-device-binding waived (no approval or login flow is involved)
Domain-gate: link-expiry-single-use waived (no link or token is issued or consumed)
Domain-gate: session-fixation waived (no session handling is touched)
Domain-gate: rate-limit-enumeration waived (no account lookup is involved)
Domain-gate: store-billing-exposure waived (no account state or billing is touched)
Domain-gate: backup-before-delete waived (nothing is deleted; the rule only refuses or warns about staging)
Domain-gate: unpushed-work-detection waived (nothing is deleted)
Domain-gate: dry-run-diff waived (nothing is deleted)
Domain-gate: scope-pinning waived (nothing is deleted)
Domain-gate: cross-host-approval-portability waived (no approval or deletion is involved)
Domain-gate: idempotent-retry waived (a stateless text rule; a rerun gives the same verdict)
Domain-gate: device-identity-binding waived (no device enrollment or grant is touched)
Domain-gate: unattended-recovery waived (a stateless text rule with nothing to recover)
Domain-gate: grant-durability waived (no grant or approval is created)
Domain-gate: remote-exec-audit waived (no remote execution is added)
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
Domain-gate: staging-exists waived (a local guard rule; a live Bash call by main after install is the real proof)
