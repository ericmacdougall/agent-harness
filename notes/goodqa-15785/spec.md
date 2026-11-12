# Spec: command_guard: block reads of GoodQA user-token and gq-browser key files

Ticket: GoodQA goodqa#15785
Author: agent:af9e33704216a1ea1 (claude-sonnet-5-5)
Click-test: not-applicable (a command-text guard rule with no UI; the proof is the real guard decision on the commands in the tests)
Sign-off: main
Review-policy: standard

## Outcome

An agent shell can no longer print the user's GoodQA user token (`~/.config/goodqa/user-token`, which acts as the user) or a minted gq-browser lease key (`~/.agent-harness/gq-browser/16-hex/key`, valid for up to 24 hours) into a transcript with cat, head, base64 and the other readers the guard already treats as secret reads. The gq-browser client keeps reading the files in-process.

## Scope

- In: two entries in `credential_path_regexes` in harness/hooks/command_guard.py; a test file; the docs line in docs/gq-browser.md and the AC-8 pin in tests/test_gq_browser.py belong to agent-harness PR 220 (O1 updates them to "command guard refuses" once this lands).
- Out: a Python script or any program that reads the file itself (the guard sees command text only; accident prevention, not an access control); other GoodQA files; changing the refusal text or the secret_dump mode.

## Acceptance criteria

- AC-1: a shell read (cat, head -c, tail, base64, strings, less, xxd, grep, sed, awk) of the user-token path or of a gq-browser `16-hex/key` path, in the forms `~/...`, `$HOME/...`, an absolute path and a quoted path, is blocked with the secret_dump rule, and so is a glob that expands to either file (`cat ~/.agent-harness/gq-browser/*/key`, `cat ~/.config/goodqa/*`, `cat ~/.config/goodqa/user-tok*`), because both paths are also credential samples; the two directories that HOLD them (`~/.config/goodqa`, `~/.agent-harness/gq-browser`, a policy list `credential_parent_dirs`) are refused to a recursive reader (grep -r, rg, ag), to a find -exec reader, to an archive (tar, zip, 7z, cpio), and to a copy tool that sends them (scp, rsync, curl), while `grep -rc` (count only), `ls`, `find -name`, `cat config.json` and the lease file stay allowed. Every block above carries the secret_dump credential rule, and the tests assert the rule id, not only the verdict. Verify by: `python3 -B -m unittest tests.test_command_guard_gq_credentials`. Source: ticket:GoodQA goodqa#15785
- AC-2: neighbouring files and non-reading commands stay allowed: `cat ~/.config/goodqa/config.json`, `ls ~/.config/goodqa`, `ls ~/.agent-harness/gq-browser`, the lease file in a key directory, a key directory whose name is not 16 hex characters, a file named `keys`, `echo user-token`, and docs that mention the name. Verify by: the same suite. Source: ticket:GoodQA goodqa#15785
- AC-3: existing credential behaviour does not change. Verify by: `python3 -B -m unittest tests.test_command_guard tests.test_command_guard_owned_checkout tests.test_command_guard_no_backup`. Source: inferred: from ticket:GoodQA goodqa#15785 -- the change adds two patterns and must not alter other verdicts.

## Negative cases

- NEG-1 (AC-1): a glob that expands to the key (`*/key`, `*/k*`) or to the token (`user-tok*`, `user-to?en`, `goodqa/*`) still blocks, and a reader with an option before the path (`head -c 5`, `sed -n 1p`) or a path spelled with `$HOME` or an absolute home still blocks. Source: ticket:GoodQA goodqa#15785
- NEG-2 (AC-2): a key directory named with fewer than 16 hex digits, a `keys` file and `user-token.md` are not credential files and stay allowed (no false refusal of ordinary docs and neighbours). Source: inferred: from ticket:GoodQA goodqa#15785 -- they anchor the exact file names.
- NEG-3 (AC-1): the broken variant with the two patterns removed fails the tests (failing-first control, run against the unchanged code: 26 failures). Source: ticket:GoodQA goodqa#15785

## Resource budget

Host: mac
Fan-out: agents=2 jobs=1 processes=1 browser_pages=0 test_workers=1
Peak memory: 0.3 GB (method: a unittest process)
CPU: 1 core (method: single-threaded unittest)
Disk: 0.01 GB (method: source and tests only)
Network: 0 MB (method: none)
Wall time: 5 min
Cap and kill: none needed (short focused tests; no heavy step)
Checkpoint: not required (under 10 min and 4 GB)

## Risks

- A program reads the token by a path the text rule cannot see (a script, a variable in the path): stated limit, the guard sees command text only; the sanctioned reader is the in-process client.
- Stated limits of a text guard, the same as for the existing credential files: `cp -r` of either directory to a readable place and a later read of the copy in another command (a copy is not a print), `cp` of the file to a readable name and a later `cat` of the copy in another command, `export TOK=$(cat F)` and a later `echo $TOK`, an archive of the directory piped to a reader, and a glob inside a key directory whose 16-hex name the agent already knows (`cat .../0123456789abcdef/*`). `ls ~/.agent-harness/gq-browser/*` stays allowed.
- A false refusal of a legitimate command naming the file: mitigation, the regexes anchor the exact file names and the neighbour cases are pinned.

## Domain checklist

Domains: auth

The ticket protects an authentication secret from being printed; it adds no sign-up, login, recovery, invite or session flow, and no account, money, delete, device or release behaviour.

Domain-gate: pre-account-hijack waived (no authentication flow is added or changed; two path patterns only)
Domain-gate: lookalike-identifier waived (no identifier handling; the guard matches fixed file names)
Domain-gate: request-device-binding waived (no approval or login flow involved)
Domain-gate: link-expiry-single-use waived (no link or token is issued or consumed by this change)
Domain-gate: session-fixation waived (no session handling is touched)
Domain-gate: rate-limit-enumeration waived (no account lookup or response text for an account is involved)
Domain-gate: store-billing-exposure waived (no account state or billing is touched)
Domain-gate: backup-before-delete waived (nothing is deleted)
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
Domain-gate: self-update-e2e waived (the install of the guard is the normal harness batch install)
Domain-gate: transport-proof waived (no integration transport is added)
Domain-gate: rollback-not-blocked waived (no release or rollback path is touched)
Domain-gate: staging-exists waived (a local guard rule; the harness batch install is rehearsed by its own process)

## Reviews

Spec core sha256: `0f968b46fcbf3b6fc5f8c2912f76a2e2a5abf557da85d4f0349b6e37acc4cdec`

| Role | Verdict | Reviewer | Kind | Source | Bound to |
|---|---|---|---|---|---|
| adversarial | ACCEPT | a0c568dfa08e7eb86 (red-team) | agent | WAL-verified red-team agent | current |
| acceptance | ACCEPT | a5d878417503c1093 (red-team) | agent | WAL-verified red-team agent | current |
