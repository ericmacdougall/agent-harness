# Spec: ah guard-selftest, a sanctioned live test of a guard rule

Ticket: GoodQA goodqa#15876
Author: agent:af9e33704216a1ea1 (claude-sonnet-5-5)
Click-test: not-applicable (a CLI self-test with no UI; the proof is its own end-to-end run on t2-dev, recorded by the owner as REALLY_TESTED for goodqa#15787 after install)
Sign-off: main
Review-policy: standard

## Outcome

Any agent, including a sub-agent under worktree isolation, can live-verify a guard rule on a host with one fixed command: `python3 -I ~/.claude/hooks/ah.py guard-selftest --rule bulk_staging --expect-guard-blob SHA --expect-policy SHA256|absent`. The command builds its own disposable repositories in a private temporary directory, runs the INSTALLED hook entry on a fixed table of commands, compares each result with the expected one, prints one JSON object, removes only the directory it created and writes one audit row. No command text comes from the caller, so none passes through the isolation scan, and the caller cannot make it run text of its own.

## Scope

- In: a new module `harness/hooks/guard_selftest.py` (the table, the setup, the run, the cleanup, the audit), the `guard-selftest` subcommand in `ah.py`, the file lists in `install.py` and `install_codex.py`, tests, a mutant script. The first rule in the table is `bulk_staging` (goodqa#15787).
- Out: a `--host` form (a host is reached with the existing ssh route and the same fixed command), caller-supplied commands or hook directories (they do not exist), rules other than `bulk_staging` (the table is built to take more; each is its own reviewed change), changing any guard rule, proving anything about commands the table does not list.

## Assumptions (labelled; none is a user decision)

- D1 "Unexpected hash" is judged against hashes the CALLER names, not constants in the module (the module cannot know the merged blob of the guard it tests): `--expect-guard-blob` is the git blob id of the installed `command_guard.py` (what `git hash-object` prints) and `--expect-policy` is the sha256 of the user policy file or the word `absent`. Both are required. Source: ticket:GoodQA goodqa#15876
- D2 The guard under test is the INSTALLED one: the directory of the running module (`~/.claude/hooks` when run as the installed copy). The hooks directory is never an argument, an environment variable or a file the caller can name; the Python API takes it only so the tests can point at a variant. Source: inferred: from ticket:GoodQA goodqa#15876 -- a caller-chosen directory would let the caller run code of their choice.
- D3 The expected result of a case follows the EFFECTIVE mode of the rule in the installed policy: in warn mode a bulk command exits 0 with a stderr line naming `bulk_staging`, in enforce mode it exits 2 with that text; every other case must exit 0 with no `bulk_staging` text in either mode. Source: inferred: from ticket:GoodQA goodqa#15876 -- the point is to check the shipped behaviour in the host's actual mode.
- D4 A time-of-check gap remains between hashing the guard file and the hook child reading it; a same-user process that edits the hooks in that window defeats the check. Stated limit: it protects against an accidentally stale or wrong install, not against a hostile same-user process. Source: inferred: from ticket:GoodQA goodqa#15876
- D5 Output is one JSON object and a non-zero exit on any mismatch or refusal, never prose only, so the result can be pasted into a REALLY_TESTED row. Exit codes: 0 all cases match, 1 a case mismatched, 3 refused before running anything (bad arguments, unknown rule, unexpected hash), 4 setup failed (git missing, the temporary directory could not be created). Source: ticket:GoodQA goodqa#15876

## Acceptance criteria

- AC-1: with the correct `--expect-guard-blob` and `--expect-policy`, the command builds a dirty original checkout, a linked worktree, a clean checkout and a plain directory under one private temporary directory, runs the installed hook on the fixed table (a bulk add and a bulk commit in the dirty original, `git -C` from the worktree into the original, an explicit-path add, a bulk add in the linked worktree, a bulk add in the clean checkout, a bulk add in a plain directory), prints one JSON object with the rule, the guard blob, the policy sha256 or `absent`, the effective mode and one record per case (label, command, expected, exit code, stderr excerpt, ok), and exits 0 when every case matches. Verify by: `python3 -B -m unittest tests.test_guard_selftest`. Source: ticket:GoodQA goodqa#15876
- AC-2: expectations follow the effective mode (D3): under warn a bulk case exits 0 with `bulk_staging` in stderr, under enforce it exits 2; explicit, worktree, clean and plain cases exit 0 with no `bulk_staging` in both. Verify by: the same suite, with a policy that sets enforce. Source: ticket:GoodQA goodqa#15876
- AC-3: it refuses with exit 3, runs no hook, creates no temporary directory and writes an audit row marked refused when the installed guard's blob id differs from `--expect-guard-blob`, when the policy file's sha256 differs from `--expect-policy`, when `--expect-policy absent` is given and a policy file exists, when the rule is unknown, or when an argument is missing, malformed or unknown. Verify by: the same suite. Source: ticket:GoodQA goodqa#15876
- AC-4: nothing the caller supplies becomes command text or reaches a shell: the table is code; every subprocess is an argument list with no shell; the hook payload is built from the table; there is no `--command`, `--hooks-dir`, `--tmp` or similar flag (an unknown flag is refused); `--rule` is checked against the table's names and the two hash arguments against `[0-9a-f]{40}` and `[0-9a-f]{64}|absent`; the git environment is rebuilt (no `GIT_*` variable inherited, a fixed empty global and system config, `core.hooksPath=/dev/null`, an absolute trusted git path); the hook child gets a minimal environment. Verify by: the same suite (injection strings in each argument and in `GIT_*`, `PATH`, `TMPDIR`, `PAGER`, `GIT_SSH_COMMAND`, `GIT_EXTERNAL_DIFF` environment variables change nothing that runs). Source: ticket:GoodQA goodqa#15876
- AC-5: it removes only the temporary directory it created: made with `mkdtemp` under the system temporary directory with a fixed prefix and mode 0700; before removal the path must still be a real directory (not a symlink), a direct child of the real system temporary directory, carry the prefix, and have the device and inode recorded at creation; removal happens on success, on a mismatch, on an error and on an interrupt, and a failed identity check refuses to remove and says so. Verify by: the same suite (a sentinel next to the directory survives, a symlink swapped in for the directory is not followed, `TMPDIR` pointing at a directory with other content leaves that content alone). Source: ticket:GoodQA goodqa#15876
- AC-6: one audit row (time, caller session and agent when known, rule, guard blob, policy sha256, mode, verdict, case count, refused or ok) is appended to `~/.agent-harness/guard-selftest-audit.jsonl` (created 0700 and 0600, `O_NOFOLLOW`); a failed audit write is reported as `audit_warning` and does not change the verdict or leave the temporary directory behind. Verify by: the same suite. Source: inferred: from ticket:GoodQA goodqa#15876 -- the other ah deploy and removal tools audit.
- AC-7: the command text of the invocation itself passes the installed guard for a main agent and a sub-agent (it contains no git command text), and the guard still blocks a hook-file copy: the self-test is not a new way to write the hooks. Verify by: the same suite (`command_guard.decide` on the command line, and a mutant that adds a write to the hooks directory fails the suite). Source: ticket:GoodQA goodqa#15876
- AC-8: the new module is in the installed file lists (`install.py`, `install_codex.py`) and `ah.py` imports it lazily, so an installed `ah` without the module fails with a clear message instead of an import error at start. Verify by: `python3 -B -m unittest tests.test_guard_selftest` and the install list tests. Source: inferred: from ticket:GoodQA goodqa#15876 -- a file missing from the install list never reaches t2-dev.

## Negative cases

- NEG-1 (AC-4): `--rule 'bulk_staging; touch /tmp/x'`, `--rule ../x`, a hash argument with shell metacharacters or an extra word, an extra positional argument, `--command ...`, `--hooks-dir /tmp/evil` and `--tmp /` are all refused with exit 3 and run nothing. Source: ticket:GoodQA goodqa#15876
- NEG-2 (AC-4): a hostile environment (`GIT_CONFIG_GLOBAL`, `GIT_EXEC_PATH`, `GIT_SSH_COMMAND`, `GIT_EXTERNAL_DIFF`, `GIT_ASKPASS`, `PAGER`, `PATH` with a fake `git` first, `HOME` with a hooks template, `PYTHONPATH`) does not change which program runs and does not execute a marker script. Source: ticket:GoodQA goodqa#15876
- NEG-3 (AC-5): a sentinel file and a sentinel directory beside the temporary directory survive; a symlink swapped in for the temporary directory before the cleanup is not followed and its target survives; `TMPDIR` set to a directory with unrelated content leaves that content untouched. Source: ticket:GoodQA goodqa#15876
- NEG-4 (AC-3): a wrong `--expect-guard-blob`, a wrong `--expect-policy`, `--expect-policy absent` with a policy present, and a missing argument each exit 3 with no temporary directory created and no hook run. Source: ticket:GoodQA goodqa#15876
- NEG-5 (AC-1): a guard variant with the bulk staging rule removed (a copy of the hooks directory, passed through the Python API only) makes the self-test exit 1 and name the failing cases; a variant that always warns makes the explicit-path and worktree cases fail. Source: ticket:GoodQA goodqa#15876
- NEG-6 (AC-1): git missing or the temporary directory not creatable exits 4 with the temporary directory removed and a clear message; a hook child that times out, crashes or prints garbage is a failed case, never a pass. Source: inferred: from ticket:GoodQA goodqa#15876 -- fail closed.
- NEG-7 (AC-2): an enforce policy makes the bulk cases expect exit 2; a warn policy makes them expect exit 0 with the text; an unknown mode value in the policy is refused as unexpected, not guessed. Source: inferred: from ticket:GoodQA goodqa#15876 -- see D3: the mode decides what to expect.
- NEG-8 (AC-5, AC-6): an interrupt (KeyboardInterrupt) and an exception inside the run still remove the temporary directory and write the audit row. Source: inferred: from ticket:GoodQA goodqa#15876 -- cleanup in a finally block.
- NEG-9 (AC-1, AC-3, AC-4, AC-5, AC-6): failing-first: the new suite fails against origin/main (no module) and against each controlled broken variant of the module (tests/mutants_guard_selftest.py: the hash check removed, the identity check before removal removed, removal of the whole temporary directory root, a caller-supplied command accepted, the environment inherited, the table not compared, a hook failure counted as a pass, the audit write before the refusal removed). Source: ticket:GoodQA goodqa#15876

## Resource budget

Host: mac
Fan-out: agents=2 jobs=1 processes=1 browser_pages=0 test_workers=1
Peak memory: 0.3 GB (method: a unittest process with a few small temporary repositories)
CPU: 1 core (method: single-threaded unittest and short git and hook subprocesses)
Disk: 0.05 GB (method: temporary repositories, removed by the tool)
Network: 0 MB (method: none; the live run on t2-dev uses only local repositories)
Wall time: 5 min (the suite plus the mutants)
Cap and kill: none needed (each subprocess has a 20 s timeout)
Checkpoint: not required (under 10 min and 4 GB)

## Risks

- The tool is a sanctioned path around the isolation scan, so the central risk is that it can be made to run text of the caller's choosing: mitigation, the table is code, no flag takes a command, a path or a directory, every subprocess is an argument list without a shell, the environment is rebuilt, and the suite plus a red-team angle in the spec reviews attack exactly this.
- The tool deletes a directory: mitigation, only the one it created, verified (real directory, not a symlink, direct child of the real temporary directory, prefix, device and inode) before `rmtree`, and never a directory named by the caller.
- A false pass: mitigation, the caller names the expected guard blob and policy hash, a hook failure or timeout is a failed case, and the mutants show each check matters. A false pass can still happen if the installed guard is replaced between the hash and the hook run (D4) or if the table misses a case (the table covers the shipped rule's documented shapes, not every shape).
- The tool tests the guard as installed on the host it runs on; it says nothing about another host, and the hook entry is exercised with a Bash payload, not through Claude Code or Codex themselves.
- A new file in the install lists is not installed until main runs `install-files`; the live run waits for that.

## Domain checklist

Domains: auth, delete, devices, money, release

The tool creates and removes one temporary directory of its own and runs the installed hook on fixed text. It adds no authentication, account, device, money or release behaviour; its one deletion is its own just-created directory.

Domain-gate: pre-account-hijack waived (no authentication flow is added or changed; a local self-test command)
Domain-gate: lookalike-identifier waived (no identifier handling is involved)
Domain-gate: request-device-binding waived (no approval or login flow is involved)
Domain-gate: link-expiry-single-use waived (no link or token is issued or consumed)
Domain-gate: session-fixation waived (no session handling is touched)
Domain-gate: rate-limit-enumeration waived (no account lookup is involved)
Domain-gate: store-billing-exposure waived (no account state or billing is touched)
Domain-gate: backup-before-delete waived (the only deletion is the temporary directory the tool itself created seconds earlier and holds no user data; it is verified as that exact directory before removal, see AC-5)
Domain-gate: unpushed-work-detection waived (the tool never touches a user checkout, branch or worktree; its repositories are its own temporary ones)
Domain-gate: dry-run-diff waived (the removal target is one directory fixed at creation and re-verified, not a list or a pattern)
Domain-gate: scope-pinning waived (pinned: the exact created path, its device and inode, a direct child of the real temporary directory, never a caller-named path; see AC-5 and NEG-3)
Domain-gate: cross-host-approval-portability waived (no approval is involved; the tool runs on the host that executes it)
Domain-gate: idempotent-retry waived (a rerun builds a new temporary directory and removes it; nothing persists but an audit row)
Domain-gate: device-identity-binding waived (no device enrollment or grant is touched)
Domain-gate: unattended-recovery waived (an interrupted run still removes its directory in a finally block, see NEG-8)
Domain-gate: grant-durability waived (no grant or approval is created)
Domain-gate: remote-exec-audit waived (no remote execution is added: the tool runs locally and writes an audit row; running it on a host uses the existing ssh route with a fixed command)
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
Domain-gate: staging-exists waived (a local self-test; the run on t2-dev after install is the live proof)
