# Spec: ah guard-selftest, a sanctioned live test of a guard rule

Ticket: GoodQA goodqa#15876
Author: agent:af9e33704216a1ea1 (claude-sonnet-5-5)
Click-test: not-applicable (a CLI self-test with no UI; the proof is its own end-to-end run on t2-dev by a worktree-isolated sub-agent, recorded by the owner as REALLY_TESTED for goodqa#15787 and goodqa#15876 after install)
Sign-off: main
Review-policy: standard

## Outcome

Any agent, including a sub-agent under worktree isolation, can live-verify a guard rule on a host with one fixed command: `python3 -I ~/.claude/hooks/ah.py guard-selftest --rule bulk_staging --expect-manifest SHA256 --expect-policy SHA256|absent`. The command checks that it is the INSTALLED copy, pins the installed hook launcher, guard and every guard module it imports against hashes taken from the merged commit, builds its own disposable repositories in a private directory, runs the installed hook on a fixed table of commands, compares each result with the expected one, prints one JSON object, removes only the directory it created and writes one audit row. No command text comes from the caller, so none passes through the isolation scan, and the caller cannot make it run text of their own.

## Scope

- In: a new module `harness/hooks/guard_selftest.py` (the table, the pin, the setup, the run, the cleanup, the audit), the `guard-selftest` subcommand in `ah.py`, the file lists in `install.py` and `install_codex.py`, tests, a mutant script. The first rule in the table is `bulk_staging` (goodqa#15787).
- Out: a `--host` form (a host is reached with the existing ssh route and the same fixed command), caller-supplied commands, hook directories or temporary directories (they do not exist), rules other than `bulk_staging` (the table takes more; each is its own reviewed change), changing any guard rule, proving anything about commands the table does not list, or about Claude Code and Codex themselves (the hook entry is exercised with a Bash payload).

## Assumptions (labelled; none is a user decision)

- D1 "Unexpected" is judged against hashes the CALLER names, because the module cannot know the merged hashes of the code it tests. The expected values MUST come from the MERGED commit, never from the installed files: `git rev-parse MERGE_SHA:harness/hooks/NAME` run in the caller's own worktree for each name that `--print-manifest` lists. A caller who computes them from the installed files (`git hash-object ~/.claude/hooks/...`) makes the check pass whatever is installed; that source is not acceptable, and the REALLY_TESTED row for the run must carry the merge SHA. Whether the caller names the hashes is a choice for main to confirm. Source: ticket:GoodQA goodqa#15876
- D2 The code under test is the INSTALLED copy. A command-line run refuses (exit 3) unless the real path of the running module's directory equals the real path of `~/.claude/hooks` where the home is taken from the system user record (`pwd`), not from `$HOME`; the JSON and the audit row name the resolved directory. Only the Python API (used by the tests) takes a hooks directory. Source: inferred: from ticket:GoodQA goodqa#15876 -- a worktree copy or a copied ah.py would otherwise test itself with its own hash and read as proof of the installed guard.
- D3 The expected result of a case follows the EFFECTIVE mode of the rule, and the channels are those of the real hook: under warn a bulk case exits 0, stdout is valid JSON (`hookSpecificOutput.additionalContext`) containing `[bulk_staging/bulk-staging]`; under enforce it exits 2 and stderr contains that text; every other case exits 0 with EMPTY stdout and no `bulk_staging` text in either stream, in both modes. ANY non-empty stderr in a case that expects an allow or a warn makes the case FAIL (this covers the launcher's fallback notes such as `command_guard: analyser ... crashed`, `timed out`, `printed invalid output`, `could not start` and `BLOCKED [guard_failure]` whatever their wording), because the launcher otherwise turns a broken analyser into a harmless-looking exit 0. Source: file:harness/hooks/command_guard_hook.py:92@42a5f99f
- D7 The manifest assumes the installer copies hook files byte for byte; the live run on t2-dev (AC-9) shows it, and a rewritten file would make the digest differ and the run refuse. Source: inferred: from ticket:GoodQA goodqa#15876 -- the pin compares installed bytes with the merged commit.
- D4 A time-of-check gap remains between hashing the files and the hook child reading them: a same-user process that edits the hooks in that window defeats the check. Stated limit: the pin protects against an accidentally stale or wrong install, not against a hostile same-user process. Source: inferred: from ticket:GoodQA goodqa#15876
- D5 Output is one JSON object and a non-zero exit on any mismatch or refusal. Exit codes: 0 all cases match, 1 a case mismatched, 3 refused before running anything (bad arguments, unknown rule, not the installed copy, unexpected manifest or policy), 4 setup failed (git missing, the private directory could not be made). Source: ticket:GoodQA goodqa#15876
- D6 The pin is a manifest: the git blob id of every file the hook run executes, i.e. a reviewed list per rule (amended after code review H1: an import-and-literal closure pinned 57 unrelated files and made the live run unsatisfiable): `command_guard_hook.py`, `command_guard.py`, the two siblings the analyser loads on the paths the table exercises (`safe_input.py`, `redact.py`) and `guard_selftest.py` itself, so a stale self-test cannot pass. A test checks that every module-level import of the launcher and the analyser is in the list; `provenance.py` is loaded only by the no-backup override path, which no case reaches. A lazy import added later on a tested path is a stated limit, caught by the review of that change. `--print-manifest` applies the same installed-copy check as a run (D2) and prints the resolved directory, so a worktree copy's manifest cannot be mistaken for the installed one. `--print-manifest` prints the names and blob ids and the manifest digest, and runs nothing else. `--expect-manifest` is the sha256 of the manifest text (one `NAME BLOBID` line per file, sorted by name, each line ending in a newline). `--expect-policy` is the sha256 of the policy file `command_guard_policy.json` in that directory or the word `absent`. Source: inferred: from ticket:GoodQA goodqa#15876 -- a stale launcher or helper must not pass.

## Acceptance criteria

- AC-1: with the correct `--expect-manifest` and `--expect-policy`, the command builds a dirty original checkout, a linked worktree, a clean checkout and a plain directory under one private directory, runs the installed hook on the fixed table (a bulk add and a bulk commit in the dirty original, a `-C` add from the worktree into the original, an explicit-path add, a bulk add in the linked worktree, a bulk add in the clean checkout, a bulk add in a plain directory), prints one JSON object (rule, resolved hooks directory, manifest with each blob id and its digest, policy sha256 or `absent`, effective mode, one record per case: label, command, expected, exit code, stdout excerpt, stderr excerpt, ok) and exits 0 when every case matches. Verify by: `python3 -B -m unittest tests.test_guard_selftest`. Source: ticket:GoodQA goodqa#15876
- AC-2: expectations follow the effective mode and the real channels (D3): warn gives exit 0 and the finding in the stdout JSON, enforce gives exit 2 and the finding on stderr, the other cases give exit 0 with empty stdout and no `bulk_staging` text. Verify by: the same suite, under a warn and an enforce policy. Source: ticket:GoodQA goodqa#15876
- AC-3: it refuses with exit 3, runs no hook, creates no directory and writes an audit row marked refused when: the running module is not the installed copy (D2); the manifest digest differs from `--expect-manifest`; the policy file's sha256 differs from `--expect-policy` or `absent` is given and a policy file exists; the rule is unknown; an argument is missing, malformed or unknown. Argument parsing does not accept abbreviations (`--exp` and `--expect-m` are unknown arguments). Verify by: the same suite. Source: ticket:GoodQA goodqa#15876
- AC-4: nothing the caller supplies becomes command text or reaches a shell. The table is code; every subprocess is an argument list with no shell; there is no flag that takes a command, a path or a directory (an unknown flag is refused); `--rule` is checked against the table, `--expect-manifest` against `[0-9a-f]{64}` and `--expect-policy` against `[0-9a-f]{64}|absent`. The hook child is started as exactly `[sys.executable, '-I', PINNED_DIR/command_guard_hook.py, 'hook']` (absolute path, no PATH lookup, the argument list `install.py` registers), with the case directory as its working directory, the tool's own 20 second timeout around each run (a hang fails the case even if the launcher's own watchdog is broken), a fixed environment (`PATH` made of the directory of the absolute git the tool uses plus `/usr/bin:/bin`, `HOME` from the system user record, `LANG=C`, nothing else inherited), and a payload of exactly `{"tool_name": "Bash", "tool_input": {"command": TABLE_COMMAND}, "cwd": CASE_DIRECTORY}` (no transcript path, no session, nothing of the caller). The disposable repositories are made with the trusted git: the first of `/usr/bin/git`, `/opt/homebrew/bin/git`, `/usr/local/bin/git` that is a regular file owned by root or the running user (never a search of the caller's `PATH`; none qualifying exits 4), `git init --template=` (empty), `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=/dev/null`, `core.hooksPath=/dev/null`, no `GIT_*` variable inherited and no `safe.directory` widening (the repositories belong to the running user). Verify by: the same suite (injection strings in each argument; hostile `GIT_*`, `PATH`, `TMPDIR`, `PAGER`, `PYTHONPATH`, `PYTHONSTARTUP`, `GIT_SSH_COMMAND` and `GIT_EXTERNAL_DIFF` environment values change nothing that runs and execute no marker script; the exact child argv and payload are asserted). Source: ticket:GoodQA goodqa#15876
- AC-5: it removes only the directory it created. The parent is fixed and private: `~/.agent-harness/tmp` (home from the system user record, created 0700, owned by the running user, `TMPDIR` ignored). The directory is made with `mkdtemp` under it with a fixed prefix; it is opened with `O_DIRECTORY|O_NOFOLLOW` and its device and inode are recorded; at the end the same device and inode must still be the directory found under the parent (the parent is opened the same way), and removal is done through the open descriptors (a descriptor walk that never follows a symlink, then `rmdir` relative to the parent descriptor), on success, on a mismatch, on an error and on an interrupt. A failed identity check refuses to remove and says so. Residual limit: a same-user process can still replace content inside the directory while it exists, and cannot make the removal leave it. Verify by: the same suite (a sentinel file and directory beside the directory survive; a symlink swapped in for the directory is not followed and its target survives; `TMPDIR` pointing at a directory with other content leaves that content alone; a symlink planted inside the directory is unlinked, not followed). Source: ticket:GoodQA goodqa#15876
- AC-6: one audit row (time, caller session and agent when known, rule, resolved hooks directory, manifest digest, policy sha256, mode, verdict, case count, refused or ok) is appended to `~/.agent-harness/guard-selftest-audit.jsonl` (created 0700 and 0600, `O_NOFOLLOW`); every caller-supplied value in the row is bounded (at most 80 printable ASCII characters); a failed audit write is reported as `audit_warning` and does not change the verdict or leave the directory behind. Verify by: the same suite. Source: inferred: from ticket:GoodQA goodqa#15876 -- the other ah deploy and removal tools audit.
- AC-7: the command text of the invocation passes the installed guard for a main agent and a sub-agent (it contains no git command text), and the guard still blocks a write into the hooks directory: the self-test is not a new way to write the hooks. The statement that a worktree-isolated sub-agent can run it is proved live by AC-9, not by the guard's decision function (the isolation refusals come from Claude Code's worktree isolation, not from command_guard). Verify by: the same suite (`command_guard.decide` on the command line) and AC-9. Source: ticket:GoodQA goodqa#15876
- AC-8: the new module is in the installed file lists (`install.py`, `install_codex.py`) and `ah.py` imports it lazily, so an installed `ah` without the module fails with a clear message instead of an import error at start. Verify by: the same suite and the install list tests. Source: inferred: from ticket:GoodQA goodqa#15876 -- a file missing from the install list never reaches t2-dev.
- AC-9: after the change is merged and installed on t2-dev, the owner (a worktree-isolated sub-agent) runs `ssh t2-dev 'python3 -I ~/.claude/hooks/ah.py guard-selftest --rule bulk_staging --expect-manifest M --expect-policy absent'` (M computed from the merge commit as D1 says; `absent` is a real check because no policy file exists there) and gets exit 0 and a JSON object with the rule, the resolved directory `/home/eric/.claude/hooks`, the manifest and its digest, `policy: absent`, `mode: warn`, and every case `ok: true` (each bulk case with a finding in the stdout JSON, each other case with empty stdout). The output is pasted into a REALLY_TESTED row for goodqa#15787 and one for goodqa#15876, each carrying the merge SHA. Verify by: that run. Source: ticket:GoodQA goodqa#15876
- AC-10: a broken analyser cannot pass: a stderr fallback note makes a case fail (D3), and a test with a crashing `command_guard.py` behind the real launcher (Python API variant directory) shows every case failing, including the negative ones, and a variant that prints garbage and one that sleeps past the launcher's timeout the same. Verify by: the same suite. Source: ticket:GoodQA goodqa#15876

## Negative cases

- NEG-1 (AC-4): `--rule 'bulk_staging; touch /tmp/x'`, `--rule ../x`, a hash argument with shell metacharacters or an extra word, an extra positional argument, `--command ...`, `--hooks-dir /tmp/evil`, `--tmp /` and the abbreviations `--exp`, `--expect-m` are all refused with exit 3 and run nothing. Source: ticket:GoodQA goodqa#15876
- NEG-2 (AC-4): a hostile environment (`GIT_CONFIG_GLOBAL`, `GIT_EXEC_PATH`, `GIT_SSH_COMMAND`, `GIT_EXTERNAL_DIFF`, `GIT_ASKPASS`, `GIT_TEMPLATE_DIR`, `PAGER`, `PATH` with a fake `git` first, `HOME` holding a git template or hooks, `PYTHONPATH`, `PYTHONSTARTUP`) does not change which program runs and does not execute a marker script. Source: ticket:GoodQA goodqa#15876
- NEG-3 (AC-5): a sentinel file and directory beside the working directory survive; a symlink swapped in for the directory before the cleanup is not followed and its target survives; `TMPDIR` set elsewhere is ignored and that content is untouched; the private parent with the wrong owner or mode is refused (exit 4). Source: ticket:GoodQA goodqa#15876
- NEG-4 (AC-3): a wrong manifest, a wrong policy sha, `absent` with a policy present, a missing argument, and a run from a copy of `ah.py` outside the installed directory each exit 3 with no directory created and no hook run. A stale `command_guard_hook.py` or a stale sibling module (one byte changed in a variant directory) changes the manifest and is refused. Source: ticket:GoodQA goodqa#15876
- NEG-5 (AC-1): a guard variant with the bulk staging rule removed (a copy of the hooks directory, passed through the Python API only) makes the self-test exit 1 and name the failing cases; a variant that always warns makes the explicit-path, worktree, clean and plain cases fail. Source: ticket:GoodQA goodqa#15876
- NEG-6 (AC-10): a crashing, garbage-printing or hanging analyser behind the real launcher fails every case, negative ones included; git missing or the private directory not creatable exits 4 with the directory removed and a clear message; a hook child that times out, crashes or prints garbage is a failed case, never a pass. Source: inferred: from ticket:GoodQA goodqa#15876 -- fail closed.
- NEG-7 (AC-2): an enforce policy makes the bulk cases expect exit 2 with the finding on stderr; a warn policy makes them expect exit 0 with the finding in the stdout JSON; an unknown mode value in the policy is refused as unexpected, not guessed. Source: inferred: from ticket:GoodQA goodqa#15876 -- see D3: the mode decides what to expect.
- NEG-8 (AC-5, AC-6): an interrupt (KeyboardInterrupt) and an exception inside the run still remove the directory and write the audit row. Source: inferred: from ticket:GoodQA goodqa#15876 -- cleanup in a finally block.
- NEG-9 (AC-1, AC-3, AC-4, AC-5, AC-6): failing-first: the new suite fails against origin/main (no module) and against each controlled broken variant of the module (tests/mutants_guard_selftest.py: the installed-copy check removed, the manifest check removed, the policy check removed, the identity check before removal removed, removal by path instead of by descriptor, a caller-supplied command accepted, the environment inherited, the table not compared, a hook failure or a fallback note counted as a pass, abbreviations allowed, the audit bound removed). Source: ticket:GoodQA goodqa#15876

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

- The tool is a sanctioned path around the isolation scan, so the central risk is that it can be made to run text of the caller's choosing: mitigation, the table is code, no flag takes a command, a path or a directory, abbreviations are refused, every subprocess is an argument list without a shell, the environment is rebuilt, the hook child is started by an absolute interpreter and path, and the suite plus the red-team angle of the spec review attack exactly this.
- The tool deletes a directory: mitigation, only the one it created, under a fixed private parent, removed through descriptors after the device and inode are re-verified, never a directory named by the caller; residual same-user limit stated in AC-5.
- A false pass: mitigation, the expected manifest and policy come from the merged commit (D1), a hook failure, a timeout or a launcher fallback note is a failed case (D3, AC-10), the warn expectation uses the real stdout channel, and the mutants show each check matters. Residual: a same-user process editing the hooks between the hash and the hook run (D4), a table that misses a case (it covers the shipped rule's documented shapes), and a caller who computes the expected values from the installed files instead of the merged commit (D1 forbids it; the REALLY_TESTED row carries the merge SHA so a reader can check).
- The tool tests the guard as installed on the host it runs on; it says nothing about another host, and the hook entry is exercised with a Bash payload, not through Claude Code or Codex.
- A new file in the install lists is not installed until main runs `install-files`; the live run waits for that.

## Domain checklist

Domains: auth, delete, devices, money, release

The tool creates and removes one directory of its own and runs the installed hook on fixed text. It adds no authentication, account, device, money or release behaviour; its one deletion is its own just-created directory.

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

## Reviews

Spec core sha256: `f2cef4a61e178974855c8cd72a5e139e823989729a11f4601c6611e03cf86074`

| Role | Verdict | Reviewer | Kind | Source | Bound to |
|---|---|---|---|---|---|
| adversarial | ACCEPT | a0c568dfa08e7eb86 (red-team) | agent | WAL-verified red-team agent | current |
| acceptance | ACCEPT | a5d878417503c1093 (red-team) | agent | WAL-verified red-team agent | current |
