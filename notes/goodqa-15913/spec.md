# Spec: agent-harness: ah install-files local target (this machine's Claude hooks and Codex harness)

Ticket: GoodQA goodqa#15913
Author: agent:afefd4e93d22b0173 (claude-opus-5-5)
Click-test: not-applicable (a main-only CLI command with no UI; the tests drive the real program end to end on disposable homes, and the live proof is main's post-merge install on this Mac, AC-7)
Sign-off: main
Review-policy: standard

## Outcome

The main agent can deploy merged hook files to the machine it runs on through the same audited route the fleet hosts use. `--host local` writes `~/.claude/hooks`, and `--host local-codex` writes `~/.codex/agent-harness`. Every step stays the same: the merged-code proof, the backups, staging every file and renaming with the guard last, reading the shas back, comparing the self-test with its baseline, automatic rollback guard first, the audit rows and the run id in the ticket comment. The guard still refuses every other writer to `~/.claude/hooks` and every caller that is not main. This unblocks the goodqa#15785 install on this Mac, whose Claude and Codex guards still allow plain reads of the GoodQA user token.

## Scope

- In:
  - harness/hooks/ah_install.py:
    - a local transport that runs the same constant program as a local subprocess (no shell, no ssh) with an allowlisted environment;
    - a fixed root token, claude or codex, which the program maps to a fixed directory;
    - the Codex name list (install_codex.py `DELIVERY_HELPERS` at the commit);
    - a check that the Codex directory exists before the fetch;
    - the host audit row skipped for a local target;
    - the Codex drift report on `--host local`.
  - harness/hooks/ah.py help text.
  - tests/test_ah_install.py and tests/test_command_guard_install_files.py.
  - tests/mutants_install_files.py.
  - This spec.
- Out:
  - Any change to the guard code. `install_files_refusal` is already host-agnostic and main-only.
  - The pre-existing guard gaps found while pinning NEG-6, filed as GoodQA goodqa#15914 (Risks):
    - `install` and `rsync` into `~/.claude/hooks` are allowed;
    - `mv` into `~/.codex/agent-harness` is allowed.
  - Codex targets on fleet hosts.
  - settings.json, CLAUDE.md and install.py.
  - goodqa#15912 (test portability; not tiny).
  - The post-merge install itself, which main runs (AC-7).

## Acceptance criteria

- AC-1: `--host local` installs merged files into this machine's `~/.claude/hooks` with the remote semantics: both backups (in the hooks directory and the caller's copy) read back by sha256, stage then rename with command_guard.py last, read-back shas, the self-test compared with the baseline, an automatic rollback guard first on a regression, audit start and result rows with host `local` and no duplicate host row, and one ticket comment naming the run id; no ssh argv is ever built, the program gets HOME and the allowlisted variables only, and a dry run changes nothing and takes no lock. Verify by: `python3 -B -m unittest tests.test_ah_install.LocalTarget`. Source: ticket:GoodQA goodqa#15913
- AC-2: `--host local-codex` does the same into `~/.codex/agent-harness`, accepts only names in install_codex.py `DELIVERY_HELPERS` at the commit, and leaves `~/.claude/hooks` untouched. Verify by: `python3 -B -m unittest tests.test_ah_install.LocalCodex`. Source: ticket:GoodQA goodqa#15913
- AC-3: after `--host local` (installed or already_current) the result lists every installed name whose Codex copy exists and differs (`codex_differs`), with a note naming `--host local-codex`; `--host local` never writes a Codex copy. Verify by: `python3 -B -m unittest tests.test_ah_install.LocalTarget.test_local_reports_the_codex_copies_that_differ_from_what_it_installed`. Source: inferred: from wal:baab765b-d85c-46b4-b7b9-588eb912c770/main.jsonl#w3d3ce13675d ; ticket:GoodQA goodqa#15913 -- main asked for this machine's hooks and the Codex home if present; with one directory per run, the drift report is what keeps the Codex home from being silently left behind
- AC-4: `--rollback RUN` and `--resume RUN` work for both local targets; a rollback is never blocked by a failing self-test (the difference is reported); an unfinished local run blocks new runs on its own target only. Verify by: `python3 -B -m unittest tests.test_ah_install.LocalTarget`. Source: ticket:GoodQA goodqa#15913
- AC-5: the guard allows the literal local forms only from the installed `~/.claude/hooks/ah.py` and only for main. Verify by: `python3 -B -m unittest tests.test_command_guard_install_files`. Source: ticket:GoodQA goodqa#15913
- AC-6: the fleet path is unchanged: the same ssh argv (no root argument), and every earlier install-files test passes. Verify by: `python3 -B -m unittest tests.test_ah_install tests.test_command_guard_install_files` and `python3 -B tests/mutants_install_files.py` (every mutant KILLED). Source: ticket:GoodQA goodqa#15742
- AC-7: live, after the merge, run by main on this Mac: the local target lives in the installed ah.py and ah_install.py, and the guard allows install-files only from the installed copy, so the first step is a one-time bootstrap through the sanctioned installers from a clean checkout of the merge commit (`install.py --apply --hooks-only`, preview first, and `install_codex.py --apply --hooks-only`; neither reads or writes CLAUDE.md or settings.json, and both keep per-file backups); then `--host local` and `--host local-codex` dry runs and real runs from the installed ah.py (at the merge commit they report already_current or install what the bootstrap missed), and the goodqa#15785 live kit (live_test.py, sha256 b753e423) and plain_probe.py pass against `~/.claude/hooks`, with plain_probe.py passing against `~/.codex/agent-harness`. Verify by: those runs, recorded as REALLY_TESTED entries naming the run ids and the installed sha256s. Source: wal:baab765b-d85c-46b4-b7b9-588eb912c770/main.jsonl#w3d3ce13675d

## Negative cases

- NEG-1 (AC-5): a sub-agent running any local form (the literal installed form, `--rollback`, `--resume`, `--dry-run`, `local-codex`) is refused under `log_delete/install-files` naming the main agent, and a worktree copy of ah.py is refused even for main. Source: ticket:GoodQA goodqa#15913
- NEG-2 (AC-1): `--host` values that only look local are refused before any call: `mac`, `localhost`, `local;ls`, `LOCAL`, `local ` (trailing space), `local-claude`, `./local`, `local-codex2` (scope-pinning: a fixed allowlist of names). Source: ticket:GoodQA goodqa#15913
- NEG-3 (AC-1, AC-2): an allow-all guard installed through a local target fails the self-test; every changed file is restored with command_guard.py first, the result is `rolled_back` with exit 4, and every live file equals its bytes from before the run (backup-before-delete: the restore reads the verified backups). Source: ticket:GoodQA goodqa#15742
- NEG-4 (AC-2): `local-codex` with no `~/.codex/agent-harness` is refused before the fetch, creates nothing and writes no start row; the program itself also refuses a missing directory with a reason, not a traceback. Source: ticket:GoodQA goodqa#15913
- NEG-5 (AC-2): `local-codex` with a name outside `DELIVERY_HELPERS` at the commit (doctor.py) is refused before any call and before any audit row (scope-pinning: names only from the target's installer list). Source: ticket:GoodQA goodqa#15913
- NEG-6 (AC-5): a direct write into the hooks directories stays refused for main and for a sub-agent: `cp` into `~/.claude/hooks` (spelled `~` and `$HOME`), `mv` into it, a `cat >` redirect into it, `tee` into it, and `cp` of the guard into `~/.codex/agent-harness`. Source: wal:baab765b-d85c-46b4-b7b9-588eb912c770/main.jsonl#w3d3ce13675d
- NEG-7 (AC-4): an unfinished local run (a lost answer after the commit) blocks a new local run with `unfinished_run` but not `local-codex` or `t2-dev`, and a fleet host's unfinished run never counts for a local target (cross-host-approval-portability: runs are keyed per target, and a rollback reads its host from the run's own start row; idempotent-retry: `--resume` finishes it). Source: ticket:GoodQA goodqa#15742
- NEG-8 (AC-1): with `AH_AGENT_ID`, `PYTHONPATH` and a guard switch set in the caller's environment, the program's environment holds only HOME (the caller's home) and the allowlist PATH, LANG, LC_ALL, TMPDIR, USER, LOGNAME, SHELL. Source: inferred: from ticket:GoodQA goodqa#15913 -- the caller's switches must not change the self-test verdict that decides a rollback
- NEG-9 (AC-1): a root token outside `ROOTS` makes the program exit with `bad root` before it touches any directory (scope-pinning: the root is a token, never a path). Source: inferred: from ticket:GoodQA goodqa#15913 -- the program must never take a directory from its caller
- NEG-10 (AC-2): a `~/.codex/agent-harness` that is a symlink is refused and the link's target is unchanged (scope-pinning). Source: inferred: from ticket:GoodQA goodqa#15913 -- a planted link must not redirect the write
- NEG-11 (AC-1): a local dry run lists the plan and leaves the hooks directory's names, sizes, mtimes and inodes unchanged, with no state directory and no stage call (dry-run-diff). Source: ticket:GoodQA goodqa#15742
- NEG-12 (AC-4): a local `--rollback` while doctor is broken completes as `restored` and reports the self-test difference instead of refusing (rollback-not-blocked; remote-exec-audit: each run writes its start and result rows and one ticket comment, AC-1). Source: ticket:GoodQA goodqa#15742

## Resource budget

Host: mac
Fan-out: agents=1 jobs=1 processes=2 browser_pages=0 test_workers=1
Peak memory: 0.3 GB (method: one unittest process plus one short program subprocess)
CPU: 1 core (method: single-threaded unittest)
Disk: 0.05 GB (method: temporary homes holding a copy of harness/hooks per test)
Network: 0 MB (method: a local bare repository stands in for the canonical URL)
Wall time: 6 min
Cap and kill: none needed (focused tests and mutants, under 10 minutes)
Checkpoint: not required (under 10 min and 4 GB)

## Risks

- R1: a local install breaks the guard of the session running it (main's own). Mitigation: dry run first; command_guard.py renamed last; the baseline must already deny the foundational probe; self-test compared with the baseline; automatic rollback guard first (NEG-3).
- R2: a sub-agent writes `~/.claude/hooks` through the local route. Mitigation: the guard allows the command only from the installed ah.py and only for main, decided from the hook payload (NEG-1). This remains accident prevention, not access control: a program that writes the directory itself is invisible to a command-text guard, as before.
- R3: the caller's environment changes the self-test result. Mitigation: `-I` and an allowlisted environment (NEG-8).
- R4: the local "host" and the caller share one audit file. Mitigation: host keys `local` and `local-codex`; the host-side audit row is skipped (AC-1).
- R5: Claude-only files are written into the Codex directory. Mitigation: names come from `DELIVERY_HELPERS` at the commit (NEG-5).
- R6: the Claude Code sandbox refuses writes from the subprocess on main's first run. Effect: stage fails before any rename, the result is refused and nothing live changes. Main's dry run and first real run will show it.
- R7: the program is killed by its timeout part way through. Mitigation: the result is unknown, and the unfinished run blocks reruns until `--resume` or `--rollback` (NEG-7).
- R9: the bootstrap (AC-7). The Mac's installed ah.py (2e4cd2c6) and ah_install.py (0ccd1893) do not know the local target. The guard allows install-files only from the installed copy, so `--host local` cannot install itself. The one sanctioned route is the installers in `--hooks-only` mode from a clean checkout of the merge commit. They bring every listed hook file to that commit, c82ad2af's guard included, without the install-files self-test rollback, but with per-file backups and no CLAUDE.md or settings.json change. Mitigation: preview first; the Mac's guard self-test probes give identical verdicts and rules on the installed guard (6e318911), the Codex copy and c82ad2af (checked read-only, 2026-11-13); the live kit and plain probe run right after.
- R8: these guard gaps exist on c82ad2af, independent of this change, for main and for a sub-agent alike:
  - `install -m 644 x ~/.claude/hooks/ah.py` is allowed;
  - `rsync x ~/.claude/hooks/` is allowed;
  - `mv x ~/.codex/agent-harness/ah.py` is allowed.

  They are filed as GoodQA goodqa#15914 and not changed here, so that this packet stays reviewable.

## Domain checklist

Domains: auth, delete, devices, money, release

Detected from repository file names. This change touches only the install-files command.

Covered:
- backup-before-delete: AC-1 (both backups read back by sha256 before any rename) and NEG-3.
- dry-run-diff: NEG-11.
- scope-pinning: NEG-2, NEG-5, NEG-9, NEG-10 (fixed names, a fixed root token, symlinks refused).
- cross-host-approval-portability: NEG-7 (runs keyed per target; a rollback reads its host from the run's own start row).
- idempotent-retry: AC-4 (`--resume` after a lost answer; a rerun is already_current).
- remote-exec-audit: AC-1 (start and result rows, run id in the ticket comment).
- rollback-not-blocked: NEG-12.

Domain-gate: pre-account-hijack waived (no authentication flow is added or changed)
Domain-gate: lookalike-identifier waived (no identifier handling; host names are a fixed allowlist, NEG-2)
Domain-gate: request-device-binding waived (no approval or login flow involved)
Domain-gate: link-expiry-single-use waived (no link or token is issued or consumed)
Domain-gate: session-fixation waived (no session handling is touched)
Domain-gate: rate-limit-enumeration waived (no account lookup is involved)
Domain-gate: store-billing-exposure waived (no account state or billing is touched)
Domain-gate: unpushed-work-detection waived (no checkout, worktree or branch is removed)
Domain-gate: device-identity-binding waived (no device enrollment or grant is touched)
Domain-gate: unattended-recovery waived (a CLI run with no prompt; an interrupted run is recovered by --resume or --rollback, AC-4)
Domain-gate: grant-durability waived (no grant or approval is created)
Domain-gate: factory-reset-guard waived (no wipe or unenroll path is involved)
Domain-gate: idempotency-key waived (no money movement is involved)
Domain-gate: double-submit waived (no money flow or form is involved)
Domain-gate: currency-precision waived (no amounts are involved)
Domain-gate: refund-reversal-path waived (no money movement is involved)
Domain-gate: ledger-reconciliation waived (no ledger is involved)
Domain-gate: authorization-vs-capture waived (no payment is involved)
Domain-gate: derived-gate-floor-with-ratchet waived (no release gate with a numeric floor is touched)
Domain-gate: artifact-inventory-mirrored waived (no signed artifact; the bytes come from the canonical git main)
Domain-gate: self-update-e2e waived (not an updater feed; main's post-merge live install on this Mac is the end-to-end proof, AC-7)
Domain-gate: transport-proof waived (the tests run the real local transport and the constant program on disposable homes; AC-7 uses the same transport)
Domain-gate: staging-exists waived (a single-machine hook install; the dry run is the rehearsal and the self-test with automatic rollback is the canary)
