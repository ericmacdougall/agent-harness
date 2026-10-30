# Validation record

This page separates observed behavior from intended workflow. Source fixtures and private Claude transcripts are not published.

## Automated checks in this repository

Run `python3 -m unittest discover -s tests -v` and `python3 -m compileall -q install.py harness tests`. The tests exercise guarded feature publication, rejected protected/stale pushes, a credential prompt under a real pseudo-terminal and a stalled local pre-push hook (both must return `BLOCKED_REMOTE` instead of hanging), merge conflict and failed-check rollback, dirty-checkout preservation, rejection of a subdirectory or unparseable check before any merge, installer preservation/idempotence/symlink refusal, tolerance of foreign hooks with empty `args`, private backup directories, and private WAL metadata including `.`/`..` session identifiers. The tests isolate Git from user and system configuration. CI is configured to run them on Ubuntu and macOS with Python 3.10 and the latest 3.x. Local remote fixtures use bare repositories and Git hooks, without network listeners. The terminal reader drains output even when it observes process exit before the output becomes readable. These are deterministic helper checks, not proof that an autonomous agent follows the whole workflow.

## Independent PR hardening review, 2026-10-29

Review baseline: Fable head `29a57b7`, compared with main `843ff33`. Focused regressions reproduced a surviving push child, unavailable preparation leaving a merge open, a false restoration report after abort failure, deletion of a foreign hook sharing a managed entry, symlinked installer/WAL destinations, and existing WAL permissions remaining public. New integration deadlines cover both preparation and checks, including child cleanup. Installer tests exercise preview/apply refusal and idempotent hook preservation; both WAL writers exercise directory/file symlinks, hardlinks, FIFOs, and existing permissions. All fixtures are disposable; no real user installation is modified.

Failure-first evidence: five existing regressions fail against `843ff33` (three failures, two errors); the new push-child, merge-abort, installer, and WAL regressions fail against the relevant `29a57b7` code. Controlled variants removing integration deadlines, returning from the PTY reader immediately on child exit, or omitting the installed process helper also fail their focused regressions. The 120-dot session case reproduces a semantic-note rejection at `29a57b7`.

Local final validation: `python3 -m unittest discover -s tests -v` runs 32 cases, exit 0. `python3 -X pycache_prefix=/tmp/astra-review-pycache -m compileall -q install.py harness tests` and `git diff --check` both exit 0. The cache override is needed because the default Apple Python cache directory is outside the writable sandbox.

A process-exit/output-read race in the original PTY loop is confirmed with a controlled scheduling variant; an intermittent CI failure has not been observed. The new reader waits for both EOF and child exit. A successful real local merge and bare-remote feature push remain covered.

The review environment has macOS, Python 3.9.6, and Git 2.54.0. Python 3.9 is below the supported minimum and is only supplemental evidence. GitHub API and web access were unavailable, so the public PR body, original failure-first logs, and hosted CI outcomes could not be independently inspected. The main reviewer must check the supported Python/OS CI matrix before merging.

## Main reviewer follow-up

The main reviewer inspected the PR body, imported Astra's commit bundle, and reran its 32-test suite with exit 0. GitHub's push and PR checks for Astra head `1b86ca9` passed on Ubuntu and macOS with Python 3.10 and latest 3.x.

The final review found that a nonstandard remote default branch such as `trunk` could still be pushed. A new disposable-remote regression first failed with `PUSHED` where `BLOCKED_POLICY` was expected. The publish helper now asks `origin` for its advertised default branch and refuses a matching name. If the remote does not advertise a default, publication returns `BLOCKED_REMOTE` and local work can continue. The revised local suite has **34 passing tests**, and compilation and whitespace checks pass. Final PR head `29c5270` passed the Ubuntu/macOS × Python 3.10/latest matrix in both the [push run](https://github.com/ericmacdougall/agent-harness/actions/runs/40969652290) and [PR run](https://github.com/ericmacdougall/agent-harness/actions/runs/40969658661) before merge commit `214bacf`.

## Second hardening author evidence, 2026-10-29

Baseline: `6d6e0ba` after merged PR #1. The original 34 cases passed. Seventeen added cases were then run with the baseline production files in a disposable source snapshot: **18 assertion failures and 2 errors** (subtests count individually), exit 1; the distinct, safe push-URL positive control passed. Focused regressions were also observed before their fixes. The repaired working tree runs **51 tests**, exit 0, with `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v`. Compilation with `PYTHONPYCACHEPREFIX=/tmp/astra-round-two-pycache python3 -m compileall -q install.py harness tests` and `git diff --check` pass.

Observed failures and corresponding checks:

- Publication returned `PUSHED` for the actual destination's default branch when `pushurl` or `pushInsteadOf` differed from the fetch destination. Multiple destinations and a second URL rewrite during inspection also bypassed the intended boundary. Disposable bare remotes now verify rejection without ref changes, plus successful publication to a distinct destination with a safe default.
- Local Git inspections, merge, abort, and real pre/post-commit hooks exceeded `--timeout 1`. A failed `git status` was accepted as clean, and a failed final HEAD read still reported `INTEGRATED`. Fault injection delegates unaffected commands to real Git; assertions inspect HEAD, merge state, hook-start and late-write markers. The pre-commit child is killed. The post-commit case confirms that a commit may already exist when an abort fails.
- A missing late installer payload or a failed final replacement left partially upgraded files. A failed restoration had no recovery report. Files in place of directories and FIFO destinations were not rejected consistently before writes (settings FIFOs hung in preview and apply). Fault injection now verifies original bytes and permission bits, removal of newly written files, retained private backups, continuation after a restoration failure, and preflight refusal.

An additional live CLI scenario installed into a disposable home, checked preview made no writes and reinstallation preserved settings, then used the **installed** publication and integration helpers. The feature ref matched the verified commit; remote `main` stayed unchanged; a real file-content unittest passed before the local merge; both merge parents and a clean checkout were verified. No user installation was read or modified.

A separate process probe confirmed the deferred detached-child limit: with a 0.25-second deadline, a child using a new session survived and wrote its marker; the helper returned `TimeoutExpired` after roughly 1.23 seconds when the inherited pipe closed. Process-group cleanup is not process containment. Installation rollback likewise does not cover crashes, concurrent edits, or persistent storage failures.

Author environment: macOS, Python 3.9.6, Git 2.54.0. This Python is below the supported minimum; supported-version Linux/macOS CI and independent Fable/main review remain required. GitHub API access failed. The author's filesystem policy also rejected `.git/index.lock` creation, so these results describe the working-tree changes, not a new committed HEAD or hosted PR.

## Earlier live exercise, 2026-10-29

The precursor user-wide harness was exercised through fresh Claude Code sessions and nine small-to-medium app builds: three TypeScript, three Go, and three Python. All nine reached passing independent checks and were merged into their original local fixture checkouts. The fixtures had no `origin`; publication failed as designed while local delivery continued. One fresh background session on a Go inventory app reported the remote failure, reran Go checks, exercised its live API, merged locally and supplied a usable run kit.

The earlier local helper suite had five passing cases. The version in this repository adds installer and WAL tests and removes machine-specific settings. A local bare Git remote confirmed that publication pushed a feature branch while leaving `main` untouched. A separate watcher probe confirmed a changed source file triggered another test run.

One TypeScript app's final Sol review and browser retest passed for the changed flows. Its hidden-tab timing comparison was inconclusive because the browser did not throttle either run. Screen reader behavior and actual audio playback were not tested. The nine-app exercise is evidence of breadth and real agent use, not a statistically representative reliability estimate.

## Claims to verify in each installation

- Run `claude doctor` and start a new session after installing.
- Confirm the session WAL appears and a human-readable intent entry is written before an edit.
- Ask for a one-line, reversible fix and confirm the fast path skips delegation.
- Ask for a substantive task and inspect the owner ledger, worktree, review packet, live-test evidence and local handoff.
- Run the helper tests and a disposable repo publication/integration scenario before relying on automatic delivery in a new environment.

Model access, permissions, remote authentication, browser tools and OS behavior determine which gates can run. A missing reviewer or click tool must be reported rather than silently counted as PASS.
