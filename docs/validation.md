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

The final review found that a nonstandard remote default branch such as `trunk` could still be pushed. A new disposable-remote regression first failed with `PUSHED` where `BLOCKED_POLICY` was expected. The publish helper now asks `origin` for its advertised default branch and refuses a matching name. If the remote does not advertise a default, publication returns `BLOCKED_REMOTE` and local work can continue. The revised local suite has **34 passing tests**, and compilation and whitespace checks pass. CI for this final commit remains the merge gate.

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
