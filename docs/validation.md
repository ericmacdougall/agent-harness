# Validation record

This page separates observed behavior from intended workflow. Source fixtures and private Claude transcripts are not published.

## Automated checks in this repository

Run `python3 -m unittest discover -s tests -v` and `python3 -m compileall -q install.py harness tests`. The tests exercise guarded feature publication, rejected protected/stale pushes, a credential prompt under a real pseudo-terminal and a stalled remote (both must return `BLOCKED_REMOTE` instead of hanging), merge conflict and failed-check rollback, dirty-checkout preservation, rejection of a subdirectory or unparseable check before any merge, installer preservation/idempotence/symlink refusal, tolerance of foreign hooks with empty `args`, private backup directories, and private WAL metadata including `.`/`..` session identifiers. The tests isolate Git from user and system configuration. CI runs them on Ubuntu and macOS with Python 3.10 and the latest 3.x. These are deterministic helper checks, not proof that an autonomous agent follows the whole workflow.

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
