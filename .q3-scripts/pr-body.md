QAC Q3 S3a: server-written run reports for QAC-drafted routines (dark), plus the AI thread invite-link privacy fix.

Tickets: GoodQA goodqa#15200 (S3a), umbrella GoodQA goodqa#14903 (also Kimi finding qac-privacy-001).

## What
- **Run reports.** Migration 14911 adds two expand-only tables, `workflow_report_threads` and `workflow_run_reports`, with a bounded backfill.
  - A routine drafted by a Commander turn remembers that turn's conversation.
  - Behind `automations.qacRunReports` (default false), the `run-automation-waits` cron posts one fixed-template report per finished real run.
  - Caps: 6 per routine and 12 per thread per UTC posting hour, plus at most one routine line and one thread line.
  - Each report has a fixed client id, so it is posted once. The audience is rechecked under the conversation lock.
- **Privacy.**
  - An invite link can neither be minted for nor admit anyone into a private AI thread.
  - The header never shows "Invite people" on an AI thread. This flips one pinned web test; main approved it as a privacy product change.
  - Sharing a report thread with full history needs crm:read for every invitee (400 `history_needs_crm_read`).
- **Tests.** The goodqa#15197 commander test world is fixed, and two wall-clock time bombs in the new tests are pinned.

## Review
- PR red-team (native, Opus xhigh) on e70133059852: BLOCK, with M1 (long waits), M2 (thread cap), M3 (privacy) and L1-L10.
- All Mediums were fixed failing-first. Delta review on 5acb018a1b52: ACCEPT-WITH-CHANGES.
- Delta findings:
  - N2 and N3 are fixed in e27659514951.
  - N1 (enqueue scan cost once the setting is on) is a hard gate on goodqa#14903 before the setting goes on (main decision). It is latent while dark.
  - N4: a read-only prod count found 0 links and 0 joiners.
  - N5 and the remaining Lows are on the goodqa#14903 checklist.

## Testing (t2-dev, pgpool, one vitest process per file)
- qac-run-reports-s3a 46/46. Every fix failed first against the previous code (counts are in the commit messages).
- qac-ai-thread-invite-link 3/3. At base, 2 failed: mint 201 and accept 200.
- Regression suites: S1 60/60, S2 61/61, waits-drafts 59/59, schedule 18/18, history 14/14, commander-actions 46/46. The invite-link, history-sharing and web header suites are in the gate run.
- tsc: the same 2 errors as base main (mxworld e2e, and a new main-side desktop-token-session.ts:143 error). Nothing new.

## Risk and rollback
- The feature is dark by default. The migration is expand-only, with lock_timeout 3s.
- Rollback: redeploy the previous image. The tables stay in place, and the down migration refuses while report rows exist.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
