# S3a delta review packet (goodqa#15200, umbrella goodqa#14903)

Stage: delta PR review after your BLOCK on e70133059852 (packet a2814df5). Native evidence.

- t2-dev worktree `~/wt/q3-ship2`, branch claude/qac-q3-s3-ship2.
- Base: origin/main c6bb4238161bed2a83b74fb10382734ee224566b (unchanged).
- New head: 5acb018a1b529b7f528937c88b85a1b5ab2d4a6a.
- Delta to read: `git diff e70133059852fe4f48c0baf7c768ec7e70d41d95 5acb018a1b529b7f528937c88b85a1b5ab2d4a6a` (same base, so this is exactly the change since your review). It is three commits, cherry-picked from claude/qac-q3-s3-reports 8c9ff0ff9c8e and 9560780be647, and from claude/qac-kimi-fixes e8868c64d714.

## Your findings and what changed
- M1: enqueue bounds created_at by MAX_WAIT_DAYS + 2 days (run-reports.ts). Test: a run created 30 days ago and finished now is reported once.
- M2: a full thread gets one line per UTC hour (client id `run-summary-collapsed-thread:<conversationId>:<hour>`, new `anyLine` count, `lineDone`), and a routine at its own cap keeps its own line. Tests: 20 routines in one thread give 12 reports plus 1 line (13 messages); the 3-routine case expects the thread line.
- M3a (invite links): mint refuses an AI thread conversation (400, orgs/routes.ts). Accept refuses a preexisting link to an AI thread (assertCreatorStillAuthorized, invite-links.ts). The web header never shows Invite people on an AI thread, even with threads off (conversation-pane.tsx; a pinned web test is flipped, approved by main as a privacy product change). Test file: qac-ai-thread-invite-link.test.ts. This was also Kimi finding qac-privacy-001.
- M3b (main-approved): shareAiThread with history full on a thread that has a workflow_report_threads binding needs crm:read for every invitee (400 history_needs_crm_read, nobody added). from_now still works.
- L4: the barrier test asserts a handler actually blocked.
- L1-L3 and L5-L10: not changed. They go on the #14903 checklist unless you call one material.

## Evidence (failing-first, t2-dev pgpool)
- M1/M2/L4: run-reports.ts at the previous commit gives 3 failed | 41 passed (44); with the fix, 44/44.
- M3b: 1 failed | 44 passed; with the fix, 45/45.
- M3a api: at base, 2 failed (mint 201, accept 200); with the fix, 3/3. Web header test: old pane 3 failed; new, 37 passed | 1 skipped.
- Ship2 gates (tsc vs base errors, S1/S2/waits/schedule/commander/history-sharing/invite-link suites, web header suites): running; logs ~/wt/aab3-ship2.*.log.

Please check that the fixes are correct and non-vacuous, and whether they introduce new failures. Examples: an existing share or invite flow that legitimately targets a non-AI private channel; the per-thread line under concurrency of two routines' handlers (each holds a different per-workflow advisory lock; both recount under the conversation FOR UPDATE); and the M1 scan cost on workflow_runs_history_idx.
