# S3a PR review packet (goodqa#15200, umbrella goodqa#14903)

Stage: PR review of the whole S3a change (native evidence; the scripted helper has failed PROVIDER_UNAVAILABLE on this repo before and needs a local clone the Mac cannot hold).

- Repo: github ericmacdougall/bugtracker. Read-only checkout on t2-dev: `ssh -o BatchMode=yes t2-dev`, path `~/wt/q3-s3a-ship`.
- Base: origin/main c6bb42381610 (live build e13e368802b3 plus its deploy record).
- Head: e70133059852fe4f48c0baf7c768ec7e70d41d95 (branch claude/qac-q3-s3-ship). Same content as review branch claude/qac-q3-s3-reports 65b2f145a316302e69f392ba282003a4c3dfa9e6 (equal stable patch-id ab9f4fb0).
- Spec: /Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/agent-a26cf320273795e32/s3spec/spec-s3a.md (v5). Prior spec reviews (v2-v4): /Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/native-reviews/qac-q3-s3a-v*-{adversarial,acceptance}.md.
- Main decisions in force (not user-confirmed): DQ-S3-1 no thread for persona-key routines; DQ-S3-3 6 reports/routine/UTC hour then one collapsed line; D1 (11-08) caps count the posting hour, not the finish hour; turn tokens gain no stop/retry powers; DQ8 only a person switches a routine live. Owner assumptions DQ-S3-4..8 are listed in the spec.

## Changed paths (15 files, +1341/-11)
apps/api/src/modules/automations/{run-reports.ts (new), engine.ts, openapi.ts, AGENT-DECISIONS.md}; apps/api/src/modules/cron/routes.ts; apps/api/test/{qac-run-reports-s3a.test.ts (new), commander-actions-world.ts, commander-approval-screen.test.ts}; packages/db/migrations/{14911_workflow_run_reports.sql, down/14911_workflow_run_reports.down.sql, meta/_journal.json}; packages/db/src/{platform-settings.ts, schema/workflows.ts}; docs/DARK-FEATURES.md; docs/qa-commander/WORKFLOW-DRAFTS.md.

## Last delta (bb3918c8bd..65b2f145)
Finish-order ranking of due rows; overlap barrier test for the row lock; collapsed-line copy; posting-hour cap test that kills mutant M31; `nextAt: NOW` pinned on two tests that failed once the wall clock passed their fixed NOW (DB default now()).

## Evidence so far
- t2-dev pgpool, `vitest run test/qac-run-reports-s3a.test.ts` on 65b2f145 tree: 42/42. Before nextAt pin: 2 failed. M31 applied: 1 failed (new test).
- Earlier owner mutant set M4-M33 on predecessor trees: all killed except M31 (now killed).
- Ship-tree gates (tsc gate, S1/S2/waits/schedule/history/commander/parity regressions) running; results reported separately.

## Risk / rollback
Dark behind platform setting `automations.qacRunReports` (default false). Migration 14911 is expand-only (two new tables, bounded backfill, lock_timeout 3s); rollback is the previous image with tables left in place; the down migration refuses while report rows exist.
