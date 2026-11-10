## goodqa#15561 slice S1e-a: contact detail and timeline in a desktop session started from a token (on by default)

User answer "Yes, on by default" (answer 419b4bba). Bound delegated door only; bearer answers unchanged in every switch state.

- W4: exact keys `GET /v1/orgs/:p/crm/contacts/:p` and `.../timeline`, ability `crm` + `read`, no org opt-in, no `userTokens.sessionActions`, never the session-action path. Operator tokens get no W4.
- Controls kept: org CRM switch (`crm.api.enabled`), a new org opt-out `userTokens.contactTimelines` false (platform-operator only today; org-admin control is a follow-up, labelled TARGET_MISMATCH in the spec), token org list, owner `crm:read`, revocation, ledger.
- Privacy: `q` and `pinned` refused for the session reader and `nextCursor` derived from the last visible entry (red-team N1, a live-probed content oracle); personal, busy_only and Gmail withholding verified on both routes.
- Spec v3 (reviews recorded: adversarial ACCEPT, acceptance ACCEPT; attached to #15561).

Evidence (t2-dev, `apps/api`): new `user-token-contact-timeline-default.test.ts` 23 of 23 (red first on 72290cc761e and again for N1); inventory, delegation (30), bearer-parity, rt3, desktop-session, gmail-limited-use (15), three CRM timeline suites green; `user-tokens-policy` keeps its 2 baseline failures; typecheck 276 baseline errors, none in changed files; 5 mutants killed.

Known limits: R1 existence bit of the cursor still follows the raw page (ticket), R2 a fully withheld page ends paging, no org-admin setter for the opt-out, a member without `crm:read` relies on the existing handler check. Not deployed, not click-tested (AC-5 needs the #15598 token mint).

Refs GoodQA #15561

🤖 Generated with [Claude Code](https://claude.com/claude-code)
