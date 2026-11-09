goodqa#14903 K2 (Kimi create-hang, Option B), API part. The web part is a separate stacked PR that ships after this one is live, because the create body schema is strict.

What
- POST /v1/orgs/:orgId/ai-threads takes an optional clientRequestId (uuid), stored as the first message client_msg_id.
- Under the per-user ai-thread advisory lock, the same request replays with 200 and replayed: true and writes nothing. "Same request" means: the caller's own general AI thread in this org, the same project, the same credential-redacted body hash, and the conversation still accessible.
- Any other reuse of the key is 409 client_request_conflict, with no detail about the other row.
- With a key, the lock wait is bounded to 5 s (lock_timeout is reset right after the lock statement). A timeout is 409 create_in_progress.
- A key needs a message and cannot carry a title. Requests without a key behave as before.

Evidence (t2-dev, pgpool lease)
- ai-thread-create-idempotency.test.ts: 12 failed and 1 passed before the change (NEG-10, the no-key path); 15 passed after.
- Controlled broken variants: lookup before the lock fails AC-3; hashing the raw body fails NEG-13.
- Neighbouring thread suites: 105 passed.
- API tsc: only 2 errors, both in untouched files (one is the known #15113; desktop-token-session.ts:143 is a base defect at 7b738654). 0 in changed files.

Spec: K2 spec with AC-1..9 and NEG-1..18, attached on goodqa#14903. AC-8 residual accepted by main and ticketed as #15508.

Risk and rollback: additive and API only, with no migration. Rollback is a revert of the commit. Any client_msg_id values already written stay harmless.

Refs: GoodQA #14903

🤖 Generated with [Claude Code](https://claude.com/claude-code)
