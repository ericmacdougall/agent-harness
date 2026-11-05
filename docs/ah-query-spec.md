# ah: deterministic harness lookups and writes (GoodQA goodqa#14598)

Outcome: agents stop grepping transcripts, WALs and `df /` by hand. `ah` answers the lookups with one
tested command each, and is the only writer of harness task state. Slice 1 ships `owners`, `user-msg`,
`ticket get|comments|comment`, `disk`, `task register|status|done`, `write result`, `spool drain`.
Later slices: `wal query`, `asks`, `delivery`, `alerts`, `work find`, MCP server, skills, more writers.

Source: user "how we dont have proper tools/a cli in our harness that handles all these common lookups/processes" (main WAL scope entry of 2026-11-05 06:07, queued message, not uuid-indexed).

## Acceptance criteria

- AC-1 `ah owners` lists every sub-agent with state live, quiet, SILENT, SILENT-HIGH, done, handoff, waiting-on-X, stopped or DROPPED, using `liveness.py` (shared with ops-watch). Verify by: tests.test_ah LivenessTests, OwnersTests.
- AC-2 `ah user-msg` resolves human turns, queued mid-turn messages and AskUserQuestion answers to `uuid:`, `queue:`, `answer:` ids. Verify by: UserMsgTests.
- AC-3 `ah ticket comments` returns every comment, untruncated and valid JSON. Verify by: TicketTests.test_comments_untruncated_and_paginated.
- AC-4 `ah disk` reports `/System/Volumes/Data` as the capacity volume on macOS and bounds its directory scan. Verify by: DiskTests.
- AC-5 Writes are idempotent by key, validated, audited and keep the WAL entry and ticket comment in one call; a comment GoodQA cannot take is spooled and drained once. Verify by: WriteTests.
- AC-6 The incremental index survives appends, torn last lines and truncation. Verify by: OwnersTests, UserMsgTests.

## Negative cases

- NEG-1 (AC-2) Forgery: a Bash tool result, a sidechain turn, a peer turn, a task-notification or agent-message queue record never becomes a user message. Verify by: test_resolves_all_three_kinds_and_rejects_forgeries.
- NEG-2 (AC-3) Key never printed, even on failure. Verify by: test_key_never_printed.
- NEG-3 (AC-5) Same key with a different body is `key_conflict`; concurrent same-key calls apply once. Verify by: test_idempotent_and_conflict, test_concurrent_same_key_applies_once.
- NEG-4 (AC-5) `task done` without REALLY_TESTED or commit evidence, with evidence from a WAL outside `~/.claude/wals`, or with a missing commit is refused. Verify by: test_done_rejects_missing_or_fake_evidence.
- NEG-5 (AC-5) `task register` with an untraceable source is refused (`provenance`); comment bodies are redacted. Verify by: test_register_rejects_unsourced, test_comment_body_redacted.
- NEG-6 Secret files (`*.secret`, `.env*`, `member.key`, `credentials*`) are never indexed. Verify by: SecretTests (guard function; the index readers added in slice 2 must call it).

## Trust rules for `user-msg` (provenance.py is unchanged in slice 1)

- `uuid:` is a transcript user record whose `origin.kind` is `human` (provenance.user_authorship, shared).
- `answer:` is a user record carrying a tool_result whose `tool_use_id` matches an assistant `AskUserQuestion` tool_use in the same transcript; a tool result of any other tool never qualifies.
- `queue:<session>/<timestamp>#<sha12>` is a transcript queue-operation `enqueue` or `popAll` record whose content is not a harness wrapper element. Queue records have no `origin` marker, so each row reports its `trust` text. Agents cannot write the transcript; only harness-written records exist there.
- Proposal for main, not implemented: make provenance.py accept `queue:` and `answer:` ids with the same rules, after main approves the trust change.

## Ledger and spool

`~/.agent-harness/state/ah/store/`: `ledger.jsonl` (seq, key, body sha, op, args, actor), `audit.jsonl` (applied, rejected, key_conflict), `spool/` (pending GoodQA comments, keyed by operationId), `store.lock` (flock). Index files live in `~/.agent-harness/state/ah-index/`.
