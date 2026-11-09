# Spec: QAC-A Q3 slice K2 -- New AI thread: cancellable, idempotent create (Kimi create-hang)

Ticket: GoodQA goodqa#14903
Author: agent:aab3ea10 (claude-opus-5-5)
Click-test: required
Sign-off: main
Review-policy: standard

Reviews: two independent spec reviews (API data contract change, main ruling).
Status of the choice: main approved Option B (agent decision, not user words; ASSUMPTION that it matches user intent).
Code base: bugtracker origin/main 7b7386543f6 (= deployed 30c7e41b + deploy record). Batch 1 (37f928ff) stays a separate PR.

## Outcome

A person who starts a New AI thread is never trapped by a slow or lost create request: they can cancel the wait at
any time, a create the server already finished still shows up in their thread list, and submitting the same message
again (retry, double click, reopen-and-resend) opens the one thread already created instead of making a duplicate.

## Scope

- In:
  - API `POST /v1/orgs/:orgId/ai-threads` accepts optional `clientRequestId` (uuid). Under the existing
    `ai-thread:ORG:USER` advisory lock (taken before the hourly count), it looks up the caller's prior message with
    that id (`chat_messages` author + `client_msg_id`, unique index `chat_messages_client_msg_uq`, INCLUDING deleted
    rows). Match with the same request hash, in an AI general thread the caller owns in this org, same projectId ->
    replay: 200, same response shape plus `replayed: true`, no new rows, no hourly-count charge, no new QAC turn.
    Any other match (different hash, other conversation kind, other org, not the owner, other project, first message
    deleted) -> 409 `client_request_conflict`; the body reveals nothing about the other row. No match -> today's
    create, passing `clientMsgId = clientRequestId` to `appendMessage` so the first message carries the key.
  - `clientRequestId` without `message` -> 400 (nothing to key on).
  - Web `useCreateAiThread`, `NewAiThreadDialog` and `AiThreadPanel`:
    - State owner: the dialog is unmounted on close (`ai-thread-panel.tsx` renders it only while `creating`), so the
      draft `{ message, scope }`, the key `{ payloadKey, id }` and the in-flight `AbortController` live in a small
      hook owned by `AiThreadPanel` (`useNewThreadDraft(orgId)`), passed to the dialog; reset when `orgId` changes.
    - Key rule: payloadKey = JSON of { trimmed message, scope }. The id is reused while payloadKey is unchanged
      (across Cancel and reopen); a new uuid when payloadKey changes; cleared after a confirmed success. Cosmetic
      edits that normalize to the same payload (trailing spaces, edit then revert) keep the id.
    - Cancel, Escape and overlay close stay enabled while pending. Every close path calls abort explicitly; an
      unmount cleanup also aborts. The abort is not shown as a failure. The hook-level onSuccess (cache insert and
      list invalidation) still runs if the server answers before the abort lands; the per-call onCreated and
      close callbacks never run after the dialog was closed.
    - Notice: after a close while pending, a dismissible `role="status"` line in the panel above the thread list
      says "Stopped waiting. If the thread was created it will appear in your list."; it clears on the next create.
      The thread list query is invalidated. Focus returns to the New thread button.
    - Pending state: textarea and scope stay disabled while pending (no edit while pending); Cancel keeps its label;
      the submit button reads "Starting...".
    - Draft: kept on cancel or failure, cleared only after a confirmed success.
    - Double click / Enter repeat while pending: one request (isPending guard stays).
    - Title: the web client never sends a title. On the server, a key with a title is compared too (title is part of
      the request hash), so MCP callers cannot replay a different title.
  - Rollout: API first (the strict body schema would 400 an unknown field), web after the API is live. Each side
    reverts independently: the API change is additive and ignored by old clients; `client_msg_id` values already
    written stay harmless after a revert.
  - Accepted behaviour: if the server finished before a cancel, the thread appears in the list while the draft stays
    in the dialog; resending replays and opens that same thread.
- Out: other create paths (MCP `create_ai_chat_conversation`, desktop) keep working without the key; no migration;
  no change to the 60/hour limit, lock order or message rails; the other Kimi findings.

## Acceptance criteria

- AC-1: A create with a fresh `clientRequestId` creates one thread whose first message has `client_msg_id` = that id and returns 201 as today. Verify by: API vitest `ai-thread-create-idempotency.test.ts` "fresh key creates once" on the test database. Source: inferred: from ticket:GoodQA goodqa#14903 ; file:apps/web/src/components/messaging/new-ai-thread-dialog.tsx:32@7b738654 -- Option B approved by main
- AC-2: Repeating the same request (same key, message and projectId) returns 200 with the same conversation id and `replayed: true`, creates no rows (conversation, thread, member, message counts unchanged) and enqueues no QAC turn. Verify by: same file, "replay returns the original", row counts before and after. Source: inferred: from ticket:GoodQA goodqa#14903 ; file:apps/web/src/components/messaging/new-ai-thread-dialog.tsx:32@7b738654 -- duplicate thread on retry is the defect
- AC-3: Two concurrent requests with the same key produce exactly one thread; the other gets the replay. Verify by: test firing both with Promise.all on separate connections. Source: inferred: from ticket:GoodQA goodqa#14903 ; file:apps/api/src/modules/messaging/ai-thread-lifecycle.ts:39@7b738654 -- advisory lock serializes per org+user
- AC-4: A replay is not charged against the 60/hour limit: with 59 threads in the hour, create #60 then replay it -> 200. Verify by: test seeding 59 threads. Source: inferred: from ticket:GoodQA goodqa#14903 ; file:apps/api/src/modules/messaging/ai-thread-lifecycle.ts:51@7b738654 -- count runs before insert
- AC-5: In the dialog, Cancel, Escape and overlay close work while the create is pending; the request is aborted client-side; no error toast; the neutral status notice shows in the panel; the thread list query is invalidated; the draft is kept; focus returns to the New thread button. Verify by: web vitest through `AiThreadPanel` with a never-resolving fetch, `it.each` over [Cancel button, Escape key, overlay click]: fetch received a signal and `signal.aborted` is true after close, no toast, `role="status"` text present, `document.activeElement` is the New thread button. Source: inferred: from ticket:GoodQA goodqa#14903 ; file:apps/web/src/components/messaging/new-ai-thread-dialog.tsx:32@7b738654 -- close blocked while pending (Kimi create-hang)
- AC-6: Reopen after cancel and submit the same text -> same `clientRequestId`; edit to a different message -> new id; cosmetic edit that trims to the same text -> same id; after success the next create uses a new id and the draft is cleared; after a cancel, a scope change gives a new id; a different org starts with an empty draft and no id. Verify by: web vitest rendering through `AiThreadPanel` (cancel, reopen, resend) capturing request bodies and asserting the same draft text and `clientRequestId`. Source: inferred: from ticket:GoodQA goodqa#14903 ; file:apps/web/src/components/messaging/new-ai-thread-dialog.tsx:32@7b738654 -- key rotation rule
- AC-7: Live on the deployed build: the same key sent twice returns 201 then 200 `replayed: true` with the same conversation id and the caller's thread list grows by exactly 1; in the UI, cancel while pending, reopen, resend gives exactly one thread in the list. Verify by: post-deploy API check as the owner (disposable thread, archived afterwards) plus independent click-test with a throttled network. Source: inferred: from ticket:GoodQA goodqa#14903 ; file:apps/web/src/components/messaging/new-ai-thread-dialog.tsx:32@7b738654 -- done means live and tested

## Negative cases

- NEG-1 (AC-2): same key, different message text -> 409 `client_request_conflict`, nothing created. Source: inferred: from ticket:GoodQA goodqa#14903 ; file:apps/api/src/modules/messaging/messages.ts:1023@7b738654 -- existing reuse-with-different-content rule
- NEG-2 (AC-2): same key and text, different projectId (or none vs some) -> 409. Source: inferred: from ticket:GoodQA goodqa#14903 ; file:apps/web/src/components/messaging/new-ai-thread-dialog.tsx:32@7b738654 -- payload includes scope
- NEG-3 (AC-2): key equal to the client_msg_id of the caller's ordinary message in a non-AI conversation, or of an AI thread in another org -> 409, response has no id, title or body of that row. Source: inferred: from ticket:GoodQA goodqa#14903 ; file:packages/db/src/schema/chat.ts:343@7b738654 -- key space is per author across all conversations
- NEG-4 (AC-2): another user's key value (same uuid) -> no match for this caller, creates normally, never returns the other user's thread. Source: inferred: from ticket:GoodQA goodqa#14903 ; file:packages/db/src/schema/chat.ts:343@7b738654 -- unique per author
- NEG-5 (AC-2): first message of the original thread deleted, then retry with the same key -> 409, never a 500 from the unique index; thread archived, then retry -> replay of the archived thread. Source: inferred: from ticket:GoodQA goodqa#14903 ; file:apps/api/src/modules/messaging/messages.ts:1016@7b738654 -- history predicate hides deleted rows from the existing lookup
- NEG-6 (AC-1): `clientRequestId` without `message` -> 400; malformed uuid -> 400. Source: inferred: from ticket:GoodQA goodqa#14903 ; file:apps/api/src/modules/messaging/routes.ts:5355@7b738654 -- strict body schema
- NEG-7 (AC-2): caller lost access to the project or org between attempts -> the access check runs first and refuses as today, no replay. Source: inferred: from ticket:GoodQA goodqa#14903 ; file:apps/api/src/modules/messaging/ai-thread-lifecycle.ts:28@7b738654 -- access checks precede the lock
- NEG-8 (AC-5): response arrives after Cancel -> no navigation, no onCreated, no toast; the list refresh shows the thread. Source: inferred: from ticket:GoodQA goodqa#14903 ; file:apps/web/src/components/messaging/new-ai-thread-dialog.tsx:32@7b738654 -- delayed completion after cancel
- NEG-9 (AC-6): network error or 5xx, then retry -> same key reused, at most one thread. Source: inferred: from ticket:GoodQA goodqa#14903 ; file:apps/web/src/components/messaging/new-ai-thread-dialog.tsx:32@7b738654 -- lost response and retry
- NEG-11 (AC-5): two rapid submits produce one fetch; then Cancel and resubmit of the same text produces a second fetch carrying the same key. Source: inferred: from ticket:GoodQA goodqa#14903 ; file:apps/web/src/components/messaging/new-ai-thread-dialog.tsx:43@7b738654 -- isPending guard on submit
- NEG-12 (AC-2): same key and message but a different title (MCP caller) -> 409. Source: inferred: from ticket:GoodQA goodqa#14903 ; file:apps/api/src/modules/messaging/routes.ts:5355@7b738654 -- title is an accepted body field
- NEG-10 (AC-1): clients without the key -> unchanged (201, no dedupe). Source: inferred: from ticket:GoodQA goodqa#14903 ; file:apps/api/src/modules/messaging/routes.ts:5355@7b738654 -- backward compatibility

## Domain invariants

- One thread per (author, clientRequestId); the first message is the durable record of the key.
- Lock order unchanged: access checks, then the `ai-thread:ORG:USER` lock, then lookup, then count, then inserts.
- A replay never reveals anything about rows outside the caller's own AI thread in this org and scope.
- A cancelled wait is not a failure and never shows as one.

## Risk table

| Invariant | Failure mode | Control | Negative case | Expected |
|---|---|---|---|---|
| no duplicates | race between two retries | lookup under advisory lock, unique index backstop | AC-3 | one thread |
| no leaks | key collides with another row of the caller | strict match on kind, org, owner, project, hash | NEG-3 | 409, no detail |
| no 500 | deleted first message hidden from lookup | lookup includes deleted rows | NEG-5 | 409 |
| quota fair | replay charged | lookup before count | AC-4 | 200 |
| no ghost UI | late response after cancel | abort signal, ignore after close | NEG-8 | no navigation |
| compat | other callers break | key optional | NEG-10 | 201 |

## Resource budget

Host: vm:t2-dev
Capacity: 110 GB memory, 48 cores, 69 GB disk free
Fan-out: agents=1 jobs=1 processes=3 browser_pages=0 test_workers=4
Peak memory: 4 GB (method: prior vitest runs in this worktree)
CPU: 4 cores (method: vitest default workers)
Disk: 1 GB (method: pgpool lease database plus build output)
Network: 50 MB (method: git push only)
Wall time: 90 min
Cap and kill: focused vitest files only, timeout 900s each; stop own pids with ah kill
Checkpoint: idempotent steps (each focused test run and commit can be repeated safely); commits on claude/qac-kimi-create pushed after each green step; it resumes from the last pushed commit, with spec and reviews under .q3-scripts/create-idem/ in the owner worktree

## Risks

- appendMessage runs its own idempotency lookup with the history predicate: the create-level lookup must run first and include deleted rows, or a deleted-message retry reaches the insert and hits the unique index (500). NEG-5 covers it.
- The replay response must rebuild the same shape (conversation + ai summary + first message); drift breaks client navigation. AC-2 asserts the shape.
- Abort on close relies on api() honouring the caller signal (documented in lib/api.ts); AC-5 verifies it.
- The 409 code is new to this route; the dialog shows the server message (batch 1 path). Rollback: revert the PR; no migration (column and index already exist).
