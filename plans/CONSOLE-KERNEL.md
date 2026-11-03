# Console kernel plan

Status: accepted. Plan review round 3 returned ACCEPT on revision 3, with the findings below carried to their slices. No kernel code exists on this branch.

## Decision and why

Console 0.2 will not ship. It is rebuilt on a durable event log with one pure reducer.

Across six exact-head reviews the blocker count did not converge, and repairs caused new blockers. The session has about 50 fields mixing presentation and authority. `Status` is assigned at about 90 non-test sites, and `restore()` is a second hand-written projection of the same truth. A seeded restore-versus-live test against the last repaired head measures the drift: see [the catalog](CONSOLE-KERNEL-CATALOG.md).

The catalog is the specification. Each entry names a defect the review record found, and the rule that excludes it.

## Invariants

- **INV1** Receipts follow the table below. Nothing leaves a terminal state.
- **INV2** The projection after replaying any prefix of the log equals the live projection at that point, for every field marked authority in the field table. A difference is allowed only where the enumerated restart rules define it.
- **INV3** A session with an unresolved receipt or a retained payload is never dropped, trimmed or closed without an `Abandoned` fact.
- **INV4** No new provider work (start, resume, continuation) is admitted unless the last receipt is resolved, the session is writable, and the runtime identity matches the one that owns the conversation. A question answer is admitted only while its own request is the active one. Stop-work effects are always available.
- **INV5** Opening the log or reconnecting a browser makes no provider call. Starting a new session is a user action or an explicit launch argument, and is outside this rule.
- **INV6** Secrets, prompt bodies, question text and attachment bytes never enter the log. It holds references and keyed digests, enum reasons, and one redacted, bounded, user-written field: the discard reason.
- **INV7** A fact is committed before the effect it authorizes. A provider effect with no observed result is unknown and is never retried. A local effect is idempotent and is reconciled from the projection on open.

### Receipt table

| From | To |
|---|---|
| none | `intent` |
| `intent` | `accepted`, `final`, `unknown`, `rejected`, `abandoned` |
| `accepted` | `final`, `unknown`, `rejected`, `abandoned` |
| `unknown` | `abandoned` |
| `final`, `rejected`, `abandoned` | terminal |

`intent -> final` covers a result that arrives before the write acknowledgement. `unknown` is sticky by decision: a native final that arrives after it is kept as `LateFrameObserved{kind: final, status}` and shown, but does not change the receipt. The user discards the turn. This is the user's decision. Discard and continue-in-new-session both show that a late final was observed and that its output is not carried forward.

## Shape

```
HTTP / UI    adapters (Codex, Claude)     frames, exits, replies
    | commands        | observations
    v                 v
 Decide(projection, input) -> facts + effects | refusal   pure
    | facts: reduced on a copy first, so an illegal fact is never committed
    v
 Log.Append(expected revision, facts)                     one transaction
    | decoded facts, read back from what was encoded
    v
 Reduce(projection, fact) -> projection                   pure, sole writer of authority
    |
    v
 effects run outside every lock, each rechecked at its fence
    | results return as observations
```

`console/internal/kernel` holds `Decide`, `Reduce` and the closed enums. It imports nothing from the console, does no I/O, and reads no clock.

### Effects

`Decide` returns effect descriptors with its facts. Replay calls only `Reduce`, so replay can never fire an effect.

**New-work effects** (start a turn, write a frame, answer a question) carry `{sessionId, requestId, processEpoch, fence}`, where `fence` is the session's control epoch. The gate belongs to the actual writer, so a shared Codex client's stdin has one gate. The adapter takes it, rechecks the fence and the log health latch against the published state, writes, and holds the gate until the write completes. A stale fence or a latch means no write, and the result is `ProviderRefused`.

**Revocation drains.** After a revoking fact (`Abandoned`, `AuthBoundaryCrossed`, a stop control) publishes, and outside the kernel lock, the revoker drains that writer's gate before acknowledging or before credentials change. If the drain passes its deadline, the revoker kills the process group and records `OutcomeUnknown`. This closes the window between a recheck and the write syscall, which a test holds open.

**Stop-work effects** (interrupt, terminate, process-group kill) never take the write gate, ignore fence staleness, and stay available when the log is latched, so a hung write or a later boundary cannot prevent a stop.

The outcome of a provider effect is an observation:
- Definitely not written: `ProviderRefused`.
- Possibly written, or past the effect's acknowledgement deadline: `OutcomeUnknown`.
- Provider acknowledged: `ProviderAccepted`.

Deadlines are per effect and cover only the write or RPC acknowledgement, generously, since `unknown` is irreversible. A running `accepted` turn has no timer, and a test shows an fsync stall cannot trigger a deadline.

A pending interrupt is projection state, not an adapter flag. `TurnBound` always reaches `Decide`, including on an abandoned request, where it emits the interrupt effect and changes no receipt. So the interrupt cannot be lost, and cannot fire on replay.

**Local effects** (rename the imported journal, attachment cleanup, worktree removal) are idempotent. On open, a reconcile pass derives them from the projection and runs them. It appends only the facts recording their results.

### Restart rule

Opening appends one global `ProcessRestarted`. Its reducer rule, the same one live and on replay:

| State | After restart |
|---|---|
| Open receipts (`intent`, `accepted`) | `unknown` |
| Every session | Read-only, no writer |
| Pending and answered-but-unconfirmed questions | Revoked |
| Dispatching inputs | `unknown` |
| Queued inputs | Held |
| Pending controls | Dropped, with the receipt unknown if unresolved |
| Running review runs | `unknown` |
| Live children | Quarantined |
| Supervision | Paused, with reason `restarted` unless discarded |
| Review results pending | Cleared |
| Resolved history beyond the visible limit | Hidden for good |

### Other rules that remove whole classes

- **Late frames cannot reopen.** A frame on a terminal or foreign request becomes `LateFrameObserved`, coalesced per `(request, kind)`, with its status and a digest. Content deltas never reach `Decide`, and a late frame's text enters the transcript only marked as late, because transcripts feed provider input in continuation.
- **Guards live once.** `Decide` is not provider-specific. Adapters translate frames and do not decide.
- **Status is derived.** `Status` is a pure function of the projection plus the connection state from `ProviderConnected` and `ProviderDisconnected`. Nothing assigns it once a session is kernel-owned.
- **Discard is a fact.** `Abandoned` needs a matching expected request and a reason. Idempotency is on `(session, request)`, so a retry with a different reason returns the first fact rather than a conflict. It moves an unresolved receipt to `abandoned`, leaves a `final` alone, and makes the session read-only and closable once payloads are released. It carries no verdict or pass, and does not claim the provider stopped.
- **A bad fact does not take down the console.** A log that cannot be read refuses with a clear message. An invalid transition in a readable log quarantines that session read-only and leaves the rest running. Discard and close still work on a quarantined session. Reducing on a copy before commit means this should arise only from a reducer change.
- **History keeps its meaning.** From K11, reducer semantics are frozen per `schemaVersion`, with golden log fixtures. Development logs before K11 are disposable.

### Fact vocabulary

Every fact has `seq`, `schemaVersion`, `at`. Session facts also have `sessionId` and `sessionRevision`. Global facts have no session.

- **Global:** `ProcessRestarted`, `LegacyImportCompleted{digest}`.
- **Session and provider:** `SessionCreated`, `ConversationBound{providerId}`, `ProviderConnected`, `ProviderDisconnected`, `RuntimeIdentityBound`, `AuthBoundaryCrossed`, `CwdChanged`, `SessionClosed`, `Abandoned{requestId, reason}`, `SessionQuarantined{reasonCode}`, `SupervisionChanged{state, reasonCode}`, `CascadeSelected`, `PolicyBound{revision}`, `ContinuationBudgetChanged{remaining, progress}`.
- **Requests:** `RequestIntended`, `ProviderAccepted`, `ProviderRefused`, `ProviderCompleted{status}`, `OutcomeUnknown{reasonCode}`, `TurnBound{turnId}`, `LateFrameObserved{kind, status, digest}`, `AdmissionRefused{reasonCode}`. The last is only for automatic continuations and queued dispatch, where no user is waiting on a response, coalesced per reason. A user command gets its refusal in the response.
- **Controls:** `ControlRequested{pause|stop|resume}`, `ControlOutcome{confirmed|rejected|unconfirmed}`.
- **Questions:** `QuestionOpened{id, kind, digest, expiresAt}`, `QuestionAnswered`, `QuestionRevoked`.
- **Children:** `ChildObserved{id, role, turnId}`, `ChildControlOutcome`, `ChildQuarantined`.
- **Inputs and payloads:** `InputQueued{payloadHash}`, `InputDispatchPrepared`, `InputOutcome`, `InputDiscarded`, `PayloadReleased`.
- **Reviews and checkpoints:** `ReviewStarted`, `ReviewCancelled`, `ReviewOutcome{verdict|failed|unknown}`, `ReviewResultPending`, `CheckpointRecorded`.
- **Import:** `LegacyImported`, `LegacyInputHeld`.

Unknown kinds or versions refuse the log. A provider ID or path is identity, not a secret, and is stored as is.

### Field ownership

Every current session field is one of these. INV2 covers authority fields only.

| Class | Fields |
|---|---|
| **Authority, in the projection** | `ID`, `Provider`, `ProviderID`, `ProfileID`, `CWD`, `lastRequest`, `requests`, `requestOrder`, `task`, `Work`, `controlEpoch`, `dispatchEpoch`, `providerFinal`, `queueUncertain`, `Restored`, `resumeRequested`, `cancelRequested`, `inputs` (metadata), `PendingQuestions` (identity), `Agents` (identity and control state), `turnID`, the `review*` fields, `Cascade`, `PolicyRevision`, `claudeStarted`, `conversationRuntimeHash`, `abandoned`, `Supervision.State`, `Supervision.Reason`, `Supervision.RemainingBursts`, `Supervision.progress`, `Supervision.lastProgress`, `pendingReviewResult` |
| **Derived** | `Status`, `Error`, `Supervision.NextCheckpoint` |
| **Adapter, process-local, gone after restart** | `codex`, `claude`, `codexTurn`, `dispatchMu`, `delivery`, `reviewDone`, `filters`, `scheduled`, `policy` (re-resolved per dispatch) |
| **Presentation, not durable** | `Title`, `Model`, `Effort`, `Messages`, `Usage`, `Attachments` (composer), `attachmentSnapshots` (composer), `context` |

Continuation guards read these budget and progress fields, so they are authority and `Decide` can see them. Each authority field has one writing fact, kept as a table in `internal/kernel` and checked by a K1 test that every fact in that table is produced by its generator. The test that every `session` struct field is classified needs that struct, so it lands in K5a as an AST test in `package main`.

### Log health

`eventlog` has one latch, documented as the only authority outside the log, and it can only refuse:

| Append outcome | Meaning | Effect |
|---|---|---|
| Committed | Fact is durable | Reduce and continue |
| Definite failure | Transaction rolled back, nothing written (disk full, quota) | Nothing reduced. The command returns an error and the turn stays resolvable. Observations stay in a bounded per-session retry buffer; on overflow, go to latched |
| Ambiguous commit | Any commit error not known to precede commit | Latched. Restart replays the truth. Read-back is not trusted, because a present fact may not be durable and an absent one may reappear on recovery. It may be added only if K2's fault injection, including an injected fsync failure, proves it safe |
| Revoking fact not committed | `AuthBoundaryCrossed`, `QuestionRevoked` or `ChildQuarantined` failed, even definitely | Latched, because authority must not outlive the failure |
| `ProcessRestarted` not committed at open | Disk full or quota at start | Start latched and read-only from replay, with a visible message |
| Latched | Log state is unknown | All new work refuses and every effect recheck sees it. Stop-work stays available. Sessions show read-only with a restart message, until restart replays the truth |

A definite failure on discard leaves the turn resolvable (D7). A latch revokes authority because nothing can be decided (P1). Both are visible in the session state. Discard on a full disk may therefore fail; the reserve below is logical only, so a real ENOSPC refuses and says so.

**Must-append class.** Every fact needed to discard, release, close, or record a terminal outcome is exempt from the quota, using a reserved headroom: `ProcessRestarted`, `ProviderCompleted`, `OutcomeUnknown`, `Abandoned`, `SessionClosed`, `InputOutcome`, `InputDiscarded`, `PayloadReleased`, `ReviewOutcome`, `ControlOutcome`, `ChildControlOutcome`, `QuestionRevoked`. The reserve is sized from the bound on open requests and payloads. `ProcessRestarted` is not appended when the last fact is already one, so a crash loop cannot spend the reserve, and process epochs need no durability because fences are in-process. If the reserve is exhausted, the log latches.

### Storage

SQLite through `modernc.org/sqlite`, as a transactional append-only log: `metadata`, `facts`, `receipts` (command ID unique, keyed digest bound, no command bodies). No materialized session tables. Open folds the log into memory.

Rejected: a custom JSONL log. Torn tails, partial writes, rename outcomes and beforeimages produced recurring blockers in the current files.

Reads serve a published immutable projection, so an fsync never blocks a read. The kernel lock is held across decide, append and reduce only, never across a provider write or a wait on another subsystem. Appends can stall on fsync, and a test covers that stall.

Falsify before building on this (first step of K2):
1. Replaying 100,000 facts of a stated mix on the Mac through the real open path takes under one second, and 1,000,000 is measured. If it fails, add a snapshot as a discardable cache keyed by reducer version.
2. p99 append latency with full sync, and projection memory, are measured and stated, including closed sessions that are never removed.
3. `kill -9` at each transaction boundary, on Linux, Mac and Windows, plus WAL truncation, loses only unacknowledged facts.
4. `fullfsync` and `checkpoint_fullfsync` are set per connection, read back, and shown by syscall trace to reach `F_FULLFSYNC` on the Mac. The current console's durable path uses it, so losing it would be a regression that kill tests cannot detect.
5. The dependency is refreshed and scanned. v1.34.5 in Slice A is old, newer releases exist (v1.52.0 appears in dependency-bot data, not confirmed from an authoritative source), and `govulncheck` has not been run. Also record and check the embedded SQLite's upstream version, which `govulncheck` may not cover.

If 3, 4 or 5 cannot be met, stop and reassess the store.

**Growth.** The 8 MiB refusal goes away. K2 states a numeric quota, and user recovery is an export followed by an explicit start in a new data directory, since export alone frees nothing. Quota checks use a counter rather than `COUNT(*)` per append.

## Reuse, verified against the branches

Executed on a Linux runner with pinned Go 1.27.3: engine `cd54641` `./internal/...` passes normal and race, including store crash and quota tests; preview `a32e510` `./internal/core` passes normal and race. This proves only that those tests pass. No review verdict covers `086b075`, `bb6e113` or `cd54641`: the last completed review of this code, on `006a17e`, blocked with nine findings, and the delta review of `086b075` has a prompt but no result.

| Item | Decision | Reason |
|---|---|---|
| Store WAL and sync pragmas, format-version refusal, headroom, test barriers, row checksums, sequence gap check | **Reuse, re-review as new code in K2** | Real mechanics, tested. Pragmas move per connection, with fullfsync added. |
| Store directory lock | **Replace** | It locks `authority-preview.lock` and refuses any directory holding other files. The kernel takes `console.lock`, which `6172744` was confirmed to hold, before reading anything. |
| Store receipts, idempotent `Submit`, digest binding | **Reuse the design, rewrite against facts** | Correct contract, but it stores canonical commands, which INV6 forbids for sends. |
| Store `sessions`, `budget_ledger`, `tombstones`, materialized checks | **Reject** | A second projection. |
| Core strict JSON prepass, canonicalization, Unicode alias defence, `Authorize` and principal binding | **Reuse in K1, adapted** | Discard must be user-only and checkpoints agent-scoped. It accepts lower-case ASCII keys only, and current wire names are camelCase, so it applies at an internal boundary with a translation. |
| Core session and budget vocabulary, `ApplyEvent` | **Reject** | No request, question or queue vocabulary. |
| Preview `unified_preview*.go` (2,328 lines) | **Reject** | Synthetic only. |
| Preview `THIRD_PARTY_NOTICES`, packaging stale-notice refusal, tests | **Reuse in K2**, regenerated | Needed once SQLite ships. |
| `plans/UNIFIED-RUNTIME.md` on the engine branch, and an earlier private next-slice plan | Reference only | The next-slice plan was written by a low-effort subagent and never reviewed. |

Engine history includes four commits under a non-public email, so no engine commit is cherry-picked. Reused code enters as new commits on the public identity. The Hermes-derived engine stays separate.

Kept from the 0.2 branch at `111631d`: UI, settings and vault, GoodQA proxy, repository views, attachment snapshot mechanics, packaging. Its discard UI, seeded test and process-tree tests are starting material. None of that branch's lifecycle code is treated as correct.

## What the kernel does not fix

These are adapter and OS concerns.

- **Lock order.** The rule above, enforced by tests with timeouts. Tests written in K4 against the old locks are rerun as acceptance in K5 to K7 on the new ones.
- **Process groups.** Stop the whole group on every path that loses supervision, before `Wait` reaps the leader. Keep background work after a true final. Add `WaitDelay` and a leader-exit watch, and recheck a reaped flag before any signal. Windows is qualified as compile-only unless K11 adds a Windows runner, and the release states which.
- **Runtime identity.** Compute a revision-free conversation identity, separate from the client cache key, for both providers, in the adapter. The refusal decision moves into `Decide` in K5 and K6, so no guard stays in the adapter.
- **Orphans.** After a crash, a provider process can outlive the console and keep writing in its cwd. Nothing can prove it stopped. The restored tab and "continue in a new session" both warn about this.

## Old sessions: one-way import

No second reader for the journal. Queue payloads need one permanent, bounded, read-only decoder in K3, because held inputs must still be shown and released; it reuses the existing `.previous` merge logic.

**Exclusion.** Import takes `console.lock` before reading anything. `6172744` holds that same lock, confirmed from source, so a running 0.1.0 makes import refuse with nothing changed. Before the first real commit, a no-write verify pass runs on the actual stopped directory; a rehearsal on a copy can capture a torn state, so it is not sufficient.

**Inventory of a 0.1.0 data directory:** `console.lock`, `sessions.jsonl`, `queued-inputs/` with `.previous` files, `attachments/`, and settings and credential transaction files. Settings stay where they are. K3 confirms this list against `6172744`.

**Journal mapping, in one transaction:**

| Last record with a request | Imported receipt | Session |
|---|---|---|
| `final` | `final` | Read-only |
| `rejected`, `paused` | `rejected` | Read-only |
| `intent`, `accepted`, `unknown` | `unknown` | Read-only, discard available |
| `abandoned` | `abandoned` | Read-only, closable |
| None (`created`, `cwd`, `admission_failed` only) | None | Read-only |

The session's last record decides only `closed`, which imports nothing for that session. Every imported session can be closed, subject only to INV3: a `final`, `rejected`, no-request or synthetic session closes directly, and an `unknown` one closes after discard. `LegacyImported` carries `{sessionId, provider, providerId, cwd, profile, lastRequestId, receipt, taskId, generation, inputRevision, objectiveHash, passes}`. Passes import as history and authorize nothing. Review records become `ReviewOutcome{unknown}` on their parent. Checkpoints become task metadata.

**Queue files** become `LegacyInputHeld` by hash, with the payload staying in place and its attachment snapshot references recorded on the fact. Kernel orphan cleanup is restricted to the kernel's own namespace, so legacy attachments are never treated as orphans. An orphan with no session is imported as a held input under a synthetic read-only session, so it stays visible. A corrupt queue file is set aside and shown on its session as unknown, without refusing the console. An entry missing `DirectoryIdentity` is held, and its release skips the identity-guarded cleanup and leaves the file for the user, so the tab can still close.

**After commit,** the swap is atomic: write a temporary sentinel, hard-link `sessions.jsonl` to `sessions.jsonl.imported-<timestamp>`, then rename the sentinel over `sessions.jsonl`. The old journal is never deleted, and there is no moment without a `sessions.jsonl`, so an old binary can never create an empty one. The sentinel is one newline-terminated non-JSON line. `6172744` refuses to start on a non-JSON line, confirmed from source. Recovery covers each intermediate state: a real `sessions.jsonl` whose digest matches the marker means the swap is unfinished. An incomplete final line in the old journal was never acknowledged, so it is set aside in its own file. A corrupt complete line refuses the import and changes nothing.

**Rollback round trip.** A documented command replaces the sentinel with the renamed file so the old binary runs. Its limits are stated in the docs: the old binary does not see anything recorded in the log, and payloads the kernel released are gone. Upgrading again finds a real `sessions.jsonl` with a different digest than the marker. It refuses to start and names `--reimport`, an explicit command that imports that file under new session identities linked to the earlier generation, so no terminal state moves and earlier facts stay intact and read-only. K3 tests both directions.

Import is tested against journal shapes generated by the actual `6172744` code, and against a private copy of the real data directory. That copy's contents stay out of the repository.

## Slices

Each slice is its own branch and PR, with its own code inspection. Sizes exclude tests. A slice that outgrows about 1,500 lines is split before review.

**K5 to K9 are mergeable and reviewable but not runnable on real data.** Until K10:
- The binary refuses any data directory lacking a development marker, which only an explicit flag creates. It survives a restart, because the guard does not depend on `sessions.jsonl` being absent.
- Every entry point, including background paths such as the scheduler, event readers and auth transitions, passes a default-deny ownership gate. An unconverted operation on a kernel-owned session refuses visibly rather than mutating.
- An AST inventory lists every authority write in `package main`, against an allowlist that shrinks by slice.
- Cross-provider reviewers refuse until K9.

| Slice | Scope | Acceptance | Depends on |
|---|---|---|---|
| **K0** | This plan and the catalog | Plan review | None |
| **K1a** | `internal/kernel` core, per [the closed tables](CONSOLE-KERNEL-K1A.md): session lifecycle, receipts, turn and control, late evidence, restart, authorization, codec. Under 1,200 non-test lines. No I/O, no wiring. | Plan review accepts the tables. In-scope reproducers fail at `2132280` and pass. Model written by a separate agent from the tables alone compares every K1a field and the effect list, at 3,000 seeds with the seed printed. `go test -race`. Every mutated table row is caught by that model. One blind inspection with no blocker on a tabled object, or one repair then a clean second. | K0 |
| **K1b** | Children, questions and the control side they share | Same recipe, deferred controls F6-child, F9, F11 | K1a, before K7 |
| **K1c** | Inputs | Same recipe | K1a, before K8 |
| **K1d** | Tasks, reviews, checkpoints, supervision and continuation budget | Same recipe, deferred controls F1, F7, F8 | K1a, before K9 |
| **K2** | `internal/eventlog`: append with revision CAS, receipts, replay, health latch, must-append reserve, quota, notices. Not wired. | The five falsifiers. Kill at each transaction boundary, `SQLITE_BUSY`, short write, disk-full, and ambiguous commit injection, then reopen. Concurrent append. Secrets canary across the database, WAL and free pages. | K1a |
| **K3** | `internal/legacyimport` and the queue decoder, not wired | Fixtures from `6172744` shapes, including cwd after receipt, torn tail, corrupt line, corrupt queue, orphan queue and missing identity. Crash at each step. Held lock refuses. Rollback and `--reimport` both ways. | K2 |
| **B** | Labelled baseline PR to `main`, per Landing | Public-repo scan clean. Guard refuses a directory without the marker. Reviewed and merged through the main agent. | K0 |
| **K4** | Process lifecycle, on the baseline. Adapter identity computation. | Catalog process entries, with real child processes on Linux and Mac. This work carries through wiring. | B |
| **K5a** | Ownership gate at every entry point, AST inventory, field classification test. No behaviour change. | Gate default-denies a marked session on every entry point. Inventory test fails on an unlisted write. | Baseline, K1a |
| **K5b** | Wire Claude send, finality and restart. Writer gate, fence and drain. | Seeded test through the real API, with the operation set limited to what K5b owns. Commit-to-effect crash matrix for send. Test holding a write between recheck and syscall. Lock rule tests rerun. | K1a, K2, K4, K5a |
| **K6** | Wire Codex: conversation binding, turn binding, finality, disconnect | Same for Codex. Client cache key stays separate from conversation identity. | K5 |
| **K7** | Controls, questions, cwd, close, auth boundary, children, and **discard** with its UI, since it shares control's state | Control, question and all discard entries. Delayed-response scenarios. Operation set grows. | K6, K1b |
| **K8** | Queue and attachment ownership as facts. Content-addressed payload is durable first, the fact second, and orphan cleanup runs only after replay. Beforeimages removed. | Queue entries, with fault injection at each step. | K7, K1c |
| **K9** | Reviews and checkpoints, including cross-provider reviewers | Review entries | K8, K1d |
| **K10** | Wire import. Remove the data-directory guard. | Seeded test with the full operation set at **10,000 seeds**, zero divergence, including questions, reviews and checkpoints. Import end to end. | K3, K9 |
| **K11** | Replacement release | One frozen full qualification on the Linux runner, Mac native, click-test including discard keyboard and focus, bounded real-provider smoke, exact-head PR review, private-copy import rehearsal, no-write verify on the stopped directory, golden fixtures. Then install. Only then is the old console stopped, with the user's existing authorization. | K10 |

**Landing.** The console is not on `main`, so a 25,000-line baseline exists once, with no line-by-line correctness review. By user decision it lands as one labelled squashed PR to `main` before K4, so later slices each show a small diff. Conditions:
1. The data-directory guard is in the baseline, so a build from `main` refuses real data.
2. `version` is an unreleased label, not `0.2.0`.
3. The workflow's executable upload on `main` is removed.
4. `README.md` and `docs/console.md` say unreleased, and the known-defect list is linked.
5. No installer change.
6. A public-repo scan for private content and non-public emails passes first, and history is squashed under the public identity.
7. Review and merge go through the main agent.

K1a, K2 and K3 are new packages. They land with `console/go.mod` and a workflow that runs `go test ./internal/...`, because the existing workflow's `go build .` needs a main package. The baseline merge reconciles `go.mod`, including any `go` directive the refreshed SQLite requires.

## Findings carried from plan review

Each is closed in the named slice.

| Slice | Finding | Direction |
|---|---|---|
| K1a, K2, K7 | Stop conflicts with INV7 and failed appends: at quota a literal implementation refuses Stop while the provider runs | Stop effects are exempt from INV7 and never depend on an append. `ControlRequested{stop}` is must-append, and a stop outcome may have no recorded request. R4 means no authority change; the stop effect still fires |
| K1a | A failed drain after `Abandoned` has no legal fact, because `abandoned` is terminal | Effect observations on a terminal or `unknown` receipt become `LateFrameObserved`, and the K1 model covers them |
| K1a | `ProcessRestarted{processEpoch}` conflicts with skipping a repeat | Remove the field. The live epoch stays outside the projection |
| K2 | Must-append list is still incomplete | Add `ProviderRefused`, `LateFrameObserved{final}`, `AuthBoundaryCrossed`, `ChildQuarantined`, coalesced where the plan coalesces, and include them in reserve sizing |
| K5b, K7 | Entering the latch drains nothing | Entering the latch drains every writer gate, with the same deadline and kill. Console-controlled credential changes wait or refuse. State the policy for running turns |
| K6 | A kill on a shared Codex writer stops other sessions | Record `OutcomeUnknown` for every open request on that client, with a test |
| K5a, K5b | Field table needs clarifying | Name the `review*` fields, since `reviewDone` is adapter state. State whether restored tabs lose `Title`, `Messages`, `Model` and `context`, and where continuation text comes from after restart |

## Stop conditions

- K1a: **S1** a second inspection after a repair still blocks with a late-frame, restore, one-path or publish-before-persist finding on a tabled object. **S2** the independent model and the reducer disagree in a way the table cannot settle. **S3** K1a passes two owner-days. **S4** K2 falsifier 3, 4 or 5 fails. On S1 or S2 the next step is a plan review of the table, never another code repair.
- K1b to K1d: same recipe, with a two-inspection cap each. If together they exceed two owner-days or one needs a third inspection, report it.
- Stop and report if K2's falsifiers 3, 4 or 5 fail, or if the log cannot run under `console.lock`.
- Stop and report if the same finding class returns after two genuine repairs in any slice.
- Reviews are helper receipts where they can route, labelled native otherwise. Sol may take a later look after about Nov 9; that is not a gate.

## Out of scope

Owner auto-dispatch, tool or effect ledger, graph DSL, Temporal server, middleware, exactly-once claims, new UI design, and the Go Hermes engine.
