# Console kernel plan

Status: proposed, awaiting plan review. No kernel code exists on this branch.

## Decision and why

Console 0.2 will not ship. It is rebuilt on a durable event log with one pure reducer.

Across six exact-head reviews the blocker count did not converge, and repairs caused new blockers. The session has about 50 fields mixing presentation and authority. `Status` is written at about 147 sites, request receipts were written at 22, and `restore()` is a second hand-written projection of the same truth. A seeded restore-versus-live property test against the last repaired head measures the drift: see [the catalog](CONSOLE-KERNEL-CATALOG.md).

The catalog is the specification. Each entry names a defect the review record already found, and the invariant that excludes it.

## Invariants

- **INV1** A request receipt only moves forward: `intent -> accepted -> {final | unknown | abandoned}`, with `rejected` from `intent` or `accepted`, and `unknown -> abandoned`. Nothing leaves a terminal state.
- **INV2** The projection after replaying any prefix of the log equals the live projection at that point, for every covered field. There is one reducer, so this holds by construction, and a property test checks it.
- **INV3** A session with an unresolved receipt or a retained payload is never dropped, trimmed or closed without an `Abandoned` fact.
- **INV4** No provider write, resume or continuation is admitted unless the last receipt is resolved, the session is writable, and the runtime identity matches the one that owns the conversation. A refusal is visible in session state.
- **INV5** Opening the log or reconnecting a browser makes no provider call. It appends only the facts that describe the restart.
- **INV6** Secrets, prompt bodies and attachment bytes never enter the log. It holds references and digests.
- **INV7** A fact is committed before the effect it authorizes. An effect with no observed result is unknown, never retried, never inferred complete.

## Shape

```
HTTP / UI    adapters (Codex, Claude)     frames, exits, replies
    | commands        | observations
    v                 v
 Decide(projection, input) -> facts | refusal      pure
    | facts
    v
 Log.Append(expected revision, facts)              one transaction
    | committed
    v
 Reduce(projection, fact) -> projection            pure, the only writer of authority
    |
    v
 effects run outside every lock; results return as observations
```

`console/internal/kernel` holds `Decide`, `Reduce`, and the closed enums. It imports nothing from the console, does no I/O, and reads no clock (time arrives in the input).

### Facts

`SessionCreated`, `RequestIntended`, `ProviderAccepted`, `ProviderRefused`, `ProviderCompleted{status}`, `OutcomeUnknown{reason}`, `TurnBound{turnId}`, `QuestionOpened`, `QuestionAnswered`, `QuestionRevoked`, `ControlRequested{pause|stop}`, `CwdChanged`, `InputQueued`, `InputDispatchPrepared`, `InputOutcome`, `InputDiscarded`, `ReviewRecorded`, `CheckpointRecorded`, `RuntimeIdentityBound`, `AuthBoundaryCrossed`, `ChildQuarantined`, `ProcessRestarted`, `SessionClosed`, `Abandoned{requestId, reason}`, `LateFrameObserved{kind}`, `LegacyImported`, `LegacyInputHeld`.

Every fact carries `seq`, `sessionId`, `sessionRevision`, `schemaVersion` and `at`. Unknown kinds or versions refuse the log rather than skip.

### Rules that remove whole classes

- **Restart is a fact.** Opening appends `ProcessRestarted`. Its reducer rule moves every open request to `unknown` and marks every session read-only. Live and restored cannot differ, because restore is the same fold.
- **Late frames cannot reopen.** `Decide` maps a frame on a terminal or foreign request to `LateFrameObserved`, whose reducer rule changes only an audit counter. A native final that arrives after a discard is kept as evidence without changing the outcome.
- **Guards live once.** `Decide` is not provider-specific, so a rule cannot apply to one provider only. Adapters translate frames and do not decide.
- **No publish before persist.** Nothing updates the projection until the commit returns. If it fails, the state stays as it was and the failure is returned.
- **Status is derived.** `Status` becomes a pure function of the projection. Nothing assigns it.
- **Discard is a fact.** `Abandoned` needs a matching expected request and a reason, and appends once (a retry returns the existing fact). It moves an unresolved receipt to `abandoned`, leaves a `final` alone, and makes the session read-only and closable once payloads are released. It carries no verdict or pass. It does not claim the provider stopped.

### Storage

SQLite through `modernc.org/sqlite`, as Slice A chose, used as a transactional append-only log. Tables: `metadata` (format version), `facts`, `receipts` (command ID unique, digest bound). There are no materialized session tables, because a second projection is the defect being removed. Open folds the log into memory.

Rejected: a custom JSONL log. Torn tails, partial writes, rename outcomes and beforeimages produced recurring blockers in the current journal and queue files. A transaction gives atomic multi-fact append and compare-and-swap on revision.

Falsify before building on this (first step of K2):
1. Replaying 100,000 representative facts on the Mac takes under one second, otherwise add a snapshot watermark in K2 rather than later.
2. `kill -9` at each transaction boundary plus power-cut style WAL truncation loses only unacknowledged facts.
3. The dependency must be refreshed and scanned: v1.34.5 in Slice A is old, newer releases exist (`modernc.org/sqlite` v1.52.0 appears in dependency-bot data, unconfirmed from an authoritative source), and `govulncheck` has not been run. If it cannot be brought to a clean pinned version, stop and reassess the store.

### Log growth

The 8 MiB refusal goes away. A storage quota remains, with a clear refusal and an export command. Rollover by generation (Temporal Continue-As-New style) is deferred until measurements show it is needed.

## Reuse, verified against the branches

Executed on a Linux runner with pinned Go 1.27.3: engine `cd54641` `./internal/...` passes normal and race, including store crash and quota tests; preview `a32e510` `./internal/core` passes normal and race. This proves only that those tests pass. No review verdict covers `086b075`, `bb6e113` or `cd54641`: the last completed review of this code, on `006a17e`, blocked with nine findings, and the delta review of `086b075` has a prompt but no result.

| Item | Decision | Reason |
|---|---|---|
| `internal/store` open, directory lock, symlink and filesystem checks, WAL and `synchronous=FULL`, format-version refusal, headroom and quota, test barriers | **Reuse, re-review as new code in K2** | Real mechanics, tested. Reimplementing gains nothing. |
| `internal/store` receipts and idempotent `Submit` with digest binding | **Reuse the design, rewrite against facts** | Correct contract; tied to the old vocabulary. |
| `internal/store` `sessions`, `budget_ledger`, materialized tables and `tombstones` | **Reject** | Materialized state alongside events is a second projection; `Snapshot` exists largely to check the two agree. |
| `internal/core` `DecodeCommand`, strict JSON prepass, canonicalization, Unicode alias defence | **Reuse in K1** | Bounded, already repaired after review. |
| `internal/core` session and budget vocabulary, `ApplyEvent` | **Reject** | No request, question or queue vocabulary. The state machine is the actual work. |
| Preview `unified_preview*.go` (2,328 lines) | **Reject** | Synthetic only; its own docs limit it to synthetic scope. |
| Preview `THIRD_PARTY_NOTICES`, packaging stale-notice refusal, and tests | **Reuse in K2**, regenerated for the pinned dependency | Needed once SQLite ships. |
| `plans/UNIFIED-RUNTIME.md` on the engine branch, and an earlier private next-slice plan | Reference only | The next-slice plan was written by a low-effort subagent and never reviewed. |

Engine history includes four commits under a non-public email, so no engine commit is cherry-picked. Reused code enters as new commits on the public identity. Hermes-derived engine work stays separate and is not part of this plan.

Kept from the 0.2 branch at `111631d`: UI, settings and vault, GoodQA proxy, repository views, attachment snapshot mechanics, packaging. Its discard UI, seeded property test and process-tree tests are starting material. None of that branch's lifecycle code is treated as correct.

## What the kernel does not fix

These are adapter and OS concerns, in K4, independent of the log.

- **Lock order.** Rule: no lock is held across a provider write or a wait on another subsystem. The kernel lock is held only to decide, append and reduce. A timeout test covers cross-profile login against publication.
- **Process groups.** Stop the whole group on every path that loses supervision, before `Wait` reaps the leader. Keep background work after a true final. Add `WaitDelay` and a leader-exit watch, and recheck a reaped flag before any signal. Windows gets its own qualified path.
- **Runtime identity.** A revision-free conversation identity, separate from the client cache key, so a settings save neither refuses a conversation nor reuses a revoked proxy, for both providers.

## Old sessions: one-way import

No second reader. At first start of a kernel build, in one transaction:
- Each journal session becomes `LegacyImported{sessionId, provider, providerId, cwd, profile, lastReceiptState}`. `final` and `closed` stay as they are. Everything else becomes `unknown`, never accepted. Task identity comes through as read-only metadata.
- Each queue file becomes `LegacyInputHeld` by hash, with the payload staying in place under the same cleanup rules.
- A marker fact records the import digest.

After commit, `sessions.jsonl` is renamed to `sessions.jsonl.imported-<timestamp>` and never deleted. A crash between commit and rename finishes the rename on next start. An incomplete final line was never acknowledged, so it is set aside in its own file. A corrupt complete line refuses the import and changes nothing.

**Downgrade.** The old binary cannot read the log and, finding no journal, starts empty, so rollback needs an explicit documented step that restores the renamed file. The kernel build refuses to re-import a new `sessions.jsonl` that appears after the marker, and reports it, because that means an old binary ran here.

Import is tested against journal shapes generated by the actual `6172744` (0.1.0) code, and against a private copy of the real data directory before install. That copy's contents stay out of the repository.

## Slices

Each slice is its own branch and PR, with its own code inspection. Sizes exclude tests. A slice that outgrows about 1,500 lines is split before review.

| Slice | Scope | Acceptance | Depends on |
|---|---|---|---|
| **K0** | This plan and the catalog | Plan review | None |
| **K1** | `internal/kernel`: enums, facts, `Decide`, `Reduce`, strict command decode. No I/O, no wiring. | Catalog entries marked reducer. Reducer property test: random inputs, INV1, INV2 on every prefix, determinism at 1,000 runs with randomized map order, seed printed. Duplicate, reordered, unknown-version and illegal facts refuse. Failing controls by mutating the transition table. | K0 |
| **K2** | `internal/eventlog`: append with revision CAS, receipts, replay, format refusal, quota, notices. Not wired. | The three falsifiers above. Kill at each transaction boundary, `SQLITE_BUSY`, short write and disk-full injection, reopen. Concurrent append. Secrets canary for INV6. | K1 |
| **K3** | `internal/legacyimport`, not wired | Fixtures from real `6172744` shapes, including the cwd-after-receipt, torn tail, corrupt line and oldest-tab cases. Crash at each step. Second-start refusal. | K2 |
| **K4** | Adapters, on the current console: process lifecycle, identity, lock rule | Catalog entries marked adapter. Real child-process tests on Linux and Mac. No log needed, so this can run beside K1 to K3. | K0 |
| **K5** | Wire Claude send, finality and restart to the kernel. `restore()` is deleted for wired state. Codex stays on the old path behind the session's provider. | Seeded property test through the real API for Claude. A converted-file check fails on any direct `Status` or receipt write. | K1, K2, K4 |
| **K6** | Wire Codex: turn binding, finality, disconnect | Same, for Codex | K5 |
| **K7** | Controls and questions: pause, stop, cwd, close, auth boundary, children | Catalog entries for those paths. Delayed-response scenarios. | K6 |
| **K8** | Queue and attachment ownership as facts; queue files become payload only, beforeimages removed | Catalog queue entries. Fault injection at each step. | K7 |
| **K9** | Reviews and checkpoints | Catalog review entries | K8 |
| **K10** | Discard as a fact; legacy import wired | User's discard requirements, including double activation, Escape, late completion, write failure, restart mid-discard, keyboard and focus. | K3, K9 |
| **K11** | Replacement release | One frozen full qualification on t2-dev, Mac native, click-test, bounded real-provider smoke, exact-head PR review, private-copy import rehearsal, then install and only then stop PID 22220 with the user's existing authorization | K10 |

**Landing.** The console is not on `main`, so a 25,000-line baseline exists once however this is done. To avoid a giant final diff, K1, K2 and K3 are new packages that do not need the baseline, so they can land on `main` directly, with their own `console/go.mod`. For K4 onward, recommended: land the `111631d` console as one labelled baseline PR with no installer change and a README line saying it is unreleased and must not be used, so later slices each show a small diff against `main`. Alternative: keep K4 to K10 on a long-lived integration branch, which keeps known-defective code off public `main` but makes the eventual merge a giant diff. This is a user choice and is asked separately. K1 to K3 do not depend on it.

## Stop conditions

- Stop and report if a class one to four blocker (late frame reopening, restore divergence, one-provider guard, publish before persist) recurs inside the reducer after K1 review: the problem would then be the specification, not the structure.
- Stop and report if K2's falsifiers fail, or if K2 cannot run under the existing single-process data directory lock.
- Stop and report if the same finding class returns after two genuine repairs in any slice.
- Reviews are helper receipts where they can route, labelled native otherwise. Sol may take a later look after about Nov 9; that is not a gate.

## Out of scope

Owner auto-dispatch, tool or effect ledger, graph DSL, Temporal server, middleware, exactly-once claims, new UI design, and the Go Hermes engine.
