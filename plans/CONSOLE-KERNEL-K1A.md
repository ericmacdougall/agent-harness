# K1a: closed tables

This is the specification for `console/internal/kernel` at K1a. A session field with no table here is not in K1a. Reviews, checkpoints, tasks, supervision, budgets, children, questions and inputs land in K1b to K1d, each with its own table. See [the plan](CONSOLE-KERNEL.md).

Terms: **open** is `intent` or `accepted`. **Unresolved** is open or `unknown`. A late frame is a fact recording evidence only; its rule is table 5.

## 1. Field map

Each field belongs to exactly one table.

| Table | Fields |
|---|---|
| 2 Session lifecycle | `ID`, `Provider`, `ProviderID`, `ProfileID`, `CWD`, `ConversationStarted`, `RuntimeIdentity`, `Connected`, `ReadOnly`, `Closed`, `Hidden`, `Quarantine`, `Abandoned`, `Revision` |
| 3 Receipt | `LastRequest`, `Requests`, `RequestOrder`, `ProviderFinal`, `FinalStatus`, `LastRefusal` |
| 4 Turn and control | `TurnID`, `PendingInterrupt`, `Paused`, `PauseUnconfirmed`, `ControlEpoch` |
| 5 Late evidence | `Evidence` |

`Revision` increases by one with every fact on the session. A fact not listed in a table changes nothing in that table. Read-only is never cleared: such a session can never send again, only stop, discard and close.

## 2. Session lifecycle

| Fact | Precondition in Reduce | Change |
|---|---|---|
| `SessionCreated` | Session absent, revision 1, provider known | Created with `Connected` false. `ConversationStarted` is `ProviderID != ""`. `RuntimeIdentity` from the fact |
| `ConversationBound` | Writable | `ProviderID` set, never empty; `ConversationStarted` true |
| `RuntimeIdentityBound` | Writable, and empty or the same identity | `RuntimeIdentity` set |
| `ProviderConnected` | Writable | `Connected` true |
| `ProviderDisconnected` | Writable | `Connected` false; rows in tables 3 and 4 |
| `AuthBoundaryCrossed` | Writable | `ReadOnly` true, `Connected` false; rows in tables 3 and 4 |
| `SessionQuarantined` | Session not closed, nonempty `ReasonCode` | `Quarantine` set, `ReadOnly` true, `Connected` false, `Hidden` false so it stays visible; table 4 row |
| `Abandoned` | Not already abandoned, `RequestID` equals `LastRequest` | `Abandoned` set to `{RequestID, Reason, At}`, `ReadOnly` true, `Connected` false; rows in tables 3 and 4 |
| `CwdChanged` | Writable, last receipt not unresolved | `CWD` set |
| `SessionClosed` | Last receipt not unresolved and no quarantine, unless `Abandoned` is set | `Closed` true |
| `ProcessRestarted` (global) | None | Every session not closed: `ReadOnly` true, `Connected` false; rows in tables 3 and 4. Then trim below |
| `LegacyImported` | Session absent, revision 1, receipt in `final`, `rejected`, `unknown`, `abandoned` or none, with a request exactly when there is a receipt | `ReadOnly` true, `Connected` false, `ConversationStarted` is `ProviderID != ""`. If receipt: `LastRequest`, `Requests`, `RequestOrder` set, `ProviderFinal` true only for `final`, and for `abandoned`, `Abandoned` set |

A closed session accepts no fact. A read-only session accepts only `LateFrameObserved`, `ControlOutcome`, `SessionClosed`, `Abandoned`, `SessionQuarantined` and `TurnBound`.

**Trim.** After a restart, a session that is not closed or hidden is protected if it is not abandoned and either its last receipt is unresolved or it is quarantined. The budget is 24 minus the protected count, clamped at 0. Candidates are sessions not closed, not hidden and not protected. Walking candidates newest to oldest by creation order, each takes one from the budget while any remains, and the rest get `Hidden` true. `Hidden` is sticky except as `SessionQuarantined` says. `VisibleSessions` returns sessions neither closed nor hidden, in creation order.

## 3. Receipt

Transitions exactly: none to `intent`; `intent` to `accepted`, `final`, `unknown`, `rejected`, `abandoned`; `accepted` to `final`, `unknown`, `rejected`, `abandoned`; `unknown` to `abandoned`. Nothing else, including a repeat of the same state.

| Fact | Precondition in Reduce | Change |
|---|---|---|
| `RequestIntended` | Writable, last receipt not unresolved, request new and nonempty | Receipt `intent`, `LastRequest` set, appended to `RequestOrder`; past 256 the oldest leaves both `RequestOrder` and `Requests`, while `Evidence` stays. `FinalStatus` empty, `ProviderFinal` false, `LastRefusal` empty |
| `ProviderAccepted` | Writable, request is `LastRequest` | Receipt `accepted` |
| `ProviderRefused` | Writable, request is `LastRequest` | Receipt `rejected`, `LastRefusal` is the reason code or `provider_refused` |
| `ProviderCompleted` | Writable, request is `LastRequest`, status in `completed`, `failed`, `interrupted` | Receipt `final`, `ProviderFinal` true, `FinalStatus` set |
| `OutcomeUnknown` | Writable, request is `LastRequest` | Receipt `unknown`, `ProviderFinal` false |
| `ProviderDisconnected`, `AuthBoundaryCrossed` | | If last receipt open: `unknown`, `ProviderFinal` false. Otherwise unchanged |
| `Abandoned` | | If last receipt unresolved: `abandoned`, `ProviderFinal` false. Otherwise unchanged, so a `final` is never overwritten |
| `ProcessRestarted` | | If last receipt open: `unknown`, `ProviderFinal` false |

## 4. Turn and control

Applies with `Provider` as written. A Claude session never has a `TurnID` or a pending interrupt, since its process is the stop handle.

**Owed** below means: last receipt, before the fact, is unresolved, `TurnID` is empty, and provider is Codex.

| Fact | `TurnID` | `PendingInterrupt` | `Paused` | `PauseUnconfirmed` | `ControlEpoch` |
|---|---|---|---|---|---|
| `RequestIntended` | Empty | False | False | False | Same |
| `TurnBound`, Codex only, request is `LastRequest` | Set, nonempty | False | Same | Same | Same |
| `ProviderCompleted` | Empty | False | Same | False | Same |
| `ProviderRefused` | Empty | False | Same | Same | Same |
| `OutcomeUnknown` | Same | Same | Same | Same | +1 |
| `ProviderDisconnected` | Empty | Same | Same | Same | +1 |
| `ControlRequested` when last receipt is `unknown` | Same | Owed | Same | Same | Same |
| `ControlRequested` otherwise | Same | Owed | True | Same | +1 |
| `ControlOutcome` | Same | Same | Same | True when outcome is not `confirmed`, the last receipt is unresolved and not abandoned; otherwise false | Same |
| `AuthBoundaryCrossed` | Same | Owed | Same | Same | +1 |
| `Abandoned` | Same | Owed | Same | Same | +1 |
| `SessionQuarantined` | Same | Owed | Same | Same | +1 |
| `CwdChanged` | Same | Same | Same | Same | +1 |
| `ProcessRestarted` | Empty | False | False | False | Same |

Epoch fences cannot outlive a process, so restart need not move it.

**Stop effects** for a session: Claude with last receipt unresolved or abandoned gives `terminate{request}`. Codex with `TurnID` set and last receipt unresolved or abandoned gives `interrupt{request, turn}`. Otherwise none. All are class `stop-work`, and the adapter fires them even when an append fails or the log is latched.

## 5. Late evidence

`Evidence` maps `(request, kind)` to `status|digest`. `request` is the frame's request if this session knows it, otherwise empty, so a provider cannot grow the map with invented requests. `kind` is one of `accepted`, `refused`, `write_unknown`, `turn_bound`, `final`, `conversation`, `connected`, `disconnected`, `control_outcome`. Later kinds arrive with their slices.

The first frame per key is sticky: if the key exists, no fact is appended. The stored status is the frame's status if it matches `[a-z0-9_]{1,40}`, otherwise `invalid`, or empty if the frame has none. The stored digest is the frame's if it matches `[A-Za-z0-9:_-]{1,128}`, otherwise empty. A late frame changes nothing else and emits no effect.

## 6. Status

First match wins.

| Condition | Status |
|---|---|
| `Closed` | `closed` |
| `Abandoned` set | `abandoned` |
| `Quarantine` set, or last receipt `unknown` | `unknown` |
| `ReadOnly` | `disconnected` |
| Last receipt open and `Paused` | `paused` |
| Last receipt open | `running` |
| Last receipt `rejected` and not `Paused` | `error` |
| `FinalStatus` is `failed` | `error` |
| `Paused`, or `FinalStatus` is `interrupted` | `paused` |
| Codex and not `Connected` | `disconnected` |
| Otherwise | `idle` |

## 7. Inputs

Authorization runs first, before every other check including restart, and is default-deny. `forbidden` otherwise. A `provider` input must carry `Principal.SessionID` equal to its session. Then a time check: `At` must be fixed-width UTC `YYYY-MM-DDTHH:MM:SS.nnnnnnnnnZ`, otherwise refusal `bad_time`.

Effects are returned with the decision, in the order listed. A refusal returns no facts. Checks run in the order written, and the first that applies decides. A session that is missing or closed gives refusal `not_found`, except as `turn-bound` says.

| Input | Principal | Rule |
|---|---|---|
| `create` | user, system | Refuse `session_exists` if ID empty or used. Refuse `bad_provider` unless Codex or Claude. Refuse `no_owner` if `ProviderID` set and `RuntimeIdentity` empty. Else `SessionCreated`, carrying `RuntimeIdentity` |
| `send` | user | Existing request: if `intent`, `accepted` or `final`, idempotent with no facts or effects; otherwise refuse `not_replayed`. Empty request: `bad_request`. Read-only: `read_only`. Last receipt unresolved: `unresolved`. Codex not connected: `disconnected`. Empty identity: `no_identity`. Session identity set and different: `runtime_changed`. Session identity empty and `ConversationStarted`: `no_owner`. Else: `RuntimeIdentityBound` if the session has none, then `RequestIntended`. Effect `start-turn{request, fence: ControlEpoch}`, class `new-work` |
| `pause`, `stop` | user | Read-only: no facts, stop effects; refuse `read_only` if there are none. Last receipt `unknown`: `ControlRequested{stop}` only if owed and not already pending, plus stop effects; refuse `nothing_to_stop` if there is neither. Otherwise `ControlRequested{pause or stop}`, plus stop effects |
| `change-cwd` | user | Read-only: `read_only`. Unresolved: `unresolved`. Empty path: `bad_request`. Else `CwdChanged` |
| `close` | user | No `Abandoned`, and last receipt unresolved or `Quarantine` set: `unresolved`. Else `SessionClosed` |
| `abandon` | user | `RequestID` on the fact is empty exactly when `LastRequest` is empty, which is how a quarantined session with no receipt reaches close. Reason empty after trimming, or over 500 bytes: `bad_reason`. Already abandoned: idempotent if the expected request matches, otherwise `discarded_other`. Expected request differs from `LastRequest`: `turn_changed`. Not read-only and status is `running`: `stop_first`. Last receipt not unresolved and status not `unknown`: `nothing_to_discard`. Else `Abandoned`, plus stop effects as they stood before the fact |
| `conversation-bound` | provider | Read-only, or provider ID empty or out of shape: late `conversation`. Session identity set and input identity set and different: `runtime_changed`. Both identities empty: `no_owner`. Else `RuntimeIdentityBound` if the input has one and the session has none, then `ConversationBound` |
| `connected` | provider | Read-only: late `connected`. Already connected: idempotent. Else `ProviderConnected` |
| `disconnected` | provider | Read-only: late `disconnected`. Else `ProviderDisconnected` |
| `accepted` | provider | Not `LastRequest`, last receipt not open, or read-only: late `accepted`. Receipt already `accepted`: idempotent. Else `ProviderAccepted` |
| `refused` | provider | Same guard, late `refused`. Else `ProviderRefused`, with a reason code out of shape dropped so the default applies |
| `write-unknown` | provider | Same guard, late `write_unknown`. Else `OutcomeUnknown`, with a reason code out of shape dropped |
| `turn-bound` | provider | Session closed, pending, request is `LastRequest`, turn in shape: no facts, effect `interrupt`. Missing or closed otherwise: `not_found`. Claude: late `turn_bound`. Request not `LastRequest`, or turn empty or out of shape: late `turn_bound`. Same turn as bound: idempotent. Different turn already bound: late `turn_bound`. Pending: `TurnBound` and effect `interrupt{request, turn}`. Last receipt unresolved: `TurnBound`, no effect. Else late `turn_bound` |
| `completed` | provider | Empty request: last receipt open and writable gives `OutcomeUnknown{unbound_completion}` on `LastRequest`; otherwise late `final`. Not `LastRequest`, last receipt not open, or read-only: late `final`. Codex and turn differs from `TurnID` or `TurnID` empty: late `final`. Status not in the enum: `OutcomeUnknown{invalid_final_status}`. Else `ProviderCompleted` |
| `control-outcome` | provider | Control not `pause`, `stop`, or outcome not `confirmed`, `rejected`, `unconfirmed`: late `control_outcome`. Would not change `PauseUnconfirmed`: idempotent. Else `ControlOutcome` |
| `auth-boundary` | system | Provider not Codex or Claude: `bad_provider`. Else one `AuthBoundaryCrossed` per session with that provider and profile, not closed and not read-only, in creation order, each with its stop effects. None: idempotent |
| `quarantine` | system | Empty reason: `bad_value`. Else `SessionQuarantined`, plus stop effects |
| `restart` | system | Last fact was `ProcessRestarted`: idempotent, no fact. Else `ProcessRestarted`. No effects |

Every value on a fact has a closed set or a shape: identities `[A-Za-z0-9._:/@+=-]{1,128}`, digests and runtime identity `[A-Za-z0-9:_-]{1,128}`, reason codes `[a-z0-9_]{1,40}`, `Control` and `Outcome` as listed, and `Reason` only on `Abandoned` and `LegacyImported`. A value out of shape on a user or system input gives `bad_value`. A provider input never does: a frame cannot be refused back to the provider, so its rows above say what happens. A request out of shape is simply not `LastRequest`. `Decide` encodes, decodes and reduces each fact before returning, and any failure there is a refusal `bad_value`, so nothing it returns can be refused by `Reduce` or changed by the codec.

`LegacyImported` and `LegacyImportCompleted` come only from the importer in K3, and have no input row. A `final` import leaves `FinalStatus` empty. `LegacyImported.RequestID` follows the same empty rule as `Abandoned`.

Fact kinds for later slices stay known to the codec so a log holding them stays readable by kind, but `Reduce` refuses them as illegal until their slice lands.

## 8. Replay

`Replay` folds decoded facts in order, calling `Reduce` for each.

| Case | Result |
|---|---|
| Schema version not current, kind not known, or sequence not increasing | The log is unreadable: `ErrUnreadableLog`, empty projection |
| Illegal fact with no session, including a global fact | Same |
| Illegal fact on a session that exists, the first for that session | Fact skipped. `LastSeq` and `LastKind` advance. `Quarantine` set to `illegal_fact` unless already set, `ReadOnly` true, `Connected` false, `Hidden` false, `ControlEpoch` +1, `PendingInterrupt` owed. `Revision` unchanged. Session reported once in `[]Quarantined` |
| Illegal fact on a session that does not exist | Fact skipped, `LastSeq` and `LastKind` advance, session reported once |
| Later fact on a quarantined session | Applied if `Reduce` accepts it, otherwise skipped with `LastSeq` and `LastKind` advancing and no further change |

A fact of a later slice's kind is illegal, so it follows the same rows. Quarantine from replay is not a fact: the same log gives the same result each time, and facts appended after it apply on the next replay too, so a discard and close survive restart. `Decide` never returns an illegal fact, so live state cannot reach these rows.

## 9. API the model drives

```go
func Decide(p Projection, in In) (Decision, error)        // error is *Refusal{Code, Message}, or a bug
func Reduce(p Projection, f Fact) (Projection, error)     // ErrIllegalFact, ErrUnreadableLog
func Replay(facts []Fact) (Projection, []Quarantined, error)
func EncodeFact(Fact) ([]byte, error); func DecodeFact([]byte) (Fact, error)
func Status(*Session) string; func VisibleSessions(Projection) []*Session
func Redact(text string, redactor func(string) string) RedactedReason
```

`In` has `Kind, Principal{Class, SessionID}, At, SessionID, Provider, ProviderID, ProfileID, CWD, RequestID, ExpectedRequest, TurnID, Reason RedactedReason, ReasonCode, Status, Control, Outcome, Digest, RuntimeIdentity`. `Decision` has `Facts []Fact, Effects []Effect, Idempotent bool`. `Effect` has `Kind, Class, SessionID, RequestID, TurnID, Fence`. `Projection` has `Sessions map[string]*Session, Order []string, LastSeq uint64, LastKind FactKind`. Principals: `PrincipalUser`, `PrincipalProvider`, `PrincipalSystem`.
