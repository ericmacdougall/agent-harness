# K1a: closed tables

This is the specification for `console/internal/kernel` at K1a. A session field with no table here is not in K1a. Reviews, checkpoints, tasks, supervision, budgets, children, questions and inputs land in K1b to K1d, each with its own table. See [the plan](CONSOLE-KERNEL.md).

Terms: **open** is `intent` or `accepted`. **Unresolved** is open or `unknown`. A late frame is a fact recording evidence only; its rule is table 5.

## 1. Field map

Each field belongs to exactly one table.

| Table | Fields |
|---|---|
| 2 Session lifecycle | `ID`, `Provider`, `ProviderID`, `ProfileID`, `CWD`, `ConversationStarted`, `RuntimeIdentity`, `Connected`, `ReadOnly`, `Closed`, `Hidden`, `Quarantine`, `Abandoned`, `Revision` |
| 3 Receipt | `LastRequest`, `Requests`, `RequestOrder`, `ProviderFinal`, `FinalStatus`, `LastRefusal` |
| 4 Turn and control | `TurnID`, `PendingInterrupt`, `Paused`, `PauseUnconfirmed`, `ControlPending`, `ControlEpoch` |
| 5 Late evidence | `Evidence` |

`Revision` increases by one with every session fact on the session. A global fact does not change it. A fact not listed in a table changes nothing in that table. Read-only is never cleared: such a session can never send again, only stop, discard and close.

## 2. Session lifecycle

| Fact | Precondition in Reduce | Change |
|---|---|---|
| `SessionCreated` | Session absent, revision 1, provider known | Created with `Connected` false. `ConversationStarted` is `ProviderID != ""`. `RuntimeIdentity` from the fact |
| `ConversationBound` | Writable | `ProviderID` set, never empty; `ConversationStarted` true |
| `RuntimeIdentityBound` | Writable, and empty or the same identity | `RuntimeIdentity` set |
| `ProviderConnected` | Writable | `Connected` true |
| `ProviderDisconnected` | Writable | `Connected` false; rows in tables 3 and 4 |
| `AuthBoundaryCrossed` | Writable | `ReadOnly` true, `Connected` false; rows in tables 3 and 4 |
| `SessionQuarantined` | Session not closed and not already quarantined, nonempty `ReasonCode` | `Quarantine` set, `ReadOnly` true, `Connected` false, `Hidden` false so it stays visible; table 4 row |
| `Abandoned` | Not already abandoned, `RequestID` equals `LastRequest` | `Abandoned` set to `{RequestID, Reason, At}`, `ReadOnly` true, `Connected` false; rows in tables 3 and 4 |
| `CwdChanged` | Writable, last receipt not unresolved | `CWD` set |
| `SessionClosed` | Last receipt not unresolved and no quarantine, unless `Abandoned` is set | `Closed` true |
| `ProcessRestarted` (global) | None | Every session not closed: `ReadOnly` true, `Connected` false; rows in tables 3 and 4. Then trim below |
| `LegacyImportCompleted` (global) | Nonempty digest, not already completed | `LegacyImported` on the projection set to the digest. No session changes |
| `LegacyImported` | Session absent, revision 1, receipt in `final`, `rejected`, `unknown`, `abandoned` or none, with a request exactly when there is a receipt | `ReadOnly` true, `Connected` false, `ConversationStarted` is `ProviderID != ""`. If receipt: `LastRequest`, `Requests`, `RequestOrder` set, `ProviderFinal` true only for `final`, and for `abandoned`, `Abandoned` set |

A closed session accepts no fact. Besides the global restart, a read-only session accepts only `LateFrameObserved`, `ControlOutcome`, `SessionClosed`, `Abandoned`, `SessionQuarantined` and `TurnBound`.

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

**Owed** below means: last receipt, before the fact, is unresolved, `TurnID` is empty, and provider is Codex. **Sticky owed** means `PendingInterrupt` stays true if already true, and otherwise becomes owed, so a later fact can never clear an interrupt still due.

| Fact | `TurnID` | `PendingInterrupt` | `Paused` | `PauseUnconfirmed` | `ControlEpoch` |
|---|---|---|---|---|---|
| `RequestIntended` | Empty | False | False | False | Same |
| `TurnBound`, Codex only, request is `LastRequest` | Set, nonempty | False | Same | Same | Same |
| `ProviderCompleted` | Empty | False | Same | False | Same |
| `ProviderRefused` | Empty | False | Same | Same | Same |
| `OutcomeUnknown` | Same | Same | Same | Same | +1 |
| `ProviderDisconnected` | Empty | Same | Same | Same | +1 |
| `ControlRequested` when last receipt is `unknown` | Same | Sticky owed | Same | Same | Same |
| `ControlRequested` otherwise | Same | Sticky owed | True | Same | +1 |
| `ControlOutcome` | Same | Same | Same | True when outcome is not `confirmed`, the last receipt is unresolved and not abandoned; otherwise false | Same |
| `AuthBoundaryCrossed` | Same | Sticky owed | Same | Same | +1 |
| `Abandoned` | Same | Sticky owed | Same | Same | +1 |
| `SessionQuarantined` | Same | Sticky owed | Same | Same | +1 |
| `CwdChanged` | Same | Same | Same | Same | +1 |
| `ProcessRestarted` | Empty | False | False | False | Same |

Epoch fences cannot outlive a process, so restart need not move it.

**Stop effects** for a session: Claude with last receipt unresolved or abandoned gives `terminate{request}`. Codex with `TurnID` set and last receipt unresolved or abandoned gives `interrupt{request, turn}`. Otherwise none. All are class `stop-work`, and the adapter fires them even when an append fails or the log is latched.

## 5. Late evidence

`Evidence` maps `(request, kind)` to `status|digest`. `request` is the frame's request if this session knows it, otherwise empty, so a provider cannot grow the map with invented requests. `kind` is one of `accepted`, `refused`, `write_unknown`, `turn_bound`, `final`, `conversation`, `connected`, `disconnected`, `control_outcome`. Later kinds arrive with their slices.

The first frame per key is sticky: if the key exists, no fact is appended. The stored status is the frame's status if it matches `[a-z0-9_]{1,40}`, otherwise `invalid`, or empty if the frame has none. The stored digest is the frame's if it is 64 lowercase hex characters, a hash the adapter computed, otherwise empty. A late frame changes nothing else and emits no effect.

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

Effects are returned with the decision, in the order listed. `Decision.Idempotent` is true exactly when a decision that is not a refusal has no facts. Adapters stamp `At` on provider frames, so `bad_time` and `not_found` reach a provider only through an adapter bug or a closed session. A refusal returns no facts. Checks run in the order written, and the first that applies decides. A session that is missing or closed gives refusal `not_found`, except as `turn-bound` says.

| Input | Principal | Rule |
|---|---|---|
| `create` | user, system | Refuse `session_exists` if ID empty or used. Refuse `bad_provider` unless Codex or Claude. Refuse `no_owner` if `ProviderID` set and `RuntimeIdentity` empty. Else `SessionCreated`, carrying `RuntimeIdentity` |
| `send` | user | Existing request: if `intent`, `accepted` or `final`, idempotent with no facts or effects; otherwise refuse `not_replayed`. Empty request: `bad_request`. Read-only: `read_only`. Last receipt unresolved: `unresolved`. Codex not connected: `disconnected`. Empty identity: `no_identity`. Session identity set and different: `runtime_changed`. Session identity empty and `ConversationStarted`: `no_owner`. Else: `RuntimeIdentityBound` if the session has none, then `RequestIntended`. Effect `start-turn{request, fence: ControlEpoch}`, class `new-work` |
| `pause`, `stop` | user | Read-only: no facts, stop effects; refuse `read_only` if there are none. Last receipt `unknown`: `ControlRequested{stop}` only if owed and not already pending, plus stop effects; refuse `nothing_to_stop` if there is neither. Already `Paused`, and the interrupt is either pending or not owed: no facts, stop effects, idempotent. Otherwise `ControlRequested{pause or stop}`, plus stop effects |
| `change-cwd` | user | Read-only: `read_only`. Unresolved: `unresolved`. Empty path: `bad_request`. Else `CwdChanged` |
| `close` | user | No `Abandoned`, and last receipt unresolved or `Quarantine` set: `unresolved`. Else `SessionClosed` |
| `abandon` | user | `RequestID` on the fact is empty exactly when `LastRequest` is empty, which is how a quarantined session with no receipt reaches close. Reason empty after trimming, or over 500 bytes: `bad_reason`. Already abandoned: idempotent if the expected request matches, otherwise `discarded_other`. Expected request differs from `LastRequest`: `turn_changed`. Not read-only and status is `running`: `stop_first`. Last receipt not unresolved and status not `unknown`: `nothing_to_discard`. Else `Abandoned`, plus stop effects as they stood before the fact |
| `conversation-bound` | provider | Read-only, provider ID empty or out of shape, or input identity out of shape: late `conversation`. Session identity set and input identity set and different: `runtime_changed`. Both identities empty: `no_owner`. Same provider ID as bound: idempotent. `ConversationStarted` with a different provider ID: late `conversation`, so a conversation is never silently replaced. Else `RuntimeIdentityBound` if the input has one and the session has none, then `ConversationBound` |
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

Every value on a fact has a closed set or a shape: identities `[A-Za-z0-9._:/@+=-]{1,128}`, digests and runtime identity `[A-Za-z0-9:_-]{1,128}`, reason codes `[a-z0-9_]{1,40}`, `Control` and `Outcome` as listed, and `Reason` only on `Abandoned` and `LegacyImported`. `CWD` is at most 4,096 bytes of valid UTF-8 with no control characters, may be empty on `create`, and must be nonempty on `change-cwd`. Only fields that reach a fact are checked, after the row's own checks, so a read-only stop always fires its effects and an idempotent retry is not refused over an unused field. A value out of shape then gives `bad_value` on a user or system input. A provider input never does: a frame cannot be refused back to the provider, so its rows above say what happens. A request out of shape is simply not `LastRequest`. `Decide` encodes, decodes and reduces each fact before returning, and any failure there is a refusal `bad_value`, so nothing it returns can be refused by `Reduce` or changed by the codec.

`LegacyImported` and `LegacyImportCompleted` come only from the importer in K3, and have no input row. A `final` import leaves `FinalStatus` empty. `LegacyImported` needs a request exactly when it has a receipt, as table 2 says.

Fact kinds for later slices stay known to the codec so a log holding them stays readable by kind, but `Reduce` refuses them as illegal until their slice lands.

## 8. Replay

`Replay` folds decoded facts in order, calling `Reduce` for each.

| Case | Result |
|---|---|
| Schema version not current, kind not known, or sequence not increasing | The log is unreadable: `ErrUnreadableLog`, empty projection |
| Illegal fact with no session, including a global fact | Same |
| Illegal fact on a session that exists, the first for that session | Fact skipped. `LastSeq` and `LastKind` advance. `Quarantine` set to `illegal_fact` unless already set, `ReadOnly` true, `Connected` false, `Hidden` false, `ControlEpoch` +1, `PendingInterrupt` sticky owed. `Revision` unchanged. Session reported once in `[]Quarantined` |
| Illegal fact on a session that does not exist | Fact skipped, `LastSeq` and `LastKind` advance, session reported once |
| Later fact on a quarantined session | Applied if `Reduce` accepts it, otherwise skipped with `LastSeq` and `LastKind` advancing and no further change |

A fact of a later slice's kind is illegal, so it follows the same rows. Quarantine from replay is not a fact: the same log gives the same result each time, and facts appended after it apply on the next replay too, so a discard and close survive restart. `Decide` never returns an illegal fact, so live state cannot reach these rows.

## 9. API the model drives

```go
package kernel

type FactKind string // FactProcessRestarted, FactLegacyImportCompleted, FactSessionCreated, FactConversationBound, FactProviderConnected, FactProviderDisconnected, FactRuntimeIdentityBound, FactAuthBoundaryCrossed, FactCwdChanged, FactSessionClosed, FactAbandoned, FactSessionQuarantined, FactRequestIntended, FactProviderAccepted, FactProviderRefused, FactProviderCompleted, FactOutcomeUnknown, FactTurnBound, FactLateFrameObserved, FactControlRequested, FactControlOutcome, FactLegacyImported
type Receipt string  // ReceiptNone "", ReceiptIntent, ReceiptAccepted, ReceiptFinal, ReceiptUnknown, ReceiptRejected, ReceiptAbandoned

type Fact struct {
	Seq, SessionRevision, Generation, InputRevision uint64
	SchemaVersion                                   int
	Kind                                            FactKind
	At, SessionID, Provider, ProviderID, ProfileID, CWD, RequestID, TurnID, Status, ReasonCode, Reason, Control, Outcome, LateKind, Digest, RuntimeIdentity, TaskID, ObjectiveHash, State string
	Receipt Receipt
	Passes  map[string]string
}
type Abandonment struct{ RequestID, Reason, At string }
type Session struct { // Field meanings: tables 1 to 5.
	ID, Provider, ProviderID, ProfileID, CWD, RuntimeIdentity, Quarantine, LastRequest, FinalStatus, LastRefusal, TurnID string
	ConversationStarted, Connected, ReadOnly, Closed, Hidden, ProviderFinal, PendingInterrupt, Paused, PauseUnconfirmed, ControlPending bool
	Abandoned             *Abandonment
	Revision, ControlEpoch uint64
	Requests              map[string]Receipt
	RequestOrder          []string
	Evidence              map[string]string // Key is request + "\x00" + kind, value is status + "|" + digest.
}
type Projection struct {
	Sessions       map[string]*Session
	Order          []string
	LastSeq        uint64
	LastKind       FactKind
	LegacyImported string
}
func NewProjection() Projection

type PrincipalClass string // PrincipalUser, PrincipalProvider, PrincipalSystem
type Principal struct {
	Class     PrincipalClass
	SessionID string
}
type InputKind string // InCreate "create", InSend "send", InPause "pause", InStop "stop", InChangeCWD "change-cwd", InClose "close", InAbandon "abandon", ObConversationBound "conversation-bound", ObConnected "connected", ObDisconnected "disconnected", ObAccepted "accepted", ObRefused "refused", ObUnknown "write-unknown", ObTurnBound "turn-bound", ObCompleted "completed", ObControlOutcome "control-outcome", ObAuthBoundary "auth-boundary", ObQuarantine "quarantine", ObRestart "restart"
type In struct {
	Kind      InputKind
	Principal Principal
	At, SessionID, Provider, ProviderID, ProfileID, CWD, RequestID, ExpectedRequest, TurnID, ReasonCode, Status, Control, Outcome, Digest, RuntimeIdentity string
	Reason RedactedReason
}
type EffectKind string  // EffectStartTurn "start-turn", EffectInterrupt "interrupt", EffectTerminate "terminate"
type EffectClass string // ClassNewWork "new-work", ClassStopWork "stop-work"
type Effect struct {
	Kind      EffectKind
	Class     EffectClass
	SessionID, RequestID, TurnID string
	Fence     uint64 // start-turn only.
}
type Decision struct {
	Facts      []Fact
	Effects    []Effect
	Idempotent bool
}
type Refusal struct{ Code, Message string } // *Refusal is the error for an expected refusal.
type Quarantined struct {
	SessionID string
	Err       error
}
var ErrIllegalFact, ErrUnreadableLog, ErrMalformedFact error
const SchemaVersion = 1
const ProviderCodex, ProviderClaude = "codex", "claude"
const MaxVisibleSessions = 24
var ReservedFactKinds []FactKind // Later-slice kinds, known to the codec, refused by Reduce.

func Decide(p Projection, in In) (Decision, error)
func Reduce(p Projection, f Fact) (Projection, error)
func Replay(facts []Fact) (Projection, []Quarantined, error)
func EncodeFact(Fact) ([]byte, error)
func DecodeFact([]byte) (Fact, error)
func Status(*Session) string
func VisibleSessions(Projection) []*Session
func Redact(text string, redactor func(string) string) RedactedReason // A nil redactor gives an empty reason.
func MustAppend(p Projection, f Fact) bool // Section 11: may f use the reserve, judged against p, the projection f was decided on.
const MaxOpenSessions = 1000
```

`Decide` stamps `Seq` as `LastSeq` plus position, `SchemaVersion`, `At`, and `SessionRevision`.

## 11. Reserve bounds

The event log keeps its last 50,000 facts (`Reserve`, out of `MaxFacts` 1,000,000) for facts that must still record when the log is otherwise full. Whether a fact may use the reserve is a kernel rule, `MustAppend(p, f)`, decided against the projection the fact was decided on; the log calls it and refuses everything else at the limit with `ErrQuota`. That refusal is final for that fact: the observation is dropped, never buffered or retried, so a stream of ordinary frames at the limit cannot latch the log. A dropped late frame is lost evidence; a dropped `TurnBound` leads to the completion recording as unknown, which is safe. The retry buffer and its latch on overflow apply only to I/O failures. A kind is never eligible as such: each fact is eligible only while it changes a one-way state, so every eligible fact consumes something that only an ordinary fact can create again.

### Changes to the tables this needs

- **Open session limit.** `create` refuses `session_limit` while 1,000 sessions are not closed (hidden ones count). The importer in K3 enforces the same limit before it commits, refusing an import that would exceed it. A log holding more than 1,000 open sessions opens normally, and new sessions are refused until enough close. The event log refuses to open one holding more than 2,000, which `Decide` cannot produce: 2,000 × 11 × 2 + 1 = 44,001 is the most the reserve is shown to cover.
- **Control pending.** New table 4 field `ControlPending`, in table 1's turn and control row: set by `ControlRequested`, cleared by `ControlOutcome`, `ProviderCompleted`, `ProviderRefused`, `RequestIntended` and restart. Table 7 `control-outcome`: when `ControlPending` is false, late `control_outcome`. Otherwise the existing closed-value and idempotence checks apply, then `ControlOutcome`. So an outcome needs a request, and alternating outcomes become sticky late evidence.
- **Disconnect.** Table 7 `disconnected`: when not `Connected` and the last receipt is not open, idempotent with no fact. So each disconnect fact needs a connect or an open request since the last one.
- **Quarantine.** Table 7 `quarantine`: already quarantined, idempotent with no fact. Table 2 and item 13 change to match: a session is quarantined once, and its first code stands. Replay's own quarantine is unchanged.
- **Late final.** Only a late `final` on the session's `LastRequest` is eligible. Late finals on older requests remain ordinary facts.

### Eligibility, per kind

| Fact | Eligible when, judged before the fact | Uses per session once ordinary facts stop |
|---|---|---|
| `ProviderCompleted`, `OutcomeUnknown`, `ProviderRefused` | Always: each needs an open `LastRequest`, and moves it out of open | 1 together: the receipt is monotone and only `RequestIntended`, ordinary, opens a new one |
| `Abandoned` | Always | 1: sticky |
| `SessionClosed` | Always | 1: sticky |
| `AuthBoundaryCrossed` | Always: needs a writable session, and makes it read-only | 1 |
| `SessionQuarantined` | Always, with the change above | 1 |
| `ProviderDisconnected` | `Connected` or last receipt open, both enforced by `Decide` above | 1: afterwards it is disconnected with no open receipt, and only `ProviderConnected` or `RequestIntended`, ordinary, re-arms it |
| `ControlRequested` | `Control` is `stop`, and it changes `Paused` or newly owes the interrupt | 2: `Paused` is cleared only by `RequestIntended` or restart, and restart leaves the session read-only, where no control fact is recorded; the owed interrupt is set at most once per request |
| `ControlOutcome` | `ControlPending` true, enforced by `Decide` above | 2: one per `ControlRequested` made after the limit, plus at most one already pending when it was reached; together still at most 2, because a pending request leaves at most one more eligible |
| `LateFrameObserved` | `LateKind` is `final` and `RequestID` is the session's `LastRequest` | 1: sticky per key, and `LastRequest` changes only with `RequestIntended` |
| `ProcessRestarted` | Always | See the proof |

Every other fact is ordinary, including `TurnBound`: at the limit a Codex completion then records as unknown, which is safe.

### Proof sketch

1. Below the limit, eligible and ordinary facts both take ordinary space, so the reserve is untouched.
2. Once ordinary facts reach `MaxFacts - Reserve`, no ordinary fact can commit. No session is created, no request opened, no connection made. So each session's eligible uses are bounded by its state at that moment, and the table above gives at most 1+1+1+1+1+1+2+2+1 = 11 per session.
3. At most 1,000 sessions are not closed. A closed session accepts no fact. So session facts use at most 11,000 reserve facts.
4. A restart is skipped when the last fact is already a restart. So restarts are at most one more than the other reserve facts: at most 11,001.
5. Total at most 22,001, under 50,000, with a factor of two in hand for a later slice's kinds, which must extend this table before they may be eligible.
6. If the reserve is still spent, which the proof says cannot happen, the log latches, and that is a defect to report.

The independent model checks this table directly: for each fact, `MustAppend` against its own reading, and a bound of 11 eligible facts per session after a simulated limit, under generators that repeat and alternate every provider frame.

## 10. Settled readings

The independent model listed 34 places these tables left open. None changes a table's rows. Each reading below is now part of the specification.

1. `At` must also be a real calendar date, otherwise `bad_time`.
2. Only the provider rule reads `Principal.SessionID`. An empty session on a provider input passes authorization and gives `not_found`.
3. An unknown input kind is `forbidden` for every principal.
4. `create` on a closed session's ID gives `session_exists`. For every other input, `not_found` comes before the row's checks.
5. The first fact in a decision has `Seq` `LastSeq+1`. `SessionRevision` is the session's value after the fact, 1 on creation, 0 on a global fact.
6. A fact holds the fields its row names. `ProviderCompleted` also carries the session's bound `TurnID`, empty for Claude. `ProviderRefused` and `OutcomeUnknown` carry their reason code.
7. A late fact holds normalized values: table 5's request, status and digest.
8. Raw `LateFrameObserved` with a key already present is illegal. Its request is stored as given, since `Decide` normalizes.
9. A raw fact with a value out of shape, or a kind out of its closed values, is illegal.
10. A session fact's `SessionRevision` must equal `Revision + 1`, otherwise it is illegal. This is the compare-and-swap the plan's `Log.Append` relies on.
11. Raw `TurnBound` needs only what table 4 says: Codex, `LastRequest`, nonempty turn. Input-level checks are in `Decide`.
12. `no_owner` is a `Decide` rule. Raw `SessionCreated` with a provider ID and no identity is legal. Raw `ConversationBound` with a different provider ID on a started conversation is illegal.
13. The quarantine reason is `ReasonCode`. A session is quarantined once; a later `quarantine` input records nothing (section 11). Replay's `illegal_fact` does not overwrite a code already set.
14. `Redact` trims, the fact holds the trimmed text, and the 500-byte limit applies after trimming.
15. `LegacyImported` copies `ProviderID`, `ProfileID`, `CWD` and `RuntimeIdentity`. An empty provider is legal there, since only shape applies.
16. Replay's first-illegal row applies even on a session already quarantined by a fact, keeping its code.
17. Replay's first-illegal row applies literally to a closed session too. It stays closed.
18. A session reported by replay and then created by a later fact is reported only once.
19. Precondition failures satisfy `errors.Is(ErrIllegalFact)`. Bad schema, unknown kind and bad sequence satisfy `errors.Is(ErrUnreadableLog)`. Decoding failures satisfy `ErrMalformedFact`.
20. `ControlRequested` and `ControlOutcome` have only the closed, read-only and closed-value rules in `Reduce`.
21. "Knows a request" means it is still in `Requests`. A request ID trimmed past 256 can be reused until K2's receipts, which make identity durable.
22. `Hidden` restricts nothing but `VisibleSessions`.
23. Comparison with a model treats nil and empty as equal, except replay against live, which is strict.
24. An already abandoned session compares the expected request with `Abandoned.RequestID`, and its idempotent result has no stop effects.
25. The identity shape covers session, profile, request, turn and provider IDs. `ProfileID` may be empty, and `auth-boundary` matches it exactly.
26. `Reduce` needs only an increasing sequence. Gapless sequence is `Log.Append`'s rule.
27. On every kind, the enum-bearing fields `Status`, `Control`, `Outcome`, `LateKind` and `State` must be empty unless that kind's row names them, otherwise the fact is illegal: `ProviderCompleted` has `Status`; `LateFrameObserved` has `Status` and `LateKind`; `ControlRequested` has `Control`; `ControlOutcome` has `Control` and `Outcome`; `LegacyImported` has `State`, in the reason-code shape. All other unnamed fields are shape-checked only and need not be empty.
28. `Provider` on any fact, when nonempty, must be Codex or Claude, including `LegacyImported`.
29. Replay reports a session once, but quarantines on the first illegal fact it sees while the session exists, even if an earlier illegal fact was reported before the session was created.
30. `Reduce` ignores `SessionID` and `SessionRevision` on a global fact beyond shape. `TaskID` is an identity, and `ObjectiveHash` a digest, on any fact. `Generation`, `InputRevision` and `Passes` have no check at K1a. None of these change a session.
31. In `Reduce`, the `Abandoned` fact's `Reason` must be nonempty, while `LegacyImported` may have none, and `Reason` on either kind is at most 500 bytes of valid UTF-8. Trimming is `Decide`'s.
32. `Redact` applies the redactor, then trims Unicode whitespace.
33. A raw fact with a bad `At` is illegal. Raw `RuntimeIdentityBound` or `CwdChanged` with an empty value is illegal.
34. `TurnBound` needs a nonempty request. With no request the fact is illegal.
35. An illegal global fact refuses the log as unreadable, whatever `SessionID` it carries.
36. If `Decide`'s own pre-check finds a fact `Reduce` refuses for a precondition, that is a kernel bug and returns a plain error, not a refusal. Only a value out of shape is `bad_value`.
37. A `quarantine` input with a code out of shape is `bad_value` with no effects: only the adapter sends it, so this is an adapter bug.
38. A disconnect ends the Codex turn: K4 stops the provider's process group whenever its stream ends, so clearing `TurnID` is correct. K6 must keep this true.
41. Changed in K2: a writable pause or stop that would change nothing records no fact, so repeated presses cannot grow the log or spend the must-append reserve. Its stop effects still fire.
40. Changed in K2 after a secrets canary found an API-key-shaped value stored as late evidence: a late frame's digest must be 64 lowercase hex characters. `Reduce` refuses a raw `LateFrameObserved` whose digest is neither empty nor that hex form. Identity fields such as provider and turn IDs are identities by design and are stored as given; adapters must never put secrets in them.
39. Superseded by section 11: repeated `disconnected` frames record only when connected or a request is open, and `control-outcome` frames only while a control request is pending.

## Review record

Round 1 blocked on nine row findings, all applied. Round 2 blocked on four (a lost interrupt, an out-of-shape identity, `CWD` shape, and the position of the shape check), all applied as the reviewer proposed. **No third table review was run**, by decision: the findings were narrow with exact fixes, and each round found finer grain rather than a wrong structure. The independent model is the check on these tables: a disagreement the tables cannot settle is stop condition S2, which returns to a plan review of the table.
