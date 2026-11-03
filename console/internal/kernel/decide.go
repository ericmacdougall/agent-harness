package kernel

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"unicode/utf8"
)

const (
	ProviderCodex  = "codex"
	ProviderClaude = "claude"
	maxPendingIn   = 8
	maxInputBytes  = 64 << 10
)

type PrincipalClass string

const (
	PrincipalUser     PrincipalClass = "user"
	PrincipalAgentRun PrincipalClass = "agent-run"
	PrincipalProvider PrincipalClass = "provider"
	PrincipalSystem   PrincipalClass = "system"
)

// Principal comes from the authenticated boundary, never from a decoded body.
type Principal struct {
	Class     PrincipalClass
	SessionID string
}

type InputKind string

const (
	// Commands.
	InCreate          InputKind = "create"
	InSend            InputKind = "send"
	InDispatchInput   InputKind = "dispatch-input"
	InPause           InputKind = "pause"
	InStop            InputKind = "stop"
	InResume          InputKind = "resume"
	InChildControl    InputKind = "child-control"
	InChangeCWD       InputKind = "change-cwd"
	InClose           InputKind = "close"
	InAbandon         InputKind = "abandon"
	InAnswer          InputKind = "answer"
	InQueueInput      InputKind = "queue-input"
	InDiscardInput    InputKind = "discard-input"
	InCheckpoint      InputKind = "checkpoint"
	InStartReview     InputKind = "start-review"
	InSetPolicy       InputKind = "set-policy"
	InSetCascade      InputKind = "set-cascade"
	InSetSupervision  InputKind = "set-supervision"
	InSetBudget       InputKind = "set-budget"
	InSetReviewResult InputKind = "set-review-result"
	// Observations.
	ObConversationBound InputKind = "conversation-bound"
	ObConnected         InputKind = "connected"
	ObDisconnected      InputKind = "disconnected"
	ObAccepted          InputKind = "accepted"
	ObRefused           InputKind = "refused"
	ObUnknown           InputKind = "write-unknown"
	ObTurnBound         InputKind = "turn-bound"
	ObCompleted         InputKind = "completed"
	ObQuestion          InputKind = "question"
	ObControlOutcome    InputKind = "control-outcome"
	ObChild             InputKind = "child"
	ObChildOutcome      InputKind = "child-outcome"
	ObAuthBoundary      InputKind = "auth-boundary"
	ObRestart           InputKind = "restart"
	ObInputOutcome      InputKind = "input-outcome"
	ObPayloadReleased   InputKind = "payload-released"
	ObReviewOutcome     InputKind = "review-outcome"
	ObReviewCancelled   InputKind = "review-cancelled"
	ObQuarantine        InputKind = "quarantine"
)

// Command is the decoded, untrusted shape of a request. Provider adapters build
// Observation inputs directly; nothing here carries prompt text.
type Command struct {
	Kind            InputKind `json:"kind"`
	SessionID       string    `json:"sessionId,omitempty"`
	Provider        string    `json:"provider,omitempty"`
	ProviderID      string    `json:"providerId,omitempty"`
	ProfileID       string    `json:"profileId,omitempty"`
	CWD             string    `json:"cwd,omitempty"`
	RequestID       string    `json:"requestId,omitempty"`
	ExpectedRequest string    `json:"expectedRequestId,omitempty"`
	Reason          string    `json:"reason,omitempty"`
	ID              string    `json:"id,omitempty"`
	TaskID          string    `json:"taskId,omitempty"`
	Generation      uint64    `json:"generation,omitempty"`
	ObjectiveHash   string    `json:"objectiveHash,omitempty"`
	PayloadHash     string    `json:"payloadHash,omitempty"`
	Attachments     []string  `json:"attachments,omitempty"`
	Stage           string    `json:"stage,omitempty"`
	Digest          string    `json:"digest,omitempty"`
	State           string    `json:"state,omitempty"`
	Status          string    `json:"status,omitempty"`
}

// userCommands are the only kinds a decoded body may name. Observations and system
// inputs come from adapters inside the process, never from a request.
var userCommands = map[InputKind]bool{InCreate: true, InSend: true, InPause: true, InStop: true, InResume: true, InChildControl: true, InChangeCWD: true, InClose: true, InAbandon: true, InAnswer: true, InQueueInput: true, InDiscardInput: true, InCheckpoint: true}

// allowedPrincipals is default-deny: a kind not listed here is refused for everyone.
var allowedPrincipals = map[InputKind][]PrincipalClass{
	InCreate: {PrincipalUser, PrincipalSystem}, InSend: {PrincipalUser, PrincipalSystem}, InDispatchInput: {PrincipalSystem},
	InPause: {PrincipalUser}, InStop: {PrincipalUser}, InResume: {PrincipalUser}, InChildControl: {PrincipalUser},
	InChangeCWD: {PrincipalUser}, InClose: {PrincipalUser}, InAbandon: {PrincipalUser}, InAnswer: {PrincipalUser},
	InQueueInput: {PrincipalUser}, InDiscardInput: {PrincipalUser}, InCheckpoint: {PrincipalAgentRun},
	InStartReview: {PrincipalSystem}, InSetPolicy: {PrincipalSystem}, InSetCascade: {PrincipalSystem},
	InSetSupervision: {PrincipalSystem}, InSetBudget: {PrincipalSystem}, InSetReviewResult: {PrincipalSystem},
	ObConversationBound: {PrincipalProvider}, ObConnected: {PrincipalProvider}, ObDisconnected: {PrincipalProvider},
	ObAccepted: {PrincipalProvider}, ObRefused: {PrincipalProvider}, ObUnknown: {PrincipalProvider}, ObTurnBound: {PrincipalProvider},
	ObCompleted: {PrincipalProvider}, ObQuestion: {PrincipalProvider}, ObControlOutcome: {PrincipalProvider}, ObChild: {PrincipalProvider},
	ObChildOutcome: {PrincipalProvider}, ObAuthBoundary: {PrincipalSystem}, ObRestart: {PrincipalSystem}, ObInputOutcome: {PrincipalSystem},
	ObPayloadReleased: {PrincipalSystem}, ObReviewOutcome: {PrincipalSystem}, ObReviewCancelled: {PrincipalSystem}, ObQuarantine: {PrincipalSystem},
}

var commandFields = func() map[string]bool {
	fields := map[string]bool{}
	kind := reflect.TypeOf(Command{})
	for i := 0; i < kind.NumField(); i++ {
		fields[strings.Split(kind.Field(i).Tag.Get("json"), ",")[0]] = true
	}
	return fields
}()

// DecodeCommand is strict about size, encoding, exact names and duplicates.
func DecodeCommand(data []byte) (Command, error) {
	var c Command
	if len(data) == 0 || len(data) > maxInputBytes || !utf8.Valid(data) {
		return c, errors.New("malformed command: size or encoding")
	}
	if err := checkJSONKeys(data, commandFields); err != nil {
		return c, fmt.Errorf("malformed command: %v", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&c); err != nil {
		return Command{}, fmt.Errorf("malformed command: %v", err)
	}
	if _, err := decoder.Token(); err != io.EOF {
		return Command{}, errors.New("malformed command: trailing content")
	}
	if !userCommands[c.Kind] {
		return Command{}, errors.New("malformed command: not a command kind")
	}
	return c, nil
}

// In is one input to Decide: time and identity arrive here, since Decide is pure.
type In struct {
	Kind            InputKind
	Principal       Principal
	At              string
	SessionID       string
	Provider        string
	ProviderID      string
	ProfileID       string
	CWD             string
	RequestID       string
	ExpectedRequest string
	TurnID          string
	Reason          RedactedReason
	ReasonCode      string
	ID              string
	Role            string
	Status          string
	Outcome         string
	Digest          string
	ExpiresAt       string
	TaskID          string
	Generation      uint64
	InputRevision   uint64
	ObjectiveHash   string
	PayloadHash     string
	Attachments     []string
	Stage           string
	State           string
	Verdict         string
	RuntimeIdentity string
	PolicyRevision  string
	Cascade         string
	RemainingBursts int64
	Progress        int64
	Automatic       bool
	ExpectedTask    string
	ExpectedEpoch   uint64
	ReviewRunID     string
}

type EffectKind string

const (
	EffectStartTurn      EffectKind = "start-turn"
	EffectAnswerQuestion EffectKind = "answer-question"
	EffectInterrupt      EffectKind = "interrupt"
	EffectTerminate      EffectKind = "terminate"
	EffectRejectQuestion EffectKind = "reject-question"
	EffectCleanupPayload EffectKind = "cleanup-payload"
)

type EffectClass string

const (
	// ClassNewWork is fenced: its fact commits first, and the adapter rechecks Fence
	// and the log latch at the writer gate immediately before writing.
	ClassNewWork EffectClass = "new-work"
	// ClassStopWork does not depend on an append. The adapter fires it even when the
	// append fails or the log is latched, and never takes the write gate, so a hung
	// write or a later boundary cannot prevent a stop.
	ClassStopWork EffectClass = "stop-work"
	// ClassLocal is idempotent and reconciled from the projection on open.
	ClassLocal EffectClass = "local"
)

// Effect is a descriptor. Replay never calls Decide, so it can never fire one. The
// adapter pairs it with its live process epoch, which is not authority.
type Effect struct {
	Kind      EffectKind
	Class     EffectClass
	SessionID string
	RequestID string
	TurnID    string
	ID        string
	Fence     uint64
}

// Decision is what to commit and what to do after. A user command's refusal returns
// as Refusal; a refusal with no user waiting is recorded as AdmissionRefused.
type Decision struct {
	Facts      []Fact
	Effects    []Effect
	Idempotent bool
}

// Refusal is a typed, expected rejection.
type Refusal struct {
	Code    string
	Message string
}

func (r *Refusal) Error() string { return r.Message }

func refuse(code, message string) (Decision, error) {
	return Decision{}, &Refusal{Code: code, Message: message}
}

type builder struct {
	p        Projection
	at       string
	facts    []Fact
	effects  []Effect
	revision map[string]uint64
}

func (b *builder) add(f Fact) {
	f.Seq = b.p.LastSeq + uint64(len(b.facts)) + 1
	f.SchemaVersion = SchemaVersion
	f.At = b.at
	if !globalFact(f.Kind) {
		rev, seen := b.revision[f.SessionID]
		if !seen {
			if s := b.p.Sessions[f.SessionID]; s != nil {
				rev = s.Revision
			}
		}
		rev++
		b.revision[f.SessionID] = rev
		f.SessionRevision = rev
	}
	b.facts = append(b.facts, f)
}

func (b *builder) effect(e Effect) { b.effects = append(b.effects, e) }

// finish reduces on a copy before anything is committed, so a Decide bug yields a
// refusal rather than an illegal fact in the log.
func (b *builder) finish() (Decision, error) {
	next := b.p
	for _, f := range b.facts {
		reduced, err := Reduce(next, f)
		if errors.Is(err, errBadValue) {
			return refuse("bad_value", "a value is outside what this field allows")
		}
		if err != nil {
			return Decision{}, fmt.Errorf("decide produced an illegal fact: %w", err)
		}
		next = reduced
	}
	return Decision{Facts: b.facts, Effects: b.effects}, nil
}

// Decide maps one input to facts and effects. It is pure and provider-neutral, so a
// guard cannot apply to one provider or one path only.
func Decide(p Projection, in In) (Decision, error) {
	if err := authorize(in); err != nil {
		return Decision{}, err
	}
	if !timePattern.MatchString(in.At) {
		return refuse("bad_time", "a fixed-width UTC time is required")
	}
	b := &builder{p: p, at: in.At, revision: map[string]uint64{}}
	if in.Kind == ObRestart {
		return decideRestart(b)
	}
	if in.Kind == InCreate {
		return decideCreate(b, in)
	}
	s := p.Sessions[in.SessionID]
	if s == nil || s.Closed {
		if in.Kind == ObAuthBoundary {
			return decideAuth(b, in)
		}
		// A discarded tab may close before its start is answered. The reply still has
		// to interrupt that turn, with nothing left to record.
		if in.Kind == ObTurnBound && s != nil && s.PendingInterrupt && in.RequestID == s.LastRequest && in.TurnID != "" {
			return Decision{Effects: []Effect{{Kind: EffectInterrupt, Class: ClassStopWork, SessionID: s.ID, RequestID: in.RequestID, TurnID: in.TurnID}}}, nil
		}
		return refuse("not_found", "session not found")
	}
	switch in.Kind {
	case InSend, InDispatchInput:
		return decideSend(b, s, in)
	case InPause, InStop:
		return decideControl(b, s, in)
	case InResume:
		return decideResume(b, s, in)
	case InChildControl:
		return decideChildControl(b, s, in)
	case InChangeCWD:
		return decideCWD(b, s, in)
	case InClose:
		return decideClose(b, s)
	case InAbandon:
		return decideAbandon(b, s, in)
	case InAnswer:
		return decideAnswer(b, s, in)
	case InQueueInput:
		return decideQueue(b, s, in)
	case InDiscardInput:
		return decideDiscardInput(b, s, in)
	case InCheckpoint:
		return decideCheckpoint(b, s, in)
	case InStartReview:
		return decideStartReview(b, s, in)
	case InSetPolicy, InSetCascade, InSetSupervision, InSetBudget, InSetReviewResult:
		return decideSetting(b, s, in)
	case ObConversationBound:
		if s.ReadOnly {
			return b.late(s, in, "conversation")
		}
		bindIdentity(b, s, in)
		b.add(Fact{Kind: FactConversationBound, SessionID: s.ID, ProviderID: in.ProviderID})
		return b.finish()
	case ObConnected:
		if s.ReadOnly {
			return b.late(s, in, "connected")
		}
		b.add(Fact{Kind: FactProviderConnected, SessionID: s.ID})
		return b.finish()
	case ObDisconnected:
		if s.ReadOnly {
			return b.late(s, in, "disconnected")
		}
		b.add(Fact{Kind: FactProviderDisconnected, SessionID: s.ID, ReasonCode: in.ReasonCode})
		return b.finish()
	case ObAccepted, ObRefused, ObUnknown:
		return decideEffectResult(b, s, in)
	case ObTurnBound:
		return decideTurnBound(b, s, in)
	case ObCompleted:
		return decideCompleted(b, s, in)
	case ObQuestion:
		return decideQuestion(b, s, in)
	case ObControlOutcome:
		b.add(Fact{Kind: FactControlOutcome, SessionID: s.ID, Control: in.Status, Outcome: in.Outcome})
		return b.finish()
	case ObChild:
		if s.ReadOnly {
			return b.late(s, in, "child")
		}
		b.add(Fact{Kind: FactChildObserved, SessionID: s.ID, ID: in.ID, Role: in.Role, TurnID: in.TurnID, Status: in.Status})
		return b.finish()
	case ObChildOutcome:
		for _, child := range s.Children {
			if child.ID == in.ID {
				b.add(Fact{Kind: FactChildControlOutcome, SessionID: s.ID, ID: in.ID, Status: in.Status, ReasonCode: in.ReasonCode})
				return b.finish()
			}
		}
		return b.late(s, in, "child")
	case ObAuthBoundary:
		return decideAuth(b, in)
	case ObInputOutcome:
		return decideInputOutcome(b, s, in)
	case ObPayloadReleased:
		if entry := findInput(s, in.RequestID); entry == nil || entry.Status != InputCleanup {
			return refuse("no_payload", "payload is not pending release")
		}
		b.add(Fact{Kind: FactPayloadReleased, SessionID: s.ID, RequestID: in.RequestID})
		return b.finish()
	case ObReviewOutcome:
		return decideReviewOutcome(b, s, in)
	case ObQuarantine:
		b.add(Fact{Kind: FactSessionQuarantined, SessionID: s.ID, ReasonCode: in.ReasonCode})
		return b.finish()
	case ObReviewCancelled:
		if s.Review == nil || s.Review.ID != in.ID || s.Review.Status != "running" {
			return b.late(s, in, "review")
		}
		b.add(Fact{Kind: FactReviewCancelled, SessionID: s.ID, ID: in.ID})
		return b.finish()
	}
	return refuse("unknown_input", "unknown input")
}

// authorize runs before anything else, including restart and create, and denies any
// kind or principal it does not name.
func authorize(in In) error {
	forbidden := &Refusal{Code: "forbidden", Message: "this principal cannot do that"}
	allowed := false
	for _, class := range allowedPrincipals[in.Kind] {
		allowed = allowed || class == in.Principal.Class
	}
	if !allowed {
		return forbidden
	}
	switch in.Kind {
	case InSend:
		// Only the scheduler continues on its own, and a user always acts directly.
		if in.Automatic != (in.Principal.Class == PrincipalSystem) {
			return forbidden
		}
	case InDispatchInput:
		if !in.Automatic {
			return forbidden
		}
	}
	// A run or a provider connection speaks for its own session only.
	if (in.Principal.Class == PrincipalProvider || in.Principal.Class == PrincipalAgentRun) && in.Principal.SessionID != in.SessionID {
		return forbidden
	}
	return nil
}

func decideRestart(b *builder) (Decision, error) {
	// A crash loop must not spend the reserve, and epochs are process-local.
	if b.p.LastKind == FactProcessRestarted {
		return Decision{Idempotent: true}, nil
	}
	b.add(Fact{Kind: FactProcessRestarted})
	return b.finish()
}

func decideCreate(b *builder, in In) (Decision, error) {
	if in.SessionID == "" || b.p.Sessions[in.SessionID] != nil {
		return refuse("session_exists", "session identity is missing or already used")
	}
	if in.Provider != ProviderCodex && in.Provider != ProviderClaude {
		return refuse("bad_provider", "choose Codex or Claude")
	}
	b.add(Fact{Kind: FactSessionCreated, SessionID: in.SessionID, Provider: in.Provider, ProviderID: in.ProviderID, ProfileID: in.ProfileID, CWD: in.CWD, Status: in.Status})
	return b.finish()
}

// refuseAdmission tells a waiting user directly. With no user waiting, the refusal
// becomes a coalesced fact so it stays visible and survives restart.
func (b *builder) refuseAdmission(s *Session, in In, code, message string) (Decision, error) {
	if !in.Automatic {
		return refuse(code, message)
	}
	if s.ReadOnly || s.LastRefusal == code {
		return Decision{Idempotent: true}, &Refusal{Code: code, Message: message}
	}
	b.add(Fact{Kind: FactAdmissionRefused, SessionID: s.ID, ReasonCode: code})
	decision, err := b.finish()
	if err != nil {
		return decision, err
	}
	return decision, &Refusal{Code: code, Message: message}
}

func decideSend(b *builder, s *Session, in In) (Decision, error) {
	if in.RequestID == "" {
		return refuse("bad_request", "a request identity is required")
	}
	if prior, exists := s.Requests[in.RequestID]; exists {
		// A lost response retries here: same outcome, no second write.
		if prior == ReceiptAccepted || prior == ReceiptFinal || prior == ReceiptIntent {
			return Decision{Idempotent: true}, nil
		}
		return refuse("not_replayed", "prior request outcome is not successful; it was not replayed")
	}
	if s.ReadOnly || s.Quarantine != "" {
		return b.refuseAdmission(s, in, "read_only", "this tab is read-only; continue in a new session")
	}
	if s.Requests[s.LastRequest].unresolved() {
		return b.refuseAdmission(s, in, "unresolved", "the last request has no final outcome; reconcile or discard it first")
	}
	if len(s.Questions) > 0 {
		return b.refuseAdmission(s, in, "waiting", "this session is waiting on a question")
	}
	if s.Provider == ProviderCodex && !s.Connected {
		return b.refuseAdmission(s, in, "disconnected", "provider connection is lost; continue in a new session")
	}
	if in.RuntimeIdentity == "" {
		return b.refuseAdmission(s, in, "no_identity", "the runtime identity is unavailable; try again")
	}
	if s.RuntimeIdentity != "" && in.RuntimeIdentity != s.RuntimeIdentity {
		return b.refuseAdmission(s, in, "runtime_changed", "credentials or tools changed; start a new context session")
	}
	// A conversation that began with no recorded owner cannot be claimed by a runtime
	// that may hold another account.
	if s.RuntimeIdentity == "" && s.ConversationStarted {
		return b.refuseAdmission(s, in, "no_owner", "this conversation has no recorded owner; start a new context session")
	}
	if in.Kind == InDispatchInput {
		return decideDispatchInput(b, s, in)
	}
	if in.Automatic {
		if s.Task == nil || s.Task.ID != in.ExpectedTask || s.ControlEpoch != in.ExpectedEpoch {
			return b.refuseAdmission(s, in, "stale_binding", "automatic continuation belongs to an older task or control")
		}
		if taskEnded(s.Task) {
			return b.refuseAdmission(s, in, "task_ended", "this task has ended; start a new objective")
		}
		if s.Supervision.State != SupervisionActive && s.Supervision.State != SupervisionWaiting {
			return b.refuseAdmission(s, in, "not_active", "automatic continuation is no longer active")
		}
		if !s.ProviderFinal {
			return b.refuseAdmission(s, in, "no_finality", "prior native finality is unverified")
		}
		if s.Supervision.RemainingBursts <= 0 {
			return b.refuseAdmission(s, in, "budget", "automatic continuation budget is exhausted")
		}
	} else {
		if activeQueue(s) {
			return refuse("queue_active", "retained or queued inputs remain; reconcile or discard before replacing the objective")
		}
		if s.Task != nil && s.Task.State != TaskComplete && s.Task.State != TaskBlocked && s.Task.State != TaskHandoff && s.Task.State != TaskIdle {
			return refuse("tracked_work", "tracked work remains; queue a follow-up instead of replacing it")
		}
		if in.TaskID == "" {
			return refuse("bad_request", "a task identity is required for a new objective")
		}
	}
	bindIdentity(b, s, in)
	fact := Fact{Kind: FactRequestIntended, SessionID: s.ID, RequestID: in.RequestID}
	if in.Automatic {
		// Spent in the same commit as the send, and the task never changes here.
		b.add(Fact{Kind: FactContinuationBudgetChanged, SessionID: s.ID, RemainingBursts: s.Supervision.RemainingBursts - 1, Progress: s.Supervision.Progress})
		fact.TaskID = s.Task.ID
	} else {
		fact.TaskID, fact.Generation, fact.ObjectiveHash = in.TaskID, in.Generation, in.ObjectiveHash
		fact.Status, fact.RemainingBursts = "new_objective", in.RemainingBursts
	}
	b.add(fact)
	b.effect(Effect{Kind: EffectStartTurn, Class: ClassNewWork, SessionID: s.ID, RequestID: in.RequestID, Fence: s.ControlEpoch})
	return b.finish()
}

func taskEnded(task *Task) bool {
	return task != nil && (task.State == TaskComplete || task.State == TaskBlocked || task.State == TaskHandoff)
}

func bindIdentity(b *builder, s *Session, in In) {
	if s.RuntimeIdentity == "" && in.RuntimeIdentity != "" {
		b.add(Fact{Kind: FactRuntimeIdentityBound, SessionID: s.ID, RuntimeIdentity: in.RuntimeIdentity})
	}
}

func decideDispatchInput(b *builder, s *Session, in In) (Decision, error) {
	if s.Supervision.State != SupervisionActive && s.Supervision.State != SupervisionWaiting {
		return b.refuseAdmission(s, in, "not_active", "queued dispatch is not active")
	}
	if s.Task == nil {
		return b.refuseAdmission(s, in, "no_task", "queued input has no task")
	}
	if taskEnded(s.Task) {
		return b.refuseAdmission(s, in, "task_ended", "this task has ended; start a new objective")
	}
	// FIFO: a held or unknown head is never bypassed.
	var head *Input
	for i := range s.Inputs {
		entry := &s.Inputs[i]
		if entry.Status == InputQueued || entry.Status == InputHeld || entry.Status == InputDispatching || entry.Status == InputUnknown {
			head = entry
			break
		}
	}
	if head == nil || head.RequestID != in.RequestID || head.Status != InputQueued {
		return b.refuseAdmission(s, in, "not_head", "this input is not the queue head")
	}
	bindIdentity(b, s, in)
	b.add(Fact{Kind: FactInputDispatchPrepared, SessionID: s.ID, RequestID: in.RequestID, TaskID: s.Task.ID, InputRevision: s.Task.InputRevision + 1, ObjectiveHash: in.ObjectiveHash})
	b.add(Fact{Kind: FactRequestIntended, SessionID: s.ID, RequestID: in.RequestID, TaskID: s.Task.ID})
	b.effect(Effect{Kind: EffectStartTurn, Class: ClassNewWork, SessionID: s.ID, RequestID: in.RequestID, Fence: s.ControlEpoch})
	return b.finish()
}

func activeQueue(s *Session) bool {
	for _, input := range s.Inputs {
		if input.Status != InputDiscarded {
			return true
		}
	}
	return false
}

func stopEffects(s *Session, kind EffectKind) []Effect {
	effects := []Effect{}
	// A Claude turn has no addressable turn to interrupt; its process is the handle.
	if s.Provider == ProviderClaude && s.Requests[s.LastRequest].unresolved() {
		effects = append(effects, Effect{Kind: EffectTerminate, Class: ClassStopWork, SessionID: s.ID, RequestID: s.LastRequest})
		return effects
	}
	if s.TurnID != "" {
		effects = append(effects, Effect{Kind: kind, Class: ClassStopWork, SessionID: s.ID, RequestID: s.LastRequest, TurnID: s.TurnID})
	}
	return effects
}

func decideControl(b *builder, s *Session, in In) (Decision, error) {
	// A read-only session changes no authority, but a stop effect still fires where
	// there may be a writer.
	if s.ReadOnly {
		decision := Decision{Idempotent: true, Effects: stopEffects(s, EffectInterrupt)}
		if len(decision.Effects) > 0 {
			return decision, nil
		}
		return decision, &Refusal{Code: "read_only", Message: "this tab is read-only; continue in a new session"}
	}
	// An unknown turn may still be running. Stop still works, and changes no admission
	// authority: it only records that the interrupt is owed if the turn is unnamed.
	if s.Requests[s.LastRequest] == ReceiptUnknown {
		effects := stopEffects(s, EffectInterrupt)
		if s.Provider == ProviderCodex && s.TurnID == "" && !s.PendingInterrupt {
			b.add(Fact{Kind: FactControlRequested, SessionID: s.ID, Control: "stop"})
		}
		if len(b.facts) == 0 && len(effects) == 0 {
			return Decision{Idempotent: true}, &Refusal{Code: "nothing_to_stop", Message: "there is nothing running to stop"}
		}
		decision, err := b.finish()
		decision.Effects = effects
		return decision, err
	}
	control := "pause"
	if in.Kind == InStop {
		control = "stop"
	}
	b.add(Fact{Kind: FactControlRequested, SessionID: s.ID, Control: control})
	for _, effect := range stopEffects(s, EffectInterrupt) {
		b.effect(effect)
	}
	return b.finish()
}

func decideResume(b *builder, s *Session, in In) (Decision, error) {
	switch {
	case s.ReadOnly:
		return refuse("read_only", "this tab is read-only; continue in a new session")
	case s.Requests[s.LastRequest] == ReceiptUnknown:
		return refuse("unresolved", "reconcile or discard the unknown request before resuming")
	case s.Supervision.State != SupervisionPaused && s.Supervision.State != SupervisionWaiting:
		return refuse("not_paused", "session is not paused or waiting for continuation")
	case s.Task == nil || s.Task.ReviewStatus == ReviewUnknown || s.Task.ReviewStatus == ReviewInvalidated || s.Task.ReviewStatus == ReviewPaused || s.Task.State == TaskComplete || s.Task.State == TaskBlocked || s.Task.State == TaskHandoff:
		return refuse("no_task", "no resumable task or unresolved review; continue in a new session")
	case !s.ProviderFinal:
		return refuse("no_finality", "prior native finality is unverified; reconcile before Resume")
	}
	b.add(Fact{Kind: FactControlRequested, SessionID: s.ID, Control: "resume"})
	return b.finish()
}

// A child's own claim of being resumable is never capability proof, so direct Resume
// has no path here at all. A parent replaces it from its current context.
func decideChildControl(b *builder, s *Session, in In) (Decision, error) {
	if in.Status == "resume" {
		return refuse("child_resume_refused", "direct child resume is refused; a parent dispatches a fresh owner after reconciling")
	}
	for _, child := range s.Children {
		if child.ID == in.ID {
			if child.TurnID == "" {
				return refuse("no_turn", "this child has no bound turn to control")
			}
			b.effect(Effect{Kind: EffectInterrupt, Class: ClassStopWork, SessionID: s.ID, ID: child.ID, TurnID: child.TurnID})
			return Decision{Effects: b.effects}, nil
		}
	}
	return refuse("not_found", "agent is not owned by this session")
}

func decideCWD(b *builder, s *Session, in In) (Decision, error) {
	switch {
	case s.ReadOnly:
		return refuse("read_only", "this tab is read-only; continue in a new session")
	case s.Requests[s.LastRequest].unresolved():
		return refuse("unresolved", "the last request has no final outcome; reconcile or discard it first")
	case activeQueue(s):
		return refuse("queue_active", "queued or retained inputs bind this directory; cancel or discard them first")
	case in.CWD == "":
		return refuse("bad_request", "a directory is required")
	}
	b.add(Fact{Kind: FactCwdChanged, SessionID: s.ID, CWD: in.CWD})
	return b.finish()
}

func decideClose(b *builder, s *Session) (Decision, error) {
	if activeQueue(s) {
		return refuse("queue_active", "queued or retained input remains; cancel or discard it before closing")
	}
	if s.Abandoned == nil {
		if s.Requests[s.LastRequest].unresolved() || s.Quarantine != "" {
			return refuse("unresolved", "the last request has no final outcome; stop or discard it before closing")
		}
		for _, child := range s.Children {
			if child.Status == ChildRunning {
				return refuse("child_active", "an owner is still active; stop or reconcile it before closing")
			}
		}
	}
	b.add(Fact{Kind: FactSessionClosed, SessionID: s.ID})
	return b.finish()
}

// decideAbandon is explicit, user-only, and needs the expected request, so a dialog
// opened for an older turn cannot discard a newer one. It never produces a final.
func decideAbandon(b *builder, s *Session, in In) (Decision, error) {
	reason := in.Reason.String()
	if reason == "" || len(reason) > MaxReasonBytes {
		return refuse("bad_reason", "a reason of up to 500 bytes is required")
	}
	if s.Abandoned != nil {
		if s.Abandoned.RequestID == in.ExpectedRequest {
			return Decision{Idempotent: true}, nil
		}
		return refuse("discarded_other", "this tab was already discarded for a different turn")
	}
	if s.LastRequest != in.ExpectedRequest {
		return refuse("turn_changed", "the turn changed since this was confirmed; check it and try again")
	}
	receipt := s.Requests[s.LastRequest]
	status := Status(s)
	if !s.ReadOnly && (status == "running" || status == "waiting") {
		return refuse("stop_first", "stop or pause this turn before discarding it")
	}
	if !receipt.unresolved() && status != "unknown" {
		return refuse("nothing_to_discard", "this turn has a final outcome; there is nothing to discard")
	}
	b.add(Fact{Kind: FactAbandoned, SessionID: s.ID, RequestID: s.LastRequest, Reason: reason})
	for _, effect := range stopEffects(s, EffectInterrupt) {
		b.effect(effect)
	}
	return b.finish()
}

func decideAnswer(b *builder, s *Session, in In) (Decision, error) {
	for _, q := range s.Questions {
		if q.ID != in.ID {
			continue
		}
		// Times are RFC 3339 UTC with fixed width from the boundary, so they compare
		// as strings and Decide stays clock-free.
		if s.ReadOnly || q.RequestID != s.LastRequest || !s.Requests[q.RequestID].open() || q.ControlEpoch != s.ControlEpoch || q.ExpiresAt <= in.At {
			return refuse("question_stale", "question expired, revoked or belongs to a different turn")
		}
		b.add(Fact{Kind: FactQuestionAnswered, SessionID: s.ID, ID: q.ID})
		// An answer is new work allowed only because its own request is active.
		b.effect(Effect{Kind: EffectAnswerQuestion, Class: ClassNewWork, SessionID: s.ID, RequestID: q.RequestID, TurnID: q.TurnID, ID: q.ID, Fence: s.ControlEpoch})
		return b.finish()
	}
	return refuse("question_stale", "question expired, revoked or belongs to a different turn")
}

func decideQueue(b *builder, s *Session, in In) (Decision, error) {
	if entry := findInput(s, in.RequestID); entry != nil {
		if entry.PayloadHash != in.PayloadHash {
			return refuse("identity_conflict", "this request identity holds different queued input")
		}
		return Decision{Idempotent: true}, nil
	}
	status := Status(s)
	if s.ReadOnly || s.Task == nil || status == "unknown" || status == "error" || status == "disconnected" || s.Task.State == TaskComplete || s.Task.State == TaskBlocked || s.Task.State == TaskHandoff {
		return refuse("needs_new_context", "session needs a new interactive context before accepting follow-ups")
	}
	if _, exists := s.Requests[in.RequestID]; exists || in.RequestID == "" {
		return refuse("identity_conflict", "this request identity belongs to a provider send")
	}
	pending := 0
	for _, entry := range s.Inputs {
		if entry.Status == InputQueued || entry.Status == InputHeld || entry.Status == InputDispatching || entry.Status == InputUnknown {
			pending++
		}
	}
	if pending >= maxPendingIn {
		return refuse("queue_full", "the queue is full; resolve existing inputs first")
	}
	b.add(Fact{Kind: FactInputQueued, SessionID: s.ID, RequestID: in.RequestID, PayloadHash: in.PayloadHash, Attachments: in.Attachments})
	return b.finish()
}

func decideDiscardInput(b *builder, s *Session, in In) (Decision, error) {
	entry := findInput(s, in.RequestID)
	if entry == nil {
		return refuse("not_found", "queued input not found")
	}
	if entry.Status == InputDiscarded || entry.Status == InputCleanup {
		return Decision{Idempotent: true}, nil
	}
	if entry.Status == InputDispatching {
		return refuse("dispatching", "dispatch is in progress; pause and reconcile before local discard")
	}
	b.add(Fact{Kind: FactInputDiscarded, SessionID: s.ID, RequestID: in.RequestID})
	b.effect(Effect{Kind: EffectCleanupPayload, Class: ClassLocal, SessionID: s.ID, RequestID: in.RequestID})
	return b.finish()
}

func decideInputOutcome(b *builder, s *Session, in In) (Decision, error) {
	entry := findInput(s, in.RequestID)
	if entry == nil || entry.Status != InputDispatching {
		return refuse("no_dispatch", "this input has no open dispatch")
	}
	b.add(Fact{Kind: FactInputOutcome, SessionID: s.ID, RequestID: in.RequestID, Status: in.Status})
	return b.finish()
}

func decideCheckpoint(b *builder, s *Session, in In) (Decision, error) {
	if s.ReadOnly || !s.Requests[s.LastRequest].open() || s.Task == nil || s.Task.ID != in.TaskID || s.Supervision.State == SupervisionPaused {
		return refuse("checkpoint_stale", "checkpoint belongs to an inactive request or task")
	}
	if s.Task.State == TaskComplete {
		return refuse("checkpoint_complete", "a complete task cannot be reopened")
	}
	b.add(Fact{Kind: FactCheckpointRecorded, SessionID: s.ID, TaskID: in.TaskID, State: in.State, Stage: in.Stage, Digest: in.Digest})
	return b.finish()
}

func decideStartReview(b *builder, s *Session, in In) (Decision, error) {
	if s.ReadOnly || s.Task == nil {
		return refuse("read_only", "this tab cannot start a review")
	}
	b.add(Fact{Kind: FactReviewStarted, SessionID: s.ID, ID: in.ID, Stage: in.Stage, Digest: in.Digest})
	return b.finish()
}

func decideSetting(b *builder, s *Session, in In) (Decision, error) {
	if s.ReadOnly {
		return refuse("read_only", "this tab is read-only")
	}
	switch in.Kind {
	case InSetPolicy:
		b.add(Fact{Kind: FactPolicyBound, SessionID: s.ID, PolicyRevision: in.PolicyRevision})
	case InSetCascade:
		b.add(Fact{Kind: FactCascadeSelected, SessionID: s.ID, Cascade: in.Cascade})
	case InSetSupervision:
		b.add(Fact{Kind: FactSupervisionChanged, SessionID: s.ID, State: in.State, ReasonCode: in.ReasonCode})
	case InSetBudget:
		b.add(Fact{Kind: FactContinuationBudgetChanged, SessionID: s.ID, RemainingBursts: in.RemainingBursts, Progress: in.Progress})
	case InSetReviewResult:
		b.add(Fact{Kind: FactReviewResultPending, SessionID: s.ID, Status: in.Status})
	}
	return b.finish()
}

// late records evidence for a frame or effect result that cannot change anything,
// coalesced per request and kind so a noisy provider cannot consume the log.
func (b *builder) late(s *Session, in In, kind string) (Decision, error) {
	// Provider values are free text, so only safe shapes reach the log. A request this
	// session never made shares one key, or a provider could grow the map at will.
	status, digest, request := in.Status, in.Digest, in.RequestID
	if status != "" && !codePattern.MatchString(status) {
		status = "invalid"
	}
	if digest != "" && !digestPattern.MatchString(digest) {
		digest = ""
	}
	if _, known := s.Requests[request]; !known {
		request = ""
	}
	if prior, seen := s.Evidence[evidenceKey(request, kind)]; seen && strings.HasPrefix(prior, status+"|") {
		return Decision{Idempotent: true}, nil
	}
	b.add(Fact{Kind: FactLateFrameObserved, SessionID: s.ID, RequestID: request, LateKind: kind, Status: status, Digest: digest})
	return b.finish()
}

func decideEffectResult(b *builder, s *Session, in In) (Decision, error) {
	receipt := s.Requests[in.RequestID]
	kind := map[InputKind]string{ObAccepted: "accepted", ObRefused: "refused", ObUnknown: "write_unknown"}[in.Kind]
	// A result on a terminal, unknown or foreign receipt still has to be recorded,
	// for instance a failed drain after a discard, but it changes no outcome.
	if in.RequestID != s.LastRequest || !receipt.open() || s.ReadOnly {
		return b.late(s, in, kind)
	}
	switch in.Kind {
	case ObAccepted:
		if receipt == ReceiptAccepted {
			return Decision{Idempotent: true}, nil
		}
		b.add(Fact{Kind: FactProviderAccepted, SessionID: s.ID, RequestID: in.RequestID})
	case ObRefused:
		b.add(Fact{Kind: FactProviderRefused, SessionID: s.ID, RequestID: in.RequestID, ReasonCode: in.ReasonCode})
	case ObUnknown:
		b.add(Fact{Kind: FactOutcomeUnknown, SessionID: s.ID, RequestID: in.RequestID, ReasonCode: in.ReasonCode})
	}
	return b.finish()
}

// decideTurnBound reaches here for every correlated reply, including on an abandoned
// request, so a pending interrupt cannot be lost and replay can never fire it.
func decideTurnBound(b *builder, s *Session, in In) (Decision, error) {
	if in.RequestID != s.LastRequest {
		return b.late(s, in, "turn_bound")
	}
	if in.TurnID == "" || (s.TurnID != "" && s.TurnID != in.TurnID) {
		return b.late(s, in, "turn_bound")
	}
	if s.TurnID == in.TurnID {
		return Decision{Idempotent: true}, nil
	}
	// An unknown turn may still be running, so its name is kept for a later Stop.
	pending := s.PendingInterrupt
	if !pending && !s.Requests[in.RequestID].unresolved() {
		return b.late(s, in, "turn_bound")
	}
	b.add(Fact{Kind: FactTurnBound, SessionID: s.ID, RequestID: in.RequestID, TurnID: in.TurnID})
	if pending {
		b.effect(Effect{Kind: EffectInterrupt, Class: ClassStopWork, SessionID: s.ID, RequestID: in.RequestID, TurnID: in.TurnID})
	}
	return b.finish()
}

func decideCompleted(b *builder, s *Session, in In) (Decision, error) {
	active := s.Requests[s.LastRequest]
	// No exact request binding: the only safe reading is that the active turn's
	// outcome is now unknown.
	if in.RequestID == "" {
		if active.open() && !s.ReadOnly {
			b.add(Fact{Kind: FactOutcomeUnknown, SessionID: s.ID, RequestID: s.LastRequest, ReasonCode: "unbound_completion"})
			return b.finish()
		}
		return b.late(s, in, "final")
	}
	if in.RequestID != s.LastRequest || !active.open() || s.ReadOnly {
		return b.late(s, in, "final")
	}
	// Codex binds by turn. A frame for another turn cannot finalize this one.
	if s.Provider == ProviderCodex && (s.TurnID == "" || s.TurnID != in.TurnID) {
		return b.late(s, in, "final")
	}
	if !oneOfValues(in.Status, finalStatuses...) {
		b.add(Fact{Kind: FactOutcomeUnknown, SessionID: s.ID, RequestID: in.RequestID, ReasonCode: "invalid_final_status"})
		return b.finish()
	}
	b.add(Fact{Kind: FactProviderCompleted, SessionID: s.ID, RequestID: in.RequestID, Status: in.Status})
	return b.finish()
}

func decideQuestion(b *builder, s *Session, in In) (Decision, error) {
	reject := Effect{Kind: EffectRejectQuestion, Class: ClassStopWork, SessionID: s.ID, RequestID: in.RequestID, ID: in.ID}
	// A reviewer must run unattended, so asking is a terminal review failure. Nothing
	// can then reopen it, since the run is no longer running. Every path to read-only
	// ends a running review first, so this cannot fire on a read-only session.
	if s.Review != nil && s.Review.Status == "running" && s.Review.ID == in.ReviewRunID {
		b.add(Fact{Kind: FactReviewOutcome, SessionID: s.ID, ID: s.Review.ID, Verdict: "failed", ReasonCode: "reviewer_interactive"})
		b.effect(reject)
		return b.finish()
	}
	if s.ReadOnly || in.ReviewRunID != "" || in.RequestID != s.LastRequest || !s.Requests[s.LastRequest].open() || len(s.Questions) >= 16 {
		decision, err := b.late(s, in, "question")
		if err == nil {
			decision.Effects = append(decision.Effects, reject)
		}
		return decision, err
	}
	if s.Provider == ProviderCodex && (s.TurnID == "" || s.TurnID != in.TurnID) {
		decision, err := b.late(s, in, "question")
		if err == nil {
			decision.Effects = append(decision.Effects, reject)
		}
		return decision, err
	}
	b.add(Fact{Kind: FactQuestionOpened, SessionID: s.ID, RequestID: in.RequestID, ID: in.ID, Status: in.Status, Digest: in.Digest, ExpiresAt: in.ExpiresAt, TurnID: in.TurnID})
	decision, err := b.finish()
	if err != nil {
		// A question this session cannot hold is still owed an answer.
		return Decision{Effects: []Effect{reject}}, err
	}
	return decision, nil
}

func decideReviewOutcome(b *builder, s *Session, in In) (Decision, error) {
	// A verdict is bound to its run and its epoch. Pause, discard and restart all end
	// that authority, so a late verdict is evidence only.
	if s.Review == nil || s.Review.ID != in.ID || s.Review.Status != "running" || s.Review.ControlEpoch != s.ControlEpoch || s.ReadOnly {
		return b.late(s, in, "review")
	}
	if s.Task == nil || s.Review.Digest != in.Digest {
		return b.late(s, in, "review")
	}
	b.add(Fact{Kind: FactReviewOutcome, SessionID: s.ID, ID: in.ID, Verdict: in.Verdict})
	return b.finish()
}

// decideAuth crosses the boundary for every session on the profile. A discarded or
// read-only session has no authority left to revoke and is not touched.
func decideAuth(b *builder, in In) (Decision, error) {
	for _, id := range b.p.Order {
		s := b.p.Sessions[id]
		if s.Closed || s.ReadOnly || s.Provider != in.Provider || s.ProfileID != in.ProfileID {
			continue
		}
		b.add(Fact{Kind: FactAuthBoundaryCrossed, SessionID: s.ID, ReasonCode: "auth_changed"})
		for _, effect := range stopEffects(s, EffectInterrupt) {
			b.effect(effect)
		}
	}
	if len(b.facts) == 0 {
		return Decision{Idempotent: true}, nil
	}
	return b.finish()
}

// ReconcileEffects derives the local effects a restart owes. Provider effects are
// never derived here: they have no observed result, so they stay unknown.
func ReconcileEffects(p Projection) []Effect {
	effects := []Effect{}
	for _, id := range p.Order {
		s := p.Sessions[id]
		for _, input := range s.Inputs {
			if input.Status == InputCleanup {
				effects = append(effects, Effect{Kind: EffectCleanupPayload, Class: ClassLocal, SessionID: id, RequestID: input.RequestID})
			}
		}
	}
	return effects
}
