package kernel

import (
	"errors"
	"fmt"
)

// Receipt is a request's position in the one transition table.
type Receipt string

const (
	ReceiptNone      Receipt = ""
	ReceiptIntent    Receipt = "intent"
	ReceiptAccepted  Receipt = "accepted"
	ReceiptFinal     Receipt = "final"
	ReceiptUnknown   Receipt = "unknown"
	ReceiptRejected  Receipt = "rejected"
	ReceiptAbandoned Receipt = "abandoned"
)

var receiptTransitions = map[Receipt][]Receipt{
	ReceiptNone:     {ReceiptIntent},
	ReceiptIntent:   {ReceiptAccepted, ReceiptFinal, ReceiptUnknown, ReceiptRejected, ReceiptAbandoned},
	ReceiptAccepted: {ReceiptFinal, ReceiptUnknown, ReceiptRejected, ReceiptAbandoned},
	ReceiptUnknown:  {ReceiptAbandoned},
}

func (r Receipt) open() bool       { return r == ReceiptIntent || r == ReceiptAccepted }
func (r Receipt) unresolved() bool { return r.open() || r == ReceiptUnknown }

// Input and task states are closed strings shared with the view.
const (
	InputQueued      = "queued"
	InputHeld        = "held"
	InputDispatching = "dispatching"
	InputRetained    = "retained"
	InputUnknown     = "unknown"
	InputCleanup     = "cleanup_pending"
	InputDiscarded   = "discarded"

	TaskIdle        = "idle"
	TaskActive      = "active"
	TaskBlocked     = "blocked"
	TaskHandoff     = "handoff"
	TaskNeedsReview = "needs_review"
	TaskComplete    = "complete"

	SupervisionActive  = "active"
	SupervisionWaiting = "waiting"
	SupervisionPaused  = "paused"
	SupervisionBlocked = "blocked"

	ReviewInvalidated = "invalidated"
	ReviewUnknown     = "unknown"
	ReviewPaused      = "paused"

	ChildRunning = "running"
	ChildUnknown = "unknown"

	maxReceiptsKept = 256
	// MaxVisibleSessions bounds resolved history shown after a restart.
	MaxVisibleSessions = 24
)

type Task struct {
	ID            string
	Generation    uint64
	State         string
	Stage         string
	InputRevision uint64
	ObjectiveHash string
	ReviewStatus  string
	Passes        map[string]string
}

type Input struct {
	RequestID      string
	Status         string
	PayloadHash    string
	Attachments    []string
	DeliveredInRev uint64
	Legacy         bool
}

type Question struct {
	ID, Kind, RequestID, Digest, ExpiresAt string
	ControlEpoch                           uint64
	TurnID                                 string
}

type Child struct {
	ID, Role, TurnID, Status, ReasonCode string
}

type ReviewRun struct {
	ID, Stage, Digest, Status string
	ControlEpoch              uint64
}

type Abandonment struct {
	RequestID, Reason, At string
}

type Supervision struct {
	State, ReasonCode string
	RemainingBursts   int64
	Progress          int64
	LastProgress      int64
}

// Session is authority only. Presentation fields and process-local handles live
// outside the kernel; Status is derived by Status, never assigned.
type Session struct {
	ID, Provider, ProviderID, ProfileID, CWD string
	ConversationStarted                      bool
	Revision                                 uint64
	LastRequest                              string
	Requests                                 map[string]Receipt
	RequestOrder                             []string
	FinalStatus                              string
	TurnID                                   string
	PendingInterrupt                         bool
	PauseUnconfirmed                         bool
	ControlEpoch                             uint64
	ProviderFinal                            bool
	ReadOnly, Closed, Hidden, Connected      bool
	Quarantine                               string
	RuntimeIdentity, PolicyRevision, Cascade string
	Task                                     *Task
	Inputs                                   []Input
	Questions                                []Question
	Children                                 []Child
	Review                                   *ReviewRun
	ReviewResultPending                      bool
	Abandoned                                *Abandonment
	Supervision                              Supervision
	LastRefusal                              string
	Evidence                                 map[string]string
}

// Projection is immutable once published: Reduce copies what it changes, so a
// reader never needs a lock and a stalled append never blocks a read.
type Projection struct {
	Sessions       map[string]*Session
	Order          []string
	LastSeq        uint64
	LastKind       FactKind
	LegacyImported string
}

func NewProjection() Projection { return Projection{Sessions: map[string]*Session{}} }

func (s *Session) clone() *Session {
	next := *s
	next.Requests = make(map[string]Receipt, len(s.Requests))
	for key, value := range s.Requests {
		next.Requests[key] = value
	}
	next.RequestOrder = append([]string(nil), s.RequestOrder...)
	if s.Task != nil {
		task := *s.Task
		task.Passes = cloneStrings(s.Task.Passes)
		next.Task = &task
	}
	next.Inputs = append([]Input(nil), s.Inputs...)
	next.Questions = append([]Question(nil), s.Questions...)
	next.Children = append([]Child(nil), s.Children...)
	if s.Review != nil {
		review := *s.Review
		next.Review = &review
	}
	if s.Abandoned != nil {
		abandoned := *s.Abandoned
		next.Abandoned = &abandoned
	}
	next.Evidence = cloneStrings(s.Evidence)
	return &next
}

func cloneStrings(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func (p Projection) copyShell() Projection {
	next := p
	next.Sessions = make(map[string]*Session, len(p.Sessions))
	for key, value := range p.Sessions {
		next.Sessions[key] = value
	}
	next.Order = append([]string(nil), p.Order...)
	return next
}

// Facts a read-only session may still receive. Everything else is illegal, which
// is what stops a returning Pause, a queue failure or an auth boundary from
// changing a discarded or restored tab, whichever path it came from.
var readOnlyFacts = map[FactKind]bool{
	FactLateFrameObserved: true, FactControlOutcome: true, FactChildControlOutcome: true, FactChildQuarantined: true,
	FactSessionClosed: true, FactAbandoned: true, FactSessionQuarantined: true, FactInputOutcome: true, FactInputDiscarded: true,
	FactPayloadReleased: true, FactReviewOutcome: true, FactReviewCancelled: true, FactTurnBound: true, FactQuestionRevoked: true,
	FactLegacyInputHeld: true,
}

func illegal(f Fact, why string) error {
	return fmt.Errorf("%w: %s on %s: %s", ErrIllegalFact, f.Kind, f.SessionID, why)
}

// Reduce is pure and the sole writer of authority. Live state and replay both call
// it, with no other path to the projection.
func Reduce(p Projection, f Fact) (Projection, error) {
	if f.SchemaVersion != SchemaVersion {
		return p, fmt.Errorf("%w: schema version %d", ErrUnreadableLog, f.SchemaVersion)
	}
	if !knownFacts[f.Kind] {
		return p, fmt.Errorf("%w: unknown fact kind %q", ErrUnreadableLog, f.Kind)
	}
	if f.Seq <= p.LastSeq {
		return p, fmt.Errorf("%w: sequence %d after %d", ErrUnreadableLog, f.Seq, p.LastSeq)
	}
	if err := validateFact(f); err != nil {
		return p, fmt.Errorf("%w: %v", ErrIllegalFact, err)
	}
	next := p.copyShell()
	next.LastSeq, next.LastKind = f.Seq, f.Kind
	switch f.Kind {
	case FactProcessRestarted:
		reduceRestart(&next)
		return next, nil
	case FactLegacyImportCompleted:
		if p.LegacyImported != "" || f.Digest == "" {
			return p, illegal(f, "import already completed or has no digest")
		}
		next.LegacyImported = f.Digest
		return next, nil
	}
	if f.SessionID == "" {
		return p, illegal(f, "no session")
	}
	current := p.Sessions[f.SessionID]
	if f.Kind == FactSessionCreated || f.Kind == FactLegacyImported {
		if current != nil || f.SessionRevision != 1 {
			return p, illegal(f, "session exists or bad revision")
		}
		created := &Session{ID: f.SessionID, Provider: f.Provider, ProviderID: f.ProviderID, ProfileID: f.ProfileID, CWD: f.CWD, Revision: 1, Requests: map[string]Receipt{}, Connected: f.Kind == FactSessionCreated && f.Status == "connected"}
		if f.Kind == FactLegacyImported {
			if err := reduceLegacy(created, f); err != nil {
				return p, err
			}
		}
		next.Sessions[f.SessionID] = created
		next.Order = append(next.Order, f.SessionID)
		return next, nil
	}
	if current == nil || current.Closed {
		return p, illegal(f, "session missing or closed")
	}
	if f.SessionRevision != current.Revision+1 {
		return p, illegal(f, fmt.Sprintf("revision %d after %d", f.SessionRevision, current.Revision))
	}
	if current.ReadOnly && !readOnlyFacts[f.Kind] {
		return p, illegal(f, "session is read-only")
	}
	s := current.clone()
	s.Revision = f.SessionRevision
	if err := reduceSession(s, f); err != nil {
		return p, err
	}
	next.Sessions[f.SessionID] = s
	return next, nil
}

func advance(s *Session, f Fact, request string, to Receipt) error {
	// A repeat is refused, not ignored: a second final could otherwise change the
	// recorded status of a turn that already finished.
	from := s.Requests[request]
	for _, allowed := range receiptTransitions[from] {
		if allowed == to {
			s.Requests[request] = to
			return nil
		}
	}
	return illegal(f, fmt.Sprintf("receipt %q to %q", from, to))
}

func revokeQuestions(s *Session) { s.Questions = nil }

func quarantineChildren(s *Session, reason string) {
	for i := range s.Children {
		if s.Children[i].Status == ChildRunning {
			s.Children[i].Status = ChildUnknown
			s.Children[i].ReasonCode = reason
			s.Children[i].TurnID = ""
		}
	}
}

func holdInputs(s *Session) {
	for i := range s.Inputs {
		if s.Inputs[i].Status == InputQueued {
			s.Inputs[i].Status = InputHeld
		}
	}
}

func dispatchingToUnknown(s *Session, request string) {
	for i := range s.Inputs {
		if s.Inputs[i].Status == InputDispatching && (request == "" || s.Inputs[i].RequestID == request) {
			s.Inputs[i].Status = InputUnknown
		}
	}
}

func findInput(s *Session, request string) *Input {
	for i := range s.Inputs {
		if s.Inputs[i].RequestID == request {
			return &s.Inputs[i]
		}
	}
	return nil
}

func requireRequest(s *Session, f Fact) error {
	if f.RequestID == "" || f.RequestID != s.LastRequest {
		return illegal(f, "not the active request")
	}
	return nil
}

func reduceSession(s *Session, f Fact) error {
	switch f.Kind {
	case FactConversationBound:
		s.ProviderID = f.ProviderID
		s.ConversationStarted = true
	case FactProviderConnected:
		s.Connected = true
	case FactProviderDisconnected:
		s.Connected = false
		if s.Requests[s.LastRequest].open() {
			if err := advance(s, f, s.LastRequest, ReceiptUnknown); err != nil {
				return err
			}
			dispatchingToUnknown(s, s.LastRequest)
			s.ProviderFinal = false
		}
		revokeQuestions(s)
		quarantineChildren(s, "disconnected")
		s.TurnID = ""
	case FactRuntimeIdentityBound:
		if s.RuntimeIdentity != "" && s.RuntimeIdentity != f.RuntimeIdentity {
			return illegal(f, "conversation already owned by another runtime")
		}
		s.RuntimeIdentity = f.RuntimeIdentity
	case FactAuthBoundaryCrossed:
		// Only an unfinished request becomes unknown. An idle session has nothing to
		// reconcile, so it becomes read-only and stays closable.
		if s.Requests[s.LastRequest].open() {
			if err := advance(s, f, s.LastRequest, ReceiptUnknown); err != nil {
				return err
			}
			dispatchingToUnknown(s, s.LastRequest)
			s.ProviderFinal = false
		}
		// A start still unanswered would otherwise run on under revoked credentials.
		s.PendingInterrupt = s.Requests[s.LastRequest].unresolved() && s.TurnID == "" && s.Provider == ProviderCodex
		s.ReadOnly, s.Connected = true, false
		s.ControlEpoch++
		revokeQuestions(s)
		holdInputs(s)
		quarantineChildren(s, "auth_changed")
		s.TurnID = ""
		s.Supervision.State, s.Supervision.ReasonCode = SupervisionPaused, "auth_changed"
		endRunningReview(s)
	case FactCwdChanged:
		if s.Requests[s.LastRequest].unresolved() {
			return illegal(f, "last request is unresolved")
		}
		s.CWD = f.CWD
		s.ControlEpoch++
	case FactSessionClosed:
		if s.Abandoned == nil && s.Requests[s.LastRequest].unresolved() {
			return illegal(f, "unresolved request without discard")
		}
		for _, input := range s.Inputs {
			if input.Status != InputDiscarded {
				return illegal(f, "retained payload")
			}
		}
		s.Closed = true
	case FactAbandoned:
		return reduceAbandoned(s, f)
	case FactSessionQuarantined:
		quarantineSession(s, f.ReasonCode)
	case FactSupervisionChanged:
		s.Supervision.State, s.Supervision.ReasonCode = f.State, f.ReasonCode
	case FactCascadeSelected:
		s.Cascade = f.Cascade
	case FactPolicyBound:
		s.PolicyRevision = f.PolicyRevision
	case FactContinuationBudgetChanged:
		s.Supervision.RemainingBursts = f.RemainingBursts
		s.Supervision.LastProgress = s.Supervision.Progress
		s.Supervision.Progress = f.Progress
	case FactRequestIntended:
		return reduceIntended(s, f)
	case FactProviderAccepted:
		if err := requireRequest(s, f); err != nil {
			return err
		}
		return advance(s, f, f.RequestID, ReceiptAccepted)
	case FactProviderRefused:
		if err := requireRequest(s, f); err != nil {
			return err
		}
		if err := advance(s, f, f.RequestID, ReceiptRejected); err != nil {
			return err
		}
		if entry := findInput(s, f.RequestID); entry != nil && entry.Status == InputDispatching {
			entry.Status = InputHeld
			// The objective already advanced for this input, so the task cannot simply
			// continue. Blocked lets a new objective start once the payload is resolved.
			if s.Task != nil {
				s.Task.State = TaskBlocked
			}
		}
		revokeQuestions(s)
		s.TurnID, s.PendingInterrupt = "", false
		s.LastRefusal = f.ReasonCode
		if s.LastRefusal == "" {
			s.LastRefusal = "provider_refused"
		}
		if s.Supervision.State != SupervisionPaused {
			s.Supervision.State, s.Supervision.ReasonCode = SupervisionBlocked, s.LastRefusal
		}
	case FactProviderCompleted:
		if err := requireRequest(s, f); err != nil {
			return err
		}
		if err := advance(s, f, f.RequestID, ReceiptFinal); err != nil {
			return err
		}
		s.ProviderFinal = true
		s.FinalStatus = f.Status
		s.PauseUnconfirmed, s.PendingInterrupt = false, false
		s.TurnID = ""
		revokeQuestions(s)
		if entry := findInput(s, f.RequestID); entry != nil && entry.Status == InputDispatching {
			entry.Status = InputRetained
		}
	case FactOutcomeUnknown:
		if err := requireRequest(s, f); err != nil {
			return err
		}
		if err := advance(s, f, f.RequestID, ReceiptUnknown); err != nil {
			return err
		}
		s.ProviderFinal = false
		revokeQuestions(s)
		dispatchingToUnknown(s, f.RequestID)
		s.Supervision.State, s.Supervision.ReasonCode = SupervisionPaused, f.ReasonCode
	case FactTurnBound:
		if err := requireRequest(s, f); err != nil {
			return err
		}
		s.TurnID = f.TurnID
		s.PendingInterrupt = false
	case FactLateFrameObserved:
		if s.Evidence == nil {
			s.Evidence = map[string]string{}
		}
		s.Evidence[evidenceKey(f.RequestID, f.LateKind)] = f.Status + "|" + f.Digest
	case FactAdmissionRefused:
		s.LastRefusal = f.ReasonCode
	case FactControlRequested:
		return reduceControl(s, f)
	case FactControlOutcome:
		s.PauseUnconfirmed = f.Outcome != "confirmed" && s.Requests[s.LastRequest].unresolved() && s.Abandoned == nil
	case FactQuestionOpened:
		if err := requireRequest(s, f); err != nil {
			return err
		}
		if !s.Requests[f.RequestID].open() {
			return illegal(f, "request is not active")
		}
		s.Questions = append(s.Questions, Question{ID: f.ID, Kind: f.Status, RequestID: f.RequestID, Digest: f.Digest, ExpiresAt: f.ExpiresAt, ControlEpoch: s.ControlEpoch, TurnID: f.TurnID})
	case FactQuestionAnswered, FactQuestionRevoked:
		var kept []Question
		found := false
		for _, q := range s.Questions {
			if q.ID == f.ID {
				found = true
				continue
			}
			kept = append(kept, q)
		}
		if !found {
			return illegal(f, "no such question")
		}
		s.Questions = kept
	case FactChildObserved:
		for i := range s.Children {
			if s.Children[i].ID == f.ID {
				s.Children[i].TurnID, s.Children[i].Status = f.TurnID, f.Status
				return nil
			}
		}
		s.Children = append(s.Children, Child{ID: f.ID, Role: f.Role, TurnID: f.TurnID, Status: f.Status})
	case FactChildControlOutcome:
		for i := range s.Children {
			if s.Children[i].ID == f.ID {
				s.Children[i].Status, s.Children[i].ReasonCode = f.Status, f.ReasonCode
				return nil
			}
		}
		return illegal(f, "no such child")
	case FactChildQuarantined:
		for i := range s.Children {
			if s.Children[i].ID == f.ID {
				s.Children[i].Status, s.Children[i].ReasonCode, s.Children[i].TurnID = ChildUnknown, f.ReasonCode, ""
				return nil
			}
		}
		return illegal(f, "no such child")
	case FactInputQueued:
		if findInput(s, f.RequestID) != nil {
			return illegal(f, "input exists")
		}
		s.Inputs = append(s.Inputs, Input{RequestID: f.RequestID, Status: InputQueued, PayloadHash: f.PayloadHash, Attachments: append([]string(nil), f.Attachments...)})
	case FactInputDispatchPrepared:
		entry := findInput(s, f.RequestID)
		if entry == nil || entry.Status != InputQueued || s.Task == nil || s.Task.ID != f.TaskID || s.Task.State == TaskComplete {
			return illegal(f, "input not dispatchable")
		}
		// A follow-up changes the objective, so every pass for the older input ends.
		s.Task.InputRevision = f.InputRevision
		s.Task.ObjectiveHash = f.ObjectiveHash
		s.Task.Passes = map[string]string{}
		s.Task.Stage, s.Task.ReviewStatus = "", ""
		s.Task.State = TaskActive
		entry.Status, entry.DeliveredInRev = InputDispatching, f.InputRevision
	case FactInputOutcome:
		entry := findInput(s, f.RequestID)
		if entry == nil || entry.Status != InputDispatching {
			return illegal(f, "input has no open dispatch")
		}
		entry.Status = f.Status
	case FactInputDiscarded:
		entry := findInput(s, f.RequestID)
		if entry == nil || entry.Status == InputDispatching || entry.Status == InputCleanup || entry.Status == InputDiscarded {
			return illegal(f, "input not discardable")
		}
		entry.Status = InputCleanup
	case FactPayloadReleased:
		entry := findInput(s, f.RequestID)
		if entry == nil || entry.Status != InputCleanup {
			return illegal(f, "payload not pending release")
		}
		entry.Status = InputDiscarded
	case FactReviewStarted:
		if s.Task == nil {
			return illegal(f, "no task")
		}
		s.Review = &ReviewRun{ID: f.ID, Stage: f.Stage, Digest: f.Digest, Status: "running", ControlEpoch: s.ControlEpoch}
		s.Task.ReviewStatus = "running"
	case FactReviewCancelled:
		if s.Review == nil || s.Review.ID != f.ID || s.Review.Status != "running" {
			return illegal(f, "no running review")
		}
		s.ReviewResultPending = false
		endRunningReview(s)
	case FactReviewOutcome:
		return reduceReviewOutcome(s, f)
	case FactReviewResultPending:
		s.ReviewResultPending = f.Status == "pending"
	case FactCheckpointRecorded:
		if s.Task == nil || s.Task.ID != f.TaskID || s.Task.State == TaskComplete {
			return illegal(f, "checkpoint on a completed or foreign task")
		}
		// An agent reports progress. It never writes a review status of its own: the
		// one thing it can ask for is a review, and only the review writes the result.
		s.Task.State, s.Task.Stage = f.State, f.Stage
		if f.State == TaskNeedsReview {
			s.Task.ReviewStatus = "queued"
		}
	case FactLegacyInputHeld:
		if findInput(s, f.RequestID) != nil {
			return illegal(f, "input exists")
		}
		s.Inputs = append(s.Inputs, Input{RequestID: f.RequestID, Status: f.Status, PayloadHash: f.PayloadHash, Attachments: append([]string(nil), f.Attachments...), Legacy: true})
	default:
		return illegal(f, "not a session fact")
	}
	return nil
}

func reduceIntended(s *Session, f Fact) error {
	if s.Requests[s.LastRequest].unresolved() {
		return illegal(f, "last request is unresolved")
	}
	if _, exists := s.Requests[f.RequestID]; exists || f.RequestID == "" {
		return illegal(f, "request identity reused")
	}
	if err := advance(s, f, f.RequestID, ReceiptIntent); err != nil {
		return err
	}
	s.LastRequest = f.RequestID
	s.RequestOrder = append(s.RequestOrder, f.RequestID)
	// Only resolved history is trimmed; the active request is always the newest.
	if len(s.RequestOrder) > maxReceiptsKept {
		delete(s.Requests, s.RequestOrder[0])
		s.RequestOrder = s.RequestOrder[1:]
	}
	s.TurnID, s.FinalStatus = "", ""
	s.ProviderFinal, s.PendingInterrupt, s.PauseUnconfirmed = false, false, false
	s.LastRefusal = ""
	revokeQuestions(s)
	if f.Status == "new_objective" && f.TaskID != "" && (s.Task == nil || s.Task.ID != f.TaskID) {
		s.Task = &Task{ID: f.TaskID, Generation: f.Generation, State: TaskIdle, ObjectiveHash: f.ObjectiveHash, InputRevision: f.InputRevision, Passes: map[string]string{}}
	}
	if f.Status == "new_objective" {
		s.Supervision = Supervision{State: SupervisionActive, RemainingBursts: f.RemainingBursts}
	}
	return nil
}

func reduceControl(s *Session, f Fact) error {
	if f.Control == "resume" {
		s.Supervision.State, s.Supervision.ReasonCode = SupervisionActive, ""
		for i := range s.Inputs {
			if s.Inputs[i].Status == InputHeld {
				s.Inputs[i].Status = InputQueued
			}
		}
		return nil
	}
	// An unknown turn was already paused when it became unknown. A stop here only
	// asks for the interrupt once the turn is named; no admission authority moves.
	if s.Requests[s.LastRequest] == ReceiptUnknown {
		s.PendingInterrupt = s.TurnID == "" && s.Provider == ProviderCodex
		return nil
	}
	s.ControlEpoch++
	holdInputs(s)
	revokeQuestions(s)
	if s.Task != nil && (s.Task.ReviewStatus == "running" || s.Task.ReviewStatus == "queued") {
		s.Task.ReviewStatus, s.Task.State = ReviewPaused, TaskBlocked
	}
	s.Supervision.State, s.Supervision.ReasonCode = SupervisionPaused, "user_"+f.Control
	s.PendingInterrupt = s.Requests[s.LastRequest].unresolved() && s.TurnID == "" && s.Provider == ProviderCodex
	return nil
}

func reduceAbandoned(s *Session, f Fact) error {
	if s.Abandoned != nil {
		return illegal(f, "already discarded")
	}
	if f.RequestID != s.LastRequest {
		return illegal(f, "not the last request")
	}
	receipt := s.Requests[f.RequestID]
	if receipt.unresolved() {
		if err := advance(s, f, f.RequestID, ReceiptAbandoned); err != nil {
			return err
		}
		s.ProviderFinal = false
	}
	if s.Task != nil && s.Task.State != TaskComplete {
		s.Task.State, s.Task.ReviewStatus = TaskBlocked, ReviewInvalidated
	}
	s.Abandoned = &Abandonment{RequestID: f.RequestID, Reason: f.Reason, At: f.At}
	// With the start unanswered, the interrupt waits for the turn to be named. The
	// flag stays set across read-only so TurnBound can still fire it.
	s.PendingInterrupt = receipt.unresolved() && s.TurnID == "" && s.Provider == ProviderCodex
	s.ReadOnly, s.Connected = true, false
	s.ControlEpoch++
	revokeQuestions(s)
	quarantineChildren(s, "parent_discarded")
	dispatchingToUnknown(s, f.RequestID)
	holdInputs(s)
	s.Supervision.State, s.Supervision.ReasonCode = SupervisionPaused, "discarded"
	endRunningReview(s)
	s.ReviewResultPending = false
	return nil
}

// endRunningReview makes a run that lost its authority terminal, so no verdict can
// still land on it.
func endRunningReview(s *Session) {
	if s.Review != nil && s.Review.Status == "running" {
		s.Review.Status = "unknown"
		if s.Task != nil {
			s.Task.ReviewStatus = ReviewUnknown
		}
	}
}

func quarantineSession(s *Session, reason string) {
	s.Quarantine, s.ReadOnly, s.Connected = reason, true, false
	endRunningReview(s)
}

func reduceReviewOutcome(s *Session, f Fact) error {
	if s.Review == nil || s.Review.ID != f.ID || s.Review.Status != "running" {
		return illegal(f, "no running review")
	}
	if s.ReadOnly && f.Verdict != "unknown" {
		return illegal(f, "a read-only session cannot record a verdict")
	}
	s.Review.Status = f.Verdict
	if s.Task == nil {
		return nil
	}
	switch f.Verdict {
	case "pass":
		if s.Task.Passes == nil {
			s.Task.Passes = map[string]string{}
		}
		s.Task.Passes[s.Review.Stage] = s.Review.Digest
		s.Task.ReviewStatus = "pass"
	case "block":
		s.Task.ReviewStatus = "block"
	default:
		s.Task.ReviewStatus = ReviewUnknown
		s.Task.State = TaskBlocked
	}
	return nil
}

func reduceLegacy(s *Session, f Fact) error {
	s.ReadOnly = true
	s.Supervision.State = SupervisionPaused
	s.ConversationStarted = f.ProviderID != ""
	switch f.Receipt {
	case ReceiptNone:
		if f.RequestID != "" {
			return illegal(f, "request with no receipt")
		}
	case ReceiptFinal, ReceiptRejected, ReceiptUnknown, ReceiptAbandoned:
		if f.RequestID == "" {
			return illegal(f, "receipt with no request")
		}
		s.Requests[f.RequestID] = f.Receipt
		s.LastRequest = f.RequestID
		s.RequestOrder = []string{f.RequestID}
		s.ProviderFinal = f.Receipt == ReceiptFinal
		if f.Receipt == ReceiptAbandoned {
			s.Abandoned = &Abandonment{RequestID: f.RequestID, Reason: f.Reason, At: f.At}
		}
	default:
		return illegal(f, "legacy receipt must already be resolved or unknown")
	}
	if f.TaskID != "" {
		passes := cloneStrings(f.Passes)
		if passes == nil {
			passes = map[string]string{}
		}
		s.Task = &Task{ID: f.TaskID, Generation: f.Generation, InputRevision: f.InputRevision, ObjectiveHash: f.ObjectiveHash, State: f.State, Passes: passes, ReviewStatus: ReviewUnknown}
	}
	return nil
}

// reduceRestart is the enumerated restart rule, identical live and on replay.
func reduceRestart(p *Projection) {
	for _, id := range p.Order {
		current := p.Sessions[id]
		if current.Closed {
			continue
		}
		s := current.clone()
		if s.Requests[s.LastRequest].open() {
			s.Requests[s.LastRequest] = ReceiptUnknown
			s.ProviderFinal = false
		}
		s.ReadOnly, s.Connected = true, false
		s.TurnID, s.PendingInterrupt, s.PauseUnconfirmed = "", false, false
		revokeQuestions(s)
		dispatchingToUnknown(s, "")
		holdInputs(s)
		endRunningReview(s)
		s.ReviewResultPending = false
		quarantineChildren(s, "restarted")
		s.Supervision.State = SupervisionPaused
		if s.Abandoned == nil {
			s.Supervision.ReasonCode = "restarted"
		}
		p.Sessions[id] = s
	}
	trimResolved(p)
}

func protectedFromTrim(s *Session) bool {
	if s.Abandoned == nil && (s.Requests[s.LastRequest].unresolved() || s.Quarantine != "") {
		return true
	}
	for _, input := range s.Inputs {
		if input.Status != InputDiscarded {
			return true
		}
	}
	return false
}

// trimResolved marks the oldest resolved history hidden. The mark is sticky, so a
// trimmed tab cannot reappear when other tabs later close.
func trimResolved(p *Projection) {
	budget := MaxVisibleSessions
	for _, id := range p.Order {
		s := p.Sessions[id]
		if !s.Closed && !s.Hidden && protectedFromTrim(s) {
			budget--
		}
	}
	for i := len(p.Order) - 1; i >= 0; i-- {
		s := p.Sessions[p.Order[i]]
		if s.Closed || s.Hidden || protectedFromTrim(s) {
			continue
		}
		if budget > 0 {
			budget--
			continue
		}
		s.Hidden = true
	}
}

// Quarantined names a session a replay could not apply a fact to.
type Quarantined struct {
	SessionID string
	Err       error
}

// Replay folds a decoded log. An unreadable log refuses. An illegal fact quarantines
// only its session, so one bad record cannot stop the whole console from starting.
func Replay(facts []Fact) (Projection, []Quarantined, error) {
	p := NewProjection()
	var quarantined []Quarantined
	bad := map[string]bool{}
	for _, f := range facts {
		next, err := Reduce(p, f)
		if err == nil {
			p = next
			continue
		}
		if !errors.Is(err, ErrIllegalFact) || f.SessionID == "" {
			return NewProjection(), nil, err
		}
		// Later legal facts still apply, so a discard and close on a quarantined
		// session survive the next restart. Only the illegal fact itself is skipped.
		if !bad[f.SessionID] {
			quarantined = append(quarantined, Quarantined{SessionID: f.SessionID, Err: err})
		}
		bad[f.SessionID] = true
		p = p.copyShell()
		p.LastSeq, p.LastKind = f.Seq, f.Kind
		if current := p.Sessions[f.SessionID]; current != nil && current.Quarantine == "" {
			s := current.clone()
			quarantineSession(s, "illegal_fact")
			p.Sessions[f.SessionID] = s
		}
	}
	return p, quarantined, nil
}

func evidenceKey(request, kind string) string { return request + "\x00" + kind }

// VisibleSessions is the one view rule for which tabs exist.
func VisibleSessions(p Projection) []*Session {
	visible := []*Session{}
	for _, id := range p.Order {
		if s := p.Sessions[id]; !s.Closed && !s.Hidden {
			visible = append(visible, s)
		}
	}
	return visible
}

// Status is derived, never assigned, so no path can leave it disagreeing with the
// receipt it describes.
func Status(s *Session) string {
	receipt := s.Requests[s.LastRequest]
	switch {
	case s.Closed:
		return "closed"
	case s.Abandoned != nil:
		return "abandoned"
	case s.Quarantine != "", receipt == ReceiptUnknown, hasInputStatus(s, InputUnknown):
		return "unknown"
	case s.ReadOnly:
		return "disconnected"
	case receipt.open() && len(s.Questions) > 0:
		return "waiting"
	case receipt.open() && s.Supervision.State == SupervisionPaused:
		return "paused"
	case receipt.open():
		return "running"
	case s.FinalStatus == "failed", receipt == ReceiptRejected && s.Supervision.State == SupervisionBlocked:
		return "error"
	case s.Supervision.State == SupervisionPaused, s.FinalStatus == "interrupted":
		return "paused"
	case s.Provider == ProviderCodex && !s.Connected:
		return "disconnected"
	}
	return "idle"
}

func hasInputStatus(s *Session, status string) bool {
	for _, input := range s.Inputs {
		if input.Status == status {
			return true
		}
	}
	return false
}
