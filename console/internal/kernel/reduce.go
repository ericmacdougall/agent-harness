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

const (
	ProviderCodex  = "codex"
	ProviderClaude = "claude"

	maxReceiptsKept = 256
	// MaxVisibleSessions bounds resolved history shown after a restart.
	MaxVisibleSessions = 24
)

type Abandonment struct {
	RequestID, Reason, At string
}

// Session is authority only, and each field belongs to one table in
// plans/CONSOLE-KERNEL-K1A.md. Status is derived by Status, never assigned.
type Session struct {
	ID, Provider, ProviderID, ProfileID, CWD string
	ConversationStarted                      bool
	RuntimeIdentity                          string
	Connected, ReadOnly, Closed, Hidden      bool
	Quarantine                               string
	Abandoned                                *Abandonment
	Revision                                 uint64

	LastRequest   string
	Requests      map[string]Receipt
	RequestOrder  []string
	ProviderFinal bool
	FinalStatus   string
	LastRefusal   string

	TurnID           string
	PendingInterrupt bool
	Paused           bool
	PauseUnconfirmed bool
	ControlEpoch     uint64

	Evidence map[string]string
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
	if s.Abandoned != nil {
		abandoned := *s.Abandoned
		next.Abandoned = &abandoned
	}
	if s.Evidence != nil {
		next.Evidence = make(map[string]string, len(s.Evidence))
		for key, value := range s.Evidence {
			next.Evidence[key] = value
		}
	}
	return &next
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

// Facts a read-only session may still receive. Everything else is illegal, whichever
// path produced it, which is what keeps a discarded or restored tab unchanged.
var readOnlyFacts = map[FactKind]bool{
	FactLateFrameObserved: true, FactControlOutcome: true, FactSessionClosed: true,
	FactAbandoned: true, FactSessionQuarantined: true, FactTurnBound: true,
}

func illegal(f Fact, why string) error {
	return fmt.Errorf("%w: %s on %s: %s", ErrIllegalFact, f.Kind, f.SessionID, why)
}

// Reduce is pure and the sole writer of authority. Live state and replay both call
// it, with no other path to the projection.
func Reduce(p Projection, f Fact) (Projection, error) {
	return reduce(p, f, true)
}

// reduce is Reduce. With owned true the caller owns p's maps outright, as Replay does,
// so the shell is reused instead of copied for every fact. Copying it per fact made
// opening a log grow with facts times sessions.
func reduce(p Projection, f Fact, copyShell bool) (Projection, error) {
	if f.SchemaVersion != SchemaVersion {
		return p, fmt.Errorf("%w: schema version %d", ErrUnreadableLog, f.SchemaVersion)
	}
	if !knownFacts[f.Kind] {
		return p, fmt.Errorf("%w: unknown fact kind %q", ErrUnreadableLog, f.Kind)
	}
	if f.Seq <= p.LastSeq {
		return p, fmt.Errorf("%w: sequence %d after %d", ErrUnreadableLog, f.Seq, p.LastSeq)
	}
	if !coreFacts[f.Kind] {
		return p, illegal(f, "kind belongs to a later slice")
	}
	if err := validateFact(f); err != nil {
		return p, fmt.Errorf("%w: %w", ErrIllegalFact, err)
	}
	next := p
	if copyShell {
		next = p.copyShell()
	}
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
		created := &Session{ID: f.SessionID, Provider: f.Provider, ProviderID: f.ProviderID, ProfileID: f.ProfileID, CWD: f.CWD, RuntimeIdentity: f.RuntimeIdentity, Revision: 1, Requests: map[string]Receipt{}, ConversationStarted: f.ProviderID != ""}
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

// advance refuses a repeat as well as a move out of a terminal state: a second final
// could otherwise change the recorded status of a turn that already finished.
func advance(s *Session, f Fact, request string, to Receipt) error {
	from := s.Requests[request]
	for _, allowed := range receiptTransitions[from] {
		if allowed == to {
			s.Requests[request] = to
			return nil
		}
	}
	return illegal(f, fmt.Sprintf("receipt %q to %q", from, to))
}

func requireRequest(s *Session, f Fact) error {
	if f.RequestID == "" || f.RequestID != s.LastRequest {
		return illegal(f, "not the active request")
	}
	return nil
}

// interruptOwed is a start still unanswered: only the correlated reply can name the
// turn, so the interrupt waits for it.
func interruptOwed(s *Session) bool {
	return s.Requests[s.LastRequest].unresolved() && s.TurnID == "" && s.Provider == ProviderCodex
}

// stickyOwed keeps an interrupt already due, so a later fact can never clear it.
func stickyOwed(s *Session) bool { return s.PendingInterrupt || interruptOwed(s) }

func quarantine(s *Session, reason string) {
	s.Quarantine = reason
	s.PendingInterrupt = stickyOwed(s)
	s.ReadOnly, s.Connected, s.Hidden = true, false, false
	s.ControlEpoch++
}

func openToUnknown(s *Session, f Fact) error {
	if !s.Requests[s.LastRequest].open() {
		return nil
	}
	s.ProviderFinal = false
	return advance(s, f, s.LastRequest, ReceiptUnknown)
}

func reduceSession(s *Session, f Fact) error {
	switch f.Kind {
	case FactConversationBound:
		if f.ProviderID == "" || s.ConversationStarted && f.ProviderID != s.ProviderID {
			return illegal(f, "a conversation is never replaced")
		}
		s.ProviderID, s.ConversationStarted = f.ProviderID, true
	case FactRuntimeIdentityBound:
		if s.RuntimeIdentity != "" && s.RuntimeIdentity != f.RuntimeIdentity {
			return illegal(f, "conversation already owned by another runtime")
		}
		s.RuntimeIdentity = f.RuntimeIdentity
	case FactProviderConnected:
		s.Connected = true
	case FactProviderDisconnected:
		if err := openToUnknown(s, f); err != nil {
			return err
		}
		s.Connected, s.TurnID = false, ""
		s.ControlEpoch++
	case FactAuthBoundaryCrossed:
		s.PendingInterrupt = stickyOwed(s)
		if err := openToUnknown(s, f); err != nil {
			return err
		}
		s.ReadOnly, s.Connected = true, false
		s.ControlEpoch++
	case FactSessionQuarantined:
		quarantine(s, f.ReasonCode)
	case FactCwdChanged:
		if s.Requests[s.LastRequest].unresolved() {
			return illegal(f, "last request is unresolved")
		}
		s.CWD = f.CWD
		s.ControlEpoch++
	case FactSessionClosed:
		if s.Abandoned == nil && (s.Requests[s.LastRequest].unresolved() || s.Quarantine != "") {
			return illegal(f, "unresolved without discard")
		}
		s.Closed = true
	case FactAbandoned:
		return reduceAbandoned(s, f)
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
		s.LastRefusal = f.ReasonCode
		if s.LastRefusal == "" {
			s.LastRefusal = "provider_refused"
		}
		s.TurnID, s.PendingInterrupt = "", false
	case FactProviderCompleted:
		if err := requireRequest(s, f); err != nil {
			return err
		}
		if err := advance(s, f, f.RequestID, ReceiptFinal); err != nil {
			return err
		}
		s.ProviderFinal, s.FinalStatus = true, f.Status
		s.TurnID, s.PendingInterrupt, s.PauseUnconfirmed = "", false, false
	case FactOutcomeUnknown:
		if err := requireRequest(s, f); err != nil {
			return err
		}
		if err := advance(s, f, f.RequestID, ReceiptUnknown); err != nil {
			return err
		}
		s.ProviderFinal = false
		s.ControlEpoch++
	case FactTurnBound:
		if err := requireRequest(s, f); err != nil {
			return err
		}
		if s.Provider != ProviderCodex {
			return illegal(f, "only Codex binds a turn")
		}
		s.TurnID, s.PendingInterrupt = f.TurnID, false
	case FactLateFrameObserved:
		if s.Evidence == nil {
			s.Evidence = map[string]string{}
		}
		key := evidenceKey(f.RequestID, f.LateKind)
		if _, seen := s.Evidence[key]; seen {
			return illegal(f, "evidence for this key is sticky")
		}
		s.Evidence[key] = f.Status + "|" + f.Digest
	case FactControlRequested:
		owed := stickyOwed(s)
		if s.Requests[s.LastRequest] == ReceiptUnknown {
			s.PendingInterrupt = owed
			return nil
		}
		s.PendingInterrupt, s.Paused = owed, true
		s.ControlEpoch++
	case FactControlOutcome:
		s.PauseUnconfirmed = f.Outcome != "confirmed" && s.Requests[s.LastRequest].unresolved() && s.Abandoned == nil
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
	// Only resolved history is trimmed: the active request is always the newest.
	if len(s.RequestOrder) > maxReceiptsKept {
		delete(s.Requests, s.RequestOrder[0])
		s.RequestOrder = s.RequestOrder[1:]
	}
	s.ProviderFinal, s.FinalStatus, s.LastRefusal = false, "", ""
	s.TurnID, s.PendingInterrupt, s.Paused, s.PauseUnconfirmed = "", false, false, false
	return nil
}

func reduceAbandoned(s *Session, f Fact) error {
	if s.Abandoned != nil {
		return illegal(f, "already discarded")
	}
	if f.RequestID != s.LastRequest {
		return illegal(f, "not the last request")
	}
	s.PendingInterrupt = stickyOwed(s)
	if s.Requests[f.RequestID].unresolved() {
		if err := advance(s, f, f.RequestID, ReceiptAbandoned); err != nil {
			return err
		}
		s.ProviderFinal = false
	}
	s.Abandoned = &Abandonment{RequestID: f.RequestID, Reason: f.Reason, At: f.At}
	s.ReadOnly, s.Connected = true, false
	s.ControlEpoch++
	return nil
}

func reduceLegacy(s *Session, f Fact) error {
	s.ReadOnly = true
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
		s.TurnID, s.PendingInterrupt, s.Paused, s.PauseUnconfirmed = "", false, false, false
		p.Sessions[id] = s
	}
	trimResolved(p)
}

func protectedFromTrim(s *Session) bool {
	return s.Abandoned == nil && (s.Requests[s.LastRequest].unresolved() || s.Quarantine != "")
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
// only its session and is skipped, while later legal facts still apply, so a discard
// and close on a quarantined session survive the next restart.
func Replay(facts []Fact) (Projection, []Quarantined, error) {
	p := NewProjection()
	var quarantined []Quarantined
	reported, applied := map[string]bool{}, map[string]bool{}
	// Replay owns this projection until it returns, so it reduces in place.
	for _, f := range facts {
		next, err := reduce(p, f, false)
		if err == nil {
			p = next
			continue
		}
		if !errors.Is(err, ErrIllegalFact) {
			return NewProjection(), nil, err
		}
		if f.SessionID == "" || globalFact(f.Kind) {
			return NewProjection(), nil, fmt.Errorf("%w: %v", ErrUnreadableLog, err)
		}
		if !reported[f.SessionID] {
			quarantined = append(quarantined, Quarantined{SessionID: f.SessionID, Err: err})
		}
		reported[f.SessionID] = true
		p = p.copyShell()
		p.LastSeq, p.LastKind = f.Seq, f.Kind
		if current := p.Sessions[f.SessionID]; current != nil && !applied[f.SessionID] {
			s := current.clone()
			code := "illegal_fact"
			if s.Quarantine != "" {
				code = s.Quarantine
			}
			quarantine(s, code)
			p.Sessions[f.SessionID] = s
			applied[f.SessionID] = true
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
	case s.Quarantine != "", receipt == ReceiptUnknown:
		return "unknown"
	case s.ReadOnly:
		return "disconnected"
	case receipt.open() && s.Paused:
		return "paused"
	case receipt.open():
		return "running"
	case receipt == ReceiptRejected && !s.Paused, s.FinalStatus == "failed":
		return "error"
	case s.Paused, s.FinalStatus == "interrupted":
		return "paused"
	case s.Provider == ProviderCodex && !s.Connected:
		return "disconnected"
	}
	return "idle"
}
