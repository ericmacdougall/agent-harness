package kernel

import (
	"errors"
	"fmt"
	"reflect"
)

type PrincipalClass string

const (
	PrincipalUser     PrincipalClass = "user"
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
	InCreate    InputKind = "create"
	InSend      InputKind = "send"
	InPause     InputKind = "pause"
	InStop      InputKind = "stop"
	InChangeCWD InputKind = "change-cwd"
	InClose     InputKind = "close"
	InAbandon   InputKind = "abandon"

	ObConversationBound InputKind = "conversation-bound"
	ObConnected         InputKind = "connected"
	ObDisconnected      InputKind = "disconnected"
	ObAccepted          InputKind = "accepted"
	ObRefused           InputKind = "refused"
	ObUnknown           InputKind = "write-unknown"
	ObTurnBound         InputKind = "turn-bound"
	ObCompleted         InputKind = "completed"
	ObControlOutcome    InputKind = "control-outcome"
	ObAuthBoundary      InputKind = "auth-boundary"
	ObQuarantine        InputKind = "quarantine"
	ObRestart           InputKind = "restart"
)

// allowedPrincipals is default-deny: a kind not listed here is refused for everyone.
var allowedPrincipals = map[InputKind][]PrincipalClass{
	InCreate: {PrincipalUser, PrincipalSystem}, InSend: {PrincipalUser}, InPause: {PrincipalUser}, InStop: {PrincipalUser},
	InChangeCWD: {PrincipalUser}, InClose: {PrincipalUser}, InAbandon: {PrincipalUser},
	ObConversationBound: {PrincipalProvider}, ObConnected: {PrincipalProvider}, ObDisconnected: {PrincipalProvider},
	ObAccepted: {PrincipalProvider}, ObRefused: {PrincipalProvider}, ObUnknown: {PrincipalProvider}, ObTurnBound: {PrincipalProvider},
	ObCompleted: {PrincipalProvider}, ObControlOutcome: {PrincipalProvider},
	ObAuthBoundary: {PrincipalSystem}, ObQuarantine: {PrincipalSystem}, ObRestart: {PrincipalSystem},
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
	Status          string
	Control         string
	Outcome         string
	Digest          string
	RuntimeIdentity string
}

type EffectKind string

const (
	EffectStartTurn EffectKind = "start-turn"
	EffectInterrupt EffectKind = "interrupt"
	EffectTerminate EffectKind = "terminate"
)

type EffectClass string

const (
	// ClassNewWork is fenced: its fact commits first, and the adapter rechecks Fence and
	// the log latch at the writer gate immediately before writing.
	ClassNewWork EffectClass = "new-work"
	// ClassStopWork does not depend on an append. The adapter fires it even when the
	// append fails or the log is latched, and never takes the write gate.
	ClassStopWork EffectClass = "stop-work"
)

// Effect is a descriptor. Replay never calls Decide, so it can never fire one. The
// adapter pairs it with its live process epoch, which is not authority.
type Effect struct {
	Kind      EffectKind
	Class     EffectClass
	SessionID string
	RequestID string
	TurnID    string
	Fence     uint64
}

// Decision is what to commit and what to do after.
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

var idempotent = Decision{Idempotent: true}

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

// finish runs each fact through the real codec and the reducer before anything is
// committed, so nothing Decide returns can be changed by encoding or refused by Reduce.
func (b *builder) finish() (Decision, error) {
	next := b.p
	for i, f := range b.facts {
		data, err := EncodeFact(f)
		if err != nil {
			return refuse("bad_value", "a value is outside what this field allows")
		}
		decoded, err := DecodeFact(data)
		if err != nil {
			return refuse("bad_value", "a value is outside what this field allows")
		}
		if !reflect.DeepEqual(decoded, f) {
			return refuse("bad_value", "a value does not survive encoding")
		}
		reduced, err := Reduce(next, decoded)
		if errors.Is(err, errBadValue) {
			return refuse("bad_value", "a value is outside what this field allows")
		}
		if err != nil {
			return Decision{}, fmt.Errorf("decide produced an illegal fact: %w", err)
		}
		next = reduced
		b.facts[i] = decoded
	}
	return Decision{Facts: b.facts, Effects: b.effects, Idempotent: len(b.facts) == 0}, nil
}

// authorize runs before anything else, including restart, and denies any kind or
// principal it does not name.
func authorize(in In) error {
	forbidden := &Refusal{Code: "forbidden", Message: "this principal cannot do that"}
	allowed := false
	for _, class := range allowedPrincipals[in.Kind] {
		allowed = allowed || class == in.Principal.Class
	}
	if !allowed {
		return forbidden
	}
	// A provider connection speaks for its own session only.
	if in.Principal.Class == PrincipalProvider && in.Principal.SessionID != in.SessionID {
		return forbidden
	}
	return nil
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
	switch in.Kind {
	case ObRestart:
		// A crash loop must not spend the reserve.
		if p.LastKind == FactProcessRestarted {
			return idempotent, nil
		}
		b.add(Fact{Kind: FactProcessRestarted})
		return b.finish()
	case InCreate:
		return decideCreate(b, in)
	case ObAuthBoundary:
		return decideAuth(b, in)
	}
	s := p.Sessions[in.SessionID]
	if s == nil || s.Closed {
		// A discarded tab may close before its start is answered. The reply still has
		// to interrupt that turn, with nothing left to record.
		if in.Kind == ObTurnBound && s != nil && s.PendingInterrupt && in.RequestID == s.LastRequest && identityPattern.MatchString(in.TurnID) {
			return Decision{Idempotent: true, Effects: []Effect{{Kind: EffectInterrupt, Class: ClassStopWork, SessionID: s.ID, RequestID: in.RequestID, TurnID: in.TurnID}}}, nil
		}
		return refuse("not_found", "session not found")
	}
	switch in.Kind {
	case InSend:
		return decideSend(b, s, in)
	case InPause, InStop:
		return decideControl(b, s, in)
	case InChangeCWD:
		return decideCWD(b, s, in)
	case InClose:
		return decideClose(b, s)
	case InAbandon:
		return decideAbandon(b, s, in)
	case ObConversationBound:
		return decideConversation(b, s, in)
	case ObConnected:
		if s.ReadOnly {
			return b.late(s, in, "connected")
		}
		if s.Connected {
			return idempotent, nil
		}
		b.add(Fact{Kind: FactProviderConnected, SessionID: s.ID})
		return b.finish()
	case ObDisconnected:
		if s.ReadOnly {
			return b.late(s, in, "disconnected")
		}
		b.add(Fact{Kind: FactProviderDisconnected, SessionID: s.ID})
		return b.finish()
	case ObAccepted, ObRefused, ObUnknown:
		return decideEffectResult(b, s, in)
	case ObTurnBound:
		return decideTurnBound(b, s, in)
	case ObCompleted:
		return decideCompleted(b, s, in)
	case ObControlOutcome:
		return decideControlOutcome(b, s, in)
	case ObQuarantine:
		if in.ReasonCode == "" {
			return refuse("bad_value", "a reason is required")
		}
		b.add(Fact{Kind: FactSessionQuarantined, SessionID: s.ID, ReasonCode: in.ReasonCode})
		b.effects = stopEffects(s)
		return b.finish()
	}
	return refuse("unknown_input", "unknown input")
}

func decideCreate(b *builder, in In) (Decision, error) {
	if in.SessionID == "" || b.p.Sessions[in.SessionID] != nil {
		return refuse("session_exists", "session identity is missing or already used")
	}
	if in.Provider != ProviderCodex && in.Provider != ProviderClaude {
		return refuse("bad_provider", "choose Codex or Claude")
	}
	if in.ProviderID != "" && in.RuntimeIdentity == "" {
		return refuse("no_owner", "an existing conversation needs its owner")
	}
	b.add(Fact{Kind: FactSessionCreated, SessionID: in.SessionID, Provider: in.Provider, ProviderID: in.ProviderID, ProfileID: in.ProfileID, CWD: in.CWD, RuntimeIdentity: in.RuntimeIdentity})
	return b.finish()
}

func decideSend(b *builder, s *Session, in In) (Decision, error) {
	if prior, exists := s.Requests[in.RequestID]; exists {
		// A lost response retries here: same outcome, no second write.
		if prior == ReceiptIntent || prior == ReceiptAccepted || prior == ReceiptFinal {
			return idempotent, nil
		}
		return refuse("not_replayed", "prior request outcome is not successful; it was not replayed")
	}
	switch {
	case in.RequestID == "":
		return refuse("bad_request", "a request identity is required")
	case s.ReadOnly:
		return refuse("read_only", "this tab is read-only; continue in a new session")
	case s.Requests[s.LastRequest].unresolved():
		return refuse("unresolved", "the last request has no final outcome; stop or discard it first")
	case s.Provider == ProviderCodex && !s.Connected:
		return refuse("disconnected", "provider connection is lost; continue in a new session")
	case in.RuntimeIdentity == "":
		return refuse("no_identity", "the runtime identity is unavailable; try again")
	case s.RuntimeIdentity != "" && in.RuntimeIdentity != s.RuntimeIdentity:
		return refuse("runtime_changed", "credentials or tools changed; start a new context session")
	case s.RuntimeIdentity == "" && s.ConversationStarted:
		return refuse("no_owner", "this conversation has no recorded owner; start a new context session")
	}
	if s.RuntimeIdentity == "" {
		b.add(Fact{Kind: FactRuntimeIdentityBound, SessionID: s.ID, RuntimeIdentity: in.RuntimeIdentity})
	}
	b.add(Fact{Kind: FactRequestIntended, SessionID: s.ID, RequestID: in.RequestID})
	b.effects = []Effect{{Kind: EffectStartTurn, Class: ClassNewWork, SessionID: s.ID, RequestID: in.RequestID, Fence: s.ControlEpoch}}
	return b.finish()
}

// stopEffects never depend on an append. The adapter no-ops if no writer remains.
func stopEffects(s *Session) []Effect {
	receipt := s.Requests[s.LastRequest]
	if !receipt.unresolved() && receipt != ReceiptAbandoned {
		return nil
	}
	switch {
	case s.Provider == ProviderClaude:
		return []Effect{{Kind: EffectTerminate, Class: ClassStopWork, SessionID: s.ID, RequestID: s.LastRequest}}
	case s.TurnID != "":
		return []Effect{{Kind: EffectInterrupt, Class: ClassStopWork, SessionID: s.ID, RequestID: s.LastRequest, TurnID: s.TurnID}}
	}
	return nil
}

func decideControl(b *builder, s *Session, in In) (Decision, error) {
	effects := stopEffects(s)
	if s.ReadOnly {
		if len(effects) == 0 {
			return refuse("read_only", "this tab is read-only; continue in a new session")
		}
		return Decision{Idempotent: true, Effects: effects}, nil
	}
	if s.Requests[s.LastRequest] == ReceiptUnknown {
		if interruptOwed(s) && !s.PendingInterrupt {
			b.add(Fact{Kind: FactControlRequested, SessionID: s.ID, Control: "stop"})
		}
		if len(b.facts) == 0 && len(effects) == 0 {
			return refuse("nothing_to_stop", "there is nothing running to stop")
		}
		b.effects = effects
		return b.finish()
	}
	control := "pause"
	if in.Kind == InStop {
		control = "stop"
	}
	b.add(Fact{Kind: FactControlRequested, SessionID: s.ID, Control: control})
	b.effects = effects
	return b.finish()
}

func decideCWD(b *builder, s *Session, in In) (Decision, error) {
	switch {
	case s.ReadOnly:
		return refuse("read_only", "this tab is read-only; continue in a new session")
	case s.Requests[s.LastRequest].unresolved():
		return refuse("unresolved", "the last request has no final outcome; stop or discard it first")
	case in.CWD == "":
		return refuse("bad_request", "a directory is required")
	}
	b.add(Fact{Kind: FactCwdChanged, SessionID: s.ID, CWD: in.CWD})
	return b.finish()
}

func decideClose(b *builder, s *Session) (Decision, error) {
	if s.Abandoned == nil && (s.Requests[s.LastRequest].unresolved() || s.Quarantine != "") {
		return refuse("unresolved", "the last request has no final outcome; stop or discard it before closing")
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
			return idempotent, nil
		}
		return refuse("discarded_other", "this tab was already discarded for a different turn")
	}
	if s.LastRequest != in.ExpectedRequest {
		return refuse("turn_changed", "the turn changed since this was confirmed; check it and try again")
	}
	status := Status(s)
	if !s.ReadOnly && status == "running" {
		return refuse("stop_first", "stop or pause this turn before discarding it")
	}
	if !s.Requests[s.LastRequest].unresolved() && status != "unknown" {
		return refuse("nothing_to_discard", "this turn has a final outcome; there is nothing to discard")
	}
	b.effects = stopEffects(s)
	b.add(Fact{Kind: FactAbandoned, SessionID: s.ID, RequestID: s.LastRequest, Reason: reason})
	return b.finish()
}

func decideConversation(b *builder, s *Session, in In) (Decision, error) {
	if s.ReadOnly || !identityPattern.MatchString(in.ProviderID) || in.RuntimeIdentity != "" && !digestPattern.MatchString(in.RuntimeIdentity) {
		return b.late(s, in, "conversation")
	}
	if s.RuntimeIdentity != "" && in.RuntimeIdentity != "" && s.RuntimeIdentity != in.RuntimeIdentity {
		return refuse("runtime_changed", "credentials or tools changed; start a new context session")
	}
	if s.RuntimeIdentity == "" && in.RuntimeIdentity == "" {
		return refuse("no_owner", "a conversation needs its owner")
	}
	if s.ConversationStarted {
		if s.ProviderID == in.ProviderID {
			return idempotent, nil
		}
		return b.late(s, in, "conversation")
	}
	if s.RuntimeIdentity == "" && in.RuntimeIdentity != "" {
		b.add(Fact{Kind: FactRuntimeIdentityBound, SessionID: s.ID, RuntimeIdentity: in.RuntimeIdentity})
	}
	b.add(Fact{Kind: FactConversationBound, SessionID: s.ID, ProviderID: in.ProviderID})
	return b.finish()
}

// late records evidence for a frame or effect result that cannot change anything. The
// first frame per key is sticky, and provider values are free text, so only safe
// shapes reach the log.
func (b *builder) late(s *Session, in In, kind string) (Decision, error) {
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
	if _, seen := s.Evidence[evidenceKey(request, kind)]; seen {
		return idempotent, nil
	}
	b.add(Fact{Kind: FactLateFrameObserved, SessionID: s.ID, RequestID: request, LateKind: kind, Status: status, Digest: digest})
	return b.finish()
}

func decideEffectResult(b *builder, s *Session, in In) (Decision, error) {
	kind := map[InputKind]string{ObAccepted: "accepted", ObRefused: "refused", ObUnknown: "write_unknown"}[in.Kind]
	receipt := s.Requests[in.RequestID]
	if in.RequestID != s.LastRequest || !receipt.open() || s.ReadOnly {
		return b.late(s, in, kind)
	}
	code := in.ReasonCode
	if !codePattern.MatchString(code) {
		code = ""
	}
	switch in.Kind {
	case ObAccepted:
		if receipt == ReceiptAccepted {
			return idempotent, nil
		}
		b.add(Fact{Kind: FactProviderAccepted, SessionID: s.ID, RequestID: in.RequestID})
	case ObRefused:
		b.add(Fact{Kind: FactProviderRefused, SessionID: s.ID, RequestID: in.RequestID, ReasonCode: code})
	case ObUnknown:
		b.add(Fact{Kind: FactOutcomeUnknown, SessionID: s.ID, RequestID: in.RequestID, ReasonCode: code})
	}
	return b.finish()
}

// decideTurnBound reaches here for every correlated reply, including on an abandoned
// request, so a pending interrupt cannot be lost and replay can never fire it.
func decideTurnBound(b *builder, s *Session, in In) (Decision, error) {
	if s.Provider != ProviderCodex || in.RequestID != s.LastRequest || !identityPattern.MatchString(in.TurnID) {
		return b.late(s, in, "turn_bound")
	}
	if s.TurnID == in.TurnID {
		return idempotent, nil
	}
	if s.TurnID != "" {
		return b.late(s, in, "turn_bound")
	}
	if s.PendingInterrupt {
		b.add(Fact{Kind: FactTurnBound, SessionID: s.ID, RequestID: in.RequestID, TurnID: in.TurnID})
		b.effects = []Effect{{Kind: EffectInterrupt, Class: ClassStopWork, SessionID: s.ID, RequestID: in.RequestID, TurnID: in.TurnID}}
		return b.finish()
	}
	if s.Requests[in.RequestID].unresolved() {
		b.add(Fact{Kind: FactTurnBound, SessionID: s.ID, RequestID: in.RequestID, TurnID: in.TurnID})
		return b.finish()
	}
	return b.late(s, in, "turn_bound")
}

func decideCompleted(b *builder, s *Session, in In) (Decision, error) {
	active := s.Requests[s.LastRequest]
	// No exact request binding: the only safe reading is that the active turn's outcome
	// is now unknown.
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

func decideControlOutcome(b *builder, s *Session, in In) (Decision, error) {
	if !oneOfValues(in.Control, "pause", "stop") || !oneOfValues(in.Outcome, "confirmed", "rejected", "unconfirmed") {
		return b.late(s, in, "control_outcome")
	}
	next := in.Outcome != "confirmed" && s.Requests[s.LastRequest].unresolved() && s.Abandoned == nil
	if next == s.PauseUnconfirmed {
		return idempotent, nil
	}
	b.add(Fact{Kind: FactControlOutcome, SessionID: s.ID, Control: in.Control, Outcome: in.Outcome})
	return b.finish()
}

// decideAuth crosses the boundary for every session on the profile. A read-only session
// has no authority left to revoke and is not touched.
func decideAuth(b *builder, in In) (Decision, error) {
	if in.Provider != ProviderCodex && in.Provider != ProviderClaude {
		return refuse("bad_provider", "choose Codex or Claude")
	}
	for _, id := range b.p.Order {
		s := b.p.Sessions[id]
		if s.Closed || s.ReadOnly || s.Provider != in.Provider || s.ProfileID != in.ProfileID {
			continue
		}
		b.add(Fact{Kind: FactAuthBoundaryCrossed, SessionID: s.ID})
		b.effects = append(b.effects, stopEffects(s)...)
	}
	if len(b.facts) == 0 {
		return idempotent, nil
	}
	return b.finish()
}
