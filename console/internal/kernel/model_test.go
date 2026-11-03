package kernel

// Independent model of SPEC.md, written from the tables alone. It is the check on
// someone else's reducer, so it shares no code with it: a plain per-session struct,
// predict() for inputs, verdict() and apply() for facts.
//
// A comment `SPEC-AMBIGUOUS: n` marks a place the tables left open. Every failure message
// carries the numbers touched in that step, so a disagreement caused by a reading can be
// told apart from a defect. Numbers 1 to 36 are settled by SPEC.md section 10; 1 to 34 use
// its numbers, and 35 and 36 were closed by its items 30 and 31. Still open:
// section 10 names no error for Quarantined.Err, so it is only required to be non-nil; and
// 37. Item 39 says repeated control-outcome frames append facts, but table 7 makes a frame that
// would not change PauseUnconfirmed idempotent. Table 7 is coded, so an exact repeat is idempotent.
// 38. Item 40 narrows the stored late digest, but section 7's fact digest shape is unchanged, so
// whether Reduce refuses a raw LateFrameObserved with a non-hex in-shape Digest is open. Raw late
// facts are generated only with a 64-hex or empty Digest.

import (
	"errors"
	"fmt"
	"math/rand"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"
)

var (
	mdlIdentityShape = regexp.MustCompile(`^[A-Za-z0-9._:/@+=-]{1,128}$`)
	mdlDigestShape   = regexp.MustCompile(`^[A-Za-z0-9:_-]{1,128}$`)
	mdlLateDigest    = regexp.MustCompile(`^[0-9a-f]{64}$`) // Table 5 and section 10 item 40.
	mdlCodeShape     = regexp.MustCompile(`^[a-z0-9_]{1,40}$`)
	mdlTimeShape     = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{9}Z$`)
)

func mdlGoodTime(s string) bool {
	if !mdlTimeShape.MatchString(s) {
		return false
	}
	// SPEC-AMBIGUOUS: 1
	_, err := time.Parse("2006-01-02T15:04:05.000000000Z", s)
	return err == nil
}

func mdlGoodCWD(c string) bool {
	if len(c) > 4096 || !utf8.ValidString(c) {
		return false
	}
	for _, r := range c {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func mdlKnownProvider(p string) bool { return p == ProviderCodex || p == ProviderClaude }

var mdlCoreKinds = []FactKind{
	FactProcessRestarted, FactLegacyImportCompleted, FactSessionCreated, FactConversationBound,
	FactProviderConnected, FactProviderDisconnected, FactRuntimeIdentityBound, FactAuthBoundaryCrossed,
	FactCwdChanged, FactSessionClosed, FactAbandoned, FactSessionQuarantined,
	FactRequestIntended, FactProviderAccepted, FactProviderRefused, FactProviderCompleted,
	FactOutcomeUnknown, FactTurnBound, FactLateFrameObserved, FactControlRequested,
	FactControlOutcome, FactLegacyImported,
}

var mdlLateKinds = []string{"accepted", "refused", "write_unknown", "turn_bound", "final", "conversation", "connected", "disconnected", "control_outcome"}

func mdlContains[T comparable](list []T, v T) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// mSession is the model's own record of one session.
type mdlMSession struct {
	id, provider, conversation, profile, mdlCwd, mdlIdentity string
	quarantine, lastReq, finalStatus, lastRefusal, mdlTurn   string

	started, connected, readOnly, closed, hidden bool
	providerFinal, pending, paused, unconfirmed  bool

	abandoned       *Abandonment
	controlFacts    int // Decided ControlRequested facts since the last RequestIntended.
	revision, epoch uint64
	receipts        map[string]Receipt
	order           []string
	evidence        map[string]string
}

func (s *mdlMSession) last() Receipt { return s.receipts[s.lastReq] }
func (s *mdlMSession) open() bool    { return s.last() == ReceiptIntent || s.last() == ReceiptAccepted }
func (s *mdlMSession) unresolved() bool {
	return s.open() || s.last() == ReceiptUnknown
}
func (s *mdlMSession) owed() bool {
	return s.unresolved() && s.mdlTurn == "" && s.provider == ProviderCodex
}

// status follows table 6, returning the row name as well for the coverage counters.
func (s *mdlMSession) mdlStatus() (string, string) {
	switch {
	case s.closed:
		return "closed", "closed"
	case s.abandoned != nil:
		return "abandoned", "abandoned"
	case s.quarantine != "":
		return "unknown", "unknown_quarantine"
	case s.last() == ReceiptUnknown:
		return "unknown", "unknown_receipt"
	case s.readOnly:
		return "disconnected", "read_only"
	case s.open() && s.paused:
		return "paused", "open_paused"
	case s.open():
		return "running", "running"
	case s.last() == ReceiptRejected && !s.paused:
		return "error", "rejected"
	case s.finalStatus == "failed":
		return "error", "failed"
	case s.paused:
		return "paused", "paused"
	case s.finalStatus == "interrupted":
		return "paused", "interrupted"
	case s.provider == ProviderCodex && !s.connected:
		return "disconnected", "codex_offline"
	}
	return "idle", "idle"
}

func (s *mdlMSession) stopEffects() []Effect {
	if !s.unresolved() && s.last() != ReceiptAbandoned {
		return nil
	}
	if s.provider == ProviderClaude {
		return []Effect{{Kind: EffectTerminate, Class: ClassStopWork, SessionID: s.id, RequestID: s.lastReq}}
	}
	if s.mdlTurn != "" {
		return []Effect{{Kind: EffectInterrupt, Class: ClassStopWork, SessionID: s.id, RequestID: s.lastReq, TurnID: s.mdlTurn}}
	}
	return nil
}

// model is the whole predicted state. Coverage goes to cov, shared across seeds.
type mdlModel struct {
	sessions map[string]*mdlMSession
	order    []string
	lastSeq  uint64
	lastKind FactKind
	legacy   string
	cov      map[string]int
	notes    map[int]bool
}

func mdlNewModel(cov map[string]int) *mdlModel {
	if cov == nil {
		cov = map[string]int{}
	}
	return &mdlModel{sessions: map[string]*mdlMSession{}, cov: cov, notes: map[int]bool{}}
}

func (m *mdlModel) hit(row string) { m.cov[row]++ }
func (m *mdlModel) note(n int)     { m.notes[n] = true }

func (m *mdlModel) addSession(f Fact) *mdlMSession {
	s := &mdlMSession{
		id: f.SessionID, provider: f.Provider, conversation: f.ProviderID, profile: f.ProfileID,
		mdlCwd: f.CWD, mdlIdentity: f.RuntimeIdentity, started: f.ProviderID != "", revision: 1,
		receipts: map[string]Receipt{}, evidence: map[string]string{},
	}
	m.sessions[s.id] = s
	m.order = append(m.order, s.id)
	return s
}

func (m *mdlModel) restart() {
	for _, id := range m.order {
		s := m.sessions[id]
		if s.closed {
			continue
		}
		s.readOnly, s.connected = true, false
		if s.open() {
			s.receipts[s.lastReq] = ReceiptUnknown
			s.providerFinal = false
			m.hit("t3.restart.open_to_unknown")
		}
		s.mdlTurn, s.pending, s.paused, s.unconfirmed = "", false, false, false
	}
	protected := map[string]bool{}
	for _, id := range m.order {
		s := m.sessions[id]
		if !s.closed && !s.hidden && s.abandoned == nil && (s.unresolved() || s.quarantine != "") {
			protected[id] = true
		}
	}
	budget := MaxVisibleSessions - len(protected)
	if budget < 0 {
		budget = 0
	}
	if budget == 0 && len(protected) > 0 {
		m.hit("t2.trim.budget_exhausted")
	}
	if len(protected) > 0 {
		m.hit("t2.trim.protected")
	}
	for i := len(m.order) - 1; i >= 0; i-- {
		s := m.sessions[m.order[i]]
		if s.closed || s.hidden || protected[s.id] {
			continue
		}
		if budget > 0 {
			budget--
			continue
		}
		s.hidden = true
		m.hit("t2.trim.hidden")
	}
}

// apply folds one fact the model already knows to be legal.
func (m *mdlModel) applyDecided(f Fact) {
	// Section 7: Decide never returns a fact Reduce would refuse. A hit here is a model bug,
	// and fails the row check because this counter is not declared.
	if m.mdlVerdict(f) != mdlVLegal {
		m.hit("model.predicted_illegal." + string(f.Kind))
	}
	m.apply(f)
	// Section 10 item 41: at most two per request, one that pauses and one that newly owes.
	if s := m.sessions[f.SessionID]; s != nil && f.Kind == FactControlRequested {
		s.controlFacts++
		if s.controlFacts == 2 {
			m.hit("t7.control.second_fact")
		}
		if s.controlFacts > 2 {
			m.hit("model.control_requested_over_two")
		}
	}
}

func (m *mdlModel) apply(f Fact) {
	m.lastSeq, m.lastKind = f.Seq, f.Kind
	m.hit("fact." + string(f.Kind))
	switch f.Kind {
	case FactProcessRestarted:
		m.restart()
		return
	case FactLegacyImportCompleted:
		m.legacy = f.Digest
		return
	case FactSessionCreated:
		m.addSession(f)
		return
	case FactLegacyImported:
		// SPEC-AMBIGUOUS: 15
		m.note(15)
		s := m.addSession(f)
		s.readOnly = true
		if f.Receipt != ReceiptNone {
			s.lastReq = f.RequestID
			s.receipts[f.RequestID] = f.Receipt
			s.order = []string{f.RequestID}
			s.providerFinal = f.Receipt == ReceiptFinal
			if f.Receipt == ReceiptAbandoned {
				s.abandoned = &Abandonment{RequestID: f.RequestID, Reason: f.Reason, At: f.At}
			}
		}
		m.hit("t2.legacy." + string(f.Receipt))
		return
	}

	s := m.sessions[f.SessionID]
	sticky := s.pending || s.owed() // Always measured before the fact.
	s.revision++
	settle := func() {
		if s.open() {
			s.receipts[s.lastReq] = ReceiptUnknown
			s.providerFinal = false
		}
	}
	switch f.Kind {
	case FactConversationBound:
		s.conversation, s.started = f.ProviderID, true
	case FactRuntimeIdentityBound:
		s.mdlIdentity = f.RuntimeIdentity
	case FactProviderConnected:
		s.connected = true
	case FactProviderDisconnected:
		s.connected = false
		settle()
		s.mdlTurn = ""
		s.epoch++
	case FactAuthBoundaryCrossed:
		s.readOnly, s.connected = true, false
		settle()
		s.pending = sticky
		s.epoch++
	case FactSessionQuarantined:
		// SPEC-AMBIGUOUS: 13
		m.note(13)
		if s.quarantine != "" && f.ReasonCode == "illegal_fact" {
			m.hit("t2.quarantine.overwrite_with_illegal_fact")
		}
		s.quarantine = f.ReasonCode
		s.readOnly, s.connected, s.hidden = true, false, false
		s.pending = sticky
		s.epoch++
	case FactAbandoned:
		if s.unresolved() {
			s.receipts[s.lastReq] = ReceiptAbandoned
			s.providerFinal = false
			m.hit("t3.abandoned.overwrites")
		} else {
			m.hit("t3.abandoned.keeps")
		}
		s.abandoned = &Abandonment{RequestID: f.RequestID, Reason: f.Reason, At: f.At}
		s.readOnly, s.connected = true, false
		s.pending = sticky
		s.epoch++
	case FactCwdChanged:
		s.mdlCwd = f.CWD
		s.epoch++
	case FactSessionClosed:
		s.closed = true
	case FactRequestIntended:
		s.controlFacts = 0
		if s.mdlTurn != "" {
			m.hit("t4.intended.clears_bound_turn")
		}
		s.receipts[f.RequestID] = ReceiptIntent
		s.lastReq = f.RequestID
		s.order = append(s.order, f.RequestID)
		if len(s.order) > 256 {
			delete(s.receipts, s.order[0])
			s.order = append([]string(nil), s.order[1:]...)
			m.hit("t3.trim256")
		}
		s.finalStatus, s.lastRefusal, s.providerFinal = "", "", false
		s.mdlTurn, s.pending, s.paused, s.unconfirmed = "", false, false, false
	case FactProviderAccepted:
		s.receipts[s.lastReq] = ReceiptAccepted
	case FactProviderRefused:
		s.receipts[s.lastReq] = ReceiptRejected
		s.lastRefusal = f.ReasonCode
		if s.lastRefusal == "" {
			s.lastRefusal = "provider_refused"
			m.hit("t3.refused.default_code")
		}
		s.mdlTurn, s.pending = "", false
	case FactProviderCompleted:
		s.receipts[s.lastReq] = ReceiptFinal
		s.providerFinal, s.finalStatus = true, f.Status
		s.mdlTurn, s.pending, s.unconfirmed = "", false, false
	case FactOutcomeUnknown:
		if s.pending {
			m.hit("t4.unknown.pending_survives")
		}
		s.receipts[s.lastReq] = ReceiptUnknown
		s.providerFinal = false
		s.epoch++
	case FactTurnBound:
		s.mdlTurn, s.pending = f.TurnID, false
	case FactLateFrameObserved:
		s.evidence[f.RequestID+"\x00"+f.LateKind] = f.Status + "|" + f.Digest
	case FactControlRequested:
		s.pending = sticky
		if s.last() == ReceiptUnknown {
			m.hit("t4.control_requested.unknown")
		} else {
			m.hit("t4.control_requested.other")
			s.paused = true
			s.epoch++
		}
	case FactControlOutcome:
		if f.Outcome != "confirmed" {
			switch {
			case s.unresolved():
				m.hit("t4.control_outcome.unresolved_not_confirmed")
			case s.abandoned != nil && s.unconfirmed:
				m.hit("t4.control_outcome.abandoned_clears")
			case s.abandoned != nil:
				m.hit("t4.control_outcome.abandoned_not_confirmed")
			default:
				m.hit("t4.control_outcome.resolved_not_confirmed")
			}
		}
		s.unconfirmed = s.wouldBeUnconfirmed(f.Outcome)
	}
}

func (s *mdlMSession) wouldBeUnconfirmed(mdlOutcome string) bool {
	return mdlOutcome != "confirmed" && s.unresolved()
}

// mdlFactInShape applies section 7's shapes to a raw fact (section 10 item 9).
func mdlFactInShape(f Fact) bool {
	// SPEC-AMBIGUOUS: 33
	if !mdlGoodTime(f.At) || !mdlGoodCWD(f.CWD) {
		return false
	}
	shaped := func(re *regexp.Regexp, values ...string) bool {
		for _, v := range values {
			if v != "" && !re.MatchString(v) {
				return false
			}
		}
		return true
	}
	// SPEC-AMBIGUOUS: 30
	if !shaped(mdlIdentityShape, f.SessionID, f.RequestID, f.TurnID, f.ProviderID, f.ProfileID, f.TaskID) ||
		!shaped(mdlDigestShape, f.Digest, f.RuntimeIdentity, f.ObjectiveHash) || !shaped(mdlCodeShape, f.ReasonCode, f.Status, f.State) {
		return false
	}
	// SPEC-AMBIGUOUS: 27
	named := func(value string, kinds ...FactKind) bool { return value == "" || mdlContains(kinds, f.Kind) }
	if !named(f.Status, FactProviderCompleted, FactLateFrameObserved) ||
		!named(f.Control, FactControlRequested, FactControlOutcome) ||
		!named(f.Outcome, FactControlOutcome) ||
		!named(f.LateKind, FactLateFrameObserved) ||
		!named(f.State, FactLegacyImported) {
		return false
	}
	// SPEC-AMBIGUOUS: 28
	if f.Provider != "" && !mdlKnownProvider(f.Provider) {
		return false
	}
	if !mdlContains([]string{"", "pause", "stop"}, f.Control) || !mdlContains([]string{"", "confirmed", "rejected", "unconfirmed"}, f.Outcome) {
		return false
	}
	if f.LateKind != "" && !mdlContains(mdlLateKinds, f.LateKind) {
		return false
	}
	if f.Reason != "" && f.Kind != FactAbandoned && f.Kind != FactLegacyImported {
		return false
	}
	// SPEC-AMBIGUOUS: 31
	if len(f.Reason) > 500 || !utf8.ValidString(f.Reason) {
		return false
	}
	return mdlContains([]Receipt{ReceiptNone, ReceiptIntent, ReceiptAccepted, ReceiptFinal, ReceiptUnknown, ReceiptRejected, ReceiptAbandoned}, f.Receipt)
}

type mdlVerdict int

const (
	mdlVLegal mdlVerdict = iota
	mdlVIllegal
	mdlVUnreadable // Schema, unknown kind, or sequence: section 8 row 1.
)

// verdict decides a fact against the Reduce preconditions in tables 2 to 4 and section 7.
func (m *mdlModel) mdlVerdict(f Fact) mdlVerdict {
	if f.SchemaVersion != SchemaVersion || f.Seq <= m.lastSeq {
		return mdlVUnreadable
	}
	if mdlContains(ReservedFactKinds, f.Kind) {
		return mdlVIllegal
	}
	if !mdlContains(mdlCoreKinds, f.Kind) {
		return mdlVUnreadable
	}
	if !mdlFactInShape(f) {
		return mdlVIllegal
	}
	ok := false
	s := m.sessions[f.SessionID]
	switch f.Kind {
	case FactProcessRestarted:
		ok = true
	case FactLegacyImportCompleted:
		ok = f.Digest != "" && m.legacy == ""
	case FactSessionCreated:
		ok = s == nil && f.SessionID != "" && f.SessionRevision == 1 && mdlKnownProvider(f.Provider)
	case FactLegacyImported:
		okReceipt := mdlContains([]Receipt{ReceiptNone, ReceiptFinal, ReceiptRejected, ReceiptUnknown, ReceiptAbandoned}, f.Receipt)
		ok = s == nil && f.SessionID != "" && f.SessionRevision == 1 && okReceipt && (f.RequestID != "") == (f.Receipt != ReceiptNone)
	default:
		// Section 10 item 10: the compare-and-swap on the session revision.
		ok = s != nil && !s.closed && f.SessionRevision == s.revision+1 && m.sessionFactOK(s, f)
	}
	if ok {
		return mdlVLegal
	}
	return mdlVIllegal
}

func (m *mdlModel) sessionFactOK(s *mdlMSession, f Fact) bool {
	readOnlyAllowed := mdlContains([]FactKind{FactLateFrameObserved, FactControlOutcome, FactSessionClosed, FactAbandoned, FactSessionQuarantined, FactTurnBound}, f.Kind)
	if s.readOnly && !readOnlyAllowed {
		return false
	}
	isLast := f.RequestID == s.lastReq
	switch f.Kind {
	case FactConversationBound:
		// Section 10 item 12: a started conversation cannot take a different ID.
		return f.ProviderID != "" && (!s.started || s.conversation == f.ProviderID)
	case FactRuntimeIdentityBound:
		// SPEC-AMBIGUOUS: 33
		return f.RuntimeIdentity != "" && (s.mdlIdentity == "" || s.mdlIdentity == f.RuntimeIdentity)
	case FactProviderConnected, FactProviderDisconnected, FactAuthBoundaryCrossed:
		return true
	case FactSessionQuarantined:
		return f.ReasonCode != ""
	case FactAbandoned:
		// SPEC-AMBIGUOUS: 31
		return f.Reason != "" && s.abandoned == nil && isLast
	case FactCwdChanged:
		// SPEC-AMBIGUOUS: 33
		return f.CWD != "" && !s.unresolved()
	case FactSessionClosed:
		return s.abandoned != nil || (!s.unresolved() && s.quarantine == "")
	case FactRequestIntended:
		_, used := s.receipts[f.RequestID]
		return !s.unresolved() && f.RequestID != "" && !used
	case FactProviderAccepted:
		return isLast && s.last() == ReceiptIntent
	case FactProviderRefused, FactOutcomeUnknown:
		return isLast && s.open()
	case FactProviderCompleted:
		return isLast && s.open() && mdlContains([]string{"completed", "failed", "interrupted"}, f.Status)
	case FactTurnBound:
		// SPEC-AMBIGUOUS: 34
		return s.provider == ProviderCodex && isLast && f.RequestID != "" && f.TurnID != ""
	case FactLateFrameObserved:
		// Section 10 item 8: a repeated key is illegal, and the request is stored as given.
		_, seen := s.evidence[f.RequestID+"\x00"+f.LateKind]
		return mdlContains(mdlLateKinds, f.LateKind) && !seen
	case FactControlRequested:
		// SPEC-AMBIGUOUS: 20
		m.note(20)
		return f.Control == "pause" || f.Control == "stop"
	case FactControlOutcome:
		// SPEC-AMBIGUOUS: 20
		m.note(20)
		return (f.Control == "pause" || f.Control == "stop") && mdlContains([]string{"confirmed", "rejected", "unconfirmed"}, f.Outcome)
	}
	return false
}

// wantFact is a predicted fact. must names the fields a table determines; other fields
// are only shape-checked.
type mdlWantFact struct {
	Fact
	must []string
}

// outcome is the predicted result of one input.
type mdlOutcome struct {
	refusal string
	facts   []mdlWantFact
	effects []Effect
}

func (o mdlOutcome) idempotent() bool { return o.refusal == "" && len(o.facts) == 0 }

func (m *mdlModel) refuse(row, mdlCode string) mdlOutcome {
	m.hit("t7." + row + "." + mdlCode)
	return mdlOutcome{refusal: mdlCode}
}

// draft stamps facts for one decision.
type mdlDraft struct {
	m     *mdlModel
	at    string
	out   mdlOutcome
	bumps map[string]uint64
}

func (m *mdlModel) newDraft(at string) *mdlDraft {
	return &mdlDraft{m: m, at: at, bumps: map[string]uint64{}}
}

func (d *mdlDraft) add(sid string, f Fact, must ...string) {
	// SPEC-AMBIGUOUS: 5
	d.m.note(5)
	f.Seq = d.m.lastSeq + uint64(len(d.out.facts)) + 1
	f.SchemaVersion = SchemaVersion
	f.At = d.at
	f.SessionID = sid
	if sid != "" {
		d.bumps[sid]++
		if s := d.m.sessions[sid]; s != nil {
			f.SessionRevision = s.revision + d.bumps[sid]
		} else {
			f.SessionRevision = d.bumps[sid]
		}
	}
	d.out.facts = append(d.out.facts, mdlWantFact{Fact: f, must: must})
}

func (m *mdlModel) late(s *mdlMSession, in In, kind string) mdlOutcome {
	m.hit("t5.kind." + kind)
	mdlReq := ""
	// SPEC-AMBIGUOUS: 21
	m.note(21)
	if _, known := s.receipts[in.RequestID]; known {
		mdlReq = in.RequestID
		m.hit("t5.request.known")
	} else {
		m.hit("t5.request.unknown")
	}
	if _, seen := s.evidence[mdlReq+"\x00"+kind]; seen {
		m.hit("t5.sticky")
		return mdlOutcome{}
	}
	mdlStatus := in.Status
	switch {
	case mdlStatus == "":
		m.hit("t5.status.empty")
	case mdlCodeShape.MatchString(mdlStatus):
		m.hit("t5.status.valid")
	default:
		mdlStatus = "invalid"
		m.hit("t5.status.invalid")
	}
	mdlDigest := in.Digest
	if mdlLateDigest.MatchString(mdlDigest) {
		m.hit("t5.digest.valid")
	} else {
		mdlDigest = ""
		m.hit("t5.digest.empty")
	}
	d := m.newDraft(in.At)
	// SPEC-AMBIGUOUS: 7
	m.note(7)
	d.add(s.id, Fact{Kind: FactLateFrameObserved, RequestID: mdlReq, LateKind: kind, Status: mdlStatus, Digest: mdlDigest},
		"RequestID", "LateKind", "Status", "Digest")
	return d.out
}

var mdlPrincipalsFor = map[InputKind][]PrincipalClass{
	InCreate: {PrincipalUser, PrincipalSystem},
	InSend:   {PrincipalUser}, InPause: {PrincipalUser}, InStop: {PrincipalUser}, InChangeCWD: {PrincipalUser}, InClose: {PrincipalUser}, InAbandon: {PrincipalUser},
	ObConversationBound: {PrincipalProvider}, ObConnected: {PrincipalProvider}, ObDisconnected: {PrincipalProvider},
	ObAccepted: {PrincipalProvider}, ObRefused: {PrincipalProvider}, ObUnknown: {PrincipalProvider},
	ObTurnBound: {PrincipalProvider}, ObCompleted: {PrincipalProvider}, ObControlOutcome: {PrincipalProvider},
	ObAuthBoundary: {PrincipalSystem}, ObQuarantine: {PrincipalSystem}, ObRestart: {PrincipalSystem},
}

// predict gives the outcome of one input from the current model state, changing nothing.
func (m *mdlModel) predict(gs mdlGenStep) mdlOutcome {
	in := gs.in
	allowed, known := mdlPrincipalsFor[in.Kind]
	if !known {
		// SPEC-AMBIGUOUS: 3
		m.note(3)
		return m.refuse("auth.unknown_kind", "forbidden")
	}
	// SPEC-AMBIGUOUS: 2
	m.note(2)
	if !mdlContains(allowed, in.Principal.Class) {
		return m.refuse("auth.class", "forbidden")
	}
	if in.Principal.Class == PrincipalProvider && in.Principal.SessionID != in.SessionID {
		return m.refuse("auth.session", "forbidden")
	}
	if !mdlGoodTime(in.At) {
		// SPEC-AMBIGUOUS: 1
		m.note(1)
		return m.refuse("time", "bad_time")
	}
	switch in.Kind {
	case InCreate:
		return m.predictCreate(in)
	case ObAuthBoundary:
		return m.predictAuthBoundary(in)
	case ObRestart:
		if m.lastKind == FactProcessRestarted {
			m.hit("t7.restart.idempotent")
			return mdlOutcome{}
		}
		m.hit("t7.restart.fact")
		d := m.newDraft(in.At)
		d.add("", Fact{Kind: FactProcessRestarted})
		return d.out
	case ObTurnBound:
		return m.predictTurnBound(in)
	}
	// SPEC-AMBIGUOUS: 4
	m.note(4)
	s := m.sessions[in.SessionID]
	if s == nil || s.closed {
		if s != nil {
			return m.refuse("closed", "not_found")
		}
		return m.refuse("missing", "not_found")
	}
	if s.hidden {
		// SPEC-AMBIGUOUS: 22
		m.note(22)
	}
	switch in.Kind {
	case InSend:
		return m.predictSend(s, in)
	case InPause, InStop:
		return m.predictControl(s, in)
	case InChangeCWD:
		return m.predictCWD(s, in)
	case InClose:
		if s.abandoned == nil && (s.unresolved() || s.quarantine != "") {
			return m.refuse("close", "unresolved")
		}
		m.hit("t7.close.fact")
		d := m.newDraft(in.At)
		d.add(s.id, Fact{Kind: FactSessionClosed})
		return d.out
	case InAbandon:
		return m.predictAbandon(s, gs)
	case ObConversationBound:
		return m.predictConversation(s, in)
	case ObConnected:
		if s.readOnly {
			return m.late(s, in, "connected")
		}
		if s.connected {
			m.hit("t7.connected.idempotent")
			return mdlOutcome{}
		}
		m.hit("t7.connected.fact")
		d := m.newDraft(in.At)
		d.add(s.id, Fact{Kind: FactProviderConnected})
		return d.out
	case ObDisconnected:
		if s.readOnly {
			return m.late(s, in, "disconnected")
		}
		m.hit("t7.disconnected.fact")
		d := m.newDraft(in.At)
		d.add(s.id, Fact{Kind: FactProviderDisconnected})
		return d.out
	case ObAccepted, ObRefused, ObUnknown:
		return m.predictReceiptFrame(s, in)
	case ObCompleted:
		return m.predictCompleted(s, in)
	case ObControlOutcome:
		return m.predictControlOutcome(s, in)
	case ObQuarantine:
		// SPEC-AMBIGUOUS: 13
		m.note(13)
		if in.ReasonCode == "" {
			return m.refuse("quarantine.empty", "bad_value")
		}
		if !mdlCodeShape.MatchString(in.ReasonCode) {
			return m.refuse("quarantine.shape", "bad_value")
		}
		m.hit("t7.quarantine.fact")
		d := m.newDraft(in.At)
		d.add(s.id, Fact{Kind: FactSessionQuarantined, ReasonCode: in.ReasonCode}, "ReasonCode")
		d.out.effects = s.stopEffects()
		return d.out
	}
	panic("model: unhandled input kind " + string(in.Kind))
}

func (m *mdlModel) predictCreate(in In) mdlOutcome {
	// SPEC-AMBIGUOUS: 4
	m.note(4)
	if in.SessionID == "" {
		return m.refuse("create.empty", "session_exists")
	}
	if prior, used := m.sessions[in.SessionID]; used {
		if prior.closed {
			return m.refuse("create.closed", "session_exists")
		}
		return m.refuse("create.used", "session_exists")
	}
	if !mdlKnownProvider(in.Provider) {
		return m.refuse("create", "bad_provider")
	}
	if in.ProviderID != "" && in.RuntimeIdentity == "" {
		return m.refuse("create", "no_owner")
	}
	// SPEC-AMBIGUOUS: 25
	m.note(25)
	shapely := mdlIdentityShape.MatchString(in.SessionID) &&
		(in.ProviderID == "" || mdlIdentityShape.MatchString(in.ProviderID)) &&
		(in.ProfileID == "" || mdlIdentityShape.MatchString(in.ProfileID)) &&
		(in.RuntimeIdentity == "" || mdlDigestShape.MatchString(in.RuntimeIdentity)) &&
		mdlGoodCWD(in.CWD)
	if !shapely {
		return m.refuse("create", "bad_value")
	}
	m.hit("t7.create.fact")
	d := m.newDraft(in.At)
	d.add(in.SessionID, Fact{Kind: FactSessionCreated, Provider: in.Provider, ProviderID: in.ProviderID, ProfileID: in.ProfileID, CWD: in.CWD, RuntimeIdentity: in.RuntimeIdentity},
		"Provider", "ProviderID", "ProfileID", "CWD", "RuntimeIdentity")
	return d.out
}

func (m *mdlModel) predictSend(s *mdlMSession, in In) mdlOutcome {
	if r, used := s.receipts[in.RequestID]; used {
		if r == ReceiptIntent || r == ReceiptAccepted || r == ReceiptFinal {
			m.hit("t7.send.replay." + string(r))
			return mdlOutcome{}
		}
		return m.refuse("send", "not_replayed")
	}
	switch {
	case in.RequestID == "":
		return m.refuse("send", "bad_request")
	case s.readOnly:
		return m.refuse("send", "read_only")
	case s.unresolved():
		return m.refuse("send", "unresolved")
	case s.provider == ProviderCodex && !s.connected:
		return m.refuse("send", "disconnected")
	case in.RuntimeIdentity == "":
		return m.refuse("send", "no_identity")
	case s.mdlIdentity != "" && s.mdlIdentity != in.RuntimeIdentity:
		return m.refuse("send", "runtime_changed")
	case s.mdlIdentity == "" && s.started:
		return m.refuse("send", "no_owner")
	}
	bind := s.mdlIdentity == ""
	if !mdlIdentityShape.MatchString(in.RequestID) || (bind && !mdlDigestShape.MatchString(in.RuntimeIdentity)) {
		return m.refuse("send", "bad_value")
	}
	d := m.newDraft(in.At)
	if bind {
		m.hit("t7.send.binds_identity")
		d.add(s.id, Fact{Kind: FactRuntimeIdentityBound, RuntimeIdentity: in.RuntimeIdentity}, "RuntimeIdentity")
	}
	m.hit("t7.send.fact")
	d.add(s.id, Fact{Kind: FactRequestIntended, RequestID: in.RequestID}, "RequestID")
	d.out.effects = []Effect{{Kind: EffectStartTurn, Class: ClassNewWork, SessionID: s.id, RequestID: in.RequestID, Fence: s.epoch}}
	return d.out
}

func (m *mdlModel) predictControl(s *mdlMSession, in In) mdlOutcome {
	effects := s.stopEffects()
	d := m.newDraft(in.At)
	switch {
	case s.readOnly:
		if len(effects) == 0 {
			return m.refuse("control", "read_only")
		}
		m.hit("t7.control.read_only_effects")
	case s.last() == ReceiptUnknown:
		if s.owed() && !s.pending {
			m.hit("t7.control.unknown_owed")
			d.add(s.id, Fact{Kind: FactControlRequested, Control: "stop"}, "Control")
		} else if len(effects) == 0 {
			return m.refuse("control", "nothing_to_stop")
		} else {
			m.hit("t7.control.unknown_effects")
		}
	case s.paused && (s.pending || !s.owed()):
		// Table 7 and section 10 item 41: a press that would change nothing.
		m.hit("t7.control.already_paused." + string(in.Kind))
	default:
		m.hit("t7.control." + string(in.Kind))
		d.add(s.id, Fact{Kind: FactControlRequested, Control: string(in.Kind)}, "Control")
	}
	d.out.effects = effects
	return d.out
}

func (m *mdlModel) predictCWD(s *mdlMSession, in In) mdlOutcome {
	switch {
	case s.readOnly:
		return m.refuse("cwd", "read_only")
	case s.unresolved():
		return m.refuse("cwd", "unresolved")
	case in.CWD == "":
		return m.refuse("cwd", "bad_request")
	case !mdlGoodCWD(in.CWD):
		return m.refuse("cwd", "bad_value")
	}
	m.hit("t7.cwd.fact")
	d := m.newDraft(in.At)
	d.add(s.id, Fact{Kind: FactCwdChanged, CWD: in.CWD}, "CWD")
	return d.out
}

func (m *mdlModel) predictAbandon(s *mdlMSession, gs mdlGenStep) mdlOutcome {
	in := gs.in
	text := gs.effectiveReason()
	// SPEC-AMBIGUOUS: 14
	m.note(14)
	if text == "" || len(text) > 500 {
		return m.refuse("abandon", "bad_reason")
	}
	if len(gs.reason) > 500 && gs.redact == 0 {
		m.hit("t7.abandon.limit_after_trim")
	}
	if s.abandoned != nil {
		// SPEC-AMBIGUOUS: 24
		m.note(24)
		if in.ExpectedRequest == s.abandoned.RequestID {
			m.hit("t7.abandon.idempotent")
			return mdlOutcome{}
		}
		return m.refuse("abandon", "discarded_other")
	}
	mdlStatus, _ := s.mdlStatus()
	switch {
	case in.ExpectedRequest != s.lastReq:
		return m.refuse("abandon", "turn_changed")
	case !s.readOnly && mdlStatus == "running":
		return m.refuse("abandon", "stop_first")
	case !s.unresolved() && mdlStatus != "unknown":
		return m.refuse("abandon", "nothing_to_discard")
	}
	if !utf8.ValidString(text) {
		// Section 7: Decide reduces each fact first, and item 31 makes this one illegal.
		return m.refuse("abandon", "bad_value")
	}
	if s.lastReq == "" {
		m.hit("t7.abandon.no_receipt")
	}
	m.hit("t7.abandon.fact")
	d := m.newDraft(in.At)
	d.add(s.id, Fact{Kind: FactAbandoned, RequestID: s.lastReq, Reason: text}, "RequestID", "Reason")
	d.out.effects = s.stopEffects()
	return d.out
}

func (m *mdlModel) predictConversation(s *mdlMSession, in In) mdlOutcome {
	if s.readOnly || !mdlIdentityShape.MatchString(in.ProviderID) ||
		(in.RuntimeIdentity != "" && !mdlDigestShape.MatchString(in.RuntimeIdentity)) {
		return m.late(s, in, "conversation")
	}
	if s.mdlIdentity != "" && in.RuntimeIdentity != "" && s.mdlIdentity != in.RuntimeIdentity {
		return m.refuse("conversation", "runtime_changed")
	}
	if s.mdlIdentity == "" && in.RuntimeIdentity == "" {
		return m.refuse("conversation", "no_owner")
	}
	if s.conversation == in.ProviderID {
		m.hit("t7.conversation.idempotent")
		return mdlOutcome{}
	}
	if s.started {
		m.hit("t7.conversation.not_replaced")
		return m.late(s, in, "conversation")
	}
	d := m.newDraft(in.At)
	if in.RuntimeIdentity != "" && s.mdlIdentity == "" {
		m.hit("t7.conversation.binds_identity")
		d.add(s.id, Fact{Kind: FactRuntimeIdentityBound, RuntimeIdentity: in.RuntimeIdentity}, "RuntimeIdentity")
	}
	m.hit("t7.conversation.fact")
	d.add(s.id, Fact{Kind: FactConversationBound, ProviderID: in.ProviderID}, "ProviderID")
	return d.out
}

func (m *mdlModel) predictReceiptFrame(s *mdlMSession, in In) mdlOutcome {
	lateName := map[InputKind]string{ObAccepted: "accepted", ObRefused: "refused", ObUnknown: "write_unknown"}[in.Kind]
	if in.RequestID != s.lastReq || !s.open() || s.readOnly {
		return m.late(s, in, lateName)
	}
	d := m.newDraft(in.At)
	mdlCode := in.ReasonCode
	if !mdlCodeShape.MatchString(mdlCode) {
		if mdlCode != "" {
			m.hit("t7.frame.reason_dropped")
		}
		mdlCode = ""
	}
	switch in.Kind {
	case ObAccepted:
		if s.last() == ReceiptAccepted {
			m.hit("t7.accepted.idempotent")
			return mdlOutcome{}
		}
		m.hit("t7.accepted.fact")
		d.add(s.id, Fact{Kind: FactProviderAccepted, RequestID: s.lastReq}, "RequestID")
	case ObRefused:
		m.hit("t7.refused.fact")
		d.add(s.id, Fact{Kind: FactProviderRefused, RequestID: s.lastReq, ReasonCode: mdlCode}, "RequestID", "ReasonCode")
	case ObUnknown:
		m.hit("t7.unknown.fact")
		d.add(s.id, Fact{Kind: FactOutcomeUnknown, RequestID: s.lastReq, ReasonCode: mdlCode}, "RequestID", "ReasonCode")
	}
	return d.out
}

func (m *mdlModel) predictTurnBound(in In) mdlOutcome {
	s := m.sessions[in.SessionID]
	shapely := mdlIdentityShape.MatchString(in.TurnID)
	if s != nil && s.closed && s.pending && in.RequestID == s.lastReq && shapely {
		m.hit("t7.turn.closed_pending")
		return mdlOutcome{effects: []Effect{{Kind: EffectInterrupt, Class: ClassStopWork, SessionID: s.id, RequestID: in.RequestID, TurnID: in.TurnID}}}
	}
	if s == nil {
		return m.refuse("turn_missing", "not_found")
	}
	if s.closed {
		return m.refuse("turn_closed", "not_found")
	}
	if s.provider == ProviderClaude {
		m.hit("t7.turn.claude_late")
		return m.late(s, in, "turn_bound")
	}
	if in.RequestID != s.lastReq || !shapely {
		m.hit("t7.turn.guard_late")
		return m.late(s, in, "turn_bound")
	}
	if s.mdlTurn == in.TurnID {
		m.hit("t7.turn.idempotent")
		return mdlOutcome{}
	}
	if s.mdlTurn != "" {
		m.hit("t7.turn.different_late")
		return m.late(s, in, "turn_bound")
	}
	d := m.newDraft(in.At)
	fact := Fact{Kind: FactTurnBound, RequestID: in.RequestID, TurnID: in.TurnID}
	switch {
	case s.pending:
		m.hit("t7.turn.pending")
		d.add(s.id, fact, "RequestID", "TurnID")
		d.out.effects = []Effect{{Kind: EffectInterrupt, Class: ClassStopWork, SessionID: s.id, RequestID: in.RequestID, TurnID: in.TurnID}}
	case s.unresolved():
		m.hit("t7.turn.fact")
		d.add(s.id, fact, "RequestID", "TurnID")
	default:
		m.hit("t7.turn.resolved_late")
		return m.late(s, in, "turn_bound")
	}
	return d.out
}

func (m *mdlModel) predictCompleted(s *mdlMSession, in In) mdlOutcome {
	d := m.newDraft(in.At)
	if in.RequestID == "" {
		if s.open() && !s.readOnly {
			m.hit("t7.completed.unbound")
			d.add(s.id, Fact{Kind: FactOutcomeUnknown, RequestID: s.lastReq, ReasonCode: "unbound_completion"}, "RequestID", "ReasonCode")
			return d.out
		}
		m.hit("t7.completed.empty_late")
		return m.late(s, in, "final")
	}
	if in.RequestID != s.lastReq || !s.open() || s.readOnly {
		m.hit("t7.completed.guard_late")
		return m.late(s, in, "final")
	}
	if s.provider == ProviderCodex && (s.mdlTurn == "" || in.TurnID != s.mdlTurn) {
		m.hit("t7.completed.turn_late")
		return m.late(s, in, "final")
	}
	if !mdlContains([]string{"completed", "failed", "interrupted"}, in.Status) {
		m.hit("t7.completed.invalid_status")
		d.add(s.id, Fact{Kind: FactOutcomeUnknown, RequestID: s.lastReq, ReasonCode: "invalid_final_status"}, "RequestID", "ReasonCode")
		return d.out
	}
	m.hit("t7.completed.fact." + in.Status)
	// Section 10 item 6: the session's bound turn, empty for Claude, not the frame's.
	d.add(s.id, Fact{Kind: FactProviderCompleted, RequestID: s.lastReq, Status: in.Status, TurnID: s.mdlTurn}, "RequestID", "Status", "TurnID")
	return d.out
}

func (m *mdlModel) predictControlOutcome(s *mdlMSession, in In) mdlOutcome {
	if (in.Control != "pause" && in.Control != "stop") || !mdlContains([]string{"confirmed", "rejected", "unconfirmed"}, in.Outcome) {
		return m.late(s, in, "control_outcome")
	}
	// SPEC-AMBIGUOUS: 37
	if s.wouldBeUnconfirmed(in.Outcome) == s.unconfirmed {
		m.hit("t7.control_outcome.idempotent")
		return mdlOutcome{}
	}
	m.hit("t7.control_outcome.fact")
	d := m.newDraft(in.At)
	d.add(s.id, Fact{Kind: FactControlOutcome, Control: in.Control, Outcome: in.Outcome}, "Control", "Outcome")
	return d.out
}

func (m *mdlModel) predictAuthBoundary(in In) mdlOutcome {
	if !mdlKnownProvider(in.Provider) {
		return m.refuse("auth_boundary", "bad_provider")
	}
	d := m.newDraft(in.At)
	var effects []Effect
	for _, id := range m.order {
		s := m.sessions[id]
		if s.provider != in.Provider || s.profile != in.ProfileID || s.closed || s.readOnly {
			continue
		}
		d.add(s.id, Fact{Kind: FactAuthBoundaryCrossed})
		effects = append(effects, s.stopEffects()...)
	}
	if len(d.out.facts) == 0 {
		m.hit("t7.auth_boundary.idempotent")
		return mdlOutcome{}
	}
	m.hit("t7.auth_boundary.fact")
	if len(d.out.facts) > 1 {
		m.hit("t7.auth_boundary.several")
	}
	d.out.effects = effects
	return d.out
}

// genStep is one generated action: an input, or a raw fact handed straight to Reduce.
type mdlGenStep struct {
	in      In
	reason  string
	redact  int // 0 identity redactor, 1 nil redactor, 2 scrubbing redactor, 3 padding redactor.
	atSet   bool
	raw     *Fact
	seqMode int // 0 next, 1 equal to LastSeq, 2 below LastSeq, 3 a gap.
	schema  *int
	keepRev bool
	tag     string
}

// SPEC-AMBIGUOUS: 32
func mdlScrub(text string) string {
	if strings.TrimSpace(text) == "" {
		return ""
	}
	return "scrubbed"
}

// mdlPaddingRedactor returns text that still needs Redact's trim.
func mdlPaddingRedactor(string) string { return " padded out\u00a0" }

// SPEC-AMBIGUOUS: 32
func (gs mdlGenStep) effectiveReason() string {
	text := gs.reason
	switch gs.redact {
	case 1:
		text = ""
	case 2:
		text = mdlScrub(text)
	case 3:
		text = mdlPaddingRedactor(text)
	}
	return strings.TrimSpace(text)
}

func (gs mdlGenStep) kernelIn() In {
	in := gs.in
	switch gs.redact {
	case 1:
		in.Reason = Redact(gs.reason, nil)
	case 2:
		in.Reason = Redact(gs.reason, mdlScrub)
	case 3:
		in.Reason = Redact(gs.reason, mdlPaddingRedactor)
	default:
		if gs.reason != "" {
			in.Reason = Redact(gs.reason, func(t string) string { return t })
		}
	}
	return in
}

// stampRaw fills a raw fact's bookkeeping from the model. SPEC-AMBIGUOUS: 10
func (m *mdlModel) stampRaw(gs mdlGenStep, at string) Fact {
	f := *gs.raw
	f.At = at
	f.SchemaVersion = SchemaVersion
	if gs.schema != nil {
		f.SchemaVersion = *gs.schema
	}
	switch gs.seqMode {
	case 1:
		f.Seq = m.lastSeq
	case 2:
		if m.lastSeq > 0 {
			f.Seq = m.lastSeq - 1
		}
	case 3:
		// SPEC-AMBIGUOUS: 26
		m.note(26)
		f.Seq = m.lastSeq + 3
	default:
		f.Seq = m.lastSeq + 1
	}
	if !gs.keepRev && f.SessionID != "" {
		f.SessionRevision = 1
		if s := m.sessions[f.SessionID]; s != nil {
			f.SessionRevision = s.revision + 1
		}
	}
	return f
}

type mdlGen struct {
	rng      *rand.Rand
	n        int
	clock    int
	mode     int // 0 benign, 1 mixed, 2 hostile.
	queue    []mdlGenStep
	pending  []func() []mdlGenStep
	reqCount int
}

const (
	mdlRtOne = "rt-1"
	mdlRtTwo = "rt-2"
)

func (g *mdlGen) fresh(prefix string) string {
	g.n++
	return prefix + "-" + strconv.Itoa(g.n)
}

func (g *mdlGen) now() string {
	g.clock++
	t := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC).Add(time.Duration(g.clock) * time.Millisecond)
	return t.Format("2006-01-02T15:04:05.000000000Z")
}

type mdlInMod func(*mdlGenStep)

func mdlReq(r string) mdlInMod      { return func(g *mdlGenStep) { g.in.RequestID = r } }
func mdlTurn(t string) mdlInMod     { return func(g *mdlGenStep) { g.in.TurnID = t } }
func mdlIdentity(x string) mdlInMod { return func(g *mdlGenStep) { g.in.RuntimeIdentity = x } }
func mdlConv(x string) mdlInMod     { return func(g *mdlGenStep) { g.in.ProviderID = x } }
func mdlStatus(x string) mdlInMod   { return func(g *mdlGenStep) { g.in.Status = x } }
func mdlCode(x string) mdlInMod     { return func(g *mdlGenStep) { g.in.ReasonCode = x } }
func mdlExpect(x string) mdlInMod   { return func(g *mdlGenStep) { g.in.ExpectedRequest = x } }
func mdlProv(x string) mdlInMod     { return func(g *mdlGenStep) { g.in.Provider = x } }
func mdlProf(x string) mdlInMod     { return func(g *mdlGenStep) { g.in.ProfileID = x } }
func mdlCwd(x string) mdlInMod      { return func(g *mdlGenStep) { g.in.CWD = x } }
func mdlDigest(x string) mdlInMod   { return func(g *mdlGenStep) { g.in.Digest = x } }
func mdlBecause(x string) mdlInMod  { return func(g *mdlGenStep) { g.reason = x } }
func mdlCtl(c, o string) mdlInMod {
	return func(g *mdlGenStep) { g.in.Control, g.in.Outcome = c, o }
}
func mdlBadAt(x string) mdlInMod { return func(g *mdlGenStep) { g.in.At, g.atSet = x, true } }

func mdlStep(kind InputKind, sid string, mods ...mdlInMod) mdlGenStep {
	gs := mdlGenStep{in: In{Kind: kind, SessionID: sid}}
	if classes, ok := mdlPrincipalsFor[kind]; ok {
		gs.in.Principal.Class = classes[0]
		if classes[0] == PrincipalProvider {
			gs.in.Principal.SessionID = sid
		}
	}
	for _, mod := range mods {
		mod(&gs)
	}
	return gs
}

func mdlRawFact(tag string, f Fact) mdlGenStep { return mdlGenStep{raw: &f, tag: tag} }

// next gives the next action. Scripts run whole, so a restart in one cannot disturb another.
func (g *mdlGen) next(m *mdlModel) mdlGenStep {
	if len(g.queue) == 0 && len(g.pending) > 0 && g.rng.Intn(6) == 0 {
		g.queue = g.pending[0]()
		g.pending = g.pending[1:]
	}
	if len(g.queue) == 0 && g.rng.Intn(60) == 0 {
		g.queue = g.scriptReach()
	}
	if len(g.queue) == 0 && g.rng.Intn(80) == 0 {
		g.queue = g.scriptRepeatedControl()
	}
	var gs mdlGenStep
	if len(g.queue) > 0 {
		gs, g.queue = g.queue[0], g.queue[1:]
	} else {
		gs = g.random(m)
	}
	if !gs.atSet {
		gs.in.At = g.now()
	}
	return gs
}

func (g *mdlGen) pick(list ...string) string { return list[g.rng.Intn(len(list))] }

// liveSession prefers a usable session, falling back to any, then to a fresh ID.
func (g *mdlGen) liveSession(m *mdlModel) string {
	var usable []string
	for _, id := range m.order {
		if s := m.sessions[id]; !s.closed && !s.readOnly {
			usable = append(usable, id)
		}
	}
	if len(usable) > 0 && g.rng.Intn(10) > 0 {
		return usable[g.rng.Intn(len(usable))]
	}
	if len(m.order) > 0 {
		return m.order[g.rng.Intn(len(m.order))]
	}
	return g.fresh("s")
}

// random builds a plausible input for the current state, which hostile modes then corrupt.
func (g *mdlGen) random(m *mdlModel) mdlGenStep {
	corruptChance := []int{3, 30, 70}[g.mode]
	if g.mode > 0 && g.rng.Intn(100) < 10+g.mode*5 {
		return g.randomRaw(m)
	}
	live := 0
	for _, id := range m.order {
		if !m.sessions[id].closed && !m.sessions[id].readOnly {
			live++
		}
	}
	var gs mdlGenStep
	if live < 2 || g.rng.Intn(12) == 0 {
		gs = mdlStep(InCreate, g.fresh("s"), mdlProv(g.pick(ProviderCodex, ProviderClaude)), mdlCwd("/work"), mdlProf(g.pick("p1", "p2")), mdlIdentity(g.pick("", mdlRtOne)))
	} else {
		gs = g.progress(m, g.liveSession(m))
	}
	if g.rng.Intn(100) < corruptChance {
		for i := 1 + g.rng.Intn(3); i > 0; i-- {
			g.corrupt(m, &gs)
		}
	}
	return gs
}

// progress picks an input that a healthy provider or user might send to this session.
func (g *mdlGen) progress(m *mdlModel, sid string) mdlGenStep {
	s := m.sessions[sid]
	if s == nil {
		return mdlStep(InCreate, sid, mdlProv(ProviderCodex))
	}
	last, cur := s.lastReq, s.mdlTurn
	if cur == "" {
		cur = g.fresh("t")
	}
	switch g.rng.Intn(16) {
	case 0, 1:
		return mdlStep(ObConnected, sid)
	case 2, 3, 4:
		g.reqCount++
		return mdlStep(InSend, sid, mdlReq("r-"+strconv.Itoa(g.reqCount)), mdlIdentity(mdlRtOne))
	case 5:
		return mdlStep(ObAccepted, sid, mdlReq(last))
	case 6:
		return mdlStep(ObTurnBound, sid, mdlReq(last), mdlTurn(cur))
	case 7, 8:
		return mdlStep(ObCompleted, sid, mdlReq(last), mdlTurn(s.mdlTurn), mdlStatus(g.pick("completed", "failed", "interrupted")))
	case 9:
		return mdlStep(ObRefused, sid, mdlReq(last), mdlCode("cap_hit"))
	case 10:
		return mdlStep(ObUnknown, sid, mdlReq(last))
	case 11:
		return mdlStep(g.pickKind(InPause, InStop), sid)
	case 12:
		return mdlStep(ObControlOutcome, sid, mdlCtl(g.pick("pause", "stop"), g.pick("confirmed", "rejected", "unconfirmed")))
	case 13:
		return mdlStep(InChangeCWD, sid, mdlCwd("/elsewhere"))
	case 14:
		return mdlStep(g.pickKind(InClose, ObDisconnected, ObConversationBound), sid, mdlConv("conv-"+sid), mdlIdentity(mdlRtOne))
	}
	return mdlStep(InAbandon, sid, mdlExpect(last), mdlBecause("no longer needed"))
}

func (g *mdlGen) pickKind(list ...InputKind) InputKind { return list[g.rng.Intn(len(list))] }

func (g *mdlGen) foreignRequest(m *mdlModel) string {
	if len(m.order) == 0 {
		return "r-none"
	}
	s := m.sessions[m.order[g.rng.Intn(len(m.order))]]
	if len(s.order) == 0 {
		return "r-none"
	}
	return s.order[g.rng.Intn(len(s.order))]
}

const (
	mdlHexA   = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	mdlHexB   = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	mdlCanary = "CANARY-sk-live-7f3a9c2e"
)

var (
	mdlLongID    = strings.Repeat("x", 129)
	mdlLongCode  = strings.Repeat("a", 41)
	mdlBadTimes  = []string{"", "now", "2026-11-03T12:00:00Z", "2026-11-03T12:00:00.000000000+01:00", "2026-11-03 12:00:00.000000000Z", "2026-11-03T12:00:00.00000000Z", "2026-13-45T12:00:00.000000000Z"}
	mdlHostility = []string{"", "bad value!", mdlLongID, "café", "a\nb"}
)

// corrupt damages one field of a generated input.
func (g *mdlGen) corrupt(m *mdlModel, gs *mdlGenStep) {
	bad := func(good ...string) string { return g.pick(append(append([]string(nil), mdlHostility...), good...)...) }
	in := &gs.in
	switch g.rng.Intn(16) {
	case 0:
		in.RequestID = bad(g.foreignRequest(m))
	case 1:
		in.TurnID = bad("t-foreign")
	case 2:
		in.Provider = bad("Codex", "codexx", "claude ", ProviderClaude)
	case 3:
		in.ProviderID = bad("conv-foreign")
	case 4:
		in.RuntimeIdentity = bad(mdlRtTwo, "bad/identity")
	case 5:
		in.Status = g.pick("", "completed", "failed", "interrupted", "running", "cancelled", "Free Text!", mdlLongCode, "COMPLETED")
	case 6:
		in.Digest = bad("sha256:abc", mdlHexA, mdlHexA, mdlCanary, strings.ToUpper(mdlHexA), mdlHexA[:63], mdlHexA+"0")
	case 7:
		in.ReasonCode = g.pick("", "BAD CODE", mdlLongCode, "ok_code")
	case 8:
		in.Principal.Class = PrincipalClass(g.pick("", "user", "provider", "system", "root"))
	case 9:
		in.Principal.SessionID = bad("s-foreign")
	case 10:
		in.Kind = InputKind(g.pick("", "bogus", "SEND", "create "))
	case 11:
		in.At, gs.atSet = g.pick(mdlBadTimes...), true
		// SPEC-AMBIGUOUS: 1
		m.note(1)
	case 12:
		in.SessionID = g.pick("", "ghost", g.foreignSession(m))
	case 13:
		in.ExpectedRequest = bad(g.foreignRequest(m))
	case 14:
		in.CWD = g.pick("", "a\x01b", strings.Repeat("c", 4097), strings.Repeat("c", 4096), "/ok", "bad\xff")
	case 15:
		gs.reason = g.pick("", "   ", " padded ", strings.Repeat("r", 500), strings.Repeat("r", 501), " "+strings.Repeat("r", 500)+" ", " "+strings.Repeat("r", 501)+" ", "bad\xff", "\u2003", "\u00a0kept\u2003")
		gs.redact = g.rng.Intn(4)
	}
	// Control and Outcome are damaged through a second roll, since few inputs read them.
	if g.rng.Intn(8) == 0 {
		in.Control, in.Outcome = g.pick("", "pause", "stop", "halt"), g.pick("", "confirmed", "maybe")
	}
}

func (g *mdlGen) foreignSession(m *mdlModel) string {
	if len(m.order) == 0 {
		return "ghost"
	}
	return m.order[g.rng.Intn(len(m.order))]
}

// randomRaw hands Reduce a fact whose legality the tables settle, so late, turn and
// conversation facts stay inside the determined cases.
// SPEC-AMBIGUOUS: 8
// SPEC-AMBIGUOUS: 9
// SPEC-AMBIGUOUS: 11
// SPEC-AMBIGUOUS: 12
// SPEC-AMBIGUOUS: 30
// SPEC-AMBIGUOUS: 31
func (g *mdlGen) randomRaw(m *mdlModel) mdlGenStep {
	sid := g.foreignSession(m)
	s := m.sessions[sid]
	last := ""
	if s != nil {
		last = s.lastReq
	}
	kinds := []func() mdlGenStep{
		func() mdlGenStep {
			return mdlRawFact("", Fact{Kind: FactProviderAccepted, SessionID: sid, RequestID: last})
		},
		func() mdlGenStep {
			return mdlRawFact("", Fact{Kind: FactProviderCompleted, SessionID: sid, RequestID: last, Status: g.pick("completed", "failed", "bogus", "")})
		},
		func() mdlGenStep {
			return mdlRawFact("", Fact{Kind: FactProviderRefused, SessionID: sid, RequestID: last})
		},
		func() mdlGenStep {
			return mdlRawFact("", Fact{Kind: FactOutcomeUnknown, SessionID: sid, RequestID: g.foreignRequest(m)})
		},
		func() mdlGenStep {
			g.reqCount++
			return mdlRawFact("", Fact{Kind: FactRequestIntended, SessionID: sid, RequestID: "r-" + strconv.Itoa(g.reqCount)})
		},
		func() mdlGenStep { return mdlRawFact("", Fact{Kind: FactProviderConnected, SessionID: sid}) },
		func() mdlGenStep { return mdlRawFact("", Fact{Kind: FactProviderDisconnected, SessionID: sid}) },
		func() mdlGenStep { return mdlRawFact("", Fact{Kind: FactSessionClosed, SessionID: sid}) },
		func() mdlGenStep { return mdlRawFact("", Fact{Kind: FactCwdChanged, SessionID: sid, CWD: "/raw"}) },
		func() mdlGenStep {
			return mdlRawFact("", Fact{Kind: FactControlRequested, SessionID: sid, Control: g.pick("pause", "stop")})
		},
		func() mdlGenStep {
			return mdlRawFact("", Fact{Kind: FactAbandoned, SessionID: sid, RequestID: "not-" + last, Reason: "raw"})
		},
		func() mdlGenStep { return mdlRawFact("", Fact{Kind: FactSessionQuarantined, SessionID: sid}) },
		func() mdlGenStep { return mdlRawFact("", Fact{Kind: FactProcessRestarted}) },
		func() mdlGenStep { return mdlRawFact("", Fact{Kind: ReservedFactKinds[0], SessionID: sid}) },
		func() mdlGenStep { return mdlRawFact("", Fact{Kind: "NotAKind", SessionID: sid}) },
		func() mdlGenStep {
			gs := mdlRawFact("", Fact{Kind: FactProviderConnected, SessionID: sid})
			gs.seqMode = 1 + g.rng.Intn(2)
			return gs
		},
		func() mdlGenStep {
			return mdlRawFact("", Fact{Kind: FactLateFrameObserved, SessionID: sid, RequestID: g.pick("", last, g.foreignRequest(m)), LateKind: g.pick(mdlLateKinds...), Status: g.pick("", "ok", "invalid"), Digest: g.pick("", mdlHexA)})
		},
		func() mdlGenStep {
			return mdlRawFact("", Fact{Kind: FactTurnBound, SessionID: sid, RequestID: last, TurnID: g.pick("t-a", "t-b", "", "bad turn")})
		},
		func() mdlGenStep {
			return mdlRawFact("", Fact{Kind: FactConversationBound, SessionID: sid, ProviderID: g.pick("conv-a", "conv-b", "", "bad conv!")})
		},
		func() mdlGenStep {
			gs := mdlRawFact("", Fact{Kind: FactProviderConnected, SessionID: sid})
			gs.keepRev = true
			gs.raw.SessionRevision = uint64(g.rng.Intn(4))
			return gs
		},
		func() mdlGenStep {
			gs := mdlRawFact("", Fact{Kind: FactProviderConnected, SessionID: sid})
			gs.in.At, gs.atSet = g.pick(mdlBadTimes...), true
			return gs
		},
		func() mdlGenStep {
			f := Fact{Kind: FactProviderConnected, SessionID: sid}
			switch g.rng.Intn(9) {
			case 0:
				f.RequestID = "bad req!"
			case 1:
				f.TurnID = mdlLongID
			case 2:
				f.ProviderID = "a\nb"
			case 3:
				f.Digest = "bad digest!"
			case 4:
				f.RuntimeIdentity = "bad/identity"
			case 5:
				f.ReasonCode = "BAD CODE"
			case 6:
				f.Status = "Free Text!"
			case 7:
				f.Control = "halt"
			case 8:
				f.Reason = "not on this kind"
			}
			return mdlRawFact("", f)
		},
		func() mdlGenStep {
			gs := mdlRawFact("", Fact{Kind: FactProcessRestarted, SessionID: g.pick("", sid, "bad id!"), SessionRevision: uint64(g.rng.Intn(3))})
			gs.keepRev = true
			return gs
		},
		func() mdlGenStep {
			return mdlRawFact("", Fact{Kind: FactProviderConnected, SessionID: sid, Provider: g.pick("", ProviderCodex, ProviderClaude, "codexx"), TaskID: g.pick("", "task-1", "bad task!"), ObjectiveHash: g.pick("", "sha256:abc", "bad hash!"), State: g.pick("", "", "open"), Status: g.pick("", "", "open"), Generation: uint64(g.rng.Intn(3)), InputRevision: uint64(g.rng.Intn(3)), Passes: map[string]string{"plan": "pass"}, Digest: g.pick("", "d9"), TurnID: g.pick("", "t-unnamed")})
		},
		func() mdlGenStep {
			return mdlRawFact("", Fact{Kind: FactAbandoned, SessionID: sid, RequestID: last, Reason: g.pick("", " spaced ", strings.Repeat("r", 500), strings.Repeat("r", 501), "bad\xff")})
		},
		func() mdlGenStep {
			return mdlRawFact("", Fact{Kind: FactControlOutcome, SessionID: sid, Control: g.pick("pause", "stop"), Outcome: g.pick("confirmed", "rejected", "unconfirmed")})
		},
		func() mdlGenStep {
			g.n++
			id := "lg-rand-" + strconv.Itoa(g.n)
			r := Receipt(g.pick("", "final", "rejected", "unknown", "abandoned", "intent", "accepted"))
			request := ""
			if r != ReceiptNone {
				request = "r1"
			}
			// SPEC-AMBIGUOUS: 31
			reason := g.pick("", "imported discard")
			return mdlRawFact("", Fact{Kind: FactLegacyImported, SessionID: id, Provider: g.pick("", ProviderCodex, ProviderClaude), Receipt: r, RequestID: request, Reason: reason, State: g.pick("", "open", "Bad State"), TaskID: g.pick("", "task-1"), ProviderID: g.pick("", "conv-old"), RuntimeIdentity: g.pick("", mdlRtOne), ProfileID: "p1", CWD: "/old"})
		},
		func() mdlGenStep {
			schema := g.pick("0", "2", "-1")
			v, _ := strconv.Atoi(schema)
			gs := mdlRawFact("", Fact{Kind: FactProviderConnected, SessionID: sid})
			gs.schema = &v
			return gs
		},
	}
	return kinds[g.rng.Intn(len(kinds))]()
}

// Scripts reach the rows that random play rarely finds. Each builds its own sessions.

func (g *mdlGen) codexReady(sid string, mods ...mdlInMod) []mdlGenStep {
	return []mdlGenStep{mdlStep(InCreate, sid, append([]mdlInMod{mdlProv(ProviderCodex), mdlCwd("/w")}, mods...)...), mdlStep(ObConnected, sid)}
}

func mdlClaudeNew(sid string, mods ...mdlInMod) mdlGenStep {
	return mdlStep(InCreate, sid, append([]mdlInMod{mdlProv(ProviderClaude), mdlCwd("/w")}, mods...)...)
}

func mdlSend(sid, r string) mdlGenStep { return mdlStep(InSend, sid, mdlReq(r), mdlIdentity(mdlRtOne)) }

func (g *mdlGen) scriptCreateAndAuth() []mdlGenStep {
	a, b, c := g.fresh("cr"), g.fresh("cr"), g.fresh("cr")
	out := []mdlGenStep{
		mdlStep(InCreate, "", mdlProv(ProviderCodex)),
		mdlStep(InCreate, a, mdlProv(ProviderCodex)),
		mdlStep(InCreate, a, mdlProv(ProviderCodex)),
		mdlStep(InCreate, b, mdlProv("codexx")),
		mdlStep(InCreate, b, mdlProv(ProviderCodex), mdlConv("c1")),
		mdlStep(InCreate, "bad id!", mdlProv(ProviderCodex)),
		mdlStep(InCreate, b, mdlProv(ProviderCodex), mdlCwd("a\nb")),
		mdlStep(InCreate, b, mdlProv(ProviderCodex), mdlCwd(strings.Repeat("c", 4097))),
		mdlStep(InCreate, b, mdlProv(ProviderCodex), mdlConv("bad conv!"), mdlIdentity(mdlRtOne)),
		mdlStep(InCreate, b, mdlProv(ProviderCodex), mdlIdentity("bad identity!")),
		mdlStep(InCreate, b, mdlProv(ProviderCodex), mdlConv("c1"), mdlIdentity(mdlRtOne), mdlCwd(strings.Repeat("c", 4096))),
		mdlClaudeNew(c),
		mdlStep(InClose, c),
		mdlStep(InCreate, c, mdlProv(ProviderClaude)),
		mdlStep(InSend, c, mdlReq("r1"), mdlIdentity(mdlRtOne)),
		mdlStep(InClose, "ghost-"+c),
		mdlStep("bogus", a),
		mdlStep(InSend, a, func(gs *mdlGenStep) { gs.in.Principal.Class = PrincipalProvider }),
		mdlStep(ObConnected, a, func(gs *mdlGenStep) { gs.in.Principal.SessionID = b }),
	}
	for _, bad := range mdlBadTimes {
		out = append(out, mdlStep(ObConnected, a, mdlBadAt(bad)))
	}
	return out
}

func (g *mdlGen) scriptSend() []mdlGenStep {
	a, b, c := g.fresh("sn"), g.fresh("sn"), g.fresh("sn")
	out := []mdlGenStep{mdlStep(InCreate, a, mdlProv(ProviderCodex)), mdlSend(a, "r1"), mdlStep(ObConnected, a)}
	out = append(out,
		mdlStep(InSend, a, mdlIdentity(mdlRtOne)),
		mdlStep(InSend, a, mdlReq("r1")),
		mdlStep(InSend, a, mdlReq("r1"), mdlIdentity("bad identity!")),
		mdlSend(a, "r1"), mdlSend(a, "r1"), mdlSend(a, "r2"),
		mdlStep(ObAccepted, a, mdlReq("r1")), mdlStep(ObAccepted, a, mdlReq("r1")), mdlSend(a, "r1"),
		mdlStep(ObTurnBound, a, mdlReq("r1"), mdlTurn("t1")),
		mdlStep(ObCompleted, a, mdlReq("r1"), mdlTurn("t1"), mdlStatus("completed")),
		mdlSend(a, "r1"),
		mdlStep(InSend, a, mdlReq("r2"), mdlIdentity(mdlRtTwo)),
		mdlSend(a, "bad req!"),
		mdlSend(a, "r3"), mdlStep(ObRefused, a, mdlReq("r3"), mdlCode("no_cap")), mdlSend(a, "r3"),
		mdlRawFact("legal", Fact{Kind: FactSessionCreated, SessionID: b, Provider: ProviderClaude, ProviderID: "conv-raw"}),
		mdlSend(b, "r1"),
		mdlClaudeNew(c),
		mdlStep(InSend, c, mdlReq("r1"), mdlIdentity("bad identity!")),
		mdlStep(ObRestart, ""),
		mdlSend(a, "r4"),
	)
	return out
}

func (g *mdlGen) scriptControl() []mdlGenStep {
	a, b, c, d := g.fresh("ct"), g.fresh("ct"), g.fresh("ct"), g.fresh("ct")
	out := g.codexReady(a)
	out = append(out, mdlStep(InStop, a), mdlStep(InPause, a), mdlSend(a, "r1"), mdlStep(InStop, a), mdlStep(ObDisconnected, a), mdlStep(InStop, a))
	out = append(out, g.codexReady(b)...)
	out = append(out, mdlSend(b, "r1"), mdlStep(ObUnknown, b, mdlReq("r1")), mdlStep(InStop, b), mdlStep(InPause, b))
	out = append(out, mdlClaudeNew(c), mdlSend(c, "r1"), mdlStep(ObUnknown, c, mdlReq("r1")), mdlStep(InStop, c))
	out = append(out, mdlStep(InCreate, d, mdlProv(ProviderCodex)), mdlStep(ObRestart, ""), mdlStep(InStop, c), mdlStep(InPause, d))
	return append(out, g.scriptRepeatedControl()...)
}

// scriptRepeatedControl presses pause and stop again and again (section 10 item 41).
func (g *mdlGen) scriptRepeatedControl() []mdlGenStep {
	idle, unbound, bound, claude, owes := g.fresh("rp"), g.fresh("rp"), g.fresh("rp"), g.fresh("rp"), g.fresh("rp")
	presses := func(sid string) []mdlGenStep {
		return []mdlGenStep{mdlStep(InPause, sid), mdlStep(InPause, sid), mdlStep(InStop, sid), mdlStep(InStop, sid), mdlStep(InPause, sid)}
	}
	out := g.codexReady(idle)
	out = append(out, presses(idle)...)
	out = append(out, g.codexReady(unbound)...)
	out = append(out, mdlSend(unbound, "r1"))
	out = append(out, presses(unbound)...)
	out = append(out, mdlStep(ObTurnBound, unbound, mdlReq("r1"), mdlTurn("t1")))
	out = append(out, presses(unbound)...)
	out = append(out, g.codexReady(bound)...)
	out = append(out, mdlSend(bound, "r1"), mdlStep(ObTurnBound, bound, mdlReq("r1"), mdlTurn("t1")))
	out = append(out, presses(bound)...)
	out = append(out, mdlClaudeNew(claude), mdlSend(claude, "r1"))
	out = append(out, presses(claude)...)
	out = append(out, mdlStep(ObCompleted, claude, mdlReq("r1"), mdlStatus("completed")))
	out = append(out, presses(claude)...)
	// Paused with the turn bound, then a disconnect makes the interrupt owed: the second fact.
	out = append(out, g.codexReady(owes)...)
	out = append(out, mdlSend(owes, "r1"), mdlStep(ObTurnBound, owes, mdlReq("r1"), mdlTurn("t1")), mdlStep(InPause, owes),
		mdlStep(ObDisconnected, owes), mdlStep(InStop, owes), mdlStep(InStop, owes), mdlStep(InPause, owes))
	return out
}

func (g *mdlGen) scriptCWD() []mdlGenStep {
	a := g.fresh("cw")
	out := g.codexReady(a)
	return append(out,
		mdlStep(InChangeCWD, a),
		mdlStep(InChangeCWD, a, mdlCwd("a\x01")),
		mdlStep(InChangeCWD, a, mdlCwd("bad\xff")),
		mdlStep(InChangeCWD, a, mdlCwd(strings.Repeat("c", 4097))),
		mdlStep(InChangeCWD, a, mdlCwd(strings.Repeat("c", 4096))),
		mdlStep(InChangeCWD, a, mdlCwd("/next")),
		mdlSend(a, "r1"),
		mdlStep(InChangeCWD, a, mdlCwd("/blocked")),
		mdlStep(ObRestart, ""),
		mdlStep(InChangeCWD, a, mdlCwd("/blocked")),
	)
}

func (g *mdlGen) scriptAbandon() []mdlGenStep {
	a, q, u, f := g.fresh("ab"), g.fresh("ab"), g.fresh("ab"), g.fresh("ab")
	why := mdlBecause("user gave up")
	out := g.codexReady(a)
	out = append(out,
		mdlStep(InAbandon, a),
		mdlStep(InAbandon, a, mdlBecause("   ")),
		mdlStep(InAbandon, a, mdlBecause(strings.Repeat("r", 501))),
		mdlStep(InAbandon, a, mdlBecause(" "+strings.Repeat("r", 501)+" ")),
		mdlStep(InAbandon, a, why),
		mdlSend(a, "r1"),
		mdlStep(InAbandon, a, mdlExpect("other"), why),
		mdlStep(InAbandon, a, mdlExpect("r1"), why),
		mdlStep(InPause, a),
		mdlStep(InAbandon, a, mdlExpect("r1"), mdlBecause("  "+strings.Repeat("r", 500)+"  ")),
		mdlStep(InAbandon, a, mdlExpect("r1"), why),
		mdlStep(InAbandon, a, mdlExpect("other"), why),
		mdlStep(InClose, a),
		mdlSend(a, "r2"),
		mdlStep(InCreate, q, mdlProv(ProviderCodex)),
		mdlStep(ObQuarantine, q, mdlCode("bad_log")),
		mdlStep(InClose, q),
		mdlStep(InAbandon, q, mdlBecause(" padded ")),
		mdlStep(InClose, q),
	)
	out = append(out, mdlClaudeNew(u), mdlSend(u, "r1"), mdlStep(InClose, u))
	nilRedactor := mdlStep(InAbandon, u, mdlExpect("r1"), why)
	nilRedactor.redact = 1
	scrubbed := mdlStep(InAbandon, u, mdlExpect("r1"), why)
	scrubbed.redact = 2
	out = append(out, nilRedactor, mdlStep(InPause, u), scrubbed)
	out = append(out, mdlClaudeNew(f), mdlSend(f, "r1"), mdlStep(ObCompleted, f, mdlReq("r1"), mdlStatus("completed")),
		mdlRawFact("legal", Fact{Kind: FactAbandoned, SessionID: f, RequestID: "r1", Reason: "raw discard"}))
	return out
}

func (g *mdlGen) scriptConversation() []mdlGenStep {
	a, b := g.fresh("cv"), g.fresh("cv")
	return []mdlGenStep{
		mdlStep(InCreate, a, mdlProv(ProviderCodex)),
		mdlStep(ObConversationBound, a, mdlConv("conv-a")),
		mdlStep(ObConversationBound, a, mdlConv("BAD PID!"), mdlIdentity(mdlRtOne)),
		mdlStep(ObConversationBound, a, mdlIdentity(mdlRtOne)),
		mdlStep(ObConversationBound, a, mdlConv("conv-a"), mdlIdentity("bad identity!")),
		mdlStep(ObConversationBound, a, mdlConv("conv-a"), mdlIdentity(mdlRtOne)),
		mdlStep(ObConversationBound, a, mdlConv("conv-a"), mdlIdentity(mdlRtOne)),
		mdlStep(ObConversationBound, a, mdlConv("conv-a")),
		mdlStep(ObConversationBound, a, mdlConv("conv-b"), mdlIdentity(mdlRtOne)),
		mdlStep(ObConversationBound, a, mdlConv("conv-a"), mdlIdentity(mdlRtTwo)),
		mdlStep(InCreate, b, mdlProv(ProviderClaude), mdlIdentity(mdlRtOne)),
		mdlStep(ObConversationBound, b, mdlConv("conv-b")),
		mdlStep(ObRestart, ""),
		mdlStep(ObConversationBound, b, mdlConv("conv-b"), mdlStatus("late_status"), mdlDigest(mdlCanary)),
	}
}

func (g *mdlGen) scriptFrames() []mdlGenStep {
	a := g.fresh("fr")
	out := []mdlGenStep{
		mdlStep(InCreate, a, mdlProv(ProviderCodex)),
		mdlStep(ObAccepted, a, mdlReq("r0")),
		mdlStep(ObConnected, a), mdlStep(ObConnected, a),
		mdlStep(ObDisconnected, a), mdlStep(ObDisconnected, a), mdlStep(ObConnected, a),
		mdlSend(a, "r1"),
		mdlStep(ObRefused, a, mdlReq("r1"), mdlCode("no_cap")),
		mdlStep(ObAccepted, a, mdlReq("r1"), mdlStatus("ok_status"), mdlDigest(mdlHexA)),
		mdlStep(ObAccepted, a, mdlReq("r1"), mdlStatus("second"), mdlDigest(mdlHexB)),
		mdlStep(ObRefused, a, mdlReq("r1"), mdlDigest(mdlCanary)),
		mdlStep(ObUnknown, a, mdlReq("r1"), mdlDigest("sha256:abc")),
		mdlStep(ObCompleted, a, mdlReq("r1"), mdlDigest(strings.ToUpper(mdlHexA))),
		mdlStep(ObAccepted, a, mdlReq("r-invented"), mdlStatus("Free Text!"), mdlDigest("bad digest!")),
		mdlStep(ObRefused, a, mdlReq("r-invented"), mdlStatus(mdlLongCode), mdlDigest(mdlLongID)),
		mdlSend(a, "r2"),
		mdlStep(ObRefused, a, mdlReq("r2"), mdlCode("BAD CODE")),
		mdlSend(a, "r3"),
		mdlStep(ObUnknown, a, mdlReq("r3"), mdlCode("BAD CODE")),
		mdlStep(ObUnknown, a, mdlReq("r3")),
		mdlStep(ObRefused, a, mdlReq("r3")),
		mdlStep(ObRestart, ""),
		mdlStep(ObDisconnected, a),
		mdlStep(ObConnected, a),
	}
	return out
}

func (g *mdlGen) scriptTurns() []mdlGenStep {
	a, b, c := g.fresh("tn"), g.fresh("tn"), g.fresh("tn")
	out := []mdlGenStep{
		mdlStep(ObTurnBound, "ghost-"+a, mdlReq("r"), mdlTurn("t")),
		mdlClaudeNew(b), mdlSend(b, "r1"), mdlStep(ObTurnBound, b, mdlReq("r1"), mdlTurn("t1")),
	}
	out = append(out, g.codexReady(a)...)
	out = append(out, mdlSend(a, "r1"),
		mdlStep(ObTurnBound, a, mdlReq("other"), mdlTurn("t1")),
		mdlStep(ObTurnBound, a, mdlReq("r1"), mdlTurn("bad turn")),
		mdlStep(ObTurnBound, a, mdlReq("r1")),
		mdlStep(InStop, a),
		mdlStep(ObTurnBound, a, mdlReq("r1"), mdlTurn("t1")),
		mdlStep(ObTurnBound, a, mdlReq("r1"), mdlTurn("t1")),
		mdlStep(ObTurnBound, a, mdlReq("r1"), mdlTurn("t2")),
		mdlStep(InPause, a),
		mdlStep(ObCompleted, a, mdlReq("r1"), mdlTurn("t1"), mdlStatus("interrupted")),
		mdlStep(ObTurnBound, a, mdlReq("r1"), mdlTurn("t3")),
		mdlSend(a, "r2"),
		mdlStep(ObTurnBound, a, mdlReq("r2"), mdlTurn("t4")),
		mdlStep(ObDisconnected, a),
	)
	out = append(out, g.codexReady(c)...)
	out = append(out, mdlSend(c, "r1"), mdlStep(InPause, c),
		mdlStep(InAbandon, c, mdlExpect("r1"), mdlBecause("done with it")),
		mdlStep(InClose, c),
		mdlStep(ObTurnBound, c, mdlReq("other"), mdlTurn("t1")),
		mdlStep(ObTurnBound, c, mdlReq("r1"), mdlTurn("bad turn")),
		mdlStep(ObTurnBound, c, mdlReq("r1"), mdlTurn("t1")),
		mdlStep(ObConnected, c),
	)
	return out
}

func (g *mdlGen) scriptCompleted() []mdlGenStep {
	a, b, c := g.fresh("cp"), g.fresh("cp"), g.fresh("cp")
	out := g.codexReady(a)
	out = append(out,
		mdlStep(ObCompleted, a, mdlStatus("completed")),
		mdlSend(a, "r1"),
		mdlStep(ObCompleted, a, mdlReq("r1"), mdlStatus("completed")),
		mdlStep(ObTurnBound, a, mdlReq("r1"), mdlTurn("t1")),
		mdlStep(ObCompleted, a, mdlReq("r1"), mdlTurn("t9"), mdlStatus("completed")),
		mdlStep(ObCompleted, a, mdlReq("other"), mdlTurn("t1"), mdlStatus("completed")),
		mdlStep(ObCompleted, a, mdlReq("r1"), mdlTurn("t1"), mdlStatus("cancelled")),
	)
	out = append(out, g.codexReady(b)...)
	out = append(out, mdlSend(b, "r1"), mdlStep(ObCompleted, b, mdlStatus("completed")))
	out = append(out, mdlClaudeNew(c), mdlStep(ObConnected, c), mdlSend(c, "r1"), mdlStep(ObCompleted, c, mdlReq("r1"), mdlStatus("failed")),
		mdlSend(c, "r2"), mdlStep(ObCompleted, c, mdlReq("r2"), mdlStatus("completed")),
		mdlStep(InPause, c),
		mdlSend(c, "r3"), mdlStep(ObCompleted, c, mdlReq("r3"), mdlStatus("interrupted")),
		mdlSend(c, "r4"), mdlStep(InPause, c), mdlStep(ObRefused, c, mdlReq("r4")),
	)
	return out
}

func (g *mdlGen) scriptControlOutcome() []mdlGenStep {
	a := g.fresh("co")
	out := g.codexReady(a)
	return append(out,
		mdlStep(ObControlOutcome, a, mdlCtl("halt", "confirmed")),
		mdlStep(ObControlOutcome, a, mdlCtl("pause", "maybe")),
		mdlStep(ObControlOutcome, a, mdlCtl("pause", "confirmed")),
		mdlStep(ObControlOutcome, a, mdlCtl("pause", "rejected")),
		mdlSend(a, "r1"),
		mdlStep(ObControlOutcome, a, mdlCtl("stop", "rejected")),
		mdlStep(ObControlOutcome, a, mdlCtl("stop", "unconfirmed")),
		mdlStep(ObControlOutcome, a, mdlCtl("stop", "confirmed")),
		mdlStep(ObControlOutcome, a, mdlCtl("stop", "unconfirmed")),
		mdlStep(ObRestart, ""),
		mdlStep(ObControlOutcome, a, mdlCtl("stop", "unconfirmed")),
	)
}

func (g *mdlGen) scriptBoundary() []mdlGenStep {
	a, b, c, profile := g.fresh("bd"), g.fresh("bd"), g.fresh("bd"), g.fresh("prof")
	out := []mdlGenStep{
		mdlStep(ObAuthBoundary, "", mdlProv("codexx"), mdlProf(profile)),
		mdlStep(ObAuthBoundary, "", mdlProv(ProviderCodex), mdlProf(profile)),
	}
	out = append(out, g.codexReady(a, mdlProf(profile))...)
	out = append(out, g.codexReady(b, mdlProf(profile))...)
	out = append(out, mdlClaudeNew(c, mdlProf(profile)),
		mdlSend(a, "r1"), mdlStep(ObTurnBound, a, mdlReq("r1"), mdlTurn("t1")),
		mdlSend(b, "r1"),
		mdlSend(c, "r1"),
		mdlStep(ObAuthBoundary, "", mdlProv(ProviderCodex), mdlProf(profile)),
		mdlStep(ObAuthBoundary, "", mdlProv(ProviderCodex), mdlProf(profile)),
		mdlStep(ObAuthBoundary, "", mdlProv(ProviderClaude), mdlProf(profile)),
	)
	return out
}

func (g *mdlGen) scriptQuarantine() []mdlGenStep {
	a, b, c := g.fresh("qr"), g.fresh("qr"), g.fresh("qr")
	out := g.codexReady(a)
	out = append(out, mdlStep(ObQuarantine, "ghost-"+a, mdlCode("x")),
		mdlStep(ObQuarantine, a), mdlStep(ObQuarantine, a, mdlCode("BAD CODE")),
		mdlStep(ObQuarantine, a, mdlCode("first_code")), mdlStep(ObQuarantine, a, mdlCode("second_code")),
		// Section 10 item 13: the code replay would use still overwrites when it arrives as a fact.
		mdlStep(ObQuarantine, a, mdlCode("illegal_fact")), mdlStep(ObQuarantine, a, mdlCode("after_illegal")))
	out = append(out, g.codexReady(b)...)
	out = append(out, mdlSend(b, "r1"), mdlStep(ObQuarantine, b, mdlCode("q")), mdlStep(ObTurnBound, b, mdlReq("r1"), mdlTurn("t1")))
	out = append(out, mdlClaudeNew(c), mdlSend(c, "r1"), mdlStep(ObQuarantine, c, mdlCode("q")), mdlStep(InStop, c))
	return out
}

func (g *mdlGen) scriptRestart() []mdlGenStep {
	a := g.fresh("rs")
	out := g.codexReady(a)
	return append(out, mdlSend(a, "r1"), mdlStep(ObTurnBound, a, mdlReq("r1"), mdlTurn("t1")),
		mdlStep(ObRestart, ""), mdlStep(ObRestart, ""),
		mdlRawFact("legal", Fact{Kind: FactProcessRestarted}),
		mdlStep(ObRestart, ""),
		mdlStep(InAbandon, a, mdlExpect("r1"), mdlBecause("after restart")),
		mdlStep(InClose, a),
		mdlStep(ObRestart, ""),
	)
}

func (g *mdlGen) scriptRaw() []mdlGenStep {
	a, b, c, d, l := g.fresh("rw"), g.fresh("rw"), g.fresh("rw"), g.fresh("rw"), g.fresh("lg")
	revised := func(rev uint64) mdlGenStep {
		gs := mdlRawFact("illegal", Fact{Kind: FactProviderConnected, SessionID: d})
		gs.keepRev = true
		gs.raw.SessionRevision = rev
		return gs
	}
	staleRev, zeroRev, futureRev := revised(1), revised(0), revised(9999)
	rawBadAt := mdlRawFact("illegal", Fact{Kind: FactProviderConnected, SessionID: d})
	rawBadAt.in.At, rawBadAt.atSet = "now", true
	rawBadCalendar := mdlRawFact("illegal", Fact{Kind: FactProviderConnected, SessionID: d})
	rawBadCalendar.in.At, rawBadCalendar.atSet = "2026-13-45T12:00:00.000000000Z", true
	schemaTwo, schemaZero := 2, 0
	wrongSchema := mdlRawFact("bad_schema", Fact{Kind: FactProviderConnected, SessionID: a})
	wrongSchema.schema = &schemaTwo
	zeroSchema := mdlRawFact("bad_schema", Fact{Kind: FactProviderConnected, SessionID: a})
	zeroSchema.schema = &schemaZero
	seqEqual := mdlRawFact("seq_equal", Fact{Kind: FactProviderConnected, SessionID: a})
	seqEqual.seqMode = 1
	seqLower := mdlRawFact("seq_lower", Fact{Kind: FactProviderConnected, SessionID: a})
	seqLower.seqMode = 2
	gap := mdlRawFact("gap", Fact{Kind: FactProviderConnected, SessionID: a})
	gap.seqMode = 3
	revTwo := mdlRawFact("illegal", Fact{Kind: FactSessionCreated, SessionID: c, Provider: ProviderCodex})
	revTwo.keepRev = true
	revTwo.raw.SessionRevision = 2
	legacyRevTwo := mdlRawFact("illegal", Fact{Kind: FactLegacyImported, SessionID: l + "-x", Provider: ProviderCodex})
	legacyRevTwo.keepRev = true
	legacyRevTwo.raw.SessionRevision = 2

	legacy := func(suffix string, r Receipt, request string) mdlGenStep {
		return mdlRawFact("legacy", Fact{Kind: FactLegacyImported, SessionID: l + suffix, Provider: ProviderCodex, ProfileID: "p1", CWD: "/old", ProviderID: "conv-old", RuntimeIdentity: mdlRtOne, Receipt: r, RequestID: request, Reason: map[Receipt]string{ReceiptAbandoned: "imported discard"}[r]})
	}
	out := []mdlGenStep{
		revTwo,
		mdlRawFact("illegal", Fact{Kind: FactSessionCreated, SessionID: c, Provider: "codexx"}),
		mdlRawFact("legal", Fact{Kind: FactSessionCreated, SessionID: a, Provider: ProviderCodex, ProfileID: "p1", CWD: "/raw", RuntimeIdentity: mdlRtOne}),
		mdlRawFact("illegal", Fact{Kind: FactSessionCreated, SessionID: a, Provider: ProviderCodex}),
		wrongSchema, zeroSchema, seqEqual, seqLower, gap,
		mdlRawFact("reserved", Fact{Kind: ReservedFactKinds[0], SessionID: a}),
		mdlRawFact("unknown_kind", Fact{Kind: "NotAKind", SessionID: a}),
		mdlRawFact("repeat", Fact{Kind: FactProviderConnected, SessionID: a}),
		mdlRawFact("illegal", Fact{Kind: FactProviderAccepted, SessionID: a}),
		mdlRawFact("legal", Fact{Kind: FactConversationBound, SessionID: a, ProviderID: "conv-raw"}),
		mdlRawFact("repeat", Fact{Kind: FactConversationBound, SessionID: a, ProviderID: "conv-raw"}),
		mdlRawFact("illegal", Fact{Kind: FactConversationBound, SessionID: a}),
		mdlRawFact("illegal", Fact{Kind: FactRuntimeIdentityBound, SessionID: a, RuntimeIdentity: mdlRtTwo}),
		mdlRawFact("repeat", Fact{Kind: FactRuntimeIdentityBound, SessionID: a, RuntimeIdentity: mdlRtOne}),
		mdlRawFact("illegal", Fact{Kind: FactRequestIntended, SessionID: a}),
		mdlRawFact("legal", Fact{Kind: FactRequestIntended, SessionID: a, RequestID: "r1"}),
		mdlRawFact("illegal", Fact{Kind: FactRequestIntended, SessionID: a, RequestID: "r2"}),
		mdlRawFact("illegal", Fact{Kind: FactCwdChanged, SessionID: a, CWD: "/no"}),
		mdlRawFact("illegal", Fact{Kind: FactSessionClosed, SessionID: a}),
		mdlRawFact("illegal", Fact{Kind: FactAbandoned, SessionID: a, RequestID: "wrong", Reason: "x"}),
		mdlRawFact("illegal", Fact{Kind: FactProviderCompleted, SessionID: a, RequestID: "r1", Status: "bogus"}),
		mdlRawFact("illegal", Fact{Kind: FactProviderAccepted, SessionID: a, RequestID: "other"}),
		mdlRawFact("illegal", Fact{Kind: FactTurnBound, SessionID: a, RequestID: "r1"}),
		mdlRawFact("legal", Fact{Kind: FactTurnBound, SessionID: a, RequestID: "r1", TurnID: "t1"}),
		mdlRawFact("legal", Fact{Kind: FactProviderAccepted, SessionID: a, RequestID: "r1"}),
		mdlRawFact("receipt_transition", Fact{Kind: FactProviderAccepted, SessionID: a, RequestID: "r1"}),
		mdlRawFact("legal", Fact{Kind: FactProviderCompleted, SessionID: a, RequestID: "r1", Status: "failed", TurnID: "t1"}),
		mdlRawFact("receipt_transition", Fact{Kind: FactProviderCompleted, SessionID: a, RequestID: "r1", Status: "failed"}),
		mdlRawFact("receipt_transition", Fact{Kind: FactProviderRefused, SessionID: a, RequestID: "r1"}),
		mdlRawFact("receipt_transition", Fact{Kind: FactOutcomeUnknown, SessionID: a, RequestID: "r1"}),
		mdlRawFact("illegal", Fact{Kind: FactRequestIntended, SessionID: a, RequestID: "r1"}),
		mdlRawFact("legal", Fact{Kind: FactCwdChanged, SessionID: a, CWD: "/after"}),
		mdlRawFact("legal", Fact{Kind: FactControlRequested, SessionID: a, Control: "pause"}),
		mdlRawFact("legal", Fact{Kind: FactControlOutcome, SessionID: a, Control: "pause", Outcome: "confirmed"}),
		mdlRawFact("illegal", Fact{Kind: FactSessionQuarantined, SessionID: a}),
		mdlRawFact("legal", Fact{Kind: FactLateFrameObserved, SessionID: a, RequestID: "r1", LateKind: "final", Status: "ok", Digest: mdlHexA}),
		mdlRawFact("illegal", Fact{Kind: FactProviderConnected, SessionID: "ghost-" + a}),
		mdlRawFact("legal", Fact{Kind: FactAuthBoundaryCrossed, SessionID: a}),
		mdlRawFact("illegal", Fact{Kind: FactProviderConnected, SessionID: a}),
		mdlRawFact("illegal", Fact{Kind: FactProviderDisconnected, SessionID: a}),
		mdlRawFact("illegal", Fact{Kind: FactAuthBoundaryCrossed, SessionID: a}),
		mdlRawFact("illegal", Fact{Kind: FactCwdChanged, SessionID: a, CWD: "/no"}),
		mdlRawFact("illegal", Fact{Kind: FactControlRequested, SessionID: a, Control: "stop"}),
		mdlRawFact("legal", Fact{Kind: FactSessionClosed, SessionID: a}),
		mdlRawFact("illegal", Fact{Kind: FactSessionClosed, SessionID: a}),
		mdlRawFact("illegal", Fact{Kind: FactLateFrameObserved, SessionID: a, LateKind: "final"}),
		mdlRawFact("legal", Fact{Kind: FactSessionCreated, SessionID: b, Provider: ProviderClaude, RuntimeIdentity: mdlRtOne}),
		mdlRawFact("legal", Fact{Kind: FactRequestIntended, SessionID: b, RequestID: "r1"}),
		mdlRawFact("illegal", Fact{Kind: FactTurnBound, SessionID: b, RequestID: "r1", TurnID: "t1"}),
		mdlRawFact("legal", Fact{Kind: FactOutcomeUnknown, SessionID: b, RequestID: "r1"}),
		mdlRawFact("receipt_transition", Fact{Kind: FactProviderCompleted, SessionID: b, RequestID: "r1", Status: "completed"}),
		mdlRawFact("legal", Fact{Kind: FactSessionCreated, SessionID: d, Provider: ProviderCodex, RuntimeIdentity: mdlRtOne}),
		// SPEC-AMBIGUOUS: 34
		mdlRawFact("illegal", Fact{Kind: FactTurnBound, SessionID: d, TurnID: "t0"}),
		mdlRawFact("legal", Fact{Kind: FactRequestIntended, SessionID: d, RequestID: "r1"}),
		mdlRawFact("legal", Fact{Kind: FactTurnBound, SessionID: d, RequestID: "r1", TurnID: "t1"}),
		mdlRawFact("repeat", Fact{Kind: FactTurnBound, SessionID: d, RequestID: "r1", TurnID: "t1"}),
		mdlRawFact("legal", Fact{Kind: FactTurnBound, SessionID: d, RequestID: "r1", TurnID: "t2"}),
		// SPEC-AMBIGUOUS: 38
		mdlRawFact("legal", Fact{Kind: FactLateFrameObserved, SessionID: d, RequestID: "r1", LateKind: "accepted", Status: "first", Digest: mdlHexA}),
		mdlRawFact("illegal", Fact{Kind: FactLateFrameObserved, SessionID: d, RequestID: "r1", LateKind: "accepted", Status: "second", Digest: mdlHexB}),
		mdlRawFact("legal", Fact{Kind: FactLateFrameObserved, SessionID: d, RequestID: "r-unknown", LateKind: "accepted"}),
		mdlRawFact("illegal", Fact{Kind: FactLateFrameObserved, SessionID: d, RequestID: "r1", LateKind: "not_a_kind"}),
		mdlRawFact("illegal", Fact{Kind: FactLateFrameObserved, SessionID: d, RequestID: "r1", LateKind: "final", Status: "Free Text!"}),
		mdlRawFact("illegal", Fact{Kind: FactLateFrameObserved, SessionID: d, RequestID: "r1", LateKind: "final", Digest: "bad digest!"}),
		mdlRawFact("legal", Fact{Kind: FactProviderCompleted, SessionID: d, RequestID: "r1", Status: "completed", TurnID: "t2"}),
		mdlRawFact("legal", Fact{Kind: FactTurnBound, SessionID: d, RequestID: "r1", TurnID: "t3"}),
		mdlRawFact("legal", Fact{Kind: FactConversationBound, SessionID: d, ProviderID: "conv-1"}),
		mdlRawFact("illegal", Fact{Kind: FactConversationBound, SessionID: d, ProviderID: "conv-2"}),
		staleRev, zeroRev, futureRev, rawBadAt, rawBadCalendar,
		mdlRawFact("illegal", Fact{Kind: FactProviderConnected, SessionID: d, ProfileID: "bad id!"}),
		mdlRawFact("illegal", Fact{Kind: FactProviderConnected, SessionID: d, Reason: "not on this kind"}),
		mdlRawFact("illegal", Fact{Kind: FactControlRequested, SessionID: d, Control: "halt"}),
		mdlRawFact("illegal", Fact{Kind: FactControlOutcome, SessionID: d, Control: "stop", Outcome: "maybe"}),
		mdlRawFact("illegal", Fact{Kind: FactCwdChanged, SessionID: d, CWD: "a\nb"}),
		mdlRawFact("illegal", Fact{Kind: FactCwdChanged, SessionID: d}),
		mdlRawFact("illegal", Fact{Kind: FactRequestIntended, SessionID: d, RequestID: "bad req!"}),
		mdlRawFact("illegal", Fact{Kind: FactRuntimeIdentityBound, SessionID: d}),
		mdlRawFact("illegal", Fact{Kind: FactSessionCreated, SessionID: "bad id!", Provider: ProviderCodex}),
		mdlRawFact("illegal", Fact{Kind: FactSessionCreated, Provider: ProviderCodex}),
		mdlRawFact("legacy", Fact{Kind: FactLegacyImported, SessionID: l + "-noprovider", ProfileID: "p1", CWD: "/old"}),
		legacy("-none", ReceiptNone, ""),
		legacy("-final", ReceiptFinal, "r1"),
		legacy("-rejected", ReceiptRejected, "r1"),
		legacy("-unknown", ReceiptUnknown, "r1"),
		legacy("-abandoned", ReceiptAbandoned, "r1"),
		legacy("-intent", ReceiptIntent, "r1"),
		legacy("-accepted", ReceiptAccepted, "r1"),
		legacy("-norequest", ReceiptFinal, ""),
		legacy("-norec", ReceiptNone, "r1"),
		legacy("-none", ReceiptNone, ""),
		legacyRevTwo,
		mdlRawFact("legacy", Fact{Kind: FactLegacyImportCompleted}),
		mdlRawFact("legacy", Fact{Kind: FactLegacyImportCompleted, Digest: "sha256:legacy"}),
		mdlRawFact("legacy", Fact{Kind: FactLegacyImportCompleted, Digest: "sha256:again"}),
		mdlStep(ObConnected, l+"-none"),
		mdlStep(InClose, l+"-unknown"),
		mdlStep(InAbandon, l+"-unknown", mdlExpect("r1"), mdlBecause("discard imported")),
		mdlStep(InClose, l+"-unknown"),
	}
	return out
}

// scriptFields covers section 10 items 27, 28, 30, 31 and 32. The late and control facts
// in it are refused for their extra field alone.
func (g *mdlGen) scriptFields() []mdlGenStep {
	a, b, c, e, l := g.fresh("fd"), g.fresh("fd"), g.fresh("fd"), g.fresh("fd"), g.fresh("lf")
	bare := func(tag string, f Fact) mdlGenStep {
		gs := mdlRawFact(tag, f)
		gs.keepRev = true
		return gs
	}
	long := strings.Repeat("r", 501)
	legacyReason := func(tag, suffix string, r Receipt, reason string) mdlGenStep {
		return mdlRawFact(tag, Fact{Kind: FactLegacyImported, SessionID: l + suffix, Provider: ProviderClaude, Receipt: r, RequestID: "r1", Reason: reason})
	}
	padding := mdlStep(InAbandon, e, mdlExpect("r1"), mdlBecause("anything"))
	padding.redact = 3
	return []mdlGenStep{
		mdlRawFact("legal", Fact{Kind: FactSessionCreated, SessionID: a, Provider: ProviderCodex, RuntimeIdentity: mdlRtOne}),
		// SPEC-AMBIGUOUS: 30
		mdlRawFact("legal", Fact{Kind: FactProviderConnected, SessionID: a, TaskID: "task-1", ObjectiveHash: "sha256:abc", Generation: 3, InputRevision: 4, Passes: map[string]string{"any key": "any value!"}}),
		mdlRawFact("illegal", Fact{Kind: FactProviderConnected, SessionID: a, TaskID: "bad task!"}),
		mdlRawFact("illegal", Fact{Kind: FactProviderConnected, SessionID: a, ObjectiveHash: "bad hash!"}),
		// SPEC-AMBIGUOUS: 27
		mdlRawFact("illegal", Fact{Kind: FactProviderConnected, SessionID: a, State: "open"}),
		mdlRawFact("illegal", Fact{Kind: FactProviderConnected, SessionID: a, Status: "open"}),
		mdlRawFact("illegal", Fact{Kind: FactProviderConnected, SessionID: a, Control: "stop"}),
		mdlRawFact("illegal", Fact{Kind: FactProviderConnected, SessionID: a, Outcome: "confirmed"}),
		mdlRawFact("illegal", Fact{Kind: FactProviderConnected, SessionID: a, LateKind: "final"}),
		mdlRawFact("illegal", Fact{Kind: FactProviderConnected, SessionID: a, Receipt: "bogus"}),
		mdlRawFact("illegal", Fact{Kind: FactControlRequested, SessionID: a, Control: "stop", Outcome: "confirmed"}),
		mdlRawFact("illegal", Fact{Kind: FactControlRequested, SessionID: a, Control: "stop", Status: "open"}),
		mdlRawFact("illegal", Fact{Kind: FactControlOutcome, SessionID: a, Control: "stop", Outcome: "confirmed", LateKind: "final"}),
		mdlRawFact("illegal", Fact{Kind: FactLateFrameObserved, SessionID: a, LateKind: "final", Control: "stop"}),
		mdlRawFact("illegal", Fact{Kind: FactLateFrameObserved, SessionID: a, LateKind: "final", State: "open"}),
		mdlRawFact("illegal", Fact{Kind: FactSessionCreated, SessionID: l + "-state", Provider: ProviderCodex, State: "open"}),
		bare("illegal", Fact{Kind: FactProcessRestarted, Status: "open"}),
		mdlRawFact("legal", Fact{Kind: FactLegacyImported, SessionID: l + "-stateok", Provider: ProviderCodex, State: "open"}),
		mdlRawFact("illegal", Fact{Kind: FactLegacyImported, SessionID: l + "-statebad", Provider: ProviderCodex, State: "Bad State"}),
		mdlRawFact("illegal", Fact{Kind: FactLegacyImported, SessionID: l + "-statectl", Provider: ProviderCodex, Control: "stop"}),
		mdlRawFact("illegal", Fact{Kind: FactLegacyImported, SessionID: l + "-recbad", Provider: ProviderCodex, Receipt: "bogus", RequestID: "r1"}),
		// SPEC-AMBIGUOUS: 27
		mdlRawFact("legal", Fact{Kind: FactProviderDisconnected, SessionID: a, Provider: ProviderClaude, ProviderID: "conv-x", ProfileID: "p9", RequestID: "r-other", TurnID: "t-other", Digest: "d9", RuntimeIdentity: mdlRtTwo, ReasonCode: "some_code", Receipt: ReceiptFinal}),
		// SPEC-AMBIGUOUS: 28
		mdlRawFact("illegal", Fact{Kind: FactProviderConnected, SessionID: a, Provider: "codexx"}),
		mdlRawFact("illegal", Fact{Kind: FactLegacyImported, SessionID: l + "-badprov", Provider: "codexx"}),
		mdlRawFact("legal", Fact{Kind: FactSessionCreated, SessionID: b, Provider: ProviderClaude}),
		// SPEC-AMBIGUOUS: 31
		mdlRawFact("illegal", Fact{Kind: FactAbandoned, SessionID: b}),
		mdlRawFact("illegal", Fact{Kind: FactAbandoned, SessionID: b, Reason: long}),
		mdlRawFact("illegal", Fact{Kind: FactAbandoned, SessionID: b, Reason: "bad\xff"}),
		mdlRawFact("legal", Fact{Kind: FactAbandoned, SessionID: b, Reason: "  not trimmed here\n"}),
		legacyReason("illegal", "-long", ReceiptAbandoned, long),
		legacyReason("illegal", "-utf8", ReceiptAbandoned, "bad\xff"),
		legacyReason("legal", "-limit", ReceiptAbandoned, strings.Repeat("r", 500)),
		legacyReason("legal", "-noreason", ReceiptAbandoned, ""),
		legacyReason("legal", "-final", ReceiptFinal, "reason ignored here"),
		mdlStep(InCreate, c, mdlProv(ProviderCodex)),
		mdlStep(ObQuarantine, c, mdlCode("q")),
		mdlStep(InAbandon, c, mdlBecause("bad\xff")),
		mdlStep(InAbandon, c, mdlBecause("\u00a0\u2003")),
		mdlStep(InAbandon, c, mdlBecause("\u00a0kept\u2003")),
		mdlClaudeNew(e), mdlSend(e, "r1"), mdlStep(ObQuarantine, e, mdlCode("q")), padding,
		// SPEC-AMBIGUOUS: 30
		bare("illegal", Fact{Kind: FactProcessRestarted, SessionID: "bad id!"}),
		bare("legal", Fact{Kind: FactProcessRestarted, SessionID: a, SessionRevision: 7}),
		bare("legal", Fact{Kind: FactProcessRestarted, SessionRevision: 5}),
		bare("legal", Fact{Kind: FactProcessRestarted, SessionID: "ghost-" + a}),
	}
}

// scriptReach puts the model in states that mutation of the table rows showed were missed.
// It holds no restart, so next can repeat it on fresh sessions.
func (g *mdlGen) scriptReach() []mdlGenStep {
	a, b, c, d, e, f, h := g.fresh("rc"), g.fresh("rc"), g.fresh("rc"), g.fresh("rc"), g.fresh("rc"), g.fresh("rc"), g.fresh("rc")
	outcome := func(sid, control, result string) mdlGenStep {
		return mdlRawFact("legal", Fact{Kind: FactControlOutcome, SessionID: sid, Control: control, Outcome: result})
	}
	// An interrupt still due survives OutcomeUnknown, and a later turn-bound fires it.
	out := g.codexReady(a)
	out = append(out, mdlSend(a, "r1"), mdlStep(InPause, a), mdlStep(ObUnknown, a, mdlReq("r1")), mdlStep(ObTurnBound, a, mdlReq("r1"), mdlTurn("t1")))
	// Abandoned, with PauseUnconfirmed true going in, then false going in.
	out = append(out, g.codexReady(b)...)
	out = append(out, mdlSend(b, "r1"), mdlStep(ObControlOutcome, b, mdlCtl("stop", "rejected")), mdlStep(InPause, b),
		mdlStep(InAbandon, b, mdlExpect("r1"), mdlBecause("discard it")),
		outcome(b, "stop", "rejected"), outcome(b, "pause", "unconfirmed"), outcome(b, "stop", "rejected"))
	// Resolved receipts: final, rejected and none.
	out = append(out, mdlClaudeNew(c), mdlSend(c, "r1"), mdlStep(ObCompleted, c, mdlReq("r1"), mdlStatus("completed")),
		outcome(c, "stop", "rejected"), outcome(c, "pause", "unconfirmed"))
	out = append(out, mdlClaudeNew(d), mdlSend(d, "r1"), mdlStep(ObRefused, d, mdlReq("r1")),
		outcome(d, "stop", "rejected"), outcome(d, "pause", "unconfirmed"))
	out = append(out, mdlClaudeNew(e), outcome(e, "stop", "rejected"), outcome(e, "pause", "unconfirmed"))
	// Unresolved, so the same outcomes do set it, and confirmed clears it.
	out = append(out, mdlClaudeNew(f), mdlSend(f, "r1"), mdlStep(ObUnknown, f, mdlReq("r1")),
		outcome(f, "stop", "rejected"), outcome(f, "stop", "confirmed"), outcome(f, "pause", "unconfirmed"))
	// A turn bound on a final receipt is cleared by the next send.
	out = append(out, g.codexReady(h)...)
	return append(out, mdlSend(h, "r1"), mdlStep(ObTurnBound, h, mdlReq("r1"), mdlTurn("t1")),
		mdlStep(ObCompleted, h, mdlReq("r1"), mdlTurn("t1"), mdlStatus("completed")),
		mdlRawFact("legal", Fact{Kind: FactTurnBound, SessionID: h, RequestID: "r1", TurnID: "t2"}),
		mdlSend(h, "r2"))
}

func (g *mdlGen) scriptManySessions() []mdlGenStep {
	var out []mdlGenStep
	var idle []string
	for i := 0; i < 30; i++ {
		id := g.fresh("ms")
		idle = append(idle, id)
		out = append(out, mdlClaudeNew(id))
	}
	out = append(out, mdlStep(ObRestart, ""), mdlStep(ObRestart, ""), mdlStep(ObQuarantine, idle[0], mdlCode("q")), mdlStep(InSend, idle[1], mdlReq("r1")))
	for i := 0; i < 26; i++ {
		id := g.fresh("mu")
		out = append(out, mdlClaudeNew(id), mdlSend(id, "r1"))
	}
	for i := 0; i < 3; i++ {
		out = append(out, mdlStep(InCreate, g.fresh("mi"), mdlProv(ProviderCodex)))
	}
	return append(out, mdlStep(ObRestart, ""), mdlStep(ObConnected, idle[2]), mdlStep(ObRestart, ""))
}

// scriptTrim drives one session past the 256-request limit, then revisits the oldest request.
func (g *mdlGen) scriptTrim() []mdlGenStep {
	a := g.fresh("tr")
	out := []mdlGenStep{mdlClaudeNew(a)}
	for i := 0; i < 258; i++ {
		r := "tr-" + strconv.Itoa(i)
		out = append(out, mdlSend(a, r), mdlStep(ObCompleted, a, mdlReq(r), mdlStatus("completed")))
	}
	return append(out,
		mdlStep(ObAccepted, a, mdlReq("tr-0"), mdlStatus("late"), mdlDigest(mdlHexB)),
		mdlStep(ObAccepted, a, mdlReq("tr-300"), mdlStatus("late")),
		mdlSend(a, "tr-200"),
		mdlSend(a, "tr-0"),
		mdlStep(ObCompleted, a, mdlReq("tr-0"), mdlStatus("completed")),
		mdlStep(ObRestart, ""),
	)
}

func (g *mdlGen) regularScripts() []func() []mdlGenStep {
	return []func() []mdlGenStep{
		g.scriptCreateAndAuth, g.scriptSend, g.scriptControl, g.scriptCWD, g.scriptAbandon,
		g.scriptConversation, g.scriptFrames, g.scriptTurns, g.scriptCompleted,
		g.scriptControlOutcome, g.scriptBoundary, g.scriptQuarantine, g.scriptRestart, g.scriptRaw, g.scriptFields, g.scriptReach,
	}
}

const mdlTourEvery = 100 // Seeds on this multiple run every script, including the long trim.

func mdlTourSeed(seed int64) bool { return seed%mdlTourEvery == 0 }

func mdlNewGen(seed int64) *mdlGen {
	g := &mdlGen{rng: rand.New(rand.NewSource(seed))}
	g.mode = int(((seed % 3) + 3) % 3)
	scripts := g.regularScripts()
	g.rng.Shuffle(len(scripts), func(i, j int) { scripts[i], scripts[j] = scripts[j], scripts[i] })
	if mdlTourSeed(seed) {
		g.mode = 1
		scripts = append(scripts, g.scriptManySessions, g.scriptTrim)
		for _, build := range scripts {
			g.queue = append(g.queue, build()...)
		}
		return g
	}
	if seed%7 == 3 {
		scripts = append([]func() []mdlGenStep{g.scriptManySessions}, scripts...)
	}
	g.pending = scripts
	return g
}

// Comparison. Both walk the real struct with reflection, so a new field fails loudly
// instead of going uncompared.

func mdlSameValue(want, got any) bool {
	w, g := reflect.ValueOf(want), reflect.ValueOf(got)
	if w.IsValid() && g.IsValid() && w.Kind() == g.Kind() && (w.Kind() == reflect.Map || w.Kind() == reflect.Slice) && w.Len() == 0 && g.Len() == 0 {
		// SPEC-AMBIGUOUS: 23
		return true
	}
	return reflect.DeepEqual(want, got)
}

func (s *mdlMSession) fieldValues() map[string]any {
	return map[string]any{
		"ID": s.id, "Provider": s.provider, "ProviderID": s.conversation, "ProfileID": s.profile, "CWD": s.mdlCwd,
		"RuntimeIdentity": s.mdlIdentity, "Quarantine": s.quarantine, "LastRequest": s.lastReq,
		"FinalStatus": s.finalStatus, "LastRefusal": s.lastRefusal, "TurnID": s.mdlTurn,
		"ConversationStarted": s.started, "Connected": s.connected, "ReadOnly": s.readOnly, "Closed": s.closed,
		"Hidden": s.hidden, "ProviderFinal": s.providerFinal, "PendingInterrupt": s.pending, "Paused": s.paused,
		"PauseUnconfirmed": s.unconfirmed, "Abandoned": s.abandoned, "Revision": s.revision, "ControlEpoch": s.epoch,
		"Requests": s.receipts, "RequestOrder": s.order, "Evidence": s.evidence,
	}
}

func mdlCompareSession(s *mdlMSession, got *Session) string {
	if got == nil {
		return "session " + s.id + " is nil"
	}
	want := s.fieldValues()
	v := reflect.ValueOf(*got)
	for i := 0; i < v.NumField(); i++ {
		name := v.Type().Field(i).Name
		expected, known := want[name]
		if !known {
			return "Session field " + name + " has no model value"
		}
		actual := v.Field(i).Interface()
		if !mdlSameValue(expected, actual) {
			return fmt.Sprintf("session %s field %s: model %#v, kernel %#v", s.id, name, expected, actual)
		}
	}
	return ""
}

func mdlCompareProjection(m *mdlModel, p Projection) string {
	v := reflect.ValueOf(p)
	for i := 0; i < v.NumField(); i++ {
		name := v.Type().Field(i).Name
		var expected any
		switch name {
		case "Sessions":
			continue
		case "Order":
			expected = m.order
		case "LastSeq":
			expected = m.lastSeq
		case "LastKind":
			expected = m.lastKind
		case "LegacyImported":
			expected = m.legacy
		default:
			return "Projection field " + name + " has no model value"
		}
		if actual := v.Field(i).Interface(); !mdlSameValue(expected, actual) {
			return fmt.Sprintf("projection %s: model %#v, kernel %#v", name, expected, actual)
		}
	}
	if len(p.Sessions) != len(m.sessions) {
		return fmt.Sprintf("projection has %d sessions, model %d", len(p.Sessions), len(m.sessions))
	}
	var visible []string
	for _, id := range m.order {
		s := m.sessions[id]
		got := p.Sessions[id]
		if msg := mdlCompareSession(s, got); msg != "" {
			return msg
		}
		want, _ := s.mdlStatus()
		if actual := Status(got); actual != want {
			return fmt.Sprintf("session %s Status: model %q, kernel %q", id, want, actual)
		}
		if !s.closed && !s.hidden {
			visible = append(visible, id)
		}
	}
	vis := VisibleSessions(p)
	var visIDs []string
	for _, s := range vis {
		visIDs = append(visIDs, s.ID)
	}
	if !mdlSameValue(visible, visIDs) {
		return fmt.Sprintf("VisibleSessions: model %v, kernel %v", visible, visIDs)
	}
	for _, s := range vis {
		if msg := mdlCompareSession(m.sessions[s.ID], s); msg != "" {
			return "VisibleSessions: " + msg
		}
	}
	return ""
}

func mdlStringField(f Fact, name string) string {
	return reflect.ValueOf(f).FieldByName(name).String()
}

// compareFact checks a decided fact against the prediction.
// SPEC-AMBIGUOUS: 6
// SPEC-AMBIGUOUS: 27
func mdlCompareFact(want mdlWantFact, got Fact) string {
	if want.Kind != got.Kind || want.SessionID != got.SessionID || want.At != got.At {
		return fmt.Sprintf("fact identity: want %s/%s/%s, got %s/%s/%s", want.Kind, want.SessionID, want.At, got.Kind, got.SessionID, got.At)
	}
	if want.Seq != got.Seq || want.SessionRevision != got.SessionRevision || got.SchemaVersion != SchemaVersion {
		return fmt.Sprintf("%s stamps: want seq %d rev %d schema %d, got seq %d rev %d schema %d", got.Kind, want.Seq, want.SessionRevision, SchemaVersion, got.Seq, got.SessionRevision, got.SchemaVersion)
	}
	// Every field, not only the named ones: an unnamed field must be empty (zero) on a
	// decided fact. SchemaVersion is stamped by Decide, so the prediction takes it too.
	expected := want.Fact
	expected.SchemaVersion = SchemaVersion
	ev, gv := reflect.ValueOf(expected), reflect.ValueOf(got)
	for i := 0; i < ev.NumField(); i++ {
		if w, g := ev.Field(i).Interface(), gv.Field(i).Interface(); !mdlSameValue(w, g) {
			return fmt.Sprintf("%s field %s: want %#v, got %#v", got.Kind, ev.Type().Field(i).Name, w, g)
		}
	}
	// Section 7: nothing Decide returns can be refused by Reduce.
	if !mdlFactInShape(got) {
		return fmt.Sprintf("%s breaks a shape or enum-field rule: %+v", got.Kind, got)
	}
	return ""
}

// modelReplay folds a log by section 8, reporting which sessions it quarantined.
func mdlModelReplay(facts []Fact, cov map[string]int) (m *mdlModel, reported []string, unreadable bool) {
	m = mdlNewModel(cov)
	seen := map[string]bool{}        // Reported, at most once each.
	quarantined := map[string]bool{} // Took the first-illegal row while existing.
	for _, f := range facts {
		v := m.mdlVerdict(f)
		if v == mdlVUnreadable {
			switch {
			case f.SchemaVersion != SchemaVersion:
				m.hit("t8.unreadable.schema")
			case f.Seq <= m.lastSeq:
				m.hit("t8.unreadable.seq")
			default:
				m.hit("t8.unreadable.kind")
			}
			return mdlNewModel(cov), nil, true
		}
		s := m.sessions[f.SessionID]
		if v == mdlVLegal {
			if s != nil && s.quarantine != "" {
				m.hit("t8.later_applied")
			}
			if s == nil && seen[f.SessionID] {
				// Section 10 item 18: created after being reported. It stays reported once.
				m.hit("t8.ghost_then_created")
			}
			m.apply(f)
			continue
		}
		// Section 10 item 35: an illegal global fact is unreadable whatever SessionID it carries.
		if f.SessionID == "" || f.Kind == FactProcessRestarted || f.Kind == FactLegacyImportCompleted {
			if f.SessionID != "" {
				if m.sessions[f.SessionID] != nil {
					m.hit("t8.unreadable.global_live_session")
				} else {
					m.hit("t8.unreadable.global_ghost_session")
				}
			}
			if mdlContains(ReservedFactKinds, f.Kind) {
				m.hit("t8.unreadable.reserved_no_session")
			} else {
				m.hit("t8.unreadable.global")
			}
			return mdlNewModel(cov), nil, true
		}
		m.lastSeq, m.lastKind = f.Seq, f.Kind
		if mdlContains(ReservedFactKinds, f.Kind) {
			m.hit("t8.reserved_follows_rows")
		}
		if s == nil {
			// SPEC-AMBIGUOUS: 18
			if !seen[f.SessionID] {
				m.hit("t8.ghost")
				seen[f.SessionID] = true
				reported = append(reported, f.SessionID)
			} else {
				m.hit("t8.ghost_once")
			}
			continue
		}
		// SPEC-AMBIGUOUS: 29
		if quarantined[s.id] {
			m.hit("t8.later_skipped")
			continue
		}
		quarantined[s.id] = true
		if seen[s.id] {
			m.hit("t8.ghost_created_quarantined")
		} else {
			seen[s.id] = true
			reported = append(reported, s.id)
		}
		m.hit("t8.first")
		if s.closed {
			// SPEC-AMBIGUOUS: 17
			m.note(17)
			m.hit("t8.first_on_closed")
		}
		if s.quarantine != "" {
			// SPEC-AMBIGUOUS: 16
			m.note(16)
			m.hit("t8.first_on_quarantined")
		} else {
			s.quarantine = "illegal_fact"
		}
		s.pending = s.pending || s.owed()
		s.readOnly, s.connected, s.hidden = true, false, false
		s.epoch++
	}
	return m, reported, false
}

type mdlReplayVariant struct {
	name  string
	facts []Fact
}

func mdlRenumbered(facts []Fact) []Fact {
	out := make([]Fact, len(facts))
	for i, f := range facts {
		f.Seq = uint64(i + 1)
		out[i] = f
	}
	return out
}

// buildReplayVariants corrupts a good log by inserting facts section 8 has rows for. With
// item 10, facts after a skipped one can go stale, so stamps come from folding the log so
// far, and one variant keeps the target's later facts to exercise that cascade.
func mdlBuildReplayVariants(m *mdlModel, log []Fact, rng *rand.Rand) []mdlReplayVariant {
	if len(log) == 0 {
		return nil
	}
	reserved := ReservedFactKinds[0]
	at := "2026-11-04T00:00:00.000000000Z"
	insert := func(pos int, extra ...Fact) []Fact {
		out := append([]Fact(nil), log[:pos]...)
		out = append(out, extra...)
		return mdlRenumbered(append(out, log[pos:]...))
	}
	base := func(kind FactKind, sid string) Fact {
		return Fact{Kind: kind, SessionID: sid, SchemaVersion: SchemaVersion, At: at}
	}
	pos := rng.Intn(len(log) + 1)
	sid := log[0].SessionID
	if len(m.order) > 0 {
		sid = m.order[rng.Intn(len(m.order))]
	}
	badSchema := base(FactProviderConnected, sid)
	badSchema.SchemaVersion = SchemaVersion + 1
	seqRepeat := insert(0)
	if len(seqRepeat) > 1 {
		i := 1 + rng.Intn(len(seqRepeat)-1)
		seqRepeat[i].Seq = seqRepeat[i-1].Seq
	}
	emptyDigest := base(FactLegacyImportCompleted, "")
	variants := []mdlReplayVariant{
		{"bad schema", insert(pos, badSchema)},
		{"unknown kind", insert(pos, base("NotAKind", sid))},
		{"illegal global", insert(pos, emptyDigest)},
	}
	for _, target := range []string{sid, "ghost-global"} {
		noDigest := base(FactLegacyImportCompleted, target)
		noDigest.SessionRevision = 1
		first, again := base(FactLegacyImportCompleted, target), base(FactLegacyImportCompleted, target)
		first.Digest, again.Digest = "sha256:first", "sha256:again"
		restartBad := base(FactProcessRestarted, target)
		restartBad.Status = "open"
		restartBadAt := base(FactProcessRestarted, target)
		restartBadAt.At = "now"
		variants = append(variants,
			mdlReplayVariant{"empty-digest import with session " + target, insert(pos, noDigest)},
			mdlReplayVariant{"repeated import with session " + target, insert(pos, first, again)},
			mdlReplayVariant{"illegal restart with session " + target, insert(pos, restartBad)},
			mdlReplayVariant{"bad-time restart with session " + target, insert(pos, restartBadAt)},
		)
	}
	variants = append(variants, []mdlReplayVariant{
		{"reserved without session", insert(pos, base(reserved, ""))},
	}...)
	if len(seqRepeat) > 1 {
		variants = append(variants, mdlReplayVariant{"sequence not increasing", seqRepeat})
	}
	ghost := "ghost-replay"
	wrongReq := base(FactProviderAccepted, ghost)
	variants = append(variants, mdlReplayVariant{"ghost session", insert(pos, base(reserved, ghost), wrongReq)})
	lateGhost := "ghost-created"
	created := base(FactSessionCreated, lateGhost)
	created.Provider, created.SessionRevision = ProviderClaude, 1
	connected := base(FactProviderConnected, lateGhost)
	connected.SessionRevision = 2
	withGhost := insert(pos, base(reserved, lateGhost))
	variants = append(variants, mdlReplayVariant{"ghost then created", mdlRenumbered(append(withGhost, created, connected))})
	illegalAfter := base(FactProviderAccepted, lateGhost)
	illegalAfter.RequestID, illegalAfter.SessionRevision = "no-such-request", 3
	withGhost2 := insert(pos, base(reserved, lateGhost))
	variants = append(variants, mdlReplayVariant{"ghost created then illegal", mdlRenumbered(append(withGhost2, created, connected, illegalAfter, illegalAfter))})

	onSession := func(name, target string, at int, keepLater bool) {
		created := -1
		for i, f := range log {
			if f.SessionID == target && (f.Kind == FactSessionCreated || f.Kind == FactLegacyImported) {
				created = i
				break
			}
		}
		if created < 0 {
			return
		}
		if at <= created {
			at = created + 1
		}
		// next stamps a fact as the session stands after folding facts.
		next := func(facts []Fact, f Fact) ([]Fact, bool) {
			facts = mdlRenumbered(facts)
			probe, _, unreadable := mdlModelReplay(facts, nil)
			if unreadable {
				return nil, false
			}
			s := probe.sessions[target]
			f.SessionRevision = s.revision + 1
			if f.Kind == FactAbandoned {
				f.RequestID = s.lastReq
			}
			return mdlRenumbered(append(facts, f)), true
		}
		illegal := base(FactProviderAccepted, target)
		illegal.RequestID = "no-such-request"
		facts, ok := next(append([]Fact(nil), log[:at]...), illegal)
		if !ok {
			return
		}
		for _, f := range log[at:] {
			if keepLater || f.SessionID != target {
				facts = append(facts, f)
			}
		}
		outcomeFact := base(FactControlOutcome, target)
		outcomeFact.Control, outcomeFact.Outcome = "stop", "confirmed"
		discard := base(FactAbandoned, target)
		discard.Reason = "discard after replay quarantine"
		for _, f := range []Fact{base(reserved, target), outcomeFact, discard, base(FactSessionClosed, target)} {
			if facts, ok = next(facts, f); !ok {
				return
			}
		}
		variants = append(variants, mdlReplayVariant{name, facts})
	}
	onSession("illegal on random session", sid, pos, false)
	onSession("illegal with later facts kept", sid, pos, true)
	pickWhere := func(test func(*mdlMSession) bool) string {
		for _, id := range m.order {
			if test(m.sessions[id]) {
				return id
			}
		}
		return ""
	}
	if id := pickWhere(func(s *mdlMSession) bool { return s.closed }); id != "" {
		onSession("illegal on closed session", id, len(log), false)
	}
	if id := pickWhere(func(s *mdlMSession) bool { return s.quarantine != "" && !s.closed }); id != "" {
		onSession("illegal on quarantined session", id, len(log), false)
	}
	if id := pickWhere(func(s *mdlMSession) bool { return s.hidden && !s.closed }); id != "" {
		onSession("illegal on hidden session", id, len(log), false)
	}
	return variants
}

func mdlQuarantinedIDs(q []Quarantined) ([]string, string) {
	var ids []string
	for _, entry := range q {
		// SPEC-AMBIGUOUS: 19
		if entry.Err == nil {
			return nil, "Quarantined entry for " + entry.SessionID + " has nil Err"
		}
		ids = append(ids, entry.SessionID)
	}
	return ids, ""
}

func mdlCheckReplayVariant(v mdlReplayVariant, cov map[string]int) string {
	want, reported, unreadable := mdlModelReplay(v.facts, cov)
	got, q, err := Replay(v.facts)
	if unreadable {
		if !errors.Is(err, ErrUnreadableLog) {
			return fmt.Sprintf("replay variant %q: want ErrUnreadableLog, got %v", v.name, err)
		}
		if msg := mdlCompareProjection(mdlNewModel(nil), got); msg != "" {
			return fmt.Sprintf("replay variant %q: projection not empty: %s", v.name, msg)
		}
		return ""
	}
	if err != nil {
		return fmt.Sprintf("replay variant %q: unexpected error %v", v.name, err)
	}
	ids, msg := mdlQuarantinedIDs(q)
	if msg != "" {
		return fmt.Sprintf("replay variant %q: %s", v.name, msg)
	}
	if !mdlSameValue(reported, ids) {
		return fmt.Sprintf("replay variant %q: reported %v, want %v", v.name, ids, reported)
	}
	if msg := mdlCompareProjection(want, got); msg != "" {
		return fmt.Sprintf("replay variant %q: %s", v.name, msg)
	}
	again, q2, err2 := Replay(v.facts)
	ids2, _ := mdlQuarantinedIDs(q2)
	if err2 != nil || !reflect.DeepEqual(again, got) || !mdlSameValue(ids, ids2) {
		return fmt.Sprintf("replay variant %q: second replay differs", v.name)
	}
	return ""
}

// modelHooks lets a control inject a fault. cov collects row counters across seeds.
type modelHooks struct {
	afterDecode func(Fact) Fact   // A dropped field in the codec.
	afterStep   func(*Projection) // A value set outside Reduce.
	cov         map[string]int
}

type mdlModelRun struct {
	seed      int64
	mdlStep   int
	m         *mdlModel
	g         *mdlGen
	p         Projection
	log       []Fact
	hooks     modelHooks
	replayRng *rand.Rand
	noKernel  bool
	trace     strings.Builder
}

func mdlNewModelRun(seed int64, hooks modelHooks, noKernel bool) *mdlModelRun {
	r := &mdlModelRun{seed: seed, m: mdlNewModel(hooks.cov), g: mdlNewGen(seed), hooks: hooks, noKernel: noKernel,
		replayRng: rand.New(rand.NewSource(seed ^ 0x5eed))}
	if !noKernel {
		r.p = NewProjection()
	}
	return r
}

func (r *mdlModelRun) commit(f Fact) string {
	enc, err := EncodeFact(f)
	if err != nil {
		return fmt.Sprintf("EncodeFact(%s): %v", f.Kind, err)
	}
	dec, err := DecodeFact(enc)
	if err != nil {
		return fmt.Sprintf("DecodeFact(%s): %v", f.Kind, err)
	}
	if !reflect.DeepEqual(dec, f) {
		return fmt.Sprintf("codec changed fact:\n before %+v\n after  %+v", f, dec)
	}
	if r.hooks.afterDecode != nil {
		dec = r.hooks.afterDecode(dec)
	}
	next, err := Reduce(r.p, dec)
	if err != nil {
		return fmt.Sprintf("Reduce refused decoded %s: %v", dec.Kind, err)
	}
	r.p = next
	r.log = append(r.log, dec)
	return ""
}

func (r *mdlModelRun) doRaw(gs mdlGenStep) string {
	f := r.m.stampRaw(gs, gs.in.At)
	v := r.m.mdlVerdict(f)
	name := map[mdlVerdict]string{mdlVLegal: "legal", mdlVIllegal: "illegal", mdlVUnreadable: "unreadable"}[v]
	r.m.hit("raw.verdict." + name)
	if gs.tag != "" {
		r.m.hit("raw.tag." + gs.tag + "." + name)
	}
	fmt.Fprintf(&r.trace, "raw %s %s seq=%d %s\n", f.Kind, f.SessionID, f.Seq, name)
	if v == mdlVLegal {
		if !r.noKernel {
			if msg := r.commit(f); msg != "" {
				return msg
			}
		}
		if r.noKernel {
			r.log = append(r.log, f)
		}
		r.m.apply(f)
		return ""
	}
	if r.noKernel {
		return ""
	}
	if mdlContains(ReservedFactKinds, f.Kind) {
		// Section 7: later-slice kinds stay readable by kind.
		enc, err := EncodeFact(f)
		if err != nil {
			return fmt.Sprintf("EncodeFact of reserved kind %s: %v", f.Kind, err)
		}
		dec, err := DecodeFact(enc)
		if err != nil || dec.Kind != f.Kind {
			return fmt.Sprintf("reserved kind %s did not round trip: kind %s, err %v", f.Kind, dec.Kind, err)
		}
	}
	_, err := Reduce(r.p, f)
	if err == nil {
		return fmt.Sprintf("Reduce accepted %s fact %+v", name, f)
	}
	// SPEC-AMBIGUOUS: 19
	r.m.note(19)
	if v == mdlVIllegal && !errors.Is(err, ErrIllegalFact) {
		return fmt.Sprintf("Reduce error for illegal fact %+v is not ErrIllegalFact: %v", f, err)
	}
	if v == mdlVUnreadable && !errors.Is(err, ErrUnreadableLog) {
		return fmt.Sprintf("Reduce error for unreadable fact %+v is not ErrUnreadableLog: %v", f, err)
	}
	return ""
}

func (r *mdlModelRun) doInput(gs mdlGenStep) string {
	want := r.m.predict(gs)
	fmt.Fprintf(&r.trace, "in %q %q refusal=%q facts=%d\n", gs.in.Kind, gs.in.SessionID, want.refusal, len(want.facts))
	if r.noKernel {
		for _, wf := range want.facts {
			r.m.applyDecided(wf.Fact)
			r.log = append(r.log, wf.Fact)
		}
		return ""
	}
	d, err := Decide(r.p, gs.kernelIn())
	if want.refusal != "" {
		var ref *Refusal
		if !errors.As(err, &ref) {
			return fmt.Sprintf("want refusal %q, got err=%v decision=%+v", want.refusal, err, d)
		}
		if ref.Code != want.refusal {
			return fmt.Sprintf("want refusal %q, got %q", want.refusal, ref.Code)
		}
		if len(d.Facts) != 0 || len(d.Effects) != 0 || d.Idempotent {
			return fmt.Sprintf("refusal %q came with a decision %+v", want.refusal, d)
		}
		return ""
	}
	if err != nil {
		return fmt.Sprintf("want facts %d effects %v, got error %v", len(want.facts), want.effects, err)
	}
	if d.Idempotent != want.idempotent() {
		return fmt.Sprintf("Idempotent: want %v, got %v", want.idempotent(), d.Idempotent)
	}
	if len(d.Facts) != len(want.facts) {
		return fmt.Sprintf("facts: want %d %+v, got %d %+v", len(want.facts), want.facts, len(d.Facts), d.Facts)
	}
	if !mdlSameValue(want.effects, d.Effects) {
		return fmt.Sprintf("effects: want %+v, got %+v", want.effects, d.Effects)
	}
	for i, wf := range want.facts {
		if msg := mdlCompareFact(wf, d.Facts[i]); msg != "" {
			return msg
		}
	}
	for i, wf := range want.facts {
		got := d.Facts[i]
		if msg := r.commit(got); msg != "" {
			return msg
		}
		r.m.applyDecided(wf.Fact)
		if s := r.m.sessions[got.SessionID]; s != nil && s.controlFacts > 2 {
			return fmt.Sprintf("session %s has %d ControlRequested facts for request %q", s.id, s.controlFacts, s.lastReq)
		}
	}
	return ""
}

func (r *mdlModelRun) touchStatuses() {
	for _, id := range r.m.order {
		_, row := r.m.sessions[id].mdlStatus()
		r.m.hit("t6." + row)
	}
}

func (r *mdlModelRun) doStep() string {
	r.m.notes = map[int]bool{}
	gs := r.g.next(r.m)
	var msg string
	if gs.raw != nil {
		msg = r.doRaw(gs)
	} else {
		msg = r.doInput(gs)
	}
	if msg != "" {
		return r.describe(gs, msg)
	}
	r.touchStatuses()
	if r.noKernel {
		return ""
	}
	if r.hooks.afterStep != nil {
		r.hooks.afterStep(&r.p)
	}
	if msg := mdlCompareProjection(r.m, r.p); msg != "" {
		return r.describe(gs, msg)
	}
	replayed, q, err := Replay(r.log)
	if err != nil {
		return r.describe(gs, fmt.Sprintf("Replay of the live log: %v", err))
	}
	if len(q) != 0 {
		return r.describe(gs, fmt.Sprintf("Replay of the live log quarantined %+v", q))
	}
	if !reflect.DeepEqual(replayed, r.p) {
		return r.describe(gs, fmt.Sprintf("Replay differs from live:\n replay %+v\n live   %+v", replayed, r.p))
	}
	return ""
}

func (r *mdlModelRun) describe(gs mdlGenStep, msg string) string {
	notes := make([]int, 0, len(r.m.notes))
	for n := range r.m.notes {
		notes = append(notes, n)
	}
	sort.Ints(notes)
	what := fmt.Sprintf("input %+v", gs.in)
	if gs.raw != nil {
		what = fmt.Sprintf("raw %+v tag=%q seqMode=%d", *gs.raw, gs.tag, gs.seqMode)
	}
	return fmt.Sprintf("seed=%d step=%d: %s\n %s\n SPEC-AMBIGUOUS touched: %v", r.seed, r.mdlStep, msg, what, notes)
}

func (r *mdlModelRun) replayTable() string {
	for _, v := range mdlBuildReplayVariants(r.m, r.log, r.replayRng) {
		if r.noKernel {
			mdlModelReplay(v.facts, r.m.cov)
			continue
		}
		if msg := mdlCheckReplayVariant(v, r.m.cov); msg != "" {
			return fmt.Sprintf("seed=%d step=%d: %s", r.seed, r.mdlStep, msg)
		}
	}
	return ""
}

func (r *mdlModelRun) steps(steps int) int {
	if need := len(r.g.queue) + 20; mdlTourSeed(r.seed) && need > steps {
		return need
	}
	return steps
}

// runModel drives one seed and returns the first failure, or "".
func runModel(seed int64, steps int, hooks modelHooks) (failure string) {
	r := mdlNewModelRun(seed, hooks, false)
	defer func() {
		if v := recover(); v != nil {
			failure = fmt.Sprintf("seed=%d step=%d: panic: %v", seed, r.mdlStep, v)
		}
	}()
	total := r.steps(steps)
	for r.mdlStep = 0; r.mdlStep < total; r.mdlStep++ {
		if msg := r.doStep(); msg != "" {
			return msg
		}
		if r.mdlStep%50 == 49 || r.mdlStep == total-1 {
			if msg := r.replayTable(); msg != "" {
				return msg
			}
		}
	}
	return ""
}

// runModelAlone plays the generator against the model only, touching no kernel function.
// It answers whether the scripts reach every row, and gives the trace for determinism.
func mdlRunModelAlone(seed int64, steps int, cov map[string]int) string {
	r := mdlNewModelRun(seed, modelHooks{cov: cov}, true)
	total := r.steps(steps)
	for r.mdlStep = 0; r.mdlStep < total; r.mdlStep++ {
		r.m.notes = map[int]bool{}
		gs := r.g.next(r.m)
		if gs.raw != nil {
			r.doRaw(gs)
		} else {
			r.doInput(gs)
		}
		r.touchStatuses()
		if r.mdlStep%50 == 49 || r.mdlStep == total-1 {
			r.replayTable()
		}
	}
	return r.trace.String()
}

// tableRows lists every row a seed run must exercise. A hit outside this list also fails,
// which catches a mistyped counter and a raw script fact whose verdict was not as tagged.
func mdlTableRows() []string {
	rows := []string{
		"t2.trim.budget_exhausted", "t2.trim.protected", "t2.trim.hidden",
		"t2.legacy.", "t2.legacy.final", "t2.legacy.rejected", "t2.legacy.unknown", "t2.legacy.abandoned",
		"t3.restart.open_to_unknown", "t3.abandoned.overwrites", "t3.abandoned.keeps", "t3.trim256", "t3.refused.default_code",
		"t4.control_requested.unknown", "t4.control_requested.other",
		"t4.unknown.pending_survives", "t4.intended.clears_bound_turn",
		"t4.control_outcome.unresolved_not_confirmed", "t4.control_outcome.abandoned_clears", "t4.control_outcome.abandoned_not_confirmed", "t4.control_outcome.resolved_not_confirmed",
		"t5.request.known", "t5.request.unknown", "t5.sticky", "t5.status.empty", "t5.status.valid", "t5.status.invalid", "t5.digest.valid", "t5.digest.empty",
		"t8.unreadable.schema", "t8.unreadable.seq", "t8.unreadable.kind", "t8.unreadable.global", "t8.unreadable.reserved_no_session", "t8.unreadable.global_live_session", "t8.unreadable.global_ghost_session", "t2.quarantine.overwrite_with_illegal_fact",
		"t8.reserved_follows_rows", "t8.ghost", "t8.ghost_once", "t8.ghost_then_created", "t8.ghost_created_quarantined", "t8.first", "t8.first_on_closed", "t8.first_on_quarantined", "t8.later_applied", "t8.later_skipped",
		"raw.verdict.legal", "raw.verdict.illegal", "raw.verdict.unreadable",
		"raw.tag.legal.legal", "raw.tag.repeat.legal", "raw.tag.gap.legal", "raw.tag.illegal.illegal", "raw.tag.receipt_transition.illegal",
		"raw.tag.reserved.illegal", "raw.tag.unknown_kind.unreadable", "raw.tag.bad_schema.unreadable", "raw.tag.seq_equal.unreadable", "raw.tag.seq_lower.unreadable",
		"raw.tag.legacy.legal", "raw.tag.legacy.illegal",
	}
	for _, k := range mdlCoreKinds {
		rows = append(rows, "fact."+string(k))
	}
	for _, k := range mdlLateKinds {
		rows = append(rows, "t5.kind."+k)
	}
	for _, s := range []string{"closed", "abandoned", "unknown_quarantine", "unknown_receipt", "read_only", "open_paused", "running", "rejected", "failed", "paused", "interrupted", "codex_offline", "idle"} {
		rows = append(rows, "t6."+s)
	}
	for _, s := range []string{
		"auth.unknown_kind.forbidden", "auth.class.forbidden", "auth.session.forbidden", "time.bad_time",
		"closed.not_found", "missing.not_found", "restart.idempotent", "restart.fact",
		"create.empty.session_exists", "create.closed.session_exists", "create.used.session_exists", "create.bad_provider", "create.no_owner", "create.bad_value", "create.fact",
		"send.replay.intent", "send.replay.accepted", "send.replay.final", "send.not_replayed", "send.bad_request", "send.read_only", "send.unresolved", "send.disconnected",
		"send.no_identity", "send.runtime_changed", "send.no_owner", "send.bad_value", "send.binds_identity", "send.fact",
		"control.read_only", "control.read_only_effects", "control.unknown_owed", "control.nothing_to_stop", "control.unknown_effects", "control.pause", "control.stop", "control.already_paused.pause", "control.already_paused.stop", "control.second_fact",
		"cwd.read_only", "cwd.unresolved", "cwd.bad_request", "cwd.bad_value", "cwd.fact",
		"close.unresolved", "close.fact",
		"abandon.bad_reason", "abandon.idempotent", "abandon.discarded_other", "abandon.turn_changed", "abandon.stop_first", "abandon.nothing_to_discard", "abandon.no_receipt", "abandon.limit_after_trim", "abandon.bad_value", "abandon.fact",
		"conversation.runtime_changed", "conversation.no_owner", "conversation.idempotent", "conversation.not_replaced", "conversation.binds_identity", "conversation.fact",
		"connected.idempotent", "connected.fact", "disconnected.fact",
		"frame.reason_dropped", "accepted.idempotent", "accepted.fact", "refused.fact", "unknown.fact",
		"turn_missing.not_found", "turn_closed.not_found", "turn.closed_pending", "turn.claude_late", "turn.guard_late", "turn.idempotent", "turn.different_late", "turn.pending", "turn.fact", "turn.resolved_late",
		"completed.unbound", "completed.empty_late", "completed.guard_late", "completed.turn_late", "completed.invalid_status", "completed.fact.completed", "completed.fact.failed", "completed.fact.interrupted",
		"control_outcome.idempotent", "control_outcome.fact",
		"auth_boundary.bad_provider", "auth_boundary.idempotent", "auth_boundary.fact", "auth_boundary.several",
		"quarantine.empty.bad_value", "quarantine.shape.bad_value", "quarantine.fact",
	} {
		rows = append(rows, "t7."+s)
	}
	return rows
}

func mdlCheckRows(t *testing.T, cov map[string]int) {
	t.Helper()
	declared := map[string]bool{}
	var missing, unexpected []string
	for _, row := range mdlTableRows() {
		declared[row] = true
		if cov[row] == 0 {
			missing = append(missing, row)
		}
	}
	for row := range cov {
		if !declared[row] {
			unexpected = append(unexpected, row)
		}
	}
	sort.Strings(missing)
	sort.Strings(unexpected)
	if len(missing) > 0 {
		t.Errorf("rows never exercised: %v", missing)
	}
	if len(unexpected) > 0 {
		t.Errorf("counters outside the row list: %v", unexpected)
	}
}

const mdlDefaultModelSteps = 200

func mdlModelSeedCount(t *testing.T) int64 {
	t.Helper()
	raw := os.Getenv("KERNEL_MODEL_SEEDS")
	if raw == "" {
		return 300
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n < 1 {
		t.Fatalf("KERNEL_MODEL_SEEDS=%q is not a positive count", raw)
	}
	return n
}

// TestModelAgainstTables is the check itself. Seed 0 is a tour of every script, so row
// coverage holds for any seed count.
func TestModelAgainstTables(t *testing.T) {
	cov := map[string]int{}
	for seed := int64(0); seed < mdlModelSeedCount(t); seed++ {
		if failure := runModel(seed, mdlDefaultModelSteps, modelHooks{cov: cov}); failure != "" {
			t.Fatal(failure)
		}
	}
	mdlCheckRows(t, cov)
}

// TestModelAloneCoversRows calls no kernel function, so it can vet the generator and the
// row list on its own.
func TestModelAloneCoversRows(t *testing.T) {
	cov := map[string]int{}
	for seed := int64(0); seed < 40; seed++ {
		mdlRunModelAlone(seed, mdlDefaultModelSteps, cov)
	}
	mdlCheckRows(t, cov)
}

func TestModelAloneIsDeterministic(t *testing.T) {
	for _, seed := range []int64{1, 2, 3, 17} {
		if mdlRunModelAlone(seed, mdlDefaultModelSteps, nil) != mdlRunModelAlone(seed, mdlDefaultModelSteps, nil) {
			t.Fatalf("seed=%d: two runs differ", seed)
		}
	}
}

// Section 10 item 19: bytes that cannot decode are ErrMalformedFact.
func TestDecodeFactMalformed(t *testing.T) {
	for _, raw := range []string{"", "not a fact", "{", "[1,2"} {
		if _, err := DecodeFact([]byte(raw)); !errors.Is(err, ErrMalformedFact) {
			t.Errorf("DecodeFact(%q): want ErrMalformedFact, got %v", raw, err)
		}
	}
}

// A control passes only when the clean run passes, the fault truly fired, and it was caught.
func TestControlDroppedField(t *testing.T) {
	const seed = 1
	if failure := runModel(seed, mdlDefaultModelSteps, modelHooks{}); failure != "" {
		t.Fatalf("clean run must pass before a control means anything: %s", failure)
	}
	changed := 0
	failure := runModel(seed, mdlDefaultModelSteps, modelHooks{afterDecode: func(f Fact) Fact {
		if f.Kind == FactSessionCreated && f.ProfileID != "" {
			f.ProfileID = ""
			changed++
		}
		return f
	}})
	if changed == 0 {
		t.Fatal("the dropped-field hook never fired")
	}
	if failure == "" {
		t.Fatal("a field dropped by the codec was not caught")
	}
	if !strings.Contains(failure, "seed=1 step=") {
		t.Fatalf("failure does not name the seed and step: %s", failure)
	}
}

func TestControlTamperedProjection(t *testing.T) {
	const seed = 1
	if failure := runModel(seed, mdlDefaultModelSteps, modelHooks{}); failure != "" {
		t.Fatalf("clean run must pass before a control means anything: %s", failure)
	}
	tampered := false
	failure := runModel(seed, mdlDefaultModelSteps, modelHooks{afterStep: func(p *Projection) {
		if tampered || len(p.Order) == 0 {
			return
		}
		s := p.Sessions[p.Order[0]]
		s.Paused = !s.Paused
		tampered = true
	}})
	if !tampered {
		t.Fatal("the tamper hook never fired")
	}
	if failure == "" {
		t.Fatal("a value set outside Reduce was not caught")
	}
	if !strings.Contains(failure, "seed=1 step=") {
		t.Fatalf("failure does not name the seed and step: %s", failure)
	}
}
