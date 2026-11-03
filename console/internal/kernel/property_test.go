package kernel

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"reflect"
	"strconv"
	"testing"
)

// modelSession is an independently written model of the receipt and restart tables.
// Live and replay are one fold over one log, so comparing only those two could not
// catch a wrong rule: this is the check that can disagree with the reducer.
type modelSession struct {
	receipts map[string]string
	last     string
	readOnly bool
	closed   bool
	inputs   map[string]string
	final    bool
}

type model struct{ sessions map[string]*modelSession }

func modelAllows(from, to string) bool {
	switch from {
	case "":
		return to == "intent"
	case "intent":
		return to == "accepted" || to == "final" || to == "unknown" || to == "rejected" || to == "abandoned"
	case "accepted":
		return to == "final" || to == "unknown" || to == "rejected" || to == "abandoned"
	case "unknown":
		return to == "abandoned"
	}
	return false
}

// receiptTarget says what a fact would do to the active receipt in the model.
func modelTarget(f Fact, s *modelSession) (string, bool) {
	switch f.Kind {
	case FactProviderAccepted:
		return "accepted", true
	case FactProviderRefused:
		return "rejected", true
	case FactProviderCompleted:
		return "final", true
	case FactOutcomeUnknown:
		return "unknown", true
	}
	return "", false
}

func (m *model) legal(f Fact) bool {
	s := m.sessions[f.SessionID]
	if f.Kind == FactProcessRestarted {
		return true
	}
	if s == nil || s.closed {
		return false
	}
	if to, ok := modelTarget(f, s); ok {
		if s.readOnly || f.RequestID != s.last {
			return false
		}
		return modelAllows(s.receipts[f.RequestID], to)
	}
	switch f.Kind {
	case FactControlRequested:
		return !s.readOnly
	case FactCwdChanged:
		state := s.receipts[s.last]
		return !s.readOnly && state != "intent" && state != "accepted" && state != "unknown"
	}
	return true
}

func (m *model) apply(f Fact) {
	if f.Kind == FactProcessRestarted {
		for _, s := range m.sessions {
			if s.closed {
				continue
			}
			if state := s.receipts[s.last]; state == "intent" || state == "accepted" {
				s.receipts[s.last] = "unknown"
				s.final = false
			}
			s.readOnly = true
			for id, status := range s.inputs {
				if status == "dispatching" {
					s.inputs[id] = "unknown"
				}
				if status == "queued" {
					s.inputs[id] = "held"
				}
			}
		}
		return
	}
	if f.Kind == FactSessionCreated {
		m.sessions[f.SessionID] = &modelSession{receipts: map[string]string{}, inputs: map[string]string{}}
		return
	}
	s := m.sessions[f.SessionID]
	if s == nil {
		return
	}
	if to, ok := modelTarget(f, s); ok {
		s.receipts[f.RequestID] = to
		s.final = to == "final"
		if to == "unknown" && s.inputs[f.RequestID] == "dispatching" {
			s.inputs[f.RequestID] = "unknown"
		}
		if to == "final" && s.inputs[f.RequestID] == "dispatching" {
			s.inputs[f.RequestID] = "retained"
		}
		if to == "rejected" && s.inputs[f.RequestID] == "dispatching" {
			s.inputs[f.RequestID] = "held"
		}
		return
	}
	switch f.Kind {
	case FactRequestIntended:
		s.receipts[f.RequestID] = "intent"
		s.last = f.RequestID
		s.final = false
	case FactAbandoned:
		if state := s.receipts[f.RequestID]; state == "intent" || state == "accepted" || state == "unknown" {
			s.receipts[f.RequestID] = "abandoned"
			s.final = false
		}
		s.readOnly = true
		for id, status := range s.inputs {
			if status == "queued" {
				s.inputs[id] = "held"
			}
			if id == f.RequestID && status == "dispatching" {
				s.inputs[id] = "unknown"
			}
		}
	case FactAuthBoundaryCrossed:
		if state := s.receipts[s.last]; state == "intent" || state == "accepted" {
			s.receipts[s.last] = "unknown"
			s.final = false
			if s.inputs[s.last] == "dispatching" {
				s.inputs[s.last] = "unknown"
			}
		}
		s.readOnly = true
		for id, status := range s.inputs {
			if status == "queued" {
				s.inputs[id] = "held"
			}
		}
	case FactProviderDisconnected:
		if state := s.receipts[s.last]; state == "intent" || state == "accepted" {
			s.receipts[s.last] = "unknown"
			s.final = false
			if s.inputs[s.last] == "dispatching" {
				s.inputs[s.last] = "unknown"
			}
		}
	case FactSessionClosed:
		s.closed = true
	case FactControlRequested:
		if s.receipts[s.last] == "unknown" {
			return
		}
		if f.Control == "resume" {
			for id, status := range s.inputs {
				if status == "held" {
					s.inputs[id] = "queued"
				}
			}
		} else {
			for id, status := range s.inputs {
				if status == "queued" {
					s.inputs[id] = "held"
				}
			}
		}
	case FactInputQueued:
		s.inputs[f.RequestID] = "queued"
	case FactInputDispatchPrepared:
		s.inputs[f.RequestID] = "dispatching"
	case FactInputOutcome:
		s.inputs[f.RequestID] = f.Status
	case FactInputDiscarded:
		s.inputs[f.RequestID] = "cleanup_pending"
	case FactPayloadReleased:
		s.inputs[f.RequestID] = "discarded"
	}
}

func (m *model) compare(p Projection) string {
	for id, want := range m.sessions {
		got := p.Sessions[id]
		if got == nil {
			return "missing session " + id
		}
		if got.ReadOnly != want.readOnly || got.Closed != want.closed || got.LastRequest != want.last || got.ProviderFinal != want.final {
			return fmt.Sprintf("%s flags: readOnly=%v/%v closed=%v/%v last=%q/%q final=%v/%v", id, got.ReadOnly, want.readOnly, got.Closed, want.closed, got.LastRequest, want.last, got.ProviderFinal, want.final)
		}
		for request, state := range want.receipts {
			if string(got.Requests[request]) != state {
				return fmt.Sprintf("%s/%s receipt %q want %q", id, request, got.Requests[request], state)
			}
		}
		for request, state := range want.inputs {
			entry := findInput(got, request)
			if entry == nil || entry.Status != state {
				return fmt.Sprintf("%s/%s input %v want %q", id, request, entry, state)
			}
		}
	}
	return ""
}

// codec is what the harness treats the log as, so a control can break it.
type codec func(Fact) (Fact, error)

func realCodec(f Fact) (Fact, error) {
	data, err := EncodeFact(f)
	if err != nil {
		return Fact{}, err
	}
	return DecodeFact(data)
}

type walk struct {
	rng      *rand.Rand
	p        Projection
	facts    []Fact
	decoded  []Fact
	model    *model
	codec    codec
	next     int
	coverage map[string]int
	written  map[string]map[string]bool
	terminal map[string]Receipt
}

func (w *walk) pick() *Session {
	if len(w.p.Order) == 0 {
		return nil
	}
	return w.p.Sessions[w.p.Order[w.rng.Intn(len(w.p.Order))]]
}

func (w *walk) id(prefix string) string {
	w.next++
	return prefix + strconv.Itoa(w.next)
}

// input draws a random input, biased to the current state so histories go deep.
func (w *walk) input() In {
	in := In{At: fmt.Sprintf("2026-11-03T10:%02d:%02d.000000000Z", w.next/60%60, w.next%60)}
	s := w.pick()
	user := func(kind InputKind) In {
		in.Kind, in.Principal = kind, Principal{Class: PrincipalUser}
		return in
	}
	provider := func(kind InputKind) In {
		in.Kind, in.Principal = kind, Principal{Class: PrincipalProvider, SessionID: in.SessionID}
		return in
	}
	system := func(kind InputKind) In {
		in.Kind, in.Principal = kind, Principal{Class: PrincipalSystem}
		return in
	}
	agent := func(kind InputKind) In {
		in.Kind, in.Principal = kind, Principal{Class: PrincipalAgentRun, SessionID: in.SessionID}
		return in
	}
	if s == nil || w.rng.Intn(12) == 0 {
		in.SessionID = w.id("s")
		in.Provider = []string{ProviderCodex, ProviderClaude}[w.rng.Intn(2)]
		in.Status = "connected"
		return user(InCreate)
	}
	in.SessionID = s.ID
	in.RequestID = s.LastRequest
	in.TurnID = s.TurnID
	in.RuntimeIdentity = "owner"
	switch w.rng.Intn(64) {
	case 0, 1, 2, 3:
		in.RequestID, in.TaskID, in.Generation, in.ObjectiveHash = w.id("r"), w.id("t"), 1, "h"
		in.RemainingBursts = 3
		return user(InSend)
	case 4, 5:
		return provider(ObAccepted)
	case 6:
		in.Status, in.ReasonCode = "", "rejected"
		return provider(ObRefused)
	case 7:
		in.ReasonCode = "deadline"
		return provider(ObUnknown)
	case 8, 9:
		in.TurnID = w.id("turn")
		return provider(ObTurnBound)
	case 10, 11, 12:
		in.Status = []string{"completed", "failed", "interrupted"}[w.rng.Intn(3)]
		if w.rng.Intn(5) == 0 {
			in.TurnID = "stale"
		}
		return provider(ObCompleted)
	case 13:
		return user([]InputKind{InPause, InStop}[w.rng.Intn(2)])
	case 14:
		return user(InResume)
	case 15:
		in.CWD = "/" + w.id("dir")
		return user(InChangeCWD)
	case 16:
		return user(InClose)
	case 17:
		in.ExpectedRequest, in.Reason = s.LastRequest, rr("done")
		return user(InAbandon)
	case 18:
		in.ID, in.Status, in.Digest, in.ExpiresAt = w.id("q"), "approval", "d", "2030-01-01T00:00:00.000000000Z"
		return provider(ObQuestion)
	case 19:
		// Questions are short-lived in a random history, so aim at one that is open.
		in.ID = ""
		for _, id := range w.p.Order {
			if open := w.p.Sessions[id]; len(open.Questions) > 0 {
				in.SessionID, in.ID = id, open.Questions[0].ID
				break
			}
		}
		return user(InAnswer)
	case 20:
		in.RequestID, in.PayloadHash = w.id("q"), "h"
		return user(InQueueInput)
	case 21:
		if len(s.Inputs) > 0 {
			in.RequestID = s.Inputs[w.rng.Intn(len(s.Inputs))].RequestID
		}
		if w.rng.Intn(2) == 0 {
			for _, id := range w.p.Order {
				for _, entry := range w.p.Sessions[id].Inputs {
					if entry.Status == InputCleanup {
						in.SessionID, in.RequestID = id, entry.RequestID
					}
				}
			}
			return system(ObPayloadReleased)
		}
		return user(InDiscardInput)
	case 22:
		if len(s.Inputs) > 0 {
			in.RequestID = s.Inputs[0].RequestID
		}
		in.ObjectiveHash, in.Automatic = "h", true
		return system(InDispatchInput)
	case 23:
		switch w.rng.Intn(3) {
		case 0:
			in.Provider = s.Provider
			return system(ObAuthBoundary)
		case 1:
			return provider(ObDisconnected)
		}
		in.ID, in.Role, in.TurnID, in.Status = "child", "owner", "t", ChildRunning
		return provider(ObChild)
	case 24, 25:
		in.ID, in.Stage, in.Digest = w.id("run"), "plan", "d"
		return system(InStartReview)
	case 26, 27, 28:
		if s.Review != nil {
			in.ID, in.Digest, in.Verdict = s.Review.ID, s.Review.Digest, []string{"pass", "block"}[w.rng.Intn(2)]
		}
		return system(ObReviewOutcome)
	case 29, 63:
		for _, id := range w.p.Order {
			for _, entry := range w.p.Sessions[id].Inputs {
				if entry.Status == InputDispatching {
					in.SessionID, in.RequestID = id, entry.RequestID
				}
			}
		}
		in.Status = []string{InputRetained, InputUnknown, InputHeld}[w.rng.Intn(3)]
		return system(ObInputOutcome)
	case 30:
		in.Status = "pause"
		in.Outcome = []string{"confirmed", "rejected", "unconfirmed"}[w.rng.Intn(3)]
		return provider(ObControlOutcome)
	case 31:
		in.ID, in.Status, in.ReasonCode = "child", "completed", "done"
		return provider(ObChildOutcome)
	case 32:
		in.TaskID, in.State, in.Stage = "", []string{TaskActive, TaskNeedsReview, TaskBlocked, TaskHandoff, TaskComplete}[w.rng.Intn(5)], "plan"
		if s.Task != nil {
			in.TaskID = s.Task.ID
		}
		return agent(InCheckpoint)
	case 33:
		in.PolicyRevision = w.id("rev")
		return system(InSetPolicy)
	case 34:
		in.Cascade = w.id("cascade")
		return system(InSetCascade)
	case 35:
		in.State, in.ReasonCode = []string{SupervisionActive, SupervisionWaiting, SupervisionPaused, SupervisionBlocked}[w.rng.Intn(4)], "scheduler"
		return system(InSetSupervision)
	case 36:
		in.RemainingBursts, in.Progress = int64(w.rng.Intn(4)), int64(w.rng.Intn(4))
		return system(InSetBudget)
	case 37:
		in.Status = []string{"pending", "clear"}[w.rng.Intn(2)]
		return system(InSetReviewResult)
	case 38:
		if s.Review != nil {
			in.ID = s.Review.ID
		}
		return system(ObReviewCancelled)
	case 39:
		in.ID, in.Status = "child", []string{"interrupt", "resume"}[w.rng.Intn(2)]
		return user(InChildControl)
	case 40:
		in.ProviderID = w.id("conv")
		return provider(ObConversationBound)
	case 41:
		return provider(ObConnected)
	case 42:
		if s.Review != nil {
			in.ReviewRunID = s.Review.ID
		}
		in.ID, in.Status, in.ExpiresAt = w.id("q"), "approval", "2030-01-01T00:00:00.000000000Z"
		return provider(ObQuestion)
	case 43:
		in.RequestID, in.Status = "", "completed"
		return provider(ObCompleted)
	case 46, 47, 48, 49:
		in.RequestID, in.PayloadHash = w.id("q"), "h"
		return user(InQueueInput)
	case 50, 51, 52, 53:
		// Aim dispatch at a session that can take it, or the queue paths stay shallow.
		for _, id := range w.p.Order {
			open := w.p.Sessions[id]
			if !open.ReadOnly && !open.Requests[open.LastRequest].unresolved() {
				for _, entry := range open.Inputs {
					if entry.Status == InputQueued {
						in.SessionID, in.RequestID = id, entry.RequestID
						break
					}
				}
			}
		}
		in.ObjectiveHash, in.Automatic = "h", true
		return system(InDispatchInput)
	case 54, 55, 56:
		for _, id := range w.p.Order {
			open := w.p.Sessions[id]
			if !open.ReadOnly && open.Requests[open.LastRequest].open() && (open.Provider == ProviderClaude || open.TurnID != "") {
				in.SessionID, in.RequestID, in.TurnID = id, open.LastRequest, open.TurnID
			}
		}
		in.ID, in.Status, in.Digest, in.ExpiresAt = w.id("q"), "approval", "d", "2030-01-01T00:00:00.000000000Z"
		return provider(ObQuestion)
	case 57, 58, 59:
		for _, id := range w.p.Order {
			if open := w.p.Sessions[id]; len(open.Questions) > 0 {
				in.SessionID, in.ID = id, open.Questions[0].ID
				break
			}
		}
		return user(InAnswer)
	case 60, 61, 62:
		for _, id := range w.p.Order {
			for _, entry := range w.p.Sessions[id].Inputs {
				if entry.Status == InputHeld || entry.Status == InputRetained || entry.Status == InputQueued {
					in.SessionID, in.RequestID = id, entry.RequestID
				}
			}
		}
		return user(InDiscardInput)
	case 44:
		in.RequestID, in.Automatic = w.id("r"), true
		if s.Task != nil {
			in.ExpectedTask = s.Task.ID
		}
		in.ExpectedEpoch = s.ControlEpoch
		return system(InSend)
	}
	return system(ObRestart)
}

func (w *walk) commit(f Fact) error {
	before := w.p.Sessions[f.SessionID]
	decoded, err := w.codec(f)
	if err != nil {
		return err
	}
	next, err := Reduce(w.p, f)
	if err != nil {
		return err
	}
	w.note(f, before, next)
	w.p = next
	w.facts = append(w.facts, f)
	w.decoded = append(w.decoded, decoded)
	w.model.apply(f)
	return nil
}

func (w *walk) note(f Fact, before *Session, next Projection) {
	w.coverage[string(f.Kind)]++
	if f.Kind == FactProcessRestarted {
		for _, id := range next.Order {
			w.noteFields(string(f.Kind), w.p.Sessions[id], next.Sessions[id])
		}
		return
	}
	w.noteFields(string(f.Kind), before, next.Sessions[f.SessionID])
}

func (w *walk) noteFields(kind string, before, after *Session) {
	if before == nil || after == nil {
		return
	}
	beforeValue, afterValue := reflect.ValueOf(*before), reflect.ValueOf(*after)
	for i := 0; i < beforeValue.NumField(); i++ {
		name := beforeValue.Type().Field(i).Name
		if name == "Revision" || reflect.DeepEqual(beforeValue.Field(i).Interface(), afterValue.Field(i).Interface()) {
			continue
		}
		if w.written[kind] == nil {
			w.written[kind] = map[string]bool{}
		}
		w.written[kind][name] = true
	}
}

// hostile throws a raw receipt fact at the reducer, as a Decide bug or corrupt log
// would. The model and the reducer must agree on whether it is legal.
func (w *walk) hostile() string {
	s := w.pick()
	if s == nil || s.Closed || s.LastRequest == "" {
		return ""
	}
	kinds := []FactKind{FactProviderAccepted, FactProviderRefused, FactProviderCompleted, FactOutcomeUnknown, FactControlRequested, FactCwdChanged}
	f := Fact{Seq: w.p.LastSeq + 1, SchemaVersion: SchemaVersion, At: "2026-11-03T11:00:00.000000000Z", Kind: kinds[w.rng.Intn(len(kinds))], SessionID: s.ID, SessionRevision: s.Revision + 1, RequestID: s.LastRequest, Status: "completed", Control: "pause", CWD: "/hostile"}
	_, err := Reduce(w.p, f)
	allowed := w.model.legal(f)
	if allowed != (err == nil) {
		return fmt.Sprintf("hostile %s on %s/%q: model allows=%v reducer err=%v", f.Kind, s.ID, s.Requests[s.LastRequest], allowed, err)
	}
	if err == nil {
		if commitErr := w.commit(f); commitErr != nil {
			return commitErr.Error()
		}
	}
	return ""
}

func (w *walk) checkMonotonic() string {
	for _, id := range w.p.Order {
		s := w.p.Sessions[id]
		for request, state := range s.Requests {
			key := id + "/" + request
			prior := w.terminal[key]
			if prior == ReceiptFinal || prior == ReceiptRejected || prior == ReceiptAbandoned {
				if state != prior {
					return fmt.Sprintf("INV1: %s moved %s -> %s", key, prior, state)
				}
			}
			if prior == ReceiptUnknown && state != ReceiptUnknown && state != ReceiptAbandoned {
				return fmt.Sprintf("INV1: %s moved unknown -> %s", key, state)
			}
			w.terminal[key] = state
		}
		if s.Closed && s.Abandoned == nil && s.Requests[s.LastRequest].unresolved() {
			return "INV3: closed with an unresolved receipt: " + id
		}
		if s.Closed || w.p.LastKind != FactProcessRestarted {
			continue
		}
		// The restart table, checked independently of how the reducer got there.
		running := s.Review != nil && s.Review.Status == "running"
		if !s.ReadOnly || s.Connected || s.TurnID != "" || s.PendingInterrupt || s.ReviewResultPending || len(s.Questions) != 0 || s.Requests[s.LastRequest].open() || running {
			return fmt.Sprintf("restart table: %s kept authority", id)
		}
		for _, child := range s.Children {
			if child.Status == ChildRunning {
				return "restart table: running child on " + id
			}
		}
		for _, input := range s.Inputs {
			if input.Status == InputQueued || input.Status == InputDispatching {
				return "restart table: open input on " + id
			}
		}
	}
	return ""
}

// runWalk returns the first violation with its seed in the message, or "".
func runWalk(seed int64, steps int, c codec) (string, *walk) {
	w := &walk{rng: rand.New(rand.NewSource(seed)), p: NewProjection(), model: &model{sessions: map[string]*modelSession{}}, codec: c, coverage: map[string]int{}, written: map[string]map[string]bool{}, terminal: map[string]Receipt{}}
	for step := 0; step < steps; step++ {
		in := w.input()
		decision, err := Decide(w.p, in)
		repeat, repeatErr := Decide(w.p, in)
		if fmt.Sprint(err) != fmt.Sprint(repeatErr) || !reflect.DeepEqual(decision, repeat) {
			return fmt.Sprintf("seed=%d step=%d %s: Decide is not pure", seed, step, in.Kind), w
		}
		var refusal *Refusal
		if err != nil && !errors.As(err, &refusal) {
			return fmt.Sprintf("seed=%d step=%d %s: %v", seed, step, in.Kind, err), w
		}
		for _, f := range decision.Facts {
			if commitErr := w.commit(f); commitErr != nil {
				return fmt.Sprintf("seed=%d step=%d Decide emitted illegal %s: %v", seed, step, f.Kind, commitErr), w
			}
		}
		if failure := w.hostile(); failure != "" {
			return fmt.Sprintf("seed=%d step=%d %s", seed, step, failure), w
		}
		if failure := w.model.compare(w.p); failure != "" {
			return fmt.Sprintf("seed=%d step=%d after %s: model: %s", seed, step, in.Kind, failure), w
		}
		if failure := w.checkMonotonic(); failure != "" {
			return fmt.Sprintf("seed=%d step=%d %s", seed, step, failure), w
		}
		// INV2 on every prefix.
		replayed, quarantined, replayErr := Replay(w.decoded)
		if replayErr != nil || len(quarantined) != 0 {
			return fmt.Sprintf("seed=%d step=%d INV2: replay: %v %+v", seed, step, replayErr, quarantined), w
		}
		if !reflect.DeepEqual(canonical(replayed), canonical(w.p)) {
			return fmt.Sprintf("seed=%d step=%d after %s: INV2: replay differs from live", seed, step, in.Kind), w
		}
	}
	return "", w
}

func canonical(p Projection) string {
	data, err := json.Marshal(p)
	if err != nil {
		return "marshal: " + err.Error()
	}
	return string(data)
}

func seedCount(fallback int) int {
	if value, err := strconv.Atoi(os.Getenv("KERNEL_PROPERTY_SEEDS")); err == nil && value > 0 {
		return value
	}
	return fallback
}

func TestPropertyAgainstModel(t *testing.T) {
	coverage := map[string]int{}
	written := map[string]map[string]bool{}
	for seed := int64(1); seed <= int64(seedCount(300)); seed++ {
		failure, w := runWalk(seed, 120, realCodec)
		if failure != "" {
			t.Fatal(failure)
		}
		for kind, count := range w.coverage {
			coverage[kind] += count
		}
		for kind, fields := range w.written {
			if written[kind] == nil {
				written[kind] = map[string]bool{}
			}
			for field := range fields {
				written[kind][field] = true
			}
		}
	}
	// A run that never reached these proves nothing.
	for kind := range factWrites {
		if coverage[string(kind)] == 0 && kind != FactLegacyInputHeld && kind != FactChildQuarantined && kind != FactQuestionRevoked && kind != FactSessionQuarantined {
			t.Errorf("vacuous run: no %s", kind)
		}
	}
	if coverage[string(FactProcessRestarted)] == 0 {
		t.Error("vacuous run: no restart")
	}
	// Reduce only writes what the field-to-fact table declares.
	for kind, fields := range written {
		declared := map[string]bool{}
		for _, field := range factWrites[FactKind(kind)] {
			declared[field] = true
		}
		if FactKind(kind) == FactProcessRestarted {
			for _, field := range restartWrites {
				declared[field] = true
			}
		}
		for field := range fields {
			if !declared[field] {
				t.Errorf("%s wrote undeclared field %s", kind, field)
			}
		}
	}
}

// Every Session field must have a writing fact, and every field the table names must exist.
func TestFieldToFactTableIsComplete(t *testing.T) {
	kind := reflect.TypeOf(Session{})
	exists := map[string]bool{}
	for i := 0; i < kind.NumField(); i++ {
		exists[kind.Field(i).Name] = true
	}
	covered := map[string]bool{"Revision": true}
	for fact, fields := range factWrites {
		if !knownFacts[fact] {
			t.Errorf("unknown fact %s", fact)
		}
		for _, field := range fields {
			if !exists[field] {
				t.Errorf("%s names missing field %s", fact, field)
			}
			covered[field] = true
		}
	}
	for _, field := range restartWrites {
		if !exists[field] {
			t.Errorf("restart names missing field %s", field)
		}
		covered[field] = true
	}
	for name := range exists {
		if !covered[name] {
			t.Errorf("field %s has no writing fact", name)
		}
	}
}

func TestDeterministicAcrossRuns(t *testing.T) {
	runs := seedCount(1000)
	first := ""
	for run := 0; run < runs; run++ {
		failure, w := runWalk(7, 60, realCodec)
		if failure != "" {
			t.Fatal(failure)
		}
		sum := sha256.Sum256([]byte(canonical(w.p)))
		digest := fmt.Sprintf("%x", sum)
		if first == "" {
			first = digest
		} else if digest != first {
			t.Fatalf("run %d differs from run 0 with the same seed", run)
		}
	}
}

// Decide must not depend on the wall clock or on anything but its arguments.
func TestDecideIsPure(t *testing.T) {
	failure, w := runWalk(11, 80, realCodec)
	if failure != "" {
		t.Fatal(failure)
	}
	in := In{Kind: ObRestart, Principal: Principal{Class: PrincipalSystem}, At: testAt}
	before := canonical(w.p)
	one, _ := Decide(w.p, in)
	two, _ := Decide(w.p, in)
	if !reflect.DeepEqual(one, two) || canonical(w.p) != before {
		t.Fatal("Decide changed its input or differed between calls")
	}
}

// Failing controls: each breaks one thing on purpose and the harness must notice.

func expectFailure(t *testing.T, name string, seeds int, c codec) {
	t.Helper()
	for seed := int64(1); seed <= int64(seeds); seed++ {
		if failure, _ := runWalk(seed, 120, c); failure != "" {
			t.Logf("control %s caught: %s", name, failure)
			return
		}
	}
	t.Errorf("control %s: harness did not notice", name)
}

func TestControlMutatedTransitionTable(t *testing.T) {
	saved := receiptTransitions
	defer func() { receiptTransitions = saved }()
	mutants := map[string]map[Receipt][]Receipt{
		"final reopens": {
			ReceiptNone: {ReceiptIntent}, ReceiptIntent: saved[ReceiptIntent], ReceiptAccepted: saved[ReceiptAccepted], ReceiptUnknown: saved[ReceiptUnknown],
			ReceiptFinal: {ReceiptUnknown},
		},
		"unknown completes": {
			ReceiptNone: {ReceiptIntent}, ReceiptIntent: saved[ReceiptIntent], ReceiptAccepted: saved[ReceiptAccepted],
			ReceiptUnknown: {ReceiptAbandoned, ReceiptFinal},
		},
		"accepted cannot finish": {
			ReceiptNone: {ReceiptIntent}, ReceiptIntent: saved[ReceiptIntent], ReceiptAccepted: {ReceiptUnknown, ReceiptRejected, ReceiptAbandoned}, ReceiptUnknown: saved[ReceiptUnknown],
		},
	}
	for name, table := range mutants {
		receiptTransitions = table
		expectFailure(t, name, 50, realCodec)
	}
}

func TestControlReadOnlyFactsWidened(t *testing.T) {
	saved := readOnlyFacts
	defer func() { readOnlyFacts = saved }()
	widened := map[FactKind]bool{}
	for kind := range saved {
		widened[kind] = true
	}
	widened[FactControlRequested] = true
	readOnlyFacts = widened
	expectFailure(t, "read-only accepts a control", 50, realCodec)
}

func TestControlEncoderDropsField(t *testing.T) {
	expectFailure(t, "encoder drops CWD", 50, func(f Fact) (Fact, error) {
		decoded, err := realCodec(f)
		decoded.CWD = ""
		return decoded, err
	})
	expectFailure(t, "encoder drops request", 50, func(f Fact) (Fact, error) {
		decoded, err := realCodec(f)
		if decoded.Kind == FactProviderAccepted {
			decoded.Kind = FactProviderConnected
		}
		return decoded, err
	})
}

func TestDecodeCommandStrict(t *testing.T) {
	good, err := DecodeCommand([]byte(`{"kind":"abandon","sessionId":"s","expectedRequestId":"A","reason":"done"}`))
	if err != nil || good.Reason != "done" || good.ExpectedRequest != "A" {
		t.Fatalf("%+v %v", good, err)
	}
	for _, bad := range []string{`{"kind":"abandon","kind":"close"}`, `{"sessionid":"s"}`, `{"ſessionId":"s"}`, `{"principal":"user"}`, `{"kind":"close"} x`, `[]`, ""} {
		if _, err := DecodeCommand([]byte(bad)); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
