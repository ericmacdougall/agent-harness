package kernel

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// Each TestCatalog<ID> is an entry in plans/CONSOLE-KERNEL-CATALOG.md owned by K1a.
// These pin one scenario each. The independent check is model_test.go.

const testAt = "2026-11-03T10:00:00.000000000Z"

type rig struct {
	t *testing.T
	p Projection
}

func newRig(t *testing.T) *rig { return &rig{t: t, p: NewProjection()} }

func rr(text string) RedactedReason {
	return Redact(text, func(value string) string { return value })
}

func (r *rig) apply(in In) (Decision, error) {
	r.t.Helper()
	if in.At == "" {
		in.At = testAt
	}
	if in.Principal.Class == "" {
		if allowed := allowedPrincipals[in.Kind]; len(allowed) > 0 {
			in.Principal.Class = allowed[0]
		}
	}
	if in.Principal.SessionID == "" && in.Principal.Class == PrincipalProvider {
		in.Principal.SessionID = in.SessionID
	}
	if in.Kind == InSend && in.RuntimeIdentity == "" {
		in.RuntimeIdentity = "owner"
	}
	decision, err := Decide(r.p, in)
	for _, f := range decision.Facts {
		next, reduceErr := Reduce(r.p, f)
		if reduceErr != nil {
			r.t.Fatalf("Decide returned a fact Reduce refuses: %v", reduceErr)
		}
		r.p = next
	}
	return decision, err
}

func (r *rig) must(in In) Decision {
	r.t.Helper()
	decision, err := r.apply(in)
	if err != nil {
		r.t.Fatalf("%s: %v", in.Kind, err)
	}
	return decision
}

func (r *rig) refused(in In, code string) {
	r.t.Helper()
	before := r.p.LastSeq
	_, err := r.apply(in)
	var refusal *Refusal
	if !errors.As(err, &refusal) || refusal.Code != code {
		r.t.Fatalf("%s: got %v, want refusal %s", in.Kind, err, code)
	}
	if r.p.LastSeq != before {
		r.t.Fatal("refusal moved the log")
	}
}

func (r *rig) session(id string) *Session { return r.p.Sessions[id] }

// sent opens a session and leaves request A at intent, with Codex connected.
func (r *rig) sent(id, provider string) {
	r.t.Helper()
	r.must(In{Kind: InCreate, SessionID: id, Provider: provider})
	if provider == ProviderCodex {
		r.must(In{Kind: ObConnected, SessionID: id})
	}
	r.must(In{Kind: InSend, SessionID: id, RequestID: "A"})
}

// started leaves request A accepted, with the Codex turn bound.
func (r *rig) started(id, provider string) *Session {
	r.t.Helper()
	r.sent(id, provider)
	r.must(In{Kind: ObAccepted, SessionID: id, RequestID: "A"})
	if provider == ProviderCodex {
		r.must(In{Kind: ObTurnBound, SessionID: id, RequestID: "A", TurnID: "turn-A"})
	}
	return r.session(id)
}

func (r *rig) complete(id, request string) {
	r.t.Helper()
	r.must(In{Kind: ObCompleted, SessionID: id, RequestID: request, TurnID: r.session(id).TurnID, Status: "completed"})
}

func (r *rig) restart() {
	r.t.Helper()
	r.must(In{Kind: ObRestart})
}

func eachProvider(t *testing.T, run func(t *testing.T, provider string)) {
	for _, provider := range []string{ProviderCodex, ProviderClaude} {
		t.Run(provider, func(t *testing.T) { run(t, provider) })
	}
}

func TestCatalogR1(t *testing.T) {
	eachProvider(t, func(t *testing.T, provider string) {
		r := newRig(t)
		r.started("s", provider)
		r.restart()
		s := r.session("s")
		if s.LastRequest != "A" || s.Requests["A"] != ReceiptUnknown || !s.ReadOnly || Status(s) != "unknown" {
			t.Fatalf("request identity lost: %q %v %v %s", s.LastRequest, s.Requests, s.ReadOnly, Status(s))
		}
	})
	r := newRig(t)
	r.sent("s", ProviderClaude)
	r.restart()
	if got := r.session("s").Requests["A"]; got != ReceiptUnknown {
		t.Fatalf("intent after restart: %q", got)
	}
}

func TestCatalogR2(t *testing.T) {
	r := newRig(t)
	for i := 0; i < MaxVisibleSessions+8; i++ {
		id := fmt.Sprintf("s%02d", i)
		r.started(id, ProviderClaude)
		if i >= 3 {
			r.complete(id, "A")
		}
	}
	r.restart()
	visible := map[string]bool{}
	for _, s := range VisibleSessions(r.p) {
		visible[s.ID] = true
	}
	for _, id := range []string{"s00", "s01", "s02"} {
		if !visible[id] {
			t.Fatalf("unresolved %s dropped", id)
		}
	}
	if len(visible) != MaxVisibleSessions {
		t.Fatalf("%d visible", len(visible))
	}
	r = newRig(t)
	for i := 0; i < MaxVisibleSessions+5; i++ {
		r.started(fmt.Sprintf("u%02d", i), ProviderClaude)
	}
	r.restart()
	if got := len(VisibleSessions(r.p)); got != MaxVisibleSessions+5 {
		t.Fatalf("unresolved tabs trimmed: %d", got)
	}
}

func TestCatalogR3(t *testing.T) {
	r := newRig(t)
	for i := 0; i < MaxVisibleSessions+2; i++ {
		id := fmt.Sprintf("s%02d", i)
		r.started(id, ProviderClaude)
		r.complete(id, "A")
	}
	r.restart()
	if !r.session("s00").Hidden {
		t.Fatal("oldest resolved tab was not trimmed")
	}
	r.must(In{Kind: InClose, SessionID: "s25"})
	r.restart()
	for _, s := range VisibleSessions(r.p) {
		if s.ID == "s00" {
			t.Fatal("trimmed tab reappeared after another closed")
		}
	}
}

func TestCatalogR4(t *testing.T) {
	r := newRig(t)
	r.started("s", ProviderClaude)
	r.restart()
	revision := r.session("s").Revision
	decision, err := r.apply(In{Kind: InPause, SessionID: "s"})
	if err != nil || len(decision.Facts) != 0 || len(decision.Effects) != 1 || decision.Effects[0].Class != ClassStopWork {
		t.Fatalf("pause on read-only: %v %+v", err, decision)
	}
	s := r.session("s")
	if s.Revision != revision || Status(s) != "unknown" {
		t.Fatalf("authority changed: rev %d status %s", s.Revision, Status(s))
	}
	r.refused(In{Kind: InClose, SessionID: "s"}, "unresolved")
	// A resolved read-only session has nothing to stop.
	r = newRig(t)
	r.started("c", ProviderClaude)
	r.complete("c", "A")
	r.restart()
	r.refused(In{Kind: InStop, SessionID: "c"}, "read_only")
}

func TestCatalogR5(t *testing.T) {
	eachProvider(t, func(t *testing.T, provider string) {
		r := newRig(t)
		r.started("s", provider)
		r.complete("s", "A")
		r.must(In{Kind: ObAuthBoundary, Provider: provider})
		if got := Status(r.session("s")); got != "disconnected" {
			t.Fatalf("idle session after auth: %s", got)
		}
		before := r.session("s")
		r.restart()
		after := r.session("s")
		if got := Status(after); got != "disconnected" {
			t.Fatalf("after restart: %s", got)
		}
		rule := map[string]bool{"Requests": true, "ProviderFinal": true, "ReadOnly": true, "Connected": true, "TurnID": true, "PendingInterrupt": true, "Paused": true, "PauseUnconfirmed": true, "Hidden": true}
		beforeValue, afterValue := reflect.ValueOf(*before), reflect.ValueOf(*after)
		for i := 0; i < beforeValue.NumField(); i++ {
			name := beforeValue.Type().Field(i).Name
			if !rule[name] && !reflect.DeepEqual(beforeValue.Field(i).Interface(), afterValue.Field(i).Interface()) {
				t.Errorf("restart changed %s, outside its rule", name)
			}
		}
	})
}

func rawFact(p Projection, s *Session, f Fact) Fact {
	f.Seq, f.SchemaVersion, f.At = p.LastSeq+1, SchemaVersion, testAt
	if s != nil {
		f.SessionID, f.SessionRevision = s.ID, s.Revision+1
	}
	return f
}

func TestCatalogR6(t *testing.T) {
	r := newRig(t)
	r.started("s", ProviderClaude)
	if _, err := Reduce(r.p, rawFact(r.p, r.session("s"), Fact{Kind: FactCwdChanged, CWD: "/other"})); !errors.Is(err, ErrIllegalFact) {
		t.Fatalf("a cwd fact over an unresolved receipt was accepted: %v", err)
	}
	r.must(In{Kind: InPause, SessionID: "s"})
	r.refused(In{Kind: InChangeCWD, SessionID: "s", CWD: "/other"}, "unresolved")
	r.restart()
	if got := r.session("s").Requests["A"]; got != ReceiptUnknown {
		t.Fatalf("receipt hidden: %q", got)
	}
}

func TestCatalogR7(t *testing.T) {
	for _, state := range []string{"intent", "accepted", "unknown"} {
		r := newRig(t)
		r.sent("s", ProviderClaude)
		if state != "intent" {
			r.must(In{Kind: ObAccepted, SessionID: "s", RequestID: "A"})
		}
		if state == "unknown" {
			r.must(In{Kind: ObUnknown, SessionID: "s", RequestID: "A"})
		}
		r.refused(In{Kind: InChangeCWD, SessionID: "s", CWD: "/other"}, "unresolved")
	}
	r := newRig(t)
	r.started("s", ProviderClaude)
	r.complete("s", "A")
	r.must(In{Kind: InChangeCWD, SessionID: "s", CWD: "/other"})
	r.refused(In{Kind: InChangeCWD, SessionID: "s", CWD: "/bad\x07path"}, "bad_value")
	r.refused(In{Kind: InChangeCWD, SessionID: "s"}, "bad_request")
}

func TestCatalogR8(t *testing.T) {
	eachProvider(t, func(t *testing.T, provider string) {
		r := newRig(t)
		r.started("s", provider)
		r.must(In{Kind: InPause, SessionID: "s"})
		r.must(In{Kind: ObControlOutcome, SessionID: "s", Control: "pause", Outcome: "rejected"})
		if !r.session("s").PauseUnconfirmed {
			t.Fatal("rejected interrupt not visible")
		}
		r.refused(In{Kind: InClose, SessionID: "s"}, "unresolved")
		r.complete("s", "A")
		if r.session("s").PauseUnconfirmed {
			t.Fatal("stale unconfirmed message on a final turn")
		}
		r.must(In{Kind: InClose, SessionID: "s"})
	})
}

func TestCatalogT3(t *testing.T) {
	r := newRig(t)
	r.started("s", ProviderCodex)
	r.must(In{Kind: ObCompleted, SessionID: "s", RequestID: "A", TurnID: "turn-stale", Status: "completed"})
	s := r.session("s")
	if s.Requests["A"] != ReceiptAccepted || s.ProviderFinal || s.Evidence[evidenceKey("A", "final")] == "" {
		t.Fatalf("foreign turn: %q %v", s.Requests["A"], s.Evidence)
	}
	r.complete("s", "A")
	if r.session("s").Requests["A"] != ReceiptFinal {
		t.Fatal("exact final lost")
	}
}

func TestCatalogT4(t *testing.T) {
	r := newRig(t)
	r.started("s", ProviderClaude)
	r.must(In{Kind: ObCompleted, SessionID: "s", Status: "completed"})
	if got := r.session("s").Requests["A"]; got != ReceiptUnknown {
		t.Fatalf("unbound result: %q", got)
	}
}

func TestCatalogT5(t *testing.T) {
	eachProvider(t, func(t *testing.T, provider string) {
		r := newRig(t)
		r.started("s", provider)
		r.complete("s", "A")
		r.must(In{Kind: ObUnknown, SessionID: "s", RequestID: "A"})
		r.must(In{Kind: ObRefused, SessionID: "s", RequestID: "A"})
		r.refused(In{Kind: InAbandon, SessionID: "s", ExpectedRequest: "A", Reason: rr("x")}, "nothing_to_discard")
		r.must(In{Kind: ObAuthBoundary, Provider: provider})
		r.restart()
		if got := r.session("s").Requests["A"]; got != ReceiptFinal {
			t.Fatalf("final overwritten: %q", got)
		}
	})
	r := newRig(t)
	r.started("q", ProviderClaude)
	r.complete("q", "A")
	r.must(In{Kind: ObQuarantine, SessionID: "q", ReasonCode: "illegal_fact"})
	r.must(In{Kind: InAbandon, SessionID: "q", ExpectedRequest: "A", Reason: rr("stuck")})
	if got := r.session("q"); got.Requests["A"] != ReceiptFinal || got.Abandoned == nil || !got.ProviderFinal {
		t.Fatalf("release rewrote a final: %+v", got.Requests)
	}
}

func TestCatalogT6(t *testing.T) {
	legal := map[[2]Receipt]bool{}
	for from, list := range map[Receipt][]Receipt{
		ReceiptNone:     {ReceiptIntent},
		ReceiptIntent:   {ReceiptAccepted, ReceiptFinal, ReceiptUnknown, ReceiptRejected, ReceiptAbandoned},
		ReceiptAccepted: {ReceiptFinal, ReceiptUnknown, ReceiptRejected, ReceiptAbandoned},
		ReceiptUnknown:  {ReceiptAbandoned},
	} {
		for _, to := range list {
			legal[[2]Receipt{from, to}] = true
		}
	}
	all := []Receipt{ReceiptNone, ReceiptIntent, ReceiptAccepted, ReceiptFinal, ReceiptUnknown, ReceiptRejected, ReceiptAbandoned}
	checked := 0
	for _, from := range all {
		for _, to := range all {
			if to == ReceiptNone {
				continue
			}
			s := &Session{ID: "s", Requests: map[string]Receipt{}, LastRequest: "r"}
			if from != ReceiptNone {
				s.Requests["r"] = from
			}
			err := advance(s, Fact{Kind: FactProviderCompleted, SessionID: "s"}, "r", to)
			if (err == nil) != legal[[2]Receipt{from, to}] {
				t.Errorf("%q -> %q: err=%v", from, to, err)
			}
			if err != nil && s.Requests["r"] != from {
				t.Errorf("illegal %q -> %q wrote %q", from, to, s.Requests["r"])
			}
			checked++
		}
	}
	if checked != 42 {
		t.Fatalf("checked %d pairs", checked)
	}
}

func TestCatalogG2(t *testing.T) {
	eachProvider(t, func(t *testing.T, provider string) {
		for _, outcome := range []string{"rejected", "confirmed"} {
			r := newRig(t)
			r.started("s", provider)
			r.must(In{Kind: InPause, SessionID: "s"})
			r.must(In{Kind: ObControlOutcome, SessionID: "s", Control: "pause", Outcome: outcome})
			r.refused(In{Kind: InSend, SessionID: "s", RequestID: "B"}, "unresolved")
			if r.session("s").LastRequest != "A" {
				t.Fatal("unresolved turn replaced")
			}
			r.complete("s", "A")
			r.must(In{Kind: InSend, SessionID: "s", RequestID: "C"})
		}
	})
}

func TestCatalogG3(t *testing.T) {
	r := newRig(t)
	r.sent("s", ProviderCodex)
	decision := r.must(In{Kind: InPause, SessionID: "s"})
	if len(decision.Effects) != 0 {
		t.Fatalf("Pause guessed a turn: %+v", decision.Effects)
	}
	decision = r.must(In{Kind: ObTurnBound, SessionID: "s", RequestID: "A", TurnID: "turn-A"})
	if len(decision.Effects) != 1 || decision.Effects[0].Kind != EffectInterrupt || decision.Effects[0].TurnID != "turn-A" {
		t.Fatalf("bound turn not interrupted: %+v", decision.Effects)
	}
	decision = r.must(In{Kind: ObTurnBound, SessionID: "s", RequestID: "A", TurnID: "turn-A"})
	if len(decision.Effects) != 0 || !decision.Idempotent {
		t.Fatal("interrupt fired twice")
	}
}

func TestCatalogG5(t *testing.T) {
	eachProvider(t, func(t *testing.T, provider string) {
		r := newRig(t)
		s := r.started("s", provider)
		fence := s.ControlEpoch
		decision := r.must(In{Kind: ObAuthBoundary, Provider: provider})
		if len(decision.Effects) != 1 || decision.Effects[0].Class != ClassStopWork {
			t.Fatalf("no stop effect: %+v", decision.Effects)
		}
		s = r.session("s")
		if s.ControlEpoch == fence || !s.ReadOnly || s.Requests["A"] != ReceiptUnknown {
			t.Fatalf("authority survived: %+v", s)
		}
		r.refused(In{Kind: InSend, SessionID: "s", RequestID: "B"}, "read_only")
	})
	r := newRig(t)
	r.must(In{Kind: InCreate, SessionID: "a", Provider: ProviderClaude, ProfileID: "one"})
	r.must(In{Kind: InCreate, SessionID: "b", Provider: ProviderClaude, ProfileID: "two"})
	r.must(In{Kind: ObAuthBoundary, Provider: ProviderClaude, ProfileID: "one"})
	if !r.session("a").ReadOnly || r.session("b").ReadOnly {
		t.Fatal("boundary crossed profiles")
	}
	r.refused(In{Kind: ObAuthBoundary, Provider: "claudee"}, "bad_provider")
}

func TestCatalogP6(t *testing.T) {
	r := newRig(t)
	r.must(In{Kind: InCreate, SessionID: "s", Provider: ProviderClaude})
	before := r.p
	decision, err := Decide(before, In{Kind: InSend, Principal: Principal{Class: PrincipalUser}, At: testAt, SessionID: "s", RequestID: "A", RuntimeIdentity: "owner"})
	if err != nil || len(decision.Facts) == 0 {
		t.Fatal(err)
	}
	if s := before.Sessions["s"]; s.LastRequest != "" || len(s.Requests) != 0 {
		t.Fatalf("Decide published state: %+v", s)
	}
}

func TestCatalogP7(t *testing.T) {
	eachProvider(t, func(t *testing.T, provider string) {
		r := newRig(t)
		r.sent("s", provider)
		r.must(In{Kind: ObRefused, SessionID: "s", RequestID: "A", ReasonCode: "over_capacity"})
		s := r.session("s")
		if s.LastRefusal != "over_capacity" || Status(s) != "error" {
			t.Fatalf("no visible reason: %q %s", s.LastRefusal, Status(s))
		}
		r.must(In{Kind: InSend, SessionID: "s", RequestID: "B"})
		if s := r.session("s"); s.LastRefusal != "" {
			t.Fatal("reason outlived the next send")
		}
	})
}

func TestCatalogD2(t *testing.T) {
	eachProvider(t, func(t *testing.T, provider string) {
		r := newRig(t)
		r.started("s", provider)
		r.must(In{Kind: InPause, SessionID: "s"})
		decision := r.must(In{Kind: InAbandon, SessionID: "s", ExpectedRequest: "A", Reason: rr("  done waiting  ")})
		if len(decision.Facts) != 1 || decision.Facts[0].Kind != FactAbandoned || decision.Facts[0].Reason != "done waiting" || decision.Facts[0].RequestID != "A" || decision.Facts[0].At != testAt {
			t.Fatalf("fact: %+v", decision.Facts)
		}
		got := r.session("s")
		if got.Requests["A"] != ReceiptAbandoned || got.ProviderFinal || Status(got) != "abandoned" {
			t.Fatalf("minted an outcome: %+v", got)
		}
		r.refused(In{Kind: InAbandon, Principal: Principal{Class: PrincipalProvider, SessionID: "s"}, SessionID: "s", ExpectedRequest: "A", Reason: rr("x")}, "forbidden")
	})
	r := newRig(t)
	r.started("s", ProviderClaude)
	r.refused(In{Kind: InAbandon, SessionID: "s", ExpectedRequest: "A", Reason: rr("x")}, "stop_first")
	r.must(In{Kind: InPause, SessionID: "s"})
	r.refused(In{Kind: InAbandon, SessionID: "s", ExpectedRequest: "B", Reason: rr("x")}, "turn_changed")
	r.refused(In{Kind: InAbandon, SessionID: "s", ExpectedRequest: "A", Reason: rr(" ")}, "bad_reason")
	r.refused(In{Kind: InAbandon, SessionID: "s", ExpectedRequest: "A", Reason: rr(strings.Repeat("x", 501))}, "bad_reason")
}

func TestCatalogD3(t *testing.T) {
	r := newRig(t)
	r.started("s", ProviderCodex)
	r.must(In{Kind: InPause, SessionID: "s"})
	r.must(In{Kind: InAbandon, SessionID: "s", ExpectedRequest: "A", Reason: rr("done")})
	r.must(In{Kind: ObCompleted, SessionID: "s", RequestID: "A", TurnID: "turn-A", Status: "completed"})
	s := r.session("s")
	if s.Requests["A"] != ReceiptAbandoned || s.ProviderFinal || s.Evidence[evidenceKey("A", "final")] == "" {
		t.Fatalf("late final changed the turn: %+v", s)
	}
}

func TestCatalogD4(t *testing.T) {
	r := newRig(t)
	r.started("s", ProviderClaude)
	r.must(In{Kind: InPause, SessionID: "s"})
	r.must(In{Kind: InAbandon, SessionID: "s", ExpectedRequest: "A", Reason: rr("first")})
	seq := r.p.LastSeq
	decision := r.must(In{Kind: InAbandon, SessionID: "s", ExpectedRequest: "A", Reason: rr("second"), At: "2026-11-04T00:00:00.000000000Z"})
	if !decision.Idempotent || r.p.LastSeq != seq || r.session("s").Abandoned.Reason != "first" || r.session("s").Abandoned.At != testAt {
		t.Fatalf("retry changed the decision: %+v", r.session("s").Abandoned)
	}
	r.refused(In{Kind: InAbandon, SessionID: "s", ExpectedRequest: "older", Reason: rr("x")}, "discarded_other")
	if _, err := Reduce(r.p, rawFact(r.p, r.session("s"), Fact{Kind: FactAbandoned, RequestID: "A", Reason: "x"})); !errors.Is(err, ErrIllegalFact) {
		t.Fatalf("second abandon accepted: %v", err)
	}
}

func TestCatalogD6(t *testing.T) {
	r := newRig(t)
	r.started("s", ProviderClaude)
	r.complete("s", "A")
	r.refused(In{Kind: InAbandon, SessionID: "s", ExpectedRequest: "A", Reason: rr("late")}, "nothing_to_discard")
	if s := r.session("s"); s.Requests["A"] != ReceiptFinal || s.Abandoned != nil {
		t.Fatal("final changed")
	}
}

func TestCatalogD11(t *testing.T) {
	eachProvider(t, func(t *testing.T, provider string) {
		r := newRig(t)
		r.started("s", provider)
		r.must(In{Kind: InPause, SessionID: "s"})
		r.must(In{Kind: InAbandon, SessionID: "s", ExpectedRequest: "A", Reason: rr("done")})
		epoch := r.session("s").ControlEpoch
		r.refused(In{Kind: InChangeCWD, SessionID: "s", CWD: "/x"}, "read_only")
		r.refused(In{Kind: InSend, SessionID: "s", RequestID: "B"}, "read_only")
		r.must(In{Kind: ObRefused, SessionID: "s", RequestID: "A"})
		r.must(In{Kind: ObUnknown, SessionID: "s", RequestID: "A"})
		r.must(In{Kind: ObDisconnected, SessionID: "s"})
		if decision := r.must(In{Kind: ObAuthBoundary, Provider: provider}); len(decision.Facts) != 0 {
			t.Fatal("auth boundary touched a discarded session")
		}
		s := r.session("s")
		if s.ControlEpoch != epoch || s.Requests["A"] != ReceiptAbandoned || Status(s) != "abandoned" {
			t.Fatalf("discarded tab changed: %d %q %s", s.ControlEpoch, s.Requests["A"], Status(s))
		}
		for _, kind := range []FactKind{FactControlRequested, FactCwdChanged, FactAuthBoundaryCrossed, FactRequestIntended, FactProviderCompleted, FactProviderConnected} {
			if _, err := Reduce(r.p, rawFact(r.p, s, Fact{Kind: kind, RequestID: "A", Control: "pause", Status: "completed"})); !errors.Is(err, ErrIllegalFact) {
				t.Errorf("%s accepted: %v", kind, err)
			}
		}
		r.must(In{Kind: InClose, SessionID: "s"})
	})
}

func TestCatalogE1(t *testing.T) {
	eachProvider(t, func(t *testing.T, provider string) {
		for _, later := range []In{{Kind: InPause, SessionID: "s"}, {Kind: ObAuthBoundary, Provider: provider}, {Kind: ObQuarantine, SessionID: "s", ReasonCode: "bad"}} {
			r := newRig(t)
			r.must(In{Kind: InCreate, SessionID: "s", Provider: provider})
			if provider == ProviderCodex {
				r.must(In{Kind: ObConnected, SessionID: "s"})
			}
			decision := r.must(In{Kind: InSend, SessionID: "s", RequestID: "A"})
			if decision.Effects[0].Class != ClassNewWork {
				t.Fatalf("class %s", decision.Effects[0].Class)
			}
			r.must(later)
			if r.session("s").ControlEpoch == decision.Effects[0].Fence {
				t.Fatalf("%s did not move the fence, so a queued write would still pass", later.Kind)
			}
		}
	})
}

func TestCatalogE4(t *testing.T) {
	r := newRig(t)
	r.sent("s", ProviderCodex)
	r.must(In{Kind: InPause, SessionID: "s"})
	r.must(In{Kind: InAbandon, SessionID: "s", ExpectedRequest: "A", Reason: rr("done")})
	if !r.session("s").PendingInterrupt {
		t.Fatal("pending interrupt lost at discard")
	}
	decision := r.must(In{Kind: ObTurnBound, SessionID: "s", RequestID: "A", TurnID: "turn-A"})
	if len(decision.Effects) != 1 || decision.Effects[0].Kind != EffectInterrupt {
		t.Fatalf("interrupt not emitted on an abandoned request: %+v", decision.Effects)
	}
	if r.session("s").Requests["A"] != ReceiptAbandoned {
		t.Fatal("receipt changed")
	}
}

// recordFacts builds a two-session log with one good and one bad session.
func recordFacts(t *testing.T) []Fact {
	t.Helper()
	r := newRig(t)
	facts := []Fact{}
	for _, in := range []In{
		{Kind: InCreate, SessionID: "good", Provider: ProviderClaude},
		{Kind: InSend, SessionID: "good", RequestID: "A"},
		{Kind: InCreate, SessionID: "bad", Provider: ProviderClaude},
		{Kind: InSend, SessionID: "bad", RequestID: "A"},
	} {
		facts = append(facts, r.must(in).Facts...)
	}
	return facts
}

func TestCatalogV1(t *testing.T) {
	facts := recordFacts(t)
	last := facts[len(facts)-1]
	facts = append(facts, Fact{Seq: last.Seq + 1, SchemaVersion: SchemaVersion, At: testAt, Kind: FactProviderCompleted, SessionID: "bad", SessionRevision: 99, RequestID: "A", Status: "completed"})
	p, quarantined, err := Replay(facts)
	if err != nil {
		t.Fatalf("a bad fact stopped the console: %v", err)
	}
	if len(quarantined) != 1 || quarantined[0].SessionID != "bad" {
		t.Fatalf("quarantined %+v", quarantined)
	}
	if s := p.Sessions["bad"]; s.Quarantine == "" || !s.ReadOnly || Status(s) != "unknown" {
		t.Fatalf("bad session not quarantined: %+v", s)
	}
	if p.Sessions["good"].ReadOnly {
		t.Fatal("good session affected")
	}
	// Discard and close survive the next replay.
	q := &rig{t: t, p: p}
	for _, in := range []In{{Kind: InAbandon, SessionID: "bad", ExpectedRequest: "A", Reason: rr("stuck")}, {Kind: InClose, SessionID: "bad"}} {
		facts = append(facts, q.must(in).Facts...)
	}
	again, _, err := Replay(facts)
	if err != nil {
		t.Fatal(err)
	}
	if s := again.Sessions["bad"]; s.Abandoned == nil || !s.Closed || !reflect.DeepEqual(again, q.p) {
		t.Fatalf("restart undid the exit: %+v", s)
	}
	// A later slice's kind quarantines rather than refusing.
	if _, list, err := Replay(append(recordFacts(t), Fact{Seq: last.Seq + 1, SchemaVersion: SchemaVersion, At: testAt, Kind: ReservedFactKinds[0], SessionID: "good", SessionRevision: 9})); err != nil || len(list) != 1 {
		t.Fatalf("reserved kind: %v %+v", err, list)
	}
	for _, broken := range []Fact{
		{Seq: last.Seq + 1, SchemaVersion: 99, At: testAt, Kind: FactProviderConnected, SessionID: "good"},
		{Seq: last.Seq + 1, SchemaVersion: SchemaVersion, At: testAt, Kind: FactKind("FutureFact"), SessionID: "good"},
		{Seq: 1, SchemaVersion: SchemaVersion, At: testAt, Kind: FactProviderConnected, SessionID: "good"},
	} {
		if _, _, err := Replay(append(recordFacts(t), broken)); !errors.Is(err, ErrUnreadableLog) {
			t.Fatalf("%+v: %v", broken, err)
		}
	}
}

func TestCatalogV3(t *testing.T) {
	f := Fact{Seq: 7, SchemaVersion: SchemaVersion, At: "2026-11-03T10:00:00.123456789Z", Kind: FactLegacyImported, SessionID: "s", SessionRevision: 1, Passes: map[string]string{"plan": "d"}, Receipt: ReceiptFinal}
	data, err := EncodeFact(f)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeFact(data)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := EncodeFact(decoded)
	if string(again) != string(data) || !reflect.DeepEqual(decoded, f) {
		t.Fatalf("not canonical: %s vs %s", again, data)
	}
	for _, bad := range []string{`{"seq":1,"seq":2}`, `{"ſeq":1}`, `{"SEQ":1}`, `{"unknown":1}`, `[1]`, `{"seq":1} trailing`, `{"passes":{"a":"1","a":"2"}}`, ""} {
		if _, err := DecodeFact([]byte(bad)); !errors.Is(err, ErrMalformedFact) {
			t.Errorf("%q accepted: %v", bad, err)
		}
	}
}

func TestCatalogS2(t *testing.T) {
	r := newRig(t)
	r.started("s", ProviderCodex)
	r.complete("s", "A")
	seq := r.p.LastSeq
	for i := 0; i < 1000; i++ {
		r.must(In{Kind: ObCompleted, SessionID: "s", RequestID: "A", TurnID: "x", Status: []string{"completed", "failed"}[i%2], Digest: fmt.Sprintf("digest%d", i)})
		r.must(In{Kind: ObCompleted, SessionID: "s", RequestID: fmt.Sprintf("foreign%d", i), TurnID: "x", Status: "completed"})
	}
	if got := r.p.LastSeq - seq; got != 2 {
		t.Fatalf("noisy provider appended %d facts", got)
	}
	if got := len(r.session("s").Evidence); got != 2 {
		t.Fatalf("evidence grew to %d", got)
	}
}

func TestCatalogI9(t *testing.T) {
	for _, row := range []struct {
		receipt Receipt
		request string
	}{{ReceiptFinal, "A"}, {ReceiptRejected, "A"}, {ReceiptUnknown, "A"}, {ReceiptAbandoned, "A"}, {ReceiptNone, ""}} {
		r := newRig(t)
		var err error
		r.p, err = Reduce(r.p, Fact{Seq: 1, SchemaVersion: SchemaVersion, At: testAt, Kind: FactLegacyImported, SessionID: "s", SessionRevision: 1, Provider: ProviderClaude, ProviderID: "conv", RequestID: row.request, Receipt: row.receipt, TaskID: "t", Reason: "old"})
		if err != nil || !r.session("s").ReadOnly {
			t.Fatalf("%q not imported read-only: %v", row.receipt, err)
		}
		if row.receipt == ReceiptUnknown {
			r.refused(In{Kind: InClose, SessionID: "s"}, "unresolved")
			r.must(In{Kind: InAbandon, SessionID: "s", ExpectedRequest: "A", Reason: rr("done")})
		}
		r.must(In{Kind: InClose, SessionID: "s"})
	}
	// A quarantined session with no receipt reaches close too.
	r := newRig(t)
	r.must(In{Kind: InCreate, SessionID: "s", Provider: ProviderClaude})
	r.must(In{Kind: ObQuarantine, SessionID: "s", ReasonCode: "bad"})
	r.refused(In{Kind: InClose, SessionID: "s"}, "unresolved")
	r.must(In{Kind: InAbandon, SessionID: "s", Reason: rr("stuck")})
	r.must(In{Kind: InClose, SessionID: "s"})
	for _, bad := range []Receipt{ReceiptIntent, ReceiptAccepted} {
		if _, err := Reduce(NewProjection(), Fact{Seq: 1, SchemaVersion: SchemaVersion, At: testAt, Kind: FactLegacyImported, SessionID: "s", SessionRevision: 1, RequestID: "A", Receipt: bad}); !errors.Is(err, ErrIllegalFact) {
			t.Fatalf("imported %q as if confirmed: %v", bad, err)
		}
	}
}

func TestCatalogL1(t *testing.T) {
	eachProvider(t, func(t *testing.T, provider string) {
		r := newRig(t)
		r.started("idle", provider)
		r.complete("idle", "A")
		r.started("busy", provider)
		r.must(In{Kind: ObAuthBoundary, Provider: provider})
		if got := r.session("idle").Requests["A"]; got != ReceiptFinal || Status(r.session("idle")) == "unknown" {
			t.Fatalf("idle receipt: %q", got)
		}
		if got := r.session("busy").Requests["A"]; got != ReceiptUnknown {
			t.Fatalf("busy receipt: %q", got)
		}
		r.must(In{Kind: InClose, SessionID: "idle"})
	})
}

// Regressions from the K1 inspections that stayed in scope.

func TestK1F2StickyEvidence(t *testing.T) {
	r := newRig(t)
	r.started("s", ProviderCodex)
	r.complete("s", "A")
	seq := r.p.LastSeq
	for i := 0; i < 1000; i++ {
		r.must(In{Kind: ObCompleted, SessionID: "s", RequestID: "A", TurnID: "x", Status: []string{"completed", "failed"}[i%2]})
	}
	if got := r.p.LastSeq - seq; got != 1 {
		t.Fatalf("appended %d facts", got)
	}
}

func TestK1F3ControlIsClosed(t *testing.T) {
	r := newRig(t)
	r.started("s", ProviderClaude)
	decision := r.must(In{Kind: ObControlOutcome, SessionID: "s", Control: "Bearer secret-value", Status: "Bearer secret-value", Outcome: "confirmed"})
	for _, f := range decision.Facts {
		if strings.Contains(fmt.Sprintf("%+v", f), "secret") {
			t.Fatalf("free text in fact: %+v", f)
		}
	}
	for name, f := range map[string]Fact{
		"control":    {Kind: FactControlOutcome, Control: "free text", Outcome: "confirmed"},
		"outcome":    {Kind: FactControlOutcome, Control: "pause", Outcome: "free"},
		"status":     {Kind: FactProviderCompleted, RequestID: "A", Status: "free text"},
		"reasonCode": {Kind: FactOutcomeUnknown, RequestID: "A", ReasonCode: "Bearer secret-value"},
		"lateKind":   {Kind: FactLateFrameObserved, LateKind: "free"},
		"latestatus": {Kind: FactLateFrameObserved, LateKind: "final", Status: "Free Text"},
		"digest":     {Kind: FactLateFrameObserved, LateKind: "final", Digest: "free text"},
		"state":      {Kind: FactProviderConnected, State: "anything"},
		"reason":     {Kind: FactCwdChanged, CWD: "/x", Reason: "free"},
		"control2":   {Kind: FactProviderConnected, Control: "pause"},
	} {
		if _, err := Reduce(r.p, rawFact(r.p, r.session("s"), f)); !errors.Is(err, ErrIllegalFact) {
			t.Errorf("%s accepted: %v", name, err)
		}
	}
}

func TestK1F4F5ConnectionAndOwner(t *testing.T) {
	r := newRig(t)
	r.refused(In{Kind: InCreate, SessionID: "s", Provider: ProviderCodex, ProviderID: "existing"}, "no_owner")
	r.must(In{Kind: InCreate, SessionID: "s", Provider: ProviderClaude, ProviderID: "existing", RuntimeIdentity: "owner"})
	if s := r.session("s"); !s.ConversationStarted || s.Connected {
		t.Fatalf("create: %+v", s)
	}
	r.refused(In{Kind: InSend, SessionID: "s", RequestID: "A", RuntimeIdentity: "other"}, "runtime_changed")
	// A create input cannot set the connection: only a provider fact can.
	r.must(In{Kind: InCreate, SessionID: "c", Provider: ProviderCodex, Status: "connected"})
	if r.session("c").Connected {
		t.Fatal("create set Connected")
	}
	r.refused(In{Kind: InSend, SessionID: "c", RequestID: "A"}, "disconnected")
	// Only a conversation started with a recorded owner can be continued.
	r.must(In{Kind: InCreate, SessionID: "u", Provider: ProviderClaude})
	r.refused(In{Kind: ObConversationBound, SessionID: "u", ProviderID: "conv"}, "no_owner")
	r.must(In{Kind: ObConversationBound, SessionID: "u", ProviderID: "conv", RuntimeIdentity: "owner"})
	r.must(In{Kind: ObConversationBound, SessionID: "u", ProviderID: "other", RuntimeIdentity: "owner"})
	if got := r.session("u").ProviderID; got != "conv" {
		t.Fatalf("conversation replaced by %s", got)
	}
}

func TestK1F6ParentStopSurvivesBoundaryAndDiscard(t *testing.T) {
	r := newRig(t)
	r.started("s", ProviderCodex)
	r.must(In{Kind: ObAuthBoundary, Provider: ProviderCodex})
	decision, err := r.apply(In{Kind: InStop, SessionID: "s"})
	if err != nil || len(decision.Effects) != 1 || decision.Effects[0].TurnID != "turn-A" {
		t.Fatalf("stop after boundary: %v %+v", err, decision)
	}
	r = newRig(t)
	r.started("c", ProviderClaude)
	r.must(In{Kind: InPause, SessionID: "c"})
	r.must(In{Kind: InAbandon, SessionID: "c", ExpectedRequest: "A", Reason: rr("done")})
	decision, err = r.apply(In{Kind: InStop, SessionID: "c"})
	if err != nil || len(decision.Effects) != 1 || decision.Effects[0].Kind != EffectTerminate {
		t.Fatalf("terminate cannot be retried after discard: %v %+v", err, decision)
	}
}

func TestK1F10DecideReturnsOnlyWhatSurvivesTheCodec(t *testing.T) {
	r := newRig(t)
	r.started("s", ProviderClaude)
	r.must(In{Kind: InPause, SessionID: "s"})
	r.refused(In{Kind: InAbandon, SessionID: "s", ExpectedRequest: "A", Reason: rr(strings.Repeat("\xff", 200))}, "bad_value")
	r2 := newRig(t)
	r2.refused(In{Kind: InCreate, SessionID: "s", Provider: ProviderClaude, CWD: "/bad\xffpath"}, "bad_value")
}

func TestStickyInterruptSurvivesEveryLaterFact(t *testing.T) {
	cases := map[string][]In{
		"pause then unknown":      {{Kind: InPause, SessionID: "s"}, {Kind: ObUnknown, SessionID: "s", RequestID: "A", ReasonCode: "deadline"}},
		"unknown then stop":       {{Kind: ObUnknown, SessionID: "s", RequestID: "A", ReasonCode: "deadline"}, {Kind: InStop, SessionID: "s"}},
		"auth while unbound":      {{Kind: ObAuthBoundary, Provider: ProviderCodex}},
		"quarantine":              {{Kind: ObQuarantine, SessionID: "s", ReasonCode: "bad"}},
		"stop then disconnect":    {{Kind: InStop, SessionID: "s"}, {Kind: ObDisconnected, SessionID: "s"}},
		"discard then quarantine": {{Kind: InPause, SessionID: "s"}, {Kind: InAbandon, SessionID: "s", ExpectedRequest: "A", Reason: rr("x")}, {Kind: ObQuarantine, SessionID: "s", ReasonCode: "bad"}},
		"discard then close":      {{Kind: InPause, SessionID: "s"}, {Kind: InAbandon, SessionID: "s", ExpectedRequest: "A", Reason: rr("x")}, {Kind: InClose, SessionID: "s"}},
	}
	for name, steps := range cases {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			r.sent("s", ProviderCodex)
			for _, step := range steps {
				r.must(step)
			}
			decision := r.must(In{Kind: ObTurnBound, SessionID: "s", RequestID: "A", TurnID: "turn-A"})
			if len(decision.Effects) != 1 || decision.Effects[0].Kind != EffectInterrupt {
				t.Fatalf("late bind did not interrupt: %+v", decision)
			}
		})
	}
}

func TestAuthorizationIsDefaultDeny(t *testing.T) {
	r := newRig(t)
	r.sent("s", ProviderClaude)
	user := Principal{Class: PrincipalUser}
	provider := Principal{Class: PrincipalProvider, SessionID: "s"}
	foreign := Principal{Class: PrincipalProvider, SessionID: "other"}
	for name, in := range map[string]In{
		"user forges final":     {Kind: ObCompleted, Principal: user, SessionID: "s", RequestID: "A", Status: "completed"},
		"foreign session frame": {Kind: ObCompleted, Principal: foreign, SessionID: "s", RequestID: "A", Status: "completed"},
		"user forges restart":   {Kind: ObRestart, Principal: user},
		"provider restarts":     {Kind: ObRestart, Principal: provider},
		"provider discards":     {Kind: InAbandon, Principal: provider, SessionID: "s", ExpectedRequest: "A", Reason: rr("x")},
		"provider boundary":     {Kind: ObAuthBoundary, Principal: provider, SessionID: "s", Provider: ProviderClaude},
		"no principal":          {Kind: InPause, SessionID: "s"},
		"unlisted kind":         {Kind: InputKind("future"), Principal: user, SessionID: "s"},
	} {
		t.Run(name, func(t *testing.T) {
			in.At = testAt
			decision, err := Decide(r.p, in)
			var refusal *Refusal
			if !errors.As(err, &refusal) || refusal.Code != "forbidden" || len(decision.Facts) != 0 {
				t.Fatalf("got %v %+v", err, decision)
			}
		})
	}
}

// Every catalog row owned by K1a must have its test here.
func TestCatalogCoverage(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "plans", "CONSOLE-KERNEL-CATALOG.md"))
	if err != nil {
		t.Fatalf("catalog is required: %v", err)
	}
	row := regexp.MustCompile(`^\| ([A-Z]\d+) \|`)
	k1a := regexp.MustCompile(`\bK1a\b`)
	owned := []string{}
	for _, line := range strings.Split(string(data), "\n") {
		match := row.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		cells := strings.Split(strings.Trim(line, "| "), "|")
		if k1a.MatchString(cells[len(cells)-1]) {
			owned = append(owned, match[1])
		}
	}
	if len(owned) < 20 {
		t.Fatalf("parsed only %d K1a rows", len(owned))
	}
	file, err := parser.ParseFile(token.NewFileSet(), "catalog_test.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	present := map[string]bool{}
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok {
			present[fn.Name.Name] = true
		}
	}
	for _, id := range owned {
		if !present["TestCatalog"+id] {
			t.Errorf("catalog entry %s has no TestCatalog%s", id, id)
		}
	}
}
