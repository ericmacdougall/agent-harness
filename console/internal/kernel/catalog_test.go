package kernel

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Each TestCatalog<ID> is an entry in plans/CONSOLE-KERNEL-CATALOG.md owned by K1.

const testAt = "2026-11-03T10:00:00.000000000Z"

type rig struct {
	t *testing.T
	p Projection
}

func newRig(t *testing.T) *rig { return &rig{t: t, p: NewProjection()} }

// apply commits the way the log will: facts round-trip through the real codec and
// only decoded facts are reduced.
func (r *rig) apply(in In) (Decision, error) {
	r.t.Helper()
	if in.At == "" {
		in.At = testAt
	}
	if in.Principal.Class == "" {
		in.Principal.Class = PrincipalUser
		if !isCommand(in.Kind) {
			in.Principal.Class = PrincipalProvider
		}
	}
	decision, err := Decide(r.p, in)
	for _, f := range decision.Facts {
		data, encodeErr := EncodeFact(f)
		if encodeErr != nil {
			r.t.Fatal(encodeErr)
		}
		decoded, decodeErr := DecodeFact(data)
		if decodeErr != nil {
			r.t.Fatal(decodeErr)
		}
		next, reduceErr := Reduce(r.p, decoded)
		if reduceErr != nil {
			r.t.Fatalf("Decide emitted an illegal fact: %v", reduceErr)
		}
		r.p = next
	}
	return decision, err
}

func isCommand(kind InputKind) bool {
	switch kind {
	case InCreate, InSend, InDispatchInput, InPause, InStop, InResume, InChildControl, InChangeCWD, InClose, InAbandon, InAnswer, InQueueInput, InDiscardInput:
		return true
	}
	return false
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
	before := r.p
	decision, err := r.apply(in)
	var refusal *Refusal
	if !errors.As(err, &refusal) || refusal.Code != code {
		r.t.Fatalf("%s: got %v, want refusal %s", in.Kind, err, code)
	}
	if len(decision.Facts) == 0 && before.LastSeq != r.p.LastSeq {
		r.t.Fatal("refusal moved the log")
	}
}

func (r *rig) session(id string) *Session { return r.p.Sessions[id] }

// started opens a session and a request in the given provider, leaving it accepted.
func (r *rig) started(id, provider string) *Session {
	r.t.Helper()
	r.must(In{Kind: InCreate, SessionID: id, Provider: provider, ProviderID: "conv-" + id, Status: "connected"})
	r.must(In{Kind: InSend, SessionID: id, RequestID: "A", TaskID: "task-" + id, Generation: 1, ObjectiveHash: "objective", RemainingBursts: 3})
	r.must(In{Kind: ObAccepted, SessionID: id, RequestID: "A"})
	if provider == ProviderCodex {
		r.must(In{Kind: ObTurnBound, SessionID: id, RequestID: "A", TurnID: "turn-A"})
	}
	return r.session(id)
}

func (r *rig) complete(id, request string) {
	r.t.Helper()
	turn := ""
	if r.session(id).Provider == ProviderCodex {
		turn = r.session(id).TurnID
	}
	r.must(In{Kind: ObCompleted, SessionID: id, RequestID: request, TurnID: turn, Status: "completed"})
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
	r.must(In{Kind: InCreate, SessionID: "s", Provider: ProviderClaude})
	r.must(In{Kind: InSend, SessionID: "s", RequestID: "A", TaskID: "t", Generation: 1})
	r.restart()
	if got := r.session("s").Requests["A"]; got != ReceiptUnknown {
		t.Fatalf("intent after restart: %q", got)
	}
}

func TestCatalogR2(t *testing.T) {
	r := newRig(t)
	for i := 0; i < MaxVisibleSessions+8; i++ {
		id := "s" + string(rune('A'+i))
		if i < 3 {
			r.started(id, ProviderClaude)
			continue
		}
		r.started(id, ProviderClaude)
		r.complete(id, "A")
	}
	r.restart()
	visible := map[string]bool{}
	for _, s := range VisibleSessions(r.p) {
		visible[s.ID] = true
	}
	for _, id := range []string{"sA", "sB", "sC"} {
		if !visible[id] {
			t.Fatalf("unresolved %s dropped", id)
		}
	}
	if len(visible) != MaxVisibleSessions {
		t.Fatalf("%d visible", len(visible))
	}
	// Everything past the limit still unresolved stays visible.
	r = newRig(t)
	for i := 0; i < MaxVisibleSessions+5; i++ {
		r.started("u"+string(rune('A'+i)), ProviderClaude)
	}
	r.restart()
	if got := len(VisibleSessions(r.p)); got != MaxVisibleSessions+5 {
		t.Fatalf("unresolved tabs trimmed: %d", got)
	}
}

func TestCatalogR3(t *testing.T) {
	r := newRig(t)
	for i := 0; i < MaxVisibleSessions+2; i++ {
		id := "s" + string(rune('A'+i))
		r.started(id, ProviderClaude)
		r.complete(id, "A")
	}
	r.restart()
	if !r.session("sA").Hidden {
		t.Fatal("oldest resolved tab was not trimmed")
	}
	r.must(In{Kind: InClose, SessionID: "sZ"})
	r.restart() // Skipped as a repeat only if nothing happened since.
	for _, s := range VisibleSessions(r.p) {
		if s.ID == "sA" {
			t.Fatal("trimmed tab reappeared after another closed")
		}
	}
}

func TestCatalogR4(t *testing.T) {
	r := newRig(t)
	r.started("s", ProviderClaude)
	r.restart()
	before := r.session("s")
	revision := before.Revision
	decision, err := r.apply(In{Kind: InPause, SessionID: "s"})
	if err == nil || len(decision.Facts) != 0 {
		t.Fatalf("pause on read-only: %v %v", err, decision.Facts)
	}
	s := r.session("s")
	if s.Revision != revision || Status(s) != "unknown" {
		t.Fatalf("authority changed: rev %d status %s", s.Revision, Status(s))
	}
	r.refused(In{Kind: InClose, SessionID: "s"}, "unresolved")
	// A stop effect still fires where there may be a writer, and changes no authority.
	r = newRig(t)
	r.started("c", ProviderCodex)
	r.must(In{Kind: InPause, SessionID: "c"})
	r.must(In{Kind: InAbandon, SessionID: "c", ExpectedRequest: "A", Reason: "done"})
	revision = r.session("c").Revision
	decision, err = r.apply(In{Kind: InStop, SessionID: "c"})
	if err != nil || len(decision.Facts) != 0 || len(decision.Effects) != 1 || decision.Effects[0].Class != ClassStopWork || decision.Effects[0].TurnID != "turn-A" {
		t.Fatalf("stop on a discarded turn with a live writer: %v %+v", err, decision)
	}
	if r.session("c").Revision != revision {
		t.Fatal("stop changed authority")
	}
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
		r.restart()
		if got := Status(r.session("s")); got != "disconnected" {
			t.Fatalf("after restart: %s", got)
		}
	})
}

func TestCatalogR6(t *testing.T) {
	r := newRig(t)
	r.started("s", ProviderClaude)
	s := r.session("s")
	f := Fact{Seq: r.p.LastSeq + 1, SchemaVersion: SchemaVersion, At: testAt, Kind: FactCwdChanged, SessionID: "s", SessionRevision: s.Revision + 1, CWD: "/other"}
	if _, err := Reduce(r.p, f); !errors.Is(err, ErrIllegalFact) {
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
		r.must(In{Kind: InCreate, SessionID: "s", Provider: ProviderClaude})
		r.must(In{Kind: InSend, SessionID: "s", RequestID: "A", TaskID: "t", Generation: 1})
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
}

func TestCatalogR8(t *testing.T) {
	eachProvider(t, func(t *testing.T, provider string) {
		r := newRig(t)
		r.started("s", provider)
		r.must(In{Kind: InPause, SessionID: "s"})
		r.must(In{Kind: ObControlOutcome, SessionID: "s", Status: "pause", Outcome: "rejected"})
		r.refused(In{Kind: InClose, SessionID: "s"}, "unresolved")
		r.complete("s", "A")
		r.must(In{Kind: InClose, SessionID: "s"})
		if !r.session("s").Closed {
			t.Fatal("not closed")
		}
	})
}

func TestCatalogT1(t *testing.T) {
	eachProvider(t, func(t *testing.T, provider string) {
		r := newRig(t)
		s := r.started("s", provider)
		_ = s
		r.must(In{Kind: InStartReview, SessionID: "s", ID: "run", Stage: "plan_review", Digest: "d"})
		decision := r.must(In{Kind: ObQuestion, SessionID: "s", RequestID: "A", ID: "q", ReviewRunID: "run"})
		if len(decision.Effects) != 1 || decision.Effects[0].Kind != EffectRejectQuestion {
			t.Fatalf("reviewer question not rejected: %+v", decision.Effects)
		}
		if got := r.session("s").Review.Status; got != "failed" {
			t.Fatalf("review %s", got)
		}
		r.must(In{Kind: ObReviewOutcome, SessionID: "s", ID: "run", Verdict: "pass", Digest: "d"})
		s = r.session("s")
		if s.Review.Status != "failed" || len(s.Task.Passes) != 0 {
			t.Fatalf("failed reviewer reopened: %s %v", s.Review.Status, s.Task.Passes)
		}
	})
}

func TestCatalogT2(t *testing.T) {
	r := newRig(t)
	r.started("s", ProviderClaude)
	r.complete("s", "A")
	decision := r.must(In{Kind: ObQuestion, SessionID: "s", RequestID: "A", ID: "q", Status: "permission", ExpiresAt: "2026-11-03T11:00:00.000000000Z"})
	if len(decision.Effects) != 1 || decision.Effects[0].Kind != EffectRejectQuestion || decision.Effects[0].Class != ClassStopWork {
		t.Fatalf("late question not rejected: %+v", decision.Effects)
	}
	s := r.session("s")
	if len(s.Questions) != 0 || Status(s) != "idle" {
		t.Fatalf("session reopened: %s", Status(s))
	}
	r.refused(In{Kind: InAnswer, SessionID: "s", ID: "q"}, "question_stale")
}

func TestAnswerIsNewWorkOnlyWhileItsRequestIsActive(t *testing.T) {
	eachProvider(t, func(t *testing.T, provider string) {
		r := newRig(t)
		s := r.started("s", provider)
		r.must(In{Kind: ObQuestion, SessionID: "s", RequestID: "A", ID: "q", TurnID: s.TurnID, Status: "approval", Digest: "d", ExpiresAt: "2026-11-03T11:00:00.000000000Z"})
		if got := Status(r.session("s")); got != "waiting" {
			t.Fatalf("status %s", got)
		}
		r.refused(In{Kind: InAnswer, SessionID: "s", ID: "q", At: "2026-11-03T12:00:00.000000000Z"}, "question_stale")
		decision := r.must(In{Kind: InAnswer, SessionID: "s", ID: "q"})
		if len(decision.Effects) != 1 || decision.Effects[0].Kind != EffectAnswerQuestion || decision.Effects[0].Class != ClassNewWork || decision.Effects[0].Fence != r.session("s").ControlEpoch {
			t.Fatalf("answer effect: %+v", decision.Effects)
		}
		if len(r.session("s").Questions) != 0 {
			t.Fatal("question still open")
		}
		r.refused(In{Kind: InAnswer, SessionID: "s", ID: "q"}, "question_stale")
	})
}

func TestCatalogT3(t *testing.T) {
	r := newRig(t)
	r.started("s", ProviderCodex)
	r.must(In{Kind: ObCompleted, SessionID: "s", RequestID: "A", TurnID: "turn-stale", Status: "completed"})
	s := r.session("s")
	if s.Requests["A"] != ReceiptAccepted || s.ProviderFinal {
		t.Fatalf("foreign turn finalized: %q", s.Requests["A"])
	}
	if s.Evidence[evidenceKey("A", "final")] == "" {
		t.Fatal("evidence not kept")
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
		r.refused(In{Kind: InAbandon, SessionID: "s", ExpectedRequest: "A", Reason: "x"}, "nothing_to_discard")
		r.must(In{Kind: ObAuthBoundary, Provider: provider})
		r.restart()
		if got := r.session("s").Requests["A"]; got != ReceiptFinal {
			t.Fatalf("final overwritten: %q", got)
		}
	})
	r := newRig(t)
	r.started("q", ProviderClaude)
	r.complete("q", "A")
	s := r.session("q").clone()
	s.Quarantine = "illegal_fact"
	r.p = r.p.copyShell()
	r.p.Sessions["q"] = s
	r.must(In{Kind: InAbandon, SessionID: "q", ExpectedRequest: "A", Reason: "stuck"})
	if got := r.session("q"); got.Requests["A"] != ReceiptFinal || got.Abandoned == nil || got.ProviderFinal != true {
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

func TestCatalogG1(t *testing.T) {
	eachProvider(t, func(t *testing.T, provider string) {
		r := newRig(t)
		r.started("s", provider)
		r.must(In{Kind: InPause, SessionID: "s"})
		r.refused(In{Kind: InResume, SessionID: "s"}, "no_finality")
		r.must(In{Kind: ObRefused, SessionID: "s", RequestID: "A"})
		r.refused(In{Kind: InResume, SessionID: "s"}, "no_finality")
	})
	r := newRig(t)
	r.started("s", ProviderClaude)
	r.complete("s", "A")
	r.must(In{Kind: InSetSupervision, SessionID: "s", State: SupervisionPaused})
	r.must(In{Kind: InResume, SessionID: "s"})
	if r.session("s").Supervision.State != SupervisionActive {
		t.Fatal("resume after verified final failed")
	}
}

func TestCatalogG2(t *testing.T) {
	eachProvider(t, func(t *testing.T, provider string) {
		for _, outcome := range []string{"rejected", "confirmed"} {
			r := newRig(t)
			r.started("s", provider)
			r.must(In{Kind: InPause, SessionID: "s"})
			r.must(In{Kind: ObControlOutcome, SessionID: "s", Status: "pause", Outcome: outcome})
			r.refused(In{Kind: InSend, SessionID: "s", RequestID: "B", TaskID: "other", Generation: 2}, "unresolved")
			s := r.session("s")
			if s.LastRequest != "A" || s.Task.ID != "task-s" {
				t.Fatal("unresolved turn replaced")
			}
			r.complete("s", "A")
			r.must(In{Kind: InSetSupervision, SessionID: "s", State: SupervisionActive})
			s2 := r.session("s").clone()
			s2.Task.State = TaskBlocked
			r.p = r.p.copyShell()
			r.p.Sessions["s"] = s2
			r.must(In{Kind: InSend, SessionID: "s", RequestID: "C", TaskID: "next", Generation: 2})
		}
	})
}

func TestCatalogG3(t *testing.T) {
	r := newRig(t)
	r.must(In{Kind: InCreate, SessionID: "s", Provider: ProviderCodex, Status: "connected"})
	r.must(In{Kind: InSend, SessionID: "s", RequestID: "A", TaskID: "t", Generation: 1})
	decision := r.must(In{Kind: InPause, SessionID: "s"})
	if len(decision.Effects) != 0 {
		t.Fatalf("Pause guessed a turn: %+v", decision.Effects)
	}
	decision = r.must(In{Kind: ObTurnBound, SessionID: "s", RequestID: "A", TurnID: "turn-A"})
	if len(decision.Effects) != 1 || decision.Effects[0].Kind != EffectInterrupt || decision.Effects[0].TurnID != "turn-A" {
		t.Fatalf("bound turn not interrupted: %+v", decision.Effects)
	}
	decision = r.must(In{Kind: ObTurnBound, SessionID: "s", RequestID: "A", TurnID: "turn-A"})
	if len(decision.Effects) != 0 {
		t.Fatal("interrupt fired twice")
	}
}

func TestCatalogG4(t *testing.T) {
	r := newRig(t)
	r.started("s", ProviderCodex)
	r.must(In{Kind: ObChild, SessionID: "s", ID: "child", TurnID: "turn-child", Status: ChildRunning})
	r.refused(In{Kind: InChildControl, SessionID: "s", ID: "child", Status: "resume"}, "child_resume_refused")
	r.must(In{Kind: ObAuthBoundary, Provider: ProviderCodex})
	r.refused(In{Kind: InChildControl, SessionID: "s", ID: "child", Status: "resume"}, "child_resume_refused")
	if got := r.session("s").Children[0]; got.Status != ChildUnknown || got.ReasonCode != "auth_changed" {
		t.Fatalf("child %+v", got)
	}
}

func TestCatalogG5(t *testing.T) {
	eachProvider(t, func(t *testing.T, provider string) {
		r := newRig(t)
		s := r.started("s", provider)
		fence := s.ControlEpoch
		r.must(In{Kind: ObQuestion, SessionID: "s", RequestID: "A", ID: "q", TurnID: s.TurnID, ExpiresAt: "2030-01-01T00:00:00.000000000Z"})
		r.must(In{Kind: ObChild, SessionID: "s", ID: "child", TurnID: "t", Status: ChildRunning})
		decision := r.must(In{Kind: ObAuthBoundary, Provider: provider})
		if len(decision.Effects) == 0 || decision.Effects[0].Class != ClassStopWork {
			t.Fatalf("no stop effect: %+v", decision.Effects)
		}
		s = r.session("s")
		if s.ControlEpoch == fence || !s.ReadOnly || s.Requests["A"] != ReceiptUnknown || len(s.Questions) != 0 || s.Children[0].Status != ChildUnknown {
			t.Fatalf("authority survived: %+v", s)
		}
		r.refused(In{Kind: InSend, SessionID: "s", RequestID: "B", TaskID: "x"}, "read_only")
		r.refused(In{Kind: InAnswer, SessionID: "s", ID: "q"}, "question_stale")
	})
	// A profile boundary leaves other profiles alone.
	r := newRig(t)
	r.must(In{Kind: InCreate, SessionID: "a", Provider: ProviderClaude, ProfileID: "one"})
	r.must(In{Kind: InCreate, SessionID: "b", Provider: ProviderClaude, ProfileID: "two"})
	r.must(In{Kind: ObAuthBoundary, Provider: ProviderClaude, ProfileID: "one"})
	if !r.session("a").ReadOnly || r.session("b").ReadOnly {
		t.Fatal("boundary crossed profiles")
	}
}

func TestCatalogP6(t *testing.T) {
	r := newRig(t)
	r.must(In{Kind: InCreate, SessionID: "s", Provider: ProviderClaude})
	before := r.p
	decision, err := Decide(before, In{Kind: InSend, Principal: Principal{Class: PrincipalUser}, At: testAt, SessionID: "s", RequestID: "A", TaskID: "t", Generation: 1})
	if err != nil || len(decision.Facts) == 0 {
		t.Fatal(err)
	}
	// The append failed, so nothing is reduced: the projection has no trace of it.
	s := before.Sessions["s"]
	if s.Task != nil || s.LastRequest != "" || len(s.Requests) != 0 {
		t.Fatalf("Decide published state: %+v", s)
	}
}

func TestCatalogP7(t *testing.T) {
	eachProvider(t, func(t *testing.T, provider string) {
		r := newRig(t)
		r.must(In{Kind: InCreate, SessionID: "s", Provider: provider, Status: "connected"})
		r.must(In{Kind: InSend, SessionID: "s", RequestID: "A", TaskID: "t", Generation: 1})
		r.must(In{Kind: ObRefused, SessionID: "s", RequestID: "A", ReasonCode: "rejected"})
		// A never-dispatched task stays idle, so a new objective is not stuck.
		r.must(In{Kind: InSend, SessionID: "s", RequestID: "B", TaskID: "t2", Generation: 2})
	})
	r := newRig(t)
	r.started("s", ProviderClaude)
	r.complete("s", "A")
	r.must(In{Kind: InSetBudget, SessionID: "s", RemainingBursts: 0})
	_, err := r.apply(In{Kind: InSend, Principal: Principal{Class: PrincipalSystem}, Automatic: true, SessionID: "s", RequestID: "B", ExpectedTask: "task-s"})
	var refusal *Refusal
	if !errors.As(err, &refusal) || r.session("s").LastRefusal != refusal.Code {
		t.Fatalf("automatic refusal not visible: %v %q", err, r.session("s").LastRefusal)
	}
	before := r.p.LastSeq
	_, _ = r.apply(In{Kind: InSend, Principal: Principal{Class: PrincipalSystem}, Automatic: true, SessionID: "s", RequestID: "C", ExpectedTask: "task-s"})
	if r.p.LastSeq != before {
		t.Fatal("repeat refusal was not coalesced")
	}
}

func TestCatalogD2(t *testing.T) {
	eachProvider(t, func(t *testing.T, provider string) {
		r := newRig(t)
		s := r.started("s", provider)
		s2 := s.clone()
		s2.Task.Passes = map[string]string{"plan": "kept"}
		r.p = r.p.copyShell()
		r.p.Sessions["s"] = s2
		r.must(In{Kind: InPause, SessionID: "s"})
		decision := r.must(In{Kind: InAbandon, SessionID: "s", ExpectedRequest: "A", Reason: "  done waiting  "})
		if len(decision.Facts) != 1 || decision.Facts[0].Kind != FactAbandoned || decision.Facts[0].Reason != "done waiting" || decision.Facts[0].RequestID != "A" || decision.Facts[0].At != testAt {
			t.Fatalf("fact: %+v", decision.Facts)
		}
		got := r.session("s")
		if got.Requests["A"] != ReceiptAbandoned || got.ProviderFinal || got.Task.Passes["plan"] != "kept" || len(got.Task.Passes) != 1 {
			t.Fatalf("minted or lost an outcome: %+v", got)
		}
		r.refused(In{Kind: InAbandon, Principal: Principal{Class: PrincipalAgentRun, SessionID: "s"}, SessionID: "s", ExpectedRequest: "A", Reason: "x"}, "forbidden")
	})
	r := newRig(t)
	r.started("s", ProviderClaude)
	r.refused(In{Kind: InAbandon, SessionID: "s", ExpectedRequest: "A", Reason: "x"}, "stop_first")
	r.must(In{Kind: InPause, SessionID: "s"})
	r.refused(In{Kind: InAbandon, SessionID: "s", ExpectedRequest: "B", Reason: "x"}, "turn_changed")
	r.refused(In{Kind: InAbandon, SessionID: "s", ExpectedRequest: "A", Reason: " "}, "bad_reason")
	r.refused(In{Kind: InAbandon, SessionID: "s", ExpectedRequest: "A", Reason: strings.Repeat("x", 501)}, "bad_reason")
}

func TestCatalogD3(t *testing.T) {
	r := newRig(t)
	r.started("s", ProviderCodex)
	r.must(In{Kind: InStartReview, SessionID: "s", ID: "run", Stage: "final", Digest: "d"})
	r.must(In{Kind: InPause, SessionID: "s"})
	r.must(In{Kind: InAbandon, SessionID: "s", ExpectedRequest: "A", Reason: "done"})
	r.must(In{Kind: ObCompleted, SessionID: "s", RequestID: "A", TurnID: "turn-A", Status: "completed"})
	decision := r.must(In{Kind: ObQuestion, SessionID: "s", RequestID: "A", ID: "q", TurnID: "turn-A"})
	r.must(In{Kind: ObReviewOutcome, SessionID: "s", ID: "run", Verdict: "pass", Digest: "d"})
	r.refused(In{Kind: InCheckpoint, Principal: Principal{Class: PrincipalAgentRun, SessionID: "s"}, SessionID: "s", TaskID: "task-s", State: TaskComplete}, "checkpoint_stale")
	s := r.session("s")
	if s.Requests["A"] != ReceiptAbandoned || s.ProviderFinal || len(s.Questions) != 0 || len(s.Task.Passes) != 0 || s.Task.State == TaskComplete {
		t.Fatalf("late frame changed the turn: %+v", s)
	}
	if len(decision.Effects) != 1 || decision.Effects[0].Kind != EffectRejectQuestion {
		t.Fatalf("late question not rejected: %+v", decision.Effects)
	}
	if s.Evidence[evidenceKey("A", "final")] == "" {
		t.Fatal("late final not kept as evidence")
	}
}

func TestCatalogD4(t *testing.T) {
	r := newRig(t)
	r.started("s", ProviderClaude)
	r.must(In{Kind: InPause, SessionID: "s"})
	r.must(In{Kind: InAbandon, SessionID: "s", ExpectedRequest: "A", Reason: "first", At: testAt})
	seq := r.p.LastSeq
	decision := r.must(In{Kind: InAbandon, SessionID: "s", ExpectedRequest: "A", Reason: "second", At: "2026-11-04T00:00:00.000000000Z"})
	if !decision.Idempotent || r.p.LastSeq != seq || r.session("s").Abandoned.Reason != "first" || r.session("s").Abandoned.At != testAt {
		t.Fatalf("retry changed the decision: %+v", r.session("s").Abandoned)
	}
	r.refused(In{Kind: InAbandon, SessionID: "s", ExpectedRequest: "older", Reason: "x"}, "discarded_other")
	// A second fact is illegal even if something emitted one.
	f := Fact{Seq: r.p.LastSeq + 1, SchemaVersion: SchemaVersion, At: testAt, Kind: FactAbandoned, SessionID: "s", SessionRevision: r.session("s").Revision + 1, RequestID: "A", Reason: "x"}
	if _, err := Reduce(r.p, f); !errors.Is(err, ErrIllegalFact) {
		t.Fatalf("second abandon accepted: %v", err)
	}
}

func TestCatalogD6(t *testing.T) {
	r := newRig(t)
	r.started("s", ProviderClaude)
	r.complete("s", "A")
	r.refused(In{Kind: InAbandon, SessionID: "s", ExpectedRequest: "A", Reason: "late"}, "nothing_to_discard")
	if s := r.session("s"); s.Requests["A"] != ReceiptFinal || s.Abandoned != nil {
		t.Fatal("final changed")
	}
}

func TestCatalogD10(t *testing.T) {
	r := newRig(t)
	r.must(In{Kind: InCreate, SessionID: "s", Provider: ProviderClaude})
	r.must(In{Kind: InSend, SessionID: "s", RequestID: "A", TaskID: "t", Generation: 1})
	r.must(In{Kind: ObAccepted, SessionID: "s", RequestID: "A"})
	r.must(In{Kind: InQueueInput, SessionID: "s", RequestID: "q1", PayloadHash: "h"})
	r.complete("s", "A")
	r.must(In{Kind: InDispatchInput, Principal: Principal{Class: PrincipalSystem}, Automatic: true, SessionID: "s", RequestID: "q1", ObjectiveHash: "next"})
	r.must(In{Kind: InPause, SessionID: "s"})
	r.must(In{Kind: InAbandon, SessionID: "s", ExpectedRequest: "q1", Reason: "done"})
	if got := findInput(r.session("s"), "q1").Status; got != InputUnknown {
		t.Fatalf("entry stuck: %s", got)
	}
	r.refused(In{Kind: InClose, SessionID: "s"}, "queue_active")
	decision := r.must(In{Kind: InDiscardInput, SessionID: "s", RequestID: "q1"})
	if len(decision.Effects) != 1 || decision.Effects[0].Class != ClassLocal {
		t.Fatalf("no local cleanup: %+v", decision.Effects)
	}
	r.refused(In{Kind: InClose, SessionID: "s"}, "queue_active")
	r.must(In{Kind: ObPayloadReleased, SessionID: "s", RequestID: "q1"})
	r.must(In{Kind: InClose, SessionID: "s"})
}

func TestCatalogD11(t *testing.T) {
	eachProvider(t, func(t *testing.T, provider string) {
		r := newRig(t)
		r.started("s", provider)
		r.must(In{Kind: InPause, SessionID: "s"})
		r.must(In{Kind: InAbandon, SessionID: "s", ExpectedRequest: "A", Reason: "done"})
		epoch := r.session("s").ControlEpoch
		_, _ = r.apply(In{Kind: InPause, SessionID: "s"})
		_, _ = r.apply(In{Kind: InStop, SessionID: "s"})
		r.refused(In{Kind: InResume, SessionID: "s"}, "read_only")
		r.refused(In{Kind: InChangeCWD, SessionID: "s", CWD: "/x"}, "read_only")
		r.refused(In{Kind: InSend, SessionID: "s", RequestID: "B", TaskID: "x"}, "read_only")
		r.must(In{Kind: ObControlOutcome, SessionID: "s", Status: "pause", Outcome: "confirmed"})
		r.must(In{Kind: ObRefused, SessionID: "s", RequestID: "A"})
		r.must(In{Kind: ObUnknown, SessionID: "s", RequestID: "A"})
		r.must(In{Kind: ObDisconnected, SessionID: "s"})
		decision := r.must(In{Kind: ObAuthBoundary, Provider: provider})
		if len(decision.Facts) != 0 {
			t.Fatal("auth boundary touched a discarded session")
		}
		s := r.session("s")
		if s.ControlEpoch != epoch || s.Requests["A"] != ReceiptAbandoned || Status(s) != "abandoned" {
			t.Fatalf("discarded tab changed: %d %q %s", s.ControlEpoch, s.Requests["A"], Status(s))
		}
		// Reduce refuses authority facts on it, whichever path produced them.
		for _, kind := range []FactKind{FactControlRequested, FactCwdChanged, FactAuthBoundaryCrossed, FactRequestIntended, FactProviderCompleted, FactCheckpointRecorded} {
			f := Fact{Seq: r.p.LastSeq + 1, SchemaVersion: SchemaVersion, At: testAt, Kind: kind, SessionID: "s", SessionRevision: s.Revision + 1, RequestID: "A"}
			if _, err := Reduce(r.p, f); !errors.Is(err, ErrIllegalFact) {
				t.Errorf("%s accepted: %v", kind, err)
			}
		}
		r.must(In{Kind: InClose, SessionID: "s"})
	})
}

func TestCatalogD12(t *testing.T) {
	r := newRig(t)
	r.started("s", ProviderClaude)
	s := r.session("s").clone()
	s.Task.State = TaskActive
	r.p = r.p.copyShell()
	r.p.Sessions["s"] = s
	r.must(In{Kind: InPause, SessionID: "s"})
	r.must(In{Kind: InAbandon, SessionID: "s", ExpectedRequest: "A", Reason: "done"})
	r.restart()
	got := r.session("s").Task
	if got.State != TaskBlocked || got.ReviewStatus != ReviewInvalidated {
		t.Fatalf("task after replay: %+v", got)
	}
}

func TestCatalogE1(t *testing.T) {
	eachProvider(t, func(t *testing.T, provider string) {
		r := newRig(t)
		r.must(In{Kind: InCreate, SessionID: "s", Provider: provider, Status: "connected"})
		decision := r.must(In{Kind: InSend, SessionID: "s", RequestID: "A", TaskID: "t", Generation: 1})
		fence := decision.Effects[0].Fence
		if decision.Effects[0].Class != ClassNewWork {
			t.Fatalf("class %s", decision.Effects[0].Class)
		}
		r.must(In{Kind: InPause, SessionID: "s"})
		if r.session("s").ControlEpoch == fence {
			t.Fatal("a later control did not move the fence, so a queued write would still pass")
		}
		r = newRig(t)
		r.must(In{Kind: InCreate, SessionID: "s", Provider: provider, Status: "connected"})
		decision = r.must(In{Kind: InSend, SessionID: "s", RequestID: "A", TaskID: "t", Generation: 1})
		fence = decision.Effects[0].Fence
		r.must(In{Kind: ObAuthBoundary, Provider: provider})
		if r.session("s").ControlEpoch == fence {
			t.Fatal("auth boundary did not move the fence")
		}
	})
}

func TestCatalogE4(t *testing.T) {
	r := newRig(t)
	r.must(In{Kind: InCreate, SessionID: "s", Provider: ProviderCodex, Status: "connected"})
	r.must(In{Kind: InSend, SessionID: "s", RequestID: "A", TaskID: "t", Generation: 1})
	r.must(In{Kind: InPause, SessionID: "s"})
	r.must(In{Kind: InAbandon, SessionID: "s", ExpectedRequest: "A", Reason: "done"})
	if !r.session("s").PendingInterrupt {
		t.Fatal("pending interrupt lost at discard")
	}
	before := r.p
	decision := r.must(In{Kind: ObTurnBound, SessionID: "s", RequestID: "A", TurnID: "turn-A"})
	if len(decision.Effects) != 1 || decision.Effects[0].Kind != EffectInterrupt {
		t.Fatalf("interrupt not emitted on an abandoned request: %+v", decision.Effects)
	}
	if r.session("s").Requests["A"] != ReceiptAbandoned {
		t.Fatal("receipt changed")
	}
	// Replay reduces the same facts and has no way to produce an effect.
	var facts []Fact
	facts = append(facts, decision.Facts...)
	if next, err := Reduce(before, facts[0]); err != nil || next.Sessions["s"].PendingInterrupt {
		t.Fatalf("replay: %v", err)
	}
	if got := ReconcileEffects(r.p); len(got) != 0 {
		t.Fatalf("restart owes no provider effect: %+v", got)
	}
}

func TestCatalogV1(t *testing.T) {
	r := newRig(t)
	r.started("good", ProviderClaude)
	r.started("bad", ProviderClaude)
	facts := append([]Fact{}, recordFacts(t)...)
	last := facts[len(facts)-1]
	illegalFact := Fact{Seq: last.Seq + 1, SchemaVersion: SchemaVersion, At: testAt, Kind: FactProviderCompleted, SessionID: "bad", SessionRevision: 99, RequestID: "A"}
	facts = append(facts, illegalFact)
	follow := Fact{Seq: last.Seq + 2, SchemaVersion: SchemaVersion, At: testAt, Kind: FactProviderConnected, SessionID: "good", SessionRevision: 4}
	facts = append(facts, follow)
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
	if p.Sessions["good"].ReadOnly || !p.Sessions["good"].Connected {
		t.Fatal("good session affected")
	}
	// Discard and close still work on a quarantined session.
	q := &rig{t: t, p: p}
	q.must(In{Kind: InAbandon, SessionID: "bad", ExpectedRequest: "A", Reason: "stuck"})
	q.must(In{Kind: InClose, SessionID: "bad"})
	// Unreadable refuses, and never partially.
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

// recordFacts builds the two-session log used by V1.
func recordFacts(t *testing.T) []Fact {
	t.Helper()
	r := newRig(t)
	facts := []Fact{}
	for _, in := range []In{
		{Kind: InCreate, SessionID: "good", Provider: ProviderClaude, Status: "connected"},
		{Kind: InSend, SessionID: "good", RequestID: "A", TaskID: "t", Generation: 1},
		{Kind: ObAccepted, SessionID: "good", RequestID: "A"},
		{Kind: InCreate, SessionID: "bad", Provider: ProviderClaude, Status: "connected"},
		{Kind: InSend, SessionID: "bad", RequestID: "A", TaskID: "t", Generation: 1},
		{Kind: ObAccepted, SessionID: "bad", RequestID: "A"},
	} {
		facts = append(facts, r.must(in).Facts...)
	}
	return facts
}

func TestCatalogV3(t *testing.T) {
	f := Fact{Seq: 7, SchemaVersion: SchemaVersion, At: "2026-11-03T10:00:00.123456789Z", Kind: FactLegacyImported, SessionID: "s", SessionRevision: 1, Passes: map[string]string{"plan": "d"}, Attachments: []string{"a"}, Receipt: ReceiptFinal, RemainingBursts: 3}
	data, err := EncodeFact(f)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeFact(data)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := EncodeFact(decoded)
	if string(again) != string(data) || decoded.At != f.At {
		t.Fatalf("not canonical: %s vs %s", again, data)
	}
	for _, bad := range []string{
		`{"seq":1,"seq":2}`,
		`{"ſeq":1}`,
		`{"SEQ":1}`,
		`{"unknown":1}`,
		`[1]`,
		`{"seq":1} trailing`,
		`{"passes":{"a":"1","a":"2"}}`,
		"",
	} {
		if _, err := DecodeFact([]byte(bad)); !errors.Is(err, ErrMalformedFact) {
			t.Errorf("%q accepted: %v", bad, err)
		}
	}
}

func TestCatalogS2(t *testing.T) {
	r := newRig(t)
	r.started("s", ProviderCodex)
	r.complete("s", "A")
	first := r.must(In{Kind: ObCompleted, SessionID: "s", RequestID: "A", TurnID: "x", Status: "completed", Digest: "d"})
	if len(first.Facts) != 1 {
		t.Fatal("first late frame not recorded")
	}
	seq := r.p.LastSeq
	for i := 0; i < 1000; i++ {
		r.must(In{Kind: ObCompleted, SessionID: "s", RequestID: "A", TurnID: "x", Status: "completed", Digest: "d"})
	}
	if r.p.LastSeq != seq {
		t.Fatalf("noisy provider appended %d facts", r.p.LastSeq-seq)
	}
}

func TestCatalogI9(t *testing.T) {
	rows := []struct {
		receipt Receipt
		request string
		state   string
	}{
		{ReceiptFinal, "A", TaskComplete}, {ReceiptRejected, "A", TaskIdle}, {ReceiptUnknown, "A", TaskActive}, {ReceiptAbandoned, "A", TaskBlocked}, {ReceiptNone, "", ""},
	}
	for _, row := range rows {
		r := newRig(t)
		r.p, _ = Reduce(r.p, Fact{Seq: 1, SchemaVersion: SchemaVersion, At: testAt, Kind: FactLegacyImported, SessionID: "s", SessionRevision: 1, Provider: ProviderClaude, ProviderID: "conv", RequestID: row.request, Receipt: row.receipt, TaskID: "t", State: row.state, Reason: "old"})
		s := r.session("s")
		if s == nil || !s.ReadOnly {
			t.Fatalf("%q not imported read-only", row.receipt)
		}
		if row.receipt == ReceiptUnknown {
			r.refused(In{Kind: InClose, SessionID: "s"}, "unresolved")
			r.must(In{Kind: InAbandon, SessionID: "s", ExpectedRequest: "A", Reason: "done"})
		}
		r.must(In{Kind: InClose, SessionID: "s"})
	}
	// Quarantine is reachable from replay and has its way out in V1.
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
		if got := r.session("idle").Requests["A"]; got != ReceiptFinal {
			t.Fatalf("idle receipt: %q", got)
		}
		if got := Status(r.session("idle")); got == "unknown" {
			t.Fatal("idle session marked unknown")
		}
		if got := r.session("busy").Requests["A"]; got != ReceiptUnknown {
			t.Fatalf("busy receipt: %q", got)
		}
		r.must(In{Kind: InClose, SessionID: "idle"})
	})
}

func TestCatalogL8(t *testing.T) {
	r := newRig(t)
	r.started("s", ProviderCodex)
	r.must(In{Kind: ObChild, SessionID: "s", ID: "child-1", Role: "owner", TurnID: "t", Status: ChildRunning})
	r.restart()
	children := r.session("s").Children
	if len(children) != 1 || children[0].ID != "child-1" || children[0].Role != "owner" || children[0].Status != ChildUnknown {
		t.Fatalf("child identity lost: %+v", children)
	}
}

// L11 is the source mutation run in tools, recorded with the slice's evidence. This
// keeps the in-process equivalents of those mutants pinned.
func TestCatalogL11(t *testing.T) {
	r := newRig(t)
	r.started("s", ProviderClaude)
	r.must(In{Kind: InQueueInput, SessionID: "s", RequestID: "q", PayloadHash: "h"})
	r.must(In{Kind: ObAuthBoundary, Provider: ProviderClaude}) // M1: inputs held at the boundary.
	if got := findInput(r.session("s"), "q").Status; got != InputHeld {
		t.Fatalf("M1: %s", got)
	}
	r2 := newRig(t)
	r2.started("s", ProviderClaude)
	r2.restart() // M7: a read-only session accepts no new writer.
	f := Fact{Seq: r2.p.LastSeq + 1, SchemaVersion: SchemaVersion, At: testAt, Kind: FactProviderConnected, SessionID: "s", SessionRevision: r2.session("s").Revision + 1}
	if _, err := Reduce(r2.p, f); !errors.Is(err, ErrIllegalFact) {
		t.Fatalf("M7: %v", err)
	}
	r3 := newRig(t)
	r3.started("s", ProviderClaude)
	r3.must(In{Kind: InStartReview, SessionID: "s", ID: "run", Stage: "plan", Digest: "d"})
	r3.must(In{Kind: InPause, SessionID: "s"}) // M21: a verdict is bound to its epoch.
	r3.must(In{Kind: ObReviewOutcome, SessionID: "s", ID: "run", Verdict: "pass", Digest: "d"})
	if len(r3.session("s").Task.Passes) != 0 {
		t.Fatal("M21: late verdict accepted after an epoch change")
	}
}

// Every catalog row owned by K1 must have its test.
func TestCatalogCoverage(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "plans", "CONSOLE-KERNEL-CATALOG.md"))
	if err != nil {
		t.Skip("catalog not present in this checkout")
	}
	row := regexp.MustCompile(`^\| ([A-Z]\d+) \|`)
	k1 := regexp.MustCompile(`\bK1\b`)
	owned := []string{}
	for _, line := range strings.Split(string(data), "\n") {
		match := row.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		cells := strings.Split(strings.Trim(line, "| "), "|")
		if k1.MatchString(cells[len(cells)-1]) {
			owned = append(owned, match[1])
		}
	}
	if len(owned) < 25 {
		t.Fatalf("parsed only %d K1 rows", len(owned))
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

// Three mutants survived the first source run. These close those gaps.

func TestDispatchEndsEveryPassForTheOlderInput(t *testing.T) {
	r := newRig(t)
	r.must(In{Kind: InCreate, SessionID: "s", Provider: ProviderClaude})
	r.must(In{Kind: InSend, SessionID: "s", RequestID: "A", TaskID: "t", Generation: 1, ObjectiveHash: "one"})
	r.must(In{Kind: ObAccepted, SessionID: "s", RequestID: "A"})
	r.must(In{Kind: InStartReview, SessionID: "s", ID: "run", Stage: "plan", Digest: "d"})
	r.must(In{Kind: ObReviewOutcome, SessionID: "s", ID: "run", Verdict: "pass", Digest: "d"})
	if r.session("s").Task.Passes["plan"] != "d" {
		t.Fatal("pass not recorded")
	}
	r.must(In{Kind: InQueueInput, SessionID: "s", RequestID: "q", PayloadHash: "h"})
	r.complete("s", "A")
	r.must(In{Kind: InDispatchInput, Principal: Principal{Class: PrincipalSystem}, Automatic: true, SessionID: "s", RequestID: "q", ObjectiveHash: "two"})
	task := r.session("s").Task
	if len(task.Passes) != 0 || task.InputRevision != 1 || task.ObjectiveHash != "two" {
		t.Fatalf("older input's pass authorizes a new objective: %+v", task)
	}
}

func TestRuntimeIdentityRefusesBothProvidersIncludingAutomatic(t *testing.T) {
	eachProvider(t, func(t *testing.T, provider string) {
		r := newRig(t)
		r.must(In{Kind: InCreate, SessionID: "s", Provider: provider, Status: "connected"})
		r.must(In{Kind: InSend, SessionID: "s", RequestID: "A", TaskID: "t", Generation: 1, RuntimeIdentity: "owner", RemainingBursts: 3})
		if r.session("s").RuntimeIdentity != "owner" {
			t.Fatal("identity not bound")
		}
		r.must(In{Kind: ObAccepted, SessionID: "s", RequestID: "A"})
		if provider == ProviderCodex {
			r.must(In{Kind: ObTurnBound, SessionID: "s", RequestID: "A", TurnID: "turn"})
		}
		r.complete("s", "A")
		r.refused(In{Kind: InSend, SessionID: "s", RequestID: "B", TaskID: "t2", Generation: 2, RuntimeIdentity: "other"}, "runtime_changed")
		r.refused(In{Kind: InSend, Principal: Principal{Class: PrincipalSystem}, Automatic: true, SessionID: "s", RequestID: "C", ExpectedTask: "t", RuntimeIdentity: "other"}, "runtime_changed")
		if got := r.session("s").LastRefusal; got != "runtime_changed" {
			t.Fatalf("automatic refusal not visible: %q", got)
		}
		r.must(In{Kind: InSend, SessionID: "s", RequestID: "D", TaskID: "t3", Generation: 2, RuntimeIdentity: "owner"})
	})
}

func TestReduceRefusesCloseOverAnUnresolvedReceipt(t *testing.T) {
	r := newRig(t)
	s := r.started("s", ProviderClaude)
	f := Fact{Seq: r.p.LastSeq + 1, SchemaVersion: SchemaVersion, At: testAt, Kind: FactSessionClosed, SessionID: "s", SessionRevision: s.Revision + 1}
	if _, err := Reduce(r.p, f); !errors.Is(err, ErrIllegalFact) {
		t.Fatalf("close accepted over an unresolved receipt: %v", err)
	}
	r2 := newRig(t)
	r2.must(In{Kind: InCreate, SessionID: "s", Provider: ProviderClaude})
	r2.must(In{Kind: InSend, SessionID: "s", RequestID: "A", TaskID: "t", Generation: 1})
	r2.must(In{Kind: ObRefused, SessionID: "s", RequestID: "A"})
	r2.must(In{Kind: InSetBudget, SessionID: "s", RemainingBursts: 0})
	r2.must(In{Kind: InQueueInput, SessionID: "s", RequestID: "q", PayloadHash: "h"})
	f = Fact{Seq: r2.p.LastSeq + 1, SchemaVersion: SchemaVersion, At: testAt, Kind: FactSessionClosed, SessionID: "s", SessionRevision: r2.session("s").Revision + 1}
	if _, err := Reduce(r2.p, f); !errors.Is(err, ErrIllegalFact) {
		t.Fatalf("close accepted over a retained payload: %v", err)
	}
}
