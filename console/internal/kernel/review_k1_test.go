package kernel

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// Regressions for the first K1 code inspection, named by its findings. Each failed
// against 86e6aa2 before the repair.

func sent(t *testing.T, r *rig, id, provider string) {
	t.Helper()
	r.must(In{Kind: InCreate, SessionID: id, Provider: provider, Status: "connected"})
	r.must(In{Kind: InSend, SessionID: id, RequestID: "A", TaskID: "t", Generation: 1, RuntimeIdentity: "owner"})
}

func TestK1F1QuarantinedDiscardSurvivesRestart(t *testing.T) {
	facts := recordFacts(t)
	last := facts[len(facts)-1]
	facts = append(facts, Fact{Seq: last.Seq + 1, SchemaVersion: SchemaVersion, At: testAt, Kind: FactProviderCompleted, SessionID: "bad", SessionRevision: 99, RequestID: "A"})
	p, _, err := Replay(facts)
	if err != nil {
		t.Fatal(err)
	}
	q := &rig{t: t, p: p}
	for _, in := range []In{
		{Kind: InAbandon, SessionID: "bad", ExpectedRequest: "A", Reason: rr("stuck")},
		{Kind: InClose, SessionID: "bad"},
	} {
		facts = append(facts, q.must(in).Facts...)
	}
	again, _, err := Replay(facts)
	if err != nil {
		t.Fatal(err)
	}
	s := again.Sessions["bad"]
	if s.Abandoned == nil || !s.Closed {
		t.Fatalf("restart undid the exit: abandoned=%v closed=%v", s.Abandoned, s.Closed)
	}
	if canonical(again) != canonical(q.p) {
		t.Fatal("replay after a quarantine differs from live")
	}
}

func TestK1F2CloseKeepsPendingInterrupt(t *testing.T) {
	r := newRig(t)
	sent(t, r, "s", ProviderCodex)
	r.must(In{Kind: InPause, SessionID: "s"})
	r.must(In{Kind: InAbandon, SessionID: "s", ExpectedRequest: "A", Reason: rr("done")})
	r.must(In{Kind: InClose, SessionID: "s"})
	decision := r.must(In{Kind: ObTurnBound, SessionID: "s", RequestID: "A", TurnID: "turn-A"})
	if len(decision.Effects) != 1 || decision.Effects[0].Kind != EffectInterrupt || decision.Effects[0].TurnID != "turn-A" {
		t.Fatalf("late reply after close lost the interrupt: %+v", decision)
	}
}

func TestK1F3InterruptSurvivesUnknownAndAuth(t *testing.T) {
	cases := map[string][]In{
		"pause then unknown": {{Kind: InPause, SessionID: "s"}, {Kind: ObUnknown, SessionID: "s", RequestID: "A", ReasonCode: "deadline"}},
		"unknown then stop":  {{Kind: ObUnknown, SessionID: "s", RequestID: "A", ReasonCode: "deadline"}, {Kind: InStop, SessionID: "s"}},
		"auth while unbound": {{Kind: ObAuthBoundary, Provider: ProviderCodex}},
	}
	for name, steps := range cases {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			sent(t, r, "s", ProviderCodex)
			for _, step := range steps {
				r.must(step)
			}
			decision := r.must(In{Kind: ObTurnBound, SessionID: "s", RequestID: "A", TurnID: "turn-A"})
			if len(decision.Effects) != 1 || decision.Effects[0].Kind != EffectInterrupt {
				t.Fatalf("late bind did not interrupt: %+v", decision)
			}
		})
	}
	// With no stop requested, a late bind still records the turn so Stop can use it.
	r := newRig(t)
	sent(t, r, "s", ProviderCodex)
	r.must(In{Kind: ObUnknown, SessionID: "s", RequestID: "A", ReasonCode: "deadline"})
	decision := r.must(In{Kind: ObTurnBound, SessionID: "s", RequestID: "A", TurnID: "turn-A"})
	if len(decision.Effects) != 0 {
		t.Fatal("interrupt without a stop request")
	}
	decision = r.must(In{Kind: InStop, SessionID: "s"})
	if len(decision.Effects) != 1 || decision.Effects[0].TurnID != "turn-A" {
		t.Fatalf("stop could not use the late turn: %+v", decision)
	}
}

func TestK1F4StopOnUnknownChangesNoAuthorityAndStillStops(t *testing.T) {
	r := newRig(t)
	r.must(In{Kind: InCreate, SessionID: "s", Provider: ProviderClaude})
	r.must(In{Kind: InSend, SessionID: "s", RequestID: "A", TaskID: "t", Generation: 1, RuntimeIdentity: "owner"})
	r.must(In{Kind: ObAccepted, SessionID: "s", RequestID: "A"})
	r.must(In{Kind: InStartReview, SessionID: "s", ID: "run", Stage: "plan", Digest: "d"})
	r.must(In{Kind: InQueueInput, SessionID: "s", RequestID: "q", PayloadHash: "h"})
	r.must(In{Kind: ObUnknown, SessionID: "s", RequestID: "A", ReasonCode: "deadline"})
	before := r.session("s")
	decision, err := r.apply(In{Kind: InStop, SessionID: "s"})
	if err != nil || len(decision.Effects) != 1 || decision.Effects[0].Kind != EffectTerminate || decision.Effects[0].Class != ClassStopWork {
		t.Fatalf("stop on unknown: %v %+v", err, decision)
	}
	after := r.session("s")
	if after.ControlEpoch != before.ControlEpoch || after.Supervision != before.Supervision || after.Task.State != before.Task.State || after.Inputs[0].Status != before.Inputs[0].Status {
		t.Fatalf("stop changed authority on an unknown session: %+v", after)
	}
	abandon, err := r.apply(In{Kind: InAbandon, SessionID: "s", ExpectedRequest: "A", Reason: rr("done")})
	if err != nil || len(abandon.Effects) != 1 || abandon.Effects[0].Kind != EffectTerminate {
		t.Fatalf("discard of an unknown Claude turn did not stop it: %v %+v", err, abandon)
	}
}

func TestK1F5AuthorizationIsDefaultDeny(t *testing.T) {
	r := newRig(t)
	r.must(In{Kind: InCreate, SessionID: "s", Provider: ProviderClaude})
	r.must(In{Kind: InSend, SessionID: "s", RequestID: "A", TaskID: "t", Generation: 1, RuntimeIdentity: "owner"})
	user := Principal{Class: PrincipalUser}
	agent := Principal{Class: PrincipalAgentRun, SessionID: "s"}
	provider := Principal{Class: PrincipalProvider, SessionID: "s"}
	foreign := Principal{Class: PrincipalProvider, SessionID: "other"}
	for name, in := range map[string]In{
		"user forges final":      {Kind: ObCompleted, Principal: user, SessionID: "s", RequestID: "A", Status: "completed"},
		"agent forges final":     {Kind: ObCompleted, Principal: agent, SessionID: "s", RequestID: "A", Status: "completed"},
		"foreign session frame":  {Kind: ObCompleted, Principal: foreign, SessionID: "s", RequestID: "A", Status: "completed"},
		"agent starts review":    {Kind: InStartReview, Principal: agent, SessionID: "s", ID: "run", Stage: "p", Digest: "d"},
		"agent records verdict":  {Kind: ObReviewOutcome, Principal: agent, SessionID: "s", ID: "run", Verdict: "pass", Digest: "d"},
		"provider sets active":   {Kind: InSetSupervision, Principal: provider, SessionID: "s", State: SupervisionActive},
		"user forges restart":    {Kind: ObRestart, Principal: user},
		"provider restarts":      {Kind: ObRestart, Principal: provider},
		"agent crosses boundary": {Kind: ObAuthBoundary, Principal: agent, Provider: ProviderClaude},
		"agent automatic send":   {Kind: InSend, Principal: agent, Automatic: true, SessionID: "s", RequestID: "B"},
		"user automatic send":    {Kind: InSend, Principal: user, Automatic: true, SessionID: "s", RequestID: "B"},
		"system sends as user":   {Kind: InSend, Principal: Principal{Class: PrincipalSystem}, SessionID: "s", RequestID: "B"},
		"no principal":           {Kind: InPause, SessionID: "s"},
		"unlisted kind":          {Kind: InputKind("future"), Principal: user, SessionID: "s"},
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
	for _, kind := range []string{"completed", "restart", "auth-boundary", "accepted", "review-outcome", "set-supervision", "future", ""} {
		if _, err := DecodeCommand([]byte(fmt.Sprintf(`{"kind":%q}`, kind))); err == nil {
			t.Errorf("DecodeCommand accepted kind %q", kind)
		}
	}
	if _, err := DecodeCommand([]byte(`{"kind":"pause"}`)); err != nil {
		t.Errorf("DecodeCommand refused a user command: %v", err)
	}
}

func TestK1F6ReviewerQuestionAfterBoundaryStillRejects(t *testing.T) {
	r := newRig(t)
	r.started("s", ProviderClaude)
	r.must(In{Kind: InStartReview, SessionID: "s", ID: "run", Stage: "plan", Digest: "d"})
	r.must(In{Kind: ObAuthBoundary, Provider: ProviderClaude})
	if got := r.session("s").Review.Status; got != "unknown" {
		t.Fatalf("running review after boundary: %s", got)
	}
	decision := r.must(In{Kind: ObQuestion, SessionID: "s", RequestID: "A", ID: "q", ReviewRunID: "run"})
	if len(decision.Effects) != 1 || decision.Effects[0].Kind != EffectRejectQuestion {
		t.Fatalf("question not rejected: %+v", decision)
	}
}

func TestK1F7ValuesAreClosedAndNoStateTraps(t *testing.T) {
	r := newRig(t)
	r.started("s", ProviderClaude)
	r.must(In{Kind: InQueueInput, SessionID: "s", RequestID: "q", PayloadHash: "h"})
	if _, err := r.apply(In{Kind: ObInputOutcome, SessionID: "s", RequestID: "q", Status: InputDispatching}); err == nil {
		t.Fatal("outcome moved a held input to dispatching")
	}
	if _, err := r.apply(In{Kind: ObInputOutcome, SessionID: "s", RequestID: "q", Status: InputDiscarded}); err == nil {
		t.Fatal("outcome skipped cleanup")
	}
	if got := findInput(r.session("s"), "q").Status; got != InputQueued {
		t.Fatalf("input moved to %s", got)
	}
	// Reduce holds the same rule if something emits the fact anyway.
	outcome := Fact{Seq: r.p.LastSeq + 1, SchemaVersion: SchemaVersion, At: testAt, Kind: FactInputOutcome, SessionID: "s", SessionRevision: r.session("s").Revision + 1, RequestID: "q", Status: InputRetained}
	if _, err := Reduce(r.p, outcome); !errors.Is(err, ErrIllegalFact) {
		t.Fatalf("outcome accepted with no open dispatch: %v", err)
	}
	for name, f := range map[string]Fact{
		"verdict":       {Kind: FactReviewOutcome, SessionID: "s", ID: "run", Verdict: "running"},
		"final status":  {Kind: FactProviderCompleted, SessionID: "s", RequestID: "A", Status: "prompt text from a provider"},
		"reason code":   {Kind: FactOutcomeUnknown, SessionID: "s", RequestID: "A", ReasonCode: "Bearer secret-value"},
		"digest":        {Kind: FactQuestionOpened, SessionID: "s", RequestID: "A", ID: "q", Digest: "free text with spaces"},
		"task state":    {Kind: FactCheckpointRecorded, SessionID: "s", TaskID: "task-s", State: "anything"},
		"long identity": {Kind: FactRequestIntended, SessionID: "s", RequestID: strings.Repeat("r", 200)},
		"empty hash":    {Kind: FactInputQueued, SessionID: "s", RequestID: "new"},
		"reason field":  {Kind: FactCwdChanged, SessionID: "s", CWD: "/x", Reason: "free text"},
	} {
		t.Run(name, func(t *testing.T) {
			f.Seq, f.SchemaVersion, f.At, f.SessionRevision = r.p.LastSeq+1, SchemaVersion, testAt, r.session("s").Revision+1
			if _, err := Reduce(r.p, f); !errors.Is(err, ErrIllegalFact) {
				t.Fatalf("accepted: %v", err)
			}
		})
	}
	// A provider-supplied value becomes a safe enum in evidence, never verbatim.
	r.complete("s", "A")
	r.must(In{Kind: ObCompleted, SessionID: "s", RequestID: "A", Status: "Bearer secret-value", Digest: "free text"})
	if got := r.session("s").Evidence[evidenceKey("A", "final")]; strings.Contains(got, "secret") || strings.Contains(got, "free") {
		t.Fatalf("free text reached evidence: %q", got)
	}
	// A repeated held input is refused, so no entry becomes unreachable.
	imported := newRig(t)
	imported.p, _ = Reduce(imported.p, Fact{Seq: 1, SchemaVersion: SchemaVersion, At: testAt, Kind: FactLegacyImported, SessionID: "s", SessionRevision: 1, Provider: ProviderClaude})
	held := Fact{Seq: 2, SchemaVersion: SchemaVersion, At: testAt, Kind: FactLegacyInputHeld, SessionID: "s", SessionRevision: 2, RequestID: "q", Status: InputHeld, PayloadHash: "h"}
	imported.p, _ = Reduce(imported.p, held)
	held.Seq, held.SessionRevision = 3, 3
	if _, err := Reduce(imported.p, held); !errors.Is(err, ErrIllegalFact) {
		t.Fatalf("duplicate held input accepted: %v", err)
	}
}

func TestK1F8CheckpointCannotClearReviewGuards(t *testing.T) {
	agent := Principal{Class: PrincipalAgentRun, SessionID: "s"}
	r := newRig(t)
	r.started("s", ProviderClaude)
	r.must(In{Kind: InStartReview, SessionID: "s", ID: "run", Stage: "plan", Digest: "d"})
	r.must(In{Kind: InPause, SessionID: "s"})
	_, err := r.apply(In{Kind: InCheckpoint, Principal: agent, SessionID: "s", TaskID: "task-s", State: TaskActive, Status: "pass", Digest: "d"})
	var refusal *Refusal
	if !errors.As(err, &refusal) {
		t.Fatalf("checkpoint admitted while paused: %v", err)
	}
	task := r.session("s").Task
	if task.ReviewStatus != ReviewPaused || task.State != TaskBlocked {
		t.Fatalf("guards cleared: %+v", task)
	}
	r = newRig(t)
	r.started("s", ProviderClaude)
	r.must(In{Kind: InCheckpoint, Principal: agent, SessionID: "s", TaskID: "task-s", State: TaskActive, Status: "pass", Digest: "d", Stage: "plan"})
	if got := r.session("s").Task.ReviewStatus; got != "" {
		t.Fatalf("an agent wrote review status %q with no verdict", got)
	}
	// The one thing it can ask for is a review.
	r.must(In{Kind: InCheckpoint, Principal: agent, SessionID: "s", TaskID: "task-s", State: TaskNeedsReview, Stage: "plan"})
	if got := r.session("s").Task.ReviewStatus; got != "queued" {
		t.Fatalf("needs_review gave %q", got)
	}
}

func TestK1F9RefusedDispatchLeavesAWayForward(t *testing.T) {
	r := newRig(t)
	r.started("s", ProviderClaude)
	r.must(In{Kind: InQueueInput, SessionID: "s", RequestID: "q", PayloadHash: "h"})
	r.complete("s", "A")
	r.must(In{Kind: InDispatchInput, Principal: Principal{Class: PrincipalSystem}, Automatic: true, SessionID: "s", RequestID: "q", ObjectiveHash: "two", RuntimeIdentity: "owner"})
	r.must(In{Kind: ObRefused, SessionID: "s", RequestID: "q", ReasonCode: "provider_rejected"})
	s := r.session("s")
	if s.LastRefusal != "provider_rejected" {
		t.Fatalf("no visible reason: %q", s.LastRefusal)
	}
	if got := Status(s); got != "error" {
		t.Fatalf("status %s", got)
	}
	r.must(In{Kind: InDiscardInput, SessionID: "s", RequestID: "q"})
	r.must(In{Kind: ObPayloadReleased, SessionID: "s", RequestID: "q"})
	r.must(In{Kind: InSend, SessionID: "s", RequestID: "B", TaskID: "t2", Generation: 2, RuntimeIdentity: "owner"})
}

func TestK1F10RuntimeIdentityIsRequired(t *testing.T) {
	r := newRig(t)
	r.must(In{Kind: InCreate, SessionID: "s", Provider: ProviderClaude})
	before := r.p
	_, err := Decide(before, In{Kind: InSend, Principal: Principal{Class: PrincipalUser}, At: testAt, SessionID: "s", RequestID: "A", TaskID: "t", Generation: 1})
	var refusal *Refusal
	if !errors.As(err, &refusal) || refusal.Code != "no_identity" {
		t.Fatalf("send with no identity: %v", err)
	}
	r2 := newRig(t)
	r2.must(In{Kind: InCreate, SessionID: "s", Provider: ProviderClaude})
	r2.must(In{Kind: ObConversationBound, SessionID: "s", ProviderID: "existing"})
	r2.refused(In{Kind: InSend, SessionID: "s", RequestID: "A", TaskID: "t", Generation: 1, RuntimeIdentity: "other"}, "no_owner")
}

func TestK1F11AutomaticSpendsBudgetAndKeepsItsTask(t *testing.T) {
	system := Principal{Class: PrincipalSystem}
	r := newRig(t)
	r.must(In{Kind: InCreate, SessionID: "s", Provider: ProviderClaude})
	r.must(In{Kind: InSend, SessionID: "s", RequestID: "A", TaskID: "t", Generation: 1, RemainingBursts: 1, RuntimeIdentity: "owner"})
	r.must(In{Kind: ObAccepted, SessionID: "s", RequestID: "A"})
	r.complete("s", "A")
	decision := r.must(In{Kind: InSend, Principal: system, Automatic: true, SessionID: "s", RequestID: "B", ExpectedTask: "t", TaskID: "replacement", RuntimeIdentity: "owner"})
	if got := r.session("s"); got.Task.ID != "t" || got.Supervision.RemainingBursts != 0 {
		t.Fatalf("task %s budget %d, facts %+v", got.Task.ID, got.Supervision.RemainingBursts, decision.Facts)
	}
	r.must(In{Kind: ObAccepted, SessionID: "s", RequestID: "B"})
	r.complete("s", "B")
	r.refused(In{Kind: InSend, Principal: system, Automatic: true, SessionID: "s", RequestID: "C", ExpectedTask: "t", RuntimeIdentity: "owner"}, "budget")

	for _, state := range []string{TaskComplete, TaskBlocked, TaskHandoff} {
		r := newRig(t)
		r.must(In{Kind: InCreate, SessionID: "s", Provider: ProviderClaude})
		r.must(In{Kind: InSend, SessionID: "s", RequestID: "A", TaskID: "t", Generation: 1, RemainingBursts: 3, RuntimeIdentity: "owner"})
		r.must(In{Kind: ObAccepted, SessionID: "s", RequestID: "A"})
		r.must(In{Kind: InQueueInput, SessionID: "s", RequestID: "q", PayloadHash: "h"})
		r.must(In{Kind: InCheckpoint, Principal: Principal{Class: PrincipalAgentRun, SessionID: "s"}, SessionID: "s", TaskID: "t", State: state, Stage: "plan"})
		r.complete("s", "A")
		r.refused(In{Kind: InSend, Principal: system, Automatic: true, SessionID: "s", RequestID: "B", ExpectedTask: "t", RuntimeIdentity: "owner"}, "task_ended")
		r.refused(In{Kind: InDispatchInput, Principal: system, Automatic: true, SessionID: "s", RequestID: "q", ObjectiveHash: "x", RuntimeIdentity: "owner"}, "task_ended")
	}
}

func TestK1F12LateFramesCoalescePerRequestAndKind(t *testing.T) {
	r := newRig(t)
	r.started("s", ProviderCodex)
	r.complete("s", "A")
	seq := r.p.LastSeq
	for i := 0; i < 1000; i++ {
		r.must(In{Kind: ObCompleted, SessionID: "s", RequestID: "A", TurnID: "x", Status: "completed", Digest: fmt.Sprintf("digest%d", i)})
		r.must(In{Kind: ObCompleted, SessionID: "s", RequestID: fmt.Sprintf("foreign%d", i), TurnID: "x", Status: "completed", Digest: "d"})
	}
	if got := r.p.LastSeq - seq; got > 2 {
		t.Fatalf("noisy provider appended %d facts", got)
	}
	if got := len(r.session("s").Evidence); got > 2 {
		t.Fatalf("evidence grew to %d", got)
	}
}

func TestQuarantineEndsARunningReview(t *testing.T) {
	r := newRig(t)
	r.started("s", ProviderClaude)
	r.must(In{Kind: InStartReview, SessionID: "s", ID: "run", Stage: "plan", Digest: "d"})
	r.must(In{Kind: ObQuarantine, SessionID: "s", ReasonCode: "illegal_fact"})
	if got := r.session("s").Review.Status; got != "unknown" {
		t.Fatalf("review stayed %s", got)
	}
	decision := r.must(In{Kind: ObQuestion, SessionID: "s", RequestID: "A", ID: "q", ReviewRunID: "run"})
	if len(decision.Effects) != 1 || decision.Effects[0].Kind != EffectRejectQuestion {
		t.Fatalf("question not rejected: %+v", decision)
	}
}
