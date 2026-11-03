package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type repairSink struct{ bytes.Buffer }

func (s *repairSink) Close() error { return nil }
func TestRepairCancelledApprovalCannotWriteDecision(t *testing.T) {
	a, s, _ := checkpointFixture(t)
	sink := &repairSink{}
	c := &rpcClient{input: sink, done: make(chan struct{})}
	s.codex = c
	s.Status = "waiting"
	s.turnID = "cancelled-turn"
	s.lastRequest = "cancelled-request"
	s.requests[s.lastRequest] = "accepted"
	s.codexTurn = &codexTurnBinding{requestID: s.lastRequest, turnID: s.turnID, client: c}
	s.PendingQuestions = []question{{ID: "approval", method: "item/commandExecution/requestApproval", Choices: []string{"accept", "decline"}, ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339), rpcID: json.RawMessage(`17`)}}
	a.codexEvent(c, "turn/completed", []byte(`{"threadId":"test-provider","turn":{"id":"cancelled-turn","status":"interrupted"}}`))
	if err := a.answerQuestion(s.ID, "approval", "accept"); err == nil || sink.Len() != 0 || s.Status != "paused" {
		t.Fatalf("cancelled approval wrote decision: err=%v status=%s out=%s", err, s.Status, sink.String())
	}
}
func TestRepairCheckpointCannotOverwritePauseDuringPolicyRead(t *testing.T) {
	a, s, input := checkpointFixture(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	a.resolvePolicy = func(string, string, string) (resolvedPolicy, error) {
		close(entered)
		<-release
		return defaultPolicy("codex", "", "main")
	}
	done := make(chan error, 1)
	go func() { done <- a.checkpointUpdate(s.ID, input) }()
	<-entered
	_ = a.control(s.ID, "pause", "")
	close(release)
	err := <-done
	if err == nil || s.Supervision.State != "paused" {
		t.Fatalf("checkpoint overwrote concurrent pause: %v %s", err, s.Supervision.State)
	}
}
func TestRepairReviewUnknownNeverActivatesRepair(t *testing.T) {
	a, s, input := checkpointFixture(t)
	if err := a.checkpointUpdate(s.ID, input); err != nil {
		t.Fatal(err)
	}
	a.resolvePolicy = func(string, string, string) (resolvedPolicy, error) {
		return resolvedPolicy{}, errors.New("controlled unavailable reviewer")
	}
	a.runtime = func(string, string) (string, []string, error) { return "", nil, errors.New("must not dispatch") }
	a.runReviews(s)
	if s.Supervision.State == "active" || s.task.State == "active" {
		t.Fatalf("review infrastructure failure activated automatic repair: %+v", s.Supervision)
	}
}
func TestRepairRPCWriteRespectsCallerDeadline(t *testing.T) {
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	c := &rpcClient{input: writer, done: make(chan struct{}), pending: map[string]chan rpcPacket{}}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- c.call(ctx, "blocked", map[string]any{"body": strings.Repeat("x", 65536)}, nil) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("blocked write accepted")
		}
	case <-time.After(150 * time.Millisecond):
		writer.Close()
		<-done
		t.Fatal("provider input write ignored caller deadline")
	}
}
func TestRepairRestoreRetainsCheckpointAndReviewerIdentity(t *testing.T) {
	a, s, input := checkpointFixture(t)
	s.ProviderID = "owned"
	if err := a.record(s, "request", "final"); err != nil {
		t.Fatal(err)
	}
	if err := a.checkpointUpdate(s.ID, input); err != nil {
		t.Fatal(err)
	}
	review := emptySession("codex", s.CWD, "")
	review.ProviderID = "review-owned"
	review.reviewParent = s.ID
	if err := a.record(review, "review-request", "accepted"); err != nil {
		t.Fatal(err)
	}
	a.journal.Sync()
	fresh := &app{journal: a.journal}
	if err := fresh.restore(); err != nil {
		t.Fatal(err)
	}
	if len(fresh.sessions) != 1 || fresh.sessions[0].task == nil || len(fresh.reviews) != 1 {
		t.Fatal("recovery discarded checkpoint/reviewer identities")
	}
}
func TestRepairAutomaticSendCannotOutrunPause(t *testing.T) {
	a, s, _ := checkpointFixture(t)
	s.Supervision.State = "active"
	entered := make(chan struct{})
	release := make(chan struct{})
	a.resolvePolicy = func(string, string, string) (resolvedPolicy, error) {
		close(entered)
		<-release
		return defaultPolicy("codex", "", "main")
	}
	a.runtime = func(string, string) (string, []string, error) { return "/trusted/cli", nil, nil }
	done := make(chan error, 1)
	go func() { done <- a.send(s.ID, "auto", "continue", nil, true, sendBinding{s.task.ID, s.controlEpoch}) }()
	<-entered
	_ = a.control(s.ID, "pause", "")
	close(release)
	if err := <-done; err == nil {
		t.Fatal("automatic send ignored pause")
	}
	if _, exists := s.requests["auto"]; exists {
		t.Fatal("paused continuation created dispatch intent")
	}
}
func TestRepairClaudeWriteRespectsContext(t *testing.T) {
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	run := &claudeRun{input: writer, done: make(chan struct{})}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := run.writeContext(ctx, map[string]any{"text": strings.Repeat("x", 65536)}); err == nil || time.Since(start) > time.Second {
		t.Fatal("Claude input failed bounded backpressure", err)
	}
}
func TestRepairRestoreCannotSendOrResumeOldWriter(t *testing.T) {
	a, s, _ := checkpointFixture(t)
	s.Restored = true
	s.Status = "disconnected"
	a.runtime = func(string, string) (string, []string, error) {
		t.Fatal("restored writer reached runtime")
		return "", nil, nil
	}
	if err := a.send(s.ID, "old", "continue", nil, false); err == nil {
		t.Fatal("restored send admitted")
	}
	if err := a.control(s.ID, "resume", ""); err == nil {
		t.Fatal("restored resume admitted")
	}
}
func TestRepairValidApprovalIsBoundToActualTurn(t *testing.T) {
	a, s, _ := checkpointFixture(t)
	sink := &repairSink{}
	client := &rpcClient{input: sink, done: make(chan struct{})}
	s.codex = client
	s.Status = "running"
	s.turnID = "turn-one"
	s.lastRequest = "request-one"
	s.requests[s.lastRequest] = "accepted"
	s.codexTurn = &codexTurnBinding{requestID: s.lastRequest, client: client, turnID: s.turnID}
	params := json.RawMessage(`{"threadId":"test-provider","turnId":"turn-one","command":"echo safe"}`)
	a.codexQuestion(client, rpcPacket{ID: json.RawMessage(`12`), Method: "item/commandExecution/requestApproval", Params: params})
	if len(s.PendingQuestions) != 1 {
		t.Fatal("question fixture absent")
	}
	id := s.PendingQuestions[0].ID
	if err := a.answerQuestion(s.ID, id, "accept"); err != nil {
		t.Fatal("matching approval rejected", err)
	}
	if !strings.Contains(sink.String(), `"decision":"accept"`) {
		t.Fatal("matching approval not delivered")
	}
	if err := a.answerQuestion(s.ID, id, "accept"); err == nil {
		t.Fatal("approval replayed")
	}
	client.input.Close()
}
func TestRepairDisconnectReconcilesManagedReview(t *testing.T) {
	a, parent, _ := checkpointFixture(t)
	client := &rpcClient{input: &repairSink{}, done: make(chan struct{})}
	review := emptySession("codex", parent.CWD, "")
	review.ProviderID = "owned-review"
	review.reviewParent = parent.ID
	review.reviewTaskID = parent.task.ID
	review.Status = "running"
	review.codex = client
	review.reviewDone = make(chan struct{})
	done := review.reviewDone
	a.reviews = append(a.reviews, review)
	a.providerDisconnected(client, errors.New("controlled disconnect"))
	select {
	case <-done:
	default:
		t.Fatal("disconnected reviewer left review waiter running")
	}
	if review.Status != "unknown" || !review.Restored || review.ProviderID != "owned-review" {
		t.Fatal("review identity or unknown outcome lost")
	}
}

type replySink struct{ reply func([]byte) }

func (s replySink) Write(data []byte) (int, error) { s.reply(data); return len(data), nil }
func (s replySink) Close() error                   { return nil }
func TestRepairCancellationInterruptsOnlyOwnedReview(t *testing.T) {
	a, parent, _ := checkpointFixture(t)
	client := &rpcClient{pending: map[string]chan rpcPacket{}, done: make(chan struct{})}
	calls := []map[string]any{}
	client.input = replySink{reply: func(data []byte) {
		var packet map[string]any
		_ = json.Unmarshal(data, &packet)
		calls = append(calls, packet)
		id, _ := json.Marshal(packet["id"])
		client.mu.Lock()
		ch := client.pending[string(id)]
		client.mu.Unlock()
		if ch != nil {
			ch <- rpcPacket{ID: id, Result: json.RawMessage(`{}`)}
		}
	}}
	review := emptySession("codex", parent.CWD, "")
	review.ProviderID = "owned-review"
	review.reviewParent = parent.ID
	review.Status = "running"
	review.codex = client
	review.turnID = "owned-turn"
	review.reviewDone = make(chan struct{})
	a.reviews = append(a.reviews, review)
	a.cancelReview(review, "controlled deadline")
	client.writeOnce.Do(func() { client.writer = newInputWriter(client.input) })
	client.writer.close()
	if len(calls) != 1 || calls[0]["method"] != "turn/interrupt" {
		t.Fatal("cancellation dispatched unexpected methods", calls)
	}
	params, _ := calls[0]["params"].(map[string]any)
	if params["threadId"] != "owned-review" || params["turnId"] != "owned-turn" || review.Status != "unknown" {
		t.Fatal("cancellation targeted wrong identity or claimed final outcome", params)
	}
}
func TestRepairReviewVerdictUnknownCannotBeProseOrMalformedPass(t *testing.T) {
	task := &trackedTask{ID: "task", Generation: 1, InputRevision: 1, ObjectiveHash: "objective", Stage: "plan_review", Subject: reviewSubject{Digest: "digest"}}
	good := `{"taskId":"task","generation":1,"inputRevision":1,"objectiveHash":"objective","stage":"plan_review","digest":"digest","verdict":"PASS","findings":[]}`
	if verdict, err := decodeReviewVerdict(good, task); err != nil || verdict.Verdict != "PASS" {
		t.Fatal("valid exact verdict rejected", err)
	}
	for _, bad := range []string{"PASS", strings.Replace(good, `"digest":"digest"`, `"digest":"foreign"`, 1), strings.Replace(good, `,"findings":[]`, "", 1), strings.Replace(good, `"findings":[]`, `"findings":null`, 1), strings.Replace(good, `"verdict":"PASS"`, `"verdict":"BLOCK"`, 1), strings.Replace(good, `"verdict":"PASS"`, `"verdict":"BLOCK","verdict":"PASS"`, 1), good + " trailing"} {
		if _, err := decodeReviewVerdict(bad, task); err == nil {
			t.Fatal("malformed verdict accepted", bad)
		}
	}
}
func TestRepairOwnerResumeRefusesBeforeProviderRPC(t *testing.T) {
	a, parent, _ := checkpointFixture(t)
	feature, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	parent.Agents = append(parent.Agents, agent{ID: "owner-thread", Provider: "codex", CWD: feature, Status: "interrupted"})
	parent.policy = resolvedPolicy{Model: "main-model", Effort: "high", Permissions: "danger-full-access", ServiceTier: "priority"}
	client := &rpcClient{pending: map[string]chan rpcPacket{}, done: make(chan struct{})}
	calls := []map[string]any{}
	client.input = replySink{reply: func(data []byte) {
		var packet map[string]any
		_ = json.Unmarshal(data, &packet)
		calls = append(calls, packet)
		id, _ := json.Marshal(packet["id"])
		result := json.RawMessage(`{}`)
		if packet["method"] == "thread/read" {
			result, _ = json.Marshal(map[string]any{"thread": map[string]any{"id": "owner-thread", "cwd": feature, "model": "owner-model", "reasoningEffort": "low", "modelProvider": "owner-runtime", "canAcceptDirectInput": true}})
		}
		client.mu.Lock()
		ch := client.pending[string(id)]
		client.mu.Unlock()
		if ch != nil {
			ch <- rpcPacket{ID: id, Result: result}
		}
	}}
	parent.codex = client
	for range 2 {
		if err = a.controlAgent(parent, "owner-thread", "resume"); err == nil || !strings.Contains(err.Error(), "fresh owner") {
			t.Fatal("native direct resume was not refused with a fresh-owner handoff", err)
		}
	}
	if len(calls) != 0 {
		t.Fatal("resume refusal contacted the old provider client", calls)
	}
	owner := parent.Agents[0]
	if owner.CanResume || !strings.Contains(owner.ControlReason, "fresh owner") || owner.Status != "interrupted" {
		t.Fatal("resume denial was not sticky and user-visible", owner)
	}
}
func TestRepairOwnerResumeRefusesAcrossObservableContextChanges(t *testing.T) {
	for _, test := range []struct {
		name      string
		configure func(*session)
	}{
		{name: "unchanged", configure: func(*session) {}},
		{name: "settings revision changed", configure: func(parent *session) { parent.PolicyRevision = "new-settings" }},
		{name: "profile changed", configure: func(parent *session) { parent.ProfileID = "new-profile" }},
		{name: "legacy provider unknown", configure: func(parent *session) { parent.Agents[0].Provider = "" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			a, parent, _ := checkpointFixture(t)
			parent.Agents = append(parent.Agents, agent{ID: "owner", Provider: "codex", Status: "interrupted", CanResume: true})
			test.configure(parent)
			calls := 0
			parent.codex = &rpcClient{pending: map[string]chan rpcPacket{}, done: make(chan struct{}), input: replySink{reply: func([]byte) { calls++ }}}
			if err := a.controlAgent(parent, "owner", "resume"); err == nil {
				t.Fatal("native direct resume was accepted")
			}
			if calls != 0 || parent.Agents[0].CanResume {
				t.Fatal("resume refusal contacted the old client or left resume enabled", calls, parent.Agents[0])
			}
		})
	}
}
func TestRepairOwnerResumeDenialSurvivesLateEventAndRefresh(t *testing.T) {
	a, parent, _ := checkpointFixture(t)
	parent.ProviderID = "parent-thread"
	parent.Agents = append(parent.Agents, agent{ID: "owner-thread", Provider: "codex", Status: "running", CanPause: true, CanStop: true})
	a.codexEvent(nil, "turn/completed", json.RawMessage(`{"threadId":"owner-thread","turn":{"id":"owner-turn","status":"interrupted"}}`))
	owner := parent.Agents[0]
	if owner.CanResume || !strings.Contains(owner.ControlReason, "fresh owner") || owner.Status != "interrupted" {
		t.Fatal("late completion removed native resume denial", owner)
	}
	client := &rpcClient{pending: map[string]chan rpcPacket{}, done: make(chan struct{})}
	calls := []map[string]any{}
	client.input = replySink{reply: func(data []byte) {
		var packet map[string]any
		_ = json.Unmarshal(data, &packet)
		calls = append(calls, packet)
		id, _ := json.Marshal(packet["id"])
		body, _ := json.Marshal(map[string]any{"data": []any{map[string]any{"id": "owner-thread", "cwd": parent.CWD, "source": map[string]any{"parent_thread_id": "parent-thread"}, "status": map[string]any{"type": "idle"}}}})
		client.mu.Lock()
		ch := client.pending[string(id)]
		client.mu.Unlock()
		if ch != nil {
			ch <- rpcPacket{ID: id, Result: body}
		}
	}}
	parent.codex = client
	a.refreshAgents(parent)
	client.writer.close()
	owner = parent.Agents[0]
	if owner.CanResume || !strings.Contains(owner.ControlReason, "fresh owner") || owner.Status != "idle" {
		t.Fatal("agent refresh removed native resume denial", owner)
	}
	if len(calls) != 1 || calls[0]["method"] != "thread/list" {
		t.Fatal("unexpected refresh calls", calls)
	}
}
func TestRepairInteractiveReviewErrorStillCancelsOwnedTurn(t *testing.T) {
	a, parent, _ := checkpointFixture(t)
	client := &rpcClient{pending: map[string]chan rpcPacket{}, done: make(chan struct{})}
	calls := []map[string]any{}
	client.input = replySink{reply: func(data []byte) {
		var packet map[string]any
		_ = json.Unmarshal(data, &packet)
		calls = append(calls, packet)
		id, _ := json.Marshal(packet["id"])
		client.mu.Lock()
		ch := client.pending[string(id)]
		client.mu.Unlock()
		if ch != nil {
			ch <- rpcPacket{ID: id, Result: json.RawMessage(`{}`)}
		}
	}}
	review := emptySession("codex", parent.CWD, "")
	review.ProviderID = "interactive-review"
	review.turnID = "owned-review-turn"
	review.lastRequest = "review-request"
	review.requests[review.lastRequest] = "accepted"
	review.codexTurn = &codexTurnBinding{requestID: review.lastRequest, client: client, turnID: review.turnID}
	review.Status = "running"
	review.codex = client
	review.reviewParent = parent.ID
	review.reviewDone = make(chan struct{})
	a.reviews = append(a.reviews, review)
	a.codexQuestion(client, rpcPacket{ID: json.RawMessage(`77`), Method: "item/tool/requestUserInput", Params: json.RawMessage(`{"threadId":"interactive-review","turnId":"owned-review-turn","questions":[]}`)})
	if review.Status != "error" || review.providerFinal {
		t.Fatal("interactive error falsely represented native final outcome")
	}
	a.cancelUnfinishedReview(review)
	client.writer.close()
	interrupted := false
	for _, call := range calls {
		if call["method"] == "turn/interrupt" {
			params, _ := call["params"].(map[string]any)
			interrupted = params["threadId"] == "interactive-review" && params["turnId"] == "owned-review-turn"
		}
	}
	if !interrupted || review.Status != "unknown" {
		t.Fatal("permission error left reviewer running without owned cancellation", calls)
	}
}

func TestRepairUnknownReviewerKeepsStopControl(t *testing.T) {
	a, parent, input := checkpointFixture(t)
	if err := a.checkpointUpdate(parent.ID, input); err != nil {
		t.Fatal(err)
	}
	parent.task.ReviewStatus = "running"
	a.runtime = func(string, string) (string, []string, error) { return "/synthetic/cli", nil, nil }
	p, _ := defaultPolicy("codex", "", "main")
	_, _, fingerprint, err := a.resolveRuntime(p)
	if err != nil {
		t.Fatal(err)
	}
	client := &rpcClient{pending: map[string]chan rpcPacket{}, done: make(chan struct{})}
	cancelled := make(chan struct{})
	client.input = replySink{reply: func(data []byte) {
		var packet map[string]any
		_ = json.Unmarshal(data, &packet)
		id, _ := json.Marshal(packet["id"])
		result := json.RawMessage(`{}`)
		if packet["method"] == "thread/start" {
			result = json.RawMessage(`{"thread":{"id":"owned-review"}}`)
		}
		client.mu.Lock()
		ch := client.pending[string(id)]
		client.mu.Unlock()
		if ch != nil {
			if packet["method"] == "turn/interrupt" {
				ch <- rpcPacket{ID: id, Error: &rpcError{Code: -1, Message: "controlled interrupt refusal"}}
			} else {
				ch <- rpcPacket{ID: id, Result: result}
			}
		}
		if packet["method"] == "turn/start" {
			go func() {
				a.mu.Lock()
				r := a.reviews[0]
				r.turnID = "owned-turn"
				a.mu.Unlock()
				a.cancelReview(r, "controlled pause with unknown result")
				close(cancelled)
			}()
		}
	}}
	a.clients["codex::"+fingerprint] = client
	_, err = a.runIndependentReview(parent, parent.task, policyStep{Provider: "codex"})
	<-cancelled
	if err == nil {
		t.Fatal("unknown review unexpectedly passed")
	}
	child := parent.Agents[0]
	if child.Status == "unknown" && !child.CanStop {
		t.Fatalf("unconfirmed live reviewer lost stop control: status=%s CanStop=%v", child.Status, child.CanStop)
	}
}
func TestRepairStopControlClosesOnlyAfterNativeFinal(t *testing.T) {
	a, parent, _ := checkpointFixture(t)
	review := emptySession("codex", parent.CWD, "")
	review.ProviderID = "owned-review"
	review.reviewParent = parent.ID
	review.Status = "unknown"
	review.Error = "Interrupt unconfirmed"
	review.lastRequest = "owned-request"
	review.requests[review.lastRequest] = "accepted"
	review.turnID = "owned-turn"
	review.codexTurn = &codexTurnBinding{requestID: review.lastRequest, turnID: review.turnID}
	review.reviewDone = make(chan struct{})
	a.reviews = append(a.reviews, review)
	parent.Agents = append(parent.Agents, agent{ID: review.ProviderID, Provider: "codex", Role: "reviewer"})
	a.mu.Lock()
	a.syncReviewAgentLocked(review)
	a.mu.Unlock()
	if !parent.Agents[0].CanStop || parent.Agents[0].ControlReason == "" {
		t.Fatal("unknown outcome lost visible stop/reconcile state")
	}
	a.codexEvent(nil, "turn/completed", json.RawMessage(`{"threadId":"owned-review","turn":{"id":"owned-turn","status":"interrupted"}}`))
	if !review.providerFinal || parent.Agents[0].CanStop {
		t.Fatal("verified final outcome did not close stop control")
	}
}
