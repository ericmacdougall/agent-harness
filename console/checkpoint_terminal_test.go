package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Exercise the provider entry points, including their native success responses.
func terminalCheckpointFixture(t *testing.T, provider string) (*app, *session, checkpointInput, func(checkpointInput) bool) {
	t.Helper()
	a, s, input := claudeCheckpointFixture(t)
	s.Provider = provider
	s.Work = s.task
	input.State, input.Stage = "complete", "final_review"
	subject, err := a.captureSubject(s.CWD, input.Kind, input.Head, input.Evidence)
	if err != nil {
		t.Fatal(err)
	}
	s.task.passes["final_review"] = bindSubject(subject, s.task).Digest
	s.task.passes["plan_review"] = "prior-plan-pass"
	responses := make(chan rpcPacket, 2)
	c := &rpcClient{done: make(chan struct{}), input: replySink{reply: func(data []byte) {
		var packet rpcPacket
		_ = json.Unmarshal(data, &packet)
		responses <- packet
	}}}
	s.codex = c
	s.turnID = "terminal-turn"
	s.codexTurn = &codexTurnBinding{client: c, requestID: s.lastRequest, turnID: s.turnID}
	t.Cleanup(func() {
		if c.writer != nil {
			c.writer.close()
		}
	})
	call := func(input checkpointInput) bool {
		if provider == "claude" {
			data, _ := json.Marshal(input)
			r := httptest.NewRequest("POST", "/checkpoint", bytes.NewReader(data))
			r.Header.Set("Authorization", "Bearer "+s.task.capability)
			w := httptest.NewRecorder()
			a.checkpointHTTP(w, r)
			return w.Code == 200 && strings.Contains(w.Body.String(), `"recorded":true`)
		}
		params, _ := json.Marshal(map[string]any{"threadId": s.ProviderID, "turnId": "terminal-turn", "tool": "harness_console_checkpoint", "arguments": input})
		a.codexQuestion(c, rpcPacket{ID: json.RawMessage(`1`), Method: "item/tool/call", Params: params})
		packet := <-responses
		var result struct{ Success bool }
		_ = json.Unmarshal(packet.Result, &result)
		return packet.Error == nil && result.Success
	}
	return a, s, input, call
}

func checkpointJournalBytes(t *testing.T, a *app) []byte {
	t.Helper()
	data, err := os.ReadFile(a.journal.Name())
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestCheckpointCompleteCannotReopen(t *testing.T) {
	for _, provider := range []string{"codex", "claude"} {
		for _, state := range []string{"active", "blocked", "handoff", "needs_review"} {
			t.Run(provider+"/"+state, func(t *testing.T) {
				a, s, input, call := terminalCheckpointFixture(t, provider)
				if !call(input) {
					t.Fatal("completion control was not acknowledged")
				}
				durable := checkpointJournalBytes(t, a)
				var record journalRecord
				if err := json.Unmarshal(bytes.TrimSpace(durable), &record); err != nil || record.Checkpoint == nil || record.Checkpoint.State != "complete" {
					t.Fatal("completion control lacks a durable receipt", err)
				}
				if record.Checkpoint.Stage != input.Stage || record.Checkpoint.ScopeHash != objectiveHash(input.Scope) || record.Checkpoint.Subject.Digest != s.task.passes["final_review"] {
					t.Error("completion receipt does not bind its stage, scope and reviewed subject")
				}
				input.State = state
				if call(input) {
					t.Error("stale checkpoint acknowledged after durable complete")
				}
				if s.task.State != "complete" || s.Supervision.State != "complete" || !bytes.Equal(durable, checkpointJournalBytes(t, a)) {
					t.Error("stale checkpoint reopened terminal state or changed its journal")
				}
				// Finish the still-bound native turn, then deliver the same late
				// checkpoint. Neither correlation nor finality reopens this task.
				if provider == "codex" {
					a.codexEvent(s.codex, "turn/completed", json.RawMessage(`{"threadId":"test-provider","turn":{"id":"terminal-turn","status":"completed"}}`))
				} else {
					a.readClaude(s, s.claude, strings.NewReader("{\"type\":\"result\",\"result\":\"finished\"}\n"))
				}
				if call(input) {
					t.Error("checkpoint acknowledged after native final")
				}
				var dispatches atomic.Int32
				a.mu.Lock()
				if !s.providerFinal || s.requests[s.lastRequest] != "final" {
					t.Error("correlated native final control failed")
				}
				q := &queuedInput{RequestID: "follow-up", TaskID: s.task.ID, Generation: s.task.Generation, Status: "queued", Text: "queued before completion"}
				s.inputs = append(s.inputs, q)
				s.scheduled = false
				a.resolvePolicy = func(string, string, string) (resolvedPolicy, error) {
					dispatches.Add(1)
					return resolvedPolicy{}, errors.New("terminal task must not dispatch")
				}
				a.mu.Unlock()
				a.scheduleInputs(s.ID)
				a.mu.Lock()
				defer a.mu.Unlock()
				if dispatches.Load() != 0 || q.Status != "held" || q.DeliveredInputRevision != 0 || s.task.State != "complete" || len(a.reviews) != 0 {
					t.Error("terminal task escaped queue/review gate")
				}
			})
		}
	}
}

func TestCheckpointCompleteDuplicateRequiresDurableIdentity(t *testing.T) {
	for _, provider := range []string{"codex", "claude"} {
		t.Run(provider, func(t *testing.T) {
			a, s, input, call := terminalCheckpointFixture(t, provider)
			if !call(input) {
				t.Fatal("completion control failed")
			}
			durable := checkpointJournalBytes(t, a)
			if !call(input) || !bytes.Equal(durable, checkpointJournalBytes(t, a)) {
				t.Error("duplicate completion was not idempotent")
			}
			for _, field := range []string{"task", "generation", "revision", "objective", "stage", "scope", "evidence"} {
				bad := input
				switch field {
				case "task":
					bad.TaskID += "-stale"
				case "generation":
					bad.Generation++
				case "revision":
					bad.InputRevision++
				case "objective":
					bad.ObjectiveHash += "-stale"
				case "stage":
					bad.Stage = "plan_review"
				case "scope":
					bad.Scope = "different completion"
				case "evidence":
					if err := os.WriteFile(filepath.Join(s.CWD, "proof.txt"), []byte("changed evidence"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				if call(bad) {
					t.Errorf("duplicate with different %s acknowledged", field)
				}
			}
			if err := os.WriteFile(filepath.Join(s.CWD, "proof.txt"), []byte("bounded proof"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := a.journal.Close(); err != nil {
				t.Fatal(err)
			}
			// A known durable duplicate needs no new write, unlike the failed
			// initial writes covered by TestCheckpointJournalFailureCannotAcknowledge.
			if !call(input) || s.task.State != "complete" || !bytes.Equal(durable, checkpointJournalBytes(t, a)) {
				t.Error("durable duplicate required another write or changed terminal state")
			}
		})
	}
}

func TestCheckpointCompleteRecheckedAfterCapture(t *testing.T) {
	for _, provider := range []string{"codex", "claude"} {
		for _, state := range []string{"needs_review", "complete"} {
			t.Run(provider+"/"+state, func(t *testing.T) {
				a, s, input, call := terminalCheckpointFixture(t, provider)
				entered, release := make(chan struct{}), make(chan struct{})
				var captures atomic.Int32
				a.resolvePolicy = func(provider, profile, stage string) (resolvedPolicy, error) {
					if captures.Add(1) == 1 {
						close(entered)
						<-release
					}
					return defaultPolicy(provider, profile, stage)
				}
				pending := input
				pending.State = state
				done := make(chan bool, 1)
				go func() { done <- call(pending) }()
				select {
				case <-entered:
				case <-time.After(5 * time.Second):
					close(release)
					t.Fatal("capture barrier not reached")
				}
				accepted := call(input)
				durable := checkpointJournalBytes(t, a)
				close(release)
				select {
				case result := <-done:
					if result != (state == "complete") {
						t.Errorf("pending %s returned success=%v", state, result)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("capture did not finish")
				}
				if !accepted || s.task.State != "complete" || !bytes.Equal(durable, checkpointJournalBytes(t, a)) {
					t.Error("pending capture rewrote durable completion")
				}
			})
		}
	}
}

func TestCheckpointCompleteFencesPendingReviewOutcome(t *testing.T) {
	a, s, input, call := terminalCheckpointFixture(t, "codex")
	queued := input
	queued.State = "needs_review"
	if !call(queued) {
		t.Fatal("review admission control failed")
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var policies atomic.Int32
	a.resolvePolicy = func(provider, profile, stage string) (resolvedPolicy, error) {
		if policies.Add(1) == 1 {
			close(entered)
			<-release
			return resolvedPolicy{}, errors.New("delayed reviewer outcome")
		}
		return defaultPolicy(provider, profile, stage)
	}
	done := make(chan struct{})
	go func() { a.runReviews(s); close(done) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("review policy barrier not reached")
	}
	accepted := call(input)
	durable := checkpointJournalBytes(t, a)
	close(release)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("review did not finish")
	}
	if !accepted || s.task.State != "complete" || s.Supervision.State != "complete" || s.task.reviewing || !bytes.Equal(durable, checkpointJournalBytes(t, a)) {
		t.Error("late review outcome rewrote durable completion")
	}
}
