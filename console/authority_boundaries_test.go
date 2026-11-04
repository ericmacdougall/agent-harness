package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCodexDisconnectRevokesLateCompletion(t *testing.T) {
	for _, reviewer := range []bool{false, true} {
		for _, state := range []string{"intent", "accepted", "final"} {
			name := state
			if reviewer {
				name += "/reviewer"
			}
			t.Run(name, func(t *testing.T) {
				a, s, c := identityCodexFixture(t)
				c.input = replySink{reply: func(data []byte) { identityReply(c, data, "turn-B") }}
				if err := a.send(s.ID, "B", "bounded request", nil, false); err != nil {
					t.Fatal(err)
				}
				a.mu.Lock()
				s.Supervision.State = "waiting"
				if reviewer {
					s.reviewParent = "parent"
					s.reviewDone = make(chan struct{})
				}
				binding := s.codexTurn
				if state == "intent" {
					s.requests["B"] = "intent"
					binding.turnID = ""
				}
				a.mu.Unlock()
				if state == "final" {
					identityEvent(a, c, "turn/completed", "turn-B")
				}
				a.mu.Lock()
				binding.frames = []codexPendingFrame{{turnID: "turn-B", raw: []byte(`{}`)}}
				binding.frameBytes = 8
				binding.pending = []codexCompletion{{turnID: "turn-B", status: "completed"}}
				binding.pendingBytes = 16
				s.PendingQuestions = []question{{ID: "revoked"}}
				queued := &queuedInput{RequestID: "C", Status: "queued"}
				s.inputs = append(s.inputs, queued)
				a.mu.Unlock()
				a.providerDisconnected(c, errors.New("controlled disconnect"))
				identityEvent(a, c, "turn/completed", "turn-B")
				// Repeated callbacks and completion cannot reopen or replay the request.
				a.providerDisconnected(c, errors.New("duplicate disconnect"))
				identityEvent(a, c, "turn/completed", "turn-B")
				a.scheduleInputs(s.ID)
				a.mu.Lock()
				defer a.mu.Unlock()
				want := "unknown"
				finals := 0
				if state == "final" {
					want, finals = "final", 1
				}
				if s.requests["B"] != want || s.providerFinal != (state == "final") {
					t.Errorf("disconnect lost terminal authority: request=%s final=%v", s.requests["B"], s.providerFinal)
				}
				if state != "final" && s.Status != "unknown" {
					t.Errorf("quarantine reopened: %s", s.Status)
				}
				if !s.Restored || s.Supervision.State != "paused" || s.codexTurn != nil || s.turnID != "" || len(s.PendingQuestions) != 0 {
					t.Error("disconnected binding/questions remained live")
				}
				if len(binding.frames) != 0 || binding.frameBytes != 0 || len(binding.pending) != 0 || binding.pendingBytes != 0 {
					t.Error("disconnected binding retained pending output")
				}
				if len(s.requestOrder) != 1 || queued.Status != "queued" || queued.DeliveredInputRevision != 0 {
					t.Error("disconnected client advanced the queue")
				}
				assertIdentityFinalReceipts(t, a, "B", finals)
			})
		}
	}
}

func TestCodexDisconnectFencesLateStartReply(t *testing.T) {
	a, s, c := identityCodexFixture(t)
	var binding *codexTurnBinding
	c.input = replySink{reply: func(data []byte) {
		identityRootFrame(a, c, "item/completed", "turn-B", "buffered-tool")
		identityEvent(a, c, "turn/completed", "turn-B")
		a.mu.Lock()
		binding = s.codexTurn
		a.mu.Unlock()
		a.providerDisconnected(c, errors.New("disconnect before correlated reply"))
		identityReply(c, data, "turn-B")
	}}
	if err := a.send(s.ID, "B", "bounded request", nil, false); err != nil {
		t.Fatal(err)
	}
	identityEvent(a, c, "turn/completed", "turn-B")
	a.mu.Lock()
	defer a.mu.Unlock()
	if s.requests["B"] != "unknown" || s.Status != "unknown" || s.providerFinal || s.codexTurn != nil || s.turnID != "" || s.Supervision.progress != 0 {
		t.Error("late reply restored disconnected request authority or published buffered content")
	}
	if binding == nil || len(binding.pending) != 0 || len(binding.frames) != 0 || binding.pendingBytes != 0 || binding.frameBytes != 0 {
		t.Error("disconnect retained pre-reply completion/content buffers")
	}
	assertIdentityFinalReceipts(t, a, "B", 0)
}

// The completion boundary must defend itself even if stale binding state remains.
func TestCodexCompletionRejectsRevokedLifecycle(t *testing.T) {
	for _, boundary := range []string{"restored", "disconnected", "unknown-request", "queue-uncertain", "replaced-client"} {
		t.Run(boundary, func(t *testing.T) {
			a, s, c := identityCodexFixture(t)
			s.lastRequest, s.turnID, s.Status = "B", "turn-B", "running"
			s.requests["B"] = "accepted"
			s.codexTurn = &codexTurnBinding{client: c, requestID: "B", turnID: "turn-B"}
			if err := a.record(s, "B", "accepted"); err != nil {
				t.Fatal(err)
			}
			switch boundary {
			case "restored":
				s.Restored = true
			case "disconnected":
				s.Status = "disconnected"
			case "unknown-request":
				s.requests["B"] = "unknown"
			case "queue-uncertain":
				s.queueUncertain = true
			case "replaced-client":
				s.codex = &rpcClient{}
			}
			a.mu.Lock()
			a.codexCompletionLocked(s, c, codexCompletion{turnID: "turn-B", status: "completed"})
			if s.requests["B"] == "final" || s.providerFinal {
				t.Error("revoked lifecycle admitted completion")
			}
			a.mu.Unlock()
			assertIdentityFinalReceipts(t, a, "B", 0)
		})
	}
}

func claudeCheckpointFixture(t *testing.T) (*app, *session, checkpointInput) {
	t.Helper()
	a, s, input := checkpointFixture(t)
	s.Provider, s.Status, s.lastRequest = "claude", "running", "active-request"
	s.requests[s.lastRequest] = "accepted"
	s.requestOrder = []string{s.lastRequest}
	s.Supervision.State = "waiting"
	s.scheduled = true // Keep the delayed final callback out of the scheduler in this admission test.
	a.runtime = func(string, string) (string, []string, error) {
		return "", nil, errors.New("providers disabled in checkpoint fixture")
	}
	s.claude = &claudeRun{input: &repairSink{}, requestID: s.lastRequest, taskID: s.task.ID, inputRevision: s.task.InputRevision, done: make(chan struct{})}
	s.task.capability = "0123456789abcdef0123456789abcdef"
	return a, s, input
}

type checkpointReadBarrier struct {
	io.Reader
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (b *checkpointReadBarrier) Read(p []byte) (int, error) {
	b.once.Do(func() { close(b.entered); <-b.release })
	return b.Reader.Read(p)
}

func TestClaudeCheckpointRechecksAuthority(t *testing.T) {
	for _, stage := range []string{"decode", "capture"} {
		for _, state := range []string{"active", "blocked", "handoff", "needs_review", "complete"} {
			if stage == "capture" && state != "needs_review" && state != "complete" {
				continue
			}
			for _, boundary := range []string{"valid", "final", "unknown", "disconnect", "pause", "epoch", "run", "request", "task", "capability", "queue", "restored", "done", "provider-final", "session"} {
				t.Run(stage+"/"+state+"/"+boundary, func(t *testing.T) {
					a, s, input := claudeCheckpointFixture(t)
					input.State, input.Scope = state, "checkpoint should only mutate while admitted"
					if state == "complete" {
						input.Stage = "final_review"
						subject, err := a.captureSubject(s.CWD, input.Kind, input.Head, input.Evidence)
						if err != nil {
							t.Fatal(err)
						}
						s.task.passes["final_review"] = bindSubject(subject, s.task).Digest
					}
					data, err := json.Marshal(input)
					if err != nil {
						t.Fatal(err)
					}
					entered, release := make(chan struct{}), make(chan struct{})
					var once sync.Once
					unblock := func() { once.Do(func() { close(release) }) }
					defer unblock()
					var body io.Reader = bytes.NewReader(data)
					if stage == "decode" {
						body = &checkpointReadBarrier{Reader: body, entered: entered, release: release}
					} else {
						a.resolvePolicy = func(provider, profile, stage string) (resolvedPolicy, error) {
							close(entered)
							<-release
							return defaultPolicy(provider, profile, stage)
						}
					}
					r := httptest.NewRequest("POST", "/checkpoint", body)
					r.Header.Set("Authorization", "Bearer "+s.task.capability)
					w := httptest.NewRecorder()
					done := make(chan struct{})
					go func() { defer close(done); a.checkpointHTTP(w, r) }()
					select {
					case <-entered:
					case <-done:
						t.Fatalf("request did not reach barrier: %d %s", w.Code, w.Body.String())
					case <-time.After(5 * time.Second):
						t.Fatal("checkpoint barrier not reached")
					}
					if boundary == "final" {
						a.readClaude(s, s.claude, strings.NewReader("{\"type\":\"result\",\"result\":\"finished\"}\n"))
						a.mu.Lock()
						if s.requests[s.lastRequest] != "final" || !s.providerFinal || s.Status != "idle" {
							t.Error("control did not finalize the Claude request")
						}
						a.mu.Unlock()
					}
					a.mu.Lock()
					switch boundary {
					case "unknown":
						s.requests[s.lastRequest] = "unknown"
					case "disconnect":
						a.claudeUnfinishedLocked(s, s.claude, "controlled disconnect")
						s.claude = nil
					case "pause":
						s.Supervision.State = "paused"
					case "epoch":
						s.controlEpoch++
					case "run":
						s.claude = &claudeRun{input: &repairSink{}, requestID: s.lastRequest, taskID: s.task.ID, inputRevision: s.task.InputRevision}
					case "request":
						s.lastRequest = "replacement"
						s.requests[s.lastRequest] = "accepted"
					case "task":
						replacement := *s.task
						s.task = &replacement
					case "capability":
						s.task.capability = "revoked"
					case "queue":
						s.queueUncertain = true
					case "restored":
						s.Restored = true
					case "done":
						close(s.claude.done)
					case "provider-final":
						s.providerFinal = true
					case "session":
						a.sessions = nil
					}
					beforeTask, beforeSupervision := *s.task, s.Supervision
					beforeJournal, err := a.journal.Stat()
					if err != nil {
						t.Error(err)
					}
					a.mu.Unlock()
					unblock()
					select {
					case <-done:
					case <-time.After(5 * time.Second):
						t.Fatal("checkpoint did not finish")
					}
					a.mu.Lock()
					defer a.mu.Unlock()
					if boundary == "valid" {
						if w.Code != 200 || s.task.State != state {
							t.Errorf("valid in-turn checkpoint refused: %d %s", w.Code, w.Body.String())
						}
					} else {
						if w.Code != 409 {
							t.Errorf("revoked checkpoint returned %d: %s", w.Code, w.Body.String())
						}
						if !reflect.DeepEqual(beforeTask, *s.task) || !reflect.DeepEqual(beforeSupervision, s.Supervision) {
							t.Error("revoked checkpoint mutated task/supervision/review")
						}
						afterJournal, err := a.journal.Stat()
						if err != nil {
							t.Error(err)
						} else if beforeJournal != nil && afterJournal.Size() != beforeJournal.Size() {
							t.Error("revoked checkpoint wrote a journal receipt")
						}
					}
				})
			}
		}
	}
}
