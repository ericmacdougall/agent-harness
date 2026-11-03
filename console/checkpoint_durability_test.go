package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestCheckpointJournalFailureCannotAcknowledge(t *testing.T) {
	for _, provider := range []string{"claude", "codex"} {
		for _, state := range []string{"needs_review", "active", "blocked", "handoff", "complete"} {
			t.Run(provider+"/"+state, func(t *testing.T) {
				a, s, input := claudeCheckpointFixture(t)
				s.Provider = provider
				s.Work = s.task
				input.State = state
				if state == "complete" {
					input.Stage = "final_review"
					subject, err := a.captureSubject(s.CWD, input.Kind, input.Head, input.Evidence)
					if err != nil {
						t.Fatal(err)
					}
					s.task.passes["final_review"] = bindSubject(subject, s.task).Digest
				}
				c := &rpcClient{}
				s.codex = c
				s.turnID = "turn-A"
				s.codexTurn = &codexTurnBinding{client: c, requestID: s.lastRequest, turnID: "turn-A"}
				binding := s.codexTurn
				if provider == "codex" && !boundCodexTurn(s, c, "turn-A") {
					t.Fatal("fixture lacks exact Codex admission")
				}
				data, err := json.Marshal(input)
				if err != nil {
					t.Fatal(err)
				}
				before, err := os.ReadFile(a.journal.Name())
				if err != nil {
					t.Fatal(err)
				}
				if err = a.journal.Close(); err != nil {
					t.Fatal(err)
				}
				for attempt := 0; attempt < 2; attempt++ {
					if provider == "claude" {
						r := httptest.NewRequest("POST", "/checkpoint", bytes.NewReader(data))
						r.Header.Set("Authorization", "Bearer "+s.task.capability)
						w := httptest.NewRecorder()
						a.checkpointHTTP(w, r)
						if w.Code != 409 || strings.Contains(w.Body.String(), `"recorded":true`) {
							t.Errorf("attempt %d falsely acknowledged checkpoint: %d %s", attempt, w.Code, w.Body.String())
						}
					} else {
						err = a.checkpointUpdateGuarded(s.ID, input, func(current *session) bool {
							return current.codexTurn == binding && boundCodexTurn(current, c, "turn-A")
						})
						if err == nil {
							t.Errorf("attempt %d falsely acknowledged checkpoint", attempt)
						}
					}
					a.mu.Lock()
					if s.task.ReviewStatus == "queued" || s.task.reviewing || s.task.State == state || s.Supervision.State == "complete" {
						t.Errorf("undurable %s survived in memory: task=%s review=%s supervision=%s", state, s.task.State, s.task.ReviewStatus, s.Supervision.State)
					}
					a.mu.Unlock()
				}
				after, err := os.ReadFile(a.journal.Name())
				if err != nil || !bytes.Equal(before, after) {
					t.Fatal("closed journal unexpectedly changed", err)
				}
				// Even once the native turn finishes, an undurable review cannot dispatch.
				a.mu.Lock()
				s.scheduled = false
				s.Status = "idle"
				s.providerFinal = true
				a.mu.Unlock()
				var dispatches atomic.Int32
				a.resolvePolicy = func(string, string, string) (resolvedPolicy, error) {
					dispatches.Add(1)
					return resolvedPolicy{}, errors.New("review dispatch forbidden")
				}
				a.scheduleInputs(s.ID)
				a.mu.Lock()
				defer a.mu.Unlock()
				if dispatches.Load() != 0 || len(a.reviews) != 0 || s.task.reviewing || len(s.task.attempts) != 0 {
					t.Error("undurable checkpoint dispatched reviewer")
				}
			})
		}
	}
}

func TestCheckpointSyncFailureQuarantinesWrittenRecord(t *testing.T) {
	a, s, input := checkpointFixture(t)
	if err := a.journal.Close(); err != nil {
		t.Fatal(err)
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	a.journal = writer
	// A pipe accepts the record bytes but cannot fsync. This exercises a
	// post-write failure, distinct from the closed-journal pre-write control.
	if err = a.checkpointUpdate(s.ID, input); err == nil {
		t.Fatal("sync failure acknowledged")
	}
	if err = a.checkpointUpdate(s.ID, input); err == nil {
		t.Fatal("retry acknowledged uncertain write")
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	var record journalRecord
	if err = json.Unmarshal(bytes.TrimSpace(data), &record); err != nil {
		t.Fatalf("expected exactly one written record: %v", err)
	}
	if record.Checkpoint == nil || record.Checkpoint.ReviewStatus != "queued" {
		t.Fatal("did not reach write-before-sync failure")
	}
	if s.task.State != "unknown" || s.task.ReviewStatus != "unknown" || len(s.task.passes) != 0 {
		t.Fatal("uncertain checkpoint not quarantined")
	}
}

func TestCheckpointQuarantineRecheckedAfterCapture(t *testing.T) {
	a, s, input := checkpointFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	a.resolvePolicy = func(provider, profile, stage string) (resolvedPolicy, error) {
		close(entered)
		<-release
		return defaultPolicy(provider, profile, stage)
	}
	done := make(chan error, 1)
	go func() { done <- a.checkpointUpdate(s.ID, input) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("capture barrier not reached")
	}
	if err := a.journal.Close(); err != nil {
		t.Fatal(err)
	}
	other := input
	other.State = "active"
	if err := a.checkpointUpdate(s.ID, other); err == nil {
		t.Error("concurrent undurable active checkpoint accepted")
	}
	// Restore storage availability; the pending checkpoint still has no
	// authority to erase the uncertainty or append a replacement receipt.
	replacement, err := os.OpenFile(a.journal.Name(), os.O_RDWR|os.O_APPEND, 0600)
	if err != nil {
		t.Fatal(err)
	}
	a.journal = replacement
	close(release)
	select {
	case err = <-done:
		if err == nil {
			t.Error("pending checkpoint erased quarantine")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("checkpoint did not finish")
	}
	info, err := replacement.Stat()
	if err != nil || info.Size() != 0 {
		t.Fatal("pending checkpoint replayed after journal recovery", err)
	}
	if s.task.ReviewStatus != "unknown" {
		t.Fatal("capture overwrote quarantine")
	}
}

func TestCheckpointDurableDuplicateEntryPoints(t *testing.T) {
	for _, provider := range []string{"claude", "codex"} {
		t.Run(provider, func(t *testing.T) {
			a, s, input := claudeCheckpointFixture(t)
			s.Provider = provider
			c := &rpcClient{}
			s.codex = c
			s.turnID = "turn-A"
			s.codexTurn = &codexTurnBinding{client: c, requestID: s.lastRequest, turnID: s.turnID}
			binding := s.codexTurn
			data, _ := json.Marshal(input)
			call := func() {
				t.Helper()
				if provider == "claude" {
					r := httptest.NewRequest("POST", "/checkpoint", bytes.NewReader(data))
					r.Header.Set("Authorization", "Bearer "+s.task.capability)
					w := httptest.NewRecorder()
					a.checkpointHTTP(w, r)
					if w.Code != 200 || !strings.Contains(w.Body.String(), `"recorded":true`) {
						t.Fatalf("durable entry failed: %d %s", w.Code, w.Body.String())
					}
				} else if err := a.checkpointUpdateGuarded(s.ID, input, func(current *session) bool {
					return current.codexTurn == binding && boundCodexTurn(current, c, "turn-A")
				}); err != nil {
					t.Fatal(err)
				}
			}
			call()
			durable, err := os.ReadFile(a.journal.Name())
			if err != nil {
				t.Fatal(err)
			}
			var record journalRecord
			if err = json.Unmarshal(bytes.TrimSpace(durable), &record); err != nil || record.Checkpoint == nil || record.Checkpoint.ReviewStatus != "queued" {
				t.Fatal("missing durable review receipt", err)
			}
			call()
			after, err := os.ReadFile(a.journal.Name())
			if err != nil || !bytes.Equal(durable, after) {
				t.Fatal("duplicate wrote another receipt", err)
			}
			if s.task.ReviewStatus != "queued" || s.task.reviewing || len(a.reviews) != 0 {
				t.Fatal("durable duplicate changed review admission")
			}
		})
	}
}

func TestCheckpointFailedPassingReviewRevokesAuthority(t *testing.T) {
	for _, fail := range []bool{false, true} {
		name := "durable"
		if fail {
			name = "journal-refused"
		}
		t.Run(name, func(t *testing.T) {
			a, s, input := checkpointFixture(t)
			s.scheduled = true // Observe the review outcome before continuation.
			s.task.passes["plan_review"] = "prior-plan-pass"
			input.Stage = "final_review"
			if err := a.checkpointUpdate(s.ID, input); err != nil {
				t.Fatal(err)
			}
			a.runtime = func(string, string) (string, []string, error) { return "/synthetic/cli", nil, nil }
			policy, err := defaultPolicy("codex", "", "main")
			if err != nil {
				t.Fatal(err)
			}
			_, _, fingerprint, err := a.resolveRuntime(policy)
			if err != nil {
				t.Fatal(err)
			}
			client := &rpcClient{pending: map[string]chan rpcPacket{}, done: make(chan struct{})}
			t.Cleanup(func() { close(client.done) })
			client.input = replySink{reply: func(data []byte) {
				var packet rpcPacket
				_ = json.Unmarshal(data, &packet)
				result := json.RawMessage(`{"thread":{"id":"passing-review"}}`)
				if packet.Method == "turn/start" {
					// Both frames precede the reply and must be correlated through
					// the real binding path before runReviews can consume PASS.
					verdict, _ := json.Marshal(reviewVerdict{TaskID: s.task.ID, Generation: s.task.Generation, InputRevision: s.task.InputRevision, ObjectiveHash: s.task.ObjectiveHash, Stage: input.Stage, Digest: s.task.Subject.Digest, Verdict: "PASS", Findings: []string{}})
					frame, _ := json.Marshal(map[string]any{"threadId": "passing-review", "turnId": "review-turn", "item": map[string]any{"id": "verdict", "type": "agentMessage", "text": string(verdict)}})
					a.codexEvent(client, "item/completed", frame)
					a.codexEvent(client, "turn/completed", json.RawMessage(`{"threadId":"passing-review","turn":{"id":"review-turn","status":"completed"}}`))
					result = json.RawMessage(`{"turn":{"id":"review-turn"}}`)
				}
				client.mu.Lock()
				ch := client.pending[string(packet.ID)]
				client.mu.Unlock()
				if ch != nil {
					ch <- rpcPacket{ID: packet.ID, Result: result}
				}
			}}
			a.clients["codex::"+fingerprint] = client
			if fail {
				// Refuse only the parent's outcome record; reviewer native final
				// receipts remain writable, so this is not a reviewer failure.
				s.PolicyRevision = strings.Repeat("x", 60001)
			}
			epoch := s.controlEpoch
			a.runReviews(s)
			if len(a.reviews) != 1 || !a.reviews[0].providerFinal || s.task.attempts[attemptKey(s.task, input.Stage)] != 1 {
				t.Fatal("control did not reach a native final and parsed passing verdict")
			}
			if !fail {
				if s.task.passes["final_review"] != s.task.Subject.Digest || s.task.ReviewStatus != "passed" || s.pendingReviewResult == "" {
					t.Fatal("durable review control did not publish PASS")
				}
				return
			}
			if len(s.task.passes) != 0 || s.task.State != "unknown" || s.task.ReviewStatus != "unknown" || s.task.reviewing || s.pendingReviewResult != "" || s.controlEpoch <= epoch {
				t.Fatal("undurable passing review retained usable authority")
			}
			for _, message := range s.Messages {
				if message.Role == "review" {
					t.Error("undurable PASS was published")
				}
			}
			s.PolicyRevision = "" // Restored storage cannot authorize replay.
			input.State = "complete"
			if a.checkpointUpdate(s.ID, input) == nil {
				t.Fatal("undurable PASS authorized completion")
			}
		})
	}
}
