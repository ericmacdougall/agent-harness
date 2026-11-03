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
