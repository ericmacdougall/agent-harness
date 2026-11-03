package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func identityCodexFixture(t *testing.T) (*app, *session, *rpcClient) {
	t.Helper()
	a := testApp(t)
	s := emptySession("codex", t.TempDir(), "")
	s.ProviderID = "identity-thread"
	s.Status = "idle"
	policy, _ := defaultPolicy("codex", "", "main")
	s.policy = policy
	a.resolvePolicy = func(string, string, string) (resolvedPolicy, error) { return policy, nil }
	a.runtime = func(string, string) (string, []string, error) { return "/fixture/codex", nil, nil }
	_, _, fingerprint, err := a.resolveRuntime(policy)
	if err != nil {
		t.Fatal(err)
	}
	c := &rpcClient{runtimeHash: fingerprint, pending: map[string]chan rpcPacket{}, done: make(chan struct{})}
	s.codex = c
	a.sessions = append(a.sessions, s)
	t.Cleanup(func() {
		if c.writer != nil {
			c.writer.close()
		}
	})
	return a, s, c
}
func identityEvent(a *app, c *rpcClient, method, turn string) {
	data, _ := json.Marshal(map[string]any{"threadId": "identity-thread", "turn": map[string]any{"id": turn, "status": "completed"}})
	a.codexEvent(c, method, data)
}
func identityReply(c *rpcClient, data []byte, turn string) {
	var packet rpcPacket
	_ = json.Unmarshal(data, &packet)
	c.mu.Lock()
	ch := c.pending[string(packet.ID)]
	c.mu.Unlock()
	result, _ := json.Marshal(map[string]any{"turn": map[string]any{"id": turn}})
	ch <- rpcPacket{ID: packet.ID, Result: result}
}
func TestIdentityCodexStaleStartedCompletedCannotFinalizeB(t *testing.T) {
	for _, early := range []bool{true, false} {
		name := "after-reply"
		if early {
			name = "before-reply"
		}
		t.Run(name, func(t *testing.T) {
			a, s, c := identityCodexFixture(t)
			s.requests["A"] = "final"
			var premature bool
			c.input = replySink{reply: func(data []byte) {
				if early {
					identityEvent(a, c, "turn/started", "turn-A")
					identityEvent(a, c, "turn/completed", "turn-A")
					a.mu.Lock()
					premature = s.providerFinal || s.requests["B"] == "final"
					a.mu.Unlock()
				}
				identityReply(c, data, "turn-B")
			}}
			if err := a.send(s.ID, "B", "bounded B", nil, false); err != nil {
				t.Fatal(err)
			}
			if !early {
				identityEvent(a, c, "turn/started", "turn-A")
				identityEvent(a, c, "turn/completed", "turn-A")
			}
			a.mu.Lock()
			if premature || s.requests["B"] != "accepted" || s.providerFinal || s.turnID != "turn-B" || s.Status != "running" {
				t.Errorf("stale A acquired B authority: premature=%v request=%s final=%v turn=%s status=%s", premature, s.requests["B"], s.providerFinal, s.turnID, s.Status)
			}
			a.mu.Unlock()
			assertIdentityFinalReceipts(t, a, "B", 0)
			a.scheduleInputs(s.ID)
			a.mu.Lock()
			if len(s.requestOrder) != 1 {
				t.Error("stale A advanced queue")
			}
			a.mu.Unlock()
			identityEvent(a, c, "turn/completed", "turn-B")
			a.mu.Lock()
			defer a.mu.Unlock()
			if s.requests["B"] != "final" || !s.providerFinal {
				t.Error("genuinely bound B did not finalize")
			}
			assertIdentityFinalReceipts(t, a, "B", 1)
		})
	}
}
func TestIdentityCodexEarlyCompletionNeedsReply(t *testing.T) {
	for _, mode := range []string{"success", "disconnect", "rejected", "empty"} {
		t.Run(mode, func(t *testing.T) {
			a, s, c := identityCodexFixture(t)
			var premature bool
			c.input = replySink{reply: func(data []byte) {
				identityEvent(a, c, "turn/started", "turn-B")
				identityEvent(a, c, "turn/completed", "turn-B")
				a.mu.Lock()
				premature = s.providerFinal || s.requests["B"] == "final"
				a.mu.Unlock()
				switch mode {
				case "disconnect":
					close(c.done)
				case "rejected":
					var packet rpcPacket
					_ = json.Unmarshal(data, &packet)
					c.mu.Lock()
					ch := c.pending[string(packet.ID)]
					c.mu.Unlock()
					ch <- rpcPacket{ID: packet.ID, Error: &rpcError{Message: "controlled rejection"}}
				case "empty":
					identityReply(c, data, "")
				default:
					identityReply(c, data, "turn-B")
				}
			}}
			err := a.send(s.ID, "B", "bounded B", nil, false)
			a.mu.Lock()
			defer a.mu.Unlock()
			if premature {
				t.Error("unbound early completion declared final before RPC reply")
			}
			if mode == "success" {
				if err != nil || s.requests["B"] != "final" || !s.providerFinal {
					t.Errorf("matched early completion lost: %v %s", err, s.requests["B"])
				}
			} else if err == nil || s.requests["B"] != "unknown" || s.providerFinal {
				t.Errorf("missing binding was not quarantined: err=%v state=%s final=%v", err, s.requests["B"], s.providerFinal)
			}
		})
	}
}
func waitIdentityState(t *testing.T, a *app, s *session, request, state string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		a.mu.Lock()
		got := s.requests[request]
		a.mu.Unlock()
		if got == state {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("request %s did not reach %s", request, state)
}
func TestIdentityClaudeDuplicateAAfterBAdmission(t *testing.T) {
	a := testApp(t)
	dir := t.TempDir()
	s := emptySession("claude", dir, "")
	s.ProviderID = "identity-conversation"
	s.policy, _ = defaultPolicy("claude", "", "main")
	a.sessions = append(a.sessions, s)
	binary, _ := os.Executable()
	gate := filepath.Join(dir, "finish-B")
	a.runtime = func(string, string) (string, []string, error) {
		return binary, append(os.Environ(), "HARNESS_CONSOLE_IDENTITY_FIXTURE=1", "HARNESS_CONSOLE_IDENTITY_GATE="+gate), nil
	}
	admit := func(id string) {
		a.mu.Lock()
		defer a.mu.Unlock()
		s.lastRequest = id
		s.requests[id] = "intent"
		s.requestOrder = append(s.requestOrder, id)
		s.Status = "running"
		s.Supervision.State = "active"
		s.providerFinal = false
		if err := a.record(s, id, "intent"); err != nil {
			t.Fatal(err)
		}
	}
	admit("A")
	if err := a.sendClaude(s, "A", "request-A", dir, ""); err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	oldRun := s.claude
	a.mu.Unlock()
	waitIdentityState(t, a, s, "A", "final")
	admit("B")
	if err := a.sendClaude(s, "B", "request-B", dir, ""); err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	s.task = &trackedTask{ID: "identity-task", Generation: 1, State: "active", passes: map[string]string{}, attempts: map[string]int{}}
	ensureTaskAuthority(s.task)
	a.mu.Unlock()
	queued, err := a.enqueueInput(s.ID, "C", "queued after B", nil)
	if err != nil {
		t.Fatal(err)
	}
	// Inject a duplicate on the original output source only after B is admitted.
	a.readClaude(s, oldRun, bytes.NewBufferString(`{"type":"result","result":"delayed A duplicate"}`+"\n"))
	a.scheduleInputs(s.ID)
	a.mu.Lock()
	if s.requests["B"] != "accepted" || s.providerFinal || s.Status != "running" || len(s.requestOrder) != 2 || queued.Status != "queued" || queued.DeliveredInputRevision != 0 {
		t.Errorf("duplicate A finalized/advanced B: state=%s final=%v status=%s requests=%v", s.requests["B"], s.providerFinal, s.Status, s.requestOrder)
	}
	newRun := s.claude
	if newRun == oldRun || oldRun.requestID != "A" || newRun == nil || newRun.requestID != "B" {
		t.Error("process request ownership was reused")
	}
	if newRun != nil && !strings.Contains(strings.Join(newRun.command.Args, " "), "--resume identity-conversation") {
		t.Error("B did not resume the same conversation")
	}
	a.mu.Unlock()
	assertIdentityFinalReceipts(t, a, "B", 0)
	if err := os.WriteFile(gate, []byte("finish"), 0600); err != nil {
		t.Fatal(err)
	}
	waitIdentityState(t, a, s, "B", "final")
	a.mu.Lock()
	defer a.mu.Unlock()
	if !s.providerFinal {
		t.Error("genuine B result was not final")
	}
	assertIdentityFinalReceipts(t, a, "B", 1)
	s.Supervision.State = "paused" // Leave C queued; this test dispatches only A and B.
}

func TestIdentityCodexUnknownCannotBeReopened(t *testing.T) {
	for _, mode := range []string{"timeout", "overflow", "unbound"} {
		t.Run(mode, func(t *testing.T) {
			a, s, c := identityCodexFixture(t)
			s.lastRequest = "B"
			s.requests["B"] = "intent"
			s.Status = "running"
			s.Supervision.State = "active"
			c.input = replySink{reply: func(data []byte) {
				count := 1
				if mode == "overflow" {
					count = 17
				}
				for i := 0; i < count; i++ {
					identityEvent(a, c, "turn/completed", fmt.Sprintf("turn-%d", i))
				}
				if mode != "timeout" {
					identityReply(c, data, "turn-0")
				}
			}}
			if mode == "unbound" {
				identityEvent(a, c, "turn/completed", "turn-0")
			} else {
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
				defer cancel()
				err := a.startCodexTurn(ctx, s, c, "B", map[string]any{"threadId": s.ProviderID}, a.turnAdmission(s, s.dispatchEpoch, "B"))
				if mode == "timeout" {
					if err == nil {
						t.Fatal("missing reply did not time out")
					}
					a.unknownSend(s, "B", err)
				}
			}
			a.unknownSend(s, "B", &providerRejectedError{Message: "late rejection"})
			a.rejectedSend(s, "B", refused("late refusal"))
			identityEvent(a, c, "turn/started", "turn-0")
			identityEvent(a, c, "turn/completed", "turn-0")
			a.mu.Lock()
			defer a.mu.Unlock()
			if s.requests["B"] != "unknown" || s.providerFinal || s.Status != "unknown" {
				t.Errorf("unknown was reopened: %s %s %v", s.requests["B"], s.Status, s.providerFinal)
			}
		})
	}
}

func TestIdentityCodexBoundFinalSurvivesLateErrors(t *testing.T) {
	a, s, c := identityCodexFixture(t)
	c.input = replySink{reply: func(data []byte) { identityReply(c, data, "turn-B") }}
	if err := a.send(s.ID, "B", "bounded B", nil, false); err != nil {
		t.Fatal(err)
	}
	identityEvent(a, c, "turn/completed", "turn-B")
	a.unknownSend(s, "B", errors.New("late transport error"))
	a.rejectedSend(s, "B", refused("late refusal"))
	identityEvent(a, c, "turn/started", "turn-A")
	identityEvent(a, c, "turn/completed", "turn-A")
	a.mu.Lock()
	defer a.mu.Unlock()
	if s.requests["B"] != "final" || !s.providerFinal || s.Status != "idle" {
		t.Error("genuinely bound final was downgraded")
	}
}

func assertIdentityFinalReceipts(t *testing.T, a *app, request string, want int) {
	t.Helper()
	a.journalMu.Lock()
	data, err := os.ReadFile(a.journal.Name())
	a.journalMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	got := 0
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte("\n")) {
		var receipt journalRecord
		if err := json.Unmarshal(line, &receipt); err != nil {
			t.Fatal(err)
		}
		if receipt.RequestID == request && receipt.State == "final" {
			got++
		}
	}
	if got != want {
		t.Errorf("request %s has %d durable finals; want %d", request, got, want)
	}
}
