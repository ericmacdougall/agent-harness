package main

import (
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestCodexPausePreservesUnresolvedRequest(t *testing.T) {
	for _, outcome := range []string{"accepted", "unknown"} {
		for _, interrupt := range []string{"rejected", "unconfirmed"} {
			t.Run(outcome+"/"+interrupt, func(t *testing.T) {
				a, s, c := identityCodexFixture(t)
				var starts atomic.Int32
				c.input = replySink{reply: func(data []byte) {
					var p rpcPacket
					_ = json.Unmarshal(data, &p)
					if p.Method == "turn/start" {
						starts.Add(1)
						identityReply(c, data, "turn-A")
						return
					}
					c.mu.Lock()
					ch := c.pending[string(p.ID)]
					c.mu.Unlock()
					reply := rpcPacket{ID: p.ID, Result: json.RawMessage(`{}`)}
					if interrupt == "rejected" {
						reply.Error = &rpcError{Message: "interrupt rejected"}
					}
					ch <- reply
				}}
				if err := a.send(s.ID, "A", "text-only A", nil, false); err != nil {
					t.Fatal(err)
				}
				a.mu.Lock()
				task, binding := s.task, s.codexTurn
				task.State = "blocked"
				s.scheduled = true
				a.mu.Unlock()
				if outcome == "unknown" {
					a.unknownSend(s, "A", errors.New("unconfirmed request"))
				}
				err := a.control(s.ID, "pause", "")
				if (err != nil) != (interrupt == "rejected") {
					t.Fatalf("interrupt: %v", err)
				}
				a.mu.Lock()
				if outcome == "unknown" && s.Status != "unknown" {
					t.Errorf("Pause masked unknown status: %s", s.Status)
				}
				a.mu.Unlock()
				if err := a.send(s.ID, "B", "replacement B", nil, false); err == nil {
					t.Error("fresh B accepted before A native final")
				}
				a.mu.Lock()
				if s.task != task || s.codexTurn != binding || s.lastRequest != "A" || s.requests["A"] != outcome || s.requests["B"] != "" || starts.Load() != 1 {
					t.Error("unresolved A binding/task replaced or turn/start reached")
				}
				a.mu.Unlock()
				if outcome == "accepted" {
					identityEvent(a, c, "turn/completed", "turn-A")
					a.mu.Lock()
					if s.requests["A"] != "final" || !s.providerFinal {
						t.Error("later exact native final lost")
					}
					a.mu.Unlock()
					if err := a.send(s.ID, "C", "fresh after verified final", nil, false); err != nil {
						t.Errorf("verified final prevented normal fresh turn: %v", err)
					}
				}
			})
		}
	}
}

func TestSendRechecksUnresolvedRequestAfterPolicy(t *testing.T) {
	for _, provider := range []string{"codex", "claude"} {
		for _, outcome := range []string{"intent", "accepted", "unknown"} {
			t.Run(provider+"/"+outcome, func(t *testing.T) {
				a, s, c := identityCodexFixture(t)
				s.Provider = provider
				s.task = &trackedTask{ID: "prior-task", State: "blocked"}
				task := s.task
				s.lastRequest, s.requests["A"] = "A", "final"
				binding := &codexTurnBinding{client: c, requestID: "A", turnID: "turn-A"}
				s.codexTurn = binding
				entered, release := make(chan struct{}), make(chan struct{})
				a.resolvePolicy = func(string, string, string) (resolvedPolicy, error) {
					close(entered)
					<-release
					policy, _ := defaultPolicy(provider, "", "main")
					return policy, nil
				}
				var starts atomic.Int32
				c.input = replySink{reply: func(data []byte) { starts.Add(1); identityReply(c, data, "turn-B") }}
				done := make(chan error, 1)
				go func() { done <- a.send(s.ID, "B", "replacement B", nil, false) }()
				select {
				case <-entered:
				case <-time.After(5 * time.Second):
					t.Fatal("policy barrier not reached")
				}
				a.mu.Lock()
				// A control/status update alone cannot confer finality. Do not change
				// epoch here: this specifically tests the second receipt admission guard.
				s.requests["A"], s.Status = outcome, "paused"
				a.mu.Unlock()
				close(release)
				select {
				case err := <-done:
					if err == nil {
						t.Error("unresolved request passed policy recheck")
					}
				case <-time.After(5 * time.Second):
					t.Fatal("send did not finish")
				}
				a.mu.Lock()
				defer a.mu.Unlock()
				if starts.Load() != 0 || s.task != task || s.codexTurn != binding || s.lastRequest != "A" || s.requests["B"] != "" {
					t.Error("policy TOCTOU replaced A or reached provider")
				}
			})
		}
	}
}
