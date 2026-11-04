package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func disconnectState(t *testing.T, a *app, s *session) string {
	t.Helper()
	a.mu.Lock()
	defer a.mu.Unlock()
	turns := []string{}
	for _, child := range s.Agents {
		turns = append(turns, child.turnID)
	}
	data, err := json.Marshal([]any{s, s.Supervision.progress, s.controlEpoch, s.turnID, turns, len(s.filters), s.requests, s.providerFinal})
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestCodexDisconnectQuarantinesChildAuthority(t *testing.T) {
	for _, parentFinal := range []bool{false, true} {
		t.Run(map[bool]string{false: "accepted-parent", true: "final-parent"}[parentFinal], func(t *testing.T) {
			a, s, c := identityCodexFixture(t)
			writes := make(chan rpcPacket, 32)
			c.input = replySink{reply: func(data []byte) {
				var p rpcPacket
				_ = json.Unmarshal(data, &p)
				if p.Method == "turn/start" {
					identityReply(c, data, "turn-B")
				} else {
					writes <- p
				}
			}}
			if err := a.send(s.ID, "B", "bounded request", nil, false); err != nil {
				t.Fatal(err)
			}
			stamp := "2026-11-03T00:00:00Z"
			finished := agent{ID: "finished-child", ParentID: s.ProviderID, Provider: "codex", Status: "completed", LastSeen: &stamp, LastWrite: &stamp}
			a.mu.Lock()
			s.Supervision.State = "waiting"
			s.Agents = []agent{{ID: "running-child", ParentID: s.ProviderID, Provider: "codex", Status: "running", turnID: "child-turn", LastSeen: &stamp, LastWrite: &stamp, CanPause: true, CanStop: true, CanResume: true}, finished}
			a.mu.Unlock()
			if parentFinal {
				identityEvent(a, c, "turn/completed", "turn-B")
			}
			a.providerDisconnected(c, errors.New("controlled connection loss"))
			a.mu.Lock()
			child := s.Agents[0]
			if s.codex != nil || !s.Restored || child.Status != "unknown" || child.CanPause || child.CanStop || child.CanResume || !strings.Contains(child.ControlReason, "fresh owner") || !strings.Contains(child.ControlReason, "not automatic") {
				t.Error("disconnect retained client/child authority or omitted recovery reason")
			}
			if !reflect.DeepEqual(s.Agents[1], finished) {
				t.Error("disconnect changed finished child")
			}
			a.mu.Unlock()
			before := disconnectState(t, a, s)
			frames := []struct{ method, raw string }{
				{"thread/started", `{"thread":{"id":"late-child","source":{"parent_thread_id":"identity-thread"}}}`},
				{"thread/started", `{"thread":{"id":"late-grandchild","source":{"parent_thread_id":"running-child"}}}`},
				{"turn/started", `{"threadId":"running-child","turn":{"id":"late-turn"}}`},
				{"item/agentMessage/delta", `{"threadId":"running-child","itemId":"late-delta","delta":"late"}`},
				{"item/completed", `{"threadId":"running-child","item":{"id":"late-message","type":"agentMessage","text":"late"}}`},
				{"item/completed", `{"threadId":"running-child","item":{"id":"late-command","type":"commandExecution","command":"late"}}`},
				{"item/completed", `{"threadId":"running-child","item":{"id":"late-file","type":"fileChange"}}`},
				{"thread/tokenUsage/updated", `{"threadId":"running-child","tokenUsage":{"total":99}}`},
				{"error", `{"threadId":"running-child","error":{"message":"late error"}}`},
				{"turn/completed", `{"threadId":"running-child","turn":{"id":"child-turn","status":"completed"}}`},
				{"turn/started", `{"threadId":"finished-child","turn":{"id":"late-turn"}}`},
			}
			for _, frame := range frames {
				a.codexEvent(c, frame.method, json.RawMessage(frame.raw))
				if got := disconnectState(t, a, s); got != before {
					t.Errorf("late %s mutated quarantined state", frame.method)
				}
			}
			for _, method := range []string{"item/commandExecution/requestApproval", "item/fileChange/requestApproval", "item/tool/requestUserInput", "mcpServer/elicitation/request", "item/tool/call", "currentTime/read"} {
				a.codexQuestion(c, rpcPacket{ID: json.RawMessage(`90`), Method: method, Params: json.RawMessage(`{"threadId":"running-child","turnId":"child-turn"}`)})
			}
			for _, action := range []string{"pause", "stop", "resume"} {
				if err := a.controlAgent(s, "running-child", action); err == nil {
					t.Errorf("disconnected child accepted %s", action)
				}
			}
			identityEvent(a, c, "turn/completed", "turn-B")
			if got := disconnectState(t, a, s); got != before {
				t.Error("late question/control/final changed disconnected state")
			}
			select {
			case p := <-writes:
				t.Errorf("disconnected source wrote provider RPC: %s", p.Method)
			default:
			}
			wantFinals := 0
			if parentFinal {
				wantFinals = 1
			}
			assertIdentityFinalReceipts(t, a, "B", wantFinals)
		})
	}
}

func TestCodexDisconnectReviewerSyncAndControl(t *testing.T) {
	for _, final := range []bool{false, true} {
		t.Run(map[bool]string{false: "unfinished", true: "native-final-before-disconnect"}[final], func(t *testing.T) {
			a, parent, c := identityCodexFixture(t)
			c.input = replySink{reply: func(data []byte) {
				var p rpcPacket
				_ = json.Unmarshal(data, &p)
				c.mu.Lock()
				ch := c.pending[string(p.ID)]
				c.mu.Unlock()
				if ch != nil {
					ch <- rpcPacket{ID: p.ID, Result: json.RawMessage(`{"data":[{"id":"review-turn","status":"running"}]}`)}
				}
			}}
			review := emptySession("codex", parent.CWD, "")
			review.ProviderID, review.reviewParent = "review-child", parent.ID
			review.codex, review.Status = c, "running"
			review.lastRequest, review.turnID = "review-request", "review-turn"
			review.requests[review.lastRequest] = "accepted"
			review.codexTurn = &codexTurnBinding{client: c, requestID: review.lastRequest, turnID: review.turnID}
			review.reviewDone = make(chan struct{})
			a.reviews = append(a.reviews, review)
			// The parent is still live on a different connection.
			parent.codex = &rpcClient{}
			parent.Agents = []agent{{ID: review.ProviderID, Provider: "codex", Role: "reviewer", Status: "running", CanPause: true, CanStop: true}}
			if final {
				a.codexEvent(c, "turn/completed", json.RawMessage(`{"threadId":"review-child","turn":{"id":"review-turn","status":"completed"}}`))
				if !review.providerFinal || parent.Agents[0].CanStop {
					t.Fatal("native final did not close reviewer Stop")
				}
			}
			a.providerDisconnected(c, errors.New("review connection lost"))
			a.mu.Lock()
			a.syncReviewAgentLocked(review)
			child := parent.Agents[0]
			if child.CanPause || child.CanStop || child.CanResume || (!final && (child.Status != "unknown" || !strings.Contains(child.ControlReason, "fresh owner"))) {
				t.Error("review sync restored disconnected controls or lost quarantine reason")
			}
			if final && (!review.providerFinal || review.requests[review.lastRequest] != "final" || child.Status != "idle") {
				t.Error("disconnect erased durable review final")
			}
			a.mu.Unlock()
			before := disconnectState(t, a, parent)
			for _, action := range []string{"pause", "stop", "resume"} {
				if err := a.controlAgent(parent, review.ProviderID, action); err == nil {
					t.Errorf("disconnected review accepted %s", action)
				}
			}
			if got := disconnectState(t, a, parent); got != before {
				t.Error("disconnected review control mutated live parent")
			}
		})
	}
}

func TestCodexDisconnectRevokesQueuedControlWrite(t *testing.T) {
	a, s, c := identityCodexFixture(t)
	s.Agents = []agent{{ID: "child", Provider: "codex", Status: "running", CanStop: true}}
	entered, release := make(chan struct{}), make(chan struct{})
	writes := make(chan rpcPacket, 4)
	c.input = replySink{reply: func(data []byte) {
		var p rpcPacket
		_ = json.Unmarshal(data, &p)
		if p.Method == "fixture-barrier" {
			close(entered)
			<-release
			return
		}
		writes <- p
		c.mu.Lock()
		ch := c.pending[string(p.ID)]
		c.mu.Unlock()
		if ch != nil {
			ch <- rpcPacket{ID: p.ID, Result: json.RawMessage(`{"data":[{"id":"child-turn","status":"running"}]}`)}
		}
	}}
	blocked := make(chan error, 1)
	go func() { blocked <- c.write(map[string]any{"method": "fixture-barrier"}) }()
	<-entered
	control := make(chan error, 1)
	go func() { control <- a.controlAgent(s, "child", "stop") }()
	waitLifecycle(t, func() bool { return len(c.writer.queue) == 1 })
	a.providerDisconnected(c, errors.New("disconnect while control is queued"))
	before := disconnectState(t, a, s)
	close(release)
	if err := <-blocked; err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-control:
		if err == nil {
			t.Error("queued stale control succeeded")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("queued stale control did not terminate")
	}
	if got := disconnectState(t, a, s); got != before {
		t.Error("queued stale control changed quarantined child")
	}
	select {
	case p := <-writes:
		t.Errorf("queued control reached disconnected provider: %s", p.Method)
	default:
	}
}

func TestCodexDisconnectFreshSessionReplacesCachedClient(t *testing.T) {
	a := testApp(t)
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	audit := filepath.Join(t.TempDir(), "rpc.jsonl")
	a.runtime = func(string, string) (string, []string, error) {
		return binary, append(os.Environ(), "HARNESS_CONSOLE_RPC_FIXTURE=1", "HARNESS_CONSOLE_RPC_AUDIT="+audit), nil
	}
	old, err := a.createSession("codex", t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	client := old.codex
	old.Agents = []agent{{ID: "old-child", Provider: "codex", Status: "running", CanStop: true}}
	// Exercise the real close callback and the existing done-channel cache path.
	client.finish(errors.New("controlled fixture close"))
	fresh, err := a.createSession("codex", old.CWD, "")
	if err != nil {
		t.Fatal(err)
	}
	if fresh.codex == nil || fresh.codex == client || fresh.ProviderID == old.ProviderID || fresh.Status != "idle" || old.codex != nil || !old.Restored || old.Agents[0].Status != "unknown" {
		t.Fatal("fresh session failed to isolate old owner and replace closed cache entry")
	}
	// A round trip ensures the fixture has logged every preceding frame.
	if err := fresh.codex.call(context.Background(), "fixture-barrier", nil, nil); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(audit)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "thread/resume") || strings.Contains(string(data), "turn/start") || strings.Contains(string(data), "old-child") {
		t.Fatal("fresh session resumed/replayed old work or dispatched a replacement owner")
	}
}

func TestCodexDisconnectRejectsLateRefreshAndControlReplies(t *testing.T) {
	for _, method := range []string{"thread/list", "thread/turns/list", "turn/interrupt"} {
		t.Run(method, func(t *testing.T) {
			a, s, c := identityCodexFixture(t)
			s.Agents = []agent{{ID: "child", Provider: "codex", Status: "running", CanStop: true, CanPause: true}}
			var before string
			var calls []string
			c.input = replySink{reply: func(data []byte) {
				var p rpcPacket
				_ = json.Unmarshal(data, &p)
				calls = append(calls, p.Method)
				if p.Method == method {
					a.providerDisconnected(c, errors.New("disconnect before reply"))
					before = disconnectState(t, a, s)
				}
				c.mu.Lock()
				ch := c.pending[string(p.ID)]
				c.mu.Unlock()
				if ch != nil {
					result := json.RawMessage(`{"data":[{"id":"child-turn","status":"running"}]}`)
					if p.Method == "thread/list" {
						result = json.RawMessage(`{"data":[{"id":"child","status":{"type":"active"}},{"id":"late-child","status":{"type":"active"}}]}`)
					}
					ch <- rpcPacket{ID: p.ID, Result: result}
				}
			}}
			if method == "thread/list" {
				a.refreshAgents(s)
			} else if err := a.controlAgent(s, "child", "stop"); err == nil {
				t.Error("late control reply reported success")
			}
			if before == "" || disconnectState(t, a, s) != before {
				t.Error("late reply changed disconnected state or boundary not reached")
			}
			want := 1
			if method == "turn/interrupt" {
				want = 2
			}
			if len(calls) != want {
				t.Errorf("control sent follow-up after disconnect: %v", calls)
			}
		})
	}
}

func TestCodexDisconnectReviewWaiterKeepsControlsRevoked(t *testing.T) {
	a, parent, input := checkpointFixture(t)
	if err := a.checkpointUpdate(parent.ID, input); err != nil {
		t.Fatal(err)
	}
	parent.task.ReviewStatus = "running"
	a.runtime = func(string, string) (string, []string, error) { return "/synthetic/cli", nil, nil }
	policy, _ := defaultPolicy("codex", "", "main")
	_, _, fingerprint, err := a.resolveRuntime(policy)
	if err != nil {
		t.Fatal(err)
	}
	c := &rpcClient{pending: map[string]chan rpcPacket{}, done: make(chan struct{})}
	c.input = replySink{reply: func(data []byte) {
		var p rpcPacket
		_ = json.Unmarshal(data, &p)
		result := json.RawMessage(`{}`)
		if p.Method == "thread/start" {
			result = json.RawMessage(`{"thread":{"id":"review-child"}}`)
		}
		if p.Method == "turn/start" {
			result = json.RawMessage(`{"turn":{"id":"review-turn"}}`)
			a.providerDisconnected(c, errors.New("review disconnected before reply"))
		}
		c.mu.Lock()
		ch := c.pending[string(p.ID)]
		c.mu.Unlock()
		if ch != nil {
			ch <- rpcPacket{ID: p.ID, Result: result}
		}
	}}
	a.clients["codex::"+fingerprint] = c
	if _, err := a.runIndependentReview(parent, parent.task, policyStep{Provider: "codex"}); err == nil {
		t.Fatal("disconnected review passed")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(parent.Agents) != 1 {
		t.Fatal("missing review child")
	}
	child := parent.Agents[0]
	if child.Status != "unknown" || child.CanStop || child.CanPause || child.CanResume || !strings.Contains(child.ControlReason, "fresh owner") {
		t.Fatal("review waiter/cancellation re-enabled disconnected controls", child)
	}
}
