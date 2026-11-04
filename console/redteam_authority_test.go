package main

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func postInput(a *app, sessionID, request string) *httptest.ResponseRecorder {
	handler := a.handler("127.0.0.1:12345", "tok")
	body := fmt.Sprintf(`{"requestId":%q,"text":"Important user follow-up","attachments":[]}`, request)
	r := httptest.NewRequest("POST", "http://127.0.0.1:12345/api/sessions/"+sessionID+"/inputs", strings.NewReader(body))
	r.Header.Set("Origin", "http://127.0.0.1:12345")
	r.Header.Set("Authorization", "Bearer tok")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

// The web client clears the draft on a 200, so a retry of an uncertain admission
// must stay uncertain or the only remaining copy of the message is discarded.
func TestUncertainAdmissionRetryIsNotAcknowledged(t *testing.T) {
	a, s := queueNativeFixture(t)
	a.writeInputs = func(string, []byte) error { return errSettingsDurability }
	first := postInput(a, s.ID, "q1")
	if first.Code != 503 {
		t.Fatalf("first admission: %d %s", first.Code, first.Body.String())
	}
	second := postInput(a, s.ID, "q1")
	if second.Code != 503 || strings.Contains(second.Body.String(), `"queued":true`) {
		t.Fatalf("retry acknowledged an uncertain admission: %d %s", second.Code, second.Body.String())
	}
}

// A lost response for a durable admission must keep working.
func TestDurableAdmissionRetryStaysQueryable(t *testing.T) {
	a, s := queueNativeFixture(t)
	first := postInput(a, s.ID, "q1")
	second := postInput(a, s.ID, "q1")
	if first.Code != 200 || second.Code != 200 || !strings.Contains(second.Body.String(), `"queued":true`) {
		t.Fatalf("durable retry: first=%d second=%d %s", first.Code, second.Code, second.Body.String())
	}
}

// The advertised recovery is a restart, so an uncertain dispatch commit must not
// journal a revision the queue file may not have reached.
func TestUncertainDispatchCommitStillRestarts(t *testing.T) {
	a, s := queueNativeFixture(t)
	if _, err := a.enqueueInput(s.ID, "d1", "Revised objective", nil); err != nil {
		t.Fatal(err)
	}
	finishNativeQueueTurn(a, s)
	a.mu.Lock()
	before := s.task.InputRevision
	a.mu.Unlock()
	a.writeInputs = func(string, []byte) error { return errSettingsDurability }
	a.scheduleInputs(s.ID)
	a.mu.Lock()
	uncertain, after := s.queueUncertain, s.task.InputRevision
	a.mu.Unlock()
	if !uncertain || after != before+1 {
		t.Fatalf("fault did not reach the uncertain commit path: uncertain=%v %d -> %d", uncertain, before, after)
	}
	dir := a.dataDir
	a.close()
	restored, err := newApp(dir, nil)
	if err != nil {
		t.Fatalf("restart refused: %v", err)
	}
	defer restored.close()
	if len(restored.sessions) != 1 || restored.sessions[0].Status != "unknown" {
		t.Fatalf("restored unresolved dispatch: %d sessions", len(restored.sessions))
	}
	if queueEntry(restored.sessions[0], "d1") == nil {
		t.Fatal("restart lost the retained input")
	}
	task := restored.sessions[0].task
	if task.InputRevision != before || len(task.passes) != 0 {
		t.Fatalf("restart kept unconfirmed authority: revision=%d want %d passes=%v", task.InputRevision, before, task.passes)
	}
}

// Tolerating the uncertain commit must not excuse a journal ahead of the queue
// file for a session that has a resolved outcome.
func TestJournalAheadOfQueueStillRefusedWhenResolved(t *testing.T) {
	a, s := queueNativeFixture(t)
	if _, err := a.enqueueInput(s.ID, "d1", "Revised objective", nil); err != nil {
		t.Fatal(err)
	}
	finishNativeQueueTurn(a, s)
	a.writeInputs = func(string, []byte) error { return errSettingsDurability }
	a.scheduleInputs(s.ID)
	a.mu.Lock()
	if !s.queueUncertain {
		a.mu.Unlock()
		t.Fatal("fault did not reach the uncertain commit path")
	}
	if err := a.record(s, "d1", "final"); err != nil {
		a.mu.Unlock()
		t.Fatal(err)
	}
	a.mu.Unlock()
	dir := a.dataDir
	a.close()
	restored, err := newApp(dir, nil)
	if err == nil {
		restored.close()
		t.Fatal("journal ahead of the queue file was accepted for a resolved session")
	}
}

type turnCalls struct {
	mu         sync.Mutex
	interrupts []string
	listed     int
}

func (c *turnCalls) snapshot() ([]string, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string{}, c.interrupts...), c.listed
}

// While turn/start is unanswered the newest listed turn is not ours; interrupting
// it reports a successful Pause and leaves the admitted turn running.
func TestPauseDuringTurnStartInterruptsTheBoundTurn(t *testing.T) {
	a, s, c := identityCodexFixture(t)
	calls := &turnCalls{}
	started := make(chan json.RawMessage, 1)
	c.input = replySink{reply: func(data []byte) {
		var p rpcPacket
		_ = json.Unmarshal(data, &p)
		reply := func(result string) {
			c.mu.Lock()
			ch := c.pending[string(p.ID)]
			c.mu.Unlock()
			if ch != nil {
				ch <- rpcPacket{ID: p.ID, Result: json.RawMessage(result)}
			}
		}
		switch p.Method {
		case "turn/start":
			started <- append(json.RawMessage(nil), data...)
		case "thread/turns/list":
			calls.mu.Lock()
			calls.listed++
			calls.mu.Unlock()
			reply(`{"data":[{"id":"turn-previous","status":"completed"}]}`)
		case "turn/interrupt":
			calls.mu.Lock()
			calls.interrupts = append(calls.interrupts, textField(object(p.Params), "turnId"))
			calls.mu.Unlock()
			reply(`{}`)
		}
	}}
	sent := make(chan error, 1)
	go func() { sent <- a.send(s.ID, "A", "text A", nil, false) }()
	raw := <-started
	if err := a.control(s.ID, "pause", ""); err != nil {
		t.Fatal(err)
	}
	if targets, listed := calls.snapshot(); len(targets) != 0 || listed != 0 {
		t.Fatalf("Pause guessed a turn before the binding existed: targets=%v listed=%d", targets, listed)
	}
	identityReply(c, raw, "turn-A")
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if targets, _ := calls.snapshot(); len(targets) > 0 {
			if len(targets) != 1 || targets[0] != "turn-A" {
				t.Fatalf("interrupted %v", targets)
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("admitted turn was never interrupted")
}

// A failed deferred interrupt must be visible, or Pause looks confirmed.
func TestDeferredInterruptFailureIsVisible(t *testing.T) {
	a, s, c := identityCodexFixture(t)
	started := make(chan json.RawMessage, 1)
	c.input = replySink{reply: func(data []byte) {
		var p rpcPacket
		_ = json.Unmarshal(data, &p)
		switch p.Method {
		case "turn/start":
			started <- append(json.RawMessage(nil), data...)
		case "turn/interrupt":
			c.mu.Lock()
			ch := c.pending[string(p.ID)]
			c.mu.Unlock()
			if ch != nil {
				ch <- rpcPacket{ID: p.ID, Error: &rpcError{Message: "interrupt rejected"}}
			}
		}
	}}
	sent := make(chan error, 1)
	go func() { sent <- a.send(s.ID, "A", "text A", nil, false) }()
	raw := <-started
	if err := a.control(s.ID, "pause", ""); err != nil {
		t.Fatal(err)
	}
	identityReply(c, raw, "turn-A")
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		a.mu.Lock()
		message := s.Error
		a.mu.Unlock()
		if strings.Contains(message, "Pause could not be confirmed") {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("failed deferred interrupt left no visible error")
}

func TestStateExposesStopForUnresolvedConnectedTurn(t *testing.T) {
	cases := []struct {
		name, request string
		connected     bool
		restored      bool
		want          bool
	}{
		{"accepted-connected", "accepted", true, false, true},
		{"unknown-connected", "unknown", true, false, true},
		{"final-connected", "final", true, false, false},
		{"accepted-disconnected", "accepted", false, false, false},
		{"unknown-restored", "unknown", true, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, s, c := identityCodexFixture(t)
			s.Status = "paused"
			s.lastRequest, s.requests["A"] = "A", tc.request
			s.Restored = tc.restored
			s.codex = nil
			if tc.connected {
				s.codex = c
			}
			state := a.state()
			sessions := state["sessions"].([]map[string]any)
			got, _ := sessions[0]["canStop"].(bool)
			if got != tc.want {
				t.Fatalf("canStop=%v want %v", got, tc.want)
			}
		})
	}
}

// Unresolved tabs cannot be closed, so restart must not let them consume the
// whole limit and refuse all new work.
func TestRestoredUnresolvedSessionsDoNotExhaustTheLimit(t *testing.T) {
	dir := t.TempDir()
	a, err := newApp(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxSessions; i++ {
		s := emptySession("claude", dir, "")
		s.ProviderID = fmt.Sprintf("provider-%d", i)
		if err = a.record(s, "r", "unknown"); err != nil {
			t.Fatal(err)
		}
	}
	a.close()
	restored, err := newApp(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.close()
	if len(restored.sessions) != maxSessions {
		t.Fatalf("restored %d", len(restored.sessions))
	}
	restored.runtime = func(string, string) (string, []string, error) { return "/bin/true", nil, nil }
	if _, err = restored.createSession("claude", dir, ""); err != nil {
		t.Fatalf("read-only restored tabs exhausted the limit: %v", err)
	}
	// Live sessions must still hit the limit.
	for i := 1; i < maxSessions; i++ {
		if _, err = restored.createSession("claude", dir, ""); err != nil {
			t.Fatalf("live session %d refused early: %v", i, err)
		}
	}
	if _, err = restored.createSession("claude", dir, ""); err == nil {
		t.Fatal("live session limit no longer enforced")
	}
}
