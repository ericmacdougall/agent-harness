package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func abandonFixture(t *testing.T, provider, state string) (*app, *session) {
	t.Helper()
	dir := t.TempDir()
	a, err := newApp(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.close)
	s := emptySession(provider, t.TempDir(), "")
	s.ID, s.ProviderID = "session-a", "provider-a"
	s.Status = "paused"
	s.lastRequest, s.requests["A"] = "A", state
	s.requestOrder = []string{"A"}
	a.sessions = append(a.sessions, s)
	if err = a.record(s, "A", state); err != nil {
		t.Fatal(err)
	}
	return a, s
}

func journalStates(t *testing.T, a *app) []journalRecord {
	t.Helper()
	file, err := os.Open(filepath.Join(a.dataDir, "sessions.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	records := []journalRecord{}
	scan := bufio.NewScanner(file)
	scan.Buffer(make([]byte, 4096), 65536)
	for scan.Scan() {
		var record journalRecord
		if err = json.Unmarshal(scan.Bytes(), &record); err != nil {
			t.Fatal(err)
		}
		records = append(records, record)
	}
	return records
}

func TestAbandonRecordsWithoutMintingAnOutcome(t *testing.T) {
	for _, provider := range []string{"codex", "claude"} {
		for _, state := range []string{"intent", "accepted", "unknown"} {
			t.Run(provider+"/"+state, func(t *testing.T) {
				a, s := abandonFixture(t, provider, state)
				s.task = &trackedTask{ID: "task", State: "active", passes: map[string]string{"plan_review": "kept-from-before"}, attempts: map[string]int{}}
				if err := a.abandonTurn(s.ID, "A", "  done waiting  "); err != nil {
					t.Fatal(err)
				}
				if s.requests["A"] != "abandoned" || s.Status != "abandoned" || !s.Restored || s.providerFinal {
					t.Fatalf("state: request=%q status=%q restored=%v final=%v", s.requests["A"], s.Status, s.Restored, s.providerFinal)
				}
				if s.task.State != "blocked" || s.task.ReviewStatus != "invalidated" || len(s.task.passes) != 1 || s.task.passes["plan_review"] != "kept-from-before" {
					t.Fatalf("task minted or lost a review outcome: %+v", s.task)
				}
				records := journalStates(t, a)
				if len(records) != 2 || records[0].State != state || records[1].State != "abandoned" {
					t.Fatalf("journal must keep the receipt and append one record: %+v", records)
				}
				last := records[1]
				if last.AbandonedRequest != "A" || last.AbandonReason != "done waiting" || last.At == "" {
					t.Fatalf("record lost identity, reason or time: %+v", last)
				}
				for _, record := range records {
					if record.State == "final" {
						t.Fatal("discard minted a final")
					}
				}
			})
		}
	}
}

func TestAbandonRefusals(t *testing.T) {
	cases := []struct {
		name, state, status, expected, reason, want string
	}{
		{"wrong turn", "accepted", "paused", "B", "reason", "turn changed"},
		{"running", "accepted", "running", "A", "reason", "stop or pause"},
		{"waiting", "accepted", "waiting", "A", "reason", "stop or pause"},
		{"final", "final", "idle", "A", "reason", "final outcome"},
		{"empty reason", "accepted", "paused", "A", "   ", "reason"},
		{"long reason", "accepted", "paused", "A", strings.Repeat("x", 501), "reason"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, s := abandonFixture(t, "codex", tc.state)
			s.Status = tc.status
			err := a.abandonTurn(s.ID, tc.expected, tc.reason)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
			if s.abandoned != nil || s.requests["A"] != tc.state || s.Status != tc.status || s.Restored {
				t.Fatalf("refusal mutated state: %+v", s.requests)
			}
			if len(journalStates(t, a)) != 1 {
				t.Fatal("refusal wrote a record")
			}
		})
	}
	a, s := abandonFixture(t, "codex", "accepted")
	s.queueUncertain = true
	if err := a.abandonTurn(s.ID, "A", "reason"); !errors.Is(err, errQueueDurability) {
		t.Fatalf("queue uncertainty: %v", err)
	}
}

func TestAbandonIsIdempotentUnderDoubleActivation(t *testing.T) {
	a, s := abandonFixture(t, "claude", "accepted")
	var group sync.WaitGroup
	errs := make([]error, 8)
	for i := range errs {
		group.Add(1)
		go func(i int) {
			defer group.Done()
			errs[i] = a.abandonTurn(s.ID, "A", "first or later")
		}(i)
	}
	group.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	first := s.abandoned.At
	if err := a.abandonTurn(s.ID, "A", "a different reason on a lost-response retry"); err != nil {
		t.Fatal(err)
	}
	if s.abandoned.Reason != "first or later" || s.abandoned.At != first {
		t.Fatalf("retry rewrote the decision: %+v", s.abandoned)
	}
	count := 0
	for _, record := range journalStates(t, a) {
		if record.State == "abandoned" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("%d abandoned records", count)
	}
	if err := a.abandonTurn(s.ID, "older-turn", "reason"); err == nil {
		t.Fatal("discard for another turn was treated as a retry")
	}
}

// A real final must survive: unknown status alone is not a turn to abandon.
func TestAbandonReleasingUnknownStatusKeepsRealFinal(t *testing.T) {
	a, s := abandonFixture(t, "claude", "final")
	s.Status = "unknown"
	dir := a.dataDir
	if err := a.abandonTurn(s.ID, "A", "stuck after a lifecycle failure"); err != nil {
		t.Fatal(err)
	}
	if s.requests["A"] != "final" {
		t.Fatalf("discard overwrote a native final: %q", s.requests["A"])
	}
	a.close()
	restored, err := newApp(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.close()
	current := restored.sessions[0]
	if current.requests["A"] != "final" || current.abandoned == nil {
		t.Fatalf("restart hid the final: %v abandoned=%v", current.requests, current.abandoned)
	}
}

func TestAbandonWithoutAnyRequest(t *testing.T) {
	a, s := abandonFixture(t, "claude", "unknown")
	s.lastRequest = ""
	delete(s.requests, "A")
	s.Status = "unknown"
	if err := a.abandonTurn(s.ID, "", "stuck tab"); err != nil {
		t.Fatal(err)
	}
	if err := a.closeSession(s.ID); err != nil {
		t.Fatalf("discarded tab could not close: %v", err)
	}
}

func startedCodexTurn(t *testing.T) (*app, *session, *rpcClient, *turnCalls) {
	t.Helper()
	a, s, c := identityCodexFixture(t)
	calls := &turnCalls{}
	c.input = replySink{reply: func(data []byte) {
		var p rpcPacket
		_ = json.Unmarshal(data, &p)
		switch p.Method {
		case "turn/start":
			identityReply(c, data, "turn-A")
		case "turn/interrupt":
			calls.mu.Lock()
			calls.interrupts = append(calls.interrupts, textField(object(p.Params), "turnId"))
			calls.mu.Unlock()
			c.mu.Lock()
			ch := c.pending[string(p.ID)]
			c.mu.Unlock()
			if ch != nil {
				ch <- rpcPacket{ID: p.ID, Result: json.RawMessage(`{}`)}
			}
		}
	}}
	if err := a.send(s.ID, "A", "text A", nil, false); err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	s.scheduled = true
	a.mu.Unlock()
	return a, s, c, calls
}

func waitInterrupt(t *testing.T, calls *turnCalls, want string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if targets, _ := calls.snapshot(); len(targets) > 0 {
			if targets[0] != want {
				t.Fatalf("interrupted %v", targets)
			}
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("best-effort interrupt was never sent")
}

func TestLateCodexEventsCannotChangeAbandonedTurn(t *testing.T) {
	a, s, c, calls := startedCodexTurn(t)
	if err := a.control(s.ID, "pause", ""); err != nil {
		t.Fatal(err)
	}
	waitInterrupt(t, calls, "turn-A")
	if err := a.abandonTurn(s.ID, "A", "done waiting"); err != nil {
		t.Fatal(err)
	}
	identityEvent(a, c, "turn/completed", "turn-A")
	params, _ := json.Marshal(map[string]any{"threadId": "identity-thread", "turnId": "turn-A"})
	a.codexQuestion(c, rpcPacket{ID: json.RawMessage(`9`), Method: "item/commandExecution/requestApproval", Params: params})
	a.mu.Lock()
	defer a.mu.Unlock()
	if s.requests["A"] != "abandoned" || s.Status != "abandoned" || s.providerFinal || len(s.PendingQuestions) != 0 {
		t.Fatalf("late frame changed abandoned turn: %q %q final=%v questions=%d", s.requests["A"], s.Status, s.providerFinal, len(s.PendingQuestions))
	}
}

func TestFinalBeforeDiscardWinsTheRace(t *testing.T) {
	a, s, c, _ := startedCodexTurn(t)
	identityEvent(a, c, "turn/completed", "turn-A")
	if err := a.abandonTurn(s.ID, "A", "too late"); err == nil {
		t.Fatal("discard overrode a final that arrived first")
	}
	if s.requests["A"] != "final" || s.abandoned != nil {
		t.Fatal("final was changed")
	}
}

func TestLateClaudeResultCannotFinishAbandonedTurn(t *testing.T) {
	a, s := abandonFixture(t, "claude", "accepted")
	s.claude = &claudeRun{input: &repairSink{}, done: make(chan struct{}), requestID: "A"}
	run := s.claude
	if err := a.abandonTurn(s.ID, "A", "done waiting"); err != nil {
		t.Fatal(err)
	}
	a.readClaude(s, run, bytes.NewBufferString(`{"type":"result","result":"late"}`+"\n"))
	if s.requests["A"] != "abandoned" || s.Status != "abandoned" {
		t.Fatalf("late result: %q %q", s.requests["A"], s.Status)
	}
	if s.claude != nil {
		t.Fatal("writer stayed attached")
	}
}

// Every other path that writes session state must leave the discarded tab alone.
func TestLaterPathsCannotReopenDiscardedTab(t *testing.T) {
	a, s, c, calls := startedCodexTurn(t)
	_ = c
	if err := a.control(s.ID, "pause", ""); err != nil {
		t.Fatal(err)
	}
	waitInterrupt(t, calls, "turn-A")
	if err := a.abandonTurn(s.ID, "A", "done"); err != nil {
		t.Fatal(err)
	}
	epoch := s.controlEpoch
	for _, action := range []string{"pause", "stop", "resume"} {
		if err := a.control(s.ID, action, ""); err == nil {
			t.Errorf("%s accepted on a discarded tab", action)
		}
	}
	if err := a.changeCWD(s.ID, t.TempDir()); err == nil {
		t.Error("cwd changed on a discarded tab")
	}
	if err := a.send(s.ID, "B", "more", nil, false); err == nil {
		t.Error("send accepted on a discarded tab")
	}
	a.rejectedSend(s, "A", errors.New("late rejection"))
	a.unknownSend(s, "A", errors.New("late unknown"))
	a.beginAuthenticationTransition("codex", "")
	a.finishAuthenticationTransition("codex", "", true)
	a.mu.Lock()
	a.quarantineQueueLocked(s)
	state := a.state
	a.mu.Unlock()
	if s.controlEpoch != epoch {
		t.Errorf("epoch moved: %d -> %d", epoch, s.controlEpoch)
	}
	if s.requests["A"] != "abandoned" {
		t.Errorf("receipt moved to %q", s.requests["A"])
	}
	view := state()["sessions"].([]map[string]any)[0]
	if view["status"] != "abandoned" || view["unresolved"] != false || view["canDiscard"] != false || view["canStop"] != false {
		t.Errorf("view reopened: %v %v %v %v", view["status"], view["unresolved"], view["canDiscard"], view["canStop"])
	}
	s.queueUncertain = false
	if err := a.closeSession(s.ID); err != nil {
		t.Errorf("stray status trapped the tab: %v", err)
	}
}

func TestPauseInFlightCannotOverwriteDiscard(t *testing.T) {
	a, s, c := identityCodexFixture(t)
	interrupted := make(chan json.RawMessage, 1)
	c.input = replySink{reply: func(data []byte) {
		var p rpcPacket
		_ = json.Unmarshal(data, &p)
		if p.Method == "turn/start" {
			identityReply(c, data, "turn-A")
		} else if p.Method == "turn/interrupt" {
			interrupted <- append(json.RawMessage(nil), p.ID...)
		}
	}}
	if err := a.send(s.ID, "A", "text A", nil, false); err != nil {
		t.Fatal(err)
	}
	s.scheduled = true
	paused := make(chan error, 1)
	go func() { paused <- a.control(s.ID, "pause", "") }()
	id := <-interrupted
	if err := a.abandonTurn(s.ID, "A", "done"); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	ch := c.pending[string(id)]
	c.mu.Unlock()
	ch <- rpcPacket{ID: id, Result: json.RawMessage(`{}`)}
	if err := <-paused; err != nil {
		t.Fatal(err)
	}
	if s.Status != "abandoned" {
		t.Fatalf("returning Pause overwrote discard with %q", s.Status)
	}
}

func TestDiscardDuringTurnStartStillInterruptsLateReply(t *testing.T) {
	a, s, c := identityCodexFixture(t)
	calls := &turnCalls{}
	started := make(chan json.RawMessage, 1)
	c.input = replySink{reply: func(data []byte) {
		var p rpcPacket
		_ = json.Unmarshal(data, &p)
		switch p.Method {
		case "turn/start":
			started <- append(json.RawMessage(nil), data...)
		case "turn/interrupt":
			calls.mu.Lock()
			calls.interrupts = append(calls.interrupts, textField(object(p.Params), "turnId"))
			calls.mu.Unlock()
			c.mu.Lock()
			ch := c.pending[string(p.ID)]
			c.mu.Unlock()
			if ch != nil {
				ch <- rpcPacket{ID: p.ID, Result: json.RawMessage(`{}`)}
			}
		}
	}}
	sent := make(chan error, 1)
	go func() { sent <- a.send(s.ID, "A", "text A", nil, false) }()
	raw := <-started
	if err := a.control(s.ID, "pause", ""); err != nil {
		t.Fatal(err)
	}
	if err := a.abandonTurn(s.ID, "A", "done"); err != nil {
		t.Fatal(err)
	}
	identityReply(c, raw, "turn-A")
	<-sent
	waitInterrupt(t, calls, "turn-A")
	if s.requests["A"] != "abandoned" {
		t.Fatalf("late reply moved receipt to %q", s.requests["A"])
	}
}

func TestDiscardWithRetainedAttachmentCanClearAndClose(t *testing.T) {
	a, s := abandonFixture(t, "claude", "accepted")
	s.task = &trackedTask{ID: "task", State: "active", Generation: 1, passes: map[string]string{}, attempts: map[string]int{}}
	entry := &queuedInput{RequestID: "A", Status: "dispatching", TaskID: "task", Generation: 1, Text: "payload", RetentionOnly: true}
	s.inputs = []*queuedInput{entry}
	s.delivery = &queuedDelivery{entry: entry, task: s.task, epoch: s.controlEpoch}
	if err := a.abandonTurn(s.ID, "A", "done"); err != nil {
		t.Fatal(err)
	}
	if entry.Status != "unknown" || s.delivery != nil {
		t.Fatalf("entry stuck: %q delivery=%v", entry.Status, s.delivery)
	}
	if err := a.closeSession(s.ID); err == nil {
		t.Fatal("retained payload was bypassed")
	}
	if err := a.discardInput(s.ID, "A", true); err != nil {
		t.Fatalf("no way to release the payload: %v", err)
	}
	if err := a.closeSession(s.ID); err != nil {
		t.Fatalf("tab stuck after releasing the payload: %v", err)
	}
}

func TestDiscardFailsClosedOnJournalWriteFailure(t *testing.T) {
	faults := map[string]func(a *app){
		"write": func(a *app) {
			a.journalWrite = func([]byte) (int, error) { return 0, errors.New("disk full") }
		},
		"partial": func(a *app) {
			a.journalWrite = func(line []byte) (int, error) {
				n, _ := a.journal.Write(line[:len(line)/2])
				return n, errors.New("disk full")
			}
		},
		"sync": func(a *app) {
			a.journalSync = func() error { return errors.New("sync failed") }
		},
	}
	for name, fault := range faults {
		t.Run(name, func(t *testing.T) {
			a, s, c, _ := startedCodexTurn(t)
			dir := a.dataDir
			fault(a)
			if err := a.abandonTurn(s.ID, "A", "done"); err == nil {
				t.Fatal("discard reported success without a durable record")
			}
			a.journalWrite, a.journalSync = nil, nil
			if s.abandoned != nil || s.Restored || s.requests["A"] != "accepted" || s.codex != c {
				t.Fatalf("failed discard changed the turn: abandoned=%v restored=%v request=%q", s.abandoned, s.Restored, s.requests["A"])
			}
			if err := a.closeSession(s.ID); err == nil {
				t.Fatal("tab closable after a failed discard")
			}
			// Nothing is wedged: a later native final still resolves it, and the
			// journal stays readable for the record that follows the failed one.
			identityEvent(a, c, "turn/completed", "turn-A")
			if s.requests["A"] != "final" {
				t.Fatalf("native final lost: %q", s.requests["A"])
			}
			a.close()
			restored, err := newApp(dir, nil)
			if err != nil {
				t.Fatalf("failed write made the journal unreadable: %v", err)
			}
			defer restored.close()
			if restored.sessions[0].requests["A"] != "final" || restored.sessions[0].abandoned != nil {
				t.Fatalf("restart: %v abandoned=%v", restored.sessions[0].requests, restored.sessions[0].abandoned)
			}
		})
	}
}

func TestDiscardRetryAfterWriteFailureSucceeds(t *testing.T) {
	a, s := abandonFixture(t, "claude", "accepted")
	a.journalWrite = func(line []byte) (int, error) {
		n, _ := a.journal.Write(line[:len(line)/2])
		return n, errors.New("disk full")
	}
	if err := a.abandonTurn(s.ID, "A", "first try"); err == nil {
		t.Fatal("no error")
	}
	a.journalWrite = nil
	if err := a.abandonTurn(s.ID, "A", "second try"); err != nil {
		t.Fatal(err)
	}
	dir := a.dataDir
	a.close()
	restored, err := newApp(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.close()
	if got := restored.sessions[0].abandoned; got == nil || got.Reason != "second try" {
		t.Fatalf("record lost: %+v", got)
	}
}

func TestJournalRefusesAppendsWhenRepairFails(t *testing.T) {
	a, s := abandonFixture(t, "claude", "accepted")
	a.journalBroken = true
	if err := a.abandonTurn(s.ID, "A", "done"); err == nil {
		t.Fatal("append after an unrepairable write")
	}
	if s.abandoned != nil {
		t.Fatal("discard applied without a record")
	}
}

func TestRestartAroundDiscard(t *testing.T) {
	t.Run("before durable record", func(t *testing.T) {
		a, s := abandonFixture(t, "claude", "accepted")
		dir := a.dataDir
		_ = s
		a.close()
		restored, err := newApp(dir, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer restored.close()
		current := restored.sessions[0]
		if current.Status != "unknown" || current.abandoned != nil || restored.closeSession(current.ID) == nil {
			t.Fatalf("status=%q", current.Status)
		}
		if err = restored.abandonTurn(current.ID, "A", "after restart"); err != nil {
			t.Fatalf("restored tab could not be discarded: %v", err)
		}
		if err = restored.closeSession(current.ID); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("torn record", func(t *testing.T) {
		a, s := abandonFixture(t, "claude", "accepted")
		dir := a.dataDir
		_ = s
		a.close()
		file, err := os.OpenFile(filepath.Join(dir, "sessions.jsonl"), os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		torn := `{"sessionId":"session-a","state":"abandoned","abando`
		if _, err = file.WriteString(torn); err != nil {
			t.Fatal(err)
		}
		file.Close()
		restored, err := newApp(dir, nil)
		if err != nil {
			t.Fatalf("crash during append refused startup: %v", err)
		}
		current := restored.sessions[0]
		if current.Status != "unknown" || current.abandoned != nil {
			t.Fatalf("torn record was believed: %q", current.Status)
		}
		// Appending after the tail must leave a readable journal.
		if err = restored.abandonTurn(current.ID, "A", "after crash"); err != nil {
			t.Fatal(err)
		}
		restored.close()
		matches, _ := filepath.Glob(filepath.Join(dir, "sessions.jsonl.torn-*"))
		if len(matches) != 1 {
			t.Fatalf("torn bytes not preserved: %v", matches)
		}
		kept, _ := os.ReadFile(matches[0])
		if string(kept) != torn {
			t.Fatalf("preserved %q", kept)
		}
		again, err := newApp(dir, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer again.close()
		if again.sessions[0].abandoned == nil {
			t.Fatal("record after the tail was lost")
		}
	})
	t.Run("interior corruption still refuses", func(t *testing.T) {
		a, _ := abandonFixture(t, "claude", "accepted")
		dir := a.dataDir
		a.close()
		file, err := os.OpenFile(filepath.Join(dir, "sessions.jsonl"), os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = file.WriteString("not-json\n")
		file.Close()
		if restored, err := newApp(dir, nil); err == nil {
			restored.close()
			t.Fatal("corrupt complete line accepted")
		}
	})
	t.Run("after durable record", func(t *testing.T) {
		a, s := abandonFixture(t, "codex", "accepted")
		s.task = &trackedTask{ID: "task", State: "active", Generation: 1, passes: map[string]string{}, attempts: map[string]int{}}
		dir := a.dataDir
		if err := a.abandonTurn(s.ID, "A", "done waiting"); err != nil {
			t.Fatal(err)
		}
		at := s.abandoned.At
		// A stale receipt written by a racing path must not reopen it.
		if err := a.record(s, "A", "unknown"); err != nil {
			t.Fatal(err)
		}
		a.close()
		restored, err := newApp(dir, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer restored.close()
		current := restored.sessions[0]
		if current.Status != "abandoned" || current.requests["A"] != "abandoned" || !current.Restored || current.abandoned == nil || current.abandoned.Reason != "done waiting" || current.abandoned.At != at {
			t.Fatalf("restored: status=%q requests=%v abandoned=%+v", current.Status, current.requests, current.abandoned)
		}
		if current.task == nil || current.task.State != "blocked" {
			t.Fatalf("record carried the pre-discard task: %+v", current.task)
		}
		if err = restored.abandonTurn(current.ID, "A", "retry after restart"); err != nil {
			t.Fatalf("idempotent retry refused after restart: %v", err)
		}
		if current.abandoned.Reason != "done waiting" {
			t.Fatal("retry rewrote the reason")
		}
		if err = restored.closeSession(current.ID); err != nil {
			t.Fatal(err)
		}
	})
}

func TestAbandonRoute(t *testing.T) {
	a, s := abandonFixture(t, "claude", "accepted")
	handler := a.handler("127.0.0.1:12345", "tok")
	post := func(token, origin, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "http://127.0.0.1:12345/api/sessions/"+s.ID+"/abandon", strings.NewReader(body))
		r.Header.Set("Origin", origin)
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	const body = `{"expectedRequestId":"A","reason":"done"}`
	if got := post("wrong", "http://127.0.0.1:12345", body); got.Code != 401 {
		t.Fatalf("token: %d", got.Code)
	}
	if got := post("tok", "http://evil.example", body); got.Code != 403 {
		t.Fatalf("origin: %d", got.Code)
	}
	if s.abandoned != nil {
		t.Fatal("unauthorized request applied")
	}
	if got := post("tok", "http://127.0.0.1:12345", `{"expectedRequestId":"A","reason":""}`); got.Code < 400 {
		t.Fatalf("empty reason: %d", got.Code)
	}
	if got := post("tok", "http://127.0.0.1:12345", body); got.Code != 200 {
		t.Fatalf("discard: %d %s", got.Code, got.Body.String())
	}
	if got := post("tok", "http://127.0.0.1:12345", body); got.Code != 200 {
		t.Fatalf("retry: %d", got.Code)
	}
}

func TestReceiptTransitionsAreMonotonic(t *testing.T) {
	a := testApp(t)
	s := emptySession("claude", t.TempDir(), "")
	for _, tc := range []struct {
		from, to string
		legal    bool
	}{
		{"", "intent", true}, {"intent", "accepted", true}, {"accepted", "final", true},
		{"accepted", "abandoned", true}, {"unknown", "abandoned", true}, {"intent", "unknown", true},
		{"final", "unknown", false}, {"final", "abandoned", false}, {"unknown", "final", false},
		{"abandoned", "final", false}, {"abandoned", "unknown", false}, {"rejected", "accepted", false},
		{"accepted", "intent", false}, {"", "final", false},
	} {
		s.requests["r"] = tc.from
		if tc.from == "" {
			delete(s.requests, "r")
		}
		got := a.transitionRequestLocked(s, "r", tc.to)
		if got != tc.legal {
			t.Errorf("%q -> %q: legal=%v", tc.from, tc.to, got)
		}
		if !tc.legal && s.requests["r"] != tc.from {
			t.Errorf("illegal %q -> %q wrote %q", tc.from, tc.to, s.requests["r"])
		}
	}
}
