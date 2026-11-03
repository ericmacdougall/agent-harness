package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// startUnresolvedCodexRequest leaves request A accepted with a rejected interrupt available.
func startUnresolvedCodexRequest(t *testing.T) (*app, *session, *rpcClient) {
	t.Helper()
	a, s, c := identityCodexFixture(t)
	c.input = replySink{reply: func(data []byte) {
		var p rpcPacket
		_ = json.Unmarshal(data, &p)
		if p.Method == "turn/start" {
			identityReply(c, data, "turn-A")
			return
		}
		c.mu.Lock()
		ch := c.pending[string(p.ID)]
		c.mu.Unlock()
		if ch != nil {
			ch <- rpcPacket{ID: p.ID, Error: &rpcError{Message: "interrupt rejected"}}
		}
	}}
	if err := a.send(s.ID, "A", "text-only A", nil, false); err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	s.task.State = "blocked"
	s.scheduled = true
	a.mu.Unlock()
	return a, s, c
}

func TestCloseRefusesCodexRequestAfterFailedInterrupt(t *testing.T) {
	a, s, c := startUnresolvedCodexRequest(t)
	if err := a.control(s.ID, "pause", ""); err == nil {
		t.Fatal("rejected interrupt reported success")
	}
	if err := a.closeSession(s.ID); err == nil {
		t.Fatal("tab closed while the provider turn was unconfirmed; its receipt would be dropped on restart")
	}
	if a.findLocked(s.ID) == nil {
		t.Fatal("session removed despite refusal")
	}
	// The refusal must lift once native finality is observed.
	identityEvent(a, c, "turn/completed", "turn-A")
	if err := a.closeSession(s.ID); err != nil {
		t.Fatalf("verified final still blocks tab closure: %v", err)
	}
}

func TestCloseRefusesEveryUnresolvedReceiptForBothProviders(t *testing.T) {
	for _, provider := range []string{"codex", "claude"} {
		for _, state := range []string{"intent", "accepted", "unknown", "final", "rejected"} {
			t.Run(provider+"/"+state, func(t *testing.T) {
				a := testApp(t)
				s := emptySession(provider, t.TempDir(), "")
				s.ProviderID = "provider"
				s.Status = "paused"
				s.lastRequest, s.requests["A"] = "A", state
				a.sessions = append(a.sessions, s)
				err := a.closeSession(s.ID)
				if resolved := state == "final" || state == "rejected"; resolved != (err == nil) {
					t.Fatalf("state %s: close err=%v", state, err)
				}
			})
		}
	}
}

func TestChangeCWDRefusesUnresolvedRequest(t *testing.T) {
	for _, state := range []string{"intent", "accepted", "unknown"} {
		t.Run(state, func(t *testing.T) {
			a := testApp(t)
			original := t.TempDir()
			s := emptySession("codex", original, "")
			s.ProviderID = "provider"
			s.Status = "paused"
			s.lastRequest, s.requests["A"] = "A", state
			a.sessions = append(a.sessions, s)
			if err := a.changeCWD(s.ID, t.TempDir()); err == nil {
				t.Fatal("cwd changed while the request outcome was unresolved")
			}
			if s.CWD != original {
				t.Fatal("cwd mutated despite refusal")
			}
		})
	}
	a := testApp(t)
	s := emptySession("codex", t.TempDir(), "")
	s.ProviderID = "provider"
	s.Status = "paused"
	s.lastRequest, s.requests["A"] = "A", "final"
	a.sessions = append(a.sessions, s)
	if err := a.changeCWD(s.ID, t.TempDir()); err != nil {
		t.Fatalf("resolved request still blocks cwd change: %v", err)
	}
}

// Restart truth comes from request receipts; bookkeeping records may follow them.
func TestRestoreNonReceiptRecordCannotHideUnresolvedRequest(t *testing.T) {
	cases := []struct {
		receipt, trailing, want string
	}{
		{"intent", "cwd", "unknown"},
		{"accepted", "cwd", "unknown"},
		{"unknown", "cwd", "unknown"},
		{"accepted", "admission_failed", "unknown"},
		{"final", "cwd", "disconnected"},
		{"rejected", "cwd", "disconnected"},
		{"accepted", "", "unknown"},
		{"final", "", "disconnected"},
	}
	for _, tc := range cases {
		t.Run(tc.receipt+"/"+tc.trailing, func(t *testing.T) {
			dir := t.TempDir()
			a, err := newApp(dir, nil)
			if err != nil {
				t.Fatal(err)
			}
			s := emptySession("codex", dir, "")
			s.ProviderID = "provider"
			if err = a.record(s, "A", tc.receipt); err != nil {
				t.Fatal(err)
			}
			if tc.trailing != "" {
				if err = a.record(s, "", tc.trailing); err != nil {
					t.Fatal(err)
				}
			}
			a.close()
			restored, err := newApp(dir, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer restored.close()
			if len(restored.sessions) != 1 {
				t.Fatalf("restored %d sessions", len(restored.sessions))
			}
			if got := restored.sessions[0].Status; got != tc.want {
				t.Fatalf("restored status %q, want %q", got, tc.want)
			}
		})
	}
	dir := t.TempDir()
	a, err := newApp(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := emptySession("codex", dir, "")
	s.ProviderID = "provider"
	_ = a.record(s, "A", "final")
	_ = a.record(s, "", "closed")
	a.close()
	restored, err := newApp(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.close()
	if len(restored.sessions) != 0 {
		t.Fatal("closed session reappeared")
	}
}

// waitForPendingWriter spins until a writer is queued on the generation lock,
// which is the exact condition that makes new readers block.
func waitForPendingWriter(t *testing.T, a *app) {
	t.Helper()
	value, _ := authGenerations.Load(a)
	state := value.(*authGenerationState)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if !state.mu.TryRLock() {
			return
		}
		state.mu.RUnlock()
		time.Sleep(time.Millisecond)
	}
	t.Fatal("generation writer was never pending")
}

// A login on profile B queues a writer behind an admitted profile A write. The
// global RWMutex then blocks every new reader, so publication may not wait for
// it while holding a.mu: the admitted write needs a.mu to finish.
func TestPublicationDoesNotInvertAuthLockAcrossProfiles(t *testing.T) {
	publishers := map[string]func(a *app, s *session) error{
		"claude": func(a *app, s *session) error {
			run := &claudeRun{input: &closeTrackingSink{}, done: make(chan struct{})}
			return a.attachStartedClaudeRun(s, run, "profile-a", 0, "task", 1)
		},
		"codex": func(a *app, s *session) error {
			client := &rpcClient{input: &closeTrackingSink{}, done: make(chan struct{}), pending: map[string]chan rpcPacket{}}
			_, err := a.publishCodexClient("codex:profile-a:key", "profile-a", 0, nil, client)
			return err
		},
	}
	for provider, publish := range publishers {
		t.Run(provider, func(t *testing.T) {
			a, err := newApp(t.TempDir(), nil)
			if err != nil {
				t.Fatal(err)
			}
			s := emptySession(provider, t.TempDir(), "profile-a")
			a.sessions = append(a.sessions, s)
			// T1: admitted profile A write, about to need a.mu.
			release, err := a.authAdmission(provider, "profile-a", 0)()
			if err != nil {
				t.Fatal(err)
			}
			proceed := make(chan struct{})
			finished := make(chan string, 3)
			go func() {
				<-proceed
				a.mu.Lock()
				a.mu.Unlock()
				release()
				finished <- "writer"
			}()
			// T3: login on an unrelated profile queues the generation writer.
			go func() {
				a.setAuthTransition(provider, "profile-b", false)
				finished <- "login"
			}()
			waitForPendingWriter(t, a)
			// T2: publication on profile A.
			go func() {
				if err := publish(a, s); err != nil {
					t.Errorf("publication refused: %v", err)
				}
				finished <- "publication"
			}()
			time.Sleep(100 * time.Millisecond) // Let publication reach its blocking point.
			close(proceed)
			for i := 0; i < 3; i++ {
				select {
				case <-finished:
				case <-time.After(3 * time.Second):
					// Deliberately no a.close: it would join the deadlock.
					t.Fatal("console deadlocked across profiles")
				}
			}
			a.close()
		})
	}
}

// Replying to an unsupported control request must not hold a.mu across a write
// that itself waits for auth admission.
func TestClaudeUnsupportedControlReplyDoesNotHoldAppLock(t *testing.T) {
	a := testApp(t)
	s := emptySession("claude", t.TempDir(), "")
	s.ProviderID = "provider"
	s.Status = "running"
	s.lastRequest, s.requests["A"] = "A", "accepted"
	blocked := make(chan struct{})
	entered := make(chan struct{}, 1)
	run := &claudeRun{input: &repairSink{}, done: make(chan struct{}), requestID: "A", authAdmit: func() (func(), error) {
		entered <- struct{}{}
		<-blocked
		return func() {}, nil
	}}
	defer close(blocked)
	s.claude = run
	a.sessions = append(a.sessions, s)
	frame := `{"type":"control_request","request_id":"r1","request":{"subtype":"unsupported"}}` + "\n"
	done := make(chan struct{})
	go func() {
		a.readClaude(s, run, bytes.NewBufferString(frame))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("reader held a.mu across a provider write waiting on auth admission")
	}
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("control reply was never attempted")
	}
}

func claudeConversationFixture(t *testing.T, live bool) (*app, *session, *[]string) {
	t.Helper()
	a := testApp(t)
	s := emptySession("claude", t.TempDir(), "")
	s.ProviderID = "claude-conversation"
	s.Status = "idle"
	s.claudeStarted = true
	s.providerFinal = true
	s.lastRequest, s.requests["A"] = "A", "final"
	policy, _ := defaultPolicy("claude", "", "main")
	s.policy = policy
	a.resolvePolicy = func(string, string, string) (resolvedPolicy, error) { return policy, nil }
	home := t.TempDir()
	env := []string{"HOME=" + home, "ANTHROPIC_API_KEY=original-credential-value"}
	a.runtime = func(string, string) (string, []string, error) { return "/fixture/claude-absent", env, nil }
	_, _, fingerprint, err := a.resolveRuntime(policy)
	if err != nil {
		t.Fatal(err)
	}
	s.conversationRuntimeHash = fingerprint
	if live {
		done := make(chan struct{})
		close(done)
		s.claude = &claudeRun{input: &closeTrackingSink{}, done: done, requestID: "A", cwd: s.CWD, runtimeHash: fingerprint, policy: policy}
	}
	a.sessions = append(a.sessions, s)
	return a, s, &env
}

func TestClaudeRefusesResumeAcrossCredentialChange(t *testing.T) {
	for _, live := range []bool{true, false} {
		for _, automatic := range []bool{false, true} {
			t.Run(map[bool]string{true: "live", false: "retired"}[live]+"/"+map[bool]string{true: "automatic", false: "manual"}[automatic], func(t *testing.T) {
				a, s, env := claudeConversationFixture(t, live)
				home := (*env)[0]
				bindings := []sendBinding{}
				if automatic {
					s.task = &trackedTask{ID: "task", State: "active", Generation: 1, passes: map[string]string{}, attempts: map[string]int{}}
					s.Supervision.State = "active"
					bindings = append(bindings, sendBinding{taskID: "task", epoch: s.controlEpoch})
				}
				*env = []string{home, "ANTHROPIC_API_KEY=replacement-credential-value"}
				err := a.send(s.ID, "B", "continue", nil, automatic, bindings...)
				if err == nil || !strings.Contains(err.Error(), "credentials or tools changed") {
					t.Fatalf("Claude conversation crossed a credential change: %v", err)
				}
				a.mu.Lock()
				defer a.mu.Unlock()
				if _, sent := s.requests["B"]; sent || s.lastRequest != "A" {
					t.Fatalf("refused send still recorded request state: %v", s.requests)
				}
			})
		}
	}
}

// A check at sendInput alone leaves a window before sendClaude re-resolves.
func TestSendClaudeRefusesCredentialChangeAfterAdmission(t *testing.T) {
	a, s, env := claudeConversationFixture(t, false)
	s.lastRequest, s.requests["B"] = "B", "intent"
	s.Status = "running"
	*env = []string{(*env)[0], "ANTHROPIC_API_KEY=replacement-credential-value"}
	err := a.sendClaude(s, "B", "continue", s.CWD, "")
	if err == nil || !strings.Contains(err.Error(), "credentials or tools changed") {
		t.Fatalf("late credential change reached process start: %v", err)
	}
	if got := s.requests["B"]; got != "rejected" {
		t.Fatalf("definite refusal recorded as %q", got)
	}
}

func TestClaudeUnchangedRuntimeStillRetiresAndContinues(t *testing.T) {
	a, s, _ := claudeConversationFixture(t, true)
	err := a.send(s.ID, "B", "continue", nil, false)
	// Reaching process start proves the guard admitted the unchanged runtime.
	if err == nil || strings.Contains(err.Error(), "credentials or tools changed") {
		t.Fatalf("unchanged runtime: %v", err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if s.lastRequest != "B" {
		t.Fatal("unchanged runtime did not reach dispatch")
	}
}

func TestAttachPublishesConversationRuntimeHash(t *testing.T) {
	a := testApp(t)
	s := emptySession("claude", t.TempDir(), "")
	run := &claudeRun{input: &closeTrackingSink{}, done: make(chan struct{}), runtimeHash: "owner-hash"}
	if err := a.attachStartedClaudeRun(s, run, "", 0, "task", 1); err != nil {
		t.Fatal(err)
	}
	if s.conversationRuntimeHash != "owner-hash" {
		t.Fatalf("conversation hash %q", s.conversationRuntimeHash)
	}
}

func TestBlockedCodexReviewerCannotBeReopenedByLateCompletion(t *testing.T) {
	a, s, c := identityCodexFixture(t)
	c.input = replySink{reply: func(data []byte) {
		var p rpcPacket
		_ = json.Unmarshal(data, &p)
		if p.Method == "turn/start" {
			identityReply(c, data, "turn-A")
		}
	}}
	if err := a.send(s.ID, "A", "review", nil, false); err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	s.reviewParent = "parent"
	s.reviewDone = make(chan struct{})
	done := s.reviewDone
	a.mu.Unlock()
	params, _ := json.Marshal(map[string]any{"threadId": "identity-thread", "turnId": "turn-A"})
	a.codexQuestion(c, rpcPacket{ID: json.RawMessage(`7`), Method: "item/commandExecution/requestApproval", Params: params})
	select {
	case <-done:
	default:
		t.Fatal("blocked reviewer did not wake its waiter")
	}
	identityEvent(a, c, "turn/completed", "turn-A")
	a.mu.Lock()
	defer a.mu.Unlock()
	if s.Status != "error" {
		t.Fatalf("late completion reopened blocked reviewer to %q", s.Status)
	}
	if s.requests["A"] == "final" {
		t.Fatal("blocked reviewer request became final")
	}
}

func TestBlockedClaudeReviewerCannotBeReopenedByLateResult(t *testing.T) {
	a := testApp(t)
	s := emptySession("claude", t.TempDir(), "")
	s.ProviderID = "review-provider"
	s.Status = "running"
	s.reviewParent = "parent"
	s.reviewDone = make(chan struct{})
	done := s.reviewDone
	s.lastRequest, s.requests["A"] = "A", "accepted"
	run := &claudeRun{input: &repairSink{}, done: make(chan struct{}), requestID: "A"}
	s.claude = run
	a.reviews = append(a.reviews, s)
	frames := `{"type":"control_request","request_id":"r1","request":{"subtype":"can_use_tool","tool_name":"Bash"}}` + "\n" +
		`{"type":"result","result":"{\"verdict\":\"PASS\"}"}` + "\n"
	a.readClaude(s, run, bytes.NewBufferString(frames))
	select {
	case <-done:
	default:
		t.Fatal("blocked reviewer did not wake its waiter")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if s.Status != "error" {
		t.Fatalf("late result reopened blocked reviewer to %q", s.Status)
	}
	if s.requests["A"] == "final" {
		t.Fatal("blocked reviewer request became final")
	}
}
