package main

import (
	"bytes"
	"context"
	"errors"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

type blockingAuthSink struct {
	mu      sync.Mutex
	data    bytes.Buffer
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (s *blockingAuthSink) Write(p []byte) (int, error) {
	s.once.Do(func() {
		close(s.entered)
		<-s.release
	})
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data.Write(p)
}
func (s *blockingAuthSink) Close() error { return nil }

func TestSuccessfulSameProfileAuthTransitionRevokesCachedClientAndChild(t *testing.T) {
	a, current, _ := checkpointFixture(t)
	settings, _ := settingsTestStore(t)
	profile := settingsTestProfile(t, settings)
	settings.app = a
	a.runtime = func(string, string) (string, []string, error) { return "/synthetic/codex", nil, nil }
	policy, err := defaultPolicy("codex", profile.ID, "main")
	if err != nil {
		t.Fatal(err)
	}
	_, _, before, err := a.resolveRuntime(policy)
	if err != nil {
		t.Fatal(err)
	}
	sink := &repairSink{}
	done := make(chan struct{})
	close(done)
	old := &rpcClient{input: sink, done: done, pending: map[string]chan rpcPacket{}, runtimeHash: before}
	current.codex = old
	current.ProfileID = profile.ID
	current.Provider = "codex"
	current.Status = "idle"
	current.providerFinal = true
	current.Agents = []agent{{ID: "old-owner", Provider: "codex", Status: "running", CanPause: true, CanStop: true, CanResume: true}}
	a.clients["codex:"+profile.ID+":"+before] = old

	task := &settingsLogin{ID: freshID(), ProfileID: profile.ID, Generation: profile.Generation, State: "running", cancel: func() {}}
	settings.login[task.ID] = task
	a.beginAuthenticationTransition("codex", profile.ID)
	settings.finishLogin(task, profile, nil)

	if task.State != "complete" {
		t.Fatal("successful login completion was not published", task.State, task.Reason)
	}
	if err = old.writeContext(context.Background(), map[string]any{"method": "turn/start"}); err == nil || sink.Len() != 0 {
		t.Fatalf("old authenticated client retained write authority: err=%v bytes=%d", err, sink.Len())
	}
	child := current.Agents[0]
	if current.codex != nil || !current.Restored || child.CanPause || child.CanStop || child.CanResume || child.Status != "unknown" {
		t.Fatalf("old parent/child authority survived auth transition: restored=%v child=%+v", current.Restored, child)
	}
	if !strings.Contains(child.ControlReason, "fresh owner") || !strings.Contains(child.ControlReason, "not automatic") {
		t.Fatal("quarantine omitted safe replacement handoff", child.ControlReason)
	}
	_, _, after, err := a.resolveRuntime(policy)
	if err != nil {
		t.Fatal(err)
	}
	if after == before {
		t.Fatal("successful same-profile authentication reused old runtime/cache identity")
	}
}

func TestAuthTransitionFencesQueuedWriteAdmission(t *testing.T) {
	a, current, _ := checkpointFixture(t)
	sink := &repairSink{}
	client := &rpcClient{input: sink, done: make(chan struct{}), pending: map[string]chan rpcPacket{}}
	current.codex = client
	current.Provider = "codex"
	current.ProfileID = ""
	a.clients["codex::old-generation"] = client
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- client.writeAdmitted(context.Background(), map[string]any{"method": "turn/start"}, func() (func(), error) {
			close(entered)
			<-release
			return func() {}, nil
		})
	}()
	<-entered
	a.beginAuthenticationTransition("codex", "")
	close(release)
	select {
	case err := <-done:
		if err == nil || sink.Len() != 0 {
			t.Fatalf("queued pre-transition write crossed auth boundary: err=%v bytes=%d", err, sink.Len())
		}
	case <-time.After(time.Second):
		t.Fatal("queued write did not resolve after auth transition")
	}
}

func TestAuthTransitionFencesBeforeLoginAndStaysClosedAfterFailure(t *testing.T) {
	a, current, _ := checkpointFixture(t)
	settings, _ := settingsTestStore(t)
	configured := settingsTestProfile(t, settings)
	settings.app = a
	profile := configured.ID
	other := "unrelated-profile"
	current.Provider, current.ProfileID = "codex", profile
	sink := &repairSink{}
	client := &rpcClient{input: sink, done: make(chan struct{}), pending: map[string]chan rpcPacket{}}
	current.codex = client
	a.clients["codex:"+profile+":old"] = client
	a.runtime = func(string, string) (string, []string, error) { return "/synthetic/codex", nil, nil }

	a.beginAuthenticationTransition("codex", profile)
	if err := client.write(map[string]any{"method": "turn/start"}); err == nil || sink.Len() != 0 {
		t.Fatalf("mid-login old client retained authority: err=%v bytes=%d", err, sink.Len())
	}
	profilePolicy, _ := defaultPolicy("codex", profile, "main")
	if _, _, _, err := a.resolveRuntime(profilePolicy); err == nil {
		t.Fatal("failed login's possibly mutated profile was reopened")
	}
	otherPolicy, _ := defaultPolicy("codex", other, "main")
	if _, _, _, err := a.resolveRuntime(otherPolicy); err != nil {
		t.Fatal("profile-scoped fence blocked unrelated profile", err)
	}
	// A failed status reconciliation deliberately leaves the fence in place.
	task := &settingsLogin{ID: freshID(), ProfileID: profile, Generation: configured.Generation, State: "running", cancel: func() {}}
	settings.login[task.ID] = task
	settings.finishLogin(task, configured, errors.New("controlled status failure after possible mutation"))
	if task.State != "failed" {
		t.Fatal("unverified login outcome was not reported as failed", task.State)
	}
	if _, _, _, err := a.resolveRuntime(profilePolicy); err == nil {
		t.Fatal("failed login reconciliation released profile authority")
	}
}

func TestLateOldGenerationClientCannotPublish(t *testing.T) {
	a, _, _ := checkpointFixture(t)
	profile := "late-publication-profile"
	a.runtime = func(string, string) (string, []string, error) { return "/synthetic/codex", nil, nil }
	policy, _ := defaultPolicy("codex", profile, "main")
	_, _, fingerprint, generation, err := a.resolveRuntimeCaptured(policy)
	if err != nil {
		t.Fatal(err)
	}
	late := &rpcClient{done: make(chan struct{}), pending: map[string]chan rpcPacket{}}
	a.beginAuthenticationTransition("codex", profile)
	key := "codex:" + profile + ":" + fingerprint
	if _, err = a.publishCodexClient(key, profile, generation, nil, late); err == nil {
		t.Fatal("old-generation client published after auth transition")
	}
	if a.clients[key] != nil {
		t.Fatal("rejected old-generation client remained cached")
	}
}

func TestClaudeAuthTransitionCancelsOldRunAndRevokesControls(t *testing.T) {
	a, current, _ := checkpointFixture(t)
	current.Provider = "claude"
	current.ProfileID = "subscription-claude"
	current.Status = "running"
	current.lastRequest = "claude-request"
	current.requests[current.lastRequest] = "accepted"
	sink := &repairSink{}
	run := &claudeRun{input: sink, done: make(chan struct{}), requestID: current.lastRequest}
	current.claude = run
	current.Agents = []agent{{ID: "claude-owner", Provider: "claude", Status: "running", CanPause: true, CanStop: true, CanResume: true}}

	a.beginAuthenticationTransition("claude", current.ProfileID)

	if current.claude != nil || !current.Restored || current.requests[current.lastRequest] != "unknown" || current.Agents[0].CanResume {
		t.Fatalf("Claude auth transition retained old authority: restored=%v request=%s child=%+v", current.Restored, current.requests[current.lastRequest], current.Agents[0])
	}
	if err := run.write(map[string]any{"type": "user"}); err == nil {
		t.Fatal("cancelled Claude authenticated context accepted a later write")
	}
}

func TestClaudeQueuedFrameCannotCrossAuthTransition(t *testing.T) {
	a, current, _ := checkpointFixture(t)
	profile := "claude-racing-frame"
	current.Provider, current.ProfileID = "claude", profile
	generation := uint64(0)
	sink := &blockingAuthSink{entered: make(chan struct{}), release: make(chan struct{})}
	run := &claudeRun{input: sink, done: make(chan struct{}), authAdmit: a.authAdmission("claude", profile, generation)}
	current.claude = run
	first := make(chan error, 1)
	second := make(chan error, 1)
	go func() { first <- run.write(map[string]any{"type": "first"}) }()
	<-sink.entered
	go func() { second <- run.write(map[string]any{"type": "second"}) }()
	deadline := time.Now().Add(time.Second)
	for len(run.writer.queue) == 0 && time.Now().Before(deadline) {
		runtime.Gosched()
	}
	if len(run.writer.queue) == 0 {
		t.Fatal("second Claude frame did not reach the serialized queue")
	}
	transitioned := make(chan struct{})
	go func() {
		a.beginAuthenticationTransition("claude", profile)
		close(transitioned)
	}()
	deadline = time.Now().Add(time.Second)
	for !a.authTransitioning("claude", profile) && time.Now().Before(deadline) {
		runtime.Gosched()
	}
	if !a.authTransitioning("claude", profile) {
		t.Fatal("Claude auth transition boundary was not published")
	}
	close(sink.release)
	if err := <-first; err != nil {
		t.Fatal("pre-transition admitted frame did not finish", err)
	}
	select {
	case <-transitioned:
	case <-time.After(time.Second):
		t.Fatal("Claude auth transition did not finish")
	}
	if err := <-second; err == nil {
		t.Fatal("queued Claude frame crossed auth transition")
	}
	sink.mu.Lock()
	written := sink.data.String()
	sink.mu.Unlock()
	if strings.Contains(written, "second") {
		t.Fatal("post-transition Claude frame reached provider input")
	}
}
