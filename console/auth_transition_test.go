package main

import (
	"context"
	"strings"
	"testing"
	"time"
)

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
	a.authenticatedProfileChanged("codex", "")
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

	a.authenticatedProfileChanged("claude", current.ProfileID)

	if current.claude != nil || !current.Restored || current.requests[current.lastRequest] != "unknown" || current.Agents[0].CanResume {
		t.Fatalf("Claude auth transition retained old authority: restored=%v request=%s child=%+v", current.Restored, current.requests[current.lastRequest], current.Agents[0])
	}
	if err := run.write(map[string]any{"type": "user"}); err == nil {
		t.Fatal("cancelled Claude authenticated context accepted a later write")
	}
}
