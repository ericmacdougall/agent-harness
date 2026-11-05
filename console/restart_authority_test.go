package main

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func journaledSessions(t *testing.T, dir string, receipts []string) {
	t.Helper()
	a, err := newApp(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i, receipt := range receipts {
		s := emptySession("claude", dir, "")
		s.ID = fmt.Sprintf("session-%02d", i)
		s.ProviderID = fmt.Sprintf("provider-%02d", i)
		if err = a.record(s, fmt.Sprintf("request-%02d", i), receipt); err != nil {
			t.Fatal(err)
		}
	}
	a.close()
}

// Restored tabs do not count toward the live limit, so more than maxSessions can
// exist across restarts. Trimming may only ever drop resolved history.
func TestRestoreNeverDropsUnresolvedTabs(t *testing.T) {
	dir := t.TempDir()
	receipts := make([]string, maxSessions+6)
	for i := range receipts {
		receipts[i] = "final"
	}
	// Oldest, so plain last-N trimming would drop them first.
	receipts[0], receipts[1], receipts[2] = "unknown", "accepted", "intent"
	journaledSessions(t, dir, receipts)
	restored, err := newApp(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.close()
	found := map[string]*session{}
	for _, s := range restored.sessions {
		found[s.ID] = s
	}
	for _, id := range []string{"session-00", "session-01", "session-02"} {
		if found[id] == nil {
			t.Fatalf("%s dropped silently on restart; have %d tabs", id, len(restored.sessions))
		}
		if found[id].Status != "unknown" {
			t.Fatalf("%s restored as %q", id, found[id].Status)
		}
	}
	if len(restored.sessions) > maxSessions {
		t.Fatalf("resolved history was not trimmed: %d tabs", len(restored.sessions))
	}
	if found[fmt.Sprintf("session-%02d", len(receipts)-1)] == nil {
		t.Fatal("newest resolved tab was trimmed instead of oldest")
	}
}

// Every unresolved tab survives even past the limit; the journal bound caps them.
func TestRestoreKeepsAllUnresolvedPastTheLimit(t *testing.T) {
	dir := t.TempDir()
	receipts := make([]string, maxSessions+3)
	for i := range receipts {
		receipts[i] = "unknown"
	}
	journaledSessions(t, dir, receipts)
	restored, err := newApp(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.close()
	if len(restored.sessions) != len(receipts) {
		t.Fatalf("restored %d of %d unresolved tabs", len(restored.sessions), len(receipts))
	}
}

func TestPauseCannotEraseRestoredUnknown(t *testing.T) {
	for _, action := range []string{"pause", "stop"} {
		t.Run(action, func(t *testing.T) {
			dir := t.TempDir()
			journaledSessions(t, dir, []string{"unknown"})
			a, err := newApp(dir, nil)
			if err != nil {
				t.Fatal(err)
			}
			current := a.sessions[0]
			epoch := current.controlEpoch
			if err = a.control(current.ID, action, ""); err == nil {
				t.Error("control on a read-only restored tab succeeded")
			}
			if current.Status != "unknown" || current.controlEpoch != epoch {
				t.Fatalf("control mutated a restored tab: status=%q epoch %d -> %d", current.Status, epoch, current.controlEpoch)
			}
			if err = a.closeSession(current.ID); err == nil {
				t.Fatal("restored unknown tab closed")
			}
			a.close()
			again, err := newApp(dir, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer again.close()
			if len(again.sessions) != 1 || again.sessions[0].Status != "unknown" {
				t.Fatal("restored unknown did not survive")
			}
		})
	}
}

// Unknown can come from a queue or lifecycle failure while the last request is
// final. Pause must not turn that into a closable paused tab.
func TestPauseKeepsLiveUnknownStatus(t *testing.T) {
	a, s, c := identityCodexFixture(t)
	c.input = replySink{reply: func(data []byte) { identityReply(c, data, "turn") }}
	s.Status = "unknown"
	s.lastRequest, s.requests["A"] = "A", "final"
	_ = a.control(s.ID, "pause", "")
	a.mu.Lock()
	defer a.mu.Unlock()
	if s.Status != "unknown" {
		t.Fatalf("Pause replaced unknown with %q", s.Status)
	}
}

func TestRestoreRebuildsLastRequestForUnresolvedTab(t *testing.T) {
	dir := t.TempDir()
	journaledSessions(t, dir, []string{"accepted"})
	a, err := newApp(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer a.close()
	current := a.sessions[0]
	if current.lastRequest != "request-00" || current.requests["request-00"] != "unknown" {
		t.Fatalf("restored request identity lost: %q %v", current.lastRequest, current.requests)
	}
	state := a.state()
	sessions := state["sessions"].([]map[string]any)
	if sessions[0]["unresolved"] != true || sessions[0]["canStop"] != false {
		t.Fatalf("restored tab state: unresolved=%v canStop=%v", sessions[0]["unresolved"], sessions[0]["canStop"])
	}
}

// A settings save bumps the GoodQA snapshot revision on purpose, which revokes the
// old proxy. That alone must not refuse the Claude conversation.
func TestClaudeSurvivesRevisionOnlyToolConfigChange(t *testing.T) {
	a, s, env := claudeConversationFixture(t, false)
	// A conversation that already has GoodQA tools: the endpoint and allowlist
	// identity stays, only the settings revision embedded in the config hash moves.
	policy := s.policy
	policy.MCPConfigSHA256 = "revision-one"
	policy.MCPIdentity = "stable-endpoint-and-allowlist"
	s.policy = policy
	s.conversationRuntimeHash = conversationIdentity("/fixture/claude-absent", *env, policy)
	policy.MCPConfigSHA256 = "revision-two"
	a.resolvePolicy = func(string, string, string) (resolvedPolicy, error) { return policy, nil }
	err := a.send(s.ID, "B", "continue", nil, false)
	if errors.Is(err, errRuntimeChanged) {
		t.Fatalf("unrelated settings save refused the conversation: %v", err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if s.lastRequest != "B" {
		t.Fatalf("send never reached dispatch: %v", err)
	}
}

// A real tool identity change still refuses.
func TestClaudeRefusesRealToolIdentityChange(t *testing.T) {
	a, s, _ := claudeConversationFixture(t, false)
	policy := s.policy
	policy.MCPConfigSHA256 = "revision-two"
	policy.MCPIdentity = "different-endpoint-or-allowlist"
	a.resolvePolicy = func(string, string, string) (resolvedPolicy, error) { return policy, nil }
	err := a.send(s.ID, "B", "continue", nil, false)
	if err == nil || !strings.Contains(err.Error(), "credentials or tools changed") {
		t.Fatalf("tool identity change was not refused: %v", err)
	}
}

// A7 for Codex: a stored credential change refuses further sends on a live
// client, manual or automatic, and records nothing for the refused request.
func TestCodexRefusesSendAcrossCredentialChange(t *testing.T) {
	for _, automatic := range []bool{false, true} {
		name := map[bool]string{false: "manual", true: "automatic"}[automatic]
		t.Run(name, func(t *testing.T) {
			a, s, c := identityCodexFixture(t)
			s.requests["A"] = "final"
			s.lastRequest = "A"
			s.providerFinal = true
			sink := &repairSink{}
			c.input = sink
			bindings := []sendBinding{}
			if automatic {
				s.task = &trackedTask{ID: "task", State: "active", Generation: 1, passes: map[string]string{}, attempts: map[string]int{}}
				s.Supervision.State = "active"
				bindings = append(bindings, sendBinding{taskID: "task", epoch: s.controlEpoch})
			}
			a.runtime = func(string, string) (string, []string, error) {
				return "/fixture/codex", []string{"OPENAI_API_KEY=replacement-credential-value"}, nil
			}
			err := a.send(s.ID, "B", "continue", nil, automatic, bindings...)
			if !errors.Is(err, errRuntimeChanged) {
				t.Fatalf("Codex conversation crossed a credential change: %v", err)
			}
			a.mu.Lock()
			defer a.mu.Unlock()
			if _, sent := s.requests["B"]; sent || s.lastRequest != "A" {
				t.Fatalf("refused send recorded request state: %v", s.requests)
			}
			if sink.Len() != 0 {
				t.Fatalf("refused send wrote %d bytes to the provider", sink.Len())
			}
		})
	}
}
