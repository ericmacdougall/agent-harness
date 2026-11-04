package main

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testApp(t *testing.T) *app {
	t.Helper()
	a, err := newApp(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.close)
	return a
}
func TestHTTPAuthorityAndOrigin(t *testing.T) {
	a := testApp(t)
	handler := a.handler("127.0.0.1:12345", "fixture-token")
	cases := []struct {
		name, method, host, origin, auth, path string
		want                                   int
	}{
		{"state without token", "GET", "127.0.0.1:12345", "", "", "/api/state", 401},
		{"wrong token", "GET", "127.0.0.1:12345", "", "Bearer other", "/api/state", 401},
		{"host rebinding", "GET", "evil.example", "", "Bearer fixture-token", "/api/state", 403},
		{"foreign origin", "GET", "127.0.0.1:12345", "https://evil.example", "Bearer fixture-token", "/api/state", 403},
		{"mutation missing origin", "POST", "127.0.0.1:12345", "", "Bearer fixture-token", "/api/shutdown", 403},
		{"authorized state", "GET", "127.0.0.1:12345", "", "Bearer fixture-token", "/api/state", 200},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(c.method, "http://"+c.host+c.path, nil)
			r.Host = c.host
			r.Header.Set("Origin", c.origin)
			r.Header.Set("Authorization", c.auth)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != c.want {
				t.Fatalf("got%d body%s want%d", w.Code, w.Body.String(), c.want)
			}
			if strings.Contains(w.Body.String(), "fixture-token") {
				t.Fatal("token entered response")
			}
		})
	}
}
func TestReferenceStrictScalarTypes(t *testing.T) {
	valid := `{"schema":1,"client":"test","captured_at":"2026-11-03T00:00:00Z","title":"context","kind":"summary","body":"hello","truncated":false}`
	if _, err := parseReference([]byte(valid)); err != nil {
		t.Fatal(err)
	}
	variants := map[string]string{"null bool": strings.Replace(valid, `"truncated":false`, `"truncated":null`, 1), "invalid timestamp": strings.Replace(valid, "2026-11-03T00:00:00Z", "yesterday", 1), "nonUTC": strings.Replace(valid, "00:00:00Z", "00:00:00+01:00", 1), "float schema": strings.Replace(valid, `"schema":1`, `"schema":1.0`, 1), "duplicate": strings.Replace(valid, `"client":"test"`, `"client":"test","client":"other"`, 1), "unpaired surrogate": strings.Replace(valid, "hello", `\ud800`, 1)}
	for name, data := range variants {
		t.Run(name, func(t *testing.T) {
			if _, err := parseReference([]byte(data)); err == nil {
				t.Fatalf("accepted invalid reference %s", data)
			}
		})
	}
}
func TestUnknownJournalSendNeverReplays(t *testing.T) {
	dir := t.TempDir()
	a, err := newApp(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	current := emptySession("codex", dir, "")
	current.ProviderID = "provider-fixture"
	if err = a.record(current, "request-fixture", "accepted"); err != nil {
		t.Fatal(err)
	}
	a.close()
	restored, err := newApp(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.close()
	if len(restored.sessions) != 1 || restored.sessions[0].Status != "unknown" {
		t.Fatalf("restart failed to preserve uncertainty %#v", restored.state())
	}
	if err = restored.send(current.ID, "new-request", "retry", nil, false); err == nil {
		t.Fatal("unknown session accepted another send")
	}
	data, err := os.ReadFile(filepath.Join(dir, "sessions.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var r map[string]any
		if json.Unmarshal([]byte(line), &r) != nil {
			t.Fatal("invalid journal")
		}
		if _, ok := r["text"]; ok {
			t.Fatal("prompt entered metadata journal")
		}
	}
}
func TestEventCursorGapAndBounds(t *testing.T) {
	h := newEventHub()
	for i := 0; i < 300; i++ {
		h.publish("state", "", i)
	}
	events, gap := h.read(1)
	if !gap || len(events) != 256 {
		t.Fatalf("missing gap or bound %v %d", gap, len(events))
	}
	events, gap = h.read(299)
	if gap || len(events) != 1 || events[0].ID != 300 {
		t.Fatal("tail cursor failed")
	}
}
func TestStateExcludesPrivateProviderContext(t *testing.T) {
	a := testApp(t)
	current := emptySession("codex", t.TempDir(), "")
	current.context = "INTERNAL_CONTEXT_SENTINEL"
	current.policy.HarnessInstructions = "INTERNAL_POLICY_SENTINEL"
	current.requests["private-request"] = "intent"
	a.sessions = append(a.sessions, current)
	data, _ := json.Marshal(a.state())
	if strings.Contains(string(data), "INTERNAL_") || strings.Contains(string(data), "private-request") {
		t.Fatal("private provider state entered GUI JSON")
	}
}

func TestResolvedPermissionsUseNativeContracts(t *testing.T) {
	for mode, kind := range map[string]string{"danger-full-access": "dangerFullAccess", "workspace-write": "workspaceWrite", "read-only": "readOnly"} {
		t.Run(mode, func(t *testing.T) {
			policy := resolvedPolicy{Permissions: mode, Model: "gpt-6.1-sol", Effort: "high", ServiceTier: "default", ApprovalPolicy: "never"}
			start := map[string]any{}
			applyThreadPolicy(start, policy)
			if start["sandbox"] != mode || start["permissions"] != nil {
				t.Fatalf("wrong thread contract %#v", start)
			}
			turn := map[string]any{}
			applyTurnPolicy(turn, policy, "/fixture")
			sandbox, _ := turn["sandboxPolicy"].(map[string]any)
			if sandbox["type"] != kind || turn["permissions"] != nil || turn["model"] != "gpt-6.1-sol" || turn["effort"] != "high" {
				t.Fatalf("wrong turn contract %#v", turn)
			}
		})
	}
}

func TestRootThreadStartedIsNotItsOwnAgent(t *testing.T) {
	a := testApp(t)
	s := emptySession("codex", t.TempDir(), "")
	a.sessions = append(a.sessions, s)
	a.codexEvent(nil, "thread/started", json.RawMessage(`{"thread":{"id":"root-provider","source":"appServer","status":{"type":"idle"}}}`))
	if len(s.Agents) != 0 {
		t.Fatalf("root was treated as child %#v", s.Agents)
	}
}

func TestCloseTabPreservesHistoryAndRefusesActiveWork(t *testing.T) {
	dir := t.TempDir()
	a, err := newApp(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	current := emptySession("codex", dir, "")
	current.ProviderID = "provider-retained"
	current.Status = "running"
	a.sessions = append(a.sessions, current)
	if err = a.closeSession(current.ID); err == nil {
		t.Fatal("active work was discarded")
	}
	current.Status = "idle"
	if err = a.closeSession(current.ID); err != nil {
		t.Fatal(err)
	}
	if len(a.sessions) != 0 {
		t.Fatal("tab was not removed")
	}
	a.close()
	restored, err := newApp(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.close()
	if len(restored.sessions) != 0 {
		t.Fatal("closed tab restored")
	}
	data, err := os.ReadFile(filepath.Join(dir, "sessions.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "provider-retained") || !strings.Contains(string(data), `"state":"closed"`) {
		t.Fatal("closure lost durable provider identity")
	}
}
