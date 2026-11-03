package main

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSettingsSecretFilterThroughCoreEventsHTTPAndJournal(t *testing.T) {
	a := testApp(t)
	s := &settingsStore{known: map[string]bool{}}
	secret := "SYNTHETIC-CORE-SINK-PRIVATE-KEY"
	s.remember(secret)
	a.redact = s.redact
	a.newRedactor = s.stream
	current := emptySession("codex", a.dataDir, "global-codex")
	client := &rpcClient{}
	current.codex = client
	current.ProviderID = "controlled-thread"
	current.lastRequest = "sink-request"
	current.turnID = "sink-turn"
	current.requests[current.lastRequest] = "accepted"
	current.codexTurn = &codexTurnBinding{client: client, requestID: current.lastRequest, turnID: current.turnID}
	a.sessions = []*session{current}
	handler := a.handler("127.0.0.1:8011", "synthetic-bootstrap")
	checkHTTP := func() {
		r := httptest.NewRequest("GET", "http://127.0.0.1:8011/api/state", nil)
		r.Header.Set("Authorization", "Bearer synthetic-bootstrap")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != 200 || strings.Contains(w.Body.String(), secret) {
			t.Fatal("known secret reached HTTP state")
		}
	}
	for split := 1; split < len(secret); split++ {
		id := freshID()
		emit := func(delta string) {
			raw, _ := json.Marshal(map[string]any{"threadId": current.ProviderID, "turnId": current.turnID, "itemId": id, "delta": delta})
			a.codexEvent(client, "item/agentMessage/delta", raw)
			checkHTTP()
		}
		emit("lead " + secret[:split])
		for _, m := range current.Messages {
			if m.ID == id && strings.Contains(m.Text, secret[:split]) {
				t.Fatalf("split%d exposed an in-progress key prefix", split)
			}
		}
		emit(secret[split:] + " tail")
		raw, _ := json.Marshal(current.Messages)
		if strings.Contains(string(raw), secret) {
			t.Fatal("raw provider message sink retained full secret")
		}
		complete, _ := json.Marshal(map[string]any{"threadId": current.ProviderID, "turnId": current.turnID, "item": map[string]any{"type": "agentMessage", "id": id, "text": "lead " + secret + " tail"}})
		a.codexEvent(client, "item/completed", complete)
		checkHTTP()
	}
	tool, _ := json.Marshal(map[string]any{"threadId": current.ProviderID, "turnId": current.turnID, "item": map[string]any{"type": "mcpToolCall", "id": "tool-result", "result": map[string]string{"text": secret}}})
	a.codexEvent(client, "item/completed", tool)
	errorFrame, _ := json.Marshal(map[string]any{"threadId": current.ProviderID, "turnId": current.turnID, "error": map[string]string{"message": secret}})
	a.codexEvent(client, "error", errorFrame)
	if len(current.Messages) != len(secret) || current.Supervision.progress != 1 || current.Error == "" {
		t.Fatal("bound redaction events were not exercised")
	}
	checkHTTP()
	raw, _ := json.Marshal(current)
	if strings.Contains(string(raw), secret) {
		t.Fatal("tool/error sink retained known secret")
	}
	a.mu.Lock()
	e := a.record(current, "synthetic-request", "accepted")
	a.mu.Unlock()
	if e != nil {
		t.Fatal(e)
	}
	journal, e := os.ReadFile(filepath.Join(a.dataDir, "sessions.jsonl"))
	if e != nil || strings.Contains(string(journal), secret) {
		t.Fatal("secret entered journal")
	}
	events, _ := a.hub.read(0)
	raw, _ = json.Marshal(events)
	if strings.Contains(string(raw), secret) {
		t.Fatal("secret entered SSE ring")
	}
}
