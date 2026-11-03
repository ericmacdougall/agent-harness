package main

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"testing"
)

func TestQueuedFollowupAcceptedWhileProviderRunning(t *testing.T) {
	a, s, _ := checkpointFixture(t)
	s.Status = "running"
	s.Supervision.State = "active"
	s.task.State = "active"
	body, _ := json.Marshal(map[string]any{"requestId": "followup-one", "text": "Preserve this requested change", "attachments": []string{}})
	req := httptest.NewRequest("POST", "http://127.0.0.1:12345/api/sessions/"+s.ID+"/inputs", bytes.NewReader(body))
	req.Header.Set("Origin", "http://127.0.0.1:12345")
	req.Header.Set("Authorization", "Bearer fixture-token")
	w := httptest.NewRecorder()
	a.handler("127.0.0.1:12345", "fixture-token").ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("running input not accepted durably: HTTP %d %s", w.Code, w.Body.String())
	}
	if s.task.ID != "task" || s.task.Generation != 1 {
		t.Fatal("queue replaced active task")
	}
}
func TestOrdinarySendCannotReplaceActiveTrackedWork(t *testing.T) {
	a, existing, _ := checkpointFixture(t)
	binary, _ := os.Executable()
	a.runtime = func(string, string) (string, []string, error) {
		return binary, append(os.Environ(), "HARNESS_CONSOLE_RPC_FIXTURE=1"), nil
	}
	s, err := a.createSession("codex", existing.CWD, "")
	if err != nil {
		t.Fatal(err)
	}
	if err = a.send(s.ID, "original", "original objective", nil, false); err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	s.Status = "idle"
	s.providerFinal = true
	s.task.State = "active"
	oldID := s.task.ID
	a.mu.Unlock()
	if err = a.send(s.ID, "ordinary-followup", "do not replace unfinished objective", nil, false); err == nil {
		t.Fatal("ordinary send silently replaced active task; require follow-up queue")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if s.task.ID != oldID {
		t.Fatal("active task identity changed")
	}
}
