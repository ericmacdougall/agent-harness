package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestScopedMCPDeliveryCannotAuthorizeGUI(t *testing.T) {
	a, s, input := claudeCheckpointFixture(t)
	input.State = "blocked"
	input.Scope = "controlled MCP transport"
	server := httptest.NewServer(http.HandlerFunc(a.checkpointHTTP))
	defer server.Close()
	t.Setenv("HARNESS_CHECKPOINT_ENDPOINT", server.URL+"/checkpoint")
	t.Setenv("HARNESS_CHECKPOINT_CAPABILITY", s.task.capability)
	packet, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": "harness_console_checkpoint", "arguments": input}})
	var out bytes.Buffer
	if err := runCheckpointMCP(bytes.NewReader(append(packet, '\n')), &out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), s.task.capability) || !strings.Contains(out.String(), "recorded") {
		t.Fatalf("unsafe or failed response: %s", out.String())
	}
	if s.task.State != "blocked" {
		t.Fatal("actual checkpoint not updated")
	}
	request := httptest.NewRequest("GET", "http://127.0.0.1:1234/api/state", nil)
	request.Header.Set("Authorization", "Bearer "+s.task.capability)
	response := httptest.NewRecorder()
	a.handler("127.0.0.1:1234", "distinct-gui-bearer").ServeHTTP(response, request)
	if response.Code != 401 {
		t.Fatal("scoped token authorized GUI", response.Code)
	}
	s.task.Generation++
	input.Generation = 1
	if a.checkpointUpdate(s.ID, input) == nil {
		t.Fatal("old generation accepted")
	}
}
