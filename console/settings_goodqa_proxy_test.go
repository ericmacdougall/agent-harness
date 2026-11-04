package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

const goodqaTestToken = "SYNTHETIC-GOODQA-PRIVATE-TOKEN"

type goodqaTestServer struct {
	mu         sync.Mutex
	calls      []string
	nonce      string
	mode       string
	callResult json.RawMessage
	sessions   int
	rejected   int
	accepted   chan struct{}
	release    chan struct{}
}

func (f *goodqaTestServer) handler(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+goodqaTestToken {
		w.WriteHeader(401)
		return
	}
	var p goodqaPacket
	if json.NewDecoder(r.Body).Decode(&p) != nil {
		w.WriteHeader(400)
		return
	}
	if len(p.Error) > 0 {
		f.mu.Lock()
		f.rejected++
		f.mu.Unlock()
		w.WriteHeader(202)
		return
	}
	if p.Method == "notifications/initialized" {
		if r.Header.Get("MCP-Protocol-Version") != "2025-06-18" || !strings.HasPrefix(r.Header.Get("Mcp-Session-Id"), "session-") {
			w.WriteHeader(400)
			return
		}
		w.WriteHeader(202)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	result := any(map[string]any{})
	switch p.Method {
	case "initialize":
		f.mu.Lock()
		f.sessions++
		session := f.sessions
		f.mu.Unlock()
		w.Header().Set("Mcp-Session-Id", fmt.Sprint("session-", session))
		result = map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{"tools": map[string]any{}, "sampling": map[string]any{}}, "serverInfo": map[string]string{"name": "controlled-upstream", "version": "1"}}
	case "tools/list":
		result = map[string]any{"tools": []goodqaTool{{Name: "safe_read", Description: "Synthetic harmless echo " + goodqaTestToken, InputSchema: json.RawMessage(`{"type":"object"}`)}, {Name: "browser_delete", InputSchema: json.RawMessage(`{"type":"object"}`)}, {Name: "hive_resume", InputSchema: json.RawMessage(`{"type":"object"}`)}}}
	case "tools/call":
		var params struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		}
		_ = json.Unmarshal(p.Params, &params)
		f.mu.Lock()
		f.calls = append(f.calls, params.Name)
		f.nonce, _ = params.Arguments["nonce"].(string)
		mode := f.mode
		override := append(json.RawMessage{}, f.callResult...)
		f.mu.Unlock()
		if f.accepted != nil {
			close(f.accepted)
			select {
			case <-f.release:
			case <-r.Context().Done():
				return
			}
		}
		if mode == "timeout" {
			<-r.Context().Done()
			return
		}
		if mode == "wrong-id" {
			p.ID = json.RawMessage(`999999`)
		}
		if mode == "request" {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = fmt.Fprint(w, "data: {\"jsonrpc\":\"2.0\",\"id\":\"server-ask\",\"method\":\"sampling/createMessage\",\"params\":{}}\n\n")
			return
		}
		if mode == "oversize" {
			_, _ = io.WriteString(w, strings.Repeat("x", goodqaFrameLimit+32))
			return
		}
		result = map[string]any{"content": []map[string]string{{"type": "text", "text": "observed " + fmt.Sprint(params.Arguments["nonce"]) + " " + goodqaTestToken}}, "isError": false}
		if len(override) > 0 {
			result = override
		}
	default:
		w.WriteHeader(400)
		return
	}
	packet, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": p.ID, "result": result})
	if p.Method == "tools/call" {
		for _, b := range packet {
			_, _ = w.Write([]byte{b})
			if flush, ok := w.(http.Flusher); ok {
				flush.Flush()
			}
		}
	} else {
		_, _ = w.Write(packet)
	}
}
func goodqaTestSetup(t *testing.T) (*settingsStore, *settingsTestVault, goodqaProxySnapshot, *goodqaTestServer) {
	t.Helper()
	s, v := settingsTestStore(t)
	f := &goodqaTestServer{}
	server := httptest.NewServer(http.HandlerFunc(f.handler))
	t.Cleanup(server.Close)
	next := settingsTestCopy(s)
	next.GoodQA.Enabled = true
	next.GoodQA.Endpoint = server.URL
	if e := s.save(s.disk.Revision, next); e != nil {
		t.Fatal(e)
	}
	if e := s.writeSecret(context.Background(), s.disk.Revision, "goodqa", s.disk.Settings.GoodQA.Generation, "credential", goodqaTestToken, false); e != nil {
		t.Fatal(e)
	}
	if _, e := s.probeGoodQA(context.Background()); e != nil {
		t.Fatal(e)
	}
	next = settingsTestCopy(s)
	next.GoodQA.AllowedTools = []string{"safe_read"}
	if e := s.save(s.disk.Revision, next); e != nil {
		t.Fatal(e)
	}
	p, e := s.policy("codex", "global-codex", "main")
	if e != nil {
		t.Fatal(e)
	}
	config, e := validateMCPConfig(p.MCPConfigPath, p.MCPConfigSHA256)
	if e != nil {
		t.Fatal(e)
	}
	var args []string
	for _, server := range config.Servers {
		args = server.Args
	}
	snapshot, e := loadGoodQASnapshot(args[2], args[4])
	if e != nil {
		t.Fatal(e)
	}
	return s, v, snapshot, f
}
