package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGoodQAProxyRejectsInvalidProtocolAndSession(t *testing.T) {
	for _, mode := range []string{"version", "response-id", "session"} {
		t.Run(mode, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var p goodqaPacket
				_ = json.NewDecoder(r.Body).Decode(&p)
				w.Header().Set("Content-Type", "application/json")
				protocol := "2025-06-18"
				if mode == "version" {
					protocol = "2100-01-01"
				}
				if mode == "response-id" {
					p.ID = json.RawMessage(`9999`)
				}
				if mode == "session" {
					w.Header().Set("Mcp-Session-Id", "contains space")
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": p.ID, "result": map[string]any{"protocolVersion": protocol, "capabilities": map[string]any{"tools": map[string]any{}}}})
			}))
			defer server.Close()
			if e := newGoodQAHTTP(server.URL, goodqaTestToken).initialize(context.Background()); e == nil {
				t.Fatal("invalid upstream negotiation accepted")
			}
		})
	}
}
func TestGoodQAProxyMissingCredentialAndOversizeFrameHaveNoUpstreamEffect(t *testing.T) {
	for _, mode := range []string{"missing", "oversize"} {
		t.Run(mode, func(t *testing.T) {
			_, v, snapshot, f := goodqaTestSetup(t)
			input := goodqaTestInput()
			if mode == "missing" {
				_ = v.Delete(context.Background(), snapshot.CredentialRef)
			} else {
				input = strings.Repeat("x", goodqaFrameLimit+1)
			}
			var out, logs bytes.Buffer
			if e := serveGoodQAProxy(context.Background(), snapshot, v, strings.NewReader(input), &out, &logs); e == nil {
				t.Fatal("unavailable credential or oversized frame accepted")
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.sessions != 1 || len(f.calls) != 0 {
				t.Fatal("rejected input reached upstream")
			}
			if strings.Contains(out.String()+logs.String(), goodqaTestToken) {
				t.Fatal("credential exposed")
			}
		})
	}
}
func TestGoodQAProxyFiltersEscapedStringsKeysAndNumericEchoes(t *testing.T) {
	secret := "SYNTHETIC-\"quoted\\TOKEN"
	input := map[string]any{"value": secret, secret: []any{secret}, "number": json.Number("99001234500")}
	raw, _ := json.Marshal(input)
	broken := bytes.ReplaceAll(raw, []byte(secret), []byte("[REDACTED]"))
	var negative map[string]any
	_ = json.Unmarshal(broken, &negative)
	if negative["value"] != secret {
		t.Fatal("escaped-JSON failure control did not reproduce risk")
	}
	filtered := goodqaFilterJSON(input, []string{secret, "12345"})
	safe, _ := json.Marshal(filtered)
	var decoded map[string]any
	if json.Unmarshal(safe, &decoded) != nil || decoded["value"] != "[REDACTED]" || decoded["number"] != "[REDACTED]" {
		t.Fatal("recursive JSON filter failed")
	}
	if _, exists := decoded[secret]; exists {
		t.Fatal("secret-bearing key survived")
	}
}
func TestGoodQAProxyCapabilityGroupOffDoesNotGrantSelectedNames(t *testing.T) {
	s, _, snapshot, _ := goodqaTestSetup(t)
	next := settingsTestCopy(s)
	next.GoodQA.AllowedTools = []string{"browser_delete"}
	next.GoodQA.Capabilities.Browser = false
	if e := s.save(s.disk.Revision, next); e != nil {
		t.Fatal(e)
	}
	p, e := s.policy("codex", "global-codex", "main")
	if e != nil {
		t.Fatal(e)
	}
	if p.MCPConfigPath != "" {
		t.Fatal("disabled browser group exposed selected browser tool")
	}
	snapshot.Revision = s.disk.Revision
	snapshot.AllowedTools = []string{"browser_delete"}
	if goodqaCheckAuthority(snapshot, "", true) == nil {
		t.Fatal("crafted snapshot bypassed disabled group")
	}
}
