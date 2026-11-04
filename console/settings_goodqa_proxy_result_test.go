package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestGoodQAProxyValidContentAndStructuredResultsRemainIntact(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"text", `{"content":[{"type":"text","text":"positive-result"}],"isError":false}`},
		{"structured", `{"content":[],"structuredContent":{"answer":"positive-result","large":9007199254740993},"_meta":{"trace":"retained"}}`},
		{"all-supported-content", `{"content":[{"type":"text","text":"positive-result","annotations":{"audience":["user","assistant"],"priority":0.5,"lastModified":"2026-11-03T00:00:00Z"}},{"type":"image","data":"YQ==","mimeType":"image/png"},{"type":"audio","data":"YQ==","mimeType":"audio/wav"},{"type":"resource","resource":{"uri":"goodqa://synthetic/item","text":"positive-resource","mimeType":"text/plain"}},{"type":"resource_link","uri":"https://example.invalid/synthetic","name":"positive-link","size":1}]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, v, snapshot, f := goodqaTestSetup(t)
			f.mu.Lock()
			f.callResult = json.RawMessage(tc.raw)
			f.mu.Unlock()
			var out, logs bytes.Buffer
			if e := serveGoodQAProxy(context.Background(), snapshot, v, strings.NewReader(goodqaTestInput()), &out, &logs); e != nil {
				t.Fatal(e)
			}
			lines := strings.Split(strings.TrimSpace(out.String()), "\n")
			var response struct {
				Result json.RawMessage `json:"result"`
			}
			if len(lines) != 6 || json.Unmarshal([]byte(lines[3]), &response) != nil || !strings.Contains(string(response.Result), "positive-result") || strings.Contains(string(response.Result), `"outcome":"unknown"`) {
				t.Fatal("valid supported result was rejected or lost")
			}
			if strings.Contains(tc.raw, "9007199254740993") && !strings.Contains(string(response.Result), "9007199254740993") {
				t.Fatal("structured numeric token changed")
			}
			if strings.Contains(tc.raw, "resource_link") && !strings.Contains(string(response.Result), "positive-link") {
				t.Fatal("supported resource content discarded")
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if len(f.calls) != 1 {
				t.Fatal("valid tool result duplicated or test was vacuous")
			}
		})
	}
}

func TestGoodQAResultNegotiatedVersionsAndFieldTypes(t *testing.T) {
	link := json.RawMessage(`{"content":[{"type":"resource_link","uri":"goodqa://item","name":"x"}]}`)
	if goodqaValidateCallResult(link, "2025-06-18") != nil || goodqaValidateCallResult(link, "2025-03-26") == nil {
		t.Fatal("resource links not bound to negotiated version")
	}
	for _, raw := range []string{`{"content":null}`, `{"content":[],"structuredContent":null}`, `{"content":[{"type":"text","text":null}]}`, `{"content":[{"type":"text","text":"x","annotations":{"priority":"high"}}]}`, `{"content":[{"type":"resource","resource":{"uri":"goodqa://item","blob":false}}]}`} {
		if goodqaValidateCallResult(json.RawMessage(raw), "2025-06-18") == nil {
			t.Fatal("invalid content field type accepted", raw)
		}
	}
}

func TestGoodQAProxyMalformedAcceptedResultsAreUnknownWithoutReplay(t *testing.T) {
	for _, raw := range []string{`null`, `"opaque"`, `[]`, `{"content":"wrong"}`, `{"content":[null]}`, `{"content":[{"type":"text","text":false}]}`, `{"content":[],"isError":"no"}`, `{"content":[],"structuredContent":[]}`, `{"content":[{"type":"image","data":1,"mimeType":"image/png"}]}`} {
		t.Run(raw, func(t *testing.T) {
			_, v, snapshot, f := goodqaTestSetup(t)
			f.mu.Lock()
			f.callResult = json.RawMessage(raw)
			f.mu.Unlock()
			var out, logs bytes.Buffer
			if e := serveGoodQAProxy(context.Background(), snapshot, v, strings.NewReader(goodqaTestInput()), &out, &logs); e != nil {
				t.Fatal(e)
			}
			f.mu.Lock()
			count := len(f.calls)
			f.mu.Unlock()
			if count != 1 {
				t.Fatal("accepted result replayed or positive fixture not reached", count)
			}
			lines := strings.Split(strings.TrimSpace(out.String()), "\n")
			if len(lines) != 6 {
				t.Fatal("protocol response missing")
			}
			var response struct {
				Result struct {
					IsError bool                          `json:"isError"`
					Content []struct{ Type, Text string } `json:"content"`
					Meta    struct {
						Outcome string `json:"outcome"`
					} `json:"_meta"`
				} `json:"result"`
			}
			if json.Unmarshal([]byte(lines[3]), &response) != nil || !response.Result.IsError || response.Result.Meta.Outcome != "unknown" || len(response.Result.Content) != 1 || !strings.Contains(response.Result.Content[0].Text, "Do not replay") {
				t.Fatal("malformed accepted result forwarded as success instead of well-formed unknown")
			}
		})
	}
}
