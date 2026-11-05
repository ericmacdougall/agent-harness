// mockanth: scripted Anthropic Messages API (streaming) stand-in for driving real Claude Code at zero cost.
// First request without tool_result -> tool_use Bash {command:-cmd}; afterwards -> text "DONE <last tool_result>".
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
)

var (
	cmd  = flag.String("cmd", "echo hi", "")
	logp = flag.String("log", "mockanth.jsonl", "")
	addr = flag.String("addr", "127.0.0.1:0", "")
)

func ev(w http.ResponseWriter, typ string, v map[string]any) {
	v["type"] = typ
	b, _ := json.Marshal(v)
	fmt.Fprintf(w, "event: %s\ndata: %s\n\n", typ, b)
}

func handle(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	if !strings.HasSuffix(r.URL.Path, "/messages") {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"input_tokens":1}`))
		return
	}
	var req map[string]any
	json.Unmarshal(body, &req)
	raw := string(body)
	hasResult := strings.Contains(raw, `"tool_result"`)
	last := ""
	if i := strings.LastIndex(raw, `"tool_result"`); i >= 0 {
		last = raw[i:]
		if len(last) > 300 {
			last = last[:300]
		}
	}
	var tools []string
	if ts, ok := req["tools"].([]any); ok {
		for _, t := range ts {
			if m, ok := t.(map[string]any); ok {
				n, _ := m["name"].(string)
				tools = append(tools, n)
			}
		}
	}
	if f, err := os.OpenFile(*logp, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
		b, _ := json.Marshal(map[string]any{"path": r.URL.Path, "has_result": hasResult, "ntools": len(tools), "stream": req["stream"], "last": last})
		f.Write(append(b, '\n'))
		f.Close()
	}
	w.Header().Set("Content-Type", "text/event-stream")
	model, _ := req["model"].(string)
	usage := map[string]any{"input_tokens": 1, "output_tokens": 1}
	ev(w, "message_start", map[string]any{"message": map[string]any{"id": "msg_mock", "type": "message", "role": "assistant", "model": model, "content": []any{}, "stop_reason": nil, "usage": usage}})
	stop := "end_turn"
	hasBash := false
	for _, t := range tools {
		if t == "Bash" || t == "PowerShell" {
			hasBash = true
		}
	}
	if !hasResult && hasBash && strings.Contains(raw, "SPIKE_RUN") {
		in, _ := json.Marshal(map[string]any{"command": *cmd, "description": "spike"})
		ev(w, "content_block_start", map[string]any{"index": 0, "content_block": map[string]any{"type": "tool_use", "id": "toolu_mock1", "name": "Bash", "input": map[string]any{}}})
		ev(w, "content_block_delta", map[string]any{"index": 0, "delta": map[string]any{"type": "input_json_delta", "partial_json": string(in)}})
		stop = "tool_use"
	} else {
		txt := "DONE " + last
		if !strings.Contains(raw, "SPIKE_RUN") {
			txt = "mock title"
		}
		ev(w, "content_block_start", map[string]any{"index": 0, "content_block": map[string]any{"type": "text", "text": ""}})
		ev(w, "content_block_delta", map[string]any{"index": 0, "delta": map[string]any{"type": "text_delta", "text": txt}})
	}
	ev(w, "content_block_stop", map[string]any{"index": 0})
	ev(w, "message_delta", map[string]any{"delta": map[string]any{"stop_reason": stop, "stop_sequence": nil}, "usage": map[string]any{"output_tokens": 1}})
	ev(w, "message_stop", map[string]any{})
}

func main() {
	flag.Parse()
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		panic(err)
	}
	fmt.Println(ln.Addr().String())
	http.Serve(ln, http.HandlerFunc(handle))
}
