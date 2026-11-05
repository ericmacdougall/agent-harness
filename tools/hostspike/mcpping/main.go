// mcpping: minimal stdio MCP server with one tool "ping" that returns "pong". Logs calls to $MCPPING_LOG.
package main

import (
	"bufio"
	"encoding/json"
	"os"
	"time"
)

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 1<<24)
	out := json.NewEncoder(os.Stdout)
	for in.Scan() {
		var req map[string]any
		if json.Unmarshal(in.Bytes(), &req) != nil {
			continue
		}
		id, hasID := req["id"]
		method, _ := req["method"].(string)
		if !hasID {
			continue
		}
		var result any
		switch method {
		case "initialize":
			pv := "2025-06-18"
			if p, ok := req["params"].(map[string]any); ok {
				if v, ok := p["protocolVersion"].(string); ok {
					pv = v
				}
			}
			result = map[string]any{"protocolVersion": pv, "capabilities": map[string]any{"tools": map[string]any{}},
				"serverInfo": map[string]any{"name": "mcpping", "version": "0.1"}}
		case "tools/list":
			result = map[string]any{"tools": []any{map[string]any{"name": "ping", "description": "Returns pong. Call it when asked to ping.",
				"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}}}}}
		case "tools/call":
			if p := os.Getenv("MCPPING_LOG"); p != "" {
				if f, err := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
					f.WriteString(time.Now().UTC().Format(time.RFC3339Nano) + " tools/call ping\n")
					f.Close()
				}
			}
			result = map[string]any{"content": []any{map[string]any{"type": "text", "text": "pong"}}}
		default:
			out.Encode(map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": -32601, "message": "method not found"}})
			continue
		}
		out.Encode(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
	}
}
