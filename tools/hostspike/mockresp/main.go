// mockresp: scripted OpenAI Responses API stand-in for driving a real Codex binary with zero model cost.
// mockresp -addr 127.0.0.1:0 -script shell|mcp|subagent -cmd '<shell cmd>' -log <file>
// Turn 1 returns one tool call; later turns return a final assistant message echoing the last tool output.
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
	"sync"
)

var (
	script = flag.String("script", "shell", "")
	cmd    = flag.String("cmd", "true", "")
	logp   = flag.String("log", "mock.jsonl", "")
	addr   = flag.String("addr", "127.0.0.1:0", "")
	mu     sync.Mutex
	n      int
)

func logj(v any) {
	f, err := os.OpenFile(*logp, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	b, _ := json.Marshal(v)
	f.Write(append(b, '\n'))
	f.Close()
}

func send(w http.ResponseWriter, evs ...map[string]any) {
	w.Header().Set("Content-Type", "text/event-stream")
	for _, e := range evs {
		b, _ := json.Marshal(e)
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", e["type"], b)
	}
}

func created(id string) map[string]any {
	return map[string]any{"type": "response.created", "response": map[string]any{"id": id}}
}
func completed(id string) map[string]any {
	return map[string]any{"type": "response.completed", "response": map[string]any{"id": id, "usage": map[string]any{"input_tokens": 0, "output_tokens": 0, "total_tokens": 0}}}
}
func message(id, text string) map[string]any {
	return map[string]any{"type": "response.output_item.done", "item": map[string]any{"type": "message", "role": "assistant", "id": id, "content": []any{map[string]any{"type": "output_text", "text": text}}}}
}

func toolNames(tools []any) (names []string, ping map[string]any, agent map[string]any) {
	for _, t := range tools {
		m, _ := t.(map[string]any)
		name, _ := m["name"].(string)
		ns, _ := m["namespace"].(string)
		typ, _ := m["type"].(string)
		names = append(names, typ+":"+ns+"/"+name)
		if strings.Contains(name, "ping") && ping == nil && typ != "namespace" {
			ping = m
		}
		if sub, ok := m["tools"].([]any); ok { // namespace groups
			for _, s := range sub {
				sm, _ := s.(map[string]any)
				sn, _ := sm["name"].(string)
				names = append(names, typ+":"+name+"/"+sn)
				if strings.Contains(sn, "ping") && ping == nil {
					ping = map[string]any{"name": sn, "namespace": name}
				}
			}
		}
		if (strings.Contains(name, "spawn") || strings.Contains(name, "agent")) && agent == nil {
			agent = m
		}
	}
	return
}

func handle(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var req map[string]any
	json.Unmarshal(body, &req)
	mu.Lock()
	n++
	k := n
	mu.Unlock()
	tools, _ := req["tools"].([]any)
	names, ping, agent := toolNames(tools)
	input, _ := req["input"].([]any)
	var outputs []string
	hasOutput := false
	for _, it := range input {
		m, _ := it.(map[string]any)
		if t, _ := m["type"].(string); strings.HasSuffix(t, "_output") {
			hasOutput = true
			ob, _ := json.Marshal(m["output"])
			outputs = append(outputs, string(ob))
		}
	}
	logj(map[string]any{"n": k, "path": r.URL.Path, "tools": names, "has_output": hasOutput, "outputs": outputs, "agent_tool": agent})
	id := fmt.Sprintf("resp_%d", k)
	if *script == "subagent" {
		raw := string(body)
		if strings.Contains(raw, "SUBTASK_REPLY_OK") && !strings.Contains(raw, "spawn_agent\",\"arguments") && len(outputs) == 0 && !strings.Contains(raw, "PARENT_TASK") {
			send(w, created(id), message("msg_"+id, "OK"), completed(id))
			return
		}
		switch len(outputs) {
		case 0:
			a, _ := json.Marshal(map[string]any{"message": "SUBTASK_REPLY_OK: reply with exactly OK"})
			send(w, created(id), map[string]any{"type": "response.output_item.done", "item": map[string]any{"type": "function_call", "call_id": "call_" + id, "namespace": "multi_agent_v1", "name": "spawn_agent", "arguments": string(a)}}, completed(id))
		case 1:
			var o map[string]any
			var s string
			json.Unmarshal([]byte(outputs[0]), &s)
			json.Unmarshal([]byte(s), &o)
			aid, _ := o["agent_id"].(string)
			if aid == "" {
				aid, _ = o["id"].(string)
			}
			a, _ := json.Marshal(map[string]any{"targets": []string{aid}, "timeout_ms": 20000})
			send(w, created(id), map[string]any{"type": "response.output_item.done", "item": map[string]any{"type": "function_call", "call_id": "call_" + id, "namespace": "multi_agent_v1", "name": "wait_agent", "arguments": string(a)}}, completed(id))
		default:
			send(w, created(id), message("msg_"+id, "DONE "+outputs[len(outputs)-1]), completed(id))
		}
		return
	}
	if hasOutput {
		last := ""
		if len(outputs) > 0 {
			last = outputs[len(outputs)-1]
		}
		if len(last) > 300 {
			last = last[:300]
		}
		send(w, created(id), message("msg_"+id, "DONE tool_output="+last), completed(id))
		return
	}
	item := map[string]any{"type": "function_call", "call_id": "call_" + id}
	switch *script {
	case "shell":
		a, _ := json.Marshal(map[string]any{"cmd": *cmd})
		item["name"], item["arguments"] = "exec_command", string(a)
	case "mcp":
		if ping == nil {
			send(w, created(id), message("msg_"+id, "NO_PING_TOOL"), completed(id))
			return
		}
		item["name"], item["arguments"] = ping["name"], "{}"
		if ns, ok := ping["namespace"].(string); ok && ns != "" {
			item["namespace"] = ns
		}
	default:
		send(w, created(id), message("msg_"+id, "NOOP"), completed(id))
		return
	}
	send(w, created(id), map[string]any{"type": "response.output_item.done", "item": item}, completed(id))
}

func main() {
	flag.Parse()
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		panic(err)
	}
	fmt.Println(ln.Addr().String())
	os.Stdout.Sync()
	http.Serve(ln, http.HandlerFunc(handle))
}
