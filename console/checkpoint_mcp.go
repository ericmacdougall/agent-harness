package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"
)

func runCheckpointMCP(input io.Reader, output io.Writer) error {
	endpoint := os.Getenv("HARNESS_CHECKPOINT_ENDPOINT")
	token := os.Getenv("HARNESS_CHECKPOINT_CAPABILITY")
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "http" || parsed.Hostname() != "127.0.0.1" || parsed.Path != "/checkpoint" || len(token) != 32 {
		return errors.New("checkpoint helper requires scoped local admission")
	}
	client := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}
	scan := bufio.NewScanner(input)
	scan.Buffer(make([]byte, 4096), 65536)
	encoder := json.NewEncoder(output)
	for scan.Scan() {
		var packet rpcPacket
		if json.Unmarshal(scan.Bytes(), &packet) != nil {
			return errors.New("invalid MCP frame")
		}
		if len(packet.ID) == 0 {
			continue
		}
		var result any
		var failure string
		switch packet.Method {
		case "initialize":
			result = map[string]any{"protocolVersion": "2024-11-05", "capabilities": map[string]any{"tools": map[string]any{}}, "serverInfo": map[string]any{"name": "agent-harness-checkpoint", "version": version}}
		case "ping":
			result = map[string]any{}
		case "tools/list":
			tool := checkpointTool()
			result = map[string]any{"tools": []any{map[string]any{"name": tool["name"], "description": tool["description"], "inputSchema": tool["inputSchema"]}}}
		case "tools/call":
			params := object(packet.Params)
			if textField(params, "name") != "harness_console_checkpoint" {
				failure = "unknown checkpoint tool"
				break
			}
			body, err := json.Marshal(params["arguments"])
			if err != nil {
				failure = "invalid arguments"
				break
			}
			req, err := http.NewRequest("POST", endpoint, bytes.NewReader(body))
			if err != nil {
				failure = "request refused"
				break
			}
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")
			response, err := client.Do(req)
			if err != nil {
				failure = "checkpoint outcome unknown; do not replay"
				break
			}
			data, readErr := io.ReadAll(io.LimitReader(response.Body, 8193))
			response.Body.Close()
			if readErr != nil || len(data) > 8192 {
				failure = "response invalid"
				break
			}
			if response.StatusCode != 200 {
				failure = "checkpoint refused: " + string(data)
				break
			}
			result = map[string]any{"content": []any{map[string]any{"type": "text", "text": string(data)}}}
		default:
			failure = "unsupported MCP method"
		}
		response := map[string]any{"jsonrpc": "2.0", "id": packet.ID}
		if failure != "" {
			response["error"] = map[string]any{"code": -32602, "message": failure}
		} else {
			response["result"] = result
		}
		if err = encoder.Encode(response); err != nil {
			return err
		}
	}
	return scan.Err()
}
func (a *app) checkpointHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method refused", 405)
		return
	}
	a.mu.Lock()
	id := ""
	for _, s := range a.sessions {
		if s.task != nil && s.Provider == "claude" && r.Header.Get("Authorization") == "Bearer "+s.task.capability && s.Status == "running" {
			id = s.ID
			break
		}
	}
	a.mu.Unlock()
	if id == "" {
		http.Error(w, "scoped admission required", 401)
		return
	}
	var input checkpointInput
	if err := decodeJSON(w, r, &input); err != nil {
		http.Error(w, "invalid checkpoint", 400)
		return
	}
	if err := a.checkpointUpdate(id, input); err != nil {
		http.Error(w, a.clean(err.Error()), 409)
		return
	}
	writeJSON(w, 200, map[string]any{"recorded": true, "note": "End turn after needs_review; independent review runs next"})
}
func (a *app) checkpointConfig(s *session) (string, []string, error) {
	binary, err := os.Executable()
	if err != nil {
		return "", nil, err
	}
	directory := a.dataDir + string(os.PathSeparator) + "checkpoint-mcp"
	if err = os.MkdirAll(directory, 0700); err != nil {
		return "", nil, err
	}
	path := directory + string(os.PathSeparator) + s.ID + ".json"
	data, err := json.Marshal(map[string]any{"mcpServers": map[string]any{checkpointMCPName(s.ID): map[string]any{"type": "stdio", "command": binary, "args": []string{"--checkpoint-mcp"}}}})
	if err != nil {
		return "", nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if os.IsExist(err) {
		if err = os.Remove(path); err != nil {
			return "", nil, err
		}
		file, err = os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	}
	if err != nil {
		return "", nil, err
	}
	_, err = file.Write(data)
	file.Close()
	if err != nil {
		return "", nil, err
	}
	return path, []string{"HARNESS_CHECKPOINT_ENDPOINT=" + a.origin + "/checkpoint", "HARNESS_CHECKPOINT_CAPABILITY=" + s.task.capability}, nil
}

func checkpointMCPName(id string) string {
	if len(id) > 24 {
		id = id[:24]
	}
	return "ahc_" + id
}
