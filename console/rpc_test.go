package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	if os.Getenv("HARNESS_CONSOLE_LIFECYCLE_FIXTURE") != "" {
		claudeLifecycleProcess()
		os.Exit(0)
	}
	if os.Getenv("HARNESS_CONSOLE_IDENTITY_FIXTURE") == "1" {
		scan := bufio.NewScanner(os.Stdin)
		for scan.Scan() {
			var frame map[string]any
			_ = json.Unmarshal(scan.Bytes(), &frame)
			_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"type": "system", "session_id": frame["session_id"]})
			if textField(mapField(frame, "message"), "content") == "request-B" {
				deadline := time.Now().Add(10 * time.Second)
				for time.Now().Before(deadline) {
					if _, err := os.Stat(os.Getenv("HARNESS_CONSOLE_IDENTITY_GATE")); err == nil {
						break
					}
					time.Sleep(5 * time.Millisecond)
				}
			}
			_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"type": "result", "result": "identity fixture complete"})
		}
		os.Exit(0)
	}
	if len(os.Args) > 2 && os.Args[1] == "mcp" && os.Args[2] == "list" && os.Getenv("HARNESS_CONSOLE_RPC_FIXTURE") == "1" {
		value := os.Getenv("HARNESS_CONSOLE_MCP_LIST_JSON")
		if value == "" {
			value = "[]"
		}
		fmt.Fprintln(os.Stdout, value)
		if audit := os.Getenv("HARNESS_CONSOLE_MCP_AUDIT"); audit != "" {
			cwd, _ := os.Getwd()
			data, _ := json.Marshal(map[string]string{"cwd": cwd, "configHome": os.Getenv("CODEX_HOME")})
			_ = os.WriteFile(audit, data, 0600)
		}
		os.Exit(0)
	}
	if os.Getenv("HARNESS_CONSOLE_CLAUDE_QUEUE_FIXTURE") == "1" {
		scan := bufio.NewScanner(os.Stdin)
		frames := 0
		for scan.Scan() {
			frames++
			if path := os.Getenv("HARNESS_CONSOLE_CLAUDE_QUEUE_AUDIT"); path != "" {
				file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
				if err != nil {
					os.Exit(3)
				}
				record, _ := json.Marshal(map[string]any{"frame": json.RawMessage(scan.Bytes()), "args": os.Args})
				_, _ = file.Write(append(record, '\n'))
				file.Close()
			}
			var frame map[string]any
			_ = json.Unmarshal(scan.Bytes(), &frame)
			_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"type": "system", "session_id": frame["session_id"]})
			if frames == 1 && os.Getenv("HARNESS_CONSOLE_CLAUDE_QUEUE_GATE") != "" {
				deadline := time.Now().Add(3 * time.Second)
				for time.Now().Before(deadline) {
					if _, err := os.Stat(os.Getenv("HARNESS_CONSOLE_CLAUDE_QUEUE_GATE")); err == nil {
						break
					}
					time.Sleep(5 * time.Millisecond)
				}
			}
			_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"type": "result", "result": "queue fixture result", "is_error": false})
		}
		os.Exit(0)
	}
	if os.Getenv("HARNESS_CONSOLE_CLAUDE_FIXTURE") == "1" {
		if audit := os.Getenv("HARNESS_CONSOLE_CLAUDE_AUDIT"); audit != "" {
			data, _ := json.Marshal(os.Args)
			_ = os.WriteFile(audit, data, 0600)
		}
		scan := bufio.NewScanner(os.Stdin)
		if scan.Scan() {
			_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"type": "result", "result": "fixture result", "is_error": false})
		}
		os.Exit(0)
	}

	if os.Getenv("HARNESS_CONSOLE_CLI_FIXTURE") == "1" {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]string{"profile": os.Getenv("PROFILE_TEST_MARKER"), "secret": os.Getenv("API_KEY_TEST")})
		os.Exit(0)
	}
	if os.Getenv("HARNESS_CONSOLE_RPC_FIXTURE") == "1" {
		serial := 0
		scan := bufio.NewScanner(os.Stdin)
		for scan.Scan() {
			var p rpcPacket
			if json.Unmarshal(scan.Bytes(), &p) != nil {
				os.Exit(2)
			}
			if path := os.Getenv("HARNESS_CONSOLE_RPC_AUDIT"); path != "" {
				f, e := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
				if e != nil {
					os.Exit(3)
				}
				_ = json.NewEncoder(f).Encode(p)
				f.Close()
			}
			if len(p.ID) == 0 {
				continue
			}
			switch p.Method {
			case "initialize":
				_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"id": p.ID, "result": map[string]any{}})
			case "thread/start":
				serial++
				_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"id": p.ID, "result": map[string]any{"thread": map[string]any{"id": fmt.Sprintf("fixture-%d-%d", os.Getpid(), serial)}}})
			case "turn/start":
				if os.Getenv("HARNESS_CONSOLE_RPC_FAIL_TURN") == "disconnect" {
					os.Exit(0)
				}
				if reason := os.Getenv("HARNESS_CONSOLE_RPC_FAIL_TURN"); reason != "" {
					_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"id": p.ID, "error": map[string]any{"code": -32000, "message": reason}})
				} else {
					_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"id": p.ID, "result": map[string]any{"turn": map[string]any{"id": "fixture-turn"}}})
				}
			case "final":
				_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"id": p.ID, "result": map[string]any{"value": "drained"}})
				os.Exit(0)
			case "reject":
				_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"id": p.ID, "error": map[string]any{"code": -32602, "message": "controlled rejection"}})
			case "thread/items/list":
				_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"id": p.ID, "result": map[string]any{"data": []any{map[string]any{"item": map[string]any{"id": "text", "type": "agentMessage", "text": "HARNESS_SENTINEL_SECRET"}}}}})
			case "silence":
			default:
				_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"id": p.ID, "result": map[string]any{"value": "echo"}})
			}
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}
func TestRPCDrainsFinalResponseBeforeProcessExit(t *testing.T) {
	binary, _ := os.Executable()
	for i := 0; i < 12; i++ {
		c, err := startRPC(binary, append(os.Environ(), "HARNESS_CONSOLE_RPC_FIXTURE=1"), nil, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		var out struct{ Value string }
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		err = c.call(ctx, "final", nil, &out)
		cancel()
		c.close()
		if err != nil || out.Value != "drained" {
			t.Fatalf("final response lost: %v %q", err, out.Value)
		}
	}
}
func TestRPCDeadlineReleasesRequestSlot(t *testing.T) {
	binary, _ := os.Executable()
	c, err := startRPC(binary, append(os.Environ(), "HARNESS_CONSOLE_RPC_FIXTURE=1"), nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if c.call(ctx, "silence", nil, nil) == nil {
		t.Fatal("missing response accepted")
	}
	c.mu.Lock()
	n := len(c.pending)
	c.mu.Unlock()
	if n != 0 {
		t.Fatalf("leaked pending requests: %d", n)
	}
}
