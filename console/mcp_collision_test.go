package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNativeClaudeMCPPreservesForeignToolsAndRefusesExactCollision(t *testing.T) {
	home := t.TempDir()
	config := filepath.Join(home, ".claude")
	cwd := filepath.Join(home, "project")
	system := filepath.Join(home, "system")
	for _, path := range []string{config, cwd, system} {
		_ = os.MkdirAll(path, 0700)
	}
	path := filepath.Join(home, ".claude.json")
	data := []byte(`{"mcpServers":{"browser":{"command":"never-run"}},"projects":{}}`)
	_ = os.WriteFile(path, data, 0600)
	name := "agent_harness_checkpoint_0123456789abcdef0123456789abcdef"
	if err := guardClaudeMCPFiles(home, config, cwd, system, []string{name}); err != nil {
		t.Fatal("unrelated native tools rejected", err)
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(data) {
		t.Fatal("native configuration modified")
	}
	collision, _ := json.Marshal(map[string]any{"mcpServers": map[string]any{name: map[string]any{"command": "do-not-execute"}}})
	_ = os.WriteFile(filepath.Join(cwd, ".mcp.json"), collision, 0600)
	if err := guardClaudeMCPFiles(home, config, cwd, system, []string{name}); err == nil {
		t.Fatal("exact project collision accepted")
	}
	_ = os.Remove(filepath.Join(cwd, ".mcp.json"))
	_ = os.WriteFile(filepath.Join(system, "managed-mcp.json"), []byte(`{"mcpServers":{}}`), 0600)
	if err := guardClaudeMCPFiles(home, config, cwd, system, []string{name}); err == nil {
		t.Fatal("exclusive native managed MCP ignored")
	}
}
func TestNativeCodexMCPUsesActualCWDAndAuthHomeWithoutExposingMetadata(t *testing.T) {
	binary, _ := os.Executable()
	cwd, _ := filepath.EvalSymlinks(t.TempDir())
	config := t.TempDir()
	audit := filepath.Join(t.TempDir(), "audit.json")
	env := append(os.Environ(), "HARNESS_CONSOLE_RPC_FIXTURE=1", "CODEX_HOME="+config, "HARNESS_CONSOLE_MCP_AUDIT="+audit, "HARNESS_CONSOLE_MCP_LIST_JSON=[{\"name\":\"foreign-browser\"}]")
	if err := guardCodexMCP(binary, env, cwd, []string{"app-helper"}); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(audit)
	var seen map[string]string
	_ = json.Unmarshal(data, &seen)
	if seen["cwd"] != cwd || seen["configHome"] != config {
		t.Fatal("native metadata probe used wrong context", seen)
	}
	env = append(env, "HARNESS_CONSOLE_MCP_LIST_JSON=[{\"name\":\"app-helper\",\"token\":\"synthetic-secret\"}]")
	if err := guardCodexMCP(binary, env, cwd, []string{"app-helper"}); err == nil || strings.Contains(err.Error(), "synthetic-secret") {
		t.Fatal("collision accepted or raw metadata leaked", err)
	}
}
func TestClaudeLaunchPreservesNativeToolsAndRefreshesTaskSystemContext(t *testing.T) {
	a, s, _ := checkpointFixture(t)
	binary, _ := os.Executable()
	home := t.TempDir()
	audit := filepath.Join(t.TempDir(), "argv.json")
	s.Provider = "claude"
	s.ProviderID = newUUID()
	s.policy, _ = defaultPolicy("claude", "", "main")
	s.Status = "running"
	s.Supervision.State = "active"
	s.lastRequest = "request"
	s.requests["request"] = "intent"
	a.runtime = func(string, string) (string, []string, error) {
		return binary, []string{"HOME=" + home, "HARNESS_CONSOLE_CLAUDE_FIXTURE=1", "HARNESS_CONSOLE_CLAUDE_AUDIT=" + audit}, nil
	}
	if err := a.sendClaude(s, "request", "bounded fixture", s.CWD, ""); err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	run := s.claude
	a.mu.Unlock()
	if run != nil {
		select {
		case <-run.done:
		case <-time.After(2 * time.Second):
			t.Fatal("fixture did not finish")
		}
	}
	data, err := os.ReadFile(audit)
	if err != nil {
		t.Fatal(err)
	}
	var args []string
	_ = json.Unmarshal(data, &args)
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "--system-prompt-snapshot off") || strings.Contains(joined, "--strict-mcp-config") || strings.Contains(joined, "--bare") {
		t.Fatal("native tools suppressed or updated task context ignored", args)
	}
}
func TestClaudeLaunchRefusesCollisionBeforeStartingForeignOrProviderProcess(t *testing.T) {
	a, s, _ := checkpointFixture(t)
	binary, _ := os.Executable()
	home := t.TempDir()
	audit := filepath.Join(t.TempDir(), "argv.json")
	s.Provider = "claude"
	s.ProviderID = newUUID()
	s.policy, _ = defaultPolicy("claude", "", "main")
	s.Status = "running"
	s.Supervision.State = "active"
	s.lastRequest = "request"
	s.requests["request"] = "intent"
	data, _ := json.Marshal(map[string]any{"mcpServers": map[string]any{checkpointMCPName(s.ID): map[string]any{"command": "never-execute-this-foreign-server"}}})
	_ = os.WriteFile(filepath.Join(home, ".claude.json"), data, 0600)
	a.runtime = func(string, string) (string, []string, error) {
		return binary, []string{"HOME=" + home, "HARNESS_CONSOLE_CLAUDE_FIXTURE=1", "HARNESS_CONSOLE_CLAUDE_AUDIT=" + audit}, nil
	}
	if err := a.sendClaude(s, "request", "bounded fixture", s.CWD, ""); err == nil {
		t.Fatal("native helper collision admitted")
	}
	if _, err := os.Stat(audit); !os.IsNotExist(err) {
		t.Fatal("provider process started despite collision")
	}
}
