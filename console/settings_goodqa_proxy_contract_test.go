package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func goodqaTestInput() string {
	return `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{"sampling":{}}}}` + "\n" + `{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n" + `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}` + "\n" + `{"jsonrpc":"2.0","id":3,"method":"roots/list","params":{}}` + "\n" + `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"safe_read","arguments":{"nonce":"positive-control"}}}` + "\n" + `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"browser_delete","arguments":{}}}` + "\n" + `{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"hive_resume","arguments":{}}}` + "\n"
}
func goodqaAssertAllowlist(t *testing.T, text, logs string, f *goodqaTestServer) {
	t.Helper()
	if strings.Contains(text+logs, goodqaTestToken) {
		t.Fatal("helper bearer escaped in split network output")
	}
	lines := strings.Split(strings.TrimSpace(text), "\n")
	if len(lines) != 6 {
		t.Fatal("missing protocol responses", len(lines))
	}
	var catalog struct {
		Result struct {
			Tools []goodqaTool `json:"tools"`
		} `json:"result"`
	}
	if json.Unmarshal([]byte(lines[1]), &catalog) != nil || len(catalog.Result.Tools) != 1 || catalog.Result.Tools[0].Name != "safe_read" {
		t.Fatal("tool discovery exceeded exact allowlist")
	}
	if !strings.Contains(lines[3], "positive-control") || !strings.Contains(lines[4], "not explicitly allowed") || !strings.Contains(lines[5], "not explicitly allowed") {
		t.Fatal("positive result or denied controls missing")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.calls) != 1 || f.calls[0] != "safe_read" || f.nonce != "positive-control" {
		t.Fatal("denied tools reached upstream or positive control vacuous")
	}
}
func TestGoodQAProxyExactAllowlistAndSplitBearerFiltering(t *testing.T) {
	_, v, snapshot, f := goodqaTestSetup(t)
	var out, logs bytes.Buffer
	if e := serveGoodQAProxy(context.Background(), snapshot, v, strings.NewReader(goodqaTestInput()), &out, &logs); e != nil {
		t.Fatal(e)
	}
	goodqaAssertAllowlist(t, out.String(), logs.String(), f)
}

func TestGoodQAProxyDuplicateRequestIDIsNotReplayed(t *testing.T) {
	_, v, snapshot, f := goodqaTestSetup(t)
	replay := `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"safe_read","arguments":{"nonce":"replay"}}}` + "\n"
	var out, log bytes.Buffer
	if e := serveGoodQAProxy(context.Background(), snapshot, v, strings.NewReader(goodqaTestInput()+replay), &out, &log); e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(out.String(), "already consumed") {
		t.Fatal("duplicate identifier was not rejected")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.calls) != 1 {
		t.Fatal("duplicate call reached upstream")
	}
}

func TestGoodQAProxyActualStdioProcess(t *testing.T) {
	if path := os.Getenv("HARNESS_GOODQA_TEST_SNAPSHOT"); path != "" {
		snapshot, e := loadGoodQASnapshot(path, os.Getenv("HARNESS_GOODQA_TEST_SHA"))
		if e != nil {
			t.Fatal(e)
		}
		v := &settingsTestVault{items: map[string]string{snapshot.CredentialRef: goodqaTestToken}}
		if e = serveGoodQAProxy(context.Background(), snapshot, v, os.Stdin, os.Stdout, os.Stderr); e != nil {
			t.Fatal(e)
		}
		os.Exit(0)
	}
	_, _, snapshot, f := goodqaTestSetup(t)
	data, _ := json.Marshal(snapshot)
	path := filepath.Join(snapshot.DataDir, "mcp", "stdio-process.json")
	if e := settingsAtomicWrite(path, data); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestGoodQAProxyActualStdioProcess$")
	cmd.Env = append(os.Environ(), "HARNESS_GOODQA_TEST_SNAPSHOT="+path, "HARNESS_GOODQA_TEST_SHA="+settingsDigest(data))
	cmd.Stdin = strings.NewReader(goodqaTestInput())
	var out, logs bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &logs
	if e := cmd.Run(); e != nil {
		t.Fatal("stdio subprocess failed", e)
	}
	goodqaAssertAllowlist(t, out.String(), logs.String(), f)
}

func TestGoodQAProxyBothClientConfigsHaveNoBearer(t *testing.T) {
	s, _, snapshot, _ := goodqaTestSetup(t)
	for _, provider := range []string{"codex", "claude"} {
		policy, e := s.policy(provider, "global-"+provider, "main")
		if e != nil {
			t.Fatal(e)
		}
		config, e := validateMCPConfig(policy.MCPConfigPath, policy.MCPConfigSHA256)
		if e != nil {
			t.Fatal(e)
		}
		raw, _ := os.ReadFile(policy.MCPConfigPath)
		args, e := codexMCPArgs(policy.MCPConfigPath, policy.MCPConfigSHA256)
		if e != nil {
			t.Fatal(e)
		}
		if strings.Contains(string(raw)+strings.Join(args, " "), goodqaTestToken) || strings.Contains(string(raw), "Authorization") || strings.Contains(string(raw), "http") {
			t.Fatal("provider received upstream auth or direct transport")
		}
		var server stdioMCPServer
		for _, value := range config.Servers {
			server = value
		}
		if len(server.Args) != 5 || server.Args[0] != "--goodqa-proxy" {
			t.Fatal("normal stdio helper configuration absent")
		}
		admitted, e := loadGoodQASnapshot(server.Args[2], server.Args[4])
		if e != nil || admitted.ProfileID != "global-"+provider || admitted.Revision != snapshot.Revision {
			t.Fatal("provider profile authority not bound")
		}
	}
}
