package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGoodQAAdmissionNamespaceIsStableBoundAndUsedByBothClients(t *testing.T) {
	s, _, _, _ := goodqaTestSetup(t)
	p, err := s.policy("codex", "global-codex", "main")
	if err != nil {
		t.Fatal(err)
	}
	config, err := validateMCPConfig(p.MCPConfigPath, p.MCPConfigSHA256)
	if err != nil {
		t.Fatal(err)
	}
	var name string
	var server stdioMCPServer
	for n, v := range config.Servers {
		name, server = n, v
	}
	want := "agent_harness_goodqa_" + server.Args[4][:24]
	if name != want {
		t.Fatalf("admission-specific server name absent: %q", name)
	}
	args, err := codexMCPArgs(p.MCPConfigPath, p.MCPConfigSHA256)
	if err != nil || !strings.Contains(strings.Join(args, " "), "mcp_servers."+name+".command=") {
		t.Fatal("Codex did not use admitted namespace")
	}
	again, err := s.policy("codex", "global-codex", "main")
	if err != nil || again.MCPConfigSHA256 != p.MCPConfigSHA256 {
		t.Fatal("unchanged admission changed runtime fingerprint")
	}
	delete(config.Servers, name)
	config.Servers["agent_harness_goodqa_000000000000000000000000"] = server
	data, _ := json.Marshal(config)
	path := filepath.Join(s.dir, "mcp", "forged-namespace.json")
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = validateMCPConfig(path, settingsDigest(data)); err == nil {
		t.Fatal("foreign namespace accepted for admitted helper")
	}
	other, err := s.policy("claude", "global-claude", "main")
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := validateMCPConfig(other.MCPConfigPath, other.MCPConfigSHA256)
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := foreign.Servers[name]; exists {
		t.Fatal("different profile reused admission namespace")
	}
}
