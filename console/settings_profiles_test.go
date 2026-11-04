package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSettingsDeletedEnvironmentRowRetiresScopedSecret(t *testing.T) {
	s, v := settingsTestStore(t)
	p := settingsTestProfile(t, s)
	next := settingsTestCopy(s)
	next.Environment = []settingsEnv{{ProfileID: p.ID, Name: "DATABASE_PASSWORD", Enabled: true}}
	if e := s.save(s.disk.Revision, next); e != nil {
		t.Fatal(e)
	}
	if e := s.writeSecret(context.Background(), s.disk.Revision, p.ID, p.Generation, "DATABASE_PASSWORD", "SYNTHETIC-ENV-SECRET", false); e != nil {
		t.Fatal(e)
	}
	next = settingsTestCopy(s)
	next.Environment = []settingsEnv{}
	if e := s.save(s.disk.Revision, next); e != nil {
		t.Fatal(e)
	}
	if len(v.items) != 0 || len(s.disk.Refs) != 0 {
		t.Fatal("deleted environment row retained unreachable credential reference")
	}
}
func TestSettingsDefaultProfileAndVersionControls(t *testing.T) {
	s, _ := settingsTestStore(t)
	next := settingsTestCopy(s)
	next.Defaults.Provider = "claude"
	if e := s.save(s.disk.Revision, next); e == nil {
		t.Fatal("mismatched default profile accepted")
	}
	for _, v := range []string{"codex-cli 0.165.0", "unknown", "codex-cli 1.0.0"} {
		if settingsCodexVersionSafe(v) {
			t.Fatal("unqualified native keyring version accepted", v)
		}
	}
	if !settingsCodexVersionSafe("codex-cli 0.166.0-alpha.5.1") || settingsClaudeVersionSafe("2.1.315 (Claude Code)") || !settingsClaudeVersionSafe("2.1.316 (Claude Code)") {
		t.Fatal("qualified version boundary wrong")
	}
}
func TestSettingsProfilePayloadIsolationAndEditedRoleBarrier(t *testing.T) {
	s, _ := settingsTestStore(t)
	home := filepath.Join(s.dir, "synthetic-home")
	for relative, content := range map[string]string{".codex/AGENTS.md": "synthetic user guidance\n", ".codex/agents/harness_owner.toml": "model = \"gpt-6.1-sol\"\n", ".codex/skills/agent-harness/SKILL.md": "synthetic reviewed skill\n", ".codex/auth.json": "SYNTHETIC-AUTH-DO-NOT-COPY", ".codex/sessions/private.jsonl": "SYNTHETIC-SESSION-DO-NOT-COPY"} {
		path := filepath.Join(home, relative)
		if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
			t.Fatal(e)
		}
		if e := os.WriteFile(path, []byte(content), 0600); e != nil {
			t.Fatal(e)
		}
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	p := settingsTestProfile(t, s)
	root, e := s.profileHome(p)
	if e != nil {
		t.Fatal(e)
	}
	guide, _ := os.ReadFile(filepath.Join(root, "AGENTS.md"))
	config, _ := os.ReadFile(filepath.Join(root, "config.toml"))
	if !strings.Contains(string(guide), "synthetic user guidance") || !strings.Contains(string(guide), consoleHarnessInstructions) || !strings.Contains(string(config), "[agents.harness_owner]") {
		t.Fatal("effective guidance or role config missing")
	}
	for _, name := range []string{"auth.json", "sessions"} {
		if _, e := os.Lstat(filepath.Join(root, name)); !os.IsNotExist(e) {
			t.Fatal("unrelated auth/session storage copied", name)
		}
	}
	q := settingsTestProfile(t, s)
	second, e := s.profileHome(q)
	if e != nil || second == root {
		t.Fatal("profile homes not independent")
	}
	role := filepath.Join(root, "agents", "harness_owner.toml")
	if e := os.WriteFile(role, []byte("user-edited role\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = s.profileHome(p); e == nil {
		t.Fatal("edited role silently overwritten or accepted")
	}
	data, _ := os.ReadFile(role)
	if string(data) != "user-edited role\n" {
		t.Fatal("user role edits overwritten")
	}
}
