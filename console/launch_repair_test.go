package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestRepairLaunchTicketExcludesSecretsAndPreservesProfile(t *testing.T) {
	a, s, _ := checkpointFixture(t)
	a.runtime = func(provider, profile string) (string, []string, error) {
		if profile != "managed-profile" {
			t.Fatalf("profile dropped: %q", profile)
		}
		return "/trusted/cli", []string{"API_KEY_TEST=synthetic-secret", "HARNESS_SETTINGS_REVISION=4"}, nil
	}
	a.resolvePolicy = func(provider, profile, stage string) (resolvedPolicy, error) {
		return resolvedPolicy{Provider: provider, ProfileID: profile, Revision: "4"}, nil
	}
	binary, args, err := a.prepareCLILaunch("codex", "managed-profile", s.CWD)
	if err != nil {
		t.Fatal(err)
	}
	if binary == "/trusted/cli" {
		t.Fatal("terminal bypassed profile-resolving helper")
	}
	data, err := os.ReadFile(args[2])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data)+strings.Join(args, " "), "synthetic-secret") {
		t.Fatal("secret persisted in metadata/argv")
	}
	ticket, err := loadCLILaunchTicket(args[2], args[4])
	if err != nil || ticket.Profile != "managed-profile" {
		t.Fatal("ticket lost account", err)
	}
	exe, _ := os.Executable()
	var out bytes.Buffer
	err = executeCLILaunch(ticket, exe, []string{"HARNESS_CONSOLE_CLI_FIXTURE=1", "PROFILE_TEST_MARKER=managed-home", "API_KEY_TEST=synthetic-secret"}, strings.NewReader(""), &out, &out)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]string
	if json.Unmarshal(out.Bytes(), &got) != nil || got["profile"] != "managed-home" || got["secret"] != "synthetic-secret" {
		t.Fatal("actual child lost resolved environment")
	}
}
func TestRepairTranscriptAPIUsesSecretRedaction(t *testing.T) {
	a, s, _ := checkpointFixture(t)
	binary, _ := os.Executable()
	c, err := startRPC(binary, append(os.Environ(), "HARNESS_CONSOLE_RPC_FIXTURE=1"), nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.close()
	s.codex = c
	s.Agents = append(s.Agents, agent{ID: "owned-child"})
	a.redact = func(text string) string { return strings.ReplaceAll(text, "HARNESS_SENTINEL_SECRET", "[REDACTED]") }
	request := httptest.NewRequest("GET", "http://127.0.0.1:1234/api/sessions/"+s.ID+"/agents/owned-child/messages", nil)
	request.Header.Set("Authorization", "Bearer gui")
	response := httptest.NewRecorder()
	a.handler("127.0.0.1:1234", "gui").ServeHTTP(response, request)
	if response.Code != 200 || strings.Contains(response.Body.String(), "HARNESS_SENTINEL_SECRET") || !strings.Contains(response.Body.String(), "[REDACTED]") {
		t.Fatal("native transcript bypassed redaction", response.Body.String())
	}
}
func TestRepairLaunchHTTPResolvesSelectedAccount(t *testing.T) {
	a, s, _ := checkpointFixture(t)
	s.ProfileID = "managed-account"
	seen := ""
	a.resolvePolicy = func(provider, profile, stage string) (resolvedPolicy, error) {
		return resolvedPolicy{Provider: provider, ProfileID: profile, Revision: "builtin-v1"}, nil
	}
	a.runtime = func(provider, profile string) (string, []string, error) {
		seen = profile
		return "", nil, errors.New("controlled missing executable prevents OS launch")
	}
	request := httptest.NewRequest("POST", "http://127.0.0.1:1234/api/launch", strings.NewReader(`{"sessionId":"`+s.ID+`","provider":"codex"}`))
	request.Header.Set("Authorization", "Bearer gui")
	request.Header.Set("Origin", "http://127.0.0.1:1234")
	response := httptest.NewRecorder()
	a.handler("127.0.0.1:1234", "gui").ServeHTTP(response, request)
	if seen != "managed-account" {
		t.Fatalf("selected account dropped: %q", seen)
	}
}
