package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSettingsPlainEnvironmentOnePreservesIDsAndUsesNoVault(t *testing.T) {
	s, v := settingsTestStore(t)
	next := settingsTestCopy(s)
	next.Environment = []settingsEnv{{ProfileID: "global-codex", Name: "FEATURE_ENABLED", Enabled: true, Sensitive: settingsBool(false), Value: "1"}}
	if e := s.save(s.disk.Revision, next); e != nil {
		t.Fatal(e)
	}
	bin := filepath.Join(s.dir, "bin")
	_ = os.Mkdir(bin, 0700)
	name := "codex"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	if e := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\nexit 0\n"), 0700); e != nil {
		t.Fatal(e)
	}
	t.Setenv("PATH", bin)
	_, env, e := s.runtime("codex", "global-codex")
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, item := range env {
		if item == "FEATURE_ENABLED=1" {
			found = true
		}
	}
	if !found || len(v.items) != 0 {
		t.Fatal("plain flag not injected directly or entered vault")
	}
	text := "id-12345 model gpt-6.1-sol"
	if s.redact(text) != text {
		t.Fatal("plain flag garbled IDs or model names")
	}
	raw, _ := json.Marshal(s.envelope())
	if !strings.Contains(string(raw), `"value":"1"`) {
		t.Fatal("explicit plain value absent from readback")
	}
}
func TestSettingsSensitiveDefaultRejectsShortAndNeverMigratesPlaintext(t *testing.T) {
	s, v := settingsTestStore(t)
	next := settingsTestCopy(s)
	next.Environment = []settingsEnv{{ProfileID: "global-codex", Name: "APP_FLAG", Enabled: true}}
	if e := s.save(s.disk.Revision, next); e != nil {
		t.Fatal(e)
	}
	p, _ := s.profileLocked("global-codex")
	if !s.disk.Settings.Environment[0].isSensitive() {
		t.Fatal("legacy sensitivity defaulted plain")
	}
	if e := s.writeSecret(context.Background(), s.disk.Revision, p.ID, p.Generation, "APP_FLAG", "1", false); e == nil || !strings.Contains(e.Error(), "8–8192") {
		t.Fatal("short sensitive value not clearly rejected")
	}
	if len(v.items) != 0 {
		t.Fatal("rejected short value touched vault")
	}
	secret := "SYNTHETIC-LONG-PRIVATE-VALUE"
	if e := s.writeSecret(context.Background(), s.disk.Revision, p.ID, p.Generation, "APP_FLAG", secret, false); e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(s.envelope())
	if strings.Contains(string(raw), secret) || !strings.Contains(string(raw), `"sensitive":true`) {
		t.Fatal("legacy secret readback unsafe")
	}
	next = settingsTestCopy(s)
	next.Environment[0].Sensitive = settingsBool(false)
	next.Environment[0].Value = "1"
	if e := s.save(s.disk.Revision, next); e != nil {
		t.Fatal(e)
	}
	raw, _ = os.ReadFile(filepath.Join(s.dir, "settings.json"))
	if strings.Contains(string(raw), secret) || len(v.items) != 0 || len(s.disk.Refs) != 0 {
		t.Fatal("conversion migrated vault plaintext or retained unreachable item")
	}
}
func TestSettingsCredentialLikeNamesCannotOptOutOfVault(t *testing.T) {
	s, _ := settingsTestStore(t)
	for _, name := range []string{"DATABASE_PASSWORD", "CUSTOM_TOKEN", "API_KEY", "AUTHORIZATION", "COOKIE", "PRIVATE_KEY", "DATABASE_URL", "SERVICE_DSN"} {
		next := settingsTestCopy(s)
		next.Environment = []settingsEnv{{ProfileID: "global-codex", Name: name, Sensitive: settingsBool(false), Value: "1"}}
		if e := s.save(s.disk.Revision, next); e == nil {
			t.Fatal("credential-like name allowed plaintext", name)
		}
	}
	if !safeEnvName("ENVIRONMENT") {
		t.Fatal("non-reserved name blocked by ENV prefix")
	}
}
