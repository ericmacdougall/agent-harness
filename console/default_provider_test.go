package main

import (
	"os"
	"testing"
)

func TestSavedDefaultProviderAndExplicitProviderOverride(t *testing.T) {
	settings, _ := settingsTestStore(t)
	next := settingsTestCopy(settings)
	next.Defaults.Provider = "claude"
	next.Defaults.ProfileID = "global-claude"
	next.Defaults.Model = "claude-fixture-model"
	next.Defaults.Effort = "low"
	if err := settings.save(settings.disk.Revision, next); err != nil {
		t.Fatal(err)
	}
	a := testApp(t)
	a.resolvePolicy = settings.policy
	binary, _ := os.Executable()
	a.runtime = func(provider, profile string) (string, []string, error) {
		return binary, append(os.Environ(), "HARNESS_CONSOLE_RPC_FIXTURE=1", "HARNESS_SETTINGS_REVISION="+settingsRevision(settings.disk.Revision)), nil
	}
	cwd, err := validCWD(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	selected, err := a.createSession("", cwd, "")
	if err != nil {
		t.Fatal(err)
	}
	if selected.Provider != "claude" || selected.ProfileID != "global-claude" || selected.Model != "claude-fixture-model" || selected.Effort != "low" {
		t.Fatalf("saved default not consumed: provider=%s profile=%s model=%s effort=%s", selected.Provider, selected.ProfileID, selected.Model, selected.Effort)
	}
	explicit, err := a.createSession("codex", cwd, "")
	if err != nil {
		t.Fatal(err)
	}
	if explicit.Provider != "codex" || explicit.ProfileID != "global-codex" || explicit.Model == "claude-fixture-model" {
		t.Fatalf("explicit provider did not win: provider=%s profile=%s model=%s", explicit.Provider, explicit.ProfileID, explicit.Model)
	}
}
