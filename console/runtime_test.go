package main

import (
	"strings"
	"testing"
)

func TestRuntimeRevisionAndStableFingerprint(t *testing.T) {
	a := &app{runtime: func(string, string) (string, []string, error) {
		return "/trusted/codex", []string{"HARNESS_SETTINGS_REVISION=8", "A=value"}, nil
	}}
	p := resolvedPolicy{Provider: "codex", Revision: "7"}
	if _, _, _, err := a.resolveRuntime(p); err == nil {
		t.Fatal("stale settings accepted")
	}
	p.Revision = "8"
	_, _, first, err := a.resolveRuntime(p)
	if err != nil {
		t.Fatal(err)
	}
	a.runtime = func(string, string) (string, []string, error) {
		return "/trusted/codex", []string{"A=value", "HARNESS_SETTINGS_REVISION=9"}, nil
	}
	p.Revision = "9"
	_, _, second, err := a.resolveRuntime(p)
	if err != nil || first != second {
		t.Fatal("revision-only update changed runtime", err)
	}
}
func TestCoreCapabilityRedactedAcrossEverySplit(t *testing.T) {
	secret := "0123456789abcdef0123456789abcdef"
	for i := 1; i < len(secret); i++ {
		a := &app{newRedactor: func() streamRedactor { return plainStream{} }}
		a.rememberCapability(secret)
		f := a.streamFilter()
		out := f.Push("before "+secret[:i]) + f.Push(secret[i:]+" after") + f.Flush()
		if strings.Contains(out, secret) || out != "before [REDACTED] after" {
			t.Fatalf("split %d leaked: %q", i, out)
		}
	}
}
