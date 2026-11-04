package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVersionJSON(t *testing.T) {
	var out, errb bytes.Buffer
	if c := run([]string{"version", "--json"}, &out, &errb); c != 0 {
		t.Fatalf("exit %d: %s", c, errb.String())
	}
	var v map[string]any
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"version", "commit", "go", "binary_sha256"} {
		if _, ok := v[k]; !ok {
			t.Errorf("missing %s in %s", k, out.String())
		}
	}
}

func TestUnportedGateHookBlocks(t *testing.T) {
	for _, host := range []string{"claude", "codex", "cursor"} {
		var out, errb bytes.Buffer
		c := run([]string{"--host", host, "--config-dir", cfgDir(), "commit-policy", "hook"}, &out, &errb)
		if c != 2 || out.Len() != 0 || !strings.Contains(errb.String(), "refusing") {
			t.Errorf("%s: exit %d stdout %q stderr %q", host, c, out.String(), errb.String())
		}
	}
}

func TestUnportedHelperRefusesWithoutBlockCode(t *testing.T) {
	var out, errb bytes.Buffer
	if c := run([]string{"--host", "claude", "--config-dir", cfgDir(), "deliver", "prepare"}, &out, &errb); c != 3 {
		t.Fatalf("exit %d", c)
	}
}

func TestUsageErrorExit2(t *testing.T) {
	var out, errb bytes.Buffer
	if c := run([]string{"--host", "emacs", "--config-dir", "/x", "hook"}, &out, &errb); c != 2 || !strings.HasPrefix(errb.String(), "usage:") {
		t.Fatalf("exit %d stderr %q", c, errb.String())
	}
}

func TestPanicIsRecovered(t *testing.T) {
	t.Setenv("HARNESS_TEST_PANIC", "1")
	var out, errb bytes.Buffer
	if c := run([]string{"--host", "codex", "--config-dir", cfgDir(), "__panic_for_test"}, &out, &errb); c != 1 || out.Len() != 0 {
		t.Fatalf("exit %d stdout %q", c, out.String())
	}
}

func cfgDir() string { return filepath.Join(os.TempDir(), "harness-cfg") }
