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
	testPanic = true
	defer func() { testPanic = false }()
	cases := []struct {
		args []string
		want int
	}{
		{[]string{"deliver", "prepare"}, 1},
		{[]string{"commit-policy", "hook"}, 2},
		{[]string{"wal", "pretool"}, 2},
		{[]string{"command-guard", "hook"}, 2},
		{[]string{"wal", "--verbose", "prompt"}, 2},
		{[]string{"wal", "session"}, 1},
	}
	for _, c := range cases {
		var out, errb bytes.Buffer
		argv := append([]string{"--host", "codex", "--config-dir", cfgDir()}, c.args...)
		if got := run(argv, &out, &errb); got != c.want || out.Len() != 0 {
			t.Errorf("%v: exit %d (want %d) stdout %q", c.args, got, c.want, out.String())
		}
	}
}

func TestGateTable(t *testing.T) {
	for sub, verbs := range map[string][]string{"command-guard": {"hook"}, "commit-policy": {"hook"}, "spec-flow": {"hook"}, "wal": {"hook", "prompt", "pretool"}} {
		for _, v := range verbs {
			if !isGate(sub, []string{v}) {
				t.Errorf("%s %s is not a gate", sub, v)
			}
		}
	}
	for _, args := range [][]string{{"wal", "session"}, {"wal", "subagent"}, {"commit-policy", "check-message"}, {"deliver", "hook"}} {
		if isGate(args[0], args[1:]) {
			t.Errorf("%v must not be a gate", args)
		}
	}
}

func TestUnportedWalGatesBlock(t *testing.T) {
	for _, verb := range []string{"hook", "prompt", "pretool"} {
		var out, errb bytes.Buffer
		if c := run([]string{"--host", "claude", "--config-dir", cfgDir(), "wal", verb}, &out, &errb); c != 2 {
			t.Errorf("wal %s: exit %d", verb, c)
		}
	}
}

func cfgDir() string { return filepath.Join(os.TempDir(), "harness-cfg") }
