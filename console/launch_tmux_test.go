package main

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func isolatedEnv(extra ...string) []string {
	env := []string{"TMUX=", "HARNESS_NO_TMUX=", "HARNESS_CLI_TMUX=", "HARNESS_CONSOLE_CLI_FIXTURE=", "HARNESS_CLI_TMUX_SESSION="}
	return append(env, extra...)
}

func TestTmuxLaunchArgsStartANamedSession(t *testing.T) {
	args := tmuxLaunchArgs("ah-cli-abc123", "/tmp/work", "/usr/bin/claude", "--resume")
	want := []string{"-u", "-L", "ah-cli-abc123", "new-session", "-c", "/tmp/work", "-s", "ah-cli-abc123", "--", "/usr/bin/claude", "--resume"}
	if strings.Join(args, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("got %#v want %#v", args, want)
	}
}

func TestTmuxSessionNameRejectsUnsafeOverrides(t *testing.T) {
	for _, bad := range []string{"", "has space", "has:colon", "has.dot", "has/slash", "newline\n", strings.Repeat("a", 65)} {
		if tmuxSessionNameOK(bad) {
			t.Fatalf("accepted unsafe name %q", bad)
		}
		name := tmuxSessionName(bad)
		if !strings.HasPrefix(name, "ah-cli-") || !tmuxSessionNameOK(name) {
			t.Fatalf("fallback for %q was %q", bad, name)
		}
	}
	if got := tmuxSessionName("ah-cli-ok_1"); got != "ah-cli-ok_1" {
		t.Fatalf("got %q", got)
	}
}

func TestCliTmuxWrapDefaultOnAndOptOut(t *testing.T) {
	look := func(string) (string, error) { return "/opt/homebrew/bin/tmux", nil }
	wrap, bin, session := cliTmuxWrap(isolatedEnv(), true, look)
	if !wrap || bin != "/opt/homebrew/bin/tmux" || !strings.HasPrefix(session, "ah-cli-") {
		t.Fatalf("default on: wrap=%v bin=%q session=%q", wrap, bin, session)
	}
	off := []struct {
		name     string
		env      []string
		terminal bool
		lookOK   bool
	}{
		{"not a tty", isolatedEnv(), false, true},
		{"fixture", isolatedEnv("HARNESS_CONSOLE_CLI_FIXTURE=1"), true, true},
		{"disabled", isolatedEnv("HARNESS_CLI_TMUX=0"), true, true},
		{"no-tmux-flag", isolatedEnv("HARNESS_NO_TMUX=1"), true, true},
		{"already-in-tmux", isolatedEnv("TMUX=/tmp/tmux-1000/default,1,0"), true, true},
		{"missing binary", isolatedEnv(), true, false},
	}
	for _, tc := range off {
		lp := look
		if !tc.lookOK {
			lp = func(string) (string, error) { return "", errors.New("not found") }
		}
		if wrap, _, _ := cliTmuxWrap(tc.env, tc.terminal, lp); wrap {
			t.Fatalf("%s: should not wrap", tc.name)
		}
	}
	wrap, _, session = cliTmuxWrap(isolatedEnv("HARNESS_CLI_TMUX_SESSION=ah-cli-fixed"), true, look)
	if !wrap || session != "ah-cli-fixed" {
		t.Fatalf("override session=%q wrap=%v", session, wrap)
	}
}

func TestStdinIsTerminalRejectsReadersAndDevNull(t *testing.T) {
	if stdinIsTerminal(strings.NewReader("")) {
		t.Fatal("a byte reader is not a terminal")
	}
	if stdinIsTerminal(nil) {
		t.Fatal("nil is not a terminal")
	}
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer devNull.Close()
	if stdinIsTerminal(devNull) {
		t.Fatal("/dev/null is a character device but not a terminal")
	}
	if stdoutIsTerminal(devNull) {
		t.Fatal("/dev/null is not a terminal on stdout either")
	}
}
