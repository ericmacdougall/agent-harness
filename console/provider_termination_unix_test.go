//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func providerScript(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "provider.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func recordedPID(t *testing.T, path string) int {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(path); err == nil {
			if pid, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil && pid > 0 {
				return pid
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("provider never recorded its pid")
	return 0
}

// A zombie awaiting Wait still answers signal 0, so poll for real exit.
func waitForExit(pid int) bool {
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if syscall.Kill(pid, 0) != nil {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

// A disconnected provider is a quarantined writer: its whole tree has to stop,
// or it keeps working while the console reports it gone.
func TestProviderTreeStopsOnEveryReadFailure(t *testing.T) {
	cases := map[string]string{
		"overflow":  `head -c 3000000 /dev/zero | tr '\0' a; echo`,
		"malformed": `echo not-json`,
	}
	for name, failure := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			leader, child := filepath.Join(dir, "leader"), filepath.Join(dir, "child")
			script := providerScript(t, `echo $$ > "`+leader+`"
sh -c 'echo $$ > "`+child+`"; exec sleep 30' &
until [ -s "`+child+`" ]; do sleep 0.01; done
read line
printf '{"id":1,"result":{}}\n'
read line
`+failure+`
sleep 30
`)
			closed := make(chan struct{})
			client, err := startRPC(script, os.Environ(), nil, nil, func(*rpcClient, error) { close(closed) })
			if err != nil {
				t.Fatal(err)
			}
			leaderPID, childPID := recordedPID(t, leader), recordedPID(t, child)
			t.Cleanup(func() { _ = syscall.Kill(-leaderPID, syscall.SIGKILL) })
			select {
			case <-closed:
			case <-time.After(5 * time.Second):
				t.Fatal("read failure did not disconnect the provider")
			}
			client.close()
			if !waitForExit(leaderPID) {
				t.Fatalf("provider leader %d survived %s", leaderPID, name)
			}
			if !waitForExit(childPID) {
				t.Fatalf("provider descendant %d survived %s", childPID, name)
			}
		})
	}
}

func claudeProcessFixture(t *testing.T, body string) (*app, *session) {
	t.Helper()
	a := testApp(t)
	s := emptySession("claude", t.TempDir(), "")
	s.ProviderID = "claude-exit"
	s.Status = "running"
	s.Supervision.State = "active"
	s.scheduled = true
	s.lastRequest, s.requests["A"] = "A", "intent"
	s.requestOrder = []string{"A"}
	policy, _ := defaultPolicy("claude", "", "main")
	s.policy = policy
	home := t.TempDir()
	script := providerScript(t, body)
	a.runtime = func(string, string) (string, []string, error) {
		return script, []string{"HOME=" + home, "PATH=/usr/bin:/bin"}, nil
	}
	a.sessions = append(a.sessions, s)
	return a, s
}

// Claude ending without a final loses supervision of its tree, like a Codex read failure.
func TestClaudeExitWithoutFinalStopsProviderTree(t *testing.T) {
	childFile := filepath.Join(t.TempDir(), "child")
	a, s := claudeProcessFixture(t, `sh -c 'echo $$ > "`+childFile+`"; exec sleep 30' >/dev/null 2>&1 &
until [ -s "`+childFile+`" ]; do sleep 0.01; done
read line
exit 0
`)
	if err := a.sendClaude(s, "A", "bounded", s.CWD, ""); err != nil {
		t.Fatal(err)
	}
	childPID := recordedPID(t, childFile)
	t.Cleanup(func() { _ = syscall.Kill(childPID, syscall.SIGKILL) })
	if !waitForExit(childPID) {
		t.Fatalf("descendant %d kept running after Claude exited without a final", childPID)
	}
}

// Each Claude turn ends with process retirement, so a final must not kill a tool's
// deliberate background work.
func TestClaudeExitAfterFinalLeavesBackgroundWork(t *testing.T) {
	childFile := filepath.Join(t.TempDir(), "child")
	a, s := claudeProcessFixture(t, `sh -c 'echo $$ > "`+childFile+`"; exec sleep 30' >/dev/null 2>&1 &
until [ -s "`+childFile+`" ]; do sleep 0.01; done
read line
printf '{"type":"result","result":"done"}\n'
exit 0
`)
	if err := a.sendClaude(s, "A", "bounded", s.CWD, ""); err != nil {
		t.Fatal(err)
	}
	childPID := recordedPID(t, childFile)
	t.Cleanup(func() { _ = syscall.Kill(childPID, syscall.SIGKILL) })
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		a.mu.Lock()
		claude, state := s.claude, s.requests["A"]
		a.mu.Unlock()
		if claude == nil && state == "final" {
			if syscall.Kill(childPID, 0) != nil {
				t.Fatal("final Claude exit killed background work")
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("final turn did not finish")
}

// A6: a descendant that keeps Claude's stdout open must not hide the leader's
// death. The console has to notice, stop the tree and release the session within
// the drain bound, not when the descendant eventually exits.
func TestClaudeLeaderExitSeenWhileDescendantHoldsStdout(t *testing.T) {
	childFile := filepath.Join(t.TempDir(), "child")
	a, s := claudeProcessFixture(t, `sh -c 'echo $$ > "`+childFile+`"; exec sleep 60' &
until [ -s "`+childFile+`" ]; do sleep 0.01; done
read line
exit 0
`)
	if err := a.sendClaude(s, "A", "bounded", s.CWD, ""); err != nil {
		t.Fatal(err)
	}
	childPID := recordedPID(t, childFile)
	t.Cleanup(func() { _ = syscall.Kill(childPID, syscall.SIGKILL) })
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		a.mu.Lock()
		claude := s.claude
		a.mu.Unlock()
		if claude == nil {
			if !waitForExit(childPID) {
				t.Fatalf("descendant %d survived the unfinished exit", childPID)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("console kept the run attached for 8 s behind a descendant holding stdout")
}

// A6 for Codex: the leader exits after the handshake while a descendant keeps
// stdout open. The disconnect must be seen within the drain bound and the
// descendant stopped, not when the descendant eventually ends.
func TestCodexLeaderExitSeenWhileDescendantHoldsStdout(t *testing.T) {
	dir := t.TempDir()
	child := filepath.Join(dir, "child")
	script := providerScript(t, `sh -c 'echo $$ > "`+child+`"; exec sleep 60' &
until [ -s "`+child+`" ]; do sleep 0.01; done
read line
printf '{"id":1,"result":{}}\n'
read line
exit 0
`)
	closed := make(chan struct{})
	client, err := startRPC(script, os.Environ(), nil, nil, func(*rpcClient, error) { close(closed) })
	if err != nil {
		t.Fatal(err)
	}
	childPID := recordedPID(t, child)
	t.Cleanup(func() { _ = syscall.Kill(childPID, syscall.SIGKILL) })
	select {
	case <-closed:
	case <-time.After(8 * time.Second):
		t.Fatal("leader exit was hidden behind a descendant holding stdout")
	}
	client.close()
	if !waitForExit(childPID) {
		t.Fatalf("descendant %d survived the provider disconnect", childPID)
	}
}
