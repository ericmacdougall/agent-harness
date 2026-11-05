//go:build !windows

package main

import (
	"context"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func loginFixture(t *testing.T) (*settingsStore, *settingsLogin, settingsProfile) {
	t.Helper()
	a, _, _ := checkpointFixture(t)
	settings, _ := settingsTestStore(t)
	profile := settingsTestProfile(t, settings)
	settings.app = a
	task := &settingsLogin{ID: freshID(), ProfileID: profile.ID, Generation: profile.Generation, State: "running", cancel: func() {}}
	settings.login[task.ID] = task
	a.beginAuthenticationTransition(profile.Provider, profile.ID)
	return settings, task, profile
}

// A clean sign-in whose provider leaves a helper holding the output pipe must
// still be seen as finished and verified, not reported as a failed wait.
func TestLoginCleanExitWithDescendantHoldingPipeCompletes(t *testing.T) {
	settings, task, profile := loginFixture(t)
	pidFile := filepath.Join(t.TempDir(), "child")
	script := providerScript(t, `if [ "$1" = login ]; then
  sleep 60 &
  echo $! > "`+pidFile+`"
  echo signed in
  exit 0
fi
exit 0
`)
	done := make(chan struct{})
	go func() { settings.runLogin(context.Background(), task, profile, script, t.TempDir()); close(done) }()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("login did not finish")
	}
	if pid := recordedPID(t, pidFile); pid > 0 {
		t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
		if syscall.Kill(pid, 0) != nil {
			t.Fatal("a finished sign-in must not kill the provider's own helper")
		}
	}
	settings.mu.Lock()
	state := task.State
	settings.mu.Unlock()
	if state != "complete" {
		t.Fatalf("login state %q, want complete", state)
	}
}

// Cancelling a running sign-in stops the provider and everything it started.
func TestLoginCancelStopsWholeTree(t *testing.T) {
	settings, task, profile := loginFixture(t)
	pidFile := filepath.Join(t.TempDir(), "child")
	script := providerScript(t, `sleep 60 &
echo $! > "`+pidFile+`"
sleep 60
`)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { settings.runLogin(ctx, task, profile, script, t.TempDir()); close(done) }()
	pid := recordedPID(t, pidFile)
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("cancelled login did not return")
	}
	if !waitForExit(pid) {
		t.Fatalf("helper %d survived a cancelled login", pid)
	}
}
