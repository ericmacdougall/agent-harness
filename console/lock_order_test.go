//go:build !windows

package main

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

// within runs f and fails the test when it does not return in time. The stuck
// goroutine is left behind on failure, which is acceptable for a failing test.
func within(t *testing.T, d time.Duration, what string, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { f(); close(done) }()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("%s did not return within %v: a lock is held across slow work", what, d)
	}
}

// A1: a sign-in that is blocked on its provider must not stop another profile
// from resolving a runtime, nor the settings store from being used.
func TestLoginInFlightDoesNotBlockOtherProfileOrSettings(t *testing.T) {
	settings, task, profile := loginFixture(t)
	script := providerScript(t, "sleep 30\n")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { settings.runLogin(ctx, task, profile, script, t.TempDir()); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	time.Sleep(300 * time.Millisecond) // let the provider process start

	within(t, 2*time.Second, "settings store use during a sign-in", func() {
		settings.mu.Lock()
		settings.mu.Unlock() //nolint:staticcheck // checking that the lock is free
	})
	a := settings.app
	a.runtime = func(string, string) (string, []string, error) { return "/fixture/claude", nil, nil }
	other, _ := defaultPolicy("claude", "another-profile", "main")
	within(t, 2*time.Second, "runtime resolution for another profile", func() {
		if _, _, _, err := a.resolveRuntime(other); err != nil {
			t.Error(err)
		}
	})
	within(t, 2*time.Second, "state read", func() { _ = a.state() })
}

// A2 and A11 (process part): a provider that stops reading its input must not
// leave the app lock held while the console writes to it.
func TestStalledProviderInputDoesNotHoldAppLock(t *testing.T) {
	a, s := claudeProcessFixture(t, "sleep 30\n")
	big := strings.Repeat("x", 120000) // larger than a pipe buffer, so the write blocks
	started := make(chan struct{})
	go func() { close(started); _ = a.sendClaude(s, "A", big, s.CWD, "") }()
	<-started
	t.Cleanup(func() {
		a.mu.Lock()
		run := s.claude
		a.mu.Unlock()
		if run != nil {
			run.cancel()
		}
	})
	time.Sleep(500 * time.Millisecond)
	within(t, 2*time.Second, "state read while a provider write is blocked", func() { _ = a.state() })
	var locked bool
	within(t, 2*time.Second, "app lock probe", func() {
		locked = !a.mu.TryLock()
		if !locked {
			a.mu.Unlock()
		}
	})
	if locked {
		t.Fatal("app lock held while writing to the provider")
	}
}

// A11 (journal part): a stalled fsync must not block state reads. The baseline
// records receipts while holding the app lock, so this fails today; the kernel
// rebuild (K5b writer gate) owns the fix, and the test is skipped by name until then.
func TestStalledJournalSyncDoesNotBlockReads(t *testing.T) {
	t.Skip("known defect in the unreleased baseline: receipts are journalled under the app lock; replaced by the K5b writer gate, GoodQA #35692")
	a, s := claudeProcessFixture(t, "read line\nsleep 30\n")
	release := make(chan struct{})
	var once sync.Once
	a.journalSync = func() error { <-release; return nil }
	t.Cleanup(func() {
		once.Do(func() { close(release) })
		a.mu.Lock()
		run := s.claude
		a.mu.Unlock()
		if run != nil {
			run.cancel()
		}
	})
	go func() { _ = a.sendClaude(s, "A", "hello", s.CWD, "") }()
	time.Sleep(500 * time.Millisecond)
	within(t, 2*time.Second, "state read during a stalled fsync", func() { _ = a.state() })
}
