package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSettingsTransactionLockAcrossProcesses(t *testing.T) {
	if path := os.Getenv("HARNESS_SETTINGS_LOCK_CHILD"); path != "" {
		release, e := settingsLock(path)
		if e != nil {
			t.Fatal(e)
		}
		defer release()
		fmt.Println("locked")
		var b [1]byte
		_, _ = os.Stdin.Read(b[:])
		return
	}
	s, _ := settingsTestStore(t)
	path := filepath.Join(s.dir, "cross-process.lock")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSettingsTransactionLockAcrossProcesses$")
	cmd.Env = append(os.Environ(), "HARNESS_SETTINGS_LOCK_CHILD="+path)
	stdout, e := cmd.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	stdin, e := cmd.StdinPipe()
	if e != nil {
		t.Fatal(e)
	}
	defer stdin.Close()
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	defer cmd.Process.Kill()
	line, e := bufio.NewReader(stdout).ReadString('\n')
	if e != nil || line != "locked\n" {
		t.Fatal("child did not acquire native lock")
	}
	if release, e := settingsLock(path); e == nil {
		release()
		t.Fatal("parent acquired a live child transaction lock")
	}
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
	release, e := settingsLock(path)
	if e != nil {
		t.Fatal("OS did not release lock after owner death", e)
	}
	release()
}

func TestSettingsOtherStoreCannotDeleteAnActiveVaultWrite(t *testing.T) {
	s, v := settingsTestStore(t)
	p := settingsTestProfile(t, s)
	v.inserted = make(chan struct{})
	v.returnGate = make(chan struct{})
	defer func() {
		select {
		case <-v.returnGate:
		default:
			close(v.returnGate)
		}
	}()
	done := make(chan error, 1)
	go func() {
		done <- s.writeSecret(context.Background(), s.disk.Revision, p.ID, p.Generation, "api_key", "SYNTHETIC-CROSS-STORE", false)
	}()
	<-v.inserted
	_, e := openSettings(s.dir, v)
	if e != nil {
		t.Fatal(e)
	}
	v.mu.Lock()
	count := len(v.items)
	v.mu.Unlock()
	close(v.returnGate)
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	id := s.disk.Refs[secretSlot(p.ID, "api_key")]
	v.mu.Lock()
	stored := v.items[id]
	v.mu.Unlock()
	if count != 1 || stored != "SYNTHETIC-CROSS-STORE" {
		t.Fatal("second store removed active native item and committed reference is dangling")
	}
}
func TestSettingsFailedDurabilityDoesNotRetireEitherCredential(t *testing.T) {
	s, v := settingsTestStore(t)
	p := settingsTestProfile(t, s)
	if e := s.writeSecret(context.Background(), s.disk.Revision, p.ID, p.Generation, "api_key", "SYNTHETIC-OLD-DURABLE", false); e != nil {
		t.Fatal(e)
	}
	old := s.disk.Refs[secretSlot(p.ID, "api_key")]
	writes := 0
	s.write = func(path string, data []byte) error {
		writes++
		if e := settingsAtomicWrite(path, data); e != nil {
			return e
		}
		if writes == 2 {
			return errSettingsDurability
		}
		return nil
	}
	e := s.writeSecret(context.Background(), s.disk.Revision, p.ID, p.Generation, "api_key", "SYNTHETIC-NEW-UNCERTAIN", false)
	if e == nil {
		t.Fatal("readable renamed metadata was treated as durably committed")
	}
	if !s.uncertain || v.items[old] != "SYNTHETIC-OLD-DURABLE" || len(v.items) != 2 {
		t.Fatal("uncertain commit retired a potentially live credential")
	}
	if _, _, e = s.runtime("codex", p.ID); e == nil {
		t.Fatal("uncertain state allowed a new provider launch")
	}
	reopened, e := openSettings(s.dir, v)
	if e != nil {
		t.Fatal(e)
	}
	current := reopened.disk.Refs[secretSlot(p.ID, "api_key")]
	if v.items[current] != "SYNTHETIC-NEW-UNCERTAIN" || len(v.items) != 1 {
		t.Fatal("durable restart did not retain the selected new item and reconcile the retired one")
	}
}

func TestSettingsEmptyReviewLadderRetainsIndependentDefault(t *testing.T) {
	s, _ := settingsTestStore(t)
	p, e := s.policy("codex", "global-codex", "main")
	if e != nil || len(p.ReviewStages) != 1 {
		t.Fatal("empty stored ladder silently removed independent review")
	}
	review := p.ReviewStages[0]
	if review.Provider != "codex" || review.ProfileID != "global-codex" || review.Model != "gpt-6.1-sol" || review.Effort != "high" {
		t.Fatal("wrong default reviewer")
	}
	if len(s.disk.Settings.ReviewLadder) != 0 {
		t.Fatal("effective defaults should not fabricate saved user rows")
	}
}
func TestSettingsHookEditPreservesExactNumbers(t *testing.T) {
	s, _ := settingsTestStore(t)
	home := filepath.Join(s.dir, "home")
	if e := os.MkdirAll(filepath.Join(home, ".claude"), 0700); e != nil {
		t.Fatal(e)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	path := filepath.Join(home, ".claude", "settings.json")
	original := `{"unrelated":{"large":9007199254740993,"exponent":1.230000e+42},"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"echo synthetic","custom":9007199254740993}]}]}}`
	if e := os.WriteFile(path, []byte(original), 0600); e != nil {
		t.Fatal(e)
	}
	hooks, e := s.inspectHooks(path)
	if e != nil || len(hooks) != 1 {
		t.Fatal("fixture did not discover handler", e)
	}
	disabled := false
	id, _, e := s.previewDocument("hook", hooks[0].ID, hooks[0].Digest, "", &disabled)
	if e != nil {
		t.Fatal(e)
	}
	_, digest, e := s.applyDocument(id)
	if e != nil {
		t.Fatal(e)
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "9007199254740993") || !strings.Contains(string(data), "1.230000e+42") {
		t.Fatal("disable rounded or normalized unrelated numeric tokens")
	}
	enabled := true
	id, _, e = s.previewDocument("hook", hooks[0].ID, digest, "", &enabled)
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = s.applyDocument(id); e != nil {
		t.Fatal(e)
	}
	data, _ = os.ReadFile(path)
	if strings.Count(string(data), "9007199254740993") != 2 || !strings.Contains(string(data), "1.230000e+42") {
		t.Fatal("enable corrupted unrelated or handler numeric tokens")
	}
}
