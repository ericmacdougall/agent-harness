package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

type settingsTestVault struct {
	mu         sync.Mutex
	items      map[string]string
	blocked    chan struct{}
	started    chan struct{}
	fail       bool
	inserted   chan struct{}
	returnGate chan struct{}
}

func (v *settingsTestVault) Name() string { return "synthetic memory vault" }
func (v *settingsTestVault) Available() error {
	if v.fail {
		return errVault
	}
	return nil
}
func (v *settingsTestVault) Put(ctx context.Context, id, value string) error {
	if v.started != nil {
		close(v.started)
		select {
		case <-v.blocked:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	v.mu.Lock()
	if v.fail {
		v.mu.Unlock()
		return errVault
	}
	if _, ok := v.items[id]; ok {
		v.mu.Unlock()
		return errors.New("overwrite forbidden")
	}
	v.items[id] = value
	v.mu.Unlock()
	if v.inserted != nil {
		close(v.inserted)
		select {
		case <-v.returnGate:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}
func (v *settingsTestVault) Get(_ context.Context, id string) (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	x, ok := v.items[id]
	if !ok {
		return "", errVault
	}
	return x, nil
}
func (v *settingsTestVault) Delete(_ context.Context, id string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.fail {
		return errVault
	}
	delete(v.items, id)
	return nil
}
func settingsTestStore(t *testing.T) (*settingsStore, *settingsTestVault) {
	t.Helper()
	dir, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	v := &settingsTestVault{items: map[string]string{}}
	s, e := openSettings(dir, v)
	if e != nil {
		t.Fatal(e)
	}
	return s, v
}
func settingsTestCopy(s *settingsStore) consoleSettings {
	data, _ := json.Marshal(s.disk.Settings)
	var out consoleSettings
	_ = json.Unmarshal(data, &out)
	return out
}
func settingsTestProfile(t *testing.T, s *settingsStore) settingsProfile {
	t.Helper()
	next := settingsTestCopy(s)
	next.Profiles = append(next.Profiles, settingsProfile{Name: "Synthetic", Provider: "codex", Kind: "api_key", Allowed: true})
	if e := s.save(s.disk.Revision, next); e != nil {
		t.Fatal(e)
	}
	return s.disk.Settings.Profiles[len(s.disk.Settings.Profiles)-1]
}

func TestSettingsSecretWriteOnlyAndCAS(t *testing.T) {
	s, v := settingsTestStore(t)
	p := settingsTestProfile(t, s)
	rev := s.disk.Revision
	secret := "SYNTHETIC-SPLIT-SECRET-123456"
	if e := s.writeSecret(context.Background(), rev, p.ID, p.Generation, "api_key", secret, false); e != nil {
		t.Fatal(e)
	}
	data, e := os.ReadFile(filepath.Join(s.dir, "settings.json"))
	if e != nil {
		t.Fatal(e)
	}
	envelope, _ := json.Marshal(s.envelope())
	if strings.Contains(string(data)+string(envelope), secret) {
		t.Fatal("secret escaped native vault")
	}
	if len(v.items) != 1 {
		t.Fatal("expected one immutable vault item")
	}
	if e := s.writeSecret(context.Background(), rev, p.ID, p.Generation, "api_key", "NEW-SYNTHETIC", false); !errors.Is(e, errSettingsConflict) {
		t.Fatal("stale revision accepted")
	}
	if len(v.items) != 1 {
		t.Fatal("stale write changed vault")
	}
}
func TestSettingsConcurrentDeleteDoesNotResurrectProfile(t *testing.T) {
	s, v := settingsTestStore(t)
	p := settingsTestProfile(t, s)
	v.started = make(chan struct{})
	v.blocked = make(chan struct{})
	done := make(chan error, 1)
	rev := s.disk.Revision
	go func() {
		done <- s.writeSecret(context.Background(), rev, p.ID, p.Generation, "api_key", "SYNTHETIC-DELETE-RACE", false)
	}()
	<-v.started
	next := settingsTestCopy(s)
	next.Profiles = next.Profiles[:len(next.Profiles)-1]
	if e := s.save(rev, next); e != nil {
		t.Fatal(e)
	}
	close(v.blocked)
	if e := <-done; !errors.Is(e, errSettingsConflict) {
		t.Fatal("late write did not conflict")
	}
	if _, ok := s.profileLocked(p.ID); ok {
		t.Fatal("deleted profile resurrected")
	}
	if len(v.items) != 0 {
		t.Fatal("orphan not safely cleaned")
	}
}
func TestSettingsCASFailedCommitRetainsOldSecret(t *testing.T) {
	s, v := settingsTestStore(t)
	p := settingsTestProfile(t, s)
	if e := s.writeSecret(context.Background(), s.disk.Revision, p.ID, p.Generation, "api_key", "OLD-SYNTHETIC", false); e != nil {
		t.Fatal(e)
	}
	old := s.disk.Refs[secretSlot(p.ID, "api_key")]
	writes := 0
	s.write = func(path string, data []byte) error {
		writes++
		if writes == 2 {
			return errors.New("injected pre-rename failure")
		}
		return settingsAtomicWrite(path, data)
	}
	if e := s.writeSecret(context.Background(), s.disk.Revision, p.ID, p.Generation, "api_key", "NEW-SYNTHETIC", false); e == nil {
		t.Fatal("failed commit accepted")
	}
	if s.disk.Refs[secretSlot(p.ID, "api_key")] != old || v.items[old] != "OLD-SYNTHETIC" {
		t.Fatal("old secret lost")
	}
	s.write = settingsAtomicWrite
	reopened, e := openSettings(s.dir, v)
	if e != nil {
		t.Fatal(e)
	}
	if reopened.disk.Refs[secretSlot(p.ID, "api_key")] != old || len(v.items) != 1 {
		t.Fatal("restart cleanup removed referenced item or retained staged orphan")
	}
}
func TestSettingsConcurrentMetadataSaveCannotCleanInflightItem(t *testing.T) {
	s, v := settingsTestStore(t)
	p := settingsTestProfile(t, s)
	v.started = make(chan struct{})
	v.blocked = make(chan struct{})
	done := make(chan error, 1)
	rev := s.disk.Revision
	go func() {
		done <- s.writeSecret(context.Background(), rev, p.ID, p.Generation, "api_key", "SYNTHETIC-INFLIGHT", false)
	}()
	<-v.started
	next := settingsTestCopy(s)
	next.Defaults.Effort = "medium"
	if e := s.save(rev, next); e != nil {
		t.Fatal(e)
	}
	if len(s.disk.Pending) != 1 {
		t.Fatal("inflight ledger lost")
	}
	close(v.blocked)
	if e := <-done; !errors.Is(e, errSettingsConflict) {
		t.Fatal("concurrent save should conflict")
	}
	if len(v.items) != 0 {
		t.Fatal("unreferenced item leaked")
	}
}
func TestSettingsPolicyRevisionAndReservedEnvironment(t *testing.T) {
	s, _ := settingsTestStore(t)
	policy, e := s.policy("codex", "", "main")
	if e != nil {
		t.Fatal(e)
	}
	if policy.Model != "gpt-6.1-sol" || policy.Effort != "high" || policy.Permissions != "danger-full-access" || policy.ServiceTier != "default" {
		t.Fatalf("wrong user defaults: %+v", policy)
	}
	next := settingsTestCopy(s)
	next.Defaults.Effort = "medium"
	next.ReviewLadder = []policyStep{{Provider: "claude", ProfileID: "global-claude", Model: "opus", Effort: "high"}}
	if e = s.save(s.disk.Revision, next); e != nil {
		t.Fatal(e)
	}
	updated, e := s.policy("codex", "", "code_review")
	if e != nil || updated.Revision == policy.Revision || updated.Effort != "medium" || len(updated.ReviewStages) != 1 {
		t.Fatal("saved policy not effective")
	}
	if policy.Effort != "high" {
		t.Fatal("active snapshot mutated")
	}
	for _, name := range []string{"PATH", "HOME", "CODEX_HOME", "CLAUDE_CONFIG_DIR", "OPENAI_API_KEY", "LD_PRELOAD", "HARNESS_SETTINGS_REVISION", "GIT_CONFIG_COUNT"} {
		if safeEnvName(name) {
			t.Fatalf("reserved variable allowed: %s", name)
		}
	}
}
func TestSettingsHTTPSecretAndConflict(t *testing.T) {
	s, _ := settingsTestStore(t)
	a, e := newApp(s.dir, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer a.close()
	s.app = a
	settingsStores.Store(a, s)
	defer settingsStores.Delete(a)
	p := settingsTestProfile(t, s)
	body := `{"expectedRevision":1,"profileId":"` + p.ID + `","profileGeneration":"` + p.Generation + `","name":"api_key","value":"SYNTHETIC-HTTP-SECRET"}`
	r := httptest.NewRequest("POST", "http://127.0.0.1:8181/api/settings/secrets", strings.NewReader(body))
	r.Header.Set("Origin", "http://127.0.0.1:8181")
	r.Header.Set("Authorization", "Bearer synthetic-capability")
	w := httptest.NewRecorder()
	a.handler("127.0.0.1:8181", "synthetic-capability").ServeHTTP(w, r)
	if w.Code != http.StatusConflict || strings.Contains(w.Body.String(), "SYNTHETIC-HTTP-SECRET") {
		t.Fatal("conflict/status or write-only contract failed", w.Code)
	}
}

func TestSettingsLostWriteAcknowledgementKeepsCommittedReference(t *testing.T) {
	s, v := settingsTestStore(t)
	p := settingsTestProfile(t, s)
	s.write = func(path string, data []byte) error {
		if e := settingsAtomicWrite(path, data); e != nil {
			return e
		}
		return errors.New("injected lost acknowledgement after rename")
	}
	if e := s.writeSecret(context.Background(), s.disk.Revision, p.ID, p.Generation, "api_key", "SYNTHETIC-LOST-ACK", false); e != nil {
		t.Fatal(e)
	}
	id := s.disk.Refs[secretSlot(p.ID, "api_key")]
	if v.items[id] != "SYNTHETIC-LOST-ACK" {
		t.Fatal("committed native item was deleted")
	}
	reopened, e := openSettings(s.dir, v)
	if e != nil || reopened.disk.Refs[secretSlot(p.ID, "api_key")] != id {
		t.Fatal("durable reference not reconciled")
	}
}
func TestSettingsSecondWriterCannotClobberMetadata(t *testing.T) {
	s, v := settingsTestStore(t)
	other, e := openSettings(s.dir, v)
	if e != nil {
		t.Fatal(e)
	}
	next := settingsTestCopy(s)
	next.Defaults.Effort = "medium"
	if e = s.save(s.disk.Revision, next); e != nil {
		t.Fatal(e)
	}
	stale := settingsTestCopy(other)
	stale.Defaults.Effort = "low"
	if e = other.save(other.disk.Revision, stale); !errors.Is(e, errSettingsConflict) {
		t.Fatal("second stale process overwrote newer settings")
	}
}
