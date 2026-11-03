package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOrdinarySendAttachmentSurvivesNextComposerSelection(t *testing.T) {
	a, base, _ := checkpointFixture(t)
	binary, _ := os.Executable()
	a.runtime = func(string, string) (string, []string, error) {
		return binary, append(os.Environ(), "HARNESS_CONSOLE_RPC_FIXTURE=1"), nil
	}
	s, err := a.createSession("codex", base.CWD, "")
	if err != nil {
		t.Fatal(err)
	}
	first := filepath.Join(s.CWD, "delayed-reader-a.txt")
	second := filepath.Join(s.CWD, "next-composer-b.txt")
	if err = os.WriteFile(first, []byte("bytes needed after provider acceptance"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(second, []byte("next composer selection"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = a.selectAttachments(s.ID, []string{first}); err != nil {
		t.Fatal(err)
	}
	firstSnapshot := s.attachmentSnapshots[first].Path
	if err = a.send(s.ID, "ordinary-with-file", "Read A after this turn starts", []string{first}, false); err != nil {
		t.Fatal(err)
	}
	if s.Status != "running" {
		t.Fatal("fixture did not preserve the provider-running selection window")
	}
	if err = a.selectAttachments(s.ID, []string{second}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(firstSnapshot)
	if err != nil || string(data) != "bytes needed after provider acceptance" {
		t.Fatalf("next composer selection removed delayed-reader bytes: %q %v", data, err)
	}
	entry := queueEntry(s, "ordinary-with-file")
	if entry == nil || !entry.RetentionOnly || entry.Status != "retained" {
		t.Fatalf("ordinary send did not retain explicit attachment ownership: %#v", entry)
	}
	finishNativeQueueTurn(a, s)
	if entry.Status != "discarded" || activeQueue(s) {
		t.Fatalf("native final outcome left ordinary attachment receipt blocking later work: %#v", entry)
	}
	if _, err = os.Stat(firstSnapshot); !os.IsNotExist(err) {
		t.Fatal("native final outcome did not release completed ordinary-send snapshot")
	}
	if _, err = a.selectedAttachments(s, []string{second}); err != nil {
		t.Fatal("discarding A disturbed independent composer B", err)
	}
}

func TestOrdinarySendAttachmentSurvivesUnknownRestart(t *testing.T) {
	dataDir := t.TempDir()
	cwd, _ := filepath.EvalSymlinks(t.TempDir())
	a, err := newApp(dataDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	binary, _ := os.Executable()
	a.runtime = func(string, string) (string, []string, error) {
		return binary, append(os.Environ(), "HARNESS_CONSOLE_RPC_FIXTURE=1"), nil
	}
	s, err := a.createSession("codex", cwd, "")
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(cwd, "unknown-reader.txt")
	if err = os.WriteFile(source, []byte("retain across unknown restart"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = a.selectAttachments(s.ID, []string{source}); err != nil {
		t.Fatal(err)
	}
	snapshot := s.attachmentSnapshots[source].Path
	if err = a.send(s.ID, "ordinary-unknown", "Provider may still consume this file", []string{source}, false); err != nil {
		t.Fatal(err)
	}
	a.close()

	restored, err := newApp(dataDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.close()
	if len(restored.sessions) != 1 || restored.sessions[0].Status != "unknown" {
		t.Fatal("accepted send did not restart with unknown writer authority")
	}
	entry := queueEntry(restored.sessions[0], "ordinary-unknown")
	if entry == nil || !entry.RetentionOnly || entry.Status != "retained" {
		t.Fatalf("restart lost conservative attachment ownership: %#v", entry)
	}
	if data, readErr := os.ReadFile(snapshot); readErr != nil || string(data) != "retain across unknown restart" {
		t.Fatalf("restart removed possibly live attachment: %q %v", data, readErr)
	}
	if err = restored.discardInput(restored.sessions[0].ID, entry.RequestID, true); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(snapshot); !os.IsNotExist(err) {
		t.Fatal("explicit recovery discard did not release snapshot")
	}
}

func TestAttachmentsBindSelectedBytes(t *testing.T) {
	a, err := newApp(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer a.close()
	s := emptySession("codex", t.TempDir(), "")
	a.sessions = append(a.sessions, s)
	sourceDir, _ := filepath.EvalSymlinks(t.TempDir())
	source := filepath.Join(sourceDir, "note.txt")
	if err = os.WriteFile(source, []byte("selected"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = a.selectAttachments(s.ID, []string{source}); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(source, []byte("changed later"), 0600); err != nil {
		t.Fatal(err)
	}
	paths, err := a.selectedAttachments(s, []string{source})
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(paths[0])
	if err != nil || string(data) != "selected" {
		t.Fatalf("selected bytes lost: %q %v", data, err)
	}
	if err = os.WriteFile(paths[0], []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = a.selectedAttachments(s, []string{source}); err == nil {
		t.Fatal("tampered snapshot accepted")
	}
}
func TestAttachmentsRejectRedirectAndCredentials(t *testing.T) {
	a, err := newApp(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer a.close()
	real := t.TempDir()
	file := filepath.Join(real, "note.txt")
	_ = os.WriteFile(file, []byte("data"), 0600)
	link := filepath.Join(t.TempDir(), "redirect")
	if err = os.Symlink(real, link); err != nil {
		t.Skip("symlink unavailable")
	}
	if _, err = a.snapshotAttachment(filepath.Join(link, "note.txt")); err == nil {
		t.Fatal("parent redirect accepted")
	}
	for _, path := range []string{"/tmp/.ssh/key", "/tmp/.env.local", "/tmp/auth.json", "/tmp/credentials.json"} {
		if !credentialFile(path) {
			t.Fatalf("credential path accepted: %s", path)
		}
	}
}
