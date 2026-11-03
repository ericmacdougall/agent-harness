package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestOrdinarySendAttachmentSurvivesNextComposerSelection(t *testing.T) {
	if !attachmentCleanupSupported() {
		t.Skip("descriptor-confined cleanup unavailable on this platform")
	}
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
	a.attachmentCleanup = func(string, os.FileInfo, string, string) error { return errors.New("injected unlink failure") }
	finishNativeQueueTurn(a, s)
	if entry.Status != "cleanup_pending" || !activeQueue(s) {
		t.Fatalf("unlink failure pruned durable attachment owner: %#v", entry)
	}
	if _, err = os.Stat(firstSnapshot); err != nil {
		t.Fatal("unlink failure lost the still-owned snapshot", err)
	}
	if _, err = a.selectedAttachments(s, []string{second}); err != nil {
		t.Fatal("failed cleanup of A disturbed independent composer B", err)
	}
	dataDir := a.dataDir
	sessionID := s.ID
	a.close()
	restored, err := newApp(dataDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.close()
	recovered := restored.findLocked(sessionID)
	if recovered == nil {
		t.Fatal("restart lost attachment owner session")
	}
	recoveredEntry := queueEntry(recovered, "ordinary-with-file")
	if recoveredEntry == nil || recoveredEntry.Status != "discarded" || activeQueue(recovered) {
		t.Fatalf("restart did not finish pending cleanup: %#v", recoveredEntry)
	}
	if _, err = os.Stat(firstSnapshot); !os.IsNotExist(err) {
		t.Fatal("restart cleanup did not remove completed ordinary-send snapshot")
	}
}

func TestOrdinarySendAttachmentSurvivesUnknownRestart(t *testing.T) {
	if !attachmentCleanupSupported() {
		t.Skip("descriptor-confined cleanup unavailable on this platform")
	}
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

func TestAttachmentCleanupRefusesSwappedDataDirectory(t *testing.T) {
	if !attachmentCleanupSupported() {
		t.Skip("descriptor-confined cleanup unavailable on this platform")
	}
	a, err := newApp(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer a.close()
	cwd, _ := filepath.EvalSymlinks(t.TempDir())
	s := emptySession("codex", cwd, "")
	s.ProviderID = "provider"
	s.task = &trackedTask{ID: "task", Generation: 1, objective: "owned cleanup", passes: map[string]string{}, attempts: map[string]int{}}
	ensureTaskAuthority(s.task)
	a.sessions = append(a.sessions, s)
	source := filepath.Join(s.CWD, "same-name.txt")
	if err = os.WriteFile(source, []byte("private original"), 0600); err != nil {
		t.Fatal(err)
	}
	snapshot, err := a.snapshotAttachment(source)
	if err != nil {
		t.Fatal(err)
	}
	entry := &queuedInput{RetentionOnly: true, RequestID: "cleanup", Status: "cleanup_pending", TaskID: s.task.ID, Generation: s.task.Generation, Snapshots: map[string]attachmentSnapshot{source: snapshot}}
	s.inputs = append(s.inputs, entry)
	if err = a.saveInputsLocked(s); err != nil {
		t.Fatal(err)
	}

	moved := a.dataDir + "-original"
	outside := t.TempDir()
	if err = os.Mkdir(filepath.Join(outside, "attachments"), 0700); err != nil {
		t.Fatal(err)
	}
	outsideFile := filepath.Join(outside, "attachments", filepath.Base(snapshot.Path))
	if err = os.WriteFile(outsideFile, []byte("outside must survive"), 0600); err != nil {
		t.Fatal(err)
	}
	a.attachmentCleanup = func(dataDir string, expected os.FileInfo, name, directoryIdentity string) error {
		if err := os.Rename(dataDir, moved); err != nil {
			return err
		}
		if err := os.Symlink(outside, dataDir); err != nil {
			return err
		}
		return removeOwnedAttachment(dataDir, expected, name, directoryIdentity)
	}
	if err = a.finishAttachmentCleanupLocked(s, entry); err == nil {
		t.Fatal("swapped data directory was allowed to redirect cleanup")
	}
	if entry.Status != "cleanup_pending" || len(entry.Snapshots) != 1 {
		t.Fatalf("failed confinement pruned cleanup owner: %#v", entry)
	}
	if data, readErr := os.ReadFile(outsideFile); readErr != nil || string(data) != "outside must survive" {
		t.Fatalf("outside same-basename target was changed: %q %v", data, readErr)
	}
	originalMoved := filepath.Join(moved, "attachments", filepath.Base(snapshot.Path))
	if data, readErr := os.ReadFile(originalMoved); readErr != nil || string(data) != "private original" {
		t.Fatalf("pinned original snapshot was lost: %q %v", data, readErr)
	}
	if err = os.Remove(a.dataDir); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(moved, a.dataDir); err != nil {
		t.Fatal(err)
	}
	a.attachmentCleanup = nil
	if err = a.finishAttachmentCleanupLocked(s, entry); err != nil {
		t.Fatal("cleanup did not resume after restoring the pinned directory", err)
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
