package main

import (
	"os"
	"path/filepath"
	"testing"
)

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
