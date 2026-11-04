package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestSettingsDocumentCASParentAndBridgeProtection(t *testing.T) {
	s, _ := settingsTestStore(t)
	root := filepath.Join(s.dir, "repo")
	if e := os.Mkdir(root, 0700); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(root, "AGENTS.md")
	old := "old\n<!-- codex-bridge:begin v1 -->\ndisabled\n<!-- codex-bridge:end -->\n"
	if e := os.WriteFile(path, []byte(old), 0640); e != nil {
		t.Fatal(e)
	}
	docs, _, e := s.listDocuments(root)
	if e != nil {
		t.Fatal(e)
	}
	var doc settingsDocument
	for _, d := range docs {
		if d.Path == path {
			doc = d
		}
	}
	if _, _, e = s.previewDocument("document", doc.ID, doc.Digest, "removed block", nil); e == nil {
		t.Fatal("bridge block removed")
	}
	id, _, e := s.previewDocument("document", doc.ID, doc.Digest, old+"changed\n", nil)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(path, []byte(old+"concurrent"), 0640); e != nil {
		t.Fatal(e)
	}
	if _, _, e = s.applyDocument(id); !errors.Is(e, errSettingsConflict) {
		t.Fatal("stale document accepted")
	}
}
func TestSettingsDuplicateHookJSONAndUnsafeEndpoints(t *testing.T) {
	if settingsUniqueJSON([]byte(`{"hooks":{"x":[],"x":[]}}`)) == nil {
		t.Fatal("ambiguous JSON accepted")
	}
	for _, url := range []string{"http://example.com/mcp", "https://user:secret@example.com/mcp", "https://example.com/mcp?key=secret", "file:///tmp/mcp"} {
		if validateGoodQAEndpoint(url, true) == nil {
			t.Fatal("unsafe endpoint accepted", url)
		}
	}
	if validateGoodQAEndpoint("http://127.0.0.1:1234/mcp", true) != nil {
		t.Fatal("explicit local endpoint rejected")
	}
}
func TestSettingsDocumentParentReplacementRejected(t *testing.T) {
	s, _ := settingsTestStore(t)
	root := filepath.Join(s.dir, "repo")
	if e := os.Mkdir(root, 0700); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(root, "AGENTS.md")
	_ = os.WriteFile(path, []byte("before"), 0600)
	docs, _, e := s.listDocuments(root)
	if e != nil {
		t.Fatal(e)
	}
	var doc settingsDocument
	for _, d := range docs {
		if d.Path == path {
			doc = d
		}
	}
	id, _, e := s.previewDocument("document", doc.ID, doc.Digest, "after", nil)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(root, root+"-old"); e != nil {
		t.Fatal(e)
	}
	_ = os.Mkdir(root, 0700)
	_ = os.WriteFile(path, []byte("before"), 0600)
	if _, _, e = s.applyDocument(id); e == nil {
		t.Fatal("parent replacement accepted")
	}
}
