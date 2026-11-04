//go:build darwin

package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// APFS folds spellings that strings.ToLower does not: U+017F long s, and NFD versus
// NFC. With the agent-harness root absent, such a spelling must still be refused,
// and refusing must not create the root.
func TestBaselineRefusesAPFSFoldedSpellings(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	nfc := filepath.Join(root, "josé", "config")
	os.MkdirAll(nfc, 0o700)
	protected := filepath.Join(nfc, "agent-harness")
	nfd := filepath.Join(root, "josé", "config")
	if _, err := os.Stat(nfd); err != nil {
		t.Skip("volume does not fold NFD to NFC")
	}
	cases := map[string]string{
		"long s":     filepath.Join(nfc, "agent-harneſs", "console"),
		"nfd parent": filepath.Join(nfd, "agent-harness", "console"),
	}
	for name, dir := range cases {
		if _, err := baselineDataDir(dir, protected); !errors.Is(err, errRealDataDir) {
			t.Fatalf("%s admitted: %v", name, err)
		}
		if entries, _ := os.ReadDir(nfc); len(entries) != 0 {
			t.Fatalf("%s: refusal created %v", name, entries)
		}
	}
}
