//go:build windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// An 8.3 short name reaches the protected root by another spelling.
func TestBaselineRefusesShortName(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	protected := filepath.Join(root, "config", "agent-harness")
	os.MkdirAll(filepath.Join(protected, "console"), 0o700)
	long, err := windows.UTF16PtrFromString(protected)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]uint16, windows.MAX_PATH)
	n, err := windows.GetShortPathName(long, &buf[0], uint32(len(buf)))
	short := windows.UTF16ToString(buf[:n])
	if err != nil || n == 0 || strings.EqualFold(short, protected) {
		t.Skipf("no short name on this volume: %q %v", short, err)
	}
	t.Logf("short name %q", short)
	for _, dir := range []string{filepath.Join(short, "console"), filepath.Join(short, "console", "new"), short} {
		if _, err := baselineDataDir(dir, protected); !errors.Is(err, errRealDataDir) {
			t.Fatalf("admitted %q: %v", dir, err)
		}
	}
	if entries, _ := os.ReadDir(filepath.Join(protected, "console")); len(entries) != 0 {
		t.Fatal("refusal wrote into the protected root")
	}
}
