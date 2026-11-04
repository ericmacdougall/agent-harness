package main

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func tree(t *testing.T, dir string) string {
	t.Helper()
	var out []string
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err == nil {
			rel, _ := filepath.Rel(dir, path)
			out = append(out, rel+" "+info.Mode().String())
		}
		return nil
	})
	return strings.Join(out, "\n")
}

func TestBaselineRefusesRealDataDirectories(t *testing.T) {
	root := t.TempDir()
	def := filepath.Join(root, "config", "agent-harness", "console")
	// Empty, so only the default-path check can refuse it.
	os.MkdirAll(def, 0o700)

	used := filepath.Join(root, "used")
	os.MkdirAll(filepath.Join(used, "queued-inputs"), 0o700)

	journal := filepath.Join(root, "journal")
	os.MkdirAll(journal, 0o700)
	os.WriteFile(filepath.Join(journal, "sessions.jsonl"), []byte(""), 0o600)

	markerDir := filepath.Join(root, "marker-dir")
	os.MkdirAll(filepath.Join(markerDir, baselineMarker), 0o700)

	forged := filepath.Join(root, "forged")
	os.MkdirAll(forged, 0o700)
	os.WriteFile(filepath.Join(forged, baselineMarker), []byte("x\n"), 0o600)
	os.WriteFile(filepath.Join(forged, "sessions.jsonl"), []byte("{}\n"), 0o600)

	cases := map[string]string{
		"no data dir":         "",
		"default":             def,
		"default, unclean":    def + string(filepath.Separator) + "." + string(filepath.Separator),
		"used, queue only":    used,
		"empty journal":       journal,
		"marker is directory": markerDir,
		"marker not this one": forged,
		"a file, not dir":     filepath.Join(journal, "sessions.jsonl"),
	}
	if runtime.GOOS != "windows" {
		link := filepath.Join(root, "link")
		os.Symlink(def, link)
		cases["symlink to default"] = link
		parent := filepath.Join(root, "parent-link")
		os.Symlink(filepath.Join(root, "config"), parent)
		cases["default through linked parent"] = filepath.Join(parent, "agent-harness", "console")
		marked := filepath.Join(root, "marked-link")
		os.MkdirAll(marked, 0o700)
		os.Symlink(filepath.Join(journal, "sessions.jsonl"), filepath.Join(marked, baselineMarker))
		cases["marker is symlink"] = marked
		// A link could be repointed at the real directory after the check.
		elsewhere := filepath.Join(root, "elsewhere")
		os.MkdirAll(elsewhere, 0o700)
		other := filepath.Join(root, "other-link")
		os.Symlink(elsewhere, other)
		cases["symlink to an empty dir"] = other
	}
	for name, dir := range cases {
		t.Run(name, func(t *testing.T) {
			before := tree(t, root)
			if _, err := baselineDataDir(dir, def); !errors.Is(err, errRealDataDir) {
				t.Fatalf("admitted %q: %v", dir, err)
			}
			if after := tree(t, root); after != before {
				t.Fatalf("refusal changed files:\n%s\n---\n%s", before, after)
			}
		})
	}
}

func TestBaselineAdmitsOnlyItsOwnDirectories(t *testing.T) {
	root := t.TempDir()
	def := filepath.Join(root, "default")
	fresh := filepath.Join(root, "new", "data")
	got, err := baselineDataDir(fresh, def)
	if err != nil || got != fresh {
		t.Fatalf("new dir: %q %v", got, err)
	}
	if data, _ := os.ReadFile(filepath.Join(fresh, baselineMarker)); string(data) != baselineContent {
		t.Fatal("marker not written")
	}
	// The app then writes its own files; the marked directory stays admitted.
	os.WriteFile(filepath.Join(fresh, "sessions.jsonl"), []byte("{}\n"), 0o600)
	if _, err = baselineDataDir(fresh, def); err != nil {
		t.Fatalf("marked dir refused: %v", err)
	}
	empty := filepath.Join(root, "empty")
	os.MkdirAll(empty, 0o700)
	if _, err = baselineDataDir(empty, def); err != nil {
		t.Fatalf("empty dir refused: %v", err)
	}
	if _, err = os.Stat(filepath.Join(empty, baselineMarker)); err != nil {
		t.Fatal("empty dir not marked")
	}
	// A missing default is still refused by path.
	if _, err = baselineDataDir(def, def); !errors.Is(err, errRealDataDir) {
		t.Fatalf("missing default admitted: %v", err)
	}
	if _, err = os.Stat(def); !os.IsNotExist(err) {
		t.Fatal("refusing the default created it")
	}
	// An empty default is refused too: emptiness alone must not admit it.
	os.MkdirAll(def, 0o700)
	if _, err = baselineDataDir(def, def); !errors.Is(err, errRealDataDir) {
		t.Fatalf("empty default admitted: %v", err)
	}
	if entries, _ := os.ReadDir(def); len(entries) != 0 {
		t.Fatal("refusing the default marked it")
	}
}

func TestRunRefusesDefaultBeforeAnyWork(t *testing.T) {
	cfg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", cfg)
	t.Setenv("HOME", cfg)
	t.Setenv("AppData", cfg)
	var out strings.Builder
	err := run([]string{"--no-open"}, &out)
	if !errors.Is(err, errRealDataDir) {
		t.Fatalf("run without --data-dir: %v", err)
	}
	if entries, _ := os.ReadDir(cfg); len(entries) != 0 {
		t.Fatalf("run wrote under the config dir: %v", entries)
	}
	out.Reset()
	if err = run([]string{"--version"}, &out); err != nil || !strings.Contains(out.String(), "unreleased") {
		t.Fatalf("version: %q %v", out.String(), err)
	}
}
