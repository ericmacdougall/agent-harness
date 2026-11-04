package main

import (
	"encoding/json"
	"errors"
	"io"
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

func caseInsensitive(dir string) bool {
	upper := filepath.Join(filepath.Dir(dir), strings.ToUpper(filepath.Base(dir)))
	if upper == dir {
		return false
	}
	a, errA := os.Stat(dir)
	b, errB := os.Stat(upper)
	return errA == nil && errB == nil && os.SameFile(a, b)
}

// expectRefused asserts that every dir is refused and that no refusal changes root.
func expectRefused(t *testing.T, root, protected string, cases map[string]string) {
	t.Helper()
	for name, dir := range cases {
		t.Run(name, func(t *testing.T) {
			before := tree(t, root)
			if _, err := baselineDataDir(dir, protected); !errors.Is(err, errRealDataDir) {
				t.Fatalf("admitted %q: %v", dir, err)
			}
			if after := tree(t, root); after != before {
				t.Fatalf("refusal changed files:\n%s\n---\n%s", before, after)
			}
		})
	}
}

func TestBaselineRefusesRealDataDirectories(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	config := filepath.Join(root, "config")
	protected := filepath.Join(config, "agent-harness")
	def := filepath.Join(protected, "console")
	// Empty, so only the protected-root check can refuse it.
	os.MkdirAll(def, 0o700)

	journal := filepath.Join(root, "journal")
	os.MkdirAll(journal, 0o700)
	os.WriteFile(filepath.Join(journal, "sessions.jsonl"), []byte(""), 0o600)
	used := filepath.Join(root, "used")
	os.MkdirAll(filepath.Join(used, "queued-inputs"), 0o700)
	markerDir := filepath.Join(root, "marker-dir")
	os.MkdirAll(filepath.Join(markerDir, baselineMarker), 0o700)
	forged := filepath.Join(root, "forged")
	os.MkdirAll(forged, 0o700)
	os.WriteFile(filepath.Join(forged, baselineMarker), []byte("x\n"), 0o600)

	cases := map[string]string{
		"no data dir":         "",
		"default":             def,
		"default, unclean":    def + string(filepath.Separator) + ".",
		"default via ..":      filepath.Join(def, "..", "console"),
		"subdirectory":        filepath.Join(def, "sub"),
		"deep new subdir":     filepath.Join(def, "a", "b"),
		"sibling of default":  filepath.Join(protected, "other"),
		"protected root":      protected,
		"used, queue only":    used,
		"empty journal":       journal,
		"marker is directory": markerDir,
		"marker not this one": forged,
		"a file, not dir":     filepath.Join(journal, "sessions.jsonl"),
	}
	if caseInsensitive(protected) {
		cases["case variant"] = filepath.Join(config, "AGENT-HARNESS", "Console")
		cases["case variant, new child"] = filepath.Join(config, "Agent-Harness", "CONSOLE", "new")
	}
	if runtime.GOOS != "windows" {
		link := filepath.Join(root, "link")
		os.Symlink(def, link)
		cases["symlink to default"] = link
		parent := filepath.Join(root, "parent-link")
		os.Symlink(config, parent)
		cases["default through linked parent"] = filepath.Join(parent, "agent-harness", "console")
		cases["new dir through linked parent"] = filepath.Join(parent, "agent-harness", "console", "new")
		marked := filepath.Join(root, "marked-link")
		os.MkdirAll(marked, 0o700)
		os.Symlink(filepath.Join(journal, "sessions.jsonl"), filepath.Join(marked, baselineMarker))
		cases["marker is symlink"] = marked
		elsewhere := filepath.Join(root, "elsewhere")
		os.MkdirAll(elsewhere, 0o700)
		other := filepath.Join(root, "other-link")
		os.Symlink(elsewhere, other)
		cases["symlink to an empty dir"] = other
	}
	expectRefused(t, root, protected, cases)
}

// The protected root may not exist yet: 0.1.0 creates it on first run. Every
// spelling of it must still be refused, and refusing must not create it.
func TestBaselineRefusesAbsentProtectedRoot(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	config := filepath.Join(root, "config")
	os.MkdirAll(config, 0o700)
	protected := filepath.Join(config, "agent-harness")
	cases := map[string]string{
		"default":      filepath.Join(protected, "console"),
		"protected":    protected,
		"deep":         filepath.Join(protected, "console", "x"),
		"unclean path": filepath.Join(config, ".", "agent-harness", "console"),
	}
	if caseInsensitive(config) {
		cases["case variant"] = filepath.Join(config, "AGENT-HARNESS", "console")
		cases["case variant parent"] = filepath.Join(filepath.Dir(config), "CONFIG", "agent-harness", "console")
	}
	if runtime.GOOS != "windows" {
		parent := filepath.Join(root, "parent-link")
		os.Symlink(config, parent)
		cases["linked parent"] = filepath.Join(parent, "agent-harness", "console")
		// The configured root is itself a link; the real path behind it is refused.
		realRoot := filepath.Join(root, "real-root")
		os.MkdirAll(realRoot, 0o700)
		linkedProtected := filepath.Join(root, "linked-protected")
		os.Symlink(realRoot, linkedProtected)
		t.Run("real path behind linked root", func(t *testing.T) {
			if _, err := baselineDataDir(filepath.Join(realRoot, "console"), linkedProtected); !errors.Is(err, errRealDataDir) {
				t.Fatalf("admitted: %v", err)
			}
			if entries, _ := os.ReadDir(realRoot); len(entries) != 0 {
				t.Fatal("refusal wrote under the real root")
			}
		})
	}
	expectRefused(t, root, protected, cases)
	if _, err := os.Stat(protected); !os.IsNotExist(err) {
		t.Fatal("refusing the protected root created it")
	}
}

func TestBaselineAdmitsOnlyItsOwnDirectories(t *testing.T) {
	root := t.TempDir()
	protected := filepath.Join(root, "config", "agent-harness")
	fresh := filepath.Join(root, "new", "data")
	got, err := baselineDataDir(fresh, protected)
	if err != nil || got != fresh {
		t.Fatalf("new dir: %q %v", got, err)
	}
	if data, _ := os.ReadFile(filepath.Join(fresh, baselineMarker)); string(data) != baselineContent {
		t.Fatal("marker not written")
	}
	// The app then writes its own files; the marked directory stays admitted.
	os.WriteFile(filepath.Join(fresh, "sessions.jsonl"), []byte("{}\n"), 0o600)
	if _, err = baselineDataDir(fresh, protected); err != nil {
		t.Fatalf("marked dir refused: %v", err)
	}
	empty := filepath.Join(root, "empty")
	os.MkdirAll(empty, 0o700)
	if _, err = baselineDataDir(empty, protected); err != nil {
		t.Fatalf("empty dir refused: %v", err)
	}
	if _, err = os.Stat(filepath.Join(empty, baselineMarker)); err != nil {
		t.Fatal("empty dir not marked")
	}
	// A name that only starts like the protected root is outside it while there is
	// no configuration directory; once there is one, anything inside it is refused.
	near := filepath.Join(root, "config", "agent-harness-scratch")
	if _, err = baselineDataDir(near, protected); err != nil {
		t.Fatalf("neighbour refused: %v", err)
	}
	inConfig := filepath.Join(root, "config", "elsewhere")
	if _, err = baselineDataDir(inConfig, protected); !errors.Is(err, errRealDataDir) {
		t.Fatalf("directory inside the configuration directory admitted: %v", err)
	}
	// With no protected root at all, nothing is admitted.
	if _, err = baselineDataDir(filepath.Join(root, "unprotected"), ""); !errors.Is(err, errRealDataDir) {
		t.Fatalf("admitted with no protected root: %v", err)
	}
	// A marked directory moved under the protected root is refused anyway.
	inside := filepath.Join(protected, "moved")
	os.MkdirAll(filepath.Dir(inside), 0o700)
	if err = os.Rename(fresh, inside); err != nil {
		t.Fatal(err)
	}
	if _, err = baselineDataDir(inside, protected); !errors.Is(err, errRealDataDir) {
		t.Fatalf("marked dir under the protected root admitted: %v", err)
	}
}

// Isolates the user's configuration directory for code that calls protectedRoot.
func isolateConfig(t *testing.T) string {
	cfg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", cfg)
	t.Setenv("HOME", cfg)
	t.Setenv("AppData", cfg)
	return cfg
}

func TestRunRefusesDefaultBeforeAnyWork(t *testing.T) {
	cfg := isolateConfig(t)
	var out strings.Builder
	if err := run([]string{"--no-open"}, &out); !errors.Is(err, errRealDataDir) {
		t.Fatalf("run without --data-dir: %v", err)
	}
	def := filepath.Join(protectedRoot(), "console")
	if err := run([]string{"--no-open", "--data-dir", def}, &out); !errors.Is(err, errRealDataDir) {
		t.Fatalf("run on the default: %v", err)
	}
	if entries, _ := os.ReadDir(cfg); len(entries) != 0 {
		t.Fatalf("run wrote under the config dir: %v", entries)
	}
	out.Reset()
	if err := run([]string{"--version"}, &out); err != nil || !strings.Contains(out.String(), "unreleased") {
		t.Fatalf("version: %q %v", out.String(), err)
	}
}

func TestBaselineAdmittedForHelpers(t *testing.T) {
	cfg := isolateConfig(t)
	marked := filepath.Join(t.TempDir(), "marked")
	if _, err := baselineDataDir(marked, protectedRoot()); err != nil {
		t.Fatal(err)
	}
	if err := baselineAdmitted(marked); err != nil {
		t.Fatalf("marked dir refused: %v", err)
	}
	unmarked := t.TempDir()
	inside := filepath.Join(protectedRoot(), "console")
	os.MkdirAll(inside, 0o700)
	os.WriteFile(filepath.Join(inside, baselineMarker), []byte(baselineContent), 0o600)
	for name, dir := range map[string]string{"unmarked": unmarked, "relative": "data", "missing": filepath.Join(cfg, "nope"), "marked but protected": inside} {
		if err := baselineAdmitted(dir); !errors.Is(err, errRealDataDir) {
			t.Fatalf("%s admitted: %v", name, err)
		}
	}
}

// A launch ticket naming a directory this baseline did not create is refused before
// the ticket is consumed or settings are opened.
func TestLaunchHelperRefusesUnmarkedDataDir(t *testing.T) {
	a, s, _ := checkpointFixture(t)
	a.runtime = func(provider, profile string) (string, []string, error) {
		return "/trusted/cli", []string{"HARNESS_SETTINGS_REVISION=4"}, nil
	}
	a.resolvePolicy = func(provider, profile, stage string) (resolvedPolicy, error) {
		return resolvedPolicy{Provider: provider, ProfileID: profile, Revision: "4"}, nil
	}
	_, args, err := a.prepareCLILaunch("codex", "managed-profile", s.CWD)
	if err != nil {
		t.Fatal(err)
	}
	isolateConfig(t)
	if err = runCLILaunch(args[1:], strings.NewReader(""), io.Discard, io.Discard); !errors.Is(err, errRealDataDir) {
		t.Fatalf("launch helper ran on an unmarked dir: %v", err)
	}
	if _, err = os.Stat(args[2]); err != nil {
		t.Fatal("the ticket was consumed before the guard")
	}
}

// A GoodQA snapshot naming a directory this baseline did not create is refused
// before the proxy takes its read lock.
func TestGoodQAHelperRefusesUnmarkedDataDir(t *testing.T) {
	_, _, snapshot, _ := goodqaTestSetup(t)
	data, _ := json.Marshal(snapshot)
	path := filepath.Join(snapshot.DataDir, "mcp", "helper-guard.json")
	if e := settingsAtomicWrite(path, data); e != nil {
		t.Fatal(e)
	}
	isolateConfig(t)
	before := tree(t, snapshot.DataDir)
	handled, err := runSettingsHelper([]string{"--goodqa-proxy", "--config", path, "--sha256", settingsDigest(data)}, strings.NewReader(""), io.Discard, io.Discard)
	if !handled || !errors.Is(err, errRealDataDir) {
		t.Fatalf("GoodQA helper ran on an unmarked dir: %v %v", handled, err)
	}
	if tree(t, snapshot.DataDir) != before {
		t.Fatal("refusal changed the data directory")
	}
}
