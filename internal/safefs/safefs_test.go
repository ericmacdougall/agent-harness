package safefs

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestPublishNewCreatesOnceAndNeverOverwrites(t *testing.T) {
	dir := t.TempDir()
	d, err := OpenDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := d.PublishNew("r.json", []byte(`{"a":1}`)); err != nil {
		t.Fatal(err)
	}
	if err := d.PublishNew("r.json", []byte(`{"a":2}`)); !errors.Is(err, ErrExists) {
		t.Fatalf("second publish: %v", err)
	}
	got, err := d.ReadRegular("r.json", 100)
	if err != nil || string(got) != `{"a":1}` {
		t.Fatalf("got %q %v", got, err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("temp files left behind: %v", entries)
	}
	if runtime.GOOS != "windows" {
		fi, _ := os.Stat(filepath.Join(dir, "r.json"))
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("mode %v", fi.Mode().Perm())
		}
	}
}

func TestRefusesEscapesAndSymlinks(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	os.WriteFile(filepath.Join(outside, "secret"), []byte("x"), 0o600)
	d, err := OpenDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	for _, name := range []string{"../x", "a/b", "..", "", "a\\b"} {
		if err := d.PublishNew(name, nil); !errors.Is(err, ErrUnsafe) {
			t.Errorf("publish %q: %v", name, err)
		}
	}
	if runtime.GOOS == "windows" {
		return
	}
	os.Symlink(filepath.Join(outside, "secret"), filepath.Join(dir, "link"))
	if _, err := d.ReadRegular("link", 10); !errors.Is(err, ErrUnsafe) {
		t.Errorf("read through symlink: %v", err)
	}
	if err := d.PublishNew("link", []byte("y")); !errors.Is(err, ErrExists) {
		t.Errorf("publish over symlink: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(outside, "secret")); string(b) != "x" {
		t.Fatalf("outside file modified: %q", b)
	}
	os.Symlink(outside, filepath.Join(dir, "sub"))
	if _, err := OpenDir(filepath.Join(dir, "sub")); !errors.Is(err, ErrUnsafe) {
		t.Errorf("symlinked directory: %v", err)
	}
}

func TestDetectsSwappedDirectory(t *testing.T) {
	base := t.TempDir()
	p := filepath.Join(base, "d")
	os.Mkdir(p, 0o700)
	d, err := OpenDir(p)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := os.Rename(p, p+".old"); err != nil {
		t.Skip("cannot rename an open directory here")
	}
	os.Mkdir(p, 0o700)
	if err := d.PublishNew("r", []byte("z")); !errors.Is(err, ErrChanged) {
		t.Fatalf("publish into swapped dir: %v", err)
	}
	if _, err := os.Stat(filepath.Join(p, "r")); err == nil {
		t.Fatal("published into the replacement directory")
	}
}

func TestReadRegularLimits(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "big"), make([]byte, 11), 0o600)
	d, _ := OpenDir(dir)
	defer d.Close()
	if _, err := d.ReadRegular("big", 10); !errors.Is(err, ErrTooBig) {
		t.Fatalf("got %v", err)
	}
	if runtime.GOOS != "windows" {
		os.Link(filepath.Join(dir, "big"), filepath.Join(dir, "big2"))
		if _, err := d.ReadRegular("big", 100); !errors.Is(err, ErrUnsafe) {
			t.Fatalf("multiply linked: %v", err)
		}
	}
}

func TestReplaceRequiresUnchangedPrior(t *testing.T) {
	dir := t.TempDir()
	d, _ := OpenDir(dir)
	defer d.Close()
	if err := d.Replace("s.json", []byte("v1"), nil); err != nil {
		t.Fatal(err)
	}
	if err := d.Replace("s.json", []byte("v1b"), nil); !errors.Is(err, ErrExists) {
		t.Fatalf("absent precondition: %v", err)
	}
	snap, err := d.Snapshot("s.json", 100)
	if err != nil {
		t.Fatal(err)
	}
	// Someone else replaces the file between our read and our write.
	os.WriteFile(filepath.Join(dir, "other"), []byte("v1"), 0o600)
	os.Rename(filepath.Join(dir, "other"), filepath.Join(dir, "s.json"))
	if err := d.Replace("s.json", []byte("v2"), snap); !errors.Is(err, ErrChanged) {
		t.Fatalf("stale snapshot: %v", err)
	}
	snap, _ = d.Snapshot("s.json", 100)
	if err := d.Replace("s.json", []byte("v2"), snap); err != nil {
		t.Fatal(err)
	}
	if b, _ := d.ReadRegular("s.json", 10); string(b) != "v2" {
		t.Fatalf("got %q", b)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("leftovers: %v", entries)
	}
}

func TestMkdirPrivate(t *testing.T) {
	dir := t.TempDir()
	d, _ := OpenDir(dir)
	defer d.Close()
	sub, err := d.MkdirPrivate("cache")
	if err != nil {
		t.Fatal(err)
	}
	sub.Close()
	again, err := d.MkdirPrivate("cache")
	if err != nil {
		t.Fatalf("existing dir: %v", err)
	}
	again.Close()
	if runtime.GOOS != "windows" {
		fi, _ := os.Stat(filepath.Join(dir, "cache"))
		if fi.Mode().Perm() != 0o700 {
			t.Fatalf("mode %v", fi.Mode().Perm())
		}
		// An existing directory wider than 0700 is not private (red-team: MkdirPrivate accepted any mode).
		if err := os.Mkdir(filepath.Join(dir, "wide"), 0o755); err != nil {
			t.Fatal(err)
		}
		os.Chmod(filepath.Join(dir, "wide"), 0o755)
		if _, err := d.MkdirPrivate("wide"); !errors.Is(err, ErrUnsafe) {
			t.Fatalf("0755 dir accepted: %v", err)
		}
		os.Symlink(t.TempDir(), filepath.Join(dir, "ln"))
		if _, err := d.MkdirPrivate("ln"); !errors.Is(err, ErrUnsafe) {
			t.Fatalf("symlink: %v", err)
		}
	}
	os.WriteFile(filepath.Join(dir, "f"), nil, 0o600)
	if _, err := d.MkdirPrivate("f"); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("file: %v", err)
	}
}
