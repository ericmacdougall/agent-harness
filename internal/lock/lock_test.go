package lock

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestExcludesWithinProcessDescriptors(t *testing.T) {
	p := filepath.Join(t.TempDir(), ".lock")
	a, err := Acquire(p, Never)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Acquire(p, Never); !errors.Is(err, ErrBusy) {
		t.Fatalf("second acquire: %v", err)
	}
	start := time.Now()
	if _, err := Acquire(p, Wait(100*time.Millisecond)); !errors.Is(err, ErrBusy) || time.Since(start) < 90*time.Millisecond {
		t.Fatalf("deadline acquire: %v after %v", err, time.Since(start))
	}
	a.Close()
	b, err := Acquire(p, Never)
	if err != nil {
		t.Fatalf("after release: %v", err)
	}
	b.Close()
}

func TestRefusesUnsafeFiles(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode, owner and symlink rules are Unix-only")
	}
	dir := t.TempDir()
	loose := filepath.Join(dir, "loose")
	os.WriteFile(loose, nil, 0o644)
	os.Chmod(loose, 0o644)
	if _, err := Acquire(loose, Never); !errors.Is(err, ErrUnsafe) {
		t.Errorf("mode 0644: %v", err)
	}
	target := filepath.Join(dir, "target")
	os.WriteFile(target, nil, 0o600)
	link := filepath.Join(dir, "link")
	os.Symlink(target, link)
	if _, err := Acquire(link, Never); !errors.Is(err, ErrUnsafe) {
		t.Errorf("symlink: %v", err)
	}
	hard := filepath.Join(dir, "hard")
	os.Link(target, hard)
	if _, err := Acquire(hard, Never); !errors.Is(err, ErrUnsafe) {
		t.Errorf("two links: %v", err)
	}
}

// Cross-implementation: a Python flock holder must exclude Go, and a Go holder must exclude Python.
func TestInteropWithPythonFlock(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the Python helpers do not lock on Windows")
	}
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	p := filepath.Join(t.TempDir(), ".lock")
	holder := exec.Command(py, "-I", "-c", `import fcntl,os,sys,time
fd=os.open(sys.argv[1], os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW, 0o600)
fcntl.flock(fd, fcntl.LOCK_EX); print("held", flush=True); sys.stdin.read()`, p)
	in, _ := holder.StdinPipe()
	out, _ := holder.StdoutPipe()
	if err := holder.Start(); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if _, err := out.Read(buf); err != nil || string(buf[:4]) != "held" {
		t.Fatalf("python holder did not start: %q %v", buf, err)
	}
	if _, err := Acquire(p, Never); !errors.Is(err, ErrBusy) {
		t.Errorf("go acquired while python held it: %v", err)
	}
	in.Close()
	holder.Wait()

	l, err := Acquire(p, Never)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	probe := exec.Command(py, "-I", "-c", `import fcntl,os,sys
fd=os.open(sys.argv[1], os.O_RDWR)
try:
    fcntl.flock(fd, fcntl.LOCK_EX|fcntl.LOCK_NB); print("acquired")
except BlockingIOError:
    print("busy")`, p)
	res, err := probe.Output()
	if err != nil || strings.TrimSpace(string(res)) != "busy" {
		t.Errorf("python saw %q (%v) while go held the lock", res, err)
	}
}
